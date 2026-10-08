package main

import (
	"context"
	"errors"
	"io"

	"github.com/Cerebral-Systems/capsule/go/internal/integration"
	"github.com/spf13/pflag"
)

func runSessionSetup(ctx context.Context, args []string, fs *pflag.FlagSet, state string, out io.Writer) error {
	o := integration.Options{Action: args[0], State: state}
	o.Directory, _ = fs.GetString("directory")
	var values []string
	switch o.Action {
	case "setup":
		o.Harness, _ = fs.GetString("harness")
		o.Integrations, _ = fs.GetString("integrations")
		o.Runner, _ = fs.GetString("runner")
		o.Agent, _ = fs.GetString("agent")
		o.ExpiresAt, _ = fs.GetString("expires-at")
		o.Routes, _ = fs.GetString("routes")
		values, _ = fs.GetStringArray("option")
	case "start":
		o.Workspace, _ = fs.GetString("workspace")
		o.Args = args[1:]
	}

	if o.Directory == "" {
		return errors.New("--directory is required")
	}
	if o.Action == "setup" && (o.Harness != "" || o.Agent != "" || o.ExpiresAt != "") && (o.Harness == "" || o.Agent == "" || o.ExpiresAt == "") {
		return errors.New("session setup requires --harness, --agent, and --expires-at")
	}
	if o.Action == "setup" && o.Agent == "" && (o.Integrations != "" || o.Runner != "" || o.Routes != "" || len(values) != 0) {
		return errors.New("resume uses the saved integration and scopes; omit new setup options")
	}
	var err error
	o.ProviderOptions, err = integration.ParseOptions(values)
	if err != nil {
		return err
	}
	return integration.Run(ctx, o, out)
}
