package main

import (
	"context"
	"errors"
	"io"
	"strconv"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/integration"
	"github.com/spf13/pflag"
)

func runSessionSetup(ctx context.Context, args []string, fs *pflag.FlagSet, state string, out io.Writer) error {
	o := integration.Options{Action: args[0], State: state, Program: programName}
	o.Directory, _ = fs.GetString("directory")
	var values []string
	var expiresIn string
	switch o.Action {
	case "setup":
		o.Harness, _ = fs.GetString("harness")
		o.Integrations, _ = fs.GetString("integrations")
		o.Runner, _ = fs.GetString("runner")
		o.Agent, _ = fs.GetString("agent")
		o.ExpiresAt, _ = fs.GetString("expires-at")
		expiresIn, _ = fs.GetString("expires-in")
		o.Routes, _ = fs.GetString("routes")
		values, _ = fs.GetStringArray("option")
	case "start":
		o.Workspace, _ = fs.GetString("workspace")
		o.Args = args[1:]
	}

	if o.Directory == "" {
		return errors.New("--directory is required")
	}
	if o.ExpiresAt != "" && expiresIn != "" {
		return errors.New("--expires-at and --expires-in are mutually exclusive")
	}
	if expiresIn != "" {
		duration, err := relativeExpiryDuration(expiresIn)
		if err != nil {
			return err
		}
		o.ExpiresAt = time.Now().UTC().Add(duration).Format(time.RFC3339)
	}
	if o.Action == "setup" && (o.Harness != "" || o.Agent != "" || o.ExpiresAt != "") && (o.Harness == "" || o.Agent == "") {
		return errors.New("session setup requires --harness and --agent, and at most one of --expires-at or --expires-in")
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

func relativeExpiryDuration(value string) (time.Duration, error) {
	if len(value) < 2 {
		return 0, errors.New("--expires-in must be a whole-minute or whole-hour duration from 1m to 720h")
	}
	amount, err := strconv.ParseInt(value[:len(value)-1], 10, 64)
	if err != nil {
		return 0, errors.New("--expires-in must be a whole-minute or whole-hour duration from 1m to 720h")
	}
	var duration time.Duration
	switch value[len(value)-1] {
	case 'm':
		if amount < 1 || amount > 30*24*60 {
			return 0, errors.New("--expires-in must be a whole-minute or whole-hour duration from 1m to 720h")
		}
		duration = time.Duration(amount) * time.Minute
	case 'h':
		if amount < 1 || amount > 30*24 {
			return 0, errors.New("--expires-in must be a whole-minute or whole-hour duration from 1m to 720h")
		}
		duration = time.Duration(amount) * time.Hour
	default:
		return 0, errors.New("--expires-in must be a whole-minute or whole-hour duration from 1m to 720h")
	}
	if duration < time.Minute || duration > 30*24*time.Hour {
		return 0, errors.New("--expires-in must be a whole-minute or whole-hour duration from 1m to 720h")
	}
	return duration, nil
}
