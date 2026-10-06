package main

import (
	"context"
	"errors"
	"flag"
	"io"

	"github.com/Cerebral-Systems/capsule/go/internal/integration"
)

func runSessionSetup(ctx context.Context, args []string, state string, out, errOut io.Writer) error {
	o := integration.Options{Action: args[0], State: state}
	fs := flag.NewFlagSet("session "+o.Action, flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.StringVar(&o.Directory, "directory", "", "private session setup directory")
	var values integrationOptions
	if o.Action == "setup" {
		fs.StringVar(&o.Harness, "harness", "", "installed harness integration ID")
		fs.StringVar(&o.Integrations, "integrations", "", "integration bundle directory; defaults to CAPSULE_INTEGRATIONS_DIR or installation")
		fs.StringVar(&o.Runner, "runner", "", "integration helper executable override")
		fs.StringVar(&o.Agent, "agent", "", "registered agent ID")
		fs.StringVar(&o.ExpiresAt, "expires-at", "", "future RFC3339 authorization expiry")
		fs.StringVar(&o.Routes, "routes", "", "owner destination JSON array")
		fs.Var(&values, "option", "integration-specific KEY=VALUE; repeatable")
	}
	if o.Action == "start" {
		fs.StringVar(&o.Workspace, "workspace", "", "harness working directory; defaults to this directory")
	}
	parseArgs := args[1:]
	for index, arg := range parseArgs {
		if arg == "--" {
			o.Args = parseArgs[index+1:]
			parseArgs = parseArgs[:index]
			break
		}
	}
	if err := fs.Parse(parseArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 || len(o.Args) != 0 && o.Action != "start" {
		return errors.New("harness arguments require session start and a -- separator")
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

type integrationOptions []string

func (s *integrationOptions) String() string         { return "KEY=VALUE" }
func (s *integrationOptions) Set(value string) error { *s = append(*s, value); return nil }
