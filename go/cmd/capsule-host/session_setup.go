package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/host"
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

	if o.Directory == "" && o.Action != "setup" {
		// Without --directory, start and doctor use the attach profile
		// recorded for the current directory.
		state := o.State
		if state == "" {
			var err error
			if state, err = host.DefaultStateDir(); err != nil {
				return err
			}
		}
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		if o.Directory, err = integration.WorkspaceProfile(state, cwd); err != nil {
			return err
		}
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

// pendingHookLead introduces the pending work in the session start hook's
// context.
const pendingHookLead = "Capsule work this session still owes, listed after /clear, compaction, or resume. Finish each task with the task_* tools and answer each delivery with reply; call pending_work for the current list. "

// runSessionPending prints the pending work of the current directory's
// attachment, read through the local administration API. Without an
// attachment it prints nothing and succeeds, so a session start hook that
// runs it never fails.
//
// The session start hook runs it without --state, so without one it finds
// the directory's attachment of any host state and reads that state's
// daemon.
func runSessionPending(ctx context.Context, fs *pflag.FlagSet, state string, out io.Writer) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	found, err := integration.WorkspaceProfiles(state, cwd)
	if err != nil || len(found) == 0 {
		return nil
	}
	if len(found) > 1 {
		return errors.New("several attach profiles record this directory: " + strings.Join(found, ", "))
	}
	p, err := integration.ReadProfile(found[0])
	if err != nil {
		return nil
	}
	client := host.Client{SocketPath: filepath.Join(p.State, "admin.sock")}
	data, err := client.Call(ctx, "GET", "/v1/sessions/"+url.PathEscape(p.SessionID)+"/pending", nil)
	if err != nil {
		return err
	}
	if asJSON, _ := fs.GetBool("json"); asJSON {
		_, err = fmt.Fprintln(out, string(data))
		return err
	}
	var work host.PendingWork
	if err = json.Unmarshal(data, &work); err != nil {
		return err
	}
	if hook, _ := fs.GetBool("hook"); hook {
		// Claude Code reads a hook's JSON output as hook output, so the list
		// reaches the model only as additionalContext.
		if len(work.Deliveries)+len(work.Replies)+len(work.Tasks) == 0 {
			return nil
		}
		var compact bytes.Buffer
		if err = json.Compact(&compact, data); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]any{"hookSpecificOutput": map[string]string{
			"hookEventName":     "SessionStart",
			"additionalContext": pendingHookLead + compact.String(),
		}})
	}
	line := func(text string) string { return strings.Join(strings.Fields(text), " ") }
	marks := func(flags ...string) string {
		var set []string
		for i := 0; i+1 < len(flags); i += 2 {
			if flags[i] != "" {
				set = append(set, flags[i+1])
			}
		}
		if len(set) == 0 {
			return ""
		}
		return " (" + strings.Join(set, ", ") + ")"
	}
	flag := func(v bool) string {
		if v {
			return "y"
		}
		return ""
	}
	for _, d := range work.Deliveries {
		fmt.Fprintf(out, "message %s request %s from %s%s: %s\n", d.DeliveryID, d.RequestID, d.SenderHostID, marks(flag(d.Seen), "seen", flag(d.Redelivered), "redelivered"), line(d.Preview))
	}
	for _, r := range work.Replies {
		fmt.Fprintf(out, "reply %s to request %s from %s: %s\n", r.NotificationID, r.RequestID, r.PeerHostID, line(r.Preview))
	}
	for _, t := range work.Tasks {
		fmt.Fprintf(out, "task %s %s from %s%s: %s\n", t.TaskID, t.State, t.SenderHostID, marks(flag(t.Adopted), "adopted"), line(t.Preview))
	}
	return nil
}
