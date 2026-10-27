package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/peerspan/peerspan/go/internal/integration"
	"github.com/peerspan/peerspan/go/internal/membership"
	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"
)

var setupSecret = regexp.MustCompile(`(?:psl2-|psi2-)[A-Za-z0-9_-]+|peerspan-(?:member-)?invite-v1\.[A-Za-z0-9_-]+|(?:token|instance)_[0-9a-f]{64}`)

type setupStage struct {
	Stage string `json:"stage"`
	State string `json:"state"`
}
type setupProgress struct {
	State  string       `json:"state"`
	Stages []setupStage `json:"stages"`
}
type setupResult struct {
	Setup      setupProgress `json:"setup"`
	Service    any           `json:"service"`
	Network    any           `json:"network"`
	Attachment any           `json:"attachment"`
	Attention  []any         `json:"attention"`
	Next       string        `json:"next"`
}

func setupPrompt(ctx context.Context, out io.Writer, question, fallback string, secret bool) (string, error) {
	if !isTerminal(os.Stdin) {
		return "", errors.New("without a terminal, supply the missing setup choices as flags")
	}
	fmt.Fprint(out, question)
	if fallback != "" {
		fmt.Fprintf(out, " [%s]", fallback)
	}
	fmt.Fprint(out, ": ")
	if secret {
		old, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS)
		if err != nil {
			return "", err
		}
		quiet := *old
		quiet.Lflag &^= unix.ECHO
		if err := unix.IoctlSetTermios(int(os.Stdin.Fd()), unix.TCSETS, &quiet); err != nil {
			return "", err
		}
		defer func() { _ = unix.IoctlSetTermios(int(os.Stdin.Fd()), unix.TCSETS, old); fmt.Fprintln(out) }()
	}
	type answer struct {
		line string
		err  error
	}
	ch := make(chan answer, 1)
	go func() { line, err := stdin.ReadString('\n'); ch <- answer{line, err} }()
	select {
	case <-ctx.Done():
		return "", errors.New("setup cancelled; completed stages were kept")
	case a := <-ch:
		if a.err != nil {
			return "", errors.New("setup input ended; completed stages were kept")
		}
		line := strings.TrimSpace(a.line)
		if line == "" {
			line = fallback
		}
		if line == "" {
			return "", errors.New("a setup choice is required; run up again to continue")
		}
		return line, nil
	}
}

// setupService preserves the installed executable and unit. Starting a stopped
// service must not silently change its state or switch its host implementation.
func setupService(ctx context.Context, state string) (map[string]any, bool, error) {
	m, err := findServiceManager()
	if err != nil {
		return nil, false, err
	}
	if m == nil {
		return nil, false, errNoServiceManager
	}
	data, err := os.ReadFile(m.unit)
	if errors.Is(err, os.ErrNotExist) {
		flags := pflag.NewFlagSet("install", pflag.ContinueOnError)
		flags.String("peer-listen", "", "")
		flags.Bool("no-start", false, "")
		var result map[string]any
		err = installService(ctx, flags, state, func(v map[string]any) error { result = v; return nil })
		if err == nil && result["started"] != true {
			err = errors.New("service did not start; run peerspan status and inspect the user service")
		}
		return result, false, err
	}
	if err != nil {
		return nil, false, err
	}
	args := m.installedArguments(string(data))
	installed := ""
	for i, a := range args {
		if a == "--state" && i+1 < len(args) {
			installed = args[i+1]
		}
	}
	if installed == "" {
		return nil, false, errors.New("installed service has no explicit state; manage it with peerspan install before up")
	}
	installed, err = filepath.Abs(installed)
	if err != nil || installed != state {
		return nil, false, fmt.Errorf("service %s uses different state; use its --state or manage it with peerspan install before up", m.unit)
	}
	active := m.active(ctx)
	if daemonReachable(state) && !active {
		return nil, false, fmt.Errorf("a daemon is running on %s outside the service; stop it first", state)
	}
	if !active {
		if _, err := tool(ctx, "systemctl", "--user", "start", systemdUnitName); err != nil {
			return nil, false, err
		}
	}
	deadline := time.Now().Add(installSocketWait)
	for !daemonReachable(state) {
		if time.Now().After(deadline) {
			return nil, false, errors.New("service did not start; run peerspan status and inspect the user service")
		}
		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return map[string]any{"service": m.name, "unit": m.unit, "state": state, "peer_listen": m.installedPeerListen(string(data)), "linger": m.linger(ctx), "started": true}, active, nil
}

func setupInvite(value string, now time.Time) (membership.Token, error) {
	if strings.HasPrefix(value, host.FeatureInvitePrefix) {
		return host.InspectCurrentFeatureInvite(value)
	}
	if strings.HasPrefix(value, membership.MemberTokenPrefix) {
		t, err := membership.DecodeMemberToken(value, now)
		return t.Token, err
	}
	return membership.DecodeToken(value, now)
}

func runUp(ctx context.Context, harness string, harnessArgs []string, fs *pflag.FlagSet, state string, out, errOut io.Writer) error {
	result := setupResult{Setup: setupProgress{State: "incomplete"}, Attention: []any{}, Next: "peerspan up"}
	for _, name := range []string{"preflight", "service", "membership", "trust", "attachment"} {
		result.Setup.Stages = append(result.Setup.Stages, setupStage{name, "pending"})
	}
	stage := 0
	finish := func(reused bool) {
		value := "completed"
		if reused {
			value = "reused"
		}
		result.Setup.Stages[stage].State = value
		fmt.Fprintf(errOut, "%s: %s\n", result.Setup.Stages[stage].Stage, value)
		stage++
	}
	noStart, _ := fs.GetBool("no-start")
	var profile *integration.Profile
	var prepared *integration.Profile
	var reusedConnection *host.Connection
	var workspace string
	work := func() error {
		if runtime.GOOS != "linux" {
			return errors.New("guided up currently supports validated Linux installs")
		}
		if err := resolveExpiry([]string{"up", ""}, fs); err != nil {
			return err
		}
		if at, _ := fs.GetString("expires-at"); at != "" {
			expires, err := time.Parse(time.RFC3339Nano, at)
			if err != nil || !expires.After(time.Now()) {
				return errors.New("use a future RFC3339 expiry")
			}
		}
		create, _ := fs.GetString("create")
		joinRequested, _ := fs.GetBool("join")
		token := ""
		trusted, _ := fs.GetBool("trusted")
		untrusted, _ := fs.GetBool("untrusted")
		if !joinRequested && (fs.Changed("invite-stdin") || fs.Changed("invite-file")) {
			return errors.New("private invitation inputs require --join")
		}
		if create != "" && joinRequested {
			return errors.New("give only one of --create and --join")
		}
		if trusted && untrusted {
			return errors.New("give only one of --trusted and --untrusted")
		}
		if noStart && len(harnessArgs) > 0 {
			return errors.New("harness arguments require a launch; omit --no-start")
		}
		if fs.Changed("coordinator") || fs.Changed("coordinator-key") {
			return errors.New("new guided setup is coordinator-free; migrate legacy history explicitly")
		}
		label, _ := fs.GetString("as")
		if joinRequested && label != "" {
			return errors.New("--as is for creation; the private introduction pins its member label")
		}
		if create != "" && !membership.ValidLabel(create) {
			return errors.New("use a valid network name for --create")
		}
		if label != "" && !membership.ValidLabel(label) {
			return errors.New("use a valid person label for --as")
		}
		if state == "" {
			var err error
			state, err = host.DefaultStateDir()
			if err != nil {
				return err
			}
		}
		var err error
		state, err = filepath.Abs(state)
		if err != nil {
			return err
		}
		result.Next = "peerspan --state " + setupQuote(state) + " up"
		project, _ := fs.GetString("directory")
		if project == "" {
			project, err = os.Getwd()
			if err != nil {
				return err
			}
		}
		workspace, err = filepath.Abs(project)
		if err == nil {
			workspace, err = filepath.EvalSymlinks(workspace)
		}
		if err != nil {
			return err
		}
		if info, err := os.Stat(workspace); err != nil || !info.IsDir() {
			return errors.New("--directory must be an existing project directory")
		}
		_ = fs.Set("directory", workspace)
		paths, err := integration.WorkspaceProfiles(state, workspace)
		if err != nil {
			return err
		}
		if len(paths) > 1 {
			return errors.New("several attach profiles record this project; use peerspan session doctor --directory PROFILE")
		}
		if len(paths) == 1 {
			profile, err = integration.ReadProfile(paths[0])
			if err != nil {
				return err
			}
		}
		if harness == "claude" {
			harness = "claude-code"
		}
		if harness == "" && profile != nil {
			harness = profile.Harness.ID
		}
		if harness == "" {
			harness, err = setupPrompt(ctx, errOut, "Agent (claude, codex, or opencode)", "", false)
			if err != nil {
				return errors.New("choose HARNESS, for example peerspan up claude: " + err.Error())
			}
			if harness == "claude" {
				harness = "claude-code"
			}
		}
		name, _ := fs.GetString("name")
		if name != "" && !host.AddressableName(name) {
			return errors.New("--name must be an addressable agent name")
		}
		values, _ := fs.GetStringArray("option")
		options, err := integration.ParseOptions(values)
		if err != nil {
			return err
		}
		if profile != nil {
			if harness != profile.Harness.ID || (name != "" && name != filepath.Base(profile.Directory)) {
				return errors.New("this project already has another agent or integration; use its existing attachment or the explicit session commands")
			}

			for key, value := range options {
				if saved, ok := profile.Options[key]; !ok || saved != value {
					return fmt.Errorf("--option %s conflicts with this project's attachment; use its existing conversation", key)
				}
			}
			at, _ := fs.GetString("expires-at")
			if at != "" && at != profile.Request.ExpiresAt {
				return errors.New("the requested expiry differs from this project's attachment; use explicit session recovery")
			}
			callsInput, _ := fs.GetBool("calls")
			noCallsInput, _ := fs.GetBool("no-calls")
			if callsInput && !profile.Request.Calls || noCallsInput && profile.Request.Calls {
				return errors.New("the requested calls setting differs from this project's attachment")
			}
			sendBudget, callBudget := int64(100), int64(100)
			if profile.Request.MaxSendsPerHour != nil {
				sendBudget = *profile.Request.MaxSendsPerHour
			}
			if profile.Request.MaxCallsPerHour != nil {
				callBudget = *profile.Request.MaxCallsPerHour
			}
			sendsInput, _ := fs.GetInt64("max-sends-per-hour")
			callsBudgetInput, _ := fs.GetInt64("max-calls-per-hour")
			if fs.Changed("max-sends-per-hour") && sendsInput != sendBudget || fs.Changed("max-calls-per-hour") && (!profile.Request.Calls || callsBudgetInput != callBudget) {
				return errors.New("the requested rate budget differs from this project's attachment")
			}
			if at == "" && profile.Request.ExpiresAt != "" {
				_ = fs.Set("expires-at", profile.Request.ExpiresAt)
			}
			if !fs.Changed("max-sends-per-hour") {
				_ = fs.Set("max-sends-per-hour", fmt.Sprint(sendBudget))
			}
			for k, v := range profile.Options {
				if supplied, ok := options[k]; ok && supplied != v {
					return fmt.Errorf("--option %s conflicts with this project's attachment; use its existing conversation", k)
				}
				options[k] = v
			}
			calls, _ := fs.GetBool("calls")
			noCalls, _ := fs.GetBool("no-calls")
			if !calls && !noCalls {
				if profile.Request.Calls {
					_ = fs.Set("calls", "true")
					if profile.Request.MaxCallsPerHour != nil && !fs.Changed("max-calls-per-hour") {
						_ = fs.Set("max-calls-per-hour", fmt.Sprint(*profile.Request.MaxCallsPerHour))
					}
				} else {
					_ = fs.Set("no-calls", "true")
				}
			}
		}
		calls, _ := fs.GetBool("calls")
		noCalls, _ := fs.GetBool("no-calls")
		maxCalls, _ := fs.GetInt64("max-calls-per-hour")
		maxSends, _ := fs.GetInt64("max-sends-per-hour")
		if calls && noCalls || noCalls && fs.Changed("max-calls-per-hour") || maxCalls < 1 || maxCalls > 10000 || maxSends < 1 || maxSends > 10000 {
			return errors.New("invalid capability call flags or rate limits; see peerspan up --help")
		}
		for _, input := range setupOptions(harness) {
			if options[input[0]] == "" {
				if !isTerminal(os.Stdin) {
					return fmt.Errorf("%s needs --option %s=VALUE; %s", harness, input[0], input[1])
				}
				v, err := setupPrompt(ctx, errOut, input[1], "", false)
				if err != nil {
					return err
				}
				options[input[0]] = v
			}
		}
		// Replace the parsed option values rather than appending defaults twice.
		if err := fs.Lookup("option").Value.(pflag.SliceValue).Replace(nil); err != nil {
			return err
		}
		for k, v := range options {
			if err := fs.Lookup("option").Value.(pflag.SliceValue).Append(k + "=" + v); err != nil {
				return err
			}
		}
		dir := filepath.Join(state, "up-preflight")
		if profile != nil {
			dir = profile.Directory
		}
		root, _ := fs.GetString("integrations")
		runner, _ := fs.GetString("runner")
		if profile != nil {
			if err := integration.ValidateAttachmentManifest(profile, root, runner); err != nil {
				return err
			}
		}
		if err := integration.Preflight(ctx, integration.Options{Directory: dir, State: state, Harness: harness, Integrations: root, Runner: runner, ProviderOptions: options, Workspace: workspace, Args: harnessArgs}); err != nil {
			return err
		}
		if joinRequested {
			token, err = decInvitationInput(ctx, fs, errOut)
			if err != nil {
				return err
			}
			if _, err = inspectDecInvitation(token); err != nil {
				return err
			}
		}
		finish(profile != nil)
		service, reused, err := setupService(ctx, state)
		result.Service = service
		if err != nil {
			return err
		}
		finish(reused)
		client := host.Client{SocketPath: filepath.Join(state, "admin.sock")}
		n, existing, err := setupDecMembership(ctx, client, create, joinRequested, token, label, personKey(fs), &result, state, errOut)
		if err != nil {
			return err
		}
		finish(existing)
		result.Next = "peerspan --state " + setupQuote(state) + " up"
		if err = setupDecTrust(ctx, client, n, existing, trusted, untrusted, personKey(fs), errOut); err != nil {
			result.Next = "peerspan trust --network " + n.ID
			return err
		}
		finish(existing && !trusted && !untrusted)
		result.Next = "peerspan --state " + setupQuote(state) + " up"
		if profile != nil {
			result.Next = "peerspan session doctor --directory " + setupQuote(profile.Directory)
		}
		if !calls && !noCalls {
			if isTerminal(os.Stdin) {
				answer, err := setupPrompt(ctx, errOut, "Let this agent call capabilities shared with you, and yours on your other trusted machines? (y/N)", "no", false)
				if err != nil {
					return err
				}
				calls = answer == "y" || answer == "yes"
			}
			_ = fs.Set("calls", fmt.Sprint(calls))
			_ = fs.Set("no-calls", fmt.Sprint(!calls))
		}
		if err := attachPrepared(ctx, client, harness, harnessArgs, fs, state, errOut, func(p *integration.Profile, v map[string]any) error {
			prepared, result.Attachment = p, v
			if connection, ok := v["connection"].(host.Connection); ok {
				reusedConnection = &connection
			}
			return nil
		}, true); err != nil {
			return err
		}
		result.Next = "peerspan session start --directory " + setupQuote(prepared.Directory)
		if reusedConnection != nil {
			result.Next = "peerspan session doctor --directory " + setupQuote(prepared.Directory)
		}
		finish(result.Attachment.(map[string]any)["reused"] == true)
		result.Setup.State = "prepared"
		return nil
	}
	err := work()
	if err == nil && !noStart && reusedConnection != nil && reusedConnection.State == "offline" {
		result.Setup.State = "incomplete"
		result.Setup.Stages = append(result.Setup.Stages, setupStage{"launch", "failed"})
		result.Next = "peerspan session doctor --directory " + setupQuote(prepared.Directory)
		err = errors.New("the existing attachment is reconnecting; reconnect its original integration or inspect " + result.Next + "; no duplicate was launched")
	}
	if err != nil {
		if stage < len(result.Setup.Stages) {
			result.Setup.Stages[stage].State = "failed"
		}
		message := setupSecret.ReplaceAllString(err.Error(), "[redacted]")
		result.Attention = append(result.Attention, map[string]any{"stage": result.Setup.Stages[min(stage, len(result.Setup.Stages)-1)].Stage, "detail": message})
		err = errors.New(message)
	}
	// Redact nested diagnostics as well as the final error, including a repair
	// command returned by onboarding that contains a bearer invite.
	data, marshalErr := json.MarshalIndent(result, "", "  ")
	if marshalErr != nil {
		return marshalErr
	}
	writer := errOut
	if noStart {
		writer = out
	}
	fmt.Fprintln(writer, setupSecret.ReplaceAllString(string(data), "[redacted]"))
	if err != nil {
		return err
	}
	if noStart {
		return nil
	}
	if reusedConnection != nil {
		fmt.Fprintln(errOut, "Prepared; the existing integration remains running. No duplicate was launched; inspect peerspan status for delivery readiness.")
		return nil
	}
	fmt.Fprintln(errOut, "Prepared; starting the integration. Check peerspan status for its connection and delivery readiness.")
	if err := integration.Run(ctx, integration.Options{Action: "start", Directory: prepared.Directory, State: state, Workspace: workspace, Args: harnessArgs, Program: programName}, out); err != nil {
		message := setupSecret.ReplaceAllString(err.Error(), "[redacted]")
		result.Setup.State = "incomplete"
		result.Setup.Stages = append(result.Setup.Stages, setupStage{"launch", "failed"})
		result.Attention = append(result.Attention, map[string]any{"stage": "launch", "detail": message})
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Fprintln(errOut, setupSecret.ReplaceAllString(string(data), "[redacted]"))
		return errors.New(message)
	}
	return nil
}

func setupOptions(harness string) [][2]string {
	switch harness {
	case "codex":
		return [][2]string{{"socket", "Existing Codex backend socket (codex app-server daemon version)"}, {"thread", "Existing loaded conversation UUID (/status in Codex)"}}
	case "opencode":
		return [][2]string{{"server", "Existing OpenCode loopback server URL"}, {"session", "Existing conversation ID (opencode session list in the project)"}, {"directory", "Existing OpenCode project directory"}, {"bindings", "Private binding directory from the installed Peerspan plugin configuration"}}
	}
	return nil
}

func setupQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'" }
