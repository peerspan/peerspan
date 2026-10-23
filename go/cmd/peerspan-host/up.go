package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/peerspan/peerspan/go/internal/integration"
	"github.com/peerspan/peerspan/go/internal/membership"
	"github.com/peerspan/peerspan/go/internal/person"
	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"
)

var setupSecret = regexp.MustCompile(`peerspan-(?:member-)?invite-v1\.[A-Za-z0-9_-]+|(?:token|instance)_[0-9a-f]{64}`)

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
		token, _ := fs.GetString("join")
		trusted, _ := fs.GetBool("trusted")
		untrusted, _ := fs.GetBool("untrusted")
		if create != "" && token != "" {
			return errors.New("give only one of --create and --join")
		}
		if trusted && untrusted {
			return errors.New("give only one of --trusted and --untrusted")
		}
		if noStart && len(harnessArgs) > 0 {
			return errors.New("harness arguments require a launch; omit --no-start")
		}
		address, _ := fs.GetString("coordinator")
		key, _ := fs.GetString("coordinator-key")
		if (address == "") != (key == "") {
			return errors.New("give both --coordinator and --coordinator-key")
		}
		if address != "" {
			if !membership.ValidCoordinatorAddress(address) {
				return errors.New("--coordinator must be HOST:PORT")
			}
			if _, err := membership.DecodeKey(key); err != nil {
				return err
			}
		}
		label, _ := fs.GetString("as")
		if token != "" && (label != "" || address != "") {
			return errors.New("--as and coordinator flags are for creation; joining uses its invite")
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
		if err := integration.Preflight(ctx, integration.Options{Directory: dir, State: state, Harness: harness, Integrations: root, Runner: runner, ProviderOptions: options, Workspace: workspace, Args: harnessArgs}); err != nil {
			return err
		}
		if token != "" {
			if _, err := setupInvite(token, time.Time{}); err != nil {
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
		networks, err := call[[]host.Network](ctx, client, "GET", "/v1/networks")
		if err != nil {
			return err
		}
		if len(networks) > 1 {
			names := []string{}
			for _, n := range networks {
				names = append(names, n.Name+" ("+n.ID+")")
			}
			return fmt.Errorf("guided up supports one network; found %s; use network and attach commands", strings.Join(names, ", "))
		}
		if len(networks) == 0 && create == "" && token == "" {
			choice, err := setupPrompt(ctx, errOut, "Create a network or join with an invite (create/join)", "", false)
			if err != nil {
				return errors.New("choose --create NAME or --join TOKEN: " + err.Error())
			}
			switch choice {
			case "create":
				create, err = setupPrompt(ctx, errOut, "Network name", "personal", false)
			case "join":
				token, err = setupPrompt(ctx, errOut, "Invite (hidden)", "", true)
			default:
				err = errors.New("choose create or join")
			}
			if err != nil {
				return err
			}
		}
		var outcome map[string]any
		existing := len(networks) == 1
		if existing {
			n := networks[0]
			if create != "" && create != n.Name || address != "" && (address != n.CoordinatorAddress || key != n.CoordinatorPublicKey) {
				return errors.New("creation inputs conflict with the existing network; use explicit network commands")
			}
			if token != "" {
				invite, err := setupInvite(token, time.Time{})
				if err != nil {
					return err
				}
				if invite.NetworkID != n.ID {
					return errors.New("invite names a different network; use explicit network commands")
				}
			}
		} else {
			reviewName, reviewLabel, reviewAddress, reviewKey := create, label, address, key
			if token != "" {
				invite, err := setupInvite(token, time.Now())
				if err != nil {
					return err
				}
				reviewName, reviewLabel, reviewAddress, reviewKey = invite.NetworkName, invite.Member, invite.CoordinatorAddress, invite.CoordinatorPublicKey
			} else {
				if reviewLabel == "" {
					reviewLabel = loginName()
				}
				if !membership.ValidLabel(create) || !membership.ValidLabel(reviewLabel) {
					return errors.New("use a valid network name and person label")
				}
				if reviewAddress == "" {
					info, err := call[host.HostInfo](ctx, client, "GET", "/v1/host")
					if err != nil {
						return err
					}
					if info.DefaultCoordinator == nil {
						return errors.New("this build has no default coordinator; pass --coordinator and --coordinator-key")
					}
					reviewAddress, reviewKey = info.DefaultCoordinator.Address, info.DefaultCoordinator.PublicKey
				}
			}
			fmt.Fprintf(errOut, "Network: %s; person: %s; coordinator: %s (pinned key %s)\n", reviewName, reviewLabel, reviewAddress, reviewKey)
			command := "create"
			if token != "" {
				command = "join"
			}
			f := pflag.NewFlagSet("onboarding", pflag.ContinueOnError)
			f.String("person-key", personKey(fs), "")
			f.Bool("no-person", false, "")
			f.Bool("trusted", trusted, "")
			f.Bool("untrusted", untrusted, "")
			f.String("as", label, "")
			f.String("member", "", "")
			f.String("name", create, "")
			f.String("coordinator", address, "")
			f.String("coordinator-key", key, "")
			f.String("token", token, "")
			f.String("descriptor", "", "")
			choice, err := person.Choose(personKey(fs))
			if err != nil {
				return err
			}
			fmt.Fprintf(errOut, "Network: %s; person key: %s\n", command, choice.Source)
			choice.Close()
			fmt.Fprintln(errOut, "A machine holding your person private key can sign a policy that marks itself trusted.")
			if token != "" {
				fmt.Fprintln(errOut, "To join as the same person on another machine, make that person's existing key available through ssh-agent or the documented key-file copy.")
			}
			if !trusted && !untrusted {
				if isTerminal(os.Stdin) {
					answer, err := setupPrompt(ctx, errOut, "Let this machine use your capabilities on other machines, and source tools those hosts allow? (y/N)", "no", false)
					if err != nil {
						return err
					}
					trusted = answer == "y" || answer == "yes"
				}
				untrusted = !trusted
				_ = f.Set("trusted", fmt.Sprint(trusted))
				_ = f.Set("untrusted", fmt.Sprint(untrusted))
			}
			if err := onboard(ctx, client, command, nil, f, state, errOut, func(v map[string]any) error { outcome = v; return nil }); err != nil {
				return err
			}
			result.Network = map[string]any{"id": outcome["id"], "name": outcome["name"], "coordinator_address": outcome["coordinator_address"], "coordinator_public_key": outcome["coordinator_public_key"], "person": outcome["person"]}
			if failure, ok := outcome["last_sync_error"].(string); ok && failure != "" {
				result.Next = "peerspan network sync " + fmt.Sprint(outcome["id"])
				return fmt.Errorf("pinned coordinator check failed: %s", failure)
			}
			p, _ := outcome["person"].(map[string]any)
			if p["admitted"] != true || p["bound"] != true {
				result.Next = fmt.Sprint(p["next"])
				return errors.New("host joined, but person identity is incomplete; " + result.Next)
			}
			if next, ok := p["next"].(string); ok && next != "" {
				fmt.Fprintln(errOut, next)
			}
			networks, err = call[[]host.Network](ctx, client, "GET", "/v1/networks")
			if err != nil {
				return err
			}
		}
		if len(networks) != 1 {
			return errors.New("membership changed during setup; inspect peerspan status before retrying")
		}
		n := networks[0]
		status, _, err := readHostPersons(ctx, client)
		if err != nil {
			return err
		}
		var bound *host.StatusPerson
		for _, entry := range status.Networks {
			if entry.ID == n.ID {
				bound = entry.Person
			}
		}
		result.Network = map[string]any{"id": n.ID, "name": n.Name, "coordinator_address": n.CoordinatorAddress, "coordinator_public_key": n.CoordinatorPublicKey, "person": bound}
		if bound == nil {
			result.Next = "peerspan network bind --network " + n.ID
			return errors.New("this host's person is unbound; use the original person key and " + result.Next)
		}
		signer, err := person.Load(personKey(fs))
		if err != nil {
			return fmt.Errorf("recover the original person key before continuing: %w", err)
		}
		id := membership.PersonID(signer.PublicKey())
		signer.Close()
		if id != bound.ID {
			return errors.New("selected person key differs from this host's bound person; recover the original key")
		}
		if label != "" && (bound.Label == nil || *bound.Label != label) {
			return errors.New("--as differs from the existing bound person")
		}
		if existing {
			result.Next = "peerspan network sync " + n.ID
			synced, err := call[host.Network](ctx, client, "POST", "/v1/networks/"+url.PathEscape(n.ID)+"/sync")
			if err != nil {
				return fmt.Errorf("pinned coordinator check failed: %w", err)
			}
			if synced.LastSyncError != nil {
				return fmt.Errorf("pinned coordinator check failed: %s", *synced.LastSyncError)
			}
			result.Network.(map[string]any)["coordinator_address"] = synced.CoordinatorAddress
			result.Network.(map[string]any)["coordinator_public_key"] = synced.CoordinatorPublicKey
			status, _, err = readHostPersons(ctx, client)
			if err != nil {
				return err
			}
			current := false
			for _, entry := range status.Networks {
				if entry.ID == n.ID && entry.Person != nil && entry.Person.ID == id {
					current = true
					bound = entry.Person
				}
			}
			if !current {
				return errors.New("person binding changed during coordination; inspect peerspan status before retrying")
			}
			result.Network.(map[string]any)["person"] = bound
		}
		fmt.Fprintf(errOut, "Network: %s (%s); person: %s\n", n.Name, n.ID, bound.ID)
		finish(existing)
		result.Next = "peerspan --state " + setupQuote(state) + " up"
		_ = fs.Set("trusted", fmt.Sprint(trusted))
		_ = fs.Set("untrusted", fmt.Sprint(untrusted))
		if existing && (trusted || untrusted) {
			f := pflag.NewFlagSet("trust", pflag.ContinueOnError)
			f.String("network", n.ID, "")
			f.String("person-key", personKey(fs), "")
			command := "trust"
			if untrusted {
				command = "untrust"
			}
			if err := runTrust(ctx, client, command, nil, f, io.Discard); err != nil {
				result.Next = "peerspan " + command + " --network " + n.ID
				return err
			}
		}
		if outcome != nil && outcome["trusted_error"] != nil {
			result.Next = "peerspan trust --network " + n.ID
			return fmt.Errorf("requested trust failed: %v", outcome["trusted_error"])
		}
		finish(existing && !trusted && !untrusted)
		result.Next = "peerspan --state " + setupQuote(state) + " up"
		if profile != nil {
			result.Next = "peerspan session doctor --directory " + setupQuote(profile.Directory)
		}
		policy, err := call[json.RawMessage](ctx, client, "GET", "/v1/networks/"+url.PathEscape(n.ID)+"/policy")
		if err == nil {
			result.Network.(map[string]any)["access"] = policy
		} else {
			var e *host.ClientError
			if !errors.As(err, &e) || e.Status != 404 {
				return err
			}
			result.Network.(map[string]any)["access"] = nil
		}
		for _, item := range status.Attention {
			result.Attention = append(result.Attention, item)
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
		if err := attachPrepared(ctx, client, harness, harnessArgs, fs, state, errOut, func(p *integration.Profile, v map[string]any) error { prepared = p; result.Attachment = v; return nil }); err != nil {
			return err
		}
		result.Next = "peerspan session start --directory " + setupQuote(prepared.Directory)
		finish(result.Attachment.(map[string]any)["reused"] == true)
		result.Setup.State = "prepared"
		return nil
	}
	err := work()
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
