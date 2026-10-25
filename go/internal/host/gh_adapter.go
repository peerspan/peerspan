package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

// The gh adapter (capabilities slice 3): a fixed set of GitHub operations
// run through the GitHub CLI, served as a built-in MCP server. This file
// holds the operations, argument validation, argument vectors, the gh
// process and its limits, and the result text, shared by the server, the
// reach check, and the bound warnings.

const (
	ghCallTimeout   = 120 * time.Second
	ghCheckTimeout  = 10 * time.Second
	ghKillGrace     = 2 * time.Second
	ghStdoutLimit   = 1000000
	ghStderrKeep    = 65536
	ghStderrShown   = 2048
	ghHost          = "github.com"
	ghMinVersion    = "2.81.0"
	ghAuthCode      = -32001
	ghTooLargeCode  = -32002
	ghAuthMessage   = "gh is not authenticated for github.com. The owner runs gh auth login, then peerspan sources refresh."
	ghTooLargeError = "gh output exceeded 1000000 bytes."
)

var ghRepoPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$`)

// validGHRepo checks a repo argument: OWNER/REPO, not ending in /. or /..
func validGHRepo(s string) bool {
	return ghRepoPattern.MatchString(s) && !strings.HasSuffix(s, "/.") && !strings.HasSuffix(s, "/..")
}

// Property kinds.
const (
	ghRepo = iota
	ghNumber
	ghEnum
	ghLimit
	ghArray
	ghString
	ghBool
	ghTitle
	ghBody
)

type ghProp struct {
	name string
	kind int
	desc string
	enum []string
	// boolDefault marks comments and name_only, which default to false.
	boolDefault bool
}

type ghOp struct {
	name, desc string
	readOnly   bool
	props      []ghProp
	required   []string
	fields     string
}

var (
	ghPropRepo   = ghProp{name: "repo", kind: ghRepo, desc: "The repository, as OWNER/REPO."}
	ghPropNumber = ghProp{name: "number", kind: ghNumber, desc: "The issue or pull request number."}
	ghPropLimit  = ghProp{name: "limit", kind: ghLimit, desc: "At most this many items."}
	ghPropLabel  = ghProp{name: "label", kind: ghArray, desc: "Only items with all of these labels."}
	ghPropAssign = ghProp{name: "assignee", kind: ghString, desc: "Only items assigned to this login."}
	ghPropAuthor = ghProp{name: "author", kind: ghString, desc: "Only items opened by this login."}
	ghPropBody   = ghProp{name: "body", kind: ghBody, desc: "The text, in Markdown."}
)

// ghOperations are the gh source's operations, in tools/list order.
var ghOperations = []ghOp{
	{name: "issue_list", desc: "List issues in a GitHub repository.", readOnly: true, required: []string{"repo"},
		props:  []ghProp{ghPropRepo, {name: "state", kind: ghEnum, desc: "Which items to list.", enum: []string{"open", "closed", "all"}}, ghPropLimit, ghPropLabel, ghPropAssign, ghPropAuthor, {name: "milestone", kind: ghString, desc: "Only issues in this milestone."}},
		fields: "number,title,state,author,labels,assignees,milestone,createdAt,updatedAt,url"},
	{name: "issue_view", desc: "Show one issue of a GitHub repository, with its comments when comments is true.", readOnly: true, required: []string{"repo", "number"},
		props:  []ghProp{ghPropRepo, ghPropNumber, {name: "comments", kind: ghBool, desc: "Include comments.", boolDefault: true}},
		fields: "number,title,state,stateReason,body,author,labels,assignees,milestone,createdAt,updatedAt,closedAt,url"},
	{name: "pr_list", desc: "List pull requests in a GitHub repository.", readOnly: true, required: []string{"repo"},
		props: []ghProp{ghPropRepo, {name: "state", kind: ghEnum, desc: "Which items to list.", enum: []string{"open", "closed", "merged", "all"}}, ghPropLimit,
			{name: "base", kind: ghString, desc: "Only pull requests into this base branch."}, {name: "head", kind: ghString, desc: "Only pull requests from this head branch."},
			ghPropLabel, ghPropAuthor, {name: "draft", kind: ghBool, desc: "Only draft pull requests."}},
		fields: "number,title,state,isDraft,author,baseRefName,headRefName,labels,createdAt,updatedAt,url"},
	{name: "pr_view", desc: "Show one pull request of a GitHub repository, with its comments and reviews when comments is true.", readOnly: true, required: []string{"repo", "number"},
		props:  []ghProp{ghPropRepo, ghPropNumber, {name: "comments", kind: ghBool, desc: "Include comments and reviews.", boolDefault: true}},
		fields: "number,title,state,isDraft,body,author,baseRefName,headRefName,mergeable,reviewDecision,additions,deletions,changedFiles,files,labels,createdAt,updatedAt,mergedAt,url"},
	{name: "pr_diff", desc: "Show the diff of a pull request, or with name_only the names of the changed files.", readOnly: true, required: []string{"repo", "number"},
		props: []ghProp{ghPropRepo, ghPropNumber, {name: "name_only", kind: ghBool, desc: "Return only the names of the changed files.", boolDefault: true}}},
	{name: "pr_checks", desc: "Show the status checks of a pull request.", readOnly: true, required: []string{"repo", "number"},
		props: []ghProp{ghPropRepo, ghPropNumber}, fields: "name,state,bucket,workflow,link,startedAt,completedAt"},
	{name: "repo_view", desc: "Show a GitHub repository.", readOnly: true, required: []string{"repo"},
		props: []ghProp{ghPropRepo}, fields: "nameWithOwner,description,url,visibility,isArchived,defaultBranchRef,homepageUrl,primaryLanguage,stargazerCount,forkCount,pushedAt,updatedAt"},
	{name: "issue_create", desc: "Create an issue in a GitHub repository.", required: []string{"repo", "title"},
		props: []ghProp{ghPropRepo, {name: "title", kind: ghTitle, desc: "The issue title."}, ghPropBody, {name: "label", kind: ghArray, desc: "Labels to add."}, {name: "assignee", kind: ghArray, desc: "Logins to assign."}}},
	{name: "issue_comment", desc: "Add a comment to an issue.", required: []string{"repo", "number", "body"},
		props: []ghProp{ghPropRepo, ghPropNumber, ghPropBody}},
	{name: "pr_comment", desc: "Add a comment to a pull request.", required: []string{"repo", "number", "body"},
		props: []ghProp{ghPropRepo, ghPropNumber, ghPropBody}},
}

func ghOperation(name string) (ghOp, bool) {
	for _, op := range ghOperations {
		if op.name == name {
			return op, true
		}
	}
	return ghOp{}, false
}

func (p ghProp) schema() map[string]any {
	s := map[string]any{"description": p.desc}
	switch p.kind {
	case ghRepo:
		s["type"], s["pattern"] = "string", ghRepoPattern.String()
	case ghNumber:
		s["type"], s["minimum"], s["maximum"] = "integer", 1, math.MaxInt32
	case ghEnum:
		s["type"], s["enum"], s["default"] = "string", p.enum, "open"
	case ghLimit:
		s["type"], s["minimum"], s["maximum"], s["default"] = "integer", 1, 100, 30
	case ghArray:
		s["type"], s["items"], s["maxItems"] = "array", map[string]any{"type": "string", "minLength": 1, "maxLength": 256}, 10
	case ghString, ghTitle:
		s["type"], s["minLength"], s["maxLength"] = "string", 1, 256
	case ghBool:
		s["type"] = "boolean"
		if p.boolDefault {
			s["default"] = false
		}
	case ghBody:
		s["type"], s["maxLength"] = "string", 65536
	}
	return s
}

// ghToolList is the tools/list result entries.
func ghToolList() []map[string]any {
	out := make([]map[string]any, 0, len(ghOperations))
	for _, op := range ghOperations {
		props := map[string]any{}
		for _, p := range op.props {
			props[p.name] = p.schema()
		}
		annotations := map[string]any{"readOnlyHint": true}
		if !op.readOnly {
			annotations = map[string]any{"readOnlyHint": false, "destructiveHint": false, "idempotentHint": false}
		}
		out = append(out, map[string]any{
			"name":        op.name,
			"description": op.desc,
			"inputSchema": map[string]any{"type": "object", "properties": props, "required": op.required, "additionalProperties": false},
			"annotations": annotations,
		})
	}
	return out
}

// ghShortString checks a string other than body: 1 to 256 bytes, without
// control characters.
func ghShortString(s string) bool {
	return s != "" && len(s) <= 256 && utf8.ValidString(s) && !hasControl(s)
}

// ghWhole reads a JSON number with a whole value.
func ghWhole(raw json.RawMessage) (int64, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var n any
	if dec.Decode(&n) != nil {
		return 0, false
	}
	num, ok := n.(json.Number)
	if !ok {
		return 0, false
	}
	if i, err := num.Int64(); err == nil {
		return i, true
	}
	f, err := num.Float64()
	if err != nil || math.IsInf(f, 0) || f != math.Trunc(f) || math.Abs(f) > 1<<53 {
		return 0, false
	}
	return int64(f), true
}

// ghArgs are validated arguments.
type ghArgs struct {
	strs   map[string]string
	ints   map[string]int64
	bools  map[string]bool
	arrays map[string][]string
}

// validateGH checks a call's arguments against the operation's schema.
func validateGH(op ghOp, raw json.RawMessage) (ghArgs, error) {
	args := ghArgs{strs: map[string]string{}, ints: map[string]int64{}, bools: map[string]bool{}, arrays: map[string][]string{}}
	fields := map[string]json.RawMessage{}
	if len(bytes.TrimSpace(raw)) > 0 && string(bytes.TrimSpace(raw)) != "null" {
		if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
			return args, errors.New("the arguments are not an object")
		}
	}
	props := map[string]ghProp{}
	for _, p := range op.props {
		props[p.name] = p
	}
	for _, name := range sortedKeys(fields) {
		if _, ok := props[name]; !ok {
			return args, fmt.Errorf("unknown argument %s", name)
		}
	}
	for _, name := range op.required {
		if _, ok := fields[name]; !ok {
			return args, fmt.Errorf("%s is required", name)
		}
	}
	for _, p := range op.props {
		value, ok := fields[p.name]
		if !ok {
			continue
		}
		switch p.kind {
		case ghNumber, ghLimit:
			n, ok := ghWhole(value)
			max := int64(math.MaxInt32)
			if p.kind == ghLimit {
				max = 100
			}
			if !ok || n < 1 || n > max {
				return args, fmt.Errorf("%s is an integer from 1 to %d", p.name, max)
			}
			args.ints[p.name] = n
		case ghBool:
			var b bool
			if json.Unmarshal(value, &b) != nil || (string(bytes.TrimSpace(value)) != "true" && string(bytes.TrimSpace(value)) != "false") {
				return args, fmt.Errorf("%s is a boolean", p.name)
			}
			args.bools[p.name] = b
		case ghArray:
			var list []json.RawMessage
			if json.Unmarshal(value, &list) != nil || list == nil || len(list) > 10 {
				return args, fmt.Errorf("%s is a list of at most 10 strings", p.name)
			}
			items := []string{}
			for _, item := range list {
				s, isString := jsonString(item)
				if !isString || !ghShortString(s) {
					return args, fmt.Errorf("each %s is 1 to 256 bytes without control characters", p.name)
				}
				items = append(items, s)
			}
			args.arrays[p.name] = items
		default:
			s, isString := jsonString(value)
			if !isString {
				return args, fmt.Errorf("%s is a string", p.name)
			}
			switch p.kind {
			case ghBody:
				if len(s) > 65536 || strings.ContainsRune(s, 0) {
					return args, fmt.Errorf("body is at most 65536 bytes")
				}
			case ghRepo:
				if !ghShortString(s) || !validGHRepo(s) {
					return args, fmt.Errorf("repo is OWNER/REPO")
				}
			case ghEnum:
				if !ghShortString(s) || !containsString(p.enum, s) {
					return args, fmt.Errorf("state is one of %s", strings.Join(p.enum, ", "))
				}
			default:
				if !ghShortString(s) {
					return args, fmt.Errorf("%s is 1 to 256 bytes without control characters", p.name)
				}
			}
			args.strs[p.name] = s
		}
	}
	return args, nil
}

func containsString(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

// ghArgv builds gh's argument vector for a validated call, and its
// standard input.
func ghArgv(op ghOp, a ghArgs) ([]string, *string) {
	repo := "--repo=" + a.strs["repo"]
	num := strconv.FormatInt(a.ints["number"], 10)
	opt := func(argv []string, name, flag string) []string {
		if v, ok := a.strs[name]; ok {
			argv = append(argv, "--"+flag+"="+v)
		}
		return argv
	}
	each := func(argv []string, name, flag string) []string {
		for _, v := range a.arrays[name] {
			argv = append(argv, "--"+flag+"="+v)
		}
		return argv
	}
	state := a.strs["state"]
	if state == "" {
		state = "open"
	}
	limit := int64(30)
	if n, ok := a.ints["limit"]; ok {
		limit = n
	}
	body := a.strs["body"]
	var argv []string
	switch op.name {
	case "issue_list":
		argv = []string{"issue", "list", repo, "--state=" + state, "--limit=" + strconv.FormatInt(limit, 10)}
		argv = each(argv, "label", "label")
		argv = opt(argv, "assignee", "assignee")
		argv = opt(argv, "author", "author")
		argv = opt(argv, "milestone", "milestone")
		argv = append(argv, "--json="+op.fields)
	case "issue_view":
		argv = []string{"issue", "view", num, repo}
		fields := op.fields
		if a.bools["comments"] {
			argv, fields = append(argv, "--comments"), fields+",comments"
		}
		argv = append(argv, "--json="+fields)
	case "pr_list":
		argv = []string{"pr", "list", repo, "--state=" + state, "--limit=" + strconv.FormatInt(limit, 10)}
		argv = opt(argv, "base", "base")
		argv = opt(argv, "head", "head")
		argv = each(argv, "label", "label")
		argv = opt(argv, "author", "author")
		if a.bools["draft"] {
			argv = append(argv, "--draft")
		}
		argv = append(argv, "--json="+op.fields)
	case "pr_view":
		argv = []string{"pr", "view", num, repo}
		fields := op.fields
		if a.bools["comments"] {
			argv, fields = append(argv, "--comments"), fields+",comments,reviews"
		}
		argv = append(argv, "--json="+fields)
	case "pr_diff":
		argv = []string{"pr", "diff", num, repo, "--color=never"}
		if a.bools["name_only"] {
			argv = append(argv, "--name-only")
		}
	case "pr_checks":
		argv = []string{"pr", "checks", num, repo, "--json=" + op.fields}
	case "repo_view":
		argv = []string{"repo", "view", a.strs["repo"], "--json=" + op.fields}
	case "issue_create":
		argv = []string{"issue", "create", repo, "--title=" + a.strs["title"], "--body-file=-"}
		argv = each(argv, "label", "label")
		argv = each(argv, "assignee", "assignee")
		return argv, &body
	case "issue_comment":
		return []string{"issue", "comment", num, repo, "--body-file=-"}, &body
	case "pr_comment":
		return []string{"pr", "comment", num, repo, "--body-file=-"}, &body
	}
	return argv, nil
}

// ghDirs are STATE/builtin/gh/work and STATE/builtin/gh/config, created
// private when missing.
func ghDirs(state string) (string, string) {
	base := filepath.Join(state, "builtin", "gh")
	work, config := filepath.Join(base, "work"), filepath.Join(base, "config")
	for _, dir := range []string{filepath.Join(state, "builtin"), base, work, config} {
		_ = os.MkdirAll(dir, 0o700)
		_ = os.Chmod(dir, 0o700)
	}
	return work, config
}

// ghEnv is the gh process environment, exactly: PATH, HOME, and a
// non-empty GH_TOKEN from the instance's environment, and the fixed
// variables.
func ghEnv(instance []string, config string) []string {
	var out []string
	values := map[string]string{}
	for _, kv := range instance {
		if name, value, ok := strings.Cut(kv, "="); ok {
			values[name] = value
		}
	}
	for _, name := range []string{"PATH", "HOME"} {
		if v, ok := values[name]; ok {
			out = append(out, name+"="+v)
		}
	}
	if v := values["GH_TOKEN"]; v != "" {
		out = append(out, "GH_TOKEN="+v)
	}
	return append(out, "GH_HOST="+ghHost, "GH_CONFIG_DIR="+config, "GH_PROMPT_DISABLED=1", "GH_NO_UPDATE_NOTIFIER=1",
		"GH_NO_EXTENSION_UPDATE_NOTIFIER=1", "GH_SPINNER_DISABLED=1", "NO_COLOR=1", "GH_PAGER=cat", "GH_TELEMETRY=0")
}

// ghRun is the outcome of one gh process.
type ghRun struct {
	stdout    []byte
	stderr    []byte // the last 64 KiB
	exitCode  int
	notStart  bool
	overLimit bool
	timedOut  bool
	cancelled bool
}

// tailBuffer keeps the last n bytes written.
type tailBuffer struct {
	n   int
	buf []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.n {
		t.buf = append([]byte{}, t.buf[len(t.buf)-t.n:]...)
	}
	return len(p), nil
}

// runGH runs gh directly, never through a shell, in its own process
// group, with standard input, the stdout limit, the stderr tail, a timeout,
// and cancellation by ctx. Killing sends SIGTERM to the group, then SIGKILL
// 2 seconds later if it is still running.
func runGH(ctx context.Context, command string, argv []string, env []string, dir string, stdin *string, timeout time.Duration) ghRun {
	var run ghRun
	cmd := exec.Command(command, argv...)
	cmd.Env, cmd.Dir = env, dir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stderr := &tailBuffer{n: ghStderrKeep}
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		run.notStart = true
		return run
	}
	in, err := cmd.StdinPipe()
	if err != nil {
		run.notStart = true
		return run
	}
	if err = cmd.Start(); err != nil {
		run.notStart = true
		return run
	}
	go func() {
		if stdin != nil {
			_, _ = io.WriteString(in, *stdin)
		}
		_ = in.Close()
	}()
	over := make(chan struct{})
	result := make(chan []byte, 1)
	go func() {
		var buf bytes.Buffer
		exceeded := false
		chunk := make([]byte, 32<<10)
		for {
			n, err := stdout.Read(chunk)
			if n > 0 && !exceeded {
				if buf.Len()+n > ghStdoutLimit {
					exceeded = true
					close(over)
				} else {
					buf.Write(chunk[:n])
				}
			}
			if err != nil {
				break
			}
		}
		// Reading has finished, so the process can be waited for.
		_ = cmd.Wait()
		result <- buf.Bytes()
	}()
	pid := cmd.Process.Pid
	finished := make(chan struct{})
	defer close(finished)
	kill := func() {
		_ = syscall.Kill(-pid, syscall.SIGTERM)
		go func() {
			select {
			case <-finished:
			case <-time.After(ghKillGrace):
				_ = syscall.Kill(-pid, syscall.SIGKILL)
			}
		}()
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	killing := func() bool { return run.overLimit || run.timedOut || run.cancelled }
	cancelled := ctx.Done()
	for {
		select {
		case <-over:
			over = nil
			if !killing() {
				run.overLimit = true
				kill()
			}
		case <-timer.C:
			if !killing() {
				run.timedOut = true
				kill()
			}
		case <-cancelled:
			cancelled = nil
			if !killing() {
				run.cancelled = true
				kill()
			}
		case out := <-result:
			// A process gone, its group may still hold children: stop them.
			_ = syscall.Kill(-pid, syscall.SIGKILL)
			run.stdout, run.stderr = out, stderr.buf
			run.exitCode = cmd.ProcessState.ExitCode()
			return run
		}
	}
}

// ghSpace is the whitespace the gh adapter trims: space, tab, LF, and CR.
const ghSpace = " \t\n\r"

// lossyUTF8 replaces each byte that is not part of valid UTF-8 with U+FFFD.
func lossyUTF8(b []byte) string {
	var out strings.Builder
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r == utf8.RuneError && size == 1 {
			out.WriteRune(utf8.RuneError)
		} else {
			out.Write(b[:size])
		}
		b = b[size:]
	}
	return out.String()
}

// ghStderrText is the last 2,048 bytes of standard error, started at a
// character boundary, with trailing whitespace removed.
func ghStderrText(stderr []byte) string {
	if len(stderr) > ghStderrShown {
		stderr = stderr[len(stderr)-ghStderrShown:]
	}
	for len(stderr) > 0 && stderr[0]&0xC0 == 0x80 {
		stderr = stderr[1:]
	}
	return strings.TrimRight(lossyUTF8(stderr), ghSpace)
}

// ghOutcome is how one gh call answers: a tool result, or a JSON-RPC error.
type ghOutcome struct {
	text    string
	isError bool
	rpc     *rpcError
	// silent marks a cancelled call, which gets no response.
	silent bool
	// exit is the log's exit field.
	exit string
}

func ghFailure(text, exit string) ghOutcome { return ghOutcome{text: text, isError: true, exit: exit} }

// ghResult maps a finished gh process to the call's answer.
func ghResult(op ghOp, a ghArgs, run ghRun) ghOutcome {
	exit := strconv.Itoa(run.exitCode)
	switch {
	case run.notStart:
		return ghFailure("gh could not be started.", "not_started")
	case run.overLimit:
		return ghOutcome{rpc: &rpcError{Code: ghTooLargeCode, Message: ghTooLargeError}, exit: "over_limit"}
	case run.timedOut:
		return ghFailure(fmt.Sprintf("gh did not finish within %d seconds.", int(ghCallTimeout/time.Second)), "timeout")
	case run.cancelled:
		return ghOutcome{silent: true, exit: "cancelled"}
	case run.exitCode == 4:
		return ghOutcome{rpc: &rpcError{Code: ghAuthCode, Message: ghAuthMessage}, exit: exit}
	}
	out := bytes.Trim(run.stdout, ghSpace)
	if op.name == "pr_checks" && (run.exitCode == 0 || run.exitCode == 1 || run.exitCode == 8) && jsonKind(out, '[') {
		return ghOutcome{text: `{"checks":` + string(out) + `}`, exit: exit}
	}
	if run.exitCode != 0 {
		if text := ghStderrText(run.stderr); text != "" {
			return ghFailure("gh failed: "+text, exit)
		}
		return ghFailure(fmt.Sprintf("gh failed with exit status %d.", run.exitCode), exit)
	}
	unreadable := ghFailure("gh returned output Peerspan could not read.", exit)
	wrap := func(key string, kind byte) ghOutcome {
		if !jsonKind(out, kind) {
			return unreadable
		}
		return ghOutcome{text: `{"` + key + `":` + string(out) + `}`, exit: exit}
	}
	switch op.name {
	case "issue_list":
		return wrap("issues", '[')
	case "pr_list":
		return wrap("pull_requests", '[')
	case "pr_checks":
		return wrap("checks", '[')
	case "issue_view":
		return wrap("issue", '{')
	case "pr_view":
		return wrap("pull_request", '{')
	case "repo_view":
		return wrap("repository", '{')
	case "pr_diff":
		if a.bools["name_only"] {
			files := []string{}
			for _, line := range strings.Split(lossyUTF8(run.stdout), "\n") {
				if line = strings.TrimSuffix(line, "\r"); line != "" {
					files = append(files, resultTextString(line))
				}
			}
			return ghOutcome{text: `{"files":[` + strings.Join(files, ",") + `]}`, exit: exit}
		}
		return ghOutcome{text: `{"diff":` + resultTextString(lossyUTF8(run.stdout)) + `}`, exit: exit}
	}
	// The writes print the new item's URL.
	url := ""
	for _, line := range strings.Split(lossyUTF8(run.stdout), "\n") {
		if line = strings.Trim(line, ghSpace); strings.HasPrefix(line, "https://") {
			url = line
		}
	}
	if url == "" {
		return unreadable
	}
	if op.name != "issue_create" {
		return ghOutcome{text: `{"url":` + resultTextString(url) + `}`, exit: exit}
	}
	path, _, _ := strings.Cut(url, "#")
	segment := path[strings.LastIndex(path, "/")+1:]
	n, err := strconv.ParseInt(segment, 10, 64)
	if err != nil || segment == "" || strings.ContainsAny(segment, "+-") {
		return unreadable
	}
	return ghOutcome{text: `{"number":` + strconv.FormatInt(n, 10) + `,"url":` + resultTextString(url) + `}`, exit: exit}
}

// jsonKind reports whether b is valid JSON starting with kind ([ or {).
func jsonKind(b []byte, kind byte) bool {
	return len(b) > 0 && b[0] == kind && json.Valid(b)
}
