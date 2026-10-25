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
	"regexp"
	"strings"

	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/spf13/pflag"
)

// Per-call approval on the owner's CLI: approvals, approvals show, approve,
// and deny ID, at the serving host's local administration socket.

// approvalIDPattern is a call ID or SENDER_HOST_ID/CALL_ID.
var approvalIDPattern = regexp.MustCompile(`^(host_[0-9a-f]{64}/)?call_[0-9a-f]{32}$`)

// isApprovalID reports whether deny's argument names an approval rather
// than a principal.
func isApprovalID(value string) bool { return approvalIDPattern.MatchString(value) }

const approveNeedsTerminal = "peerspan approve needs a terminal: approval must come from the person."

// approvalView is an approval as the CLI reads it.
type approvalView struct {
	SenderHostID  string `json:"sender_host_id"`
	CallID        string `json:"call_id"`
	State         string `json:"state"`
	Capability    string `json:"capability"`
	Operation     string `json:"operation"`
	ChangesThings bool   `json:"changes_things"`
	Caller        struct {
		PersonID    *string `json:"person_id"`
		PersonLabel *string `json:"person_label"`
		HostID      string  `json:"host_id"`
		Via         string  `json:"via"`
	} `json:"caller"`
	Origin *struct {
		AgentID   string `json:"agent_id"`
		SessionID string `json:"session_id"`
	} `json:"origin"`
	RequestedAt  string          `json:"requested_at"`
	ExpiresAt    string          `json:"expires_at"`
	DecidedAt    *string         `json:"decided_at"`
	Reason       *string         `json:"reason"`
	InputPreview *string         `json:"input_preview"`
	InputBytes   *int64          `json:"input_bytes"`
	Input        json.RawMessage `json:"input"`
}

// escapeUntrusted writes every character below U+0020 other than a line
// break, U+007F, and U+0080 to U+009F as \u and four lowercase hex digits,
// so no terminal escape sequence from a caller reaches the terminal.
func escapeUntrusted(value string, keepNewlines bool) string {
	var b strings.Builder
	for _, r := range value {
		if (r < 0x20 && !(keepNewlines && r == '\n')) || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			fmt.Fprintf(&b, `\u%04x`, r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func esc(value string) string { return escapeUntrusted(value, false) }

// callerText is the caller, by label and host, escaped.
func (a approvalView) callerText() string {
	text := esc(a.Caller.HostID)
	if a.Caller.PersonLabel != nil {
		text = esc(*a.Caller.PersonLabel) + " (" + text + ")"
	}
	if a.Origin != nil {
		text += ", agent " + esc(a.Origin.AgentID)
	}
	return text
}

// prettyInput is the input object indented, with numbers as sent, escaped
// for the terminal.
func prettyInput(input json.RawMessage) string {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return esc(string(input))
	}
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return esc(string(input))
	}
	return escapeUntrusted(strings.TrimRight(buf.String(), "\n"), true)
}

// printApprovalLine prints one approval of approvals.
func printApprovalLine(out io.Writer, a approvalView) {
	fmt.Fprintf(out, "%s/%s  %s  %s (%s)  from %s  until %s", esc(a.SenderHostID), esc(a.CallID), a.State, esc(a.Capability), esc(a.Operation), a.callerText(), esc(a.ExpiresAt))
	if a.InputPreview != nil {
		fmt.Fprintf(out, "  input: %s", esc(*a.InputPreview))
	}
	fmt.Fprintln(out)
}

// printApproval prints what approvals show prints: the approval, the
// capability's source and credential context when it still exists, and
// the whole input.
func printApproval(ctx context.Context, client host.Client, out io.Writer, a approvalView) {
	fmt.Fprintf(out, "Call: %s/%s\n", esc(a.SenderHostID), esc(a.CallID))
	fmt.Fprintf(out, "State: %s\n", a.State)
	kind := "read-only"
	if a.ChangesThings {
		kind = "can change things"
	}
	fmt.Fprintf(out, "Capability: %s, operation %s (%s)\n", esc(a.Capability), esc(a.Operation), kind)
	from := esc(a.Caller.HostID)
	if a.Caller.PersonID != nil {
		from = esc(*a.Caller.PersonID) + " on host " + from
		if a.Caller.PersonLabel != nil {
			from = esc(*a.Caller.PersonLabel) + " (" + from + ")"
		}
	}
	fmt.Fprintf(out, "Caller: from %s, through %s\n", from, esc(a.Caller.Via))
	if a.Origin != nil {
		fmt.Fprintf(out, "Agent: %s", esc(a.Origin.AgentID))
		if a.Origin.SessionID != "" {
			fmt.Fprintf(out, ", session %s", esc(a.Origin.SessionID))
		}
		fmt.Fprintln(out)
	}
	fmt.Fprintf(out, "Requested: %s\nWaits until: %s\n", esc(a.RequestedAt), esc(a.ExpiresAt))
	if a.DecidedAt != nil {
		fmt.Fprintf(out, "Decided: %s\n", esc(*a.DecidedAt))
	}
	if a.Reason != nil {
		fmt.Fprintf(out, "Reason: %s\n", esc(*a.Reason))
	}
	if c, err := call[capabilityRecord](ctx, client, "GET", "/v1/capabilities/"+url.PathEscape(a.Capability)); err == nil {
		fmt.Fprintf(out, "Source: %s/%s\n", c.Source.Agent, c.Source.Server)
		if c.Credential.EnvFile != nil || c.Credential.Args != nil {
			fmt.Fprintf(out, "Credentials: the capability's own environment file %s", deref(c.Credential.EnvFile))
			if c.Credential.Args != nil {
				fmt.Fprintf(out, ", with arguments %s", strings.Join(c.Credential.Args, " "))
			}
			fmt.Fprintln(out)
		} else {
			fmt.Fprintln(out, "Credentials: the source's own environment on this host")
		}
	}
	if len(a.Input) == 0 || string(a.Input) == "null" {
		fmt.Fprintln(out, "Input: deleted")
		return
	}
	size := int64(0)
	if a.InputBytes != nil {
		size = *a.InputBytes
	}
	fmt.Fprintf(out, "Input (%d bytes):\n%s\n", size, prettyInput(a.Input))
}

// approvalPath resolves ID, a call ID or SENDER_HOST_ID/CALL_ID, to the
// approval's path; a bare call ID is resolved by the daemon. Anything else
// is refused before any request.
func approvalPath(ctx context.Context, client host.Client, id string) (string, error) {
	if !isApprovalID(id) {
		return "", fmt.Errorf("an approval ID is a call ID (call_ and 32 lowercase hex digits) or SENDER_HOST_ID/CALL_ID, not %q", id)
	}
	if sender, callID, ok := strings.Cut(id, "/"); ok {
		return "/v1/approvals/" + url.PathEscape(sender) + "/" + url.PathEscape(callID), nil
	}
	a, err := call[approvalView](ctx, client, "GET", "/v1/approvals/"+url.PathEscape(id))
	if err != nil {
		return "", err
	}
	return "/v1/approvals/" + url.PathEscape(a.SenderHostID) + "/" + url.PathEscape(a.CallID), nil
}

// runApprovals runs approvals and approvals show.
func runApprovals(ctx context.Context, client host.Client, args []string, fs *pflag.FlagSet, out io.Writer) error {
	asJSON, _ := fs.GetBool("json")
	if len(args) >= 2 && args[1] == "show" {
		path, err := approvalPath(ctx, client, args[2])
		if err != nil {
			return err
		}
		data, err := client.Call(ctx, "GET", path, nil)
		if err != nil {
			return err
		}
		if asJSON {
			return printJSON(out, json.RawMessage(data))
		}
		var a approvalView
		if err = json.Unmarshal(data, &a); err != nil {
			return err
		}
		printApproval(ctx, client, out, a)
		return nil
	}
	state := "pending"
	if all, _ := fs.GetBool("all"); all {
		state = "all"
	}
	data, err := client.Call(ctx, "GET", "/v1/approvals?state="+state, nil)
	if err != nil {
		return err
	}
	if asJSON {
		return printJSON(out, json.RawMessage(data))
	}
	var list struct {
		Approvals []approvalView `json:"approvals"`
	}
	if err = json.Unmarshal(data, &list); err != nil {
		return err
	}
	if len(list.Approvals) == 0 {
		fmt.Fprintln(out, "No calls are waiting for your approval.")
	}
	for _, a := range list.Approvals {
		printApprovalLine(out, a)
	}
	return nil
}

// runApprove approves one call at a terminal, after showing it and asking.
func runApprove(ctx context.Context, client host.Client, id string, out, errOut io.Writer) error {
	if !isTerminal(os.Stdin) {
		return errors.New(approveNeedsTerminal)
	}
	path, err := approvalPath(ctx, client, id)
	if err != nil {
		return err
	}
	a, err := call[approvalView](ctx, client, "GET", path)
	if err != nil {
		return err
	}
	printApproval(ctx, client, errOut, a)
	if a.State == "pending" && !askYes(errOut, "Approve this call? It runs once, with the credentials it runs with on this machine.") {
		fmt.Fprintln(errOut, "Not approved.")
		return exitStatus(1)
	}
	data, err := client.Call(ctx, "POST", path+"/approve", map[string]any{})
	if err != nil {
		return err
	}
	return printJSON(out, json.RawMessage(data))
}

// runDenyApproval denies one call at once, with an optional reason.
func runDenyApproval(ctx context.Context, client host.Client, id string, fs *pflag.FlagSet, out io.Writer) error {
	path, err := approvalPath(ctx, client, id)
	if err != nil {
		return err
	}
	body := map[string]any{"reason": nil}
	if fs.Changed("reason") {
		reason, _ := fs.GetString("reason")
		body["reason"] = reason
	}
	data, err := client.Call(ctx, "POST", path+"/deny", body)
	if err != nil {
		return err
	}
	return printJSON(out, json.RawMessage(data))
}
