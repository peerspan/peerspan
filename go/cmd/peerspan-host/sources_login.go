package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/spf13/pflag"
)

// Signing in to remote MCP servers (capabilities slice 3, item A): the CLI
// starts a sign-in at the daemon, has the person approve in a browser, and
// hands the redirect URL back. The PKCE verifier and the tokens stay in the
// daemon.

// loginOptions are the flags of sources login and capability login.
type loginOptions struct {
	scopes, clientID, secretFile, account string
	port                                  int
	noBrowser                             bool
	command                               string
}

func readLoginOptions(fs *pflag.FlagSet, command string) loginOptions {
	o := loginOptions{command: command}
	if fs.Lookup("scopes") == nil {
		return o
	}
	o.scopes, _ = fs.GetString("scopes")
	o.clientID, _ = fs.GetString("client-id")
	o.secretFile, _ = fs.GetString("client-secret-file")
	o.account, _ = fs.GetString("account")
	o.port, _ = fs.GetInt("port")
	o.noBrowser, _ = fs.GetBool("no-browser")
	return o
}

// loginSourceArg resolves SOURCE for sources login and logout.
func loginSourceArg(ctx context.Context, client host.Client, given string) (string, string, error) {
	listing, err := readSources(ctx, client, "/v1/sources")
	if err != nil {
		return "", "", err
	}
	agent, server, qualified := strings.Cut(given, "/")
	if !qualified {
		agent, server = "", given
	}
	var matches []string
	for _, a := range listing.Agents {
		if (agent == "" || a.Agent.Name == agent || a.Agent.ID == agent) && a.server(server) != nil {
			matches = append(matches, a.Agent.Name)
		}
	}
	switch len(matches) {
	case 0:
		return "", "", fmt.Errorf("No source %s on this host. Run peerspan sources.", given)
	case 1:
		return matches[0], server, nil
	}
	var names []string
	for _, m := range matches {
		names = append(names, m+"/"+server)
	}
	return "", "", fmt.Errorf("several agents have %s: %s; give AGENT/SERVER", server, strings.Join(names, ", "))
}

// capabilitySourceOf reads a capability's source for capability login and
// logout.
func capabilitySourceOf(ctx context.Context, client host.Client, name string) (string, string, capabilityRecord, error) {
	var c capabilityRecord
	data, err := client.Call(ctx, "GET", "/v1/capabilities/"+url.PathEscape(name), nil)
	var failure *host.ClientError
	if errors.As(err, &failure) && failure.Status == http.StatusNotFound {
		return "", "", c, fmt.Errorf("No capability %s on this host. Run peerspan capability list.", name)
	}
	if err != nil {
		return "", "", c, err
	}
	if err = json.Unmarshal(data, &c); err != nil {
		return "", "", c, err
	}
	return c.Source.Agent, c.Source.Server, c, nil
}

// printMode reports whether the link is printed rather than opened.
func printMode(noBrowser bool) bool {
	return noBrowser || os.Getenv("SSH_CONNECTION") != "" || (runtime.GOOS == "linux" && os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "")
}

func openBrowser(link string) bool {
	command := "xdg-open"
	if runtime.GOOS == "darwin" {
		command = "open"
	}
	cmd := exec.Command(command, link)
	if cmd.Start() != nil {
		return false
	}
	// The opener normally hands the link to a browser and exits; the link is
	// printed once it has, or after 5 seconds.
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
	}
	return true
}

// issuerHost is the issuer's host, lowercased, without port.
func issuerHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	h := strings.ToLower(u.Hostname())
	if strings.Contains(h, ":") {
		return "[" + h + "]"
	}
	return h
}

// callback is a redirect received by the listener, waiting for the
// daemon's answer.
type callback struct {
	url   string
	reply chan error
}

// signIn runs a sign-in: it starts it at the daemon, shows the link, waits
// for the redirect at the loopback listener or a pasted address, and
// completes it.
func signIn(ctx context.Context, client host.Client, agent, server string, capability *string, o loginOptions, out, errOut io.Writer) error {
	if !o.noBrowser && !isTerminal(os.Stdin) {
		return fmt.Errorf("%s needs a terminal, or --no-browser to print the link and read the pasted address from stdin.", o.command)
	}
	body := map[string]any{}
	if capability != nil {
		body["capability"] = *capability
	}
	if o.scopes != "" {
		body["scopes"] = o.scopes
	}
	if o.secretFile != "" && o.clientID == "" {
		return errors.New("--client-secret-file needs --client-id.")
	}
	if o.clientID != "" {
		body["client_id"] = o.clientID
	}
	if o.secretFile != "" {
		info, err := os.Stat(o.secretFile)
		if err != nil {
			return err
		}
		if info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("%s must have mode 0600 or stricter.", o.secretFile)
		}
		data, err := os.ReadFile(o.secretFile)
		if err != nil {
			return err
		}
		body["client_secret"] = strings.TrimRight(string(data), " \t\r\n")
	}
	if o.port != 0 {
		body["redirect_port"] = o.port
	}
	if o.account != "" {
		body["account"] = o.account
	}
	data, err := client.Call(ctx, "POST", "/v1/sources/"+url.PathEscape(agent)+"/"+url.PathEscape(server)+"/login", body)
	if err != nil {
		return err
	}
	var started host.LoginStarted
	if err = json.Unmarshal(data, &started); err != nil {
		return err
	}
	source := agent + "/" + server
	expired := fmt.Errorf("This sign-in link is no longer valid. Run peerspan sources login %s again.", source)
	redirect, err := url.Parse(started.RedirectURI)
	if err != nil {
		return err
	}
	port := redirect.Port()
	callbacks := make(chan callback)
	listener, listenErr := net.Listen("tcp", "127.0.0.1:"+port)
	if listenErr != nil {
		fmt.Fprintf(errOut, "Port %s on 127.0.0.1 is in use, so Peerspan cannot receive the redirect; paste the address instead.\n", port)
	} else {
		server := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/callback" {
				http.NotFound(w, r)
				return
			}
			cb := callback{url: "http://127.0.0.1:" + port + r.URL.RequestURI(), reply: make(chan error, 1)}
			select {
			case callbacks <- cb:
			case <-r.Context().Done():
				return
			}
			result := <-cb.reply
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if result != nil {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "<!doctype html><title>Peerspan</title><p>Peerspan sign-in failed. %s See the terminal.</p>\n", html.EscapeString(result.Error()))
				return
			}
			fmt.Fprint(w, "<!doctype html><title>Peerspan</title><p>Peerspan sign-in complete. You can close this tab.</p>\n")
		})}
		go func() { _ = server.Serve(listener) }()
		defer func() {
			shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdown)
		}()
	}
	first := "Open this link in a browser on any machine and approve Peerspan:"
	if !printMode(o.noBrowser) && openBrowser(started.AuthorizationURL) {
		first = "Opening your browser to approve Peerspan. If it does not open, use this link:"
	}
	fmt.Fprintf(errOut, "%s\n  %s\nIf the browser then shows a page that cannot be reached, copy the full address\nfrom its address bar and paste it here:\n", first, started.AuthorizationURL)
	lines := lineSource()
	deadline, err := time.Parse(time.RFC3339Nano, started.ExpiresAt)
	if err != nil {
		deadline = time.Now().Add(10 * time.Minute)
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	var address string
	var reply chan error
	for address == "" {
		select {
		case cb := <-callbacks:
			address, reply = cb.url, cb.reply
		case line, ok := <-lines:
			if trimmed := strings.TrimSpace(line.text); trimmed != "" {
				address = trimmed
			} else if !ok || line.err != nil {
				lines = nil
				if listenErr != nil {
					return errors.New("The sign-in was not completed.")
				}
			}
		case <-timer.C:
			return expired
		}
	}
	result, err := client.Call(ctx, "POST", "/v1/oauth/logins/"+url.PathEscape(started.LoginID)+"/complete", map[string]string{"callback_url": address})
	if reply != nil {
		var failure *host.ClientError
		if errors.As(err, &failure) {
			reply <- errors.New(failure.Message)
		} else {
			reply <- err
		}
	}
	if err != nil {
		return err
	}
	var done host.LoginResult
	if err = json.Unmarshal(result, &done); err != nil {
		return err
	}
	if err = printJSON(out, result); err != nil {
		return err
	}
	scope := "none"
	if done.Scopes != nil {
		scope = *done.Scopes
	}
	fmt.Fprintf(errOut, "Signed in to %s for %s (scopes: %s).\n", issuerHost(done.Issuer), done.Source, scope)
	return nil
}

// runLogin runs sources login and capability login.
func runLogin(ctx context.Context, client host.Client, kind, given string, fs *pflag.FlagSet, out, errOut io.Writer) error {
	o := readLoginOptions(fs, kind+" login")
	if kind == "capability" {
		agent, server, _, err := capabilitySourceOf(ctx, client, given)
		if err != nil {
			return err
		}
		return signIn(ctx, client, agent, server, &given, o, out, errOut)
	}
	agent, server, err := loginSourceArg(ctx, client, given)
	if err != nil {
		return err
	}
	return signIn(ctx, client, agent, server, nil, o, out, errOut)
}

// runLogout runs sources logout and capability logout.
func runLogout(ctx context.Context, client host.Client, kind, given string, fs *pflag.FlagSet, out, errOut io.Writer) error {
	var agent, server string
	var capability *string
	var err error
	issuer := ""
	if kind == "capability" {
		var c capabilityRecord
		if agent, server, c, err = capabilitySourceOf(ctx, client, given); err != nil {
			return err
		}
		capability = &given
		if c.Auth != nil && c.Auth.Issuer != nil {
			issuer = *c.Auth.Issuer
		}
	} else {
		if agent, server, err = loginSourceArg(ctx, client, given); err != nil {
			return err
		}
		if listing, err := readSources(ctx, client, "/v1/sources"); err == nil {
			for _, a := range listing.Agents {
				if srv := a.server(server); a.Agent.Name == agent && srv != nil && srv.Auth != nil && srv.Auth.Issuer != nil {
					issuer = *srv.Auth.Issuer
				}
			}
		}
		// Capabilities on the source's sign-in fail until the next one.
		data, err := client.Call(ctx, "GET", "/v1/capabilities", nil)
		if err != nil {
			return err
		}
		var list struct {
			Capabilities []capabilityRecord `json:"capabilities"`
		}
		if err = json.Unmarshal(data, &list); err != nil {
			return err
		}
		var using []string
		for _, c := range list.Capabilities {
			if c.Source.Agent == agent && c.Source.Server == server && (c.Auth == nil || c.Auth.Own == nil || !*c.Auth.Own) {
				using = append(using, c.Name)
			}
		}
		if len(using) > 0 {
			yes, _ := fs.GetBool("yes")
			for _, name := range using {
				fmt.Fprintln(errOut, name)
			}
			switch {
			case yes:
			case isTerminal(os.Stdin):
				if !askYes(errOut, "Sign out? Calls to these capabilities will fail until the next sign-in.") {
					fmt.Fprintln(errOut, "Not signed out.")
					return exitStatus(1)
				}
			default:
				return errors.New("confirm this sign-out at a terminal, or pass --yes")
			}
		}
	}
	body := map[string]any{}
	if capability != nil {
		body["capability"] = *capability
	}
	data, err := client.Call(ctx, "POST", "/v1/sources/"+url.PathEscape(agent)+"/"+url.PathEscape(server)+"/logout", body)
	if err != nil {
		return err
	}
	var result host.Logout
	if err = json.Unmarshal(data, &result); err != nil {
		return err
	}
	if err = printJSON(out, data); err != nil {
		return err
	}
	switch {
	case !result.Deleted && capability != nil:
		fmt.Fprintf(errOut, "%s has no sign-in of its own on this host.\n", *capability)
	case !result.Deleted:
		fmt.Fprintf(errOut, "%s has no sign-in on this host.\n", result.Source)
	case !result.Revoked:
		fmt.Fprintf(errOut, "%s has no revocation endpoint Peerspan could use. To revoke access there, remove %s from the connected apps of your account.\n", issuer, strconv.Quote(clientLabel()))
	}
	return nil
}

// clientLabel is the client name Peerspan registers with.
func clientLabel() string {
	if label := host.HostLabel(); label != "" {
		return "Peerspan (" + label + ")"
	}
	return "Peerspan"
}

// credentialText is the review's Credential line, without its prefix, for
// a capability on a remote source; empty for other sources. auth is the
// capability's, or for a new capability the source's.
func credentialText(c capabilityRecord, server sourceServer, auth *host.AuthView) string {
	if server.Transport != "remote" {
		return ""
	}
	source := c.Source.Agent + "/" + c.Source.Server
	own := auth != nil && auth.Own != nil && *auth.Own
	if auth == nil || auth.Mode == nil {
		return "unknown; Peerspan has not reached " + source + " yet."
	}
	switch *auth.Mode {
	case "none":
		return "none. " + source + " (" + issuerHost(deref(server.URL)) + ") asks for no sign-in, so it serves anyone who can reach it. Sharing it lets the people you share with use the selected operations through this host, including when the server is only reachable from here (a local, home, VPN, or company network)."
	case "headers":
		names := make([]string, 0, len(server.Headers))
		for name := range server.Headers {
			names = append(names, name)
		}
		sort.Strings(names)
		text := "the token in the " + strings.Join(names, ", ") + " header of " + source + " (from " + server.Source + ")."
		if len(names) > 1 {
			text = "the tokens in the " + strings.Join(names, ", ") + " headers of " + source + " (from " + server.Source + ")."
		}
		if c.Credential.EnvFile != nil {
			text += " Values from the capability's environment file " + *c.Credential.EnvFile + " override the variables those headers reference."
		}
		return text
	}
	if auth.State != nil && (*auth.State == "ok" || *auth.State == "refresh_failed") && auth.Issuer != nil {
		scope := "none"
		if auth.Scope != nil {
			scope = *auth.Scope
		}
		account := "account not labelled; Peerspan cannot see which account approved"
		if auth.Account != nil {
			account = "account " + *auth.Account
		}
		date := deref(auth.ObtainedAt)
		if len(date) >= 10 {
			date = date[:10]
		}
		who := "Peerspan's own sign-in"
		if own {
			who = "this capability's own sign-in"
		}
		return who + " to " + issuerHost(*auth.Issuer) + ", scopes " + scope + ", " + account + ", signed in on " + date + "."
	}
	if own {
		return "the sign-in to " + source + " has lapsed; run peerspan capability login " + c.Name
	}
	return "the sign-in to " + source + " has lapsed; run peerspan sources login " + source
}

// authLine is the sources text's auth line for a remote source.
func authLine(source string, s sourceServer) string {
	switch {
	case s.Auth == nil || s.Auth.Mode == nil:
		return "auth: not reached yet"
	case *s.Auth.Mode == "none":
		return "auth: none (the server asks for no sign-in)"
	case *s.Auth.Mode == "headers":
		names := make([]string, 0, len(s.Headers))
		for name := range s.Headers {
			names = append(names, name)
		}
		sort.Strings(names)
		return "auth: headers " + strings.Join(names, ", ")
	}
	if s.Auth.State != nil && (*s.Auth.State == "ok" || *s.Auth.State == "refresh_failed") && s.Auth.Issuer != nil {
		scope, account := "none", "not labelled"
		if s.Auth.Scope != nil {
			scope = *s.Auth.Scope
		}
		if s.Auth.Account != nil {
			account = *s.Auth.Account
		}
		return "auth: signed in to " + issuerHost(*s.Auth.Issuer) + ", scopes " + scope + ", account " + account + ", " + *s.Auth.State
	}
	return "auth: needs a sign-in: peerspan sources login " + source
}
