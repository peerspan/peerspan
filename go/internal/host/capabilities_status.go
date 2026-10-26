package host

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

const capabilityAttentionWindow = 24 * time.Hour

// capabilitiesStatus counts sources, capabilities, shared capabilities,
// running calls, and the open list, and adds attention items 14,
// capability_failing, and 15, capability_name_conflict.
func (s *Store) capabilitiesStatus(ctx context.Context, tx *sql.Tx, now time.Time, attend func(kind, subject, detail, command string)) (CapabilitiesStatus, error) {
	var st CapabilitiesStatus
	rules, err := s.ownCapabilityRules(ctx, tx)
	if err != nil {
		return st, err
	}
	agents, err := agentsIn(ctx, tx)
	if err != nil {
		return st, err
	}
	recent := func(at *string) bool {
		if at == nil {
			return false
		}
		t, err := parseTime(*at)
		return err == nil && now.Sub(t) < capabilityAttentionWindow
	}
	causes := func(state toolSnapshotState) []string {
		var out []string
		if state.SnapshotError != nil {
			out = append(out, "its latest snapshot failed: "+*state.SnapshotError)
		}
		if recent(state.StartFailedAt) {
			out = append(out, "it failed to start at "+*state.StartFailedAt)
		}
		if recent(state.AuthErrorAt) {
			out = append(out, "it answered with an error that suggests authentication at "+*state.AuthErrorAt+"; a captured token may be stale, so refresh it")
		}
		return out
	}
	capabilities, err := records[capabilityRecord](ctx, tx, `SELECT record FROM capabilities ORDER BY name`)
	if err != nil {
		return st, err
	}
	// lapsed reports a credential that needs a new sign-in.
	lapsed := func(k credKey) (bool, bool, error) {
		cred, found, err := readCredential(ctx, tx, k)
		if err != nil || !found {
			return false, found, err
		}
		if cred.State == credLoginRequired {
			return true, true, nil
		}
		if cred.State == credRefreshFailed && cred.RefreshFailedAt != nil {
			if t, err := parseTime(*cred.RefreshFailedAt); err == nil && now.Sub(t) > time.Hour {
				return true, true, nil
			}
		}
		return false, true, nil
	}
	for _, a := range agents {
		servers, err := records[toolServerRecord](ctx, tx, `SELECT record FROM tool_servers WHERE agent_id = ? ORDER BY name`, a.id)
		if err != nil {
			return st, err
		}
		for _, srv := range servers {
			st.Sources++
			subject := a.name + "/" + srv.Name
			found := causes(srv.toolSnapshotState)
			command := "peerspan sources refresh --agent " + a.name
			if srv.Transport == "remote" {
				st.RemoteSources++
				using := 0
				for _, c := range capabilities {
					if c.AgentID == a.id && c.Source.Server == srv.Name && !c.OwnSignIn {
						using++
					}
				}
				gone, hasCred, err := lapsed(credKey{a.id, srv.Name, ""})
				if err != nil {
					return st, err
				}
				switch {
				case gone || (!hasCred && deref(srv.Reason) == reasonLogin && using > 0):
					found = append([]string{"its sign-in has lapsed or is missing, so calls fail"}, found...)
					command = "peerspan sources login " + subject
				case recent(srv.InsufficientScopeAt):
					found = append([]string{"the server refused a call for insufficient scope at " + *srv.InsufficientScopeAt}, found...)
					command = "peerspan sources login " + subject + " --scopes \"" + deref(srv.InsufficientScope) + "\""
				}
			}
			if len(found) > 0 {
				attend("capability_failing", subject, strings.Join(found, "; "), command)
			}
		}
	}
	builtin, err := sourceRecords(ctx, tx, builtinAgent)
	if err != nil {
		return st, err
	}
	for _, srv := range builtin {
		st.Sources++
		if found := causes(srv.toolSnapshotState); len(found) > 0 {
			attend("capability_failing", builtinAgent+"/"+srv.Name, strings.Join(found, "; "), "peerspan sources refresh --builtin")
		}
	}
	for _, c := range capabilities {
		st.Capabilities++
		shared, conflict := false, false
		for _, r := range rules {
			if r.Capability != c.Name {
				continue
			}
			if r.Host == s.identity.ID {
				// A claim, without principals, shares nothing.
				shared = shared || len(r.Principals) > 0
			} else {
				conflict = true
			}
		}
		if shared {
			st.Shared++
		}
		if conflict {
			attend("capability_name_conflict", c.Name, "a capability rule of yours binds "+c.Name+" to another host, because a concurrent claim won; it still works through self access as HOST_ID/"+c.Name+" only, and cannot be shared under its name", renameCommand(c))
		}
		state, unavailable, _, err := capabilityState(ctx, tx, c)
		if err != nil {
			return st, err
		}
		var found []string
		if state == CapabilityUnavailable {
			found = append(found, "it is unavailable: "+strings.Join(unavailable, ", "))
		}
		if c.Snapshot != nil {
			found = append(found, causes(*c.Snapshot)...)
		}
		command := "peerspan capability show " + c.Name
		if c.OwnSignIn {
			gone, hasCred, err := lapsed(credKey{c.AgentID, c.Source.Server, c.Name})
			if err != nil {
				return st, err
			}
			switch {
			case gone || !hasCred:
				found = append([]string{"its own sign-in has lapsed or is missing, so calls fail"}, found...)
				command = "peerspan capability login " + c.Name
			case c.Snapshot != nil && recent(c.Snapshot.InsufficientScopeAt):
				found = append([]string{"the server refused a call for insufficient scope at " + *c.Snapshot.InsufficientScopeAt}, found...)
				command = "peerspan capability login " + c.Name + " --scopes \"" + deref(c.Snapshot.InsufficientScope) + "\""
			}
		}
		if len(found) > 0 {
			attend("capability_failing", c.Name, strings.Join(found, "; "), command)
		}
	}
	if path := ToolEnvFile(); path != "" && envFileTooOpen(path) {
		attend("capability_failing", "env", "the environment file "+path+" is readable by others, so servers start without it", "chmod 600 "+path)
	}
	if st.CallsRunning, err = runningCalls(ctx, tx); err != nil {
		return st, err
	}
	open, err := openList(ctx, tx)
	if err != nil {
		return st, err
	}
	st.OpenTo = int64(len(open))
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM oauth_credentials WHERE json_extract(record, '$.state') != 'login_required'`).Scan(&st.SignedIn); err != nil {
		return st, err
	}
	if err = approvalAttention(ctx, tx, &st, attend); err != nil {
		return st, err
	}
	return st, nil
}

// renameCommand recreates a capability under a new name, with its
// operations and credential options, then removes it.
func renameCommand(c capabilityRecord) string {
	parts := []string{"peerspan capability create NEW_NAME --from " + c.Source.Agent + "/" + c.Source.Server}
	if len(c.Operations) > 0 {
		parts = append(parts, "--operations "+strings.Join(c.Operations, ","))
	}
	switch {
	case c.Resources.All:
		parts = append(parts, "--resources all")
	case c.Resources.Set:
		parts = append(parts, "--resources "+strings.Join(c.Resources.URIs, ","))
	}
	if c.Credential.EnvFile != nil {
		parts = append(parts, "--env-file "+*c.Credential.EnvFile)
	}
	for _, arg := range c.Credential.Args {
		parts = append(parts, "--arg "+arg)
	}
	return strings.Join(parts, " ") + " && peerspan capability remove " + c.Name
}
