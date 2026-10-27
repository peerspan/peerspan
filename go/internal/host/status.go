package host

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/peerspan/peerspan/go/internal/membership"
)

// Version names this build; release builds set it with -ldflags -X.
var Version = "dev"

// Status is GET /v1/status: one view of the host and what needs attention.
type Status struct {
	HostID       string             `json:"host_id"`
	Version      string             `json:"version"`
	Networks     []NetworkStatus    `json:"networks"`
	Blocks       int64              `json:"blocks"`
	Agents       []AgentStatus      `json:"agents"`
	Artifacts    ArtifactUsage      `json:"artifacts"`
	Capabilities CapabilitiesStatus `json:"capabilities"`
	Attention    []AttentionItem    `json:"attention"`
}

// CapabilitiesStatus counts this host's sources, its capabilities, those a
// rule for this host shares, received calls running, and the entries of its
// open list.
type CapabilitiesStatus struct {
	Sources      int64 `json:"sources"`
	Capabilities int64 `json:"capabilities"`
	Shared       int64 `json:"shared"`
	CallsRunning int64 `json:"calls_running"`
	OpenTo       int64 `json:"open_to"`
	// ApprovalsPending counts approvals in pending.
	ApprovalsPending int64 `json:"approvals_pending"`
	// RemoteSources counts remote sources; SignedIn the OAuth credentials
	// that are not login_required.
	RemoteSources int64 `json:"remote_sources"`
	SignedIn      int64 `json:"signed_in"`
}

type NetworkStatus struct {
	ID                      string        `json:"id"`
	Name                    string        `json:"name"`
	Coordinator             string        `json:"coordinator"`
	LastSyncAt              *string       `json:"last_sync_at"`
	LastSyncError           *string       `json:"last_sync_error"`
	Members                 int64         `json:"members"`
	Person                  *StatusPerson `json:"person"`
	Policy                  *StatusPolicy `json:"policy"`
	PolicyDeliveriesPending int64         `json:"policy_deliveries_pending"`
}

type StatusPerson struct {
	ID    string  `json:"id"`
	Label *string `json:"label"`
}

type StatusPolicy struct {
	Version    uint64 `json:"version"`
	ValidUntil string `json:"valid_until"`
}

type AgentStatus struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Sessions []SessionStatus `json:"sessions"`
}

type SessionStatus struct {
	ID          string  `json:"id"`
	Integration string  `json:"integration"`
	AdapterID   *string `json:"adapter_id"`
	Connection  *string `json:"connection"`
	ExpiresAt   *string `json:"expires_at"`
	Renewable   bool    `json:"renewable"`
}

type ArtifactUsage struct {
	Quota        int64 `json:"quota"`
	StoredBytes  int64 `json:"stored_bytes"`
	PendingBytes int64 `json:"pending_bytes"`
}

// AttentionItem is one thing the owner should act on, with the command that
// addresses it.
type AttentionItem struct {
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
	Detail  string `json:"detail"`
	Command string `json:"command"`
}

// Attention kinds, in the order status reports them. The CLI adds
// service_not_installed and linger_disabled.
var AttentionOrder = []string{"coordination_error", "policy_expired", "policy_expiring", "policy_delivery_failing", "credential_expiring", "tasks_failed", "artifact_quota",
	"service_not_installed", "linger_disabled", "person_agent_unreachable", "network_authority_expired", "network_proof_required", "network_state_conflict", "network_clock_rollback", "network_migration_pending", "person_device_signer_unavailable", "coordinator_limit", "agent_name_conflict", "channel_unverified", "capability_failing", "capability_name_conflict", "policy_edit_unsettled", "policy_edit_dropped", "call_approval_pending"}

// SortAttention orders items by kind, then subject.
func SortAttention(items []AttentionItem) {
	rank := map[string]int{}
	for i, kind := range AttentionOrder {
		rank[kind] = i
	}
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.Kind != b.Kind {
			return rank[a.Kind] < rank[b.Kind]
		}
		return a.Subject < b.Subject
	})
}

const (
	credentialAttentionWindow = 24 * time.Hour
	taskAttentionWindow       = 24 * time.Hour
)

func (s *Store) Status(ctx context.Context) (Status, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return Status{}, err
	}
	defer tx.Rollback()
	return s.statusIn(ctx, tx, time.Now(), false)
}

func (s *Store) statusIn(ctx context.Context, tx *sql.Tx, now time.Time, modern bool) (Status, error) {
	var err error
	st := Status{HostID: s.identity.ID, Version: Version, Networks: []NetworkStatus{}, Agents: []AgentStatus{}, Attention: []AttentionItem{}}
	attend := func(kind, subject, detail, command string) {
		st.Attention = append(st.Attention, AttentionItem{kind, subject, detail, command})
	}
	// owners maps networks to the key of this host's person, when that
	// person has a stored policy the daemon renews.
	owners := map[string]string{}
	networkAttention := attend
	if modern {
		networkAttention = func(string, string, string, string) {}
	}
	if st.Networks, err = s.networkStatus(ctx, tx, now, owners, networkAttention); err != nil {
		return st, err
	}
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM access_blocks`).Scan(&st.Blocks); err != nil {
		return st, err
	}
	if st.Agents, err = agentStatus(ctx, tx, now, attend); err != nil {
		return st, err
	}
	failed, err := failedTasks(ctx, tx, now)
	if err != nil {
		return st, err
	}
	if failed > 0 {
		attend("tasks_failed", strconv.Itoa(failed), fmt.Sprintf("%d outbound tasks failed, were rejected, or expired in the last 24 hours", failed), "peerspan task list")
	}
	st.Artifacts.Quota = s.quota()
	if st.Artifacts.StoredBytes, st.Artifacts.PendingBytes, err = artifactUsage(ctx, tx); err != nil {
		return st, err
	}
	if used := st.Artifacts.StoredBytes + st.Artifacts.PendingBytes; used*10 > st.Artifacts.Quota*9 {
		attend("artifact_quota", "artifacts", fmt.Sprintf("%d of %d artifact bytes are stored or pending", used, st.Artifacts.Quota), "peerspan artifact prune")
	}
	if !modern {
		s.personAgentAttention(owners, attend)
	}
	if err = s.nameConflicts(ctx, tx, attend); err != nil {
		return st, err
	}
	if !modern {
		s.limitAttention(st.Networks, attend)
	}
	if err = channelAttention(ctx, tx, now, attend); err != nil {
		return st, err
	}
	if st.Capabilities, err = s.capabilitiesStatus(ctx, tx, now, attend); err != nil {
		return st, err
	}
	SortAttention(st.Attention)
	return st, nil
}

func (s *Store) networkStatus(ctx context.Context, tx *sql.Tx, now time.Time, owners map[string]string, attend func(kind, subject, detail, command string)) ([]NetworkStatus, error) {
	rows, err := tx.QueryContext(ctx, networkColumns+" WHERE COALESCE(json_extract(record, '$.mode'), '') != 'decentralized' ORDER BY id")
	if err != nil {
		return nil, err
	}
	networks := []Network{}
	for rows.Next() {
		n, err := scanNetwork(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		networks = append(networks, n)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	out := []NetworkStatus{}
	for _, n := range networks {
		ns := NetworkStatus{ID: n.ID, Name: n.Name, Coordinator: n.CoordinatorAddress, LastSyncAt: n.LastSyncAt, LastSyncError: n.LastSyncError}
		if n.LastSyncError != nil {
			attend("coordination_error", n.ID, *n.LastSyncError, "peerspan network sync "+n.ID)
		}
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM network_members WHERE network_id = ?`, n.ID).Scan(&ns.Members); err != nil {
			return nil, err
		}
		self, err := readJSON[NetworkMember](tx.QueryRowContext(ctx, `SELECT record FROM network_members WHERE network_id = ? AND host_id = ?`, n.ID, s.identity.ID))
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		if err == nil && self.PersonID != nil {
			person := *self.PersonID
			ns.Person = &StatusPerson{ID: person, Label: self.PersonMember}
			g, err := s.loadGovernance(ctx, tx, n.ID)
			if err != nil {
				return nil, err
			}
			key, knownPerson := g.personKey(person)
			if g.linking != nil {
				key, knownPerson = g.linking.Network.Facts.State.Bindings[s.identity.PublicKey]
				knownPerson = knownPerson && key != "" && key != "-"
			}
			if knownPerson {
				selected, err := s.selectedPolicyAttention(ctx, tx, g, key, attend)
				if err != nil {
					return nil, err
				}
				if p, ok := g.storedPolicy(key); ok {
					ns.Policy = &StatusPolicy{Version: p.Version, ValidUntil: p.ValidUntil}
					if !selected {
						owners[n.ID] = key
					}
					renew := "peerspan access renew --network " + n.ID
					until, _ := membership.ParseTime(p.ValidUntil)
					switch {
					case !now.Before(until):
						attend("policy_expired", n.ID, "your access policy expired at "+p.ValidUntil, renew)
					case membership.PolicyExpiresSoon(p, now):
						detail := "your access policy expires at " + p.ValidUntil + " and was not renewed; check the daemon's ssh-agent"
						if selected {
							detail = "your access policy expires at " + p.ValidUntil + " and was not renewed; check the selected device's policy signing path"
						}
						attend("policy_expiring", n.ID, detail, renew)
					}
				}
			}
			if err = s.editAttention(ctx, tx, n.ID, person, now, attend); err != nil {
				return nil, err
			}
			_, hosts, err := s.siblings(ctx, tx, n.ID)
			if err != nil {
				return nil, err
			}
			current := map[string]bool{policyTargetCoordinator: true}
			for _, h := range hosts {
				current[h] = true
			}
			deliveries, err := tx.QueryContext(ctx, `SELECT target, record FROM policy_deliveries WHERE network_id = ? AND person_id = ? ORDER BY target`, n.ID, person)
			if err != nil {
				return nil, err
			}
			for deliveries.Next() {
				var target, record string
				var rec policyDeliveryRecord
				if err = deliveries.Scan(&target, &record); err == nil {
					err = json.Unmarshal([]byte(record), &rec)
				}
				if err != nil {
					deliveries.Close()
					return nil, err
				}
				if !current[target] || rec.State != "pending" {
					continue
				}
				ns.PolicyDeliveriesPending++
				if rec.Attempts >= 1 {
					detail := fmt.Sprintf("policy version %d has not reached %s after %d attempts", rec.Version, target, rec.Attempts)
					if rec.Error != nil {
						detail += ": " + *rec.Error
					}
					attend("policy_delivery_failing", n.ID+"/"+target, detail, "peerspan access sync --network "+n.ID)
				}
			}
			deliveries.Close()
			if err = deliveries.Err(); err != nil {
				return nil, err
			}
		}
		out = append(out, ns)
	}
	return out, nil
}

// agentStatus lists every agent with its attached sessions and its sessions
// holding a usable credential.
func agentStatus(ctx context.Context, tx *sql.Tx, now time.Time, attend func(kind, subject, detail, command string)) ([]AgentStatus, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, name FROM agents ORDER BY name, id`)
	if err != nil {
		return nil, err
	}
	agents := []AgentStatus{}
	for rows.Next() {
		a := AgentStatus{Sessions: []SessionStatus{}}
		if err = rows.Scan(&a.ID, &a.Name); err != nil {
			rows.Close()
			return nil, err
		}
		agents = append(agents, a)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	for i := range agents {
		sessions, err := tx.QueryContext(ctx, `SELECT id, agent_id, integration, state, created_at, updated_at FROM sessions WHERE agent_id = ? ORDER BY id`, agents[i].ID)
		if err != nil {
			return nil, err
		}
		var list []Session
		for sessions.Next() {
			ss, err := scanSession(sessions)
			if err != nil {
				sessions.Close()
				return nil, err
			}
			list = append(list, ss)
		}
		sessions.Close()
		if err = sessions.Err(); err != nil {
			return nil, err
		}
		for _, ss := range list {
			credentials, err := records[Adapter](ctx, tx, `SELECT record FROM adapter_credentials WHERE session_id = ? ORDER BY rowid`, ss.ID)
			if err != nil {
				return nil, err
			}
			var chosen *Adapter
			usable := false
			for j := range credentials {
				c := &credentials[j]
				exp, err := parseTime(c.ExpiresAt)
				if err != nil {
					return nil, err
				}
				if c.RevokedAt == nil && exp.After(now) {
					chosen, usable = c, true
					break
				}
				chosen = c
			}
			if ss.State != SessionAttached && !usable {
				continue
			}
			view := SessionStatus{ID: ss.ID, Integration: ss.Integration}
			if chosen != nil {
				c, err := connectionStatus(ctx, tx, *chosen, ss)
				if err != nil {
					return nil, err
				}
				id, expires := chosen.ID, chosen.ExpiresAt
				view.AdapterID, view.Connection, view.ExpiresAt, view.Renewable = &id, &c.State, &expires, chosen.Renewable
				exp, _ := parseTime(expires)
				if usable && !chosen.Renewable && ss.State == SessionAttached && !exp.After(now.Add(credentialAttentionWindow)) {
					attend("credential_expiring", id, "the session credential expires at "+expires, "peerspan session setup --agent "+agents[i].ID+" --harness "+ss.Integration)
				}
			}
			agents[i].Sessions = append(agents[i].Sessions, view)
		}
	}
	return agents, nil
}

// failedTasks counts outbound tasks that failed, were rejected, or expired
// and last changed within the attention window.
func failedTasks(ctx context.Context, tx *sql.Tx, now time.Time) (int, error) {
	tasks, err := records[OutboundTask](ctx, tx, `SELECT record FROM outbound_tasks`)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, t := range tasks {
		state := ""
		if t.Status != nil {
			state = t.Status.State
		} else if t.SubmitState == submitRejected {
			state = TaskRejected
		}
		if state != TaskFailed && state != TaskRejected && state != TaskExpired {
			continue
		}
		var last sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT created_at FROM events WHERE kind = 'task.updated' AND subject_id = ? ORDER BY sequence DESC LIMIT 1`, taskSubject(t.PeerHostID, t.Request.TaskID)).Scan(&last)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return 0, err
		}
		if !last.Valid {
			continue
		}
		if at, err := parseTime(last.String); err == nil && now.Sub(at) < taskAttentionWindow {
			count++
		}
	}
	return count, nil
}

// personAgentAttention reports networks whose policy the daemon cannot
// renew: its --person-agent is unset, unreachable, or lacks the person's key,
// and its --person-key-file does not hold that key.
func (s *Store) personAgentAttention(owners map[string]string, attend func(kind, subject, detail, command string)) {
	if len(owners) == 0 {
		return
	}
	networks := make([]string, 0, len(owners))
	for network := range owners {
		networks = append(networks, network)
	}
	sort.Strings(networks)
	for _, network := range networks {
		public, err := membership.DecodeKey(owners[network])
		if err != nil {
			continue
		}
		signer, err := s.renewalSigner(ed25519.PublicKey(public))
		if err == nil {
			signer.Close()
			continue
		}
		detail := err.Error()
		attend("person_agent_unreachable", network, detail, "peerspan install")
	}
}

func localStatusRoutes(mux *http.ServeMux, store *Store) {
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		st, err := store.Status(r.Context())
		respond(w, http.StatusOK, st, err)
	})
}
