package host

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"time"
)

// Channel readiness (milestone 9, slice 1). An adapter proves that its
// session receives channel events when the model answers the adapter's hello
// event; the adapter checks the nonce and then reports readiness here. The
// daemon records the verification on the authorization, so recovery after a
// restart keeps it and a new authorization starts unverified.

// The v14 schema adds the verification time and the MCP protocol revision the
// adapter negotiated to adapter_connections. Existing authorizations migrate
// as unverified. Columns already present (a state whose version was lowered)
// are kept, so the result is the same schema either way.
var channelColumns = []string{"channel_verified_at", "protocol_version"}

func migrateChannel(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT name FROM pragma_table_info('adapter_connections')`)
	if err != nil {
		return err
	}
	present := map[string]bool{}
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		present[name] = true
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	for _, column := range channelColumns {
		if present[column] {
			continue
		}
		if _, err = tx.ExecContext(ctx, `ALTER TABLE adapter_connections ADD COLUMN `+column+` TEXT`); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `PRAGMA user_version = 14`)
	return err
}

// Channel states of an authorization, session, or agent holding a lease.
const (
	ChannelVerified   = "verified"
	ChannelUnverified = "unverified"
)

// channelUnverifiedAfter is how long an adapter may hold a lease without
// verification before status reports channel_unverified.
const channelUnverifiedAfter = 120 * time.Second

// adapterSendDeadline is the default deadline of adapter sends by address and
// through routes, bounded by the credential's expiry.
const adapterSendDeadline = time.Hour

// MinimumClaudeVersion is the oldest Claude Code release whose channel
// delivery Peerspan supports.
const MinimumClaudeVersion = "2.1.187"

// ChannelUnverifiedDetail is the status item 13 message, also used by
// session doctor.
func ChannelUnverifiedDetail(agent string) string {
	return fmt.Sprintf("the session of agent %s holds a lease but has not confirmed that it receives Peerspan's channel events (peerspan_ready), so no messages or tasks are delivered to it. Likely causes: the organization has not enabled channels (channelsEnabled); the provider does not support channels; the Claude Code version is older than %s; or the session was started without the channel flag", agent, MinimumClaudeVersion)
}

var errChannelNotVerified = &codedError{status: http.StatusConflict, code: "conflict", message: "channel not verified"}

var noncePattern = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
var protocolPattern = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$`)

// requireVerified refuses work routes until the authorization is verified.
func requireVerified(ctx context.Context, tx *sql.Tx, adapterID string) error {
	var at sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT channel_verified_at FROM adapter_connections WHERE adapter_id = ?`, adapterID).Scan(&at); err != nil {
		return err
	}
	if !at.Valid {
		return errChannelNotVerified
	}
	return nil
}

// ReadyAdapter records that the adapter's session receives channel events.
// It requires the credential and lease, and keeps the first verification time.
func (s *Store) ReadyAdapter(ctx context.Context, auth AdapterAuth, nonce string) (Connection, error) {
	if !noncePattern.MatchString(nonce) {
		return Connection{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Connection{}, err
	}
	defer tx.Rollback()
	a, ss, err := adapterAuthority(ctx, tx, auth)
	if err != nil {
		return Connection{}, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE adapter_connections SET channel_verified_at = COALESCE(channel_verified_at, ?) WHERE adapter_id = ?`, timestamp(time.Now()), a.ID); err != nil {
		return Connection{}, err
	}
	c, err := connectionStatus(ctx, tx, a, ss)
	if err != nil {
		return c, err
	}
	return c, tx.Commit()
}

// leaseChannel is the channel of the leases matching a condition: verified
// when any is verified, unverified when there is a lease, else nil.
func leaseChannel(ctx context.Context, q dbQuerier, condition, id string, now time.Time) (*string, error) {
	var leases, verified int
	err := q.QueryRowContext(ctx, `SELECT COUNT(*), COUNT(x.channel_verified_at) FROM sessions ss JOIN adapter_credentials c ON c.session_id = ss.id JOIN adapter_connections x ON x.adapter_id = c.id WHERE `+condition+` = ? AND ss.state = 'attached' AND x.lease_until_ms > ? AND json_extract(c.record, '$.revoked_at') IS NULL AND json_extract(c.record, '$.expires_at') > ?`, id, now.UnixMilli(), timestamp(now)).Scan(&leases, &verified)
	if err != nil {
		return nil, err
	}
	var state string
	switch {
	case verified > 0:
		state = ChannelVerified
	case leases > 0:
		state = ChannelUnverified
	default:
		return nil, nil
	}
	return &state, nil
}

// agentChannel is the channel of an agent's attached sessions.
func agentChannel(ctx context.Context, q dbQuerier, agent string, now time.Time) (*string, error) {
	return leaseChannel(ctx, q, "ss.agent_id", agent, now)
}

// sessionChannel is the channel of one session.
func sessionChannel(ctx context.Context, q dbQuerier, session string, now time.Time) (*string, error) {
	return leaseChannel(ctx, q, "ss.id", session, now)
}

// channelAttention adds channel_unverified for each authorization whose
// adapter holds a lease and first connected more than 120 seconds ago without
// verification. Measuring from the first adapter.connected event keeps a
// brief lapse and reconnect (or a daemon restart) from hiding the item.
func channelAttention(ctx context.Context, tx *sql.Tx, now time.Time, attend func(kind, subject, detail, command string)) error {
	rows, err := tx.QueryContext(ctx, `SELECT c.id, a.name FROM sessions ss JOIN agents a ON a.id = ss.agent_id JOIN adapter_credentials c ON c.session_id = ss.id JOIN adapter_connections x ON x.adapter_id = c.id WHERE ss.state = 'attached' AND x.lease_until_ms > ? AND x.channel_verified_at IS NULL AND json_extract(c.record, '$.revoked_at') IS NULL AND json_extract(c.record, '$.expires_at') > ? ORDER BY c.id`, now.UnixMilli(), timestamp(now))
	if err != nil {
		return err
	}
	type unverified struct{ adapter, agent string }
	var list []unverified
	for rows.Next() {
		var u unverified
		if err = rows.Scan(&u.adapter, &u.agent); err != nil {
			rows.Close()
			return err
		}
		list = append(list, u)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	for _, u := range list {
		var since string
		err := tx.QueryRowContext(ctx, `SELECT created_at FROM events WHERE kind = 'adapter.connected' AND subject_id = ? ORDER BY sequence LIMIT 1`, u.adapter).Scan(&since)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		at, err := parseTime(since)
		if err != nil {
			return err
		}
		if now.Sub(at) > channelUnverifiedAfter {
			attend("channel_unverified", u.agent, ChannelUnverifiedDetail(u.agent), "peerspan session doctor")
		}
	}
	return nil
}

func adapterChannelRoutes(mux *http.ServeMux, s *Store, auth func(*http.Request) AdapterAuth) {
	mux.HandleFunc("POST /adapter/v1/ready", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Nonce string `json:"nonce"`
		}
		if !decode(w, r, &body, "nonce") {
			return
		}
		c, err := s.ReadyAdapter(r.Context(), auth(r), body.Nonce)
		respond(w, http.StatusOK, c, err)
	})
}
