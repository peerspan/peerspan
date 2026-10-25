package coord

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
	"github.com/peerspan/peerspan/go/internal/tlsid"
)

// Public operation/proof categories are separate from disposable transport.
const linkingSchema = `
CREATE TABLE link_mailboxes (
 locator TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE,
 creator TEXT NOT NULL, source_ip TEXT NOT NULL,
 created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('open','expired','deleted')),
 next_sequence INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE link_frames (
 locator TEXT NOT NULL REFERENCES link_mailboxes(locator) ON DELETE CASCADE,
 request_id TEXT NOT NULL, sequence INTEGER NOT NULL, role TEXT NOT NULL,
 writer_public_key TEXT NOT NULL, frame_id TEXT NOT NULL, body BLOB NOT NULL,
 PRIMARY KEY(locator,sequence), UNIQUE(request_id,role,writer_public_key,frame_id)
);
CREATE TABLE link_operations (
 request_id TEXT PRIMARY KEY, network_id TEXT NOT NULL,
 manifest_id TEXT NOT NULL, host_public_key TEXT NOT NULL, result BLOB NOT NULL
);
CREATE TABLE link_objects (
 network_id TEXT NOT NULL, proof_id TEXT NOT NULL, kind TEXT NOT NULL,
 body BLOB NOT NULL, PRIMARY KEY(network_id,proof_id)
);
CREATE TABLE link_features (
 network_id TEXT NOT NULL, feature_id TEXT NOT NULL, proposal BLOB NOT NULL,
 feature BLOB, active INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(network_id,feature_id)
);
CREATE UNIQUE INDEX link_one_active_feature ON link_features(network_id) WHERE active = 1;
CREATE TABLE link_rates (
 category TEXT NOT NULL, source TEXT NOT NULL, window INTEGER NOT NULL,
 count INTEGER NOT NULL, PRIMARY KEY(category,source,window)
);
CREATE TABLE link_polls (
 locator TEXT NOT NULL REFERENCES link_mailboxes(locator) ON DELETE CASCADE,
 host_id TEXT NOT NULL, next_at INTEGER NOT NULL,
 PRIMARY KEY(locator,host_id)
);
PRAGMA user_version = 7;
`

type linkError struct {
	status int
	code   string
	retry  int64
}

func (e *linkError) Error() string              { return e.code }
func linkFailure(status int, code string) error { return &linkError{status: status, code: code} }

func respondLink(w http.ResponseWriter, status int, value any, err error, requestID string) {
	if err != nil {
		failure := &linkError{status: http.StatusInternalServerError, code: "internal"}
		var known *linkError
		if errors.As(err, &known) {
			failure = known
		}
		if failure.code == "internal" {
			// Preserve generic diagnostics without ever recording request data.
			recordError(w, errors.New("linking operation failed"))
		}
		if failure.retry > 0 {
			w.Header().Set("Retry-After", strconv.FormatInt(failure.retry, 10))
		}
		if requestID == "" {
			requestID = "-"
		}
		status = failure.status
		value = map[string]any{"code": failure.code, "error": strings.ReplaceAll(failure.code, "_", " "), "details": map[string]any{
			"request_id": requestID, "stage": "-", "required_ids": []string{}, "next": []string{},
		}}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func linkSource(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return ""
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return ""
	}
	return ip.Unmap().String()
}

func linkCaller(r *http.Request) (string, error) {
	if r.TLS != nil {
		if key, err := tlsid.PeerKey(*r.TLS); err == nil {
			return membership.HostID(key), nil
		}
	}
	return "", linkFailure(403, "forbidden")
}

func (s *Server) linkingRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /coord/v2/link-mailboxes", s.linkMailboxHTTP)
	mux.HandleFunc("POST /coord/v2/link-mailboxes/{locator}/frames", s.linkMailboxHTTP)
	mux.HandleFunc("GET /coord/v2/link-mailboxes/{locator}", s.linkMailboxHTTP)
	mux.HandleFunc("DELETE /coord/v2/link-mailboxes/{locator}", s.linkMailboxHTTP)
}

func (s *Server) linkMailboxHTTP(w http.ResponseWriter, r *http.Request) {
	caller, err := linkCaller(r)
	if err != nil {
		respondLink(w, 0, nil, err, "")
		return
	}
	now, err := linking.RuntimeNow(s.Now)
	if err != nil {
		respondLink(w, 0, nil, err, "")
		return
	}
	create := r.Method == http.MethodPost && r.PathValue("locator") == ""
	var submission linking.MailboxSubmission
	var after uint64
	if r.Method == http.MethodPost {
		data, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		_ = r.Body.Close()
		if readErr == nil {
			submission, readErr = linking.ParseMailboxSubmission(data, create)
		}
		if readErr != nil || r.URL.RawQuery != "" {
			respondLink(w, 0, nil, linkFailure(400, "invalid"), "")
			return
		}
		if create {
			key, _ := membership.DecodeKey(submission.Frame.WriterPublicKey)
			if membership.HostID(key) != caller {
				respondLink(w, 0, nil, linkFailure(403, "forbidden"), submission.Frame.RequestID)
				return
			}
		}
	} else {
		body, readErr := io.ReadAll(io.LimitReader(r.Body, 1))
		_ = r.Body.Close()
		if readErr != nil || len(body) != 0 {
			respondLink(w, 0, nil, linkFailure(400, "invalid"), "")
			return
		}
		if r.Method == http.MethodGet && r.URL.RawQuery != "" {
			q := r.URL.Query()
			values := q["after"]
			if len(q) != 1 || len(values) != 1 || values[0] == "" {
				err = linkFailure(400, "invalid")
			} else {
				after, err = strconv.ParseUint(values[0], 10, 64)
				if err != nil || strconv.FormatUint(after, 10) != values[0] {
					err = linkFailure(400, "invalid")
				}
			}
		} else if r.URL.RawQuery != "" {
			err = linkFailure(400, "invalid")
		}
		if err != nil {
			respondLink(w, 0, nil, err, "")
			return
		}
	}
	locator := r.PathValue("locator")
	if create {
		locator = submission.Frame.Locator
	}
	if decoded, decodeErr := hex.DecodeString(locator); decodeErr != nil || len(decoded) != 32 || strings.ToLower(locator) != locator {
		respondLink(w, 0, nil, linkFailure(400, "invalid"), submission.Frame.RequestID)
		return
	}
	category := "write"
	if create {
		category = "create"
	} else if r.Method == http.MethodGet {
		category = "poll"
	}
	if err = s.linkBudget(r.Context(), now.Unix(), category, linkSource(r.RemoteAddr), caller, locator); err != nil {
		respondLink(w, 0, nil, err, submission.Frame.RequestID)
		return
	}
	status, result, requestID, err := s.linkMailbox(r.Context(), now.Unix(), caller, linkSource(r.RemoteAddr), locator, r.Method, create, after, submission)
	if err == nil && r.Method == http.MethodPost {
		barrier := "coord.frame.after_commit"
		if create {
			barrier = "coord.mailbox.after_commit"
		}
		err = linking.RuntimeBarrier(r.Context(), barrier, requestID)
	}
	respondLink(w, status, result, err, requestID)
}

// Rate accounting commits separately from data mutations: retries and rejected
// capacity additions consume budget, but a blocked source never charges global.
func (s *Server) linkBudget(ctx context.Context, now int64, category, source, caller, locator string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, cleanup := range []struct {
		query  string
		before int64
	}{
		{`DELETE FROM link_mailboxes WHERE expires_at <= ?`, now - 86400},
		{`UPDATE link_mailboxes SET state='expired' WHERE state='open' AND expires_at <= ?`, now},
		{`DELETE FROM link_rates WHERE window < ?`, now - 7200},
	} {
		if _, err = tx.ExecContext(ctx, cleanup.query, cleanup.before); err != nil {
			return err
		}
	}
	window, duration, perSource, global := now/60*60, int64(60), 60, 12000
	if category == "create" {
		window, duration, perSource, global = now/3600*3600, 3600, 5, 1000
	}
	if category == "poll" {
		perSource = 120
	}
	type bucket struct {
		source string
		max    int
	}
	for _, b := range []bucket{{"ip:" + source, perSource}, {"global", global}} {
		var count int
		err = tx.QueryRowContext(ctx, `SELECT count FROM link_rates WHERE category=? AND source=? AND window=?`, category, b.source, window).Scan(&count)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if count >= b.max {
			if err = tx.Commit(); err != nil {
				return err
			}
			return &linkError{status: 429, code: "rate_limited", retry: window + duration - now}
		}
	}
	if category == "poll" {
		var next int64
		err = tx.QueryRowContext(ctx, `SELECT next_at FROM link_polls WHERE locator=? AND host_id=?`, locator, caller).Scan(&next)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if next > now {
			if err = tx.Commit(); err != nil {
				return err
			}
			return &linkError{status: 429, code: "rate_limited", retry: next - now}
		}
	}
	for _, b := range []bucket{{"ip:" + source, perSource}, {"global", global}} {
		if _, err = tx.ExecContext(ctx, `INSERT INTO link_rates VALUES(?,?,?,1) ON CONFLICT(category,source,window) DO UPDATE SET count=count+1`, category, b.source, window); err != nil {
			return err
		}
	}
	if category == "poll" {
		if _, err = tx.ExecContext(ctx, `INSERT INTO link_polls SELECT locator,?,? FROM link_mailboxes WHERE locator=? ON CONFLICT(locator,host_id) DO UPDATE SET next_at=excluded.next_at`, caller, now+2, locator); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type mailboxFrame struct {
	Sequence int64           `json:"sequence"`
	Frame    json.RawMessage `json:"frame"`
}
type mailboxView struct {
	RequestID    string         `json:"request_id"`
	Locator      string         `json:"locator"`
	CreatedAt    string         `json:"created_at"`
	ExpiresAt    string         `json:"expires_at"`
	NextSequence int64          `json:"next_sequence"`
	State        string         `json:"state"`
	Frames       []mailboxFrame `json:"frames"`
}

func (s *Server) linkMailbox(ctx context.Context, now int64, caller, source, locator, method string, create bool, after uint64, in linking.MailboxSubmission) (int, any, string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, nil, "", err
	}
	defer tx.Rollback()
	v := mailboxView{Locator: locator, Frames: []mailboxFrame{}}
	var creator, storedSource string
	var created, expires int64
	err = tx.QueryRowContext(ctx, `SELECT request_id,creator,source_ip,created_at,expires_at,state,next_sequence FROM link_mailboxes WHERE locator=?`, locator).Scan(&v.RequestID, &creator, &storedSource, &created, &expires, &v.State, &v.NextSequence)
	exists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, nil, "", err
	}
	fail := func(status int, code string) (int, any, string, error) {
		return 0, nil, v.RequestID, linkFailure(status, code)
	}
	status := 200
	if create {
		v.RequestID = in.Frame.RequestID
		if exists {
			if creator != caller || created != in.CreatedAt.Unix() || expires != in.ExpiresAt.Unix() {
				return fail(409, "operation_conflict")
			}
			if v.State != "open" {
				return fail(410, v.State)
			}
			var original []byte
			if err = tx.QueryRowContext(ctx, `SELECT body FROM link_frames WHERE locator=? AND sequence=1`, locator).Scan(&original); err != nil {
				return 0, nil, v.RequestID, err
			}
			if !bytes.Equal(original, in.RawFrame) {
				return fail(409, "operation_conflict")
			}
		} else {
			var used int
			if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM link_mailboxes WHERE request_id=?`, v.RequestID).Scan(&used); err != nil {
				return 0, nil, v.RequestID, err
			}
			if used > 0 {
				return fail(409, "operation_conflict")
			}
			if in.CreatedAt.Unix() > now || in.ExpiresAt.Unix() <= now {
				return fail(400, "invalid")
			}
			var retained, open, local int
			if err = tx.QueryRowContext(ctx, `SELECT count(*),COALESCE(sum(state='open'),0),COALESCE(sum(state='open' AND source_ip=?),0) FROM link_mailboxes`, source).Scan(&retained, &open, &local); err != nil {
				return 0, nil, v.RequestID, err
			}
			if retained >= 4096 || open >= 256 || local >= 8 {
				return fail(409, "quota_exceeded")
			}
			created, expires, v.State = in.CreatedAt.Unix(), in.ExpiresAt.Unix(), "open"
			v.NextSequence = 1
			if _, err = tx.ExecContext(ctx, `INSERT INTO link_mailboxes(locator,request_id,creator,source_ip,created_at,expires_at,state) VALUES(?,?,?,?,?,?,'open')`, locator, v.RequestID, caller, source, created, expires); err != nil {
				return 0, nil, v.RequestID, err
			}
			status = 201
		}
	} else if !exists {
		return fail(404, "not_found")
	}
	if method == http.MethodPost && v.State != "open" {
		return fail(410, v.State)
	}
	if method == http.MethodDelete {
		if creator != caller {
			return fail(403, "forbidden")
		}
		if _, err = tx.ExecContext(ctx, `UPDATE link_mailboxes SET state='deleted' WHERE locator=?`, locator); err != nil {
			return 0, nil, v.RequestID, err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM link_frames WHERE locator=?`, locator); err != nil {
			return 0, nil, v.RequestID, err
		}
		if err = tx.Commit(); err != nil {
			return 0, nil, v.RequestID, err
		}
		return 200, map[string]string{"state": "deleted"}, v.RequestID, nil
	}
	if method == http.MethodPost {
		f := in.Frame
		if f.Locator != locator || f.RequestID != v.RequestID {
			return fail(400, "invalid")
		}
		var sequence int64
		var original []byte
		err = tx.QueryRowContext(ctx, `SELECT sequence,body FROM link_frames WHERE request_id=? AND role=? AND writer_public_key=? AND frame_id=?`, f.RequestID, f.Role, f.WriterPublicKey, f.FrameID).Scan(&sequence, &original)
		if err == nil {
			if !bytes.Equal(original, in.RawFrame) {
				return fail(409, "operation_conflict")
			}
		} else if errors.Is(err, sql.ErrNoRows) {
			var count, used, total int64
			if err = tx.QueryRowContext(ctx, `SELECT count(*),COALESCE(sum(length(body)),0) FROM link_frames WHERE locator=?`, locator).Scan(&count, &used); err != nil {
				return 0, nil, v.RequestID, err
			}
			if err = tx.QueryRowContext(ctx, `SELECT COALESCE(sum(length(body)),0) FROM link_frames`).Scan(&total); err != nil {
				return 0, nil, v.RequestID, err
			}
			if count >= 64 || used+int64(len(in.RawFrame)) > 512<<10 || total+int64(len(in.RawFrame)) > 256<<20 {
				return fail(409, "quota_exceeded")
			}
			sequence = v.NextSequence
			if _, err = tx.ExecContext(ctx, `INSERT INTO link_frames VALUES(?,?,?,?,?,?,?)`, locator, f.RequestID, sequence, f.Role, f.WriterPublicKey, f.FrameID, []byte(in.RawFrame)); err != nil {
				return 0, nil, v.RequestID, err
			}
			v.NextSequence = sequence + 1
			if _, err = tx.ExecContext(ctx, `UPDATE link_mailboxes SET next_sequence=? WHERE locator=?`, v.NextSequence, locator); err != nil {
				return 0, nil, v.RequestID, err
			}
			status = 201
		} else {
			return 0, nil, v.RequestID, err
		}
		if !create {
			if err = tx.Commit(); err != nil {
				return 0, nil, v.RequestID, err
			}
			return status, map[string]int64{"sequence": sequence}, v.RequestID, nil
		}
	}
	v.CreatedAt = membership.Timestamp(time.Unix(created, 0))
	v.ExpiresAt = membership.Timestamp(time.Unix(expires, 0))
	// after may exceed SQLite's signed INTEGER range; it then selects no rows.
	if after < uint64(v.NextSequence) {
		rows, queryErr := tx.QueryContext(ctx, `SELECT sequence,body FROM link_frames WHERE locator=? AND sequence>? ORDER BY sequence`, locator, int64(after))
		if queryErr != nil {
			return 0, nil, v.RequestID, queryErr
		}
		for rows.Next() {
			var f mailboxFrame
			if err = rows.Scan(&f.Sequence, &f.Frame); err != nil {
				break
			}
			v.Frames = append(v.Frames, f)
		}
		err = errors.Join(err, rows.Err(), rows.Close())
		if err != nil {
			return 0, nil, v.RequestID, err
		}
	}
	if err = tx.Commit(); err != nil {
		return 0, nil, v.RequestID, err
	}
	return status, v, v.RequestID, nil
}
