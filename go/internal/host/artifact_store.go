package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
	"unicode"
	"unicode/utf8"
)

// Task artifacts (milestone 6, slice 3). Files attached to tasks are
// content-addressed: the host that holds a file lists it in a manifest, and
// the other party of that task pulls it over the peer connection and checks
// its size and SHA-256 digest before storing it. Files live under artifacts/
// in the state directory, named by digest and shared across tasks.
const artifactSchema = `
CREATE TABLE artifact_files (sha256 TEXT PRIMARY KEY, record TEXT NOT NULL);
CREATE TABLE task_artifacts (side TEXT NOT NULL, peer TEXT NOT NULL, task_id TEXT NOT NULL, direction TEXT NOT NULL, sha256 TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(side, peer, task_id, direction, sha256));
PRAGMA user_version = 10;
`

const (
	artifactMaxSize    = 100 << 20 // bytes per artifact
	artifactMaxEntries = 64
	// DefaultArtifactQuota is the per-host quota unless the daemon sets one.
	DefaultArtifactQuota = 10 << 30
	artifactUploadHold   = 24 * time.Hour
	artifactRetention    = 7 * 24 * time.Hour
	artifactSweep        = time.Minute
	defaultMediaType     = "application/octet-stream"
)

// Sides, directions, and states of a task's artifacts.
const (
	sideSent        = "sent"
	sideReceived    = "received"
	directionInput  = "input"
	directionResult = "result"
	artifactStored  = "stored"
	artifactPending = "pending"
	artifactPruned  = "pruned"
)

// ArtifactEntry is one manifest entry.
type ArtifactEntry struct {
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	MediaType string `json:"media_type"`
}

// UnmarshalJSON accepts exactly the four fields, none null.
func (e *ArtifactEntry) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil || raw == nil || len(raw) != 4 {
		return ErrInvalid
	}
	for _, field := range []string{"name", "size", "sha256", "media_type"} {
		value, ok := raw[field]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return ErrInvalid
		}
	}
	type plain ArtifactEntry
	return json.Unmarshal(data, (*plain)(e))
}

// LocalArtifact is one artifact of a local task record.
type LocalArtifact struct {
	Direction string `json:"direction"`
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	MediaType string `json:"media_type"`
	State     string `json:"state"`
}

// taskArtifact is a task_artifacts record.
type taskArtifact struct {
	Side       string `json:"side"`
	PeerHostID string `json:"peer_host_id"`
	TaskID     string `json:"task_id"`
	Direction  string `json:"direction"`
	Name       string `json:"name"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	MediaType  string `json:"media_type"`
	State      string `json:"state"`
}

// artifactFile is an artifact_files record; a row exists while the file is
// stored. UploadUntil holds an upload not yet referenced by a task.
type artifactFile struct {
	SHA256      string  `json:"sha256"`
	Size        int64   `json:"size"`
	CreatedAt   string  `json:"created_at"`
	UploadUntil *string `json:"upload_until"`
}

// ArtifactFileView is one stored file in `artifact list`.
type ArtifactFileView struct {
	SHA256      string  `json:"sha256"`
	Size        int64   `json:"size"`
	CreatedAt   string  `json:"created_at"`
	UploadUntil *string `json:"upload_until"`
	Tasks       int64   `json:"tasks"`
}

// ArtifactList is `artifact list`: stored files and the quota.
type ArtifactList struct {
	Quota        int64              `json:"quota"`
	StoredBytes  int64              `json:"stored_bytes"`
	PendingBytes int64              `json:"pending_bytes"`
	Files        []ArtifactFileView `json:"files"`
}

// ArtifactPrune reports what `artifact prune` deleted.
type ArtifactPrune struct {
	FilesDeleted int64 `json:"files_deleted"`
	BytesFreed   int64 `json:"bytes_freed"`
}

func validArtifactName(name string) bool {
	if name == "" || len(name) > 255 || !utf8.ValidString(name) || name == "." || name == ".." {
		return false
	}
	for _, r := range name {
		if r == '/' || r == '\\' || r == 0 || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validMediaType(value string) bool {
	if value == "" || len(value) > 255 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if !(value[i] >= '0' && value[i] <= '9' || value[i] >= 'a' && value[i] <= 'f') {
			return false
		}
	}
	return true
}

// validManifest checks a non-empty manifest: at most 64 valid entries with
// unique names and digests.
func validManifest(entries []ArtifactEntry) bool {
	if len(entries) == 0 || len(entries) > artifactMaxEntries {
		return false
	}
	names, digests := map[string]bool{}, map[string]bool{}
	for _, e := range entries {
		if !validArtifactName(e.Name) || e.Size < 0 || e.Size > artifactMaxSize || !validDigest(e.SHA256) || !validMediaType(e.MediaType) || names[e.Name] || digests[e.SHA256] {
			return false
		}
		names[e.Name], digests[e.SHA256] = true, true
	}
	return true
}

func manifestTotal(entries []ArtifactEntry) int64 {
	var total int64
	for _, e := range entries {
		total += e.Size
	}
	return total
}

func sameManifest(a, b []ArtifactEntry) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// emptyAsNone treats an empty local manifest as no artifacts.
func emptyAsNone(entries []ArtifactEntry) []ArtifactEntry {
	if len(entries) == 0 {
		return nil
	}
	return entries
}

// ConfigureArtifacts sets the artifact quota in bytes.
func (s *Store) ConfigureArtifacts(quota int64) error {
	if quota < 1 {
		return fmt.Errorf("%w: the artifact quota must be at least 1 byte", ErrInvalid)
	}
	s.artifactQuota.Store(quota)
	return nil
}

func (s *Store) quota() int64 {
	if q := s.artifactQuota.Load(); q > 0 {
		return q
	}
	return DefaultArtifactQuota
}

func (s *Store) artifactDir() string { return filepath.Join(s.dir, "artifacts") }

func (s *Store) artifactPath(digest string) string { return filepath.Join(s.artifactDir(), digest) }

// prepareArtifactDir creates the private artifact directory and removes any
// file that is not a recorded digest, such as a download interrupted by a
// crash before its rename.
func (s *Store) prepareArtifactDir(ctx context.Context) error {
	dir := s.artifactDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("artifact directory must be a private directory (mode 0700): %s", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		var exists bool
		if err = s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM artifact_files WHERE sha256 = ?)`, entry.Name()).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			if err = os.RemoveAll(filepath.Join(dir, entry.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

// artifactUsage returns the bytes of stored files and of pending fetches
// whose content is not stored yet.
func artifactUsage(ctx context.Context, q dbQuerier) (stored, pending int64, err error) {
	if err = q.QueryRowContext(ctx, `SELECT COALESCE(SUM(json_extract(record, '$.size')), 0) FROM artifact_files`).Scan(&stored); err != nil {
		return
	}
	err = q.QueryRowContext(ctx, `SELECT COALESCE(SUM(size), 0) FROM (SELECT MAX(json_extract(record, '$.size')) AS size FROM task_artifacts WHERE json_extract(record, '$.state') = 'pending' AND sha256 NOT IN (SELECT sha256 FROM artifact_files) GROUP BY sha256)`).Scan(&pending)
	return
}

func storedFile(ctx context.Context, q dbQuerier, digest string) (artifactFile, error) {
	return readJSON[artifactFile](q.QueryRowContext(ctx, `SELECT record FROM artifact_files WHERE sha256 = ?`, digest))
}

// requireStored checks that every entry names a stored file of that size.
func requireStored(ctx context.Context, q dbQuerier, entries []ArtifactEntry) error {
	for _, e := range entries {
		f, err := storedFile(ctx, q, e.SHA256)
		if errors.Is(err, ErrNotFound) || (err == nil && f.Size != e.Size) {
			return fmt.Errorf("%w: artifact %s is not a stored upload of %d bytes", ErrInvalid, e.Name, e.Size)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// quotaFor refuses a manifest whose content not yet stored or pending would
// exceed the quota together with stored files and pending fetches.
func (s *Store) quotaFor(ctx context.Context, q dbQuerier, entries []ArtifactEntry) error {
	var need int64
	for _, e := range entries {
		// Stored content, or content another task already waits for, is
		// counted already.
		var counted bool
		if err := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM artifact_files WHERE sha256 = ?1) OR EXISTS(SELECT 1 FROM task_artifacts WHERE sha256 = ?1 AND json_extract(record, '$.state') = 'pending')`, e.SHA256).Scan(&counted); err != nil {
			return err
		}
		if !counted {
			need += e.Size
		}
	}
	if need == 0 {
		return nil
	}
	stored, pending, err := artifactUsage(ctx, q)
	if err != nil {
		return err
	}
	if stored+pending+need > s.quota() {
		return fmt.Errorf("%w: the artifact quota is exhausted", ErrInsufficientStorage)
	}
	return nil
}

// insertArtifacts records a task's manifest in order. Content already stored
// is stored at once; otherwise the entry has the given state.
func insertArtifacts(ctx context.Context, tx *sql.Tx, side, peer, task, direction string, entries []ArtifactEntry, state string) error {
	for _, e := range entries {
		row := taskArtifact{Side: side, PeerHostID: peer, TaskID: task, Direction: direction, Name: e.Name, Size: e.Size, SHA256: e.SHA256, MediaType: e.MediaType, State: state}
		if state == artifactPending {
			if _, err := storedFile(ctx, tx, e.SHA256); err == nil {
				row.State = artifactStored
			} else if !errors.Is(err, ErrNotFound) {
				return err
			}
		}
		if err := putJSON(ctx, tx, `INSERT INTO task_artifacts (record, side, peer, task_id, direction, sha256) VALUES (?, ?, ?, ?, ?, ?)`, row, side, peer, task, direction, e.SHA256); err != nil {
			return err
		}
	}
	return nil
}

func taskArtifacts(ctx context.Context, q queryer, side, peer, task string) ([]taskArtifact, error) {
	rows, err := q.QueryContext(ctx, `SELECT record FROM task_artifacts WHERE side = ? AND peer = ? AND task_id = ? ORDER BY rowid`, side, peer, task)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []taskArtifact
	for rows.Next() {
		row, err := readJSON[taskArtifact](rows)
		if err != nil {
			return nil, err
		}
		items = append(items, row)
	}
	return items, rows.Err()
}

// withArtifacts adds a local record's artifacts and their states.
func (s *Store) withArtifacts(ctx context.Context, out OutboundTask, err error) (OutboundTask, error) {
	if err != nil {
		return out, err
	}
	rows, err := taskArtifacts(ctx, s.db, sideSent, out.PeerHostID, out.Request.TaskID)
	if err != nil {
		return out, err
	}
	out.Artifacts = []LocalArtifact{}
	for _, row := range rows {
		out.Artifacts = append(out.Artifacts, LocalArtifact{Direction: row.Direction, Name: row.Name, Size: row.Size, SHA256: row.SHA256, MediaType: row.MediaType, State: row.State})
	}
	return out, nil
}

// openTaskArtifact opens a stored artifact of one task. A digest listed only
// as pending is a conflict; anything else is not found. The file is opened
// inside the caller's transaction, so pruning cannot remove it first.
func (s *Store) openTaskArtifact(ctx context.Context, tx *sql.Tx, side, peer, task, digest string, directions ...string) (*os.File, int64, error) {
	rows, err := taskArtifacts(ctx, tx, side, peer, task)
	if err != nil {
		return nil, 0, err
	}
	pending := false
	for _, row := range rows {
		if row.SHA256 != digest || (len(directions) > 0 && !contains(directions, row.Direction)) {
			continue
		}
		switch row.State {
		case artifactStored:
			f, err := os.Open(s.artifactPath(digest))
			if errors.Is(err, os.ErrNotExist) {
				return nil, 0, ErrNotFound
			}
			if err != nil {
				return nil, 0, err
			}
			info, err := f.Stat()
			if err != nil {
				f.Close()
				return nil, 0, err
			}
			return f, info.Size(), nil
		case artifactPending:
			pending = true
		}
	}
	if pending {
		return nil, 0, fmt.Errorf("%w: the artifact has not been fetched yet", ErrConflict)
	}
	return nil, 0, ErrNotFound
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func (s *Store) readTx(ctx context.Context) (*sql.Tx, error) {
	return s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
}

// OutboundArtifact opens an input or fetched result of a local task.
func (s *Store) OutboundArtifact(ctx context.Context, peer, id, digest string) (*os.File, int64, error) {
	tx, err := s.readTx(ctx)
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	if _, err = readJSON[OutboundTask](tx.QueryRowContext(ctx, `SELECT record FROM outbound_tasks WHERE peer = ? AND task_id = ?`, peer, id)); err != nil {
		return nil, 0, err
	}
	return s.openTaskArtifact(ctx, tx, sideSent, peer, id, digest)
}

// AdapterDelegationArtifact opens an artifact of a task this credential
// submitted.
func (s *Store) AdapterDelegationArtifact(ctx context.Context, auth AdapterAuth, id, digest string) (*os.File, int64, error) {
	tx, err := s.readTx(ctx)
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	a, _, err := adapterAuthority(ctx, tx, auth)
	if err != nil {
		return nil, 0, err
	}
	out, err := readJSON[OutboundTask](tx.QueryRowContext(ctx, `SELECT record FROM outbound_tasks WHERE task_id = ? AND json_extract(record, '$.adapter_id') = ? ORDER BY rowid LIMIT 1`, id, a.ID))
	if err != nil {
		return nil, 0, err
	}
	return s.openTaskArtifact(ctx, tx, sideSent, out.PeerHostID, id, digest)
}

// AdapterTaskArtifact opens an input or result of a task this session claimed.
func (s *Store) AdapterTaskArtifact(ctx context.Context, auth AdapterAuth, id, digest string) (*os.File, int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	d, _, _, err := ownedTask(ctx, tx, auth, id)
	if err != nil {
		return nil, 0, err
	}
	return s.openTaskArtifact(ctx, tx, sideReceived, d.SenderHostID, d.TaskID, digest)
}

// PeerArtifact opens what a host serves to the other party of a task: an
// input of its outbound task to that receiver, or a result of the task it
// received from that submitter. Fetching authorizes no new work.
func (s *Store) PeerArtifact(ctx context.Context, requester, id, digest string) (*os.File, int64, error) {
	tx, err := s.readTx(ctx)
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	f, size, err := s.openTaskArtifact(ctx, tx, sideSent, requester, id, digest, directionInput)
	if err == nil {
		return f, size, nil
	}
	f, size, err = s.openTaskArtifact(ctx, tx, sideReceived, requester, id, digest, directionResult)
	if err != nil {
		// A peer sees only stored files; nothing else is distinguishable.
		if errors.Is(err, ErrConflict) {
			err = ErrNotFound
		}
		return nil, 0, err
	}
	return f, size, nil
}

// UploadArtifact stores an upload and returns its manifest entry. The body
// is read to a temporary file and renamed under its digest.
func (s *Store) UploadArtifact(ctx context.Context, name, mediaType string, body io.Reader) (ArtifactEntry, error) {
	if !validArtifactName(name) || !validMediaType(mediaType) {
		return ArtifactEntry{}, fmt.Errorf("%w: invalid artifact name or media type", ErrInvalid)
	}
	temp, err := os.CreateTemp(s.artifactDir(), ".upload-*")
	if err != nil {
		return ArtifactEntry{}, err
	}
	keep := false
	defer func() {
		temp.Close()
		if !keep {
			os.Remove(temp.Name())
		}
	}()
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(temp, hash), io.LimitReader(body, artifactMaxSize+1))
	if err != nil {
		return ArtifactEntry{}, err
	}
	if n > artifactMaxSize {
		return ArtifactEntry{}, ErrTooLarge
	}
	if err = temp.Sync(); err != nil {
		return ArtifactEntry{}, err
	}
	entry := ArtifactEntry{Name: name, Size: n, SHA256: hex.EncodeToString(hash.Sum(nil)), MediaType: mediaType}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return entry, err
	}
	defer tx.Rollback()
	now := time.Now()
	until := timestamp(now.Add(artifactUploadHold))
	f, err := storedFile(ctx, tx, entry.SHA256)
	switch {
	case err == nil:
		f.UploadUntil = &until
		if err = putJSON(ctx, tx, `UPDATE artifact_files SET record = ? WHERE sha256 = ?`, f, f.SHA256); err != nil {
			return entry, err
		}
		return entry, tx.Commit()
	case !errors.Is(err, ErrNotFound):
		return entry, err
	}
	stored, pending, err := artifactUsage(ctx, tx)
	if err != nil {
		return entry, err
	}
	if stored+pending+n > s.quota() {
		return entry, fmt.Errorf("%w: the artifact quota is exhausted", ErrInsufficientStorage)
	}
	if err = os.Rename(temp.Name(), s.artifactPath(entry.SHA256)); err != nil {
		return entry, err
	}
	keep = true
	f = artifactFile{SHA256: entry.SHA256, Size: n, CreatedAt: timestamp(now), UploadUntil: &until}
	if err = putJSON(ctx, tx, `INSERT INTO artifact_files (record, sha256) VALUES (?, ?)`, f, f.SHA256); err == nil {
		err = tx.Commit()
	}
	if err != nil {
		os.Remove(s.artifactPath(entry.SHA256))
	}
	return entry, err
}

// Artifacts lists stored files and the quota.
func (s *Store) Artifacts(ctx context.Context) (ArtifactList, error) {
	tx, err := s.readTx(ctx)
	if err != nil {
		return ArtifactList{}, err
	}
	defer tx.Rollback()
	list := ArtifactList{Quota: s.quota(), Files: []ArtifactFileView{}}
	if list.StoredBytes, list.PendingBytes, err = artifactUsage(ctx, tx); err != nil {
		return list, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT f.record, (SELECT COUNT(*) FROM task_artifacts a WHERE a.sha256 = f.sha256 AND json_extract(a.record, '$.state') = 'stored') FROM artifact_files f ORDER BY f.sha256`)
	if err != nil {
		return list, err
	}
	defer rows.Close()
	for rows.Next() {
		var record string
		var tasks int64
		if err = rows.Scan(&record, &tasks); err != nil {
			return list, err
		}
		var f artifactFile
		if err = json.Unmarshal([]byte(record), &f); err != nil {
			return list, err
		}
		list.Files = append(list.Files, ArtifactFileView{SHA256: f.SHA256, Size: f.Size, CreatedAt: f.CreatedAt, UploadUntil: f.UploadUntil, Tasks: tasks})
	}
	return list, rows.Err()
}

// PruneArtifacts releases the artifacts of every final task and every upload
// now, and deletes the files nothing else keeps.
func (s *Store) PruneArtifacts(ctx context.Context) (ArtifactPrune, error) {
	return s.sweepArtifacts(ctx, time.Now(), true)
}

// RunArtifactRetention applies retention at startup and every minute.
func (s *Store) RunArtifactRetention(ctx context.Context) {
	ticker := time.NewTicker(artifactSweep)
	defer ticker.Stop()
	for {
		_, _ = s.sweepArtifacts(ctx, time.Now(), false)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

type taskRef struct{ side, peer, task string }

// releasedTasks lists tasks whose artifacts are released: with all, every
// final task; otherwise those 7 days past their final state, or, for an
// outbound task never accepted, past its deadline.
func releasedTasks(ctx context.Context, tx *sql.Tx, now time.Time, all bool) ([]taskRef, error) {
	var released []taskRef
	due := func(at string) bool {
		t, err := parseTime(at)
		return err == nil && (all || !t.Add(artifactRetention).After(now))
	}
	rows, err := tx.QueryContext(ctx, `SELECT t.sender, t.task_id, t.record FROM received_tasks t WHERE EXISTS (SELECT 1 FROM task_artifacts a WHERE a.side = 'received' AND a.peer = t.sender AND a.task_id = t.task_id AND json_extract(a.record, '$.state') != 'pruned')`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var ref taskRef
		var record string
		if err = rows.Scan(&ref.peer, &ref.task, &record); err != nil {
			break
		}
		var st TaskStatus
		if err = json.Unmarshal([]byte(record), &st); err != nil {
			break
		}
		if taskFinal(st.State) && due(st.UpdatedAt) {
			ref.side = sideReceived
			released = append(released, ref)
		}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return nil, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT t.record FROM outbound_tasks t WHERE EXISTS (SELECT 1 FROM task_artifacts a WHERE a.side = 'sent' AND a.peer = t.peer AND a.task_id = t.task_id AND json_extract(a.record, '$.state') != 'pruned')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		out, err := readJSON[OutboundTask](rows)
		if err != nil {
			return nil, err
		}
		release := false
		switch {
		case out.Status != nil && taskFinal(out.Status.State):
			release = due(out.Status.UpdatedAt)
		case out.SubmitState == submitRejected:
			release = all || due(out.Request.Deadline)
		case out.SubmitState == submitUnknown:
			release = !all && due(out.Request.Deadline)
		}
		if release {
			released = append(released, taskRef{sideSent, out.PeerHostID, out.Request.TaskID})
		}
	}
	return released, rows.Err()
}

// sweepArtifacts releases what retention (or, with all, prune) allows and
// deletes every file that neither an upload hold nor a task keeps.
func (s *Store) sweepArtifacts(ctx context.Context, now time.Time, all bool) (ArtifactPrune, error) {
	var result ArtifactPrune
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	released, err := releasedTasks(ctx, tx, now, all)
	if err != nil {
		return result, err
	}
	for _, ref := range released {
		if _, err = tx.ExecContext(ctx, `UPDATE task_artifacts SET record = json_set(record, '$.state', 'pruned') WHERE side = ? AND peer = ? AND task_id = ? AND json_extract(record, '$.state') != 'pruned'`, ref.side, ref.peer, ref.task); err != nil {
			return result, err
		}
	}
	files, err := allFiles(ctx, tx)
	if err != nil {
		return result, err
	}
	at := timestamp(now)
	for _, f := range files {
		held := false
		if f.UploadUntil != nil {
			until, err := parseTime(*f.UploadUntil)
			held = err == nil && until.After(now) && !all
		}
		if !held && f.UploadUntil != nil {
			f.UploadUntil = nil
			if err = putJSON(ctx, tx, `UPDATE artifact_files SET record = ? WHERE sha256 = ?`, f, f.SHA256); err != nil {
				return result, err
			}
		}
		var used bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM task_artifacts WHERE sha256 = ? AND json_extract(record, '$.state') = 'stored')`, f.SHA256).Scan(&used); err != nil {
			return result, err
		}
		if held || used {
			continue
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM artifact_files WHERE sha256 = ?`, f.SHA256); err != nil {
			return result, err
		}
		if err = appendEvent(ctx, tx, "artifact.pruned", f.SHA256, at); err != nil {
			return result, err
		}
		if err = os.Remove(s.artifactPath(f.SHA256)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return result, err
		}
		result.FilesDeleted++
		result.BytesFreed += f.Size
	}
	return result, tx.Commit()
}

func allFiles(ctx context.Context, tx *sql.Tx) ([]artifactFile, error) {
	rows, err := tx.QueryContext(ctx, `SELECT record FROM artifact_files ORDER BY sha256`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var files []artifactFile
	for rows.Next() {
		f, err := readJSON[artifactFile](rows)
		if err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	return files, rows.Err()
}

// Fetching. Each pending artifact is pulled from the other party of its task
// with backoff, sharing the task workers' slots.

func fetchKey(row taskArtifact) string {
	return "artifact:" + row.Side + "/" + row.PeerHostID + "/" + row.TaskID + "/" + row.Direction + "/" + row.SHA256
}

// pendingFetches lists artifacts to pull: inputs of queued received tasks,
// and results of sent tasks.
func (s *Store) pendingFetches(ctx context.Context) ([]taskArtifact, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT a.record FROM task_artifacts a WHERE json_extract(a.record, '$.state') = 'pending' AND ((a.side = 'received' AND a.direction = 'input' AND EXISTS (SELECT 1 FROM received_tasks t WHERE t.sender = a.peer AND t.task_id = a.task_id AND json_extract(t.record, '$.state') = 'queued')) OR (a.side = 'sent' AND a.direction = 'result')) ORDER BY a.rowid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []taskArtifact
	for rows.Next() {
		row, err := readJSON[taskArtifact](rows)
		if err != nil {
			return nil, err
		}
		items = append(items, row)
	}
	return items, rows.Err()
}

// fetchTimeout allows a slow path for large files.
func fetchTimeout(size int64) time.Duration {
	return 30*time.Second + time.Duration(size/(256<<10))*time.Second
}

// fetchArtifact pulls one pending artifact and stores it once its size and
// digest match. It reports whether the artifact is now stored. The caller
// holds the digest with beginFetch.
func (s *Store) fetchArtifact(ctx context.Context, row taskArtifact) (bool, error) {
	if _, err := storedFile(ctx, s.db, row.SHA256); err == nil {
		return true, s.completeFetch(ctx, row, "")
	} else if !errors.Is(err, ErrNotFound) {
		return false, err
	}
	stored, _, err := artifactUsage(ctx, s.db)
	if err != nil {
		return false, err
	}
	if stored+row.Size > s.quota() {
		return false, errors.New("waiting for artifact quota")
	}
	peer, err := s.dialPeer(ctx, row.PeerHostID)
	if err != nil {
		return false, err
	}
	temp, err := os.CreateTemp(s.artifactDir(), ".fetch-*")
	if err != nil {
		return false, err
	}
	defer func() {
		temp.Close()
		os.Remove(temp.Name())
	}()
	hash := sha256.New()
	fetchCtx, cancel := context.WithTimeout(ctx, fetchTimeout(row.Size))
	defer cancel()
	status, n, err := s.peerDownload(fetchCtx, peer, "/peer/v1/tasks/"+row.TaskID+"/artifacts/"+row.SHA256, io.MultiWriter(temp, hash), row.Size)
	switch {
	case err != nil:
		return false, err
	case status != 200:
		return false, fmt.Errorf("peer returned HTTP %d", status)
	case n != row.Size:
		return false, errors.New("artifact size mismatch")
	case hex.EncodeToString(hash.Sum(nil)) != row.SHA256:
		return false, errors.New("artifact digest mismatch")
	}
	if err = temp.Sync(); err != nil {
		return false, err
	}
	return true, s.completeFetch(ctx, row, temp.Name())
}

// completeFetch stores a verified download under its digest and marks every
// pending entry of that content stored. With no temporary file, the content
// was already stored.
func (s *Store) completeFetch(ctx context.Context, row taskArtifact, temp string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT record FROM task_artifacts WHERE sha256 = ? AND json_extract(record, '$.state') = 'pending' ORDER BY rowid`, row.SHA256)
	if err != nil {
		return err
	}
	var waiting []taskArtifact
	for rows.Next() {
		r, err := readJSON[taskArtifact](rows)
		if err != nil {
			rows.Close()
			return err
		}
		waiting = append(waiting, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(waiting) == 0 {
		return err
	}
	created := false
	now := time.Now()
	if _, err = storedFile(ctx, tx, row.SHA256); errors.Is(err, ErrNotFound) && temp != "" {
		if err = os.Rename(temp, s.artifactPath(row.SHA256)); err != nil {
			return err
		}
		created = true
		err = putJSON(ctx, tx, `INSERT INTO artifact_files (record, sha256) VALUES (?, ?)`, artifactFile{SHA256: row.SHA256, Size: row.Size, CreatedAt: timestamp(now)}, row.SHA256)
	}
	if err == nil {
		for _, r := range waiting {
			r.State = artifactStored
			if err = putJSON(ctx, tx, `UPDATE task_artifacts SET record = ? WHERE side = ? AND peer = ? AND task_id = ? AND direction = ? AND sha256 = ?`, r, r.Side, r.PeerHostID, r.TaskID, r.Direction, r.SHA256); err != nil {
				break
			}
			if temp != "" {
				if err = appendEvent(ctx, tx, "task.artifact_fetched", r.PeerHostID+"/"+r.TaskID+"/"+r.SHA256, timestamp(now)); err != nil {
					break
				}
			}
		}
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil && created {
		os.Remove(s.artifactPath(row.SHA256))
	}
	return err
}

func (s *Store) beginFetch(digest string) bool {
	s.tasks.mu.Lock()
	defer s.tasks.mu.Unlock()
	if s.tasks.fetching == nil {
		s.tasks.fetching = map[string]bool{}
	}
	if s.tasks.fetching[digest] {
		return false
	}
	s.tasks.fetching[digest] = true
	return true
}

func (s *Store) endFetch(digest string) {
	s.tasks.mu.Lock()
	defer s.tasks.mu.Unlock()
	delete(s.tasks.fetching, digest)
}

func (s *Store) fetchBusy(digest string) bool {
	s.tasks.mu.Lock()
	defer s.tasks.mu.Unlock()
	return s.tasks.fetching[digest]
}

// fetchJobs returns the pending fetches that are due, one per digest.
func (s *Store) fetchJobs(ctx context.Context) []taskArtifact {
	items, err := s.pendingFetches(ctx)
	if err != nil {
		return nil
	}
	now := time.Now()
	seen := map[string]bool{}
	var due []taskArtifact
	for _, row := range items {
		if seen[row.SHA256] || s.fetchBusy(row.SHA256) || !s.pollDue(fetchKey(row), now) {
			continue
		}
		seen[row.SHA256] = true
		due = append(due, row)
	}
	return due
}

// manifestAuthority describes a task's input manifest for authorization.
func manifestAuthority(m *MessageRequest, entries []ArtifactEntry) {
	m.artifacts, m.artifactBytes = len(entries), manifestTotal(entries)
}
