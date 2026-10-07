package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
)

func digestOf(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func upload(t *testing.T, s *Store, name, content string) ArtifactEntry {
	t.Helper()
	return must(s.UploadArtifact(context.Background(), name, defaultMediaType, strings.NewReader(content)))
}

// fetchAll runs every due fetch once and reports how many stored.
func fetchAll(t *testing.T, s *Store) int {
	t.Helper()
	stored := 0
	for _, row := range s.fetchJobs(context.Background()) {
		if !s.beginFetch(row.SHA256) {
			continue
		}
		ok, _ := s.fetchArtifact(context.Background(), row)
		s.endFetch(row.SHA256)
		if ok {
			stored++
		} else {
			s.backoffFetch(fetchKey(row))
		}
	}
	return stored
}

type opened struct {
	f    *os.File
	size int64
	err  error
}

func must3(f *os.File, size int64, err error) opened { return opened{f, size, err} }

func readArtifact(t *testing.T, o opened) string {
	t.Helper()
	if o.err != nil {
		t.Fatal(o.err)
	}
	defer o.f.Close()
	data := must(io.ReadAll(o.f))
	if int64(len(data)) != o.size {
		t.Fatalf("size %d, read %d", o.size, len(data))
	}
	return string(data)
}

// artifactGrant is a task.submit grant with an artifact bound.
func (f *taskFixture) artifactGrant(bound int64) Grant {
	return must(f.receiver.CreateGrant(context.Background(), CreateGrant{RequesterHostID: f.sender.Identity().ID, TargetAgentID: f.target.ID, ExpiresAt: timestamp(time.Now().Add(2 * time.Hour)), MaxMessageBytes: 1000, AllowDisconnected: true, Action: membership.PolicyActionTask, MaxArtifactBytes: bound}))
}

func (f *taskFixture) submitWith(g Grant, input string, artifacts []ArtifactEntry) OutboundTask {
	f.t.Helper()
	ctx := context.Background()
	out, err := f.sender.PrepareOutboundTask(ctx, SubmitTask{PeerHostID: f.receiver.Identity().ID, GrantID: &g.ID, TargetAgentID: f.target.ID, Input: input, Artifacts: artifacts})
	if err != nil {
		f.t.Fatal(err)
	}
	return must(f.sender.ExchangeTask(ctx, out.PeerHostID, out.Request.TaskID, false))
}

func TestArtifactManifestValidation(t *testing.T) {
	good := ArtifactEntry{Name: "report.txt", Size: 3, SHA256: digestOf("abc"), MediaType: "text/plain"}
	if !validManifest([]ArtifactEntry{good}) {
		t.Fatal("valid manifest refused")
	}
	bad := map[string]func(*ArtifactEntry){
		"empty name":  func(e *ArtifactEntry) { e.Name = "" },
		"slash":       func(e *ArtifactEntry) { e.Name = "a/b" },
		"backslash":   func(e *ArtifactEntry) { e.Name = `a\b` },
		"nul":         func(e *ArtifactEntry) { e.Name = "a\x00b" },
		"control":     func(e *ArtifactEntry) { e.Name = "a\nb" },
		"c1 control":  func(e *ArtifactEntry) { e.Name = "a\u0085b" },
		"dot":         func(e *ArtifactEntry) { e.Name = "." },
		"dotdot":      func(e *ArtifactEntry) { e.Name = ".." },
		"long name":   func(e *ArtifactEntry) { e.Name = strings.Repeat("a", 256) },
		"invalid utf": func(e *ArtifactEntry) { e.Name = "\xff" },
		"negative":    func(e *ArtifactEntry) { e.Size = -1 },
		"too large":   func(e *ArtifactEntry) { e.Size = artifactMaxSize + 1 },
		"uppercase":   func(e *ArtifactEntry) { e.SHA256 = strings.ToUpper(e.SHA256) },
		"short":       func(e *ArtifactEntry) { e.SHA256 = e.SHA256[:63] },
		"no type":     func(e *ArtifactEntry) { e.MediaType = "" },
		"type tab":    func(e *ArtifactEntry) { e.MediaType = "text/\tplain" },
		"long type":   func(e *ArtifactEntry) { e.MediaType = strings.Repeat("a", 256) },
	}
	for name, change := range bad {
		e := good
		change(&e)
		if validManifest([]ArtifactEntry{e}) {
			t.Errorf("%s accepted", name)
		}
	}
	if !validManifest([]ArtifactEntry{{Name: strings.Repeat("é", 127), Size: artifactMaxSize, SHA256: good.SHA256, MediaType: "a b"}}) {
		t.Error("boundary entry refused")
	}
	other := ArtifactEntry{Name: "other", Size: 1, SHA256: digestOf("x"), MediaType: "x"}
	sameName, sameDigest := other, other
	sameName.Name, sameDigest.SHA256 = good.Name, good.SHA256
	for _, m := range [][]ArtifactEntry{nil, {}, {good, sameName}, {good, sameDigest}} {
		if validManifest(m) {
			t.Errorf("manifest %+v accepted", m)
		}
	}
	many := make([]ArtifactEntry, 65)
	for i := range many {
		many[i] = ArtifactEntry{Name: strings.Repeat("n", i+1), SHA256: digestOf(strings.Repeat("c", i)), MediaType: "x"}
	}
	if validManifest(many) || !validManifest(many[:64]) {
		t.Error("64-entry limit")
	}
	// Entries are strict JSON: exactly four fields, none null.
	var e ArtifactEntry
	for _, data := range []string{`{"name":"a","size":1,"sha256":"x"}`, `{"name":"a","size":1,"sha256":"x","media_type":null}`, `{"name":"a","size":1,"sha256":"x","media_type":"y","z":1}`} {
		if json.Unmarshal([]byte(data), &e) == nil {
			t.Errorf("%s decoded", data)
		}
	}
}

func TestGrantArtifactBound(t *testing.T) {
	ctx := context.Background()
	f := newTaskFixture(t)
	base := CreateGrant{RequesterHostID: f.sender.Identity().ID, TargetAgentID: f.target.ID, ExpiresAt: timestamp(time.Now().Add(time.Hour)), MaxMessageBytes: 10}
	for name, change := range map[string]func(*CreateGrant){
		"message action": func(g *CreateGrant) { g.MaxArtifactBytes = 1 },
		"over 1 GiB":     func(g *CreateGrant) { g.Action, g.MaxArtifactBytes = membership.PolicyActionTask, 1<<30+1 },
		"negative":       func(g *CreateGrant) { g.Action, g.MaxArtifactBytes = membership.PolicyActionTask, -1 },
	} {
		g := base
		change(&g)
		if _, err := f.receiver.CreateGrant(ctx, g); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	g := base
	g.Action, g.MaxArtifactBytes = membership.PolicyActionTask, 1<<30
	created := must(f.receiver.CreateGrant(ctx, g))
	var fields map[string]any
	must(0, json.Unmarshal(must(json.Marshal(created)), &fields))
	if fields["max_artifact_bytes"] != float64(1<<30) || len(fields) != 10 {
		t.Fatalf("grant JSON: %v", fields)
	}
	// The default grant shows 0.
	plain := must(f.receiver.CreateGrant(ctx, base))
	if plain.MaxArtifactBytes != 0 || !strings.Contains(string(must(json.Marshal(plain))), `"max_artifact_bytes":0`) {
		t.Fatalf("default grant: %+v", plain)
	}
}

func TestArtifactLifecycle(t *testing.T) {
	ctx := context.Background()
	f := newTaskFixture(t)
	grant := f.artifactGrant(100)
	input := upload(t, f.sender, "notes.txt", "input bytes")
	if input.Size != 11 || input.SHA256 != digestOf("input bytes") || input.MediaType != defaultMediaType || input.Name != "notes.txt" {
		t.Fatalf("upload entry: %+v", input)
	}
	// An entry that names no stored upload, or the wrong size, is invalid.
	for _, entry := range []ArtifactEntry{{Name: "x", Size: 1, SHA256: digestOf("nothing"), MediaType: "x"}, {Name: "x", Size: 12, SHA256: input.SHA256, MediaType: "x"}} {
		if _, err := f.sender.PrepareOutboundTask(ctx, SubmitTask{PeerHostID: f.receiver.Identity().ID, GrantID: &grant.ID, TargetAgentID: f.target.ID, Input: "x", Artifacts: []ArtifactEntry{entry}}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("unstored entry: %v", err)
		}
	}
	out := f.submitWith(grant, "use the notes", []ArtifactEntry{input})
	if out.SubmitState != submitAccepted || len(out.Request.Artifacts) != 1 {
		t.Fatalf("submission: %+v", out)
	}
	local := must(f.sender.withArtifacts(ctx, out, nil))
	if len(local.Artifacts) != 1 || local.Artifacts[0] != (LocalArtifact{Direction: directionInput, Name: "notes.txt", Size: 11, SHA256: input.SHA256, MediaType: defaultMediaType, State: artifactStored}) {
		t.Fatalf("local artifacts: %+v", local.Artifacts)
	}
	id := out.Request.TaskID
	// The task is not handed off until its input is stored.
	if h := must(f.receiver.NextTask(ctx, f.auth)); h != nil {
		t.Fatalf("handoff before the input is stored: %+v", h)
	}
	// Only the other party of the task can fetch it.
	stranger := startQUICHost(t, t.TempDir()+"/stranger", "127.0.0.1:0").store
	if _, _, err := f.sender.PeerArtifact(ctx, stranger.Identity().ID, id, input.SHA256); !errors.Is(err, ErrNotFound) {
		t.Fatalf("non-party fetch: %v", err)
	}
	if _, _, err := f.sender.PeerArtifact(ctx, f.receiver.Identity().ID, id, digestOf("other")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unlisted digest: %v", err)
	}
	if n := fetchAll(t, f.receiver); n != 1 {
		t.Fatalf("fetched %d", n)
	}
	if kinds := activityKinds(t, f.receiver, "task.artifact"); len(kinds) != 1 {
		t.Fatalf("fetch activity: %v", kinds)
	}
	h := must(f.receiver.NextTask(ctx, f.auth))
	if h == nil || h.Task.TaskID != id || len(h.Task.Artifacts) != 1 || h.Task.Artifacts[0] != input {
		t.Fatalf("handoff: %+v", h)
	}
	if got := readArtifact(t, must3(f.receiver.AdapterTaskArtifact(ctx, f.auth, id, input.SHA256))); got != "input bytes" {
		t.Fatalf("input content %q", got)
	}
	must(f.change(f.auth, id, TaskChange{Op: "accept"}))
	// The result is bounded by what remains of the stored bound: 11 + 90 > 100.
	big := upload(t, f.receiver, "big.bin", strings.Repeat("b", 90))
	if _, err := f.change(f.auth, id, TaskChange{Op: "complete", Status: TaskSucceeded, Output: "done", Artifacts: []ArtifactEntry{big}}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("over the combined bound: %v", err)
	}
	if st := must(f.receiver.SubmitterTask(ctx, f.sender.Identity().ID, id)); st.State != TaskRunning {
		t.Fatalf("refused completion changed state: %+v", st)
	}
	result := upload(t, f.receiver, "result.txt", "result bytes")
	done := must(f.change(f.auth, id, TaskChange{Op: "complete", Status: TaskSucceeded, Output: "done", Artifacts: []ArtifactEntry{result}}))
	if again := must(f.change(f.auth, id, TaskChange{Op: "complete", Status: TaskSucceeded, Output: "done", Artifacts: []ArtifactEntry{result}})); again != done {
		t.Fatalf("identical repeat: %+v", again)
	}
	for _, other := range [][]ArtifactEntry{nil, {big}} {
		if _, err := f.change(f.auth, id, TaskChange{Op: "complete", Status: TaskSucceeded, Output: "done", Artifacts: other}); !errors.Is(err, ErrConflict) {
			t.Fatalf("repeat with other artifacts: %v", err)
		}
	}
	// Status records never show the stored bound.
	if data := string(must(json.Marshal(done))); strings.Contains(data, "max_artifact_bytes") {
		t.Fatalf("status shows the bound: %s", data)
	}
	if got := readArtifact(t, must3(f.receiver.AdapterTaskArtifact(ctx, f.auth, id, result.SHA256))); got != "result bytes" {
		t.Fatalf("result on the receiver %q", got)
	}
	out = f.poll(out)
	events := must(f.sender.OutboundTaskEvents(ctx, out.PeerHostID, id, 0, 10))
	last := events[len(events)-1]
	if last.Kind != TaskSucceeded || len(last.Artifacts) != 1 || last.Artifacts[0] != result || events[0].Artifacts != nil {
		t.Fatalf("events: %+v", events)
	}
	if _, _, err := f.sender.OutboundArtifact(ctx, out.PeerHostID, id, result.SHA256); !errors.Is(err, ErrConflict) {
		t.Fatalf("result before fetch: %v", err)
	}
	if n := fetchAll(t, f.sender); n != 1 {
		t.Fatalf("result fetches %d", n)
	}
	if got := readArtifact(t, must3(f.sender.OutboundArtifact(ctx, out.PeerHostID, id, result.SHA256))); got != "result bytes" {
		t.Fatalf("result on the submitter %q", got)
	}
	local = must(f.sender.withArtifacts(ctx, out, nil))
	if len(local.Artifacts) != 2 || local.Artifacts[1].Direction != directionResult || local.Artifacts[1].State != artifactStored {
		t.Fatalf("local artifacts: %+v", local.Artifacts)
	}
	// Fetching survives revocation: it authorizes no new work.
	must(f.receiver.RevokeGrant(ctx, grant.ID))
	if got := readArtifact(t, must3(f.receiver.PeerArtifact(ctx, f.sender.Identity().ID, id, result.SHA256))); got != "result bytes" {
		t.Fatalf("result after revocation %q", got)
	}

	// Retention keeps a final task's files for 7 days; prune releases them.
	if r := must(f.sender.sweepArtifacts(ctx, time.Now().Add(6*24*time.Hour), false)); r.FilesDeleted != 0 {
		t.Fatalf("early sweep: %+v", r)
	}
	if r := must(f.sender.sweepArtifacts(ctx, time.Now().Add(8*24*time.Hour), false)); r.FilesDeleted != 2 || r.BytesFreed != 23 {
		t.Fatalf("retention sweep: %+v", r)
	}
	local = must(f.sender.withArtifacts(ctx, out, nil))
	if local.Artifacts[0].State != artifactPruned || local.Artifacts[1].State != artifactPruned {
		t.Fatalf("pruned states: %+v", local.Artifacts)
	}
	if _, _, err := f.sender.OutboundArtifact(ctx, out.PeerHostID, id, result.SHA256); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pruned result: %v", err)
	}
	if _, _, err := f.sender.PeerArtifact(ctx, f.receiver.Identity().ID, id, input.SHA256); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pruned input served: %v", err)
	}
	if kinds := activityKinds(t, f.sender, "artifact.pruned"); len(kinds) != 2 {
		t.Fatalf("prune activity: %v", kinds)
	}
	// On the receiver, the unreferenced upload stays until prune.
	r := must(f.receiver.PruneArtifacts(ctx))
	if r.FilesDeleted != 3 {
		t.Fatalf("receiver prune: %+v", r)
	}
	if list := must(f.receiver.Artifacts(ctx)); len(list.Files) != 0 || list.StoredBytes != 0 || list.Quota != DefaultArtifactQuota {
		t.Fatalf("list after prune: %+v", list)
	}
	if entries := must(os.ReadDir(f.receiver.artifactDir())); len(entries) != 0 {
		t.Fatalf("files left: %v", entries)
	}
}

func TestArtifactsRefusedWithoutBound(t *testing.T) {
	ctx := context.Background()
	f := newTaskFixture(t)
	input := upload(t, f.sender, "a", "")
	// A bound of 0 refuses even an empty file.
	if out := f.submitWith(f.grant, "x", []ArtifactEntry{input}); out.SubmitState != submitRejected || !strings.Contains(*out.Error, "403") {
		t.Fatalf("input under bound 0: %+v", out)
	}
	small := f.artifactGrant(5)
	six := upload(t, f.sender, "six", "123456")
	if out := f.submitWith(small, "x", []ArtifactEntry{six}); out.SubmitState != submitRejected {
		t.Fatalf("input over bound: %+v", out)
	}
	// A result under bound 0 is refused and changes nothing.
	out := f.submitWith(f.grant, "no files", nil)
	id := out.Request.TaskID
	must(f.receiver.NextTask(ctx, f.auth))
	must(f.change(f.auth, id, TaskChange{Op: "accept"}))
	result := upload(t, f.receiver, "r", "")
	if _, err := f.change(f.auth, id, TaskChange{Op: "complete", Status: TaskFailed, Output: "x", Artifacts: []ArtifactEntry{result}}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("result under bound 0: %v", err)
	}
	unstored := ArtifactEntry{Name: "u", Size: 1, SHA256: digestOf("u"), MediaType: "x"}
	if _, err := f.change(f.auth, id, TaskChange{Op: "complete", Status: TaskFailed, Output: "x", Artifacts: []ArtifactEntry{unstored}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unstored result: %v", err)
	}
	if st := must(f.change(f.auth, id, TaskChange{Op: "complete", Status: TaskFailed, Output: "x"})); st.State != TaskFailed {
		t.Fatalf("completion without files: %+v", st)
	}
}

func TestArtifactCorruptionAndQuota(t *testing.T) {
	ctx := context.Background()
	f := newTaskFixture(t)
	grant := f.artifactGrant(1 << 20)
	input := upload(t, f.sender, "data", "original")
	out := f.submitWith(grant, "x", []ArtifactEntry{input})
	// A corrupted served file fails the digest check: the task stays queued.
	if err := os.WriteFile(f.sender.artifactPath(input.SHA256), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if n := fetchAll(t, f.receiver); n != 0 {
		t.Fatalf("corrupt fetch stored %d", n)
	}
	if h := must(f.receiver.NextTask(ctx, f.auth)); h != nil {
		t.Fatalf("handoff after a corrupt fetch: %+v", h)
	}
	if entries := must(os.ReadDir(f.receiver.artifactDir())); len(entries) != 0 {
		t.Fatalf("partial download kept: %v", entries)
	}
	// Backoff delays the retry; once due and repaired, the fetch succeeds.
	if err := os.WriteFile(f.sender.artifactPath(input.SHA256), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if n := fetchAll(t, f.receiver); n != 0 {
		t.Fatalf("retry before backoff: %d", n)
	}
	time.Sleep(2100 * time.Millisecond)
	if n := fetchAll(t, f.receiver); n != 1 {
		t.Fatalf("retry after repair: %d", n)
	}
	if h := must(f.receiver.NextTask(ctx, f.auth)); h == nil || h.Task.TaskID != out.Request.TaskID {
		t.Fatalf("handoff after repair: %+v", h)
	}

	// The quota counts stored files and pending fetches.
	must(0, f.receiver.ConfigureArtifacts(19))
	twelve := upload(t, f.sender, "twelve", "123456789012")
	refused := f.submitWith(grant, "x", []ArtifactEntry{twelve})
	if refused.SubmitState != submitUnknown || !strings.Contains(*refused.Error, "507") {
		t.Fatalf("over quota: %+v", refused)
	}
	if _, err := f.receiver.UploadArtifact(ctx, "q", defaultMediaType, strings.NewReader("123456789012345")); !errors.Is(err, ErrInsufficientStorage) {
		t.Fatalf("upload over quota: %v", err)
	}
	// Content already stored needs no quota.
	if _, err := f.receiver.UploadArtifact(ctx, "again", defaultMediaType, strings.NewReader("original")); err != nil {
		t.Fatalf("stored content refused: %v", err)
	}
	must(0, f.receiver.ConfigureArtifacts(1<<20))
	if retried := must(f.sender.ExchangeTask(ctx, refused.PeerHostID, refused.Request.TaskID, false)); retried.SubmitState != submitAccepted {
		t.Fatalf("retry with quota: %+v", retried)
	}
	// Uploads over 100 MiB are refused.
	if _, err := f.receiver.UploadArtifact(ctx, "huge", defaultMediaType, io.LimitReader(zeros{}, artifactMaxSize+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("huge upload: %v", err)
	}
	for _, name := range []string{"", ".", "a/b"} {
		if _, err := f.receiver.UploadArtifact(ctx, name, defaultMediaType, strings.NewReader("x")); !errors.Is(err, ErrInvalid) {
			t.Fatalf("upload name %q: %v", name, err)
		}
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func TestArtifactUploadHoldAndRoutes(t *testing.T) {
	ctx := context.Background()
	f := newTaskFixture(t)
	// Uploads are kept for 24 hours unless a task keeps them.
	entry := upload(t, f.receiver, "x", "held")
	if r := must(f.receiver.sweepArtifacts(ctx, time.Now().Add(23*time.Hour), false)); r.FilesDeleted != 0 {
		t.Fatalf("early: %+v", r)
	}
	if r := must(f.receiver.sweepArtifacts(ctx, time.Now().Add(25*time.Hour), false)); r.FilesDeleted != 1 || r.BytesFreed != 4 {
		t.Fatalf("expired upload: %+v", r)
	}
	// The local API: upload, list, download, and errors.
	handler := Handler(f.receiver)
	call := func(method, path string, body io.Reader) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(method, path, body))
		return w
	}
	w := call("POST", "/v1/artifacts?name=report.md&media_type=text/markdown", strings.NewReader("# hi"))
	var uploaded ArtifactEntry
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &uploaded) != nil || uploaded != (ArtifactEntry{Name: "report.md", Size: 4, SHA256: digestOf("# hi"), MediaType: "text/markdown"}) {
		t.Fatalf("upload: %d %s", w.Code, w.Body)
	}
	for _, query := range []string{"", "?name=", "?name=a&media_type=", "?name=a%2Fb"} {
		if w = call("POST", "/v1/artifacts"+query, strings.NewReader("x")); w.Code != 400 {
			t.Fatalf("upload %q: %d", query, w.Code)
		}
	}
	w = call("GET", "/v1/artifacts", nil)
	var list ArtifactList
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &list) != nil || len(list.Files) != 1 || list.Files[0].UploadUntil == nil || list.StoredBytes != 4 {
		t.Fatalf("list: %s", w.Body)
	}
	if w = call("GET", "/v1/tasks/"+f.sender.Identity().ID+"/"+entry.SHA256[:5]+"/artifacts/"+entry.SHA256, nil); w.Code != 404 {
		t.Fatalf("unknown task download: %d", w.Code)
	}
	w = call("POST", "/v1/artifacts/prune", nil)
	var pruned ArtifactPrune
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &pruned) != nil || pruned.FilesDeleted != 1 {
		t.Fatalf("prune: %s", w.Body)
	}
	// The adapter API needs a credential before reading the body.
	adapter := AdapterHandler(f.receiver)
	req := httptest.NewRequest("POST", "/adapter/v1/artifacts?name=a", bytes.NewReader([]byte("adapter")))
	w = httptest.NewRecorder()
	adapter.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatalf("anonymous adapter upload: %d", w.Code)
	}
	req = httptest.NewRequest("POST", "/adapter/v1/artifacts?name=a", bytes.NewReader([]byte("adapter")))
	req.Header.Set("Authorization", "Bearer "+f.auth.Token)
	req.Header.Set("X-Capsule-Instance", f.auth.Instance)
	w = httptest.NewRecorder()
	adapter.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("adapter upload: %d %s", w.Code, w.Body)
	}
	// Error codes for size and quota.
	for err, want := range map[error]int{ErrTooLarge: http.StatusRequestEntityTooLarge, ErrInsufficientStorage: http.StatusInsufficientStorage} {
		w = httptest.NewRecorder()
		respond(w, 0, nil, err)
		if w.Code != want {
			t.Fatalf("%v: %d", err, w.Code)
		}
	}
}

func TestArtifactPeerWire(t *testing.T) {
	ctx := context.Background()
	f := newTaskFixture(t)
	grant := f.artifactGrant(100)
	input := upload(t, f.sender, "in", "wire")
	r := TaskRequest{TaskID: "task_" + strings.Repeat("1", 32), GrantID: &grant.ID, TargetAgentID: f.target.ID, Deadline: timestamp(time.Now().Add(time.Hour)), Input: "x", Artifacts: []ArtifactEntry{input}}
	sender := f.sender.Identity().ID
	must(f.receiver.AcceptTask(ctx, sender, r))
	must(f.receiver.AcceptTask(ctx, sender, r))
	changed := r
	changed.Artifacts = []ArtifactEntry{{Name: "other", Size: 4, SHA256: input.SHA256, MediaType: input.MediaType}}
	if _, err := f.receiver.AcceptTask(ctx, sender, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed manifest: %v", err)
	}
	empty := r
	empty.TaskID, empty.Artifacts = "task_"+strings.Repeat("2", 32), []ArtifactEntry{}
	if _, err := f.receiver.AcceptTask(ctx, sender, empty); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty wire manifest: %v", err)
	}
	// The request decodes strictly, and the event carries artifacts: null.
	data := must(json.Marshal(r))
	if !strings.Contains(string(data), `"artifacts":[{"name":"in","size":4,"sha256":"`+input.SHA256+`","media_type":"application/octet-stream"}]`) {
		t.Fatalf("request JSON: %s", data)
	}
	without := r
	without.Artifacts = nil
	if strings.Contains(string(must(json.Marshal(without))), "artifacts") {
		t.Fatal("absent manifest serialized")
	}
	events := must(f.receiver.SubmitterTaskEvents(ctx, sender, r.TaskID, 0, 10))
	if data = must(json.Marshal(events[0])); !strings.Contains(string(data), `"artifacts":null`) {
		t.Fatalf("event JSON: %s", data)
	}
	// Event validation on the submitter.
	result := []ArtifactEntry{input}
	for _, e := range []TaskEvent{{Sequence: 1, Kind: "progress", State: TaskRunning, CreatedAt: timestamp(time.Now()), Artifacts: result}, {Sequence: 1, Kind: TaskSucceeded, State: TaskSucceeded, CreatedAt: timestamp(time.Now()), Artifacts: []ArtifactEntry{{Name: "/"}}}} {
		if validTaskEventRecord(e, 1) {
			t.Fatalf("event accepted: %+v", e)
		}
	}
	if !validTaskEventRecord(TaskEvent{Sequence: 1, Kind: TaskFailed, State: TaskFailed, CreatedAt: timestamp(time.Now()), Artifacts: result}, 1) {
		t.Fatal("final event with results refused")
	}
	// The peer route serves raw bytes with an exact length.
	w := httptest.NewRecorder()
	f0, size, err := f.sender.PeerArtifact(ctx, f.receiver.Identity().ID, r.TaskID, input.SHA256)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("a task the sender never submitted: %v", err)
	}
	out := f.submitWith(grant, "y", []ArtifactEntry{input})
	f0, size, err = f.sender.PeerArtifact(ctx, f.receiver.Identity().ID, out.Request.TaskID, input.SHA256)
	serveArtifact(w, f0, size, err)
	if w.Code != 200 || w.Body.String() != "wire" || w.Header().Get("Content-Length") != "4" || w.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("served: %d %v %q", w.Code, w.Header(), w.Body)
	}
}

func TestPolicyArtifactsAndDeadlineCap(t *testing.T) {
	ctx := context.Background()
	network := startCoordinator(t)
	alice, bob := startPeerHost(t, "alice"), startPeerHost(t, "bob")
	id := must(alice.CreateNetwork(ctx, CreateNetwork{Name: "team", Member: "alice", CoordinatorAddress: network.address, CoordinatorPublicKey: network.coord.Identity().PublicKey})).ID
	invite := must(alice.CreateInvite(ctx, id, CreateInvite{Member: "m", ExpiresAt: timestamp(time.Now().Add(time.Hour)), HostOnly: true}))
	must(bob.JoinNetwork(ctx, JoinNetwork{Token: invite.Token}))
	pat, quinn := personKey(t), personKey(t)
	for label, key := range map[string]membership.KeySigner{"pat": pat, "quinn": quinn} {
		must(alice.AdmitPerson(ctx, id, AdmitPerson{PersonPublicKey: membership.EncodeKey(key.PublicKey()), Member: label}))
	}
	bindTo(t, alice, id, pat)
	bindTo(t, bob, id, quinn)
	reviewer := must(alice.RegisterAgent(ctx, RegisterAgent{Name: "reviewer", Owner: "pat"}))
	taskRule := func(bound int64) membership.PolicyRule {
		r := rule("reviewer", 100, true, membership.PrincipalNetwork)
		r.Actions = []string{membership.PolicyActionTask}
		r.MaxArtifactBytes = bound
		return r
	}
	// The policy expires in 30 minutes, sooner than the default hour.
	issued := time.Now().Add(-23*time.Hour - 30*time.Minute)
	must(alice.SubmitPolicy(ctx, id, must(membership.SignPolicy(pat, id, 1, issued, 24*time.Hour, []membership.PolicyRule{taskRule(10)}))))
	for _, s := range []*Store{alice, bob} {
		mustSync(t, s, id)
	}
	submit := func(content string, files []ArtifactEntry) OutboundTask {
		t.Helper()
		out := must(bob.PrepareOutboundTask(ctx, SubmitTask{PeerHostID: alice.Identity().ID, TargetAgentID: reviewer.ID, Input: "x", Artifacts: files}))
		return must(bob.ExchangeTask(ctx, out.PeerHostID, out.Request.TaskID, false))
	}
	ten := upload(t, bob, "ten", "0123456789")
	out := submit("x", []ArtifactEntry{ten})
	deadline := must(parseTime(out.Request.Deadline))
	if out.SubmitState != submitAccepted || deadline.Sub(issued.Add(24*time.Hour)).Abs() > time.Second || time.Until(deadline) > 31*time.Minute {
		t.Fatalf("policy-capped submission: %+v", out)
	}
	eleven := upload(t, bob, "eleven", "0123456789a")
	if out = submit("x", []ArtifactEntry{eleven}); out.SubmitState != submitRejected {
		t.Fatalf("over the rule bound: %+v", out)
	}
	// A rule without the bound refuses artifacts.
	must(alice.SubmitPolicy(ctx, id, must(membership.SignPolicy(pat, id, 2, time.Now(), 24*time.Hour, []membership.PolicyRule{taskRule(0)}))))
	mustSync(t, bob, id)
	if out = submit("x", []ArtifactEntry{ten}); out.SubmitState != submitRejected {
		t.Fatalf("rule without artifacts: %+v", out)
	}
	if out = submit("x", nil); out.SubmitState != submitAccepted || time.Until(must(parseTime(out.Request.Deadline))) < 59*time.Minute {
		t.Fatalf("rule without artifacts, no files: %+v", out)
	}
}
