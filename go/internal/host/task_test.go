package host

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
)

type taskFixture struct {
	t                *testing.T
	receiver, sender *Store
	receiverHost     *quicHost
	target           Agent
	session          Session
	auth             AdapterAuth
	grant            Grant
}

func connectedAdapter(t *testing.T, s *Store, agent Agent, instance string) (Session, AdapterAuth, AdapterCredential) {
	t.Helper()
	ctx := context.Background()
	session := must(s.AttachSession(ctx, AttachSession{AgentID: agent.ID, Integration: "test"}))
	credential := must(s.CreateAdapter(ctx, CreateAdapter{SessionID: session.ID, ExpiresAt: timestamp(time.Now().Add(time.Hour))}))
	auth := AdapterAuth{Token: credential.Token, Instance: "instance_" + strings.Repeat(instance, 64)}
	must(s.ConnectAdapter(ctx, auth.Token, auth.Instance, credential.Adapter.ID, session.ID))
	return session, auth, credential
}

func newTaskFixture(t *testing.T) *taskFixture {
	t.Helper()
	ctx := context.Background()
	receiverHost := startQUICHost(t, filepath.Join(t.TempDir(), "receiver"), "127.0.0.1:0")
	senderHost := startQUICHost(t, filepath.Join(t.TempDir(), "sender"), "127.0.0.1:0")
	f := &taskFixture{t: t, receiver: receiverHost.store, sender: senderHost.store, receiverHost: receiverHost}
	must(f.receiver.AddPeer(ctx, senderHost.peer()))
	must(f.sender.AddPeer(ctx, receiverHost.peer()))
	f.target = must(f.receiver.RegisterAgent(ctx, RegisterAgent{Name: "target", Owner: "pat"}))
	f.session, f.auth, _ = connectedAdapter(t, f.receiver, f.target, "a")
	f.grant = must(f.receiver.CreateGrant(ctx, CreateGrant{RequesterHostID: f.sender.Identity().ID, TargetAgentID: f.target.ID, ExpiresAt: timestamp(time.Now().Add(2 * time.Hour)), MaxMessageBytes: 1000, AllowDisconnected: true, Action: membership.PolicyActionTask}))
	return f
}

func (f *taskFixture) submit(input string, deadline time.Duration) OutboundTask {
	f.t.Helper()
	ctx := context.Background()
	grant := f.grant.ID
	out, err := f.sender.PrepareOutboundTask(ctx, SubmitTask{PeerHostID: f.receiver.Identity().ID, GrantID: &grant, TargetAgentID: f.target.ID, Deadline: timestamp(time.Now().Add(deadline)), Input: input})
	if err != nil {
		f.t.Fatal(err)
	}
	return must(f.sender.ExchangeTask(ctx, out.PeerHostID, out.Request.TaskID, false))
}

// poll fetches until nothing new arrives and returns the local record.
func (f *taskFixture) poll(out OutboundTask) OutboundTask {
	f.t.Helper()
	ctx := context.Background()
	for {
		progressed, err := f.sender.pollTask(ctx, out.PeerHostID, out.Request.TaskID)
		if err != nil {
			f.t.Fatal(err)
		}
		if !progressed {
			return must(f.sender.OutboundTask(ctx, out.PeerHostID, out.Request.TaskID))
		}
	}
}

func (f *taskFixture) change(auth AdapterAuth, id string, c TaskChange) (TaskStatus, error) {
	return f.receiver.ChangeTask(context.Background(), auth, id, c)
}

func eventKinds(events []TaskEvent) string {
	kinds := []string{}
	for _, e := range events {
		kinds = append(kinds, e.Kind+":"+e.State)
	}
	return strings.Join(kinds, " ")
}

func activityKinds(t *testing.T, s *Store, prefix string) []string {
	t.Helper()
	events := must(s.Events(context.Background(), 0, 1000))
	kinds := []string{}
	for _, e := range events {
		if strings.HasPrefix(e.Kind, prefix) {
			kinds = append(kinds, e.Kind)
		}
	}
	return kinds
}

func TestTaskLifecycle(t *testing.T) {
	ctx := context.Background()
	f := newTaskFixture(t)
	out := f.submit("review this", time.Hour)
	if out.SubmitState != submitAccepted || out.Status == nil || out.Status.State != TaskQueued || out.Status.LastEvent != 1 || out.Attempts != 1 || out.NextAttemptAt != nil {
		t.Fatalf("submission: %+v", out)
	}
	id := out.Request.TaskID
	if !validID(id, "task", 16) {
		t.Fatalf("task ID %q", id)
	}
	// A transition before the claim is refused: no session owns the task.
	if _, err := f.change(f.auth, id, TaskChange{Op: "accept"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("accept before claim: %v", err)
	}
	h := must(f.receiver.NextTask(ctx, f.auth))
	if h == nil || h.Task.TaskID != id || h.Task.Input != "review this" || h.Delivery.SessionID != f.session.ID || h.Status.State != TaskQueued || h.SenderPersonID != nil {
		t.Fatalf("handoff: %+v", h)
	}
	if again := must(f.receiver.NextTask(ctx, f.auth)); again != nil {
		t.Fatalf("second claim: %+v", again)
	}
	// Progress before acceptance and completion before running conflict.
	if _, err := f.change(f.auth, id, TaskChange{Op: "progress", Message: "early"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("progress while queued: %v", err)
	}
	st := must(f.change(f.auth, id, TaskChange{Op: "accept"}))
	if st.State != TaskRunning || st.LastEvent != 2 {
		t.Fatalf("accepted: %+v", st)
	}
	if again := must(f.change(f.auth, id, TaskChange{Op: "accept"})); again != st {
		t.Fatalf("repeated accept: %+v", again)
	}
	must(f.change(f.auth, id, TaskChange{Op: "progress", Message: "half"}))
	if again := must(f.change(f.auth, id, TaskChange{Op: "progress", Message: "half"})); again.LastEvent != 3 {
		t.Fatalf("identical progress appended: %+v", again)
	}
	must(f.change(f.auth, id, TaskChange{Op: "progress", Message: "most"}))
	// The submitter resumes from its cursor: poll part, then the rest.
	out = f.poll(out)
	if out.EventsAfter != 4 || out.Status.State != TaskRunning {
		t.Fatalf("polled: %+v", out)
	}
	st = must(f.change(f.auth, id, TaskChange{Op: "complete", Status: TaskSucceeded, Output: "looks good"}))
	if st.State != TaskSucceeded || st.LastEvent != 5 {
		t.Fatalf("completed: %+v", st)
	}
	if again := must(f.change(f.auth, id, TaskChange{Op: "complete", Status: TaskSucceeded, Output: "looks good"})); again != st {
		t.Fatalf("identical completion: %+v", again)
	}
	if _, err := f.change(f.auth, id, TaskChange{Op: "complete", Status: TaskFailed, Output: "changed"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed completion: %v", err)
	}
	if _, err := f.change(f.auth, id, TaskChange{Op: "progress", Message: "after"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("progress after completion: %v", err)
	}
	out = f.poll(out)
	if out.needsPoll() || out.EventsAfter != 5 || *out.Status != st {
		t.Fatalf("final record: %+v", out)
	}
	events := must(f.sender.OutboundTaskEvents(ctx, out.PeerHostID, id, 0, 100))
	if got := eventKinds(events); got != "queued:queued accepted:running progress:running progress:running succeeded:succeeded" {
		t.Fatalf("events: %s", got)
	}
	if events[4].Output == nil || *events[4].Output != "looks good" || events[2].Message == nil || *events[2].Message != "half" || events[0].Message != nil {
		t.Fatalf("event fields: %+v", events)
	}
	if page := must(f.sender.OutboundTaskEvents(ctx, out.PeerHostID, id, 3, 1)); len(page) != 1 || page[0].Sequence != 4 {
		t.Fatalf("cursor page: %+v", page)
	}
	// The wire events match the stored ones.
	remote := must(f.receiver.SubmitterTaskEvents(ctx, f.sender.Identity().ID, id, 0, 1000))
	if string(rawJSON(t, remote)) != string(rawJSON(t, events)) {
		t.Fatalf("remote %s\nlocal %s", rawJSON(t, remote), rawJSON(t, events))
	}
	if got := strings.Join(activityKinds(t, f.receiver, "task."), " "); got != "task.received task.accepted task.progress task.progress task.completed" {
		t.Fatalf("receiver activity: %s", got)
	}
	if got := strings.Join(activityKinds(t, f.sender, "task."), " "); got != "task.submitted task.updated task.updated task.updated task.updated task.updated task.updated" {
		t.Fatalf("sender activity: %s", got)
	}
	// Status, events, and cancel are for the submitter only.
	other := "host_" + strings.Repeat("0", 64)
	if _, err := f.receiver.SubmitterTask(ctx, other, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("status for another sender: %v", err)
	}
	if _, err := f.receiver.SubmitterTaskEvents(ctx, other, id, 0, 10); !errors.Is(err, ErrNotFound) {
		t.Fatalf("events for another sender: %v", err)
	}
	if _, err := f.receiver.RequestTaskCancel(ctx, other, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cancel for another sender: %v", err)
	}
	if _, err := f.receiver.SubmitterTaskEvents(ctx, f.sender.Identity().ID, id, 0, 1001); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized page: %v", err)
	}
	// Cancelling a final task changes nothing.
	if st := must(f.receiver.RequestTaskCancel(ctx, f.sender.Identity().ID, id)); st.CancelRequested || st.LastEvent != 5 {
		t.Fatalf("cancel after completion: %+v", st)
	}
	if local := must(f.sender.CancelOutboundTask(ctx, out.PeerHostID, id)); local.CancelState != nil {
		t.Fatalf("local cancel after completion: %+v", local)
	}
}

func TestTaskSubmissionIsIdempotentAndAuthorized(t *testing.T) {
	ctx := context.Background()
	f := newTaskFixture(t)
	sender := f.sender.Identity().ID
	grant := f.grant.ID
	request := TaskRequest{TaskID: "task_" + strings.Repeat("1", 32), GrantID: &grant, TargetAgentID: f.target.ID, Deadline: timestamp(time.Now().Add(time.Hour)), Input: "x"}
	// The receiver accepted, but the response was lost: an automatic retry
	// with the same ID returns the original record without a second task.
	first := must(f.receiver.AcceptTask(ctx, sender, request))
	out, err := f.sender.PrepareOutboundTask(ctx, SubmitTask{PeerHostID: f.receiver.Identity().ID, TaskID: request.TaskID, GrantID: &grant, TargetAgentID: request.TargetAgentID, Deadline: request.Deadline, Input: request.Input})
	if err != nil || out.SubmitState != submitUnknown || out.NextAttemptAt == nil {
		t.Fatalf("prepared: %+v %v", out, err)
	}
	if out = must(f.sender.ExchangeTask(ctx, out.PeerHostID, request.TaskID, false)); out.SubmitState != submitAccepted || *out.Status != first {
		t.Fatalf("retry: %+v", out)
	}
	var count int
	if err = f.receiver.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM received_tasks").Scan(&count); err != nil || count != 1 {
		t.Fatalf("received tasks: %d %v", count, err)
	}
	changed := request
	changed.Input = "y"
	if _, err = f.receiver.AcceptTask(ctx, sender, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed resubmission: %v", err)
	}
	// Locally, the same ID with other fields conflicts; omitting the deadline
	// keeps the original.
	if _, err = f.sender.PrepareOutboundTask(ctx, SubmitTask{PeerHostID: f.receiver.Identity().ID, TaskID: request.TaskID, GrantID: &grant, TargetAgentID: request.TargetAgentID, Input: "y"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("local conflict: %v", err)
	}
	if same := must(f.sender.PrepareOutboundTask(ctx, SubmitTask{PeerHostID: f.receiver.Identity().ID, TaskID: request.TaskID, GrantID: &grant, TargetAgentID: request.TargetAgentID, Input: "x"})); same.SubmitState != submitAccepted {
		t.Fatalf("identical local resubmission: %+v", same)
	}
	// Validation.
	for name, r := range map[string]func(*TaskRequest){
		"id":       func(r *TaskRequest) { r.TaskID = "request_" + strings.Repeat("1", 32) },
		"input":    func(r *TaskRequest) { r.Input = "" },
		"large":    func(r *TaskRequest) { r.Input = strings.Repeat("x", 65537) },
		"deadline": func(r *TaskRequest) { r.Deadline = "tomorrow" },
		"both": func(r *TaskRequest) {
			r.Policy = &PolicyCitation{PersonID: "person_" + strings.Repeat("a", 64), Version: 1}
		},
		"none": func(r *TaskRequest) { r.GrantID = nil },
	} {
		bad := request
		bad.TaskID = "task_" + strings.Repeat("2", 32)
		r(&bad)
		if _, err := f.receiver.AcceptTask(ctx, sender, bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The grant's action decides: a message grant refuses tasks, and a task
	// grant refuses messages. The grant's byte bound limits the input.
	messageGrant := must(f.receiver.CreateGrant(ctx, CreateGrant{RequesterHostID: sender, TargetAgentID: f.target.ID, ExpiresAt: timestamp(time.Now().Add(time.Hour)), MaxMessageBytes: 1000, AllowDisconnected: true}))
	if messageGrant.Action != membership.PolicyActionMessage {
		t.Fatalf("default action: %+v", messageGrant)
	}
	bad := request
	bad.TaskID, bad.GrantID = "task_"+strings.Repeat("3", 32), &messageGrant.ID
	if _, err = f.receiver.AcceptTask(ctx, sender, bad); !errors.Is(err, ErrForbidden) {
		t.Fatalf("task under a message grant: %v", err)
	}
	if _, err = f.receiver.AcceptMessage(ctx, sender, MessageRequest{RequestID: "request_" + strings.Repeat("3", 32), GrantID: &grant, TargetAgentID: f.target.ID, Deadline: request.Deadline, Content: "x"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("message under a task grant: %v", err)
	}
	bad.GrantID, bad.Input = &grant, strings.Repeat("x", 1001)
	if _, err = f.receiver.AcceptTask(ctx, sender, bad); !errors.Is(err, ErrForbidden) {
		t.Fatalf("input over the grant bound: %v", err)
	}
	if _, err = f.receiver.CreateGrant(ctx, CreateGrant{RequesterHostID: sender, TargetAgentID: f.target.ID, ExpiresAt: timestamp(time.Now().Add(time.Hour)), MaxMessageBytes: 1, Action: "shell.exec"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown action: %v", err)
	}
	if code, body := localCall(t, f.receiver, "POST", "/v1/grants", map[string]any{"requester_host_id": sender, "target_agent_id": f.target.ID, "expires_at": timestamp(time.Now().Add(time.Hour)), "max_message_bytes": 1, "allow_disconnected": false, "action": nil}); code != http.StatusBadRequest {
		t.Fatalf("null action: %d %s", code, body)
	}
	// A refused submission is rejected on the sender, and a blocked sender
	// is refused under a valid grant.
	must(f.receiver.Block(ctx, BlockAccess{Host: sender}))
	refused := f.submit("blocked", time.Hour)
	if refused.SubmitState != submitRejected || refused.Error == nil || !strings.Contains(*refused.Error, "403") || refused.NextAttemptAt != nil {
		t.Fatalf("blocked submission: %+v", refused)
	}
}

func TestTaskRejectionExpiryAndFailure(t *testing.T) {
	ctx := context.Background()
	f := newTaskFixture(t)
	rejected := f.submit("no", time.Hour)
	failed := f.submit("try", time.Hour)
	must(f.receiver.NextTask(ctx, f.auth))
	must(f.receiver.NextTask(ctx, f.auth))
	if _, err := f.change(f.auth, rejected.Request.TaskID, TaskChange{Op: "reject", Reason: "busy"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.change(f.auth, rejected.Request.TaskID, TaskChange{Op: "reject", Reason: "busy"}); err != nil {
		t.Fatalf("identical reject: %v", err)
	}
	if _, err := f.change(f.auth, rejected.Request.TaskID, TaskChange{Op: "reject", Reason: "other"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed reject: %v", err)
	}
	if _, err := f.change(f.auth, rejected.Request.TaskID, TaskChange{Op: "accept"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("accept after reject: %v", err)
	}
	must(f.change(f.auth, failed.Request.TaskID, TaskChange{Op: "accept"}))
	must(f.change(f.auth, failed.Request.TaskID, TaskChange{Op: "complete", Status: TaskFailed, Output: "broke"}))
	if r := f.poll(rejected); r.Status.State != TaskRejected || r.needsPoll() {
		t.Fatalf("rejected: %+v", r)
	}
	events := must(f.sender.OutboundTaskEvents(ctx, rejected.PeerHostID, rejected.Request.TaskID, 0, 10))
	if eventKinds(events) != "queued:queued rejected:rejected" || *events[1].Message != "busy" {
		t.Fatalf("rejected events: %+v", events)
	}
	if r := f.poll(failed); r.Status.State != TaskFailed {
		t.Fatalf("failed: %+v", r)
	}
	// An empty rejection reason is allowed; an invalid body is not.
	if _, err := f.change(f.auth, failed.Request.TaskID, TaskChange{Op: "complete", Status: "done", Output: "x"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid status: %v", err)
	}
	// A queued task expires at its deadline, claimed or not, and cannot then
	// be accepted.
	short := f.submit("soon", 1500*time.Millisecond)
	unclaimed := f.submit("soon too", 1500*time.Millisecond)
	if h := must(f.receiver.NextTask(ctx, f.auth)); h == nil || h.Task.TaskID != short.Request.TaskID {
		t.Fatalf("claim: %+v", h)
	}
	time.Sleep(1600 * time.Millisecond)
	if _, err := f.change(f.auth, short.Request.TaskID, TaskChange{Op: "accept"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("accept after the deadline: %v", err)
	}
	for _, out := range []OutboundTask{short, unclaimed} {
		if r := f.poll(out); r.Status.State != TaskExpired {
			t.Fatalf("expired: %+v", r)
		}
	}
	if h := must(f.receiver.NextTask(ctx, f.auth)); h != nil {
		t.Fatalf("expired task handed off: %+v", h)
	}
	if got := strings.Join(activityKinds(t, f.receiver, "task.expired"), " "); got != "task.expired task.expired" {
		t.Fatalf("expiry activity: %s", got)
	}
}

func TestTaskCancellation(t *testing.T) {
	ctx := context.Background()
	f := newTaskFixture(t)
	confirmed := f.submit("long", time.Hour)
	ignored := f.submit("short", time.Hour)
	for range 2 {
		must(f.receiver.NextTask(ctx, f.auth))
	}
	// Confirming a cancellation nobody requested conflicts.
	must(f.change(f.auth, confirmed.Request.TaskID, TaskChange{Op: "accept"}))
	must(f.change(f.auth, ignored.Request.TaskID, TaskChange{Op: "accept"}))
	if _, err := f.change(f.auth, confirmed.Request.TaskID, TaskChange{Op: "cancelled"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("unrequested cancel: %v", err)
	}
	if c := must(f.receiver.NextTaskCancel(ctx, f.auth)); c != nil {
		t.Fatalf("cancel without a request: %+v", c)
	}
	local := must(f.sender.CancelOutboundTask(ctx, confirmed.PeerHostID, confirmed.Request.TaskID))
	if local.CancelState == nil || *local.CancelState != cancelSent || !local.Status.CancelRequested || local.Status.State != TaskRunning {
		t.Fatalf("local cancel: %+v", local)
	}
	// Requesting again is idempotent on the wire.
	if st := must(f.receiver.RequestTaskCancel(ctx, f.sender.Identity().ID, confirmed.Request.TaskID)); st.LastEvent != 3 {
		t.Fatalf("repeated cancel: %+v", st)
	}
	must(f.sender.CancelOutboundTask(ctx, ignored.PeerHostID, ignored.Request.TaskID))
	first := must(f.receiver.NextTaskCancel(ctx, f.auth))
	second := must(f.receiver.NextTaskCancel(ctx, f.auth))
	if first == nil || second == nil || first.Delivery.TaskID != confirmed.Request.TaskID || second.Delivery.TaskID != ignored.Request.TaskID || first.Delivery.CancelClaimedAt == nil {
		t.Fatalf("cancel claims: %+v %+v", first, second)
	}
	if c := must(f.receiver.NextTaskCancel(ctx, f.auth)); c != nil {
		t.Fatalf("cancel claimed twice: %+v", c)
	}
	must(f.change(f.auth, confirmed.Request.TaskID, TaskChange{Op: "cancelled"}))
	if again := must(f.change(f.auth, confirmed.Request.TaskID, TaskChange{Op: "cancelled"})); again.State != TaskCancelled {
		t.Fatalf("repeated cancelled: %+v", again)
	}
	must(f.change(f.auth, ignored.Request.TaskID, TaskChange{Op: "complete", Status: TaskSucceeded, Output: "done anyway"}))
	a, b := f.poll(confirmed), f.poll(ignored)
	if a.Status.State != TaskCancelled || b.Status.State != TaskSucceeded || !b.Status.CancelRequested {
		t.Fatalf("outcomes: %+v %+v", a.Status, b.Status)
	}
	if got := eventKinds(must(f.sender.OutboundTaskEvents(ctx, a.PeerHostID, a.Request.TaskID, 0, 10))); got != "queued:queued accepted:running cancel_requested:running cancelled:cancelled" {
		t.Fatalf("cancelled events: %s", got)
	}
}

func TestTaskRefusesOtherSessionsAndLapsedAuthorization(t *testing.T) {
	ctx := context.Background()
	f := newTaskFixture(t)
	out := f.submit("mine", time.Hour)
	must(f.receiver.NextTask(ctx, f.auth))
	// Another session of the same agent cannot change the claimed task.
	must(f.receiver.DetachSession(ctx, f.session.ID))
	_, otherAuth, _ := connectedAdapter(t, f.receiver, f.target, "b")
	if _, err := f.change(otherAuth, out.Request.TaskID, TaskChange{Op: "accept"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("other session: %v", err)
	}
	if _, err := f.change(otherAuth, "task_"+strings.Repeat("9", 32), TaskChange{Op: "accept"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown task: %v", err)
	}
	if _, err := f.change(AdapterAuth{Token: "token_" + strings.Repeat("0", 64), Instance: otherAuth.Instance}, out.Request.TaskID, TaskChange{Op: "accept"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unknown credential: %v", err)
	}
	// The new session receives new tasks. Revoking the grant before
	// acceptance rejects a queued task at handoff, and at acceptance.
	accepted := f.submit("keep going", time.Hour)
	atHandoff := f.submit("lapse at handoff", time.Hour)
	if h := must(f.receiver.NextTask(ctx, otherAuth)); h == nil || h.Task.TaskID != accepted.Request.TaskID {
		t.Fatalf("claim: %+v", h)
	}
	must(f.change(otherAuth, accepted.Request.TaskID, TaskChange{Op: "accept"}))
	pending := f.submit("lapse at accept", time.Hour)
	// Claim atHandoff's successor ordering: atHandoff is next, then pending.
	if h := must(f.receiver.NextTask(ctx, otherAuth)); h == nil || h.Task.TaskID != atHandoff.Request.TaskID {
		t.Fatalf("claim: %+v", h)
	}
	must(f.receiver.RevokeGrant(ctx, f.grant.ID))
	if _, err := f.change(otherAuth, atHandoff.Request.TaskID, TaskChange{Op: "accept"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("accept after revocation: %v", err)
	}
	if h := must(f.receiver.NextTask(ctx, otherAuth)); h != nil {
		t.Fatalf("handoff after revocation: %+v", h)
	}
	for _, o := range []OutboundTask{atHandoff, pending} {
		r := f.poll(o)
		events := must(f.sender.OutboundTaskEvents(ctx, o.PeerHostID, o.Request.TaskID, 0, 10))
		if r.Status.State != TaskRejected || *events[len(events)-1].Message != taskLapsed {
			t.Fatalf("lapsed: %+v %+v", r.Status, events)
		}
	}
	// The accepted task belongs to its agent: it can still finish.
	must(f.change(otherAuth, accepted.Request.TaskID, TaskChange{Op: "progress", Message: "still here"}))
	must(f.change(otherAuth, accepted.Request.TaskID, TaskChange{Op: "complete", Status: TaskSucceeded, Output: "ok"}))
	// Status remains available to the submitter after revocation.
	if r := f.poll(accepted); r.Status.State != TaskSucceeded {
		t.Fatalf("after revocation: %+v", r)
	}
}

func TestAdapterTaskRoutesAndUpdates(t *testing.T) {
	ctx := context.Background()
	f := newTaskFixture(t)
	author := must(f.sender.RegisterAgent(ctx, RegisterAgent{Name: "author", Owner: "quinn"}))
	session, auth, credential := connectedAdapter(t, f.sender, author, "c")
	expires := timestamp(time.Now().Add(30 * time.Minute))
	grant := f.grant.ID
	route := must(f.sender.CreateOutboundRoute(ctx, CreateOutboundRoute{AdapterID: credential.Adapter.ID, Name: "review", PeerHostID: f.receiver.Identity().ID, TargetAgentID: f.target.ID, GrantID: &grant, ExpiresAt: expires, MaxMessageBytes: 100, MaxMessages: 2, Action: membership.PolicyActionTask}))
	messages := must(f.sender.CreateOutboundRoute(ctx, CreateOutboundRoute{AdapterID: credential.Adapter.ID, Name: "chat", PeerHostID: f.receiver.Identity().ID, TargetAgentID: f.target.ID, GrantID: &grant, ExpiresAt: expires, MaxMessageBytes: 100, MaxMessages: 2}))
	if route.Action != membership.PolicyActionTask || messages.Action != membership.PolicyActionMessage {
		t.Fatalf("route actions: %+v %+v", route, messages)
	}
	if _, err := f.sender.CreateOutboundRoute(ctx, CreateOutboundRoute{AdapterID: credential.Adapter.ID, Name: "bad", PeerHostID: f.receiver.Identity().ID, TargetAgentID: f.target.ID, GrantID: &grant, ExpiresAt: expires, MaxMessageBytes: 100, MaxMessages: 2, Action: "x"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid route action: %v", err)
	}
	destinations := must(f.sender.Destinations(ctx, auth))
	if len(destinations) != 2 || destinations[0].Name != "chat" || destinations[0].Action != membership.PolicyActionMessage || destinations[1].Action != membership.PolicyActionTask {
		t.Fatalf("destinations: %+v", destinations)
	}
	// Each route serves only its own action.
	if _, err := f.sender.PrepareAdapterSend(ctx, auth, AdapterSend{Destination: "review", RequestID: "request_" + strings.Repeat("4", 32), Content: "x"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("send through a task route: %v", err)
	}
	taskID := "task_" + strings.Repeat("4", 32)
	if _, err := f.sender.PrepareAdapterTask(ctx, auth, AdapterDelegate{Destination: "chat", TaskID: taskID, Input: "x"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("delegate through a message route: %v", err)
	}
	if _, err := f.sender.PrepareAdapterTask(ctx, auth, AdapterDelegate{Destination: "review", TaskID: taskID, Input: strings.Repeat("x", 101)}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("input over the route bound: %v", err)
	}
	out := must(f.sender.PrepareAdapterTask(ctx, auth, AdapterDelegate{Destination: "review", TaskID: taskID, Input: "please review"}))
	if out.Request.Origin == nil || *out.Request.Origin != (Origin{AgentID: author.ID, SessionID: session.ID}) || *out.AdapterID != credential.Adapter.ID || *out.RouteID != route.ID {
		t.Fatalf("delegated: %+v", out)
	}
	if again := must(f.sender.PrepareAdapterTask(ctx, auth, AdapterDelegate{Destination: "review", TaskID: taskID, Input: "please review"})); !again.Request.same(out.Request) {
		t.Fatalf("identical delegation: %+v", again)
	}
	if _, err := f.sender.PrepareAdapterTask(ctx, auth, AdapterDelegate{Destination: "review", TaskID: taskID, Input: "other"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed delegation: %v", err)
	}
	out = must(f.sender.ExchangeTask(ctx, out.PeerHostID, taskID, false))
	if out.SubmitState != submitAccepted {
		t.Fatalf("submitted: %+v", out)
	}
	// The budget counts tasks.
	if destinations = must(f.sender.Destinations(ctx, auth)); destinations[1].MessagesRemaining != 1 {
		t.Fatalf("budget: %+v", destinations)
	}
	if status := must(f.sender.AdapterTask(ctx, auth, taskID)); status.Request.TaskID != taskID {
		t.Fatalf("task status: %+v", status)
	}
	if _, err := f.sender.AdapterTask(ctx, auth, "task_"+strings.Repeat("5", 32)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown task status: %v", err)
	}
	// The receiver sees the origin; updates return to the originating session.
	h := must(f.receiver.NextTask(ctx, f.auth))
	if h == nil || h.Task.Origin == nil || h.Task.Origin.SessionID != session.ID {
		t.Fatalf("handoff: %+v", h)
	}
	must(f.change(f.auth, taskID, TaskChange{Op: "accept"}))
	must(f.change(f.auth, taskID, TaskChange{Op: "complete", Status: TaskSucceeded, Output: "approved"}))
	f.poll(out)
	var kinds []string
	for {
		u := must(f.sender.NextTaskUpdate(ctx, auth))
		if u == nil {
			break
		}
		if u.Delivery.TaskID != taskID || u.Delivery.SessionID != session.ID || u.Delivery.State != "unknown" || u.Delivery.Sequence != u.Event.Sequence {
			t.Fatalf("update: %+v", u)
		}
		kinds = append(kinds, u.Event.Kind)
		// Another credential cannot acknowledge it.
		if _, err := f.sender.TaskUpdateForwarded(ctx, AdapterAuth{}, u.Delivery.ID); err == nil {
			t.Fatal("acknowledged without a credential")
		}
		if d := must(f.sender.TaskUpdateForwarded(ctx, auth, u.Delivery.ID)); d.State != "forwarded" {
			t.Fatalf("forwarded: %+v", d)
		}
	}
	if strings.Join(kinds, " ") != "queued accepted succeeded" {
		t.Fatalf("updates: %v", kinds)
	}
	// Owner submissions are never handed to sessions.
	f.poll(f.submit("owner", time.Hour))
	if u := must(f.sender.NextTaskUpdate(ctx, auth)); u != nil {
		t.Fatalf("owner task update: %+v", u)
	}
}

func TestTaskPolicyAuthorization(t *testing.T) {
	ctx := context.Background()
	network := startCoordinator(t)
	alice, bob := startPeerHost(t, "alice"), startPeerHost(t, "bob")
	created := must(alice.CreateNetwork(ctx, CreateNetwork{Name: "team", Member: "alice", CoordinatorAddress: network.address, CoordinatorPublicKey: network.coord.Identity().PublicKey}))
	id := created.ID
	invite := must(alice.CreateInvite(ctx, id, CreateInvite{Member: "bob", ExpiresAt: timestamp(time.Now().Add(time.Hour)), HostOnly: true}))
	must(bob.JoinNetwork(ctx, JoinNetwork{Token: invite.Token}))
	pat := personKey(t)
	must(alice.AdmitPerson(ctx, id, AdmitPerson{PersonPublicKey: membership.EncodeKey(pat.PublicKey()), Member: "pat"}))
	bindTo(t, alice, id, pat)
	reviewer := must(alice.RegisterAgent(ctx, RegisterAgent{Name: "reviewer", Owner: "pat"}))
	submit := func(state string) {
		t.Helper()
		out, err := bob.PrepareOutboundTask(ctx, SubmitTask{PeerHostID: alice.Identity().ID, TargetAgentID: reviewer.ID, Input: "work"})
		if err == nil {
			out, err = bob.ExchangeTask(ctx, out.PeerHostID, out.Request.TaskID, false)
		}
		if err != nil || out.SubmitState != state || out.Request.Policy == nil || out.Request.GrantID != nil {
			t.Fatalf("policy task: want %s, got %+v %v", state, out, err)
		}
	}
	// A message-only rule refuses tasks; a rule with task.submit allows them.
	messageOnly := must(membership.SignPolicy(pat, id, 1, time.Now(), 7*24*time.Hour, []membership.PolicyRule{rule("reviewer", 100, true, membership.PrincipalNetwork)}))
	must(alice.SubmitPolicy(ctx, id, messageOnly))
	mustSync(t, alice, id)
	mustSync(t, bob, id)
	submit(submitRejected)
	tasks := rule("reviewer", 100, true, membership.PrincipalNetwork)
	tasks.Actions = []string{membership.PolicyActionMessage, membership.PolicyActionTask}
	withTasks := must(membership.SignPolicy(pat, id, 2, time.Now(), 7*24*time.Hour, []membership.PolicyRule{tasks}))
	must(alice.SubmitPolicy(ctx, id, withTasks))
	mustSync(t, alice, id)
	mustSync(t, bob, id)
	submit(submitAccepted)
	bad := tasks
	bad.Actions = []string{"task.forward"}
	if _, err := membership.SignPolicy(pat, id, 3, time.Now(), 7*24*time.Hour, []membership.PolicyRule{bad}); err == nil {
		t.Fatal("unknown policy action signed")
	}
}

func TestAdapterTaskHTTPBodies(t *testing.T) {
	f := newTaskFixture(t)
	out := f.submit("x", time.Hour)
	must(f.receiver.NextTask(context.Background(), f.auth))
	call := func(path, body string) int {
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+f.auth.Token)
		req.Header.Set("X-Capsule-Instance", f.auth.Instance)
		w := httptest.NewRecorder()
		AdapterHandler(f.receiver).ServeHTTP(w, req)
		return w.Code
	}
	base := "/adapter/v1/tasks/" + out.Request.TaskID
	for path, body := range map[string]string{
		"/accept":   `{"x":1}`,
		"/reject":   `{}`,
		"/progress": `{"message":null}`,
		"/complete": `{"status":"succeeded"}`,
	} {
		if code := call(base+path, body); code != http.StatusBadRequest {
			t.Errorf("%s %s: %d", path, body, code)
		}
	}
	if code := call(base+"/accept", `{}`); code != http.StatusOK {
		t.Fatalf("accept: %d", code)
	}
	if code := call(base+"/complete", `{"status":"failed","output":"no"}`); code != http.StatusOK {
		t.Fatalf("complete: %d", code)
	}
	var status TaskStatus
	req := httptest.NewRequest("POST", base+"/cancelled", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+f.auth.Token)
	req.Header.Set("X-Capsule-Instance", f.auth.Instance)
	w := httptest.NewRecorder()
	AdapterHandler(f.receiver).ServeHTTP(w, req)
	if w.Code != http.StatusConflict || json.Unmarshal(w.Body.Bytes(), &status) != nil {
		t.Fatalf("cancelled without a request: %d %s", w.Code, w.Body.String())
	}
}

const dropArtifactTables = "DROP TABLE directory_sends; DROP TABLE policy_deliveries; DROP TABLE task_children; DROP TABLE artifact_files; DROP TABLE task_artifacts"
const dropTaskTables = dropArtifactTables + "; DROP TABLE received_tasks; DROP TABLE task_events; DROP TABLE outbound_tasks; DROP TABLE outbound_task_events; DROP TABLE task_deliveries; DROP TABLE task_update_notifications"

func TestTaskMigrationToVersion10(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "host")
	s := must(Open(ctx, dir))
	agent := must(s.RegisterAgent(ctx, RegisterAgent{Name: "kept", Owner: "pat"}))
	if _, err := s.db.ExecContext(ctx, dropTaskTables+"; PRAGMA user_version = 8"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s = must(Open(ctx, dir))
	defer s.Close()
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil || version != 13 {
		t.Fatalf("version %d %v", version, err)
	}
	if kept := must(s.Agent(ctx, agent.ID)); kept.Name != "kept" {
		t.Fatalf("agent: %+v", kept)
	}
	if tasks := must(s.OutboundTasks(ctx, 0, 10)); len(tasks) != 0 {
		t.Fatalf("tasks: %+v", tasks)
	}
}

func TestTaskRetryAndPollSchedules(t *testing.T) {
	ctx := context.Background()
	f := newTaskFixture(t)
	// An unreachable receiver leaves the submission unknown with a backoff.
	f.receiverHost.stop()
	grant := f.grant.ID
	out := must(f.sender.PrepareOutboundTask(ctx, SubmitTask{PeerHostID: f.receiver.Identity().ID, GrantID: &grant, TargetAgentID: f.target.ID, Input: "x"}))
	if deadline := must(parseTime(out.Request.Deadline)); deadline.Sub(time.Now()) < 59*time.Minute {
		t.Fatalf("default deadline: %s", out.Request.Deadline)
	}
	short, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, _ = f.sender.ExchangeTask(short, out.PeerHostID, out.Request.TaskID, false)
	if out.SubmitState != submitUnknown || out.Attempts != 1 || out.NextAttemptAt == nil || out.Error == nil {
		t.Fatalf("unknown submission: %+v", out)
	}
	key := taskKey("p", "t")
	if !f.sender.pollDue(key, time.Now()) {
		t.Fatal("new task not due")
	}
	f.sender.schedulePoll(key, false)
	f.sender.schedulePoll(key, false)
	if p := f.sender.tasks.poll[key]; p.delay != 2*time.Second {
		t.Fatalf("backoff: %+v", p)
	}
	for range 10 {
		f.sender.schedulePoll(key, false)
	}
	if p := f.sender.tasks.poll[key]; p.delay != taskPollMax {
		t.Fatalf("capped backoff: %+v", p)
	}
	f.sender.schedulePoll(key, true)
	if p := f.sender.tasks.poll[key]; p.delay != taskPollFirst || f.sender.pollDue(key, time.Now()) {
		t.Fatalf("reset backoff: %+v", p)
	}
	// Local cancellation of an unconfirmed submission is remembered.
	if c := must(f.sender.CancelOutboundTask(ctx, out.PeerHostID, out.Request.TaskID)); c.CancelState == nil || *c.CancelState != cancelUnknown {
		t.Fatalf("pending cancel: %+v", c)
	}
	// The local record encodes grant_id and nulls as specified.
	var fields map[string]any
	if err := json.Unmarshal(rawJSON(t, out), &fields); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"peer_host_id", "request", "submit_state", "status", "events_after", "cancel_state", "adapter_id", "route_id", "attempts", "next_attempt_at", "error", "status_queries"} {
		if _, ok := fields[name]; !ok {
			t.Errorf("record lacks %s", name)
		}
	}
}
