package host

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
)

// chainNet is n hosts in one network, each with one agent and one attached
// adapter session. Host 0 originates.
type chainNet struct {
	t      *testing.T
	id     string
	hosts  []*Store
	agents []Agent
	auths  []AdapterAuth
}

func newChainNet(t *testing.T, n int) *chainNet {
	t.Helper()
	ctx := context.Background()
	network := startCoordinator(t)
	c := &chainNet{t: t}
	names := []string{"alice", "bob", "carol", "dave"}[:n]
	for _, name := range names {
		c.hosts = append(c.hosts, startPeerHost(t, name))
	}
	created := must(c.hosts[0].CreateNetwork(ctx, CreateNetwork{Name: "team", Member: names[0], CoordinatorAddress: network.address, CoordinatorPublicKey: network.coord.Identity().PublicKey}))
	c.id = created.ID
	for i, name := range names[1:] {
		invite := must(c.hosts[0].CreateInvite(ctx, c.id, CreateInvite{Member: name, ExpiresAt: timestamp(time.Now().Add(time.Hour)), HostOnly: true}))
		must(c.hosts[i+1].JoinNetwork(ctx, JoinNetwork{Token: invite.Token}))
	}
	for i, s := range c.hosts {
		mustSync(t, s, c.id)
		agent := must(s.RegisterAgent(ctx, RegisterAgent{Name: names[i] + "-agent", Owner: names[i]}))
		_, auth, _ := connectedAdapter(t, s, agent, string(rune('a'+i)))
		c.agents, c.auths = append(c.agents, agent), append(c.auths, auth)
	}
	return c
}

func (c *chainNet) host(i int) string { return c.hosts[i].Identity().ID }

// grant lets requester submit tasks to host on's agent with action.
func (c *chainNet) grant(on, requester int, action string, agent *string) Grant {
	c.t.Helper()
	return must(c.hosts[on].CreateGrant(context.Background(), CreateGrant{RequesterHostID: c.host(requester), TargetAgentID: c.agents[on].ID, ExpiresAt: timestamp(time.Now().Add(2 * time.Hour)), MaxMessageBytes: 1000, AllowDisconnected: true, Action: action, RequesterAgentID: agent}))
}

// root submits a task from host 0's agent to host to.
func (c *chainNet) root(to int, g Grant, depth int64, principals []string) OutboundTask {
	c.t.Helper()
	ctx := context.Background()
	out := must(c.hosts[0].PrepareOutboundTask(ctx, SubmitTask{PeerHostID: c.host(to), GrantID: &g.ID, TargetAgentID: c.agents[to].ID, Input: "work", Origin: &Origin{AgentID: c.agents[0].ID}, DelegationDepth: depth, DelegationPrincipals: principals}))
	out = must(c.hosts[0].ExchangeTask(ctx, out.PeerHostID, out.Request.TaskID, false))
	if out.SubmitState != submitAccepted {
		c.t.Fatalf("root submission: %+v", out)
	}
	return out
}

// claim hands the oldest queued task at host i to its session and accepts it.
func (c *chainNet) claim(i int) *TaskHandoff {
	c.t.Helper()
	h := must(c.hosts[i].NextTask(context.Background(), c.auths[i]))
	if h == nil {
		c.t.Fatalf("host %d has no task", i)
	}
	must(c.hosts[i].ChangeTask(context.Background(), c.auths[i], h.Task.TaskID, TaskChange{Op: "accept"}))
	return h
}

// forward passes the received task h at host from on to host to by the
// owner API, and submits it.
func (c *chainNet) forward(from int, h *TaskHandoff, to int, g Grant, deadline string) (OutboundTask, error) {
	ctx := context.Background()
	out, err := c.hosts[from].PrepareOutboundTask(ctx, SubmitTask{PeerHostID: c.host(to), GrantID: &g.ID, TargetAgentID: c.agents[to].ID, Input: "part", Deadline: deadline, Parent: &TaskParent{SenderHostID: h.Delivery.SenderHostID, TaskID: h.Task.TaskID}})
	if err != nil {
		return out, err
	}
	return c.hosts[from].ExchangeTask(ctx, out.PeerHostID, out.Request.TaskID, false)
}

func TestDelegationChainForwarding(t *testing.T) {
	ctx := context.Background()
	c := newChainNet(t, 4)
	a, b, cc := c.host(0), c.host(1), c.host(2)
	gB := c.grant(1, 0, membership.PolicyActionDelegate, nil)
	t0 := c.root(1, gB, 2, nil)
	if len(t0.Delegation) != 1 || len(t0.Request.Delegation) != 1 || t0.Parent != nil {
		t.Fatalf("root record: %+v", t0)
	}
	l0 := t0.Delegation[0]
	if l0.NetworkID != c.id || l0.Index != 0 || l0.Previous != "none" || l0.IssuerHostID != a || l0.AudienceHostID != b || l0.TaskID != t0.Request.TaskID || l0.OriginatorAgentID != c.agents[0].ID || strings.Join(l0.Principals, " ") != "network" || l0.Deadline != t0.Request.Deadline || l0.Depth != 2 {
		t.Fatalf("link 0: %+v", l0)
	}
	h := must(c.hosts[1].NextTask(ctx, c.auths[1]))
	if h == nil || !h.Delegable || h.OriginatorPersonID != nil || !sameChain(h.Task.Delegation, t0.Delegation) {
		t.Fatalf("handoff: %+v", h)
	}
	gC := c.grant(2, 0, membership.PolicyActionTask, nil)
	// Only a running task can be passed on.
	if _, err := c.forward(1, h, 2, gC, ""); !errors.Is(err, ErrForbidden) {
		t.Fatalf("forward before acceptance: %v", err)
	}
	must(c.hosts[1].ChangeTask(ctx, c.auths[1], h.Task.TaskID, TaskChange{Op: "accept"}))
	// A later deadline than the parent's is refused.
	late := timestamp(time.Now().Add(90 * time.Minute))
	if _, err := c.forward(1, h, 2, gC, late); !errors.Is(err, ErrForbidden) {
		t.Fatalf("later deadline: %v", err)
	}
	t1, err := c.forward(1, h, 2, gC, "")
	if err != nil || t1.SubmitState != submitAccepted {
		t.Fatalf("forward: %+v %v", t1, err)
	}
	if t1.Parent == nil || *t1.Parent != (TaskParent{a, t0.Request.TaskID}) || len(t1.Delegation) != 2 || t1.Request.Origin == nil || t1.Request.Origin.AgentID != c.agents[1].ID {
		t.Fatalf("forward record: %+v", t1)
	}
	l1 := t1.Delegation[1]
	if l1.Index != 1 || l1.Previous != l0.Hash() || l1.IssuerHostID != b || l1.AudienceHostID != cc || l1.Depth != 1 || l1.TaskID != t1.Request.TaskID || l1.Deadline != t1.Request.Deadline || l1.OriginatorAgentID != c.agents[0].ID {
		t.Fatalf("link 1: %+v", l1)
	}
	if deadline, _ := parseTime(t1.Request.Deadline); deadline.After(must(parseTime(t0.Request.Deadline))) {
		t.Fatalf("forward deadline %s after %s", t1.Request.Deadline, t0.Request.Deadline)
	}
	var children int
	if err = c.hosts[1].db.QueryRowContext(ctx, `SELECT COUNT(*) FROM task_children WHERE sender = ? AND task_id = ? AND peer = ? AND child_task_id = ?`, a, t0.Request.TaskID, cc, t1.Request.TaskID).Scan(&children); err != nil || children != 1 {
		t.Fatalf("children: %d %v", children, err)
	}
	if kinds := strings.Join(activityKinds(t, c.hosts[1], "task.delegated"), " "); kinds != "task.delegated" {
		t.Fatalf("activity: %s", kinds)
	}
	// A repeat returns the same record.
	again := must(c.hosts[1].PrepareOutboundTask(ctx, SubmitTask{PeerHostID: cc, TaskID: t1.Request.TaskID, GrantID: &gC.ID, TargetAgentID: c.agents[2].ID, Input: "part", Parent: t1.Parent}))
	if !sameChain(again.Delegation, t1.Delegation) {
		t.Fatalf("repeat: %+v", again)
	}
	if _, err = c.hosts[1].PrepareOutboundTask(ctx, SubmitTask{PeerHostID: cc, TaskID: t1.Request.TaskID, GrantID: &gC.ID, TargetAgentID: c.agents[2].ID, Input: "other", Parent: t1.Parent}); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed repeat: %v", err)
	}
	// Carol's grant lacks task.delegate: the task is not delegable there.
	hc := c.claim(2)
	if hc.Delegable || len(hc.Task.Delegation) != 2 {
		t.Fatalf("carol handoff: %+v", hc)
	}
	gD := c.grant(3, 0, membership.PolicyActionDelegate, nil)
	if _, err = c.forward(2, hc, 3, gD, ""); !errors.Is(err, ErrForbidden) {
		t.Fatalf("forward without task.delegate: %v", err)
	}
	// The stored delegable key survives later status writes and is never served.
	must(c.hosts[2].ChangeTask(ctx, c.auths[2], hc.Task.TaskID, TaskChange{Op: "progress", Message: "half"}))
	var record string
	if err = c.hosts[2].db.QueryRowContext(ctx, `SELECT record FROM received_tasks WHERE task_id = ?`, hc.Task.TaskID).Scan(&record); err != nil || !strings.Contains(record, `"delegable":false`) {
		t.Fatalf("stored record: %s %v", record, err)
	}
	if st := must(c.hosts[2].SubmitterTask(ctx, b, hc.Task.TaskID)); st.LastEvent != 3 {
		t.Fatalf("status: %+v", st)
	}

	// Cancelling the root asks every forwarded task to stop.
	must(c.hosts[1].RequestTaskCancel(ctx, a, t0.Request.TaskID))
	child := must(c.hosts[1].OutboundTask(ctx, cc, t1.Request.TaskID))
	if child.CancelState == nil || *child.CancelState != cancelUnknown {
		t.Fatalf("child cancel: %+v", child)
	}
	if _, err = c.forward(1, h, 3, gD, ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("forward after cancellation: %v", err)
	}
	if _, err = c.hosts[1].pollTask(ctx, cc, t1.Request.TaskID); err != nil {
		t.Fatal(err)
	}
	if st := must(c.hosts[2].SubmitterTask(ctx, b, t1.Request.TaskID)); !st.CancelRequested {
		t.Fatalf("carol status: %+v", st)
	}
}

func TestDelegationForwardRefusals(t *testing.T) {
	ctx := context.Background()
	c := newChainNet(t, 4)
	gB := c.grant(1, 0, membership.PolicyActionDelegate, nil)
	gC := c.grant(2, 0, membership.PolicyActionDelegate, nil)
	gD := c.grant(3, 0, membership.PolicyActionDelegate, nil)
	// Without a chain, a task cannot be passed on, even under task.delegate.
	c.root(1, gB, 0, nil)
	h := c.claim(1)
	if h.Delegable || h.Task.Delegation != nil {
		t.Fatalf("chainless handoff: %+v", h)
	}
	if _, err := c.forward(1, h, 2, gC, ""); !errors.Is(err, ErrForbidden) {
		t.Fatalf("chainless forward: %v", err)
	}
	// Principals bound the next hop.
	c.root(1, gB, 2, []string{"host:" + c.host(2)})
	h = c.claim(1)
	if _, err := c.forward(1, h, 3, gD, ""); !errors.Is(err, ErrForbidden) {
		t.Fatalf("forward outside principals: %v", err)
	}
	// Depth 1 allows one more hop and no further.
	c.root(1, gB, 1, nil)
	h = c.claim(1)
	if !h.Delegable {
		t.Fatalf("depth 1 handoff: %+v", h)
	}
	if _, err := c.forward(1, h, 2, gC, ""); err != nil {
		t.Fatal(err)
	}
	hc := c.claim(2)
	if hc.Delegable || hc.Task.Delegation[1].Depth != 0 {
		t.Fatalf("depth 0 handoff: %+v", hc)
	}
	if _, err := c.forward(2, hc, 3, gD, ""); !errors.Is(err, ErrForbidden) {
		t.Fatalf("forward at depth 0: %v", err)
	}
	// Owner-side validation.
	for name, r := range map[string]SubmitTask{
		"depth 3":           {DelegationDepth: 3, Origin: &Origin{AgentID: c.agents[0].ID}},
		"no origin":         {DelegationDepth: 1},
		"principals only":   {DelegationPrincipals: []string{"network"}},
		"bad principal":     {DelegationDepth: 1, DelegationPrincipals: []string{"group:x"}, Origin: &Origin{AgentID: c.agents[0].ID}},
		"parent with depth": {DelegationDepth: 1, Parent: &TaskParent{c.host(1), "task_" + strings.Repeat("1", 32)}, Origin: &Origin{AgentID: c.agents[0].ID}},
	} {
		r.PeerHostID, r.GrantID, r.TargetAgentID, r.Input = c.host(1), &gB.ID, c.agents[1].ID, "x"
		if _, err := c.hosts[0].PrepareOutboundTask(ctx, r); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := c.hosts[1].PrepareOutboundTask(ctx, SubmitTask{PeerHostID: c.host(2), GrantID: &gC.ID, TargetAgentID: c.agents[2].ID, Input: "x", Parent: &TaskParent{c.host(0), "task_" + strings.Repeat("1", 32)}}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown parent: %v", err)
	}
	// Principals are sorted and de-duplicated into link 0.
	out := c.root(1, gB, 2, []string{"network", "host:" + c.host(2), "network"})
	if got := strings.Join(out.Delegation[0].Principals, " "); got != "host:"+c.host(2)+" network" {
		t.Fatalf("principals: %s", got)
	}
}

func TestDelegationAdapterForward(t *testing.T) {
	ctx := context.Background()
	c := newChainNet(t, 3)
	gB := c.grant(1, 0, membership.PolicyActionDelegate, nil)
	gC := c.grant(2, 0, membership.PolicyActionTask, nil)
	t0 := c.root(1, gB, 2, nil)
	h := c.claim(1)
	b := c.hosts[1]
	credential := must(b.Adapters(ctx))[0]
	route := must(b.CreateOutboundRoute(ctx, CreateOutboundRoute{AdapterID: credential.ID, Name: "carol", PeerHostID: c.host(2), TargetAgentID: c.agents[2].ID, GrantID: &gC.ID, ExpiresAt: timestamp(time.Now().Add(30 * time.Minute)), MaxMessageBytes: 1000, MaxMessages: 10, Action: membership.PolicyActionTask}))
	if route.DelegationDepth != 0 {
		t.Fatalf("route: %+v", route)
	}
	child := "task_" + strings.Repeat("c", 32)
	out := must(b.PrepareAdapterTask(ctx, c.auths[1], AdapterDelegate{Destination: "carol", TaskID: child, Input: "part", ParentTaskID: h.Task.TaskID}))
	if out.Parent == nil || out.Parent.TaskID != t0.Request.TaskID || len(out.Delegation) != 2 || out.Request.Origin.SessionID == "" {
		t.Fatalf("adapter forward: %+v", out)
	}
	// The deadline is capped by the route's expiry, below the parent's.
	if out.Request.Deadline != route.ExpiresAt && must(parseTime(out.Request.Deadline)).After(must(parseTime(route.ExpiresAt))) {
		t.Fatalf("deadline %s, route %s", out.Request.Deadline, route.ExpiresAt)
	}
	if again := must(b.PrepareAdapterTask(ctx, c.auths[1], AdapterDelegate{Destination: "carol", TaskID: child, Input: "part", ParentTaskID: h.Task.TaskID})); !sameChain(again.Delegation, out.Delegation) {
		t.Fatalf("repeat: %+v", again)
	}
	if _, err := b.PrepareAdapterTask(ctx, c.auths[1], AdapterDelegate{Destination: "carol", TaskID: child, Input: "part"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("repeat without parent: %v", err)
	}
	if _, err := b.PrepareAdapterTask(ctx, c.auths[1], AdapterDelegate{Destination: "carol", TaskID: "task_" + strings.Repeat("d", 32), Input: "part", ParentTaskID: "task_" + strings.Repeat("e", 32)}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown parent: %v", err)
	}
	// A route with a delegation depth creates link 0 for the session's agent.
	if _, err := b.CreateOutboundRoute(ctx, CreateOutboundRoute{AdapterID: credential.ID, Name: "bad", PeerHostID: c.host(2), TargetAgentID: c.agents[2].ID, ExpiresAt: route.ExpiresAt, MaxMessageBytes: 10, MaxMessages: 1, DelegationDepth: 1}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("message route with depth: %v", err)
	}
	if _, err := b.CreateOutboundRoute(ctx, CreateOutboundRoute{AdapterID: credential.ID, Name: "bad", PeerHostID: c.host(2), TargetAgentID: c.agents[2].ID, ExpiresAt: route.ExpiresAt, MaxMessageBytes: 10, MaxMessages: 1, Action: membership.PolicyActionDelegate}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("delegate route: %v", err)
	}
	must(b.CreateOutboundRoute(ctx, CreateOutboundRoute{AdapterID: credential.ID, Name: "deep", PeerHostID: c.host(2), TargetAgentID: c.agents[2].ID, GrantID: &gC.ID, ExpiresAt: route.ExpiresAt, MaxMessageBytes: 1000, MaxMessages: 10, Action: membership.PolicyActionTask, DelegationDepth: 2}))
	root := must(b.PrepareAdapterTask(ctx, c.auths[1], AdapterDelegate{Destination: "deep", TaskID: "task_" + strings.Repeat("f", 32), Input: "own"}))
	if len(root.Delegation) != 1 || root.Delegation[0].Depth != 2 || root.Delegation[0].OriginatorAgentID != c.agents[1].ID || root.Parent != nil {
		t.Fatalf("route link 0: %+v", root)
	}
}

func TestDelegationChainVerification(t *testing.T) {
	ctx := context.Background()
	c := newChainNet(t, 4)
	a, b, cc, d := c.host(0), c.host(1), c.host(2), c.host(3)
	carol := c.hosts[2]
	gC := c.grant(2, 0, membership.PolicyActionTask, nil)
	deadline := time.Now().Add(30 * time.Minute).UTC().Truncate(time.Second)
	t0, t1 := "task_"+strings.Repeat("0", 32), "task_"+strings.Repeat("1", 32)
	base := func() []membership.Link {
		l0 := membership.SignLink(c.hosts[0].privateKey, membership.Link{NetworkID: c.id, Index: 0, Previous: "none", IssuerHostID: a, AudienceHostID: b, TaskID: t0, OriginatorAgentID: c.agents[0].ID, Principals: []string{"network"}, Deadline: timestamp(deadline.Add(time.Minute)), Depth: 2})
		l1 := membership.SignLink(c.hosts[1].privateKey, membership.Link{NetworkID: c.id, Index: 1, Previous: l0.Hash(), IssuerHostID: b, AudienceHostID: cc, TaskID: t1, OriginatorAgentID: c.agents[0].ID, Principals: []string{"network"}, Deadline: timestamp(deadline), Depth: 1})
		return []membership.Link{l0, l1}
	}
	request := func(links []membership.Link) TaskRequest {
		return TaskRequest{TaskID: t1, GrantID: &gC.ID, TargetAgentID: c.agents[2].ID, Deadline: timestamp(deadline), Input: "x", Origin: &Origin{AgentID: c.agents[1].ID}, Delegation: links}
	}
	resign := func(i int, l membership.Link) membership.Link {
		for _, s := range c.hosts {
			if s.Identity().ID == l.IssuerHostID {
				return membership.SignLink(s.privateKey, l)
			}
		}
		return membership.SignLink(c.hosts[i].privateKey, l)
	}
	check := func(name string, sender string, r TaskRequest, want error) {
		t.Helper()
		_, err := carol.AcceptTask(ctx, sender, r)
		if (want == nil && err != nil) || (want != nil && !errors.Is(err, want)) {
			t.Errorf("%s: want %v, got %v", name, want, err)
		}
	}
	type mutation func(links []membership.Link) []membership.Link
	relink := func(links []membership.Link) []membership.Link {
		links[1].Previous = links[0].Hash()
		links[1] = resign(1, links[1])
		return links
	}
	for name, m := range map[string]mutation{
		"widened principals": func(l []membership.Link) []membership.Link {
			l[0].Principals = []string{"host:" + cc}
			l[0] = resign(0, l[0])
			l[1].Principals = []string{"network"}
			return relink(l)
		},
		"widened depth": func(l []membership.Link) []membership.Link { l[1].Depth = 2; l[1] = resign(1, l[1]); return l },
		"widened deadline": func(l []membership.Link) []membership.Link {
			l[0].Deadline = timestamp(deadline.Add(-time.Minute))
			l[0] = resign(0, l[0])
			return relink(l)
		},
		"link 0 depth 3": func(l []membership.Link) []membership.Link {
			l[0].Depth = 3
			l[0] = resign(0, l[0])
			l[1].Depth = 2
			return relink(l)
		},
		"wrong previous": func(l []membership.Link) []membership.Link {
			l[1].Previous = strings.Repeat("0", 64)
			l[1] = resign(1, l[1])
			return l
		},
		"bad signature":  func(l []membership.Link) []membership.Link { l[1].Signature = l[0].Signature; return l },
		"reordered":      func(l []membership.Link) []membership.Link { return []membership.Link{l[1], l[0]} },
		"wrong index":    func(l []membership.Link) []membership.Link { l[1].Index = 2; l[1] = resign(1, l[1]); return l },
		"wrong audience": func(l []membership.Link) []membership.Link { l[1].AudienceHostID = d; l[1] = resign(1, l[1]); return l },
		"wrong task":     func(l []membership.Link) []membership.Link { l[1].TaskID = t0; l[1] = resign(1, l[1]); return l },
		"broken continue": func(l []membership.Link) []membership.Link {
			l[0].AudienceHostID = d
			l[0] = resign(0, l[0])
			return relink(l)
		},
		"other agent": func(l []membership.Link) []membership.Link {
			l[1].OriginatorAgentID = c.agents[1].ID
			l[1] = resign(1, l[1])
			return l
		},
		"spliced": func(l []membership.Link) []membership.Link {
			// Link 0 of another task.
			other := l[0]
			other.TaskID = "task_" + strings.Repeat("9", 32)
			l[0] = resign(0, other)
			return l
		},
	} {
		check(name, b, request(m(base())), ErrForbidden)
	}
	// The chain must end at the authenticated sender, at this deadline.
	check("other sender", d, request(base()), ErrForbidden)
	r := request(base())
	r.Deadline = timestamp(deadline.Add(-time.Second))
	check("other deadline", b, r, ErrForbidden)
	// Malformed chains.
	for name, links := range map[string][]membership.Link{
		"empty":    {},
		"too long": append(base(), base()...),
	} {
		check(name, b, request(links), ErrInvalid)
	}
	unsorted := base()
	unsorted[1].Principals = []string{"network", "host:" + d}
	check("unsorted", b, request(unsorted), ErrInvalid)
	// A single link needs the request origin to be the originator.
	single := membership.SignLink(c.hosts[1].privateKey, membership.Link{NetworkID: c.id, Previous: "none", IssuerHostID: b, AudienceHostID: cc, TaskID: t1, OriginatorAgentID: c.agents[1].ID, Principals: []string{"network"}, Deadline: timestamp(deadline), Depth: 1})
	gCB := c.grant(2, 1, membership.PolicyActionTask, nil)
	r = request([]membership.Link{single})
	r.GrantID = &gCB.ID
	r.Origin = nil
	check("single without origin", b, r, ErrForbidden)
	// The originator, not the sender, must be authorized.
	r = request(base())
	r.GrantID = &gCB.ID
	check("sender-only grant", b, r, ErrForbidden)
	agentBound := c.grant(2, 0, membership.PolicyActionTask, &c.agents[1].ID)
	r.GrantID = &agentBound.ID
	check("grant for another agent", b, r, ErrForbidden)
	// Blocks apply to every issuer.
	for _, host := range []string{a, b} {
		must(carol.Block(ctx, BlockAccess{Host: host}))
		check("blocked "+host[:9], b, request(base()), ErrForbidden)
		must(carol.Unblock(ctx, BlockAccess{Host: host}))
	}
	// The valid chain is accepted, and a different chain under its ID conflicts.
	check("valid", b, request(base()), nil)
	other := base()
	other[1].Principals = []string{"host:" + d}
	other[1] = resign(1, other[1])
	check("different chain", b, request(other), ErrConflict)
	// A block before the handoff rejects the queued task.
	must(carol.Block(ctx, BlockAccess{Host: a}))
	if h := must(carol.NextTask(ctx, c.auths[2])); h != nil {
		t.Fatalf("handoff despite a blocked originator: %+v", h)
	}
	st := must(carol.SubmitterTask(ctx, b, t1))
	if st.State != TaskRejected {
		t.Fatalf("status after block: %+v", st)
	}
}

func TestDelegationMigrationToVersion11(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir() + "/host"
	s := must(Open(ctx, dir))
	if _, err := s.db.ExecContext(ctx, "DROP TABLE directory_sends; DROP TABLE policy_deliveries; DROP TABLE task_children; PRAGMA user_version = 10"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s = must(Open(ctx, dir))
	var version, tables int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil || version != 14 {
		t.Fatalf("version %d %v", version, err)
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE name = 'task_children'").Scan(&tables); err != nil || tables != 1 {
		t.Fatalf("task_children: %d %v", tables, err)
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA user_version = 15"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := Open(ctx, dir); err == nil || !strings.Contains(err.Error(), "unsupported host database version: 15") {
		t.Fatalf("version 15 opened: %v", err)
	}
}
