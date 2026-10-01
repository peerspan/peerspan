package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Cerebral-Systems/capsule/internal/capsule"
	"github.com/Cerebral-Systems/capsule/internal/runtime"
	"github.com/Cerebral-Systems/capsule/internal/secret"
	"github.com/Cerebral-Systems/capsule/internal/session"
)

// CreateSessionRequest opens a pending peering session from one capsule.
type CreateSessionRequest struct {
	CapsuleID string        `json:"capsule_id"`
	Task      string        `json:"task"`
	Allow     []string      `json:"allow,omitempty"`
	AllowExec []string      `json:"allow_exec,omitempty"`
	TTL       time.Duration `json:"-"`
}

// CreateSession records a pending session. Other capsules join later through AcceptSession.
func (s Service) CreateSession(req CreateSessionRequest) (session.Session, error) {
	task := strings.TrimSpace(req.Task)
	if task == "" {
		return session.Session{}, fmt.Errorf("session create requires --task")
	}
	opened, err := s.Inspect(req.CapsuleID)
	if err != nil {
		return session.Session{}, err
	}
	if opened.Status != capsule.StatusRunning {
		return session.Session{}, fmt.Errorf("capsule %s is %s", opened.ID, opened.Status)
	}
	allow, err := cleanAllow(req.Allow)
	if err != nil {
		return session.Session{}, err
	}

	now := s.now()
	id, err := session.NewID(now)
	if err != nil {
		return session.Session{}, err
	}
	sess := session.Session{
		ID:     id,
		Task:   task,
		Status: session.StatusPending,
		Members: []session.Member{{
			CapsuleID: opened.ID,
			Role:      session.RoleOpened,
			Allow:     allow,
			AllowExec: req.AllowExec,
			Name:      opened.Network.Name,
			Owner:     opened.Owner,
		}},
		Audit: []capsule.AuditEvent{{
			At:      now,
			Type:    "session.created",
			Message: "peering session opened",
		}},
		CreatedAt: now,
		UpdatedAt: now,
	}
	if req.TTL > 0 {
		exp := now.Add(req.TTL)
		sess.ExpiresAt = &exp
	}
	if err := s.Store.SaveSession(sess); err != nil {
		return session.Session{}, err
	}
	return sess, nil
}

// AcceptSession attaches a capsule running on this machine.
// The first accept marks a pending session active. Later accepts add another peer.
func (s Service) AcceptSession(id, capsuleID string, allow, allowExec []string) (session.Session, error) {
	joined, err := s.Inspect(capsuleID)
	if err != nil {
		return session.Session{}, err
	}
	if joined.Status != capsule.StatusRunning {
		return session.Session{}, fmt.Errorf("capsule %s is %s", joined.ID, joined.Status)
	}
	return s.admit(id, session.Member{
		CapsuleID: joined.ID,
		Role:      session.RoleJoined,
		Allow:     allow,
		AllowExec: allowExec,
		Name:      joined.Network.Name,
		Owner:     joined.Owner,
	})
}

// AcceptRemoteSession attaches a capsule whose guest is on another machine.
// name is that capsule's recorded name. underlay is the address of its machine.
func (s Service) AcceptRemoteSession(id, capsuleID string, allow, allowExec []string, name, owner, underlay string) (session.Session, error) {
	if strings.TrimSpace(s.Underlay) == "" {
		return session.Session{}, fmt.Errorf("capsule serve --underlay is required before a remote capsule can join")
	}
	if net.ParseIP(underlay) == nil {
		return session.Session{}, fmt.Errorf("underlay %q is not an address", underlay)
	}
	if underlay == s.Underlay {
		return session.Session{}, fmt.Errorf("capsule %s is on this machine", capsuleID)
	}
	if strings.TrimSpace(name) == "" {
		return session.Session{}, fmt.Errorf("remote capsule requires a name")
	}
	return s.admit(id, session.Member{
		CapsuleID: capsuleID,
		Role:      session.RoleJoined,
		Allow:     allow,
		AllowExec: allowExec,
		Name:      name,
		Owner:     owner,
		Underlay:  underlay,
	})
}

func (s Service) admit(id string, joined session.Member) (session.Session, error) {
	sess, err := s.loadSession(id)
	if err != nil {
		return session.Session{}, err
	}
	if sess.Status != session.StatusPending && sess.Status != session.StatusActive {
		return session.Session{}, fmt.Errorf("session %s is %s", sess.ID, sess.Status)
	}
	if _, ok := sess.Member(joined.CapsuleID); ok {
		return session.Session{}, fmt.Errorf("capsule %s is already in session %s", joined.CapsuleID, sess.ID)
	}
	cleaned, err := cleanAllow(joined.Allow)
	if err != nil {
		return session.Session{}, err
	}
	joined.Allow = cleaned
	if s.Runtime == nil {
		return session.Session{}, fmt.Errorf("no runtime configured")
	}
	if joined.Underlay != "" {
		for i := range sess.Members {
			if sess.Members[i].Underlay == "" {
				sess.Members[i].Underlay = s.Underlay
			}
		}
	}
	current, err := s.linkSides(sess.Members)
	if err != nil {
		return session.Session{}, err
	}
	nextMembers := append(append([]session.Member{}, sess.Members...), joined)
	next, err := s.linkSides(nextMembers)
	if err != nil {
		return session.Session{}, err
	}
	addrs, err := s.Runtime.Connect(context.Background(), sess.ID, s.Underlay, linkPeers(next))
	if err != nil {
		return session.Session{}, err
	}
	if len(addrs) != len(next) {
		s.restoreLink(sess.ID, linkPeers(current), linkPeers(next))
		return session.Session{}, fmt.Errorf("session link returned %d addresses for %d peers", len(addrs), len(next))
	}
	now := s.now()
	sess.Members = nextMembers
	sess.Link = linkFrom(next, addrs)
	sess.Status = session.StatusActive
	sess.UpdatedAt = now
	sess.Audit = append(sess.Audit, capsule.AuditEvent{
		At:      now,
		Type:    "session.accepted",
		Message: "capsule joined the session",
	})
	if err := s.Store.SaveSession(sess); err != nil {
		s.restoreLink(sess.ID, linkPeers(current), linkPeers(next))
		return session.Session{}, err
	}
	for i, side := range next {
		if side.local == nil {
			continue
		}
		if err := s.setEndpoint(*side.local, addrs[i].IP); err != nil {
			return sess, err
		}
	}
	return sess, nil
}

// MessageSession appends one transcript entry from a participant.
func (s Service) MessageSession(id, capsuleID, text string) (session.Session, error) {
	sess, err := s.loadSession(id)
	if err != nil {
		return session.Session{}, err
	}
	if err := s.requireActive(&sess); err != nil {
		return session.Session{}, err
	}
	if !participant(sess, capsuleID) {
		return session.Session{}, fmt.Errorf("capsule %s is not in session %s", capsuleID, sess.ID)
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return session.Session{}, fmt.Errorf("session message requires --text")
	}
	now := s.now()
	sess.Transcript = append(sess.Transcript, session.Entry{At: now, CapsuleID: capsuleID, Text: text})
	sess.UpdatedAt = now
	sess.Audit = append(sess.Audit, capsule.AuditEvent{
		At:      now,
		Type:    "session.message",
		Message: clip(capsuleID + ": " + text),
	})
	if err := s.Store.SaveSession(sess); err != nil {
		return session.Session{}, err
	}
	return sess, nil
}

// ShareSession copies an allowlisted workspace file into the session artifacts.
func (s Service) ShareSession(id, capsuleID, relPath string) (session.Session, error) {
	sess, err := s.loadSession(id)
	if err != nil {
		return session.Session{}, err
	}
	if err := s.requireActive(&sess); err != nil {
		return session.Session{}, err
	}
	if !participant(sess, capsuleID) {
		return session.Session{}, fmt.Errorf("capsule %s is not in session %s", capsuleID, sess.ID)
	}
	rel, err := cleanRel(relPath)
	if err != nil {
		return session.Session{}, err
	}
	if !allowed(allowFor(sess, capsuleID), rel) {
		return s.auditSession(sess, capsuleID, "share.denied", fmt.Sprintf("path %q is not allowlisted", rel))
	}
	c, err := s.Store.Load(capsuleID)
	if err != nil {
		return session.Session{}, err
	}

	if !(hasCap(c.Authority.Capabilities, "share") || hasCap(c.Authority.Capabilities, "share:approval-required")) {
		return s.auditSession(sess, capsuleID, "share.denied", "capsule has no share capability")
	}
	if hasCap(c.Authority.Capabilities, "share:approval-required") {
		action := "share " + rel
		switch approvalStatus(sess, capsuleID, action) {
		case session.ApprovalGranted:
		case session.ApprovalPending:
			return sess, fmt.Errorf("approval required for %s", action)
		default:
			return s.pendApproval(sess, capsuleID, action)
		}
	}
	c, err = s.Store.Load(capsuleID)
	if err != nil {
		return session.Session{}, err
	}
	src := filepath.Join(c.Runtime.WorkDir, rel)
	body, err := os.ReadFile(src)
	if err != nil {
		return session.Session{}, err
	}
	values, err := s.secretValues(c.Authority.Secrets)
	if err != nil {
		return session.Session{}, err
	}
	if secret.Contains(string(body), values) {
		return s.auditSession(sess, capsuleID, "share.denied", fmt.Sprintf("path %q contains a secret value", rel))
	}

	savedAs := filepath.Join("artifacts", capsuleID, filepath.Base(rel))
	dst := filepath.Join(s.Store.SessionDir(sess.ID), savedAs)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return session.Session{}, err
	}
	if err := os.WriteFile(dst, body, 0o644); err != nil {
		return session.Session{}, err
	}
	sum := sha256.Sum256(body)

	now := s.now()
	sess.Artifacts = append(sess.Artifacts, session.Artifact{
		At:        now,
		CapsuleID: capsuleID,
		Path:      rel,
		SHA256:    hex.EncodeToString(sum[:]),
		SavedAs:   filepath.ToSlash(savedAs),
	})
	sess.UpdatedAt = now
	sess.Audit = append(sess.Audit, capsule.AuditEvent{
		At:      now,
		Type:    "session.shared",
		Message: capsuleID + " shared " + rel,
	})
	if err := s.Store.SaveSession(sess); err != nil {
		return session.Session{}, err
	}
	return sess, nil
}

// RevokeSession ends an open session.
func (s Service) RevokeSession(id string) (session.Session, error) {
	sess, err := s.loadSession(id)
	if err != nil {
		return session.Session{}, err
	}
	if sess.Status == session.StatusRevoked || sess.Status == session.StatusExpired {
		return sess, nil
	}
	if err := s.dropLink(sess); err != nil {
		return session.Session{}, err
	}
	now := s.now()
	sess.Status = session.StatusRevoked
	sess.UpdatedAt = now
	sess.Audit = append(sess.Audit, capsule.AuditEvent{
		At:      now,
		Type:    "session.revoked",
		Message: "peering session revoked",
	})
	if err := s.Store.SaveSession(sess); err != nil {
		return session.Session{}, err
	}
	return sess, nil
}

// ExportSession builds the evidence bundle for a session and writes it beside the session record.
func (s Service) ExportSession(id string) (session.Evidence, error) {
	sess, err := s.loadSession(id)
	if err != nil {
		return session.Evidence{}, err
	}
	evidence := s.evidence(sess)
	if err := s.Store.SaveEvidence(sess.ID, evidence); err != nil {
		return session.Evidence{}, err
	}
	return evidence, nil
}

func (s Service) loadSession(id string) (session.Session, error) {
	sess, err := s.Store.LoadSession(id)
	if err != nil {
		return session.Session{}, err
	}
	if sess.Status != session.StatusPending && sess.Status != session.StatusActive {
		return sess, nil
	}
	if sess.ExpiresAt == nil || s.now().Before(*sess.ExpiresAt) {
		return sess, nil
	}
	if err := s.dropLink(sess); err != nil {
		return session.Session{}, err
	}
	now := s.now()
	sess.Status = session.StatusExpired
	sess.UpdatedAt = now
	sess.Audit = append(sess.Audit, capsule.AuditEvent{
		At:      now,
		Type:    "session.expired",
		Message: "peering session expired",
	})
	if err := s.Store.SaveSession(sess); err != nil {
		return session.Session{}, err
	}
	return sess, nil
}

func (s Service) requireActive(sess *session.Session) error {
	if sess.Status != session.StatusActive {
		return fmt.Errorf("session %s is %s", sess.ID, sess.Status)
	}
	return nil
}

type linkSide struct {
	member session.Member
	pid    int
	name   string
	local  *capsule.Capsule
}

func (s Service) isLocal(member session.Member) bool {
	if member.Underlay == "" {
		return true
	}
	return s.Underlay != "" && member.Underlay == s.Underlay
}

func (s Service) linkSides(members []session.Member) ([]linkSide, error) {
	out := make([]linkSide, 0, len(members))
	for _, member := range members {
		if !s.isLocal(member) {
			if member.Name == "" || member.Underlay == "" {
				return nil, fmt.Errorf("remote capsule %s has no reachability", member.CapsuleID)
			}
			out = append(out, linkSide{member: member, name: member.Name})
			continue
		}
		c, err := s.Inspect(member.CapsuleID)
		if err != nil {
			return nil, err
		}
		if c.Status != capsule.StatusRunning {
			return nil, fmt.Errorf("capsule %s is %s", c.ID, c.Status)
		}
		stamped := member
		stamped.Name = c.Network.Name
		if s.Underlay != "" {
			stamped.Underlay = s.Underlay
		}
		recorded := c
		out = append(out, linkSide{member: stamped, pid: c.Runtime.PID, name: c.Network.Name, local: &recorded})
	}
	return out, nil
}

func (s Service) restoreLink(id string, previous, attempted []runtime.Peer) {
	ctx := context.Background()
	_ = s.Runtime.Disconnect(ctx, id, s.Underlay, attempted)
	if len(previous) >= 2 {
		_, _ = s.Runtime.Connect(ctx, id, s.Underlay, previous)
	}
}

func linkPeers(sides []linkSide) []runtime.Peer {
	peers := make([]runtime.Peer, len(sides))
	for i, side := range sides {
		peer := runtime.Peer{PID: side.pid, Name: side.name}
		if side.pid <= 0 {
			peer.Underlay = side.member.Underlay
		}
		peers[i] = peer
	}
	return peers
}

func linkFrom(sides []linkSide, addrs []runtime.Address) *session.Link {
	endpoints := make([]session.Endpoint, len(addrs))
	for i, addr := range addrs {
		endpoints[i] = session.Endpoint{
			CapsuleID: sides[i].member.CapsuleID,
			Name:      addr.Name,
			IP:        addr.IP,
			Underlay:  sides[i].member.Underlay,
		}
	}
	return &session.Link{Endpoints: endpoints}
}

// LinkSession attaches a local capsule to a session opened on another machine.
// link is the record that machine returned.
func (s Service) LinkSession(id, capsuleID string, link session.Link) error {
	if s.Runtime == nil {
		return fmt.Errorf("no runtime configured")
	}
	if strings.TrimSpace(s.Underlay) == "" {
		return fmt.Errorf("capsule serve --underlay is required")
	}
	c, err := s.Inspect(capsuleID)
	if err != nil {
		return err
	}
	if c.Status != capsule.StatusRunning {
		return fmt.Errorf("capsule %s is %s", c.ID, c.Status)
	}
	if len(link.Endpoints) < 2 {
		return fmt.Errorf("session link requires at least two peers")
	}
	peers := make([]runtime.Peer, len(link.Endpoints))
	found := false
	ip := ""
	for i, ep := range link.Endpoints {
		if ep.CapsuleID == capsuleID {
			if ep.Underlay != s.Underlay {
				return fmt.Errorf("underlay does not match this machine")
			}
			peers[i] = runtime.Peer{PID: c.Runtime.PID, Name: c.Network.Name}
			found = true
			ip = ep.IP
			continue
		}
		if ep.Underlay == "" || ep.Name == "" {
			return fmt.Errorf("peer %s has no underlay", ep.CapsuleID)
		}
		peers[i] = runtime.Peer{Name: ep.Name, Underlay: ep.Underlay}
	}
	if !found {
		return fmt.Errorf("capsule %s is not on this session link", capsuleID)
	}
	addrs, err := s.Runtime.Connect(context.Background(), id, s.Underlay, peers)
	if err != nil {
		return err
	}
	for i, addr := range addrs {
		if addr.IP != link.Endpoints[i].IP {
			_ = s.Runtime.Disconnect(context.Background(), id, s.Underlay, peers)
			return fmt.Errorf("session link address for %s is %s, not %s", link.Endpoints[i].Name, addr.IP, link.Endpoints[i].IP)
		}
	}
	return s.setEndpoint(c, ip)
}

// LeaveSession removes this machine's side of a session link.
func (s Service) LeaveSession(id, capsuleID string) error {
	if s.Runtime == nil {
		return fmt.Errorf("no runtime configured")
	}
	c, err := s.Inspect(capsuleID)
	if err != nil {
		return err
	}
	if err := s.Runtime.Disconnect(context.Background(), id, s.Underlay, []runtime.Peer{{
		PID:  c.Runtime.PID,
		Name: c.Network.Name,
	}}); err != nil {
		return err
	}
	c.Network.Endpoints = nil
	c.UpdatedAt = s.now()
	return s.Store.Save(c)
}

func participant(sess session.Session, capsuleID string) bool {
	_, ok := sess.Member(capsuleID)
	return ok
}

func allowFor(sess session.Session, capsuleID string) []string {
	member, ok := sess.Member(capsuleID)
	if !ok {
		return nil
	}
	return member.Allow
}

func allowed(allow []string, rel string) bool {
	for _, path := range allow {
		if path == rel {
			return true
		}
	}
	return false
}

func cleanAllow(paths []string) ([]string, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		rel, err := cleanRel(path)
		if err != nil {
			return nil, err
		}
		out = append(out, rel)
	}
	return out, nil
}

func cleanRel(path string) (string, error) {
	if path == "" || filepath.IsAbs(path) {
		return "", fmt.Errorf("path %q must be relative", path)
	}
	rel := filepath.Clean(path)
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes the workspace", path)
	}
	return filepath.ToSlash(rel), nil
}
