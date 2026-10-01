package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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

// CreateSession records a pending session. The other capsule joins later through AcceptSession.
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
		ID:            id,
		Task:          task,
		Status:        session.StatusPending,
		OpenedCapsule: opened.ID,
		OpenedAllow:   allow,
		OpenedExec:    req.AllowExec,
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

// AcceptSession attaches the second capsule and marks the session active.
func (s Service) AcceptSession(id, capsuleID string, allow, allowExec []string) (session.Session, error) {
	sess, err := s.loadSession(id)
	if err != nil {
		return session.Session{}, err
	}
	if sess.Status != session.StatusPending {
		return session.Session{}, fmt.Errorf("session %s is %s", sess.ID, sess.Status)
	}
	joined, err := s.Inspect(capsuleID)
	if err != nil {
		return session.Session{}, err
	}
	if joined.Status != capsule.StatusRunning {
		return session.Session{}, fmt.Errorf("capsule %s is %s", joined.ID, joined.Status)
	}
	if joined.ID == sess.OpenedCapsule {
		return session.Session{}, fmt.Errorf("session requires two capsules")
	}
	opened, err := s.Inspect(sess.OpenedCapsule)
	if err != nil {
		return session.Session{}, err
	}
	if opened.Status != capsule.StatusRunning {
		return session.Session{}, fmt.Errorf("capsule %s is %s", opened.ID, opened.Status)
	}
	cleaned, err := cleanAllow(allow)
	if err != nil {
		return session.Session{}, err
	}
	if s.Runtime == nil {
		return session.Session{}, fmt.Errorf("no runtime configured")
	}
	link, err := s.Runtime.Connect(context.Background(), sess.ID, runtime.Peer{
		PID:  opened.Runtime.PID,
		Name: opened.Network.Name,
	}, runtime.Peer{
		PID:  joined.Runtime.PID,
		Name: joined.Network.Name,
	})
	if err != nil {
		return session.Session{}, err
	}
	now := s.now()
	sess.JoinedCapsule = joined.ID
	sess.JoinedAllow = cleaned
	sess.JoinedExec = allowExec
	sess.Link = &session.Link{
		OpenedName: opened.Network.Name,
		JoinedName: joined.Network.Name,
		OpenedIP:   link.OpenedIP,
		JoinedIP:   link.JoinedIP,
	}
	sess.Status = session.StatusActive
	sess.UpdatedAt = now
	sess.Audit = append(sess.Audit, capsule.AuditEvent{
		At:      now,
		Type:    "session.accepted",
		Message: "capsule joined the session",
	})
	if err := s.Store.SaveSession(sess); err != nil {
		_ = s.Runtime.Disconnect(context.Background(), sess.ID, opened.Runtime.PID, joined.Runtime.PID)
		return session.Session{}, err
	}
	if err := s.setEndpoint(opened, link.OpenedIP); err != nil {
		return sess, err
	}
	if err := s.setEndpoint(joined, link.JoinedIP); err != nil {
		return sess, err
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

func participant(sess session.Session, capsuleID string) bool {
	return capsuleID == sess.OpenedCapsule || (sess.JoinedCapsule != "" && capsuleID == sess.JoinedCapsule)
}

func allowFor(sess session.Session, capsuleID string) []string {
	if capsuleID == sess.OpenedCapsule {
		return sess.OpenedAllow
	}
	return sess.JoinedAllow
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
