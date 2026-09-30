package control

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Cerebral-Systems/capsule/internal/capsule"
	"github.com/Cerebral-Systems/capsule/internal/session"
)

// CreateSessionRequest opens a pending peering session from one capsule.
type CreateSessionRequest struct {
	CapsuleID string        `json:"capsule_id"`
	Task      string        `json:"task"`
	Allow     []string      `json:"allow,omitempty"`
	TTL       time.Duration `json:"-"`
}

// CreateSession records a pending session. The guest joins later through AcceptSession.
func (s Service) CreateSession(req CreateSessionRequest) (session.Session, error) {
	task := strings.TrimSpace(req.Task)
	if task == "" {
		return session.Session{}, fmt.Errorf("session create requires --task")
	}
	host, err := s.Inspect(req.CapsuleID)
	if err != nil {
		return session.Session{}, err
	}
	if host.Status != capsule.StatusRunning {
		return session.Session{}, fmt.Errorf("capsule %s is %s", host.ID, host.Status)
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
		ID:          id,
		Task:        task,
		Status:      session.StatusPending,
		HostCapsule: host.ID,
		HostAllow:   allow,
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
func (s Service) AcceptSession(id, capsuleID string, allow []string) (session.Session, error) {
	sess, err := s.loadSession(id)
	if err != nil {
		return session.Session{}, err
	}
	if sess.Status != session.StatusPending {
		return session.Session{}, fmt.Errorf("session %s is %s", sess.ID, sess.Status)
	}
	guest, err := s.Inspect(capsuleID)
	if err != nil {
		return session.Session{}, err
	}
	if guest.Status != capsule.StatusRunning {
		return session.Session{}, fmt.Errorf("capsule %s is %s", guest.ID, guest.Status)
	}
	if guest.ID == sess.HostCapsule {
		return session.Session{}, fmt.Errorf("session requires two capsules")
	}
	cleaned, err := cleanAllow(allow)
	if err != nil {
		return session.Session{}, err
	}
	now := s.now()
	sess.GuestCapsule = guest.ID
	sess.GuestAllow = cleaned
	sess.Status = session.StatusActive
	sess.UpdatedAt = now
	sess.Audit = append(sess.Audit, capsule.AuditEvent{
		At:      now,
		Type:    "session.accepted",
		Message: "guest capsule joined",
	})
	if err := s.Store.SaveSession(sess); err != nil {
		return session.Session{}, err
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
		return session.Session{}, fmt.Errorf("path %q is not allowlisted", rel)
	}
	c, err := s.Store.Load(capsuleID)
	if err != nil {
		return session.Session{}, err
	}
	src := filepath.Join(c.Runtime.WorkDir, rel)
	f, err := os.Open(src)
	if err != nil {
		return session.Session{}, err
	}
	defer f.Close()

	savedAs := filepath.Join("artifacts", capsuleID, filepath.Base(rel))
	dst := filepath.Join(s.Store.SessionDir(sess.ID), savedAs)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return session.Session{}, err
	}
	out, err := os.Create(dst)
	if err != nil {
		return session.Session{}, err
	}
	defer out.Close()
	hash := sha256.New()
	if _, err := io.Copy(out, io.TeeReader(f, hash)); err != nil {
		return session.Session{}, err
	}

	now := s.now()
	sess.Artifacts = append(sess.Artifacts, session.Artifact{
		At:        now,
		CapsuleID: capsuleID,
		Path:      rel,
		SHA256:    hex.EncodeToString(hash.Sum(nil)),
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

// ExportSession returns the session record, including transcript and artifacts.
func (s Service) ExportSession(id string) (session.Session, error) {
	return s.loadSession(id)
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
	return capsuleID == sess.HostCapsule || (sess.GuestCapsule != "" && capsuleID == sess.GuestCapsule)
}

func allowFor(sess session.Session, capsuleID string) []string {
	if capsuleID == sess.HostCapsule {
		return sess.HostAllow
	}
	return sess.GuestAllow
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
