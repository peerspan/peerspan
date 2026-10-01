package control

import (
	"fmt"
	"strings"

	"github.com/Cerebral-Systems/capsule/internal/capsule"
	"github.com/Cerebral-Systems/capsule/internal/secret"
	"github.com/Cerebral-Systems/capsule/internal/session"
)

func (s Service) authorizeExec(c capsule.Capsule, argv []string) error {
	command := strings.Join(argv, " ")
	values, err := s.secretValues(c.Authority.Secrets)
	if err != nil {
		return err
	}
	shown := secret.Redact(command, values)
	if !hasCap(c.Authority.Capabilities, "exec") && !hasCap(c.Authority.Capabilities, "exec:approval-required") {
		return s.auditCapsule(c, "command.denied", "capsule has no exec capability")
	}
	sessions, err := s.activeSessionsFor(c.ID)
	if err != nil {
		return err
	}
	needsApproval := hasCap(c.Authority.Capabilities, "exec:approval-required")
	if len(sessions) == 0 {
		if needsApproval && !hasCap(c.Authority.Capabilities, "exec") {
			return fmt.Errorf("approval required for exec %s", shown)
		}
		return nil
	}
	action := "exec " + shown
	for _, sess := range sessions {
		if !allowed(execAllow(sess, c.ID), command) && !allowed(execAllow(sess, c.ID), "*") {
			_, err := s.auditSession(sess, c.ID, "command.denied", fmt.Sprintf("command %q is not allowlisted", shown))
			return err
		}
		if !needsApproval {
			continue
		}
		switch approvalStatus(sess, c.ID, action) {
		case session.ApprovalGranted:
		case session.ApprovalPending:
			return fmt.Errorf("approval required for %s", action)
		default:
			_, err := s.pendApproval(sess, c.ID, action)
			return err
		}
	}
	return nil
}

// ApproveSession records a granted approval for a share or exec action.
func (s Service) ApproveSession(id, capsuleID, action string) (session.Session, error) {
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
	action = strings.TrimSpace(action)
	if action == "" {
		return session.Session{}, fmt.Errorf("session approve requires --action")
	}
	now := s.now()
	updated := false
	for i := range sess.Approvals {
		if sess.Approvals[i].CapsuleID == capsuleID && sess.Approvals[i].Action == action {
			sess.Approvals[i].Status = session.ApprovalGranted
			sess.Approvals[i].At = now
			updated = true
		}
	}
	if !updated {
		sess.Approvals = append(sess.Approvals, session.Approval{
			At:        now,
			CapsuleID: capsuleID,
			Action:    action,
			Status:    session.ApprovalGranted,
		})
	}
	sess.UpdatedAt = now
	sess.Audit = append(sess.Audit, capsule.AuditEvent{
		At:      now,
		Type:    "session.approved",
		Message: capsuleID + " approved " + action,
	})
	if err := s.Store.SaveSession(sess); err != nil {
		return session.Session{}, err
	}
	return sess, nil
}

func (s Service) activeSessionsFor(capsuleID string) ([]session.Session, error) {
	all, err := s.Store.ListSessions()
	if err != nil {
		return nil, err
	}
	var active []session.Session
	for _, sess := range all {
		loaded, err := s.loadSession(sess.ID)
		if err != nil {
			return nil, err
		}
		if loaded.Status == session.StatusActive && participant(loaded, capsuleID) {
			active = append(active, loaded)
		}
	}
	return active, nil
}

func (s Service) auditCapsule(c capsule.Capsule, eventType, message string) error {
	now := s.now()
	c.UpdatedAt = now
	c.Audit = append(c.Audit, capsule.AuditEvent{At: now, Type: eventType, Message: message})
	if err := s.Store.Save(c); err != nil {
		return err
	}
	return fmt.Errorf("%s", message)
}

func (s Service) auditSession(sess session.Session, capsuleID, eventType, message string) (session.Session, error) {
	now := s.now()
	sess.UpdatedAt = now
	sess.Audit = append(sess.Audit, capsule.AuditEvent{
		At:      now,
		Type:    eventType,
		Message: capsuleID + ": " + message,
	})
	if err := s.Store.SaveSession(sess); err != nil {
		return session.Session{}, err
	}
	return sess, fmt.Errorf("%s", message)
}

func (s Service) pendApproval(sess session.Session, capsuleID, action string) (session.Session, error) {
	now := s.now()
	sess.Approvals = append(sess.Approvals, session.Approval{
		At:        now,
		CapsuleID: capsuleID,
		Action:    action,
		Status:    session.ApprovalPending,
	})
	sess.UpdatedAt = now
	sess.Audit = append(sess.Audit, capsule.AuditEvent{
		At:      now,
		Type:    "approval.pending",
		Message: "approval required for " + action,
	})
	if err := s.Store.SaveSession(sess); err != nil {
		return session.Session{}, err
	}
	return sess, fmt.Errorf("approval required for %s", action)
}

func hasCap(caps []string, name string) bool {
	for _, cap := range caps {
		if cap == name {
			return true
		}
	}
	return false
}

func execAllow(sess session.Session, capsuleID string) []string {
	member, ok := sess.Member(capsuleID)
	if !ok {
		return nil
	}
	return member.AllowExec
}

func approvalStatus(sess session.Session, capsuleID, action string) string {
	status := ""
	for _, approval := range sess.Approvals {
		if approval.CapsuleID == capsuleID && approval.Action == action {
			status = approval.Status
		}
	}
	return status
}
