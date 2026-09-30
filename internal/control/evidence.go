package control

import (
	"time"

	"github.com/Cerebral-Systems/capsule/internal/session"
)

func (s Service) evidence(sess session.Session) session.Evidence {
	ended := endedAt(sess)
	return session.Evidence{
		ID:           sess.ID,
		Task:         sess.Task,
		Status:       sess.Status,
		CreatedAt:    sess.CreatedAt,
		EndedAt:      ended,
		Participants: s.participants(sess),
		Transcript:   sess.Transcript,
		Artifacts:    sess.Artifacts,
		Approvals:    sess.Approvals,
		Reachability: sess.Link,
		Commands:     s.commandsDuring(sess, ended),
		Audit:        sess.Audit,
	}
}

func (s Service) participants(sess session.Session) []session.Participant {
	out := []session.Participant{s.participant(sess.HostCapsule, "opened", sess.HostAllow, sess.HostExec)}
	if sess.GuestCapsule != "" {
		out = append(out, s.participant(sess.GuestCapsule, "joined", sess.GuestAllow, sess.GuestExec))
	}
	return out
}

func (s Service) participant(id, role string, allow, allowExec []string) session.Participant {
	p := session.Participant{
		CapsuleID: id,
		Role:      role,
		Allow:     allow,
		AllowExec: allowExec,
	}
	c, err := s.Store.Load(id)
	if err != nil {
		return p
	}
	p.Owner = c.Owner
	p.Capabilities = c.Authority.Capabilities
	return p
}

func (s Service) commandsDuring(sess session.Session, ended *time.Time) []session.Executed {
	var out []session.Executed
	for _, id := range []string{sess.HostCapsule, sess.GuestCapsule} {
		if id == "" {
			continue
		}
		c, err := s.Store.Load(id)
		if err != nil {
			continue
		}
		for _, cmd := range c.Commands {
			if cmd.At.Before(sess.CreatedAt) {
				continue
			}
			if ended != nil && cmd.At.After(*ended) {
				continue
			}
			out = append(out, session.Executed{
				At:        cmd.At,
				CapsuleID: id,
				Argv:      cmd.Argv,
				ExitCode:  cmd.ExitCode,
			})
		}
	}
	return out
}

func endedAt(sess session.Session) *time.Time {
	if sess.Status != session.StatusRevoked && sess.Status != session.StatusExpired {
		return nil
	}
	for i := len(sess.Audit) - 1; i >= 0; i-- {
		event := sess.Audit[i]
		if event.Type == "session.revoked" || event.Type == "session.expired" {
			at := event.At
			return &at
		}
	}
	at := sess.UpdatedAt
	return &at
}
