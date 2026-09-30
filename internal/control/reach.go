package control

import (
	"context"

	"github.com/Cerebral-Systems/capsule/internal/capsule"
	"github.com/Cerebral-Systems/capsule/internal/session"
)

func (s Service) dropLink(sess session.Session) error {
	if sess.Link == nil || s.Runtime == nil {
		return nil
	}
	opened, err := s.Store.Load(sess.OpenedCapsule)
	if err != nil {
		return err
	}
	joined, err := s.Store.Load(sess.JoinedCapsule)
	if err != nil {
		return err
	}
	if err := s.Runtime.Disconnect(context.Background(), sess.ID, opened.Runtime.PID, joined.Runtime.PID); err != nil {
		return err
	}
	if err := s.clearEndpoint(opened.ID, sess.Link.OpenedIP); err != nil {
		return err
	}
	return s.clearEndpoint(joined.ID, sess.Link.JoinedIP)
}

func (s Service) setEndpoint(c capsule.Capsule, ip string) error {
	for _, existing := range c.Network.Endpoints {
		if existing == ip {
			return nil
		}
	}
	c.Network.Endpoints = append(c.Network.Endpoints, ip)
	c.UpdatedAt = s.now()
	return s.Store.Save(c)
}

func (s Service) clearEndpoint(id, ip string) error {
	if ip == "" {
		return nil
	}
	c, err := s.Store.Load(id)
	if err != nil {
		return err
	}
	var next []string
	for _, existing := range c.Network.Endpoints {
		if existing != ip {
			next = append(next, existing)
		}
	}
	c.Network.Endpoints = next
	c.UpdatedAt = s.now()
	return s.Store.Save(c)
}
