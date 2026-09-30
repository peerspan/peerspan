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
	host, err := s.Store.Load(sess.HostCapsule)
	if err != nil {
		return err
	}
	guest, err := s.Store.Load(sess.GuestCapsule)
	if err != nil {
		return err
	}
	if err := s.Runtime.Disconnect(context.Background(), sess.ID, host.Runtime.PID, guest.Runtime.PID); err != nil {
		return err
	}
	if err := s.clearEndpoint(host.ID, sess.Link.HostIP); err != nil {
		return err
	}
	return s.clearEndpoint(guest.ID, sess.Link.GuestIP)
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
