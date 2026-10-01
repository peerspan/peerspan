package control

import (
	"context"

	"github.com/Cerebral-Systems/capsule/internal/capsule"
	"github.com/Cerebral-Systems/capsule/internal/runtime"
	"github.com/Cerebral-Systems/capsule/internal/session"
)

func (s Service) dropLink(sess session.Session) error {
	if sess.Link == nil || s.Runtime == nil {
		return nil
	}
	peers := make([]runtime.Peer, 0, len(sess.Members))
	for _, member := range sess.Members {
		c, err := s.Store.Load(member.CapsuleID)
		if err != nil {
			return err
		}
		peers = append(peers, runtime.Peer{PID: c.Runtime.PID, Name: c.Network.Name})
	}
	if err := s.Runtime.Disconnect(context.Background(), sess.ID, peers); err != nil {
		return err
	}
	for _, endpoint := range sess.Link.Endpoints {
		if err := s.clearEndpoint(endpoint.CapsuleID, endpoint.IP); err != nil {
			return err
		}
	}
	return nil
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
