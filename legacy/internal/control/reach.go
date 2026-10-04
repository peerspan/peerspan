package control

import (
	"context"

	"github.com/Cerebral-Systems/capsule/internal/capsule"
	"github.com/Cerebral-Systems/capsule/internal/runtime"
	"github.com/Cerebral-Systems/capsule/internal/session"
)

func (s Service) dropLink(sess session.Session) error {
	if sess.Link == nil {
		return nil
	}
	peers := make([]runtime.Peer, 0, len(sess.Members))
	local := map[string]bool{}
	capsules := make([]capsule.Capsule, 0, len(sess.Members))
	for _, member := range sess.Members {
		if !s.isLocal(member) {
			continue
		}
		local[member.CapsuleID] = true
		c, err := s.Store.Load(member.CapsuleID)
		if err != nil {
			return err
		}
		capsules = append(capsules, c)
		peers = append(peers, runtime.Peer{PID: c.Runtime.PID, Name: c.Network.Name})
	}
	var rt runtime.Runtime
	if len(capsules) == 0 {
		rt = s.Runtime
	} else {
		var err error
		rt, err = s.sessionRuntime(capsules)
		if err != nil {
			return err
		}
	}
	if rt != nil {
		if err := rt.Disconnect(context.Background(), sess.ID, s.Underlay, peers); err != nil {
			return err
		}
	}
	for _, endpoint := range sess.Link.Endpoints {
		if !local[endpoint.CapsuleID] {
			continue
		}
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
