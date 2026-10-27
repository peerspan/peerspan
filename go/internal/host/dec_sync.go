package host

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"sync"
	"time"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type DecSyncResult struct {
	Network     DecNetworkView `json:"network"`
	Attempted   []string       `json:"attempted"`
	Learned     []string       `json:"learned_proof_ids"`
	Unavailable []DecPeerError `json:"unavailable"`
}

type decSyncTarget struct {
	Key     string
	Contact *dec.Contact
}

// A contact supplies addresses only after the corresponding exact host has
// independent durable admission. The catalog arriving over this connection
// can never establish the transport's right to submit it.
func (s *Store) decSyncInputs(ctx context.Context, network string) (*decSnapshot, *dec.Projection, []decSyncTarget, error) {
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return nil, nil, nil, e
	}
	defer tx.Rollback()
	snapshot, e := s.loadDecSnapshot(ctx, tx, network)
	if e != nil {
		return nil, nil, nil, e
	}
	now, e := decNow()
	if e != nil {
		return nil, nil, nil, e
	}
	p, e := verifyDecSnapshot(snapshot, linkTime(now))
	if e != nil {
		return nil, nil, nil, e
	}
	contacts, e := readDecProductContacts(ctx, tx, snapshot, p.DecisionTime)
	if e != nil {
		return nil, nil, nil, e
	}
	remembered := map[string]bool{}
	for _, id := range snapshot.Prior.AdmittedStatements {
		if statement := snapshot.Catalog.Statements[id]; statement != nil && statement.Kind == "host_lease" {
			remembered[statement.Lease.Subject.Host] = true
		}
	}
	targets := []decSyncTarget{}
	for _, key := range sortedKeys(remembered) {
		if key != s.identity.PublicKey {
			targets = append(targets, decSyncTarget{key, contacts[key]})
		}
	}
	return snapshot, p, targets, nil
}

func decTransportCode(e error) string {
	var failure *dec.Failure
	if errors.As(e, &failure) {
		return failure.Code
	}
	return "recovery_required"
}

func decPeerResponse(status int, body []byte) error {
	if status == 200 {
		return nil
	}
	var wire struct {
		Code    string          `json:"code"`
		Error   string          `json:"error"`
		Details decErrorDetails `json:"details"`
	}
	if dec.ReadPrivateRecord(body, "code error details", &wire) != nil {
		return decTransportFailure()
	}
	// Only protocol errors from the authenticated actual peer are propagated.
	expected := map[string]int{"invalid": 400, "forbidden": 403, "authority_expired": 403, "device_revoked": 403, "not_yet_valid": 403, "not_found": 404, "expired": 410, "rate_limited": 429, "upgrade_required": 426, "proof_required": 409, "state_conflict": 409, "operation_conflict": 409, "version_exhausted": 409, "quota_exceeded": 409, "clock_rollback": 409, "migration_pending": 409, "review_required": 409, "signer_unavailable": 409, "recovery_required": 409}
	if expected[wire.Code] != status {
		return decTransportFailure()
	}
	return decFailure(wire.Code, wire.Details.Required...)
}

func (s *Store) reserveDecExchange(size int64) (func(), error) {
	s.decTransport.mu.Lock()
	defer s.decTransport.mu.Unlock()
	if size < 0 || s.decTransport.ReceiveBytes+size > 64<<20 {
		return nil, decFailure("rate_limited")
	}
	s.decTransport.ReceiveBytes += size
	return func() { s.decTransport.mu.Lock(); s.decTransport.ReceiveBytes -= size; s.decTransport.mu.Unlock() }, nil
}

// Each address is tried with the SAME independently pinned host identity.
// Neither contact sequence nor a DNS result can replace that key.
func (s *Store) decOrdinaryExchange(ctx context.Context, network string, target decSyncTarget, method, path string, body []byte, max int) ([]byte, error) {
	if target.Contact == nil || target.Contact.Host != target.Key {
		return nil, decTransportFailure()
	}
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return nil, e
	}
	_, p, e := s.decPeerSnapshot(ctx, tx, network, target.Key)
	_ = tx.Rollback()
	if e != nil {
		return nil, e
	}
	if e = target.Contact.Current(p.DecisionTime); e != nil {
		return nil, e
	}
	release, e := s.reserveDecExchange(int64(len(body) + max))
	if e != nil {
		return nil, e
	}
	defer release()
	key, e := membership.DecodeKey(target.Key)
	if e != nil {
		return nil, decFailure("invalid")
	}
	var last error = decTransportFailure()
	addresses := append([]string{}, target.Contact.Addresses.QUIC...)
	if len(addresses) == 0 && len(s.decResourceClients()) != 0 {
		addresses = []string{""}
	}
	for _, address := range addresses {
		if ctx.Err() != nil {
			return nil, decTransportFailure()
		}
		peer := Peer{ID: membership.HostID(key), PublicKey: target.Key, Address: address}
		status, raw, e := s.decPinnedQUICRequest(ctx, peer, method, path, body, max, PeerALPN)
		if e != nil {
			last = decTransportFailure()
			continue
		}
		if e = decPeerResponse(status, raw); e != nil {
			return nil, e
		}
		return raw, nil
	}
	return nil, last
}

// DEC contacts never fall through the old coordinator-relay chooser, even
// when the same exact peer also occurs in retained legacy history.
func (s *Store) decPinnedQUICRequest(ctx context.Context, peer Peer, method, path string, body []byte, max int, protocol string) (int, []byte, error) {
	transport, e := s.peerUDP(nil)
	if e != nil {
		return 0, nil, e
	}
	config, e := s.PeerTLS(ctx, &peer)
	if e != nil {
		return 0, nil, e
	}
	config.NextProtos = []string{protocol}
	resources := s.decResourceClients()
	bound := 5 * time.Second
	if len(resources) != 0 {
		bound = 2 * time.Second
	}
	connecting, cancel := context.WithTimeout(ctx, bound)
	defer cancel()
	host, port, e := net.SplitHostPort(peer.Address)
	n, portError := strconv.Atoi(port)
	addresses := []netip.Addr{}
	if e != nil || portError != nil || n < 1 || n > 65535 {
		// An empty direct hint is valid only as a transport attempt through
		// explicitly selected resources; no endpoint/pin is synthesized.
		if len(resources) == 0 {
			return 0, nil, decTransportFailure()
		}
	} else if ip, e := netip.ParseAddr(host); e == nil {
		addresses = append(addresses, ip)
	} else {
		addresses, e = net.DefaultResolver.LookupNetIP(connecting, "ip", host)
		if e != nil && len(resources) == 0 {
			return 0, nil, e
		}
	}
	var last error = decTransportFailure()
	for _, address := range addresses {
		conn, e := transport.Dial(connecting, net.UDPAddrFromAddrPort(netip.AddrPortFrom(address, uint16(n))), config, PeerQUICConfig(false))
		if e != nil {
			last = e
			continue
		}
		if conn.ConnectionState().TLS.NegotiatedProtocol != protocol {
			_ = conn.CloseWithError(1, "wrong protocol")
			return 0, nil, decTransportFailure()
		}
		status, raw, e := peerStreamRequest(ctx, conn, peer.Address, method, path, body, max)
		_ = conn.CloseWithError(0, "exchange complete")
		return status, raw, e
	}
	if len(resources) != 0 {
		conn, e := s.dialDecResourcePeer(ctx, transport, peer, config, resources)
		if e != nil {
			return 0, nil, e
		}
		status, raw, e := peerStreamRequest(ctx, conn, "relay.invalid", method, path, body, max)
		_ = conn.CloseWithError(0, "exchange complete")
		return status, raw, e
	}
	return 0, nil, last
}

func decResponseCatalog(d dec.Descriptor, raw []byte) (*dec.Catalog, error) {
	var response struct {
		Catalog json.RawMessage `json:"catalog"`
	}
	if e := dec.ReadPrivateRecord(raw, "catalog", &response); e != nil {
		return nil, e
	}
	return dec.ReadCatalog(d, response.Catalog)
}

func (s *Store) syncDecTarget(ctx context.Context, network string, target decSyncTarget) error {
	path := "/peer/v2/networks/" + url.PathEscape(network) + "/catalog"
	raw, e := s.decOrdinaryExchange(ctx, network, target, "GET", path, nil, decPublicationLimit)
	if e != nil {
		// Proof repair discloses public evidence only to an independently
		// remembered unrevoked member. It does not open ordinary peer routes.
		return s.fetchDecRepair(ctx, network, target)
	}
	snapshot, _, _, e := s.decSyncInputs(ctx, network)
	if e != nil {
		return e
	}
	catalog, e := decResponseCatalog(snapshot.Descriptor, raw)
	if e != nil {
		return e
	}
	snapshot, _, e = s.applyDecCatalogFromPeer(ctx, network, target.Key, catalog.Raw)
	if e != nil {
		return e
	}
	body, e := json.Marshal(struct {
		Catalog json.RawMessage `json:"catalog"`
	}{snapshot.Catalog.Raw})
	if e != nil {
		return e
	}
	if len(body) > decPublicationLimit {
		return decFailure("quota_exceeded")
	}
	raw, e = s.decOrdinaryExchange(ctx, network, target, "POST", path, body, decPublicationLimit)
	if e != nil {
		return e
	}
	catalog, e = decResponseCatalog(snapshot.Descriptor, raw)
	if e != nil {
		return e
	}
	if _, _, e = s.applyDecCatalogFromPeer(ctx, network, target.Key, catalog.Raw); e != nil {
		return e
	}
	return s.syncDecContacts(ctx, network, target)
}

func (s *Store) syncDecContacts(ctx context.Context, network string, target decSyncTarget) error {
	own, e := s.refreshDecLocalContact(ctx, network)
	if e != nil {
		return e
	}
	if own != nil {
		body, e := json.Marshal(struct {
			Contact json.RawMessage `json:"contact"`
		}{own.Raw})
		if e != nil {
			return e
		}
		raw, e := s.decOrdinaryExchange(ctx, network, target, "POST", "/peer/v2/networks/"+url.PathEscape(network)+"/contact", body, 16<<10)
		if e != nil {
			return e
		}
		var reply struct {
			Contact json.RawMessage `json:"contact"`
		}
		if dec.ReadPrivateRecord(raw, "contact", &reply) != nil || !bytes.Equal(reply.Contact, own.Raw) {
			return decTransportFailure()
		}
	}
	raw, e := s.decOrdinaryExchange(ctx, network, target, "GET", "/peer/v2/networks/"+url.PathEscape(network)+"/contacts", nil, 1<<20)
	if e != nil {
		return e
	}
	var response struct {
		Contacts []json.RawMessage `json:"contacts"`
	}
	if e = dec.ReadPrivateRecord(raw, "contacts", &response); e != nil {
		return e
	}
	if response.Contacts == nil || len(response.Contacts) > 4096 {
		return decFailure("invalid")
	}
	contacts := []*dec.Contact{}
	lastKey := ""
	for _, body := range response.Contacts {
		contact, e := dec.ReadContact(body)
		if e != nil {
			return e
		}
		if lastKey >= contact.Host {
			return decFailure("invalid")
		}
		lastKey = contact.Host
		contacts = append(contacts, contact)
	}
	s.syncing.Lock()
	defer s.syncing.Unlock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	snapshot, p, e := s.decPeerSnapshot(ctx, tx, network, target.Key)
	if e != nil {
		return e
	}
	retained := []*dec.Contact{}
	for _, contact := range contacts {
		if contact.Context != snapshot.Descriptor.ContextID {
			return decFailure("invalid")
		}
		if _, _, e = p.Current([]string{"host", contact.Host}); e != nil {
			continue
		}
		if contact.Current(p.DecisionTime) != nil {
			continue
		}
		if _, e = cacheDecContact(ctx, tx, network, contact); e != nil {
			return e
		}
		retained = append(retained, contact)
	}
	if _, p, e = s.decPeerSnapshot(ctx, tx, network, target.Key); e != nil {
		return e
	}
	for _, contact := range retained {
		if e = contact.Current(p.DecisionTime); e != nil {
			return e
		}
	}
	return tx.Commit()
}

// Renew only our own transport hint. This host-key signature cannot renew any
// membership lease, create consent or change the persistent provider choice.
func (s *Store) refreshDecLocalContact(ctx context.Context, network string) (*dec.Contact, error) {
	s.syncing.Lock()
	defer s.syncing.Unlock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	snapshot, p, e := s.decPeerSnapshot(ctx, tx, network, s.identity.PublicKey)
	if e != nil {
		return nil, e
	}
	contacts, e := readDecProductContacts(ctx, tx, snapshot, p.DecisionTime)
	if e != nil {
		return nil, e
	}
	now, e := dec.ParseTime(p.DecisionTime)
	if e != nil {
		return nil, e
	}
	s.decTransport.mu.RLock()
	addresses := dec.ContactPayload{QUIC: append([]string{}, s.decTransport.QUIC...), Bootstrap: append([]string{}, s.decTransport.Bootstrap...), Relays: []dec.ContactRelay{}}
	for _, helper := range s.decTransport.Relays {
		addresses.Relays = append(addresses.Relays, dec.ContactRelay{Address: helper.Address, PublicKey: helper.Key})
	}
	s.decTransport.mu.RUnlock()
	if old := contacts[s.identity.PublicKey]; old != nil {
		expires, e := dec.ParseTime(old.Expires)
		if e != nil {
			return nil, e
		}
		want, _ := json.Marshal(addresses)
		if expires.After(now.Add(120*time.Second)) && bytes.Equal(want, old.Payload) {
			return old, nil
		}
	}
	bodies, e := s.decOwnContact(ctx, tx, network, snapshot.Descriptor.ContextID, linkTime(now), linkTime(now.Add(300*time.Second)))
	if e != nil {
		return nil, e
	}
	if len(bodies) == 0 {
		return nil, nil
	}
	contact, e := dec.ReadContact(bodies[0])
	if e != nil {
		return nil, e
	}
	if _, p, e = s.decPeerSnapshot(ctx, tx, network, s.identity.PublicKey); e != nil {
		return nil, e
	}
	if e = contact.Current(p.DecisionTime); e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return contact, nil
}

func (s *Store) SyncDecentralizedNetwork(ctx context.Context, network string) (DecSyncResult, error) {
	result := DecSyncResult{Attempted: []string{}, Learned: []string{}, Unavailable: []DecPeerError{}}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	before, _, targets, e := s.decSyncInputs(ctx, network)
	var held map[string]bool
	if e != nil {
		if decTransportCode(e) != "proof_required" {
			return result, e
		}
		view, repairError := s.decRepairSnapshot(ctx, network)
		if repairError != nil {
			return result, repairError
		}
		held = decSet(view.Catalog.ProofIDs())
		targets = []decSyncTarget{}
		for _, key := range sortedKeys(view.Hosts) {
			if key != s.identity.PublicKey {
				targets = append(targets, decSyncTarget{key, view.Contacts[key]})
			}
		}
	} else {
		held = decSet(before.Catalog.ProofIDs())
	}
	type answer struct {
		key string
		e   error
	}
	jobs := make(chan decSyncTarget)
	answers := make(chan answer, len(targets))
	workers := 4
	if len(targets) < workers {
		workers = len(targets)
	}
	for n := 0; n < workers; n++ {
		go func() {
			for target := range jobs {
				answers <- answer{target.Key, s.syncDecTarget(ctx, network, target)}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, target := range targets {
			jobs <- target
		}
	}()
	for range targets {
		answer := <-answers
		result.Attempted = append(result.Attempted, answer.key)
		if answer.e != nil {
			result.Unavailable = append(result.Unavailable, DecPeerError{answer.key, decTransportCode(answer.e)})
		}
	}
	sort.Strings(result.Attempted)
	sort.Slice(result.Unavailable, func(i, j int) bool { return result.Unavailable[i].Host < result.Unavailable[j].Host })
	after, p, _, e := s.decSyncInputs(ctx, network)
	if e != nil {
		return result, e
	}
	for _, id := range after.Catalog.ProofIDs() {
		if !held[id] {
			result.Learned = append(result.Learned, id)
		}
	}
	result.Network = s.decNetworkView(after, p)
	if _, _, e = p.Current([]string{"host", s.identity.PublicKey}); e != nil {
		return result, e
	}
	return result, nil
}

// A delivery is retired only after a strict, authenticated response actually
// retains every exact queued proof. Unknown failures leave the original body.
func (s *Store) deliverDecProofs(ctx context.Context, row decHeldDelivery) error {
	snapshot, _, targets, e := s.decSyncInputs(ctx, row.Network)
	if e != nil {
		return e
	}
	var target decSyncTarget
	for _, candidate := range targets {
		if candidate.Key == row.Target {
			target = candidate
			break
		}
	}
	if target.Key == "" {
		return decFailure("forbidden")
	}
	if row.Context != snapshot.Descriptor.ContextID || row.Record.Kind != "proofs" {
		return decFailure("invalid")
	}
	raw, e := s.decOrdinaryExchange(ctx, row.Network, target, "POST", "/peer/v2/networks/"+url.PathEscape(row.Network)+"/catalog", row.Body, decPublicationLimit)
	if e != nil {
		return e
	}
	catalog, e := decResponseCatalog(snapshot.Descriptor, raw)
	if e != nil {
		return e
	}
	proofs := decSet(catalog.ProofIDs())
	for _, id := range row.Record.Proofs {
		if !proofs[id] {
			return decFailure("proof_required", id)
		}
	}
	if _, _, e = s.applyDecCatalogFromPeer(ctx, row.Network, target.Key, catalog.Raw); e != nil {
		return e
	}
	s.syncing.Lock()
	defer s.syncing.Unlock()
	_, e = s.db.ExecContext(ctx, `DELETE FROM dec_outbox WHERE delivery_id=? AND network_id=? AND context_id=? AND target_key=? AND record=?`, row.ID, row.Network, row.Context, row.Target, row.Raw)
	return e
}

func (s *Store) retryDecOutbox(ctx context.Context, row decHeldDelivery) {
	attempt, cancel := context.WithTimeout(ctx, 30*time.Second)
	e := s.deliverDecProofs(attempt, row)
	cancel()
	if e == nil {
		return
	}
	updated := row.Record
	if updated.Attempts < ^uint64(0) {
		updated.Attempts++
	}
	power := updated.Attempts
	if power > 6 {
		power = 6
	}
	delay := time.Duration(1<<power) * time.Second
	if delay > 60*time.Second {
		delay = 60 * time.Second
	}
	updated.Next = linkTime(time.Now().Add(delay))
	updated.Code, updated.Detail = decTransportCode(e), decTransportCode(e)
	raw, e := json.Marshal(updated)
	if e != nil {
		return
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE dec_outbox SET record=? WHERE delivery_id=? AND record=?`, string(raw), row.ID, row.Raw)
}

func (s *Store) RunDecentralizedReplication(ctx context.Context) {
	relaysDone := make(chan struct{})
	go func() { defer close(relaysDone); s.runDecResourceRelays(ctx) }()
	defer func() { <-relaysDone }()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	next := time.Now().Add(60 * time.Second)
	done := make(chan string, 4)
	active := map[string]bool{}
	antiDone := make(chan struct{}, 1)
	antiActive := false
	var workers sync.WaitGroup
	defer workers.Wait()
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-done:
			delete(active, id)
			continue
		case <-antiDone:
			antiActive = false
			var jitter [1]byte
			_, _ = rand.Read(jitter[:])
			next = time.Now().Add(60*time.Second + time.Duration(jitter[0]%11)*time.Second)
			continue
		case <-tick.C:
		}
		held, e := heldDecDeliveries(ctx, s.db)
		if e == nil {
			for _, row := range held {
				if len(active) >= 4 {
					break
				}
				when, e := dec.ParseTime(row.Record.Next)
				if e != nil || active[row.ID] || time.Now().Before(when) {
					continue
				}
				active[row.ID] = true
				workers.Add(1)
				go func(row decHeldDelivery) { defer workers.Done(); s.retryDecOutbox(ctx, row); done <- row.ID }(row)
			}
		}
		if antiActive || time.Now().Before(next) {
			continue
		}
		antiActive = true
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { antiDone <- struct{}{} }()
			ids, e := s.networkIDs(ctx, s.db)
			if e == nil {
				for _, id := range ids {
					modern, e := decContextMode(ctx, s.db, id)
					if e == nil && modern {
						_, _ = s.SyncDecentralizedNetwork(ctx, id)
					}
					if ctx.Err() != nil {
						return
					}
				}
			}
		}()
	}
}
