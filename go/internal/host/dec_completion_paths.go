package host

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"time"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/membership"
)

// A refreshed contact repairs paths only. The caller has already selected the
// actual immutable transcript participant; every TCP/QUIC attempt pins that
// same key before sending HTTP. Helpers supply no participant/adoption fact.
func (s *Store) decParticipantExchange(parent context.Context, pending decPending, carrier decCarrier, method, path string, body []byte) ([]byte, int, error) {
	if carrier.Kind != "participant" || !dec.ValidPublicKey(carrier.Key) || len(body) > decPublicationLimit {
		return nil, 0, decFailure("invalid")
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	s.peer.mu.Lock()
	mailbox := s.peer.mailbox
	s.peer.mu.Unlock()
	if mailbox == nil {
		return nil, 0, decTransportFailure()
	}
	release, ok := mailbox.ReserveCompletionExchange()
	if !ok {
		return nil, 0, decFailure("quota_exceeded")
	}
	defer release()
	resources := len(s.decResourceClients()) != 0
	connecting := 5 * time.Second
	if resources {
		connecting = 2 * time.Second
	}
	var last error = decTransportFailure()
	if carrier.Address != "" {
		tcp, stop := context.WithTimeout(ctx, connecting)
		raw, status, e := s.decBootstrapExchange(tcp, carrier, method, path, nil, body, decPublicationLimit, true)
		stop()
		if e == nil {
			return raw, status, nil
		}
		last = e
	}
	// Immutable historical TCP completion does not consult current contact or
	// decision-clock state. Only fallback needs current signed address hints.
	addresses, hintError := s.decCompletionQUICAddresses(ctx, pending, carrier.Key)
	if hintError != nil {
		if !resources {
			return nil, 0, hintError
		}
		// Explicit local helper selection still reaches the SAME transcript
		// pin without consuming any invalid/current-contact hint. Its response
		// gets the original complete-operation authority/history verification.
		addresses = nil
	}
	key, e := membership.DecodeKey(carrier.Key)
	if e != nil {
		return nil, 0, e
	}
	if len(addresses) == 0 && resources {
		addresses = []string{""}
	}
	for _, address := range addresses {
		if ctx.Err() != nil {
			break
		}
		peer := Peer{ID: membership.HostID(key), PublicKey: carrier.Key, Address: address}
		status, raw, e := s.decPinnedQUICRequest(ctx, peer, method, path, body, decPublicationLimit, DecCompletionALPN)
		if e == nil {
			return raw, status, nil
		}
		last = e
	}
	return nil, 0, last
}

func (s *Store) decCompletionQUICAddresses(ctx context.Context, pending decPending, key string) ([]string, error) {
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	now, e := decNow()
	if e != nil {
		return nil, e
	}
	guard := "-"
	var raw string
	e = tx.QueryRowContext(ctx, `SELECT record FROM dec_clock WHERE network_id=?`, pending.Descriptor.NetworkID).Scan(&raw)
	if e == nil {
		var clock decClockRecord
		if dec.ReadPrivateRecord([]byte(raw), "format largest_local_time", &clock) != nil || clock.Format != 1 {
			return nil, decStorageError()
		}
		guard = clock.Largest
	} else if !errors.Is(e, sql.ErrNoRows) {
		return nil, e
	}
	decision, e := dec.DecisionTime(linkTime(now), guard)
	if e != nil {
		return nil, e
	}
	addresses := map[string]bool{}
	for _, d := range []dec.Descriptor{pending.Descriptor, {NetworkID: "-", ContextID: "-"}} {
		contacts, e := readDecProductContacts(ctx, tx, &decSnapshot{Descriptor: d}, decision)
		if e != nil {
			return nil, e
		}
		if contact := contacts[key]; contact != nil {
			for _, address := range contact.Addresses.QUIC {
				addresses[address] = true
			}
		}
	}
	// The original reviewed invitation is also a signed transport hint. It
	// neither extends expired contact validity nor overrides a cached sequence.
	if pending.Record.Invitation != "-" {
		i, e := dec.ReadContactInvitationBody(mustDecBytes(pending.Record.Invitation))
		if e != nil {
			return nil, e
		}
		for _, contact := range i.Contacts {
			if contact.Host == key && contact.Current(decision) == nil {
				var sequence any
				e := tx.QueryRowContext(ctx, `SELECT sequence FROM dec_contacts WHERE network_id=? AND context_id=? AND host_key=?`, i.Descriptor.NetworkID, i.Context, key).Scan(&sequence)
				if e == nil {
					continue
				} // cached monotonic/conflict guard wins
				if !errors.Is(e, sql.ErrNoRows) {
					return nil, e
				}
				for _, address := range contact.Addresses.QUIC {
					addresses[address] = true
				}
			}
		}
	}
	result := make([]string, 0, len(addresses))
	for address := range addresses {
		result = append(result, address)
	}
	sort.Strings(result)
	if len(result) > 32 {
		return nil, decFailure("quota_exceeded")
	}
	return result, nil
}

// A participant need not advertise TCP. Ephemeral empty-address entries let
// exact transcript peers try their QUIC hints/explicit resources without adding
// an invalid carrier, host pin or new field to durable pending state.
func decCompletionCarriers(p decPending) ([]decCarrier, error) {
	result := append([]decCarrier{}, p.Record.Carriers...)
	participants := map[string]bool{p.Request.Writer: true}
	for _, body := range []string{p.Record.Owner, p.Record.Administrator} {
		if body == "-" {
			continue
		}
		packet, e := dec.ReadPacket(p.Descriptor, mustDecBytes(body))
		if e != nil {
			return nil, e
		}
		participants[packet.Writer] = true
	}
	keys := []string{}
	for key := range participants {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		found := false
		for _, carrier := range result {
			found = found || carrier.Kind == "participant" && carrier.Key == key
		}
		if !found {
			result = append(result, decCarrier{Kind: "participant", Key: key})
		}
	}
	return result, nil
}

// Exact ciphertext is already durably sealed before this attempt. Carrier
// failure is attention only; the caller still performs its final authority
// transaction on the original context, outside this transport deadline/locks.
func (s *Store) attemptDecCommitFrames(ctx context.Context, pending decPending) error {
	attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.publishDecFrames(attempt, pending)
}
