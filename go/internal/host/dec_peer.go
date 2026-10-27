package host

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"sort"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/membership"
	"github.com/peerspan/peerspan/go/internal/tlsid"
)

const decPublicationLimit = 20 << 20

func decRequireMember(snapshot *decSnapshot, p *dec.Projection, caller string) error {
	if len(snapshot.Fenced) > 0 {
		return decFailure("migration_pending", snapshot.Fenced...)
	}
	// The candidate never establishes the caller's right to use this route.
	for _, key := range []string{snapshot.Network.Own.Host, caller} {
		if !dec.ValidPublicKey(key) {
			return decFailure("forbidden")
		}
		if _, _, e := p.Current([]string{"host", key}); e != nil {
			return e
		}
	}
	return nil
}
func (s *Store) decPeerSnapshot(ctx context.Context, q dbQuerier, id, caller string) (*decSnapshot, *dec.Projection, error) {
	snapshot, e := s.loadDecSnapshot(ctx, q, id)
	if e != nil {
		return nil, nil, e
	}
	now, e := decNow()
	if e != nil {
		return nil, nil, e
	}
	p, e := verifyDecSnapshot(snapshot, linkTime(now))
	if e != nil {
		return nil, nil, e
	}
	if e = decRequireMember(snapshot, p, caller); e != nil {
		return nil, nil, e
	}
	return snapshot, p, nil
}
func boundedDecPeerResponse(w http.ResponseWriter, value any, e error, network string, max int) {
	if e != nil {
		respondDec(w, 0, nil, e, network, "-", "-", "transport")
		return
	}
	body, e := json.Marshal(value)
	if e != nil {
		respondDec(w, 0, nil, e, network, "-", "-", "transport")
		return
	}
	if len(body) > max {
		respondDec(w, 0, nil, decFailure("quota_exceeded"), network, "-", "-", "transport")
		return
	}
	respondDec(w, 200, json.RawMessage(body), nil, network, "-", "-", "transport")
}
func (s *Store) decentralizedPeerCatalog(ctx context.Context, id, caller string) (any, error) {
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	snapshot, _, e := s.decPeerSnapshot(ctx, tx, id, caller)
	if e != nil {
		return nil, e
	}
	return decCatalogResponse(snapshot), nil
}
func (s *Store) decentralizedPeerContacts(ctx context.Context, id, caller string) (any, error) {
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	snapshot, p, e := s.decPeerSnapshot(ctx, tx, id, caller)
	if e != nil {
		return nil, e
	}
	contacts, e := readDecProductContacts(ctx, tx, snapshot, p.DecisionTime)
	if e != nil {
		return nil, e
	}
	keys := sortedKeys(contacts)
	sort.Strings(keys)
	bodies := []json.RawMessage{}
	for _, key := range keys {
		if _, _, e := p.Current([]string{"host", key}); e == nil {
			bodies = append(bodies, json.RawMessage(contacts[key].Raw))
		}
	}
	return struct {
		Contacts []json.RawMessage `json:"contacts"`
	}{bodies}, nil
}
func (s *Store) receiveDecContact(ctx context.Context, id, caller string, body json.RawMessage) (any, error) {
	contact, e := dec.ReadContact(body)
	if e != nil {
		return nil, e
	}
	if contact.Host != caller {
		return nil, decFailure("forbidden")
	}
	s.syncing.Lock()
	defer s.syncing.Unlock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	snapshot, p, e := s.decPeerSnapshot(ctx, tx, id, caller)
	if e != nil {
		return nil, e
	}
	if contact.Context != snapshot.Descriptor.ContextID {
		return nil, decFailure("invalid")
	}
	if e = contact.Current(p.DecisionTime); e != nil {
		return nil, e
	}
	if _, e = cacheDecContact(ctx, tx, id, contact); e != nil {
		return nil, e
	}
	if _, p, e = s.decPeerSnapshot(ctx, tx, id, caller); e != nil {
		return nil, e
	}
	if e = contact.Current(p.DecisionTime); e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return struct {
		Contact json.RawMessage `json:"contact"`
	}{json.RawMessage(contact.Raw)}, nil
}
func decPeerRoutes(mux *http.ServeMux, s *Store, sender func(http.ResponseWriter, *http.Request) (string, bool)) {
	reserve := func(w http.ResponseWriter, r *http.Request, response int) (func(), bool) {
		request := int64(0)
		if r.Method == "POST" {
			request = r.ContentLength
			if request <= 0 || request > int64(response) || len(r.TransferEncoding) != 0 {
				respondDec(w, 0, nil, decFailure("invalid"), r.PathValue("id"), "-", "-", "transport")
				return nil, false
			}
		}
		size := request + int64(response)
		s.decTransport.mu.Lock()
		if s.decTransport.ReceiveBytes+size > 64<<20 {
			s.decTransport.mu.Unlock()
			respondDec(w, 0, nil, decFailure("rate_limited"), r.PathValue("id"), "-", "-", "transport")
			return nil, false
		}
		s.decTransport.ReceiveBytes += size
		s.decTransport.mu.Unlock()
		return func() { s.decTransport.mu.Lock(); s.decTransport.ReceiveBytes -= size; s.decTransport.mu.Unlock() }, true
	}
	decMigrationPeerRoutes(mux, s, sender, reserve)

	actual := func(w http.ResponseWriter, r *http.Request) (string, bool) {
		if _, ok := sender(w, r); !ok {
			return "", false
		}
		state := requestTLS(r)
		if state == nil {
			respondDec(w, 0, nil, decFailure("forbidden"), r.PathValue("id"), "-", "-", "transport")
			return "", false
		}
		key, e := tlsid.PeerKey(*state)
		if e != nil {
			respondDec(w, 0, nil, decFailure("forbidden"), r.PathValue("id"), "-", "-", "transport")
			return "", false
		}
		caller := membership.EncodeKey(key)
		tx, e := s.db.BeginTx(r.Context(), &sql.TxOptions{ReadOnly: true})
		if e == nil {
			_, _, e = s.decPeerSnapshot(r.Context(), tx, r.PathValue("id"), caller)
			_ = tx.Rollback()
		}
		if e != nil {
			respondDec(w, 0, nil, e, r.PathValue("id"), "-", "-", "transport")
			return "", false
		}
		return caller, true
	}
	mux.HandleFunc("GET /peer/v2/networks/{id}/catalog", func(w http.ResponseWriter, r *http.Request) {
		release, ok := reserve(w, r, decPublicationLimit)
		if !ok {
			return
		}
		defer release()
		if !validDecRead(w, r) {
			return
		}
		caller, ok := actual(w, r)
		if !ok {
			return
		}
		value, e := s.decentralizedPeerCatalog(r.Context(), r.PathValue("id"), caller)
		boundedDecPeerResponse(w, value, e, r.PathValue("id"), decPublicationLimit)
	})
	mux.HandleFunc("POST /peer/v2/networks/{id}/catalog", func(w http.ResponseWriter, r *http.Request) {
		release, ok := reserve(w, r, decPublicationLimit)
		if !ok {
			return
		}
		defer release()
		caller, ok := actual(w, r)
		if !ok {
			return
		}
		var input struct {
			Catalog json.RawMessage `json:"catalog"`
		}
		if !decodeDecMutation(w, r, "catalog", &input, decPublicationLimit) {
			return
		}
		snapshot, _, e := s.applyDecCatalogFromPeer(r.Context(), r.PathValue("id"), caller, input.Catalog)
		var value any
		if e == nil {
			value = decCatalogResponse(snapshot)
		}
		boundedDecPeerResponse(w, value, e, r.PathValue("id"), decPublicationLimit)
	})
	mux.HandleFunc("GET /peer/v2/networks/{id}/contacts", func(w http.ResponseWriter, r *http.Request) {
		release, ok := reserve(w, r, 1<<20)
		if !ok {
			return
		}
		defer release()
		if !validDecRead(w, r) {
			return
		}
		caller, ok := actual(w, r)
		if !ok {
			return
		}
		value, e := s.decentralizedPeerContacts(r.Context(), r.PathValue("id"), caller)
		boundedDecPeerResponse(w, value, e, r.PathValue("id"), 1<<20)
	})
	mux.HandleFunc("POST /peer/v2/networks/{id}/contact", func(w http.ResponseWriter, r *http.Request) {
		release, ok := reserve(w, r, 16<<10)
		if !ok {
			return
		}
		defer release()
		caller, ok := actual(w, r)
		if !ok {
			return
		}
		var input struct {
			Contact json.RawMessage `json:"contact"`
		}
		if !decodeDecMutation(w, r, "contact", &input, 16<<10) {
			return
		}
		value, e := s.receiveDecContact(r.Context(), r.PathValue("id"), caller, input.Contact)
		boundedDecPeerResponse(w, value, e, r.PathValue("id"), 16<<10)
	})
}
