package host

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/membership"
	"github.com/peerspan/peerspan/go/internal/tlsid"
)

func emptyMigrationEvidence() DecMigrationEvidence {
	return DecMigrationEvidence{Proposal: json.RawMessage(`"-"`), Source: "-", State: "-", Catalog: json.RawMessage(`"-"`), Acknowledgments: []json.RawMessage{}, Commit: json.RawMessage(`"-"`)}
}

// Only independently verified local source membership may open preparation
// exchange. A manual pin, recent synchronization or incoming roster cannot.
func checkMigrationSourcePeer(source *decMigrationSource, caller, own string) error {
	if source == nil || !dec.ValidPublicKey(caller) || !dec.ValidPublicKey(own) {
		return decFailure("forbidden")
	}
	for _, key := range []string{caller, own} {
		if !containsString(source.Snapshot.Hosts, key) {
			return decFailure("forbidden")
		}
	}
	return nil
}

// The adopted original transition has its own narrow historical read identity.
// It never supplies current DEC membership, repair admission or new authority.
func (s *Store) retainedMigrationEvidence(ctx context.Context, q dbQuerier, network, caller string) (DecMigrationEvidence, error) {
	_, d, _, e := readDecNetwork(ctx, q, network, s.identity.PublicKey)
	if e != nil {
		return DecMigrationEvidence{}, e
	}
	proposal, r, e := migrationRecord(ctx, q, network)
	if e != nil {
		return DecMigrationEvidence{}, e
	}
	if r.State != "adopted" || r.Migration == "-" || r.LocalAck == "-" || !r.Fenced {
		return DecMigrationEvidence{}, decFailure("forbidden")
	}
	var raw string
	if e = q.QueryRowContext(ctx, `SELECT record FROM dec_contexts WHERE network_id=? AND context_id=?`, network, d.ContextID).Scan(&raw); e != nil {
		return DecMigrationEvidence{}, e
	}
	var pin decContextRecord
	if dec.ReadPrivateRecord([]byte(raw), "format descriptor_base64 origin initial_root_state_id origin_proof_id migration_proposal_id adopted_at", &pin) != nil || pin.Format != 1 || pin.Origin != "migration" || pin.Proposal != proposal || pin.OriginProof != dec.ProofID("migration", mustDecBytes(r.Migration)) || pin.Descriptor != base64.StdEncoding.EncodeToString(d.Raw) {
		return DecMigrationEvidence{}, decStorageError()
	}
	now, e := decNow()
	if e != nil {
		return DecMigrationEvidence{}, e
	}
	verified, e := dec.VerifyMigration(d, []byte(`"-"`), []byte(`"-"`), mustDecBytes(r.Migration), linkTime(now), "evidence", "-")
	if e != nil {
		return DecMigrationEvidence{}, e
	}
	if verified.ProposalID != proposal || verified.RootStateID != pin.InitialRoot || verified.PreparedHash != decMigrationHash(mustDecBytes(r.PreparedCatalog)) {
		return DecMigrationEvidence{}, decStorageError()
	}
	evidence := migrationRecordEvidence(r)
	if _, e = readMigrationPrefix(d, evidence); e != nil {
		return DecMigrationEvidence{}, e
	}
	for _, key := range []string{caller, s.identity.PublicKey} {
		found := false
		for _, body := range evidence.Acknowledgments {
			ack, e := dec.ReadStatement(d, body)
			if e != nil {
				return DecMigrationEvidence{}, e
			}
			found = found || ack.Signer("host") == key
		}
		if !found {
			return DecMigrationEvidence{}, decFailure("forbidden")
		}
	}
	return evidence, nil
}

func (s *Store) migrationPeerEvidence(ctx context.Context, q dbQuerier, network, caller string) (DecMigrationEvidence, error) {
	var raw string
	if e := q.QueryRowContext(ctx, `SELECT record FROM networks WHERE id=?`, network).Scan(&raw); errors.Is(e, sql.ErrNoRows) {
		return DecMigrationEvidence{}, ErrNotFound
	} else if e != nil {
		return DecMigrationEvidence{}, e
	}
	var tag struct {
		Mode string `json:"mode"`
	}
	if json.Unmarshal([]byte(raw), &tag) != nil {
		return DecMigrationEvidence{}, decStorageError()
	}
	if tag.Mode == "decentralized" {
		return s.retainedMigrationEvidence(ctx, q, network, caller)
	}
	source, e := s.decMigrationSource(ctx, q, network)
	if e != nil {
		return DecMigrationEvidence{}, e
	}
	if e = checkMigrationSourcePeer(source, caller, s.identity.PublicKey); e != nil {
		return DecMigrationEvidence{}, e
	}
	_, r, e := migrationRecord(ctx, q, network)
	if errors.Is(e, ErrNotFound) {
		return emptyMigrationEvidence(), nil
	}
	if e != nil {
		return DecMigrationEvidence{}, e
	}
	if r.Proposal == "-" {
		return emptyMigrationEvidence(), nil
	}
	evidence := migrationRecordEvidence(r)
	prefix, e := readMigrationPrefix(source.Descriptor, evidence)
	if e != nil {
		return DecMigrationEvidence{}, e
	}
	if e = s.checkMigrationSourceKnown(ctx, q, source, prefix, evidence); e != nil {
		return DecMigrationEvidence{}, e
	}
	return evidence, nil
}

// Certificate recognition from a private adopted marker is identity only.
// Every route still applies its own current or exact historical authorization.
func (s *Store) retainedMigrationPeer(ctx context.Context, id string) (Peer, error) {
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return Peer{}, e
	}
	defer tx.Rollback()
	rows, e := tx.QueryContext(ctx, `SELECT network_id FROM dec_migrations WHERE json_extract(record,'$.state')='adopted' ORDER BY network_id`)
	if e != nil {
		return Peer{}, e
	}
	networks := []string{}
	for rows.Next() {
		var network string
		if e = rows.Scan(&network); e != nil {
			rows.Close()
			return Peer{}, e
		}
		networks = append(networks, network)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return Peer{}, e
	}
	for _, network := range networks {
		_, r, e := migrationRecord(ctx, tx, network)
		if e != nil {
			return Peer{}, e
		}
		d, e := migrationDescriptor(r)
		if e != nil {
			return Peer{}, e
		}
		for _, encoded := range r.Acknowledgments {
			ack, e := dec.ReadStatement(d, mustDecBytes(encoded))
			if e != nil {
				return Peer{}, e
			}
			key, e := membership.DecodeKey(ack.Signer("host"))
			if e != nil {
				return Peer{}, e
			}
			if membership.HostID(key) != id {
				continue
			}
			if _, e = s.retainedMigrationEvidence(ctx, tx, network, ack.Signer("host")); e != nil {
				return Peer{}, e
			}
			return Peer{ID: id, PublicKey: ack.Signer("host")}, nil
		}
	}
	return Peer{}, ErrNotFound
}

func decMigrationPeerRoutes(mux *http.ServeMux, s *Store, sender func(http.ResponseWriter, *http.Request) (string, bool), reserve func(http.ResponseWriter, *http.Request, int) (func(), bool)) {
	actual := func(w http.ResponseWriter, r *http.Request) (string, bool) {
		if _, ok := sender(w, r); !ok {
			return "", false
		}
		state := requestTLS(r)
		if state == nil {
			respondDec(w, 0, nil, decFailure("forbidden"), r.PathValue("id"), "-", "-", "migration")
			return "", false
		}
		key, e := tlsid.PeerKey(*state)
		if e != nil {
			respondDec(w, 0, nil, decFailure("forbidden"), r.PathValue("id"), "-", "-", "migration")
			return "", false
		}
		caller := membership.EncodeKey(key)
		tx, e := s.db.BeginTx(r.Context(), &sql.TxOptions{ReadOnly: true})
		if e == nil {
			_, e = s.migrationPeerEvidence(r.Context(), tx, r.PathValue("id"), caller)
			tx.Rollback()
		}
		if e != nil {
			respondDec(w, 0, nil, e, r.PathValue("id"), "-", "-", "migration")
			return "", false
		}
		return caller, true
	}
	get := func(ctx context.Context, network, caller string) (DecMigrationEvidence, error) {
		tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if e != nil {
			return DecMigrationEvidence{}, e
		}
		defer tx.Rollback()
		return s.migrationPeerEvidence(ctx, tx, network, caller)
	}
	mux.HandleFunc("GET /peer/v2/networks/{id}/migration", func(w http.ResponseWriter, r *http.Request) {
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
		value, e := get(r.Context(), r.PathValue("id"), caller)
		boundedDecPeerResponse(w, value, e, r.PathValue("id"), decPublicationLimit)
	})
	mux.HandleFunc("POST /peer/v2/networks/{id}/migration", func(w http.ResponseWriter, r *http.Request) {
		release, ok := reserve(w, r, decPublicationLimit)
		if !ok {
			return
		}
		defer release()
		caller, ok := actual(w, r)
		if !ok {
			return
		}
		var input DecMigrationEvidence
		if !decodeDecMutation(w, r, DecMigrationEvidenceFields, &input, decPublicationLimit) {
			return
		}
		if _, e := s.receiveDecMigration(r.Context(), r.PathValue("id"), input, caller); e != nil {
			boundedDecPeerResponse(w, nil, e, r.PathValue("id"), decPublicationLimit)
			return
		}
		value, e := get(r.Context(), r.PathValue("id"), caller)
		boundedDecPeerResponse(w, value, e, r.PathValue("id"), decPublicationLimit)
	})
}
