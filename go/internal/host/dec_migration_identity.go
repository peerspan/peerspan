package host

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type DecMigrationRoster struct {
	Host   string `json:"host_public_key"`
	Member string `json:"member"`
	Person string `json:"person_public_key"`
	Device string `json:"device_public_key"`
	Scopes uint64 `json:"scopes"`
}

func (r *DecMigrationRoster) UnmarshalJSON(raw []byte) error {
	type plain DecMigrationRoster
	return dec.ReadPrivateRecord(raw, "host_public_key member person_public_key device_public_key scopes", (*plain)(r))
}

type DecMigrationReview struct {
	Stage        string               `json:"stage"`
	Network      string               `json:"network_id"`
	Proposal     string               `json:"proposal_id"`
	LegacyRoot   string               `json:"legacy_root_public_key"`
	Epoch        uint64               `json:"legacy_epoch"`
	Context      string               `json:"new_context_id"`
	Roster       []DecMigrationRoster `json:"roster"`
	SourceHash   string               `json:"source_catalog_sha256"`
	StateHash    string               `json:"source_state_sha256"`
	PreparedHash string               `json:"prepared_catalog_sha256"`
	Warning      string               `json:"authority_warning"`
}

const decMigrationReviewFields = "stage network_id proposal_id legacy_root_public_key legacy_epoch new_context_id roster source_catalog_sha256 source_state_sha256 prepared_catalog_sha256 authority_warning"

type DecMigrationIdentityRequest struct {
	Scopes  uint64 `json:"scopes"`
	Approve bool   `json:"approve"`
}
type DecMigrationIdentityResult struct {
	Migration DecMigrationView    `json:"migration"`
	Identity  DecMigrationRoster  `json:"identity"`
	Review    DecMigrationReview  `json:"review"`
	Signing   []DecSigningRequest `json:"signing_requests"`
}

func readDecMigrationIdentityIntent(i decIntent) (DecMigrationReview, error) {
	var review DecMigrationReview
	r := i.Record
	if i.Kind != "migration_identity" || !dec.ValidID(i.Network, "net_") || i.Context != "-" || r.Operation != "-" || r.Root != "-" || r.Provider != (decIntentProvider{Kind: "host", Signer: r.Host, Format: "ed25519", Lease: "-"}) || !dec.ValidPublicKey(r.Host) || !r.Approved || !r.Completed || r.NotAfter != "-" || r.Result != "-" || len(r.Templates) != 0 || len(r.Signatures) != 0 || r.Terminal != "-" && r.Terminal != "applied" {
		return review, decStorageError()
	}
	created, e := dec.ParseTime(r.Created)
	if e != nil {
		return review, e
	}
	expires, e := dec.ParseTime(r.Expires)
	if e != nil {
		return review, e
	}
	if expires.Sub(created) != 300*time.Second {
		return review, decStorageError()
	}
	raw, e := decBytes(r.Review, 1<<20)
	if e != nil {
		return review, e
	}
	if e = dec.ReadPrivateRecord(raw, decMigrationReviewFields, &review); e != nil {
		return review, e
	}
	if review.Stage != "identity" || review.Network != i.Network || review.Proposal != "-" || review.Context != "-" || review.PreparedHash != "-" || !dec.ValidPublicKey(review.LegacyRoot) || !dec.ValidID(review.SourceHash, "") || !dec.ValidID(review.StateHash, "") || len(review.Roster) != 1 || review.Warning == "" || len(review.Warning) > 1024 {
		return review, decStorageError()
	}
	row := review.Roster[0]
	if row.Host != r.Host || row.Person != r.Person || row.Device != r.Device || row.Scopes != r.Scopes || !membership.ValidLabel(row.Member) || row.Person == "-" && (row.Device != "-" || row.Scopes != 0 || i.Secret != nil) || row.Person != "-" && (!dec.ValidPublicKey(row.Person) || !dec.ValidPublicKey(row.Device) || row.Scopes == 0 || row.Scopes > 15) {
		return review, decStorageError()
	}
	if i.Secret != nil && (len(i.Secret) != ed25519.SeedSize || r.Terminal == "applied" || membership.EncodeKey(ed25519.NewKeyFromSeed(i.Secret).Public().(ed25519.PublicKey)) != row.Device) {
		return review, decStorageError()
	}
	return review, nil
}

func (s *Store) migrationIdentityIntent(ctx context.Context, q dbQuerier, network string) (*decIntent, error) {
	rows, e := q.QueryContext(ctx, `SELECT intent_id FROM dec_intents WHERE network_id=? AND kind='migration_identity' ORDER BY intent_id`, network)
	if e != nil {
		return nil, e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return nil, e
		}
		ids = append(ids, id)
		if len(ids) > 4096 {
			rows.Close()
			return nil, decStorageError()
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	var found *decIntent
	for _, id := range ids {
		i, e := readDecIntent(ctx, q, id)
		if e != nil {
			return nil, e
		}
		if i.Record.Host != s.identity.PublicKey {
			return nil, decStorageError()
		}
		if i.Record.Terminal == "applied" {
			continue
		}
		if found != nil {
			return nil, decFailure("operation_conflict")
		}
		copy := i
		found = &copy
	}
	return found, nil
}

func (s *Store) migrationOwnIdentity(ctx context.Context, q dbQuerier, source *decMigrationSource, scopes uint64) (DecMigrationRoster, error) {
	row := DecMigrationRoster{Host: s.identity.PublicKey, Person: "-", Device: "-", Scopes: scopes}
	for _, member := range source.Facts.Members {
		if member.HostPublicKey == row.Host {
			row.Member, row.Person = member.Member, member.PersonPublicKey
			break
		}
	}
	if row.Member == "" {
		return row, decFailure("forbidden")
	}
	if row.Person == "-" {
		if scopes != 0 {
			return row, decFailure("operation_conflict")
		}
		return row, nil
	}
	if scopes == 0 || scopes > 15 {
		return row, decFailure("invalid")
	}
	var person, device, certificate string
	e := q.QueryRowContext(ctx, `SELECT person_key,device_key,certificate_id FROM link_signers WHERE network_id=?`, source.Network.ID).Scan(&person, &device, &certificate)
	if errors.Is(e, sql.ErrNoRows) {
		return row, nil
	}
	if e != nil {
		return row, e
	}
	if person != row.Person || !dec.ValidPublicKey(device) || !linkID(certificate, "dc_") {
		return row, decFailure("operation_conflict")
	}
	body, exists := source.Facts.Facts.State.Certificates[certificate]
	if !exists {
		return row, decFailure("proof_required", certificate)
	}
	var old struct {
		Person  string `json:"person_public_key"`
		Host    string `json:"host_public_key"`
		Device  string `json:"device_public_key"`
		Request string `json:"request_id"`
		Scopes  uint64 `json:"scopes"`
	}
	if json.Unmarshal(body, &old) != nil || old.Person != person || old.Host != row.Host || old.Device != device || old.Scopes == 0 || old.Scopes > 15 {
		return row, decStorageError()
	}
	if !source.Facts.Facts.State.ActivatedCertificates[certificate] {
		return row, decFailure("proof_required", old.Request)
	}
	if scopes != old.Scopes {
		return row, decFailure("operation_conflict")
	}
	row.Device = device
	return row, nil
}

func decMigrationIdentityReview(source *decMigrationSource, row DecMigrationRoster) DecMigrationReview {
	return DecMigrationReview{Stage: "identity", Network: source.Network.ID, Proposal: "-", LegacyRoot: source.Facts.RootPublicKey, Epoch: source.Facts.Epoch, Context: "-", Roster: []DecMigrationRoster{row}, SourceHash: decMigrationHash(source.Catalog), StateHash: decMigrationHash(source.State), PreparedHash: "-", Warning: "This approves only this machine's unchanged migration identity. Every original owner and known host must separately approve the exact proposal and finite authority. A later acknowledgment creates a durable fence with no timeout abort; this identity approval does not."}
}

func (s *Store) PrepareDecentralizedMigrationIdentity(ctx context.Context, network string, input DecMigrationIdentityRequest) (result DecMigrationIdentityResult, err error) {
	if !dec.ValidID(network, "net_") || input.Scopes > 15 {
		return result, decFailure("invalid")
	}
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	s.syncing.Lock()
	defer s.syncing.Unlock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return result, e
	}
	defer tx.Rollback()
	source, e := s.decMigrationSource(ctx, tx, network)
	if e != nil {
		return result, e
	}
	row, e := s.migrationOwnIdentity(ctx, tx, source, input.Scopes)
	if e != nil {
		return result, e
	}
	prior, e := s.migrationIdentityIntent(ctx, tx, network)
	if e != nil {
		return result, e
	}
	review := decMigrationIdentityReview(source, row)
	if prior != nil {
		saved, e := readDecMigrationIdentityIntent(*prior)
		if e != nil {
			return result, e
		}
		old := saved.Roster[0]
		if old.Host != row.Host || old.Member != row.Member || old.Person != row.Person || old.Scopes != row.Scopes || row.Device != "-" && old.Device != row.Device || row.Device == "-" && old.Person != "-" && prior.Secret == nil {
			return result, decFailure("operation_conflict")
		}
		row, review = old, saved
		if input.Approve && row.Device != "-" && prior.Secret == nil {
			if _, e = loadLinkDevice(ctx, tx, row.Device); e != nil {
				return result, decFailure("signer_unavailable")
			}
		}
		// Exact approved retries remain nonsigning historical identity reads.
		// They neither regenerate a key nor refresh approved_at/clock/window.
		return DecMigrationIdentityResult{emptyDecMigrationView(network), row, review, []DecSigningRequest{}}, nil
	}
	if !input.Approve {
		return DecMigrationIdentityResult{emptyDecMigrationView(network), row, review, []DecSigningRequest{}}, nil
	}
	if e = decIntentCapacity(ctx, tx); e != nil {
		return result, e
	}
	var seed []byte
	if row.Person != "-" {
		if row.Device == "-" {
			public, private, e := ed25519.GenerateKey(rand.Reader)
			if e != nil {
				return result, e
			}
			row.Device = membership.EncodeKey(public)
			seed = append([]byte{}, private.Seed()...)
		} else if _, e = loadLinkDevice(ctx, tx, row.Device); e != nil {
			return result, decFailure("signer_unavailable")
		}
	}
	review = decMigrationIdentityReview(source, row)
	reviewRaw, e := json.Marshal(review)
	if e != nil {
		return result, e
	}
	created, e := dec.ParseTime(source.Time)
	if e != nil {
		return result, e
	}
	id, e := decRandomID("dint_")
	if e != nil {
		return result, e
	}
	now, e := decCreationClock(ctx, tx, network)
	if e != nil {
		return result, e
	}
	decision, e := dec.DecisionTime(now, source.Time)
	if e != nil {
		return result, e
	}
	if decision > linkTime(created.Add(300*time.Second)) {
		return result, decFailure("review_required")
	}
	i := decIntent{ID: id, Network: network, Context: "-", Kind: "migration_identity", Secret: seed, Record: decIntentRecord{Format: 1, Operation: "-", Approved: true, ApprovedAt: decision, Review: base64.StdEncoding.EncodeToString(reviewRaw), Provider: decIntentProvider{Kind: "host", Signer: row.Host, Format: "ed25519", Lease: "-"}, Root: "-", Person: row.Person, Host: row.Host, Device: row.Device, Scopes: row.Scopes, NotAfter: "-", Created: source.Time, Expires: linkTime(created.Add(300 * time.Second)), Templates: []decIntentTemplate{}, Signatures: []decIntentSignature{}, Completed: true, Terminal: "-", Result: "-"}}
	if e = storeDecIntent(ctx, tx, i, true); e != nil {
		return result, e
	}
	clock, _ := json.Marshal(decClockRecord{1, decision})
	if _, e = tx.ExecContext(ctx, `INSERT INTO dec_clock(network_id,record) VALUES(?,?) ON CONFLICT(network_id) DO UPDATE SET record=excluded.record`, network, string(clock)); e != nil {
		return result, e
	}
	if e = tx.Commit(); e != nil {
		return result, e
	}
	return DecMigrationIdentityResult{emptyDecMigrationView(network), row, review, []DecSigningRequest{}}, nil
}
