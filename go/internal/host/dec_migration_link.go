package host

import (
	"context"
	"crypto/ed25519"
	"encoding/json"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type DecMigrationLinkRequest struct {
	Proposal string `json:"proposal_id"`
}

type decMigrationLinkContext struct {
	Source *decMigrationSource
	Prefix *decMigrationPrefix
	Record decMigrationRecord
	Own    DecMigrationRoster
	Seed   []byte
}

// This is private preparation, never a new-mode Snapshot or reusable provider.
// Every local phase rechecks the original source and the host's own separately
// approved tuple. Remote roster claims cannot supply this private approval.
func (s *Store) migrationPreparationContext(ctx context.Context, q dbQuerier, network, proposal, now string) (*decMigrationLinkContext, error) {
	if !dec.ValidID(network, "net_") || !dec.ValidID(proposal, "ds_") {
		return nil, decFailure("invalid")
	}
	source, e := s.decMigrationSource(ctx, q, network)
	if e != nil {
		return nil, e
	}
	id, record, e := migrationRecord(ctx, q, network)
	if e != nil {
		return nil, e
	}
	if id != proposal {
		return nil, decFailure("state_conflict")
	}
	if !record.Approved || record.Proposal == "-" {
		return nil, decFailure("review_required")
	}
	if record.State == "adopted" || record.State == "conflict" {
		return nil, decFailure("state_conflict")
	}
	evidence := migrationRecordEvidence(record)
	prefix, e := readMigrationPrefix(source.Descriptor, evidence)
	if e != nil {
		return nil, e
	}
	if prefix.Proposal.ID != proposal || record.Context != source.Descriptor.ContextID {
		return nil, decStorageError()
	}
	if e = s.checkMigrationSourceKnown(ctx, q, source, prefix, evidence); e != nil {
		return nil, e
	}
	if now < prefix.Fields.Issued {
		return nil, decFailure("clock_rollback")
	}
	if now >= prefix.Fields.Expires {
		return nil, decFailure("expired")
	}
	if e = s.checkMigrationOwnRoster(ctx, q, source, prefix.Fields.Roster); e != nil {
		return nil, e
	}
	var own DecMigrationRoster
	for _, row := range prefix.Fields.Roster {
		if row.Host == s.identity.PublicKey {
			own = row
		}
	}
	if own.Host == "" {
		return nil, decFailure("forbidden")
	}
	return &decMigrationLinkContext{Source: source, Prefix: prefix, Record: record, Own: own}, nil
}

func (s *Store) migrationLinkContext(ctx context.Context, q dbQuerier, network, proposal, now string) (*decMigrationLinkContext, error) {
	staged, e := s.migrationPreparationContext(ctx, q, network, proposal, now)
	if e != nil {
		return nil, e
	}
	if staged.Own.Person == "-" {
		return nil, decFailure("forbidden")
	}
	identity, e := s.migrationIdentityIntent(ctx, q, network)
	if e != nil {
		return nil, e
	}
	if identity == nil {
		return nil, decFailure("review_required")
	}
	seed := append([]byte{}, identity.Secret...)
	if seed == nil || len(seed) == 0 {
		seed, e = decOwnedDeviceSeed(ctx, q, staged.Own.Device)
		if e != nil {
			return nil, e
		}
	}
	if len(seed) != ed25519.SeedSize || membership.EncodeKey(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)) != staged.Own.Device {
		return nil, decFailure("signer_unavailable")
	}
	staged.Seed = seed
	return staged, nil
}

func decSelectedRendezvous(ctx context.Context, q dbQuerier) ([]dec.ContactRelay, error) {
	rows, e := q.QueryContext(ctx, `SELECT address,public_key,record FROM dec_helpers WHERE kind='rendezvous' ORDER BY address,public_key`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	helpers := []dec.ContactRelay{}
	for rows.Next() {
		var address, key, raw string
		if e = rows.Scan(&address, &key, &raw); e != nil {
			return nil, e
		}
		var setting struct {
			Format  uint64 `json:"format"`
			Enabled bool   `json:"enabled"`
		}
		if dec.ReadPrivateRecord([]byte(raw), "format enabled", &setting) != nil || setting.Format != 1 || !dec.ValidEndpoint(address) || !dec.ValidPublicKey(key) {
			return nil, decStorageError()
		}
		if setting.Enabled {
			helpers = append(helpers, dec.ContactRelay{Address: address, PublicKey: key})
			if len(helpers) > 4 {
				return nil, decFailure("quota_exceeded")
			}
		}
	}
	return helpers, rows.Err()
}

func (s *Store) CreateDecentralizedMigrationLink(ctx context.Context, network string, input DecMigrationLinkRequest) (json.RawMessage, bool, error) {
	if !dec.ValidID(network, "net_") || !dec.ValidID(input.Proposal, "ds_") {
		return nil, false, decFailure("invalid")
	}
	return s.createDecentralizedLink(ctx, DecLinkCreate{Mode: "new", Network: network, Person: "-", Migration: input.Proposal, Invitation: "-", Helpers: []dec.ContactRelay{}})
}

func (s *Store) decRequesterDeviceSeed(ctx context.Context, q dbQuerier, p decPending, now string) ([]byte, error) {
	if p.Record.Migration == "-" {
		return decOwnedDeviceSeed(ctx, q, p.Record.Device)
	}
	staged, e := s.migrationLinkContext(ctx, q, p.Record.Network, p.Record.Migration, now)
	if e != nil {
		return nil, e
	}
	if p.Record.Mode != "new" || p.Record.Host != staged.Own.Host || p.Record.Person != staged.Own.Person || p.Record.Device != staged.Own.Device || p.Record.Context != staged.Source.Descriptor.ContextID {
		return nil, decFailure("operation_conflict")
	}
	return staged.Seed, nil
}
