package host

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type DecSelectProvider struct {
	Provider string `json:"provider_id"`
	Person   string `json:"person_public_key"`
	Host     string `json:"host_public_key"`
	Approve  bool   `json:"approve"`
}
type decProviderSelectionResult struct {
	Network  DecNetworkView   `json:"network"`
	Provider *DecProviderView `json:"provider"`
	State    DecProviderState `json:"provider_state"`
}

func decOwnedDeviceSeed(ctx context.Context, q dbQuerier, public string) ([]byte, error) {
	var raw any
	var created string
	e := q.QueryRowContext(ctx, `SELECT seed,created_at FROM link_device_keys WHERE public_key=?`, public).Scan(&raw, &created)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, decFailure("signer_unavailable")
	}
	if e != nil {
		return nil, e
	}
	seed, ok := raw.([]byte)
	if !ok || len(seed) != 32 {
		return nil, decFailure("signer_unavailable")
	}
	if _, e = dec.ParseTime(created); e != nil {
		return nil, decFailure("signer_unavailable")
	}
	key := ed25519.NewKeyFromSeed(seed)
	if membership.EncodeKey(key.Public().(ed25519.PublicKey)) != public {
		return nil, decFailure("signer_unavailable")
	}
	return append([]byte{}, seed...), nil
}
func decRequestedProvider(snapshot *decSnapshot, p *dec.Projection, request DecSelectProvider) (*decSnapshot, *DecProviderView, error) {
	if !dec.ValidPublicKey(request.Person) || !dec.ValidPublicKey(request.Host) || request.Host != snapshot.Network.Own.Host {
		return nil, nil, decFailure("invalid")
	}
	selected := decSelectedProvider{Person: request.Person, Device: "-", Lease: "-"}
	if request.Provider == request.Person {
		selected.Kind = "original"
	} else if dec.ValidID(request.Provider, "ds_") {
		device := snapshot.Catalog.Statements[request.Provider]
		if device == nil {
			return nil, nil, decFailure("proof_required", request.Provider)
		}
		if device.Kind != "device_lease" || device.Lease.Subject.Person != request.Person || device.Lease.Subject.Host != request.Host {
			return nil, nil, decFailure("forbidden")
		}
		selected.Kind = "device"
		selected.Device = device.Lease.Subject.Device
		selected.Lease = device.ID
	} else {
		return nil, nil, decFailure("invalid")
	}
	proposed := *snapshot
	proposed.Provider = &selected
	view, e := decPublicProvider(&proposed, p)
	if e != nil {
		return nil, nil, e
	}
	return &proposed, view, nil
}
func (s *Store) SelectDecentralizedProvider(ctx context.Context, id string, request DecSelectProvider) (decProviderSelectionResult, error) {
	var result decProviderSelectionResult
	s.syncing.Lock()
	defer s.syncing.Unlock()
	now, e := decNow()
	if e != nil {
		return result, e
	}
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return result, e
	}
	old, e := s.loadDecSnapshot(ctx, tx, id)
	if e != nil {
		tx.Rollback()
		return result, e
	}
	p, e := verifyDecSnapshot(old, linkTime(now))
	if e != nil {
		tx.Rollback()
		return result, e
	}
	proposed, view, e := decRequestedProvider(old, p, request)
	if e != nil {
		tx.Rollback()
		return result, e
	}
	if proposed.Provider.Kind == "device" {
		proposed.DeviceSeed, e = decOwnedDeviceSeed(ctx, tx, proposed.Provider.Device)
		if e != nil {
			tx.Rollback()
			return result, e
		}
	}
	if e = tx.Rollback(); e != nil {
		return result, e
	}
	result = decProviderSelectionResult{s.decNetworkView(old, p), view, s.decProviderAvailable(proposed, view, nil)}
	if !request.Approve {
		return result, nil
	}
	tx, e = s.db.BeginTx(ctx, nil)
	if e != nil {
		return result, e
	}
	defer tx.Rollback()
	current, e := s.loadDecSnapshot(ctx, tx, id)
	if e != nil {
		return result, e
	}
	if old.Fingerprint != current.Fingerprint {
		return result, decFailure("state_conflict")
	}
	now, e = decNow()
	if e != nil {
		return result, e
	}
	p, e = verifyDecSnapshot(current, linkTime(now))
	if e != nil {
		return result, e
	}
	proposed, view, e = decRequestedProvider(current, p, request)
	if e != nil {
		return result, e
	}
	selected := proposed.Provider
	if selected.Kind == "device" {
		if _, e = decOwnedDeviceSeed(ctx, tx, selected.Device); e != nil {
			return result, e
		}
	}
	member, e := decCurrentMember(p, request.Host)
	if e != nil {
		return result, e
	}
	// Only this explicit owner-local consent updates the remembered identity.
	// Catalog replication and historical outcome retries leave it unchanged.
	record := current.Network
	record.Own.Person = request.Person
	record.Own.Member = member.View.Member
	raw, e := json.Marshal(record)
	if e != nil {
		return result, e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE networks SET record=? WHERE id=?`, string(raw), id); e != nil {
		return result, e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO dec_signers(network_id,context_id,provider_kind,person_key,device_key,lease_id) VALUES(?,?,?,?,?,?) ON CONFLICT(network_id,context_id) DO UPDATE SET provider_kind=excluded.provider_kind,person_key=excluded.person_key,device_key=excluded.device_key,lease_id=excluded.lease_id`, id, current.Descriptor.ContextID, selected.Kind, selected.Person, selected.Device, selected.Lease); e != nil {
		return result, e
	}
	clock, _ := json.Marshal(decClockRecord{1, p.DecisionTime})
	if _, e = tx.ExecContext(ctx, `UPDATE dec_clock SET record=? WHERE network_id=?`, string(clock), id); e != nil {
		return result, e
	}
	if e = tx.Commit(); e != nil {
		return result, e
	}
	current, p, e = s.decentralizedProjection(ctx, id, linkTime(now))
	if e != nil {
		return result, e
	}
	value := s.decNetworkView(current, p)
	return decProviderSelectionResult{value, value.Provider, value.ProviderState}, nil
}
