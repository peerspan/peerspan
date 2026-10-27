package host

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type DecPolicyReapplyPreview struct {
	Context   string          `json:"context_id"`
	Person    string          `json:"person_public_key"`
	Host      string          `json:"host_public_key"`
	Provider  DecProviderView `json:"provider"`
	Payload   string          `json:"payload_base64"`
	Unsettled []int64         `json:"unsettled_seqs"`
}

// This POST is a pure read: no intent, guard write, signature, agent/key probe,
// reservation, peer request or edit settlement. External originals are public
// path choices; the existing action ceremony will perform actual signing.
func (s *Store) PreviewDecentralizedPolicyReapply(ctx context.Context, network, provider string) (DecPolicyReapplyPreview, error) {
	var result DecPolicyReapplyPreview
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return result, e
	}
	defer tx.Rollback()
	snapshot, e := s.loadDecSnapshot(ctx, tx, network)
	if e != nil {
		return result, e
	}
	now, e := decCreationClock(ctx, tx, network)
	if e != nil {
		return result, e
	}
	p, e := verifyDecSnapshot(snapshot, now)
	if e != nil {
		return result, e
	}
	if provider == "network_root" {
		return result, decFailure("forbidden")
	}
	selected := snapshot
	if provider != "auto" {
		selected, _, e = decRequestedProvider(snapshot, p, DecSelectProvider{Provider: provider, Person: snapshot.Network.Own.Person, Host: s.identity.PublicKey})
		if e != nil {
			return result, e
		}
	}
	view, e := decPublicProvider(selected, p)
	if e != nil {
		return result, e
	}
	if view.Scopes&1 == 0 || view.Person != snapshot.Network.Own.Person || view.Host != s.identity.PublicKey {
		return result, decFailure("forbidden")
	}
	if selected.Provider.Kind == "device" {
		if _, e = decOwnedDeviceSeed(ctx, tx, selected.Provider.Device); e != nil {
			return result, e
		}
	}
	current, _, e := decPolicyStream(snapshot, view.Person)
	if e != nil {
		return result, e
	}
	body := decEmptyPolicyBody()
	if current != nil {
		if e = p.CompleteProof(current.ID); e != nil {
			return result, e
		}
		old, e := decPolicyBody(current)
		if e != nil {
			return result, e
		}
		body = old.delta()
	}
	edits, e := readDecPolicyEdits(ctx, tx, snapshot, view.Person)
	if e != nil {
		return result, e
	}
	result = DecPolicyReapplyPreview{snapshot.Descriptor.ContextID, view.Person, view.Host, *view, "-", []int64{}}
	for _, edit := range edits {
		if edit.State == editUnsettled {
			result.Unsettled = append(result.Unsettled, edit.Seq)
		}
	}
	if len(result.Unsettled) != 0 {
		merged, _, _, e := decReappliedPolicy(snapshot, body, edits, view.Person, s.identity.ID)
		if e != nil {
			return result, e
		}
		merged.Edits = membership.WithEdit(merged.Edits, s.identity.ID, result.Unsettled[len(result.Unsettled)-1])
		payload, e := decPolicyUpdatePayload(snapshot, p, *view, merged, p.DecisionTime)
		if e != nil {
			return result, e
		}
		if len(payload) > dec.MaxPayload {
			return result, decFailure("quota_exceeded")
		}
		if _, e = dec.ReadActionPayload(snapshot.Descriptor, "policy", payload); e != nil {
			return result, e
		}
		result.Payload = base64.StdEncoding.EncodeToString(payload)
	}
	raw, e := json.Marshal(result)
	if e != nil {
		return result, e
	}
	if len(raw) > dec.MaxPrivateRecord {
		return result, decFailure("quota_exceeded")
	}
	return result, nil
}
