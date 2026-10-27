package host

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
)

type decCapabilityClaim struct {
	snapshot   *decSnapshot
	projection *dec.Projection
	statement  *dec.Statement
	owner      string
}

func decContextMode(ctx context.Context, q dbQuerier, id string) (bool, error) {
	var mode string
	if e := q.QueryRowContext(ctx, `SELECT COALESCE(json_extract(record,'$.mode'),'') FROM networks WHERE id=?`, id).Scan(&mode); e != nil {
		return false, e
	}
	return mode == "decentralized", nil
}
func (s *Store) prepareDecCapabilityClaims(ctx context.Context, tx *sql.Tx, r CreateCapability, now string) (map[string]decCapabilityClaim, []CapabilityClaimCatalog, error) {
	claims := map[string]decCapabilityClaim{}
	legacy := []CapabilityClaimCatalog{}
	for _, entry := range r.Catalogs {
		modern, e := decContextMode(ctx, tx, entry.NetworkID)
		if e != nil {
			return nil, nil, e
		}
		if !modern {
			legacy = append(legacy, entry)
			continue
		}
		if _, duplicate := claims[entry.NetworkID]; duplicate {
			return nil, nil, decFailure("invalid")
		}
		snapshot, e := s.loadDecSnapshot(ctx, tx, entry.NetworkID)
		if e != nil {
			return nil, nil, e
		}
		p, e := verifyDecSnapshot(snapshot, now)
		if e != nil {
			return nil, nil, e
		}
		if len(snapshot.Fenced) > 0 {
			return nil, nil, decFailure("migration_pending", snapshot.Fenced...)
		}
		own, e := decCurrentMember(p, s.identity.PublicKey)
		if e != nil {
			return nil, nil, e
		}
		if own.BindingError != nil {
			return nil, nil, own.BindingError
		}
		if own.View.Person == "-" {
			return nil, nil, decFailure("forbidden")
		}
		catalog, e := dec.ReadCatalog(snapshot.Descriptor, entry.Catalog)
		if e != nil {
			return nil, nil, e
		}
		var maximum uint64
		for _, m := range snapshot.Prior.Maxima {
			if len(m.Stream) == 2 && m.Stream[0] == "policy" && m.Stream[1] == own.View.Person {
				maximum = m.Sequence
			}
		}
		current, _, currentError := p.Current([]string{"policy", own.View.Person})
		var selected, currentCandidate *dec.Statement
		for _, id := range sortedKeys(catalog.Statements) {
			candidate := catalog.Statements[id]
			if candidate.Kind != "policy" {
				continue
			}
			body, e := decPolicyBody(candidate)
			if e != nil {
				return nil, nil, e
			}
			if body.Person != own.View.Person {
				continue
			}
			if candidate.Access.Sequence > maximum {
				if selected != nil && selected.ID != candidate.ID {
					return nil, nil, decFailure("state_conflict")
				}
				selected = candidate
			} else if currentError == nil && candidate.ID == current.ID {
				currentCandidate = candidate
			}
		}
		if selected == nil {
			selected = currentCandidate
		}
		if selected == nil {
			return nil, nil, decFailure("forbidden")
		}
		selected, e = exactDecPreparedClaim(ctx, tx, snapshot, catalog, selected)
		if e != nil {
			return nil, nil, e
		}
		if e = checkDecClaimPolicy(selected, r.Name, s.identity.ID); e != nil {
			return nil, nil, e
		}
		if currentError != nil || selected.ID != current.ID {
			actor := dec.Actor{Person: own.View.Person, Host: "-", Device: "-", IssuerID: "-"}
			if selected.Access.Issuer.Kind == "device" {
				actor.IssuerID = decParentID(selected.Access.Parents, "issuer_device")
				issuer := snapshot.Catalog.Statements[actor.IssuerID]
				if issuer == nil {
					return nil, nil, decFailure("proof_required", actor.IssuerID)
				}
				if issuer.Kind != "device_lease" {
					return nil, nil, decFailure("invalid")
				}
				actor.Host, actor.Device = issuer.Lease.Subject.Host, issuer.Lease.Subject.Device
			}
			actorRaw, _ := json.Marshal(actor)
			if _, e = dec.VerifyActionIntent(snapshot.Descriptor, snapshot.PriorRaw, snapshot.Catalog.Raw, actorRaw, selected.Payload, now, "policy"); e != nil {
				return nil, nil, e
			}
		}
		if currentError != nil || selected.ID != current.ID {
			if e = checkDecActionEditBoundary(ctx, tx, snapshot, selected); e != nil {
				return nil, nil, e
			}
		}
		projected, e := dec.Project(snapshot.Descriptor, snapshot.PriorRaw, catalog.Raw, now, "fresh")
		if e != nil {
			return nil, nil, e
		}
		actual, _, e := projected.Current([]string{"policy", own.View.Person})
		if e != nil {
			return nil, nil, e
		}
		if actual.ID != selected.ID {
			return nil, nil, decFailure("state_conflict")
		}
		if _, e = s.planDecProofs(ctx, tx, snapshot, projected); e != nil {
			return nil, nil, e
		}
		claims[entry.NetworkID] = decCapabilityClaim{snapshot, projected, selected, own.View.Person}
	}
	return claims, legacy, nil
}
func (s *Store) applyDecCapabilityClaims(ctx context.Context, tx *sql.Tx, claims map[string]decCapabilityClaim) error {
	if len(claims) == 0 {
		return nil
	}
	for _, id := range sortedKeys(claims) {
		claim := claims[id]
		plan, e := s.planDecProofs(ctx, tx, claim.snapshot, claim.projection)
		if e != nil {
			return e
		}
		if e = s.storeDecProjection(ctx, tx, claim.snapshot, claim.projection); e != nil {
			return e
		}
		if e = s.settleDecPolicyEdits(ctx, tx, claim.snapshot, claim.statement, claim.projection.DecisionTime, false); e != nil {
			return e
		}
		if e = plan.store(ctx, tx); e != nil {
			return e
		}
	}
	// The entire multi-network fanout must fit together. Refusal rolls every
	// projection, edit, queue and capability change back in this transaction.
	held, e := heldDecDeliveries(ctx, tx)
	if e != nil {
		return e
	}
	if e = checkDecDeliveryBudget(held, nil, nil); e != nil {
		return e
	}
	now, e := decNow()
	if e != nil {
		return e
	}
	for _, id := range sortedKeys(claims) {
		claim := claims[id]
		snapshot, e := s.loadDecSnapshot(ctx, tx, id)
		if e != nil {
			return e
		}
		projection, e := verifyDecSnapshot(snapshot, linkTime(now))
		if e != nil {
			return e
		}
		own, e := decCurrentMember(projection, s.identity.PublicKey)
		if e != nil {
			return e
		}
		if own.BindingError != nil {
			return own.BindingError
		}
		if own.View.Person != claim.owner {
			return decFailure("forbidden")
		}
		policy, _, e := projection.Current([]string{"policy", claim.owner})
		if e != nil {
			return e
		}
		if policy.ID != claim.statement.ID {
			return decFailure("state_conflict")
		}
		clock, _ := json.Marshal(decClockRecord{1, projection.DecisionTime})
		if _, e = tx.ExecContext(ctx, `UPDATE dec_clock SET record=? WHERE network_id=?`, string(clock), id); e != nil {
			return e
		}
	}
	return nil
}

// If this host already retained a completed typed claim, a repeated catalog
// must carry that exact signed original. A semantic alias cannot replace its
// cached reference, even though every alias is independently verified.
func exactDecPreparedClaim(ctx context.Context, q dbQuerier, snapshot *decSnapshot, catalog *dec.Catalog, statement *dec.Statement) (*dec.Statement, error) {
	body, e := decPolicyBody(statement)
	if e != nil {
		return nil, e
	}
	provider := body.Person
	if statement.Access.Issuer.Kind == "device" {
		provider = decParentID(statement.Access.Parents, "issuer_device")
	}
	operation := dec.ActionID(snapshot.Descriptor.ContextID, "policy_claim", statement.ID, provider)
	intent, e := findDecAction(ctx, q, snapshot.Descriptor.NetworkID, operation)
	if errors.Is(e, ErrNotFound) {
		return statement, nil
	}
	if e != nil {
		return nil, e
	}
	if intent.Kind != "policy_claim" {
		return nil, decStorageError()
	}
	if !intent.Record.Completed {
		return statement, nil
	}
	_, original, raw, e := readDecAction(intent, snapshot.Descriptor)
	if e != nil {
		return nil, e
	}
	received := catalog.Proofs[dec.ProofID("policy", raw)]
	if received == nil || received.ID != original.ID || !bytes.Equal(received.Raw, raw) {
		return nil, decFailure("operation_conflict")
	}
	return original, nil
}
