package host

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/peerspan/peerspan/go/internal/membership"
)

func (s *Store) hasLinkSigner(ctx context.Context, network string) (bool, error) {
	var found bool
	e := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM link_signers WHERE network_id=?)`, network).Scan(&found)
	return found, e
}

func (s *Store) policyRenewalDecisionTime(ctx context.Context, network string, g governance, legacyNow time.Time) (bool, time.Time, error) {
	selected, e := s.hasLinkSigner(ctx, network)
	if e != nil || !selected {
		return selected, legacyNow, e
	}
	if g.linking == nil {
		return true, time.Time{}, linkFail("state_conflict", "-", "feature")
	}
	now, e := linkNow()
	return true, now, e
}
func (s *Store) nextLinkPolicy(ctx context.Context, network string, current membership.Policy, body membership.PolicyBody, duration time.Duration) (LinkActionRequest, error) {
	selected, e := s.LinkSigner(ctx, network)
	if e != nil {
		return LinkActionRequest{}, e
	}
	if selected.PersonPublicKey != current.PersonPublicKey {
		return LinkActionRequest{}, linkFail("forbidden", "-", "person")
	}
	now, e := linkNow()
	if e != nil {
		return LinkActionRequest{}, e
	}
	versions, e := s.LinkAccessVersions(ctx, network)
	if e != nil {
		return LinkActionRequest{}, e
	}
	maximum := current.Version
	for _, policy := range versions.Policies {
		if policy.PersonPublicKey == current.PersonPublicKey {
			maximum = max(maximum, policy.Version)
		}
	}
	version, e := membership.NextAccessVersion(maximum)
	if e != nil {
		return LinkActionRequest{}, e
	}
	until := now.Add(duration)
	if selected.NotAfter != "-" {
		limit, e := linkStamp(selected.NotAfter)
		if e != nil {
			return LinkActionRequest{}, e
		}
		if limit.Before(until) {
			until = limit
		}
	}
	policy := membership.Policy{Format: 2, NetworkID: network, PersonPublicKey: current.PersonPublicKey, Version: version, IssuedAt: linkTime(now), ValidUntil: linkTime(until), Rules: body.Rules, CapabilityRules: body.CapabilityRules, TrustedHosts: body.TrustedHosts, Edits: body.Edits, Signature: "-"}
	if e = membership.CheckPolicy(network, policy); e != nil {
		return LinkActionRequest{}, e
	}
	raw, e := linkJSON(policy)
	if e != nil {
		return LinkActionRequest{}, e
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return LinkActionRequest{}, linkFail("invalid", "-", "policy")
	}
	delete(fields, "signature")
	raw, e = linkJSON(fields)
	if e != nil {
		return LinkActionRequest{}, e
	}
	return LinkActionRequest{Kind: "peerspan-policy-v2", PayloadBase64: base64.StdEncoding.EncodeToString(raw), CertificateID: selected.CertificateID}, nil
}
func (s *Store) reapplyLinkEdits(ctx context.Context, network string, logf func(string, ...any)) error {
	now, e := linkNow()
	if e != nil {
		return e
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	person, stored, e := s.ownPolicy(ctx, tx, network)
	if e != nil {
		return e
	}
	if person == "" || stored == nil {
		return nil
	}
	if _, e = s.settleEdits(ctx, tx, network, person, stored, now); e != nil {
		return e
	}
	unsettled, e := editRecords(ctx, tx, network, person, `json_extract(record, '$.state') = 'unsettled'`)
	if e != nil {
		return e
	}
	if e = tx.Commit(); e != nil || len(unsettled) == 0 {
		return e
	}
	g, e := s.loadGovernance(ctx, s.db, network)
	if e != nil {
		return e
	}
	body, dropped := reapplied(stored.Body(), unsettled)
	changed := !membership.SameContent(body, stored.Body())
	at := linkTime(now)
	for index := range unsettled {
		if len(dropped[index]) > 0 {
			unsettled[index].Dropped = append(unsettled[index].Dropped, dropped[index]...)
			unsettled[index].DroppedAt = &at
		}
		if !changed {
			unsettled[index].State, unsettled[index].ClosedAt, unsettled[index].UnsettledAt = editClosed, &at, nil
		}
	}
	if !changed {
		tx, e := s.db.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		defer tx.Rollback()
		for _, record := range unsettled {
			if e = putEdit(ctx, tx, network, person, record); e != nil {
				return e
			}
		}
		return tx.Commit()
	}
	last := unsettled[len(unsettled)-1]
	issued, until, e := policyDuration(*last.Signed)
	if e != nil {
		return e
	}
	body.Edits, e = s.retiredDropped(ctx, s.db, network, membership.WithEdit(stored.Edits, s.identity.ID, last.Seq))
	if e != nil {
		return e
	}
	request, e := s.nextLinkPolicy(ctx, network, *stored, body, until.Sub(issued))
	if e != nil {
		return e
	}
	_, e = s.linkAction(ctx, network, request, &linkPolicyReapply{stored.Version, g.policyHash(stored.PersonPublicKey, *stored), unsettled})
	if errors.Is(e, errEditConflict) {
		s.scheduleReapply(network)
		return nil
	}
	if e != nil {
		return e
	}
	logf("re-applied policy edits for %s", network)
	return nil
}
