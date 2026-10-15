package host

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
)

// PersonOutcome reports the person part of a one-command create or join.
// Admitted means the person is admitted in the network after the command;
// Skipped explains what did not happen and Next is the command that finishes
// it. A skipped person part never fails the command.
type PersonOutcome struct {
	PersonID *string `json:"person_id"`
	Admitted bool    `json:"admitted"`
	Bound    bool    `json:"bound"`
	Skipped  *string `json:"skipped"`
	Next     *string `json:"next"`
}

// JoinResult is a network record plus the person part, null when no person
// key was supplied.
type JoinResult struct {
	Network
	Person *PersonOutcome `json:"person"`
}

func (o *PersonOutcome) skip(reason, next string) *PersonOutcome {
	o.Skipped = &reason
	if next != "" {
		o.Next = &next
	}
	return o
}

func bindCommand(network string) string {
	return "peerspan-host network bind --network " + network
}

// personAdmitted reports whether personKey is a currently valid person of
// the network on this host's verified state.
func (s *Store) personAdmitted(ctx context.Context, network, personKey string) bool {
	persons, err := s.Persons(ctx, network)
	if err != nil {
		return false
	}
	for _, p := range persons {
		if p.PublicKey == personKey {
			return true
		}
	}
	return false
}

// createWithPerson creates a network and, given the creator's person key,
// admits it with the new root. The CLI binds this host afterwards, because the
// network ID does not exist before creation.
func (s *Store) createWithPerson(ctx context.Context, r CreateNetwork) (JoinResult, error) {
	n, err := s.CreateNetwork(ctx, r)
	if err != nil {
		return JoinResult{Network: n}, err
	}
	result := JoinResult{Network: n}
	if r.PersonPublicKey == "" {
		return result, nil
	}
	key, err := membership.NormalizePersonKey(r.PersonPublicKey)
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	raw, _ := membership.DecodeKey(key)
	id := membership.PersonID(raw)
	out := &PersonOutcome{PersonID: &id}
	result.Person = out
	admit := fmt.Sprintf("peerspan-host network admit --network %s --person '%s' --member %s, then %s", n.ID, membership.SSHAuthorizedKey(raw), r.Member, bindCommand(n.ID))
	if n.LastSyncAt == nil || n.LastSyncError != nil {
		out.skip("the network is not registered with the coordinator yet", admit)
		return result, nil
	}
	if _, err = s.AdmitPerson(ctx, n.ID, AdmitPerson{PersonPublicKey: key, Member: r.Member}); err != nil {
		out.skip("the person was not admitted: "+err.Error(), admit)
		return result, nil
	}
	out.Admitted = true
	// The network ID exists only now, so binding is a second request; the CLI
	// makes it, and an API-only caller is pointed at it.
	next := bindCommand(n.ID)
	// The creator's person also becomes the first administrator, so they can
	// administer from any of their machines.
	if _, err = s.DelegateAdmin(ctx, n.ID, DelegateAdmin{Person: id}); err != nil {
		out.skip("the person was not made an administrator: "+err.Error(), fmt.Sprintf("peerspan-host network delegate-admin --network %s --person %s, then %s", n.ID, id, next))
		return result, nil
	}
	out.Next = &next
	return result, nil
}

// joinWithPerson joins the host as before, then completes the optional person
// part: admission through a member invite unless already admitted, then the
// CLI-signed binding with this host's own signature.
func (s *Store) joinWithPerson(ctx context.Context, r JoinNetwork) (JoinResult, error) {
	n, err := s.JoinNetwork(ctx, r)
	if err != nil {
		return JoinResult{Network: n}, err
	}
	result := JoinResult{Network: n}
	if r.PersonPublicKey == "" {
		return result, nil
	}
	var invite *membership.PersonToken
	if strings.HasPrefix(r.Token, membership.MemberTokenPrefix) {
		if t, err := membership.DecodeMemberToken(r.Token, time.Now()); err == nil {
			p := t.PersonToken()
			invite = &p
		}
	}
	result.Person = s.completePerson(ctx, n, r.PersonPublicKey, r.Token, invite, r.Binding)
	return result, nil
}

func (s *Store) completePerson(ctx context.Context, n Network, personKey, token string, invite *membership.PersonToken, binding json.RawMessage) *PersonOutcome {
	out := &PersonOutcome{}
	key, err := membership.NormalizePersonKey(personKey)
	if err != nil {
		return out.skip("invalid person key: "+err.Error(), "")
	}
	raw, _ := membership.DecodeKey(key)
	id := membership.PersonID(raw)
	out.PersonID = &id
	if !s.personAdmitted(ctx, n.ID, key) {
		if invite == nil {
			return out.skip("this person is not admitted in the network; an administrator can admit them with network admit --person, or send a member invite",
				"after the person is admitted: "+bindCommand(n.ID))
		}
		if err = s.redeemPerson(ctx, n, *invite, key); err != nil {
			return out.skip("the person was not admitted: "+err.Error(),
				fmt.Sprintf("peerspan-host network redeem-person --token %s, then %s", token, bindCommand(n.ID)))
		}
	}
	out.Admitted = true
	if len(binding) == 0 {
		return out.skip("no binding was supplied", bindCommand(n.ID))
	}
	if _, err = s.Bind(ctx, n.ID, BindHost{Binding: binding}); err != nil {
		return out.skip("this host was not bound: "+err.Error(), bindCommand(n.ID))
	}
	out.Bound = true
	return out
}
