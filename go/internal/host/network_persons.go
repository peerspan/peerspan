package host

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/peerspan/peerspan/go/internal/membership"
)

// Persons and host binding (milestone 2b, slice 1). The daemon never holds a
// person key: the CLI signs bindings and unbindings and hands them over.

// AdmitPerson and AdmitHost carry a key and label for this host to sign with
// the root seed, or an admission an administrator signed through the CLI.
type AdmitPerson struct {
	PersonPublicKey string                      `json:"person_public_key,omitempty"`
	Member          string                      `json:"member,omitempty"`
	Admission       *membership.PersonAdmission `json:"admission,omitempty"`
}
type AdmitHost struct {
	HostPublicKey string                    `json:"host_public_key,omitempty"`
	Member        string                    `json:"member,omitempty"`
	Admission     *membership.HostAdmission `json:"admission,omitempty"`
}

// Admitted is {person_id, descriptor} or {host_id, descriptor}.
type Admitted struct {
	PersonID   string `json:"person_id,omitempty"`
	HostID     string `json:"host_id,omitempty"`
	Descriptor string `json:"descriptor"`
}
type RedeemPerson struct {
	Token           string `json:"token"`
	PersonPublicKey string `json:"person_public_key"`
}

// BindHost carries a person-signed binding; host_signature may be absent, as
// the daemon adds its own.
type BindHost struct {
	Binding json.RawMessage `json:"binding"`
}
type Bound struct {
	NetworkID string `json:"network_id"`
	HostID    string `json:"host_id"`
	PersonID  string `json:"person_id"`
}
type UnbindHost struct {
	Unbinding membership.HostUnbinding `json:"unbinding"`
}
type RemovePerson struct {
	PersonID string                    `json:"person_id,omitempty"`
	Removal  *membership.PersonRemoval `json:"removal,omitempty"`
}
type Person struct {
	PersonID  string   `json:"person_id"`
	PublicKey string   `json:"public_key"`
	Member    string   `json:"member"`
	Hosts     []string `json:"hosts"`
	// Administrator is true for a current administrator of the network.
	Administrator bool `json:"administrator"`
	LabelConflict bool `json:"label_conflict"`
}

// labelTaken reports whether a current person other than exceptKey holds a
// label that conflicts with label.
func (s *Store) labelTaken(ctx context.Context, id, label, exceptKey string) error {
	persons, err := s.Persons(ctx, id)
	if err != nil {
		return err
	}
	for _, p := range persons {
		if p.PublicKey != exceptKey && membership.LabelsConflict(p.Member, label) {
			return fmt.Errorf("%w: person label %q is taken", ErrConflict, label)
		}
	}
	return nil
}

func descriptorOf(n Network) (string, error) {
	return membership.Descriptor{NetworkID: n.ID, NetworkName: n.Name, RootPublicKey: n.RootPublicKey, CoordinatorAddress: n.CoordinatorAddress, CoordinatorPublicKey: n.CoordinatorPublicKey}.Encode()
}

func networkPath(n Network, suffix string) string {
	return "/coord/v1/networks/" + url.PathEscape(n.ID) + suffix
}

// presigned checks a statement an administrator (or a root key held by the
// CLI) signed: the signer must be the current root or a current
// administrator, and the statement must verify at the current epoch.
func (s *Store) presigned(ctx context.Context, id, signature string, verify func(membership.Chain) error) (Network, error) {
	g, err := s.loadGovernance(ctx, s.db, id)
	if err != nil {
		return g.network, err
	}
	if err = g.acceptSignature(signature); err != nil {
		return g.network, err
	}
	if err = verify(g.chain); err != nil {
		return g.network, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return g.network, nil
}

// AdmitPerson signs a person admission with the current root, or takes one an
// administrator signed, and submits it.
func (s *Store) AdmitPerson(ctx context.Context, id string, r AdmitPerson) (Admitted, error) {
	var n Network
	var admission membership.PersonAdmission
	if r.Admission != nil {
		if r.PersonPublicKey != "" || r.Member != "" {
			return Admitted{}, fmt.Errorf("%w: give an admission or a key and label, not both", ErrInvalid)
		}
		admission = *r.Admission
		var err error
		n, err = s.presigned(ctx, id, admission.Signature, func(c membership.Chain) error {
			if admission.Epoch != c.Epoch() {
				return errors.New("admission is not at the current epoch")
			}
			return c.VerifyPersonAdmission(admission)
		})
		if err != nil {
			return Admitted{}, err
		}
		r.PersonPublicKey, r.Member = admission.PersonPublicKey, admission.Member
	}
	if normalized, err := membership.NormalizePersonKey(r.PersonPublicKey); err == nil {
		r.PersonPublicKey = normalized
	}
	key, err := membership.DecodeKey(r.PersonPublicKey)
	if err != nil || !membership.ValidLabel(r.Member) {
		return Admitted{}, fmt.Errorf("%w: person key must be canonical Base64 and member a valid label", ErrInvalid)
	}
	if r.Admission == nil {
		var root ed25519.PrivateKey
		if n, root, err = s.administeredNetwork(ctx, s.db, id); err != nil {
			return Admitted{}, err
		}
		admission = membership.SignPersonAdmission(root, n.ID, n.RootEpoch, r.PersonPublicKey, r.Member, timestamp(time.Now()))
	}
	if err = s.labelTaken(ctx, id, r.Member, r.PersonPublicKey); err != nil {
		return Admitted{}, err
	}
	if _, err = s.callCoordinator(ctx, n, networkPath(n, "/persons"), map[string]any{"admission": admission}); err != nil {
		return Admitted{}, err
	}
	if _, err = s.SyncNetwork(ctx, id); err != nil {
		return Admitted{}, err
	}
	descriptor, err := descriptorOf(n)
	return Admitted{PersonID: membership.PersonID(key), Descriptor: descriptor}, err
}

// AdmitHost signs a host admission with the current root and submits it; the
// host then joins with the descriptor.
func (s *Store) AdmitHost(ctx context.Context, id string, r AdmitHost) (Admitted, error) {
	var n Network
	var admission membership.HostAdmission
	now := timestamp(time.Now())
	if r.Admission != nil {
		if r.HostPublicKey != "" || r.Member != "" {
			return Admitted{}, fmt.Errorf("%w: give an admission or a key and label, not both", ErrInvalid)
		}
		admission = *r.Admission
		var err error
		n, err = s.presigned(ctx, id, admission.Signature, func(c membership.Chain) error {
			if admission.Epoch != c.Epoch() {
				return errors.New("admission is not at the current epoch")
			}
			_, err := c.VerifyHostAdmission(admission)
			return err
		})
		if err != nil {
			return Admitted{}, err
		}
		r.HostPublicKey, r.Member = admission.HostPublicKey, admission.Member
	}
	key, err := membership.DecodeKey(r.HostPublicKey)
	if err != nil || !membership.ValidLabel(r.Member) {
		return Admitted{}, fmt.Errorf("%w: host key must be canonical Base64 and member a valid label", ErrInvalid)
	}
	if r.Admission == nil {
		var root ed25519.PrivateKey
		if n, root, err = s.administeredNetwork(ctx, s.db, id); err != nil {
			return Admitted{}, err
		}
		admission = membership.SignHostAdmission(root, n.ID, n.RootEpoch, r.HostPublicKey, r.Member, now)
	}
	if _, err = s.callCoordinator(ctx, n, networkPath(n, "/hosts"), map[string]any{"admission": admission}); err != nil {
		return Admitted{}, err
	}
	data, err := json.Marshal(admission)
	if err != nil {
		return Admitted{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Admitted{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "INSERT INTO network_statements VALUES (?, ?, ?, ?) ON CONFLICT DO UPDATE SET record = excluded.record", n.ID, kindHostAdmission, r.HostPublicKey, string(data)); err != nil {
		return Admitted{}, err
	}
	if err = appendEvent(ctx, tx, "network.host_admitted", membership.HostID(key), now); err != nil {
		return Admitted{}, err
	}
	if err = tx.Commit(); err != nil {
		return Admitted{}, err
	}
	descriptor, err := descriptorOf(n)
	return Admitted{HostID: membership.HostID(key), Descriptor: descriptor}, err
}

// CreatePersonInvite issues a one-time person invite signed by the current
// root, or records one an administrator signed through the CLI.
func (s *Store) CreatePersonInvite(ctx context.Context, id string, r CreateInvite) (Invite, error) {
	if strings.HasPrefix(r.Token, FeatureInvitePrefix) {
		return s.recordFeatureInvite(ctx, id, r)
	}
	if r.Token != "" {
		return s.recordSignedInvite(ctx, id, r)
	}
	n, root, err := s.administeredNetwork(ctx, s.db, id)
	if err != nil {
		return Invite{}, err
	}
	if !membership.ValidLabel(r.Member) {
		return Invite{}, fmt.Errorf("%w: invalid member label", ErrInvalid)
	}
	if err = s.labelTaken(ctx, id, r.Member, ""); err != nil {
		return Invite{}, err
	}
	feature, _, err := readLinkFeature(ctx, s.db, id)
	if err != nil {
		return Invite{}, err
	}
	if feature != "-" {
		r.ExpiresAt, err = floorLinkInviteExpiry(r.ExpiresAt)
		if err != nil {
			return Invite{}, err
		}
	}
	expires, err := parseTime(r.ExpiresAt)
	now := time.Now()
	if err != nil || !expires.After(now) || expires.After(now.Add(30*24*time.Hour)) {
		return Invite{}, fmt.Errorf("%w: invite expiration must be in the next 30 days", ErrInvalid)
	}
	token, err := membership.PersonInvite(n.ID, root, n.RootEpoch, r.Member, r.ExpiresAt)
	if err != nil {
		return Invite{}, err
	}
	token.NetworkName, token.CoordinatorAddress, token.CoordinatorPublicKey = n.Name, n.CoordinatorAddress, n.CoordinatorPublicKey
	encoded, err := token.Encode()
	if err != nil {
		return Invite{}, err
	}
	if feature != "-" {
		encoded, err = s.wrapRootLinkInvite(ctx, n, encoded, root)
		if err != nil {
			return Invite{}, err
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Invite{}, err
	}
	defer tx.Rollback()
	if err = appendEvent(ctx, tx, "network.invite_issued", n.ID, timestamp(now)); err != nil {
		return Invite{}, err
	}
	return Invite{NetworkID: n.ID, Member: r.Member, InvitePublicKey: token.InvitePublicKey, InviteExpiresAt: r.ExpiresAt, Token: encoded}, tx.Commit()
}

// RedeemPerson admits a person through a person invite, from any member host.
type Redeemed struct {
	PersonID string `json:"person_id"`
}

func (s *Store) RedeemPerson(ctx context.Context, r RedeemPerson) (Redeemed, error) {
	if strings.HasPrefix(r.Token, FeatureInvitePrefix) {
		_, e := s.redeemFeatureInvite(ctx, JoinNetwork{Token: r.Token, PersonPublicKey: r.PersonPublicKey}, true)
		if e != nil {
			return Redeemed{}, e
		}
		key, e := membership.NormalizePersonKey(r.PersonPublicKey)
		if e != nil {
			return Redeemed{}, e
		}
		return Redeemed{PersonID: personIDOf(key)}, nil
	}
	// A member invite's person half is redeemable here too, until it expires.
	token, err := membership.DecodeAnyPersonToken(r.Token, time.Now())
	if err != nil {
		return Redeemed{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	normalized, err := membership.NormalizePersonKey(r.PersonPublicKey)
	if err != nil {
		return Redeemed{}, err
	}
	key, _ := membership.DecodeKey(normalized)
	n, err := s.Network(ctx, token.NetworkID)
	if err != nil {
		return Redeemed{}, err
	}
	if err = s.redeemPerson(ctx, n, token, normalized); err != nil {
		return Redeemed{}, err
	}
	return Redeemed{PersonID: membership.PersonID(key)}, nil
}

// redeemPerson signs the person membership with the invite seed, submits it,
// and refreshes the map so this host stores the new person.
func (s *Store) redeemPerson(ctx context.Context, n Network, token membership.PersonToken, personKey string) error {
	redeemed, err := token.Redeem(personKey, timestamp(time.Now()))
	if err != nil {
		return err
	}
	if _, err = s.callCoordinator(ctx, n, networkPath(n, "/persons"), map[string]any{"membership": redeemed}); err != nil {
		return err
	}
	_, err = s.SyncNetwork(ctx, n.ID)
	return err
}

// joinByDescriptor joins a network that an administrator admitted this host's
// key to. The coordinator uses its stored admission for this host.
func (s *Store) joinByDescriptor(ctx context.Context, value string) (Network, error) {
	d, err := membership.DecodeDescriptor(value)
	if err != nil {
		return Network{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if _, err = s.Network(ctx, d.NetworkID); err == nil {
		return Network{}, fmt.Errorf("%w: network already joined", ErrConflict)
	} else if !errors.Is(err, ErrNotFound) {
		return Network{}, err
	}
	n := Network{ID: d.NetworkID, Name: d.NetworkName, RootPublicKey: d.RootPublicKey, CoordinatorAddress: d.CoordinatorAddress, CoordinatorPublicKey: d.CoordinatorPublicKey}
	advertise, _ := s.coordinationConfig()
	m, chain, err := s.callCoordinatorMap(ctx, n, networkPath(n, "/members"), map[string]any{"address": advertise, "candidates": s.ownCandidates(ctx, n.CoordinatorAddress)})
	if err != nil {
		return n, err
	}
	return s.finishJoin(ctx, n, m, chain)
}

// Bind submits a person-signed binding of this host; the daemon submitting
// it as itself is the host's consent.
func (s *Store) Bind(ctx context.Context, id string, r BindHost) (Bound, error) {
	n, err := s.Network(ctx, id)
	if err != nil {
		return Bound{}, err
	}
	binding, err := membership.DecodePersonBinding(r.Binding)
	if err != nil {
		return Bound{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	// The daemon signs only bindings of its own key: that signature is this
	// host's consent, verified by the coordinator and every peer.
	if binding.HostPublicKey != s.identity.PublicKey {
		return Bound{}, fmt.Errorf("%w: a binding must name this host", ErrInvalid)
	}
	if err = membership.VerifyPersonBinding(n.ID, binding); err != nil {
		return Bound{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err = binding.SignHost(s.privateKey); err != nil {
		return Bound{}, err
	}
	if _, err = s.callCoordinator(ctx, n, networkPath(n, "/bindings"), map[string]any{"binding": binding}); err != nil {
		return Bound{}, err
	}
	key, _ := membership.DecodeKey(binding.PersonPublicKey)
	personID := membership.PersonID(key)
	// Store the accepted binding before responding, so success means this host
	// has it whatever a later sync does; the sync then sees no change and
	// records no second event.
	if err = s.storeOwnBinding(ctx, n.ID, binding, personID); err != nil {
		return Bound{}, err
	}
	_, _ = syncAfterBind(s, ctx, id)
	return Bound{NetworkID: n.ID, HostID: s.identity.ID, PersonID: personID}, nil
}

// syncAfterBind refreshes the map after a binding; tests replace it to show
// the binding does not depend on that sync.
var syncAfterBind = (*Store).SyncNetwork

// storeOwnBinding records this host's coordinator-accepted binding and its
// network.host_bound event in one transaction.
func (s *Store) storeOwnBinding(ctx context.Context, network string, binding membership.HostBinding, personID string) error {
	data, err := json.Marshal(binding)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	persisted, err := loadStatements(ctx, tx, network)
	if err != nil {
		return err
	}
	var label *string
	if raw, ok := persisted.persons[binding.PersonPublicKey]; ok {
		var proof membership.PersonProof
		if json.Unmarshal(raw, &proof) == nil && (proof.Admission != nil) != (proof.Membership != nil) {
			value := personLabel(proof)
			label = &value
		}
	}
	member, err := readJSON[NetworkMember](tx.QueryRowContext(ctx, "SELECT record FROM network_members WHERE network_id = ? AND host_id = ?", network, s.identity.ID))
	if err != nil {
		return err
	}
	already := member.PersonID != nil && *member.PersonID == personID
	member.PersonID, member.PersonMember = &personID, label
	if err = putJSON(ctx, tx, "UPDATE network_members SET record = ? WHERE network_id = ? AND host_id = ?", member, network, s.identity.ID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO network_statements VALUES (?, ?, ?, ?) ON CONFLICT DO UPDATE SET record = excluded.record", network, kindBinding, binding.HostPublicKey, string(data)); err != nil {
		return err
	}
	if !already {
		if err = appendEvent(ctx, tx, "network.host_bound", s.identity.ID, timestamp(time.Now())); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	if !already {
		// The person's other hosts, if any, are now siblings.
		s.siblingGained(network)
	}
	return nil
}

// storeRevocation persists a sticky statement once, records its event, ends
// any affected bindings locally at once, and submits it; it is resubmitted on
// every sync until the coordinator serves it.
func (s *Store) storeRevocation(ctx context.Context, n Network, record statementRecord, event, eventSubject string) (RevocationResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RevocationResult{}, err
	}
	defer tx.Rollback()
	now := timestamp(time.Now())
	var stored string
	err = tx.QueryRowContext(ctx, "SELECT record FROM network_statements WHERE network_id = ? AND kind = ? AND subject = ?", n.ID, record.kind, record.subject).Scan(&stored)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if err = putStatementRecord(ctx, tx, n.ID, record); err != nil {
			return RevocationResult{}, err
		}
		if err = appendEvent(ctx, tx, event, eventSubject, now); err != nil {
			return RevocationResult{}, err
		}
	case err != nil:
		return RevocationResult{}, err
	default:
		record.statement = json.RawMessage(stored)
	}
	if err = s.endBindings(ctx, tx, n.ID, now); err != nil {
		return RevocationResult{}, err
	}
	if err = tx.Commit(); err != nil {
		return RevocationResult{}, err
	}
	kind := revocationKind(record.kind)
	_, submitErr := s.callCoordinator(ctx, n, networkPath(n, "/revocations"), map[string]any{"kind": kind, "statement": record.statement})
	return RevocationResult{NetworkID: n.ID, Kind: kind, Subject: record.subject, Submitted: submitErr == nil}, nil
}

// endBindings clears local bindings ended by a persisted person removal or
// unbinding.
func (s *Store) endBindings(ctx context.Context, tx *sql.Tx, network, now string) error {
	g, err := s.loadGovernance(ctx, tx, network)
	if err != nil {
		return err
	}
	revoked := g.revoked
	rows, err := tx.QueryContext(ctx, "SELECT record FROM network_statements WHERE network_id = ? AND kind = ?", network, kindBinding)
	if err != nil {
		return err
	}
	var ended []membership.HostBinding
	for rows.Next() {
		var record string
		if err = rows.Scan(&record); err != nil {
			rows.Close()
			return err
		}
		var b membership.HostBinding
		if json.Unmarshal([]byte(record), &b) == nil && !revoked.Bound(b.PersonPublicKey, b.HostPublicKey) {
			ended = append(ended, b)
		}
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	for _, b := range ended {
		if _, err = tx.ExecContext(ctx, "DELETE FROM network_statements WHERE network_id = ? AND kind = ? AND subject = ?", network, kindBinding, b.HostPublicKey); err != nil {
			return err
		}
		key, _ := membership.DecodeKey(b.HostPublicKey)
		hostID := membership.HostID(key)
		member, err := readJSON[NetworkMember](tx.QueryRowContext(ctx, "SELECT record FROM network_members WHERE network_id = ? AND host_id = ?", network, hostID))
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if member.PersonID != nil {
			member.PersonID, member.PersonMember = nil, nil
			if err = putJSON(ctx, tx, "UPDATE network_members SET record = ? WHERE network_id = ? AND host_id = ?", member, network, hostID); err != nil {
				return err
			}
			if err = appendEvent(ctx, tx, "network.host_unbound", hostID, now); err != nil {
				return err
			}
		}
	}
	return nil
}

// Unbind records a person-signed unbinding, enforced locally at once.
func (s *Store) Unbind(ctx context.Context, id string, r UnbindHost) (RevocationResult, error) {
	n, err := s.Network(ctx, id)
	if err != nil {
		return RevocationResult{}, err
	}
	if err = membership.VerifyHostUnbinding(n.ID, r.Unbinding); err != nil {
		return RevocationResult{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	data, err := json.Marshal(r.Unbinding)
	if err != nil {
		return RevocationResult{}, err
	}
	subject := membership.UnbindSubject(r.Unbinding.PersonPublicKey, r.Unbinding.HostPublicKey)
	key, _ := membership.DecodeKey(r.Unbinding.HostPublicKey)
	return s.storeRevocation(ctx, n, statementRecord{membership.KindUnbind, subject, data}, "network.host_unbound", membership.HostID(key))
}

// RemovePerson signs a person removal with the current root, or records one
// an administrator signed.
func (s *Store) RemovePerson(ctx context.Context, id string, r RemovePerson) (RevocationResult, error) {
	if r.Removal != nil {
		if r.PersonID != "" {
			return RevocationResult{}, fmt.Errorf("%w: give person_id or removal, not both", ErrInvalid)
		}
		removal := *r.Removal
		data, err := json.Marshal(removal)
		if err != nil {
			return RevocationResult{}, err
		}
		n, err := s.presigned(ctx, id, removal.Signature, func(c membership.Chain) error {
			_, _, err := c.VerifyRevocation(membership.Revocation{Kind: membership.KindPerson, Statement: data})
			return err
		})
		if err != nil {
			return RevocationResult{}, err
		}
		if err = s.refuseRemovingAdmin(ctx, id, removal.PersonPublicKey); err != nil {
			return RevocationResult{}, err
		}
		return s.storeRevocation(ctx, n, statementRecord{kindPersonRemoval, removal.PersonPublicKey, data}, "network.person_removed", personIDOf(removal.PersonPublicKey))
	}
	n, root, err := s.administeredNetwork(ctx, s.db, id)
	if err != nil {
		return RevocationResult{}, err
	}
	persisted, err := loadStatements(ctx, s.db, id)
	if err != nil {
		return RevocationResult{}, err
	}
	key := ""
	for _, rec := range persisted.revocations {
		if rec.kind == kindPersonRemoval && personIDOf(rec.subject) == r.PersonID {
			key = rec.subject
		}
	}
	for subject := range persisted.persons {
		if key == "" && personIDOf(subject) == r.PersonID {
			key = subject
		}
	}
	if key == "" {
		return RevocationResult{}, ErrNotFound
	}
	data, err := json.Marshal(membership.SignPersonRemoval(root, n.ID, key, timestamp(time.Now())))
	if err != nil {
		return RevocationResult{}, err
	}
	if err = s.refuseRemovingAdmin(ctx, id, key); err != nil {
		return RevocationResult{}, err
	}
	return s.storeRevocation(ctx, n, statementRecord{kindPersonRemoval, key, data}, "network.person_removed", r.PersonID)
}

func personIDOf(key string) string {
	public, err := membership.DecodeKey(key)
	if err != nil {
		return ""
	}
	return membership.PersonID(public)
}

// Persons lists valid persons with their bound hosts.
func (s *Store) Persons(ctx context.Context, id string) ([]Person, error) {
	product, e := s.loadProductGovernance(ctx, s.db, id)
	if e != nil {
		return nil, e
	}
	if product.snapshot != nil {
		out := product.personList()
		members := product.members()
		for i := range out {
			out[i].Hosts = []string{}
			_, _, e := product.projection.Current([]string{"admin", out[i].PublicKey})
			out[i].Administrator = e == nil
			for _, member := range members {
				if member.PersonID != nil && *member.PersonID == out[i].PersonID {
					out[i].Hosts = append(out[i].Hosts, member.HostID)
				}
			}
			sort.Strings(out[i].Hosts)
			for j := range out {
				if i != j && membership.LabelsConflict(out[i].Member, out[j].Member) {
					out[i].LabelConflict = true
				}
			}
		}
		return out, nil
	}
	g, err := s.loadGovernance(ctx, s.db, id)
	if err != nil {
		return nil, err
	}
	if g.linking != nil {
		members, err := s.NetworkMembers(ctx, id)
		if err != nil {
			return nil, err
		}
		out := g.personList()
		admins := g.currentAdmins()
		for i := range out {
			out[i].Hosts = []string{}
			out[i].Administrator = admins[out[i].PublicKey]
			for _, member := range members {
				if member.PersonID != nil && *member.PersonID == out[i].PersonID {
					out[i].Hosts = append(out[i].Hosts, member.HostID)
				}
			}
			for j := range out {
				if i != j && membership.LabelsConflict(out[i].Member, out[j].Member) {
					out[i].LabelConflict = true
				}
			}
		}
		return out, nil
	}
	removed := g.revoked.Persons
	admins := g.currentAdmins()
	persisted := g.persisted
	members, err := s.NetworkMembers(ctx, id)
	if err != nil {
		return nil, err
	}
	persons := []Person{}
	for key, data := range persisted.persons {
		var proof membership.PersonProof
		if removed[key] || json.Unmarshal(data, &proof) != nil || (proof.Admission == nil) == (proof.Membership == nil) {
			continue
		}
		if _, _, err := g.chain.VerifyPerson(proof); err != nil {
			continue // signed by an administrator removed with revoke_admitted
		}
		p := Person{PersonID: personIDOf(key), PublicKey: key, Member: personLabel(proof), Hosts: []string{}, Administrator: admins[key]}
		for _, m := range members {
			if m.PersonID != nil && *m.PersonID == p.PersonID {
				p.Hosts = append(p.Hosts, m.HostID)
			}
		}
		persons = append(persons, p)
	}
	sort.Slice(persons, func(i, j int) bool { return persons[i].PersonID < persons[j].PersonID })
	// Only a misbehaving coordinator can serve conflicting labels; keep both
	// persons and flag them rather than dropping either.
	for i := range persons {
		for j := range persons {
			if i != j && membership.LabelsConflict(persons[i].Member, persons[j].Member) {
				persons[i].LabelConflict = true
			}
		}
	}
	return persons, nil
}

func localPersonRoutes(mux *http.ServeMux, store *Store) {
	mux.HandleFunc("POST /v1/networks/{id}/persons", func(w http.ResponseWriter, r *http.Request) {
		var req AdmitPerson
		if !decode(w, r, &req, "person_public_key", "member", "admission") {
			return
		}
		result, err := store.AdmitPerson(r.Context(), r.PathValue("id"), req)
		respond(w, http.StatusCreated, result, err)
	})
	mux.HandleFunc("GET /v1/networks/{id}/persons", func(w http.ResponseWriter, r *http.Request) {
		result, err := store.Persons(r.Context(), r.PathValue("id"))
		respond(w, http.StatusOK, result, err)
	})
	mux.HandleFunc("POST /v1/networks/{id}/hosts", func(w http.ResponseWriter, r *http.Request) {
		var req AdmitHost
		if !decode(w, r, &req, "host_public_key", "member", "admission") {
			return
		}
		result, err := store.AdmitHost(r.Context(), r.PathValue("id"), req)
		respond(w, http.StatusCreated, result, err)
	})
	mux.HandleFunc("POST /v1/networks/{id}/person-invites", func(w http.ResponseWriter, r *http.Request) {
		var req CreateInvite
		if !decode(w, r, &req, "member", "expires_at", "token") {
			return
		}
		result, err := store.CreatePersonInvite(r.Context(), r.PathValue("id"), req)
		respond(w, http.StatusCreated, result, err)
	})
	mux.HandleFunc("POST /v1/networks/redeem-person", func(w http.ResponseWriter, r *http.Request) {
		var req RedeemPerson
		if !decode(w, r, &req, "token", "person_public_key") {
			return
		}
		result, err := store.RedeemPerson(r.Context(), req)
		respond(w, http.StatusCreated, result, err)
	})
	mux.HandleFunc("POST /v1/networks/{id}/bindings", func(w http.ResponseWriter, r *http.Request) {
		var req BindHost
		if !decode(w, r, &req, "binding") {
			return
		}
		result, err := store.Bind(r.Context(), r.PathValue("id"), req)
		respond(w, http.StatusCreated, result, err)
	})
	mux.HandleFunc("POST /v1/networks/{id}/unbindings", func(w http.ResponseWriter, r *http.Request) {
		var req UnbindHost
		if !decode(w, r, &req, "unbinding") {
			return
		}
		result, err := store.Unbind(r.Context(), r.PathValue("id"), req)
		respond(w, http.StatusCreated, result, err)
	})
	mux.HandleFunc("POST /v1/networks/{id}/person-removals", func(w http.ResponseWriter, r *http.Request) {
		var req RemovePerson
		if !decode(w, r, &req, "person_id", "removal") {
			return
		}
		result, err := store.RemovePerson(r.Context(), r.PathValue("id"), req)
		respond(w, http.StatusCreated, result, err)
	})
}

func (s *Store) refuseRemovingAdmin(ctx context.Context, id, personKey string) error {
	g, err := s.loadGovernance(ctx, s.db, id)
	if err != nil {
		return err
	}
	return g.refuseAdminRemoval(personKey)
}
