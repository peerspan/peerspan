package host

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/membership"
)

// productGovernance is an evaluation view, never a signed wire record. DEC
// policies keep their exact statement and unsigned body separate from legacy
// policies. Reading this view neither admits proofs nor selects a provider.
type productGovernance struct {
	historyOnly bool
	legacy      *governance
	snapshot    *decSnapshot
	projection  *dec.Projection
	contacts    map[string]*dec.Contact
}
type productPolicy struct {
	membership.PolicyBody
	Version    uint64
	ValidUntil string
	legacy     *membership.Policy
	statement  *dec.Statement
}

func (p productPolicy) active(now time.Time) bool {
	if p.legacy != nil {
		return membership.PolicyActive(*p.legacy, now)
	}
	// The DEC projection already checked its local guarded decision time and
	// every authority ceiling. Resource wall time does not replace that clock.
	return p.statement != nil
}
func (p productPolicy) namesAgent(name string) bool {
	for _, r := range p.Rules {
		if r.Agent == name {
			return true
		}
	}
	return false
}
func (s *Store) loadProductGovernance(ctx context.Context, q dbQuerier, id string) (productGovernance, error) {
	// Callers already holding a transaction retain their exact snapshot. A DB
	// caller gets one read transaction for tag, objects, pins, heads and guard.
	if db, ok := q.(*sql.DB); ok {
		tx, e := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if e != nil {
			return productGovernance{}, e
		}
		defer tx.Rollback()
		return s.loadProductGovernance(ctx, tx, id)
	}
	var raw string
	if e := q.QueryRowContext(ctx, `SELECT record FROM networks WHERE id=?`, id).Scan(&raw); e != nil {
		if errors.Is(e, sql.ErrNoRows) {
			return productGovernance{}, ErrNotFound
		}
		return productGovernance{}, e
	}
	var tag struct {
		Mode string `json:"mode"`
	}
	if json.Unmarshal([]byte(raw), &tag) != nil {
		return productGovernance{}, decStorageError()
	}
	if tag.Mode != "decentralized" {
		legacy, e := s.loadGovernance(ctx, q, id)
		return productGovernance{legacy: &legacy, historyOnly: s.publicDecRuntime()}, e
	}
	snapshot, e := s.loadDecSnapshot(ctx, q, id)
	if e != nil {
		return productGovernance{}, e
	}
	now, e := decProductReadNow(ctx)
	if e != nil {
		return productGovernance{}, e
	}
	projection, e := verifyDecSnapshot(snapshot, linkTime(now))
	if e != nil {
		if _, status := ctx.Value(decStatusReadKey{}).(time.Time); !status || dec.Code(e) != "clock_rollback" {
			return productGovernance{}, e
		}
		// Status may describe this unusable context while unrelated local fields
		// remain readable. No authorization path receives a substitute projection.
		return productGovernance{snapshot: snapshot}, nil
	}
	contacts, e := readDecProductContacts(ctx, q, snapshot, projection.DecisionTime)
	if e != nil {
		return productGovernance{}, e
	}
	return productGovernance{snapshot: snapshot, projection: projection, contacts: contacts}, nil
}
func (g productGovernance) personKey(id string) (string, bool) {
	if g.historyOnly {
		return "", false
	}
	if g.legacy != nil {
		return g.legacy.personKey(id)
	}
	if g.projection == nil || len(g.snapshot.Fenced) != 0 {
		return "", false
	}
	for _, row := range g.projection.Streams {
		if len(row.Stream) == 2 && row.Stream[0] == "person" && row.Active && personIDOf(row.Stream[1]) == id {
			return row.Stream[1], true
		}
	}
	return "", false
}
func (g productGovernance) personKeys() []string {
	if g.historyOnly {
		return []string{}
	}
	if g.legacy != nil {
		return sortedKeys(g.legacy.persons())
	}
	out := []string{}
	if g.projection == nil || len(g.snapshot.Fenced) != 0 {
		return out
	}
	for _, row := range g.projection.Streams {
		if len(row.Stream) == 2 && row.Stream[0] == "person" && row.Active {
			out = append(out, row.Stream[1])
		}
	}
	return out
}
func (g productGovernance) storedPolicy(key string) (productPolicy, bool) {
	if g.historyOnly {
		return productPolicy{}, false
	}
	if g.legacy != nil {
		p, ok := g.legacy.storedPolicy(key)
		return productPolicy{p.Body(), p.Version, p.ValidUntil, &p, nil}, ok
	}
	if g.projection == nil || len(g.snapshot.Fenced) != 0 {
		return productPolicy{}, false
	}
	statement, path, e := g.projection.Current([]string{"policy", key})
	if e != nil {
		return productPolicy{}, false
	}
	body, e := decPolicyBody(statement)
	if e != nil {
		return productPolicy{}, false
	}
	return productPolicy{PolicyBody: body.delta(), Version: body.Version, ValidUntil: decEarlier(body.After, path.NotAfter), statement: statement}, true
}
func (s *Store) enforcedProductPolicy(ctx context.Context, q dbQuerier, g productGovernance, key string, p productPolicy) (productPolicy, error) {
	if g.legacy != nil {
		legacy, e := s.enforcedPolicy(ctx, q, g.legacy.network.ID, *p.legacy)
		p.PolicyBody = legacy.Body()
		p.legacy = &legacy
		return p, e
	}
	own, e := decCurrentMember(g.projection, s.identity.PublicKey)
	if e != nil || own.BindingError != nil || own.View.Person != key {
		return p, nil
	}
	edits, e := readDecPolicyEdits(ctx, q, g.snapshot, key)
	if e != nil {
		return p, e
	}
	for _, edit := range edits {
		if edit.State != editUnsettled {
			continue
		}
		_, start, e := readDecPolicyReference(g.snapshot, edit.Start, key)
		if e != nil {
			return p, e
		}
		_, signed, e := readDecPolicyReference(g.snapshot, edit.Signed, key)
		if e != nil {
			return p, e
		}
		p.PolicyBody, _ = membership.MergeEdit(start, signed, p.PolicyBody, true, nil)
	}
	return p, nil
}
func (g productGovernance) principalMatches(rule membership.PolicyRule, sender NetworkMember, origin *Origin) bool {
	if g.historyOnly {
		return false
	}
	if g.legacy != nil {
		return g.legacy.principalMatches(rule, sender, origin)
	}
	// A network principal is meaningful only for a currently verified member.
	member, ok := g.member(sender.HostID)
	if !ok {
		return false
	}
	for _, principal := range rule.Principals {
		if host, agent, ok := membership.AgentPrincipal(principal); ok {
			if host == sender.HostID && origin != nil && origin.AgentID == agent {
				return true
			}
			continue
		}
		if principal == membership.PrincipalNetwork {
			return true
		}
		if member.PersonID == nil {
			continue
		}
		if strings.HasPrefix(principal, "person:") && strings.TrimPrefix(principal, "person:") == *member.PersonID {
			return true
		}
		if strings.HasPrefix(principal, "group:") {
			group, _, e := g.projection.Current([]string{"group", strings.TrimPrefix(principal, "group:")})
			if e != nil {
				continue
			}
			raw, e := decBytes(group.Access.BodyBase64, dec.MaxPayload)
			if e != nil {
				continue
			}
			var body struct {
				Members []string `json:"members"`
			}
			if json.Unmarshal(raw, &body) != nil {
				continue
			}
			for _, id := range body.Members {
				if id == *member.PersonID {
					return true
				}
			}
		}
	}
	return false
}
func (g productGovernance) members() map[string]NetworkMember {
	out := map[string]NetworkMember{}
	if g.snapshot == nil || g.projection == nil || len(g.snapshot.Fenced) != 0 {
		return out
	}
	for _, row := range decMemberViews(g.projection) {
		key, e := membership.DecodeKey(row.Host)
		if e != nil {
			continue
		}
		m := NetworkMember{HostID: membership.HostID(key), PublicKey: row.Host, Member: row.Member, Candidates: []string{}}
		if contact := g.contacts[row.Host]; contact != nil {
			m.Candidates = append([]string{}, contact.Addresses.QUIC...)
			if len(m.Candidates) > 0 {
				m.Address = m.Candidates[0]
			}
			m.UpdatedAt = contact.Issued
		}
		if row.Person != "-" {
			person := personIDOf(row.Person)
			m.PersonID = &person
			if p, _, e := g.projection.Current([]string{"person", row.Person}); e == nil {
				label := p.Lease.Subject.Member
				m.PersonMember = &label
			}
		}
		out[m.HostID] = m
	}
	return out
}
func (g productGovernance) member(id string) (NetworkMember, bool) {
	m, ok := g.members()[id]
	return m, ok
}
func (s *Store) networkIDs(ctx context.Context, q queryer) ([]string, error) {
	rows, e := q.QueryContext(ctx, `SELECT id FROM networks ORDER BY id`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			return nil, e
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (g productGovernance) personList() []Person {
	if g.legacy != nil {
		return g.legacy.personList()
	}
	result := []Person{}
	for _, key := range g.personKeys() {
		p, _, e := g.projection.Current([]string{"person", key})
		if e != nil {
			continue
		}
		result = append(result, Person{PersonID: personIDOf(key), PublicKey: key, Member: p.Lease.Subject.Member})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].PersonID < result[j].PersonID })
	return result
}

// Contacts are signed, expiring hints only. Even a good contact is used only
// after independently current network membership has been established above.
func readDecProductContacts(ctx context.Context, q dbQuerier, snapshot *decSnapshot, decision string) (map[string]*dec.Contact, error) {
	out := map[string]*dec.Contact{}
	rows, e := q.QueryContext(ctx, `SELECT host_key,sequence,record FROM dec_contacts WHERE network_id=? AND context_id=? ORDER BY host_key`, snapshot.Descriptor.NetworkID, snapshot.Descriptor.ContextID)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	now := decision
	for rows.Next() {
		var host, raw string
		var version any
		var record decContactRecord
		if e = rows.Scan(&host, &version, &raw); e != nil {
			return nil, e
		}
		sequence, e := decVersion(version, false)
		if e != nil {
			return nil, e
		}
		if dec.ReadPrivateRecord([]byte(raw), "format message_hashes conflicted contacts_base64", &record) != nil || record.Format != 1 || record.Hashes == nil || len(record.Hashes) < 1 || len(record.Hashes) > 2 || record.Conflicted != (len(record.Hashes) == 2) || record.Contacts == nil || len(record.Contacts) > 2 {
			return nil, decStorageError()
		}
		for i, hash := range record.Hashes {
			b, e := hex.DecodeString(hash)
			if e != nil || len(b) != 32 || hex.EncodeToString(b) != hash || i > 0 && record.Hashes[i-1] >= hash {
				return nil, decStorageError()
			}
		}
		for _, encoded := range record.Contacts {
			raw, e := decBytes(encoded, dec.MaxContact)
			if e != nil {
				return nil, e
			}
			contact, e := dec.ReadContact(raw)
			if e != nil {
				return nil, e
			}
			hash := sha256.Sum256(contact.Message)
			if contact.Context != snapshot.Descriptor.ContextID || contact.Host != host || contact.Sequence != sequence || !containsString(record.Hashes, hex.EncodeToString(hash[:])) {
				return nil, decStorageError()
			}
			if !record.Conflicted && contact.Current(now) == nil {
				out[host] = contact
			}
		}
	}
	return out, rows.Err()
}

// retainedDecPeer establishes only a transport identity. Historical admitted
// host provenance lets an exact sender retrieve its already accepted work;
// every route granting new work still checks its current authority separately.
func (s *Store) retainedDecPeer(ctx context.Context, id string) (Peer, error) {
	ids, e := s.networkIDs(ctx, s.db)
	if e != nil {
		return Peer{}, e
	}
	for _, network := range ids {
		g, e := s.loadProductGovernance(ctx, s.db, network)
		if e != nil {
			return Peer{}, e
		}
		if g.snapshot == nil {
			continue
		}
		for _, statementID := range g.snapshot.Prior.AdmittedStatements {
			statement := g.snapshot.Catalog.Statements[statementID]
			if statement == nil || statement.Kind != "host_lease" {
				continue
			}
			key, e := membership.DecodeKey(statement.Lease.Subject.Host)
			if e != nil || membership.HostID(key) != id {
				continue
			}
			peer := Peer{ID: id, PublicKey: statement.Lease.Subject.Host}
			if contact := g.contacts[peer.PublicKey]; contact != nil && len(contact.Addresses.QUIC) > 0 {
				peer.Address = contact.Addresses.QUIC[0]
			}
			return peer, nil
		}
	}
	return Peer{}, ErrNotFound
}
