package coord

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
)

// Persons and host binding (milestone 2b, slice 1). Administrators keep
// admitting hosts, by invite or by public key; persons are an optional layer.
// Everything is verified on acceptance and again by every host.

const (
	kindPersonAdmission = "person_admission" // subject: person key; a PersonProof
	kindPersonInvite    = "person_invite"    // subject: invite key; the redeeming person key
	kindHostAdmission   = "host_admission"   // subject: host key
	kindBinding         = "binding"          // subject: host key
	admissionPrefix     = "admission:"       // members.invite_public_key for an admitted host
)

// rawFields decodes one JSON object of raw fields, treating null as absent.
func rawFields(data []byte) (map[string]json.RawMessage, error) {
	var raw map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&raw); err != nil || raw == nil || decoder.More() {
		return nil, fmt.Errorf("%w: expected one JSON object", errInvalid)
	}
	for k, v := range raw {
		if bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			delete(raw, k)
		}
	}
	return raw, nil
}

func only(raw map[string]json.RawMessage, allowed ...string) error {
	ok := map[string]bool{}
	for _, field := range allowed {
		ok[field] = true
	}
	for field := range raw {
		if !ok[field] {
			return fmt.Errorf("%w: unexpected field %s", errInvalid, field)
		}
	}
	return nil
}

// joinRequest accepts a join by invite chain (`membership`) or by an
// administrator's admission of the caller's key: either `admission`, or
// neither field, in which case the stored admission for the caller is used.
func (s *Server) joinRequest(ctx context.Context, caller, network string, data []byte) (int, *membership.Map, error) {
	raw, err := rawFields(data)
	if err != nil {
		return 0, nil, err
	}
	if err = only(raw, "membership", "admission", "address", "candidates"); err != nil {
		return 0, nil, err
	}
	var address string
	var candidates []string
	if json.Unmarshal(raw["address"], &address) != nil || json.Unmarshal(raw["candidates"], &candidates) != nil || raw["address"] == nil || raw["candidates"] == nil {
		return 0, nil, fmt.Errorf("%w: address and candidates are required", errInvalid)
	}
	if raw["membership"] != nil {
		if raw["admission"] != nil {
			return 0, nil, fmt.Errorf("%w: give membership or admission, not both", errInvalid)
		}
		var req joinRequest
		if err = json.Unmarshal(raw["membership"], &req.Membership); err != nil {
			return 0, nil, fmt.Errorf("%w: %v", errInvalid, err)
		}
		req.Address, req.Candidates = address, candidates
		return s.join(ctx, caller, network, req)
	}
	var admission *membership.HostAdmission
	if raw["admission"] != nil {
		admission = new(membership.HostAdmission)
		if err = json.Unmarshal(raw["admission"], admission); err != nil {
			return 0, nil, fmt.Errorf("%w: %v", errInvalid, err)
		}
	}
	return s.joinByAdmission(ctx, caller, network, admission, address, candidates)
}

func (s *Server) joinByAdmission(ctx context.Context, caller, network string, admission *membership.HostAdmission, address string, candidates []string) (int, *membership.Map, error) {
	if err := validEndpoints(address, candidates); err != nil {
		return 0, nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, nil, err
	}
	defer tx.Rollback()
	chain, err := chainOf(ctx, tx, network)
	if err != nil {
		return 0, nil, err
	}
	if admission == nil {
		// Use the stored admission for the caller's key, if any.
		stored, err := hostAdmissionFor(ctx, tx, network, caller)
		if err != nil {
			return 0, nil, err
		}
		if stored == nil {
			return 0, nil, fmt.Errorf("%w: no administrator has admitted this host", errForbidden)
		}
		admission = stored
	}
	id, err := chain.VerifyHostAdmission(*admission)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %v", errForbidden, err)
	}
	if id != caller {
		return 0, nil, fmt.Errorf("%w: admission is for a different host", errForbidden)
	}
	if revoked, err := revokedHost(ctx, tx, network, admission.HostPublicKey); err != nil || revoked {
		return 0, nil, errors.Join(err, fmt.Errorf("%w: host has been revoked or has left", errForbidden))
	}
	var exists int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM members WHERE network_id = ? AND host_id = ?`, network, caller).Scan(&exists); err != nil {
		return 0, nil, err
	}
	if exists != 0 {
		m, err := networkMap(ctx, tx, network)
		return http.StatusOK, m, err
	}
	data, err := json.Marshal(admission)
	if err != nil {
		return 0, nil, err
	}
	if _, err = putStatement(ctx, tx, network, kindHostAdmission, admission.HostPublicKey, data); err != nil {
		return 0, nil, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO members (network_id, host_id, invite_public_key, membership, address, updated_at, admission) VALUES (?, ?, ?, '', ?, ?, ?)`, network, caller, admissionPrefix+admission.HostPublicKey, address, membership.Timestamp(s.Now()), string(data)); err != nil {
		return 0, nil, err
	}
	if err = putCandidates(ctx, tx, network, caller, candidates); err != nil {
		return 0, nil, err
	}
	m, err := networkMap(ctx, tx, network)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusCreated, m, tx.Commit()
}

// hostAdmissionFor returns the stored admission whose key derives hostID.
func hostAdmissionFor(ctx context.Context, tx *sql.Tx, network, hostID string) (*membership.HostAdmission, error) {
	raw, err := statementsOf(ctx, tx, network, kindHostAdmission)
	if err != nil {
		return nil, err
	}
	for _, data := range raw {
		var a membership.HostAdmission
		if json.Unmarshal(data, &a) != nil {
			continue
		}
		if key, err := membership.DecodeKey(a.HostPublicKey); err == nil && membership.HostID(key) == hostID {
			return &a, nil
		}
	}
	return nil, nil
}

func (s *Server) personRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /coord/v1/networks/{network}/persons", func(w http.ResponseWriter, r *http.Request) {
		caller, ok := callerID(w, r)
		if !ok {
			return
		}
		data, ok := readBody(w, r)
		if !ok {
			return
		}
		m, err := s.admitPerson(r.Context(), caller, r.PathValue("network"), data)
		respond(w, http.StatusOK, m, err)
	})
	mux.HandleFunc("POST /coord/v1/networks/{network}/hosts", func(w http.ResponseWriter, r *http.Request) {
		caller, ok := callerID(w, r)
		if !ok {
			return
		}
		var req struct {
			Admission membership.HostAdmission `json:"admission"`
		}
		if !decode(w, r, &req, "admission") {
			return
		}
		m, err := s.admitHost(r.Context(), caller, r.PathValue("network"), req.Admission)
		respond(w, http.StatusOK, m, err)
	})
	mux.HandleFunc("POST /coord/v1/networks/{network}/bindings", func(w http.ResponseWriter, r *http.Request) {
		caller, ok := callerID(w, r)
		if !ok {
			return
		}
		var req struct {
			Binding membership.HostBinding `json:"binding"`
		}
		if !decode(w, r, &req, "binding") {
			return
		}
		m, err := s.bind(r.Context(), caller, r.PathValue("network"), req.Binding)
		respond(w, http.StatusOK, m, err)
	})
}

func (s *Server) admitPerson(ctx context.Context, caller, network string, data []byte) (*membership.Map, error) {
	raw, err := rawFields(data)
	if err != nil {
		return nil, err
	}
	if err = only(raw, "admission", "membership"); err != nil {
		return nil, err
	}
	var proof membership.PersonProof
	if raw["admission"] != nil {
		proof.Admission = new(membership.PersonAdmission)
		if err = json.Unmarshal(raw["admission"], proof.Admission); err != nil {
			return nil, fmt.Errorf("%w: %v", errInvalid, err)
		}
	}
	if raw["membership"] != nil {
		proof.Membership = new(membership.PersonMembership)
		if err = json.Unmarshal(raw["membership"], proof.Membership); err != nil {
			return nil, fmt.Errorf("%w: %v", errInvalid, err)
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	chain, err := chainOf(ctx, tx, network)
	if err != nil {
		return nil, mapNotFound(err)
	}
	if err = isMember(ctx, tx, network, caller); err != nil {
		return nil, err
	}
	key, _, err := chain.VerifyPerson(proof)
	if err != nil {
		return nil, err
	}
	revoked, err := revokedOf(ctx, tx, chain)
	if err != nil {
		return nil, err
	}
	if revoked.Persons[key] {
		return nil, fmt.Errorf("%w: person has been removed", errForbidden)
	}
	if m := proof.Membership; m != nil {
		if revoked.Invites[m.InvitePublicKey] {
			return nil, fmt.Errorf("%w: person invite has been revoked", errForbidden)
		}
		var user string
		err = tx.QueryRowContext(ctx, `SELECT statement FROM statements WHERE network_id = ? AND kind = ? AND subject = ?`, network, kindPersonInvite, m.InvitePublicKey).Scan(&user)
		switch {
		case err == nil && user != jsonString(key):
			return nil, fmt.Errorf("%w: person invite has already been used", errConflict)
		case err == nil:
		case errors.Is(err, sql.ErrNoRows):
			expires, _ := membership.ParseTime(m.InviteExpiresAt)
			if !expires.After(s.Now()) {
				return nil, fmt.Errorf("%w: person invite has expired", errForbidden)
			}
			if _, err = putStatement(ctx, tx, network, kindPersonInvite, m.InvitePublicKey, json.RawMessage(jsonString(key))); err != nil {
				return nil, err
			}
		default:
			return nil, err
		}
	}
	stored, err := json.Marshal(proof)
	if err != nil {
		return nil, err
	}
	// An already admitted person keeps its original admission.
	if _, err = putStatement(ctx, tx, network, kindPersonAdmission, key, stored); err != nil {
		return nil, err
	}
	m, err := networkMap(ctx, tx, network)
	if err != nil {
		return nil, err
	}
	return m, tx.Commit()
}

func jsonString(value string) string {
	data, _ := json.Marshal(value)
	return string(data)
}

func (s *Server) admitHost(ctx context.Context, caller, network string, a membership.HostAdmission) (*membership.Map, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	chain, err := chainOf(ctx, tx, network)
	if err != nil {
		return nil, mapNotFound(err)
	}
	if err = isMember(ctx, tx, network, caller); err != nil {
		return nil, err
	}
	if _, err = chain.VerifyHostAdmission(a); err != nil {
		return nil, err
	}
	if revoked, err := revokedHost(ctx, tx, network, a.HostPublicKey); err != nil || revoked {
		return nil, errors.Join(err, fmt.Errorf("%w: host has been revoked or has left", errForbidden))
	}
	data, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	if _, err = putStatement(ctx, tx, network, kindHostAdmission, a.HostPublicKey, data); err != nil {
		return nil, err
	}
	m, err := networkMap(ctx, tx, network)
	if err != nil {
		return nil, err
	}
	return m, tx.Commit()
}

// validPersons returns admitted, unremoved persons by key.
func validPersons(ctx context.Context, tx *sql.Tx, chain membership.Chain, revoked membership.Revoked) (map[string]membership.PersonProof, error) {
	raw, err := statementsOf(ctx, tx, chain.NetworkID, kindPersonAdmission)
	if err != nil {
		return nil, err
	}
	persons := map[string]membership.PersonProof{}
	for _, data := range raw {
		var proof membership.PersonProof
		if json.Unmarshal(data, &proof) != nil {
			continue
		}
		key, _, err := chain.VerifyPerson(proof)
		if err != nil || revoked.Persons[key] || (proof.Membership != nil && revoked.Invites[proof.Membership.InvitePublicKey]) {
			continue
		}
		persons[key] = proof
	}
	return persons, nil
}

func (s *Server) bind(ctx context.Context, caller, network string, b membership.HostBinding) (*membership.Map, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	chain, err := chainOf(ctx, tx, network)
	if err != nil {
		return nil, mapNotFound(err)
	}
	if err = isMember(ctx, tx, network, caller); err != nil {
		return nil, err
	}
	if err = membership.VerifyHostBinding(network, b); err != nil {
		return nil, err
	}
	host, _ := membership.DecodeKey(b.HostPublicKey)
	if membership.HostID(host) != caller {
		return nil, fmt.Errorf("%w: a binding must be submitted by the bound host itself", errForbidden)
	}
	revoked, err := revokedOf(ctx, tx, chain)
	if err != nil {
		return nil, err
	}
	persons, err := validPersons(ctx, tx, chain, revoked)
	if err != nil {
		return nil, err
	}
	if _, ok := persons[b.PersonPublicKey]; !ok {
		return nil, fmt.Errorf("%w: person is not admitted to this network", errForbidden)
	}
	if revoked.Unbound[membership.UnbindSubject(b.PersonPublicKey, b.HostPublicKey)] {
		return nil, fmt.Errorf("%w: this host was unbound from this person, which is permanent", errForbidden)
	}
	var existing string
	err = tx.QueryRowContext(ctx, `SELECT statement FROM statements WHERE network_id = ? AND kind = ? AND subject = ?`, network, kindBinding, b.HostPublicKey).Scan(&existing)
	if err == nil {
		var current membership.HostBinding
		if json.Unmarshal([]byte(existing), &current) == nil && revoked.Bound(current.PersonPublicKey, current.HostPublicKey) {
			if _, ok := persons[current.PersonPublicKey]; ok {
				if current.PersonPublicKey != b.PersonPublicKey {
					return nil, fmt.Errorf("%w: host is already bound to another person", errConflict)
				}
				m, err := networkMap(ctx, tx, network) // identical or re-signed: keep the original
				return m, err
			}
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM statements WHERE network_id = ? AND kind = ? AND subject = ?`, network, kindBinding, b.HostPublicKey); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	data, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	if _, err = putStatement(ctx, tx, network, kindBinding, b.HostPublicKey, data); err != nil {
		return nil, err
	}
	m, err := networkMap(ctx, tx, network)
	if err != nil {
		return nil, err
	}
	return m, tx.Commit()
}

// addPersons fills the map's valid persons and each member's current binding.
// Stored entries are served once verified on acceptance; hosts verify again.
func addPersons(ctx context.Context, tx *sql.Tx, m *membership.Map) error {
	m.Persons = []membership.MapPerson{}
	chain, err := chainOf(ctx, tx, m.NetworkID)
	if err != nil {
		return err
	}
	revoked, err := revokedOf(ctx, tx, chain)
	if err != nil {
		return err
	}
	persons, err := validPersons(ctx, tx, chain, revoked)
	if err != nil {
		return err
	}
	for key, proof := range persons {
		public, _ := membership.DecodeKey(key)
		entry := membership.MapPerson{PersonID: membership.PersonID(public), PersonPublicKey: key}
		if proof.Admission != nil {
			entry.Member = proof.Admission.Member
			entry.Admission, _ = json.Marshal(proof.Admission)
		} else {
			entry.Member = proof.Membership.Member
			entry.Membership, _ = json.Marshal(proof.Membership)
		}
		m.Persons = append(m.Persons, entry)
	}
	sortPersons(m.Persons)
	bindings, err := statementsOf(ctx, tx, m.NetworkID, kindBinding)
	if err != nil {
		return err
	}
	byHost := map[string]json.RawMessage{}
	for _, data := range bindings {
		var b membership.HostBinding
		if json.Unmarshal(data, &b) != nil {
			continue
		}
		if _, ok := persons[b.PersonPublicKey]; !ok || !revoked.Bound(b.PersonPublicKey, b.HostPublicKey) {
			continue
		}
		if key, err := membership.DecodeKey(b.HostPublicKey); err == nil {
			byHost[membership.HostID(key)] = data
		}
	}
	for i := range m.Members {
		m.Members[i].Binding = byHost[m.Members[i].HostID]
	}
	return nil
}

func sortPersons(persons []membership.MapPerson) {
	for i := 1; i < len(persons); i++ {
		for j := i; j > 0 && persons[j].PersonID < persons[j-1].PersonID; j-- {
			persons[j], persons[j-1] = persons[j-1], persons[j]
		}
	}
}

// rotationAdmissions verifies admissions re-signed by the new root. They must
// cover every member admitted by public key and every current person; extra
// host admissions may renew admitted hosts that have not joined yet.
func (s *Server) rotationAdmissions(ctx context.Context, tx *sql.Tx, chain, next membership.Chain, raw []json.RawMessage) ([]membership.HostAdmission, []membership.PersonAdmission, error) {
	revoked, err := revokedOf(ctx, tx, chain)
	if err != nil {
		return nil, nil, err
	}
	persons, err := validPersons(ctx, tx, chain, revoked)
	if err != nil {
		return nil, nil, err
	}
	storedHosts := map[string]string{}
	stored, err := statementsOf(ctx, tx, chain.NetworkID, kindHostAdmission)
	if err != nil {
		return nil, nil, err
	}
	for _, data := range stored {
		var a membership.HostAdmission
		if json.Unmarshal(data, &a) == nil && !revoked.ExcludesHost(a.HostPublicKey, "") {
			storedHosts[a.HostPublicKey] = a.Member
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT admission FROM members WHERE network_id = ? AND membership = ''`, chain.NetworkID)
	if err != nil {
		return nil, nil, err
	}
	joined := map[string]bool{}
	for rows.Next() {
		var data string
		if err = rows.Scan(&data); err != nil {
			rows.Close()
			return nil, nil, err
		}
		var a membership.HostAdmission
		if json.Unmarshal([]byte(data), &a) == nil {
			joined[a.HostPublicKey] = true
		}
	}
	rows.Close()
	var hosts []membership.HostAdmission
	var people []membership.PersonAdmission
	seen := map[string]bool{}
	for _, data := range raw {
		fields, err := rawFields(data)
		if err != nil {
			return nil, nil, err
		}
		if fields["person_public_key"] != nil {
			var a membership.PersonAdmission
			if err = json.Unmarshal(data, &a); err != nil {
				return nil, nil, fmt.Errorf("%w: %v", errInvalid, err)
			}
			if err = next.VerifyPersonAdmission(a); err != nil {
				return nil, nil, err
			}
			proof, ok := persons[a.PersonPublicKey]
			if !ok || seen["p "+a.PersonPublicKey] || personLabel(proof) != a.Member {
				return nil, nil, fmt.Errorf("%w: admission for a person that is not current", errInvalid)
			}
			seen["p "+a.PersonPublicKey] = true
			people = append(people, a)
			continue
		}
		var a membership.HostAdmission
		if err = json.Unmarshal(data, &a); err != nil {
			return nil, nil, fmt.Errorf("%w: %v", errInvalid, err)
		}
		if _, err = next.VerifyHostAdmission(a); err != nil {
			return nil, nil, err
		}
		label, ok := storedHosts[a.HostPublicKey]
		if !ok || seen["h "+a.HostPublicKey] || label != a.Member {
			return nil, nil, fmt.Errorf("%w: admission for a host that is not admitted", errInvalid)
		}
		seen["h "+a.HostPublicKey] = true
		hosts = append(hosts, a)
	}
	for key := range joined {
		if !seen["h "+key] {
			return nil, nil, fmt.Errorf("%w: admissions must cover every host admitted by public key", errInvalid)
		}
	}
	for key := range persons {
		if !seen["p "+key] {
			return nil, nil, fmt.Errorf("%w: admissions must cover every current person", errInvalid)
		}
	}
	return hosts, people, nil
}

func personLabel(p membership.PersonProof) string {
	if p.Admission != nil {
		return p.Admission.Member
	}
	return p.Membership.Member
}

// replaceAdmissions installs the new root's admissions. Host admissions not
// renewed lapse; persons admitted by invite become admitted by public key.
func replaceAdmissions(ctx context.Context, tx *sql.Tx, network string, hosts []membership.HostAdmission, people []membership.PersonAdmission) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM statements WHERE network_id = ? AND kind IN (?, ?)`, network, kindHostAdmission, kindPersonAdmission); err != nil {
		return err
	}
	for _, a := range hosts {
		data, err := json.Marshal(a)
		if err != nil {
			return err
		}
		if _, err = putStatement(ctx, tx, network, kindHostAdmission, a.HostPublicKey, data); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE members SET admission = ? WHERE network_id = ? AND invite_public_key = ?`, string(data), network, admissionPrefix+a.HostPublicKey); err != nil {
			return err
		}
	}
	for _, a := range people {
		data, err := json.Marshal(membership.PersonProof{Admission: &a})
		if err != nil {
			return err
		}
		if _, err = putStatement(ctx, tx, network, kindPersonAdmission, a.PersonPublicKey, data); err != nil {
			return err
		}
	}
	return nil
}
