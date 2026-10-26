package decentralized

import (
	"crypto/ed25519"
	"encoding/json"
	"sort"
	"strings"

	"github.com/peerspan/peerspan/go/internal/membership"
)

type Signature struct {
	Role      string `json:"role"`
	PublicKey string `json:"public_key"`
	Format    string `json:"format"`
	Signature string `json:"signature"`
}
type Issuer struct {
	Kind   string `json:"kind"`
	Person string `json:"person_public_key"`
}
type Subject struct {
	Person string `json:"person_public_key"`
	Host   string `json:"host_public_key"`
	Device string `json:"device_public_key"`
	Member string `json:"member"`
	Scopes uint64 `json:"scopes"`
}
type Parent struct {
	Role string `json:"role"`
	ID   string `json:"id"`
}
type Lease struct {
	Root         string   `json:"root_state_id"`
	Operation    string   `json:"operation_id"`
	Sequence     uint64   `json:"sequence"`
	Predecessors []string `json:"predecessors"`
	Resolves     []string `json:"resolves"`
	Retained     []string `json:"retained_statement_ids"`
	Subject      Subject  `json:"subject"`
	Issuer       Issuer   `json:"issuer"`
	Parents      []Parent `json:"parents"`
	Issued       string   `json:"issued_at"`
	Before       string   `json:"not_before"`
	After        string   `json:"not_after"`
}
type RootState struct {
	Epoch        uint64   `json:"epoch"`
	Predecessors []string `json:"predecessors"`
	Resolves     []string `json:"resolves"`
	Migration    string   `json:"migration_proposal_id"`
	Key          string   `json:"root_public_key"`
	Issued       string   `json:"issued_at"`
	Retained     []string `json:"retained_statement_ids"`
}
type Access struct {
	Root         string   `json:"root_state_id"`
	Operation    string   `json:"operation_id"`
	Sequence     uint64   `json:"sequence"`
	Predecessors []string `json:"predecessors"`
	Resolves     []string `json:"resolves"`
	Issuer       Issuer   `json:"issuer"`
	Parents      []Parent `json:"parents"`
	Issued       string   `json:"issued_at"`
	Before       string   `json:"not_before"`
	After        string   `json:"not_after"`
	BodyBase64   string   `json:"body_base64"`
}
type Target struct {
	Statement string `json:"statement_id"`
	Person    string `json:"person_public_key"`
	Host      string `json:"host_public_key"`
	Device    string `json:"device_public_key"`
}
type Restriction struct {
	Root     string   `json:"root_state_id"`
	Issuer   Issuer   `json:"issuer"`
	Parents  []Parent `json:"parents"`
	Issued   string   `json:"issued_at"`
	Target   Target   `json:"target"`
	Kept     []string `json:"kept_statement_ids"`
	Ratifies string   `json:"ratifies"`
}

// Statement retains the exact public bytes, exact payload and role message.
// Intrinsic verification is not a current authority or admission decision.
type Statement struct {
	Kind, ContextID, ID, ProofID string
	Raw, Payload, Message        []byte
	Signatures                   []Signature
	Object                       Object
	Lease                        *Lease
	Root                         *RootState
	Access                       *Access
	Restriction                  *Restriction
	Body                         Object
}

func ProofID(kind string, raw []byte) string {
	return "dp_" + digest(message("peerspan-decentralized-proof-v1", kind, digest(raw)))
}
func StatementMessage(kind, ctx string, payload []byte) []byte {
	return message("peerspan-decentralized-statement-v1", kind, ctx, digest(payload))
}
func SignatureMessage(id, role, key string) []byte {
	return message("peerspan-decentralized-signature-v1", id, role, key)
}
func VerifySignature(public, format string, m []byte, s string) error {
	if !key(public) {
		return invalid()
	}
	pub, _ := membership.DecodeKey(public)
	switch format {
	case "ed25519":
		sig, e := decode(s, 64)
		if e != nil {
			return e
		}
		if len(sig) != 64 || !point(sig[:32]) || !ed25519.Verify(pub, m, sig) {
			return invalid()
		}
	case "sshsig":
		blob, e := decode(s, MaxObject)
		if e != nil {
			return e
		}
		if len(blob) < 64 || !point(blob[len(blob)-64:len(blob)-32]) || membership.VerifySSHSIG(pub, m, s) != nil {
			return invalid()
		}
	default:
		return invalid()
	}
	return nil
}
func ReadStatement(d Descriptor, raw []byte) (*Statement, error) { return readStatement(d, raw, false) }
func readStatement(d Descriptor, raw []byte, pendingBinding bool) (*Statement, error) {
	o, e := parse(raw)
	if e != nil {
		return nil, e
	}
	if fields(o, "format kind context_id payload_base64 signatures") != nil || version(o, 1) != nil {
		return nil, invalid()
	}
	a, e := texts(o, "kind", "context_id", "payload_base64")
	if e != nil {
		return nil, e
	}
	if a[1] != d.ContextID {
		return nil, invalid()
	}
	payload, e := decode(a[2], MaxPayload)
	if e != nil {
		return nil, e
	}
	p, e := parseLimit(payload, MaxPayload)
	if e != nil {
		return nil, e
	}
	s := &Statement{Kind: a[0], ContextID: a[1], Payload: payload, Raw: append([]byte{}, raw...), Object: p}
	s.Message = StatementMessage(s.Kind, s.ContextID, payload)
	s.ID = "ds_" + digest(s.Message)
	s.ProofID = ProofID(s.Kind, raw)
	roles, e := s.checkPayload(d)
	if e != nil {
		return nil, e
	}
	var signatures []json.RawMessage
	if json.Unmarshal(o["signatures"], &signatures) != nil || signatures == nil {
		return nil, invalid()
	}
	if len(signatures) > MaxObjects {
		return nil, failure("quota_exceeded")
	}
	if len(signatures) != len(roles) {
		return nil, invalid()
	}
	sort.Strings(roles)
	for i, rawsig := range signatures {
		so, e := readObject(rawsig, "role public_key format signature")
		if e != nil {
			return nil, e
		}
		var sig Signature
		if json.Unmarshal(rawsig, &sig) != nil || sig.Role != roles[i] {
			return nil, invalid()
		}
		if _, e = texts(so, "role", "public_key", "format", "signature"); e != nil {
			return nil, e
		}
		if pendingBinding && s.Kind == "binding_lease" && sig.Role == "host" {
			if sig.PublicKey != s.Lease.Subject.Host || sig.Format != "ed25519" || sig.Signature != "-" {
				return nil, invalid()
			}
			s.Signatures = append(s.Signatures, sig)
			continue
		}
		if e = VerifySignature(sig.PublicKey, sig.Format, SignatureMessage(s.ID, sig.Role, sig.PublicKey), sig.Signature); e != nil {
			return nil, e
		}
		if sig.Role == "host" || sig.Role == "device" || sig.Role == "issuer" && s.issuerKind() == "device" {
			if sig.Format != "ed25519" {
				return nil, invalid()
			}
		}
		if sig.Role == "issuer" && s.issuerKind() == "person" && sig.Format != "sshsig" {
			return nil, invalid()
		}
		if expected := s.intrinsicSigner(sig.Role); expected != "" && sig.PublicKey != expected {
			return nil, invalid()
		}
		s.Signatures = append(s.Signatures, sig)
	}
	return s, nil
}
func (s *Statement) Signer(role string) string {
	for _, sig := range s.Signatures {
		if sig.Role == role {
			return sig.PublicKey
		}
	}
	return ""
}
func (s *Statement) issuerKind() string {
	if s.Lease != nil {
		return s.Lease.Issuer.Kind
	}
	if s.Access != nil {
		return s.Access.Issuer.Kind
	}
	if s.Restriction != nil {
		return s.Restriction.Issuer.Kind
	}
	return "root"
}
func (s *Statement) intrinsicSigner(role string) string {
	if s.Kind == "migration_ack" && (role == "host" || role == "device") {
		return stringField(s.Object, role+"_public_key")
	}
	if s.Kind == "migration_proposal" && role == "issuer" {
		return stringField(s.Object, "legacy_root_public_key")
	}
	if role == "host" && s.Lease != nil {
		return s.Lease.Subject.Host
	}
	if s.Root != nil && (role == "new_root" || role == "issuer" && len(s.Root.Predecessors) == 0) {
		return s.Root.Key
	}
	if role == "issuer" {
		var i *Issuer
		if s.Lease != nil {
			i = &s.Lease.Issuer
		}
		if s.Access != nil {
			i = &s.Access.Issuer
		}
		if s.Restriction != nil {
			i = &s.Restriction.Issuer
		}
		if i != nil && i.Kind == "person" {
			return i.Person
		}
	}
	return ""
}
func issuerAndParents(o Object) (Issuer, []Parent, error) {
	var issuer Issuer
	var parents []Parent
	io, e := readObject(o["issuer"], "kind person_public_key")
	if e != nil {
		return issuer, nil, e
	}
	if json.Unmarshal(o["issuer"], &issuer) != nil {
		return issuer, nil, invalid()
	}
	if _, e = texts(io, "kind", "person_public_key"); e != nil {
		return issuer, nil, e
	}
	switch issuer.Kind {
	case "root":
		if issuer.Person != "-" {
			return issuer, nil, invalid()
		}
	case "person", "device":
		if !key(issuer.Person) {
			return issuer, nil, invalid()
		}
	default:
		return issuer, nil, invalid()
	}
	var entries []json.RawMessage
	if json.Unmarshal(o["parents"], &entries) != nil || entries == nil {
		return issuer, nil, invalid()
	}
	if len(entries) > 6 {
		return issuer, nil, invalid()
	}
	allowed := map[string]bool{"issuer_admin": true, "issuer_device": true, "issuer_person": true, "subject_binding": true, "subject_host": true, "subject_person": true}
	last := ""
	for _, raw := range entries {
		po, e := readObject(raw, "role id")
		if e != nil {
			return issuer, nil, e
		}
		pair, e := texts(po, "role", "id")
		if e != nil || !allowed[pair[0]] || pair[0] <= last || !identifier(pair[1], "ds_") {
			return issuer, nil, invalid()
		}
		parents = append(parents, Parent{pair[0], pair[1]})
		last = pair[0]
	}
	if parents == nil {
		parents = []Parent{}
	}
	return issuer, parents, nil
}
func exactParents(parents []Parent, roles ...string) bool {
	sort.Strings(roles)
	if len(parents) != len(roles) {
		return false
	}
	for i := range roles {
		if parents[i].Role != roles[i] {
			return false
		}
	}
	return true
}
func requiredRoles(issuer Issuer, admin bool, subject ...string) []string {
	roles := append([]string{}, subject...)
	if issuer.Kind != "root" {
		roles = append(roles, "issuer_person")
		if admin {
			roles = append(roles, "issuer_admin")
		}
		if issuer.Kind == "device" {
			roles = append(roles, "issuer_device")
		}
	}
	return roles
}
func (s *Statement) checkPayload(d Descriptor) ([]string, error) {
	p := s.Object
	switch s.Kind {
	case "root_state":
		if fields(p, "epoch predecessors resolves migration_proposal_id root_public_key issued_at retained_statement_ids") != nil {
			return nil, invalid()
		}
		var r RootState
		if json.Unmarshal(s.Payload, &r) != nil || !key(r.Key) || !literalOrID(r.Migration, "ds_") {
			return nil, invalid()
		}
		if _, e := stamp(r.Issued); e != nil {
			return nil, e
		}
		if _, e := ids(p, "predecessors", "ds_"); e != nil {
			return nil, e
		}
		if _, e := ids(p, "resolves", "ds_"); e != nil {
			return nil, e
		}
		if _, e := ids(p, "retained_statement_ids", "ds_"); e != nil {
			return nil, e
		}
		s.Root = &r
		if len(r.Predecessors) == 0 {
			if len(r.Resolves) != 0 || len(r.Retained) != 0 || r.Migration == "-" && (r.Epoch != 0 || r.Key != d.GenesisRootPublicKey) {
				return nil, invalid()
			}
			return []string{"issuer"}, nil
		}
		if r.Migration != "-" {
			return nil, invalid()
		}
		if len(r.Predecessors) == 1 {
			if r.Epoch == 0 || len(r.Resolves) != 0 {
				return nil, invalid()
			}
			return []string{"issuer", "new_root"}, nil
		}
		if !equalStrings(r.Predecessors, r.Resolves) || r.Epoch == 0 {
			return nil, invalid()
		}
		roles := []string{"new_root"}
		for _, id := range r.Predecessors {
			roles = append(roles, "root_branch:"+id)
		}
		return roles, nil
	case "admin_lease", "person_lease", "host_lease", "binding_lease", "device_lease":
		if fields(p, "root_state_id operation_id sequence predecessors resolves retained_statement_ids subject issuer parents issued_at not_before not_after") != nil {
			return nil, invalid()
		}
		var l Lease
		if json.Unmarshal(s.Payload, &l) != nil {
			return nil, invalid()
		}
		if !identifier(l.Root, "ds_") || l.Sequence == 0 || !literalOrID(l.Operation, "link_") && !(s.Kind == "host_lease" && identifier(l.Operation, "ds_")) {
			return nil, invalid()
		}
		for _, f := range []string{"predecessors", "resolves", "retained_statement_ids"} {
			if _, e := ids(p, f, "ds_"); e != nil {
				return nil, e
			}
		}
		if len(l.Predecessors) == 0 && len(l.Retained) != 0 {
			return nil, invalid()
		}
		if e := validInterval(l.Issued, l.Before, l.After, 604800); e != nil {
			return nil, e
		}
		if _, e := readObject(p["subject"], "person_public_key host_public_key device_public_key member scopes"); e != nil {
			return nil, e
		}
		issuer, parents, e := issuerAndParents(p)
		if e != nil {
			return nil, e
		}
		l.Issuer = issuer
		l.Parents = parents
		sub := l.Subject
		if !literalOrKey(sub.Person) || !literalOrKey(sub.Host) || !literalOrKey(sub.Device) {
			return nil, invalid()
		}
		roles := []string{"issuer"}
		parentRoles := []string{}
		switch s.Kind {
		case "admin_lease":
			if !key(sub.Person) || sub.Host != "-" || sub.Device != "-" || sub.Member != "-" || sub.Scopes != 8 || issuer.Kind != "root" || l.Operation != "-" {
				return nil, invalid()
			}
		case "person_lease":
			if !key(sub.Person) || sub.Host != "-" || sub.Device != "-" || !membership.ValidLabel(sub.Member) || sub.Scopes != 0 {
				return nil, invalid()
			}
			parentRoles = requiredRoles(issuer, true)
		case "host_lease":
			if sub.Person != "-" || !key(sub.Host) || sub.Device != "-" || !membership.ValidLabel(sub.Member) || sub.Scopes != 0 {
				return nil, invalid()
			}
			parentRoles = requiredRoles(issuer, true)
			if l.Operation == "-" || identifier(l.Operation, "ds_") {
				roles = append(roles, "host")
			}
		case "binding_lease":
			if !key(sub.Person) || !key(sub.Host) || sub.Device != "-" || sub.Member != "-" || sub.Scopes != 2 || issuer.Kind == "root" || issuer.Person != sub.Person {
				return nil, invalid()
			}
			parentRoles = requiredRoles(issuer, false, "subject_person", "subject_host")
			roles = append(roles, "host")
		case "device_lease":
			if !key(sub.Person) || !key(sub.Host) || !key(sub.Device) || sub.Member != "-" || sub.Scopes == 0 || sub.Scopes > 15 || issuer.Kind == "root" || issuer.Person != sub.Person || l.Operation == "-" {
				return nil, invalid()
			}
			parentRoles = requiredRoles(issuer, false, "subject_person", "subject_host", "subject_binding")
		}
		if !exactParents(parents, parentRoles...) {
			return nil, invalid()
		}
		s.Lease = &l
		return roles, nil
	case "policy", "group":
		if fields(p, "root_state_id operation_id sequence predecessors resolves issuer parents issued_at not_before not_after body_base64") != nil {
			return nil, invalid()
		}
		var a Access
		if json.Unmarshal(s.Payload, &a) != nil || !identifier(a.Root, "ds_") || a.Operation != "-" || a.Sequence == 0 {
			return nil, invalid()
		}
		for _, f := range []string{"predecessors", "resolves"} {
			if _, e := ids(p, f, "ds_"); e != nil {
				return nil, e
			}
		}
		if e := validInterval(a.Issued, a.Before, a.After, 86400); e != nil {
			return nil, e
		}
		issuer, parents, e := issuerAndParents(p)
		if e != nil {
			return nil, e
		}
		a.Issuer = issuer
		a.Parents = parents
		if s.Kind == "policy" && issuer.Kind == "root" || !exactParents(parents, requiredRoles(issuer, s.Kind == "group")...) {
			return nil, invalid()
		}
		body, e := decode(a.BodyBase64, MaxPayload)
		if e != nil {
			return nil, e
		}
		bo, e := parseLimit(body, MaxPayload)
		if e != nil {
			return nil, e
		}
		if e = checkAccessBody(d, s.Kind, a, bo); e != nil {
			return nil, e
		}
		s.Access = &a
		s.Body = bo
		return []string{"issuer"}, nil
	case "admin_withdraw", "person_remove", "host_revoke", "host_unbind", "device_revoke":
		if fields(p, "root_state_id issuer parents issued_at target kept_statement_ids ratifies") != nil {
			return nil, invalid()
		}
		var r Restriction
		if json.Unmarshal(s.Payload, &r) != nil || !identifier(r.Root, "ds_") || !literalOrID(r.Ratifies, "ds_") {
			return nil, invalid()
		}
		if _, e := stamp(r.Issued); e != nil {
			return nil, e
		}
		if _, e := ids(p, "kept_statement_ids", "ds_"); e != nil {
			return nil, e
		}
		if _, e := readObject(p["target"], "statement_id person_public_key host_public_key device_public_key"); e != nil {
			return nil, e
		}
		issuer, parents, e := issuerAndParents(p)
		if e != nil {
			return nil, e
		}
		r.Issuer = issuer
		r.Parents = parents
		t := r.Target
		if !literalOrID(t.Statement, "ds_") || !literalOrKey(t.Person) || !literalOrKey(t.Host) || !literalOrKey(t.Device) {
			return nil, invalid()
		}
		switch s.Kind {
		case "admin_withdraw":
			if !identifier(t.Statement, "ds_") || !key(t.Person) || t.Host != "-" || t.Device != "-" || issuer.Kind != "root" {
				return nil, invalid()
			}
		case "person_remove":
			if t.Statement != "-" || !key(t.Person) || t.Host != "-" || t.Device != "-" {
				return nil, invalid()
			}
		case "host_revoke":
			if t.Statement != "-" || t.Person != "-" || !key(t.Host) || t.Device != "-" {
				return nil, invalid()
			}
		case "host_unbind":
			if !identifier(t.Statement, "ds_") || !key(t.Person) || !key(t.Host) || t.Device != "-" || issuer.Kind == "root" || issuer.Person != t.Person {
				return nil, invalid()
			}
		case "device_revoke":
			if t.Statement != "-" || !key(t.Person) || t.Host != "-" || !key(t.Device) || issuer.Kind == "root" || issuer.Person != t.Person {
				return nil, invalid()
			}
		}
		if s.Kind != "admin_withdraw" && len(r.Kept) != 0 {
			return nil, invalid()
		}
		if !exactParents(parents, requiredRoles(issuer, s.Kind == "person_remove" || s.Kind == "host_revoke")...) {
			return nil, invalid()
		}
		s.Restriction = &r
		return []string{"issuer"}, nil
	case "migration_proposal", "migration_ack", "migration_commit":
		return s.checkMigrationPayload(d)
	default:
		return nil, invalid()
	}
}
func checkAccessBody(d Descriptor, kind string, a Access, o Object) error {
	network, e := text(o, "network_id")
	if e != nil || network != d.NetworkID {
		return invalid()
	}
	n, e := num(o, "version")
	if e != nil || n != a.Sequence {
		return invalid()
	}
	if kind == "group" {
		if fields(o, "network_id name version defined_at members") != nil {
			return invalid()
		}
		name, e := text(o, "name")
		if e != nil || !membership.ValidGroupName(name) {
			return invalid()
		}
		at, e := text(o, "defined_at")
		if e != nil || at != a.Issued {
			return invalid()
		}
		members, e := stringsOf(o, "members")
		if e != nil {
			return e
		}
		if !sorted(members) {
			return invalid()
		}
		for _, v := range members {
			if !identifier(v, "person_") {
				return invalid()
			}
		}
		return nil
	}
	if fields(o, "format network_id person_public_key version issued_at valid_until rules", "capability_rules", "trusted_hosts", "edits") != nil || version(o, 2) != nil {
		return invalid()
	}
	person, e := text(o, "person_public_key")
	if e != nil || person != a.Issuer.Person || !key(person) {
		return invalid()
	}
	issued, e := text(o, "issued_at")
	if e != nil || issued != a.Issued {
		return invalid()
	}
	after, e := text(o, "valid_until")
	if e != nil || after != a.After {
		return invalid()
	}
	// Membership's strict shape/rule checks are shared, while DEC's finite interval
	// is selected by its explicit fixed validator rather than a permissive mode.
	copy := Object{}
	for k, v := range o {
		copy[k] = v
	}
	copy["signature"] = json.RawMessage(`"-"`)
	for _, f := range []string{"capability_rules", "trusted_hosts", "edits"} {
		if _, ok := copy[f]; !ok {
			copy[f] = json.RawMessage(`[]`)
		}
	}
	raw, e := json.Marshal(copy)
	if e != nil {
		return invalid()
	}
	var p membership.Policy
	if json.Unmarshal(raw, &p) != nil {
		return invalid()
	}
	if membership.CheckDecentralizedPolicy(d.NetworkID, p) != nil {
		return invalid()
	}
	return nil
}
func parentID(parents []Parent, role string) string {
	for _, p := range parents {
		if p.Role == role {
			return p.ID
		}
	}
	return ""
}
func (s *Statement) stream() []string {
	if s.Root != nil {
		return []string{"root"}
	}
	if l := s.Lease; l != nil {
		switch s.Kind {
		case "admin_lease":
			return []string{"admin", l.Subject.Person}
		case "person_lease":
			return []string{"person", l.Subject.Person}
		case "host_lease":
			return []string{"host", l.Subject.Host}
		case "binding_lease":
			return []string{"binding", l.Subject.Host}
		case "device_lease":
			return []string{"device", l.Subject.Person, l.Subject.Device}
		}
	}
	if s.Access != nil {
		if s.Kind == "policy" {
			return []string{"policy", s.Access.Issuer.Person}
		}
		name, _ := text(s.Body, "name")
		return []string{"group", name}
	}
	return nil
}
func (s *Statement) sequence() uint64 {
	if s.Root != nil {
		return s.Root.Epoch
	}
	if s.Lease != nil {
		return s.Lease.Sequence
	}
	if s.Access != nil {
		return s.Access.Sequence
	}
	return 0
}
func (s *Statement) predecessors() []string {
	if s.Root != nil {
		return s.Root.Predecessors
	}
	if s.Lease != nil {
		return s.Lease.Predecessors
	}
	if s.Access != nil {
		return s.Access.Predecessors
	}
	return nil
}
func (s *Statement) resolves() []string {
	if s.Root != nil {
		return s.Root.Resolves
	}
	if s.Lease != nil {
		return s.Lease.Resolves
	}
	if s.Access != nil {
		return s.Access.Resolves
	}
	return nil
}
func (s *Statement) rootID() string {
	if s.Lease != nil {
		return s.Lease.Root
	}
	if s.Access != nil {
		return s.Access.Root
	}
	if s.Restriction != nil {
		return s.Restriction.Root
	}
	return ""
}
func (s *Statement) parents() []Parent {
	if s.Lease != nil {
		return s.Lease.Parents
	}
	if s.Access != nil {
		return s.Access.Parents
	}
	if s.Restriction != nil {
		return s.Restriction.Parents
	}
	return nil
}
func streamKey(stream []string) string { return strings.Join(stream, "\x00") }
