package linking

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
	"time"

	"github.com/peerspan/peerspan/go/internal/membership"
)

const MaxActivation = 512 << 10

// ActivationContext contains caller-pinned facts, never coordinator assertions.
// Epoch zero is the only supported epoch. Verification is first or historical.
type ActivationContext struct {
	Network                                                      []byte
	Epoch                                                        uint64
	KnownFeatureID, CallerHostPublicKey, ExpectedPersonPublicKey string
	Now                                                          time.Time
	Verification                                                 string
}

// ActivationEvidence establishes eligibility under supplied public evidence.
// It does not commit, establish freshness, or enable linking on a network.
type ActivationEvidence struct {
	RequestID       string     `json:"request_id"`
	ManifestID      string     `json:"manifest_id"`
	CertificateID   string     `json:"certificate_id"`
	NetworkID       string     `json:"network_id"`
	FeatureID       string     `json:"feature_id"`
	PersonPublicKey string     `json:"person_public_key"`
	HostPublicKey   string     `json:"host_public_key"`
	DevicePublicKey string     `json:"device_public_key"`
	Mode            string     `json:"mode"`
	State           *PathState `json:"-"`
}

type catalogProof struct {
	kind   string
	body   []byte
	object Object
}
type catalogContext struct {
	KnownFeatureID string
	Now            time.Time
}
type activationVerifier struct {
	ctx                catalogContext
	network            Object
	net, root, feature string
	state              *PathState
	proofs             map[string]catalogProof
	semantics          map[string]Object
	activations        map[string][]byte
	busy               map[string]bool
	done               map[string]ActivationEvidence
	admins             map[string]bool
	persons, hosts     map[string]string // verified admission labels
	activeRecords      map[string]bool   // exact proof IDs authorized by full activations
	history            historyFacts
	evidence           map[string]catalogProof // derived ar_/dr_ IDs, never asserted indexes
}

func scalar(o Object, k string) string { s, _ := text(o, k); return s }
func zeroEpoch(o Object) bool          { n, e := num(o, "epoch"); return e == nil && n == 0 }
func genesisEpoch(o Object) error {
	n, e := num(o, "epoch")
	if e != nil {
		return pathError("invalid")
	}
	if n != 0 {
		return pathError("upgrade_required")
	}
	return nil
}
func equivalent(a, b Object) bool {
	var x, y any
	da, _ := json.Marshal(a)
	db, _ := json.Marshal(b)
	ax, by := json.NewDecoder(bytes.NewReader(da)), json.NewDecoder(bytes.NewReader(db))
	ax.UseNumber()
	by.UseNumber()
	_ = ax.Decode(&x)
	_ = by.Decode(&y)
	return reflect.DeepEqual(x, y)
}
func proofID(kind string, body []byte) string {
	return "pf_" + digest(message("peerspan-link-proof-v1", kind, digest(body)))
}

// VerifyActivation derives authority from signed evidence in a private snapshot.
// No state is exposed on failure. The caller must still transactionally enforce
// freshness, feature high-water, current epoch and durable operation semantics.
func VerifyActivation(ctx ActivationContext, catalog, activation []byte) (ActivationEvidence, error) {
	bad := func(code string) (ActivationEvidence, error) { return ActivationEvidence{}, pathError(code) }
	if len(ctx.Network)+len(catalog)+len(activation) > MaxActivation || !key(ctx.CallerHostPublicKey) || ctx.ExpectedPersonPublicKey != "-" && !key(ctx.ExpectedPersonPublicKey) || ctx.KnownFeatureID != "-" && !identifier(ctx.KnownFeatureID, "lf_") || ctx.Verification != "first" && ctx.Verification != "historical" {
		return bad("invalid")
	}
	v, e := newCatalogVerifier(ctx.Network, ctx.Epoch, ctx.KnownFeatureID, ctx.Now)
	if e != nil {
		return ActivationEvidence{}, e
	}
	if e = v.catalog(catalog); e != nil {
		return ActivationEvidence{}, e
	}
	request, e := v.indexActivation(activation)
	if e != nil {
		return ActivationEvidence{}, e
	}
	if e = v.bootstrap(true); e != nil {
		return ActivationEvidence{}, e
	}
	if e = v.revocations(); e != nil {
		return ActivationEvidence{}, e
	}
	r, e := v.activate(request, ctx.Verification == "historical", 0)
	if e != nil {
		return ActivationEvidence{}, e
	}
	if r.HostPublicKey != ctx.CallerHostPublicKey || ctx.ExpectedPersonPublicKey != "-" && r.PersonPublicKey != ctx.ExpectedPersonPublicKey {
		return bad("invalid")
	}
	r.State = v.state
	return r, nil
}

func newCatalogVerifier(network []byte, epoch uint64, knownFeature string, now time.Time) (*activationVerifier, error) {
	if knownFeature != "-" && !identifier(knownFeature, "lf_") {
		return nil, pathError("invalid")
	}
	if epoch != 0 {
		return nil, pathError("upgrade_required")
	}
	n, e := parse(network)
	if e != nil || fields(n, "network_id name genesis_root_public_key coordinator_address coordinator_public_key") != nil {
		return nil, pathError("invalid")
	}
	root, net := scalar(n, "genesis_root_public_key"), scalar(n, "network_id")
	pub, e := membership.DecodeKey(root)
	if e != nil || !key(root) || !key(scalar(n, "coordinator_public_key")) || membership.NetworkID(pub) != net || !membership.ValidLabel(scalar(n, "name")) || !membership.ValidCoordinatorAddress(scalar(n, "coordinator_address")) {
		return nil, pathError("invalid")
	}
	v := &activationVerifier{ctx: catalogContext{KnownFeatureID: knownFeature, Now: now}, network: n, net: net, root: root, proofs: map[string]catalogProof{}, semantics: map[string]Object{}, activations: map[string][]byte{}, busy: map[string]bool{}, done: map[string]ActivationEvidence{}, admins: map[string]bool{}, persons: map[string]string{}, hosts: map[string]string{}, activeRecords: map[string]bool{}, evidence: map[string]catalogProof{}}
	v.state = &PathState{NetworkID: net, Persons: map[string]PersonState{}, Hosts: map[string]bool{}, Bindings: map[string]string{}, Certificates: map[string][]byte{}, ActivatedCertificates: map[string]bool{}, RevokedDevices: map[DeviceKey]bool{}}
	return v, nil
}

func (v *activationVerifier) semantic(id string, o Object) error {
	if old, ok := v.semantics[id]; ok && !equivalent(old, o) {
		return pathError("state_conflict")
	}
	v.semantics[id] = o
	return nil
}

func candidateCertificateID(o Object) (string, error) {
	if fields(o, "format network_id person_public_key device_public_key host_public_key parent_id scopes issued_at not_after request_id signature") != nil || version(o, 1) != nil {
		return "", pathError("invalid")
	}
	a, e := texts(o, "network_id", "person_public_key", "device_public_key", "host_public_key", "parent_id")
	if e != nil {
		return "", pathError("invalid")
	}
	sc, e := scope(o)
	if e != nil {
		return "", pathError("invalid")
	}
	b, e := texts(o, "issued_at", "not_after", "request_id", "signature")
	if e != nil {
		return "", pathError("invalid")
	}
	return "dc_" + digest(message(append(append([]string{"peerspan-device-certificate-v1"}, a...), sc, b[0], b[1], b[2])...)), nil
}

func (v *activationVerifier) index(kind string, body []byte) (string, error) {
	o, e := parse(body)
	if e != nil {
		return "", pathError("invalid")
	}
	id := proofID(kind, body)
	if _, ok := v.proofs[id]; ok {
		return id, nil
	}
	if len(v.proofs) >= 16384 {
		return "", pathError("invalid")
	}
	v.proofs[id] = catalogProof{kind, body, o}
	switch kind {
	case "certificate":
		cid, e := candidateCertificateID(o)
		if e != nil {
			return "", e
		}
		if e = v.semantic(cid, o); e != nil {
			return "", e
		}
		// Select a stable candidate among equivalent byte aliases.
		old, ok := v.state.Certificates[cid]
		if !ok || proofID(kind, old) > id {
			v.state.Certificates[cid] = body
		}
	case "person_record", "root_record":
		if nestedRecord(body) != nil {
			return "", pathError("invalid")
		}
		if scalar(o, "operation_id") == "-" {
			return "", pathError("upgrade_required")
		}
		b, _, e := payload(o)
		if e != nil {
			return "", pathError("invalid")
		}
		epoch, e := num(o, "epoch")
		if e != nil {
			return "", pathError("invalid")
		}
		a := []string{scalar(o, "kind"), scalar(o, "network_id"), strconv.FormatUint(epoch, 10), scalar(o, "operation_id")}
		var rid string
		if kind == "root_record" {
			m := message(append(append([]string{"peerspan-root-authorization-v1"}, a...), digest(b))...)
			rid = "rr_" + digest(message("peerspan-root-authorized-record-v1", digest(m), scalar(o, "signature")))
		} else {
			m := message(append(append([]string{"peerspan-person-authorization-v1"}, a...), scalar(o, "person_public_key"), scalar(o, "certificate_id"), digest(b))...)
			rid = "ar_" + digest(message("peerspan-authorized-record-v1", digest(m), scalar(o, "signature"), scalar(o, "host_signature")))
		}
		if e = v.semantic(rid, o); e != nil {
			return "", e
		}
		v.evidence[rid] = v.proofs[id]
	case "device_revocation":
		// Signature authority is resolved later. The derived message identity is
		// usable only as a lookup key for exact checkpoint references.
		a, e := texts(o, "network_id", "person_public_key", "target_device_public_key", "target_certificate_id", "issuer_certificate_id", "revoked_at")
		if e != nil {
			return "", pathError("invalid")
		}
		rid := "dr_" + digest(message(append([]string{"peerspan-device-revoke-v1"}, a...)...))
		if e = v.semantic(rid, o); e != nil {
			return "", e
		}
		v.evidence[rid] = v.proofs[id]
	case "checkpoint":
		if fields(o, "format network_id person_public_key issuer_certificate_id issued_at records signature") != nil || version(o, 1) != nil || !identifier(scalar(o, "network_id"), "net_") || !key(scalar(o, "person_public_key")) || scalar(o, "issuer_certificate_id") != "root" && !identifier(scalar(o, "issuer_certificate_id"), "dc_") {
			return "", pathError("invalid")
		}
		if _, e = stamp(scalar(o, "issued_at")); e != nil {
			return "", pathError("invalid")
		}
		if _, e = text(o, "signature"); e != nil {
			return "", pathError("invalid")
		}
		ids, e := stringsOf(o, "records")
		if e != nil || !sorted(ids) {
			return "", pathError("invalid")
		}
		for _, rid := range ids {
			if identifier(rid, "pf_") {
				return "", pathError("upgrade_required")
			}
			if !identifier(rid, "ar_") && !identifier(rid, "dr_") {
				return "", pathError("invalid")
			}
		}
	case "activation":
		if _, e = v.indexActivation(body); e != nil {
			return "", e
		}
	}
	return id, nil
}

func (v *activationVerifier) indexActivation(body []byte) (string, error) {
	a, e := parse(body)
	if e != nil || fields(a, "request owner selection administrator commit") != nil {
		return "", pathError("invalid")
	}
	request, e := parse(a["request"])
	if e != nil {
		return "", pathError("invalid")
	}
	id := scalar(request, "request_id")
	if !identifier(id, "link_") {
		return "", pathError("invalid")
	}
	if old, ok := v.activations[id]; ok {
		o, _ := parse(old)
		oldCommit, _ := parse(o["commit"])
		newCommit, _ := parse(a["commit"])
		if !equivalent(oldCommit, newCommit) {
			return "", pathError("operation_conflict")
		}
		if !equivalent(o, a) {
			return "", pathError("state_conflict")
		}
		return id, nil
	}
	v.activations[id] = body
	owner, e := parse(a["owner"])
	if e != nil {
		return "", pathError("invalid")
	}
	_, p, e := payload(owner)
	if e != nil {
		return "", pathError("invalid")
	}
	if _, e = v.index("certificate", p["certificate"]); e != nil {
		return "", e
	}
	commit, e := parse(a["commit"])
	if e != nil {
		return "", pathError("invalid")
	}
	_, c, e := payload(commit)
	if e != nil {
		return "", pathError("invalid")
	}
	if !absent(c["binding_record"]) {
		if _, e = v.index("person_record", c["binding_record"]); e != nil {
			return "", e
		}
	}
	if !absent(a["administrator"]) {
		admin, e := parse(a["administrator"])
		if e != nil {
			return "", pathError("invalid")
		}
		_, p, e := payload(admin)
		if e != nil {
			return "", pathError("invalid")
		}
		r, e := parse(p["admission_record"])
		if e != nil {
			return "", pathError("invalid")
		}
		kind := "root_record"
		if _, ok := r["person_public_key"]; ok {
			kind = "person_record"
		}
		if _, e = v.index(kind, p["admission_record"]); e != nil {
			return "", e
		}
	}
	return id, nil
}

func (v *activationVerifier) catalog(body []byte) error {
	c, e := parse(body)
	if e != nil || fields(c, "format network_id objects") != nil || version(c, 1) != nil || scalar(c, "network_id") != v.net {
		return pathError("invalid")
	}
	entries, e := pathEntries(c, "objects")
	if e != nil {
		return pathError("invalid")
	}
	last := ""
	for _, entry := range entries {
		if fields(entry, "id kind body_base64") != nil {
			return pathError("invalid")
		}
		id, kind := scalar(entry, "id"), scalar(entry, "kind")
		b, e := decode(scalar(entry, "body_base64"), MaxObject)
		if e != nil || id <= last || !identifier(id, "pf_") || id != proofID(kind, b) {
			return pathError("invalid")
		}
		last = id
		switch kind {
		case "admin_delegation", "person_admission", "host_admission", "host_binding", "feature", "certificate", "activation", "person_record", "root_record", "device_revocation", "admin_removal", "person_membership", "host_membership", "host_unbinding", "host_leave", "host_revocation", "invite_revocation", "person_removal", "join_ack", "checkpoint":
		case "rotation", "group", "policy", "invite_redemption":
			return pathError("upgrade_required")
		default:
			return pathError("invalid")
		}
		if _, e = v.index(kind, b); e != nil {
			return e
		}
	}
	return nil
}

func (v *activationVerifier) orderedProofs() []string {
	ids := make([]string, 0, len(v.proofs))
	for id := range v.proofs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// structural verifies signatures and the exact certificate chain without live
// admission/activation/expiry. Used only for retained identity and root revocation.
func (v *activationVerifier) structural(id, person string) (pathCertificate, error) {
	if !identifier(id, "dc_") || !key(person) {
		return pathCertificate{}, pathError("invalid")
	}
	chain := []pathCertificate{}
	seen := map[string]bool{}
	for next := id; next != "root"; {
		if seen[next] || len(chain) == 8 {
			return pathCertificate{}, pathError("invalid")
		}
		seen[next] = true
		body, ok := v.state.Certificates[next]
		if !ok {
			return pathCertificate{}, pathError("proof_required", next)
		}
		c, e := pathCertificateFrom(next, body)
		if e != nil {
			return pathCertificate{}, e
		}
		chain = append(chain, c)
		next = c.parent
	}
	if len(chain) == 0 {
		return pathCertificate{}, pathError("invalid")
	}
	devices, hosts := map[string]bool{}, map[string]bool{}
	signer := person
	for i := len(chain) - 1; i >= 0; i-- {
		c := chain[i]
		r, e := Read("certificate", c.body, signer, "-")
		if e != nil || r.ID != c.id || c.network != v.net || c.person != person || devices[c.device] || hosts[c.host] || c.device == person {
			return pathCertificate{}, pathError("invalid")
		}
		if i+1 < len(chain) {
			p := chain[i+1]
			if p.scopes&4 == 0 || c.scopes&p.scopes != c.scopes || c.issued.Before(p.issued) || c.until.After(p.until) {
				return pathCertificate{}, pathError("forbidden")
			}
		}
		devices[c.device], hosts[c.host] = true, true
		signer = c.device
	}
	for d := range devices {
		if hosts[d] {
			return pathCertificate{}, pathError("invalid")
		}
	}
	return chain[0], nil
}

func (v *activationVerifier) authority(person, cert string, scope uint64, depth int) (SigningPath, error) {
	if !key(person) || cert != "root" && !identifier(cert, "dc_") {
		return SigningPath{}, pathError("invalid")
	}
	if cert != "root" {
		c, e := v.structural(cert, person)
		if e != nil {
			return SigningPath{}, e
		}
		if !v.state.ActivatedCertificates[cert] {
			if _, e = v.activate(c.request, true, depth+1); e != nil {
				return SigningPath{}, e
			}
		}
	}
	return EvaluatePath(v.state, person, cert, scope, v.ctx.Now)
}

func (v *activationVerifier) checkedPacket(raw []byte, role, request, signer, device string) (Object, Object, string, error) {
	o, e := parse(raw)
	if e != nil || scalar(o, "role") != role || scalar(o, "request_id") != request {
		return nil, nil, "", pathError("invalid")
	}
	r, e := Read("packet", raw, signer, device)
	if e != nil {
		return nil, nil, "", pathError("invalid")
	}
	p, e := parse(r.Payload)
	if e != nil {
		return nil, nil, "", pathError("invalid")
	}
	return o, p, r.ID, nil
}

func (v *activationVerifier) record(raw []byte, kind, operation, person, cert, signer string) (SignedObject, Object, error) {
	o, e := parse(raw)
	if e != nil || scalar(o, "network_id") != v.net || scalar(o, "kind") != kind || scalar(o, "operation_id") != operation {
		return SignedObject{}, nil, pathError("invalid")
	}
	if !zeroEpoch(o) {
		return SignedObject{}, nil, pathError("invalid")
	}
	typ := "person_record"
	if person == "-" {
		typ = "root_record"
	} else if scalar(o, "person_public_key") != person || scalar(o, "certificate_id") != cert {
		return SignedObject{}, nil, pathError("invalid")
	}
	r, e := Read(typ, raw, signer, "-")
	if e != nil {
		return SignedObject{}, nil, pathError("invalid")
	}
	p, e := parse(r.Payload)
	if e != nil {
		return SignedObject{}, nil, pathError("invalid")
	}
	return r, p, nil
}

func (v *activationVerifier) renewalProof(id, kind, person, host string, depth int) error {
	p, ok := v.proofs[id]
	if !ok {
		return pathError("proof_required", id)
	}
	if p.kind == "person_record" || p.kind == "root_record" {
		operation := scalar(p.object, "operation_id")
		if _, e := v.activate(operation, true, depth+1); e != nil {
			return e
		}
		if !v.activeRecords[id] || scalar(p.object, "kind") != kind {
			return pathError("invalid")
		}
		_, o, e := payload(p.object)
		if e != nil {
			return pathError("invalid")
		}
		if scalar(o, "host_public_key") != host {
			return pathError("invalid")
		}
		if kind == "peerspan-host-bind-v1" && scalar(o, "person_public_key") != person {
			return pathError("invalid")
		}
		if kind == "peerspan-host-admit-v1" && scalar(o, "member") != v.persons[person] {
			return pathError("invalid")
		}
		return nil
	}
	if kind == "peerspan-host-bind-v1" && p.kind == "host_binding" && scalar(p.object, "host_public_key") == host && scalar(p.object, "person_public_key") == person {
		return nil
	}
	if kind == "peerspan-host-admit-v1" && p.kind == "host_admission" && scalar(p.object, "host_public_key") == host && scalar(p.object, "member") == v.persons[person] {
		valid, e := v.legacyAuthority(message("peerspan-host-admit-v1", v.net, "0", host, scalar(p.object, "member"), scalar(p.object, "admitted_at")), scalar(p.object, "signature"))
		if e != nil {
			return e
		}
		if !valid {
			return pathError("forbidden")
		}
		return nil
	}
	if kind == "peerspan-host-admit-v1" && p.kind == "host_membership" && scalar(p.object, "host_public_key") == host && scalar(p.object, "member") == v.persons[person] {
		valid, e := v.legacyMembership(p, false)
		if e != nil {
			return e
		}
		if !valid {
			return pathError("forbidden")
		}
		return nil
	}
	return pathError("invalid")
}

// An unrelated, complete catalog activation may already admit this target host.
// Resolve those facts before accepting new membership, even when the owner path
// does not traverse that activation. In-progress operations cannot supply facts.
func (v *activationVerifier) hostActivations(host string, depth int) error {
	ids := make([]string, 0, len(v.activations))
	for id := range v.activations {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if v.busy[id] {
			continue
		}
		a, _ := parse(v.activations[id])
		r, e := parse(a["request"])
		if e != nil {
			return pathError("invalid")
		}
		_, p, e := payload(r)
		if e != nil {
			return pathError("invalid")
		}
		if scalar(p, "host_public_key") == host && scalar(p, "mode") == "new" {
			if _, e = v.activate(id, true, depth+1); e != nil {
				return e
			}
		}
	}
	return nil
}

func (v *activationVerifier) activate(id string, historical bool, depth int) (ActivationEvidence, error) {
	bad := func(code string) (ActivationEvidence, error) { return ActivationEvidence{}, pathError(code) }
	// Roster or other dependency resolution may have verified this same
	// transcript historically. Its cached evidence cannot skip first-operation
	// deadline, live-authority or current membership/binding checks.
	if r, ok := v.done[id]; historical && ok {
		return r, nil
	}
	if v.busy[id] || depth >= 8 {
		return bad("invalid")
	}
	body, ok := v.activations[id]
	if !ok {
		return ActivationEvidence{}, pathError("proof_required", id)
	}
	v.busy[id] = true
	defer delete(v.busy, id)
	a, e := parse(body)
	if e != nil {
		return bad("invalid")
	}
	request, _ := parse(a["request"])
	_, req, e := payload(request)
	if e != nil {
		return bad("invalid")
	}
	host, device := scalar(req, "host_public_key"), scalar(req, "device_public_key")
	_, req, rid, e := v.checkedPacket(a["request"], "request", id, host, device)
	if e != nil {
		return ActivationEvidence{}, e
	}
	if host == device || scalar(req, "coordinator_address") != scalar(v.network, "coordinator_address") || scalar(req, "coordinator_public_key") != scalar(v.network, "coordinator_public_key") {
		return bad("invalid")
	}
	expectedID := "link_" + digest(message("peerspan-link-request-id-v1", scalar(req, "coordinator_public_key"), host, device, scalar(req, "request_nonce")))
	if id != expectedID {
		return bad("invalid")
	}
	created, e := stamp(scalar(req, "created_at"))
	if e != nil {
		return bad("invalid")
	}
	expires, e := stamp(scalar(req, "expires_at"))
	if e != nil || expires.Sub(created) != 300*time.Second {
		return bad("invalid")
	}
	if !historical && (v.ctx.Now.Before(created) || !v.ctx.Now.Before(expires)) {
		return bad("expired")
	}
	mode := scalar(req, "mode")
	owner, e := parse(a["owner"])
	if e != nil {
		return bad("invalid")
	}
	_, offer, e := payload(owner)
	if e != nil {
		return bad("invalid")
	}
	person, issuer := scalar(offer, "person_public_key"), scalar(owner, "certificate_id")
	if !historical && (v.history.hosts[host] || v.history.persons[person] || v.history.unbound[bindingPair{person, host}]) {
		return bad("forbidden")
	}
	if scalar(owner, "person_public_key") != person || scalar(req, "expected_network_id") != "-" && scalar(req, "expected_network_id") != v.net || scalar(req, "expected_person_public_key") != "-" && scalar(req, "expected_person_public_key") != person {
		return bad("invalid")
	}
	network, e := parse(offer["network"])
	if e != nil || !equivalent(network, v.network) {
		return bad("invalid")
	}
	if !zeroEpoch(offer) {
		return bad("invalid")
	}
	if scalar(offer, "feature_id") != v.feature || scalar(offer, "request_packet_id") != rid {
		return bad("invalid")
	}
	required := uint64(6)
	if mode == "renew" {
		required = 4
	}
	path, e := v.actor(person, issuer, required, historical, depth)
	if e != nil {
		return ActivationEvidence{}, e
	}
	_, offer, oid, e := v.checkedPacket(a["owner"], "owner", id, path.SignerPublicKey, "-")
	if e != nil {
		return ActivationEvidence{}, e
	}
	certRaw := offer["certificate"]
	certObj, e := parse(certRaw)
	if e != nil {
		return bad("invalid")
	}
	cid, e := candidateCertificateID(certObj)
	if e != nil {
		return ActivationEvidence{}, e
	}
	c, e := pathCertificateFrom(cid, certRaw)
	if e != nil {
		return ActivationEvidence{}, e
	}
	if c.person != person || c.host != host || c.device != device || c.parent != issuer || c.request != id || c.network != v.net {
		return bad("invalid")
	}
	if issuer != "root" {
		parent, _ := pathCertificateFrom(issuer, v.state.Certificates[issuer])
		if c.scopes&parent.scopes != c.scopes || c.issued.Before(parent.issued) || c.until.After(parent.until) {
			return bad("forbidden")
		}
	}
	if _, e = v.structural(cid, person); e != nil {
		return ActivationEvidence{}, e
	}
	if !historical {
		if v.state.RevokedDevices[DeviceKey{PersonPublicKey: person, DevicePublicKey: device}] {
			return bad("device_revoked")
		}
		if v.ctx.Now.Before(c.issued) || !v.ctx.Now.Before(c.until) {
			return bad("authority_expired")
		}
	}
	selection, sel, sid, e := v.checkedPacket(a["selection"], "selection", id, host, device)
	if e != nil {
		return ActivationEvidence{}, e
	}
	if scalar(selection, "person_public_key") != person || scalar(sel, "owner_offer_id") != oid || scalar(sel, "network_id") != v.net || !zeroEpoch(sel) || scalar(sel, "feature_id") != v.feature || scalar(sel, "person_public_key") != person {
		return bad("invalid")
	}
	commit, com, mid, e := v.checkedPacket(a["commit"], "commit", id, host, device)
	if e != nil {
		return ActivationEvidence{}, e
	}
	if scalar(commit, "person_public_key") != person || scalar(com, "mode") != mode || scalar(com, "request_packet_id") != rid || scalar(com, "owner_offer_id") != oid || scalar(com, "selection_id") != sid || scalar(com, "network_id") != v.net || !zeroEpoch(com) || scalar(com, "feature_id") != v.feature || scalar(com, "person_public_key") != person || scalar(com, "certificate_id") != cid || scalar(com, "expires_at") != scalar(req, "expires_at") {
		return bad("invalid")
	}
	var binding, admission []byte
	if mode == "new" {
		if scalar(req, "renewed_certificate_id") != "-" || scalar(offer, "membership_proof_id") != "-" || scalar(offer, "binding_proof_id") != "-" || absent(a["administrator"]) || absent(offer["binding_record"]) || absent(com["binding_record"]) {
			return bad("invalid")
		}
		admin, e := parse(a["administrator"])
		if e != nil {
			return bad("invalid")
		}
		ap, ac := scalar(admin, "person_public_key"), scalar(admin, "certificate_id")
		signer := v.root
		if ac == "network_root" {
			if ap != "-" {
				return bad("invalid")
			}
		} else {
			p, e := v.actor(ap, ac, 8, historical, depth)
			if e != nil {
				return ActivationEvidence{}, e
			}
			signer = p.SignerPublicKey
		}
		_, adm, aid, e := v.checkedPacket(a["administrator"], "administrator", id, signer, "-")
		if e != nil {
			return ActivationEvidence{}, e
		}
		if scalar(adm, "owner_offer_id") != oid || scalar(adm, "selection_id") != sid || scalar(com, "administrator_offer_id") != aid {
			return bad("invalid")
		}
		admission = adm["admission_record"]
		ar, p, e := v.record(admission, "peerspan-host-admit-v1", id, ap, ac, signer)
		if e != nil {
			return ActivationEvidence{}, e
		}
		if scalar(p, "host_public_key") != host || scalar(p, "member") != v.persons[person] || scalar(com, "admission_record_id") != ar.ID {
			return bad("invalid")
		}
		if historical {
			o, _ := parse(admission)
			if e = v.historicalRecord(ar, o, 8, depth); e != nil {
				return ActivationEvidence{}, e
			}
		}
		binding = com["binding_record"]
		br, p, e := v.record(binding, "peerspan-host-bind-v1", id, person, issuer, path.SignerPublicKey)
		if e != nil {
			return ActivationEvidence{}, e
		}
		if scalar(p, "host_public_key") != host || scalar(p, "person_public_key") != person {
			return bad("invalid")
		}
		if historical {
			o, _ := parse(binding)
			if e = v.historicalRecord(br, o, 2, depth); e != nil {
				return ActivationEvidence{}, e
			}
		}
		draft, e := parse(offer["binding_record"])
		if e != nil || scalar(draft, "host_signature") != "-" {
			return bad("invalid")
		}
		final, _ := parse(binding)
		delete(draft, "host_signature")
		delete(final, "host_signature")
		if !equivalent(draft, final) {
			return bad("invalid")
		}
		if e = v.hostActivations(host, depth); e != nil {
			return ActivationEvidence{}, e
		}
		if admitted := v.state.Hosts[host]; admitted && (!historical || v.hosts[host] != v.persons[person]) {
			return bad("state_conflict")
		}
		if bound, ok := v.state.Bindings[host]; ok && bound != "-" && (!historical || bound != person && !v.history.unbound[bindingPair{person, host}]) {
			return bad("state_conflict")
		}
	} else if mode == "renew" {
		if scalar(req, "expected_network_id") != v.net || scalar(req, "expected_person_public_key") != person || scalar(req, "renewed_certificate_id") == "-" || !identifier(scalar(offer, "membership_proof_id"), "pf_") || !identifier(scalar(offer, "binding_proof_id"), "pf_") || !absent(a["administrator"]) || !absent(offer["binding_record"]) || !absent(com["binding_record"]) || scalar(com, "administrator_offer_id") != "-" || scalar(com, "admission_record_id") != "-" {
			return bad("invalid")
		}
		old, e := v.structural(scalar(req, "renewed_certificate_id"), person)
		if e != nil {
			return ActivationEvidence{}, e
		}
		if old.host != host || old.device != device {
			return bad("invalid")
		}
		if _, e = v.activate(old.request, true, depth+1); e != nil {
			return ActivationEvidence{}, e
		}
		if !v.state.ActivatedCertificates[old.id] {
			return bad("invalid")
		}
		if e = v.renewalProof(scalar(offer, "membership_proof_id"), "peerspan-host-admit-v1", person, host, depth); e != nil {
			return ActivationEvidence{}, e
		}
		if e = v.renewalProof(scalar(offer, "binding_proof_id"), "peerspan-host-bind-v1", person, host, depth); e != nil {
			return ActivationEvidence{}, e
		}
		if !v.state.Hosts[host] || v.state.Bindings[host] != person {
			return bad("forbidden")
		}
	} else {
		return bad("invalid")
	}
	// Publish facts only after every transcript check. Recursive ancestors are
	// independently complete. The caller never sees this scratch state on error.
	if mode == "new" {
		v.state.Hosts[host] = true
		v.hosts[host] = v.persons[person]
		if e = v.addBinding(host, person); e != nil {
			return ActivationEvidence{}, e
		}
		v.restrictState()
		for _, raw := range [][]byte{binding, admission} {
			o, _ := parse(raw)
			kind := "root_record"
			if _, ok := o["person_public_key"]; ok {
				kind = "person_record"
			}
			for pf, p := range v.proofs {
				if p.kind == kind && equivalent(o, p.object) {
					v.activeRecords[pf] = true
				}
			}
		}
	}
	v.state.ActivatedCertificates[cid] = true
	r := ActivationEvidence{RequestID: id, ManifestID: mid, CertificateID: cid, NetworkID: v.net, FeatureID: v.feature, PersonPublicKey: person, HostPublicKey: host, DevicePublicKey: device, Mode: mode}
	v.done[id] = r
	return r, nil
}

func activationProbe(o Object) any {
	fail := func(e error) any {
		if p, ok := e.(*PathError); ok {
			r := map[string]any{"ok": false, "code": p.Code}
			if p.Code == "proof_required" {
				r["required_ids"] = p.RequiredIDs
			}
			return r
		}
		return map[string]any{"ok": false, "code": "invalid"}
	}
	if fields(o, "kind network_base64 catalog_base64 activation_base64 epoch known_feature_id caller_host_public_key expected_person_public_key now verification") != nil {
		return fail(invalid())
	}
	b := [][]byte{}
	for _, k := range []string{"network_base64", "catalog_base64", "activation_base64"} {
		raw, e := decode(scalar(o, k), MaxActivation)
		if e != nil {
			return fail(e)
		}
		b = append(b, raw)
	}
	epoch, e := num(o, "epoch")
	if e != nil {
		return fail(e)
	}
	now, e := stamp(scalar(o, "now"))
	if e != nil {
		return fail(e)
	}
	r, e := VerifyActivation(ActivationContext{Network: b[0], Epoch: epoch, KnownFeatureID: scalar(o, "known_feature_id"), CallerHostPublicKey: scalar(o, "caller_host_public_key"), ExpectedPersonPublicKey: scalar(o, "expected_person_public_key"), Now: now, Verification: scalar(o, "verification")}, b[1], b[2])
	if e != nil {
		return fail(e)
	}
	data, _ := json.Marshal(r)
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	out["ok"] = true
	return out
}
