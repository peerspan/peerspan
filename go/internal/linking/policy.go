package linking

import (
	"encoding/base64"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/peerspan/peerspan/go/internal/membership"
)

// AccessHighWater is caller-pinned verified selection, retained after authority loss.
type AccessHighWater struct {
	Version     uint64 `json:"version"`
	MessageHash string `json:"message_hash"`
}
type PolicyHighWater struct {
	PersonPublicKey string `json:"person_public_key"`
	AccessHighWater
}
type GroupHighWater struct {
	Name string `json:"name"`
	AccessHighWater
}
type AccessContext struct {
	Network        []byte
	Epoch          uint64
	KnownFeatureID string
	Now            time.Time
	PriorPolicies  []PolicyHighWater
	PriorGroups    []GroupHighWater
}
type AccessSelection struct {
	AccessHighWater
	ProofID     string   `json:"proof_id"`
	RecordID    string   `json:"record_id"`
	BodyBase64  string   `json:"body_base64"`
	Active      bool     `json:"active"`
	Code        string   `json:"code"`
	RequiredIDs []string `json:"required_ids"`
}
type PolicyAccess struct {
	PersonPublicKey string `json:"person_public_key"`
	AccessSelection
}
type GroupAccess struct {
	Name string `json:"name"`
	AccessSelection
}
type AccessState struct {
	NetworkID string         `json:"network_id"`
	FeatureID string         `json:"feature_id"`
	Policies  []PolicyAccess `json:"policies"`
	Groups    []GroupAccess  `json:"groups"`
}

func accessKind(kind string) bool {
	return kind == "peerspan-policy-v1" || kind == "peerspan-policy-v2" || kind == "peerspan-group-v1"
}

type accessCandidate struct {
	key          string
	group        bool
	selection    AccessSelection
	person, cert string
	payload      Object
	root         bool
}

// Legacy policy storage uses int64 versions. Only its shape/message helpers are
// reused: the verified uint64 version is substituted into the signed header.
func legacyPolicyMessage(p Object, kind string) ([]byte, error) {
	if e := recordPayload(kind, p); e != nil {
		return nil, pathError("invalid")
	}
	normalized := Object{}
	for k, v := range p {
		normalized[k] = v
	}
	normalized["version"] = json.RawMessage(`1`)
	normalized["signature"] = json.RawMessage(`"-"`)
	if kind == "peerspan-policy-v2" {
		for _, k := range []string{"capability_rules", "trusted_hosts", "edits"} {
			if _, ok := normalized[k]; !ok {
				normalized[k] = json.RawMessage(`[]`)
			}
		}
	}
	b, e := json.Marshal(normalized)
	if e != nil {
		return nil, pathError("invalid")
	}
	var parsed membership.Policy
	if json.Unmarshal(b, &parsed) != nil {
		return nil, pathError("invalid")
	}
	parts := strings.Split(string(parsed.Message()), "\n")
	n, _ := num(p, "version")
	parts[3] = strconv.FormatUint(n, 10)
	return []byte(strings.Join(parts, "\n")), nil
}
func (v *activationVerifier) accessCandidate(id string, p catalogProof) (accessCandidate, error) {
	c := accessCandidate{cert: "root"}
	o := p.object
	var m []byte
	recordID := "-"
	if p.kind == "person_record" {
		kind := scalar(o, "kind")
		c.group = kind == "peerspan-group-v1"
		c.person, c.cert = scalar(o, "person_public_key"), scalar(o, "certificate_id")
		if !accessKind(kind) || scalar(o, "operation_id") != "-" || !key(c.person) || c.cert != "root" && !identifier(c.cert, "dc_") {
			return c, pathError("invalid")
		}
		scope := uint64(1)
		if c.group {
			scope = 8
		}
		signer := c.person
		var expiry time.Time
		if c.cert != "root" {
			cert, e := v.structural(c.cert, c.person)
			if e != nil {
				return c, e
			}
			if cert.scopes&scope != scope {
				return c, pathError("forbidden")
			}
			signer, expiry = cert.device, cert.until
		}
		r, payload, e := v.record(p.body, kind, "-", c.person, c.cert, signer)
		if e != nil {
			return c, e
		}
		c.payload, m, recordID = payload, r.Message, r.ID
		if c.group && !v.history.delegated[c.person] {
			return c, pathError("forbidden")
		}
		if !c.group && c.cert != "root" {
			until, _ := stamp(scalar(payload, "valid_until"))
			if until.After(expiry) {
				return c, pathError("forbidden")
			}
		}
	} else {
		c.group = p.kind == "group"
		c.payload = Object{}
		for k, b := range o {
			if k != "signature" {
				c.payload[k] = b
			}
		}
		kind := "peerspan-group-v1"
		var e error
		if c.group {
			if recordPayload(kind, c.payload) != nil {
				return c, pathError("invalid")
			}
			members, _ := stringsOf(c.payload, "members")
			n, _ := num(c.payload, "version")
			m = message(append([]string{kind, v.net, scalar(c.payload, "name"), strconv.FormatUint(n, 10), scalar(c.payload, "defined_at")}, members...)...)
		} else {
			kind = "peerspan-policy-v1"
			if _, ok := c.payload["format"]; ok {
				kind = "peerspan-policy-v2"
			}
			m, e = legacyPolicyMessage(c.payload, kind)
			if e != nil {
				return c, e
			}
		}
		sig, e := text(o, "signature")
		if e != nil {
			return c, pathError("invalid")
		}
		if c.group && rootSignature(v.root, m, sig) == nil {
			c.root = true
		} else {
			c.person = scalar(c.payload, "person_public_key")
			if c.group {
				pub, ok := membership.SSHSIGKey(sig)
				if !ok {
					return c, pathError("invalid")
				}
				c.person = membership.EncodeKey(pub)
				if !v.history.delegated[c.person] {
					return c, pathError("forbidden")
				}
			}
			if personSignature(c.person, m, sig) != nil {
				return c, pathError("invalid")
			}
		}
	}
	if scalar(c.payload, "network_id") != v.net {
		return c, pathError("invalid")
	}
	if !c.root {
		if e := v.ensurePerson(c.person); e != nil {
			return c, e
		}
		if _, known := v.persons[c.person]; !known {
			return c, pathError("proof_required")
		}
		if c.cert != "root" && !v.state.ActivatedCertificates[c.cert] {
			cert, e := v.structural(c.cert, c.person)
			if e != nil {
				return c, e
			}
			if _, e = v.activate(cert.request, true, 0); e != nil {
				return c, e
			}
		}
	}
	c.key = c.person
	if c.group {
		c.key = scalar(c.payload, "name")
	}
	n, e := num(c.payload, "version")
	if e != nil {
		return c, pathError("invalid")
	}
	c.selection = AccessSelection{AccessHighWater: AccessHighWater{n, digest(m)}, ProofID: id, RecordID: recordID, BodyBase64: base64.StdEncoding.EncodeToString(p.body), Code: "active", Active: true, RequiredIDs: []string{}}
	return c, nil
}
func (v *activationVerifier) validateAccessCandidates() error {
	for _, id := range v.orderedProofs() {
		p := v.proofs[id]
		if p.kind == "policy" || p.kind == "group" || p.kind == "person_record" && scalar(p.object, "operation_id") == "-" && accessKind(scalar(p.object, "kind")) {
			if _, e := v.accessCandidate(id, p); e != nil {
				return e
			}
		}
	}
	return nil
}

func (v *activationVerifier) accessStatus(c *accessCandidate) error {
	if !c.root {
		scope := uint64(1)
		if c.group {
			scope = 8
		}
		_, e := EvaluatePath(v.state, c.person, c.cert, scope, v.ctx.Now)
		if e != nil {
			p, ok := e.(*PathError)
			if !ok || p.Code == "invalid" || p.Code == "proof_required" {
				return e
			}
			c.selection.Active = false
			c.selection.Code = p.Code
			return nil
		}
	}
	if !c.group {
		issued, _ := stamp(scalar(c.payload, "issued_at"))
		until, _ := stamp(scalar(c.payload, "valid_until"))
		if v.ctx.Now.Before(issued.Add(-5*time.Minute)) || !v.ctx.Now.Before(until) {
			c.selection.Active = false
			c.selection.Code = "expired"
		}
	}
	return nil
}
func missingSelection(w AccessHighWater) AccessSelection {
	return AccessSelection{AccessHighWater: w, ProofID: "-", RecordID: "-", BodyBase64: "-", Code: "proof_required", RequiredIDs: []string{}}
}
func validWater(w AccessHighWater) bool { return w.Version > 0 && identifier(w.MessageHash, "") }

// VerifyAccessState selects exact signed statements and preserves pinned maxima.
// It does not decide permission or durably commit the returned high-water marks.
func VerifyAccessState(ctx AccessContext, catalog []byte) (AccessState, error) {
	fail := func(e error) (AccessState, error) { return AccessState{}, e }
	if len(ctx.Network)+len(catalog) > MaxActivation || len(ctx.PriorPolicies)+len(ctx.PriorGroups) > 16384 {
		return fail(pathError("invalid"))
	}
	policies, groups := map[string]AccessSelection{}, map[string]AccessSelection{}
	last := ""
	for _, p := range ctx.PriorPolicies {
		if !key(p.PersonPublicKey) || p.PersonPublicKey <= last || !validWater(p.AccessHighWater) {
			return fail(pathError("invalid"))
		}
		last = p.PersonPublicKey
		policies[last] = missingSelection(p.AccessHighWater)
	}
	last = ""
	for _, g := range ctx.PriorGroups {
		if !membership.ValidGroupName(g.Name) || g.Name <= last || !validWater(g.AccessHighWater) {
			return fail(pathError("invalid"))
		}
		last = g.Name
		groups[last] = missingSelection(g.AccessHighWater)
	}
	v, e := newCatalogVerifier(ctx.Network, ctx.Epoch, ctx.KnownFeatureID, ctx.Now)
	if e != nil {
		return fail(e)
	}
	if ctx.KnownFeatureID == "-" {
		return fail(pathError("upgrade_required"))
	}
	if e = v.catalog(catalog); e == nil {
		e = v.bootstrap(true)
	}
	if e == nil {
		e = v.revocations()
	}
	if e != nil {
		return fail(e)
	}
	candidates := []accessCandidate{}
	for _, id := range v.orderedProofs() {
		p := v.proofs[id]
		if p.kind == "policy" || p.kind == "group" || p.kind == "person_record" && scalar(p.object, "operation_id") == "-" && accessKind(scalar(p.object, "kind")) {
			c, e := v.accessCandidate(id, p)
			if e != nil {
				return fail(e)
			}
			candidates = append(candidates, c)
		}
	}
	if e = v.revocations(); e != nil {
		return fail(e)
	}
	seenGroups := map[string]map[uint64]string{}
	for _, g := range ctx.PriorGroups {
		seenGroups[g.Name] = map[uint64]string{g.Version: g.MessageHash}
	}
	for _, c := range candidates {
		if e = v.accessStatus(&c); e != nil {
			return fail(e)
		}
		selected := policies
		if c.group {
			selected = groups
			if seenGroups[c.key] == nil {
				seenGroups[c.key] = map[uint64]string{}
			}
			if h, ok := seenGroups[c.key][c.selection.Version]; ok && h != c.selection.MessageHash {
				return fail(pathError("state_conflict"))
			}
			seenGroups[c.key][c.selection.Version] = c.selection.MessageHash
		}
		old, exists := selected[c.key]
		n := c.selection
		if !exists || n.Version > old.Version || n.Version == old.Version && (n.MessageHash < old.MessageHash || n.MessageHash == old.MessageHash && (old.ProofID == "-" || n.ProofID < old.ProofID)) {
			selected[c.key] = n
		}
	}
	r := AccessState{NetworkID: v.net, FeatureID: v.feature, Policies: []PolicyAccess{}, Groups: []GroupAccess{}}
	keys := make([]string, 0, len(policies))
	for k := range policies {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		r.Policies = append(r.Policies, PolicyAccess{k, policies[k]})
	}
	keys = keys[:0]
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		r.Groups = append(r.Groups, GroupAccess{k, groups[k]})
	}
	return r, nil
}
func accessStateProbe(o Object) any {
	fail := func(e error) any {
		r := map[string]any{"ok": false, "code": "invalid"}
		if p, ok := e.(*PathError); ok {
			r["code"] = p.Code
			if p.Code == "proof_required" {
				r["required_ids"] = p.RequiredIDs
			}
		}
		return r
	}
	if fields(o, "kind network_base64 catalog_base64 epoch known_feature_id now prior_policies prior_groups") != nil {
		return fail(invalid())
	}
	network, e := decode(scalar(o, "network_base64"), MaxActivation)
	if e != nil {
		return fail(e)
	}
	catalog, e := decode(scalar(o, "catalog_base64"), MaxActivation)
	if e != nil {
		return fail(e)
	}
	epoch, e := num(o, "epoch")
	if e != nil {
		return fail(e)
	}
	now, e := stamp(scalar(o, "now"))
	if e != nil {
		return fail(e)
	}
	ctx := AccessContext{Network: network, Epoch: epoch, KnownFeatureID: scalar(o, "known_feature_id"), Now: now}
	for _, field := range []string{"prior_policies", "prior_groups"} {
		var entries []json.RawMessage
		if json.Unmarshal(o[field], &entries) != nil || entries == nil {
			return fail(invalid())
		}
		for _, raw := range entries {
			row, e := parse(raw)
			if e != nil {
				return fail(e)
			}
			subject := "person_public_key"
			if field == "prior_groups" {
				subject = "name"
			}
			if fields(row, subject+" version message_hash") != nil {
				return fail(invalid())
			}
			n, e := num(row, "version")
			if e != nil {
				return fail(e)
			}
			w := AccessHighWater{n, scalar(row, "message_hash")}
			if field == "prior_groups" {
				ctx.PriorGroups = append(ctx.PriorGroups, GroupHighWater{scalar(row, subject), w})
			} else {
				ctx.PriorPolicies = append(ctx.PriorPolicies, PolicyHighWater{scalar(row, subject), w})
			}
		}
	}
	r, e := VerifyAccessState(ctx, catalog)
	if e != nil {
		return fail(e)
	}
	return struct {
		OK bool `json:"ok"`
		AccessState
	}{true, r}
}
