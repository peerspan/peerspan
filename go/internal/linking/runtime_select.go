package linking

import (
	"encoding/base64"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/peerspan/peerspan/go/internal/membership"
)

// ProofSeed supplies exact signed bytes for dependency discovery only. A seed
// does not become a public catalog entry or establish any current authority.
type ProofSeed struct {
	Kind string
	Body []byte
}

type proofSubjects struct {
	refs, aliases, people, hosts, devices, invites map[string]bool
}

func newProofSubjects() proofSubjects {
	return proofSubjects{map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}}
}
func (s proofSubjects) merge(other proofSubjects) bool {
	changed := false
	for i, a := range []map[string]bool{s.refs, s.aliases, s.people, s.hosts, s.devices, s.invites} {
		b := []map[string]bool{other.refs, other.aliases, other.people, other.hosts, other.devices, other.invites}[i]
		for k := range b {
			if !a[k] {
				a[k] = true
				changed = true
			}
		}
	}
	return changed
}
func semanticProofIDs(o Object) []string {
	ids := []string{}
	if _, ok := o["parent_id"]; ok {
		if id, e := candidateCertificateID(o); e == nil {
			ids = append(ids, id)
		}
	}
	if _, ok := o["payload_base64"]; ok {
		b, _, e := payload(o)
		if e != nil {
			return ids
		}
		if _, ok := o["role"]; ok {
			m := message("peerspan-link-packet-v1", scalar(o, "request_id"), scalar(o, "role"), scalar(o, "writer_public_key"), scalar(o, "person_public_key"), scalar(o, "certificate_id"), digest(b))
			ids = append(ids, "lp_"+digest(message("peerspan-link-packet-id-v1", digest(m), scalar(o, "host_signature"), scalar(o, "device_signature"), scalar(o, "authority_signature"))))
			if scalar(o, "role") == "request" {
				ids = append(ids, scalar(o, "request_id"))
			}
		} else if kind := scalar(o, "kind"); kind != "" {
			epoch, e := num(o, "epoch")
			if e != nil {
				return ids
			}
			a := []string{kind, scalar(o, "network_id"), strconv.FormatUint(epoch, 10), scalar(o, "operation_id")}
			if _, ok := o["person_public_key"]; ok {
				m := message(append(append([]string{"peerspan-person-authorization-v1"}, a...), scalar(o, "person_public_key"), scalar(o, "certificate_id"), digest(b))...)
				ids = append(ids, "ar_"+digest(message("peerspan-authorized-record-v1", digest(m), scalar(o, "signature"), scalar(o, "host_signature"))))
			} else {
				m := message(append(append([]string{"peerspan-root-authorization-v1"}, a...), digest(b))...)
				ids = append(ids, "rr_"+digest(message("peerspan-root-authorized-record-v1", digest(m), scalar(o, "signature"))))
			}
		}
	}
	if _, ok := o["target_device_public_key"]; ok {
		a, e := texts(o, "network_id", "person_public_key", "target_device_public_key", "target_certificate_id", "issuer_certificate_id", "revoked_at")
		if e == nil {
			ids = append(ids, "dr_"+digest(message(append([]string{"peerspan-device-revoke-v1"}, a...)...)))
		}
	}
	return ids
}
func discoverProofSubjects(o Object, out proofSubjects, feature bool) {
	for _, id := range semanticProofIDs(o) {
		out.aliases[id] = true
	}
	if feature {
		return
	} // The signed roster is retained whole, without expanding it.
	for k, raw := range o {
		var str string
		if json.Unmarshal(raw, &str) == nil {
			for _, prefix := range []string{"pf_", "dc_", "ar_", "rr_", "dr_", "lp_", "lf_", "link_"} {
				if identifier(str, prefix) {
					out.refs[str] = true
					break
				}
			}
			if key(str) {
				switch k {
				case "person_public_key", "expected_person_public_key":
					out.people[str] = true
				case "host_public_key":
					out.hosts[str] = true
				case "device_public_key", "target_device_public_key":
					out.devices[str] = true
				case "invite_public_key":
					out.invites[str] = true
				}
			}
			if k == "signature" || k == "invite_signature" || k == "authority_signature" {
				if pub, ok := membership.SSHSIGKey(str); ok {
					out.people[membership.EncodeKey(pub)] = true
				}
			}
			if k == "payload_base64" {
				if b, e := decode(str, MaxPayload); e == nil {
					if nested, e := parseLimit(b, MaxPayload); e == nil {
						discoverProofSubjects(nested, out, false)
					}
				}
			}
			continue
		}
		if nested, e := parseLimit(raw, MaxPayload); e == nil {
			// Exact nested public statements resolve to their enclosing source
			// object. Do not emit reconstructed or synthetic standalone rows.
			nestedKind := ""
			switch k {
			case "certificate":
				nestedKind = "certificate"
			case "binding_record":
				if scalar(nested, "host_signature") != "-" {
					nestedKind = "person_record"
				}
			case "admission_record":
				nestedKind = "root_record"
				if _, ok := nested["person_public_key"]; ok {
					nestedKind = "person_record"
				}
			}
			if nestedKind != "" {
				out.aliases[proofID(nestedKind, raw)] = true
			}
			discoverProofSubjects(nested, out, false)
			continue
		}
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) == nil {
			for _, v := range values {
				var id string
				if json.Unmarshal(v, &id) == nil {
					if identifier(id, "pf_") || identifier(id, "ar_") || identifier(id, "dr_") {
						out.refs[id] = true
					}
				} else if nested, e := parseLimit(v, MaxPayload); e == nil {
					discoverProofSubjects(nested, out, false)
				}
			}
		}
	}
}

type selectionProof struct {
	id, kind string
	body     []byte
	object   Object
	subjects proofSubjects
}

func selectedSubject(p selectionProof, s proofSubjects) bool {
	o := p.object
	switch p.kind {
	case "rotation", "feature":
		return true
	case "person_admission", "person_membership", "admin_delegation", "admin_removal", "person_removal":
		return s.people[scalar(o, "person_public_key")]
	case "checkpoint":
		if !s.people[scalar(o, "person_public_key")] {
			return false
		}
		for _, field := range []string{"records", "activations"} {
			var targets []string
			if json.Unmarshal(o[field], &targets) != nil {
				continue
			}
			for _, id := range targets {
				if s.refs[id] || s.aliases[id] {
					return true
				}
			}
		}
		return false
	case "host_admission", "host_membership", "host_binding", "host_unbinding", "host_leave", "host_revocation", "attestation", "join_ack":
		return s.hosts[scalar(o, "host_public_key")]
	case "invite_revocation":
		return s.invites[scalar(o, "invite_public_key")]
	case "device_revocation":
		return s.people[scalar(o, "person_public_key")] && s.devices[scalar(o, "target_device_public_key")]
	case "activation":
		request, e := parse(o["request"])
		if e != nil {
			return false
		}
		_, body, e := payload(request)
		return e == nil && s.hosts[scalar(body, "host_public_key")]
	case "invite_redemption":
		return s.hosts[scalar(o, "host_public_key")] || scalar(o, "person_action") == "admit" && s.people[scalar(o, "person_public_key")]
	case "person_record", "root_record":
		_, b, e := payload(o)
		if e != nil {
			return false
		}
		switch scalar(o, "kind") {
		case "peerspan-person-admit-v1", "peerspan-person-remove-v1":
			return s.people[scalar(b, "person_public_key")]
		case "peerspan-host-admit-v1", "peerspan-host-bind-v1", "peerspan-host-unbind-v1", "peerspan-revoke-host-v1":
			return s.hosts[scalar(b, "host_public_key")]
		case "peerspan-revoke-invite-v1":
			return s.invites[scalar(b, "invite_public_key")]
		}
	}
	return false
}
func proofCatalog(net string, proofs []selectionProof) ([]byte, error) {
	rows := make([]map[string]string, 0, len(proofs))
	for _, p := range proofs {
		rows = append(rows, map[string]string{"id": p.id, "kind": p.kind, "body_base64": base64.StdEncoding.EncodeToString(p.body)})
	}
	return json.Marshal(map[string]any{"format": 1, "network_id": net, "objects": rows})
}
func validateProofSeed(ctx CatalogFactContext, catalog []byte, p ProofSeed, source map[string]selectionProof) error {
	o, e := parse(p.Body)
	if e != nil {
		return pathError("invalid")
	}
	if p.Kind == "packet" {
		device := "-"
		switch scalar(o, "role") {
		case "request", "selection", "commit":
			pub, ok := membership.SSHSIGKey(scalar(o, "device_signature"))
			if !ok {
				return pathError("invalid")
			}
			device = membership.EncodeKey(pub)
		}
		if _, e := Read("packet", p.Body, scalar(o, "writer_public_key"), device); e != nil {
			return pathError("invalid")
		}
		if role := scalar(o, "role"); (role == "owner" || role == "administrator") && scalar(o, "certificate_id") != "root" && scalar(o, "certificate_id") != "network_root" {
			v, err := storedWriterVerifier(ctx, catalog)
			if err != nil {
				return err
			}
			path, err := v.actor(scalar(o, "person_public_key"), scalar(o, "certificate_id"), 0, true, 0)
			if err != nil {
				return err
			}
			if path.SignerPublicKey != scalar(o, "writer_public_key") {
				return pathError("invalid")
			}
		}
		return nil
	}
	if p.Kind == "person_record" || p.Kind == "root_record" {
		v, err := storedWriterVerifier(ctx, catalog)
		if err != nil {
			return err
		}
		signer, _, err := v.epochRoot(o, "epoch")
		if err != nil {
			return err
		}
		if scalar(o, "network_id") != v.net {
			return pathError("invalid")
		}
		if p.Kind == "person_record" {
			person, cert := scalar(o, "person_public_key"), scalar(o, "certificate_id")
			signer = person
			if cert != "root" {
				path, err := v.actor(person, cert, 0, true, 0)
				if err != nil {
					return err
				}
				signer = path.SignerPublicKey
			}
		}
		if _, err = Read(p.Kind, p.Body, signer, "-"); err != nil {
			return pathError("invalid")
		}
		return nil
	}
	id := proofID(p.Kind, p.Body)
	if _, ok := source[id]; ok && p.Kind != "certificate" && p.Kind != "checkpoint" {
		return nil
	}
	// The supplied object is checked in a private candidate snapshot. It is never
	// copied into the returned source catalog or persisted by this selector.
	rows := make([]selectionProof, 0, len(source)+1)
	for _, v := range source {
		rows = append(rows, v)
	}
	if _, exists := source[id]; !exists {
		rows = append(rows, selectionProof{id: id, kind: p.Kind, body: p.Body})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].id < rows[j].id })
	candidate, e := proofCatalog(scalarFromNetwork(ctx.Network, "network_id"), rows)
	if e != nil {
		return pathError("invalid")
	}
	if _, e = VerifyStoredNetworkState(ctx, candidate); e != nil {
		return e
	}
	switch p.Kind {
	case "certificate", "checkpoint":
		v, e := newCatalogVerifierWithBudget(ctx.Network, ctx.Epoch, ctx.KnownFeatureID, ctx.Now, true)
		if e != nil {
			return e
		}
		if e = v.catalog(candidate); e != nil {
			return e
		}
		if e = v.bootstrap(true); e != nil {
			return e
		}
		person := scalar(o, "person_public_key")
		if p.Kind == "certificate" {
			if _, e = v.structural(scalarCertificateID(o), person); e != nil {
				return e
			}
			if parent := scalar(o, "parent_id"); parent != "root" {
				_, e = v.actor(person, parent, 0, true, 0)
			}
			return e
		}
		issuer := scalar(o, "issuer_certificate_id")
		signer := person
		if issuer != "root" {
			c, err := v.structural(issuer, person)
			if err != nil {
				return err
			}
			signer = c.device
		}
		if _, e = Read("checkpoint", p.Body, signer, "-"); e != nil {
			return pathError("invalid")
		}
	}
	return nil
}
func scalarFromNetwork(b []byte, k string) string { o, _ := parse(b); return scalar(o, k) }
func scalarCertificateID(o Object) string         { id, _ := candidateCertificateID(o); return id }

// SelectStoredProofCatalog chooses a sufficient conservative dependency closure.
// It establishes no authority for seeds and never emits a partial result.
func SelectStoredProofCatalog(ctx CatalogFactContext, catalog []byte, seeds []ProofSeed) ([]byte, error) {
	if len(seeds) == 0 || len(seeds) > 4096 {
		return nil, pathError("invalid")
	}
	state, e := VerifyStoredNetworkState(ctx, catalog)
	if e != nil {
		return nil, e
	}
	v, e := newCatalogVerifierWithBudget(ctx.Network, ctx.Epoch, ctx.KnownFeatureID, ctx.Now, true)
	if e != nil {
		return nil, e
	}
	if e = v.catalog(catalog); e != nil {
		return nil, e
	}
	c, e := parseCatalog(catalog, true)
	if e != nil {
		return nil, e
	}
	entries, e := catalogEntries(c, true)
	if e != nil {
		return nil, e
	}
	nodes := make([]selectionProof, 0, len(entries))
	source := map[string]selectionProof{}
	providers := map[string][]int{}
	for _, row := range entries {
		kind, id := scalar(row, "kind"), scalar(row, "id")
		p := v.proofs[id]
		subjects := newProofSubjects()
		discoverProofSubjects(p.object, subjects, kind == "feature")
		subjects.aliases[id] = true
		if kind == "feature" {
			subjects.aliases[state.Facts.FeatureID] = true
		}
		node := selectionProof{id, kind, p.body, p.object, subjects}
		source[id] = node
		for alias := range subjects.aliases {
			providers[alias] = append(providers[alias], len(nodes))
		}
		nodes = append(nodes, node)
	}
	found := newProofSubjects()
	seedAliases := map[string]bool{}
	seedBytes := 0
	for _, seed := range seeds {
		seedBytes += len(seed.Body)
		if seedBytes > MaxActivation {
			return nil, pathError("invalid")
		}
		if e = validateProofSeed(ctx, catalog, seed, source); e != nil {
			return nil, e
		}
		o, _ := parse(seed.Body)
		s := newProofSubjects()
		discoverProofSubjects(o, s, seed.Kind == "feature")
		found.merge(s)
		for id := range s.aliases {
			seedAliases[id] = true
		}
		if seed.Kind != "packet" {
			id := proofID(seed.Kind, seed.Body)
			if _, ok := source[id]; ok {
				found.refs[id] = true
			}
		}
	}
	picked := map[int]bool{}
	for changed := true; changed; {
		changed = false
		for id := range found.refs {
			for _, i := range providers[id] {
				if !picked[i] {
					picked[i] = true
					changed = true
				}
			}
		}
		for i, p := range nodes {
			if selectedSubject(p, found) && !picked[i] {
				picked[i] = true
				changed = true
			}
		}
		for i := range picked {
			if found.merge(nodes[i].subjects) {
				changed = true
			}
		}
	}
	missing := []string{}
	for id := range found.refs {
		if len(providers[id]) == 0 && !seedAliases[id] {
			// Packet IDs and a pending request can be supplied separately by the
			// caller; a public reference to an absent exact proof cannot.
			if strings.HasPrefix(id, "pf_") || strings.HasPrefix(id, "dc_") || strings.HasPrefix(id, "ar_") || strings.HasPrefix(id, "rr_") || strings.HasPrefix(id, "dr_") || strings.HasPrefix(id, "lf_") {
				missing = append(missing, id)
			}
		}
	}
	if len(missing) > 0 {
		return nil, pathError("proof_required", missing...)
	}
	result := make([]selectionProof, 0, len(picked))
	for i, p := range nodes {
		if picked[i] {
			result = append(result, p)
		}
	}
	out, e := proofCatalog(state.Facts.NetworkID, result)
	if e != nil {
		return nil, pathError("invalid")
	}
	if len(out) > 1<<20 || len(result) > 4096 {
		return nil, pathError("quota_exceeded")
	}
	if _, e = VerifyStoredNetworkState(ctx, out); e != nil {
		return nil, e
	}
	return out, nil
}

func proofSelectionProbe(o Object) any {
	fail := func(e error) any {
		result := map[string]any{"ok": false, "code": "invalid"}
		if p, ok := e.(*PathError); ok {
			result["code"] = p.Code
			if p.Code == "proof_required" {
				result["required_ids"] = p.RequiredIDs
			}
		}
		return result
	}
	if fields(o, "kind network_base64 catalog_base64 seeds epoch known_feature_id now") != nil {
		return fail(invalid())
	}
	network, e := decode(scalar(o, "network_base64"), MaxActivation)
	if e != nil {
		return fail(e)
	}
	catalog, e := decode(scalar(o, "catalog_base64"), MaxStoredCatalog)
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
	var rows []json.RawMessage
	if json.Unmarshal(o["seeds"], &rows) != nil || rows == nil || len(rows) == 0 || len(rows) > 4096 {
		return fail(invalid())
	}
	seeds := make([]ProofSeed, 0, len(rows))
	for _, raw := range rows {
		row, e := parse(raw)
		if e != nil || fields(row, "kind body_base64") != nil {
			return fail(invalid())
		}
		body, e := decode(scalar(row, "body_base64"), MaxActivation)
		if e != nil {
			return fail(e)
		}
		seeds = append(seeds, ProofSeed{Kind: scalar(row, "kind"), Body: body})
	}
	result, e := SelectStoredProofCatalog(CatalogFactContext{network, epoch, scalar(o, "known_feature_id"), now}, catalog, seeds)
	if e != nil {
		return fail(e)
	}
	return map[string]any{"ok": true, "catalog_base64": base64.StdEncoding.EncodeToString(result)}
}
