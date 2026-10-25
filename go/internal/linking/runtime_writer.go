package linking

import (
	"encoding/json"
	"sort"
	"strconv"

	"github.com/peerspan/peerspan/go/internal/membership"
)

// VerifyStoredCatalogAdditions checks newly submitted records against current
// typed authority before the caller commits the verified union. Operation
// drafts must be exact records of a complete activation in that union.
func VerifyStoredCatalogAdditions(ctx CatalogFactContext, prior, catalog []byte) error {
	return verifyStoredCatalogMerge(ctx, prior, catalog, true)
}

// VerifyStoredCatalogRepair validates historical complete evidence without
// treating its old signature as authority to issue a new statement today.
func VerifyStoredCatalogRepair(ctx CatalogFactContext, prior, catalog []byte) error {
	if _, err := VerifyStoredNetworkState(ctx, catalog); err != nil {
		return err
	}
	return verifyStoredCatalogMerge(ctx, prior, catalog, false)
}

func verifyStoredCatalogMerge(ctx CatalogFactContext, prior, catalog []byte, fresh bool) error {
	v, err := storedWriterVerifier(ctx, catalog)
	if err != nil {
		return err
	}
	old, err := parseCatalog(prior, true)
	if err != nil {
		return err
	}
	entries, err := catalogEntries(old, true)
	if err != nil {
		return err
	}
	known := map[string]bool{}
	for _, entry := range entries {
		known[scalar(entry, "id")] = true
	}
	// Completed activations index their exact nested records and certificates as
	// virtual proofs. They are already retained evidence, even when a new root
	// restriction makes their admissions inactive in the candidate projection.
	priorIndex, err := newCatalogVerifierWithBudget(ctx.Network, ctx.Epoch, ctx.KnownFeatureID, ctx.Now, true)
	if err != nil {
		return err
	}
	if err = priorIndex.catalog(prior); err != nil {
		return err
	}
	for id := range priorIndex.proofs {
		known[id] = true
	}
	maxima := map[string]uint64{}
	var moveSequence uint64
	accessKey := func(c accessCandidate) string {
		if c.group {
			return "group:" + c.key
		}
		return "policy:" + c.key
	}
	for id := range known {
		p, ok := v.proofs[id]
		if !ok {
			continue
		}
		if p.kind == "coordinator_move" {
			sequence, e := num(p.object, "sequence")
			if e != nil {
				return e
			}
			if sequence > moveSequence {
				moveSequence = sequence
			}
		}
		if p.kind == "policy" || p.kind == "group" || p.kind == "person_record" && accessKind(scalar(p.object, "kind")) {
			c, e := v.accessCandidate(id, p)
			if e != nil {
				return e
			}
			k := accessKey(c)
			if c.selection.Version > maxima[k] {
				maxima[k] = c.selection.Version
			}
		}
	}
	// Preserve only independently root-renewed preexisting authority while old
	// complete activations are replayed at a new root epoch. This never admits a
	// new person or role into the issuer-authority snapshot.
	renewals := map[string]bool{}
	if fresh {
		var priorEpoch uint64
		priorFeature := false
		for _, entry := range entries {
			priorFeature = priorFeature || scalar(entry, "kind") == "feature"
			if scalar(entry, "kind") == "rotation" {
				body, e := decode(scalar(entry, "body_base64"), MaxObject)
				if e != nil {
					return e
				}
				rotation, e := parse(body)
				if e != nil {
					return e
				}
				epoch, e := num(rotation, "epoch")
				if e != nil {
					return e
				}
				if epoch > priorEpoch {
					priorEpoch = epoch
				}
			}
		}
		if priorFeature && ctx.Epoch > priorEpoch {
			previous := ctx
			previous.Epoch = priorEpoch
			state, e := VerifyStoredNetworkState(previous, prior)
			if e != nil {
				return e
			}
			for id, p := range v.proofs {
				if known[id] || !epochIs(p.object, v.epoch) {
					continue
				}
				o := p.object
				person := scalar(o, "person_public_key")
				old := state.Facts.State.Persons[person]
				if !old.Admitted {
					continue
				}
				var m []byte
				switch p.kind {
				case "person_admission":
					m = message("peerspan-person-admit-v1", v.net, strconv.FormatUint(v.epoch, 10), person, scalar(o, "member"), scalar(o, "admitted_at"))
				case "admin_delegation":
					if old.Administrator {
						m = message("peerspan-admin-delegate-v1", v.net, strconv.FormatUint(v.epoch, 10), person, scalar(o, "delegated_at"))
					}
				}
				if len(m) > 0 && rootSignature(v.root, m, scalar(o, "signature")) == nil {
					renewals[id] = true
				}
			}
		}
	}
	// A fresh restriction must be authorized before it changes its own path.
	var authority struct {
		Format    uint64            `json:"format"`
		NetworkID string            `json:"network_id"`
		Objects   []json.RawMessage `json:"objects"`
	}
	if json.Unmarshal(catalog, &authority) != nil {
		return pathError("invalid")
	}
	allObjects := authority.Objects
	retained := []json.RawMessage{}
	newBinding := false
	for _, raw := range authority.Objects {
		var entry struct {
			ID   string `json:"id"`
			Kind string `json:"kind"`
		}
		if json.Unmarshal(raw, &entry) != nil {
			return pathError("invalid")
		}
		p := v.proofs[entry.ID]
		newBinding = newBinding || !known[entry.ID] && p.kind == "host_binding"
		freshAction := !known[entry.ID] && (p.kind == "device_revocation" || p.kind == "person_record" && scalar(p.object, "operation_id") == "-" || freshLegacyMutation(p.kind))
		if !freshAction || renewals[entry.ID] {
			retained = append(retained, raw)
		}
	}
	authority.Objects = retained
	beforeActions, err := json.Marshal(authority)
	if err != nil {
		return err
	}
	var before *activationVerifier
	var bindingTargets *activationVerifier
	var beforeAdmissions []byte
	if fresh {
		before, err = storedWriterVerifier(ctx, beforeActions)
		if err != nil {
			return err
		}
		if newBinding {
			// Consent bindings may refer to new independently authorized admission
			// targets, but those targets never authorize another fresh grant.
			bindingAuthority := authority
			bindingAuthority.Objects = append([]json.RawMessage{}, authority.Objects...)
			for _, raw := range allObjects {
				var entry struct {
					ID   string `json:"id"`
					Kind string `json:"kind"`
				}
				_ = json.Unmarshal(raw, &entry)
				if known[entry.ID] || renewals[entry.ID] {
					continue
				}
				switch entry.Kind {
				case "person_admission", "person_membership", "host_admission", "host_membership":
					if err = before.freshLegacy(v.proofs[entry.ID]); err != nil {
						return err
					}
					bindingAuthority.Objects = append(bindingAuthority.Objects, raw)
				}
			}
			sort.Slice(bindingAuthority.Objects, func(i, j int) bool {
				a, _ := parse(bindingAuthority.Objects[i])
				b, _ := parse(bindingAuthority.Objects[j])
				return scalar(a, "id") < scalar(b, "id")
			})
			bindingCatalog, e := json.Marshal(bindingAuthority)
			if e != nil {
				return e
			}
			bindingTargets, err = storedWriterVerifier(ctx, bindingCatalog)
			if err != nil {
				return err
			}
		}
		var pending struct {
			Format    uint64            `json:"format"`
			NetworkID string            `json:"network_id"`
			Objects   []json.RawMessage `json:"objects"`
		}
		if json.Unmarshal(catalog, &pending) != nil {
			return pathError("invalid")
		}
		kept := []json.RawMessage{}
		for _, raw := range pending.Objects {
			var entry struct {
				ID   string `json:"id"`
				Kind string `json:"kind"`
			}
			if json.Unmarshal(raw, &entry) != nil {
				return pathError("invalid")
			}
			if !known[entry.ID] && (entry.Kind == "activation" || entry.Kind == "invite_redemption") {
				continue
			}
			kept = append(kept, raw)
		}
		pending.Objects = kept
		beforeAdmissions, err = json.Marshal(pending)
		if err != nil {
			return err
		}
	}
	for _, id := range v.orderedProofs() {
		if known[id] {
			continue
		}
		p := v.proofs[id]
		o := p.object
		if fresh && freshLegacyMutation(p.kind) {
			authority := before
			if p.kind == "host_binding" {
				authority = bindingTargets
			}
			if e := authority.freshLegacy(p); e != nil {
				return e
			}
			if p.kind == "coordinator_move" {
				sequence, e := num(o, "sequence")
				if e != nil || sequence <= moveSequence {
					return pathError("state_conflict")
				}
			}
		}
		if fresh && (p.kind == "policy" || p.kind == "group" || p.kind == "person_record" && accessKind(scalar(o, "kind"))) {
			c, e := v.accessCandidate(id, p)
			if e != nil {
				return e
			}
			if c.selection.Version <= maxima[accessKey(c)] {
				return pathError("state_conflict")
			}
			if p.kind != "person_record" {
				if e = before.accessStatus(&c); e != nil {
					return e
				}
				if !c.selection.Active {
					return pathError("forbidden")
				}
			}
		}
		switch p.kind {
		case "invite_redemption":
			if fresh {
				_, err = VerifyStoredFreshRedemption(ctx, beforeAdmissions, p.body)
			}
		case "activation":
			if fresh {
				request, e := parse(o["request"])
				if e != nil {
					return pathError("invalid")
				}
				_, body, e := payload(request)
				if e != nil {
					return pathError("invalid")
				}
				_, err = VerifyStoredActivation(ActivationContext{Network: ctx.Network, Epoch: ctx.Epoch, KnownFeatureID: ctx.KnownFeatureID, CallerHostPublicKey: scalar(body, "host_public_key"), ExpectedPersonPublicKey: "-", Now: ctx.Now, Verification: "first"}, beforeAdmissions, p.body)
			}
		case "person_record", "root_record":
			if scalar(o, "operation_id") != "-" {
				signer, _, e := v.epochRoot(o, "epoch")
				if e != nil {
					return e
				}
				if p.kind == "person_record" {
					person, cert := scalar(o, "person_public_key"), scalar(o, "certificate_id")
					signer = person
					if cert != "root" {
						c, e := v.structural(cert, person)
						if e != nil {
							return e
						}
						signer = c.device
					}
				}
				if _, e = Read(p.kind, p.body, signer, "-"); e != nil {
					return pathError("invalid")
				}
				if !v.activeRecords[id] && (fresh || !v.inertRecords[id]) {
					return pathError("forbidden")
				}
				continue
			}
			if p.kind != "person_record" {
				return pathError("upgrade_required")
			}
			if fresh {
				_, err = VerifyStoredActionAuthority(ActionContext{Network: ctx.Network, Epoch: ctx.Epoch, KnownFeatureID: ctx.KnownFeatureID, PersonPublicKey: scalar(o, "person_public_key"), CertificateID: scalar(o, "certificate_id"), Now: ctx.Now}, "person_record", beforeActions, p.body)
			}
		case "device_revocation":
			if fresh {
				_, err = VerifyStoredActionAuthority(ActionContext{Network: ctx.Network, Epoch: ctx.Epoch, KnownFeatureID: ctx.KnownFeatureID, PersonPublicKey: scalar(o, "person_public_key"), CertificateID: scalar(o, "issuer_certificate_id"), Now: ctx.Now}, "device_revocation", beforeActions, p.body)
			}
		case "checkpoint":
			if fresh {
				err = v.checkpoint(p, id, scalar(o, "person_public_key"), scalar(o, "issuer_certificate_id"), 0)
			}
		case "certificate":
			cid, e := candidateCertificateID(o)
			if e != nil {
				return e
			}
			_, err = v.structural(cid, scalar(o, "person_public_key"))
		}
		if err != nil {
			return err
		}
	}
	if fresh {
		people := []string{}
		for person, state := range v.state.Persons {
			if !state.Admitted {
				continue
			}
			for _, priorPerson := range people {
				if membership.LabelsConflict(v.persons[person], v.persons[priorPerson]) {
					return pathError("state_conflict")
				}
			}
			people = append(people, person)
		}
	}
	return nil
}

// storedWriterVerifier verifies complete historical state before evaluating a
// fresh mutation. No scratch facts escape if any dependency fails.
func storedWriterVerifier(ctx CatalogFactContext, catalog []byte) (*activationVerifier, error) {
	if !verificationBudget(true, len(ctx.Network), len(catalog), 0) {
		return nil, pathError("invalid")
	}
	v, err := newCatalogVerifierWithBudget(ctx.Network, ctx.Epoch, ctx.KnownFeatureID, ctx.Now, true)
	if err != nil {
		return nil, err
	}
	if err = v.catalog(catalog); err != nil {
		return nil, err
	}
	if err = v.bootstrap(true); err != nil {
		return nil, err
	}
	requests := []string{}
	for id := range v.activations {
		requests = append(requests, id)
	}
	sort.Strings(requests)
	for _, id := range requests {
		if _, err = v.activate(id, true, 0); err != nil {
			return nil, err
		}
	}
	if err = v.revocations(); err != nil {
		return nil, err
	}
	if err = v.verifyStoredObjects(); err != nil {
		return nil, err
	}
	v.restrictState()
	return v, nil
}

// VerifyStoredCheckpoint enforces authority over every retained item. Parsing
// and a valid signer alone cannot authorize a checkpoint.
func VerifyStoredCheckpoint(ctx CatalogFactContext, catalog, checkpoint []byte) error {
	return verifyStoredCheckpoint(ctx, catalog, checkpoint, true)
}

// VerifyStoredCheckpointIntent checks the fixed unsigned checkpoint shape and
// every retention precondition before a caller asks an owned provider to sign.
// It does not derive a signed identifier or grant authority to publish.
func VerifyStoredCheckpointIntent(ctx CatalogFactContext, catalog, unsigned []byte) error {
	return verifyStoredCheckpoint(ctx, catalog, unsigned, false)
}

func verifyStoredCheckpoint(ctx CatalogFactContext, catalog, checkpoint []byte, signed bool) error {
	v, err := storedWriterVerifier(ctx, catalog)
	if err != nil {
		return err
	}
	o, err := parse(checkpoint)
	if err != nil || scalar(o, "network_id") != v.net {
		return pathError("invalid")
	}
	person, issuer := scalar(o, "person_public_key"), scalar(o, "issuer_certificate_id")
	id := "-"
	if signed {
		id = proofID("checkpoint", checkpoint)
	}
	return v.checkpointWithSignature(catalogProof{"checkpoint", checkpoint, o}, id, person, issuer, 0, signed)
}

type RedemptionEvidence struct {
	Mode, PersonAction, HostPublicKey, PersonPublicKey string
	HostInvitePublicKey, PersonInvitePublicKey         string
}

// VerifyStoredFreshRedemption checks live first-use eligibility without adding
// admission or consuming either invitation. Durable single-use is the caller's
// transaction responsibility.
func VerifyStoredFreshRedemption(ctx CatalogFactContext, catalog, body []byte) (RedemptionEvidence, error) {
	fail := func(err error) (RedemptionEvidence, error) { return RedemptionEvidence{}, err }
	v, err := storedWriterVerifier(ctx, catalog)
	if err != nil {
		return fail(err)
	}
	o, err := parse(body)
	if err != nil {
		return fail(pathError("invalid"))
	}
	r, err := v.readRedemption(catalogProof{"invite_redemption", body, o})
	if err != nil {
		return fail(err)
	}
	joined, _ := stamp(scalar(o, "joined_at"))
	if ctx.Now.Before(joined) {
		return fail(pathError("invalid"))
	}
	out := RedemptionEvidence{Mode: scalar(o, "mode"), PersonAction: scalar(o, "person_action"), HostPublicKey: scalar(o, "host_public_key"), PersonPublicKey: scalar(o, "person_public_key"), HostInvitePublicKey: "-", PersonInvitePublicKey: "-"}
	if out.Mode != "person" && (v.state.Hosts[out.HostPublicKey] || v.history.hosts[out.HostPublicKey]) {
		return fail(pathError("state_conflict"))
	}
	if out.PersonAction == "admit" && (v.state.Persons[out.PersonPublicKey].Admitted || v.history.persons[out.PersonPublicKey]) {
		return fail(pathError("state_conflict"))
	}
	if out.PersonAction == "admit" {
		for person, label := range v.persons {
			if person != out.PersonPublicKey && v.state.Persons[person].Admitted && membership.LabelsConflict(label, r.halves[0].label) {
				return fail(pathError("state_conflict"))
			}
		}
	}
	if out.PersonAction == "skip" && (!v.state.Persons[out.PersonPublicKey].Admitted || len(r.halves) != 1 || v.persons[out.PersonPublicKey] != r.halves[0].label) {
		return fail(pathError("forbidden"))
	}
	for _, h := range r.halves {
		if v.history.invites[h.key] {
			return fail(pathError("forbidden"))
		}
		until, _ := legacyStamp(h.expires)
		if !ctx.Now.Before(until) {
			return fail(pathError("expired"))
		}
		part, kind := "person_invite", "peerspan-person-invite-v1"
		if h.host {
			part, kind = "host_invite", "peerspan-invite-v1"
			out.HostInvitePublicKey = h.key
		} else {
			out.PersonInvitePublicKey = h.key
		}
		invite, _ := parse(o[part])
		if !h.legacy {
			if _, err = VerifyStoredActionAuthority(ActionContext{Network: ctx.Network, Epoch: ctx.Epoch, KnownFeatureID: ctx.KnownFeatureID, PersonPublicKey: h.person, CertificateID: h.cert, Now: ctx.Now}, "person_record", catalog, o[part]); err != nil {
				return fail(err)
			}
			continue
		}
		parts := []string{kind, v.net}
		if !h.host {
			epoch, e := num(invite, "invite_epoch")
			if e != nil || epoch != v.epoch {
				return fail(pathError("invalid"))
			}
			parts = append(parts, strconv.FormatUint(epoch, 10))
		}
		parts = append(parts, h.key, h.label, h.expires)
		m, sig := message(parts...), scalar(invite, "signature")
		if rootSignature(v.root, m, sig) == nil {
			continue
		}
		pub, ok := membership.SSHSIGKey(sig)
		if !ok {
			return fail(pathError("invalid"))
		}
		person := membership.EncodeKey(pub)
		_, withdrawn := v.history.withdrawals[person]
		if !v.state.Persons[person].Admitted || !v.state.Persons[person].Administrator || withdrawn {
			return fail(pathError("forbidden"))
		}
		if personSignature(person, m, sig) != nil {
			return fail(pathError("invalid"))
		}
	}
	return out, nil
}

// VerifyStoredFreshLegacyJoin authorizes a new post-upgrade registration from
// the existing legacy public grant shapes, independently of reachability rows.
func VerifyStoredFreshLegacyJoin(ctx CatalogFactContext, catalog []byte, kind string, body []byte) (string, string, error) {
	bad := func(code string) (string, string, error) { return "", "", pathError(code) }
	v, err := storedWriterVerifier(ctx, catalog)
	if err != nil {
		return "", "", err
	}
	o, err := parse(body)
	if err != nil || scalar(o, "network_id") != v.net {
		return bad("invalid")
	}
	host, invite := scalar(o, "host_public_key"), "-"
	if !key(host) || v.history.hosts[host] {
		return bad("forbidden")
	}
	var m []byte
	var sig string
	switch kind {
	case "host_membership":
		valid, e := v.legacyMembership(catalogProof{kind, body, o}, false)
		if e != nil {
			return "", "", e
		}
		if !valid {
			return bad("forbidden")
		}
		invite = scalar(o, "invite_public_key")
		joined, e := legacyStamp(scalar(o, "joined_at"))
		if e != nil || ctx.Now.Before(joined) {
			return bad("invalid")
		}
		until, e := legacyStamp(scalar(o, "invite_expires_at"))
		if e != nil {
			return bad("invalid")
		}
		if !ctx.Now.Before(until) {
			return bad("expired")
		}
		if v.history.invites[invite] {
			return bad("forbidden")
		}
		m = message("peerspan-invite-v1", v.net, invite, scalar(o, "member"), scalar(o, "invite_expires_at"))
		sig = scalar(o, "invite_signature")
	case "host_admission":
		if fields(o, "network_id epoch host_public_key member admitted_at signature") != nil || !epochIs(o, v.epoch) || !membership.ValidLabel(scalar(o, "member")) {
			return bad("invalid")
		}
		at, e := legacyStamp(scalar(o, "admitted_at"))
		if e != nil || ctx.Now.Before(at) {
			return bad("invalid")
		}
		m = message("peerspan-host-admit-v1", v.net, strconv.FormatUint(v.epoch, 10), host, scalar(o, "member"), scalar(o, "admitted_at"))
		sig = scalar(o, "signature")
	default:
		return bad("invalid")
	}
	if rootSignature(v.root, m, sig) == nil {
		return host, invite, nil
	}
	pub, ok := membership.SSHSIGKey(sig)
	if !ok {
		return bad("invalid")
	}
	person := membership.EncodeKey(pub)
	_, withdrawn := v.history.withdrawals[person]
	if !v.state.Persons[person].Admitted || !v.state.Persons[person].Administrator || withdrawn || personSignature(person, m, sig) != nil {
		return bad("forbidden")
	}
	return host, invite, nil
}
