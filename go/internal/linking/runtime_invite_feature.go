package linking

import (
	"encoding/base64"
	"errors"
	"strconv"
	"time"
)

// InviteFeatureEvidence describes a checked fixed invitation binding. Intent
// verification provides no signature, admission or published authority.
type InviteFeatureEvidence struct {
	FeatureID, IssuerKind, PersonPublicKey, CertificateID string
	SignerPublicKey, IssuedAt, ExpiresAt, NotAfter        string
	Epoch                                                 uint64
	Message                                               []byte
}

func inviteFeatureProbe(o Object, stored bool) any {
	fail := func(err error) any {
		out := map[string]any{"ok": false, "code": "invalid"}
		var p *PathError
		if errors.As(err, &p) {
			out["code"] = p.Code
			if p.Code == "proof_required" {
				out["required_ids"] = p.RequiredIDs
			}
		}
		return out
	}
	signed := scalar(o, "kind") == "invite_feature"
	required := "kind network_base64 catalog_base64 unsigned_base64 epoch known_feature_id now"
	if signed {
		required = "kind network_base64 catalog_base64 binding_base64 host_invite_base64 person_invite_base64 epoch known_feature_id now"
	}
	if fields(o, required) != nil {
		return fail(pathError("invalid"))
	}
	decoded := map[string][]byte{}
	total := 0
	for _, name := range []string{"network_base64", "catalog_base64", "binding_base64", "host_invite_base64", "person_invite_base64", "unsigned_base64"} {
		if _, ok := o[name]; !ok {
			continue
		}
		encoded, err := text(o, name)
		if err != nil {
			return fail(pathError("invalid"))
		}
		if (name == "host_invite_base64" || name == "person_invite_base64") && encoded == "-" {
			continue
		}
		limit := MaxObject
		if name == "catalog_base64" {
			limit = catalogProbeLimit(name, stored)
		}
		raw, err := decode(encoded, limit)
		if err != nil || len(raw) == 0 {
			return fail(pathError("invalid"))
		}
		decoded[name] = raw
		total += len(raw)
	}
	if !stored && total > MaxActivation {
		return fail(pathError("invalid"))
	}
	epoch, err := num(o, "epoch")
	if err != nil {
		return fail(pathError("invalid"))
	}
	now, err := stamp(scalar(o, "now"))
	if err != nil {
		return fail(pathError("invalid"))
	}
	ctx := CatalogFactContext{Network: decoded["network_base64"], Epoch: epoch, KnownFeatureID: scalar(o, "known_feature_id"), Now: now}
	var evidence InviteFeatureEvidence
	if signed {
		evidence, err = VerifyStoredInviteFeature(ctx, decoded["catalog_base64"], decoded["binding_base64"], decoded["host_invite_base64"], decoded["person_invite_base64"])
	} else {
		evidence, err = VerifyStoredInviteFeatureIntent(ctx, decoded["catalog_base64"], decoded["unsigned_base64"])
	}
	if err != nil {
		return fail(err)
	}
	return map[string]any{"ok": true, "feature_id": evidence.FeatureID, "epoch": evidence.Epoch, "issuer_kind": evidence.IssuerKind, "person_public_key": evidence.PersonPublicKey, "certificate_id": evidence.CertificateID, "signer_public_key": evidence.SignerPublicKey, "issued_at": evidence.IssuedAt, "expires_at": evidence.ExpiresAt, "not_after": evidence.NotAfter, "message_base64": base64.StdEncoding.EncodeToString(evidence.Message)}
}

const inviteFeatureFields = "format network_id network_name genesis_root_public_key epoch feature_id coordinator_address coordinator_public_key mode host_invite_sha256 person_invite_sha256 issuer_kind person_public_key certificate_id signer_public_key issued_at expires_at"

// VerifyStoredInviteFeature checks an explicit signed feature choice before
// cold feature adoption, then checks the full catalog and current grant issuer.
// An absent public half is nil. Private token/seed consistency and atomic invite
// consumption remain the caller's separate responsibilities.
func VerifyStoredInviteFeature(ctx CatalogFactContext, catalog, binding, hostInvite, personInvite []byte) (InviteFeatureEvidence, error) {
	return verifyStoredInviteFeature(ctx, catalog, binding, hostInvite, personInvite, true)
}

// VerifyStoredInviteFeatureIntent validates only the fixed typed preconditions
// for an already feature-pinned issuer before a private provider signs anything.
func VerifyStoredInviteFeatureIntent(ctx CatalogFactContext, catalog, unsigned []byte) (InviteFeatureEvidence, error) {
	if ctx.KnownFeatureID == "-" {
		return InviteFeatureEvidence{}, pathError("upgrade_required")
	}
	return verifyStoredInviteFeature(ctx, catalog, unsigned, nil, nil, false)
}

func verifyStoredInviteFeature(ctx CatalogFactContext, catalog, binding, hostInvite, personInvite []byte, signed bool) (InviteFeatureEvidence, error) {
	fail := func(err error) (InviteFeatureEvidence, error) { return InviteFeatureEvidence{}, err }
	if !verificationBudget(true, len(ctx.Network), len(catalog), len(binding)) || len(hostInvite) > MaxObject || len(personInvite) > MaxObject {
		return fail(pathError("invalid"))
	}
	o, err := parse(binding)
	required := inviteFeatureFields + " host_invite_base64 person_invite_base64"
	if signed {
		required = inviteFeatureFields + " signature"
	}
	if err != nil || fields(o, required) != nil || version(o, 1) != nil {
		return fail(pathError("invalid"))
	}
	if !signed {
		for name, target := range map[string]*[]byte{"host_invite_base64": &hostInvite, "person_invite_base64": &personInvite} {
			encoded, e := text(o, name)
			if e != nil {
				return fail(pathError("invalid"))
			}
			if encoded != "-" {
				*target, e = decode(encoded, MaxObject)
				if e != nil {
					return fail(pathError("invalid"))
				}
			}
		}
	}
	v, err := newCatalogVerifierWithBudget(ctx.Network, ctx.Epoch, ctx.KnownFeatureID, ctx.Now, true)
	if err != nil {
		return fail(err)
	}
	if err = v.catalog(catalog); err != nil {
		return fail(err)
	}
	if err = v.loadRoots(); err != nil {
		return fail(err)
	}
	for field, descriptor := range map[string]string{"network_id": "network_id", "network_name": "name", "genesis_root_public_key": "genesis_root_public_key", "coordinator_address": "coordinator_address", "coordinator_public_key": "coordinator_public_key"} {
		if scalar(o, field) != scalar(v.network, descriptor) {
			return fail(pathError("invalid"))
		}
	}
	epoch, err := num(o, "epoch")
	if err != nil || epoch != v.epoch {
		return fail(pathError("invalid"))
	}
	feature := scalar(o, "feature_id")
	if !identifier(feature, "lf_") {
		return fail(pathError("invalid"))
	}
	if ctx.KnownFeatureID != "-" && ctx.KnownFeatureID != feature {
		return fail(pathError("state_conflict"))
	}
	mode := scalar(o, "mode")
	if mode != "host" && mode != "person" && mode != "member" || (len(hostInvite) != 0) != (mode != "person") || (len(personInvite) != 0) != (mode != "host") {
		return fail(pathError("invalid"))
	}
	for name, raw := range map[string][]byte{"host_invite_sha256": hostInvite, "person_invite_sha256": personInvite} {
		want := "-"
		if len(raw) != 0 {
			want = digest(raw)
		}
		if scalar(o, name) != want {
			return fail(pathError("invalid"))
		}
	}
	issued, err := stamp(scalar(o, "issued_at"))
	if err != nil {
		return fail(pathError("invalid"))
	}
	expires, err := stamp(scalar(o, "expires_at"))
	if err != nil || !expires.After(issued) || expires.Sub(issued) > 30*24*time.Hour || ctx.Now.Before(issued) {
		return fail(pathError("invalid"))
	}
	if !ctx.Now.Before(expires) {
		return fail(pathError("expired"))
	}
	issuer, person, certificate, signer := scalar(o, "issuer_kind"), scalar(o, "person_public_key"), scalar(o, "certificate_id"), scalar(o, "signer_public_key")
	if !key(signer) {
		return fail(pathError("invalid"))
	}
	switch issuer {
	case "network_root":
		if person != "-" || certificate != "-" || signer != v.root {
			return fail(pathError("invalid"))
		}
	case "person":
		if !key(person) || certificate != "root" && !identifier(certificate, "dc_") {
			return fail(pathError("invalid"))
		}
	default:
		return fail(pathError("invalid"))
	}
	parts := []string{"peerspan-link-invite-feature-v1", v.net, scalar(o, "network_name"), scalar(o, "genesis_root_public_key"), strconv.FormatUint(epoch, 10), feature, scalar(o, "coordinator_address"), scalar(o, "coordinator_public_key"), mode, scalar(o, "host_invite_sha256"), scalar(o, "person_invite_sha256"), issuer, person, certificate, signer, scalar(o, "issued_at"), scalar(o, "expires_at")}
	m := message(parts...)
	if signed {
		signature, e := text(o, "signature")
		if e != nil {
			return fail(pathError("invalid"))
		}
		verify := personSignature
		if issuer == "network_root" {
			verify = rootSignature
		}
		if verify(signer, m, signature) != nil {
			return fail(pathError("invalid"))
		}
	}
	// Only the explicit signed choice (or the issuer's independently durable
	// choice for an intent) supplies this feature pin. A candidate catalog does
	// not promote its own feature into previously known authority.
	ctx.KnownFeatureID = feature
	v, err = storedWriterVerifier(ctx, catalog)
	if err != nil {
		return fail(err)
	}
	notAfter := "-"
	if issuer == "person" {
		path, e := v.authority(person, certificate, 8, 0)
		if e != nil {
			return fail(e)
		}
		if path.SignerPublicKey != signer {
			return fail(pathError("forbidden"))
		}
		notAfter = path.NotAfter
		if notAfter != "-" {
			limit, _ := stamp(notAfter)
			if expires.After(limit) {
				return fail(pathError("forbidden"))
			}
		}
	}
	var first *inviteHalf
	for _, half := range []struct {
		raw  []byte
		host bool
	}{{hostInvite, true}, {personInvite, false}} {
		if len(half.raw) == 0 {
			continue
		}
		h, e := v.readInvite(half.raw, half.host)
		if e != nil {
			return fail(e)
		}
		until, _ := legacyStamp(h.expires)
		if !until.Equal(expires) {
			return fail(pathError("invalid"))
		}
		if v.history.invites[h.key] {
			return fail(pathError("forbidden"))
		}
		if first != nil && (first.key != h.key || first.label != h.label || first.expires != h.expires) {
			return fail(pathError("invalid"))
		}
		copy := h
		first = &copy
		if !h.legacy {
			if issuer != "person" || h.person != person || h.cert != certificate || h.epoch != epoch {
				return fail(pathError("forbidden"))
			}
			if _, e = VerifyStoredActionAuthority(ActionContext{Network: ctx.Network, Epoch: epoch, KnownFeatureID: feature, PersonPublicKey: person, CertificateID: certificate, Now: ctx.Now}, "person_record", catalog, half.raw); e != nil {
				return fail(e)
			}
			continue
		}
		if issuer == "person" && certificate != "root" || !half.host && h.epoch != epoch {
			return fail(pathError("forbidden"))
		}
		grant, _ := parse(half.raw)
		domain := "peerspan-invite-v1"
		grantParts := []string{domain, v.net}
		if !half.host {
			grantParts = []string{"peerspan-person-invite-v1", v.net, strconv.FormatUint(epoch, 10)}
		}
		grantParts = append(grantParts, h.key, h.label, h.expires)
		verify := personSignature
		if issuer == "network_root" {
			verify = rootSignature
		}
		if verify(signer, message(grantParts...), scalar(grant, "signature")) != nil {
			return fail(pathError("forbidden"))
		}
	}
	return InviteFeatureEvidence{FeatureID: feature, IssuerKind: issuer, PersonPublicKey: person, CertificateID: certificate, SignerPublicKey: signer, IssuedAt: scalar(o, "issued_at"), ExpiresAt: scalar(o, "expires_at"), NotAfter: notAfter, Epoch: epoch, Message: m}, nil
}
