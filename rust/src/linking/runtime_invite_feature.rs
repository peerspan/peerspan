//! An explicit issuer signature binds invitation consent to one durable feature.
use super::*;
pub struct InviteFeatureEvidence {
    pub feature_id: String,
    pub issuer_kind: String,
    pub person_public_key: String,
    pub certificate_id: String,
    pub signer_public_key: String,
    pub issued_at: String,
    pub expires_at: String,
    pub not_after: String,
    pub epoch: u64,
    pub message: Vec<u8>,
}
const FIELDS: &str = "format network_id network_name genesis_root_public_key epoch feature_id coordinator_address coordinator_public_key mode host_invite_sha256 person_invite_sha256 issuer_kind person_public_key certificate_id signer_public_key issued_at expires_at";
pub fn verify_stored_invite_feature(
    ctx: CatalogFactContext<'_>,
    catalog: &[u8],
    binding: &[u8],
    host_invite: &[u8],
    person_invite: &[u8],
) -> Result<InviteFeatureEvidence> {
    verify(ctx, catalog, binding, host_invite, person_invite, true)
}
pub fn verify_stored_invite_feature_intent(
    ctx: CatalogFactContext<'_>,
    catalog: &[u8],
    unsigned: &[u8],
) -> Result<InviteFeatureEvidence> {
    check(ctx.known_feature_id != "-", "upgrade_required")?;
    verify(ctx, catalog, unsigned, &[], &[], false)
}
fn verify(
    ctx: CatalogFactContext<'_>,
    catalog: &[u8],
    binding: &[u8],
    host: &[u8],
    person_half: &[u8],
    signed_body: bool,
) -> Result<InviteFeatureEvidence> {
    let run = || -> Result<InviteFeatureEvidence> {
        check(
            verification_budget(true, ctx.network.len(), catalog.len(), binding.len())
                && host.len() <= MAX_OBJECT
                && person_half.len() <= MAX_OBJECT,
            "invalid",
        )?;
        let o = obj(binding)?;
        let required = format!(
            "{FIELDS} {}",
            if signed_body {
                "signature"
            } else {
                "host_invite_base64 person_invite_base64"
            }
        );
        fields(&o, &required, &[])?;
        version(&o, 1)?;
        let (host_invite, person_invite) = if signed_body {
            (host.to_vec(), person_half.to_vec())
        } else {
            let half = |name: &str| -> Result<Vec<u8>> {
                let encoded = text(&o, name)?;
                if encoded == "-" {
                    Ok(Vec::new())
                } else {
                    decode(encoded, MAX_OBJECT)
                }
            };
            (half("host_invite_base64")?, half("person_invite_base64")?)
        };
        let mut v = Verifier::new(ctx.network, ctx.epoch, ctx.known_feature_id, ctx.now)?;
        v.stored_snapshot = true;
        v.catalog(catalog)?;
        v.load_roots()?;
        for (field, descriptor) in [
            ("network_id", "network_id"),
            ("network_name", "name"),
            ("genesis_root_public_key", "genesis_root_public_key"),
            ("coordinator_address", "coordinator_address"),
            ("coordinator_public_key", "coordinator_public_key"),
        ] {
            check(text(&o, field)? == text(&v.network, descriptor)?, "invalid")?;
        }
        let epoch = num(&o, "epoch")?;
        check(epoch == v.epoch, "invalid")?;
        let feature = text(&o, "feature_id")?;
        check(ident(feature, "lf_"), "invalid")?;
        check(
            ctx.known_feature_id == "-" || ctx.known_feature_id == feature,
            "state_conflict",
        )?;
        let mode = text(&o, "mode")?;
        check(
            matches!(mode, "host" | "person" | "member")
                && (!host_invite.is_empty()) == (mode != "person")
                && (!person_invite.is_empty()) == (mode != "host"),
            "invalid",
        )?;
        for (name, raw) in [
            ("host_invite_sha256", &host_invite),
            ("person_invite_sha256", &person_invite),
        ] {
            let expected = if raw.is_empty() {
                "-".into()
            } else {
                hash(raw)
            };
            check(text(&o, name)? == expected, "invalid")?;
        }
        let issued = stamp(text(&o, "issued_at")?)?;
        let expires = stamp(text(&o, "expires_at")?)?;
        check(
            expires > issued && expires - issued <= chrono::Duration::days(30) && ctx.now >= issued,
            "invalid",
        )?;
        check(ctx.now < expires, "expired")?;
        let issuer = text(&o, "issuer_kind")?;
        let person = text(&o, "person_public_key")?;
        let cert = text(&o, "certificate_id")?;
        let signer = text(&o, "signer_public_key")?;
        check(key(signer), "invalid")?;
        match issuer {
            "network_root" => check(person == "-" && cert == "-" && signer == v.root, "invalid")?,
            "person" => check(
                key(person) && (cert == "root" || ident(cert, "dc_")),
                "invalid",
            )?,
            _ => return Err(problem("invalid")),
        };
        let message = lines(&[
            "peerspan-link-invite-feature-v1",
            &v.net,
            text(&o, "network_name")?,
            text(&o, "genesis_root_public_key")?,
            &epoch.to_string(),
            feature,
            text(&o, "coordinator_address")?,
            text(&o, "coordinator_public_key")?,
            mode,
            text(&o, "host_invite_sha256")?,
            text(&o, "person_invite_sha256")?,
            issuer,
            person,
            cert,
            signer,
            text(&o, "issued_at")?,
            text(&o, "expires_at")?,
        ]);
        if signed_body {
            let verify = if issuer == "network_root" { root } else { ssh };
            verify(signer, &message, text(&o, "signature")?).map_err(|_| problem("invalid"))?;
        }
        // This exact signature, or an issuer's durable pin for an intent, is
        // checked before using the selected feature to verify complete state.
        let mut v = runtime_write::stored_writer_verifier(
            &CatalogFactContext {
                network: ctx.network,
                epoch,
                known_feature_id: feature,
                now: ctx.now,
            },
            catalog,
        )?;
        let not_after = if issuer == "person" {
            let path = v.authority(person, cert, 8, 0)?;
            check(path.signer_public_key == signer, "forbidden")?;
            if path.not_after != "-" {
                check(expires <= stamp(&path.not_after)?, "forbidden")?;
            }
            path.not_after
        } else {
            "-".into()
        };
        let mut first: Option<redemptions::InviteHalf> = None;
        for (raw, host) in [(&host_invite, true), (&person_invite, false)] {
            if raw.is_empty() {
                continue;
            }
            let grant: Value = serde_json::from_slice(raw)?;
            let h = v.read_invite(&grant, host)?;
            check(legacy_stamp(&h.expires)? == expires, "invalid")?;
            check(!v.invite_revoked(&h.key), "forbidden")?;
            if let Some(old) = &first {
                check(
                    old.key == h.key && old.label == h.label && old.expires == h.expires,
                    "invalid",
                )?;
            }
            if !h.legacy {
                check(
                    issuer == "person" && h.person == person && h.cert == cert && h.epoch == epoch,
                    "forbidden",
                )?;
                verify_stored_action_authority(
                    ActionContext {
                        network: ctx.network,
                        epoch,
                        known_feature_id: feature,
                        person_public_key: person,
                        certificate_id: cert,
                        now: ctx.now,
                    },
                    "person_record",
                    catalog,
                    raw,
                )?;
            } else {
                check(
                    !(issuer == "person" && cert != "root") && (host || h.epoch == epoch),
                    "forbidden",
                )?;
                let mut parts = if host {
                    vec!["peerspan-invite-v1".to_owned(), v.net.clone()]
                } else {
                    vec![
                        "peerspan-person-invite-v1".into(),
                        v.net.clone(),
                        epoch.to_string(),
                    ]
                };
                parts.extend([h.key.clone(), h.label.clone(), h.expires.clone()]);
                let refs: Vec<_> = parts.iter().map(String::as_str).collect();
                let verify = if issuer == "network_root" { root } else { ssh };
                verify(signer, &lines(&refs), text(object(&grant)?, "signature")?)
                    .map_err(|_| problem("forbidden"))?;
            }
            first = Some(h);
        }
        Ok(InviteFeatureEvidence {
            feature_id: feature.into(),
            issuer_kind: issuer.into(),
            person_public_key: person.into(),
            certificate_id: cert.into(),
            signer_public_key: signer.into(),
            issued_at: text(&o, "issued_at")?.into(),
            expires_at: text(&o, "expires_at")?.into(),
            not_after,
            epoch,
            message,
        })
    };
    run().map_err(|e| {
        if e.downcast_ref::<PathError>().is_some() {
            e
        } else {
            problem("invalid")
        }
    })
}

pub(super) fn probe(o: &Obj, stored: bool) -> Value {
    let run = || -> Result<Value> {
        let signed = text(o, "kind")? == "invite_feature";
        fields(
            o,
            if signed {
                "kind network_base64 catalog_base64 binding_base64 host_invite_base64 person_invite_base64 epoch known_feature_id now"
            } else {
                "kind network_base64 catalog_base64 unsigned_base64 epoch known_feature_id now"
            },
            &[],
        )?;
        let network = decode(text(o, "network_base64")?, MAX_ACTIVATION)?;
        let catalog = decode(
            text(o, "catalog_base64")?,
            if stored {
                MAX_STORED_CATALOG
            } else {
                MAX_ACTIVATION
            },
        )?;
        let body = decode(
            text(
                o,
                if signed {
                    "binding_base64"
                } else {
                    "unsigned_base64"
                },
            )?,
            MAX_OBJECT,
        )?;
        let mut halves = [Vec::new(), Vec::new()];
        if signed {
            for (i, name) in ["host_invite_base64", "person_invite_base64"]
                .iter()
                .enumerate()
            {
                let value = text(o, name)?;
                if value != "-" {
                    halves[i] = decode(value, MAX_OBJECT)?;
                }
            }
        }
        check(
            stored
                || network.len() + catalog.len() + body.len() + halves[0].len() + halves[1].len()
                    <= MAX_ACTIVATION,
            "invalid",
        )?;
        let ctx = CatalogFactContext {
            network: &network,
            epoch: num(o, "epoch")?,
            known_feature_id: text(o, "known_feature_id")?,
            now: stamp(text(o, "now")?)?,
        };
        let e = if signed {
            verify_stored_invite_feature(ctx, &catalog, &body, &halves[0], &halves[1])?
        } else {
            verify_stored_invite_feature_intent(ctx, &catalog, &body)?
        };
        Ok(
            json!({"ok":true,"feature_id":e.feature_id,"epoch":e.epoch,"issuer_kind":e.issuer_kind,"person_public_key":e.person_public_key,"certificate_id":e.certificate_id,"signer_public_key":e.signer_public_key,"issued_at":e.issued_at,"expires_at":e.expires_at,"not_after":e.not_after,"message_base64":STANDARD.encode(e.message)}),
        )
    };
    run().unwrap_or_else(|e| {
        let p = e.downcast_ref::<PathError>();
        let code = p.map_or("invalid", |e| e.code);
        if code == "proof_required" {
            json!({"ok":false,"code":code,"required_ids":p.expect("known").required_ids})
        } else {
            json!({"ok":false,"code":code})
        }
    })
}
