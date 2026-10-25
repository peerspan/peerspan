//! Exact eligible grant tags for a reviewed administrator withdrawal.
use super::*;
pub fn build_stored_admin_removal_plan(
    ctx: CatalogFactContext<'_>,
    catalog: &[u8],
    person: &str,
) -> Result<Vec<String>> {
    let run = || -> Result<Vec<String>> {
        check(key(person), "invalid")?;
        check(ctx.known_feature_id != "-", "upgrade_required")?;
        let mut v = runtime_write::stored_writer_verifier(&ctx, catalog)?;
        check(v.access_admin_known(person), "proof_required")?;
        let access = verify_stored_access_state(
            AccessContext {
                network: ctx.network,
                epoch: ctx.epoch,
                known_feature_id: ctx.known_feature_id,
                now: ctx.now,
                prior_policies: &[],
                prior_groups: &[],
            },
            catalog,
        )?;
        let groups: BTreeSet<_> = access
            .groups
            .iter()
            .filter(|g| g.selection.active)
            .flat_map(|g| [g.selection.proof_id.clone(), g.selection.record_id.clone()])
            .collect();
        let mut kept = BTreeSet::new();
        let proofs: Vec<_> = v
            .proofs
            .iter()
            .map(|(id, p)| (id.clone(), p.clone()))
            .collect();
        for (id, p) in proofs {
            let o = &p.object;
            if p.kind == "invite_redemption" {
                let r = v.read_redemption(&p)?;
                let mut eligible = (s(o, "mode") == "person"
                    || v.state
                        .hosts
                        .get(s(o, "host_public_key"))
                        .copied()
                        .unwrap_or(false))
                    && (s(o, "person_action") != "admit"
                        || v.state
                            .persons
                            .get(s(o, "person_public_key"))
                            .is_some_and(|p| p.admitted));
                let mut issued = false;
                for h in &r.halves {
                    if h.person != person {
                        eligible = false;
                        continue;
                    }
                    issued = true;
                    eligible &= v.redemption_half(&id, h)?;
                }
                if eligible && issued {
                    kept.insert(format!("redemption:{id}"));
                    for h in &r.halves {
                        if !h.legacy {
                            kept.insert(format!("record:{}", h.record));
                            continue;
                        }
                        let part = if h.host {
                            "host_invite"
                        } else {
                            "person_invite"
                        };
                        let half = object(o.get(part).ok_or_else(|| problem("invalid"))?)?;
                        let mut parts = vec![
                            if h.host {
                                "peerspan-invite-v1"
                            } else {
                                "peerspan-person-invite-v1"
                            }
                            .to_owned(),
                            v.net.clone(),
                        ];
                        if !h.host {
                            parts.push(h.epoch.to_string());
                        }
                        parts.extend([h.key.clone(), h.label.clone(), h.expires.clone()]);
                        add_legacy(
                            &v,
                            person,
                            &lines(&parts.iter().map(String::as_str).collect::<Vec<_>>()),
                            text(half, "signature")?,
                            &mut kept,
                        )?;
                    }
                }
                continue;
            }
            if let Some((message, sig)) = legacy_message(&v, &p, groups.contains(&id))? {
                add_legacy(&v, person, &message, &sig, &mut kept)?;
            }
        }
        let evidence: Vec<_> = v
            .evidence
            .iter()
            .map(|(id, p)| (id.clone(), p.clone()))
            .collect();
        for (id, p) in evidence {
            let o = &p.object;
            if p.kind != "person_record"
                || s(o, "person_public_key") != person
                || v.inline_invites.contains(&id)
            {
                continue;
            }
            let kind = s(o, "kind");
            if kind == "peerspan-group-v1" {
                if groups.contains(&id) {
                    kept.insert(format!("record:{id}"));
                }
                continue;
            }
            if records::ordinary_scope(kind) != 8 {
                continue;
            }
            let (_, _, scope) = v.retention_subject(&id)?;
            if let Err(e) = v.historical_record(
                &SignedObject {
                    message: Vec::new(),
                    id: id.clone(),
                    payload: None,
                },
                o,
                scope,
                0,
            ) {
                if e.downcast_ref::<PathError>().is_some_and(|p| {
                    matches!(p.code, "forbidden" | "authority_expired" | "device_revoked")
                }) {
                    continue;
                }
                return Err(e);
            }
            let (_, payload) = p_obj(o)?;
            if kind == "peerspan-host-admit-v1"
                && !v
                    .state
                    .hosts
                    .get(s(&payload, "host_public_key"))
                    .copied()
                    .unwrap_or(false)
            {
                continue;
            }
            if kind == "peerspan-person-admit-v1"
                && !v
                    .state
                    .persons
                    .get(s(&payload, "person_public_key"))
                    .is_some_and(|p| p.admitted)
            {
                continue;
            }
            kept.insert(format!("record:{id}"));
        }
        Ok(kept.into_iter().collect())
    };
    run().map_err(|e| {
        if e.downcast_ref::<PathError>().is_some() {
            e
        } else {
            problem("invalid")
        }
    })
}
fn add_legacy(
    v: &Verifier<'_>,
    person: &str,
    message: &[u8],
    sig: &str,
    kept: &mut BTreeSet<String>,
) -> Result<()> {
    if v.any_root_signature(message, sig)
        || crate::persons::sshsig_signer(sig).as_deref() != Some(person)
    {
        return Ok(());
    }
    if v.legacy_authority(message, sig)? {
        kept.insert(format!("legacy:{}", hash(message)));
    }
    Ok(())
}
fn legacy_message(v: &Verifier<'_>, p: &Proof, group: bool) -> Result<Option<(Vec<u8>, String)>> {
    let o = &p.object;
    let mut sig = s(o, "signature").to_owned();
    let mut parts = Vec::<String>::new();
    match p.kind.as_str() {
        "host_admission" | "person_admission" => {
            let person = p.kind == "person_admission";
            let field = if person {
                "person_public_key"
            } else {
                "host_public_key"
            };
            if if person {
                !v.state.persons.get(s(o, field)).is_some_and(|p| p.admitted)
            } else {
                !v.state.hosts.get(s(o, field)).copied().unwrap_or(false)
            } {
                return Ok(None);
            }
            parts.extend([
                if person {
                    "peerspan-person-admit-v1"
                } else {
                    "peerspan-host-admit-v1"
                }
                .into(),
                v.net.clone(),
                num(o, "epoch")?.to_string(),
                s(o, field).into(),
                s(o, "member").into(),
                s(o, "admitted_at").into(),
            ]);
        }
        "host_membership" | "person_membership" => {
            let person = p.kind == "person_membership";
            if if person {
                !v.state
                    .persons
                    .get(s(o, "person_public_key"))
                    .is_some_and(|p| p.admitted)
            } else {
                !v.state
                    .hosts
                    .get(s(o, "host_public_key"))
                    .copied()
                    .unwrap_or(false)
            } {
                return Ok(None);
            }
            if !v.legacy_membership(p, person)? {
                return Ok(None);
            }
            sig = s(o, "invite_signature").into();
            parts.extend([
                if person {
                    "peerspan-person-invite-v1"
                } else {
                    "peerspan-invite-v1"
                }
                .into(),
                v.net.clone(),
            ]);
            if person {
                parts.push(num(o, "invite_epoch")?.to_string());
            }
            parts.extend([
                s(o, "invite_public_key").into(),
                s(o, "member").into(),
                s(o, "invite_expires_at").into(),
            ]);
        }
        "group" => {
            if !group {
                return Ok(None);
            }
            parts.extend([
                "peerspan-group-v1".into(),
                v.net.clone(),
                s(o, "name").into(),
                num(o, "version")?.to_string(),
                s(o, "defined_at").into(),
            ]);
            parts.extend(string_list(o, "members")?.into_iter().map(str::to_owned));
        }
        "person_removal" => parts.extend([
            "peerspan-person-remove-v1".into(),
            v.net.clone(),
            s(o, "person_public_key").into(),
            s(o, "removed_at").into(),
        ]),
        "host_revocation" => parts.extend([
            "peerspan-revoke-host-v1".into(),
            v.net.clone(),
            s(o, "host_public_key").into(),
            s(o, "revoked_at").into(),
        ]),
        "invite_revocation" => parts.extend([
            "peerspan-revoke-invite-v1".into(),
            v.net.clone(),
            s(o, "invite_public_key").into(),
            s(o, "revoked_at").into(),
        ]),
        _ => return Ok(None),
    }
    Ok(Some((
        lines(&parts.iter().map(String::as_str).collect::<Vec<_>>()),
        sig,
    )))
}
pub(super) fn probe(o: &Obj) -> Value {
    let run = || -> Result<Value> {
        fields(
            o,
            "kind network_base64 catalog_base64 epoch known_feature_id now person_public_key",
            &[],
        )?;
        let network = decode(text(o, "network_base64")?, MAX_ACTIVATION)?;
        let catalog = decode(text(o, "catalog_base64")?, MAX_STORED_CATALOG)?;
        let kept = build_stored_admin_removal_plan(
            CatalogFactContext {
                network: &network,
                epoch: num(o, "epoch")?,
                known_feature_id: text(o, "known_feature_id")?,
                now: stamp(text(o, "now")?)?,
            },
            &catalog,
            text(o, "person_public_key")?,
        )?;
        Ok(json!({"ok":true,"kept":kept}))
    };
    run().unwrap_or_else(|e| {
        let p = e.downcast_ref::<PathError>();
        let code = p.map_or("invalid", |p| p.code);
        if code == "proof_required" {
            json!({"ok":false,"code":code,"required_ids":p.expect("known").required_ids})
        } else {
            json!({"ok":false,"code":code})
        }
    })
}
