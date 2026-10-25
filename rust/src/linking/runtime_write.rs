//! Current runtime writer snapshots and exact retention checkpoint validation.
use super::*;

pub(super) fn stored_writer_verifier<'a>(
    ctx: &CatalogFactContext<'a>,
    catalog: &[u8],
) -> Result<Verifier<'a>> {
    check(
        verification_budget(true, ctx.network.len(), catalog.len(), 0),
        "invalid",
    )?;
    let mut v = Verifier::new(ctx.network, ctx.epoch, ctx.known_feature_id, ctx.now)?;
    v.stored_snapshot = true;
    v.catalog(catalog)?;
    v.bootstrap(true)?;
    let requests: Vec<_> = v.activations.keys().cloned().collect();
    for id in requests {
        v.activate(&id, true, 0)?;
    }
    v.revocations()?;
    v.verify_stored_objects()?;
    v.restrict_state();
    Ok(v)
}

pub fn verify_stored_checkpoint(
    ctx: CatalogFactContext<'_>,
    catalog: &[u8],
    checkpoint: &[u8],
) -> Result<()> {
    verify_checkpoint(ctx, catalog, checkpoint, true)
}
pub fn verify_stored_checkpoint_intent(
    ctx: CatalogFactContext<'_>,
    catalog: &[u8],
    unsigned: &[u8],
) -> Result<()> {
    verify_checkpoint(ctx, catalog, unsigned, false)
}
fn verify_checkpoint(
    ctx: CatalogFactContext<'_>,
    catalog: &[u8],
    checkpoint: &[u8],
    signed_body: bool,
) -> Result<()> {
    let run = || -> Result<()> {
        let mut v = stored_writer_verifier(&ctx, catalog)?;
        let object = obj(checkpoint)?;
        check(s(&object, "network_id") == v.net, "invalid")?;
        let person = text(&object, "person_public_key")?.to_owned();
        let p = Proof {
            kind: "checkpoint".into(),
            body: checkpoint.to_vec(),
            object,
        };
        v.checkpoint_with_signature(
            &p,
            &if signed_body {
                proof_id("checkpoint", checkpoint)
            } else {
                "-".into()
            },
            &person,
            0,
            signed_body,
        )
    };
    run().map_err(|e| {
        if e.downcast_ref::<PathError>().is_some() {
            e
        } else {
            problem("invalid")
        }
    })
}

/// Historical replication verifies complete evidence without issuing a fresh grant.
pub fn verify_stored_catalog_repair(
    ctx: CatalogFactContext<'_>,
    prior: &[u8],
    catalog: &[u8],
) -> Result<()> {
    let run = || -> Result<()> {
        check(prior.len() <= MAX_STORED_CATALOG, "invalid")?;
        let old = object(&parse_limit(prior, MAX_STORED_CATALOG)?)?.clone();
        fields(&old, "format network_id objects", &[])?;
        check(num(&old, "format")? == 1, "invalid")?;
        // The caller merges exact prior objects before this historical check.
        // Complete projection validates every retained certificate/checkpoint and
        // operation-bound record, including objects not reached as dependencies.
        verify_stored_network_state(ctx, catalog)?;
        Ok(())
    };
    run().map_err(|e| {
        if e.downcast_ref::<PathError>().is_some() {
            e
        } else {
            problem("invalid")
        }
    })
}

/// Newly issued mutations use current authority; historical dependencies retain
/// their exact signed bodies and confer no fresh writer authority.
pub fn verify_stored_catalog_additions(
    ctx: CatalogFactContext<'_>,
    prior: &[u8],
    catalog: &[u8],
) -> Result<()> {
    let run = || -> Result<()> {
        let mut v = stored_writer_verifier(&ctx, catalog)?;
        let mut old = Verifier::new(ctx.network, ctx.epoch, ctx.known_feature_id, ctx.now)?;
        old.stored_snapshot = true;
        old.catalog(prior)?;
        // Indexing includes exact nested activation records/certificates: these
        // virtual proofs remain prior evidence after a restrictive withdrawal.
        let known: BTreeSet<_> = old.proofs.keys().cloned().collect();
        check(
            known.iter().all(|id| v.proofs.contains_key(id)),
            "proof_required",
        )?;
        let prior_epoch = old
            .proofs
            .values()
            .filter(|p| p.kind == "rotation")
            .map(|p| num(&p.object, "epoch"))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .max()
            .unwrap_or(0);
        let mut renewals = BTreeSet::new();
        if old.proofs.values().any(|p| p.kind == "feature") && ctx.epoch > prior_epoch {
            let previous = verify_stored_network_state(
                CatalogFactContext {
                    network: ctx.network,
                    epoch: prior_epoch,
                    known_feature_id: ctx.known_feature_id,
                    now: ctx.now,
                },
                prior,
            )?;
            for (id, p) in &v.proofs {
                if known.contains(id) || num(&p.object, "epoch").ok() != Some(v.epoch) {
                    continue;
                }
                let person = s(&p.object, "person_public_key");
                let Some(state) = previous
                    .facts
                    .state
                    .persons
                    .get(person)
                    .filter(|state| state.admitted)
                else {
                    continue;
                };
                let message = match p.kind.as_str() {
                    "person_admission" => lines(&[
                        "peerspan-person-admit-v1",
                        &v.net,
                        &v.epoch.to_string(),
                        person,
                        s(&p.object, "member"),
                        s(&p.object, "admitted_at"),
                    ]),
                    "admin_delegation" if state.administrator => lines(&[
                        "peerspan-admin-delegate-v1",
                        &v.net,
                        &v.epoch.to_string(),
                        person,
                        s(&p.object, "delegated_at"),
                    ]),
                    _ => continue,
                };
                if root(&v.root, &message, s(&p.object, "signature")).is_ok() {
                    renewals.insert(id.clone());
                }
            }
        }
        let mut object = object(&parse_limit(catalog, MAX_STORED_CATALOG)?)?.clone();
        let entries = object
            .get("objects")
            .and_then(Value::as_array)
            .ok_or_else(|| problem("invalid"))?
            .clone();
        let before_entries: Vec<_> = entries
            .iter()
            .filter(|entry| {
                let id = entry["id"].as_str().unwrap_or("");
                let Some(p) = v.proofs.get(id) else {
                    return false;
                };
                known.contains(id)
                    || renewals.contains(id)
                    || !(p.kind == "device_revocation"
                        || p.kind == "person_record" && s(&p.object, "operation_id") == "-"
                        || runtime_legacy::mutation(&p.kind))
            })
            .cloned()
            .collect();
        object.insert("objects".into(), Value::Array(before_entries.clone()));
        let before_raw = serde_json::to_vec(&object)?;
        let mut before = stored_writer_verifier(&ctx, &before_raw)?;
        let admissions_entries: Vec<_> = entries
            .iter()
            .filter(|e| {
                known.contains(e["id"].as_str().unwrap_or(""))
                    || !matches!(e["kind"].as_str(), Some("activation" | "invite_redemption"))
            })
            .cloned()
            .collect();
        let mut admissions = object.clone();
        admissions.insert("objects".into(), Value::Array(admissions_entries));
        let admissions_raw = serde_json::to_vec(&admissions)?;
        let new_binding = entries.iter().any(|e| {
            e["kind"] == "host_binding" && !known.contains(e["id"].as_str().unwrap_or(""))
        });
        let mut binding_targets = None;
        if new_binding {
            let mut targets = before_entries.clone();
            for e in &entries {
                let id = e["id"].as_str().unwrap_or("");
                if !known.contains(id)
                    && !renewals.contains(id)
                    && matches!(
                        e["kind"].as_str(),
                        Some(
                            "person_admission"
                                | "person_membership"
                                | "host_admission"
                                | "host_membership"
                        )
                    )
                {
                    before.fresh_legacy(v.proofs.get(id).ok_or_else(|| problem("invalid"))?)?;
                    targets.push(e.clone());
                }
            }
            targets.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
            let mut o = object.clone();
            o.insert("objects".into(), Value::Array(targets));
            binding_targets = Some(stored_writer_verifier(&ctx, &serde_json::to_vec(&o)?)?);
        }

        let access_context = || AccessContext {
            network: ctx.network,
            epoch: ctx.epoch,
            known_feature_id: ctx.known_feature_id,
            now: ctx.now,
            prior_policies: &[],
            prior_groups: &[],
        };
        let maxima = verify_stored_access_state(access_context(), &before_raw)?;
        let max_move = known
            .iter()
            .filter_map(|id| v.proofs.get(id))
            .filter(|p| p.kind == "coordinator_move")
            .map(|p| num(&p.object, "sequence"))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .max()
            .unwrap_or(0);
        let proofs: Vec<_> = v
            .proofs
            .iter()
            .filter(|(id, _)| !known.contains(*id))
            .map(|(id, p)| (id.clone(), p.clone()))
            .collect();
        for (id, p) in proofs {
            let o = &p.object;
            if runtime_legacy::mutation(&p.kind) {
                if p.kind == "host_binding" {
                    binding_targets
                        .as_mut()
                        .ok_or_else(|| problem("invalid"))?
                        .fresh_legacy(&p)?;
                } else {
                    before.fresh_legacy(&p)?;
                }
                if p.kind == "coordinator_move" {
                    check(num(o, "sequence")? > max_move, "state_conflict")?;
                }
            }
            if matches!(p.kind.as_str(), "policy" | "group")
                || p.kind == "person_record" && policy::access_kind(s(o, "kind"))
            {
                let payload = if p.kind == "person_record" {
                    obj(&STANDARD.decode(text(o, "payload_base64")?)?)?
                } else {
                    o.clone()
                };
                let version = num(&payload, "version")?;
                let group = p.kind == "group" || s(o, "kind") == "peerspan-group-v1";
                let prior = if group {
                    maxima
                        .groups
                        .iter()
                        .find(|p| p.name == s(&payload, "name"))
                        .map(|p| p.selection.high_water.version)
                } else {
                    maxima
                        .policies
                        .iter()
                        .find(|p| p.person_public_key == s(&payload, "person_public_key"))
                        .map(|p| p.selection.high_water.version)
                }
                .unwrap_or(0);
                check(version > prior, "state_conflict")?;
                if p.kind != "person_record" {
                    let mut one = before_entries.clone();
                    one.push(
                        entries
                            .iter()
                            .find(|e| e["id"].as_str() == Some(&id))
                            .ok_or_else(|| problem("invalid"))?
                            .clone(),
                    );
                    one.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
                    let mut single = object.clone();
                    single.insert("objects".into(), Value::Array(one));
                    let access = verify_stored_access_state(
                        access_context(),
                        &serde_json::to_vec(&single)?,
                    )?;
                    let active = if group {
                        access
                            .groups
                            .iter()
                            .any(|p| p.selection.proof_id == id && p.selection.active)
                    } else {
                        access
                            .policies
                            .iter()
                            .any(|p| p.selection.proof_id == id && p.selection.active)
                    };
                    check(active, "forbidden")?;
                }
            }
            match p.kind.as_str() {
                "invite_redemption" => fresh_redemption(&ctx, &admissions_raw, &p.body)?,
                "activation" => {
                    let request =
                        super::object(o.get("request").ok_or_else(|| problem("invalid"))?)?;
                    let (_, body) = p_obj(request)?;
                    verify_stored_activation(
                        ActivationContext {
                            network: ctx.network,
                            epoch: ctx.epoch,
                            known_feature_id: ctx.known_feature_id,
                            caller_host_public_key: text(&body, "host_public_key")?,
                            expected_person_public_key: "-",
                            now: ctx.now,
                            verification: "first",
                        },
                        &admissions_raw,
                        &p.body,
                    )?;
                }
                "person_record" | "root_record" if s(o, "operation_id") != "-" => {
                    check(v.active_records.contains(&id), "forbidden")?
                }
                "root_record" => return Err(problem("upgrade_required")),
                "person_record" | "device_revocation" => {
                    let issuer = if p.kind == "person_record" {
                        "certificate_id"
                    } else {
                        "issuer_certificate_id"
                    };
                    verify_stored_action_authority(
                        ActionContext {
                            network: ctx.network,
                            epoch: ctx.epoch,
                            known_feature_id: ctx.known_feature_id,
                            person_public_key: text(o, "person_public_key")?,
                            certificate_id: text(o, issuer)?,
                            now: ctx.now,
                        },
                        &p.kind,
                        &before_raw,
                        &p.body,
                    )?;
                }
                "checkpoint" => v.checkpoint(&p, &id, text(o, "person_public_key")?, 0)?,
                _ => {}
            }
        }
        let people: Vec<_> = v
            .state
            .persons
            .iter()
            .filter(|(_, p)| p.admitted)
            .map(|(k, _)| k)
            .collect();
        for (i, person) in people.iter().enumerate() {
            for other in people.iter().take(i) {
                check(
                    !v.persons
                        .get(*person)
                        .zip(v.persons.get(*other))
                        .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b)),
                    "state_conflict",
                )?;
            }
        }
        Ok(())
    };
    run().map_err(|e| {
        if e.downcast_ref::<PathError>().is_some() {
            e
        } else {
            problem("invalid")
        }
    })
}

fn fresh_redemption(ctx: &CatalogFactContext<'_>, catalog: &[u8], body: &[u8]) -> Result<()> {
    let v = stored_writer_verifier(ctx, catalog)?;
    let o = obj(body)?;
    let p = Proof {
        kind: "invite_redemption".into(),
        body: body.to_vec(),
        object: o.clone(),
    };
    let r = v.read_redemption(&p)?;
    check(ctx.now >= stamp(text(&o, "joined_at")?)?, "invalid")?;
    let mode = text(&o, "mode")?;
    let action = text(&o, "person_action")?;
    let host = text(&o, "host_public_key")?;
    let person = text(&o, "person_public_key")?;
    check(
        mode == "person"
            || !(v.state.hosts.get(host).copied().unwrap_or(false)
                || v.history.hosts.contains(host)),
        "state_conflict",
    )?;
    check(
        action != "admit"
            || !(v.state.persons.get(person).is_some_and(|p| p.admitted)
                || v.history.persons.contains(person)),
        "state_conflict",
    )?;
    if action == "admit" {
        for (key, label) in &v.persons {
            check(
                key == person
                    || !v.state.persons.get(key).is_some_and(|p| p.admitted)
                    || !label.eq_ignore_ascii_case(&r.halves[0].label),
                "state_conflict",
            )?;
        }
    }
    if action == "skip" {
        check(
            v.state.persons.get(person).is_some_and(|p| p.admitted)
                && r.halves.len() == 1
                && v.persons.get(person) == Some(&r.halves[0].label),
            "forbidden",
        )?;
    }
    for h in r.halves {
        check(!v.invite_revoked(&h.key), "forbidden")?;
        check(ctx.now < legacy_stamp(&h.expires)?, "expired")?;
        let part = if h.host {
            "host_invite"
        } else {
            "person_invite"
        };
        let invite = object(o.get(part).ok_or_else(|| problem("invalid"))?)?;
        if !h.legacy {
            verify_stored_action_authority(
                ActionContext {
                    network: ctx.network,
                    epoch: ctx.epoch,
                    known_feature_id: ctx.known_feature_id,
                    person_public_key: &h.person,
                    certificate_id: &h.cert,
                    now: ctx.now,
                },
                "person_record",
                catalog,
                &raw_field(body, part)?,
            )?;
            continue;
        }
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
            let epoch = num(invite, "invite_epoch")?;
            check(epoch == v.epoch, "invalid")?;
            parts.push(epoch.to_string());
        }
        parts.extend([h.key, h.label, h.expires]);
        let message = lines(&parts.iter().map(String::as_str).collect::<Vec<_>>());
        let sig = text(invite, "signature")?;
        if root(&v.root, &message, sig).is_ok() {
            continue;
        }
        let signer = crate::persons::sshsig_signer(sig).ok_or_else(|| problem("invalid"))?;
        check(
            v.state
                .persons
                .get(&signer)
                .is_some_and(|p| p.admitted && p.administrator)
                && !v.access_admin_withdrawn(&signer),
            "forbidden",
        )?;
        ssh(&signer, &message, sig).map_err(|_| problem("invalid"))?;
    }
    Ok(())
}
