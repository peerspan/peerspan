//! Owner-local fixed typed actions: durable consent, immutable signature slots,
//! current-authority rechecks, and atomic local publication with bounded fanout.
use super::{
    codec::*,
    controls, edits,
    intents::{Filled, Intent, Record, Template},
    provider::Resolved,
    state::Projection,
    statement::{Descriptor, Statement, access_body, lease, restriction},
    storage::{Snapshot, check_outbox_capacity},
    template::FixedStatement,
    views,
};
use crate::store::Store;
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::{Connection, OptionalExtension};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

fn db(_: rusqlite::Error) -> Error {
    Error::new("internal")
}
pub(super) fn bytes(v: &Value) -> Result<Vec<u8>> {
    serde_json::to_vec(v).map_err(|_| Error::new("internal"))
}
pub(super) fn at(time: &str, seconds: i64) -> Result<String> {
    Ok((stamp(time)? + chrono::TimeDelta::seconds(seconds))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string())
}
pub(super) fn remember_clock(connection: &Connection, network: &str, time: &str) -> Result<()> {
    let record = json!({"format":1,"largest_local_time":time});
    connection
        .execute(
            "UPDATE dec_clock SET record=?2 WHERE network_id=?1",
            rusqlite::params![network, record.to_string()],
        )
        .map_err(db)?;
    Ok(())
}
pub(super) fn review(i: &Intent) -> Result<Value> {
    parse(&b64(&i.record.review_base64, 1 << 20)?, 1 << 20)
}
pub(super) fn descriptor(connection: &Connection, network: &str) -> Result<Descriptor> {
    let raw: String = connection
        .query_row("SELECT record FROM networks WHERE id=?1", [network], |r| {
            r.get(0)
        })
        .optional()
        .map_err(db)?
        .ok_or_else(|| Error::new("not_found"))?;
    let record: super::storage::NetworkRecord =
        serde_json::from_value(parse(raw.as_bytes(), 32 << 20)?)
            .map_err(|_| Error::new("upgrade_required"))?;
    check(record.mode == "decentralized" && record.format == 2)?;
    let d = Descriptor::read(&b64(&record.descriptor_base64, MAX_OBJECT)?)?;
    check(d.network_id == network && d.context_id() == record.context_id)?;
    Ok(d)
}
pub(super) fn validate(i: &Intent, d: &Descriptor) -> Result<()> {
    check(
        i.network_id == d.network_id
            && i.context_id == d.context_id()
            && i.record.templates.len() == 1
            && (i.secret.is_none() || i.kind == "root_transition"),
    )?;
    let fixed = i.assembled(d)?.remove(0);
    let s = fixed.typed();
    let r = &i.record;
    check(
        r.completed == fixed.pending().is_empty()
            && r.templates[0].object_type == s.kind
            && s.issued_at()? <= r.created_at.as_str()
            && r.created_at < r.expires_at
            && (i.kind != "root_transition" || r.created_at == s.issued_at()?)
            && r.expires_at == at(s.issued_at()?, 300)?,
    )?;
    let concrete = match r.provider.kind.as_str() {
        "root" => "network_root",
        "device" => r.provider.lease_id.as_str(),
        "original" => r.provider.signer_public_key.as_str(),
        _ => return Err(Error::new("invalid")),
    };
    check(
        r.operation_id
            == action_id(
                &i.context_id,
                if i.kind == "policy_claim" {
                    "policy_claim"
                } else {
                    &s.kind
                },
                &s.id,
                concrete,
            ),
    )?;
    let expected_person = if r.provider.kind == "root" {
        "-"
    } else if r.provider.kind == "original" {
        r.provider.signer_public_key.as_str()
    } else {
        text(s.issuer()?, "person_public_key")?
    };
    let expected_device = if r.provider.kind == "device" {
        r.provider.signer_public_key.as_str()
    } else {
        "-"
    };
    check(r.person_public_key == expected_person && r.device_public_key == expected_device)?;
    if s.kind != "root_state" {
        check(text(&s.payload, "root_state_id")? == r.root_state_id)?;
    }
    let v = review(i)?;
    let o = object(&v)?;
    fields(
        o,
        "kind statement_id provider subject sequence not_after authority_warning",
    )?;
    let provider = object(o.get("provider").ok_or_else(|| Error::new("invalid"))?)?;
    fields(
        provider,
        "kind person_public_key host_public_key device_public_key lease_id root_state_id scopes not_after",
    )?;
    let root_provider = r.provider.kind == "root";
    let expected_lease = if root_provider {
        "-".to_owned()
    } else if r.provider.kind == "device" {
        r.provider.lease_id.clone()
    } else {
        s.parents()?
            .get("issuer_person")
            .cloned()
            .ok_or_else(|| Error::new("invalid"))?
    };
    check(
        text(provider, "kind")?
            == match r.provider.kind.as_str() {
                "root" => "network_root",
                "original" => "original_person",
                _ => "device",
            }
            && text(provider, "person_public_key")? == r.person_public_key
            && text(provider, "host_public_key")?
                == if root_provider {
                    "-"
                } else {
                    &r.host_public_key
                }
            && text(provider, "device_public_key")? == r.device_public_key
            && text(provider, "lease_id")? == expected_lease
            && text(provider, "root_state_id")? == r.root_state_id
            && num(provider, "scopes")? == r.scopes,
    )?;
    if root_provider {
        check(
            r.scopes
                == if i.kind == "root_transition" && r.root_state_id == "-" {
                    0
                } else {
                    8
                }
                && text(provider, "not_after")? == "-",
        )?;
    } else {
        stamp(text(provider, "not_after")?)?;
    }
    check(
        text(o, "kind")?
            == if i.kind == "policy_claim" {
                "policy_claim"
            } else {
                &s.kind
            },
    )?;
    check(
        text(o, "statement_id")? == s.id
            && o.get("subject") == Some(&subject(s)?)
            && num(o, "sequence")?
                == if restriction(&s.kind) {
                    0
                } else {
                    s.sequence()?
                }
            && text(o, "not_after")? == r.not_after
            && r.not_after
                == s.payload
                    .get("not_after")
                    .and_then(Value::as_str)
                    .unwrap_or("-")
            && text(o, "authority_warning")?.len() <= 1024,
    )?;
    if i.kind == "policy_claim" {
        check_claim(s, o, &r.host_public_key)?;
    }
    if r.terminal == "applied" {
        let result = parse(&b64(&r.result_base64, 32 << 20)?, 32 << 20)?;
        let out = object(&result)?;
        fields(
            out,
            "action_id review signing_requests statement_base64 proof_id catalog committed delivery",
        )?;
        let signed = fixed.signed(d)?.ok_or_else(|| Error::new("invalid"))?;
        check(
            text(out, "action_id")? == r.operation_id
                && out.get("review") == Some(&v)
                && array(out, "signing_requests")?.is_empty()
                && text(out, "statement_base64")? == encode(&signed.body)
                && text(out, "proof_id")? == signed.proof_id
                && out.get("committed").and_then(Value::as_bool) == Some(true),
        )?;
        let catalog = super::catalog::Catalog::read(
            d,
            &bytes(out.get("catalog").ok_or_else(|| Error::new("invalid"))?)?,
        )?;
        check(
            catalog
                .proofs
                .get(&signed.proof_id)
                .is_some_and(|p| p.kind == signed.kind && p.body == signed.body),
        )?;
        // Recheck every exact alias's contextual signatures and complete
        // consent closure. This scratch historical reader grants no local
        // admission and is not used as today's authority or readiness.
        Projection::build(
            d,
            &Value::from("-"),
            Some(&catalog.bytes),
            &r.created_at,
            "repair",
        )?;
        let delivery = object(out.get("delivery").ok_or_else(|| Error::new("invalid"))?)?;
        fields(delivery, "pending_proof_ids peer_errors")?;
        ids(delivery, "pending_proof_ids", "dp_")?;
        let mut previous = "";
        for value in array(delivery, "peer_errors")? {
            let e = object(value)?;
            fields(e, "host_public_key code")?;
            let host = text(e, "host_public_key")?;
            check(key(host) && host > previous && text(e, "code")?.len() <= 1024)?;
            previous = host;
        }
    } else {
        check(r.terminal == "-" && r.result_base64 == "-")?;
    }
    Ok(())
}
pub(super) fn load(connection: &Connection, network: &str, id: &str, kind: &str) -> Result<Intent> {
    check(ident(id, "act_") && ident(network, "net_"))?;
    let mut q = connection
        .prepare(
            "SELECT intent_id FROM dec_intents WHERE network_id=?1 AND kind=?2 ORDER BY intent_id",
        )
        .map_err(db)?;
    let rows = q
        .query_map([network, kind], |r| r.get::<_, String>(0))
        .map_err(db)?;
    let mut found = None;
    for row in rows {
        let i = Intent::load(connection, &row.map_err(db)?)?;
        if i.record.operation_id == id {
            require(found.is_none(), "state_conflict")?;
            validate(&i, &descriptor(connection, network)?)
                .map_err(|_| Error::new("state_conflict"))?;
            found = Some(i);
        }
    }
    found.ok_or_else(|| Error::new("not_found"))
}
pub(super) fn action_id(context: &str, kind: &str, statement: &str, provider: &str) -> String {
    format!(
        "act_{}",
        hash(&lines(&[
            "peerspan-decentralized-action-intent-v1",
            context,
            kind,
            statement,
            provider
        ]))
    )
}
fn template(
    p: &Projection,
    provider: &Resolved,
    kind: &str,
    payload: &[u8],
) -> Result<FixedStatement> {
    let value = parse(payload, MAX_PAYLOAD)?;
    let o = object(&value)?;
    let mut roles = BTreeMap::new();
    if kind == "root_state" {
        let predecessors = ids(o, "predecessors", "ds_")?;
        for id in &predecessors {
            let key = text(&p.catalog.get(id)?.payload, "root_public_key")?;
            let role = if predecessors.len() == 1 {
                "issuer".into()
            } else {
                format!("root_branch:{id}")
            };
            roles.insert(
                role,
                (key.to_owned(), provider.provider.signature_format.clone()),
            );
        }
        roles.insert(
            "new_root".into(),
            (text(o, "root_public_key")?.into(), "ed25519".into()),
        );
    } else {
        roles.insert(
            "issuer".into(),
            (
                provider.provider.signer_public_key.clone(),
                provider.provider.signature_format.clone(),
            ),
        );
        if kind == "binding_lease" || kind == "host_lease" {
            roles.insert(
                "host".into(),
                (
                    text(
                        object(o.get("subject").ok_or_else(|| Error::new("invalid"))?)?,
                        "host_public_key",
                    )?
                    .into(),
                    "ed25519".into(),
                ),
            );
        }
    }
    let raw = bytes(
        &json!({"format":1,"kind":kind,"context_id":p.descriptor.context_id(),"payload_base64":encode(payload),"signatures":roles.into_iter().map(|(role,(public_key,format))|json!({"role":role,"public_key":public_key,"format":format,"signature":"-"})).collect::<Vec<_>>()}),
    )?;
    FixedStatement::read(&p.descriptor, &raw)
}
fn subject(s: &Statement) -> Result<Value> {
    Ok(if lease(&s.kind) {
        Value::Object(s.subject()?.clone())
    } else if restriction(&s.kind) {
        s.payload
            .get("target")
            .cloned()
            .ok_or_else(|| Error::new("invalid"))?
    } else if s.kind == "root_state" {
        json!({"root_public_key":text(&s.payload,"root_public_key")?,"epoch":s.sequence()?})
    } else {
        let body = access_body(&s.payload)?;
        if s.kind == "policy" {
            json!({"person_public_key":text(&body,"person_public_key")?})
        } else {
            json!({"name":text(&body,"name")?})
        }
    })
}
pub(super) fn revalidate(
    connection: &Connection,
    snapshot: &Snapshot,
    p: &Projection,
    i: &Intent,
) -> Result<Resolved> {
    let assembled = i.assembled(&snapshot.descriptor)?;
    check(assembled.len() == 1)?;
    let fixed = &assembled[0];
    let s = fixed.typed();
    let r = &i.record;
    check(
        i.context_id == snapshot.descriptor.context_id()
            && i.network_id == snapshot.descriptor.network_id
            && r.host_public_key == snapshot.network.own_identity.host_public_key
            && r.templates[0].object_type == s.kind
            && r.completed == fixed.pending().is_empty()
            && i.secret.is_none(),
    )?;
    let requested = match r.provider.kind.as_str() {
        "root" => "network_root",
        "device" => r.provider.lease_id.as_str(),
        "original" => r.provider.signer_public_key.as_str(),
        _ => return Err(Error::new("invalid")),
    };
    let resolved = Resolved::resolve(
        connection,
        snapshot,
        p,
        requested,
        &r.provider.signature_format,
        &s.kind,
    )?;
    require(
        resolved.provider.kind == r.provider.kind
            && resolved.provider.signer_public_key == r.provider.signer_public_key
            && resolved.provider.signature_format == r.provider.signature_format
            && resolved.provider.lease_id == r.provider.lease_id,
        "state_conflict",
    )?;
    let expected = action_id(
        &i.context_id,
        if i.kind == "policy_claim" {
            "policy_claim"
        } else {
            &s.kind
        },
        &s.id,
        &resolved.concrete_id,
    );
    check(
        expected == r.operation_id
            && s.issued_at()? <= r.created_at.as_str()
            && r.created_at < r.expires_at
            && r.expires_at == at(s.issued_at()?, 300)?,
    )?;
    p.action(&resolved.actor, &s.kind, &s.payload_bytes)?;
    edits::check_policy(
        connection,
        p,
        s,
        &r.host_public_key,
        i.kind == "policy_claim",
    )?;
    if i.kind == "policy_claim" {
        check_claim(s, object(&review(i)?)?, &r.host_public_key)?;
    }
    Ok(resolved)
}
pub(super) fn candidate(p: &Projection, kind: &str, body: &[u8]) -> Result<Vec<u8>> {
    require(body.len() <= MAX_OBJECT, "quota_exceeded")?;
    let id = super::statement::proof_id(kind, body);
    let mut objects: BTreeMap<_, _> = p
        .catalog
        .proofs
        .values()
        .map(|proof| {
            (
                proof.id.clone(),
                json!({"id":proof.id,"kind":proof.kind,"body_base64":encode(&proof.body)}),
            )
        })
        .collect();
    objects.insert(
        id.clone(),
        json!({"id":id,"kind":kind,"body_base64":encode(body)}),
    );
    require(objects.len() <= 4096, "quota_exceeded")?;
    let decoded = p
        .catalog
        .proofs
        .values()
        .map(|s| s.body.len())
        .sum::<usize>()
        .checked_add(if p.catalog.proofs.contains_key(&id) {
            0
        } else {
            body.len()
        })
        .ok_or_else(|| Error::new("quota_exceeded"))?;
    require(decoded <= MAX_DECODED, "quota_exceeded")?;
    let raw = bytes(
        &json!({"format":1,"context_id":p.descriptor.context_id(),"objects":objects.into_values().collect::<Vec<_>>()}),
    )?;
    require(raw.len() <= MAX_CATALOG, "quota_exceeded")?;
    Ok(raw)
}
pub(super) fn preflight(
    connection: &Connection,
    p: &Projection,
    snapshot: &Snapshot,
    fixed: &FixedStatement,
) -> Result<()> {
    let catalog = candidate(p, &fixed.typed().kind, &fixed.budget_bytes()?)?;
    let mut targets: BTreeSet<_> = p
        .members()?
        .into_iter()
        .map(|m| m.host_public_key)
        .collect();
    if fixed.typed().kind == "host_lease" {
        targets.insert(text(fixed.typed().subject()?, "host_public_key")?.into());
    }
    if fixed.typed().kind == "root_state" {
        for id in ids(&fixed.typed().payload, "retained_statement_ids", "ds_")? {
            let retained = p.catalog.get(&id)?;
            if retained.kind == "host_lease" {
                targets.insert(text(retained.subject()?, "host_public_key")?.into());
            }
        }
    }
    targets.remove(&snapshot.network.own_identity.host_public_key);
    let body = bytes(&json!({"catalog":parse(&catalog,MAX_CATALOG)?}))?;
    require(body.len() <= 20 << 20, "quota_exceeded")?;
    let record = json!({"format":1,"kind":"proofs","body_base64":encode(&body),"proof_ids":[super::statement::proof_id(&fixed.typed().kind,&fixed.budget_bytes()?)],"created_at":p.decision_time,"attempts":0,"next_attempt_at":p.decision_time,"last_error_code":"-","last_error_detail":"-"});
    check_outbox_capacity(
        connection,
        &targets.iter().map(|_| &record).collect::<Vec<_>>(),
    )
}
fn check_claim(s: &Statement, review: &Obj, host: &str) -> Result<()> {
    require(s.kind == "policy", "invalid")?;
    let marker = text(review, "authority_warning")?;
    let capability = marker
        .strip_prefix("prepare capability claim: ")
        .ok_or_else(|| Error::new("invalid"))?;
    check(crate::policy::name_shape(capability) && capability != crate::capabilities::READ)?;
    // The actual stable host identity, not its display member label, names a
    // claim. No other host may claim this same name in the prepared body.
    let host = format!("host_{}", hash(&b64(host, 32)?));
    let body = access_body(&s.payload)?;
    let mut found = false;
    for value in array(&body, "capability_rules")? {
        let rule = object(value)?;
        if text(rule, "capability")? == capability {
            require(text(rule, "host")? == host, "invalid")?;
            found = true;
        }
    }
    check(found)?;
    Ok(())
}
fn requests(i: &Intent, d: &Descriptor) -> Result<Vec<Value>> {
    if !i.record.approved || i.record.terminal != "-" {
        return Ok(Vec::new());
    }
    let templates = i.assembled(d)?;
    Ok(templates[0].pending().into_iter().take(16).map(|s|json!({"intent_id":i.id,"slot_id":1,"object_type":s.object_type,"object_id":s.statement_id,"role":s.role,"public_key":s.public_key,"format":s.signature_format,"template_base64":encode(templates[0].bytes()),"message_base64":s.message_base64})).collect())
}
pub(super) fn response(
    connection: &Connection,
    snapshot: &Snapshot,
    p: &Projection,
    i: &Intent,
) -> Result<Vec<u8>> {
    if i.record.terminal == "applied" {
        return b64(&i.record.result_base64, 32 << 20);
    }
    let fixed = i.assembled(&snapshot.descriptor)?.remove(0);
    let signed = fixed.signed(&snapshot.descriptor)?;
    let (statement, proof, catalog) = if let Some(s) = signed {
        (
            encode(&s.body),
            s.proof_id.clone(),
            parse(&candidate(p, &s.kind, &s.body)?, MAX_CATALOG)?,
        )
    } else {
        ("-".into(), "-".into(), Value::from("-"))
    };
    bytes(
        &json!({"action_id":i.record.operation_id,"review":review(i)?,"signing_requests":requests(i,&snapshot.descriptor)?,"statement_base64":statement,"proof_id":proof,"catalog":catalog,"committed":false,"delivery":views::delivery(connection,&i.network_id,&i.context_id)?}),
    )
}
pub(super) fn add_signature(i: &mut Intent, role: &str, sig: &str) -> Result<bool> {
    if let Some(old) = i
        .record
        .signatures
        .iter()
        .find(|s| s.slot_id == 1 && s.role == role)
    {
        require(old.signature == sig, "operation_conflict")?;
        return Ok(false);
    }
    i.record.signatures.push(Filled {
        slot_id: 1,
        role: role.into(),
        signature: sig.into(),
    });
    i.record.signatures.sort_by(|a, b| a.role.cmp(&b.role));
    Ok(true)
}
fn completed_retry(
    connection: &Connection,
    network: &str,
    kind: &str,
    payload: &[u8],
    request: &Obj,
    claim: bool,
) -> Result<Option<Vec<u8>>> {
    let d = descriptor(connection, network)?;
    super::statement::validate_payload(&d, kind, object(&parse(payload, MAX_PAYLOAD)?)?)?;
    let ds = super::statement::statement_id(kind, &d.context_id(), payload);
    let requested = text(request, "provider_id")?;
    let concrete = if requested == "auto" {
        let selected:Option<(String,String,String)>=connection.query_row("SELECT provider_kind,person_key,lease_id FROM dec_signers WHERE network_id=?1 AND context_id=?2",[network,&d.context_id()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(db)?;
        selected.map(|(kind, person, lease)| if kind == "device" { lease } else { person })
    } else {
        Some(requested.into())
    };
    let Some(concrete) = concrete else {
        return Ok(None);
    };
    let id = action_id(
        &d.context_id(),
        if claim { "policy_claim" } else { kind },
        &ds,
        &concrete,
    );
    let old = match load(
        connection,
        network,
        &id,
        if claim { "policy_claim" } else { "action" },
    ) {
        Ok(old) if old.record.terminal == "applied" => old,
        Ok(_) => return Ok(None),
        Err(e) if e.code == "not_found" => return Ok(None),
        Err(e) => return Err(e),
    };
    let format = text(request, "signature_format")?;
    require(
        format == "auto" || format == old.record.provider.signature_format,
        "operation_conflict",
    )?;
    let fixed = old.assembled(&d)?.remove(0);
    require(
        fixed.typed().kind == kind && fixed.typed().payload_bytes == payload,
        "operation_conflict",
    )?;
    Ok(Some(b64(&old.record.result_base64, 32 << 20)?))
}
pub(crate) fn prepare(store: &Store, network: &str, request: &Obj, claim: bool) -> Result<Vec<u8>> {
    fields(
        request,
        if claim {
            "capability provider_id signature_format payload_base64 approve"
        } else {
            "kind provider_id signature_format payload_base64 approve"
        },
    )?;
    let kind = if claim {
        "policy"
    } else {
        text(request, "kind")?
    };
    check(
        (lease(kind) && kind != "device_lease")
            || restriction(kind)
            || matches!(kind, "policy" | "group" | "root_state"),
    )?;
    let payload = b64(text(request, "payload_base64")?, MAX_PAYLOAD)?;
    let requested = text(request, "provider_id")?;
    check(
        matches!(requested, "auto" | "network_root") || key(requested) || ident(requested, "ds_"),
    )?;
    check(matches!(
        text(request, "signature_format")?,
        "auto" | "ed25519" | "sshsig"
    ))?;
    let approved = request
        .get("approve")
        .and_then(Value::as_bool)
        .ok_or_else(|| Error::new("invalid"))?;
    let (id, new, approval, provider) = {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        if let Some(result) = completed_retry(&tx, network, kind, &payload, request, claim)? {
            return Ok(result);
        }
        let s = Snapshot::load(&tx, network, &store.identity().public_key)?;
        let p = s.project(&controls::local_decision_time()?)?;
        let provider = Resolved::resolve(
            &tx,
            &s,
            &p,
            text(request, "provider_id")?,
            text(request, "signature_format")?,
            kind,
        )?;
        p.action(&provider.actor, kind, &payload)?;
        let fixed = template(&p, &provider, kind, &payload)?;
        require(
            p.decision_time < at(fixed.typed().issued_at()?, 300)?,
            "expired",
        )?;
        edits::check_policy(&tx, &p, fixed.typed(), &store.identity().public_key, claim)?;
        preflight(&tx, &p, &s, &fixed)?;
        let id = action_id(
            &s.network.context_id,
            if claim { "policy_claim" } else { kind },
            fixed.statement_id(),
            &provider.concrete_id,
        );
        let original_binding = kind == "binding_lease" && provider.provider.kind == "original";
        let existing = load(
            &tx,
            network,
            &id,
            if claim { "policy_claim" } else { "action" },
        );
        let new = matches!(&existing,Err(e) if e.code=="not_found");
        let mut i = match existing {
            Ok(i) => {
                require(
                    i.record.templates[0].template_base64 == encode(fixed.bytes()),
                    "operation_conflict",
                )?;
                i
            }
            Err(e) if e.code == "not_found" => {
                let total: i64 = tx
                    .query_row("SELECT COUNT(*) FROM dec_intents", [], |r| r.get(0))
                    .map_err(db)?;
                let unsigned:i64=tx.query_row("SELECT COUNT(*) FROM dec_intents WHERE json_extract(record,'$.terminal')='-' AND json_extract(record,'$.completed')=0",[],|r|r.get(0)).map_err(db)?;
                require(total < 4096 && unsigned < 64, "quota_exceeded")?;
                let s = fixed.typed();
                let warning = if claim {
                    format!("prepare capability claim: {}", text(request, "capability")?)
                } else {
                    "bounded authority cannot prove that no unseen revocation exists".into()
                };
                let public_provider =
                    provider.public(&p, &store.identity().public_key, original_binding)?;
                let r = json!({"kind":if claim {"policy_claim"}else{kind},"statement_id":s.id,"provider":public_provider,"subject":subject(s)?,"sequence":if restriction(kind){0}else{s.sequence()?},"not_after":s.payload.get("not_after").and_then(Value::as_str).unwrap_or("-"),"authority_warning":warning});
                Intent {
                    id: crate::store::new_id("dint").map_err(|_| Error::new("internal"))?,
                    network_id: network.into(),
                    context_id: p.descriptor.context_id(),
                    kind: if claim { "policy_claim" } else { "action" }.into(),
                    record: Record {
                        format: 1,
                        operation_id: id.clone(),
                        approved: false,
                        approved_at: "-".into(),
                        review_base64: encode(&bytes(&r)?),
                        provider: provider.provider.clone(),
                        root_state_id: p.root_state_id()?.into(),
                        person_public_key: text(&provider.actor, "person_public_key")?.into(),
                        host_public_key: store.identity().public_key,
                        device_public_key: text(&provider.actor, "device_public_key")?.into(),
                        scopes: num(
                            object(r.get("provider").ok_or_else(|| Error::new("invalid"))?)?,
                            "scopes",
                        )?,
                        not_after: s
                            .payload
                            .get("not_after")
                            .and_then(Value::as_str)
                            .unwrap_or("-")
                            .into(),
                        created_at: p.decision_time.clone(),
                        expires_at: at(s.issued_at()?, 300)?,
                        templates: vec![Template {
                            slot_id: 1,
                            object_type: kind.into(),
                            template_base64: encode(fixed.bytes()),
                        }],
                        signatures: Vec::new(),
                        completed: false,
                        terminal: "-".into(),
                        result_base64: "-".into(),
                    },
                    secret: None,
                }
            }
            Err(e) => return Err(e),
        };
        if i.record.terminal == "applied" {
            return b64(&i.record.result_base64, 32 << 20);
        }
        if claim {
            require(
                text(object(&review(&i)?)?, "authority_warning")?
                    == format!("prepare capability claim: {}", text(request, "capability")?),
                "operation_conflict",
            )?;
            check_claim(
                fixed.typed(),
                object(&review(&i)?)?,
                &store.identity().public_key,
            )?;
        }
        let approval = approved && !i.record.approved;
        if approval {
            i.record.approved = true;
            i.record.approved_at = p.decision_time.clone();
            remember_clock(&tx, network, &p.decision_time)?;
        }
        i.save(&tx)?;
        tx.commit().map_err(db)?;
        (id, new, approval, provider)
    };
    if new {
        controls::barrier(store, "dec.intent.after_commit", &id)?;
    }
    if approval {
        controls::barrier(store, "dec.approval.after_commit", &id)?;
    }
    if approved {
        provider.available(store)?;
        finish(store, network, &id, claim)
    } else {
        get(store, network, &id, claim)
    }
}
pub(crate) fn get(store: &Store, network: &str, id: &str, claim: bool) -> Result<Vec<u8>> {
    if !claim && super::roots::contains(store, network, id)? {
        return super::roots::get(store, network, id);
    }

    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let i = load(
        &tx,
        network,
        id,
        if claim { "policy_claim" } else { "action" },
    )?;
    if i.record.terminal == "applied" {
        return b64(&i.record.result_base64, 32 << 20);
    }
    let s = Snapshot::load(&tx, network, &store.identity().public_key)?;
    let p = s.project(&controls::local_decision_time()?)?;
    revalidate(&tx, &s, &p, &i)?;
    response(&tx, &s, &p, &i)
}
fn finish(store: &Store, network: &str, id: &str, claim: bool) -> Result<Vec<u8>> {
    let (mut pending, ssh_slots, provider) = {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        let i = load(
            &tx,
            network,
            id,
            if claim { "policy_claim" } else { "action" },
        )?;
        if i.record.terminal == "applied" {
            return b64(&i.record.result_base64, 32 << 20);
        }
        let s = Snapshot::load(&tx, network, &store.identity().public_key)?;
        let p = s.project(&controls::local_decision_time()?)?;
        let provider = revalidate(&tx, &s, &p, &i)?;
        require(i.record.approved, "state_conflict")?;
        let fixed = i.assembled(&s.descriptor)?.remove(0);
        preflight(&tx, &p, &s, &fixed)?;
        let mut signatures = Vec::new();
        let mut ssh_slots = Vec::new();
        for slot in fixed.pending() {
            let message = b64(&slot.message_base64, 4096)?;
            let key = if slot.public_key == store.identity().public_key
                && slot.signature_format == "ed25519"
            {
                Some(store.signing_key.clone())
            } else if slot.public_key == provider.provider.signer_public_key
                && slot.signature_format == "ed25519"
            {
                provider.seed.map(|s| SigningKey::from_bytes(&s))
            } else {
                None
            };
            if let Some(key) = key {
                signatures.push((slot.role, encode(&key.sign(&message).to_bytes())));
            } else if slot.public_key == provider.provider.signer_public_key
                && slot.signature_format == "sshsig"
            {
                ssh_slots.push((slot.role, message));
            }
        }
        // Raw signatures above are computed only after the coherent gates and
        // approval. External SSH is deliberately handled after dropping TX.
        remember_clock(&tx, network, &p.decision_time)?;
        tx.commit().map_err(db)?;
        (signatures, ssh_slots, provider)
    };
    provider.available(store)?;
    if !ssh_slots.is_empty() {
        let public: [u8; 32] = b64(&provider.provider.signer_public_key, 32)?
            .try_into()
            .map_err(|_| Error::new("invalid"))?;
        if let Ok(signer) = store.renewal_signer(public) {
            for (role, message) in ssh_slots {
                let text = std::str::from_utf8(&message).map_err(|_| Error::new("invalid"))?;
                let sig = signer
                    .sign(&text.split('\n').collect::<Vec<_>>())
                    .map_err(|_| Error::new("signer_unavailable"))?;
                pending.push((role, sig));
            }
        }
    }
    if !pending.is_empty() {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        let mut i = load(
            &tx,
            network,
            id,
            if claim { "policy_claim" } else { "action" },
        )?;
        let s = Snapshot::load(&tx, network, &store.identity().public_key)?;
        let p = s.project(&controls::local_decision_time()?)?;
        revalidate(&tx, &s, &p, &i)?;
        let fixed = i.assembled(&s.descriptor)?.remove(0);
        for (role, sig) in pending {
            fixed.fill(&s.descriptor, &role, &sig)?;
            add_signature(&mut i, &role, &sig)?;
        }
        i.record.completed = i.assembled(&s.descriptor)?[0].pending().is_empty();
        remember_clock(&tx, network, &p.decision_time)?;
        i.save(&tx)?;
        tx.commit().map_err(db)?;
        drop(c);
        controls::barrier(store, "dec.signature.after_commit", id)?;
    }
    controls::barrier(store, "dec.apply.before_transaction", id)?;
    let result = {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let mut tx = c.transaction().map_err(db)?;
        let mut i = load(
            &tx,
            network,
            id,
            if claim { "policy_claim" } else { "action" },
        )?;
        if i.record.terminal == "applied" {
            return b64(&i.record.result_base64, 32 << 20);
        }
        let s = Snapshot::load(&tx, network, &store.identity().public_key)?;
        let p = s.project(&controls::local_decision_time()?)?;
        revalidate(&tx, &s, &p, &i)?;
        let fixed = i.assembled(&s.descriptor)?.remove(0);
        preflight(&tx, &p, &s, &fixed)?;
        let Some(signed) = fixed.signed(&s.descriptor)? else {
            return response(&tx, &s, &p, &i);
        };
        if claim {
            return response(&tx, &s, &p, &i);
        }
        let catalog = candidate(&p, &signed.kind, &signed.body)?;
        let applied = s.apply_catalog(&mut tx, &catalog, &p.decision_time, "fresh")?;
        require(
            applied.admitted.contains(&signed.id) || applied.restrictions.contains(&signed.id),
            "forbidden",
        )?;
        edits::settle(&tx, &p, &applied, &signed, &store.identity().public_key)?;
        if signed.kind == "binding_lease"
            && s.network.own_identity.person_public_key == "-"
            && i.record.provider.kind == "original"
            && text(signed.subject()?, "host_public_key")? == store.identity().public_key
        {
            let person = text(signed.subject()?, "person_public_key")?;
            require(
                person == i.record.provider.signer_public_key
                    && text(signed.issuer()?, "kind")? == "person",
                "forbidden",
            )?;
            let member = applied.member_for(&store.identity().public_key, person)?;
            let mut native = s.network.clone();
            native.root_state_id = applied.root_state_id()?.into();
            native.own_identity = super::storage::OwnIdentity {
                member: member.member,
                person_public_key: person.into(),
                host_public_key: store.identity().public_key,
            };
            tx.execute(
                "UPDATE networks SET record=?2 WHERE id=?1",
                rusqlite::params![
                    network,
                    serde_json::to_string(&native).map_err(|_| Error::new("internal"))?
                ],
            )
            .map_err(db)?;
            tx.execute("INSERT INTO dec_signers(network_id,context_id,provider_kind,person_key,device_key,lease_id) VALUES(?1,?2,'original',?3,'-','-')",rusqlite::params![network,s.network.context_id,person]).map_err(db)?;
        }
        let delivery = views::delivery(&tx, network, &s.network.context_id)?;
        let result = bytes(
            &json!({"action_id":id,"review":review(&i)?,"signing_requests":[],"statement_base64":encode(&signed.body),"proof_id":signed.proof_id,"catalog":parse(&applied.catalog.bytes,MAX_CATALOG)?,"committed":true,"delivery":delivery}),
        )?;
        i.record.terminal = "applied".into();
        i.record.result_base64 = encode(&result);
        i.record.completed = true;
        i.save(&tx)?;
        crate::store::append_event(&tx, "network.action_applied", network, &p.decision_time)
            .map_err(db)?;
        tx.commit().map_err(db)?;
        result
    };
    controls::barrier(store, "dec.apply.after_commit", id)?;
    Ok(result)
}
pub(crate) fn signed(
    store: &Store,
    network: &str,
    id: &str,
    request: &Obj,
    claim: bool,
) -> Result<Vec<u8>> {
    if !claim && super::roots::contains(store, network, id)? {
        return super::roots::signed(store, network, id, request);
    }
    fields(request, "intent_id signatures")?;
    let entries = array(request, "signatures")?;
    check(!entries.is_empty() && entries.len() <= 16)?;
    let changed = {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        let mut i = load(
            &tx,
            network,
            id,
            if claim { "policy_claim" } else { "action" },
        )?;
        require(text(request, "intent_id")? == i.id, "invalid")?;
        require(i.record.approved, "state_conflict")?;
        if i.record.terminal == "applied" {
            let mut previous = None;
            for entry in entries {
                let e = object(entry)?;
                fields(e, "slot_id role signature")?;
                let slot = num(e, "slot_id")?;
                let role = text(e, "role")?;
                let sig = text(e, "signature")?;
                check(slot == 1 && previous.is_none_or(|old: &str| old < role))?;
                previous = Some(role);
                require(
                    i.record
                        .signatures
                        .iter()
                        .any(|v| v.slot_id == slot && v.role == role && v.signature == sig),
                    "operation_conflict",
                )?;
            }
            return b64(&i.record.result_base64, 32 << 20);
        }
        let s = Snapshot::load(&tx, network, &store.identity().public_key)?;
        let p = s.project(&controls::local_decision_time()?)?;
        revalidate(&tx, &s, &p, &i)?;
        preflight(&tx, &p, &s, &i.assembled(&s.descriptor)?.remove(0))?;
        let mut previous = None;
        let mut changed = false;
        for entry in entries {
            let e = object(entry)?;
            fields(e, "slot_id role signature")?;
            let slot = num(e, "slot_id")?;
            let role = text(e, "role")?;
            let sig = text(e, "signature")?;
            check(slot == 1 && previous.is_none_or(|old: &str| old < role))?;
            previous = Some(role);
            let fixed = i.assembled(&s.descriptor)?.remove(0);
            fixed.fill(&s.descriptor, role, sig)?;
            changed |= add_signature(&mut i, role, sig)?;
        }
        i.record.completed = i.assembled(&s.descriptor)?[0].pending().is_empty();
        remember_clock(&tx, network, &p.decision_time)?;
        i.save(&tx)?;
        tx.commit().map_err(db)?;
        changed
    };
    if changed {
        controls::barrier(store, "dec.signature.after_commit", id)?;
    }
    finish(store, network, id, claim)
}
