//! Automatic renewal of 7-day grants (spec 7.1, 7.2, 7.3; DEC-S10, DEC-S11,
//! DEC-Q6 to DEC-Q12, DEC-Q22, DEC-Q27, DEC-Q28). The root host renews admin,
//! person and host grants; a host's selected device renews its person's
//! bindings and other devices, and the creator device renews itself while it
//! is the creator's only current device. Each renewal is a deadline-only
//! statement with `operation_id` `-`, approved by the approval that created
//! the grant, signed with the daemon's own key and applied like any other
//! fresh statement; the ordinary outbox delivers it.
use super::{
    actions,
    codec::*,
    controls,
    state::Projection,
    statement::{lease, signature_message},
    storage::Snapshot,
};
use crate::store::Store;
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::{Connection, OptionalExtension};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

/// 7-day grants renew with 2 days left; the root host renews with 4 days
/// left (DEC-Q12, DEC-Q24).
const SEVEN_DAYS: i64 = 604_800;
const DEVICE_THRESHOLD: i64 = super::renewal::SEVEN_DAY_THRESHOLD;
const ROOT_THRESHOLD: i64 = 345_600;

fn db(_: rusqlite::Error) -> Error {
    Error::new("internal")
}
fn format(t: chrono::DateTime<chrono::Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

#[derive(Clone)]
enum Signer_ {
    Root([u8; 32]),
    Device {
        seed: [u8; 32],
        public: String,
        lease: String,
        person: String,
        scopes: u64,
    },
}
#[derive(Clone)]
struct Plan {
    stream: Vec<String>,
    signer: Signer_,
}

fn root_seed(c: &Connection, network: &str, p: &Projection) -> Result<Option<[u8; 32]>> {
    let raw: Option<Vec<u8>> = c
        .query_row(
            "SELECT root_seed FROM networks WHERE id=?1",
            [network],
            |r| r.get(0),
        )
        .optional()
        .map_err(db)?
        .flatten();
    let Some(raw) = raw else { return Ok(None) };
    let Ok(seed) = <[u8; 32]>::try_from(raw) else {
        return Ok(None);
    };
    let root = p.catalog.get(p.root_state_id()?)?;
    Ok(
        (encode(SigningKey::from_bytes(&seed).verifying_key().as_bytes())
            == text(&root.payload, "root_public_key")?)
        .then_some(seed),
    )
}
/// This host's selected device, when it is current and its key is here.
fn own_device(c: &Connection, s: &Snapshot, p: &Projection) -> Result<Option<Signer_>> {
    let Some(selected) = s.selection.as_ref().filter(|s| s.kind == "device") else {
        return Ok(None);
    };
    let stream = vec![
        "device".to_string(),
        selected.person_key.clone(),
        selected.device_key.clone(),
    ];
    let Some((own, _)) = heads(p, &stream) else {
        return Ok(None);
    };
    let head = own[0];
    let seed: Option<Vec<u8>> = c
        .query_row(
            "SELECT seed FROM link_device_keys WHERE public_key=?1",
            [&selected.device_key],
            |r| r.get(0),
        )
        .optional()
        .map_err(db)?;
    let Some(Ok(seed)) = seed.map(<[u8; 32]>::try_from) else {
        return Ok(None);
    };
    if encode(SigningKey::from_bytes(&seed).verifying_key().as_bytes()) != selected.device_key {
        return Ok(None);
    }
    Ok(Some(Signer_::Device {
        seed,
        public: selected.device_key.clone(),
        lease: head.id.clone(),
        person: selected.person_key.clone(),
        scopes: num(head.subject()?, "scopes")?,
    }))
}
/// The heads a renewal replaces (one current head, or a fork of identical
/// renewals to resolve) and the earliest of their own deadlines.
fn heads<'a>(
    p: &'a Projection,
    stream: &[String],
) -> Option<(
    Vec<&'a super::statement::Statement>,
    chrono::DateTime<chrono::Utc>,
)> {
    let heads = p.renewable_heads(stream).ok()?;
    let mut end = None;
    for head in &heads {
        let at = stamp(text(&head.payload, "not_after").ok()?).ok()?;
        end = Some(end.map_or(at, |e: chrono::DateTime<chrono::Utc>| e.min(at)));
    }
    Some((heads, end?))
}
/// The current head's own deadline, if the stream has one current head.
fn current(p: &Projection, stream: &[String]) -> Option<(String, chrono::DateTime<chrono::Utc>)> {
    let (head, _) = p.current_statement(stream).ok()?;
    let end = stamp(text(&head.payload, "not_after").ok()?).ok()?;
    Some((head.id.clone(), end))
}
/// The parents' deadline cap of a device-signed renewal: the person, host
/// and (for a device grant) binding grants only (DEC-Q7, DEC-Q27).
fn device_cap(
    p: &Projection,
    kind: &str,
    person: &str,
    host: &str,
) -> Option<(BTreeMap<String, String>, chrono::DateTime<chrono::Utc>)> {
    let (person_id, person_end) = current(p, &["person".into(), person.into()])?;
    let (host_id, host_end) = current(p, &["host".into(), host.into()])?;
    let mut parents = BTreeMap::from([
        ("issuer_person".to_string(), person_id.clone()),
        ("subject_person".to_string(), person_id),
        ("subject_host".to_string(), host_id),
    ]);
    let mut cap = person_end.min(host_end);
    if kind == "device_lease" {
        let (binding_id, binding_end) = current(p, &["binding".into(), host.into()])?;
        parents.insert("subject_binding".into(), binding_id);
        cap = cap.min(binding_end);
    }
    Some((parents, cap))
}
/// Current devices of `person` with `scope`, ordered by host key: the hosts
/// that take turns renewing one of that person's grants (DEC-Q11).
fn ranked(p: &Projection, person: &str, scope: u64, except: Option<&str>) -> Vec<String> {
    let mut hosts: Vec<(String, String)> = p
        .streams
        .values()
        .filter(|s| s.key[0] == "device" && s.key[1] == person)
        .filter(|s| except != Some(s.key[2].as_str()))
        .filter_map(|s| {
            let (head, _) = p.current_statement(&s.key).ok()?;
            let subject = head.subject().ok()?;
            if num(subject, "scopes").ok()? & scope == 0 {
                return None;
            }
            Some((
                text(subject, "host_public_key").ok()?.to_owned(),
                s.key[2].clone(),
            ))
        })
        .collect();
    hosts.sort();
    hosts.into_iter().map(|(_, device)| device).collect()
}
/// Whether this signer's turn in the renewal window has started: signer i of
/// K starts at i × W ÷ (K + 1) into the window W (DEC-Q11).
fn turn(
    now: chrono::DateTime<chrono::Utc>,
    end: chrono::DateTime<chrono::Utc>,
    threshold: i64,
    order: &[String],
    own: &str,
) -> bool {
    let i = order.iter().position(|d| d == own).unwrap_or(0) as i64;
    let k = order.len().max(1) as i64;
    let start = end - chrono::TimeDelta::seconds(threshold)
        + chrono::TimeDelta::seconds(i * threshold / (k + 1));
    now >= start
}
/// Grants this host may renew now, root renewals first.
fn plans(c: &Connection, s: &Snapshot, p: &Projection) -> Result<Vec<Plan>> {
    let now = stamp(&p.decision_time)?;
    let mut out = Vec::new();
    if let Some(seed) = root_seed(c, &s.descriptor.network_id, p)? {
        for kind in ["admin", "person", "host"] {
            for stream in p.streams.values().filter(|st| st.key[0] == kind) {
                let Some((found, end)) = heads(p, &stream.key) else {
                    continue;
                };
                if found.len() > 1 || end - now <= chrono::TimeDelta::seconds(ROOT_THRESHOLD) {
                    out.push(Plan {
                        stream: stream.key.clone(),
                        signer: Signer_::Root(seed),
                    });
                }
            }
        }
    }
    let Some(device) = own_device(c, s, p)? else {
        return Ok(out);
    };
    let Signer_::Device {
        public,
        person,
        scopes,
        ..
    } = &device
    else {
        return Ok(out);
    };
    for stream in p.streams.values() {
        let kind = stream.key[0].as_str();
        let (host, scope) = match kind {
            "binding" if scopes & 6 != 0 => (stream.key[1].clone(), 6),
            "device" if stream.key[1] == *person && scopes & 4 == 4 => {
                let Some((found, _)) = heads(p, &stream.key) else {
                    continue;
                };
                (text(found[0].subject()?, "host_public_key")?.to_owned(), 4)
            }
            _ => continue,
        };
        let Some((found, end)) = heads(p, &stream.key) else {
            continue;
        };
        if text(found[0].subject()?, "person_public_key")? != person {
            continue;
        }
        let forked = found.len() > 1;
        let lease = format!("{kind}_lease");
        let Some((_, cap)) = device_cap(p, &lease, person, &host) else {
            continue;
        };
        if !forked && (end - now > chrono::TimeDelta::seconds(DEVICE_THRESHOLD) || cap <= end) {
            continue;
        }
        let order = if kind == "device" && stream.key[2] == *public {
            // The creator device renews itself only while it is the
            // creator's only current device; the verifier checks the rest.
            let creator = p.catalog.statements.values().any(|d| {
                d.stream().ok().flatten().as_ref() == Some(&stream.key)
                    && d.sequence().ok() == Some(1)
                    && text(&d.payload, "operation_id").is_ok_and(|op| op == "-")
            });
            if !creator || ranked(p, person, 15, None).len() != 1 {
                continue;
            }
            vec![public.clone()]
        } else if kind == "device" {
            ranked(p, person, scope, Some(&stream.key[2]))
        } else {
            ranked(p, person, scope, None)
        };
        // A fork of identical renewals is resolved at once (spec 7.1).
        if forked || turn(now, end, DEVICE_THRESHOLD, &order, public) {
            out.push(Plan {
                stream: stream.key.clone(),
                signer: device.clone(),
            });
        }
    }
    Ok(out)
}
/// The children a renewal keeps (spec 7.2): every current stream head that
/// names a generation of the renewed stream as a parent, with the
/// generations they name, plus the replaced heads.
fn retained(p: &Projection, stream: &[String], heads: &BTreeSet<String>) -> Result<Vec<String>> {
    let generations: BTreeSet<String> = p
        .catalog
        .statements
        .values()
        .filter(|s| s.stream().ok().flatten().as_deref() == Some(stream))
        .map(|s| s.id.clone())
        .collect();
    let mut kept: BTreeSet<String> = heads.clone();
    for other in p.streams.values() {
        if other.key[0] == "root" || other.key == stream {
            continue;
        }
        for id in &other.heads {
            let child = p.catalog.get(id)?;
            if !(lease(&child.kind) || matches!(child.kind.as_str(), "policy" | "group")) {
                continue;
            }
            if p.active(id).is_err() {
                continue;
            }
            // Walk the live child's authority dependencies, including
            // non-head generations it still names (a device naming an older
            // binding that names an older person grant): each statement on
            // the way that names a generation of the renewed stream is kept
            // with that generation.
            let mut pending = vec![id.clone()];
            let mut seen = BTreeSet::new();
            while let Some(current) = pending.pop() {
                if !seen.insert(current.clone()) || seen.len() > 4096 {
                    continue;
                }
                let Ok(node) = p.catalog.get(&current) else {
                    continue;
                };
                for parent in node.parents()?.into_values() {
                    if generations.contains(&parent) {
                        kept.insert(current.clone());
                        kept.insert(parent);
                    } else {
                        pending.push(parent);
                    }
                }
            }
        }
    }
    Ok(kept.into_iter().collect())
}
/// The signed renewal statement for `plan`, or `None` when it no longer
/// applies.
fn draft(p: &Projection, plan: &Plan) -> Result<Option<(String, Vec<u8>, String)>> {
    let now = stamp(&p.decision_time)?;
    let Some(stream) = p.streams.get(&plan.stream) else {
        return Ok(None);
    };
    // A fork of plain renewals with the same subject resolves itself.
    let Some((found, old_end)) = heads(p, &plan.stream) else {
        return Ok(None);
    };
    let head = found[0];
    let forked = found.len() > 1;
    let kind = head.kind.clone();
    let subject = head.subject()?.clone();
    let heads: Vec<String> = stream.heads.iter().cloned().collect();
    let resolves: Vec<String> = if heads.len() > 1 {
        heads.clone()
    } else {
        Vec::new()
    };
    let mut end = now + chrono::TimeDelta::seconds(SEVEN_DAYS);
    let (issuer, parents, key, public) = match &plan.signer {
        Signer_::Root(seed) => {
            let key = SigningKey::from_bytes(seed);
            let public = encode(key.verifying_key().as_bytes());
            (
                json!({"kind":"root","person_public_key":"-"}),
                BTreeMap::new(),
                key,
                public,
            )
        }
        Signer_::Device {
            seed,
            public,
            lease,
            person,
            ..
        } => {
            let host = text(&subject, "host_public_key")?;
            let Some((mut parents, cap)) = device_cap(p, &kind, person, host) else {
                return Ok(None);
            };
            end = end.min(cap);
            if kind == "binding_lease" {
                parents.insert("issuer_device".into(), lease.clone());
            } else if let Some(kept) = head.parents()?.get("issuer_device") {
                parents.insert("issuer_device".into(), kept.clone());
            }
            (
                json!({"kind":"device","person_public_key":person}),
                parents,
                SigningKey::from_bytes(seed),
                public.clone(),
            )
        }
    };
    // Later than the single head, or no earlier than any head of a fork.
    let latest = found
        .iter()
        .filter_map(|h| stamp(text(&h.payload, "not_after").ok()?).ok())
        .max()
        .unwrap_or(old_end);
    if end < latest || !forked && end == latest {
        return Ok(None);
    }
    let time = format(now);
    let payload = json!({"root_state_id":p.root_state_id()?,"operation_id":"-","sequence":stream.maximum.checked_add(1).ok_or_else(||Error::new("version_exhausted"))?,"predecessors":heads,"resolves":resolves,"retained_statement_ids":retained(p,&plan.stream,&stream.heads)?,"subject":subject,"issuer":issuer,"parents":parents.into_iter().map(|(role,id)|json!({"role":role,"id":id})).collect::<Vec<_>>(),"issued_at":time,"not_before":time,"not_after":format(end)});
    let payload = serde_json::to_vec(&payload).map_err(|_| Error::new("internal"))?;
    let context = p.descriptor.context_id();
    let id = super::statement::statement_id(&kind, &context, &payload);
    let signature = encode(
        &key.sign(&signature_message(&id, "issuer", &public))
            .to_bytes(),
    );
    let body = serde_json::to_vec(
        &json!({"format":1,"kind":kind,"context_id":context,"payload_base64":encode(&payload),"signatures":[{"role":"issuer","public_key":public,"format":"ed25519","signature":signature}]}),
    )
    .map_err(|_| Error::new("internal"))?;
    Ok(Some((kind, body, id)))
}
/// Sign and apply one renewal in its own transaction.
fn apply(store: &Store, network: &str, plan: &Plan) -> Result<bool> {
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let mut tx = c.transaction().map_err(db)?;
    let s = Snapshot::load(&tx, network, &store.identity().public_key)?;
    let p = s.project(&controls::local_decision_time()?)?;
    let Some((kind, body, id)) = draft(&p, plan)? else {
        return Ok(false);
    };
    let catalog = actions::candidate(&p, &kind, &body)?;
    let applied = s.apply_catalog(&mut tx, &catalog, &p.decision_time, "fresh")?;
    require(applied.admitted.contains(&id), "forbidden")?;
    actions::remember_clock(&tx, network, &p.decision_time)?;
    crate::store::append_event(&tx, "network.grant_renewed", network, &p.decision_time)
        .map_err(db)?;
    tx.commit().map_err(db)?;
    Ok(true)
}
/// Whether any grant is due for renewal by this host now.
pub(crate) fn due(store: &Store, network: &str) -> Result<bool> {
    let c = store.connection().map_err(|_| Error::new("internal"))?;
    let s = Snapshot::load(&c, network, &store.identity().public_key)?;
    let p = s.project(&controls::local_decision_time()?)?;
    Ok(!plans(&c, &s, &p)?.is_empty())
}
/// Renew every due grant this host can sign, root renewals first, then the
/// device renewals they make possible. A renewal the verifier refuses is
/// skipped until the next pass.
pub(crate) fn renew(store: &Store, network: &str) -> Result<()> {
    let mut failed = BTreeSet::new();
    for _ in 0..256 {
        let next = {
            let c = store.connection().map_err(|_| Error::new("internal"))?;
            let s = Snapshot::load(&c, network, &store.identity().public_key)?;
            let p = s.project(&controls::local_decision_time()?)?;
            plans(&c, &s, &p)?
                .into_iter()
                .find(|plan| !failed.contains(&plan.stream))
        };
        let Some(plan) = next else {
            return Ok(());
        };
        if !matches!(apply(store, network, &plan), Ok(true)) {
            failed.insert(plan.stream);
        }
    }
    Ok(())
}
