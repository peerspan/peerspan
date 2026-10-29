//! Automatic grant renewal (spec 7.1 to 7.3). The root renews network
//! authority, admins renew person/host grants and groups, and the selected
//! original key or device renews its person's bindings and devices. Renewals
//! reuse the original approval and ordinary statement admission and outbox.
//! External SSH signers run outside the database lock, followed by an exact
//! current-authority recheck before publication.
use super::{
    actions,
    codec::*,
    controls,
    provider::Resolved,
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
const DAY: i64 = 86_400;
const GROUP_THRESHOLD: i64 = super::renewal::DAY_THRESHOLD;

fn db(_: rusqlite::Error) -> Error {
    Error::new("internal")
}
fn format(t: chrono::DateTime<chrono::Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

#[derive(Clone, PartialEq, Eq)]
enum Signer_ {
    Root {
        seed: Option<[u8; 32]>,
        public: String,
    },
    Original {
        public: String,
        scopes: u64,
    },
    Device {
        seed: [u8; 32],
        public: String,
        lease: String,
        person: String,
        scopes: u64,
    },
}
#[derive(Clone, PartialEq, Eq)]
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
        scopes: own.iter().try_fold(15, |scopes, head| {
            Ok::<_, Error>(scopes & p.effective_scopes(&head.id)?)
        })?,
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
/// The current head's effective deadline, if the stream has one current head.
fn current(p: &Projection, stream: &[String]) -> Option<(String, chrono::DateTime<chrono::Utc>)> {
    let (head, end) = p.current_statement(stream).ok()?;
    let end = stamp(&end).ok()?;
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
            if p.effective_scopes(&head.id).ok()? & scope == 0 {
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
/// Selected person signer. An unavailable device never falls back to the
/// original key; original-key availability is checked outside the Store lock.
fn own(c: &Connection, s: &Snapshot, p: &Projection) -> Result<Option<Signer_>> {
    let Some(selected) = &s.selection else {
        return Ok(None);
    };
    if selected.kind == "device" {
        return own_device(c, s, p);
    }
    let Ok(provider) = Resolved::resolve(c, s, p, "auto", "auto", "person_lease") else {
        return Ok(None);
    };
    let public = provider.public(p, &s.network.own_identity.host_public_key, false)?;
    Ok(Some(Signer_::Original {
        public: selected.person_key.clone(),
        scopes: num(object(&public)?, "scopes")?,
    }))
}
impl Signer_ {
    fn public(&self) -> &str {
        match self {
            Self::Root { public, .. }
            | Self::Original { public, .. }
            | Self::Device { public, .. } => public,
        }
    }
    fn seed(&self) -> Option<[u8; 32]> {
        match self {
            Self::Root { seed, .. } => *seed,
            Self::Device { seed, .. } => Some(*seed),
            Self::Original { .. } => None,
        }
    }
    fn available(&self, store: &Store) -> bool {
        self.seed().is_some()
            || b64(self.public(), 32)
                .ok()
                .and_then(|key| key.try_into().ok())
                .is_some_and(|key| store.renewal_signer(key).is_ok())
    }
}
/// Original keys have a reserved first turn: private key availability is not
/// advertised. Devices follow in host-key order and still start before expiry.
fn owner_order(p: &Projection, person: &str, scope: u64, except: Option<&str>) -> Vec<String> {
    std::iter::once(person.to_owned())
        .chain(ranked(p, person, scope, except))
        .collect()
}
fn admin_order(p: &Projection) -> Vec<String> {
    let mut originals = Vec::new();
    let mut devices = Vec::new();
    for stream in p.streams.values().filter(|s| s.key[0] == "admin") {
        if p.current_statement(&stream.key).is_err() {
            continue;
        }
        let person = &stream.key[1];
        originals.push(person.clone());
        for public in ranked(p, person, 8, None) {
            let key = vec!["device".into(), person.clone(), public.clone()];
            if let Ok((head, _)) = p.current_statement(&key)
                && let Ok(subject) = head.subject()
                && let Ok(host) = text(subject, "host_public_key")
            {
                devices.push((host.to_owned(), public));
            }
        }
    }
    originals.sort();
    devices.sort();
    originals.extend(devices.into_iter().map(|(_, key)| key));
    originals
}
/// Parent grants and their effective deadline for an admin-signed renewal.
fn admin_cap(
    p: &Projection,
    signer: &Signer_,
) -> Option<(BTreeMap<String, String>, chrono::DateTime<chrono::Utc>)> {
    let (person, device) = match signer {
        Signer_::Original { public, scopes } if scopes & 8 == 8 => (public, None),
        Signer_::Device {
            person,
            lease,
            scopes,
            ..
        } if scopes & 8 == 8 => (person, Some(lease)),
        _ => return None,
    };
    let (person_id, person_end) = current(p, &["person".into(), person.clone()])?;
    let (admin_id, admin_end) = current(p, &["admin".into(), person.clone()])?;
    let mut parents = BTreeMap::from([
        ("issuer_person".into(), person_id),
        ("issuer_admin".into(), admin_id),
    ]);
    let mut cap = person_end.min(admin_end);
    if let Some(device) = device {
        let statement = p.catalog.get(device).ok()?;
        let (_, end) = current(p, &statement.stream().ok()??)?;
        if p.effective_scopes(device).ok()? & 8 == 0 {
            return None;
        }
        parents.insert("issuer_device".into(), device.clone());
        cap = cap.min(end);
    }
    Some((parents, cap))
}
/// Grants this host may renew now, root renewals first.
fn plans(c: &Connection, s: &Snapshot, p: &Projection) -> Result<Vec<Plan>> {
    let now = stamp(&p.decision_time)?;
    let mut out = Vec::new();
    let root = p.catalog.get(p.root_state_id()?)?;
    let root_signer = Signer_::Root {
        seed: root_seed(c, &s.descriptor.network_id, p)?,
        public: text(&root.payload, "root_public_key")?.into(),
    };
    for stream in p
        .streams
        .values()
        .filter(|st| matches!(st.key[0].as_str(), "admin" | "person" | "host" | "group"))
    {
        let Some((found, end)) = heads(p, &stream.key) else {
            continue;
        };
        let threshold = if stream.key[0] == "group" {
            GROUP_THRESHOLD
        } else if text(found[0].issuer()?, "kind")? == "root" {
            ROOT_THRESHOLD
        } else {
            DEVICE_THRESHOLD
        };
        if found.len() > 1 || end - now <= chrono::TimeDelta::seconds(threshold) {
            out.push(Plan {
                stream: stream.key.clone(),
                signer: root_signer.clone(),
            });
        }
    }
    let Some(signer) = own(c, s, p)? else {
        return Ok(out);
    };
    let (person, public, scopes) = match &signer {
        Signer_::Original { public, scopes } => (public, public, *scopes),
        Signer_::Device {
            person,
            public,
            scopes,
            ..
        } => (person, public, *scopes),
        _ => return Ok(out),
    };
    for stream in p.streams.values() {
        let kind = stream.key[0].as_str();
        let Some((found, end)) = heads(p, &stream.key) else {
            continue;
        };
        let forked = found.len() > 1;
        if matches!(kind, "person" | "host" | "group") && scopes & 8 == 8 {
            if let Some((_, cap)) = admin_cap(p, &signer) {
                let threshold = if kind == "group" {
                    GROUP_THRESHOLD
                } else {
                    DEVICE_THRESHOLD
                };
                if (forked || end - now <= chrono::TimeDelta::seconds(threshold) && cap > end)
                    && (forked || turn(now, end, threshold, &admin_order(p), public))
                {
                    out.push(Plan {
                        stream: stream.key.clone(),
                        signer: signer.clone(),
                    });
                }
            }
            continue;
        }
        let (host, scope) = match kind {
            "binding" if scopes & 6 != 0 => (stream.key[1].clone(), 6),
            "device" if stream.key[1] == *person && scopes & 4 == 4 => {
                (text(found[0].subject()?, "host_public_key")?.to_owned(), 4)
            }
            _ => continue,
        };
        if text(found[0].subject()?, "person_public_key")? != person {
            continue;
        }
        let lease = format!("{kind}_lease");
        let Some((_, cap)) = device_cap(p, &lease, person, &host) else {
            continue;
        };
        if !forked && (end - now > chrono::TimeDelta::seconds(DEVICE_THRESHOLD) || cap <= end) {
            continue;
        }
        let own_device = matches!(&signer, Signer_::Device { .. });
        let order = if kind == "device" && stream.key[2] == *public && own_device {
            let creator = p.catalog.statements.values().any(|d| {
                d.stream().ok().flatten().as_ref() == Some(&stream.key)
                    && d.sequence().ok() == Some(1)
                    && text(&d.payload, "operation_id").is_ok_and(|op| op == "-")
            });
            if !creator || ranked(p, person, 15, None).len() != 1 {
                continue;
            }
            vec![public.clone()]
        } else {
            owner_order(
                p,
                person,
                scope,
                if kind == "device" {
                    Some(stream.key[2].as_str())
                } else {
                    None
                },
            )
        };
        if forked || turn(now, end, DEVICE_THRESHOLD, &order, public) {
            out.push(Plan {
                stream: stream.key.clone(),
                signer: signer.clone(),
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
    // A compatible renewal fork temporarily makes dependents fail `active`:
    // their parent lookup needs one head. Check each predecessor branch as it
    // stood before resolution. A child dropped by either branch must stay
    // dropped; the resolver cannot revive it by listing it again.
    let mut branch = (heads.len() > 1).then(|| p.clone());
    for other in p.streams.values() {
        if other.key[0] == "root" || other.key == stream {
            continue;
        }
        for id in &other.heads {
            let child = p.catalog.get(id)?;
            if !(lease(&child.kind) || matches!(child.kind.as_str(), "policy" | "group")) {
                continue;
            }
            let active = if let Some(branch) = &mut branch {
                let mut all = true;
                for head in heads {
                    branch
                        .streams
                        .get_mut(stream)
                        .ok_or_else(|| Error::new("proof_required"))?
                        .heads = BTreeSet::from([head.clone()]);
                    if branch.active(id).is_err() {
                        all = false;
                        break;
                    }
                }
                all
            } else {
                p.active(id).is_ok()
            };
            if !active {
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
    let subject = if kind == "group" {
        None
    } else {
        Some(head.subject()?.clone())
    };
    let heads: Vec<String> = stream.heads.iter().cloned().collect();
    let resolves: Vec<String> = if heads.len() > 1 {
        heads.clone()
    } else {
        Vec::new()
    };
    let mut end = now + chrono::TimeDelta::seconds(if kind == "group" { DAY } else { SEVEN_DAYS });
    let (issuer, parents) = match &plan.signer {
        Signer_::Root { .. } => (
            json!({"kind":"root","person_public_key":"-"}),
            BTreeMap::new(),
        ),
        Signer_::Original { public: person, .. } | Signer_::Device { person, .. } => {
            let device = matches!(&plan.signer, Signer_::Device { .. });
            let (mut parents, cap) =
                if matches!(kind.as_str(), "person_lease" | "host_lease" | "group") {
                    let Some(value) = admin_cap(p, &plan.signer) else {
                        return Ok(None);
                    };
                    value
                } else {
                    let host = text(
                        subject.as_ref().ok_or_else(|| Error::new("invalid"))?,
                        "host_public_key",
                    )?;
                    let Some(value) = device_cap(p, &kind, person, host) else {
                        return Ok(None);
                    };
                    value
                };
            end = end.min(cap);
            if kind == "binding_lease" && device {
                if let Signer_::Device { lease, .. } = &plan.signer {
                    parents.insert("issuer_device".into(), lease.clone());
                }
            } else if kind == "device_lease"
                && let Some(kept) = head.parents()?.get("issuer_device")
            {
                parents.insert("issuer_device".into(), kept.clone());
                if !device {
                    let Some((_, cap)) = current(
                        p,
                        &p.catalog
                            .get(kept)?
                            .stream()?
                            .ok_or_else(|| Error::new("invalid"))?,
                    ) else {
                        return Ok(None);
                    };
                    end = end
                        .min(cap)
                        .min(stamp(text(&p.catalog.get(kept)?.payload, "not_after")?)?);
                }
            }
            (
                json!({"kind":if device {"device"} else {"person"},"person_public_key":person}),
                parents,
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
    let sequence = stream
        .maximum
        .checked_add(1)
        .ok_or_else(|| Error::new("version_exhausted"))?;
    let mut payload = json!({"root_state_id":p.root_state_id()?,"operation_id":"-","sequence":sequence,"predecessors":heads,"resolves":resolves,"issuer":issuer,"parents":parents.into_iter().map(|(role,id)|json!({"role":role,"id":id})).collect::<Vec<_>>(),"issued_at":time,"not_before":time,"not_after":format(end)});
    if let Some(subject) = subject {
        payload["subject"] = serde_json::Value::Object(subject);
        payload["retained_statement_ids"] = json!(retained(p, &plan.stream, &stream.heads)?);
    } else {
        let raw = b64(text(&head.payload, "body_base64")?, MAX_PAYLOAD)?;
        let mut body = parse(&raw, MAX_PAYLOAD)?;
        body["version"] = json!(sequence);
        body["defined_at"] = json!(time);
        payload["body_base64"] = json!(encode(&actions::bytes(&body)?));
    }
    let payload = serde_json::to_vec(&payload).map_err(|_| Error::new("internal"))?;
    let context = p.descriptor.context_id();
    let id = super::statement::statement_id(&kind, &context, &payload);
    let body = serde_json::to_vec(
        &json!({"format":1,"kind":kind,"context_id":context,"payload_base64":encode(&payload),"signatures":[{"role":"issuer","public_key":plan.signer.public(),"format":if plan.signer.seed().is_some() {"ed25519"} else {"sshsig"},"signature":"-"}]}),
    ).map_err(|_| Error::new("internal"))?;
    Ok(Some((kind, body, id)))
}
/// Sign outside the database lock, then recheck the exact plan and draft in the
/// writer transaction before admission. An SSH agent never runs under a lock.
fn apply(store: &Store, network: &str, plan: &Plan) -> Result<bool> {
    let unsigned = {
        let c = store.connection().map_err(|_| Error::new("internal"))?;
        let s = Snapshot::load(&c, network, &store.identity().public_key)?;
        let p = s.project(&controls::local_decision_time()?)?;
        require(plans(&c, &s, &p)?.contains(plan), "review_required")?;
        draft(&p, plan)?
    };
    let Some((kind, template, id)) = unsigned else {
        return Ok(false);
    };
    let message = signature_message(&id, "issuer", plan.signer.public());
    let signature = if let Some(seed) = plan.signer.seed() {
        encode(&SigningKey::from_bytes(&seed).sign(&message).to_bytes())
    } else {
        let key = b64(plan.signer.public(), 32)?
            .try_into()
            .map_err(|_| Error::new("invalid"))?;
        let signer = store
            .renewal_signer(key)
            .map_err(|_| Error::new("signer_unavailable"))?;
        let message = std::str::from_utf8(&message).map_err(|_| Error::new("invalid"))?;
        signer
            .sign(&message.split('\n').collect::<Vec<_>>())
            .map_err(|_| Error::new("signer_unavailable"))?
    };
    let mut body = parse(&template, MAX_OBJECT)?;
    body["signatures"][0]["signature"] = json!(signature);
    let body = actions::bytes(&body)?;
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let mut tx = c.transaction().map_err(db)?;
    let s = Snapshot::load(&tx, network, &store.identity().public_key)?;
    let p = s.project(&controls::local_decision_time()?)?;
    require(plans(&tx, &s, &p)?.contains(plan), "review_required")?;
    // Keep the original decision time while rechecking current authority: a
    // second ticking between capture and signing must not change signed bytes.
    let mut fixed = p.clone();
    let original = parse(
        &b64(
            text(object(&parse(&template, MAX_OBJECT)?)?, "payload_base64")?,
            MAX_PAYLOAD,
        )?,
        MAX_PAYLOAD,
    )?;
    fixed.decision_time = text(object(&original)?, "issued_at")?.into();
    require(
        draft(&fixed, plan)?.is_some_and(|(k, raw, i)| k == kind && raw == template && i == id),
        "review_required",
    )?;
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
    let plans = {
        let c = store.connection().map_err(|_| Error::new("internal"))?;
        let s = Snapshot::load(&c, network, &store.identity().public_key)?;
        let p = s.project(&controls::local_decision_time()?)?;
        plans(&c, &s, &p)?
    };
    Ok(plans.iter().any(|plan| plan.signer.available(store)))
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
            plans(&c, &s, &p)?.into_iter().find(|plan| {
                !failed.contains(&(plan.stream.clone(), plan.signer.public().to_owned()))
            })
        };
        let Some(plan) = next else {
            return Ok(());
        };
        if !matches!(apply(store, network, &plan), Ok(true)) {
            failed.insert((plan.stream, plan.signer.public().to_owned()));
        }
    }
    Ok(())
}
