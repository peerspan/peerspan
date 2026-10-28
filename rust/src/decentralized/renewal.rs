//! Selected-provider policy renewal and retained edit reapplication. Public
//! authority remains in the ordinary typed action controller and final writer.
use super::{
    actions, codec::*, controls, edits, intents::Intent, provider::Resolved, state::Projection,
    statement::Statement, storage::Snapshot,
};
use crate::{
    policy::{Content, PolicyBody},
    store::Store,
};
use chrono::TimeDelta;
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

fn db(_: rusqlite::Error) -> Error {
    Error::new("internal")
}
fn host_id(host: &str) -> Result<String> {
    Ok(format!("host_{}", hash(&b64(host, 32)?)))
}
fn own_seq(body: &PolicyBody, host: &str) -> u64 {
    body.edits()
        .iter()
        .find(|e| e.host == host)
        .map(|e| e.seq)
        .unwrap_or(0)
}
fn same_body(a: &PolicyBody, b: &PolicyBody) -> Result<bool> {
    let mut a = serde_json::to_value(a).map_err(|_| Error::new("internal"))?;
    let mut b = serde_json::to_value(b).map_err(|_| Error::new("internal"))?;
    for v in [&mut a, &mut b] {
        for field in ["version", "issued_at", "valid_until"] {
            v.as_object_mut()
                .ok_or_else(|| Error::new("invalid"))?
                .remove(field);
        }
    }
    Ok(a == b)
}
fn same_content(a: &Content, b: &Content) -> bool {
    let mut a = a.clone();
    let mut b = b.clone();
    a.dedup_rules();
    b.dedup_rules();
    a.trusted_hosts.sort();
    b.trusted_hosts.sort();
    a == b
}
pub(super) fn head<'a>(p: &'a Projection, person: &str) -> Result<Option<&'a Statement>> {
    let Some(stream) = p.streams.get(&vec!["policy".into(), person.into()]) else {
        return Ok(None);
    };
    if stream.heads.len() > 1 {
        let mut error = Error::new("state_conflict");
        error.required_ids = stream.heads.clone();
        return Err(error);
    }
    if stream.heads.is_empty() {
        return Ok(None);
    }
    let statement = p.catalog.get(
        stream
            .heads
            .first()
            .ok_or_else(|| Error::new("proof_required"))?,
    )?;
    p.proof_complete(&statement.id)?;
    Ok(Some(statement))
}
pub(super) struct Reapplied {
    pub(super) body: PolicyBody,
    dropped: BTreeMap<u64, Vec<String>>,
    last: u64,
    unsettled: bool,
    pub(super) sequences: Vec<u64>,
}
pub(super) fn reapplied(
    c: &Connection,
    p: &Projection,
    person: &str,
    host: &str,
    current: &PolicyBody,
) -> Result<Reapplied> {
    let mut baseline = current.content();
    baseline.dedup_rules();
    let mut frozen = Vec::new();
    let mut last = own_seq(current, host);
    for edit in edits::read(c, p, person)?
        .into_iter()
        .filter(|e| e.state == "unsettled")
    {
        let signed = edits::check_reference(p, &edit.signed, person)?
            .ok_or_else(|| Error::new("state_conflict"))?;
        let start = edits::check_reference(p, &edit.start, person)?
            .map(|s| edits::policy(&s))
            .transpose()?
            .map(|p| p.content())
            .unwrap_or_default();
        let signed = edits::policy(&signed)?.content();
        let skip = edits::dropped_groups(&start, &signed, &edit.dropped)?;
        frozen.push((edit.seq, start, signed, skip));
        last = last.max(edit.seq);
    }
    // Every frozen row consumes at least one merge step; history has no separate cap.
    require(frozen.len() <= MAX_ITEMS * 16, "quota_exceeded")?;
    if let Some((highest, _, _, _)) = frozen.last() {
        require(own_seq(current, host) <= *highest, "state_conflict")?;
        last = *highest;
    }
    let original: Vec<_> = frozen.iter().map(|(_, _, _, skip)| skip.clone()).collect();
    let mut work = 0usize;
    let content = loop {
        let mut content = baseline.clone();
        let mut changed = false;
        for (_, start, signed, skip) in &mut frozen {
            work += 1;
            require(work <= MAX_ITEMS * 16, "quota_exceeded")?;
            let (next, new) = edits::merge_delta(&content, start, signed, skip)?;
            content = next;
            for marker in new {
                changed |= skip.insert(marker);
            }
        }
        if !changed {
            break content;
        }
    };
    let dropped = frozen
        .iter()
        .zip(original)
        .map(|((seq, _, _, skip), old)| (*seq, skip.difference(&old).cloned().collect()))
        .collect();
    let sequences = frozen.iter().map(|(seq, _, _, _)| *seq).collect();
    let unsettled = !frozen.is_empty();
    let mut body = current.clone();
    if unsettled {
        body.rules = content.rules;
        body.capability_rules = Some(content.capability_rules);
        body.trusted_hosts = Some(content.trusted_hosts);
        body.edits = Some(body.edits_with(host, last));
    }
    Ok(Reapplied {
        body,
        dropped,
        last,
        unsettled,
        sequences,
    })
}
/// This is not a bypass flag: the already validated existing unsettled seq is
/// checked against exactly the frozen deltas and current selected body.
pub(super) fn check_reapplication(
    c: &Connection,
    p: &Projection,
    person: &str,
    host: &str,
    statement: &Statement,
    seq: u64,
) -> Result<()> {
    let current = head(p, person)?.ok_or_else(|| Error::new("edit_conflict"))?;
    p.proof_complete(&current.id)?;
    let expected = reapplied(c, p, person, &host_id(host)?, &edits::policy(current)?)?;
    require(
        expected.unsettled
            && expected.last == seq
            && same_body(&expected.body, &edits::policy(statement)?)?,
        "edit_conflict",
    )
}
/// The storage hook executes after projection persistence in the same writer
/// savepoint. It never settles a reserved/unsigned edit or changes frozen refs.
pub(super) fn reconcile(c: &Connection, before: &Snapshot, after: &Projection) -> Result<()> {
    let person = &before.network.own_identity.person_public_key;
    if person == "-" {
        return Ok(());
    }
    let stream = vec!["policy".into(), person.clone()];
    let old_heads = before
        .prior
        .maxima
        .get(&stream)
        .map(|s| s.head_ids.clone())
        .unwrap_or_default();
    let new_heads = after
        .streams
        .get(&stream)
        .map(|s| s.heads.clone())
        .unwrap_or_default();
    if old_heads == new_heads {
        return Ok(());
    }
    let host = host_id(&before.network.own_identity.host_public_key)?;
    let current = head(after, person).ok().flatten();
    let reflected = current
        .map(edits::policy)
        .transpose()?
        .map(|p| own_seq(&p, &host))
        .unwrap_or(0);
    let dropped =
        if let (Ok(previous), Some(current)) = (before.project(&after.decision_time), current) {
            if let Some(old) = head(&previous, person).ok().flatten() {
                let expected = reapplied(c, after, person, &host, &edits::policy(old)?)?;
                if expected.unsettled && same_body(&expected.body, &edits::policy(current)?)? {
                    expected.dropped
                } else {
                    BTreeMap::new()
                }
            } else {
                BTreeMap::new()
            }
        } else {
            BTreeMap::new()
        };
    for mut edit in edits::read(c, after, person)? {
        if !matches!(edit.state.as_str(), "settled" | "unsettled") {
            continue;
        }
        let next = if edit.seq <= reflected {
            "settled"
        } else {
            "unsettled"
        };
        let mut changed = edit.state != next;
        if changed {
            edit.state = next.into();
            edit.unsettled_at = if next == "unsettled" {
                after.decision_time.clone()
            } else {
                "-".into()
            };
        }
        if let Some(keys) = dropped.get(&edit.seq).filter(|k| !k.is_empty())
            && edits::append_dropped(after, person, &mut edit, keys)?
        {
            edit.dropped_at = after.decision_time.clone();
            changed = true;
        }
        if changed {
            edits::save(c, after, person, &edit)?;
        }
    }
    Ok(())
}
fn cap(
    p: &Projection,
    id: &str,
    seen: &mut BTreeSet<String>,
    depth: usize,
    until: &mut String,
) -> Result<()> {
    require(depth <= 32, "quota_exceeded")?;
    if !seen.insert(id.into()) {
        return Ok(());
    }
    let s = p.catalog.get(id)?;
    if let Some(after) = s.payload.get("not_after").and_then(Value::as_str) {
        *until = until.clone().min(after.into());
    }
    for (role, parent) in s.parents()? {
        if !s.uncapped_parent(&role) {
            cap(p, &parent, seen, depth + 1, until)?;
        }
    }
    Ok(())
}
pub(super) fn payload(p: &Projection, provider: &Resolved, body: PolicyBody) -> Result<Value> {
    let person = text(&provider.actor, "person_public_key")?;
    let person_stream = vec!["person".into(), person.into()];
    let (person_lease, _) = p.current_statement(&person_stream)?;
    let stream = vec!["policy".into(), person.into()];
    let row = p
        .streams
        .get(&stream)
        .ok_or_else(|| Error::new("proof_required"))?;
    require(row.heads.len() == 1, "state_conflict")?;
    let next = row
        .maximum
        .checked_add(1)
        .ok_or_else(|| Error::new("version_exhausted"))?;
    let mut parents = BTreeMap::from([("issuer_person".to_owned(), person_lease.id.clone())]);
    if provider.provider.kind == "device" {
        parents.insert("issuer_device".into(), provider.provider.lease_id.clone());
    }
    let mut until = (stamp(&p.decision_time)? + TimeDelta::hours(24))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let mut seen = BTreeSet::new();
    for parent in parents.values() {
        cap(p, parent, &mut seen, 0, &mut until)?;
        let (_, deadline) = p.current_statement(
            &p.catalog
                .get(parent)?
                .stream()?
                .ok_or_else(|| Error::new("invalid"))?,
        )?;
        until = until.min(deadline);
    }
    require(until > p.decision_time, "authority_expired")?;
    let mut body = body;
    body.version = next;
    body.issued_at = p.decision_time.clone();
    body.valid_until = until.clone();
    let encoded = serde_json::to_vec(&body).map_err(|_| Error::new("internal"))?;
    Ok(
        json!({"root_state_id":p.root_state_id()?,"operation_id":"-","sequence":next,"predecessors":row.heads,"resolves":[],"issuer":{"kind":if provider.provider.kind=="device"{"device"}else{"person"},"person_public_key":person},"parents":parents.into_iter().map(|(role,id)|json!({"role":role,"id":id})).collect::<Vec<_>>(),"issued_at":p.decision_time,"not_before":p.decision_time,"not_after":until,"body_base64":encode(&encoded)}),
    )
}
fn matching_provider(a: &super::intents::Provider, b: &super::intents::Provider) -> bool {
    a.kind == b.kind
        && a.signer_public_key == b.signer_public_key
        && a.signature_format == b.signature_format
        && a.lease_id == b.lease_id
}
fn close_reflected(store: &Store, network: &str, expected_revision: &str) -> Result<()> {
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let s = Snapshot::load(&tx, network, &store.identity().public_key)?;
    require(s.revision == expected_revision, "state_conflict")?;
    let p = s.project(&controls::local_decision_time()?)?;
    let provider = Resolved::resolve(&tx, &s, &p, "auto", "auto", "policy")?;
    let public = provider.public(&p, &store.identity().public_key, false)?;
    require(num(object(&public)?, "scopes")? & 1 == 1, "forbidden")?;
    let person = text(&provider.actor, "person_public_key")?;
    let current = head(&p, person)?.ok_or_else(|| Error::new("proof_required"))?;
    p.active(&current.id)?;
    let merged = reapplied(
        &tx,
        &p,
        person,
        &store.identity().id,
        &edits::policy(current)?,
    )?;
    require(
        merged.unsettled
            && same_content(&merged.body.content(), &edits::policy(current)?.content()),
        "state_conflict",
    )?;
    let latest = s.project(&controls::local_decision_time()?)?;
    let rechecked = Resolved::resolve(&tx, &s, &latest, "auto", "auto", "policy")?;
    require(
        matching_provider(&provider.provider, &rechecked.provider),
        "state_conflict",
    )?;
    let public = rechecked.public(&latest, &store.identity().public_key, false)?;
    require(num(object(&public)?, "scopes")? & 1 == 1, "forbidden")?;
    latest.current_statement(&["policy".into(), person.into()])?;
    for mut edit in edits::read(&tx, &latest, person)?
        .into_iter()
        .filter(|e| e.state == "unsettled")
    {
        edit.state = "closed".into();
        edit.closed_at = latest.decision_time.clone();
        edit.unsettled_at = "-".into();
        if let Some(keys) = merged.dropped.get(&edit.seq).filter(|k| !k.is_empty())
            && edits::append_dropped(&latest, person, &mut edit, keys)?
        {
            edit.dropped_at = latest.decision_time.clone();
        }
        edits::save(&tx, &latest, person, &edit)?;
    }
    actions::remember_clock(&tx, network, &latest.decision_time)?;
    tx.commit().map_err(db)
}
fn renew(store: &Store, network: &str) -> Result<()> {
    let (request, provider, revision, close) = 'capture: {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        let s = Snapshot::load(&tx, network, &store.identity().public_key)?;
        require(
            !s.migrations
                .iter()
                .any(|m| m.fenced && m.state != "adopted"),
            "migration_pending",
        )?;
        let p = s.project(&controls::local_decision_time()?)?;
        let provider = Resolved::resolve(&tx, &s, &p, "auto", "auto", "policy")?;
        let public = provider.public(&p, &store.identity().public_key, false)?;
        require(num(object(&public)?, "scopes")? & 1 == 1, "forbidden")?;
        let person = text(&provider.actor, "person_public_key")?;
        let Some(current) = head(&p, person)? else {
            return Ok(());
        };
        let body = edits::policy(current)?;
        let merged = reapplied(&tx, &p, person, &store.identity().id, &body)?;
        let changed = !same_content(&merged.body.content(), &body.content());
        let closing = merged.unsettled && !changed;
        if closing {
            break 'capture (Value::Null, provider, s.revision, true);
        }
        let decision = stamp(&p.decision_time)?;
        let expiry = stamp(&body.valid_until)?;
        let issued = stamp(&body.issued_at)?;
        // A 24-hour policy renews with 8 hours left (DEC-Q24); a shorter one
        // with a third of its lifetime left.
        let threshold = ((expiry - issued) / 3).min(TimeDelta::seconds(DAY_THRESHOLD));
        if !closing && !changed && (decision >= expiry || expiry - decision > threshold) {
            return Ok(());
        }
        let mut q=tx.prepare("SELECT intent_id FROM dec_intents WHERE network_id=?1 AND kind='action' ORDER BY intent_id").map_err(db)?;
        let intent_ids = q
            .query_map([network], |r| r.get::<_, String>(0))
            .map_err(db)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db)?;
        let mut fixed = None;
        for id in intent_ids {
            let i = Intent::load(&tx, &id)?;
            if i.record.approved
                && i.record.terminal == "-"
                && i.record.person_public_key == person
                && matching_provider(&i.record.provider, &provider.provider)
                && i.record.templates.len() == 1
                && i.record.templates[0].object_type == "policy"
            {
                // Validate retained private bytes before classifying any
                // current authority failure as stale. Never skip malformed
                // candidate state, even when its signing window has elapsed.
                actions::validate(&i, &s.descriptor)?;
                let assembled = i.assembled(&s.descriptor)?;
                let statement = assembled[0].typed();
                check(i.record.host_public_key == store.identity().public_key)?;
                let age = decision - stamp(statement.issued_at()?)?;
                check(age >= TimeDelta::zero())?;
                let stream = p
                    .streams
                    .get(&vec!["policy".into(), person.into()])
                    .ok_or_else(|| Error::new("proof_required"))?;
                if age > TimeDelta::seconds(300)
                    || text(&statement.payload, "root_state_id")? != p.root_state_id()?
                    || statement.sequence()? <= stream.maximum
                    || ids(&statement.payload, "predecessors", "ds_")?
                        .into_iter()
                        .collect::<BTreeSet<_>>()
                        != stream.heads
                {
                    continue;
                }
                match actions::revalidate(&tx, &s, &p, &i) {
                    Ok(_) => {}
                    Err(e)
                        if matches!(
                            e.code,
                            "expired"
                                | "authority_expired"
                                | "not_yet_valid"
                                | "forbidden"
                                | "proof_required"
                                | "state_conflict"
                                | "edit_conflict"
                                | "device_revoked"
                        ) =>
                    {
                        continue;
                    }
                    Err(e) => return Err(e),
                }
                fixed = Some(statement.payload_bytes.clone());
                break;
            }
        }
        let payload = if let Some(fixed) = fixed {
            fixed
        } else {
            serde_json::to_vec(&payload(&p, &provider, merged.body)?)
                .map_err(|_| Error::new("internal"))?
        };
        (
            json!({"kind":"policy","provider_id":"auto","signature_format":"auto","payload_base64":encode(&payload),"approve":true}),
            provider,
            s.revision,
            closing,
        )
    };
    // Agent I/O and durable action barriers run after dropping the read TX.
    provider.available(store)?;
    if close {
        return close_reflected(store, network, &revision);
    }
    let outcome = actions::prepare(store, network, object(&request)?, false)?;
    let value = parse(&outcome, 32 << 20)?;
    require(
        value.get("committed").and_then(Value::as_bool) == Some(true),
        "signer_unavailable",
    )
}
fn cleanup(store: &Store, network: &str) -> Result<()> {
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let s = Snapshot::load(&tx, network, &store.identity().public_key)?;
    let person = &s.network.own_identity.person_public_key;
    if person == "-" {
        return Ok(());
    }
    let p = s.project(&controls::local_decision_time()?)?;
    let rows = edits::read(&tx, &p, person)?;
    let largest: i64 = tx
        .query_row(
            "SELECT COALESCE(MAX(seq),0) FROM policy_edits WHERE network_id=?1 AND person_id=?2",
            params![network, crate::persons::person_id(&b64(person, 32)?)],
            |r| r.get(0),
        )
        .map_err(db)?;
    let mut retired = Vec::new();
    for e in rows {
        if Some(largest) == i64::try_from(e.seq).ok() {
            continue;
        }
        let (at, age) = match e.state.as_str() {
            "reserved" => (&e.reserved_at, TimeDelta::minutes(10)),
            "closed" => (&e.closed_at, TimeDelta::days(7)),
            _ => continue,
        };
        if stamp(&p.decision_time)? - stamp(at)? <= age
            || e.dropped_at != "-"
                && stamp(&p.decision_time)? - stamp(&e.dropped_at)? <= TimeDelta::days(7)
        {
            continue;
        }
        retired.push(e.seq);
    }
    if retired.is_empty() {
        return Ok(());
    }
    let latest = s.project(&controls::local_decision_time()?)?;
    for seq in retired {
        tx.execute(
            "DELETE FROM policy_edits WHERE network_id=?1 AND person_id=?2 AND seq=?3",
            params![
                network,
                crate::persons::person_id(&b64(person, 32)?),
                i64::try_from(seq).map_err(|_| Error::new("invalid"))?
            ],
        )
        .map_err(db)?;
    }
    actions::remember_clock(&tx, network, &latest.decision_time)?;
    tx.commit().map_err(db)
}
/// Renewal thresholds (spec 7.1, DEC-Q12, DEC-Q24).
pub(crate) const SEVEN_DAY_THRESHOLD: i64 = 172_800;
pub(crate) const DAY_THRESHOLD: i64 = 28_800;
fn left(p: &Projection, until: &str) -> Result<TimeDelta> {
    Ok(stamp(until)? - stamp(&p.decision_time)?)
}
/// Status items for renewal (spec 7.1 warnings, 7.3 countdown), in the order
/// of spec 16: `network_root_unreachable`, then
/// `person_device_signer_unavailable`.
pub(crate) fn attention(
    s: &Snapshot,
    p: &Projection,
    network: &str,
) -> Result<Vec<(String, String, String, String)>> {
    let mut out = Vec::new();
    // The countdown: the latest deadline among current admin grants and
    // root-signed person and host grants (DEC-Q12).
    let mut latest: Option<String> = None;
    for stream in p.streams.values() {
        if !matches!(stream.key[0].as_str(), "admin" | "person" | "host") {
            continue;
        }
        let Ok((statement, _)) = p.current_statement(&stream.key) else {
            continue;
        };
        if statement.kind != "admin_lease" && text(statement.issuer()?, "kind")? != "root" {
            continue;
        }
        let until = text(&statement.payload, "not_after")?.to_owned();
        if latest.as_ref().is_none_or(|l| *l < until) {
            latest = Some(until);
        }
    }
    if let Some(latest) = latest {
        let seconds = left(p, &latest)?.num_seconds();
        let days = (seconds + 86_399) / 86_400;
        if seconds > 0 && days <= 3 {
            out.push((
                "network_root_unreachable".into(),
                network.into(),
                format!(
                    "root unreachable: network stops in {days} days; root-signed grants end at {latest} unless the root host renews them"
                ),
                format!("peerspan network sync {network}"),
            ));
        }
    }
    // This host's own device grant inside its threshold with no renewer.
    let own = &s.network.own_identity;
    if let Some(selected) = s.selection.as_ref().filter(|s| s.kind == "device") {
        let person = &selected.person_key;
        let stream = vec!["device".into(), person.clone(), selected.device_key.clone()];
        if let Ok((device, deadline)) = p.current_statement(&stream)
            && left(p, &deadline)?.num_seconds() <= SEVEN_DAY_THRESHOLD
        {
            let mut current = 0;
            let mut renewers = 0;
            for other in p
                .streams
                .values()
                .filter(|s| s.key[0] == "device" && s.key[1] == *person)
            {
                let Ok((grant, _)) = p.current_statement(&other.key) else {
                    continue;
                };
                current += 1;
                if other.key[2] != selected.device_key && num(grant.subject()?, "scopes")? & 4 == 4
                {
                    renewers += 1;
                }
            }
            let creator = text(&device.payload, "operation_id")? == "-"
                && !device.parents()?.contains_key("issuer_device");
            if renewers == 0 && !(creator && current == 1) {
                out.push((
                    "person_device_signer_unavailable".into(),
                    network.into(),
                    format!(
                        "no host able to renew this host's device grant {} is reachable; it ends at {deadline}",
                        device.id
                    ),
                    format!(
                        "peerspan link --network {network} --expect-person {}",
                        own.person_public_key
                    ),
                ));
            }
        }
    }
    Ok(out)
}
pub(crate) async fn worker(store: Arc<Store>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    let mut attempted = BTreeMap::<String, std::time::Instant>::new();
    tick.tick().await;
    loop {
        tokio::select! {_ = shutdown.changed()=>break,_=tick.tick()=>{}}
        let s = store.clone();
        let ids=tokio::task::spawn_blocking(move||->Result<Vec<String>>{let c=s.connection().map_err(|_|Error::new("internal"))?;let mut q=c.prepare("SELECT id FROM networks WHERE json_extract(record,'$.mode')='decentralized' ORDER BY id").map_err(db)?;q.query_map([],|r|r.get(0)).map_err(db)?.collect::<std::result::Result<_,_>>().map_err(db)}).await;
        if let Ok(Ok(ids)) = ids {
            for id in ids {
                if *shutdown.borrow() {
                    return;
                }
                let s = store.clone();
                let network = id.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    let _ = renew(&s, &network);
                    let _ = cleanup(&s, &network);
                })
                .await;
                // Grants (spec 7.1): sync with known peers (30-second bound)
                // before signing, so already renewed grants and unknown
                // children are seen; at most one attempt per 30 seconds.
                let s = store.clone();
                let network = id.clone();
                let due =
                    tokio::task::spawn_blocking(move || super::grant_renewal::due(&s, &network))
                        .await;
                if !matches!(due, Ok(Ok(true)))
                    || attempted.get(&id).is_some_and(|at: &std::time::Instant| {
                        at.elapsed() < Duration::from_secs(30)
                    })
                {
                    continue;
                }
                attempted.insert(id.clone(), std::time::Instant::now());
                let _ = tokio::time::timeout(
                    Duration::from_secs(30),
                    super::peer::sync(store.clone(), &id),
                )
                .await;
                let s = store.clone();
                let _ =
                    tokio::task::spawn_blocking(move || super::grant_renewal::renew(&s, &id)).await;
            }
        }
    }
}
