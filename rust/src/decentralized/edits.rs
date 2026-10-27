//! DEC policy reservations retain exact native proof references in the existing
//! edit table. They never manufacture a legacy signed policy or grant access.
use super::{
    catalog::Catalog,
    codec::*,
    provider::Resolved,
    state::Projection,
    statement::{Statement, access_body},
    storage::Snapshot,
};
use crate::store::Store;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Edit {
    pub(super) format: u64,
    pub(super) mode: String,
    pub(super) context_id: String,
    pub(super) seq: u64,
    pub(super) state: String,
    pub(super) start: Value,
    pub(super) signed: Value,
    pub(super) signed_version: u64,
    pub(super) dropped: Vec<String>,
    pub(super) reserved_at: String,
    pub(super) signed_at: String,
    pub(super) unsettled_at: String,
    pub(super) closed_at: String,
    pub(super) dropped_at: String,
}
fn db(_: rusqlite::Error) -> Error {
    Error::new("internal")
}
fn pid(person: &str) -> Result<String> {
    Ok(crate::persons::person_id(&b64(person, 32)?))
}
fn host_id(host: &str) -> Result<String> {
    Ok(format!("host_{}", hash(&b64(host, 32)?)))
}
fn bytes(v: &Value) -> Result<Vec<u8>> {
    serde_json::to_vec(v).map_err(|_| Error::new("internal"))
}
fn reference(p: &Projection, s: &Statement) -> Result<Value> {
    require(
        s.kind == "policy" && p.admitted.contains(&s.id),
        "forbidden",
    )?;
    let proof = p
        .catalog
        .statement_proofs
        .get(&s.id)
        .and_then(|ids| ids.first())
        .ok_or_else(|| Error::missing(&s.id))?;
    Ok(
        json!({"statement_id":s.id,"proof_id":proof,"statement_base64":encode(&s.body),"body_base64":text(&s.payload,"body_base64")?}),
    )
}
pub(super) fn check_reference(
    p: &Projection,
    value: &Value,
    person: &str,
) -> Result<Option<Statement>> {
    if value == "-" {
        return Ok(None);
    }
    let o = object(value)?;
    fields(o, "statement_id proof_id statement_base64 body_base64")?;
    let statement = Statement::read(
        &p.descriptor,
        &b64(text(o, "statement_base64")?, MAX_OBJECT)?,
    )?;
    check(
        statement.kind == "policy"
            && statement.id == text(o, "statement_id")?
            && text(&statement.payload, "body_base64")? == text(o, "body_base64")?,
    )?;
    let body = access_body(&statement.payload)?;
    check(text(&body, "person_public_key")? == person)?;
    let proof_id = text(o, "proof_id")?;
    let proof = p
        .catalog
        .proofs
        .get(proof_id)
        .ok_or_else(|| Error::missing(proof_id))?;
    let single = json!({"format":1,"context_id":p.descriptor.context_id(),"objects":[{"id":proof.id,"kind":proof.kind,"body_base64":encode(&proof.body)}]});
    let source = Catalog::read(&p.descriptor, &bytes(&single)?)?;
    check(
        source
            .aliases
            .get(&statement.id)
            .is_some_and(|aliases| aliases.iter().any(|s| s.body == statement.body)),
    )?;
    require(p.admitted.contains(&statement.id), "forbidden")?;
    p.proof_complete(&statement.id)?;
    Ok(Some(statement))
}
fn addition_keys(
    before: &crate::policy::Content,
    after: &crate::policy::Content,
) -> BTreeMap<String, String> {
    let mut keys = BTreeMap::new();
    let mut add = |canonical: String, alternate: Option<String>| {
        keys.insert(canonical.clone(), canonical.clone());
        if let Some(alternate) = alternate {
            keys.insert(alternate, canonical);
        }
    };
    for rule in &after.rules {
        let old = before.rules.iter().find(|r| r.same_key(rule));
        if old.is_none() {
            add(format!("rule {}", rule.agent), None);
        }
        for principal in &rule.principals {
            if old.is_none_or(|r| !r.principals.contains(principal)) {
                add(
                    format!("principal {principal} in rule {}", rule.agent),
                    Some(format!("principal {principal} of rule {}", rule.agent)),
                );
            }
        }
    }
    for rule in &after.capability_rules {
        let old = before
            .capability_rules
            .iter()
            .find(|r| r.capability == rule.capability && r.host == rule.host);
        if old.is_none() {
            add(
                format!(
                    "{} {}",
                    if rule.principals.is_empty() {
                        "claim"
                    } else {
                        "capability rule"
                    },
                    rule.capability
                ),
                None,
            );
        }
        for principal in &rule.principals {
            if old.is_none_or(|r| !r.principals.contains(principal)) {
                add(
                    format!(
                        "principal {principal} in capability rule {}",
                        rule.capability
                    ),
                    Some(format!(
                        "principal {principal} of capability rule {}",
                        rule.capability
                    )),
                );
            }
        }
    }
    keys
}
pub(super) fn dropped_groups(
    before: &crate::policy::Content,
    after: &crate::policy::Content,
    dropped: &[String],
) -> Result<BTreeSet<String>> {
    let aliases = addition_keys(before, after);
    let mut groups = BTreeSet::new();
    for key in dropped {
        let group = aliases
            .get(key)
            .ok_or_else(|| Error::new("state_conflict"))?;
        require(groups.insert(group.clone()), "state_conflict")?;
    }
    Ok(groups)
}
/// Filter only this frozen delta's additions, leaving independently selected
/// baseline grants intact. The legacy merger and its stored keys stay unchanged.
pub(super) fn merge_delta(
    current: &crate::policy::Content,
    before: &crate::policy::Content,
    after: &crate::policy::Content,
    skip: &BTreeSet<String>,
) -> Result<(crate::policy::Content, BTreeSet<String>)> {
    let aliases = addition_keys(before, after);
    require(
        skip.iter().all(|k| aliases.get(k) == Some(k)),
        "state_conflict",
    )?;
    let mut filtered = after.clone();
    let mut groups = BTreeSet::new();
    filtered.rules.retain_mut(|rule| {
        let old = before.rules.iter().find(|r| r.same_key(rule));
        if old.is_none() && skip.contains(&format!("rule {}", rule.agent)) {
            return false;
        }
        rule.principals.retain(|principal| {
            old.is_some_and(|r| r.principals.contains(principal))
                || !skip.contains(&format!("principal {principal} in rule {}", rule.agent))
        });
        true
    });
    filtered.capability_rules.retain_mut(|rule| {
        let old = before
            .capability_rules
            .iter()
            .find(|r| r.capability == rule.capability && r.host == rule.host);
        let marker = format!(
            "{} {}",
            if rule.principals.is_empty() {
                "claim"
            } else {
                "capability rule"
            },
            rule.capability
        );
        if old.is_none() && skip.contains(&marker) {
            return false;
        }
        if old.is_none()
            && current
                .capability_rules
                .iter()
                .any(|r| r.capability == rule.capability && r.host != rule.host)
        {
            groups.insert(marker);
            return false;
        }
        rule.principals.retain(|principal| {
            old.is_some_and(|r| r.principals.contains(principal))
                || !skip.contains(&format!(
                    "principal {principal} in capability rule {}",
                    rule.capability
                ))
        });
        true
    });
    let (content, dropped) = crate::policy_edit::merge(current, before, &filtered, &[], true);
    for key in dropped {
        groups.insert(
            aliases
                .get(&key)
                .ok_or_else(|| Error::new("state_conflict"))?
                .clone(),
        );
    }
    Ok((content, groups))
}
pub(super) fn append_dropped(
    p: &Projection,
    person: &str,
    edit: &mut Edit,
    added: &[String],
) -> Result<bool> {
    let signed =
        check_reference(p, &edit.signed, person)?.ok_or_else(|| Error::new("state_conflict"))?;
    let before = check_reference(p, &edit.start, person)?
        .map(|s| policy(&s))
        .transpose()?
        .map(|p| p.content())
        .unwrap_or_default();
    let after = policy(&signed)?.content();
    let mut represented = dropped_groups(&before, &after, &edit.dropped)?;
    let aliases = addition_keys(&before, &after);
    let mut changed = false;
    for key in added {
        require(aliases.get(key) == Some(key), "state_conflict")?;
        if represented.insert(key.clone()) {
            edit.dropped.push(key.clone());
            changed = true;
        }
    }
    edit.dropped.sort();
    Ok(changed)
}
pub(super) fn read(connection: &Connection, p: &Projection, person: &str) -> Result<Vec<Edit>> {
    let mut query = connection
        .prepare(
            "SELECT seq,record FROM policy_edits WHERE network_id=?1 AND person_id=?2 ORDER BY seq",
        )
        .map_err(db)?;
    let rows = query
        .query_map(
            rusqlite::params![p.descriptor.network_id, pid(person)?],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
        )
        .map_err(db)?;
    let mut out = Vec::new();
    for row in rows {
        let (seq, raw) = row.map_err(db)?;
        let v = parse(raw.as_bytes(), 32 << 20)?;
        if v.get("mode").is_none() {
            // Migration preserves old edit history as-is. It never supplies a
            // native proof or authority; its counter still reserves its place.
            let old: crate::policy_edit::EditRecord =
                serde_json::from_value(v).map_err(|_| Error::new("state_conflict"))?;
            check(i64::try_from(old.seq).ok() == Some(seq) && seq > 0)?;
            continue;
        }
        let e: Edit = serde_json::from_value(v).map_err(|_| Error::new("state_conflict"))?;
        check(
            e.format == 2
                && e.mode == "decentralized"
                && e.context_id == p.descriptor.context_id()
                && e.seq > 0
                && e.seq <= i64::MAX as u64
                && i64::try_from(e.seq).ok() == Some(seq),
        )?;
        stamp(&e.reserved_at)?;
        let start = check_reference(p, &e.start, person)?;
        let signed = check_reference(p, &e.signed, person)?;
        if let Some(s) = &signed {
            check(s.sequence()? == e.signed_version && e.signed_version > 0)?;
            stamp(&e.signed_at)?;
            check(e.reserved_at <= e.signed_at)?;
        } else {
            check(e.signed_version == 0 && e.signed_at == "-")?;
        }
        match e.state.as_str() {
            "reserved" => check(
                signed.is_none()
                    && e.unsettled_at == "-"
                    && e.closed_at == "-"
                    && e.dropped.is_empty()
                    && e.dropped_at == "-",
            )?,
            "settled" => check(signed.is_some() && e.unsettled_at == "-" && e.closed_at == "-")?,
            "unsettled" => {
                check(signed.is_some() && e.closed_at == "-")?;
                stamp(&e.unsettled_at)?;
                check(e.unsettled_at >= e.signed_at)?;
            }
            "closed" => {
                check(signed.is_some() && e.unsettled_at == "-")?;
                stamp(&e.closed_at)?;
                check(e.closed_at >= e.signed_at)?;
            }
            _ => return Err(Error::new("state_conflict")),
        }
        check(e.dropped.windows(2).all(|w| w[0] < w[1]))?;
        if e.dropped.is_empty() {
            check(e.dropped_at == "-")?;
        } else {
            stamp(&e.dropped_at)?;
            check(e.dropped_at >= e.signed_at)?;
            let signed = signed
                .as_ref()
                .ok_or_else(|| Error::new("state_conflict"))?;
            let original = policy(signed)?;
            let baseline = start.as_ref().map(policy).transpose()?;
            let baseline = baseline.map(|p| p.content()).unwrap_or_default();
            dropped_groups(&baseline, &original.content(), &e.dropped)?;
        }
        out.push(e);
    }
    Ok(out)
}
pub(super) fn policy(s: &Statement) -> Result<crate::policy::PolicyBody> {
    let body = access_body(&s.payload)?;
    serde_json::from_value(Value::Object(body)).map_err(|_| Error::new("invalid"))
}
pub(crate) fn enforced(
    connection: &Connection,
    p: &Projection,
    person: &str,
    mut content: crate::policy::Content,
) -> Result<crate::policy::Content> {
    for edit in read(connection, p, person)?
        .into_iter()
        .filter(|e| e.state == "unsettled")
    {
        let Some(signed) = check_reference(p, &edit.signed, person)? else {
            continue;
        };
        let start = check_reference(p, &edit.start, person)?
            .map(|s| policy(&s))
            .transpose()?
            .map(|p| p.content())
            .unwrap_or_default();
        content =
            crate::policy_edit::merge(&content, &start, &policy(&signed)?.content(), &[], false).0;
    }
    Ok(content)
}
pub(super) fn save(connection: &Connection, p: &Projection, person: &str, e: &Edit) -> Result<()> {
    let raw = serde_json::to_vec(e).map_err(|_| Error::new("internal"))?;
    require(raw.len() <= 32 << 20, "quota_exceeded")?;
    connection.execute("INSERT INTO policy_edits(network_id,person_id,seq,record) VALUES(?1,?2,?3,?4) ON CONFLICT(network_id,person_id,seq) DO UPDATE SET record=excluded.record",rusqlite::params![p.descriptor.network_id,pid(person)?,i64::try_from(e.seq).map_err(|_|Error::new("version_exhausted"))?,String::from_utf8(raw).map_err(|_|Error::new("internal"))?]).map_err(db)?;
    Ok(())
}
fn selected_policy<'a>(p: &'a Projection, person: &str) -> Result<(u64, Option<&'a Statement>)> {
    let Some(stream) = p.streams.get(&vec!["policy".into(), person.into()]) else {
        return Ok((0, None));
    };
    require(!stream.heads.is_empty(), "proof_required")?;
    require(stream.heads.len() == 1, "state_conflict")?;
    let id = stream
        .heads
        .first()
        .ok_or_else(|| Error::new("proof_required"))?;
    let selected = p.catalog.get(id)?;
    let selected = match p.active(id) {
        Ok(()) => Some(selected),
        Err(error)
            if matches!(
                error.code,
                "authority_expired"
                    | "expired"
                    | "not_yet_valid"
                    | "forbidden"
                    | "person_removed"
                    | "device_revoked"
            ) =>
        {
            None
        }
        Err(error) => return Err(error),
    };
    Ok((stream.maximum, selected))
}
pub(crate) fn reserve(store: &Store, network: &str, request: &Obj) -> Result<Vec<u8>> {
    fields(request, "provider_id")?;
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let s = Snapshot::load(&tx, network, &store.identity().public_key)?;
    let p = s.project(&super::controls::local_decision_time()?)?;
    let provider = Resolved::resolve(&tx, &s, &p, text(request, "provider_id")?, "auto", "policy")?;
    require(provider.provider.kind != "root", "forbidden")?;
    let person = text(&provider.actor, "person_public_key")?;
    let power = p.provider_potential(
        person,
        &store.identity().public_key,
        (provider.provider.kind == "device").then_some(provider.provider.lease_id.as_str()),
    )?;
    require(num(object(&power)?, "scopes")? & 1 == 1, "forbidden")?;
    let rows = read(&tx, &p, person)?;
    require(
        !rows.iter().any(|e| e.state == "unsettled"),
        "state_conflict",
    )?;
    let largest: i64 = tx
        .query_row(
            "SELECT COALESCE(MAX(seq),0) FROM policy_edits WHERE network_id=?1 AND person_id=?2",
            rusqlite::params![network, pid(person)?],
            |r| r.get(0),
        )
        .map_err(db)?;
    let seq = u64::try_from(largest)
        .map_err(|_| Error::new("state_conflict"))?
        .checked_add(1)
        .filter(|s| *s <= i64::MAX as u64)
        .ok_or_else(|| Error::new("version_exhausted"))?;
    let (version, selected) = selected_policy(&p, person)?;
    require(version < u64::MAX, "version_exhausted")?;
    let start = selected
        .map(|s| reference(&p, s))
        .transpose()?
        .unwrap_or(Value::from("-"));
    let e = Edit {
        format: 2,
        mode: "decentralized".into(),
        context_id: p.descriptor.context_id(),
        seq,
        state: "reserved".into(),
        start: start.clone(),
        signed: Value::from("-"),
        signed_version: 0,
        dropped: Vec::new(),
        reserved_at: p.decision_time.clone(),
        signed_at: "-".into(),
        unsettled_at: "-".into(),
        closed_at: "-".into(),
        dropped_at: "-".into(),
    };
    save(&tx, &p, person, &e)?;
    let clock = json!({"format":1,"largest_local_time":p.decision_time});
    tx.execute(
        "UPDATE dec_clock SET record=?2 WHERE network_id=?1",
        rusqlite::params![network, clock.to_string()],
    )
    .map_err(db)?;
    tx.commit().map_err(db)?;
    let expires = (stamp(&p.decision_time)? + chrono::TimeDelta::minutes(10))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    bytes(
        &json!({"context_id":p.descriptor.context_id(),"person_public_key":person,"policy":start,"version":version,"seq":seq,"created_at":p.decision_time,"expires_at":expires}),
    )
}
/// Status-only diagnostics from the same exact admitted references. No edit is
/// settled, dropped, pruned or reapplied by this read.
pub(crate) fn attention(
    c: &Connection,
    p: &Projection,
    person: &str,
    host: &str,
    now: &str,
) -> Result<Vec<(String, String, String, String)>> {
    if p.member_for(host, person).is_err() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let mut late = Vec::new();
    let network = &p.descriptor.network_id;
    for e in read(c, p, person)? {
        if e.state == "unsettled"
            && stamp(&e.unsettled_at)? + chrono::TimeDelta::seconds(60) < stamp(now)?
        {
            late.push(e.seq);
        }
        if !e.dropped.is_empty()
            && stamp(&e.dropped_at)? + chrono::TimeDelta::days(7) >= stamp(now)?
        {
            out.push((
                "policy_edit_dropped".into(),
                format!("{network}/{}", e.seq),
                format!(
                    "a concurrent withdrawal dropped from policy edit {}: {}",
                    e.seq,
                    e.dropped.join(", ")
                ),
                format!("peerspan access show --network {network}"),
            ));
        }
    }
    if !late.is_empty() {
        out.push(("policy_edit_unsettled".into(),network.clone(),format!("policy edits {} have not settled for more than a minute; use the selected scope1 provider to reapply",late.iter().map(u64::to_string).collect::<Vec<_>>().join(", ")),format!("peerspan access renew --network {network}")));
    }
    Ok(out)
}
pub(crate) fn summary(store: &Store, network: &str) -> Result<Vec<u8>> {
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let s = Snapshot::load(&tx, network, &store.identity().public_key)?;
    let p = s.project(&super::controls::local_decision_time()?)?;
    let person = &s.network.own_identity.person_public_key;
    require(key(person), "not_found")?;
    let rows = read(&tx, &p, person)?;
    bytes(
        &json!({"context_id":p.descriptor.context_id(),"person_public_key":person,"edits":rows.into_iter().map(|e|json!({"seq":e.seq,"state":e.state,"signed_version":e.signed_version,"dropped":e.dropped})).collect::<Vec<_>>()}),
    )
}
pub(crate) fn reapply_preview(
    store: &Store,
    network: &str,
    request: &Obj,
    context: &std::sync::OnceLock<String>,
) -> Result<Vec<u8>> {
    fields(request, "provider_id")?;
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let snapshot = Snapshot::load(&tx, network, &store.identity().public_key)?;
    let _ = context.set(snapshot.network.context_id.clone());
    let p = snapshot.project(&super::controls::local_decision_time()?)?;
    let provider = Resolved::resolve(
        &tx,
        &snapshot,
        &p,
        text(request, "provider_id")?,
        "auto",
        "policy",
    )?;
    require(provider.provider.kind != "root", "forbidden")?;
    let public = provider.public(&p, &store.identity().public_key, false)?;
    require(num(object(&public)?, "scopes")? & 1 == 1, "forbidden")?;
    let person = text(&provider.actor, "person_public_key")?;
    require(
        person == snapshot.network.own_identity.person_public_key,
        "forbidden",
    )?;
    let current = super::renewal::head(&p, person)?;
    let baseline = current
        .map(policy)
        .transpose()?
        .unwrap_or_else(|| crate::policy::PolicyBody {
            format: Some(2),
            network_id: network.into(),
            person_public_key: person.into(),
            version: 0,
            issued_at: p.decision_time.clone(),
            valid_until: p.decision_time.clone(),
            rules: Vec::new(),
            capability_rules: Some(Vec::new()),
            trusted_hosts: Some(Vec::new()),
            edits: Some(Vec::new()),
        });
    let merged = super::renewal::reapplied(&tx, &p, person, &store.identity().id, &baseline)?;
    let payload = if merged.sequences.is_empty() {
        "-".into()
    } else {
        let payload = super::renewal::payload(&p, &provider, merged.body)?;
        let raw = bytes(&payload)?;
        require(raw.len() <= MAX_PAYLOAD, "quota_exceeded")?;
        p.action(&provider.actor, "policy", &raw)?;
        encode(&raw)
    };
    let result = bytes(
        &json!({"context_id":snapshot.network.context_id,"person_public_key":person,
        "host_public_key":store.identity().public_key,"provider":public,"payload_base64":payload,"unsettled_seqs":merged.sequences}),
    )?;
    require(result.len() <= 32 << 20, "quota_exceeded")?;
    Ok(result)
}
/// Preparation checks an exact reservation but never consumes it. A byte-exact
/// semantic automatic renewal may retain its already-applied own edit number.
pub(super) fn resolution(p: &Projection, s: &Statement) -> Result<bool> {
    if s.kind != "policy" {
        return Ok(false);
    }
    let body = access_body(&s.payload)?;
    let person = text(&body, "person_public_key")?;
    let Some(stream) = p.streams.get(&vec!["policy".into(), person.into()]) else {
        return Ok(false);
    };
    if stream.heads.len() <= 1 {
        return Ok(false);
    }
    require(
        ids(&s.payload, "predecessors", "ds_")?
            .into_iter()
            .collect::<BTreeSet<_>>()
            == stream.heads
            && stream
                .heads
                .is_subset(&ids(&s.payload, "resolves", "ds_")?.into_iter().collect())
            && stream.maximum.checked_add(1) == Some(s.sequence()?),
        "state_conflict",
    )?;
    let mut body = body;
    for field in ["version", "issued_at", "valid_until"] {
        body.remove(field);
    }
    let mut matched = false;
    for id in &stream.heads {
        p.proof_complete(id)?;
        require(p.admitted.contains(id), "state_conflict")?;
        let mut prior = access_body(&p.catalog.get(id)?.payload)?;
        for field in ["version", "issued_at", "valid_until"] {
            prior.remove(field);
        }
        matched |= prior == body;
    }
    require(matched, "state_conflict")?;
    Ok(true)
}
pub(crate) fn check_policy(
    connection: &Connection,
    p: &Projection,
    s: &Statement,
    host: &str,
    claim: bool,
) -> Result<()> {
    if s.kind != "policy" {
        return Ok(());
    }
    let body = access_body(&s.payload)?;
    let person = text(&body, "person_public_key")?;
    let rows = read(connection, p, person)?;
    if p.streams
        .get(&vec!["policy".into(), person.into()])
        .is_some_and(|s| s.heads.len() > 1)
    {
        require(!claim && resolution(p, s)?, "state_conflict")?;
        return Ok(());
    }
    let own = host_id(host)?;
    let seq = array(&body, "edits")?.iter().find_map(|v| {
        v.as_object()
            .filter(|o| o.get("host").and_then(Value::as_str) == Some(&own))
            .and_then(|o| o.get("seq").and_then(Value::as_u64))
    });
    let (maximum, selected) = selected_policy(p, person)?;
    require(
        maximum.checked_add(1) == Some(s.sequence()?),
        "edit_conflict",
    )?;
    let Some(seq) = seq else {
        // An initial policy can have no local edit. Renew only its exact
        // current semantics; there is no reservation to consume or invent.
        let current = selected.ok_or_else(|| Error::new("edit_conflict"))?;
        let mut a = access_body(&current.payload)?;
        require(
            !array(&a, "edits")?
                .iter()
                .any(|v| v.get("host").and_then(Value::as_str) == Some(&own)),
            "edit_conflict",
        )?;
        let mut b = body;
        for name in ["version", "issued_at", "valid_until"] {
            a.remove(name);
            b.remove(name);
        }
        return require(a == b, "edit_conflict");
    };
    let row = rows
        .iter()
        .find(|e| e.seq == seq)
        .ok_or_else(|| Error::new("edit_conflict"))?;
    if row.state == "reserved" {
        require(
            !rows.iter().any(|e| e.state == "unsettled"),
            "state_conflict",
        )?;
        require(
            rows.last().is_some_and(|e| e.seq == seq)
                && stamp(&p.decision_time)? - stamp(&row.reserved_at)?
                    < chrono::TimeDelta::minutes(10),
            "edit_conflict",
        )?;
        let active = selected
            .map(|s| reference(p, s))
            .transpose()?
            .unwrap_or(Value::from("-"));
        require(active == row.start, "edit_conflict")?;
    } else if row.state == "unsettled" {
        super::renewal::check_reapplication(connection, p, person, host, s, seq)?;
    } else {
        require(row.state == "settled", "edit_conflict")?;
        check_reference(p, &row.signed, person)?.ok_or_else(|| Error::new("edit_conflict"))?;
        let current = selected.ok_or_else(|| Error::new("edit_conflict"))?;
        // Reapplication preserves the original signed delta. An unchanged
        // renewal follows the actual current body, without replacing that ref.
        let mut a = access_body(&current.payload)?;
        let mut b = body;
        for name in ["version", "issued_at", "valid_until"] {
            a.remove(name);
            b.remove(name);
        }
        require(a == b, "edit_conflict")?;
    }
    Ok(())
}
pub(crate) fn settle(
    connection: &Connection,
    before: &Projection,
    p: &Projection,
    s: &Statement,
    host: &str,
) -> Result<()> {
    if s.kind != "policy" {
        return Ok(());
    }
    if resolution(before, s)? {
        return Ok(());
    }
    let body = access_body(&s.payload)?;
    let person = text(&body, "person_public_key")?;
    let own = host_id(host)?;
    let seq = array(&body, "edits")?.iter().find_map(|v| {
        v.as_object()
            .filter(|o| o.get("host").and_then(Value::as_str) == Some(&own))
            .and_then(|o| o.get("seq").and_then(Value::as_u64))
    });
    let Some(seq) = seq else {
        // The initial-policy semantic renewal has no local edit to settle.
        return Ok(());
    };
    let mut rows = read(connection, p, person)?;
    let e = rows
        .iter_mut()
        .find(|e| e.seq == seq)
        .ok_or_else(|| Error::new("edit_conflict"))?;
    if e.state == "reserved" {
        e.state = "settled".into();
        e.signed = reference(p, s)?;
        e.signed_version = s.sequence()?;
        e.signed_at = p.decision_time.clone();
        save(connection, p, person, e)?;
    }
    Ok(())
}
