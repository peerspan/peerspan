//! Nonsigning public-review receipt bound to one ordinary immutable policy action.
use super::{
    actions, codec::*, edits, intents::Intent, provider::Resolved, statement::access_body,
    storage::Snapshot, template::FixedStatement,
};
use crate::{onboarding_access_consent::Input, store::Store};
use rusqlite::{Connection, OptionalExtension};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

fn db(_: rusqlite::Error) -> Error {
    Error::new("internal")
}
fn bytes(v: &Value) -> Result<Vec<u8>> {
    serde_json::to_vec(v).map_err(|_| Error::new("internal"))
}
fn key_for(input: &Input) -> String {
    format!(
        "arev_{}",
        hash(
            format!(
                "peerspan-project-access-key-v1\n{}",
                crate::canonical::value_text(&input.selection())
            )
            .as_bytes()
        )
    )
}
fn review_id(v: &Value) -> String {
    format!(
        "review_{}",
        hash(
            format!(
                "peerspan-project-access-consent-v1\n{}",
                crate::canonical::value_text(v)
            )
            .as_bytes()
        )
    )
}
fn inspection_id(v: &Value) -> String {
    format!(
        "review_{}",
        hash(
            format!(
                "peerspan-project-access-inspection-v1\n{}",
                crate::canonical::value_text(v)
            )
            .as_bytes()
        )
    )
}
fn latest(c: &Connection, input: &Input) -> Result<Option<String>> {
    c.query_row("SELECT intent_id FROM dec_intents WHERE kind='access_review' AND network_id=?1 AND json_extract(record,'$.operation_id')=?2 ORDER BY rowid DESC LIMIT 1",
        rusqlite::params![input.network_id,key_for(input)],|r|r.get(0)).optional().map_err(db)
}
fn current(c: &Connection, store: &Store, input: &Input, now: &str) -> Result<Value> {
    crate::onboarding_access::inspect_in(c, store, &input.inspection(), now)
        .map_err(|_| Error::new("access_review_unavailable"))
}
fn grant(inspection: &Value, input: &Input) -> Result<Value> {
    let principal = format!(
        "person:{}",
        crate::persons::person_id(&b64(&input.person_public_key, 32)?)
    );
    Ok(
        json!({"policy_scope":"owner_agent_name","agent_id":inspection["agent"]["id"],
        "agent_name":inspection["agent"]["name"],"principal":principal,
        "actions":["message.append","task.submit"],"max_message_bytes":65536,
        "max_artifact_bytes":0,"allow_disconnected":false}),
    )
}
fn statement(action: &Intent, d: &super::Descriptor) -> Result<Value> {
    let raw = b64(&action.record.templates[0].template_base64, MAX_OBJECT)?;
    let fixed = FixedStatement::read(d, &raw)?;
    let s = fixed.typed();
    let mut payload = s.payload.clone();
    let body = Value::Object(access_body(&payload)?);
    payload.remove("body_base64");
    payload.insert("body".into(), body);
    Ok(json!({"id":s.id,"payload_sha256":hash(&s.payload_bytes),"payload":payload}))
}
fn make_review(
    input: &Input,
    inspection: &Value,
    meta: &Intent,
    action: &Intent,
    d: &super::Descriptor,
    replaces: &str,
) -> Result<Value> {
    let r = &action.record;
    let expires = r.expires_at.as_str().min(r.not_after.as_str());
    stamp(expires)?;
    let v = json!({"version":1,"kind":"approve_project_agent_access","access_id":meta.id,
        "host_id":inspection["host_id"],"context":input.context,
        "inspection_review_id":inspection_id(inspection),"inspection":inspection,
        "replaces_access_id":replaces,"grant":grant(inspection,input)?,
        "action_id":r.operation_id,"intent_id":action.id,"provider":actions::review(action)?["provider"],
        "statement":statement(action,d)?,"created_at":r.created_at,"expires_at":expires,
        "effects":{"approve_policy_intent":true,"authorize_policy_signature":true,
            "authorize_policy_publication":true,"grant_agent_access_after_signatures":true,
            "grant_membership":false,"delegate_tasks":false,"share_files":false,
            "share_conversation":false,"capability_calls":false,"allow_disconnected":false}});
    require(
        crate::onboarding_admission::safe(&v) && bytes(&v)?.len() <= 1 << 20,
        "access_review_unavailable",
    )?;
    Ok(v)
}
struct Receipt {
    meta: Intent,
    action: Intent,
    review: Value,
}
fn load(c: &Connection, store: &Store, input: &Input, parent: &Value, id: &str) -> Result<Receipt> {
    let meta = Intent::load(c, id)?;
    require(meta.kind == "access_review", "not_found")?;
    require(
        meta.network_id == input.network_id && meta.record.operation_id == key_for(input),
        "review_changed",
    )?;
    let review = parse(&b64(&meta.record.review_base64, 1 << 20)?, 1 << 20)?;
    let o = object(&review)?;
    fields(
        o,
        "version kind access_id host_id context inspection_review_id inspection replaces_access_id grant action_id intent_id provider statement created_at expires_at effects",
    )?;
    let action = Intent::load(c, text(o, "intent_id")?)?;
    let d = actions::descriptor(c, &input.network_id)?;
    require(
        action.kind == "action"
            && action.network_id == input.network_id
            && action.context_id == d.context_id()
            && meta.context_id == d.context_id()
            && action.record.host_public_key == store.identity().public_key,
        "state_conflict",
    )?;
    actions::validate(&action, &d)?;
    require(
        action.record.templates.len() == 1 && action.record.templates[0].object_type == "policy",
        "state_conflict",
    )?;
    let inspection = &review["inspection"];
    fields(
        object(inspection)?,
        "version kind host_id context agent network root_state_id owner participant policy effects",
    )?;
    require(
        inspection["host_id"] == store.identity().id
            && inspection["context"] == input.selection()["context"]
            && inspection["agent"] == parent["agent"]
            && inspection["network"]["id"] == input.network_id
            && inspection["participant"]["person_public_key"] == input.person_public_key
            && inspection["owner"]["person_public_key"] == action.record.person_public_key
            && inspection["root_state_id"] == action.record.root_state_id,
        "state_conflict",
    )?;
    let replaces = text(o, "replaces_access_id")?;
    if replaces != "-" {
        let previous = Intent::load(c, replaces)?;
        let row = |id: &str| -> Result<i64> {
            c.query_row(
                "SELECT rowid FROM dec_intents WHERE intent_id=?1",
                [id],
                |r| r.get(0),
            )
            .map_err(db)
        };
        require(
            previous.kind == "access_review"
                && previous.network_id == meta.network_id
                && previous.record.operation_id == meta.record.operation_id
                && row(replaces)? < row(id)?,
            "state_conflict",
        )?;
    }
    let expected = make_review(input, inspection, &meta, &action, &d, replaces)?;
    require(review == expected, "state_conflict")?;
    let mut record = action.record.clone();
    record.operation_id = key_for(input);
    record.approved = meta.record.approved;
    record.approved_at = meta.record.approved_at.clone();
    record.review_base64 = encode(crate::canonical::value_text(&expected).as_bytes());
    record.expires_at = text(object(&review)?, "expires_at")?.into();
    record.templates.clear();
    record.signatures.clear();
    record.completed = true;
    record.terminal = "-".into();
    record.result_base64 = "-".into();
    require(
        serde_json::to_value(&record).map_err(|_| Error::new("internal"))?
            == serde_json::to_value(&meta.record).map_err(|_| Error::new("internal"))?,
        "state_conflict",
    )?;
    if meta.record.approved {
        require(
            action.record.approved && meta.record.approved_at == action.record.approved_at,
            "state_conflict",
        )?;
    }
    Ok(Receipt {
        meta,
        action,
        review,
    })
}
fn live(
    c: &Connection,
    store: &Store,
    input: &Input,
    r: &Receipt,
    parent: &Value,
    attached: bool,
    now: &str,
) -> Result<()> {
    require(
        attached && parent["agent"] == r.review["inspection"]["agent"],
        "review_changed",
    )?;
    require(now >= r.meta.record.created_at.as_str(), "review_changed")?;
    require(now < r.meta.record.expires_at.as_str(), "review_expired")?;
    require(
        r.action.record.terminal == "-"
            && !r.action.record.completed
            && r.action.record.signatures.is_empty()
            && r.action.record.approved == r.meta.record.approved,
        "review_changed",
    )?;
    let observed = current(c, store, input, now)?;
    require(
        observed["review_id"] == r.review["inspection_review_id"],
        "review_changed",
    )?;
    let s = Snapshot::load(c, &input.network_id, &store.identity().public_key)?;
    let p = s.project(now)?;
    let provider = Resolved::resolve(c, &s, &p, "auto", "auto", "policy")?;
    require(
        bytes(&serde_json::to_value(&provider.provider).map_err(|_| Error::new("internal"))?)?
            == bytes(
                &serde_json::to_value(&r.action.record.provider)
                    .map_err(|_| Error::new("internal"))?,
            )?
            && provider.public(&p, &store.identity().public_key, false)? == r.review["provider"],
        "review_changed",
    )?;
    actions::revalidate(c, &s, &p, &r.action)?;
    let fixed = FixedStatement::read(
        &s.descriptor,
        &b64(&r.action.record.templates[0].template_base64, MAX_OBJECT)?,
    )?;
    actions::preflight(c, &p, &s, &fixed)
}
fn view(
    c: &Connection,
    store: &Store,
    input: &Input,
    r: &Receipt,
    parent: &Value,
    attached: bool,
    now: &str,
) -> Result<Value> {
    require(
        now >= r.meta.record.created_at.as_str(),
        "access_review_unavailable",
    )?;
    let state = if r.meta.record.approved {
        "approved"
    } else if r.action.record.approved {
        "invalidated"
    } else if now >= r.meta.record.expires_at.as_str() {
        "expired"
    } else if live(c, store, input, r, parent, attached, now).is_err() {
        "invalidated"
    } else {
        "review"
    };
    let next = match state {
        "approved" => "follow_policy_action",
        "review" => "approve_policy_intent",
        _ => "inspect_agent_access",
    };
    Ok(
        json!({"access_id":r.meta.id,"review_id":review_id(&r.review),"review":r.review,"state":state,"next_action":next}),
    )
}
fn payload(
    c: &Connection,
    store: &Store,
    s: &Snapshot,
    p: &super::Projection,
    provider: &Resolved,
    inspection: &Value,
    input: &Input,
) -> Result<Vec<u8>> {
    let person = text(&provider.actor, "person_public_key")?;
    require(
        provider.provider.kind != "root" && person == s.network.own_identity.person_public_key,
        "forbidden",
    )?;
    let public = provider.public(p, &store.identity().public_key, false)?;
    require(num(object(&public)?, "scopes")? & 1 == 1, "forbidden")?;
    let rows = edits::read(c, p, person)?;
    require(
        !rows.iter().any(|e| e.state == "unsettled"),
        "state_conflict",
    )?;
    let largest: i64 = c
        .query_row(
            "SELECT COALESCE(MAX(seq),0) FROM policy_edits WHERE network_id=?1 AND person_id=?2",
            rusqlite::params![
                input.network_id,
                crate::persons::person_id(&b64(person, 32)?)
            ],
            |r| r.get(0),
        )
        .map_err(db)?;
    let seq = largest
        .checked_add(1)
        .filter(|v| *v > 0)
        .ok_or_else(|| Error::new("version_exhausted"))?;
    let stream = p.streams.get(&vec!["policy".into(), person.into()]);
    let version = stream
        .map(|s| s.maximum)
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| Error::new("version_exhausted"))?;
    let predecessors: Vec<_> = stream
        .map(|s| s.heads.iter().cloned().collect())
        .unwrap_or_default();
    require(predecessors.len() <= 1, "state_conflict")?;
    let mut parents = BTreeMap::from([(
        "issuer_person",
        p.current_statement(&["person".into(), person.into()])?
            .0
            .id
            .clone(),
    )]);
    if provider.provider.kind == "device" {
        parents.insert("issuer_device", provider.provider.lease_id.clone());
    }
    let mut until = actions::at(&p.decision_time, 86400)?;
    let mut seen = BTreeSet::new();
    for id in parents.values() {
        super::renewal::cap(p, id, &mut seen, 0, &mut until)?;
        let (_, end) = p.current_statement(
            &p.catalog
                .get(id)?
                .stream()?
                .ok_or_else(|| Error::new("invalid"))?,
        )?;
        until = until.min(end);
    }
    until = until.min(text(object(&inspection["participant"])?, "not_after")?.into());
    require(until > p.decision_time, "authority_expired")?;
    let mut body = if inspection["policy"].is_null() {
        json!({"format":2,"network_id":input.network_id,
        "person_public_key":person,"version":0,"issued_at":p.decision_time,"valid_until":until,
        "rules":[],"capability_rules":[],"trusted_hosts":[],"edits":[]})
    } else {
        inspection["policy"]["body"].clone()
    };
    body["version"] = json!(version);
    body["issued_at"] = json!(p.decision_time);
    body["valid_until"] = json!(until);
    let grant = grant(inspection, input)?;
    let rule = json!({"agent":grant["agent_name"],"principals":[grant["principal"]],"actions":grant["actions"],
        "max_message_bytes":65536,"max_artifact_bytes":0,"allow_disconnected":false});
    let typed: crate::policy::Rule =
        serde_json::from_value(rule.clone()).map_err(|_| Error::new("invalid"))?;
    let rules = body["rules"]
        .as_array_mut()
        .ok_or_else(|| Error::new("invalid"))?;
    let mut same = None;
    for (index, item) in rules.iter().enumerate() {
        let old: crate::policy::Rule =
            serde_json::from_value(item.clone()).map_err(|_| Error::new("invalid"))?;
        if old.same_key(&typed) {
            same = Some(index);
            break;
        }
    }
    if let Some(index) = same {
        let principals = rules[index]["principals"]
            .as_array_mut()
            .ok_or_else(|| Error::new("invalid"))?;
        if !principals.contains(&grant["principal"]) {
            principals.push(grant["principal"].clone());
        }
    } else {
        rules.push(rule);
    }
    let entries = body["edits"]
        .as_array_mut()
        .ok_or_else(|| Error::new("invalid"))?;
    if let Some(e) = entries
        .iter_mut()
        .find(|e| e["host"] == store.identity().id)
    {
        e["seq"] = json!(seq);
    } else {
        entries.push(json!({"host":store.identity().id,"seq":seq}));
    }
    let raw = bytes(
        &json!({"root_state_id":p.root_state_id()?,"operation_id":"-","sequence":version,
        "predecessors":predecessors,"resolves":[],"issuer":{"kind":if provider.provider.kind=="device"{"device"}else{"person"},
        "person_public_key":person},"parents":parents.into_iter().map(|(role,id)|json!({"role":role,"id":id})).collect::<Vec<_>>(),
        "issued_at":p.decision_time,"not_before":p.decision_time,"not_after":until,"body_base64":encode(&bytes(&body)?)}),
    )?;
    require(raw.len() <= MAX_PAYLOAD, "quota_exceeded")?;
    Ok(raw)
}
pub(crate) fn run(
    c: &Connection,
    store: &Store,
    op: &str,
    input: &Input,
    parent: &Value,
    attached: bool,
    now: &str,
) -> Result<Value> {
    let d = actions::descriptor(c, &input.network_id)?;
    let existing = latest(c, input)?;
    if op == "lookup" {
        return existing
            .map(|id| {
                view(
                    c,
                    store,
                    input,
                    &load(c, store, input, parent, &id)?,
                    parent,
                    attached,
                    now,
                )
            })
            .transpose()
            .map(|v| v.unwrap_or(Value::Null));
    }
    if op == "approve" {
        let id = input
            .access_id
            .as_deref()
            .ok_or_else(|| Error::new("invalid"))?;
        let mut r = load(c, store, input, parent, id)?;
        require(
            existing.as_deref() == Some(id)
                && input.access_review_id.as_deref() == Some(review_id(&r.review).as_str()),
            "review_changed",
        )?;
        if !r.meta.record.approved {
            live(c, store, input, &r, parent, attached, now).map_err(|e| {
                if e.code == "review_expired" {
                    e
                } else {
                    Error::new("review_changed")
                }
            })?;
            r.action.record.approved = true;
            r.action.record.approved_at = now.into();
            r.meta.record.approved = true;
            r.meta.record.approved_at = now.into();
            r.action.save(c)?;
            r.meta.save(c)?;
            actions::remember_clock(c, &input.network_id, now)?;
        }
        return view(c, store, input, &r, parent, attached, now);
    }
    require(op == "prepare", "invalid")?;
    if let Some(id) = &existing {
        let r = load(c, store, input, parent, id)?;
        let same =
            input.inspection_review_id.as_deref() == r.review["inspection_review_id"].as_str();
        match input.replace_access_id.as_deref() {
            None => {
                require(same, "review_changed")?;
                return view(c, store, input, &r, parent, attached, now);
            }
            Some(old) if r.review["replaces_access_id"] == old => {
                require(same, "review_changed")?;
                return view(c, store, input, &r, parent, attached, now);
            }
            Some(old) if old == id => {
                require(
                    !(r.action.record.approved && !r.meta.record.approved)
                        && live(c, store, input, &r, parent, attached, now).is_err(),
                    "review_changed",
                )?;
            }
            _ => return Err(Error::new("review_changed")),
        }
    } else {
        require(input.replace_access_id.is_none(), "review_changed")?;
    }
    require(attached, "review_changed")?;
    let observed = current(c, store, input, now)?;
    require(
        input.inspection_review_id.as_deref() == observed["review_id"].as_str(),
        "review_changed",
    )?;
    let inspection = &observed["review"];
    let s = Snapshot::load(c, &input.network_id, &store.identity().public_key)?;
    let p = s.project(now)?;
    let provider = Resolved::resolve(c, &s, &p, "auto", "auto", "policy")?;
    let payload = payload(c, store, &s, &p, &provider, inspection, input)?;
    p.action(&provider.actor, "policy", &payload)?;
    let fixed = actions::template(&p, &provider, "policy", &payload)?;
    edits::check_policy(c, &p, fixed.typed(), &store.identity().public_key, false)?;
    actions::preflight(c, &p, &s, &fixed)?;
    let (action, new) = actions::intent_in(c, store, &s, &p, &provider, &fixed, None)?;
    require(new, "access_review_unavailable")?;
    let mut record = action.record.clone();
    record.operation_id = key_for(input);
    record.templates.clear();
    record.signatures.clear();
    record.completed = true;
    let mut meta = Intent {
        id: crate::store::new_id("dint").map_err(|_| Error::new("internal"))?,
        network_id: input.network_id.clone(),
        context_id: d.context_id(),
        kind: "access_review".into(),
        record,
        secret: None,
    };
    let review = make_review(
        input,
        inspection,
        &meta,
        &action,
        &d,
        input.replace_access_id.as_deref().unwrap_or("-"),
    )?;
    meta.record.review_base64 = encode(crate::canonical::value_text(&review).as_bytes());
    meta.record.expires_at = text(object(&review)?, "expires_at")?.into();
    let (count,total,size):(i64,i64,i64)=c.query_row("SELECT COUNT(*),(SELECT COUNT(*) FROM dec_intents),COALESCE(SUM(length(CAST(record AS BLOB))),0) FROM dec_intents WHERE kind='access_review'",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(db)?;
    require(
        count < 256
            && total <= 4094
            && (size as usize)
                .checked_add(
                    bytes(
                        &serde_json::to_value(&meta.record).map_err(|_| Error::new("internal"))?,
                    )?
                    .len(),
                )
                .is_some_and(|v| v <= 16 << 20),
        "quota_exceeded",
    )?;
    action.save(c)?;
    meta.save(c)?;
    view(
        c,
        store,
        input,
        &Receipt {
            meta,
            action,
            review,
        },
        parent,
        attached,
        now,
    )
}
