//! Current public access terms; no consent, signing, repair or authority save.
use super::{codec::*, controls, edits, statement::access_body, storage::Snapshot};
use crate::{policy::PolicyBody, store::Store};
use rusqlite::{Connection, OptionalExtension};
use serde_json::{Value, json};

pub(crate) fn inspect(c: &Connection, store: &Store, network: &str, person: &str) -> Result<Value> {
    let raw: Option<String> = c
        .query_row("SELECT record FROM networks WHERE id=?1", [network], |r| {
            r.get(0)
        })
        .optional()
        .map_err(|_| Error::new("internal"))?;
    let raw = raw.ok_or_else(|| Error::new("not_found"))?;
    let tag = parse(raw.as_bytes(), 32 << 20)?;
    require(tag["mode"] == "decentralized", "upgrade_required")?;
    let time = controls::local_decision_time()?;
    let s = Snapshot::load(c, network, &store.identity().public_key)?;
    require(
        !s.migrations
            .iter()
            .any(|m| m.fenced && m.state != "adopted"),
        "migration_pending",
    )?;
    let p = s.project(&time)?;
    let root = p.root_state_id()?;
    p.active(root)?;
    let members = p.members()?;
    let owner_key = &s.network.own_identity.person_public_key;
    let own = members
        .iter()
        .find(|m| m.host_public_key == store.identity().public_key)
        .ok_or_else(|| Error::new("forbidden"))?;
    require(
        key(owner_key) && own.person_public_key == *owner_key,
        "forbidden",
    )?;
    let (owner, _) = p.current_statement(&["person".into(), owner_key.clone()])?;
    let (participant, until) = p.current_statement(&["person".into(), person.into()])?;
    let policy_stream = vec!["policy".into(), owner_key.clone()];
    let policy = if p.streams.contains_key(&policy_stream) {
        let (statement, valid_until) = p.current_statement(&policy_stream)?;
        let body = Value::Object(access_body(&statement.payload)?);
        let typed: PolicyBody =
            serde_json::from_value(body.clone()).map_err(|_| Error::new("state_conflict"))?;
        let enforced = edits::enforced(c, &p, owner_key, typed.content())?;
        let proof = p
            .catalog
            .statement_proofs
            .get(&statement.id)
            .and_then(|ids| ids.iter().min())
            .ok_or_else(|| Error::missing(&statement.id))?;
        json!({"statement_id":statement.id,"proof_id":proof,"body":body,
            "enforced_content":{"rules":enforced.rules,"capability_rules":enforced.capability_rules,
                "trusted_hosts":enforced.trusted_hosts},"valid_until":valid_until})
    } else {
        Value::Null
    };
    let hosts: Vec<_> = members
        .iter()
        .filter(|m| m.person_public_key == person)
        .map(|m| m.response())
        .collect();
    Ok(json!({"observed_at":p.decision_time,
        "network":{"id":network,"name":s.descriptor.name,"context_id":s.network.context_id},
        "root_state_id":root,
        "owner":{"person_public_key":owner_key,"member":text(owner.subject()?,"member")?,
            "person_lease_id":owner.id,"host":own.response()},
        "participant":{"person_public_key":person,"member":text(participant.subject()?,"member")?,
            "person_lease_id":participant.id,"not_after":until,"hosts":hosts},
        "policy":policy}))
}
