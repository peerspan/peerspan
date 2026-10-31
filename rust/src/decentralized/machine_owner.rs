//! Public existing-person owner authority, without resolving private signers.
use super::{codec::*, controls, requests::Pending, storage::Snapshot};
use crate::store::Store;
use rusqlite::Connection;
use serde_json::{Value, json};

pub(crate) fn inspect(c: &Connection, store: &Store, p: &Pending) -> Result<Value> {
    let r = &p.record;
    require(
        !r.roles.iter().any(|r| r == "requester")
            && r.mode == "new"
            && r.migration_proposal_id == "-"
            && r.terminal == "-"
            && r.host_public_key != store.identity().public_key
            && ident(&r.expected_network_id, "net_")
            && ident(&r.expected_context_id, "ctx_")
            && key(&r.expected_person_public_key)
            && !r.selection_approved
            && !r.commit_approved,
        "state_conflict",
    )?;
    require(
        [
            &r.owner_intent_id,
            &r.administrator_intent_id,
            &r.selection_intent_id,
            &r.commit_intent_id,
            &r.owner_offer_id,
            &r.selection_id,
            &r.administrator_offer_id,
            &r.owner_finalization_id,
            &r.owner_packet_base64,
            &r.selection_packet_base64,
            &r.administrator_packet_base64,
            &r.owner_finalization_packet_base64,
            &r.commit_packet_base64,
            &r.outcome_packet_base64,
            &r.manifest_id,
            &r.activation_id,
        ]
        .iter()
        .all(|v| v.as_str() == "-"),
        "state_conflict",
    )?;
    // Pending::load verifies the actual signed request and every retained pin.
    let packet = p.packet()?;
    let created = text(&packet.payload, "created_at")?;
    let raw =
        controls::guarded_decision(c, &r.expected_network_id, &controls::local_decision_time()?)?;
    let s = Snapshot::load_public(c, &r.expected_network_id, &store.identity().public_key)?;
    require(
        s.descriptor.context_id() == r.expected_context_id
            && s.network.own_identity.person_public_key == r.expected_person_public_key
            && !s
                .migrations
                .iter()
                .any(|m| m.fenced && m.state != "adopted"),
        "forbidden",
    )?;
    let projection = s.project(&raw)?;
    let now = &projection.decision_time;
    let latest = if r.stage_at == "-" {
        created
    } else {
        &r.stage_at
    };
    require(
        stamp(now)? >= stamp(created)?
            && stamp(now)? >= stamp(latest)?
            && stamp(now)? < stamp(latest)? + chrono::TimeDelta::seconds(600)
            && stamp(now)? < stamp(&p.deadline)?,
        "expired",
    )?;
    let request = p.view(now)?;
    require(request["state"] == "pending", "state_conflict")?;
    let root = projection.root_state_id()?;
    projection.active(root)?;
    let person = &r.expected_person_public_key;
    let own = projection.member_for(&store.identity().public_key, person)?;
    let selection = s
        .selection
        .as_ref()
        .ok_or_else(|| Error::new("forbidden"))?;
    require(selection.person_key == *person, "forbidden")?;
    let device = selection.kind == "device";
    // Read public P/H/B/D and selection only. Resolved::resolve also reads
    // seeds, so it deliberately is not used for this public inspection.
    let provider = projection.provider_potential(
        person,
        &store.identity().public_key,
        device.then_some(selection.lease_id.as_str()),
    )?;
    require(
        !device
            || provider["device_public_key"] == selection.device_key
                && selection.device_key != r.device_public_key,
        "forbidden",
    )?;
    let scopes = num(object(&provider)?, "scopes")?;
    require(scopes & 7 == 7, "forbidden")?;
    for member in projection.members()? {
        if member.host_public_key == r.host_public_key {
            require(
                member.person_public_key == "-" || member.person_public_key == *person,
                "forbidden",
            )?;
        }
    }
    let (person_lease, _) = projection.current_statement(&["person".into(), person.clone()])?;
    let end = (stamp(created)? + chrono::TimeDelta::days(7))
        .min(stamp(text(object(&provider)?, "not_after")?)?);
    require(end > stamp(now)?, "expired")?;
    let result = json!({"observed_at":now,"request":request,
        "network":{"id":s.descriptor.network_id,"name":s.descriptor.name,
            "context_id":s.descriptor.context_id(),"genesis_root_public_key":s.descriptor.genesis_root_public_key},
        "root_state_id":root,"person_lease_id":person_lease.id,
        "member":text(person_lease.subject()?,"member")?,"local_host":own.response(),
        "provider_id":if device {&selection.lease_id} else {person},
        "signature_format":if device {"ed25519"} else {"sshsig"},"provider":provider,
        "not_after":end.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        "host_admission":if scopes & 8 == 8 {"owner_may_fold"} else {"separate_administrator_required"}});
    Ok(result)
}
