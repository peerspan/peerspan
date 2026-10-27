//! Owner-local views use public authority independently from signer availability.
use super::{codec::*, state::Projection, storage::Snapshot};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn network(
    snapshot: &Snapshot,
    projection: &Projection,
    available: Result<()>,
    delivery: Value,
) -> Result<Value> {
    let identity = &snapshot.network.own_identity;
    let root = projection.root_state_id().unwrap_or("-");
    let root_key = projection
        .catalog
        .statements
        .get(root)
        .and_then(|s| s.payload.get("root_public_key"))
        .and_then(Value::as_str)
        .unwrap_or("-");
    let root_stream = projection
        .streams
        .get(&vec!["root".into()])
        .ok_or_else(|| Error::new("proof_required"))?;
    let authority = match projection
        .member_for(&identity.host_public_key, &identity.person_public_key)
    {
        Ok(member) => {
            json!({"state":if identity.person_public_key=="-" {"unbound"} else {"usable"},"not_after":member.not_after,"required_ids":[],"conflict_ids":[]})
        }
        Err(e) => {
            json!({"state":e.code,"not_after":"-","required_ids":e.required_ids,"conflict_ids":if e.code=="state_conflict" {root_stream.heads.clone()} else {BTreeSet::new()}})
        }
    };
    let (provider, provider_state) = if let Some(selected) = &snapshot.selection {
        let potential = projection.provider_potential(
            &selected.person_key,
            &identity.host_public_key,
            (selected.kind == "device").then_some(selected.lease_id.as_str()),
        );
        let mut remembered = json!({"kind":if selected.kind=="device" {"device"} else {"original_person"},"person_public_key":selected.person_key,"host_public_key":identity.host_public_key,"device_public_key":selected.device_key,"lease_id":selected.lease_id,"root_state_id":root,"scopes":0,"not_after":"-"});
        if selected.kind == "original" {
            remembered["lease_id"] = projection
                .streams
                .get(&vec!["person".into(), selected.person_key.clone()])
                .filter(|s| s.heads.len() == 1)
                .and_then(|s| s.heads.first())
                .map(|id| Value::from(id.clone()))
                .unwrap_or(Value::from("-"));
        }
        let (value, error) = match potential {
            Ok(value) => (value, available.err()),
            Err(e) => (remembered, Some(e)),
        };
        let state = availability_state(error.map_or(Ok(()), Err));
        (value, state)
    } else {
        (
            Value::Null,
            json!({"state":"not_selected","code":"-","error":"-","required_ids":[]}),
        )
    };
    Ok(
        json!({"id":snapshot.descriptor.network_id,"name":snapshot.descriptor.name,"mode":"decentralized","context_id":snapshot.descriptor.context_id(),"genesis_root_public_key":snapshot.descriptor.genesis_root_public_key,"root_state_id":root,"root_public_key":root_key,"root_epoch":root_stream.maximum,"member":identity.member,"host_public_key":identity.host_public_key,"person_public_key":identity.person_public_key,"provider":provider,"provider_state":provider_state,"authority":authority,"delivery":delivery,"created_at":snapshot.network.created_at}),
    )
}
pub(crate) fn availability_state(available: Result<()>) -> Value {
    match available {
        Ok(()) => json!({"state":"available","code":"-","error":"-","required_ids":[]}),
        Err(e) => {
            json!({"state":"unavailable","code":e.code,"error":e.code.replace('_'," "),"required_ids":e.required_ids})
        }
    }
}
pub(crate) fn delivery(connection: &Connection, network: &str, context: &str) -> Result<Value> {
    let mut pending = BTreeSet::new();
    let mut errors = BTreeMap::new();
    let mut query=connection.prepare("SELECT target_key,record FROM dec_outbox WHERE network_id=?1 AND context_id=?2 ORDER BY delivery_id").map_err(|_|Error::new("internal"))?;
    let rows = query
        .query_map([network, context], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })
        .map_err(|_| Error::new("internal"))?;
    for row in rows {
        let (target, raw) = row.map_err(|_| Error::new("internal"))?;
        check(key(&target))?;
        let value = parse(raw.as_bytes(), 32 << 20)?;
        let record = object(&value)?;
        fields(
            record,
            "format kind body_base64 proof_ids created_at attempts next_attempt_at last_error_code last_error_detail",
        )?;
        version(record)?;
        pending.extend(ids(record, "proof_ids", "dp_")?);
        let code = text(record, "last_error_code")?;
        check(code.len() <= 1024)?;
        if code != "-" {
            errors.entry(target).or_insert(code.to_owned());
        }
    }
    Ok(
        json!({"pending_proof_ids":pending,"peer_errors":errors.into_iter().map(|(host_public_key,code)|json!({"host_public_key":host_public_key,"code":code})).collect::<Vec<_>>()}),
    )
}
