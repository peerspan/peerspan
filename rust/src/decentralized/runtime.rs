//! Private Unix administration only. This router is never a bootstrap/peer API.
use super::{
    actions,
    codec::*,
    creation, edits, requester, requests, requests_io,
    state::Projection,
    storage::{ProviderSelection, Snapshot},
    views,
};
use crate::store::Store;
use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State, rejection::BytesRejection},
    http::{Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::any,
};
use ed25519_dalek::SigningKey;
use rusqlite::{Connection, OptionalExtension};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    sync::{Arc, OnceLock},
};

pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v2", any(dispatch))
        .route("/v2/{*path}", any(dispatch))
        .layer(DefaultBodyLimit::max(20 << 20))
}
fn db(_: rusqlite::Error) -> Error {
    Error::new("internal")
}
fn encode_json(value: &Value) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| Error::new("internal"))
}
fn now() -> Result<String> {
    super::controls::local_decision_time()
}
fn provider_available(store: &Store, snapshot: &Snapshot, device_available: bool) -> Result<()> {
    let Some(selected) = &snapshot.selection else {
        return Err(Error::new("not_found"));
    };
    selected_available(store, selected, device_available)
}
fn selected_available(
    store: &Store,
    selected: &ProviderSelection,
    device_available: bool,
) -> Result<()> {
    if selected.kind == "device" {
        return require(device_available, "signer_unavailable");
    }
    let key: [u8; 32] = b64(&selected.person_key, 32)?
        .try_into()
        .map_err(|_| Error::new("state_conflict"))?;
    store
        .renewal_signer(key)
        .map(|_| ())
        .map_err(|_| Error::new("signer_unavailable"))
}
fn owned_device(connection: &Connection, selection: &ProviderSelection) -> Result<bool> {
    if selection.kind != "device" {
        return Ok(false);
    }
    let seed: Option<Vec<u8>> = connection
        .query_row(
            "SELECT seed FROM link_device_keys WHERE public_key=?1",
            [&selection.device_key],
            |r| r.get(0),
        )
        .optional()
        .map_err(db)?;
    let Some(seed) = seed else {
        return Ok(false);
    };
    let Ok(seed) = <&[u8; 32]>::try_from(seed.as_slice()) else {
        return Ok(false);
    };
    Ok(encode(SigningKey::from_bytes(seed).verifying_key().as_bytes()) == selection.device_key)
}
fn load(connection: &Connection, network: &str, host: &str) -> Result<Snapshot> {
    check(ident(network, "net_"))?;
    let present: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM networks WHERE id=?1)",
            [network],
            |r| r.get(0),
        )
        .map_err(db)?;
    require(present, "not_found")?;
    let raw: String = connection
        .query_row("SELECT record FROM networks WHERE id=?1", [network], |r| {
            r.get(0)
        })
        .map_err(db)?;
    require(raw.len() <= 32 << 20, "quota_exceeded")?;
    let tag: Value = serde_json::from_str(&raw).map_err(|_| Error::new("state_conflict"))?;
    require(
        tag.get("mode").and_then(Value::as_str) == Some("decentralized"),
        "upgrade_required",
    )?;
    Snapshot::load(connection, network, host)
}
struct Read {
    snapshot: Snapshot,
    projection: Projection,
    delivery: Value,
    device_available: bool,
}
fn capture(store: &Store, network: &str, context: Option<&OnceLock<String>>) -> Result<Read> {
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let snapshot = load(&tx, network, &store.identity().public_key)?;
    // This request-local diagnostic pin comes from the same held snapshot.
    // A later proof/fork refusal must not discard an already known context.
    if let Some(context) = context {
        let _ = context.set(snapshot.network.context_id.clone());
    }
    let projection = snapshot.project(&now()?)?;
    let delivery = views::delivery(&tx, network, &snapshot.network.context_id)?;
    let device_available = snapshot
        .selection
        .as_ref()
        .map(|s| owned_device(&tx, s))
        .transpose()?
        .unwrap_or(false);
    tx.commit().map_err(db)?;
    Ok(Read {
        snapshot,
        projection,
        delivery,
        device_available,
    })
}
fn public_network(store: &Store, read: &Read) -> Result<Value> {
    let available = provider_available(store, &read.snapshot, read.device_available);
    views::network(
        &read.snapshot,
        &read.projection,
        available,
        read.delivery.clone(),
    )
}
/// One held owner-status read. No signing, contact minting, proof admission,
/// guard update or transport operation occurs here.
pub(crate) struct StatusRead {
    pub network: Value,
    pub guard: String,
    pub edit_attention: Vec<(String, String, String, String)>,
}
pub(crate) fn status_network(
    store: &Store,
    c: &Connection,
    network: &str,
    time: &str,
) -> Result<StatusRead> {
    let s = load(c, network, &store.identity().public_key)?;
    let delivery = views::delivery(c, network, &s.network.context_id)?;
    let guard = s.prior.clock_guard.clone();
    let available = provider_available(
        store,
        &s,
        s.selection
            .as_ref()
            .map(|p| owned_device(c, p))
            .transpose()?
            .unwrap_or(false),
    );
    let mut edit_attention = Vec::new();
    let view = match s.project(time) {
        Ok(p) => {
            let mut view = views::network(&s, &p, available, delivery)?;
            if s.migrations
                .iter()
                .any(|m| m.fenced && m.state != "adopted")
            {
                view["authority"] = json!({"state":"migration_pending","not_after":"-","required_ids":[],"conflict_ids":[]});
                if !view["provider"].is_null() {
                    view["provider"]["scopes"] = Value::from(0);
                }
                view["provider_state"] =
                    views::availability_state(Err(Error::new("migration_pending")));
            } else if s.network.own_identity.person_public_key != "-" {
                edit_attention = super::edits::attention(
                    c,
                    &p,
                    &s.network.own_identity.person_public_key,
                    &s.network.own_identity.host_public_key,
                    &p.decision_time,
                )?;
                let stream = vec![
                    "policy".into(),
                    s.network.own_identity.person_public_key.clone(),
                ];
                if p.streams.contains_key(&stream)
                    && let Err(e) = p.current_statement(&stream)
                {
                    let kind = match e.code {
                        "proof_required" => "network_proof_required",
                        "state_conflict" => "network_state_conflict",
                        "authority_expired" | "expired" => "policy_expired",
                        "forbidden" | "not_yet_valid" | "device_revoked" | "person_removed" => {
                            "network_authority_expired"
                        }
                        _ => return Err(e),
                    };
                    edit_attention.push((
                        kind.into(),
                        network.into(),
                        format!(
                            "own policy path is unavailable: {}; required_ids {}",
                            e.code,
                            e.required_ids.iter().cloned().collect::<Vec<_>>().join(",")
                        ),
                        format!("peerspan access renew --network {network}"),
                    ));
                }
            }
            edit_attention.extend(super::renewal::attention(&s, &p, network)?);
            view
        }
        Err(e)
            if matches!(
                e.code,
                "clock_rollback"
                    | "proof_required"
                    | "state_conflict"
                    | "migration_pending"
                    | "forbidden"
                    | "authority_expired"
                    | "device_revoked"
                    | "not_yet_valid"
            ) =>
        {
            let own = &s.network.own_identity;
            let root_id = if s.prior.root_heads.len() == 1 {
                s.prior
                    .root_heads
                    .first()
                    .map(String::as_str)
                    .unwrap_or("-")
            } else {
                "-"
            };
            let root_key = s
                .prior
                .catalog
                .statements
                .get(root_id)
                .and_then(|s| s.payload.get("root_public_key"))
                .and_then(Value::as_str)
                .unwrap_or("-");
            let provider=s.selection.as_ref().map(|p| {
                let lease=if p.kind=="original" {s.prior.maxima.get(&vec!["person".into(),p.person_key.clone()]).filter(|m|m.head_ids.len()==1).and_then(|m|m.head_ids.first()).map(String::as_str).unwrap_or("-")} else {p.lease_id.as_str()};
                json!({"kind":if p.kind=="device" {"device"} else {"original_person"},"person_public_key":p.person_key,"host_public_key":own.host_public_key,"device_public_key":p.device_key,"lease_id":lease,"root_state_id":root_id,"scopes":0,"not_after":"-"})
            });
            let root = s
                .prior
                .maxima
                .get(&vec!["root".into()])
                .map(|m| m.sequence)
                .unwrap_or(0);
            json!({"id":network,"name":s.descriptor.name,"mode":"decentralized","context_id":s.network.context_id,"genesis_root_public_key":s.descriptor.genesis_root_public_key,"root_state_id":root_id,"root_public_key":root_key,"root_epoch":root,"member":own.member,"host_public_key":own.host_public_key,"person_public_key":own.person_public_key,"provider":provider,"provider_state":if s.selection.is_some() {views::availability_state(Err(e.clone()))} else {json!({"state":"not_selected","code":"-","error":"-","required_ids":[]})},"authority":{"state":e.code,"not_after":"-","required_ids":e.required_ids,"conflict_ids":if s.prior.root_heads.len()>1 {s.prior.root_heads.clone()} else {Default::default()}},"delivery":delivery,"created_at":s.network.created_at})
        }
        Err(e) => return Err(e),
    };
    Ok(StatusRead {
        network: view,
        guard,
        edit_attention,
    })
}
pub(crate) fn read_network(
    store: &Store,
    network: &str,
    suffix: &str,
    time: &str,
) -> Result<Vec<u8>> {
    read_network_context(store, network, suffix, time, None)
}
fn read_network_context(
    store: &Store,
    network: &str,
    suffix: &str,
    _time: &str,
    context: Option<&OnceLock<String>>,
) -> Result<Vec<u8>> {
    let read = capture(store, network, context)?;
    let p = &read.projection;
    let s = &read.snapshot;
    let value = match suffix {
        "" => public_network(store, &read)?,
        "members" => {
            json!({"context_id":s.network.context_id,"members":p.members()?.into_iter().map(|m|json!({"host_public_key":m.host_public_key,"member":m.member,"person_public_key":m.person_public_key,"host_lease_id":m.host_lease_id,"binding_lease_id":m.binding_lease_id,"device_lease_id":m.device_lease_id,"not_after":m.not_after})).collect::<Vec<_>>()})
        }
        "persons" => {
            let mut persons = Vec::new();
            for stream in p
                .streams
                .values()
                .filter(|s| s.key.first().is_some_and(|k| k == "person"))
            {
                let (statement, deadline) = match p.current_statement(&stream.key) {
                    Ok(value) => value,
                    Err(e) if inactive(&e) => continue,
                    Err(e) => return Err(e),
                };
                persons.push(json!({"person_public_key":text(statement.subject()?,"person_public_key")?,
                    "member":text(statement.subject()?,"member")?,"person_lease_id":statement.id,"not_after":deadline}));
            }
            require(persons.len() <= 4096, "quota_exceeded")?;
            json!({"context_id":s.network.context_id,"persons":persons})
        }
        "groups" => {
            let root = p.root_state_id().map_err(|mut error| {
                if error.code == "state_conflict"
                    && let Some(stream) = p.streams.get(&vec!["root".into()])
                    && stream.heads.len() > 1
                {
                    error.required_ids.extend(stream.heads.iter().cloned());
                }
                error
            })?;
            p.catalog.get(root)?;
            let mut groups = Vec::new();
            let mut failure: Option<Error> = None;
            let mut size =
                encode_json(&json!({"context_id":s.network.context_id,"groups":[]}))?.len();
            for stream in p
                .streams
                .values()
                .filter(|stream| stream.key.first().is_some_and(|kind| kind == "group"))
            {
                // An authenticated inherited floor has no current DEC body.
                // A remembered missing head instead retains its exact ID and
                // must pass through current_statement's proof diagnostics.
                if stream.heads.is_empty() {
                    continue;
                }
                let current = if stream.heads.len() > 1 {
                    let mut error = Error::new("state_conflict");
                    error.required_ids = stream.heads.iter().cloned().collect();
                    Err(error)
                } else {
                    p.current_statement(&stream.key)
                };
                let (statement, _) = match current {
                    Ok(value) => value,
                    Err(e) if inactive(&e) => continue,
                    Err(error) => {
                        if let Some(first) = &mut failure {
                            if first.code == error.code {
                                first.required_ids.extend(error.required_ids);
                            }
                        } else {
                            failure = Some(error);
                        }
                        continue;
                    }
                };
                // Keep evaluating all domains for the selected error class,
                // but no positive response will be emitted after a failure.
                if failure.is_some() {
                    continue;
                }
                require(statement.kind == "group", "state_conflict")?;
                require(statement.body.len() <= MAX_OBJECT, "quota_exceeded")?;
                let entry = json!({"name":stream.key[1],"statement_id":statement.id,
                    "statement_base64":encode(&statement.body)});
                size = size
                    .checked_add(encode_json(&entry)?.len() + usize::from(!groups.is_empty()))
                    .ok_or_else(|| Error::new("quota_exceeded"))?;
                require(size <= 32 << 20 && groups.len() < 4096, "quota_exceeded")?;
                groups.push(entry);
            }
            if let Some(error) = failure {
                return Err(error);
            }
            json!({"context_id":s.network.context_id,"groups":groups})
        }
        "provider" => {
            let selected = s
                .selection
                .as_ref()
                .ok_or_else(|| Error::new("not_found"))?;
            let value = p.provider_potential(
                &selected.person_key,
                &s.network.own_identity.host_public_key,
                (selected.kind == "device").then_some(selected.lease_id.as_str()),
            )?;
            provider_available(store, s, read.device_available)?;
            value
        }
        "catalog" => json!({"catalog":parse(&p.catalog.bytes,MAX_CATALOG)?}),
        "access-versions" => {
            let mut policies = Vec::new();
            let mut groups = Vec::new();
            for stream in p.streams.values() {
                match stream.key.as_slice() {
                    [kind,person] if kind=="policy"=>policies.push(json!({"person_public_key":person,"version":stream.maximum,"statement_ids":stream.at_maximum,"head_ids":stream.heads})),
                    [kind,name] if kind=="group"=>groups.push(json!({"name":name,"version":stream.maximum,"statement_ids":stream.at_maximum,"head_ids":stream.heads})),_=>{}
                }
            }
            json!({"policies":policies,"groups":groups})
        }
        "root-retention" => p.root_retention_preview()?,
        "planning" => {
            let streams=p.streams.values().map(|stream|->Result<Value>{
                let (kind,subject,subject2)=match stream.key.as_slice() { [kind] if kind=="root"=>(kind.as_str(),"-","-"),[kind,subject]=>(kind.as_str(),subject.as_str(),"-"),[kind,subject,subject2]=>(kind.as_str(),subject.as_str(),subject2.as_str()),_=>return Err(Error::new("state_conflict"))};
                let floors=if stream.at_maximum.is_empty() && s.context.origin=="migration" {vec![s.context.origin_proof_id.clone()]} else {Vec::new()};
                Ok(json!({"stream_kind":kind,"subject":subject,"subject2":subject2,"head_ids":stream.heads,"version":stream.maximum,"statement_ids":stream.at_maximum,"floor_proof_ids":floors}))
            }).collect::<Result<Vec<_>>>()?;
            json!({"network":public_network(store,&read)?,"decision_time":p.decision_time,"catalog":parse(&p.catalog.bytes,MAX_CATALOG)?,"streams":streams})
        }
        _ => return Err(Error::new("not_found")),
    };
    encode_json(&value)
}
fn inactive(error: &Error) -> bool {
    matches!(
        error.code,
        "authority_expired"
            | "expired"
            | "not_yet_valid"
            | "forbidden"
            | "person_removed"
            | "device_revoked"
    )
}
fn path_person(encoded: &str) -> Result<String> {
    let mut bytes = Vec::new();
    let mut input = encoded.as_bytes().iter().copied();
    while let Some(byte) = input.next() {
        if byte == b'%' {
            let a = input
                .next()
                .and_then(|c| (c as char).to_digit(16))
                .ok_or_else(|| Error::new("invalid"))?;
            let b = input
                .next()
                .and_then(|c| (c as char).to_digit(16))
                .ok_or_else(|| Error::new("invalid"))?;
            bytes.push((a * 16 + b) as u8);
        } else {
            bytes.push(byte);
        }
    }
    let person = String::from_utf8(bytes).map_err(|_| Error::new("invalid"))?;
    check(key(&person))?;
    Ok(person)
}
fn current_policy(
    store: &Store,
    network: &str,
    person: &str,
    context: Option<&OnceLock<String>>,
) -> Result<Vec<u8>> {
    let person = path_person(person)?;
    let read = capture(store, network, context)?;
    let stream = vec!["policy".to_owned(), person];
    require(
        read.projection
            .streams
            .get(&stream)
            .is_some_and(|s| !s.heads.is_empty()),
        "not_found",
    )?;
    let statement = match read.projection.current_statement(&stream) {
        Ok((statement, _)) => statement,
        Err(e) if inactive(&e) => return Err(Error::new("not_found")),
        Err(e) => return Err(e),
    };
    require(statement.body.len() <= MAX_OBJECT, "quota_exceeded")?;
    let body = encode_json(
        &json!({"statement_id":statement.id,"statement_base64":encode(&statement.body)}),
    )?;
    require(body.len() <= 2 << 20, "quota_exceeded")?;
    Ok(body)
}
fn networks(store: &Store, _time: &str) -> Result<Vec<u8>> {
    // All coupled rows are copied under one coherent held read transaction;
    // local SSH availability is checked only after releasing it.
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let time = now()?;
    let mut q = tx
        .prepare("SELECT id,record FROM networks ORDER BY id")
        .map_err(db)?;
    let rows = q
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .map_err(db)?;
    let mut captured = Vec::new();
    for row in rows {
        let (id, raw) = row.map_err(db)?;
        let v: Value = serde_json::from_str(&raw).map_err(|_| Error::new("state_conflict"))?;
        if v.get("mode").and_then(Value::as_str) != Some("decentralized") {
            continue;
        }
        let snapshot = Snapshot::load(&tx, &id, &store.identity().public_key)?;
        let projection = snapshot.project(&time)?;
        let delivery = views::delivery(&tx, &id, &snapshot.network.context_id)?;
        let device_available = snapshot
            .selection
            .as_ref()
            .map(|s| owned_device(&tx, s))
            .transpose()?
            .unwrap_or(false);
        captured.push(Read {
            snapshot,
            projection,
            delivery,
            device_available,
        });
    }
    drop(q);
    tx.commit().map_err(db)?;
    drop(c);
    encode_json(&Value::Array(
        captured
            .iter()
            .map(|r| public_network(store, r))
            .collect::<Result<Vec<_>>>()?,
    ))
}
fn invitation(store: &Store, network: &str, input: &Obj) -> Result<Vec<u8>> {
    // `expires_at` is optional (DEC-Q2): 60 to 86400 seconds after the
    // decision time; the default is one hour.
    let lifetime = input.get("expires_at");
    if lifetime.is_some() {
        fields(input, "member expected_person_public_key expires_at")?;
    } else {
        fields(input, "member expected_person_public_key")?;
    }
    label(text(input, "member")?)?;
    let person = text(input, "expected_person_public_key")?;
    check(person == "-" || key(person))?;
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let snapshot = load(&tx, network, &store.identity().public_key)?;
    let projection = snapshot.project(&now()?)?;
    let own = projection
        .members()?
        .into_iter()
        .find(|m| m.host_public_key == store.identity().public_key)
        .ok_or_else(|| Error::new("forbidden"))?;
    let actual = decision_clock(&now()?, &projection.decision_time)?;
    require(actual < own.not_after, "authority_expired")?;
    let contact = super::bootstrap_io::own_contact(
        &tx,
        store,
        &actual,
        network,
        &snapshot.network.context_id,
    )?;
    let helpers = store
        .bootstrap_settings
        .read()
        .map_err(|_| Error::new("internal"))?
        .rendezvous
        .clone();
    let end = match lifetime {
        Some(value) => {
            let end = value.as_str().ok_or_else(|| Error::new("invalid"))?;
            let lasts = stamp(end)? - stamp(&actual)?;
            check(
                lasts >= chrono::TimeDelta::seconds(super::bootstrap::INVITE_MIN)
                    && lasts <= chrono::TimeDelta::seconds(super::bootstrap::INVITE_MAX),
            )?;
            end.to_owned()
        }
        None => (stamp(&actual)? + chrono::TimeDelta::seconds(super::bootstrap::INVITE_DEFAULT))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string(),
    };
    // The return secret of the automatic return path (DEC-Q3).
    let mut secret = [0u8; 16];
    getrandom::fill(&mut secret).map_err(|_| Error::new("internal"))?;
    let (invite, token) = super::bootstrap::Invitation::create(
        &store.signing_key,
        &json!({"descriptor":snapshot.descriptor,"member":text(input,"member")?,"expected_person_public_key":person,"issued_at":actual,"expires_at":end,"contacts":[parse(&contact.body,8<<10)?],"helpers":helpers,"return_secret_base64":encode(&secret)}),
        &actual,
    )?;
    super::invite_return::remember(&tx, &invite, &secret)?;
    let result = encode_json(
        &json!({"network_id":network,"context_id":snapshot.network.context_id,"invitation_id":invite.id,"invitation":token,"expires_at":invite.expires_at}),
    )?;
    tx.commit().map_err(db)?;
    Ok(result)
}
fn select_provider(store: &Store, network: &str, request: &Obj, _time: &str) -> Result<Vec<u8>> {
    fields(
        request,
        "provider_id person_public_key host_public_key approve",
    )?;
    let provider = text(request, "provider_id")?;
    let person = text(request, "person_public_key")?;
    let host = text(request, "host_public_key")?;
    check(key(person) && key(host) && (key(provider) || ident(provider, "ds_")))?;
    let approve = request
        .get("approve")
        .and_then(Value::as_bool)
        .ok_or_else(|| Error::new("invalid"))?;
    let (captured, requested, requested_selection, requested_owned) = {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        let mut snapshot = load(&tx, network, &store.identity().public_key)?;
        check(host == store.identity().public_key)?;
        let identity = &snapshot.network.own_identity;
        check(identity.person_public_key == "-" || identity.person_public_key == person)?;
        let projection = snapshot.project(&now()?)?;
        let member = projection.member_for(host, person)?;
        let device = ident(provider, "ds_");
        let value = projection.provider_potential(person, host, device.then_some(provider))?;
        let selection = ProviderSelection {
            kind: if device { "device" } else { "original" }.into(),
            person_key: person.into(),
            device_key: if device {
                value
                    .get("device_public_key")
                    .and_then(Value::as_str)
                    .ok_or_else(|| Error::new("invalid"))?
            } else {
                "-"
            }
            .into(),
            lease_id: if device { provider } else { "-" }.into(),
        };
        if !device {
            check(provider == person)?;
        }
        let device_available = owned_device(&tx, &selection)?;
        if device {
            require(device_available, "signer_unavailable")?;
        }
        let requested_selection = selection.clone();
        if approve {
            tx.execute("INSERT INTO dec_signers(network_id,context_id,provider_kind,person_key,device_key,lease_id) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(network_id,context_id) DO UPDATE SET provider_kind=excluded.provider_kind,person_key=excluded.person_key,device_key=excluded.device_key,lease_id=excluded.lease_id",rusqlite::params![network,snapshot.network.context_id,selection.kind,selection.person_key,selection.device_key,selection.lease_id]).map_err(db)?;
            snapshot.network.own_identity.person_public_key = person.into();
            snapshot.network.own_identity.member = member.member;
            tx.execute(
                "UPDATE networks SET record=?2 WHERE id=?1",
                rusqlite::params![
                    network,
                    serde_json::to_string(&snapshot.network).map_err(|_| Error::new("internal"))?
                ],
            )
            .map_err(db)?;
            let clock = json!({"format":1,"largest_local_time":projection.decision_time});
            tx.execute("INSERT INTO dec_clock(network_id,record) VALUES(?1,?2) ON CONFLICT(network_id) DO UPDATE SET record=excluded.record",rusqlite::params![network,clock.to_string()]).map_err(db)?;
            snapshot.selection = Some(selection);
        }
        let delivery = views::delivery(&tx, network, &snapshot.network.context_id)?;
        let current_owned = snapshot
            .selection
            .as_ref()
            .map(|s| owned_device(&tx, s))
            .transpose()?
            .unwrap_or(false);
        tx.commit().map_err(db)?;
        (
            Read {
                snapshot,
                projection,
                delivery,
                device_available: current_owned,
            },
            value,
            requested_selection,
            device_available,
        )
    };
    let n = public_network(store, &captured)?;
    let requested_state = views::availability_state(selected_available(
        store,
        &requested_selection,
        requested_owned,
    ));
    encode_json(&json!({"network":n,"provider":requested,"provider_state":requested_state}))
}
struct Route {
    method: &'static str,
    stage: &'static str,
}
fn route(parts: &[&str]) -> Option<Route> {
    let (method, stage) = match parts {
        ["v2", "info"] => ("GET", "request"),
        ["v2", "status"] => ("GET", "repair"),
        ["v2", "link", "approvals"] => ("POST", "owner"),
        ["v2", "link", "admissions"] => ("POST", "administrator"),
        ["v2", "link", "requests", _, "approval"] => ("GET", "owner"),
        ["v2", "link", "requests", _, "signed"] => ("POST", "sign"),
        ["v2", "link", "requests"] => ("GET, POST", "request"),
        ["v2", "link", "requests", _] => ("GET", "request"),
        ["v2", "link", "requests", _, "resume" | "cancel"] => ("POST", "request"),
        ["v2", "link", "requests", _, "selection"] => ("POST", "selection"),
        ["v2", "link", "requests", _, "commit"] => ("POST", "commit"),
        ["v2", "link", "requests", _, "finalization"] => ("POST", "owner_finalization"),
        ["v2", "networks"] => ("GET, POST", "create"),
        ["v2", "network-creations", _] => ("GET", "create"),
        ["v2", "network-creations", _, "approve"] => ("POST", "create"),
        ["v2", "network-creations", _, "signed"] => ("POST", "sign"),
        ["v2", "networks", _] => ("GET", "repair"),
        ["v2", "networks", _, "provider"] => ("GET, POST", "sign"),
        ["v2", "networks", _, "policy-edits"] => ("GET", "sign"),
        ["v2", "networks", _, "policy-edits", "plan"] => ("POST", "sign"),
        ["v2", "networks", _, "policy-edits", "reapply-preview"] => ("POST", "repair"),
        ["v2", "networks", _, "invitations"] => ("POST", "request"),
        ["v2", "networks", _, "root-transitions"] => ("POST", "sign"),
        ["v2", "networks", _, "migration", "identity"] => ("POST", "migration"),
        [
            "v2",
            "networks",
            _,
            "migration",
            "prepare" | "signed" | "resume" | "review" | "host-lease" | "device-bans" | "link"
            | "acknowledgment" | "commit" | "adopt",
        ] => ("POST", "migration"),
        ["v2", "networks", _, "migration", "evidence"] => ("GET, POST", "migration"),
        ["v2", "networks", _, "migration"] => ("GET", "migration"),
        ["v2", "networks", _, "actions" | "policy-claims"] => ("POST", "sign"),
        ["v2", "networks", _, "actions" | "policy-claims", _] => ("GET", "sign"),
        [
            "v2",
            "networks",
            _,
            "actions" | "policy-claims",
            _,
            "signed",
        ] => ("POST", "sign"),
        [
            "v2",
            "networks",
            _,
            "members" | "persons" | "groups" | "catalog" | "access-versions" | "planning"
            | "root-retention",
        ] => ("GET", "repair"),
        ["v2", "networks", _, "policy", _] => ("GET", "repair"),
        _ => return None,
    };
    Some(Route { method, stage })
}
async fn dispatch(
    State(store): State<Arc<Store>>,
    uri: Uri,
    method: Method,
    body: std::result::Result<Bytes, BytesRejection>,
) -> Response {
    let path = uri.path().to_owned();
    let parts: Vec<_> = path.trim_start_matches('/').split('/').collect();
    let Some(route) = route(&parts) else {
        return failure(Error::new("not_found"), "-", "-", "request", None);
    };
    let network = if parts.get(1) == Some(&"networks") {
        parts.get(2).copied().unwrap_or("-")
    } else {
        "-"
    };
    if !route.method.split(", ").any(|m| m == method.as_str()) {
        return failure(
            Error::new("invalid"),
            network,
            "-",
            route.stage,
            Some(route.method),
        );
    }
    let body = match body {
        Ok(body) => body,
        Err(_) => return failure(Error::new("invalid"), network, "-", route.stage, None),
    };
    if uri.query().is_some() || (method == Method::GET && !body.is_empty()) {
        return failure(Error::new("invalid"), network, "-", route.stage, None);
    }
    let limit = if matches!(
        parts.as_slice(),
        ["v2", "networks", _, "migration", "host-lease"]
    ) {
        2 << 20
    } else if matches!(
        parts.as_slice(),
        ["v2", "networks", _, "migration", "evidence"]
    ) {
        20 << 20
    } else {
        1 << 20
    };
    if body.len() > limit {
        return failure(
            Error::new("quota_exceeded"),
            network,
            "-",
            route.stage,
            None,
        );
    }
    let object = if method == Method::POST {
        match parse(&body, limit).and_then(|v| object(&v).cloned()) {
            Ok(value) => Some(value),
            Err(e) => return failure(e, network, "-", route.stage, None),
        }
    } else {
        None
    };
    if method == Method::POST
        && let ["v2", "link", "requests", id, "resume"] = parts.as_slice()
    {
        match completed_resume(
            store.clone(),
            id,
            object.as_ref().ok_or_else(|| Error::new("invalid")),
        )
        .await
        {
            Ok(Some(body)) if body.len() <= 32 << 20 => {
                return (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/json")],
                    body,
                )
                    .into_response();
            }
            Ok(Some(_)) => {
                return failure(
                    Error::new("quota_exceeded"),
                    network,
                    "-",
                    route.stage,
                    None,
                );
            }
            Ok(None) => {}
            Err(error) => return failure(error, network, "-", route.stage, None),
        }
    }
    if method == Method::POST && parts.as_slice() == ["v2", "link", "admissions"] {
        let capture = store.clone();
        let input = object.clone().unwrap_or_default();
        let id = match tokio::task::spawn_blocking(move || {
            super::ceremony_admin::open(&capture, &input)
        })
        .await
        .unwrap_or_else(|_| Err(Error::new("internal")))
        {
            Ok(id) => id,
            Err(e) => return failure(e, network, "-", route.stage, None),
        };
        if let Err(e) = requests_io::poll(store.clone(), &id).await {
            return failure(e, network, "-", route.stage, None);
        }
    }
    if method == Method::POST
        && let ["v2", "link", "requests", id, "finalization"] = parts.as_slice()
    {
        // A carrier's real retention deadline cannot invalidate an exact
        // already retained prefix. The typed writer still checks every packet,
        // current authority/clock/term and final review pin independently.
        let capture = store.clone();
        let id = id.to_string();
        let input = object.clone().unwrap_or_default();
        let cached = tokio::task::spawn_blocking(move || -> Result<bool> {
            let c = capture.connection().map_err(|_| Error::new("internal"))?;
            let p = requests::load(&c, &id)?;
            Ok(p.record.owner_offer_id == text(&input, "owner_offer_id")?
                && p.record.owner_packet_base64 != "-"
                && p.record.selection_id == text(&input, "selection_id")?
                && p.record.selection_packet_base64 != "-"
                && p.record.administrator_offer_id == text(&input, "administrator_offer_id")?
                && (p.record.administrator_packet_base64 != "-"
                    || (p.record.mode == "renew" && p.record.administrator_offer_id == "-")))
        })
        .await
        .unwrap_or_else(|_| Err(Error::new("internal")));
        let cached = match cached {
            Ok(cached) => cached,
            Err(e) => return failure(e, network, "-", route.stage, None),
        };
        if !cached && let Err(e) = requests_io::poll(store.clone(), parts[3]).await {
            return failure(e, network, "-", route.stage, None);
        }
    }
    let create_request = method == Method::POST
        && (parts.as_slice() == ["v2", "link", "requests"]
            || matches!(parts.as_slice(), ["v2", "networks", _, "migration", "link"]));
    let resume_request = method == Method::POST
        && matches!(parts.as_slice(), ["v2", "link", "requests", _, "resume"]);
    let selection_request = method == Method::POST
        && matches!(
            parts.as_slice(),
            [
                "v2",
                "link",
                "requests",
                _,
                "selection" | "commit" | "signed" | "finalization"
            ] | ["v2", "link", "approvals" | "admissions"]
        )
        && object
            .as_ref()
            .and_then(|o| o.get("approve"))
            .and_then(Value::as_bool)
            == Some(true)
        || method == Method::POST
            && matches!(parts.as_slice(), ["v2", "link", "requests", _, "signed"]);
    let transport_store = store.clone();
    let method = method.to_string();
    let network = network.to_owned();
    let error_network = network.clone();
    let error_context = Arc::new(OnceLock::new());
    let read_context = error_context.clone();
    let stage = route.stage;
    let timed = crate::timing::current();
    let result = tokio::task::spawn_blocking(move || -> Result<(u16, Vec<u8>)> {
        let _request = crate::timing::within(timed);
        let parts: Vec<_> = path.trim_start_matches('/').split('/').collect();
        // Each current-state operation captures guarded time inside its own
        // coherent snapshot. Historical exact replies need no clock read.
        let time = "-";
        let body = match parts.as_slice() {
            ["v2","networks",id,"policy",person] => current_policy(&store,id,person,Some(&read_context)),
            ["v2","info"] => {let identity=store.identity();encode_json(&json!({"id":identity.id,"public_key":identity.public_key,"created_at":identity.created_at,"default_coordinator":Value::Null,"network_protocols":["peerspan-decentralized-v1"]}))},
            ["v2","networks",id,"root-transitions"] => super::roots::prepare(&store,id,object.as_ref().ok_or_else(||Error::new("invalid"))?),
            ["v2","status"] => encode_json(&store.status_v2().map_err(|_|Error::new("state_conflict"))?),
            ["v2","networks",id,"migration","link"] => return super::migration_link::create(&store,id,object.as_ref().ok_or_else(||Error::new("invalid"))?),
            ["v2","networks",id,"migration","adopt"] => super::migration_adopt::adopt(&store,id,object.as_ref().ok_or_else(||Error::new("invalid"))?),
            ["v2","networks",id,"migration","commit"] => super::migration_commit::prepare(&store,id,object.as_ref().ok_or_else(||Error::new("invalid"))?),
            ["v2","networks",id,"migration","acknowledgment"] => super::migration_ack::acknowledge(&store,id,object.as_ref().ok_or_else(||Error::new("invalid"))?),
            ["v2","networks",id,"migration","identity"] => super::migration_local::identity(&store,id,object.as_ref().ok_or_else(||Error::new("invalid"))?),
            ["v2","networks",id,"migration","prepare"] => super::migration_prepare::prepare(&store,id,object.as_ref().ok_or_else(||Error::new("invalid"))?),
            ["v2","networks",id,"migration","signed"] => super::migration_prepare::signed(&store,id,object.as_ref().ok_or_else(||Error::new("invalid"))?),
            ["v2","networks",id,"migration","resume"] => super::migration_evidence::resume(&store,id,object.as_ref().ok_or_else(||Error::new("invalid"))?),
            ["v2","networks",id,"migration","review"] => super::migration_evidence::participate(&store,id,object.as_ref().ok_or_else(||Error::new("invalid"))?),
            ["v2","networks",id,"migration","host-lease"] => super::migration_host::prepare(&store,id,object.as_ref().ok_or_else(||Error::new("invalid"))?),
            ["v2","networks",id,"migration","device-bans"] => super::migration_device_bans::prepare(&store,id,object.as_ref().ok_or_else(||Error::new("invalid"))?),
            ["v2","networks",id,"migration","evidence"] if method=="POST" => super::migration_evidence::receive(&store,id,object.as_ref().ok_or_else(||Error::new("invalid"))?),
            ["v2","networks",id,"migration","evidence"] => super::migration_prepare::evidence(&store,id),
            ["v2","networks",id,"migration"] => super::migration_local::status(&store,id),
            ["v2","networks",id,"invitations"] =>return invitation(&store,id,object.as_ref().ok_or_else(||Error::new("invalid"))?).map(|body|(201,body)),
            ["v2","link","admissions"] => super::ceremony_admin::prepare(&store,object.as_ref().ok_or_else(||Error::new("invalid"))?),
            ["v2","link","approvals"] => super::ceremony::owner(&store,object.as_ref().ok_or_else(||Error::new("invalid"))?),
            ["v2","link","requests",id,"approval"] => super::ceremony::get(&store,id),
            ["v2","link","requests",id,"signed"] => super::ceremony::signed(&store,id,object.as_ref().ok_or_else(||Error::new("invalid"))?),
            ["v2","link","requests",id,"finalization"] => super::ceremony_finalization::prepare(&store,id,object.as_ref().ok_or_else(||Error::new("invalid"))?),
            ["v2", "link", "requests"] if method == "POST" => {
                return requests::create(
                    &store,
                    object.as_ref().ok_or_else(|| Error::new("invalid"))?,
                );
            }
            ["v2", "link", "requests"] => requests::get(&store, None, false),
            ["v2", "link", "requests", id] => requests::get(&store, Some(id), false),
            ["v2", "link", "requests", id, "resume"] => {
                fields(object.as_ref().ok_or_else(|| Error::new("invalid"))?, "")?;
                requests::resume(&store, id)?;
                super::observer::observe(&store,id)?;
                requester::resume_approved(&store,id)?;
                requests::get(&store,Some(id),true)
            }
            ["v2", "link", "requests", id, "cancel"] => {
                fields(object.as_ref().ok_or_else(|| Error::new("invalid"))?, "")?;
                requests::cancel(&store, id)
            }
            ["v2", "link", "requests", id, "selection"] => requester::select(&store,id,object.as_ref().ok_or_else(||Error::new("invalid"))?),
            ["v2", "link", "requests", id, "commit"] => requester::commit(&store,id,object.as_ref().ok_or_else(||Error::new("invalid"))?),
            ["v2", "networks"] if method == "POST" => creation::create(
                &store,
                object.as_ref().ok_or_else(|| Error::new("invalid"))?,
                time,
            ),
            ["v2", "networks"] => networks(&store, time),
            ["v2", "network-creations", id] => creation::get(&store, id),
            ["v2", "network-creations", id, "approve"] => creation::approve(
                &store,
                id,
                object.as_ref().ok_or_else(|| Error::new("invalid"))?,
                time,
            ),
            ["v2", "network-creations", id, "signed"] => creation::signed(
                &store,
                id,
                object.as_ref().ok_or_else(|| Error::new("invalid"))?,
                time,
            ),
            ["v2", "networks", id, "provider"] if method == "POST" => select_provider(
                &store,
                id,
                object.as_ref().ok_or_else(|| Error::new("invalid"))?,
                time,
            ),
            ["v2", "networks", id, "policy-edits", "plan"] => edits::plan(
                &store,
                id,
                object.as_ref().ok_or_else(|| Error::new("invalid"))?,
            ),
            ["v2", "networks", id, "policy-edits"] => edits::summary(&store, id),
            ["v2", "networks", id, "policy-edits", "reapply-preview"] => edits::reapply_preview(&store,id,object.as_ref().ok_or_else(||Error::new("invalid"))?,&read_context),
            ["v2", "networks", id, kind @ ("actions" | "policy-claims")] => actions::prepare(
                &store,
                id,
                object.as_ref().ok_or_else(|| Error::new("invalid"))?,
                *kind == "policy-claims",
            ),
            [
                "v2",
                "networks",
                id,
                kind @ ("actions" | "policy-claims"),
                action,
            ] => actions::get(&store, id, action, *kind == "policy-claims"),
            [
                "v2",
                "networks",
                id,
                kind @ ("actions" | "policy-claims"),
                action,
                "signed",
            ] => actions::signed(
                &store,
                id,
                action,
                object.as_ref().ok_or_else(|| Error::new("invalid"))?,
                *kind == "policy-claims",
            ),
            ["v2", "networks", id] => read_network_context(&store, id, "", time, Some(&read_context)),
            ["v2", "networks", id, suffix] => read_network_context(&store, id, suffix, time, Some(&read_context)),
            _ => Err(Error::new("not_found")),
        };
        body.map(|body| (200, body))
    })
    .await
    .unwrap_or_else(|_| Err(Error::new("internal")));
    let result = match result {
        Ok((status, body)) if create_request || resume_request => {
            match parse(&body, 32 << 20).and_then(|v| {
                v.get("request_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| Error::new("internal"))
            }) {
                Ok(id) => {
                    let delivery = requests_io::publish(transport_store.clone(), &id).await;
                    if create_request {
                        // The automatic return path, one 30-second attempt
                        // (spec 8.1 step 4, DEC-Q3).
                        let _ = tokio::time::timeout(
                            std::time::Duration::from_secs(30),
                            super::invite_return::send(transport_store.clone(), &id),
                        )
                        .await;
                    }
                    let refresh = transport_store.clone();
                    let read_id = id.clone();
                    let refreshed = tokio::task::spawn_blocking(move || {
                        requests::get(&refresh, Some(&read_id), true)
                    })
                    .await
                    .unwrap_or_else(|_| Err(Error::new("internal")));
                    let body = refreshed.unwrap_or(body);
                    if create_request {
                        Ok((
                            status,
                            match delivery {
                                Ok(()) => body,
                                Err(e) => {
                                    requests_io::transport_attention(&body, &e).unwrap_or(body)
                                }
                            },
                        ))
                    } else {
                        resume_delivery(transport_store.clone(), &id, status, delivery.err()).await
                    }
                }
                Err(e) => Err(e),
            }
        }
        Ok((status, body)) if selection_request => {
            async {
                let mut wrapper = parse(&body, 32 << 20)?;
                let id = wrapper["request"]["request_id"]
                    .as_str()
                    .unwrap_or("-")
                    .to_owned();
                let mut delivery = requests_io::publish(transport_store.clone(), &id)
                    .await
                    .err();
                let applied = apply_after_publication(transport_store.clone(), &id).await?;
                if applied
                    && let Err(error) = requests_io::publish(transport_store.clone(), &id).await
                    && delivery.is_none()
                {
                    delivery = Some(error);
                }
                let capture = transport_store.clone();
                let request_id = id.clone();
                wrapper["request"] = tokio::task::spawn_blocking(move || {
                    requests::get(&capture, Some(&request_id), false)
                        .and_then(|raw| parse(&raw, 32 << 20))
                })
                .await
                .map_err(|_| Error::new("internal"))??;
                if let Some(e) = delivery
                    && let Ok(raw) = encode_json(&wrapper["request"])
                    && let Ok(attention) = requests_io::transport_attention(&raw, &e)
                    && let Ok(view) = parse(&attention, 32 << 20)
                {
                    wrapper["request"] = view;
                }
                encode_json(&wrapper).map(|body| (status, body))
            }
            .await
        }
        other => other,
    };
    let error_context = error_context.get().map(String::as_str).unwrap_or("-");
    match result {
        Ok((status, body)) if body.len() <= 32 << 20 => (
            StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            [(header::CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response(),
        Ok(_) => failure(
            Error::new("quota_exceeded"),
            &error_network,
            error_context,
            stage,
            None,
        ),
        Err(e) => failure(e, &error_network, error_context, stage, None),
    }
}
/// Explicit completed delivery repair has one bounded attempt, without
/// entering the pending intent/observer/apply/clock workflow again.
async fn completed_resume(
    store: Arc<Store>,
    id: &str,
    input: Result<&Obj>,
) -> Result<Option<Vec<u8>>> {
    fields(input?, "")?;
    let capture = store.clone();
    let request_id = id.to_owned();
    let applied = tokio::task::spawn_blocking(move || {
        let c = capture.connection().map_err(|_| Error::new("internal"))?;
        requests::load(&c, &request_id).map(|p| p.record.terminal == "applied")
    })
    .await
    .map_err(|_| Error::new("internal"))??;
    if !applied {
        return Ok(None);
    }
    let publication = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        super::completion::publish(store.clone(), id),
    )
    .await;
    let attention = match publication {
        Ok(Ok(_)) => None,
        Ok(Err(mut error)) => {
            if error.stage != Some("transport") && error.code != "quota_exceeded" {
                return Err(error);
            }
            error.stage = Some("transport");
            Some(error)
        }
        Err(_) => {
            let mut error = Error::new("recovery_required");
            error.stage = Some("transport");
            Some(error)
        }
    };
    let capture = store;
    let request_id = id.to_owned();
    let body =
        tokio::task::spawn_blocking(move || requests::get(&capture, Some(&request_id), false))
            .await
            .map_err(|_| Error::new("internal"))??;
    Ok(Some(match attention {
        Some(error) => requests_io::transport_attention(&body, &error)?,
        None => body,
    }))
}
async fn resume_delivery(
    store: Arc<Store>,
    id: &str,
    status: u16,
    delivery: Option<Error>,
) -> Result<(u16, Vec<u8>)> {
    let mut attention = None;
    if let Some(error) = delivery {
        attention = Some(error);
    }
    match requests_io::poll(store.clone(), id).await {
        Ok(()) => {
            let target = store.clone();
            let resume_id = id.to_owned();
            tokio::task::spawn_blocking(move || requester::resume_approved(&target, &resume_id))
                .await
                .map_err(|_| Error::new("internal"))??;
        }
        Err(error) if error.stage == Some("transport") => {
            if attention.is_none() {
                attention = Some(error)
            }
        }
        Err(error) => return Err(error),
    }
    if let Err(error) = requests_io::publish(store.clone(), id).await
        && attention.is_none()
    {
        attention = Some(error)
    }
    // Carrier storage failure is not a membership predicate. The actual local
    // apply still performs all current proof/consent/clock checks in its TX.
    let applied = apply_after_publication(store.clone(), id).await?;
    if applied
        && let Err(error) = requests_io::publish(store.clone(), id).await
        && attention.is_none()
    {
        attention = Some(error);
    }
    let target = store.clone();
    let read_id = id.to_owned();
    let body = tokio::task::spawn_blocking(move || requests::get(&target, Some(&read_id), true))
        .await
        .map_err(|_| Error::new("internal"))??;
    Ok((
        status,
        match attention {
            Some(error) => requests_io::transport_attention(&body, &error)?,
            None => body,
        },
    ))
}

async fn apply_after_publication(store: Arc<Store>, id: &str) -> Result<bool> {
    let id = id.to_owned();
    tokio::task::spawn_blocking(move || super::completion::apply_local(&store, &id))
        .await
        .map_err(|_| Error::new("internal"))?
}

fn failure(
    error: Error,
    network: &str,
    context: &str,
    stage: &str,
    allow: Option<&str>,
) -> Response {
    let stage = error.stage.unwrap_or(stage);
    let status = if allow.is_some() {
        StatusCode::METHOD_NOT_ALLOWED
    } else {
        match error.code {
            "invalid" => StatusCode::BAD_REQUEST,
            "forbidden"
            | "authority_expired"
            | "device_revoked"
            | "not_yet_valid"
            | "authority_would_be_invalidated" => StatusCode::FORBIDDEN,
            "not_found" => StatusCode::NOT_FOUND,
            "expired" => StatusCode::GONE,
            "rate_limited" => StatusCode::TOO_MANY_REQUESTS,
            "upgrade_required" => StatusCode::UPGRADE_REQUIRED,
            "internal" => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::CONFLICT,
        }
    };
    let message = if error.code == "internal" {
        "internal error".to_owned()
    } else if let Some(detail) = error.detail {
        format!("{}: {detail}", error.code.replace('_', " "))
    } else {
        error.code.replace('_', " ")
    };
    // Internal exact references on a conflict identify known conflicting
    // objects, not missing proofs. Pure verifier response fields stay separate.
    let (required, conflicts) = if error.code == "state_conflict" {
        (BTreeSet::new(), error.required_ids)
    } else {
        (error.required_ids, BTreeSet::new())
    };
    let body = json!({"code":error.code,"error":message,"details":{"network_id":network,"context_id":context,"request_id":"-","stage":stage,"required_ids":required,"conflict_ids":conflicts,"next":[]}});
    let mut response = (status, axum::Json(body)).into_response();
    if let Some(seconds) = error.retry_after
        && let Ok(value) = seconds.to_string().parse()
    {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    if let Some(allow) = allow
        && let Ok(value) = allow.parse()
    {
        response.headers_mut().insert(header::ALLOW, value);
    }
    response
}
