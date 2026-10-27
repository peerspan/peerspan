//! Exact operation retrieval and atomic local application of signed outcomes.
use super::{
    catalog, ceremony, crypto, map, persistence, request,
    support::{self, Failure},
    transport,
};
use crate::{
    linking,
    store::{Store, append_event},
};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use hyper::Method;
use rusqlite::{OptionalExtension, params};
use serde::Deserialize;
use serde_json::value::RawValue;
use std::{collections::BTreeMap, sync::Arc};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultPayload {
    manifest_id: String,
    activation: Box<RawValue>,
    catalog: Box<RawValue>,
}
async fn load(store: Arc<Store>, id: &str) -> Result<persistence::Pending> {
    let id = id.to_owned();
    tokio::task::spawn_blocking(move || {
        let c = store.connection()?;
        persistence::pending(&c, &id)?
            .ok_or_else(|| Failure::new("not_found", &id, "finalize").into())
    })
    .await?
}
fn link_projection(
    c: &rusqlite::Connection,
    n: &crate::network::Network,
    p: &persistence::Pending,
    raw: &[u8],
    activation: &[u8],
    verification: &str,
) -> Result<catalog::Projection> {
    let descriptor = catalog::descriptor(n)?;
    let epoch = catalog::target_epoch(&catalog::decode(raw, &n.id)?)?;
    let (known, _) = catalog::feature(c, &n.id)?;
    let state = linking::verify_stored_network_state(
        linking::CatalogFactContext {
            network: &descriptor,
            epoch,
            known_feature_id: &known,
            now: support::now()?,
        },
        raw,
    )?;
    linking::verify_stored_activation(
        linking::ActivationContext {
            network: &descriptor,
            epoch,
            known_feature_id: &state.facts.feature_id,
            caller_host_public_key: &p.record.host_public_key,
            expected_person_public_key: &p.record.expected_person_public_key,
            now: support::now()?,
            verification,
        },
        raw,
        activation,
    )?;
    catalog::verify_with_adoption(c, n, raw, support::now()?, Some(&state.facts.feature_id))
}
pub async fn finish(store: Arc<Store>, id: &str) -> Result<bool> {
    let p = load(store.clone(), id).await?;
    if !p.record.commit_approved || p.state == "linked" {
        return Ok(false);
    }
    let descriptor = crypto::bytes(&p.record.network_base64, linking::MAX_OBJECT)?;
    let d: map::Descriptor = linking::decode_mutation(
        &descriptor,
        "network_id name genesis_root_public_key coordinator_address coordinator_public_key",
    )?;
    let path = format!("/coord/v2/networks/{}/link-operations/{}", d.network_id, id);
    let retrieved = transport::request(
        store.clone(),
        &p.record.coordinator_address,
        &p.record.coordinator_public_key,
        Method::GET,
        &path,
        Vec::new(),
    )
    .await;
    let raw = match retrieved {
        Ok(raw) => raw,
        Err(error)
            if error
                .downcast_ref::<Failure>()
                .is_some_and(|f| f.code == "not_found") =>
        {
            // Unknown outcome after deadline stays finalizing with its tombstone.
            if support::now()? >= support::stamp(&p.deadline)? {
                return Ok(false);
            }
            let run = store.clone();
            let p = p.clone();
            let body=tokio::task::spawn_blocking(move||->Result<Vec<u8>>{
                let c=run.connection()?;
                let commit=crypto::bytes(&p.record.commit_packet_base64,linking::MAX_OBJECT)?;
                let activation=ceremony::activation(&p,&commit)?;
                let raw_catalog=crypto::bytes(&p.record.catalog_base64,16<<20)?;
                let descriptor=crypto::bytes(&p.record.network_base64,linking::MAX_OBJECT)?;
                let d:map::Descriptor=linking::decode_mutation(&descriptor,"network_id name genesis_root_public_key coordinator_address coordinator_public_key")?;
                let n=match run.network_record(&c,&d.network_id){Ok(n)=>n,Err(crate::model::Error::NotFound)=>crate::network::Network{id:d.network_id,name:d.name,root_public_key:d.genesis_root_public_key,member:String::new(),coordinator_address:d.coordinator_address,coordinator_public_key:d.coordinator_public_key,administrator:false,last_sync_at:None,last_sync_error:None,root_epoch:0,current_root_public_key:String::new(),root_ssh:false,coordinator_pending:None},Err(e)=>return Err(e.into())};
                let prior=catalog::read(&c,&n.id)?;let merged=catalog::merge(&n.id,&[&prior,&raw_catalog])?;let projection=link_projection(&c,&n,&p,&merged,&activation,"first")?;
                linking::verify_stored_activation(linking::ActivationContext{network:&descriptor,epoch:projection.network.epoch,known_feature_id:&projection.network.facts.feature_id,caller_host_public_key:&p.record.host_public_key,expected_person_public_key:&p.record.expected_person_public_key,now:support::now()?,verification:"first"},&merged,&activation)?;
                let selected=linking::select_stored_proof_catalog(linking::CatalogFactContext{network:&descriptor,epoch:projection.network.epoch,known_feature_id:&projection.network.facts.feature_id,now:support::now()?},&merged,&[linking::ProofSeed{kind:"activation".into(),body:activation.clone()}])?;
                let body=crypto::raw_object(vec![("activation",activation),("catalog",selected),("address",serde_json::to_vec(&run.advertised())?),("candidates",serde_json::to_vec(&run.published_candidates().iter().map(ToString::to_string).collect::<Vec<_>>())?)])?;
                ensure!(body.len()<=512<<10,Failure::new("quota_exceeded",&p.request_id,"operation"));Ok(body)
            }).await??;
            transport::request(
                store.clone(),
                &d.coordinator_address,
                &d.coordinator_public_key,
                Method::POST,
                &format!("/coord/v2/networks/{}/link-operations", d.network_id),
                body,
            )
            .await?
        }
        Err(e) => return Err(e),
    };
    let run = store.clone();
    let id = id.to_owned();
    tokio::task::spawn_blocking(move || apply(&run, &id, &raw)).await??;
    support::barrier(
        "host.result.after_commit",
        &p.request_id,
        std::future::pending(),
    )
    .await?;
    Ok(true)
}
/// Settle only an already durably signed old operation. This path never
/// publishes an activation, signs a packet, refreshes a deadline or recreates a
/// pairing resource; an unknown remote result remains unresolved recovery work.
pub(crate) async fn finish_historical(store: Arc<Store>, id: &str) -> Result<()> {
    let p = load(store.clone(), id).await?;
    ensure!(
        p.record.commit_approved && p.record.commit_packet_base64 != "-",
        Failure::new("recovery_required", id, "resume")
    );
    let lookup = id.to_owned();
    let captured = store.clone();
    let retained = tokio::task::spawn_blocking(move || -> Result<Option<Vec<u8>>> {
        let c = captured.connection()?;
        let raw: Option<String> = c
            .query_row(
                "SELECT record FROM link_operations WHERE request_id=?1",
                [&lookup],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(raw) = raw {
            return Ok(Some(raw.into_bytes()));
        }
        if p.record.result_packet_base64 != "-" {
            return Ok(Some(crypto::bytes(
                &p.record.result_packet_base64,
                linking::MAX_OBJECT,
            )?));
        }
        Ok(None)
    })
    .await??;
    let raw = if let Some(raw) = retained {
        raw
    } else {
        let p = load(store.clone(), id).await?;
        let d: map::Descriptor = linking::decode_mutation(
            &crypto::bytes(&p.record.network_base64, linking::MAX_OBJECT)?,
            "network_id name genesis_root_public_key coordinator_address coordinator_public_key",
        )
        .map_err(|_| Failure::new("recovery_required", id, "resume"))?;
        transport::request(
            store.clone(),
            &p.record.coordinator_address,
            &p.record.coordinator_public_key,
            Method::GET,
            &format!("/coord/v2/networks/{}/link-operations/{}", d.network_id, id),
            Vec::new(),
        )
        .await
        .map_err(|_| Failure::new("recovery_required", id, "resume"))?
    };
    let captured = store.clone();
    let lookup = id.to_owned();
    tokio::task::spawn_blocking(move || apply(&captured, &lookup, &raw))
        .await?
        .map_err(|_| Failure::new("recovery_required", id, "resume"))?;
    Ok(())
}
fn apply(store: &Store, id: &str, raw: &[u8]) -> Result<()> {
    ensure!(
        raw.len() <= linking::MAX_OBJECT,
        Failure::new("invalid", id, "result")
    );
    let mut c = store.connection()?;
    let tx = c.transaction()?;
    let mut p =
        persistence::pending(&tx, id)?.ok_or_else(|| Failure::new("not_found", id, "result"))?;
    ensure!(
        p.record.commit_approved,
        Failure::new("forbidden", id, "result")
    );
    let packet: request::Packet = linking::decode_mutation(
        raw,
        "format request_id role writer_public_key person_public_key certificate_id payload_base64 host_signature device_signature authority_signature",
    )?;
    ensure!(
        packet.request_id == id && packet.role == "result",
        Failure::new("invalid", id, "result")
    );
    linking::read("packet", raw, &p.record.coordinator_public_key, "-")?;
    let payload: ResultPayload = linking::decode_mutation(
        &crypto::bytes(&packet.payload_base64, linking::MAX_PAYLOAD)?,
        "manifest_id activation catalog",
    )?;
    ensure!(
        payload.manifest_id == p.record.manifest_id,
        Failure::new("operation_conflict", id, "result")
    );
    let expected = ceremony::activation(
        &p,
        &crypto::bytes(&p.record.commit_packet_base64, linking::MAX_OBJECT)?,
    )?;
    let actual: BTreeMap<String, Box<RawValue>> = serde_json::from_str(payload.activation.get())?;
    let expected: BTreeMap<String, Box<RawValue>> = serde_json::from_slice(&expected)?;
    ensure!(
        actual.len() == expected.len()
            && expected.iter().all(|(name, body)| actual
                .get(name)
                .is_some_and(|other| other.get() == body.get())),
        Failure::new("operation_conflict", id, "result")
    );
    let descriptor = crypto::bytes(&p.record.network_base64, linking::MAX_OBJECT)?;
    let d: map::Descriptor = linking::decode_mutation(
        &descriptor,
        "network_id name genesis_root_public_key coordinator_address coordinator_public_key",
    )?;
    let (mut n, joined) = match store.network_record(&tx, &d.network_id) {
        Ok(n) => (n, false),
        Err(crate::model::Error::NotFound) => (
            crate::network::Network {
                id: d.network_id,
                name: d.name,
                root_public_key: d.genesis_root_public_key,
                member: String::new(),
                coordinator_address: d.coordinator_address,
                coordinator_public_key: d.coordinator_public_key,
                administrator: false,
                last_sync_at: None,
                last_sync_error: None,
                root_epoch: 0,
                current_root_public_key: String::new(),
                root_ssh: false,
                coordinator_pending: None,
            },
            true,
        ),
        Err(e) => return Err(e.into()),
    };
    ensure!(
        n.coordinator_address == p.record.coordinator_address
            && n.coordinator_public_key == p.record.coordinator_public_key,
        Failure::new("state_conflict", id, "coordinator")
    );
    let old: Option<(String, String, i64)> = tx
        .query_row(
            "SELECT manifest_id,record,locally_applied FROM link_operations WHERE request_id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    if let Some((manifest, record, applied)) = &old {
        ensure!(
            manifest == &p.record.manifest_id && record.as_bytes() == raw,
            Failure::new("operation_conflict", id, "result")
        );
        if *applied == 1 {
            return Ok(());
        }
    }
    if old.is_none() {
        let retained: i64 = tx.query_row(
            "SELECT count(*) FROM link_operations WHERE network_id=?1",
            [&n.id],
            |r| r.get(0),
        )?;
        ensure!(
            retained < 4096,
            Failure::new("quota_exceeded", id, "operation")
        );
    }
    let prior = catalog::read(&tx, &n.id)?;
    let retained = crypto::bytes(&p.record.catalog_base64, 16 << 20)?;
    let activation = payload.activation.get().as_bytes();
    let added = crypto::json(&catalog::Catalog {
        format: 1,
        network_id: n.id.clone(),
        objects: vec![catalog::Entry {
            id: catalog::proof_id("activation", activation),
            kind: "activation".into(),
            body_base64: STANDARD.encode(activation),
        }],
    })?;
    let merged = catalog::merge(
        &n.id,
        &[&prior, &retained, payload.catalog.get().as_bytes(), &added],
    )?;
    let projection = link_projection(&tx, &n, &p, &merged, activation, "historical")?;
    let evidence = linking::verify_stored_activation(
        linking::ActivationContext {
            network: &descriptor,
            epoch: projection.network.epoch,
            known_feature_id: &projection.network.facts.feature_id,
            caller_host_public_key: &p.record.host_public_key,
            expected_person_public_key: &p.record.expected_person_public_key,
            now: support::now()?,
            verification: "historical",
        },
        &merged,
        activation,
    )?;
    ensure!(
        evidence.manifest_id == p.record.manifest_id
            && evidence.request_id == id
            && evidence.device_public_key == p.record.device_public_key
            && evidence.host_public_key == store.identity().public_key,
        Failure::new("operation_conflict", id, "result")
    );
    let local_seed = persistence::device(&tx, &evidence.device_public_key)?;
    ensure!(
        STANDARD.encode(local_seed.verifying_key().as_bytes()) == evidence.device_public_key,
        Failure::new("state_conflict", id, "signer")
    );
    let existing: Option<(String, String)> = tx
        .query_row(
            "SELECT person_key,device_key FROM link_signers WHERE network_id=?1",
            [&n.id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((person, device)) = existing {
        ensure!(
            person == evidence.person_public_key && device == evidence.device_public_key,
            Failure::new("state_conflict", id, "signer")
        );
    }
    let stamp = support::now()?.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let own = projection
        .network
        .members
        .iter()
        .find(|m| m.host_public_key == store.identity().public_key)
        .ok_or_else(|| Failure::new("forbidden", id, "member"))?;
    n.member = own.member.clone();
    if joined {
        tx.execute(
            "INSERT INTO networks(id,record,root_seed) VALUES(?1,?2,NULL)",
            params![n.id, serde_json::to_string(&n)?],
        )?;
        append_event(&tx, "network.joined", &n.id, &stamp)?;
    }
    let prior_members = {
        let mut q =
            tx.prepare("SELECT record FROM network_members WHERE network_id=?1 ORDER BY host_id")?;
        q.query_map([&n.id], |r| r.get::<_, String>(0))?
            .map(|r| Ok(serde_json::from_str(&r?)?))
            .collect::<Result<Vec<crate::network::Member>>>()?
    };
    let mut members = map::projected_members(&projection, &prior_members, &stamp)?;
    map::persist(store, &tx, &mut n, &projection, &mut members, &stamp)?;
    tx.execute("INSERT INTO link_signers(network_id,person_key,device_key,certificate_id) VALUES(?1,?2,?3,?4) ON CONFLICT(network_id) DO UPDATE SET certificate_id=excluded.certificate_id",params![n.id,evidence.person_public_key,evidence.device_public_key,evidence.certificate_id])?;
    tx.execute("INSERT INTO link_operations(request_id,network_id,manifest_id,record,locally_applied) VALUES(?1,?2,?3,?4,1) ON CONFLICT(request_id) DO UPDATE SET locally_applied=1",params![id,n.id,p.record.manifest_id,std::str::from_utf8(raw)?])?;
    p.record.result_packet_base64 = STANDARD.encode(raw);
    p.record.catalog_base64 = STANDARD.encode(&merged);
    p.state = "linked".into();
    p.secret = None;
    tx.execute("DELETE FROM link_frames WHERE request_id=?1", [id])?;
    persistence::save_pending(&tx, &p)?;
    append_event(&tx, "network.link_applied", id, &stamp)?;
    tx.commit()?;
    store.refresh_member_pins(&c)?;
    store.relay_wake.notify_one();
    Ok(())
}
