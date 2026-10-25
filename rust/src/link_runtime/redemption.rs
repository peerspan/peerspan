//! Public retry intents contain no private invitation seed or token.
use super::{
    catalog, crypto, invite, map,
    support::{self, Failure},
    transport,
};
use crate::{
    linking,
    model::Error,
    network::{JoinNetwork, Joined, Network, PersonOutcome},
    store::{Store, append_event},
};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::Signer;
use hyper::Method;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
const KIND: &str = "link_invite_redemption_intent";
const FIELDS: &str = "format network_base64 feature_id feature_binding_base64 redemption_base64 request_base64 submitted result_map_base64";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    format: u64,
    network_base64: String,
    feature_id: String,
    feature_binding_base64: String,
    redemption_base64: String,
    request_base64: String,
    submitted: bool,
    result_map_base64: String,
}
#[derive(Clone)]
struct Prepared {
    network: Network,
    id: String,
    intent: Intent,
}
fn save(c: &Connection, net: &str, id: &str, i: &Intent) -> Result<()> {
    c.execute("INSERT INTO network_statements(network_id,kind,subject,record) VALUES(?1,?2,?3,?4) ON CONFLICT(network_id,kind,subject) DO UPDATE SET record=excluded.record",params![net,KIND,id,String::from_utf8(crypto::json(i)?)?])?;
    Ok(())
}
fn parts(i: &Intent) -> Result<(Vec<u8>, Value, Value, Vec<u8>)> {
    ensure!(
        i.format == 1 && crypto::id(&i.feature_id, "lf_"),
        Failure::new("state_conflict", "-", "invite")
    );
    let descriptor = crypto::bytes(&i.network_base64, linking::MAX_OBJECT)?;
    let redemption = crypto::bytes(&i.redemption_base64, linking::MAX_OBJECT)?;
    let r: Value = linking::decode_mutation(
        &redemption,
        "format mode person_action host_public_key person_public_key joined_at host_invite person_invite host_member_signature person_member_signature",
    )?;
    let request = crypto::bytes(&i.request_base64, 1 << 20)?;
    let req: Value =
        linking::decode_mutation(&request, "redemption catalog address candidates join_ack")?;
    ensure!(
        req["redemption"] == r,
        Failure::new("state_conflict", "-", "invite")
    );
    let seed: Value = linking::decode_mutation(
        &crypto::bytes(&i.feature_binding_base64, linking::MAX_OBJECT)?,
        "binding host_invite_base64 person_invite_base64",
    )?;
    Ok((descriptor, r, seed, request))
}
fn prepare(store: &Store, text: &str, person: Option<&str>, person_only: bool) -> Result<Prepared> {
    // An exact durable retry is found before current expiry checks. Its signed
    // feature consent is reverified at the immutable original joined_at.
    let outer: invite::Token = linking::decode_stored_json(
        &invite::decode_private(text)?,
        "format network token mode host_invite_base64 person_invite_base64 feature_binding catalog",
    )?;
    let descriptor: map::Descriptor = linking::decode_mutation(
        outer.network.get().as_bytes(),
        "network_id name genesis_root_public_key coordinator_address coordinator_public_key",
    )?;
    let normalized = person
        .map(crate::persons::normalize_person_key)
        .transpose()?;
    let host = if person_only {
        "-"
    } else {
        &store.identity().public_key
    };
    let who = normalized.as_deref().unwrap_or("-");
    let binding: Value = serde_json::from_str(outer.feature_binding.get())?;
    let raw_half = if outer.host_invite_base64 != "-" {
        crypto::bytes(&outer.host_invite_base64, linking::MAX_OBJECT)?
    } else {
        crypto::bytes(&outer.person_invite_base64, linking::MAX_OBJECT)?
    };
    let grant: Value = serde_json::from_slice(&raw_half)?;
    let grant = if grant.get("payload_base64").is_some() {
        serde_json::from_slice::<Value>(&crypto::bytes(
            grant["payload_base64"].as_str().unwrap_or(""),
            linking::MAX_PAYLOAD,
        )?)?
    } else {
        grant
    };
    let invite_key = grant["invite_public_key"]
        .as_str()
        .ok_or_else(|| Failure::new("invalid", "-", "invite"))?;
    let mode = outer.mode.as_str();
    ensure!(
        matches!(
            (mode, person_only),
            ("person", true) | ("host" | "member", false)
        ) && (mode != "member" || who != "-"),
        Failure::new("invalid", "-", "invite")
    );
    let id = format!(
        "lri_{}",
        crypto::hash(
            [
                "peerspan-invite-redemption-intent-v1",
                &descriptor.network_id,
                mode,
                host,
                who,
                invite_key
            ]
            .join("\n")
            .as_bytes()
        )
    );
    let c = store.connection()?;
    let existing: Option<String> = c
        .query_row(
            "SELECT record FROM network_statements WHERE network_id=?1 AND kind=?2 AND subject=?3",
            params![descriptor.network_id, KIND, id],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(raw) = existing {
        let intent: Intent = linking::decode_stored_json(raw.as_bytes(), FIELDS)?;
        let (_, r, seed, _) = parts(&intent)?;
        let at = support::stamp(r["joined_at"].as_str().unwrap_or(""))?;
        let decoded = invite::decode(text, at, &intent.feature_id)?;
        ensure!(
            seed == serde_json::from_slice::<Value>(&invite::seed_body(&decoded.token)?)?,
            Failure::new("operation_conflict", "-", "invite")
        );
        return Ok(Prepared {
            network: decoded.network,
            id,
            intent,
        });
    }
    // Changed identities cannot replace an unknown or completed use.
    {
        let mut q =
            c.prepare("SELECT record FROM network_statements WHERE network_id=?1 AND kind=?2")?;
        for raw in q.query_map(params![descriptor.network_id, KIND], |r| {
            r.get::<_, String>(0)
        })? {
            let old: Intent = linking::decode_stored_json(raw?.as_bytes(), FIELDS)?;
            let (_, r, _, _) = parts(&old)?;
            let half = if r["host_invite"].is_object() {
                &r["host_invite"]
            } else {
                &r["person_invite"]
            };
            let old_grant = if half.get("payload_base64").is_some() {
                serde_json::from_slice::<Value>(&crypto::bytes(
                    half["payload_base64"].as_str().unwrap_or(""),
                    linking::MAX_PAYLOAD,
                )?)?
            } else {
                half.clone()
            };
            ensure!(
                !(r["host_public_key"] == host && old_grant["invite_public_key"] == invite_key),
                Failure::new("operation_conflict", "-", "invite")
            );
        }
    }
    let network_count: i64 = c.query_row(
        "SELECT count(*) FROM network_statements WHERE network_id=?1 AND kind=?2",
        params![descriptor.network_id, KIND],
        |r| r.get(0),
    )?;
    let host_count: i64 = c.query_row(
        "SELECT count(*) FROM network_statements WHERE kind=?1",
        [KIND],
        |r| r.get(0),
    )?;
    ensure!(
        network_count < 8 && host_count < 32,
        Failure::new("quota_exceeded", "-", "invite")
    );
    let at = support::now()?;
    let decoded = invite::decode(text, at, "-")?;
    let existing_network = store.network_record(&c, &decoded.network.id).ok();
    if let Some(n) = &existing_network {
        ensure!(
            n.coordinator_address == decoded.network.coordinator_address
                && n.coordinator_public_key == decoded.network.coordinator_public_key,
            Failure::new("state_conflict", "-", "coordinator")
        );
    }
    ensure!(
        person_only || existing_network.is_none(),
        Failure::new("state_conflict", "-", "member")
    );
    if person_only {
        ensure!(
            existing_network.is_some(),
            Failure::new("forbidden", "-", "member")
        );
    }
    let full = linking::verify_stored_network_state(
        linking::CatalogFactContext {
            network: decoded.token.network.get().as_bytes(),
            epoch: decoded.epoch,
            known_feature_id: &decoded.feature,
            now: at,
        },
        decoded.token.catalog.get().as_bytes(),
    )?;
    let skip = mode == "member"
        && full
            .facts
            .state
            .persons
            .get(who)
            .is_some_and(|s| s.admitted);
    if skip {
        ensure!(
            full.facts.person_labels.get(who) == Some(&decoded.member),
            Failure::new("invalid", "-", "person")
        );
    }
    let action = if mode == "host" {
        "none"
    } else if skip {
        "skip"
    } else {
        "admit"
    };
    let joined = at.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let mut redemption = json!({"format":1,"mode":mode,"person_action":action,"host_public_key":host,"person_public_key":if mode=="host"{"-"}else{who},"joined_at":joined,"host_invite":"-","person_invite":"-","host_member_signature":"-","person_member_signature":"-"});
    if mode != "person" {
        redemption["host_invite"] = serde_json::from_slice(&decoded.host)?;
        redemption["host_member_signature"] = json!(
            STANDARD.encode(
                decoded
                    .seed
                    .sign(
                        crate::membership::member_statement(
                            &decoded.network.id,
                            invite_key,
                            host,
                            &joined
                        )
                        .as_bytes()
                    )
                    .to_bytes()
            )
        );
    }
    if action == "admit" {
        ensure!(who != "-", Failure::new("invalid", "-", "person"));
        redemption["person_invite"] = serde_json::from_slice(&decoded.person)?;
        let message = [
            "peerspan-person-member-v1",
            &decoded.network.id,
            invite_key,
            who,
            &joined,
        ]
        .join("\n");
        redemption["person_member_signature"] =
            json!(STANDARD.encode(decoded.seed.sign(message.as_bytes()).to_bytes()));
    }
    let ack = if mode == "person" {
        Value::String("-".into())
    } else {
        let message = ["peerspan-link-feature-ack-v1", &decoded.feature, host].join("\n");
        json!({"format":1,"feature_id":decoded.feature,"host_public_key":host,"signature":STANDARD.encode(store.signing_key.sign(message.as_bytes()).to_bytes())})
    };
    let request = crypto::json(
        &json!({"redemption":redemption,"catalog":serde_json::from_str::<Value>(decoded.token.catalog.get())?,"address":if person_only{String::new()}else{store.advertised()},"candidates":if person_only{Vec::<String>::new()}else{store.published_candidates().iter().map(ToString::to_string).collect()},"join_ack":ack}),
    )?;
    ensure!(
        request.len() <= 1 << 20,
        Failure::new("quota_exceeded", "-", "invite")
    );
    let intent = Intent {
        format: 1,
        network_base64: STANDARD.encode(decoded.token.network.get().as_bytes()),
        feature_id: decoded.feature,
        feature_binding_base64: STANDARD.encode(invite::seed_body(&decoded.token)?),
        redemption_base64: STANDARD.encode(crypto::json(&redemption)?),
        request_base64: STANDARD.encode(request),
        submitted: false,
        result_map_base64: "-".into(),
    };
    ensure!(
        binding["feature_id"] == intent.feature_id,
        Failure::new("invalid", "-", "invite")
    );
    save(&c, &decoded.network.id, &id, &intent)?;
    Ok(Prepared {
        network: decoded.network,
        id,
        intent,
    })
}
fn frozen_receipt(p: &Prepared, raw: &[u8]) -> Result<map::Map> {
    let (descriptor, r, seed, request) = parts(&p.intent)?;
    let at = support::stamp(r["joined_at"].as_str().unwrap_or(""))?;
    let wire = map::Map::decode(raw)?;
    ensure!(
        serde_json::from_slice::<Value>(&descriptor)?
            == serde_json::from_str::<Value>(wire.network.get())?,
        Failure::new("invalid", "-", "coordinator")
    );
    let original: Value = serde_json::from_slice(&request)?;
    let returned = catalog::decode(wire.catalog.get().as_bytes(), &p.network.id)?;
    let halves = ["host_invite_base64", "person_invite_base64"].map(|name| {
        if seed[name] == "-" {
            Ok(Vec::new())
        } else {
            crypto::bytes(seed[name].as_str().unwrap_or(""), linking::MAX_OBJECT)
        }
    });
    let [host, person] = halves;
    let epoch = catalog::target_epoch(&returned)?;
    linking::verify_stored_invite_feature(
        linking::CatalogFactContext {
            network: &descriptor,
            epoch,
            known_feature_id: &p.intent.feature_id,
            now: at,
        },
        wire.catalog.get().as_bytes(),
        &crypto::json(&seed["binding"])?,
        &host?,
        &person?,
    )?;
    for object in catalog::decode(&crypto::json(&original["catalog"])?, &p.network.id)?.objects {
        ensure!(
            returned.objects.iter().any(|o| o == &object),
            Failure::required("-", "invite", vec![object.id])
        );
    }
    let proof = catalog::proof_id(
        "invite_redemption",
        &crypto::bytes(&p.intent.redemption_base64, linking::MAX_OBJECT)?,
    );
    ensure!(
        returned.objects.iter().any(|o| o.id == proof),
        Failure::required("-", "invite", vec![proof])
    );
    // Independent immutable receipt verification precedes the current union.
    linking::verify_stored_network_state(
        linking::CatalogFactContext {
            network: &descriptor,
            epoch,
            known_feature_id: &p.intent.feature_id,
            now: at,
        },
        wire.catalog.get().as_bytes(),
    )?;
    linking::verify_stored_access_state(
        linking::AccessContext {
            network: &descriptor,
            epoch,
            known_feature_id: &p.intent.feature_id,
            now: at,
            prior_policies: &[],
            prior_groups: &[],
        },
        wire.catalog.get().as_bytes(),
    )?;
    Ok(wire)
}

// A saved receipt supplies only the original immutable commitment. An unknown
// local network can learn later retention from its independently pinned target.
fn retain_repair_receipt(store: &Store, p: &mut Prepared, raw: &[u8]) -> Result<bool> {
    let wire = frozen_receipt(p, raw)?;
    let c = store.connection()?;
    match store.network_record(&c, &p.network.id) {
        Ok(_) => return Ok(false),
        Err(Error::NotFound) => {}
        Err(error) => return Err(error.into()),
    }
    let (descriptor, redemption, _, _) = parts(&p.intent)?;
    let objects = catalog::decode(wire.catalog.get().as_bytes(), &p.network.id)?;
    let historical = linking::verify_stored_network_state(
        linking::CatalogFactContext {
            network: &descriptor,
            epoch: catalog::target_epoch(&objects)?,
            known_feature_id: &p.intent.feature_id,
            now: support::stamp(redemption["joined_at"].as_str().unwrap_or(""))?,
        },
        wire.catalog.get().as_bytes(),
    )?;
    ensure!(
        redemption["host_public_key"] == store.identity().public_key
            && historical
                .facts
                .state
                .hosts
                .get(&store.identity().public_key)
                .copied()
                .unwrap_or(false),
        Failure::new("forbidden", "-", "invite")
    );
    let receipt = STANDARD.encode(raw);
    ensure!(
        p.intent.result_map_base64 == "-" || p.intent.result_map_base64 == receipt,
        Failure::new("operation_conflict", "-", "invite")
    );
    p.intent.result_map_base64 = receipt;
    save(&c, &p.network.id, &p.id, &p.intent)?;
    Ok(true)
}

fn apply(store: &Store, p: &mut Prepared, raw: &[u8], repair: Option<&[u8]>) -> Result<Network> {
    let wire = frozen_receipt(p, raw)?;
    let mut c = store.connection()?;
    let tx = c.transaction()?;
    let known = match store.network_record(&tx, &p.network.id) {
        Ok(network) => Some(network),
        Err(Error::NotFound) => None,
        Err(error) => return Err(error.into()),
    };
    let (feature, _) = catalog::feature(&tx, &p.network.id)?;
    ensure!(
        feature == "-" || feature == p.intent.feature_id,
        Failure::new("state_conflict", "-", "feature")
    );
    let mut n = known.clone().unwrap_or_else(|| p.network.clone());
    let prior = catalog::read(&tx, &n.id)?;
    let repair_map = repair.map(map::Map::decode).transpose()?;
    if let Some(repair_map) = &repair_map {
        ensure!(
            known.is_none()
                && serde_json::from_str::<Value>(repair_map.network.get())?
                    == serde_json::from_str::<Value>(wire.network.get())?,
            Failure::new("invalid", "-", "coordinator")
        );
    }
    let repair_catalog = repair_map
        .as_ref()
        .map(|m| m.catalog.get().as_bytes())
        .unwrap_or(&prior);
    let union = catalog::merge(
        &n.id,
        &[&prior, wire.catalog.get().as_bytes(), repair_catalog],
    )?;
    if let Some(repair_map) = &repair_map {
        let objects = catalog::decode(repair_map.catalog.get().as_bytes(), &n.id)?;
        let feature = objects
            .objects
            .iter()
            .find(|o| o.kind == "feature")
            .ok_or_else(|| Failure::new("proof_required", "-", "feature"))?;
        let feature = crypto::bytes(&feature.body_base64, linking::MAX_OBJECT)?;
        let epoch = catalog::target_epoch(&catalog::decode(&union, &n.id)?)?;
        let verified = linking::verify_stored_feature(
            linking::FeatureContext {
                network: wire.network.get().as_bytes(),
                epoch,
                known_feature_id: &p.intent.feature_id,
                now: support::now()?,
            },
            &union,
            &feature,
        )?;
        ensure!(
            verified.feature_id == p.intent.feature_id,
            Failure::new("state_conflict", "-", "feature")
        );
    }
    let projection = catalog::verify_with_adoption(
        &tx,
        &n,
        &union,
        support::now()?,
        Some(&p.intent.feature_id),
    )?;
    linking::verify_stored_catalog_repair(
        linking::CatalogFactContext {
            network: &projection.descriptor,
            epoch: projection.network.epoch,
            known_feature_id: &p.intent.feature_id,
            now: support::now()?,
        },
        &prior,
        &union,
    )?;
    let stamp = support::now()?.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let mut members = if repair_map.is_some() {
        // Repair responses supply public proofs, never new reachability hints.
        map::projected_members(&projection, &[], &stamp)?
    } else if known.is_none() {
        map::verified_hints(store, &projection, &wire)?
    } else {
        map::projected_members(&projection, &store.stored_members(&tx, &n.id)?, &stamp)?
    };
    if known.is_none() {
        tx.execute(
            "INSERT INTO networks(id,record,root_seed) VALUES(?1,?2,NULL)",
            params![n.id, serde_json::to_string(&n)?],
        )?;
        append_event(&tx, "network.joined", &n.id, &stamp)?;
    }
    map::persist(store, &tx, &mut n, &projection, &mut members, &stamp)?;
    p.intent.result_map_base64 = STANDARD.encode(raw);
    save(&tx, &n.id, &p.id, &p.intent)?;
    tx.commit()?;
    store.refresh_member_pins(&c)?;
    Ok(n)
}
pub(crate) async fn redeem(
    store: Arc<Store>,
    text: String,
    person: Option<String>,
    person_only: bool,
) -> Result<Network, Error> {
    let _guard = store.link_mutation.lock().await;
    let run = store.clone();
    let mut p =
        tokio::task::spawn_blocking(move || prepare(&run, &text, person.as_deref(), person_only))
            .await
            .map_err(|e| Error::Internal(e.into()))?
            .map_err(support::model_error)?;
    let raw = if p.intent.result_map_base64 != "-" {
        crypto::bytes(&p.intent.result_map_base64, 16 << 20).map_err(support::model_error)?
    } else {
        p.intent.submitted = true;
        let (run, net, id, encoded) = (
            store.clone(),
            p.network.id.clone(),
            p.id.clone(),
            crypto::json(&p.intent).map_err(support::model_error)?,
        );
        tokio::task::spawn_blocking(move || -> Result<()> {
            let i: Intent = linking::decode_stored_json(&encoded, FIELDS)?;
            save(&*run.connection()?, &net, &id, &i)
        })
        .await
        .map_err(|e| Error::Internal(e.into()))?
        .map_err(support::model_error)?;
        transport::request(
            store.clone(),
            &p.network.coordinator_address,
            &p.network.coordinator_public_key,
            Method::POST,
            &format!("/coord/v2/networks/{}/invite-redemptions", p.network.id),
            crypto::bytes(&p.intent.request_base64, 1 << 20).map_err(support::model_error)?,
        )
        .await
        .map_err(support::model_error)?
    };
    let (run, mut attempt, original) = (store.clone(), p.clone(), raw.clone());
    let result = tokio::task::spawn_blocking(move || apply(&run, &mut attempt, &original, None))
        .await
        .map_err(|e| Error::Internal(e.into()))?;
    let error = match result {
        Ok(network) => return Ok(network),
        Err(error) => error,
    };
    let missing = error
        .downcast_ref::<linking::PathError>()
        .is_some_and(|e| e.code == "proof_required")
        || error
            .downcast_ref::<Failure>()
            .is_some_and(|e| e.code == "proof_required");
    if !missing {
        return Err(support::model_error(error));
    }
    let (run, mut pending, original) = (store.clone(), p.clone(), raw.clone());
    let eligible = tokio::task::spawn_blocking(move || -> Result<(Prepared, bool)> {
        let eligible = retain_repair_receipt(&run, &mut pending, &original)?;
        Ok((pending, eligible))
    })
    .await
    .map_err(|e| Error::Internal(e.into()))?
    .map_err(support::model_error)?;
    p = eligible.0;
    if !eligible.1 {
        return Err(support::model_error(error));
    }
    let repair = transport::request(
        store.clone(),
        &p.network.coordinator_address,
        &p.network.coordinator_public_key,
        Method::GET,
        &format!("/coord/v2/networks/{}/map", p.network.id),
        Vec::new(),
    )
    .await
    .map_err(support::model_error)?;
    let run = store.clone();
    tokio::task::spawn_blocking(move || apply(&run, &mut p, &raw, Some(&repair)))
        .await
        .map_err(|e| Error::Internal(e.into()))?
        .map_err(support::model_error)
}
pub(crate) async fn join(store: Arc<Store>, request: JoinNetwork) -> Result<Joined, Error> {
    let network = redeem(
        store.clone(),
        request
            .token
            .ok_or_else(|| Error::Invalid("token required".into()))?,
        request.person_public_key.clone(),
        false,
    )
    .await?;
    let person = if let Some(key) = request.person_public_key {
        let key = crate::persons::normalize_person_key(&key)?;
        let (run, id, expected) = (store.clone(), network.id.clone(), key.clone());
        let (admitted, bound) = tokio::task::spawn_blocking(move || -> Result<(bool, bool)> {
            let c = run.connection()?;
            let n = run.network_record(&c, &id)?;
            let p = catalog::projection(&c, &n, support::now()?)?
                .ok_or_else(|| Failure::new("proof_required", "-", "feature"))?;
            let key = crate::persons::normalize_person_key(&expected)?;
            let admitted = p
                .network
                .facts
                .state
                .persons
                .get(&key)
                .is_some_and(|p| p.admitted);
            let bound = p.network.members.iter().any(|m| {
                m.host_public_key == run.identity().public_key && m.person_public_key == key
            });
            Ok((admitted, bound))
        })
        .await
        .map_err(|e| Error::Internal(e.into()))?
        .map_err(support::model_error)?;
        if admitted && bound {
            Some(PersonOutcome {
                person_id: crate::persons::person_id_of(&key).ok(),
                admitted: true,
                bound: true,
                skipped: None,
                next: None,
            })
        } else {
            // The public host redemption grants no implicit person admission.
            // Reuse the verified ordinary person step and its repair guidance;
            // the feature wrapper's member half was already handled above.
            Some(crate::network::person_step(store, &network, None, &key, request.binding).await)
        }
    } else {
        None
    };
    Ok(Joined { network, person })
}
