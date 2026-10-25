//! Complete durable public catalogs and unsigned views of verified selections.
use super::{crypto, persistence, support::Failure};
use crate::{linking, network::Network, store::Store};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub id: String,
    pub kind: String,
    pub body_base64: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub format: u64,
    pub network_id: String,
    pub objects: Vec<Entry>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureRecord {
    pub state: String,
    pub proposal: Value,
    pub acknowledgments: Vec<Value>,
    pub activate: bool,
}

pub fn proof_id(kind: &str, body: &[u8]) -> String {
    format!(
        "pf_{}",
        crypto::hash(
            ["peerspan-link-proof-v1", kind, &crypto::hash(body)]
                .join("\n")
                .as_bytes()
        )
    )
}
pub fn descriptor(n: &Network) -> Result<Vec<u8>> {
    crypto::json(
        &json!({"network_id":n.id,"name":n.name,"genesis_root_public_key":n.root_public_key,"coordinator_address":n.coordinator_address,"coordinator_public_key":n.coordinator_public_key}),
    )
}
pub fn decode(raw: &[u8], network: &str) -> Result<Catalog> {
    ensure!(
        raw.len() <= 16 << 20,
        Failure::new("invalid", "-", "catalog")
    );
    let c: Catalog = linking::decode_stored_json(raw, "format network_id objects")
        .map_err(|_| Failure::new("invalid", "-", "catalog"))?;
    ensure!(
        c.format == 1 && c.network_id == network && c.objects.len() <= 4096,
        Failure::new("invalid", "-", "catalog")
    );
    let mut previous = "";
    let mut decoded = 0usize;
    for p in &c.objects {
        let body = crypto::bytes(&p.body_base64, linking::MAX_OBJECT)?;
        ensure!(
            crypto::id(&p.id, "pf_")
                && p.id.as_str() > previous
                && p.id == proof_id(&p.kind, &body),
            Failure::new("invalid", "-", "catalog")
        );
        decoded += body.len();
        ensure!(
            decoded <= 8 << 20,
            Failure::new("quota_exceeded", "-", "catalog")
        );
        previous = &p.id;
    }
    Ok(c)
}
pub fn read(connection: &Connection, network: &str) -> Result<Vec<u8>> {
    let mut statement = connection.prepare(
        "SELECT proof_id,kind,body FROM link_objects WHERE network_id=?1 ORDER BY proof_id",
    )?;
    let rows = statement.query_map([network], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    let mut objects = Vec::new();
    for row in rows {
        let (id, kind, body) = row?;
        objects.push(Entry {
            id,
            kind,
            body_base64: STANDARD.encode(body),
        });
    }
    let raw = crypto::json(&Catalog {
        format: 1,
        network_id: network.into(),
        objects,
    })?;
    decode(&raw, network).map_err(|_| Failure::new("state_conflict", "-", "storage"))?;
    Ok(raw)
}
pub fn merge(network: &str, catalogs: &[&[u8]]) -> Result<Vec<u8>> {
    let mut entries = BTreeMap::new();
    for raw in catalogs {
        for p in decode(raw, network)?.objects {
            ensure!(
                entries.get(&p.id).is_none_or(|old| old == &p),
                Failure::new("state_conflict", "-", "catalog")
            );
            entries.insert(p.id.clone(), p);
        }
    }
    let raw = crypto::json(&Catalog {
        format: 1,
        network_id: network.into(),
        objects: entries.into_values().collect(),
    })?;
    decode(&raw, network)?;
    Ok(raw)
}
pub fn target_epoch(catalog: &Catalog) -> Result<u64> {
    let mut epoch = 0;
    for p in catalog.objects.iter().filter(|p| p.kind == "rotation") {
        let o: Value =
            serde_json::from_slice(&crypto::bytes(&p.body_base64, linking::MAX_OBJECT)?)?;
        epoch = epoch.max(
            o["epoch"]
                .as_u64()
                .ok_or_else(|| Failure::new("invalid", "-", "catalog"))?,
        );
    }
    Ok(epoch)
}
pub fn feature(connection: &Connection, network: &str) -> Result<(String, Option<FeatureRecord>)> {
    let row: Option<(String, String)> = connection
        .query_row(
            "SELECT feature_id,record FROM link_features WHERE network_id=?1",
            [network],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((id, raw)) = row else {
        return Ok(("-".into(), None));
    };
    let record: FeatureRecord =
        linking::decode_stored_json(raw.as_bytes(), "state proposal acknowledgments activate")
            .map_err(|_| Failure::new("state_conflict", "-", "storage"))?;
    ensure!(
        crypto::id(&id, "lf_")
            && matches!(record.state.as_str(), "preparing" | "collecting" | "active"),
        Failure::new("state_conflict", "-", "storage")
    );
    Ok((
        if record.state == "active" {
            id
        } else {
            "-".into()
        },
        Some(record),
    ))
}

pub struct Projection {
    pub descriptor: Vec<u8>,
    pub catalog: Vec<u8>,
    pub objects: Catalog,
    pub network: linking::NetworkState,
    pub access: linking::AccessState,
    pub policies: BTreeMap<String, crate::policy::Policy>,
    pub groups: BTreeMap<String, crate::admins::Group>,
    pub policy_authorizations: BTreeMap<String, String>,
    pub group_authorizations: BTreeMap<String, String>,
}
impl Projection {
    pub fn roots(&self) -> Result<Vec<String>> {
        let descriptor: Value = serde_json::from_slice(&self.descriptor)?;
        let mut roots = vec![
            descriptor["genesis_root_public_key"]
                .as_str()
                .ok_or_else(|| Failure::new("state_conflict", "-", "catalog"))?
                .to_owned(),
        ];
        let mut rotations = BTreeMap::new();
        for entry in self.objects.objects.iter().filter(|e| e.kind == "rotation") {
            let object: Value =
                serde_json::from_slice(&crypto::bytes(&entry.body_base64, linking::MAX_OBJECT)?)?;
            let epoch = object["epoch"]
                .as_u64()
                .ok_or_else(|| Failure::new("state_conflict", "-", "catalog"))?;
            rotations.insert(
                epoch,
                object["root_public_key"]
                    .as_str()
                    .ok_or_else(|| Failure::new("state_conflict", "-", "catalog"))?
                    .to_owned(),
            );
        }
        roots.extend(rotations.into_values());
        Ok(roots)
    }
}

pub(crate) fn access_body(selection: &linking::AccessSelection) -> Result<(Vec<u8>, String)> {
    let raw = crypto::bytes(&selection.body_base64, linking::MAX_OBJECT)?;
    if selection.record_id == "-" {
        return Ok((raw, "-".into()));
    }
    let record: Value = serde_json::from_slice(&raw)?;
    let payload = crypto::bytes(
        record["payload_base64"]
            .as_str()
            .ok_or_else(|| Failure::new("state_conflict", "-", "catalog"))?,
        linking::MAX_PAYLOAD,
    )?;
    let mut payload: Value = serde_json::from_slice(&payload)?;
    payload
        .as_object_mut()
        .ok_or_else(|| Failure::new("state_conflict", "-", "catalog"))?
        .insert("signature".into(), Value::String("-".into()));
    Ok((crypto::json(&payload)?, STANDARD.encode(raw)))
}

pub fn verify(
    connection: &Connection,
    n: &Network,
    catalog: &[u8],
    now: DateTime<Utc>,
) -> Result<Projection> {
    verify_with_adoption(connection, n, catalog, now, None)
}

/// The optional pin is accepted only after an exact feature or ceremony verifier
/// has independently authorized adoption in this same operation.
pub(super) fn verify_with_adoption(
    connection: &Connection,
    n: &Network,
    catalog: &[u8],
    now: DateTime<Utc>,
    verified_feature: Option<&str>,
) -> Result<Projection> {
    let objects = decode(catalog, &n.id)?;
    let epoch = target_epoch(&objects)?;
    let (feature, _) = feature(connection, &n.id)?;
    let descriptor = descriptor(n)?;
    let network = linking::verify_stored_network_state(
        linking::CatalogFactContext {
            network: &descriptor,
            epoch,
            known_feature_id: &feature,
            now,
        },
        catalog,
    )?;
    let adopted;
    let access_feature = if feature != "-" {
        ensure!(
            verified_feature.is_none_or(|id| id == feature),
            Failure::new("state_conflict", "-", "feature")
        );
        feature.as_str()
    } else if let Some(id) = verified_feature {
        ensure!(
            id == network.facts.feature_id,
            Failure::new("state_conflict", "-", "feature")
        );
        id
    } else {
        let feature_entry = objects
            .objects
            .iter()
            .find(|p| p.kind == "feature")
            .ok_or_else(|| Failure::new("proof_required", "-", "feature"))?;
        let body = crypto::bytes(&feature_entry.body_base64, linking::MAX_OBJECT)?;
        adopted = linking::verify_stored_feature(
            linking::FeatureContext {
                network: &descriptor,
                epoch,
                known_feature_id: "-",
                now,
            },
            catalog,
            &body,
        )?
        .feature_id;
        ensure!(
            adopted == network.facts.feature_id,
            Failure::new("state_conflict", "-", "feature")
        );
        adopted.as_str()
    };
    let (prior_policies, prior_groups) = persistence::high_water(connection, &n.id)?;
    let access = linking::verify_stored_access_state(
        linking::AccessContext {
            network: &descriptor,
            epoch,
            known_feature_id: access_feature,
            now,
            prior_policies: &prior_policies,
            prior_groups: &prior_groups,
        },
        catalog,
    )?;
    let (mut policies, mut groups, mut policy_authorizations, mut group_authorizations) = (
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    );
    for p in access.policies.iter().filter(|p| p.selection.active) {
        let (body, authorization) = access_body(&p.selection)?;
        let policy = serde_json::from_slice(&body)?;
        policies.insert(p.person_public_key.clone(), policy);
        policy_authorizations.insert(p.person_public_key.clone(), authorization);
    }
    for g in access.groups.iter().filter(|g| g.selection.active) {
        let (body, authorization) = access_body(&g.selection)?;
        let group = serde_json::from_slice(&body)?;
        groups.insert(g.name.clone(), group);
        group_authorizations.insert(g.name.clone(), authorization);
    }
    Ok(Projection {
        descriptor,
        catalog: catalog.to_vec(),
        objects,
        network,
        access,
        policies,
        groups,
        policy_authorizations,
        group_authorizations,
    })
}
pub fn projection(
    connection: &Connection,
    n: &Network,
    now: DateTime<Utc>,
) -> Result<Option<Projection>> {
    let (feature, _) = feature(connection, &n.id)?;
    if feature == "-" {
        return Ok(None);
    }
    let catalog = read(connection, &n.id)?;
    Ok(Some(verify(connection, n, &catalog, now)?))
}

pub fn persist(tx: &Transaction<'_>, n: &Network, p: &Projection) -> Result<()> {
    for entry in &p.objects.objects {
        let body = crypto::bytes(&entry.body_base64, linking::MAX_OBJECT)?;
        let old: Option<(String, Vec<u8>)> = tx
            .query_row(
                "SELECT kind,body FROM link_objects WHERE network_id=?1 AND proof_id=?2",
                params![n.id, entry.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((kind, old)) = old {
            ensure!(
                kind == entry.kind && old == body,
                Failure::new("state_conflict", "-", "storage")
            );
        } else {
            tx.execute(
                "INSERT INTO link_objects(network_id,proof_id,kind,body) VALUES(?1,?2,?3,?4)",
                params![n.id, entry.id, entry.kind, body],
            )?;
        }
    }
    let (known, _) = feature(tx, &n.id)?;
    ensure!(
        known == "-" || known == p.network.facts.feature_id,
        Failure::new("state_conflict", "-", "feature")
    );
    let feature_entry = p
        .objects
        .objects
        .iter()
        .find(|e| e.kind == "feature")
        .ok_or_else(|| Failure::new("proof_required", "-", "feature"))?;
    let object: Value = serde_json::from_slice(&crypto::bytes(
        &feature_entry.body_base64,
        linking::MAX_OBJECT,
    )?)?;
    let record = FeatureRecord {
        state: "active".into(),
        proposal: object["proposal"].clone(),
        acknowledgments: object["acknowledgments"]
            .as_array()
            .ok_or_else(|| Failure::new("state_conflict", "-", "feature"))?
            .clone(),
        activate: true,
    };
    tx.execute("INSERT INTO link_features(network_id,feature_id,record) VALUES(?1,?2,?3) ON CONFLICT(network_id) DO UPDATE SET feature_id=excluded.feature_id,record=excluded.record",params![n.id,p.network.facts.feature_id,String::from_utf8(crypto::json(&record)?)?])?;
    persistence::persist_high_water(tx, &p.access)?;
    Ok(())
}

impl Store {
    pub(crate) fn linking_projection(
        &self,
        connection: &Connection,
        n: &Network,
    ) -> Result<Option<Projection>> {
        projection(connection, n, super::support::now()?)
    }
}
