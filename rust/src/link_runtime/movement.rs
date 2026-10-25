//! Active coordinator transfer uses exact catalogs and explicit root recovery.
use super::{
    catalog, crypto, map,
    support::{self, Failure},
    transport,
};
use crate::{coordinator_move::CoordinatorMove, linking, network::Network, store::Store};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use hyper::Method;
use serde_json::Value;
use std::sync::Arc;
struct Prepared {
    network: Network,
    catalog: Vec<u8>,
    publication: Vec<u8>,
}
fn prepare(
    store: &Store,
    n: &Network,
    moved: Option<&CoordinatorMove>,
) -> Result<Option<Prepared>> {
    let c = store.connection()?;
    let Some(p) = catalog::projection(&c, n, support::now()?)? else {
        return Ok(None);
    };
    let mut full = p.catalog.clone();
    let mut publication = full.clone();
    if let Some(m) = moved {
        let body = crypto::json(m)?;
        let added = crypto::json(&catalog::Catalog {
            format: 1,
            network_id: n.id.clone(),
            objects: vec![catalog::Entry {
                id: catalog::proof_id("coordinator_move", &body),
                kind: "coordinator_move".into(),
                body_base64: STANDARD.encode(&body),
            }],
        })?;
        full = catalog::merge(&n.id, &[&full, &added])?;
        linking::verify_stored_catalog_additions(
            linking::CatalogFactContext {
                network: &p.descriptor,
                epoch: p.network.epoch,
                known_feature_id: &p.network.facts.feature_id,
                now: support::now()?,
            },
            &p.catalog,
            &full,
        )?;
        publication = linking::select_stored_proof_catalog(
            linking::CatalogFactContext {
                network: &p.descriptor,
                epoch: p.network.epoch,
                known_feature_id: &p.network.facts.feature_id,
                now: support::now()?,
            },
            &full,
            &[linking::ProofSeed {
                kind: "coordinator_move".into(),
                body,
            }],
        )?;
        publication = catalog::merge(&n.id, &[&publication, &added])?;
    }
    Ok(Some(Prepared {
        network: n.clone(),
        catalog: full,
        publication,
    }))
}
pub(crate) async fn import(
    store: &Arc<Store>,
    n: &Network,
    address: &str,
    key: &str,
    moved: Option<&CoordinatorMove>,
) -> Result<Option<Value>> {
    let (run, current, m) = (store.clone(), n.clone(), moved.cloned());
    let prepared =
        tokio::task::spawn_blocking(move || prepare(&run, &current, m.as_ref())).await??;
    let Some(p) = prepared else { return Ok(None) };
    let mut target = p.network.clone();
    target.coordinator_address = address.into();
    target.coordinator_public_key = key.into();
    let descriptor = catalog::descriptor(&target)?;
    let body = crypto::raw_object(vec![
        ("network", descriptor),
        ("catalog", p.catalog.clone()),
        ("feature_authorization", crypto::json(&"-")?),
    ])?;
    ensure!(
        body.len() <= 1 << 20,
        Failure::new("quota_exceeded", "-", "move")
    );
    // Missing target LF requires an explicitly reviewed root import. This path
    // never constructs or signs an import authorization automatically.
    let raw = transport::request(
        store.clone(),
        address,
        key,
        Method::POST,
        "/coord/v2/networks/import",
        body,
    )
    .await?;
    let run = store.clone();
    let raw_copy = raw.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let c = run.connection()?;
        map::verify(&run, &c, &target, &raw_copy)?;
        Ok(())
    })
    .await??;
    Ok(Some(serde_json::from_slice(&raw)?))
}
pub(crate) async fn publish(
    store: Arc<Store>,
    n: &Network,
    m: &CoordinatorMove,
) -> Result<Option<&'static str>> {
    let (run, current, moved) = (store.clone(), n.clone(), m.clone());
    let prepared =
        tokio::task::spawn_blocking(move || prepare(&run, &current, Some(&moved))).await??;
    let Some(p) = prepared else { return Ok(None) };
    let body = crypto::raw_object(vec![("move", crypto::json(m)?), ("catalog", p.publication)])?;
    match transport::request(
        store,
        &n.coordinator_address,
        &n.coordinator_public_key,
        Method::POST,
        &format!("/coord/v2/networks/{}/moves", n.id),
        body,
    )
    .await
    {
        Ok(_) => Ok(Some("accepted")),
        Err(e)
            if e.downcast_ref::<Failure>().is_some_and(|f| {
                matches!(
                    f.code.as_str(),
                    "invalid"
                        | "forbidden"
                        | "state_conflict"
                        | "proof_required"
                        | "quota_exceeded"
                )
            }) =>
        {
            Ok(Some("refused"))
        }
        Err(_) => Ok(Some("unreachable")),
    }
}

const KIND: &str = "pending_link_move";
const FIELDS: &str = "format source_network_base64 network_base64 feature_id move_base64 request_base64 submitted result_map_base64";
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    format: u64,
    source_network_base64: String,
    network_base64: String,
    feature_id: String,
    move_base64: String,
    request_base64: String,
    submitted: bool,
    result_map_base64: String,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportRequest {
    network: Box<serde_json::value::RawValue>,
    catalog: Box<serde_json::value::RawValue>,
    feature_authorization: String,
}
type Materialized = (Network, Network, CoordinatorMove, Vec<u8>, Vec<u8>);
impl Intent {
    fn materialize(&self, n: &Network) -> Result<Materialized> {
        ensure!(
            self.format == 1 && crypto::id(&self.feature_id, "lf_") && self.submitted,
            Failure::new("state_conflict", "-", "move")
        );
        let mut targets = Vec::new();
        for encoded in [&self.source_network_base64, &self.network_base64] {
            let raw = crypto::bytes(encoded, linking::MAX_OBJECT)?;
            let d: map::Descriptor = linking::decode_mutation(
                &raw,
                "network_id name genesis_root_public_key coordinator_address coordinator_public_key",
            )?;
            ensure!(
                d.network_id == n.id
                    && d.name == n.name
                    && d.genesis_root_public_key == n.root_public_key
                    && crate::membership::split_host_port(&d.coordinator_address).is_ok()
                    && crypto::public_key(&d.coordinator_public_key),
                Failure::new("state_conflict", "-", "move")
            );
            let mut target = n.clone();
            target.coordinator_address = d.coordinator_address;
            target.coordinator_public_key = d.coordinator_public_key;
            target.coordinator_pending = None;
            targets.push(target);
        }
        let raw = crypto::bytes(&self.move_base64, linking::MAX_OBJECT)?;
        let moved: CoordinatorMove = linking::decode_mutation(
            &raw,
            "network_id sequence address public_key moved_at signer signature",
        )?;
        ensure!(
            moved.network_id == n.id
                && moved.sequence > 0
                && moved.sequence <= i64::MAX as u64
                && moved.address == targets[1].coordinator_address
                && moved.public_key == targets[1].coordinator_public_key,
            Failure::new("state_conflict", "-", "move")
        );
        let request = crypto::bytes(&self.request_base64, 1 << 20)?;
        let r: ImportRequest =
            linking::decode_stored_json(&request, "network catalog feature_authorization")?;
        ensure!(
            r.feature_authorization == "-"
                && r.network.get().as_bytes()
                    == crypto::bytes(&self.network_base64, linking::MAX_OBJECT)?,
            Failure::new("state_conflict", "-", "move")
        );
        let objects = catalog::decode(r.catalog.get().as_bytes(), &n.id)?;
        ensure!(
            objects.objects.iter().any(|e| e.kind == "coordinator_move"
                && e.id == catalog::proof_id("coordinator_move", &raw)
                && e.body_base64 == self.move_base64),
            Failure::new("state_conflict", "-", "move")
        );
        if self.result_map_base64 != "-" {
            crypto::bytes(&self.result_map_base64, 16 << 20)?;
        }
        Ok((
            targets.remove(0),
            targets.remove(0),
            moved,
            request,
            r.catalog.get().as_bytes().to_vec(),
        ))
    }
}
fn read_intent(c: &rusqlite::Connection, n: &Network) -> Result<Option<Intent>> {
    use rusqlite::OptionalExtension;
    let raw: Option<String> = c
        .query_row(
            "SELECT record FROM network_statements WHERE network_id=?1 AND kind=?2 AND subject=''",
            rusqlite::params![n.id, KIND],
            |r| r.get(0),
        )
        .optional()?;
    raw.map(|raw| {
        let i: Intent = linking::decode_stored_json(raw.as_bytes(), FIELDS)?;
        i.materialize(n)?;
        Ok(i)
    })
    .transpose()
}
fn save_intent(c: &rusqlite::Connection, id: &str, i: &Intent) -> Result<()> {
    c.execute(
        "INSERT OR REPLACE INTO network_statements VALUES(?1,?2,'',?3)",
        rusqlite::params![id, KIND, serde_json::to_string(i)?],
    )?;
    Ok(())
}
fn authority(p: &catalog::Projection) -> Result<crate::admins::Authority> {
    Ok(crate::admins::Authority {
        roots: p.roots()?,
        admins: p
            .network
            .facts
            .state
            .persons
            .iter()
            .filter(|(_, v)| v.admitted && v.administrator)
            .map(|(k, _)| k.clone())
            .collect(),
        ..Default::default()
    })
}
fn obsolete(
    store: &Store,
    c: &rusqlite::Connection,
    n: &Network,
    p: &catalog::Projection,
    m: &CoordinatorMove,
) -> Result<bool> {
    let Some(held) = store.latest_move(c, &n.id)? else {
        return Ok(false);
    };
    ensure!(
        held.sequence != m.sequence || held == *m,
        Failure::new("operation_conflict", "-", "move")
    );
    if held.sequence <= m.sequence || held.verify(&n.id, &authority(p)?).is_err() {
        return Ok(false);
    }
    for e in p
        .objects
        .objects
        .iter()
        .filter(|e| e.kind == "coordinator_move")
    {
        let body = crypto::bytes(&e.body_base64, linking::MAX_OBJECT)?;
        let value: CoordinatorMove = serde_json::from_slice(&body)?;
        if value == held {
            return Ok(true);
        }
    }
    Ok(false)
}
/// Immutable pending moves are returned before any new signing decision.
pub(crate) fn pending_plan(
    store: &Store,
    c: &rusqlite::Connection,
    n: &Network,
) -> Result<Option<CoordinatorMove>> {
    let Some(i) = read_intent(c, n)? else {
        return Ok(None);
    };
    let (_, target, m, _, _) = i.materialize(n)?;
    let p = catalog::projection(c, n, support::now()?)?
        .ok_or_else(|| Failure::new("upgrade_required", "-", "move"))?;
    ensure!(
        i.feature_id == p.network.facts.feature_id,
        Failure::new("state_conflict", "-", "move")
    );
    if obsolete(store, c, n, &p, &m)? {
        return Ok(None);
    }
    if i.result_map_base64 != "-"
        && target.coordinator_address == n.coordinator_address
        && target.coordinator_public_key == n.coordinator_public_key
    {
        return Ok(None);
    }
    Ok(Some(m))
}
fn prepare_intent(
    store: &Store,
    id: &str,
    r: &crate::coordinator_move::MoveNetwork,
) -> Result<(Network, Intent, bool)> {
    let c = store.connection()?;
    let n = store.network_record(&c, id)?;
    let p = catalog::projection(&c, &n, support::now()?)?
        .ok_or_else(|| Failure::new("upgrade_required", "-", "feature"))?;
    if let Some(i) = read_intent(&c, &n)? {
        let (_, target, m, _, _) = i.materialize(&n)?;
        ensure!(
            i.feature_id == p.network.facts.feature_id,
            Failure::new("state_conflict", "-", "move")
        );
        let different = target.coordinator_address != r.coordinator_address
            || target.coordinator_public_key != r.coordinator_public_key;
        if obsolete(store, &c, &n, &p, &m)? || i.result_map_base64 != "-" && different {
            c.execute(
                "DELETE FROM network_statements WHERE network_id=?1 AND kind=?2 AND subject=''",
                rusqlite::params![id, KIND],
            )?;
        } else {
            ensure!(!different, Failure::new("operation_conflict", "-", "move"));
            if let Some(value) = &r.signed {
                let provided: CoordinatorMove = serde_json::from_value(value.clone())?;
                ensure!(
                    provided == m,
                    Failure::new("operation_conflict", "-", "move")
                );
            }
            return Ok((n, i, false));
        }
    }
    ensure!(
        n.coordinator_address != r.coordinator_address
            || n.coordinator_public_key != r.coordinator_public_key,
        Failure::new("state_conflict", "-", "move")
    );
    let next = store.next_move_sequence(&c, id)?;
    let m = if let Some(value) = &r.signed {
        serde_json::from_value::<CoordinatorMove>(value.clone())?
    } else {
        let root = store.current_root(&c, id)?;
        ensure!(
            STANDARD.encode(root.verifying_key().as_bytes()) == p.network.root_public_key,
            Failure::new("forbidden", "-", "move")
        );
        CoordinatorMove::sign(
            &crate::membership::KeySigner::Raw(&root),
            crate::coordinator_move::ROOT_SIGNER,
            id,
            next,
            &r.coordinator_address,
            &r.coordinator_public_key,
            &support::now()?.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        )?
    };
    ensure!(
        m.sequence == next
            && m.address == r.coordinator_address
            && m.public_key == r.coordinator_public_key,
        Failure::new("state_conflict", "-", "move")
    );
    m.verify(id, &authority(&p)?)?;
    drop(c);
    let prepared = prepare(store, &n, Some(&m))?
        .ok_or_else(|| Failure::new("upgrade_required", "-", "feature"))?;
    let mut target = n.clone();
    target.coordinator_address = m.address.clone();
    target.coordinator_public_key = m.public_key.clone();
    target.coordinator_pending = None;
    let target_raw = catalog::descriptor(&target)?;
    let body = crypto::raw_object(vec![
        ("network", target_raw.clone()),
        ("catalog", prepared.catalog),
        ("feature_authorization", crypto::json(&"-")?),
    ])?;
    ensure!(
        body.len() <= 1 << 20,
        Failure::new("quota_exceeded", "-", "move")
    );
    let i = Intent {
        format: 1,
        source_network_base64: STANDARD.encode(catalog::descriptor(&n)?),
        network_base64: STANDARD.encode(target_raw),
        feature_id: p.network.facts.feature_id,
        move_base64: STANDARD.encode(crypto::json(&m)?),
        request_base64: STANDARD.encode(body),
        submitted: true,
        result_map_base64: "-".into(),
    };
    save_intent(&*store.connection()?, id, &i)?;
    Ok((n, i, true))
}
fn receipt(store: &Store, n: &Network, i: &mut Intent, raw: &[u8]) -> Result<()> {
    let (_, target, _, _, submitted) = i.materialize(n)?;
    let expected = crypto::bytes(&i.network_base64, linking::MAX_OBJECT)?;
    let wire = map::Map::decode(raw)?;
    let d: map::Descriptor = linking::decode_mutation(
        wire.network.get().as_bytes(),
        "network_id name genesis_root_public_key coordinator_address coordinator_public_key",
    )?;
    ensure!(
        d.network_id == target.id
            && d.name == target.name
            && d.genesis_root_public_key == target.root_public_key
            && d.coordinator_address == target.coordinator_address
            && d.coordinator_public_key == target.coordinator_public_key,
        Failure::new("invalid", "-", "move")
    );
    let received = catalog::decode(wire.catalog.get().as_bytes(), &n.id)?;
    let present: std::collections::BTreeSet<_> =
        received.objects.iter().map(|e| e.id.as_str()).collect();
    let missing: Vec<_> = catalog::decode(&submitted, &n.id)?
        .objects
        .into_iter()
        .filter(|e| !present.contains(e.id.as_str()))
        .map(|e| e.id)
        .collect();
    ensure!(missing.is_empty(), Failure::required("-", "move", missing));
    let at = support::now()?;
    let epoch = catalog::target_epoch(&received)?;
    linking::verify_stored_network_state(
        linking::CatalogFactContext {
            network: &expected,
            epoch,
            known_feature_id: &i.feature_id,
            now: at,
        },
        wire.catalog.get().as_bytes(),
    )?;
    linking::verify_stored_access_state(
        linking::AccessContext {
            network: &expected,
            epoch,
            known_feature_id: &i.feature_id,
            now: at,
            prior_policies: &[],
            prior_groups: &[],
        },
        wire.catalog.get().as_bytes(),
    )?;
    let mut c = store.connection()?;
    let tx = c.transaction()?;
    let mut current = store.network_record(&tx, &n.id)?;
    ensure!(
        catalog::feature(&tx, &n.id)?.0 == i.feature_id,
        Failure::new("state_conflict", "-", "move")
    );
    let retained =
        read_intent(&tx, &current)?.ok_or_else(|| Failure::new("state_conflict", "-", "move"))?;
    ensure!(
        retained.move_base64 == i.move_base64 && retained.request_base64 == i.request_base64,
        Failure::new("operation_conflict", "-", "move")
    );
    let prior = catalog::read(&tx, &n.id)?;
    let union = catalog::merge(&n.id, &[&prior, wire.catalog.get().as_bytes()])?;
    let p = catalog::verify(&tx, &current, &union, at)?;
    linking::verify_stored_catalog_repair(
        linking::CatalogFactContext {
            network: &p.descriptor,
            epoch: p.network.epoch,
            known_feature_id: &i.feature_id,
            now: at,
        },
        &prior,
        &union,
    )?;
    let mut hints: std::collections::BTreeMap<_, _> = map::verified_hints(store, &p, &wire)?
        .into_iter()
        .map(|m| (m.public_key.clone(), m))
        .collect();
    for old in store.stored_members(&tx, &n.id)? {
        if hints
            .get(&old.public_key)
            .is_none_or(|new| old.updated_at >= new.updated_at)
        {
            hints.insert(old.public_key.clone(), old);
        }
    }
    let at = at.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let mut members = map::projected_members(&p, &hints.into_values().collect::<Vec<_>>(), &at)?;
    map::persist(store, &tx, &mut current, &p, &mut members, &at)?;
    i.result_map_base64 = STANDARD.encode(raw);
    save_intent(&tx, &n.id, i)?;
    tx.commit()?;
    store.refresh_member_pins(&c)?;
    Ok(())
}
/// Executes an immutable active move import; publication/following stay shared.
pub(crate) async fn start(
    store: Arc<Store>,
    id: String,
    r: crate::coordinator_move::MoveNetwork,
) -> Result<(Network, CoordinatorMove)> {
    let run = store.clone();
    let (n, mut i, first) =
        tokio::task::spawn_blocking(move || prepare_intent(&run, &id, &r)).await??;
    let (source, target, m, request, _) = i.materialize(&n)?;
    let raw = if i.result_map_base64 == "-" {
        match transport::request(
            store.clone(),
            &target.coordinator_address,
            &target.coordinator_public_key,
            Method::POST,
            "/coord/v2/networks/import",
            request,
        )
        .await
        {
            Ok(raw) => raw,
            Err(e) => {
                if first
                    && e.downcast_ref::<Failure>().is_some_and(|f| {
                        matches!(
                            f.code.as_str(),
                            "invalid"
                                | "forbidden"
                                | "state_conflict"
                                | "proof_required"
                                | "quota_exceeded"
                                | "upgrade_required"
                        )
                    })
                {
                    let run = store.clone();
                    let id = n.id.clone();
                    tokio::task::spawn_blocking(move||->Result<()>{run.connection()?.execute("DELETE FROM network_statements WHERE network_id=?1 AND kind=?2 AND subject=''",rusqlite::params![id,KIND])?;Ok(())}).await??;
                }
                if let Some(f) = e.downcast_ref::<Failure>()
                    && f.code == "proof_required"
                {
                    let mut failure = f.clone();
                    failure.details.next=vec!["Review and approve network repair for this exact target, then retry network move.".into()];
                    return Err(failure.into());
                }
                return Err(e);
            }
        }
    } else {
        crypto::bytes(&i.result_map_base64, 16 << 20)?
    };
    let run = store.clone();
    tokio::task::spawn_blocking(move || receipt(&run, &n, &mut i, &raw)).await??;
    Ok((source, m))
}
