//! Private local machine linking, durable signed catalogs and device providers.
//! Public protocol bytes are retained verbatim. Transport hints confer no authority.
mod api;
pub mod approve;
pub mod catalog;
pub mod ceremony;
pub(crate) mod claims;
pub mod crypto;
pub(crate) mod delivery;
pub mod feature;
pub mod finalize;
pub mod invite;
pub(crate) mod legacy;
pub mod map;
pub mod model;
pub(crate) mod movement;
pub(crate) mod peer;
pub mod persistence;
pub mod provider;
pub mod recovery;
pub(crate) mod redemption;
pub mod request;
pub(crate) mod restrictions;
pub(crate) mod rotation;
pub mod support;
pub mod transport;
pub(crate) mod withdrawal;
pub(crate) use api::local_routes;

pub(crate) const SCHEMA: &str = "
CREATE TABLE link_device_keys (public_key TEXT PRIMARY KEY, seed BLOB NOT NULL CHECK(length(seed) = 32), created_at TEXT NOT NULL);
CREATE TABLE link_pending (request_id TEXT PRIMARY KEY, role TEXT NOT NULL, state TEXT NOT NULL, deadline TEXT NOT NULL, record TEXT NOT NULL, secret BLOB);
CREATE TABLE link_frames (request_id TEXT NOT NULL, role TEXT NOT NULL, writer_key TEXT NOT NULL, frame_id TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(request_id, role, writer_key, frame_id));
CREATE TABLE link_operations (request_id TEXT PRIMARY KEY, network_id TEXT NOT NULL, manifest_id TEXT NOT NULL, record TEXT NOT NULL, locally_applied INTEGER NOT NULL);
CREATE TABLE link_objects (network_id TEXT NOT NULL, proof_id TEXT NOT NULL, kind TEXT NOT NULL, body BLOB NOT NULL, PRIMARY KEY(network_id, proof_id));
CREATE TABLE link_features (network_id TEXT PRIMARY KEY, feature_id TEXT NOT NULL, record TEXT NOT NULL);
CREATE TABLE link_signers (network_id TEXT PRIMARY KEY, person_key TEXT NOT NULL, device_key TEXT NOT NULL, certificate_id TEXT NOT NULL);
CREATE TABLE link_highwater (network_id TEXT NOT NULL, kind TEXT NOT NULL, subject TEXT NOT NULL, version INTEGER NOT NULL, record_hash TEXT NOT NULL, PRIMARY KEY(network_id, kind, subject));
PRAGMA user_version = 19;
";

/// Retries durable work; this worker never grants requester consent.
pub async fn worker(
    store: std::sync::Arc<crate::store::Store>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        let run = store.clone();
        let ids = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<String>> {
            let mut c = run.connection()?;
            let tx = c.transaction()?;
            let rows = {
                let mut q =
                    tx.prepare("SELECT request_id FROM link_pending ORDER BY request_id")?;
                q.query_map([], |r| r.get::<_, String>(0))?
                    .collect::<std::result::Result<Vec<_>, _>>()?
            };
            let mut active = Vec::new();
            let at = support::now()?;
            for id in rows {
                let Some(mut p) = persistence::pending(&tx, &id)? else {
                    continue;
                };
                if matches!(p.state.as_str(), "linked" | "cancelled" | "expired") {
                    if p.state != "linked"
                        && !p.record.commit_approved
                        && at >= support::stamp(&p.deadline)? + chrono::Duration::hours(24)
                    {
                        tx.execute("DELETE FROM link_pending WHERE request_id=?1", [&id])?;
                    }
                    continue;
                }
                if !p.record.commit_approved && at >= support::stamp(&p.deadline)? {
                    p.secret = None;
                    p.state = "expired".into();
                    tx.execute("DELETE FROM link_frames WHERE request_id=?1", [&id])?;
                    persistence::save_pending(&tx, &p)?;
                    continue;
                }
                if p.role != "approver"
                    || p.record.owner_intent.0.as_ref().is_some_and(|i| i.approved)
                    || p.record
                        .administrator_intent
                        .0
                        .as_ref()
                        .is_some_and(|i| i.approved)
                {
                    active.push(id);
                }
            }
            tx.commit()?;
            Ok(active)
        })
        .await;
        if let Ok(Ok(ids)) = ids {
            for id in ids {
                let operation = api::resume(
                    axum::extract::State(store.clone()),
                    axum::extract::Path(id),
                    Ok(axum::body::Bytes::from_static(b"{}")),
                );
                tokio::select! {_ = shutdown.changed()=>return,_ = operation=>{}}
            }
        }
        tokio::select! {_ = shutdown.changed()=>return,_ = tokio::time::sleep(std::time::Duration::from_secs(2))=>{}}
    }
}
