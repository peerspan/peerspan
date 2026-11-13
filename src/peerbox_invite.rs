//! Pending shares of peerbox invites (peerbox contract, Invitations for new
//! participants): the home host keeps one per invitation ID, notes whose
//! join requests came through that invite's return path, and once such a
//! person is a member of the network grants them the share's actions and
//! bounds exactly as `peerbox share --for` would, signing the next policy
//! version itself. When the owner's provider needs the owner, status shows
//! `peerbox_share_waiting` until `peerbox share --pending` signs it.
use crate::{
    api::{blocking, decode},
    decentralized::peerbox_share::{Signing, sign_peerbox_rules},
    model::Error,
    policy::{
        MAX_BUNDLE_BYTES, MAX_PENDING, PEERBOX_ACTIONS, PEERBOX_READ, PEERBOX_SUBMIT, PeerboxRule,
    },
    store::{Store, append_event, now},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State, rejection::BytesRejection},
    routing::{delete, get, post},
};
use chrono::{DateTime, TimeDelta, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tokio::sync::watch;

/// A pending share ends at most this long after its invite was created,
/// even while it waits for the owner.
const CAP: TimeDelta = TimeDelta::days(7);
/// How long a request that came through an invite may take to be admitted
/// before it counts as abandoned: a join request's own window.
const REQUEST_WINDOW: TimeDelta = TimeDelta::hours(1);
/// The most requests noted per invite.
const MAX_REQUESTS: usize = 16;

/// One join request that came through the invite's return path.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Came {
    pub request_id: String,
    pub person_public_key: String,
    pub at: String,
}
/// The person admitted through the invite.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Admitted {
    pub person_id: String,
    pub person_public_key: String,
}
/// A pending share, keyed by its invite's invitation ID.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PendingShare {
    pub invitation_id: String,
    pub peerbox_id: String,
    pub network_id: String,
    pub label: String,
    pub actions: Vec<String>,
    pub max_bundle_bytes: i64,
    pub max_pending: i64,
    pub created_at: String,
    /// The invite's expiry.
    pub expires_at: String,
    #[serde(default)]
    pub requests: Vec<Came>,
    #[serde(default)]
    pub person: Option<Admitted>,
    /// Automatic signing needed the owner (`peerbox_share_waiting`).
    #[serde(default)]
    pub waiting: bool,
}
impl PendingShare {
    /// The rule unit the share grants its admitted person on `host`.
    fn unit(&self, host: &str) -> Option<PeerboxRule> {
        let person = self.person.as_ref()?;
        Some(PeerboxRule {
            host: host.into(),
            peerbox: self.peerbox_id.clone(),
            principals: vec![format!("person:{}", person.person_id)],
            actions: self.actions.clone(),
            max_bundle_bytes: self.max_bundle_bytes,
            max_pending: self.max_pending,
            allow_disconnected: false,
        })
    }
    /// Whether the share ended without an admission: its invite expired
    /// with no request through it, or every request through it was left
    /// for longer than a request lasts; and in any case 7 days after the
    /// invite was created.
    fn ended(&self, at: DateTime<Utc>) -> bool {
        let time = |s: &str| {
            DateTime::parse_from_rfc3339(s)
                .map(|t| t.with_timezone(&Utc))
                .unwrap_or(at)
        };
        if at >= time(&self.created_at) + CAP {
            return true;
        }
        if self.person.is_some() {
            return false;
        }
        let mut end = time(&self.expires_at);
        for r in &self.requests {
            end = end.max(time(&r.at) + REQUEST_WINDOW);
        }
        at >= end
    }
}

fn read(conn: &Connection, id: &str) -> Result<Option<PendingShare>, Error> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT record FROM peerbox_pending_shares WHERE invitation_id = ?1",
            [id],
            |r| r.get(0),
        )
        .optional()?;
    raw.map(|r| Ok(serde_json::from_str(&r)?)).transpose()
}
fn all(conn: &Connection) -> Result<Vec<PendingShare>, Error> {
    let mut statement =
        conn.prepare("SELECT record FROM peerbox_pending_shares ORDER BY invitation_id")?;
    let rows = statement
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|r| Ok(serde_json::from_str(&r)?))
        .collect()
}
fn save(conn: &Connection, share: &PendingShare) -> Result<(), Error> {
    conn.execute(
        "INSERT INTO peerbox_pending_shares VALUES (?1, ?2, ?3) ON CONFLICT(invitation_id) DO UPDATE SET record = excluded.record",
        params![
            share.invitation_id,
            share.peerbox_id,
            serde_json::to_string(share)?
        ],
    )?;
    Ok(())
}
fn remove(conn: &Connection, id: &str) -> Result<(), Error> {
    conn.execute(
        "DELETE FROM peerbox_pending_shares WHERE invitation_id = ?1",
        [id],
    )?;
    Ok(())
}

/// The invite's return path received a join request through invitation
/// `id`: the request's person is noted on the invite's pending share.
pub(crate) fn came_through(
    conn: &Connection,
    id: &str,
    request_id: &str,
    person_public_key: &str,
) -> Result<(), Error> {
    let Some(mut share) = read(conn, id)? else {
        return Ok(());
    };
    if share.person.is_some()
        || share.requests.len() >= MAX_REQUESTS
        || share.requests.iter().any(|r| r.request_id == request_id)
    {
        return Ok(());
    }
    share.requests.push(Came {
        request_id: request_id.into(),
        person_public_key: person_public_key.into(),
        at: now(),
    });
    save(conn, &share)
}

/// Deletes the pending shares that ended without an admission, or whose
/// peerbox is gone.
fn sweep(conn: &Connection) -> Result<(), Error> {
    let at = crate::clock::now();
    for share in all(conn)? {
        if share.ended(at) || crate::peerbox::record(conn, &share.peerbox_id)?.is_none() {
            remove(conn, &share.invitation_id)?;
        }
    }
    Ok(())
}

/// Whether this host's owner's stored policy grants the share's unit.
fn granted(store: &Store, conn: &Connection, share: &PendingShare) -> Result<bool, Error> {
    let me = store.identity().id;
    let Some(unit) = share.unit(&me) else {
        return Ok(false);
    };
    for (network, member) in store.decentralized_own_members(conn)? {
        if network != share.network_id {
            continue;
        }
        let Some(person) = member.person_id else {
            continue;
        };
        let Some(key) = store.product_person_key(conn, &network, &person)? else {
            continue;
        };
        if let Some(policy) = store.product_policy(conn, &network, &key)? {
            let found = policy.peerbox_rules().iter().any(|r| {
                r.host == unit.host
                    && r.peerbox == unit.peerbox
                    && r.actions == unit.actions
                    && r.max_bundle_bytes == unit.max_bundle_bytes
                    && r.max_pending == unit.max_pending
                    && r.allow_disconnected == unit.allow_disconnected
                    && r.principals.contains(&unit.principals[0])
            });
            if found {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// The share is signed: it is deleted and `peerbox.shared` recorded.
fn signed(store: &Store, id: &str) -> Result<(), Error> {
    let mut conn = store.connection()?;
    let tx = conn.transaction()?;
    if let Some(share) = read(&tx, id)? {
        remove(&tx, id)?;
        append_event(
            &tx,
            "peerbox.shared",
            &format!("{}/{}", share.peerbox_id, id),
            &now(),
        )?;
    }
    tx.commit()?;
    Ok(())
}

/// One pass over the pending shares: ended ones are deleted, a request's
/// person who is now a member is admitted, and an admitted person's share
/// is signed when the owner's provider can sign without the owner.
fn pass(store: &Store) -> Result<(), Error> {
    let shares = {
        let mut conn = store.connection()?;
        let tx = conn.transaction()?;
        sweep(&tx)?;
        let mut shares = all(&tx)?;
        for share in shares.iter_mut().filter(|s| s.person.is_none()) {
            if share.requests.is_empty() {
                continue;
            }
            let persons = store.product_persons(&tx, &share.network_id)?;
            let found = share.requests.iter().find_map(|r| {
                persons
                    .iter()
                    .find(|p| p.person_public_key == r.person_public_key)
            });
            if let Some(p) = found {
                share.person = Some(Admitted {
                    person_id: p.person_id.clone(),
                    person_public_key: p.person_public_key.clone(),
                });
                save(&tx, share)?;
            }
        }
        tx.commit()?;
        shares
    };
    for share in shares {
        let me = store.identity().id;
        let Some(unit) = share.unit(&me) else {
            continue;
        };
        let outcome = sign_peerbox_rules(store, &share.network_id, |host, rules| {
            crate::policy::peerbox_put(
                rules,
                &PeerboxRule {
                    host: host.into(),
                    ..unit.clone()
                },
            );
        });
        match outcome {
            Ok(Signing::Done | Signing::Unchanged) => signed(store, &share.invitation_id)?,
            Ok(Signing::NeedsOwner) if !share.waiting => {
                let mut conn = store.connection()?;
                let tx = conn.transaction()?;
                if let Some(mut current) = read(&tx, &share.invitation_id)? {
                    current.waiting = true;
                    save(&tx, &current)?;
                }
                tx.commit()?;
            }
            // Waiting already, or a recoverable failure: tried again.
            Ok(Signing::NeedsOwner) | Err(_) => {}
        }
    }
    Ok(())
}

/// Admits and signs pending shares until shutdown.
pub async fn worker(store: Arc<Store>, mut shutdown: watch::Receiver<bool>) {
    loop {
        if let Err(e) = blocking(store.clone(), pass).await {
            eprintln!("peerbox invites: {e:?}");
        }
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = tokio::time::sleep(Duration::from_secs(2)) => {}
        }
    }
}

/// `peerbox_share_waiting` items: (subject, detail, command).
pub(crate) fn attention(conn: &Connection) -> Result<Vec<(String, String, String)>, Error> {
    let at = crate::clock::now();
    Ok(all(conn)?
        .into_iter()
        .filter(|s| s.waiting && s.person.is_some() && !s.ended(at))
        .map(|s| {
            let id = s.invitation_id;
            (
                id.clone(),
                format!(
                    "the peerbox share of invite {id} for peerbox {} waits for the owner's signature",
                    s.peerbox_id
                ),
                format!("peerspan peerbox share --pending {id}"),
            )
        })
        .collect())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    invitation_id: String,
    peerbox_id: String,
    label: String,
    actions: Vec<String>,
    max_bundle_bytes: i64,
    max_pending: i64,
}

impl Store {
    /// Stores the pending share of a network invite just created in the
    /// peerbox's network.
    fn create_pending_share(&self, c: Create) -> Result<Value, Error> {
        let in_order = c
            .actions
            .iter()
            .map(|a| PEERBOX_ACTIONS.iter().position(|k| k == a))
            .collect::<Option<Vec<_>>>()
            .is_some_and(|p| p.windows(2).all(|w| w[0] < w[1]));
        if c.actions.is_empty() || !in_order || !c.actions.iter().any(|a| a == PEERBOX_READ) {
            return Err(Error::Invalid("actions".into()));
        }
        if !(1..=MAX_BUNDLE_BYTES).contains(&c.max_bundle_bytes) {
            return Err(Error::Invalid("max_bundle_bytes".into()));
        }
        let submit = c.actions.iter().any(|a| a == PEERBOX_SUBMIT);
        if (submit && !(1..=MAX_PENDING).contains(&c.max_pending))
            || (!submit && c.max_pending != 0)
        {
            return Err(Error::Invalid("max_pending".into()));
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let record = crate::peerbox::record(&tx, &c.peerbox_id)?.ok_or(Error::NotFound)?;
        // The invite this host just created in the peerbox's network.
        let invite: Option<(String, String)> = tx
            .query_row(
                "SELECT deadline, json_extract(record, '$.network_id') FROM dec_pending WHERE request_id = ?1 AND request_id GLOB 'di_*'",
                [&c.invitation_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((expires_at, network)) = invite else {
            return Err(Error::Invalid("invitation_id".into()));
        };
        if network != record.network_id {
            return Err(Error::Invalid("invitation_id".into()));
        }
        if read(&tx, &c.invitation_id)?.is_some() {
            return Err(Error::Conflict(
                "a pending share exists for this invite".into(),
            ));
        }
        let share = PendingShare {
            invitation_id: c.invitation_id,
            peerbox_id: c.peerbox_id,
            network_id: network,
            label: c.label,
            actions: c.actions,
            max_bundle_bytes: c.max_bundle_bytes,
            max_pending: c.max_pending,
            created_at: now(),
            expires_at,
            requests: Vec::new(),
            person: None,
            waiting: false,
        };
        save(&tx, &share)?;
        append_event(
            &tx,
            "peerbox.invited",
            &format!("{}/{}", share.peerbox_id, share.invitation_id),
            &share.created_at,
        )?;
        tx.commit()?;
        Ok(serde_json::to_value(&share)?)
    }
}

pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/peerbox-invites", get(list).post(create))
        .route("/v1/peerbox-invites/{id}", delete(cancel))
        .route("/v1/peerbox-invites/{id}/complete", post(complete))
}
async fn list(State(store): State<Arc<Store>>) -> Result<Json<Vec<PendingShare>>, Error> {
    Ok(Json(
        blocking(store, |s| {
            let mut conn = s.connection()?;
            let tx = conn.transaction()?;
            sweep(&tx)?;
            let shares = all(&tx)?;
            tx.commit()?;
            Ok(shares)
        })
        .await?,
    ))
}
async fn create(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let request: Create = decode(body)?;
    Ok(Json(
        blocking(store, move |s| s.create_pending_share(request)).await?,
    ))
}
/// Deletes a pending share; the network invite stays, since invite codes
/// cannot be revoked.
async fn cancel(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, Error> {
    Ok(Json(
        blocking(store, move |s| {
            let conn = s.connection()?;
            read(&conn, &id)?.ok_or(Error::NotFound)?;
            remove(&conn, &id)?;
            Ok(json!({"invitation_id": id, "cancelled": true}))
        })
        .await?,
    ))
}
/// `peerbox share --pending` signed the share's rule: the share is deleted
/// once this host stores a policy version granting it.
async fn complete(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, Error> {
    Ok(Json(
        blocking(store, move |s| {
            let share = read(&*s.connection()?, &id)?.ok_or(Error::NotFound)?;
            if !granted(s, &*s.connection()?, &share)? {
                return Err(Error::Conflict(
                    "no stored policy version grants this pending share yet".into(),
                ));
            }
            signed(s, &id)?;
            Ok(json!({"invitation_id": id, "signed": true}))
        })
        .await?,
    ))
}
