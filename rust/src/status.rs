//! `GET /v1/status`: one summary of this host and what needs the owner's
//! attention. It reads existing records.
use crate::{adapter::Adapter, api::blocking, model::Error, policy::Policy, store::Store};
use axum::{Json, Router, extract::State, routing::get};
use chrono::{DateTime, TimeDelta, Utc};
use serde_json::{Value, json};
use std::sync::Arc;

/// Credentials and outbound task failures within this window draw attention.
const WINDOW: TimeDelta = TimeDelta::hours(24);

fn time(text: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

fn item(kind: &str, subject: String, detail: String, command: String) -> (String, String, Value) {
    let value = json!({"kind": kind, "subject": subject, "detail": detail, "command": command});
    (kind.to_owned(), subject, value)
}

/// Every kind in order; the CLI adds `service_not_installed` and
/// `linger_disabled`.
const KINDS: [&str; 11] = [
    "coordination_error",
    "policy_expired",
    "policy_expiring",
    "policy_delivery_failing",
    "credential_expiring",
    "tasks_failed",
    "artifact_quota",
    "service_not_installed",
    "linger_disabled",
    "person_agent_unreachable",
    "coordinator_limit",
];

impl Store {
    /// Why the daemon cannot renew `key`'s policy, if it cannot: neither its
    /// ssh-agent nor its generated key file holds the key.
    fn renewal_problem(&self, key: &str) -> Option<String> {
        let key: [u8; 32] = match crate::membership::canonical(key, 32)
            .ok()
            .and_then(|k| k.try_into().ok())
        {
            Some(key) => key,
            None => return Some("the person key is invalid".into()),
        };
        self.renewal_signer(key).err()
    }
    pub fn status(&self) -> Result<Value, Error> {
        let now = Utc::now();
        let own = self.identity().id;
        let mut attention = Vec::new();
        let mut networks = Vec::new();
        for network in self.networks()? {
            let id = network.id.clone();
            let members = self.members(&id)?;
            let me = members.iter().find(|m| m.host_id == own);
            let person = me.and_then(|m| m.person_id.clone());
            let label = me.and_then(|m| m.person_member.clone());
            let policy: Option<Policy> = match &person {
                Some(person) => {
                    let connection = self.connection()?;
                    match self.person_key(&connection, &id, person)? {
                        Some(key) => self.stored_policy(&connection, &id, &key)?,
                        None => None,
                    }
                }
                None => None,
            };
            let deliveries = match &person {
                Some(_) => self
                    .policy_sync_status(&id)?
                    .deliveries
                    .into_iter()
                    .filter(|d| d.state == "pending")
                    .collect(),
                None => Vec::new(),
            };
            if let Some(error) = &network.last_sync_error {
                attention.push(item(
                    "coordination_error",
                    id.clone(),
                    error.clone(),
                    format!("capsule network sync {id}"),
                ));
            }
            if let Some(p) = &policy
                && let (Some(issued), Some(until)) = (time(&p.issued_at), time(&p.valid_until))
            {
                let renew = format!("capsule access renew --network {id}");
                if now >= until {
                    attention.push(item(
                        "policy_expired",
                        id.clone(),
                        format!(
                            "access policy version {} expired at {}",
                            p.version, p.valid_until
                        ),
                        renew,
                    ));
                } else if (until - now) * 4 < until - issued {
                    attention.push(item(
                        "policy_expiring",
                        id.clone(),
                        format!(
                            "access policy version {} expires at {} and has not been renewed",
                            p.version, p.valid_until
                        ),
                        renew,
                    ));
                }
            }
            if let Some(p) = &policy
                && let Some(problem) = self.renewal_problem(&p.person_public_key)
            {
                attention.push(item(
                    "person_agent_unreachable",
                    id.clone(),
                    format!("the daemon cannot renew this person's access policy: {problem}"),
                    "capsule install".into(),
                ));
            }
            for d in deliveries.iter().filter(|d| d.attempts >= 1) {
                attention.push(item(
                    "policy_delivery_failing",
                    format!("{id}/{}", d.target),
                    format!(
                        "policy version {} delivery failed {} times: {}",
                        d.version,
                        d.attempts,
                        d.error.as_deref().unwrap_or("unknown error")
                    ),
                    format!("capsule access sync --network {id}"),
                ));
            }
            networks.push(json!({
                "id": id,
                "name": network.name,
                "coordinator": network.coordinator_address,
                "last_sync_at": network.last_sync_at,
                "last_sync_error": network.last_sync_error,
                "members": members.len(),
                "person": person.map(|p| json!({"id": p, "label": label})),
                "policy": policy.map(|p| json!({"version": p.version, "valid_until": p.valid_until})),
                "policy_deliveries_pending": deliveries.len(),
            }));
        }
        let blocks = self.access_blocks()?.len();

        // Credentials in creation order, so the last of a session's is its
        // most recent.
        let credentials: Vec<Adapter> = {
            let connection = self.connection()?;
            let mut statement =
                connection.prepare("SELECT record FROM adapter_credentials ORDER BY rowid")?;
            statement
                .query_map([], |r| r.get::<_, String>(0))?
                .map(|r| Ok(serde_json::from_str(&r?)?))
                .collect::<Result<_, Error>>()?
        };
        let live =
            |a: &Adapter| a.revoked_at.is_none() && time(&a.expires_at).is_some_and(|t| t > now);
        let sessions = self.sessions("")?;
        let mut agents = self.agents()?;
        agents.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));
        let mut agent_views = Vec::new();
        for agent in agents {
            let mut owned: Vec<_> = sessions.iter().filter(|s| s.agent_id == agent.id).collect();
            owned.sort_by(|a, b| a.id.cmp(&b.id));
            let mut views = Vec::new();
            for session in owned {
                let mine: Vec<&Adapter> = credentials
                    .iter()
                    .filter(|a| a.session_id == session.id)
                    .collect();
                let current = mine
                    .iter()
                    .rev()
                    .find(|a| live(a))
                    .or_else(|| mine.last())
                    .copied();
                if session.state != "attached" && !current.is_some_and(live) {
                    continue;
                }
                let connection = match current {
                    Some(a) => Some(self.adapter_connection(&a.id)?.state),
                    None => None,
                };
                views.push(json!({
                    "id": session.id,
                    "integration": session.integration,
                    "adapter_id": current.map(|a| a.id.clone()),
                    "connection": connection,
                    "expires_at": current.map(|a| a.expires_at.clone()),
                    "renewable": current.is_some_and(|a| a.renewable),
                }));
            }
            agent_views.push(json!({"id": agent.id, "name": agent.name, "sessions": views}));
        }
        for a in &credentials {
            let Some(session) = sessions.iter().find(|s| s.id == a.session_id) else {
                continue;
            };
            if a.revoked_at.is_some() || a.renewable || session.state != "attached" {
                continue;
            }
            if let Some(expires) = time(&a.expires_at)
                && expires > now
                && expires <= now + WINDOW
            {
                attention.push(item(
                    "credential_expiring",
                    a.id.clone(),
                    format!(
                        "session {} credential expires at {}",
                        session.id, a.expires_at
                    ),
                    format!(
                        "capsule session setup --agent {} --harness {}",
                        session.agent_id, session.integration
                    ),
                ));
            }
        }

        let failed = self.recently_failed_tasks(now)?;
        if failed > 0 {
            attention.push(item(
                "tasks_failed",
                failed.to_string(),
                format!(
                    "{failed} outbound tasks failed, were rejected, or expired in the last 24 hours"
                ),
                "capsule task list".into(),
            ));
        }
        let artifacts = self.artifact_list()?;
        if (artifacts.stored_bytes + artifacts.pending_bytes) as i128 * 10
            > artifacts.quota as i128 * 9
        {
            attention.push(item(
                "artifact_quota",
                "artifacts".into(),
                format!(
                    "{} of {} artifact bytes are stored or pending",
                    artifacts.stored_bytes + artifacts.pending_bytes,
                    artifacts.quota
                ),
                "capsule artifact prune".into(),
            ));
        }
        let joined: Vec<String> = networks
            .iter()
            .filter_map(|n| n["id"].as_str().map(str::to_owned))
            .collect();
        for (network, limit) in self.reached_limits(&joined) {
            attention.push(item(
                "coordinator_limit",
                format!("{network}/{limit}"),
                format!("the coordinator of network {network} reports its {limit} limit reached"),
                String::new(),
            ));
        }
        attention.sort_by(|a, b| {
            let rank = |k: &str| KINDS.iter().position(|x| *x == k);
            rank(&a.0).cmp(&rank(&b.0)).then_with(|| a.1.cmp(&b.1))
        });
        Ok(json!({
            "host_id": own,
            "version": env!("CARGO_PKG_VERSION"),
            "networks": networks,
            "blocks": blocks,
            "agents": agent_views,
            "artifacts": {
                "quota": artifacts.quota,
                "stored_bytes": artifacts.stored_bytes,
                "pending_bytes": artifacts.pending_bytes,
            },
            "attention": attention.into_iter().map(|(_, _, v)| v).collect::<Vec<_>>(),
        }))
    }

    /// Outbound tasks that ended failed, rejected, or expired and whose last
    /// update is within the window.
    fn recently_failed_tasks(&self, now: DateTime<Utc>) -> Result<usize, Error> {
        let connection = self.connection()?;
        let records = {
            let mut statement =
                connection.prepare("SELECT peer, task_id, record FROM outbound_tasks")?;
            statement
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut count = 0;
        for (peer, task, record) in records {
            let record: Value = serde_json::from_str(&record)?;
            let failed = match &record["status"] {
                Value::Null => record["submit_state"] == "rejected",
                status => matches!(
                    status["state"].as_str(),
                    Some("failed" | "rejected" | "expired")
                ),
            };
            if !failed {
                continue;
            }
            let updated: Option<String> = rusqlite::OptionalExtension::optional(connection.query_row(
                "SELECT created_at FROM events WHERE kind = 'task.updated' AND subject_id = ?1 ORDER BY sequence DESC LIMIT 1",
                [format!("{peer}/{task}")],
                |r| r.get(0),
            ))?;
            if updated
                .as_deref()
                .and_then(time)
                .is_some_and(|at| now - at <= WINDOW)
            {
                count += 1;
            }
        }
        Ok(count)
    }
}

pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new().route("/v1/status", get(status))
}
async fn status(State(store): State<Arc<Store>>) -> Result<Json<Value>, Error> {
    Ok(Json(blocking(store, Store::status).await?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        adapter::CreateAdapter,
        model::{AttachSession, RegisterAgent},
    };

    #[test]
    fn status_lists_sessions_and_orders_attention() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(&temporary.path().join("host")).unwrap();
        store.set_artifact_quota(1);
        let empty = store.status().unwrap();
        assert_eq!(empty["attention"], json!([]));
        assert_eq!(empty["networks"], json!([]));
        let mut sessions = Vec::new();
        for name in ["zed", "amy"] {
            let agent = store
                .register_agent(RegisterAgent {
                    name: name.into(),
                    owner: "o".into(),
                    capabilities: vec![],
                })
                .unwrap();
            sessions.push(
                store
                    .attach_session(AttachSession {
                        agent_id: agent.id,
                        integration: "claude-code".into(),
                    })
                    .unwrap(),
            );
        }
        // A fixed credential expiring within a day draws attention; a
        // renewable one does not.
        let fixed = store
            .create_adapter(CreateAdapter {
                session_id: sessions[0].id.clone(),
                expires_at: Some(crate::store::rfc3339(Utc::now() + TimeDelta::hours(2))),
            })
            .unwrap()
            .adapter;
        store
            .create_adapter(CreateAdapter {
                session_id: sessions[1].id.clone(),
                expires_at: None,
            })
            .unwrap();
        let status = store.status().unwrap();
        let names: Vec<_> = status["agents"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["name"].clone())
            .collect();
        assert_eq!(names, [json!("amy"), json!("zed")]);
        let amy = &status["agents"][0]["sessions"][0];
        assert_eq!(amy["renewable"], true);
        assert_eq!(amy["connection"], "registered");
        let kinds: Vec<_> = status["attention"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| (a["kind"].clone(), a["subject"].clone()))
            .collect();
        assert_eq!(kinds, [(json!("credential_expiring"), json!(fixed.id))]);
        // A detached session without a live credential is not listed.
        store.revoke_adapter(&fixed.id).unwrap();
        store.detach_session(&sessions[0].id).unwrap();
        let status = store.status().unwrap();
        assert_eq!(status["agents"][1]["sessions"], json!([]));
        assert_eq!(status["attention"], json!([]));
    }
}
