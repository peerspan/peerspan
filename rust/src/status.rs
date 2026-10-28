//! `GET /v1/status`: one summary of this host and what needs the owner's
//! attention. It reads existing records.
use crate::{
    adapter::Adapter, api::blocking, link_runtime::support::Failure, model::Error, policy::Policy,
    store::Store,
};
use axum::{Json, Router, extract::State, routing::get};
use chrono::{DateTime, TimeDelta, Utc};
use rusqlite::{Connection, OptionalExtension};
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
pub const ATTENTION_ORDER: [&str; 26] = [
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
    "network_authority_expired",
    "network_proof_required",
    "network_state_conflict",
    "network_clock_rollback",
    "network_migration_pending",
    "network_root_unreachable",
    "person_device_signer_unavailable",
    "link_request_waiting",
    "coordinator_limit",
    "agent_name_conflict",
    "channel_unverified",
    "capability_failing",
    "capability_name_conflict",
    "policy_edit_unsettled",
    "policy_edit_dropped",
    "call_approval_pending",
];

fn network_attention(v: &Value, guard: &str) -> Option<(String, String, Value)> {
    let code = v["authority"]["state"].as_str()?;
    if matches!(code, "usable" | "unbound") {
        return None;
    }
    let id = v["id"].as_str()?;
    let kind = match code {
        "proof_required" => "network_proof_required",
        "state_conflict" => "network_state_conflict",
        "clock_rollback" => "network_clock_rollback",
        "migration_pending" => "network_migration_pending",
        _ => "network_authority_expired",
    };
    // A root split (spec 13.2): the network view shows root_state_id `-`.
    let mut detail = if code == "state_conflict" && v["root_state_id"] == "-" {
        "root split: changes are frozen; create a new network and run network reinvite".to_owned()
    } else {
        format!(
            "network authority requires repair: {code}; required_ids {}; deadline {}",
            v["authority"]["required_ids"], v["authority"]["not_after"]
        )
    };
    if code == "clock_rollback" {
        detail.push_str(&format!("; correct local UTC or wait until retained guard {guard} and rerun the command; the guard cannot be lowered or reset"));
    }
    let command = if code == "migration_pending" {
        // In-place migration is removed (DEC-OWN3): the stuck request is
        // cancelled and the network re-created (spec 14.2).
        "peerspan link cancel REQUEST_ID".to_string()
    } else {
        format!("peerspan network sync {id}")
    };
    Some(item(kind, id.into(), detail, command))
}

enum RenewalProvider {
    Original,
    Device(Option<Failure>),
}

/// How long an adapter may hold a lease without verifying its channel
/// before status reports `channel_unverified`.
const CHANNEL_UNVERIFIED_AFTER: TimeDelta = TimeDelta::seconds(120);

/// The oldest Claude Code release whose channel delivery Peerspan supports.
pub const MINIMUM_CLAUDE_VERSION: &str = "2.1.187";

/// The status item 13 message, which `session doctor` also uses.
pub fn channel_unverified_detail(agent: &str) -> String {
    format!(
        "the session of agent {agent} holds a lease but has not confirmed that it receives Peerspan's channel events (peerspan_ready), so no messages or tasks are delivered to it. Likely causes: the organization has not enabled channels (channelsEnabled); the provider does not support channels; the Claude Code version is older than {MINIMUM_CLAUDE_VERSION}; or the session was started without the channel flag"
    )
}

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
        self.status_in(&*self.connection()?, crate::clock::now(), None)
    }
    pub fn status_v2(&self) -> Result<Value, Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let at = crate::decentralized::local_decision_time()
            .map_err(crate::decentralized::product::model)?;
        let now = crate::clock::now();
        crate::decentralized::product::with_read_time(&at, || self.status_in(&tx, now, Some(&at)))
    }
    fn status_in(
        &self,
        connection: &Connection,
        now: DateTime<Utc>,
        modern: Option<&str>,
    ) -> Result<Value, Error> {
        let own = self.identity().id;
        let mut attention = Vec::new();
        let mut networks = Vec::new();
        let network_ids = {
            let mut q = connection.prepare("SELECT id FROM networks WHERE COALESCE(json_extract(record,'$.mode'),'') <> 'decentralized' ORDER BY id")?;
            q.query_map([], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        for id in network_ids {
            let network = self.network_record(connection, &id)?;
            let members = self.stored_members(connection, &id)?;
            let me = members.iter().find(|m| m.host_id == own);
            let person = me.and_then(|m| m.person_id.clone());
            let label = me.and_then(|m| m.person_member.clone());
            if modern.is_some() {
                // Retained local legacy history, with no proof repair, pruning,
                // provider warning, coordinator activity or fresh authority.
                let mut policy = None;
                if let Some(person) = &person {
                    let mut q=connection.prepare("SELECT record FROM network_statements WHERE network_id=?1 AND kind='policy' ORDER BY subject")?;
                    for row in q.query_map([&id], |r| r.get::<_, String>(0))? {
                        let p: Policy = serde_json::from_str(&row?)?;
                        if p.person_id() == *person {
                            if policy.is_some() {
                                return Err(Error::Conflict(
                                    "ambiguous retained person policy".into(),
                                ));
                            }
                            policy = Some(p);
                        }
                    }
                }
                let deliveries: i64 = connection.query_row(
                    "SELECT COUNT(*) FROM policy_deliveries WHERE network_id=?1 AND person_id=?2 AND json_extract(record,'$.state')='pending'",
                    rusqlite::params![id,person.as_deref().unwrap_or("-")],
                    |r| r.get(0),
                )?;
                networks.push(json!({"mode":"legacy_history","migration_required":true,"id":id,"name":network.name,"coordinator":network.coordinator_address,"last_sync_at":network.last_sync_at,"last_sync_error":network.last_sync_error,"members":members.len(),"person":person.map(|p|json!({"id":p,"label":label})),"policy":policy.map(|p|json!({"version":p.version,"valid_until":p.valid_until})),"policy_deliveries_pending":deliveries}));
                attention.push(item("network_migration_pending", id.clone(), "legacy network kept as read-only history; create a new network and run network reinvite to move its members".into(), format!("peerspan network reinvite {id} NEW_NETWORK_ID")));
                continue;
            }

            let (policy, provider): (Option<Policy>, RenewalProvider) = {
                let current = self.network_record(connection, &id)?;
                let projection = self
                    .linking_projection(connection, &current)
                    .map_err(crate::link_runtime::support::model_error)?;
                let key = match (&projection, &person) {
                    (Some(p), _) => p
                        .network
                        .facts
                        .state
                        .bindings
                        .get(&self.identity().public_key)
                        .filter(|key| key.as_str() != "-")
                        .cloned(),
                    (None, Some(person)) => self.person_key(connection, &id, person)?,
                    (None, None) => None,
                };
                let policy = match (&projection, key.as_ref()) {
                    (Some(p), Some(key)) => p.policies.get(key).cloned(),
                    (None, Some(key)) => self.stored_policy(connection, &id, key)?,
                    (_, None) => None,
                };
                let selected: bool = connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM link_signers WHERE network_id=?1)",
                    [&id],
                    |row| row.get(0),
                )?;
                let provider = if selected {
                    let eligible = match (&projection, key.as_ref()) {
                        (Some(p), Some(key)) => {
                            crate::link_runtime::provider::automatic_policy_device(
                                self, connection, &current, p, key,
                            )
                            .map(|_| ())
                        }
                        (Some(_), None) => Err(Failure::new("forbidden", "-", "binding").into()),
                        (None, _) => Err(Failure::new("proof_required", "-", "feature").into()),
                    };
                    RenewalProvider::Device(
                        eligible.err().map(|e| Failure::cause(e, "-", "signer")),
                    )
                } else {
                    RenewalProvider::Original
                };
                (policy, provider)
            };
            let deliveries: Vec<crate::policy_sync::PolicyDelivery> = match &person {
                Some(person) => {
                    let mut q=connection.prepare("SELECT record FROM policy_deliveries WHERE network_id=?1 AND person_id=?2 ORDER BY target")?;
                    q.query_map(rusqlite::params![id, person], |r| r.get::<_, String>(0))?
                        .map(|raw| {
                            Ok(serde_json::from_str::<crate::policy_sync::PolicyDelivery>(
                                &raw?,
                            )?)
                        })
                        .collect::<Result<Vec<_>, Error>>()?
                        .into_iter()
                        .filter(|d| d.state == "pending")
                        .collect()
                }
                None => Vec::new(),
            };
            if let Some(error) = &network.last_sync_error {
                attention.push(item(
                    "coordination_error",
                    id.clone(),
                    error.clone(),
                    format!("peerspan network sync {id}"),
                ));
            }
            if let Some(p) = &policy
                && let (Some(issued), Some(until)) = (time(&p.issued_at), time(&p.valid_until))
            {
                let renew = format!("peerspan access renew --network {id}");
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
            match provider {
                RenewalProvider::Original => {
                    if let Some(p) = &policy
                        && let Some(problem) = self.renewal_problem(&p.person_public_key)
                    {
                        attention.push(item(
                            "person_agent_unreachable",
                            id.clone(),
                            format!(
                                "the daemon cannot renew this person's access policy: {problem}"
                            ),
                            "peerspan install".into(),
                        ));
                    }
                }
                RenewalProvider::Device(Some(problem)) => attention.push(item(
                    "person_device_signer_unavailable",
                    id.clone(),
                    format!(
                        "selected device cannot renew this person's access policy: {}: {}",
                        problem.code, problem.error
                    ),
                    format!("peerspan network sync {id}"),
                )),
                RenewalProvider::Device(None) => {}
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
                    format!("peerspan access sync --network {id}"),
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
        if let Some(at) = modern {
            let ids = {
                let mut q=connection.prepare("SELECT id FROM networks WHERE json_extract(record,'$.mode')='decentralized' ORDER BY id")?;
                q.query_map([], |r| r.get::<_, String>(0))?
                    .collect::<Result<Vec<_>, _>>()?
            };
            for id in ids {
                let read = crate::decentralized::runtime::status_network(self, connection, &id, at)
                    .map_err(crate::decentralized::product::model)?;
                let view = read.network;
                if let Some(value) = network_attention(&view, &read.guard) {
                    attention.push(value);
                }
                for (kind, subject, detail, command) in read.edit_attention {
                    attention.push(item(&kind, subject, detail, command));
                }
                let selected = view["provider"].as_object();
                if let Some(provider) = selected {
                    let device = provider.get("kind").and_then(Value::as_str) == Some("device");
                    let state = &view["provider_state"];
                    let policy_scope = provider
                        .get("scopes")
                        .and_then(Value::as_u64)
                        .is_some_and(|scopes| scopes & 1 != 0);
                    if state["state"] == "unavailable"
                        && (device || state["code"] == "signer_unavailable")
                        || device && !policy_scope
                    {
                        let kind = if device {
                            "person_device_signer_unavailable"
                        } else {
                            "person_agent_unreachable"
                        };
                        let code = if state["state"] == "available" && !policy_scope {
                            "forbidden (scope1 unavailable)"
                        } else {
                            state["code"].as_str().unwrap_or("invalid")
                        };
                        attention.push(item(
                            kind,
                            id.clone(),
                            format!(
                                "selected policy provider requires repair: {}; required_ids {}",
                                code, state["required_ids"]
                            ),
                            format!("peerspan network sync {id}"),
                        ));
                    }
                }
                networks.push(view);
            }
            networks.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        }
        let blocks: i64 =
            connection.query_row("SELECT COUNT(*) FROM access_blocks", [], |r| r.get(0))?;

        // Credentials in creation order, so the last of a session's is its
        // most recent.
        let credentials: Vec<Adapter> = {
            let mut statement =
                connection.prepare("SELECT record FROM adapter_credentials ORDER BY rowid")?;
            statement
                .query_map([], |r| r.get::<_, String>(0))?
                .map(|r| Ok(serde_json::from_str(&r?)?))
                .collect::<Result<_, Error>>()?
        };
        let live =
            |a: &Adapter| a.revoked_at.is_none() && time(&a.expires_at).is_some_and(|t| t > now);
        let sessions = self.sessions_in(connection, "")?;
        let mut agents = self.agents_in(connection)?;
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
                    Some(a) => Some(self.adapter_connection_in(connection, &a.id)?.state),
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
                        "peerspan session setup --agent {} --harness {}",
                        session.agent_id, session.integration
                    ),
                ));
            }
        }

        let failed = self.recently_failed_tasks(connection, now)?;
        if failed > 0 {
            attention.push(item(
                "tasks_failed",
                failed.to_string(),
                format!(
                    "{failed} outbound tasks failed, were rejected, or expired in the last 24 hours"
                ),
                "peerspan task list".into(),
            ));
        }
        let (stored_bytes, pending_bytes) = crate::artifact::usage(connection)?;
        let quota = self.artifact_quota();
        if (stored_bytes + pending_bytes) as i128 * 10 > quota as i128 * 9 {
            attention.push(item(
                "artifact_quota",
                "artifacts".into(),
                format!(
                    "{} of {} artifact bytes are stored or pending",
                    stored_bytes + pending_bytes,
                    quota
                ),
                "peerspan artifact prune".into(),
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
        for (network, name, integration) in self.name_conflicts(connection)? {
            let harness = match integration.as_deref() {
                Some("claude-code") => "claude".to_owned(),
                Some(other) => other.to_owned(),
                None => "HARNESS".to_owned(),
            };
            attention.push(item(
                "agent_name_conflict",
                format!("{network}/{name}"),
                format!(
                    "another agent of this host's person in network {network} is also named {name}; rename this host's agent in its project"
                ),
                format!("peerspan attach {harness} --name NEW"),
            ));
        }
        for agent in self.unverified_channels(connection, now)? {
            attention.push(item(
                "channel_unverified",
                agent.clone(),
                channel_unverified_detail(&agent),
                "peerspan session doctor".into(),
            ));
        }
        for (subject, detail, command) in self.failing_capabilities(connection, now)? {
            attention.push(item("capability_failing", subject, detail, command));
        }
        for (subject, detail, command) in self.capability_name_conflicts(connection)? {
            attention.push(item("capability_name_conflict", subject, detail, command));
        }
        for (kind, subject, detail, command) in self.edit_attention(connection, now)? {
            attention.push(item(&kind, subject, detail, command));
        }
        if let Some((subject, detail, command)) = self.approval_attention(connection)? {
            attention.push(item("call_approval_pending", subject, detail, command));
        }
        let capabilities = self.capabilities_summary(connection)?;
        attention.sort_by(|a, b| {
            let rank = |k: &str| ATTENTION_ORDER.iter().position(|x| *x == k);
            rank(&a.0).cmp(&rank(&b.0)).then_with(|| a.1.cmp(&b.1))
        });
        Ok(json!({
            "host_id": own,
            "version": env!("CARGO_PKG_VERSION"),
            "networks": networks,
            "blocks": blocks,
            "agents": agent_views,
            "artifacts": {
                "quota": quota,
                "stored_bytes": stored_bytes,
                "pending_bytes": pending_bytes,
            },
            "capabilities": capabilities,
            "attention": attention.into_iter().map(|(_, _, v)| v).collect::<Vec<_>>(),
        }))
    }

    /// Status item 13: the agent name of each authorization whose adapter
    /// has held its lease for more than 120 seconds without verifying its
    /// channel, counted from the authorization's first connection (its
    /// first `adapter.connected` event), so a reconnection after a lapsed
    /// lease does not restart the count.
    fn unverified_channels(
        &self,
        connection: &Connection,
        now: DateTime<Utc>,
    ) -> Result<Vec<String>, Error> {
        let leases = {
            let mut statement = connection.prepare(
                "SELECT c.record, a.name FROM sessions s JOIN agents a ON a.id = s.agent_id JOIN adapter_credentials c ON c.session_id = s.id JOIN adapter_connections x ON x.adapter_id = c.id WHERE s.state = 'attached' AND x.lease_until_ms > ?1 AND x.channel_verified_at IS NULL ORDER BY c.id",
            )?;
            statement
                .query_map([now.timestamp_millis()], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut agents = Vec::new();
        for (record, agent) in leases {
            let a: Adapter = serde_json::from_str(&record)?;
            if a.revoked_at.is_some() || !time(&a.expires_at).is_some_and(|t| t > now) {
                continue;
            }
            let since: Option<String> = connection
                .query_row(
                    "SELECT created_at FROM events WHERE kind = 'adapter.connected' AND subject_id = ?1 ORDER BY sequence LIMIT 1",
                    [&a.id],
                    |r| r.get(0),
                )
                .optional()?;
            if since
                .as_deref()
                .and_then(time)
                .is_some_and(|since| now - since > CHANNEL_UNVERIFIED_AFTER)
            {
                agents.push(agent);
            }
        }
        Ok(agents)
    }

    /// Outbound tasks that ended failed, rejected, or expired and whose last
    /// update is within the window.
    fn recently_failed_tasks(
        &self,
        connection: &Connection,
        now: DateTime<Utc>,
    ) -> Result<usize, Error> {
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
                expires_at: Some(crate::store::rfc3339(
                    crate::clock::now() + TimeDelta::hours(2),
                )),
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
