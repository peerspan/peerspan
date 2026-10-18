//! Capabilities (capabilities contract, milestone 10 slice 1): the owner's
//! named, host-local definitions of one use case each. A capability binds a
//! source, selected operations (tools, and `read` over selected resources),
//! and the credential context that serves calls. Shares are capability
//! rules in the owner's signed policy; this module keeps the records.
use crate::{
    api::{blocking, decode},
    model::Error,
    peer_store::json,
    policy::{Policy, name_shape},
    sources::{Health, Instance, ServerRecord, Snapshot, server_record, take_snapshot},
    store::{Store, append_event, now},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State, rejection::BytesRejection},
    http::StatusCode,
    routing::get,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;

/// The operation that reads a capability's resources.
pub const READ: &str = "read";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceRef {
    /// The agent's name.
    pub agent: String,
    pub server: String,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Credential {
    pub env_file: Option<String>,
    pub args: Option<Vec<String>>,
}
impl Credential {
    /// Whether the capability runs its own instance.
    pub fn own(&self) -> bool {
        self.env_file.is_some() || self.args.is_some()
    }
}

/// `capabilities.record`: the record, with the source's agent ID and, for a
/// capability with its own credential, its own snapshot and health.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CapabilityRecord {
    pub name: String,
    pub source: SourceRef,
    pub agent_id: String,
    pub operations: Vec<String>,
    /// Null for no `read`, `"all"`, or a list of URIs.
    pub resources: Value,
    pub credential: Credential,
    pub created_at: String,
    #[serde(default)]
    pub snapshot: Option<Snapshot>,
    #[serde(default)]
    pub snapshot_error: Option<String>,
    #[serde(default)]
    pub health: Health,
}
impl CapabilityRecord {
    /// The instance its calls run on.
    pub fn instance(&self) -> Instance {
        Instance {
            agent_id: self.agent_id.clone(),
            server: self.source.server.clone(),
            capability: self.credential.own().then(|| self.name.clone()),
        }
    }
    pub fn reads(&self) -> bool {
        !self.resources.is_null()
    }
    /// Whether `uri` is one of its selected resources.
    pub fn selects(&self, uri: &str) -> bool {
        match &self.resources {
            Value::String(all) => all == "all",
            Value::Array(list) => list.iter().any(|u| u.as_str() == Some(uri)),
            _ => false,
        }
    }
    fn same(&self, other: &Self) -> bool {
        self.agent_id == other.agent_id
            && self.source.server == other.source.server
            && self.operations == other.operations
            && self.resources == other.resources
            && self.credential == other.credential
    }
}

pub(crate) fn capability_record(
    conn: &Connection,
    name: &str,
) -> Result<Option<CapabilityRecord>, Error> {
    conn.query_row(
        "SELECT record FROM capabilities WHERE name = ?1",
        [name],
        |r| r.get::<_, String>(0),
    )
    .optional()?
    .map(json)
    .transpose()
}
pub(crate) fn capability_records(conn: &Connection) -> Result<Vec<CapabilityRecord>, Error> {
    let mut statement = conn.prepare("SELECT record FROM capabilities ORDER BY name")?;
    statement
        .query_map([], |r| r.get::<_, String>(0))?
        .map(|r| json(r?))
        .collect()
}
pub(crate) fn save(tx: &Transaction<'_>, r: &CapabilityRecord) -> Result<(), Error> {
    tx.execute(
        "INSERT OR REPLACE INTO capabilities VALUES (?1, ?2)",
        params![r.name, serde_json::to_string(r)?],
    )?;
    Ok(())
}

/// The capability record as the contract shows it, without recipients.
fn record_view(conn: &Connection, r: &CapabilityRecord) -> Result<Value, Error> {
    let now = current(conn, r)?;
    Ok(json!({
        "name": r.name,
        "source": r.source,
        "operations": r.operations,
        "resources": r.resources,
        "credential": r.credential,
        "bounds": {},
        "state": now.state(),
        "unavailable": now.unavailable,
        "created_at": r.created_at,
    }))
}

/// What a capability can do now: the snapshot it serves from, and the
/// operations that cannot run (or `source` when the source is gone).
pub(crate) struct Current {
    pub snapshot: Option<Snapshot>,
    pub unavailable: Vec<String>,
}
impl Current {
    pub fn state(&self) -> &'static str {
        if self.unavailable.is_empty() {
            "available"
        } else {
            "unavailable"
        }
    }
    /// Whether the source itself is gone.
    pub fn gone(&self) -> bool {
        self.unavailable.iter().any(|u| u == "source")
    }
}
pub(crate) fn current(conn: &Connection, r: &CapabilityRecord) -> Result<Current, Error> {
    let source: Option<ServerRecord> = server_record(conn, &r.agent_id, &r.source.server)?;
    let Some(source) = source.filter(|s| s.shareable) else {
        return Ok(Current {
            snapshot: None,
            unavailable: vec!["source".into()],
        });
    };
    let snapshot = if r.credential.own() {
        r.snapshot.clone()
    } else {
        source.snapshot
    };
    let unavailable = r
        .operations
        .iter()
        .filter(|op| snapshot.as_ref().is_none_or(|s| s.tool(op).is_none()))
        .cloned()
        .collect();
    Ok(Current {
        snapshot,
        unavailable,
    })
}

/// The selected resources currently in a snapshot.
pub(crate) fn present_resources(
    r: &CapabilityRecord,
    snapshot: Option<&Snapshot>,
) -> Vec<crate::sources::ResourceEntry> {
    snapshot
        .map(|s| {
            s.resources
                .iter()
                .filter(|res| r.selects(&res.uri))
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// `POST /v1/capabilities`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateCapability {
    pub name: String,
    pub source: SourceRef,
    #[serde(default)]
    pub operations: Option<Vec<String>>,
    #[serde(default)]
    pub resources: Option<Value>,
    #[serde(default)]
    pub env_file: Option<String>,
    /// Absent, or an array.
    #[serde(default, deserialize_with = "crate::policy::present")]
    pub args: Option<Vec<String>>,
    /// One signed policy for each network in which this host is bound to
    /// its person, each claiming `name` for this host.
    #[serde(default)]
    pub policies: Option<Vec<Policy>>,
}

/// A checked new capability and its claims, by network.
type Drafted = (CapabilityRecord, Vec<(String, Policy)>);

impl Store {
    /// This host's person's stored policies, by network.
    pub(crate) fn own_policies(&self, conn: &Connection) -> Result<Vec<(String, Policy)>, Error> {
        let mut out = Vec::new();
        for (network, own) in self.own_members(conn)? {
            if let Some(person) = &own.person_id
                && let Some(key) = self.person_key(conn, &network, person)?
                && let Some(policy) = self.stored_policy(conn, &network, &key)?
            {
                out.push((network, policy));
            }
        }
        Ok(out)
    }
    /// The recipients of this host's rule for a capability, in each network.
    fn recipients(&self, conn: &Connection, name: &str) -> Result<Vec<Value>, Error> {
        let me = self.identity().id;
        let mut out = Vec::new();
        for (network, policy) in self.own_policies(conn)? {
            let persons = self.stored_persons(conn, &network)?;
            for rule in policy.capability_rules() {
                if rule.host != me || rule.capability != name {
                    continue;
                }
                for p in &rule.principals {
                    let label = p.strip_prefix("person:").and_then(|id| {
                        persons
                            .iter()
                            .find(|x| x.person_id == id)
                            .map(|x| x.member.clone())
                    });
                    out.push(json!({"network_id": network, "principal": p, "label": label}));
                }
            }
        }
        Ok(out)
    }
    /// Whether a stored rule of this person binds `name` to another host.
    pub(crate) fn bound_elsewhere(&self, conn: &Connection, name: &str) -> Result<bool, Error> {
        let me = self.identity().id;
        Ok(self.own_policies(conn)?.iter().any(|(_, p)| {
            p.capability_rules()
                .iter()
                .any(|r| r.capability == name && r.host != me)
        }))
    }
    fn capability_view(&self, conn: &Connection, r: &CapabilityRecord) -> Result<Value, Error> {
        let mut view = record_view(conn, r)?;
        view["recipients"] = json!(self.recipients(conn, &r.name)?);
        Ok(view)
    }
    pub fn capabilities_view(&self) -> Result<Value, Error> {
        let conn = self.connection()?;
        let mut out = Vec::new();
        for r in capability_records(&conn)? {
            out.push(self.capability_view(&conn, &r)?);
        }
        Ok(json!({"capabilities": out}))
    }
    pub fn capability_show(&self, name: &str) -> Result<Value, Error> {
        let conn = self.connection()?;
        let r = capability_record(&conn, name)?.ok_or(Error::NotFound)?;
        self.capability_view(&conn, &r)
    }
    /// Checks a new capability and builds its record. Returns an existing
    /// identical record instead, when there is one.
    fn draft(&self, c: CreateCapability) -> Result<Result<Drafted, Value>, Error> {
        let conn = self.connection()?;
        let agent: Option<String> = conn
            .query_row(
                "SELECT id FROM agents WHERE name = ?1",
                [&c.source.agent],
                |r| r.get(0),
            )
            .optional()?;
        let Some(agent_id) = agent else {
            return Err(Error::NotFound);
        };
        let Some(source) = server_record(&conn, &agent_id, &c.source.server)? else {
            return Err(Error::NotFound);
        };
        if !name_shape(&c.name) || c.name == READ {
            return Err(Error::Invalid(
                "capability names match [a-z0-9][a-z0-9_-]{0,62} and are not read".into(),
            ));
        }
        if !source.shareable {
            return Err(Error::Invalid(format!(
                "source {}/{} is not shareable ({})",
                c.source.agent,
                c.source.server,
                source.reason.unwrap_or_default()
            )));
        }
        let operations = c.operations.unwrap_or_default();
        if operations.iter().any(|o| o == READ) {
            return Err(Error::Invalid(
                "read is reserved for resources; a tool named read cannot be selected".into(),
            ));
        }
        let mut unique = operations.clone();
        unique.sort();
        unique.dedup();
        if unique.len() != operations.len() || operations.iter().any(String::is_empty) {
            return Err(Error::Invalid("operations are distinct tool names".into()));
        }
        let resources = match c.resources {
            None | Some(Value::Null) => Value::Null,
            Some(Value::String(all)) if all == "all" => json!("all"),
            Some(Value::Array(list))
                if !list.is_empty()
                    && list
                        .iter()
                        .all(|u| u.as_str().is_some_and(|u| !u.is_empty())) =>
            {
                Value::Array(list)
            }
            _ => {
                return Err(Error::Invalid(
                    "resources is null, \"all\", or a list of URIs".into(),
                ));
            }
        };
        if operations.is_empty() && resources.is_null() {
            return Err(Error::Invalid(
                "a capability has at least one operation or resources".into(),
            ));
        }
        if let Some(path) = &c.env_file
            && !(std::path::Path::new(path).is_absolute() && std::path::Path::new(path).is_file())
        {
            return Err(Error::Invalid(
                "the environment file must be an existing absolute path".into(),
            ));
        }
        let record = CapabilityRecord {
            name: c.name.clone(),
            source: c.source,
            agent_id,
            operations,
            resources,
            credential: Credential {
                env_file: c.env_file,
                args: c.args,
            },
            created_at: now(),
            snapshot: None,
            snapshot_error: None,
            health: Health::default(),
        };
        if let Some(old) = capability_record(&conn, &c.name)? {
            if old.same(&record) {
                return Ok(Err(record_view(&conn, &old)?));
            }
            return Err(Error::Conflict(format!(
                "capability {} exists with other settings",
                c.name
            )));
        }
        if self.bound_elsewhere(&conn, &c.name)? {
            return Err(Error::Conflict(format!(
                "a capability rule of yours binds {} to another host",
                c.name
            )));
        }
        let policies = self.claim_policies(&conn, &c.name, c.policies.unwrap_or_default())?;
        Ok(Ok((record, policies)))
    }
    /// Checks the claims sent with a new capability: one policy for each
    /// network in which this host is bound to its person, verified, signed
    /// by that person, and binding `name` to this host.
    fn claim_policies(
        &self,
        conn: &Connection,
        name: &str,
        mut given: Vec<Policy>,
    ) -> Result<Vec<(String, Policy)>, Error> {
        let me = self.identity().id;
        let at = chrono::Utc::now();
        let mut out = Vec::new();
        for (network, own) in self.own_members(conn)? {
            let Some(person) = &own.person_id else {
                continue;
            };
            let Some(i) = given.iter().position(|p| p.network_id == network) else {
                return Err(Error::Invalid(format!(
                    "policies has no signed policy for network {network}, in which this host is bound"
                )));
            };
            let p = given.remove(i);
            p.verify(&network)?;
            if !p.in_window(at) {
                return Err(Error::Invalid(
                    "a claim policy is not within its validity window".into(),
                ));
            }
            if self.person_key(conn, &network, person)?.as_deref()
                != Some(p.person_public_key.as_str())
            {
                return Err(Error::Invalid(format!(
                    "the policy for network {network} is not signed by this host's person"
                )));
            }
            if !p
                .capability_rules()
                .iter()
                .any(|r| r.host == me && r.capability == name)
            {
                return Err(Error::Invalid(format!(
                    "the policy for network {network} does not claim {name} for this host"
                )));
            }
            out.push((network, p));
        }
        if !given.is_empty() {
            return Err(Error::Invalid(
                "policies holds a policy for a network in which this host is not bound, or two for one network".into(),
            ));
        }
        Ok(out)
    }
    /// Checks the operations and URIs against the snapshot that will serve
    /// them, and stores the record.
    fn store_capability(
        &self,
        mut record: CapabilityRecord,
        own: Option<Snapshot>,
        policies: &[(String, Policy)],
    ) -> Result<Value, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let snapshot = match own {
            Some(s) => Some(s),
            None => server_record(&tx, &record.agent_id, &record.source.server)?
                .and_then(|s| s.snapshot),
        };
        let missing: Vec<&String> = record
            .operations
            .iter()
            .filter(|o| snapshot.as_ref().is_none_or(|s| s.tool(o).is_none()))
            .collect();
        if !missing.is_empty() {
            return Err(Error::Invalid(format!(
                "not in the source's snapshot: {}",
                missing
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        if let Value::Array(list) = &record.resources {
            let absent: Vec<&str> = list
                .iter()
                .filter_map(Value::as_str)
                .filter(|u| snapshot.as_ref().is_none_or(|s| s.resource(u).is_none()))
                .collect();
            if !absent.is_empty() {
                return Err(Error::Invalid(format!(
                    "resources not in the source's snapshot: {}",
                    absent.join(", ")
                )));
            }
        }
        if capability_record(&tx, &record.name)?.is_some() {
            return Err(Error::Conflict(format!(
                "capability {} exists",
                record.name
            )));
        }
        if record.credential.own() {
            record.snapshot = snapshot;
        }
        // The claims and the record are stored together; a refusal stores
        // nothing.
        for (network, p) in policies {
            self.submit_local_in(&tx, network, p)?;
        }
        save(&tx, &record)?;
        append_event(&tx, "capability.created", &record.name, &record.created_at)?;
        tx.commit()?;
        record_view(&conn, &record)
    }
    fn remove_capability(&self, name: &str) -> Result<Value, Error> {
        let view = self.capability_show(name)?;
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM capabilities WHERE name = ?1", [name])?;
        append_event(&tx, "capability.removed", name, &now())?;
        tx.commit()?;
        Ok(view)
    }

    /// `status`'s `capabilities` counts.
    pub(crate) fn capabilities_summary(&self) -> Result<Value, Error> {
        let conn = self.connection()?;
        let sources: i64 = conn.query_row("SELECT COUNT(*) FROM tool_servers", [], |r| r.get(0))?;
        let records = capability_records(&conn)?;
        let me = self.identity().id;
        let policies = self.own_policies(&conn)?;
        let shared = records
            .iter()
            .filter(|c| {
                policies.iter().any(|(_, p)| {
                    p.capability_rules()
                        .iter()
                        .any(|r| r.host == me && r.capability == c.name && !r.principals.is_empty())
                })
            })
            .count();
        let running: i64 = conn.query_row(
            "SELECT COUNT(*) FROM received_calls WHERE json_extract(record, '$.state') = 'running'",
            [],
            |r| r.get(0),
        )?;
        let open: i64 = conn.query_row("SELECT COUNT(*) FROM source_access", [], |r| r.get(0))?;
        Ok(json!({
            "sources": sources,
            "capabilities": records.len(),
            "shared": shared,
            "calls_running": running,
            "open_to": open,
        }))
    }
    /// Status item 14: sources failing, the environment file, and each
    /// capability that is unavailable or whose own instance is failing.
    pub(crate) fn failing_capabilities(&self) -> Result<Vec<(String, String, String)>, Error> {
        let mut out = self.failing_sources()?;
        let conn = self.connection()?;
        let day = chrono::Utc::now() - chrono::TimeDelta::hours(24);
        let recent = |at: &Option<String>| {
            at.as_deref()
                .and_then(|t| crate::membership::time(t).ok())
                .is_some_and(|t| t > day)
        };
        for r in capability_records(&conn)? {
            let now = current(&conn, &r)?;
            let mut causes = Vec::new();
            if !now.unavailable.is_empty() {
                causes.push(format!("unavailable: {}", now.unavailable.join(", ")));
            }
            if let Some(e) = &r.snapshot_error {
                causes.push(format!("its own instance's latest snapshot failed: {e}"));
            }
            if recent(&r.health.start_failed_at) {
                causes.push("its own instance failed to start in the last 24 hours".into());
            }
            if recent(&r.health.auth_error_at) {
                causes.push(format!(
                    "it answered with an error suggesting authentication in the last 24 hours ({})",
                    r.health.auth_error.clone().unwrap_or_default()
                ));
            }
            if !causes.is_empty() {
                out.push((
                    r.name.clone(),
                    causes.join("; "),
                    format!("peerspan capability show {}", r.name),
                ));
            }
        }
        Ok(out)
    }
    /// Status item 15: capability names here that a stored rule of this
    /// person binds to another host.
    pub(crate) fn capability_name_conflicts(&self) -> Result<Vec<(String, String, String)>, Error> {
        let conn = self.connection()?;
        let mut out = Vec::new();
        for r in capability_records(&conn)? {
            if self.bound_elsewhere(&conn, &r.name)? {
                let mut create = format!(
                    "peerspan capability create NEW_NAME --from {}/{}",
                    r.source.agent, r.source.server
                );
                if !r.operations.is_empty() {
                    create.push_str(&format!(" --operations {}", r.operations.join(",")));
                }
                match &r.resources {
                    Value::String(all) => create.push_str(&format!(" --resources {all}")),
                    Value::Array(list) => create.push_str(&format!(
                        " --resources {}",
                        list.iter()
                            .filter_map(Value::as_str)
                            .collect::<Vec<_>>()
                            .join(",")
                    )),
                    _ => {}
                }
                if let Some(file) = &r.credential.env_file {
                    create.push_str(&format!(" --env-file {file}"));
                }
                for a in r.credential.args.iter().flatten() {
                    create.push_str(&format!(" --arg {a}"));
                }
                out.push((
                    r.name.clone(),
                    format!(
                        "a capability rule of yours binds {} to another host, because a concurrent claim of that name won; it still works through self access, addressed as {}/{} only, but cannot be shared under its name",
                        r.name,
                        self.identity().id,
                        r.name
                    ),
                    format!("{create} && peerspan capability remove {}", r.name),
                ));
            }
        }
        Ok(out)
    }
}

pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/capabilities", get(list_route).post(create_route))
        .route(
            "/v1/capabilities/{name}",
            get(show_route).delete(remove_route),
        )
}
async fn list_route(State(store): State<Arc<Store>>) -> Result<Json<Value>, Error> {
    Ok(Json(blocking(store, |s| s.capabilities_view()).await?))
}
async fn show_route(
    State(store): State<Arc<Store>>,
    Path(name): Path<String>,
) -> Result<Json<Value>, Error> {
    Ok(Json(
        blocking(store, move |s| s.capability_show(&name)).await?,
    ))
}
async fn remove_route(
    State(store): State<Arc<Store>>,
    Path(name): Path<String>,
) -> Result<Json<Value>, Error> {
    Ok(Json(
        blocking(store, move |s| s.remove_capability(&name)).await?,
    ))
}
async fn create_route(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<Value>), Error> {
    let request: CreateCapability = decode(body)?;
    let (record, policies) = match blocking(store.clone(), move |s| s.draft(request)).await? {
        Ok(drafted) => drafted,
        Err(existing) => return Ok((StatusCode::OK, Json(existing))),
    };
    // A capability with its own credential is snapshotted with it, and its
    // operations are checked against that snapshot.
    let own = if record.credential.own() {
        let (r, instance) = (record.clone(), record.instance());
        let launch = blocking(store.clone(), move |s| {
            s.launch_with(&*s.connection()?, &instance, Some(&r))
        })
        .await?;
        match take_snapshot(launch).await {
            Ok(snapshot) => Some(snapshot),
            Err(e) => {
                return Err(Error::Invalid(format!(
                    "the capability's own credential could not list the source: {e}"
                )));
            }
        }
    } else {
        None
    };
    let claims = policies.clone();
    let view = blocking(store.clone(), move |s| {
        s.store_capability(record, own, &claims)
    })
    .await?;
    // The claims are then submitted as any policy.
    for (network, p) in policies {
        crate::policy_sync::after_store(store.clone(), network, p).await;
    }
    Ok((StatusCode::CREATED, Json(view)))
}
