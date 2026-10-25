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
    extract::{Path, Query, State, rejection::BytesRejection},
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
    /// The approval requirement; a record without one reads as none.
    #[serde(default)]
    pub approval: crate::approvals::Requirement,
    /// `{}`, or `{"arguments": [COMBINATION, ...]}`.
    #[serde(default = "no_bounds")]
    pub bounds: Value,
}
fn no_bounds() -> Value {
    json!({})
}
impl CapabilityRecord {
    /// Its bound's combinations; empty for none.
    pub fn combinations(&self) -> Vec<crate::bounds::Combination> {
        crate::bounds::of_record(&self.bounds)
    }
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
            && self.approval == other.approval
            && self.combinations() == other.combinations()
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
    .map(|t| decode_capability(&t))
    .transpose()
}
pub(crate) fn capability_records(conn: &Connection) -> Result<Vec<CapabilityRecord>, Error> {
    let mut statement = conn.prepare("SELECT record FROM capabilities ORDER BY name")?;
    statement
        .query_map([], |r| r.get::<_, String>(0))?
        .map(|r| decode_capability(&r?))
        .collect()
}
/// A `capabilities.record`, in this host's shape or as the Go host writes
/// it, whose own snapshot is its flat snapshot state, so a database moved
/// between the two reads either way.
fn decode_capability(text: &str) -> Result<CapabilityRecord, Error> {
    if let Ok(record) = serde_json::from_str::<CapabilityRecord>(text) {
        return Ok(record);
    }
    let mut v: Value = serde_json::from_str(text)?;
    let flat = v
        .as_object_mut()
        .and_then(|o| o.remove("snapshot"))
        .unwrap_or(Value::Null);
    let mut record: CapabilityRecord = json(v.to_string())?;
    if !flat.is_null() {
        let (snapshot, snapshot_error, health) = crate::sources::flat_snapshot(&flat)?;
        record.snapshot = snapshot;
        record.snapshot_error = snapshot_error;
        record.health = health;
    }
    Ok(record)
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
        "bounds": crate::bounds::to_value(&r.combinations()),
        "credential_reach": credential_reach(conn, r)?,
        "state": now.state(),
        "unavailable": now.unavailable,
        "created_at": r.created_at,
        "approval": r.approval,
    }))
}

/// Whether a capability is built on a built-in `gh` source.
pub(crate) fn on_gh(conn: &Connection, r: &CapabilityRecord) -> Result<bool, Error> {
    Ok(crate::builtin::is_builtin(&r.agent_id)
        && server_record(conn, &r.agent_id, &r.source.server)?
            .and_then(|s| s.builtin)
            .is_some_and(|b| b.adapter == "gh"))
}
/// The reach of a gh capability's credential: its own snapshot's, or the
/// source's; null otherwise.
fn credential_reach(conn: &Connection, r: &CapabilityRecord) -> Result<Value, Error> {
    if !on_gh(conn, r)? {
        return Ok(Value::Null);
    }
    let reach = if r.credential.own() {
        r.snapshot.as_ref().and_then(|s| s.reach.clone())
    } else {
        server_record(conn, &r.agent_id, &r.source.server)?
            .and_then(|s| s.snapshot)
            .and_then(|s| s.reach)
    };
    Ok(json!(reach))
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
    #[serde(default)]
    pub(crate) catalogs: Vec<crate::link_runtime::claims::ClaimCatalog>,
    /// The approval requirement, `{operations, agent_self}`.
    #[serde(default)]
    pub approval: Option<Value>,
    /// Absent, `{}`, or `{"arguments": [...]}`; an explicit null is kept
    /// as `Some(Null)` so validation refuses it.
    #[serde(default, deserialize_with = "present_value")]
    pub bounds: Option<Value>,
}

/// A checked new capability and its claims, by network.
type Drafted = (
    CapabilityRecord,
    Vec<(String, Policy)>,
    Vec<crate::link_runtime::claims::ClaimCatalog>,
);

impl Store {
    /// This host's person's stored policies, by network.
    pub(crate) fn own_policies(&self, conn: &Connection) -> Result<Vec<(String, Policy)>, Error> {
        let mut out = Vec::new();
        for (network, own) in self.own_members(conn)? {
            if let Some(person) = &own.person_id
                && let Some(key) = self.person_key(conn, &network, person)?
                && let Some(policy) = self.stored_policy(conn, &network, &key)?
            {
                // With this host's unsettled withdrawals applied, as
                // authorization sees it.
                out.push((network.clone(), self.enforced(conn, &network, policy)?));
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
        // `builtin/NAME` always names a built-in source.
        let agent: Option<String> = if c.source.agent == crate::builtin::AGENT {
            Some(crate::builtin::AGENT.into())
        } else {
            conn.query_row(
                "SELECT id FROM agents WHERE name = ?1",
                [&c.source.agent],
                |r| r.get(0),
            )
            .optional()?
        };
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
        let builtin = source.builtin.clone();
        if builtin.is_some() && c.args.is_some() {
            return Err(Error::Invalid(
                "a built-in source has no arguments to replace; --arg is refused".into(),
            ));
        }
        let combinations = crate::bounds::parse(c.bounds.as_ref())?;
        let gh = builtin.as_ref().is_some_and(|b| b.adapter == "gh");
        if gh
            && combinations
                .iter()
                .filter_map(|k| k.get("repo"))
                .any(|v| !crate::bounds::gh_repo_bound(v))
        {
            return Err(Error::Coded {
                status: 400,
                code: "invalid",
                message: "A gh repository bound is OWNER/REPO or OWNER/*.".into(),
                extra: Default::default(),
            });
        }
        if !combinations.is_empty() && operations.is_empty() {
            return Err(Error::Coded {
                status: 400,
                code: "invalid",
                message: "A bound applies to tool operations, and the capability has none.".into(),
                extra: Default::default(),
            });
        }
        let approval = match &c.approval {
            None | Some(Value::Null) => crate::approvals::Requirement::default(),
            Some(body) => {
                crate::approvals::parse_requirement(body, &operations, !resources.is_null(), true)?
            }
        };
        let record = CapabilityRecord {
            approval,
            bounds: crate::bounds::to_value(&combinations),
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
        let policies =
            self.claim_policies(&conn, &c.name, c.policies.unwrap_or_default(), &c.catalogs)?;
        Ok(Ok((record, policies, c.catalogs)))
    }
    /// Checks the claims sent with a new capability: one policy for each
    /// network in which this host is bound to its person, verified, signed
    /// by that person, and binding `name` to this host.
    fn claim_policies(
        &self,
        conn: &Connection,
        name: &str,
        mut given: Vec<Policy>,
        catalogs: &[crate::link_runtime::claims::ClaimCatalog],
    ) -> Result<Vec<(String, Policy)>, Error> {
        let mut networks: std::collections::BTreeSet<String> =
            given.iter().map(|p| p.network_id.clone()).collect();
        if networks.len() != given.len() {
            return Err(Error::Invalid("duplicate claim network".into()));
        }
        for claim in catalogs {
            if !networks.insert(claim.network_id.clone()) {
                return Err(Error::Invalid("duplicate claim network".into()));
            }
            let checked = crate::link_runtime::claims::check(self, conn, name, claim)
                .map_err(crate::link_runtime::support::model_error)?;
            given.push(checked.policy);
        }
        let me = self.identity().id;
        let at = chrono::Utc::now();
        let mut out = Vec::new();
        // Claims are signed by one person: required in each network where
        // this host is bound to that person. Other networks gain theirs at
        // the first share there.
        let signer = given.first().map(Policy::person_id);
        if given.iter().any(|p| Some(p.person_id()) != signer) {
            return Err(Error::Invalid(
                "the policies are signed by more than one person".into(),
            ));
        }
        let members = self.own_members(conn)?;
        if signer.is_none() && members.iter().any(|(_, m)| m.person_id.is_some()) {
            return Err(Error::Invalid(
                "policies has no signed policy, and this host is bound to a person".into(),
            ));
        }
        for (network, own) in members {
            let Some(person) = &own.person_id else {
                continue;
            };
            if signer.as_ref() != Some(person) {
                continue;
            }
            let Some(i) = given.iter().position(|p| p.network_id == network) else {
                return Err(Error::Invalid(format!(
                    "policies has no signed policy for network {network}, in which this host is bound"
                )));
            };
            let p = given.remove(i);
            if !catalogs.iter().any(|c| c.network_id == network) {
                p.verify(&network)?;
            }
            // Typed catalogs were revalidated at the runtime decision clock
            // above; preserve the legacy policy clock for legacy submissions.
            if !catalogs.iter().any(|c| c.network_id == network) && !p.in_window(at) {
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
        catalogs: &[crate::link_runtime::claims::ClaimCatalog],
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
        if let Some(refusal) = crate::bounds::unenforceable(
            &record.combinations(),
            record.operations.iter().map(|o| {
                (
                    o.as_str(),
                    snapshot
                        .as_ref()
                        .and_then(|s| s.tool(o))
                        .map(|t| &t.input_schema),
                )
            }),
        ) {
            return Err(refusal);
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
        self.claim_policies(
            &tx,
            &record.name,
            policies
                .iter()
                .filter(|(n, _)| !catalogs.iter().any(|c| &c.network_id == n))
                .map(|(_, p)| p.clone())
                .collect(),
            catalogs,
        )?;
        crate::link_runtime::claims::apply(self, &tx, &record.name, catalogs)
            .map_err(crate::link_runtime::support::model_error)?;
        // The claims and the record are stored together; a refusal stores
        // nothing.
        for (network, p) in policies
            .iter()
            .filter(|(n, _)| !catalogs.iter().any(|c| &c.network_id == n))
        {
            self.submit_local_in(&tx, network, p)?;
        }
        save(&tx, &record)?;
        append_event(&tx, "capability.created", &record.name, &record.created_at)?;
        tx.commit()?;
        self.refresh_member_pins(&conn)?;
        record_view(&conn, &record)
    }
    /// `PUT /v1/capabilities/{name}/approval`: replaces the requirement,
    /// signing nothing, and records `capability.approval_changed`.
    pub fn set_approval(&self, name: &str, body: &Value) -> Result<Value, Error> {
        {
            let mut conn = self.connection()?;
            let tx = conn.transaction()?;
            let mut record = capability_record(&tx, name)?.ok_or(Error::NotFound)?;
            record.approval = crate::approvals::parse_requirement(
                body,
                &record.operations,
                record.reads(),
                record.approval.agent_self,
            )?;
            save(&tx, &record)?;
            append_event(&tx, "capability.approval_changed", name, &now())?;
            tx.commit()?;
        }
        self.capability_show(name)
    }
    fn remove_capability(&self, name: &str) -> Result<Value, Error> {
        let view = self.capability_show(name)?;
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        // The record stays while any stored policy, of any person, holds
        // this host's rule for the name.
        let me = self.identity().id;
        let holders: Vec<(String, String)> = {
            let mut statement = tx.prepare(
                "SELECT network_id, record FROM network_statements WHERE kind = 'policy' ORDER BY network_id, subject",
            )?;
            statement
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<_, _>>()?
        };
        for (network, record) in holders {
            let p: Policy = json(record)?;
            if p.capability_rules()
                .iter()
                .any(|r| r.host == me && r.capability == name)
            {
                return Err(Error::Conflict(format!(
                    "the policy of {} in network {network} still holds this host's rule for {name}; withdraw it first",
                    p.person_id()
                )));
            }
        }
        tx.execute("DELETE FROM capabilities WHERE name = ?1", [name])?;
        append_event(&tx, "capability.removed", name, &now())?;
        tx.commit()?;
        Ok(view)
    }

    /// `status`'s `capabilities` counts.
    pub(crate) fn capabilities_summary(&self) -> Result<Value, Error> {
        let conn = self.connection()?;
        let sources: i64 = conn.query_row(
            "SELECT (SELECT COUNT(*) FROM tool_servers) + (SELECT COUNT(*) FROM builtin_sources)",
            [],
            |r| r.get(0),
        )?;
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
        let pending: i64 = conn.query_row(
            "SELECT COUNT(*) FROM call_approvals WHERE state = 'pending'",
            [],
            |r| r.get(0),
        )?;
        Ok(json!({
            "sources": sources,
            "capabilities": records.len(),
            "shared": shared,
            "calls_running": running,
            "open_to": open,
            "approvals_pending": pending,
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
        .route(
            "/v1/capabilities/{name}/approval",
            axum::routing::put(approval_route),
        )
}
async fn approval_route(
    State(store): State<Arc<Store>>,
    Path(name): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let body: Value = decode(body)?;
    let view = blocking(store.clone(), move |s| s.set_approval(&name, &body)).await?;
    // As `capability show` without `lookup`: agent recipients are labeled
    // from the cache, with no peer traffic.
    let mut views = [view];
    label_views(&store, &mut views, false).await?;
    let [view] = views;
    Ok(Json(view))
}
#[derive(Deserialize)]
struct LookupQuery {
    #[serde(default)]
    lookup: Option<String>,
}
/// Labels the agent recipients of capability views, asking their hosts
/// first with `lookup`.
async fn label_views(store: &Arc<Store>, views: &mut [Value], lookup: bool) -> Result<(), Error> {
    let mut all: Vec<Value> = Vec::new();
    let mut counts = Vec::new();
    for v in views.iter() {
        let list = v["recipients"].as_array().cloned().unwrap_or_default();
        counts.push(list.len());
        all.extend(list);
    }
    crate::agent_lookup::label_agent_recipients(store, &mut all, lookup).await?;
    let mut rest = all.into_iter();
    for (v, n) in views.iter_mut().zip(counts) {
        v["recipients"] = Value::Array(rest.by_ref().take(n).collect());
    }
    Ok(())
}
async fn list_route(
    State(store): State<Arc<Store>>,
    query: Query<LookupQuery>,
) -> Result<Json<Value>, Error> {
    let mut view = blocking(store.clone(), |s| s.capabilities_view()).await?;
    if let Some(list) = view["capabilities"].as_array_mut() {
        label_views(&store, list, query.lookup.as_deref() == Some("true")).await?;
    }
    Ok(Json(view))
}
async fn show_route(
    State(store): State<Arc<Store>>,
    Path(name): Path<String>,
    query: Query<LookupQuery>,
) -> Result<Json<Value>, Error> {
    let view = blocking(store.clone(), move |s| s.capability_show(&name)).await?;
    let mut views = [view];
    label_views(&store, &mut views, query.lookup.as_deref() == Some("true")).await?;
    let [view] = views;
    Ok(Json(view))
}
async fn remove_route(
    State(store): State<Arc<Store>>,
    Path(name): Path<String>,
) -> Result<Json<Value>, Error> {
    Ok(Json(
        blocking(store, move |s| s.remove_capability(&name)).await?,
    ))
}
/// For a new gh capability with a bound: each exact bound repository the
/// capability's credential cannot see, as a warning.
/// A field that is present, null included.
fn present_value<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(d).map(Some)
}
/// The bound warnings' total time budget.
const WARNING_BUDGET: std::time::Duration = std::time::Duration::from_secs(40);
async fn visibility_warnings(store: &Arc<Store>, record: CapabilityRecord) -> Vec<String> {
    let mut repos: Vec<String> = Vec::new();
    for c in record.combinations() {
        if let Some(r) = c.get("repo")
            && crate::bounds::owner_wildcard(r).is_none()
            && !repos.contains(r)
        {
            repos.push(r.clone());
        }
    }
    if repos.is_empty() {
        return Vec::new();
    }
    let r = record.clone();
    let launch = blocking(store.clone(), move |s| {
        let conn = s.connection()?;
        if !on_gh(&conn, &r)? {
            return Ok(None);
        }
        s.launch_with(&conn, &r.instance(), Some(&r)).map(Some)
    })
    .await;
    let Ok(Some(launch)) = launch else {
        return Vec::new();
    };
    let Some((gh, state)) = crate::gh::launch_target(&launch.args) else {
        return Vec::new();
    };
    // The checks run in order and share one budget, so the create answers
    // well inside the CLI's request timeout however many repositories the
    // bound names; a repository the budget leaves no time for is not
    // checked and gets no warning.
    let started = std::time::Instant::now();
    let mut out = Vec::new();
    for repo in repos {
        let Some(left) = WARNING_BUDGET.checked_sub(started.elapsed()) else {
            break;
        };
        if left.is_zero() {
            break;
        }
        if !crate::gh::repo_visible(&gh, &state, &launch.env, &repo, left).await {
            out.push(format!("{repo} is not visible to this credential"));
        }
    }
    out
}
async fn create_route(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<Value>), Error> {
    let request: CreateCapability = decode(body)?;
    let (record, policies, catalogs) =
        match blocking(store.clone(), move |s| s.draft(request)).await? {
            Ok(drafted) => drafted,
            Err(mut existing) => {
                existing["warnings"] = json!([]);
                return Ok((StatusCode::OK, Json(existing)));
            }
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
    let legacy: Vec<_> = policies
        .iter()
        .filter(|(n, _)| !catalogs.iter().any(|c| &c.network_id == n))
        .cloned()
        .collect();
    let stored = record.clone();
    let mut view = blocking(store.clone(), move |s| {
        s.store_capability(record, own, &claims, &catalogs)
    })
    .await?;
    view["warnings"] = json!(visibility_warnings(&store, stored).await);
    // The claims are then submitted as any policy.
    for (network, p) in legacy {
        crate::policy_sync::after_store(store.clone(), network, p).await;
    }
    Ok((StatusCode::CREATED, Json(view)))
}
