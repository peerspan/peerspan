//! Built-in sources (capabilities contract, slice 3): adapters Peerspan
//! ships, detected by the CLI and addressed `builtin/NAME`. Their
//! definitions live in `builtin_sources`, and their values in
//! `tool_values` with `agent_id` `builtin`. Slice 3 registers only `gh`.
use crate::{
    api::{blocking, decode},
    capabilities::capability_records,
    model::Error,
    policy::name_shape,
    sources::{EnvSource, Instance, ServerRecord},
    store::{Store, append_event, now},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{State, rejection::BytesRejection},
    routing::put,
};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

/// Database version 21: built-in source definitions.
pub(crate) const SCHEMA: &str = "
CREATE TABLE builtin_sources (name TEXT PRIMARY KEY, record TEXT NOT NULL);
PRAGMA user_version = 21;
";
/// The agent position of a built-in source's address.
pub const AGENT: &str = "builtin";
/// The adapters this binary registers.
pub const ADAPTERS: [&str; 1] = ["gh"];
/// The first `gh` release with `gh auth status --json`.
pub const MIN_GH: (u64, u64, u64) = (2, 81, 0);

/// A built-in source definition, as the CLI discovered it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BuiltinDefinition {
    pub name: String,
    pub adapter: String,
    pub command: String,
    pub version: Option<String>,
    pub host: String,
    pub account: Option<String>,
    pub authenticated: bool,
    pub env: BTreeMap<String, EnvSource>,
    pub disabled: bool,
}

const FIELDS: [&str; 9] = [
    "name",
    "adapter",
    "command",
    "version",
    "host",
    "account",
    "authenticated",
    "env",
    "disabled",
];

/// `X.Y.Z` as numbers.
pub fn version_of(text: &str) -> Option<(u64, u64, u64)> {
    let mut parts = text.split('.');
    let v = (
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    );
    parts.next().is_none().then_some(v)
}

/// The stored record of a built-in source, as a `ServerRecord`.
pub(crate) fn record(conn: &Connection, name: &str) -> Result<Option<ServerRecord>, Error> {
    use rusqlite::OptionalExtension;
    conn.query_row(
        "SELECT record FROM builtin_sources WHERE name = ?1",
        [name],
        |r| r.get::<_, String>(0),
    )
    .optional()?
    .map(|t| decode_record(&t))
    .transpose()
}
pub(crate) fn records(conn: &Connection) -> Result<Vec<ServerRecord>, Error> {
    let mut statement = conn.prepare("SELECT record FROM builtin_sources ORDER BY name")?;
    statement
        .query_map([], |r| r.get::<_, String>(0))?
        .map(|r| decode_record(&r?))
        .collect()
}
/// A `builtin_sources.record`, in this host's shape or as the Go host
/// writes it (the definition flat beside the snapshot state and `reach`),
/// so a database moved between the two reads either way.
fn decode_record(text: &str) -> Result<ServerRecord, Error> {
    if let Ok(record) = serde_json::from_str::<ServerRecord>(text) {
        return Ok(record);
    }
    let mut v: Value = serde_json::from_str(text)?;
    let builtin: BuiltinDefinition = serde_json::from_value(json!({
        "name": v["name"], "adapter": v["adapter"], "command": v["command"],
        "version": v["version"], "host": v["host"], "account": v["account"],
        "authenticated": v["authenticated"].as_bool().unwrap_or(false),
        "env": v.get("env").cloned().filter(|e| e.is_object()).unwrap_or(json!({})),
        "disabled": v["disabled"].as_bool().unwrap_or(false),
    }))?;
    if let Some(o) = v.as_object_mut() {
        o.insert("transport".into(), json!("stdio"));
        o.insert("args".into(), json!([]));
        o.insert("url".into(), Value::Null);
        o.insert("source".into(), json!(AGENT));
    }
    let mut record = crate::sources::decode_server(AGENT, &v.to_string())?;
    record.builtin = Some(builtin);
    Ok(record)
}
pub(crate) fn save(conn: &Connection, r: &ServerRecord) -> Result<(), Error> {
    conn.execute(
        "INSERT OR REPLACE INTO builtin_sources VALUES (?1, ?2)",
        params![r.definition.name, serde_json::to_string(r)?],
    )?;
    Ok(())
}

/// Validates one definition from `PUT /v1/builtin-sources`.
fn definition(value: &Value) -> Result<BuiltinDefinition, Error> {
    let bad = |m: &str| Err(Error::Invalid(format!("built-in source: {m}")));
    let Some(object) = value.as_object() else {
        return bad("a definition is an object");
    };
    for field in FIELDS {
        if !object.contains_key(field) {
            return bad(&format!("a definition needs {field}"));
        }
    }
    if object.len() != FIELDS.len() {
        return bad("unknown definition field");
    }
    let Ok(d) = serde_json::from_value::<BuiltinDefinition>(value.clone()) else {
        return bad("invalid definition");
    };
    if d.name.is_empty() || d.name.len() > 256 || d.name.chars().any(char::is_control) {
        return bad("invalid name");
    }
    if !ADAPTERS.contains(&d.adapter.as_str()) {
        return bad("adapter is gh");
    }
    if !std::path::Path::new(&d.command).is_absolute() || d.command.contains('\0') {
        return bad("command is an absolute path");
    }
    if d.host != "github.com" {
        return bad("host is github.com");
    }
    let env_ok = |s: &EnvSource| match (s.source.as_str(), &s.variables) {
        ("missing", Some(v)) => !v.is_empty() && v.iter().all(|n| !n.is_empty()),
        ("literal" | "captured", None) => true,
        _ => false,
    };
    if d.env.values().any(|s| !env_ok(s))
        || d.env
            .keys()
            .any(|k| k.is_empty() || k.contains('=') || k.contains('\0'))
    {
        return bad("env sources are literal, captured, or missing");
    }
    Ok(d)
}

/// The `ServerRecord` of a definition: a stdio source from `builtin`.
fn as_server(d: &BuiltinDefinition) -> crate::sources::Definition {
    crate::sources::Definition {
        name: d.name.clone(),
        transport: "stdio".into(),
        command: Some(d.command.clone()),
        args: Vec::new(),
        env: d.env.clone(),
        url: None,
        source: AGENT.into(),
        disabled: None,
    }
}

impl Store {
    /// Whether an agent named `builtin` has a tool server named `name`.
    fn builtin_name_taken(&self, conn: &Connection, name: &str) -> Result<bool, Error> {
        Ok(conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM agents a JOIN tool_servers t ON t.agent_id = a.id WHERE a.name = 'builtin' AND t.name = ?1)",
            [name],
            |r| r.get(0),
        )?)
    }
    /// Replaces every built-in source definition and value in one
    /// transaction. Returns the instances to snapshot and the sources whose
    /// instances stop.
    fn replace_builtin(&self, body: Value) -> Result<(Vec<Instance>, Vec<String>), Error> {
        let Some(object) = body.as_object() else {
            return Err(Error::Invalid("invalid request".into()));
        };
        if object.keys().any(|k| k != "sources" && k != "values") {
            return Err(Error::Invalid("unknown field".into()));
        }
        let Some(Value::Array(list)) = object.get("sources") else {
            return Err(Error::Invalid("sources is a list".into()));
        };
        if list.len() > 100 {
            return Err(Error::Invalid("at most 100 built-in sources".into()));
        }
        let values: BTreeMap<String, BTreeMap<String, String>> = match object.get("values") {
            None | Some(Value::Null) => BTreeMap::new(),
            Some(v) => serde_json::from_value(v.clone())
                .map_err(|_| Error::Invalid("values maps NAME to {FIELD: VALUE}".into()))?,
        };
        let mut definitions = Vec::new();
        let mut names = BTreeSet::new();
        for item in list {
            let d = definition(item)?;
            if !names.insert(d.name.clone()) {
                return Err(Error::Invalid(format!("{:?} is listed twice", d.name)));
            }
            definitions.push(d);
        }
        for (server, fields) in &values {
            let Some(d) = definitions.iter().find(|d| &d.name == server) else {
                return Err(Error::Invalid(format!(
                    "values name unknown source {server:?}"
                )));
            };
            for (field, value) in fields {
                let ok = field.strip_prefix("env.").is_some_and(|n| {
                    d.env
                        .get(n)
                        .is_some_and(|s| s.source == "literal" || s.source == "captured")
                });
                if !ok || value.len() > 65536 || value.contains('\0') {
                    return Err(Error::Invalid(format!(
                        "invalid value field {field:?} of {server:?}"
                    )));
                }
            }
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let old: BTreeMap<String, ServerRecord> = records(&tx)?
            .into_iter()
            .map(|s| (s.definition.name.clone(), s))
            .collect();
        let mut old_values: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        {
            let mut statement =
                tx.prepare("SELECT server, field, value FROM tool_values WHERE agent_id = ?1")?;
            let rows = statement.query_map([AGENT], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?;
            for row in rows {
                let (s, f, v) = row?;
                old_values.entry(s).or_default().insert(f, v);
            }
        }
        let mut stop: Vec<String> = old
            .keys()
            .filter(|n| !names.contains(*n))
            .cloned()
            .collect();
        tx.execute("DELETE FROM builtin_sources", [])?;
        tx.execute("DELETE FROM tool_values WHERE agent_id = ?1", [AGENT])?;
        let at = now();
        let mut snapshot = Vec::new();
        for d in definitions {
            let mut missing: Vec<String> = d
                .env
                .values()
                .filter(|s| s.source == "missing")
                .flat_map(|s| s.variables.clone().unwrap_or_default())
                .collect();
            missing.sort();
            missing.dedup();
            let too_old = d
                .version
                .as_deref()
                .and_then(version_of)
                .is_none_or(|v| v < MIN_GH);
            let reason = if !name_shape(&d.name) || self.builtin_name_taken(&tx, &d.name)? {
                Some("name")
            } else if too_old {
                Some("version")
            } else if !d.authenticated {
                Some("not_authenticated")
            } else if !missing.is_empty() {
                Some("missing_env")
            } else {
                None
            };
            let new_values = values.get(&d.name).cloned().unwrap_or_default();
            let previous = old.get(&d.name);
            if previous.is_some_and(|p| {
                p.builtin.as_ref() != Some(&d)
                    || old_values.get(&d.name).cloned().unwrap_or_default() != new_values
            }) {
                stop.push(d.name.clone());
            }
            let record = ServerRecord {
                agent_id: AGENT.into(),
                definition: as_server(&d),
                workspace: String::new(),
                shareable: reason.is_none(),
                reason: reason.map(str::to_owned),
                missing_env: missing,
                snapshot: previous.and_then(|p| p.snapshot.clone()),
                snapshot_error: previous.and_then(|p| p.snapshot_error.clone()),
                health: previous.map(|p| p.health.clone()).unwrap_or_default(),
                updated_at: at.clone(),
                builtin: Some(d.clone()),
            };
            save(&tx, &record)?;
            for (field, value) in &new_values {
                tx.execute(
                    "INSERT INTO tool_values VALUES (?1, ?2, ?3, ?4)",
                    params![AGENT, d.name, field, value],
                )?;
            }
            if reason.is_none() {
                snapshot.push(Instance {
                    agent_id: AGENT.into(),
                    server: d.name.clone(),
                    capability: None,
                });
            }
        }
        for c in capability_records(&tx)? {
            if c.agent_id == AGENT
                && c.credential.own()
                && snapshot
                    .iter()
                    .any(|i| i.capability.is_none() && i.server == c.source.server)
            {
                snapshot.push(c.instance());
            }
        }
        append_event(&tx, "sources.discovered", AGENT, &at)?;
        tx.commit()?;
        Ok((snapshot, stop))
    }

    /// The built-in sources as `GET /v1/sources` lists them.
    pub(crate) fn builtin_view(&self, conn: &Connection) -> Result<Vec<Value>, Error> {
        let built = capability_records(conn)?;
        let mut out = Vec::new();
        for s in records(conn)? {
            let Some(b) = &s.builtin else { continue };
            let capabilities: Vec<&str> = built
                .iter()
                .filter(|c| c.agent_id == AGENT && c.source.server == b.name)
                .map(|c| c.name.as_str())
                .collect();
            let snap = s.snapshot.as_ref();
            out.push(json!({
                "name": b.name,
                "adapter": b.adapter,
                "transport": "stdio",
                "command": b.command,
                "args": [],
                "env": b.env,
                "url": null,
                "source": AGENT,
                "version": b.version,
                "host": b.host,
                "account": b.account,
                "authenticated": b.authenticated,
                "disabled": b.disabled,
                "shareable": s.shareable,
                "reason": s.reason,
                "missing_env": s.missing_env,
                "tools": snap.map(|s| s.tools.clone()).unwrap_or_default(),
                "resources": snap.map(|s| s.resources.clone()).unwrap_or_default(),
                "snapshot_at": snap.map(|s| s.taken_at.clone()),
                "snapshot_error": s.snapshot_error,
                "start_failed_at": s.health.start_failed_at,
                "auth_error_at": s.health.auth_error_at,
                "capabilities": capabilities,
                "reach": snap.and_then(|s| s.reach.clone()),
            }));
        }
        Ok(out)
    }
    /// The definition's account of a built-in source.
    pub(crate) fn builtin_account(&self, conn: &Connection, name: &str) -> Option<String> {
        record(conn, name)
            .ok()
            .flatten()
            .and_then(|r| r.builtin)
            .and_then(|b| b.account)
    }
}

/// Whether an instance or source belongs to a built-in source.
pub fn is_builtin(agent_id: &str) -> bool {
    agent_id == AGENT
}

pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new().route("/v1/builtin-sources", put(put_route))
}
async fn put_route(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let request: Value = decode(body)?;
    let (instances, stop) = blocking(store.clone(), move |s| s.replace_builtin(request)).await?;
    for server in &stop {
        store.tool_pool.stop(AGENT, server);
    }
    crate::sources::snapshot_all(store.clone(), instances).await;
    let view = blocking(store, |s| {
        let conn = s.connection()?;
        s.builtin_view(&conn)
    })
    .await?;
    Ok(Json(json!({"builtin": view})))
}
