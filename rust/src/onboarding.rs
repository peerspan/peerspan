//! Owner-local exact project reviews. Registry metadata is never readiness.
use crate::{
    api::{blocking, decode},
    model::{AttachSession, Error},
    store::{Store, append_event, new_id},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State, rejection::BytesRejection},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, SecondsFormat, TimeDelta, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{path::Component, sync::Arc};

pub(crate) const SCHEMA: &str = "
CREATE TABLE onboarding_project_flows (
 flow_id TEXT PRIMARY KEY NOT NULL,
 project_root TEXT NOT NULL,
 native_session_id TEXT NOT NULL,
 integration TEXT NOT NULL,
 request TEXT NOT NULL,
 review TEXT NOT NULL,
 review_id TEXT NOT NULL,
 state TEXT NOT NULL CHECK (state IN ('review', 'attached', 'declined')),
 created_at TEXT NOT NULL,
 expires_at TEXT NOT NULL,
 session_id TEXT REFERENCES sessions(id),
 decided_at TEXT
);
PRAGMA user_version = 24;
";

pub(crate) fn check_namespace(connection: &Connection) -> anyhow::Result<()> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='onboarding_project_flows')",
        [],
        |r| r.get(0),
    )?;
    anyhow::ensure!(
        !exists,
        "reserved project-flow object exists before schema24"
    );
    Ok(())
}

pub(crate) fn check_schema(connection: &Connection) -> anyhow::Result<()> {
    let sql: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name='onboarding_project_flows'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    let expected = SCHEMA.split(';').next().unwrap_or_default();
    let normalized = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
    anyhow::ensure!(
        sql.as_deref()
            .is_some_and(|s| normalized(s) == normalized(expected)),
        "corrupt schema24 project-flow table"
    );
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum AgentChoice {
    #[serde(rename = "new")]
    New { name: String, owner: String },
    #[serde(rename = "existing")]
    Existing { id: String },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prepare {
    pub project_root: String,
    pub native_session_id: String,
    pub integration: String,
    pub agent: AgentChoice,
    #[serde(default, deserialize_with = "non_null_string")]
    pub replace_flow_id: Option<String>,
}
fn non_null_string<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct Proposal {
    project_root: String,
    native_session_id: String,
    integration: String,
    agent: AgentChoice,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    Approve,
    Decline,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub review_id: String,
    pub project_root: String,
    pub native_session_id: String,
    pub integration: String,
    pub decision: DecisionKind,
}

struct Flow {
    id: String,
    proposal: Proposal,
    review: Value,
    review_id: String,
    state: String,
    expires_at: String,
    session_id: Option<String>,
}

fn coded(code: &'static str, message: &str) -> Error {
    Error::Coded {
        status: 409,
        code,
        message: message.into(),
        extra: Default::default(),
    }
}
fn conflict() -> Error {
    coded(
        "flow_conflict",
        "project flow requires a current exact review",
    )
}
fn invalid() -> Error {
    Error::Invalid("invalid project review request".into())
}

fn proposal(request: &Prepare) -> Result<Proposal, Error> {
    let root = &request.project_root;
    if !root.starts_with('/')
        || root.len() > 4096
        || root.chars().any(char::is_control)
        || (root != "/" && root.ends_with('/'))
        || root.contains("//")
        || root.split('/').any(|s| s == "." || s == "..")
        || std::path::Path::new(root)
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        || request.native_session_id.is_empty()
        || request.native_session_id.len() > 256
        || request
            .native_session_id
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
        || request.integration != "claude-code"
    {
        return Err(invalid());
    }
    let agent = match &request.agent {
        AgentChoice::New { name, owner } => {
            let (name, owner) = (name.trim(), owner.trim());
            if name.is_empty()
                || owner.is_empty()
                || name.len() > 128
                || owner.len() > 128
                || name == crate::policy::ALL_AGENTS
            {
                return Err(invalid());
            }
            AgentChoice::New {
                name: name.into(),
                owner: owner.into(),
            }
        }
        AgentChoice::Existing { id } => {
            if !crate::peer_store::valid_id(id, "agent", 16) {
                return Err(invalid());
            }
            AgentChoice::Existing { id: id.clone() }
        }
    };
    Ok(Proposal {
        project_root: root.clone(),
        native_session_id: request.native_session_id.clone(),
        integration: request.integration.clone(),
        agent,
    })
}

fn latest(connection: &Connection, p: &Proposal) -> Result<Option<String>, Error> {
    Ok(connection.query_row(
        "SELECT flow_id FROM onboarding_project_flows WHERE project_root=?1 AND native_session_id=?2 AND integration=?3 ORDER BY rowid DESC LIMIT 1",
        params![p.project_root, p.native_session_id, p.integration], |r| r.get(0),
    ).optional()?)
}
fn load(connection: &Connection, id: &str) -> Result<Flow, Error> {
    let (request, review, review_id, state, expires_at, session_id): (String, String, String, String, String, Option<String>) = connection.query_row(
        "SELECT request,review,review_id,state,expires_at,session_id FROM onboarding_project_flows WHERE flow_id=?1",
        [id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)),
    )?;
    Ok(Flow {
        id: id.into(),
        proposal: serde_json::from_str(&request)?,
        review: serde_json::from_str(&review)?,
        review_id,
        state,
        expires_at,
        session_id,
    })
}
fn agent_terms(connection: &Connection, id: &str) -> Result<Value, Error> {
    let (name, owner, capabilities): (String, String, String) = connection.query_row(
        "SELECT name,owner,capabilities FROM agents WHERE id=?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let capabilities: Vec<String> = serde_json::from_str(&capabilities)?;
    Ok(json!({"id":id,"name":name,"owner":owner,"capabilities":capabilities}))
}
fn name_exists(connection: &Connection, name: &str) -> Result<bool, Error> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM agents WHERE name=?1)",
        [name],
        |r| r.get(0),
    )?)
}
fn terms_current(connection: &Connection, f: &Flow) -> Result<bool, Error> {
    if f.state == "review"
        && let AgentChoice::New { name, .. } = &f.proposal.agent
    {
        return Ok(!name_exists(connection, name)?);
    }
    let Some(id) = f.review["agent"]["id"].as_str() else {
        return Err(invalid());
    };
    match agent_terms(connection, id) {
        Ok(terms) => Ok(terms == f.review["agent"]),
        Err(Error::NotFound) => Ok(false),
        Err(e) => Err(e),
    }
}
fn current_state(
    connection: &Connection,
    f: &Flow,
    now: DateTime<Utc>,
) -> Result<&'static str, Error> {
    match f.state.as_str() {
        "declined" => Ok("declined"),
        "review" => {
            let expiry = DateTime::parse_from_rfc3339(&f.expires_at)
                .map_err(|e| Error::Internal(e.into()))?;
            if now >= expiry {
                return Ok("expired");
            }
            Ok(if terms_current(connection, f)? {
                "review"
            } else {
                "invalidated"
            })
        }
        "attached" => {
            let attached: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM sessions WHERE id=?1 AND agent_id=?2 AND integration=?3 AND state='attached')",
                params![f.session_id, f.review["agent"]["id"].as_str(), f.proposal.integration], |r| r.get(0),
            )?;
            Ok(if attached && terms_current(connection, f)? {
                "attached"
            } else {
                "invalidated"
            })
        }
        _ => Err(Error::Internal(anyhow::anyhow!(
            "invalid project flow state"
        ))),
    }
}
fn view(connection: &Connection, f: &Flow, now: DateTime<Utc>) -> Result<Value, Error> {
    let state = current_state(connection, f, now)?;
    Ok(
        json!({"version":1,"flow_id":f.id,"state":state,"review_id":f.review_id,"review":f.review,
        "attachment":f.session_id.as_ref().map(|id|json!({"agent_id":f.review["agent"]["id"],"session_id":id})),
        "next_action":match state { "review"=>"review", "attached"=>"continue_adapter_setup", _=>"restart_review" }}),
    )
}

impl Store {
    pub fn prepare_project(&self, request: Prepare) -> Result<(bool, Value), Error> {
        let p = proposal(&request)?;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let now = crate::clock::now();
        let previous = latest(&tx, &p)?;
        match (&previous, &request.replace_flow_id) {
            (Some(id), None) => {
                let f = load(&tx, id)?;
                if f.proposal != p {
                    return Err(conflict());
                }
                return Ok((false, view(&tx, &f, now)?));
            }
            (Some(id), Some(replace)) if id == replace => {
                let f = load(&tx, id)?;
                if !matches!(
                    current_state(&tx, &f, now)?,
                    "declined" | "expired" | "invalidated"
                ) {
                    return Err(conflict());
                }
            }
            (None, None) => {}
            _ => return Err(conflict()),
        }
        let is_new = matches!(p.agent, AgentChoice::New { .. });
        let agent = match &p.agent {
            AgentChoice::New { name, owner } => {
                if name_exists(&tx, name)? {
                    return Err(conflict());
                }
                json!({"id":new_id("agent")?,"name":name,"owner":owner,"capabilities":[]})
            }
            AgentChoice::Existing { id } => agent_terms(&tx, id)?,
        };
        let id = new_id("flow")?;
        let expiry = (now + TimeDelta::minutes(15)).to_rfc3339_opts(SecondsFormat::Secs, true);
        let review = json!({"version":1,"kind":"attach_project","flow_id":id,"host_id":self.identity().id,
            "project_root":p.project_root,"native_session_id":p.native_session_id,"integration":p.integration,
            "create_agent":is_new,"agent":agent,"session_id":new_id("session")?,"expires_at":expiry,
            "effects":{"register_agent":is_new,"attach_session":true,"issue_adapter_credential":false,
                "grant_network_access":false,"share_files":false,"share_conversation":false,"capability_calls":false}});
        let review_text = crate::canonical::value_text(&review);
        let digest = Sha256::digest(format!("peerspan-project-review-v1\n{review_text}"));
        let review_id = format!("review_{}", hex::encode(digest));
        tx.execute(
            "INSERT INTO onboarding_project_flows (flow_id,project_root,native_session_id,integration,request,review,review_id,state,created_at,expires_at) VALUES (?1,?2,?3,?4,?5,?6,?7,'review',?8,?9)",
            params![id,p.project_root,p.native_session_id,p.integration,serde_json::to_string(&p)?,review_text,review_id,
                now.to_rfc3339_opts(SecondsFormat::Secs,true),expiry],
        )?;
        let result = view(&tx, &load(&tx, &id)?, now)?;
        tx.commit()?;
        Ok((true, result))
    }

    pub fn project_flow(&self, id: &str) -> Result<Value, Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        view(&tx, &load(&tx, id)?, crate::clock::now())
    }

    pub fn decide_project(&self, id: &str, decision: Decision) -> Result<Value, Error> {
        if decision.integration != "claude-code" {
            return Err(invalid());
        }
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let f = load(&tx, id)?;
        if latest(&tx, &f.proposal)?.as_deref() != Some(id) {
            return Err(conflict());
        }
        if decision.review_id != f.review_id
            || decision.project_root != f.proposal.project_root
            || decision.native_session_id != f.proposal.native_session_id
            || decision.integration != f.proposal.integration
        {
            return Err(coded(
                "review_changed",
                "project review or conversation changed",
            ));
        }
        let now = crate::clock::now();
        let state = current_state(&tx, &f, now)?;
        let approve = decision.decision == DecisionKind::Approve;
        if (state == "attached" && approve) || (state == "declined" && !approve) {
            return view(&tx, &f, now);
        }
        if state == "expired" {
            return Err(coded("review_expired", "project review expired"));
        }
        if state != "review" {
            return Err(conflict());
        }
        let at = now.to_rfc3339_opts(SecondsFormat::Secs, true);
        let session_id = if approve {
            let a = &f.review["agent"];
            if f.review["create_agent"] == true {
                tx.execute(
                    "INSERT INTO agents VALUES (?1,?2,?3,'[]',?4)",
                    params![
                        a["id"].as_str(),
                        a["name"].as_str(),
                        a["owner"].as_str(),
                        at
                    ],
                )?;
                append_event(
                    &tx,
                    "agent.registered",
                    a["id"].as_str().ok_or_else(invalid)?,
                    &at,
                )?;
            }
            let session = Self::attach_session_in(
                &tx,
                AttachSession {
                    agent_id: a["id"].as_str().ok_or_else(invalid)?.into(),
                    integration: f.proposal.integration.clone(),
                },
                Some(f.review["session_id"].as_str().ok_or_else(invalid)?.into()),
            )?;
            Some(session.id)
        } else {
            None
        };
        tx.execute("UPDATE onboarding_project_flows SET state=?1,session_id=?2,decided_at=?3 WHERE flow_id=?4",
            params![if approve {"attached"} else {"declined"},session_id,at,id])?;
        let result = view(&tx, &load(&tx, id)?, now)?;
        tx.commit()?;
        if approve && f.review["create_agent"] == true {
            self.presence_changed();
        }
        Ok(result)
    }
}

pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/onboarding/project-flows", post(prepare))
        .route("/v1/onboarding/project-flows/{id}", get(inspect))
        .route("/v1/onboarding/project-flows/{id}/decision", post(decide))
}
async fn prepare(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<Value>), Error> {
    let request: Prepare = decode(body)?;
    let (created, value) = blocking(store, move |s| s.prepare_project(request)).await?;
    Ok((
        if created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        Json(value),
    ))
}
async fn inspect(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, Error> {
    Ok(Json(blocking(store, move |s| s.project_flow(&id)).await?))
}
async fn decide(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let decision: Decision = decode(body)?;
    Ok(Json(
        blocking(store, move |s| s.decide_project(&id, decision)).await?,
    ))
}
