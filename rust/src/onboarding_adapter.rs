//! Exact owner-local authorization of a guided project's existing session.
use crate::{
    adapter::{Adapter, CreateAdapter, CredentialMaterial},
    api::{blocking, decode},
    model::Error,
    onboarding::{DecisionKind, ProjectContext, project_attachment, validate_context},
    store::{Store, new_id},
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
use std::sync::Arc;

pub(crate) const SCHEMA: &str = "
CREATE TABLE onboarding_adapter_flows (
 flow_id TEXT PRIMARY KEY NOT NULL,
 project_flow_id TEXT NOT NULL REFERENCES onboarding_project_flows(flow_id),
 request TEXT NOT NULL,
 review TEXT NOT NULL,
 review_id TEXT NOT NULL,
 state TEXT NOT NULL CHECK (state IN ('review','authorized','declined')),
 created_at TEXT NOT NULL,
 expires_at TEXT NOT NULL,
 adapter_id TEXT REFERENCES adapter_credentials(id),
 decided_at TEXT
);
PRAGMA user_version = 25;
";

pub(crate) fn check_namespace(connection: &Connection) -> anyhow::Result<()> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='onboarding_adapter_flows')",
        [],
        |r| r.get(0),
    )?;
    anyhow::ensure!(
        !exists,
        "reserved adapter-flow object exists before schema25"
    );
    Ok(())
}

pub(crate) fn check_schema(connection: &Connection) -> anyhow::Result<()> {
    let sql: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name='onboarding_adapter_flows'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    let expected = SCHEMA.split(';').next().unwrap_or_default();
    let normalized = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
    anyhow::ensure!(
        sql.as_deref()
            .is_some_and(|s| normalized(s) == normalized(expected)),
        "corrupt schema25 adapter-flow table"
    );
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdapterContext {
    pub project_flow_id: String,
    pub project_review_id: String,
    pub project_root: String,
    pub native_session_id: String,
    pub integration: String,
}
impl AdapterContext {
    fn validate(&self) -> Result<(), Error> {
        if !crate::peer_store::valid_id(&self.project_flow_id, "flow", 16)
            || !crate::peer_store::valid_id(&self.project_review_id, "review", 32)
        {
            return Err(Error::Invalid("invalid adapter review context".into()));
        }
        validate_context(
            &self.project_root,
            &self.native_session_id,
            &self.integration,
        )
    }
    fn project(&self, connection: &Connection, now: DateTime<Utc>) -> Result<(Value, bool), Error> {
        project_attachment(
            connection,
            &self.project_flow_id,
            &self.project_review_id,
            &ProjectContext {
                project_root: self.project_root.clone(),
                native_session_id: self.native_session_id.clone(),
                integration: self.integration.clone(),
            },
            now,
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prepare {
    pub context: AdapterContext,
    #[serde(default, deserialize_with = "non_null_string")]
    pub replace_flow_id: Option<String>,
}
fn non_null_string<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRequest {
    pub context: AdapterContext,
    pub review_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub context: AdapterContext,
    pub review_id: String,
    pub decision: DecisionKind,
}
struct Flow {
    id: String,
    context: AdapterContext,
    review: Value,
    review_id: String,
    state: String,
    expires_at: String,
    adapter_id: Option<String>,
}
fn coded(code: &'static str, message: &'static str) -> Error {
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
        "adapter flow requires a current exact review",
    )
}
fn changed() -> Error {
    coded("review_changed", "adapter review or conversation changed")
}
fn field<'a>(value: &'a Value, name: &str) -> Result<&'a str, Error> {
    value[name]
        .as_str()
        .ok_or_else(|| Error::Internal(anyhow::anyhow!("invalid adapter review")))
}
fn expiry(value: &str) -> Result<DateTime<Utc>, Error> {
    Ok(DateTime::parse_from_rfc3339(value)
        .map_err(|e| Error::Internal(e.into()))?
        .with_timezone(&Utc))
}
fn stamp(now: DateTime<Utc>) -> String {
    now.to_rfc3339_opts(SecondsFormat::Secs, true)
}
fn latest(connection: &Connection, project: &str) -> Result<Option<String>, Error> {
    Ok(connection.query_row(
        "SELECT flow_id FROM onboarding_adapter_flows WHERE project_flow_id=?1 ORDER BY rowid DESC LIMIT 1",
        [project], |r| r.get(0),
    ).optional()?)
}
fn load(connection: &Connection, id: &str) -> Result<Flow, Error> {
    if !crate::peer_store::valid_id(id, "flow", 16) {
        return Err(Error::Invalid("invalid adapter flow reference".into()));
    }
    let (context, review, review_id, state, expires_at, adapter_id): (String,String,String,String,String,Option<String>) = connection.query_row(
        "SELECT request,review,review_id,state,expires_at,adapter_id FROM onboarding_adapter_flows WHERE flow_id=?1",
        [id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)),
    )?;
    Ok(Flow {
        id: id.into(),
        context: serde_json::from_str(&context)?,
        review: serde_json::from_str(&review)?,
        review_id,
        state,
        expires_at,
        adapter_id,
    })
}
fn other_active(connection: &Connection, agent: &str, now: DateTime<Utc>) -> Result<bool, Error> {
    let mut statement = connection.prepare(
        "SELECT c.record FROM adapter_credentials c JOIN sessions s ON c.session_id=s.id JOIN adapter_connections x ON x.adapter_id=c.id WHERE s.agent_id=?1 AND (s.state='attached' OR x.recoverable=1)",
    )?;
    for row in statement.query_map([agent], |r| r.get::<_, String>(0))? {
        let adapter: Adapter = serde_json::from_str(&row?)?;
        if adapter.revoked_at.is_none() && expiry(&adapter.expires_at)? > now {
            return Ok(true);
        }
    }
    Ok(false)
}
fn authorization(connection: &Connection, id: &str) -> Result<Adapter, Error> {
    crate::adapter::read(
        connection,
        "SELECT record FROM adapter_credentials WHERE id=?1",
        [id],
    )
}
fn check_request(f: &Flow, context: &AdapterContext, review_id: &str) -> Result<(), Error> {
    context.validate()?;
    if !crate::peer_store::valid_id(review_id, "review", 32) {
        return Err(Error::Invalid("invalid adapter review reference".into()));
    }
    if f.context != *context || f.review_id != review_id {
        return Err(changed());
    }
    Ok(())
}

impl Store {
    fn guided_adapter_token(&self, f: &Flow) -> String {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &self.signing_key.to_bytes());
        let input = format!(
            "peerspan-guided-adapter-token-v1\n{}\n{}",
            f.id, f.review_id
        );
        format!(
            "token_{}",
            hex::encode(ring::hmac::sign(&key, input.as_bytes()).as_ref())
        )
    }
    fn adapter_flow_state(
        &self,
        connection: &Connection,
        f: &Flow,
        now: DateTime<Utc>,
    ) -> Result<&'static str, Error> {
        if f.state == "declined" {
            return Ok("declined");
        }
        if f.state == "review" && now >= expiry(&f.expires_at)? {
            return Ok("expired");
        }
        if f.state == "authorized" && now >= expiry(field(&f.review, "credential_expires_at")?)? {
            return Ok("expired");
        }
        let (_, current) = f.context.project(connection, now)?;
        if !current {
            return Ok("invalidated");
        }
        if f.state == "review" {
            return Ok(
                if other_active(connection, field(&f.review["agent"], "id")?, now)? {
                    "invalidated"
                } else {
                    "review"
                },
            );
        }
        if f.state != "authorized" {
            return Err(Error::Internal(anyhow::anyhow!(
                "invalid adapter flow state"
            )));
        }
        let id = f.adapter_id.as_deref().ok_or_else(conflict)?;
        let adapter = authorization(connection, id)?;
        let routes: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM adapter_routes WHERE adapter_id=?1)",
            [id],
            |r| r.get(0),
        )?;
        let hash: String = connection.query_row(
            "SELECT token_hash FROM adapter_credentials WHERE id=?1",
            [id],
            |r| r.get(0),
        )?;
        Ok(
            if adapter.id == field(&f.review, "adapter_id")?
                && adapter.session_id == field(&f.review, "session_id")?
                && adapter.expires_at == field(&f.review, "credential_expires_at")?
                && adapter.revoked_at.is_none()
                && !adapter.renewable
                && !adapter.directory
                && !adapter.calls
                && adapter.max_sends_per_hour.is_none()
                && adapter.max_calls_per_hour.is_none()
                && !routes
                && hash == crate::adapter::token_hash(&self.guided_adapter_token(f))
            {
                "authorized"
            } else {
                "invalidated"
            },
        )
    }
    fn adapter_flow_view(
        &self,
        connection: &Connection,
        f: &Flow,
        now: DateTime<Utc>,
    ) -> Result<Value, Error> {
        let state = self.adapter_flow_state(connection, f, now)?;
        let (issued, connection_view) = if let Some(id) = &f.adapter_id {
            (
                json!({"adapter_id":id,"session_id":f.review["session_id"],"agent_id":f.review["agent"]["id"],
                "expires_at":f.review["credential_expires_at"],"renewable":false}),
                serde_json::to_value(self.adapter_connection_in(connection, id)?)?,
            )
        } else {
            (Value::Null, Value::Null)
        };
        Ok(
            json!({"version":1,"flow_id":f.id,"state":state,"review_id":f.review_id,"review":f.review,
            "authorization":issued,"connection":connection_view,
            "next_action":match state {"review"=>"review","authorized"=>"connect_adapter",_=>"restart_review"}}),
        )
    }
    pub fn lookup_adapter_flow(&self, context: AdapterContext) -> Result<Value, Error> {
        context.validate()?;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let now = crate::clock::now();
        context.project(&tx, now)?;
        let flow = latest(&tx, &context.project_flow_id)?
            .map(|id| self.adapter_flow_view(&tx, &load(&tx, &id)?, now))
            .transpose()?;
        Ok(json!({"version":1,"host_id":self.identity().id,"context":context,"flow":flow}))
    }
    pub fn prepare_adapter_flow(&self, request: Prepare) -> Result<(bool, Value), Error> {
        request.context.validate()?;
        if request
            .replace_flow_id
            .as_ref()
            .is_some_and(|id| !crate::peer_store::valid_id(id, "flow", 16))
        {
            return Err(Error::Invalid(
                "invalid adapter replacement reference".into(),
            ));
        }
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let now = crate::clock::now();
        let (project, current) = request.context.project(&tx, now)?;
        let previous = latest(&tx, &request.context.project_flow_id)?;
        match (&previous, &request.replace_flow_id) {
            (Some(id), None) => {
                let f = load(&tx, id)?;
                if f.context != request.context {
                    return Err(changed());
                }
                return Ok((false, self.adapter_flow_view(&tx, &f, now)?));
            }
            (Some(id), Some(replace)) if id == replace => {
                if !matches!(
                    self.adapter_flow_state(&tx, &load(&tx, id)?, now)?,
                    "declined" | "expired" | "invalidated"
                ) {
                    return Err(conflict());
                }
            }
            (None, None) => {}
            _ => return Err(conflict()),
        }
        if !current || other_active(&tx, field(&project["agent"], "id")?, now)? {
            return Err(conflict());
        }
        let id = new_id("flow")?;
        let deadline = stamp(now + TimeDelta::minutes(15));
        let c = &request.context;
        let review = json!({"version":1,"kind":"authorize_adapter","flow_id":id,"host_id":self.identity().id,
            "project_flow_id":c.project_flow_id,"project_review_id":c.project_review_id,
            "project_root":c.project_root,"native_session_id":c.native_session_id,"integration":c.integration,
            "agent":project["agent"],"session_id":project["session_id"],"adapter_id":new_id("adapter")?,
            "expires_at":deadline,"credential_expires_at":stamp(now+TimeDelta::hours(24)),"renewable":false,
            "effects":{"issue_adapter_credential":true,"receive_authorized_work":true,"reply_to_authorized_work":true,
                "handle_authorized_tasks":true,"task_artifacts":true,"register_agent":false,"attach_session":false,
                "grant_network_access":false,"directory_access":false,"outbound_routes":false,"capability_calls":false,
                "share_files":false,"share_conversation":false}});
        let text = crate::canonical::value_text(&review);
        let review_id = format!(
            "review_{}",
            hex::encode(Sha256::digest(format!(
                "peerspan-adapter-review-v1\n{text}"
            )))
        );
        tx.execute("INSERT INTO onboarding_adapter_flows (flow_id,project_flow_id,request,review,review_id,state,created_at,expires_at) VALUES (?1,?2,?3,?4,?5,'review',?6,?7)",
            params![id,c.project_flow_id,serde_json::to_string(c)?,text,review_id,stamp(now),deadline])?;
        let result = self.adapter_flow_view(&tx, &load(&tx, &id)?, now)?;
        tx.commit()?;
        Ok((true, result))
    }
    pub fn adapter_flow(&self, id: &str) -> Result<Value, Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        self.adapter_flow_view(&tx, &load(&tx, id)?, crate::clock::now())
    }
    pub fn decide_adapter_flow(&self, id: &str, decision: Decision) -> Result<Value, Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let f = load(&tx, id)?;
        check_request(&f, &decision.context, &decision.review_id)?;
        if latest(&tx, &f.context.project_flow_id)?.as_deref() != Some(id) {
            return Err(conflict());
        }
        let now = crate::clock::now();
        let state = self.adapter_flow_state(&tx, &f, now)?;
        let approve = decision.decision == DecisionKind::Approve;
        if (state == "authorized" && approve) || (state == "declined" && !approve) {
            return self.adapter_flow_view(&tx, &f, now);
        }
        if state == "expired" {
            return Err(coded("review_expired", "adapter review expired"));
        }
        if state != "review" {
            return Err(conflict());
        }
        let adapter = if approve {
            let material = CredentialMaterial {
                id: field(&f.review, "adapter_id")?.into(),
                token: self.guided_adapter_token(&f),
            };
            // The same transaction has refused every active authorization,
            // including offline/unbound instances. No replacement is reviewed.
            let credential = self.create_adapter_material_in(
                &tx,
                CreateAdapter {
                    session_id: field(&f.review, "session_id")?.into(),
                    expires_at: Some(field(&f.review, "credential_expires_at")?.into()),
                },
                None,
                None,
                Some(material),
            )?;
            Some(credential.adapter.id)
        } else {
            None
        };
        tx.execute("UPDATE onboarding_adapter_flows SET state=?1,adapter_id=?2,decided_at=?3 WHERE flow_id=?4",
            params![if approve {"authorized"} else {"declined"},adapter,stamp(now),id])?;
        let result = self.adapter_flow_view(&tx, &load(&tx, id)?, now)?;
        tx.commit()?;
        Ok(result)
    }
    pub fn adapter_flow_credential(
        &self,
        id: &str,
        request: CredentialRequest,
    ) -> Result<Value, Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let f = load(&tx, id)?;
        check_request(&f, &request.context, &request.review_id)?;
        if latest(&tx, &f.context.project_flow_id)?.as_deref() != Some(id)
            || self.adapter_flow_state(&tx, &f, crate::clock::now())? != "authorized"
        {
            return Err(conflict());
        }
        Ok(
            json!({"version":1,"adapter_id":f.adapter_id,"session_id":f.review["session_id"],"token":self.guided_adapter_token(&f)}),
        )
    }
}

pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/onboarding/adapter-flows", post(prepare))
        .route("/v1/onboarding/adapter-flows/lookup", post(lookup))
        .route("/v1/onboarding/adapter-flows/{id}", get(inspect))
        .route("/v1/onboarding/adapter-flows/{id}/decision", post(decide))
        .route(
            "/v1/onboarding/adapter-flows/{id}/credential",
            post(credential),
        )
}
async fn prepare(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<Value>), Error> {
    let request = decode(body)?;
    let (created, value) = blocking(store, move |s| s.prepare_adapter_flow(request)).await?;
    Ok((
        if created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        Json(value),
    ))
}
async fn lookup(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let request = decode(body)?;
    Ok(Json(
        blocking(store, move |s| s.lookup_adapter_flow(request)).await?,
    ))
}
async fn inspect(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, Error> {
    Ok(Json(blocking(store, move |s| s.adapter_flow(&id)).await?))
}
async fn decide(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let request = decode(body)?;
    Ok(Json(
        blocking(store, move |s| s.decide_adapter_flow(&id, request)).await?,
    ))
}
async fn credential(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let request = decode(body)?;
    Ok(Json(
        blocking(store, move |s| s.adapter_flow_credential(&id, request)).await?,
    ))
}
