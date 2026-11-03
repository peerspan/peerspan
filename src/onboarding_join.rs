//! Exact public-key consent to publish an ordinary join request.
use crate::{
    api::blocking,
    decentralized::{codec, product, requests},
    model::Error,
    onboarding::DecisionKind,
    onboarding_adapter::AdapterContext,
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
use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;

mod owner;
pub use owner::{
    OwnerApproval, OwnerContext, decode_commit_input, decode_machine_commit_input,
    decode_owner_input,
};

pub(crate) const SCHEMA: &str = "
CREATE TABLE onboarding_join_flows (
 flow_id TEXT PRIMARY KEY NOT NULL,
 project_flow_id TEXT NOT NULL REFERENCES onboarding_project_flows(flow_id),
 request TEXT NOT NULL,
 review TEXT NOT NULL,
 review_id TEXT NOT NULL,
 state TEXT NOT NULL CHECK (state IN ('review','requested','declined')),
 created_at TEXT NOT NULL,
 expires_at TEXT NOT NULL,
 outcome TEXT,
 decided_at TEXT
);
PRAGMA user_version = 27;
";
pub(crate) fn check_namespace(c: &Connection) -> anyhow::Result<()> {
    let exists: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='onboarding_join_flows')",
        [],
        |r| r.get(0),
    )?;
    anyhow::ensure!(!exists, "reserved join-flow object exists before schema27");
    Ok(())
}
pub(crate) fn check_schema(c: &Connection) -> anyhow::Result<()> {
    let sql: Option<String> = c
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name='onboarding_join_flows'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    let normalized = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
    anyhow::ensure!(
        sql.as_deref().is_some_and(
            |s| normalized(s) == normalized(SCHEMA.split(';').next().unwrap_or_default())
        ),
        "corrupt schema27 join-flow table"
    );
    Ok(())
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Proposal {
    context: AdapterContext,
    person_public_key: String,
    invitation_digest: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prepare {
    pub context: AdapterContext,
    pub invitation: String,
    pub person_public_key: String,
    #[serde(default, deserialize_with = "non_null_string")]
    pub replace_flow_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lookup {
    pub context: AdapterContext,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Progress {
    pub context: AdapterContext,
    pub review_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub context: AdapterContext,
    pub review_id: String,
    pub decision: DecisionKind,
    #[serde(default, deserialize_with = "non_null_string")]
    pub invitation: Option<String>,
}
fn non_null_string<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}
struct Flow {
    id: String,
    proposal: Proposal,
    review: Value,
    review_id: String,
    state: String,
    expires: String,
    outcome: Option<Value>,
}
fn invalid() -> Error {
    Error::Invalid("invalid join review request".into())
}
fn corrupt() -> Error {
    Error::Internal(anyhow::anyhow!("invalid retained join review"))
}
fn coded(code: &'static str) -> Error {
    Error::Coded {
        status: 409,
        code,
        message: code.replace('_', " "),
        extra: Default::default(),
    }
}
fn time(s: &str) -> Result<DateTime<Utc>, Error> {
    DateTime::parse_from_rfc3339(s)
        .map(|v| v.with_timezone(&Utc))
        .map_err(|_| corrupt())
}
fn stamp(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}
fn now() -> Result<DateTime<Utc>, Error> {
    time(&crate::decentralized::local_decision_time().map_err(product::model)?)
}
fn field<'a>(v: &'a Value, k: &str) -> Result<&'a str, Error> {
    v[k].as_str().ok_or_else(corrupt)
}
fn digest(review: &Value) -> String {
    format!(
        "review_{}",
        codec::hash(
            format!(
                "peerspan-join-review-v1\n{}",
                crate::canonical::value_text(review)
            )
            .as_bytes()
        )
    )
}
fn token_digest(token: &str) -> Result<String, Error> {
    if token.len() > 32 << 10
        || !token.strip_prefix("psi2-").is_some_and(|v| {
            !v.is_empty()
                && v.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        })
    {
        return Err(invalid());
    }
    Ok(hex::encode(Sha256::digest(token.as_bytes())))
}
fn validate(p: &Proposal) -> Result<(), Error> {
    p.context.validate()?;
    if !codec::key(&p.person_public_key) || !codec::digest(&p.invitation_digest) {
        return Err(invalid());
    }
    Ok(())
}
fn latest(c: &Connection, parent: &str) -> Result<Option<String>, Error> {
    Ok(c.query_row(
        "SELECT flow_id FROM onboarding_join_flows WHERE project_flow_id=?1 ORDER BY rowid DESC LIMIT 1",
        [parent], |r| r.get(0),
    ).optional()?)
}
fn load(c: &Connection, id: &str) -> Result<Flow, Error> {
    if !crate::peer_store::valid_id(id, "flow", 16) {
        return Err(invalid());
    }
    let row = c.query_row(
        "SELECT request,review,review_id,state,expires_at,outcome FROM onboarding_join_flows WHERE flow_id=?1",
        [id], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,
            r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,Option<String>>(5)?)),
    ).optional()?.ok_or(Error::NotFound)?;
    let f = Flow {
        id: id.into(),
        proposal: serde_json::from_str(&row.0).map_err(|_| corrupt())?,
        review: serde_json::from_str(&row.1).map_err(|_| corrupt())?,
        review_id: row.2,
        state: row.3,
        expires: row.4,
        outcome: row
            .5
            .map(|v| serde_json::from_str(&v).map_err(|_| corrupt()))
            .transpose()?,
    };
    validate(&f.proposal).map_err(|_| corrupt())?;
    if digest(&f.review) != f.review_id
        || f.review["flow_id"] != id
        || f.review["context"] != serde_json::to_value(&f.proposal.context)?
        || f.review["person_public_key"] != f.proposal.person_public_key
        || f.review["expires_at"] != f.expires
        || !["review", "declined", "requested"].contains(&f.state.as_str())
        || (f.state == "requested") != f.outcome.is_some()
    {
        return Err(corrupt());
    }
    Ok(f)
}
fn current(c: &Connection, f: &Flow, now: DateTime<Utc>) -> Result<&'static str, Error> {
    if f.state == "requested" {
        return Ok("requested");
    }
    if f.state == "declined" {
        return Ok("declined");
    }
    if latest(c, &f.proposal.context.project_flow_id)?.as_deref() != Some(&f.id) {
        return Ok("replaced");
    }
    if now >= time(&f.expires)? {
        return Ok("expired");
    }
    let (project, attached) = f.proposal.context.project(c, now)?;
    if !attached || project["agent"] != f.review["agent"] {
        return Ok("invalidated");
    }
    Ok("review")
}
fn view(store: &Store, c: &Connection, f: &Flow, now: DateTime<Utc>) -> Result<Value, Error> {
    let state = current(c, f, now)?;
    Ok(
        json!({"version":1,"host_id":store.identity().id,"flow_id":f.id,"review_id":f.review_id,
        "state":state,"review":f.review,"outcome":f.outcome,"next_action":match state {
            "review"=>"approve_join_request", "requested"=>"await_participant_reviews",
            "declined"=>"none", _=>"review_replacement" }}),
    )
}
impl Store {
    pub fn prepare_join_flow(&self, request: Prepare) -> Result<(bool, Value), Error> {
        let proposal = Proposal {
            context: request.context,
            person_public_key: request.person_public_key,
            invitation_digest: token_digest(&request.invitation)?,
        };
        validate(&proposal)?;
        if request
            .replace_flow_id
            .as_ref()
            .is_some_and(|id| !crate::peer_store::valid_id(id, "flow", 16))
        {
            return Err(invalid());
        }
        let mut c = self.connection()?;
        let tx = c.transaction()?;
        let now = now()?;
        // Reject a substituted review/conversation before comparing proposals.
        // A detached historical parent may still inspect its recorded outcome.
        proposal.context.project(&tx, now)?;
        match (
            latest(&tx, &proposal.context.project_flow_id)?,
            &request.replace_flow_id,
        ) {
            (Some(id), None) => {
                let f = load(&tx, &id)?;
                if f.proposal != proposal {
                    return Err(coded("flow_conflict"));
                }
                return Ok((false, view(self, &tx, &f, now)?));
            }
            (Some(id), Some(previous)) if &id == previous => {
                if current(&tx, &load(&tx, &id)?, now)? == "review" {
                    return Err(coded("flow_conflict"));
                }
            }
            (None, None) => {}
            _ => return Err(coded("flow_conflict")),
        }
        let preview =
            self.invitation_preview_in(&tx, &proposal.context, &request.invitation, now)?;
        let public = &preview["review"];
        let pin = field(&public["invitation"], "expected_person_public_key")?;
        if pin != "-" && pin != proposal.person_public_key {
            return Err(invalid());
        }
        let expires =
            (now + TimeDelta::minutes(15)).min(time(field(&public["invitation"], "expires_at")?)?);
        let id = new_id("flow")?;
        let review = json!({"version":1,"kind":"create_join_request","flow_id":id,
            "host_id":self.identity().id,"context":proposal.context,"agent":public["agent"],
            "invitation_review_id":preview["review_id"],"invitation":public,
            "person_public_key":proposal.person_public_key,"expires_at":stamp(expires),
            "effects":{"create_identity":false,"create_link_request":true,"publish_request":true,
                "select_owner":false,"grant_membership":false,"grant_agent_access":false,"approve_machine":false,
                "share_files":false,"share_conversation":false,"capability_calls":false}});
        let review_id = digest(&review);
        tx.execute("INSERT INTO onboarding_join_flows(flow_id,project_flow_id,request,review,review_id,state,created_at,expires_at) VALUES(?1,?2,?3,?4,?5,'review',?6,?7)",
            params![id,proposal.context.project_flow_id,serde_json::to_string(&proposal)?,
                crate::canonical::value_text(&review),review_id,stamp(now),stamp(expires)])?;
        let result = view(self, &tx, &load(&tx, &id)?, now)?;
        tx.commit()?;
        Ok((true, result))
    }
    pub fn lookup_join_flow(&self, context: AdapterContext) -> Result<Value, Error> {
        context.validate()?;
        let mut c = self.connection()?;
        let tx = c.transaction()?;
        let now = now()?;
        context.project(&tx, now)?;
        let flow = latest(&tx, &context.project_flow_id)?
            .map(|id| {
                let f = load(&tx, &id)?;
                if f.proposal.context != context {
                    return Err(coded("review_changed"));
                }
                view(self, &tx, &f, now)
            })
            .transpose()?;
        Ok(json!({"version":1,"host_id":self.identity().id,"context":context,"flow":flow}))
    }
    pub fn join_flow(&self, id: &str) -> Result<Value, Error> {
        let mut c = self.connection()?;
        let tx = c.transaction()?;
        view(self, &tx, &load(&tx, id)?, now()?)
    }
    pub fn join_progress(&self, id: &str, request: Progress) -> Result<Value, Error> {
        request.context.validate()?;
        if !crate::peer_store::valid_id(&request.review_id, "review", 32) {
            return Err(invalid());
        }
        let mut c = self.connection()?;
        let tx = c.transaction()?;
        let now = now()?;
        let f = load(&tx, id)?;
        if request.context != f.proposal.context || request.review_id != f.review_id {
            return Err(coded("review_changed"));
        }
        request.context.project(&tx, now)?;
        if f.state != "requested" {
            return Err(coded("state_conflict"));
        }
        let outcome = f.outcome.as_ref().ok_or_else(corrupt)?;
        let fields = [
            "request_id",
            "network_id",
            "context_id",
            "person_public_key",
        ];
        if !outcome
            .as_object()
            .is_some_and(|o| o.len() == fields.len() && fields.iter().all(|k| o.contains_key(*k)))
        {
            return Err(corrupt());
        }
        let request_id = field(outcome, "request_id")?;
        if !crate::peer_store::valid_id(request_id, "link", 32)
            || outcome["network_id"] != f.review["invitation"]["network"]["id"]
            || outcome["context_id"] != f.review["invitation"]["network"]["context_id"]
            || outcome["person_public_key"] != f.proposal.person_public_key
        {
            return Err(coded("request_mismatch"));
        }
        let pending = requests::load(&tx, request_id).map_err(|e| {
            if e.code == "not_found" {
                coded("request_unavailable")
            } else {
                product::model(e)
            }
        })?;
        let observed_at = stamp(now);
        let ordinary = pending.view(&observed_at).map_err(product::model)?;
        if ordinary["request_id"] != request_id
            || ordinary["role"] != "requester"
            || ordinary["mode"] != "new"
            || ordinary["migration_proposal_id"] != "-"
            || ordinary["host_public_key"] != self.identity().public_key
            || ["network_id", "context_id", "person_public_key"]
                .iter()
                .any(|k| ordinary[*k] != outcome[*k])
        {
            return Err(coded("request_mismatch"));
        }
        let (next_participant, next_action) = match ordinary["state"].as_str() {
            Some("pending") => ("person_owner", "review_owner_offer"),
            Some("needs_selection") => ("requesting_machine", "review_owner_selection"),
            Some("needs_administrator") => ("network_administrator", "review_admission"),
            Some("needs_owner_finalization") => ("person_owner", "review_owner_finalization"),
            Some("needs_commit") => ("requesting_machine", "review_final_commit"),
            Some("finalizing") => ("host", "await_local_application"),
            Some("linked") => ("requesting_machine", "inspect_access_readiness"),
            Some("cancelled" | "expired") => ("requesting_machine", "review_replacement"),
            Some("blocked") => ("local_owner", "inspect_advanced_status"),
            _ => return Err(coded("request_mismatch")),
        };
        Ok(
            json!({"version":1,"host_id":self.identity().id,"flow_id":id,"review_id":f.review_id,
            "context":request.context,"observed_at":observed_at,"outcome":outcome,"request":ordinary,
            "next_participant":next_participant,"next_action":next_action}),
        )
    }
    fn decide_join_flow(
        &self,
        id: &str,
        request: Decision,
    ) -> Result<(Value, Option<String>), Error> {
        request.context.validate()?;
        let approve = request.decision == DecisionKind::Approve;
        let code_digest = match (&request.invitation, approve) {
            (Some(code), true) => Some(token_digest(code)?),
            (None, false) => None,
            _ => return Err(invalid()),
        };
        let mut c = self.connection()?;
        let tx = c.transaction()?;
        let f = load(&tx, id)?;
        if request.context != f.proposal.context
            || request.review_id != f.review_id
            || code_digest
                .as_ref()
                .is_some_and(|v| v != &f.proposal.invitation_digest)
        {
            return Err(coded("review_changed"));
        }
        let now = now()?;
        if f.state != "review" {
            if (f.state == "requested" && approve) || (f.state == "declined" && !approve) {
                return Ok((view(self, &tx, &f, now)?, None));
            }
            return Err(coded("flow_conflict"));
        }
        match current(&tx, &f, now)? {
            "review" => {}
            "replaced" => return Err(coded("flow_conflict")),
            "expired" => return Err(coded("review_expired")),
            _ => return Err(coded("review_changed")),
        }
        let mut fresh_request = false;
        let outcome = if approve {
            let code = request.invitation.as_deref().ok_or_else(invalid)?;
            let preview = self.invitation_preview_in(&tx, &f.proposal.context, code, now)?;
            if preview["review_id"] != f.review["invitation_review_id"]
                || preview["review"] != f.review["invitation"]
            {
                return Err(coded("review_changed"));
            }
            let public = &preview["review"];
            let input = json!({"mode":"new","network_id":public["network"]["id"],
                "person_public_key":f.proposal.person_public_key,"migration_proposal_id":"-",
                "contact_invitation":code,"helpers":public["helpers"]});
            let (status, bytes) =
                requests::create_in(self, &tx, input.as_object().ok_or_else(corrupt)?)
                    .map_err(product::model)?;
            fresh_request = status == 201;
            let v: Value = serde_json::from_slice(&bytes)?;
            if v["network_id"] != public["network"]["id"]
                || v["context_id"] != public["network"]["context_id"]
                || v["person_public_key"] != f.proposal.person_public_key
                || v["role"] != "requester"
            {
                return Err(corrupt());
            }
            // The protocol also captures guarded time. A boundary crossed while
            // signing must abort the whole transaction, including its device key.
            if now_time_expired(&f.expires)? {
                return Err(coded("review_expired"));
            }
            Some(
                json!({"request_id":v["request_id"],"network_id":v["network_id"],
                "context_id":v["context_id"],"person_public_key":v["person_public_key"]}),
            )
        } else {
            None
        };
        tx.execute(
            "UPDATE onboarding_join_flows SET state=?1,outcome=?2,decided_at=?3 WHERE flow_id=?4",
            params![
                if approve { "requested" } else { "declined" },
                outcome.as_ref().map(crate::canonical::value_text),
                stamp(now),
                id
            ],
        )?;
        let result = view(self, &tx, &load(&tx, id)?, now)?;
        tx.commit()?;
        drop(c);
        let created = if fresh_request {
            let request_id = field(outcome.as_ref().ok_or_else(corrupt)?, "request_id")?;
            requests::after_create_commit(self, request_id).map_err(product::model)?;
            Some(request_id.to_owned())
        } else {
            None
        };
        Ok((result, created))
    }
}
fn now_time_expired(expires: &str) -> Result<bool, Error> {
    Ok(now()? >= time(expires)?)
}

/// Decode strict JSON before serde can discard duplicate keys or null values.
pub fn decode_input<T: DeserializeOwned>(
    bytes: &[u8],
    operation: &str,
    cli: bool,
) -> Result<T, Error> {
    if bytes.len() > 65536 {
        return Err(invalid());
    }
    let shape: Value = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    let fields = match operation {
        "prepare" if shape.get("replace_flow_id").is_some() => {
            "context invitation person_public_key replace_flow_id"
        }
        "prepare" => "context invitation person_public_key",
        "lookup" => "context",
        "progress" => "context review_id",
        "decision" if shape.get("invitation").is_some() => "context review_id decision invitation",
        "decision" => "context review_id decision",
        _ => return Err(invalid()),
    };
    let fields = if cli && matches!(operation, "decision" | "progress") {
        format!("flow_id {fields}")
    } else {
        fields.into()
    };
    crate::linking::decode_mutation(bytes, &fields).map_err(|_| invalid())
}
pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/onboarding/join-flows", post(prepare))
        .route("/v1/onboarding/join-flows/lookup", post(lookup))
        .route("/v1/onboarding/join-flows/{id}", get(inspect))
        .route("/v1/onboarding/join-flows/{id}/decision", post(decide))
        .route("/v1/onboarding/join-flows/{id}/progress", post(progress))
        .merge(owner::routes())
}
async fn prepare(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<Value>), Error> {
    let request = decode_input(&body.map_err(|_| invalid())?, "prepare", false)?;
    let (fresh, v) = blocking(store, move |s| s.prepare_join_flow(request)).await?;
    Ok((
        if fresh {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        Json(v),
    ))
}
async fn lookup(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let request: Lookup = decode_input(&body.map_err(|_| invalid())?, "lookup", false)?;
    Ok(Json(
        blocking(store, move |s| s.lookup_join_flow(request.context)).await?,
    ))
}
async fn inspect(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, Error> {
    Ok(Json(blocking(store, move |s| s.join_flow(&id)).await?))
}
async fn decide(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let request = decode_input(&body.map_err(|_| invalid())?, "decision", false)?;
    let (result, created) =
        blocking(store.clone(), move |s| s.decide_join_flow(&id, request)).await?;
    if let Some(request_id) = created {
        // This response records consent, not delivery. Only fresh committed
        // creation starts transport; historical recovery remains pure.
        tokio::spawn(async move {
            let bound = std::time::Duration::from_secs(30);
            let _ = tokio::join!(
                tokio::time::timeout(
                    bound,
                    crate::decentralized::publish_request(store.clone(), &request_id),
                ),
                tokio::time::timeout(
                    bound,
                    crate::decentralized::return_request(store, &request_id),
                ),
            );
        });
    }
    Ok(Json(result))
}
async fn progress(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let request = decode_input(&body.map_err(|_| invalid())?, "progress", false)?;
    Ok(Json(
        blocking(store, move |s| s.join_progress(&id, request)).await?,
    ))
}
