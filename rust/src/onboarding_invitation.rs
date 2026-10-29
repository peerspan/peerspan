//! Exact owner-local contact invitations. An introduction grants no authority.
use crate::{
    api::{blocking, decode},
    decentralized::{codec, product, runtime},
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
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub(crate) const SCHEMA: &str = "
CREATE TABLE onboarding_invitation_flows (
 flow_id TEXT PRIMARY KEY NOT NULL,
 project_flow_id TEXT NOT NULL REFERENCES onboarding_project_flows(flow_id),
 request TEXT NOT NULL,
 review TEXT NOT NULL,
 review_id TEXT NOT NULL,
 state TEXT NOT NULL CHECK (state IN ('review','issued','declined')),
 created_at TEXT NOT NULL,
 expires_at TEXT NOT NULL,
 invitation_id TEXT,
 decided_at TEXT
);
PRAGMA user_version = 26;
";
pub(crate) fn check_namespace(c: &Connection) -> anyhow::Result<()> {
    let exists: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='onboarding_invitation_flows')",
        [],
        |r| r.get(0),
    )?;
    anyhow::ensure!(
        !exists,
        "reserved invitation-flow object exists before schema26"
    );
    Ok(())
}
pub(crate) fn check_schema(c: &Connection) -> anyhow::Result<()> {
    let sql: Option<String> = c.query_row(
        "SELECT sql FROM sqlite_schema WHERE type='table' AND name='onboarding_invitation_flows'",
        [], |r| r.get(0),
    ).optional()?;
    let normalized = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
    anyhow::ensure!(
        sql.as_deref().is_some_and(
            |s| normalized(s) == normalized(SCHEMA.split(';').next().unwrap_or_default())
        ),
        "corrupt schema26 invitation-flow table"
    );
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Proposal {
    context: AdapterContext,
    network_id: String,
    member: String,
    expected_person_public_key: String,
}
/// Private read-only recipient inspection; no code is retained or returned.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preview {
    pub context: AdapterContext,
    pub invitation: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prepare {
    pub context: AdapterContext,
    pub network_id: String,
    pub member: String,
    pub expected_person_public_key: String,
    #[serde(default, deserialize_with = "non_null_string")]
    pub replace_flow_id: Option<String>,
}
fn non_null_string<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Handoff {
    pub context: AdapterContext,
    pub review_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lookup {
    pub context: AdapterContext,
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
    proposal: Proposal,
    review: Value,
    review_id: String,
    state: String,
    expires: String,
    invitation: Option<String>,
}
fn coded(code: &'static str) -> Error {
    Error::Coded {
        status: 409,
        code,
        message: code.replace('_', " "),
        extra: Default::default(),
    }
}
fn invalid() -> Error {
    Error::Invalid("invalid invitation review request".into())
}
fn corrupt() -> Error {
    Error::Internal(anyhow::anyhow!("invalid retained invitation review"))
}
fn field<'a>(v: &'a Value, key: &str) -> Result<&'a str, Error> {
    v[key].as_str().ok_or_else(corrupt)
}
fn time(v: &str) -> Result<DateTime<Utc>, Error> {
    DateTime::parse_from_rfc3339(v)
        .map(|v| v.with_timezone(&Utc))
        .map_err(|_| corrupt())
}
fn stamp(v: DateTime<Utc>) -> String {
    v.to_rfc3339_opts(SecondsFormat::Secs, true)
}
fn now() -> Result<DateTime<Utc>, Error> {
    time(&crate::decentralized::local_decision_time().map_err(product::model)?)
}
fn digest(review: &Value) -> String {
    format!(
        "review_{}",
        hex::encode(Sha256::digest(format!(
            "peerspan-invitation-review-v1\n{}",
            crate::canonical::value_text(review)
        )))
    )
}
fn validate_proposal(p: &Proposal) -> Result<(), Error> {
    p.context.validate()?;
    if !codec::ident(&p.network_id, "net_")
        || codec::label(&p.member).is_err()
        || !(p.expected_person_public_key == "-" || codec::key(&p.expected_person_public_key))
    {
        return Err(invalid());
    }
    Ok(())
}
fn latest(c: &Connection, project: &str) -> Result<Option<String>, Error> {
    Ok(c.query_row(
        "SELECT flow_id FROM onboarding_invitation_flows WHERE project_flow_id=?1 ORDER BY rowid DESC LIMIT 1",
        [project], |r| r.get(0),
    ).optional()?)
}
fn load(c: &Connection, id: &str) -> Result<Flow, Error> {
    if !crate::peer_store::valid_id(id, "flow", 16) {
        return Err(invalid());
    }
    let row = c.query_row(
        "SELECT request,review,review_id,state,expires_at,invitation_id FROM onboarding_invitation_flows WHERE flow_id=?1",
        [id], |r| Ok((r.get::<_, String>(0)?,r.get::<_, String>(1)?,r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,r.get::<_, String>(4)?,r.get::<_, Option<String>>(5)?)),
    ).optional()?.ok_or(Error::NotFound)?;
    let f = Flow {
        id: id.into(),
        proposal: serde_json::from_str(&row.0).map_err(|_| corrupt())?,
        review: serde_json::from_str(&row.1).map_err(|_| corrupt())?,
        review_id: row.2,
        state: row.3,
        expires: row.4,
        invitation: row.5,
    };
    if digest(&f.review) != f.review_id
        || f.review["flow_id"] != id
        || f.review["context"] != serde_json::to_value(&f.proposal.context)?
        || !["review", "issued", "declined"].contains(&f.state.as_str())
    {
        return Err(corrupt());
    }
    Ok(f)
}
fn binding(f: &Flow, context: &AdapterContext, review: &str) -> Result<(), Error> {
    context.validate()?;
    if context != &f.proposal.context || review != f.review_id {
        return Err(coded("review_changed"));
    }
    Ok(())
}
fn logical_unavailable(e: &codec::Error) -> bool {
    matches!(
        e.code,
        "not_found"
            | "upgrade_required"
            | "forbidden"
            | "authority_expired"
            | "person_removed"
            | "device_revoked"
            | "not_yet_valid"
            | "clock_rollback"
            | "proof_required"
            | "state_conflict"
            | "migration_pending"
            | "expired"
    )
}
fn plan_matches(plan: &runtime::InvitationPlan, f: &Flow) -> bool {
    ["network", "transport", "inviter_host_public_key"]
        .iter()
        .all(|key| plan.terms[*key] == f.review[*key])
}
fn retained(c: &Connection, f: &Flow, now: DateTime<Utc>) -> Result<Option<String>, Error> {
    let id = f.invitation.as_deref().ok_or_else(corrupt)?;
    let (v, code) = match runtime::retained_invitation(c, id, &stamp(now)) {
        Ok(v) => v,
        Err(e) if e.code == "not_found" || e.code == "expired" => return Ok(None),
        Err(_) => return Err(corrupt()),
    };
    if v.descriptor.network_id != f.proposal.network_id
        || v.descriptor.context_id() != field(&f.review["network"], "context_id")?
        || v.descriptor.name != field(&f.review["network"], "name")?
        || v.descriptor.genesis_root_public_key
            != field(&f.review["network"], "genesis_root_public_key")?
        || v.inviter_host_public_key != field(&f.review, "inviter_host_public_key")?
        || v.member != f.proposal.member
        || v.expected_person_public_key != f.proposal.expected_person_public_key
        || v.expires_at != field(&f.review, "invitation_expires_at")?
    {
        return Err(corrupt());
    }
    Ok(Some(code))
}
impl Store {
    pub fn preview_invitation(&self, request: Preview) -> Result<Value, Error> {
        request.context.validate()?;
        if request.invitation.len() > 32 << 10 {
            return Err(invalid());
        }
        let mut c = self.connection()?;
        let tx = c.transaction()?;
        let now = now()?;
        let (parent, attached) = request.context.project(&tx, now)?;
        if !attached {
            return Err(coded("review_changed"));
        }
        let invite = crate::decentralized::Invitation::read_token(&request.invitation, &stamp(now))
            .map_err(product::model)?;
        let contacts: Vec<Value> = invite.contacts.iter().map(|contact| json!({
            "sequence":contact.sequence.to_string(), "issued_at":contact.issued_at,
            "expires_at":contact.expires_at, "quic_addresses":contact.payload["quic_addresses"],
            "bootstrap_addresses":contact.payload["bootstrap_addresses"], "relays":contact.payload["relays"]
        })).collect();
        let host = self.identity().id;
        let review = json!({"version":1,"kind":"inspect_contact_invitation","host_id":host,
            "context":request.context,"agent":parent["agent"],
            "network":{"id":invite.descriptor.network_id,"name":invite.descriptor.name,
                "context_id":invite.descriptor.context_id(),"genesis_root_public_key":invite.descriptor.genesis_root_public_key},
            "inviter_host_public_key":invite.inviter_host_public_key,
            "invitation":{"id":invite.id,"member":invite.member,"expected_person_public_key":invite.expected_person_public_key,
                "issued_at":invite.issued_at,"expires_at":invite.expires_at,"automatic_return":invite.return_secret.is_some()},
            "contacts":contacts,"helpers":invite.helpers,
            "effects":{"verify_contact_signature":true,"create_identity":false,"create_link_request":false,
                "select_owner":false,"grant_membership":false,"grant_agent_access":false,"approve_machine":false,
                "share_files":false,"share_conversation":false,"capability_calls":false}});
        let review_id = format!(
            "review_{}",
            hex::encode(Sha256::digest(format!(
                "peerspan-invitation-preview-v1\n{}",
                crate::canonical::value_text(&review)
            )))
        );
        Ok(
            json!({"version":1,"host_id":host,"context":request.context,"review_id":review_id,
            "review":review,"next_action":"choose_join_identity"}),
        )
    }
    fn invitation_flow_state(
        &self,
        c: &Connection,
        f: &Flow,
        now: DateTime<Utc>,
    ) -> Result<&'static str, Error> {
        if f.state == "declined" {
            return Ok("declined");
        }
        let deadline = if f.state == "issued" {
            field(&f.review, "invitation_expires_at")?
        } else {
            &f.expires
        };
        if now >= time(deadline)? {
            return Ok("expired");
        }
        if f.state == "review" {
            let (_, current) = f.proposal.context.project(c, now)?;
            if !current {
                return Ok("invalidated");
            }
        }
        let plan = match runtime::invitation_plan(self, c, &f.proposal.network_id) {
            Ok(v) => v,
            Err(e) if logical_unavailable(&e) => return Ok("invalidated"),
            Err(e) => return Err(product::model(e)),
        };
        if !plan_matches(&plan, f) {
            return Ok("invalidated");
        }
        if f.state == "issued" && retained(c, f, now)?.is_none() {
            return Ok("invalidated");
        }
        Ok(if f.state == "issued" {
            "issued"
        } else {
            "review"
        })
    }
    fn invitation_flow_view(
        &self,
        c: &Connection,
        f: &Flow,
        now: DateTime<Utc>,
    ) -> Result<Value, Error> {
        let state = self.invitation_flow_state(c, f, now)?;
        Ok(
            json!({"version":1,"flow_id":f.id,"state":state,"review_id":f.review_id,"review":f.review,
            "invitation":f.invitation.as_ref().map(|id| json!({"invitation_id":id,"expires_at":f.review["invitation_expires_at"]})),
            "next_action":match state { "review"=>"review", "issued"=>"share_private_invitation", _=>"restart_review" }}),
        )
    }
    pub fn lookup_invitation_flow(&self, context: AdapterContext) -> Result<Value, Error> {
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
                self.invitation_flow_view(&tx, &f, now)
            })
            .transpose()?;
        Ok(json!({"version":1,"host_id":self.identity().id,"context":context,"flow":flow}))
    }
    pub fn prepare_invitation_flow(&self, request: Prepare) -> Result<(bool, Value), Error> {
        let p = Proposal {
            context: request.context,
            network_id: request.network_id,
            member: request.member.trim().into(),
            expected_person_public_key: request.expected_person_public_key,
        };
        validate_proposal(&p)?;
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
        let (project, attached) = p.context.project(&tx, now)?;
        match (
            latest(&tx, &p.context.project_flow_id)?,
            &request.replace_flow_id,
        ) {
            (Some(id), None) => {
                let f = load(&tx, &id)?;
                if f.proposal != p {
                    return Err(coded("flow_conflict"));
                }
                return Ok((false, self.invitation_flow_view(&tx, &f, now)?));
            }
            (Some(id), Some(previous)) if &id == previous => {
                if self.invitation_flow_state(&tx, &load(&tx, &id)?, now)? == "review" {
                    return Err(coded("flow_conflict"));
                }
            }
            (None, None) => {}
            _ => return Err(coded("flow_conflict")),
        }
        if !attached {
            return Err(coded("flow_conflict"));
        }
        let plan = runtime::invitation_plan(self, &tx, &p.network_id).map_err(product::model)?;
        let actual = time(&plan.time)?;
        let id = new_id("flow")?;
        let review = json!({"version":1,"kind":"create_contact_invitation","flow_id":id,
            "host_id":self.identity().id,"context":p.context,"agent":project["agent"],
            "network":plan.terms["network"],"inviter_host_public_key":plan.terms["inviter_host_public_key"],
            "member":p.member,"expected_person_public_key":p.expected_person_public_key,
            "transport":plan.terms["transport"],"expires_at":stamp(actual+TimeDelta::minutes(15)),
            "invitation_expires_at":stamp(actual+TimeDelta::hours(1)),
            "effects":{"create_contact_invitation":true,"receive_join_requests":true,"grant_membership":false,
                "grant_agent_access":false,"approve_machine":false,"share_files":false,"share_conversation":false,
                "capability_calls":false}});
        let review_id = digest(&review);
        tx.execute("INSERT INTO onboarding_invitation_flows (flow_id,project_flow_id,request,review,review_id,state,created_at,expires_at) VALUES(?1,?2,?3,?4,?5,'review',?6,?7)",
            params![id,p.context.project_flow_id,serde_json::to_string(&p)?,crate::canonical::value_text(&review),
                review_id,stamp(actual),field(&review,"expires_at")?])?;
        let result = self.invitation_flow_view(&tx, &load(&tx, &id)?, actual)?;
        tx.commit()?;
        Ok((true, result))
    }
    pub fn invitation_flow(&self, id: &str) -> Result<Value, Error> {
        let mut c = self.connection()?;
        let tx = c.transaction()?;
        self.invitation_flow_view(&tx, &load(&tx, id)?, now()?)
    }
    pub fn decide_invitation_flow(&self, id: &str, request: Decision) -> Result<Value, Error> {
        let mut c = self.connection()?;
        let tx = c.transaction()?;
        let f = load(&tx, id)?;
        binding(&f, &request.context, &request.review_id)?;
        let now = now()?;
        let approve = request.decision == DecisionKind::Approve;
        if f.state != "review" {
            if (f.state == "issued" && approve) || (f.state == "declined" && !approve) {
                return self.invitation_flow_view(&tx, &f, now);
            }
            return Err(coded("flow_conflict"));
        }
        if latest(&tx, &f.proposal.context.project_flow_id)?.as_deref() != Some(id) {
            return Err(coded("flow_conflict"));
        }
        match self.invitation_flow_state(&tx, &f, now)? {
            "review" => {}
            "expired" => return Err(coded("review_expired")),
            _ => return Err(coded("review_changed")),
        }
        let invitation = if approve {
            let plan = runtime::invitation_plan(self, &tx, &f.proposal.network_id)
                .map_err(product::model)?;
            if !plan_matches(&plan, &f) {
                return Err(coded("review_changed"));
            }
            if time(&plan.time)? >= time(&f.expires)? {
                return Err(coded("review_expired"));
            }
            let result = runtime::mint_invitation_in(
                self,
                &tx,
                &plan,
                &f.proposal.member,
                &f.proposal.expected_person_public_key,
                field(&f.review, "invitation_expires_at")?,
            )
            .map_err(product::model)?;
            Some(field(&result, "invitation_id")?.to_owned())
        } else {
            None
        };
        tx.execute("UPDATE onboarding_invitation_flows SET state=?1,invitation_id=?2,decided_at=?3 WHERE flow_id=?4",
            params![if approve {"issued"} else {"declined"},invitation,stamp(now),id])?;
        let result = self.invitation_flow_view(&tx, &load(&tx, id)?, now)?;
        tx.commit()?;
        Ok(result)
    }
    pub fn invitation_handoff(&self, id: &str, request: Handoff) -> Result<Value, Error> {
        let mut c = self.connection()?;
        let tx = c.transaction()?;
        let f = load(&tx, id)?;
        binding(&f, &request.context, &request.review_id)?;
        if f.state != "issued" {
            return Err(coded("flow_conflict"));
        }
        let now = now()?;
        match self.invitation_flow_state(&tx, &f, now)? {
            "issued" => {}
            "invalidated" => return Err(coded("review_changed")),
            _ => return Err(coded("flow_conflict")),
        }
        let code = retained(&tx, &f, now)?.ok_or_else(|| coded("review_changed"))?;
        Ok(json!({"version":1,"flow_id":id,"review_id":f.review_id,
            "network_id":f.proposal.network_id,"context_id":f.review["network"]["context_id"],
            "invitation_id":f.invitation,"invitation":code,"expires_at":f.review["invitation_expires_at"]}))
    }
}

pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/onboarding/invitation-preview", post(preview))
        .route("/v1/onboarding/invitation-flows", post(prepare))
        .route("/v1/onboarding/invitation-flows/lookup", post(lookup))
        .route("/v1/onboarding/invitation-flows/{id}", get(inspect))
        .route(
            "/v1/onboarding/invitation-flows/{id}/decision",
            post(decide),
        )
        .route(
            "/v1/onboarding/invitation-flows/{id}/handoff",
            post(handoff),
        )
}
async fn prepare(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<Value>), Error> {
    let request = decode(body)?;
    let (fresh, value) = blocking(store, move |s| s.prepare_invitation_flow(request)).await?;
    Ok((
        if fresh {
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
    let request: Lookup = decode(body)?;
    Ok(Json(
        blocking(store, move |s| s.lookup_invitation_flow(request.context)).await?,
    ))
}
async fn inspect(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, Error> {
    Ok(Json(
        blocking(store, move |s| s.invitation_flow(&id)).await?,
    ))
}
async fn decide(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let request = decode(body)?;
    Ok(Json(
        blocking(store, move |s| s.decide_invitation_flow(&id, request)).await?,
    ))
}
async fn handoff(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let request = decode(body)?;
    Ok(Json(
        blocking(store, move |s| s.invitation_handoff(&id, request)).await?,
    ))
}

async fn preview(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let body = body.map_err(|_| invalid())?;
    if body.len() > 65536 {
        return Err(invalid());
    }
    let request: Preview =
        crate::linking::decode_mutation(&body, "context invitation").map_err(|_| invalid())?;
    Ok(Json(
        blocking(store, move |s| s.preview_invitation(request)).await?,
    ))
}
