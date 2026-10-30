//! Exact public consent over the existing ordinary unapproved owner intent.
use super::*;
use crate::decentralized::{ceremony, controls};
mod commit;
mod finalization;
pub use commit::decode_commit_input;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerContext {
    pub context: AdapterContext,
    pub join_review_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerApproval {
    pub context: AdapterContext,
    pub join_review_id: String,
    pub owner_review_id: String,
}

pub fn decode_owner_input<T: DeserializeOwned>(
    bytes: &[u8],
    operation: &str,
    cli: bool,
) -> Result<T, Error> {
    if bytes.len() > 65536 {
        return Err(invalid());
    }
    let fields = match operation {
        "prepare" | "lookup" => "context join_review_id",
        "approve" | "inspect-finalization" => "context join_review_id owner_review_id",
        _ => return Err(invalid()),
    };
    let fields = if cli {
        format!("flow_id {fields}")
    } else {
        fields.into()
    };
    crate::linking::decode_mutation(bytes, &fields).map_err(|_| invalid())
}
fn review_id(review: &Value) -> String {
    format!(
        "review_{}",
        codec::hash(
            format!(
                "peerspan-onboarding-original-owner-review-v1\n{}",
                crate::canonical::value_text(review)
            )
            .as_bytes()
        )
    )
}
fn network_exists(c: &Connection, network: &str) -> Result<bool, Error> {
    Ok(c.query_row(
        "SELECT EXISTS(SELECT 1 FROM networks WHERE id=?1)",
        [network],
        |r| r.get(0),
    )?)
}
fn guarded(c: &Connection, network: &str) -> Result<DateTime<Utc>, Error> {
    time(
        &controls::guarded_decision(
            c,
            network,
            &crate::decentralized::local_decision_time().map_err(product::model)?,
        )
        .map_err(product::model)?,
    )
}
fn bind(
    store: &Store,
    c: &Connection,
    id: &str,
    request: &OwnerContext,
) -> Result<(Flow, requests::Pending, bool, DateTime<Utc>), Error> {
    request.context.validate()?;
    if !crate::peer_store::valid_id(&request.join_review_id, "review", 32) {
        return Err(invalid());
    }
    let f = load(c, id)?;
    if request.context != f.proposal.context || request.join_review_id != f.review_id {
        return Err(coded("review_changed"));
    }
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
        return Err(corrupt());
    }
    let now = guarded(c, field(outcome, "network_id")?)?;
    let (project, attached) = request.context.project(c, now)?;
    let exists: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM dec_pending WHERE request_id=?1)",
        [request_id],
        |r| r.get(0),
    )?;
    if !exists {
        return Err(coded("request_unavailable"));
    }
    let p = requests::load(c, request_id).map_err(|e| {
        if matches!(e.code, "not_found" | "state_conflict") {
            coded("owner_review_unavailable")
        } else {
            product::model(e)
        }
    })?;
    let v = p.view(&stamp(now)).map_err(product::model)?;
    if v["request_id"] != request_id
        || v["role"] != "requester"
        || v["mode"] != "new"
        || v["migration_proposal_id"] != "-"
        || v["host_public_key"] != store.identity().public_key
        || ["network_id", "context_id", "person_public_key"]
            .iter()
            .any(|k| v[*k] != outcome[*k])
    {
        return Err(coded("owner_review_unavailable"));
    }
    let attached = attached && project["agent"] == f.review["agent"];
    Ok((f, p, attached, now))
}
fn not_after(p: &requests::Pending) -> Result<String, Error> {
    let packet = p.packet().map_err(product::model)?;
    Ok(stamp(
        time(codec::text(&packet.payload, "created_at").map_err(product::model)?)?
            + TimeDelta::days(7),
    ))
}
fn review(
    store: &Store,
    f: &Flow,
    p: &requests::Pending,
    proposal: &Value,
) -> Result<Value, Error> {
    let network = &f.review["invitation"]["network"];
    let member = &f.review["invitation"]["invitation"]["member"];
    if proposal["possession_only"] != true
        || proposal["scopes"] != 7
        || proposal["not_after"] != not_after(p)?
        || proposal["network_id"] != network["id"]
        || proposal["context_id"] != network["context_id"]
        || proposal["member"] != *member
        || proposal["person_public_key"] != f.proposal.person_public_key
        || proposal["host_public_key"] != p.record.host_public_key
        || proposal["device_public_key"] != p.record.device_public_key
        || !crate::peer_store::valid_id(field(proposal, "intent_id")?, "dint", 16)
        || !crate::peer_store::valid_id(field(proposal, "owner_offer_id")?, "dpk", 32)
    {
        return Err(coded("owner_review_unavailable"));
    }
    let expires =
        time(&p.deadline)?.min(time(field(proposal, "created_at")?)? + TimeDelta::minutes(15));
    Ok(
        json!({"version":1,"kind":"approve_new_original_owner","host_id":store.identity().id,
        "context":f.proposal.context,"flow_id":f.id,"join_review_id":f.review_id,
        "request_id":p.id,"intent_id":proposal["intent_id"],"network":network,"member":member,
        "person_public_key":proposal["person_public_key"],"host_public_key":proposal["host_public_key"],
        "device_public_key":proposal["device_public_key"],"proposed_owner_offer_id":proposal["owner_offer_id"],
        "scopes":7,"not_after":proposal["not_after"],"expires_at":stamp(expires),
        "effects":{"approve_owner_intent":true,"authorize_original_signature":true,
            "authorize_bounded_owner_finalization":true,"auto_select_single_offer_after_signature":true,
            "publish_owner_offer_after_signature":true,"grant_membership":false,"grant_agent_access":false,
            "approve_network_administrator":false,"commit_request":false,"share_files":false,
            "share_conversation":false,"capability_calls":false}}),
    )
}
fn stored(c: &Connection, p: &requests::Pending) -> Result<Value, Error> {
    ceremony::stored_owner_proposal(c, p).map_err(|_| coded("owner_review_unavailable"))
}
fn state(
    c: &Connection,
    p: &requests::Pending,
    proposal: &Value,
    review: &Value,
    attached: bool,
    now: DateTime<Utc>,
) -> Result<&'static str, Error> {
    if proposal["approved"] == true {
        return Ok("approved");
    }
    let v = p.view(&stamp(now)).map_err(product::model)?;
    if v["state"] == "cancelled" || proposal["terminal"] == "cancelled" {
        return Ok("cancelled");
    }
    if now >= time(field(review, "expires_at")?)?
        || now >= time(field(proposal, "expires_at")?)?
        || v["state"] == "expired"
        || proposal["terminal"] == "expired"
    {
        return Ok("expired");
    }
    if !attached
        || network_exists(c, field(proposal, "network_id")?)?
        || v["state"] != "pending"
        || proposal["terminal"] != "-"
    {
        return Ok("invalidated");
    }
    Ok("review")
}
fn response(
    store: &Store,
    c: &Connection,
    f: &Flow,
    p: &requests::Pending,
    attached: bool,
    now: DateTime<Utc>,
) -> Result<Value, Error> {
    let ordinary = p.view(&stamp(now)).map_err(product::model)?;
    let owner = if p.record.owner_intent_id == "-" {
        Value::Null
    } else {
        let proposal = stored(c, p)?;
        let review = review(store, f, p, &proposal)?;
        let state = state(c, p, &proposal, &review, attached, now)?;
        let next = match state {
            "approved" if p.record.owner_packet_base64 == "-" => "provide_original_signature",
            "approved" => "follow_join_progress",
            "review" => "approve_owner_intent",
            _ => "inspect_join_progress",
        };
        json!({"review_id":review_id(&review),"review":review,"state":state,"next_action":next})
    };
    Ok(
        json!({"version":1,"host_id":store.identity().id,"flow_id":f.id,"join_review_id":f.review_id,
        "context":f.proposal.context,"observed_at":stamp(now),"request":ordinary,"owner":owner}),
    )
}
fn eligible(
    c: &Connection,
    f: &Flow,
    p: &requests::Pending,
    attached: bool,
    now: DateTime<Utc>,
    expires: Option<&str>,
) -> Result<(), Error> {
    if expires.is_some_and(|e| time(e).is_ok_and(|e| now >= e))
        || p.view(&stamp(now)).map_err(product::model)?["state"] == "expired"
    {
        return Err(coded("review_expired"));
    }
    if !attached {
        return Err(coded("review_changed"));
    }
    if network_exists(c, field(&f.review["invitation"]["network"], "id")?)?
        || p.view(&stamp(now)).map_err(product::model)?["state"] != "pending"
    {
        return Err(coded("owner_review_unavailable"));
    }
    Ok(())
}
fn ordinary_input(
    c: &Connection,
    f: &Flow,
    p: &requests::Pending,
    now: DateTime<Utc>,
    approve: bool,
) -> Result<Value, Error> {
    let code = p
        .code(c, &stamp(now))
        .map_err(product::model)?
        .ok_or_else(|| coded("owner_review_unavailable"))?;
    Ok(
        json!({"code":code,"network_id":f.review["invitation"]["network"]["id"],
        "person_public_key":f.proposal.person_public_key,"provider_id":f.proposal.person_public_key,
        "signature_format":"sshsig","scopes":7,"not_after":not_after(p)?,
        "expected_host_public_key":p.record.host_public_key,
        "expected_device_public_key":p.record.device_public_key,"approve":approve}),
    )
}
impl Store {
    pub fn lookup_join_owner(&self, id: &str, request: OwnerContext) -> Result<Value, Error> {
        let mut c = self.connection()?;
        let tx = c.transaction()?;
        let (f, p, attached, now) = bind(self, &tx, id, &request)?;
        response(self, &tx, &f, &p, attached, now)
    }
    pub fn prepare_join_owner(&self, id: &str, request: OwnerContext) -> Result<Value, Error> {
        let mut c = self.connection()?;
        let tx = c.transaction()?;
        let (f, p, attached, now) = bind(self, &tx, id, &request)?;
        if p.record.owner_intent_id != "-" {
            return response(self, &tx, &f, &p, attached, now);
        }
        eligible(&tx, &f, &p, attached, now, None)?;
        let input = ordinary_input(&tx, &f, &p, now, false)?;
        let (_, fresh, _) = ceremony::owner_in(
            self,
            &tx,
            input.as_object().ok_or_else(corrupt)?,
            |proposal| {
                review(self, &f, &p, proposal)
                    .map(|_| ())
                    .map_err(|_| codec::Error::new("owner_review_unavailable"))
            },
        )
        .map_err(product::model)?;
        let p = requests::load(&tx, &p.id).map_err(product::model)?;
        let now = guarded(&tx, field(&f.review["invitation"]["network"], "id")?)?;
        let public = response(self, &tx, &f, &p, attached, now)?;
        eligible(
            &tx,
            &f,
            &p,
            attached,
            now,
            Some(field(&public["owner"]["review"], "expires_at")?),
        )?;
        controls::remember_decision(
            &tx,
            field(&f.review["invitation"]["network"], "id")?,
            &stamp(now),
        )
        .map_err(product::model)?;
        tx.commit()?;
        drop(c);
        if fresh {
            controls::barrier(self, "dec.intent.after_commit", &p.id).map_err(product::model)?;
        }
        Ok(public)
    }
    pub fn approve_join_owner(&self, id: &str, request: OwnerApproval) -> Result<Value, Error> {
        if !crate::peer_store::valid_id(&request.owner_review_id, "review", 32) {
            return Err(invalid());
        }
        let context = OwnerContext {
            context: request.context,
            join_review_id: request.join_review_id,
        };
        let mut c = self.connection()?;
        let tx = c.transaction()?;
        let (f, p, attached, now) = bind(self, &tx, id, &context)?;
        if p.record.owner_intent_id == "-" {
            return Err(coded("owner_review_unavailable"));
        }
        let proposal = stored(&tx, &p)?;
        let review = review(self, &f, &p, &proposal)?;
        if review_id(&review) != request.owner_review_id {
            return Err(coded("review_changed"));
        }
        if proposal["approved"] == true {
            return response(self, &tx, &f, &p, attached, now);
        }
        eligible(
            &tx,
            &f,
            &p,
            attached,
            now,
            Some(field(&review, "expires_at")?),
        )?;
        if state(&tx, &p, &proposal, &review, attached, now)? != "review" {
            return Err(coded("owner_review_unavailable"));
        }
        let input = ordinary_input(&tx, &f, &p, now, true)?;
        let (_, _, approved) = ceremony::owner_in(
            self,
            &tx,
            input.as_object().ok_or_else(corrupt)?,
            |proposal| {
                let actual = self::review(self, &f, &p, proposal)
                    .map_err(|_| codec::Error::new("owner_review_unavailable"))?;
                if review_id(&actual) != request.owner_review_id {
                    return Err(codec::Error::new("review_changed"));
                }
                if proposal["decision_time"]
                    .as_str()
                    .is_some_and(|t| t >= actual["expires_at"].as_str().unwrap_or(""))
                {
                    return Err(codec::Error::new("review_expired"));
                }
                Ok(())
            },
        )
        .map_err(product::model)?;
        let p = requests::load(&tx, &p.id).map_err(product::model)?;
        let now = guarded(&tx, field(&f.review["invitation"]["network"], "id")?)?;
        eligible(
            &tx,
            &f,
            &p,
            attached,
            now,
            Some(field(&review, "expires_at")?),
        )?;
        let public = response(self, &tx, &f, &p, attached, now)?;
        controls::remember_decision(
            &tx,
            field(&f.review["invitation"]["network"], "id")?,
            &stamp(now),
        )
        .map_err(product::model)?;
        tx.commit()?;
        drop(c);
        if approved {
            controls::barrier(self, "dec.approval.after_commit", &p.id).map_err(product::model)?;
        }
        Ok(public)
    }
}
pub(super) fn routes() -> Router<Arc<Store>> {
    Router::new()
        .merge(commit::routes())
        .route(
            "/v1/onboarding/join-flows/{id}/owner/finalization/inspect",
            post(finalization::inspect),
        )
        .route("/v1/onboarding/join-flows/{id}/owner/lookup", post(lookup))
        .route(
            "/v1/onboarding/join-flows/{id}/owner/prepare",
            post(prepare),
        )
        .route(
            "/v1/onboarding/join-flows/{id}/owner/approve",
            post(approve),
        )
}
async fn lookup(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let request = decode_owner_input(&body.map_err(|_| invalid())?, "lookup", false)?;
    Ok(Json(
        blocking(store, move |s| s.lookup_join_owner(&id, request)).await?,
    ))
}
async fn prepare(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let request = decode_owner_input(&body.map_err(|_| invalid())?, "prepare", false)?;
    Ok(Json(
        blocking(store, move |s| s.prepare_join_owner(&id, request)).await?,
    ))
}
async fn approve(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let request = decode_owner_input(&body.map_err(|_| invalid())?, "approve", false)?;
    Ok(Json(
        blocking(store, move |s| s.approve_join_owner(&id, request)).await?,
    ))
}
