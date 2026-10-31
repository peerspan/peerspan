//! Durable exact requester consent over the ordinary intent; pure recovery.
use super::*;
use crate::decentralized::{commit_in, commit_live, commit_proposal};
mod complete;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    context: AdapterContext,
    join_review_id: String,
    commit_review_id: String,
}
fn unavailable() -> Error {
    coded("commit_review_unavailable")
}
fn dec(e: codec::Error) -> Error {
    match e.code {
        "review_changed" => coded("review_changed"),
        "expired" | "review_expired" => coded("review_expired"),
        _ => unavailable(),
    }
}
fn binding_error(e: Error) -> Error {
    match e {
        Error::NotFound => Error::NotFound,
        Error::Invalid(_) => invalid(),
        Error::Coded {
            code: "review_changed" | "state_conflict" | "request_unavailable",
            ..
        } => e,
        _ => unavailable(),
    }
}
pub fn decode_commit_input(bytes: &[u8], operation: &str, cli: bool) -> Result<Value, Error> {
    if bytes.len() > 65536 {
        return Err(invalid());
    }
    let keys = match operation {
        "lookup" | "prepare" => "context join_review_id",
        "approve" => "context join_review_id commit_review_id",
        "complete" => "context join_review_id commit_review_id decision",
        _ => return Err(invalid()),
    };
    let keys = if cli {
        format!("flow_id {keys}")
    } else {
        keys.into()
    };
    let value: Value = crate::linking::decode_mutation(bytes, &keys).map_err(|_| invalid())?;
    let mut body = value.clone();
    if cli {
        let id = body
            .as_object_mut()
            .and_then(|v| v.remove("flow_id"))
            .ok_or_else(invalid)?;
        if !id
            .as_str()
            .is_some_and(|s| crate::peer_store::valid_id(s, "flow", 16))
        {
            return Err(invalid());
        }
    }
    let context = if operation == "complete" {
        let input = complete::parse(body)?;
        OwnerContext {
            context: input.context,
            join_review_id: input.join_review_id,
        }
    } else if operation == "approve" {
        let a: Approval = serde_json::from_value(body).map_err(|_| invalid())?;
        if !crate::peer_store::valid_id(&a.commit_review_id, "review", 32) {
            return Err(invalid());
        }
        OwnerContext {
            context: a.context,
            join_review_id: a.join_review_id,
        }
    } else {
        serde_json::from_value::<OwnerContext>(body).map_err(|_| invalid())?
    };
    context.context.validate().map_err(|_| invalid())?;
    if !crate::peer_store::valid_id(&context.join_review_id, "review", 32)
        || !crate::onboarding_admission::safe(&value)
    {
        return Err(invalid());
    }
    Ok(value)
}
fn digest(review: &Value) -> String {
    format!(
        "review_{}",
        codec::hash(
            format!(
                "peerspan-requester-commit-review-v1\n{}",
                crate::canonical::value_text(review)
            )
            .as_bytes()
        )
    )
}
fn review(
    store: &Store,
    c: &Connection,
    f: &Flow,
    p: &requests::Pending,
    proposal: &Value,
) -> Result<Value, Error> {
    let original = stored(c, p).map_err(|_| unavailable())?;
    let owner = super::review(store, f, p, &original).map_err(|_| unavailable())?;
    if original["approved"] != true
        || proposal["network"] != owner["network"]
        || proposal["member"] != owner["member"]
        || proposal["owner_offer_id"] != owner["proposed_owner_offer_id"]
        || proposal["scopes"] != 7
        || proposal["not_after"] != owner["not_after"]
        || ["person_public_key", "host_public_key", "device_public_key"]
            .iter()
            .any(|k| proposal[*k] != owner[*k])
    {
        return Err(unavailable());
    }
    let created = time(field(proposal, "created_at")?)?;
    let expires = time(&p.deadline)?
        .min(created + TimeDelta::minutes(15))
        .min(time(field(proposal, "not_after")?)?);
    let packet = p.packet().map_err(dec)?;
    let r = json!({"version":1,"kind":"approve_new_original_requester_commit","host_id":store.identity().id,
        "context":f.proposal.context,"flow_id":f.id,"join_review_id":f.review_id,
        "owner_review_id":super::review_id(&owner),"request_id":p.id,"intent_id":proposal["intent_id"],
        "network":proposal["network"],"member":proposal["member"],"person_public_key":proposal["person_public_key"],
        "host_public_key":proposal["host_public_key"],"device_public_key":proposal["device_public_key"],
        "request_packet_id":packet.id,"owner_offer_id":proposal["owner_offer_id"],"selection_id":proposal["selection_id"],
        "administrator_offer_id":proposal["administrator_offer_id"],"owner_finalization_id":proposal["owner_finalization_id"],
        "root_state_id":proposal["root_state_id"],"person_lease_id":proposal["person_lease_id"],"host_lease_id":proposal["host_lease_id"],
        "binding_lease_id":proposal["binding_lease_id"],"device_lease_id":proposal["device_lease_id"],"scopes":7,"binding_scopes":2,
        "not_after":proposal["not_after"],"provider":{"kind":"requester","host_public_key":p.record.host_public_key,
        "device_public_key":p.record.device_public_key,"signature_format":"ed25519"},"created_at":stamp(created),"expires_at":stamp(expires),
        "effects":{"approve_commit_intent":true,"authorize_binding_host_signature":true,"authorize_requester_commit_signatures":true,
        "authorize_commit_publication":true,"authorize_local_application":true,"grant_agent_access":false,"share_files":false,
        "share_conversation":false,"capability_calls":false}});
    if !crate::onboarding_admission::safe(&r) {
        return Err(unavailable());
    }
    Ok(r)
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
    if p.record.terminal == "cancelled" || proposal["terminal"] == "cancelled" {
        return Ok("cancelled");
    }
    if now >= time(field(review, "expires_at")?)?
        || now >= time(field(proposal, "expires_at")?)?
        || p.view(&stamp(now)).map_err(dec)?["state"] == "expired"
        || p.stage_expired(&stamp(now)).map_err(dec)?
        || p.record.terminal == "expired"
        || proposal["terminal"] == "expired"
    {
        return Ok("expired");
    }
    if !attached
        || network_exists(c, field(&proposal["network"], "id")?)?
        || p.view(&stamp(now)).map_err(dec)?["state"] != "needs_commit"
        || p.record.terminal != "-"
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
    let commit = match commit_proposal(c, p).map_err(dec)? {
        None => Value::Null,
        Some(proposal) => {
            let review = review(store, c, f, p, &proposal)?;
            let state = state(c, p, &proposal, &review, attached, now)?;
            let next = match state {
                "approved" => "follow_join_progress",
                "review" => "approve_requester_commit",
                _ => "inspect_join_progress",
            };
            json!({"review_id":digest(&review),"review":review,"state":state,"next_action":next})
        }
    };
    let v = json!({"version":1,"host_id":store.identity().id,"flow_id":f.id,"join_review_id":f.review_id,
        "context":f.proposal.context,"observed_at":stamp(now),"request":p.view(&stamp(now)).map_err(dec)?,"commit":commit});
    if !crate::onboarding_admission::safe(&v) {
        return Err(unavailable());
    }
    Ok(v)
}
fn eligible(
    c: &Connection,
    f: &Flow,
    p: &requests::Pending,
    attached: bool,
    now: DateTime<Utc>,
    expires: Option<&str>,
) -> Result<(), Error> {
    if !attached {
        return Err(coded("review_changed"));
    }
    let raw = time(&controls::local_decision_time().map_err(dec)?)?;
    let packet = p.packet().map_err(dec)?;
    if raw < time(codec::text(&packet.payload, "created_at").map_err(dec)?)?
        || p.record.stage_at != "-" && raw < time(&p.record.stage_at)?
    {
        return Err(unavailable());
    }
    let effective = now.max(raw);
    if expires.is_some_and(|e| time(e).is_ok_and(|e| effective >= e))
        || effective >= time(&p.deadline)?
        || p.stage_expired(&stamp(effective)).map_err(dec)?
    {
        return Err(coded("review_expired"));
    }
    let v = p.view(&stamp(effective)).map_err(dec)?;
    if network_exists(c, field(&f.review["invitation"]["network"], "id")?)?
        || v["state"] != "needs_commit"
        || v["completed"]
            != json!([
                "request_created",
                "owner_offered",
                "owner_selected",
                "administrator_offered",
                "owner_finalized"
            ])
        || v["selection_approved"] != true
        || p.record.commit_packet_base64 != "-"
        || p.record.manifest_id != "-"
        || p.record.activation_id != "-"
        || p.record.outcome_packet_base64 != "-"
        || p.record.terminal != "-"
    {
        return Err(unavailable());
    }
    Ok(())
}
impl Store {
    pub fn join_commit_consent(
        &self,
        id: &str,
        operation: &str,
        value: Value,
    ) -> Result<Value, Error> {
        if !crate::peer_store::valid_id(id, "flow", 16)
            || !matches!(operation, "lookup" | "prepare" | "approve")
            || !crate::onboarding_admission::safe(&value)
        {
            return Err(invalid());
        }
        let expected = value["commit_review_id"].as_str().map(str::to_owned);
        let input: OwnerContext = if operation == "approve" {
            let a: Approval = serde_json::from_value(value).map_err(|_| invalid())?;
            OwnerContext {
                context: a.context,
                join_review_id: a.join_review_id,
            }
        } else {
            serde_json::from_value(value).map_err(|_| invalid())?
        };
        input.context.validate().map_err(|_| invalid())?;
        if !crate::peer_store::valid_id(&input.join_review_id, "review", 32)
            || expected
                .as_ref()
                .is_some_and(|e| !crate::peer_store::valid_id(e, "review", 32))
        {
            return Err(invalid());
        }
        let mut c = self.connection().map_err(|_| unavailable())?;
        let tx = c.transaction().map_err(|_| unavailable())?;
        let (f, mut p, attached, now) = bind(self, &tx, id, &input).map_err(binding_error)?;
        let current = response(self, &tx, &f, &p, attached, now)?;
        if operation == "lookup" {
            return Ok(current);
        }
        if operation == "approve"
            && (current["commit"].is_null()
                || current["commit"]["review_id"].as_str() != expected.as_deref())
        {
            return Err(if current["commit"].is_null() {
                unavailable()
            } else {
                coded("review_changed")
            });
        }
        if !current["commit"].is_null()
            && (operation == "prepare" || current["commit"]["state"] == "approved")
        {
            return Ok(current);
        }
        eligible(&tx, &f, &p, attached, now, None)?;
        let original = requests::load(&tx, &p.id).map_err(dec)?;
        let (fresh, approved) = commit_in(
            &tx,
            self,
            &mut p,
            operation == "approve",
            |proposal, effective| {
                let check = || -> Result<(), Error> {
                    let at = time(effective)?;
                    let (parent, attached) = input.context.project(&tx, at)?;
                    let attached = attached && parent["agent"] == f.review["agent"];
                    eligible(&tx, &f, &original, attached, at, None)?;
                    let actual = review(self, &tx, &f, &original, proposal)?;
                    if expected.as_deref().is_some_and(|e| e != digest(&actual)) {
                        return Err(coded("review_changed"));
                    }
                    let raw = time(&controls::local_decision_time().map_err(dec)?)?;
                    if raw < time(field(&actual, "created_at")?)?
                        || at < time(field(&actual, "created_at")?)?
                    {
                        return Err(unavailable());
                    }
                    if raw.max(at) >= time(field(&actual, "expires_at")?)? {
                        return Err(coded("review_expired"));
                    }
                    Ok(())
                };
                check().map_err(|e| match e {
                    Error::Coded {
                        code: "review_changed",
                        ..
                    } => codec::Error::new("review_changed"),
                    Error::Coded {
                        code: "review_expired",
                        ..
                    } => codec::Error::new("review_expired"),
                    _ => codec::Error::new("commit_review_unavailable"),
                })
            },
        )
        .map_err(dec)?;
        let now = time(&commit_live(&tx, self, &p).map_err(dec)?)?;
        let (parent, attached) = input.context.project(&tx, now)?;
        if !attached || parent["agent"] != f.review["agent"] {
            return Err(coded("review_changed"));
        }
        let public = response(self, &tx, &f, &p, true, now)?;
        let raw = time(&controls::local_decision_time().map_err(dec)?)?;
        if raw < time(field(&public["commit"]["review"], "created_at")?)? {
            return Err(unavailable());
        }
        let final_time = raw.max(now);
        let (parent, attached) = input.context.project(&tx, final_time)?;
        if parent["agent"] != f.review["agent"] {
            return Err(coded("review_changed"));
        }
        eligible(
            &tx,
            &f,
            &p,
            attached,
            final_time,
            Some(field(&public["commit"]["review"], "expires_at")?),
        )?;
        controls::remember_decision(&tx, &p.record.expected_network_id, &stamp(final_time))
            .map_err(dec)?;
        tx.commit().map_err(|_| unavailable())?;
        drop(c);
        if fresh {
            controls::barrier(self, "dec.intent.after_commit", &p.id).map_err(dec)?;
        }
        if approved {
            controls::barrier(self, "dec.approval.after_commit", &p.id).map_err(dec)?;
        }
        Ok(public)
    }
}
async fn action(
    store: Arc<Store>,
    id: String,
    body: Result<Bytes, BytesRejection>,
    operation: &'static str,
) -> Result<Json<Value>, Error> {
    let value = decode_commit_input(&body.map_err(|_| invalid())?, operation, false)?;
    Ok(Json(
        blocking(store, move |s| s.join_commit_consent(&id, operation, value)).await?,
    ))
}
async fn lookup(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    action(store, id, body, "lookup").await
}
async fn prepare(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    action(store, id, body, "prepare").await
}
async fn approve(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    action(store, id, body, "approve").await
}
pub(super) fn routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/onboarding/join-flows/{id}/commit/lookup", post(lookup))
        .route(
            "/v1/onboarding/join-flows/{id}/commit/prepare",
            post(prepare),
        )
        .route(
            "/v1/onboarding/join-flows/{id}/commit/approve",
            post(approve),
        )
        .merge(complete::routes())
        .merge(super::machine_commit::routes())
}
