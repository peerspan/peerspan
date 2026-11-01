//! Exact current received machine-finalization inspection, never requester consent.
use super::*;
mod consent;
pub use consent::decode_input as decode_machine_commit_input;

fn unavailable() -> Error {
    coded("machine_requester_inspection_unavailable")
}
fn domain(e: codec::Error) -> Error {
    if matches!(e.code, "expired" | "review_expired" | "authority_expired") {
        coded("review_expired")
    } else {
        unavailable()
    }
}
impl Store {
    pub fn inspect_machine_requester_commit(
        &self,
        id: &str,
        input: OwnerContext,
    ) -> Result<Value, Error> {
        let mut c = self.connection().map_err(|_| unavailable())?;
        let tx = c.transaction().map_err(|_| unavailable())?;
        let (f, p, attached, _) = bind(self, &tx, id, &input).map_err(|e| match e {
            Error::NotFound | Error::Invalid(_) => e,
            Error::Coded {
                code: "review_changed" | "request_unavailable",
                ..
            } => e,
            _ => unavailable(),
        })?;
        if !attached {
            return Err(coded("review_changed"));
        }
        inspection_in(&tx, self, &f, &p, &input, false)
    }
}
fn inspection_in(
    c: &Connection,
    store: &Store,
    f: &Flow,
    p: &requests::Pending,
    input: &OwnerContext,
    prepared: bool,
) -> Result<Value, Error> {
    if f.review["invitation"]["invitation"]["expected_person_public_key"]
        != f.proposal.person_public_key
    {
        return Err(unavailable());
    }
    let e = if prepared {
        crate::decentralized::inspect_machine_requester_prepared(c, store, p)
    } else {
        crate::decentralized::inspect_machine_requester_commit(c, store, p)
    }
    .map_err(domain)?;
    let observed = time(field(&e, "observed_at")?)?;
    let (parent, attached) = input
        .context
        .project(c, observed)
        .map_err(|_| coded("review_changed"))?;
    if !attached || parent["agent"] != f.review["agent"] {
        return Err(coded("review_changed"));
    }
    if e["network"] != f.review["invitation"]["network"]
        || e["member"] != f.review["invitation"]["invitation"]["member"]
    {
        return Err(unavailable());
    }
    let r = &e["request"];
    let effects = json!({"verify_existing_owner":true,"verify_requester_selection":true,"verify_host_admission":true,
                "verify_owner_finalization":true,"prepare_commit_intent":false,"approve_commit_intent":false,
                "sign_requester_commit":false,"publish_requester_commit":false,"apply_network":false,
                "grant_membership":false,"grant_machine_powers":false,"grant_agent_access":false,
                "share_files":false,"share_conversation":false,"capability_calls":false});
    let review = json!({"version":1,"kind":"inspect_existing_person_requester_commit","host_id":store.identity().id,
            "context":input.context,"agent":parent["agent"],"flow_id":f.id,"join_review_id":f.review_id,
            "request_id":p.id,"network":e["network"],"member":e["member"],"person_public_key":r["person_public_key"],
            "host_public_key":r["host_public_key"],"device_public_key":r["device_public_key"],
            "request_packet_id":r["request_packet_id"],"owner_offer_id":r["owner_offer_id"],"selection_id":r["selection_id"],
            "administrator_offer_id":r["administrator_offer_id"],"owner_finalization_id":r["owner_finalization_id"],
            "owner_root_state_id":e["owner_root_state_id"],"root_state_id":e["root_state_id"],
            "person_lease_id":e["person_lease_id"],"host_lease_id":e["host_lease_id"],"binding_lease_id":e["binding_lease_id"],
            "device_lease_id":e["device_lease_id"],"owner_provider":e["owner_provider"],"host_admission":e["host_admission"],
            "reused_binding":e["reused_binding"],"scopes":7,"binding_scopes":2,"not_after":e["not_after"],
            "created_at":r["created_at"],"expires_at":r["expires_at"],"request_stage_deadline":e["request_stage_deadline"],
            "effects":effects});
    let review_id = format!(
        "review_{}",
        codec::hash(
            format!(
                "peerspan-machine-requester-inspection-v1\n{}",
                crate::canonical::value_text(&review)
            )
            .as_bytes()
        )
    );
    let result = json!({"version":1,"host_id":store.identity().id,"context":input.context,"flow_id":f.id,
            "join_review_id":f.review_id,"observed_at":e["observed_at"],"request":r,"review_id":review_id,
            "review":review,"next_action":"review_machine_requester_consent"});
    if !crate::onboarding_admission::safe(&result)
        || serde_json::to_vec(&result)
            .map_err(|_| unavailable())?
            .len()
            > 2 << 20
    {
        return Err(unavailable());
    }
    Ok(result)
}

async fn inspect(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let input: OwnerContext = decode_owner_input(&body.map_err(|_| invalid())?, "lookup", false)?;
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        blocking(store, move |s| {
            s.inspect_machine_requester_commit(&id, input)
        }),
    )
    .await
    .map_err(|_| unavailable())?
    .map(Json)
}
pub(super) fn routes() -> Router<Arc<Store>> {
    Router::new()
        .route(
            "/v1/onboarding/join-flows/{id}/machine-commit/inspect",
            post(inspect),
        )
        .merge(consent::routes())
}
