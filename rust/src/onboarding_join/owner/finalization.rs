//! Pure view of independently verified administrator parents, never key use.
use super::*;

impl Store {
    pub fn inspect_join_owner_finalization(
        &self,
        id: &str,
        request: OwnerApproval,
    ) -> Result<Value, Error> {
        if !crate::peer_store::valid_id(&request.owner_review_id, "review", 32) {
            return Err(invalid());
        }
        let mut c = self.connection()?;
        let tx = c.transaction()?;
        let (f, p, attached, now) = bind(
            self,
            &tx,
            id,
            &OwnerContext {
                context: request.context,
                join_review_id: request.join_review_id,
            },
        )?;
        if !attached {
            return Err(coded("review_changed"));
        }
        if p.view(&stamp(now)).map_err(product::model)?["state"] == "expired" {
            return Err(coded("review_expired"));
        }
        let unavailable = || coded("finalization_inspection_unavailable");
        let proposal = stored(&tx, &p).map_err(|_| unavailable())?;
        let owner = review(self, &f, &p, &proposal).map_err(|_| unavailable())?;
        if review_id(&owner) != request.owner_review_id {
            return Err(coded("review_changed"));
        }
        if proposal["approved"] != true || proposal["terminal"] != "-" {
            return Err(unavailable());
        }
        let e = crate::decentralized::inspect_original_finalization(&tx, self, &p)
            .map_err(|_| unavailable())?;
        let observed = time(field(&e, "observed_at")?)?;
        let (parent, attached) = f.proposal.context.project(&tx, observed)?;
        if !attached || parent["agent"] != f.review["agent"] {
            return Err(coded("review_changed"));
        }
        if e["network"] != owner["network"]
            || e["member"] != owner["member"]
            || e["owner_offer_id"] != owner["proposed_owner_offer_id"]
            || e["not_after"] != owner["not_after"]
        {
            return Err(unavailable());
        }
        let r = &e["request"];
        for key in ["person_public_key", "host_public_key", "device_public_key"] {
            if r[key] != owner[key] {
                return Err(unavailable());
            }
        }
        let review = json!({"version":1,"kind":"inspect_new_original_finalization",
            "host_id":self.identity().id,"context":f.proposal.context,"flow_id":f.id,
            "join_review_id":f.review_id,"owner_review_id":request.owner_review_id,
            "request_id":p.id,"intent_id":proposal["intent_id"],"network":e["network"],
            "member":e["member"],"person_public_key":r["person_public_key"],
            "host_public_key":r["host_public_key"],"device_public_key":r["device_public_key"],
            "request_packet_id":r["request_packet_id"],"owner_offer_id":e["owner_offer_id"],
            "selection_id":e["selection_id"],"administrator_offer_id":e["administrator_offer_id"],
            "root_state_id":e["root_state_id"],"person_lease_id":e["person_lease_id"],
            "host_lease_id":e["host_lease_id"],"administrator":e["administrator"],
            "scopes":7,"binding_scopes":2,"not_after":e["not_after"],
            "created_at":r["created_at"],"expires_at":r["expires_at"],
            "effects":{"verify_original_owner":true,"verify_requester_selection":true,
                "verify_administrator_admission":true,"verify_owner_finalization_bounds":true,
                "prepare_finalization":false,"sign_original":false,"publish_finalization":false,
                "commit_request":false,"grant_membership":false,"grant_agent_access":false,
                "share_files":false,"share_conversation":false,"capability_calls":false}});
        let digest = format!(
            "review_{}",
            codec::hash(
                format!(
                    "peerspan-original-finalization-inspection-v1\n{}",
                    crate::canonical::value_text(&review)
                )
                .as_bytes()
            )
        );
        let result = json!({"version":1,"host_id":self.identity().id,"flow_id":f.id,
            "join_review_id":f.review_id,"owner_review_id":request.owner_review_id,
            "context":f.proposal.context,"observed_at":e["observed_at"],"request":r,
            "review_id":digest,"review":review,"next_action":"review_original_finalization"});
        if !crate::onboarding_admission::safe(&result) {
            return Err(unavailable());
        }
        // Read transaction is dropped: no clock, templates, cleanup or event save.
        Ok(result)
    }
}
pub(super) async fn inspect(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let request = decode_owner_input(&body.map_err(|_| invalid())?, "inspect-finalization", false)?;
    Ok(Json(
        blocking(store, move |s| {
            s.inspect_join_owner_finalization(&id, request)
        })
        .await?,
    ))
}
