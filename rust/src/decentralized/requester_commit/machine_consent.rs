//! One immutable unsigned receipt over an ordinary existing-person requester intent.
use super::*;

fn id(domain: &str, value: &Value) -> String {
    format!(
        "review_{}",
        hash(format!("{domain}\n{}", crate::canonical::value_text(value)).as_bytes())
    )
}
fn inspection_id(v: &Value) -> String {
    id("peerspan-machine-requester-inspection-v1", v)
}
fn review_id(v: &Value) -> String {
    id("peerspan-machine-requester-consent-v1", v)
}
fn find(c: &Connection, p: &Pending, kind: &str) -> Result<Option<Intent>> {
    let mut q=c.prepare("SELECT intent_id FROM dec_intents WHERE kind=?1 AND json_extract(record,'$.operation_id')=?2 ORDER BY intent_id").map_err(db)?;
    let ids = q
        .query_map(rusqlite::params![kind, p.id], |r| r.get::<_, String>(0))
        .map_err(db)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(db)?;
    check(ids.len() <= 1)?;
    ids.first().map(|id| Intent::load(c, id)).transpose()
}
fn effects() -> Value {
    json!({"approve_commit_intent":true,"authorize_binding_host_signature":true,
        "authorize_requester_commit_signatures":true,"authorize_commit_publication":true,
        "authorize_local_application":true,"grant_agent_access":false,"share_files":false,
        "share_conversation":false,"capability_calls":false})
}
fn make_review(meta: &Intent, ordinary: &Intent, inspection: &Value) -> Result<Value> {
    let r = &ordinary.record;
    let end = (stamp(&r.created_at)? + chrono::TimeDelta::minutes(15))
        .min(stamp(&r.expires_at)?)
        .min(stamp(text(object(inspection)?, "request_stage_deadline")?)?)
        .min(stamp(&r.not_after)?);
    require(stamp(&r.created_at)? < end, "review_expired")?;
    Ok(
        json!({"version":1,"kind":"approve_existing_person_requester_commit","consent_id":meta.id,
        "host_id":inspection["host_id"],"context":inspection["context"],"agent":inspection["agent"],
        "flow_id":inspection["flow_id"],"join_review_id":inspection["join_review_id"],
        "request_id":r.operation_id,"intent_id":ordinary.id,"inspection_review_id":inspection_id(inspection),
        "inspection":inspection,"created_at":r.created_at,"expires_at":end.to_rfc3339_opts(chrono::SecondsFormat::Secs,true),
        "effects":effects()}),
    )
}
fn record(ordinary: &Intent, review: &Value, approved: bool, approved_at: &str) -> Result<Record> {
    let mut r = ordinary.record.clone();
    r.review_base64 = encode(crate::canonical::value_text(review).as_bytes());
    r.approved = approved;
    r.approved_at = approved_at.into();
    r.expires_at = text(object(review)?, "expires_at")?.into();
    r.templates.clear();
    r.signatures.clear();
    r.completed = true;
    r.terminal = "-".into();
    r.result_base64 = "-".into();
    Ok(r)
}
// Historical binding checks use immutable ordinary evidence. They do not
// reconstruct live authority at a made-up time or resolve a private signer.
fn bindings(
    store: &Store,
    p: &Pending,
    i: &Intent,
    inspection: &Value,
    scope: &Value,
) -> Result<()> {
    let o = object(inspection)?;
    fields(
        o,
        "version kind host_id context agent flow_id join_review_id request_id network member person_public_key host_public_key device_public_key request_packet_id owner_offer_id selection_id administrator_offer_id owner_finalization_id owner_root_state_id root_state_id person_lease_id host_lease_id binding_lease_id device_lease_id owner_provider host_admission reused_binding scopes binding_scopes not_after created_at expires_at request_stage_deadline effects",
    )?;
    let d = Descriptor::read(&b64(&p.record.descriptor_base64, MAX_OBJECT)?)?;
    let owner = Packet::read(&b64(&p.record.owner_packet_base64, MAX_OBJECT)?)?;
    check_reference(p, i, &d, &owner)?;
    let r = &i.record;
    let ordinary = parse(&b64(&r.review_base64, MAX_OBJECT)?, MAX_OBJECT)?;
    let packet = p.packet()?;
    check(
        inspection["version"] == 1
            && inspection["kind"] == "inspect_existing_person_requester_commit"
            && inspection["host_id"] == store.identity().id
            && inspection["request_id"] == p.id
            && inspection["request_packet_id"] == packet.id
            && inspection["network"]
                == json!({"id":d.network_id,"name":d.name,"context_id":d.context_id(),"genesis_root_public_key":d.genesis_root_public_key})
            && inspection["member"] == owner.payload["member"]
            && inspection["scopes"] == 7
            && inspection["binding_scopes"] == 2
            && inspection["person_public_key"] == r.person_public_key
            && inspection["host_public_key"] == r.host_public_key
            && inspection["device_public_key"] == r.device_public_key
            && inspection["not_after"] == r.not_after
            && inspection["owner_root_state_id"] == owner.payload["root_state_id"]
            && ident(text(&owner.payload, "root_state_id")?, "ds_")
            && ident(text(&owner.payload, "person_lease_id")?, "ds_")
            && text(&owner.object, "writer_host_public_key")? != r.host_public_key
            && inspection["owner_provider"] == ordinary["provider"]
            && inspection["created_at"] == packet.payload["created_at"]
            && inspection["expires_at"] == p.deadline
            && inspection["host_admission"]
                == if p.record.administrator_packet_base64 == "-" {
                    "folded_owner"
                } else {
                    "separate_administrator"
                },
    )?;
    for k in ["context", "agent", "flow_id", "join_review_id"] {
        check(inspection[k] == scope[k])?;
    }
    for k in [
        "owner_offer_id",
        "selection_id",
        "administrator_offer_id",
        "root_state_id",
        "person_lease_id",
        "host_lease_id",
        "binding_lease_id",
        "device_lease_id",
    ] {
        check(inspection[k] == ordinary[k])?;
    }
    check(inspection["owner_finalization_id"] == p.record.owner_finalization_id)?;
    let f = Packet::read(&b64(
        &p.record.owner_finalization_packet_base64,
        MAX_OBJECT,
    )?)?;
    check(inspection["reused_binding"] == f.payload["binding_lease"].is_string())?;
    let created = stamp(text(&packet.payload, "created_at")?)?;
    let deadline = stamp(text(o, "request_stage_deadline")?)?;
    check(
        deadline >= created + chrono::TimeDelta::seconds(600)
            && deadline <= stamp(&r.created_at)? + chrono::TimeDelta::seconds(600),
    )?;
    check(
        inspection["effects"]
            == json!({"verify_existing_owner":true,"verify_requester_selection":true,
        "verify_host_admission":true,"verify_owner_finalization":true,"prepare_commit_intent":false,
        "approve_commit_intent":false,"sign_requester_commit":false,"publish_requester_commit":false,
        "apply_network":false,"grant_membership":false,"grant_machine_powers":false,"grant_agent_access":false,
        "share_files":false,"share_conversation":false,"capability_calls":false}),
    )
}
struct Receipt {
    meta: Intent,
    ordinary: Intent,
    review: Value,
}
fn load(
    c: &Connection,
    store: &Store,
    p: &Pending,
    meta: Intent,
    scope: &Value,
) -> Result<Receipt> {
    let review = parse(&b64(&meta.record.review_base64, 1 << 20)?, 1 << 20)?;
    let ordinary = find(c, p, "requester_commit")?.ok_or_else(|| Error::new("state_conflict"))?;
    bindings(store, p, &ordinary, &review["inspection"], scope)?;
    let expected = make_review(&meta, &ordinary, &review["inspection"])?;
    check(
        review == expected
            && meta.network_id == ordinary.network_id
            && meta.context_id == ordinary.context_id
            && serde_json::to_value(&meta.record).map_err(|_| Error::new("internal"))?
                == serde_json::to_value(record(
                    &ordinary,
                    &review,
                    meta.record.approved,
                    &meta.record.approved_at,
                )?)
                .map_err(|_| Error::new("internal"))?
            && ordinary.record.approved == p.record.commit_approved
            && if ordinary.record.approved {
                p.record.commit_intent_id == ordinary.id
            } else {
                p.record.commit_intent_id == "-"
            },
    )?;
    if meta.record.approved {
        check(ordinary.record.approved && meta.record.approved_at == ordinary.record.approved_at)?;
    }
    Ok(Receipt {
        meta,
        ordinary,
        review,
    })
}
fn current(r: &Receipt, p: &Pending, evidence: &Value) -> Result<String> {
    let now = text(object(evidence)?, "observed_at")?;
    require(
        stamp(&controls::local_decision_time()?)? >= stamp(&r.ordinary.record.created_at)?,
        "machine_requester_consent_unavailable",
    )?;
    require(
        stamp(now)? >= stamp(&r.ordinary.record.created_at)?,
        "machine_requester_consent_unavailable",
    )?;
    require(now < r.meta.record.expires_at.as_str(), "review_expired")?;
    require(
        evidence["review"] == r.review["inspection"],
        "review_changed",
    )?;
    require(
        !r.ordinary.record.approved
            && !p.record.commit_approved
            && p.record.commit_intent_id == "-"
            && r.ordinary.record.terminal == "-"
            && !r.ordinary.record.completed
            && r.ordinary.record.signatures.is_empty(),
        "review_changed",
    )?;
    Ok(now.into())
}
fn wrapper(
    store: &Store,
    p: &Pending,
    scope: &Value,
    r: Option<&Receipt>,
    now: &str,
    state: &str,
) -> Result<Value> {
    let consent=r.map(|r|json!({"consent_id":r.meta.id,"review_id":review_id(&r.review),"review":r.review,
        "state":state,"next_action":match state {"approved"=>"follow_machine_link","review"=>"approve_machine_requester_commit",_=>"inspect_machine_link"}}));
    let v = json!({"version":1,"host_id":store.identity().id,"context":scope["context"],"flow_id":scope["flow_id"],
        "join_review_id":scope["join_review_id"],"observed_at":now,"request":p.view(now)?,"consent":consent});
    check(crate::onboarding_admission::safe(&v) && bytes(&v)?.len() <= 2 << 20)?;
    Ok(v)
}
/// Caller holds one transaction and supplies the section45 exact project binding.
pub(crate) fn run(
    c: &Connection,
    store: &Store,
    p: &mut Pending,
    scope: &Value,
    op: &str,
    expected: Option<&str>,
    mut inspect: impl FnMut(&Pending, bool) -> Result<Value>,
) -> Result<(Value, bool)> {
    let raw = controls::local_decision_time()?;
    let now = controls::guarded_decision(c, &p.record.expected_network_id, &raw)?;
    let meta = find(c, p, "machine_requester_review")?;
    let mut receipt = meta.map(|m| load(c, store, p, m, scope)).transpose()?;
    if let Some(r) = &receipt {
        if op == "prepare" {
            require(
                expected == Some(inspection_id(&r.review["inspection"]).as_str()),
                "review_changed",
            )?;
        }
        if op == "approve" {
            require(
                expected == Some(review_id(&r.review).as_str()),
                "review_changed",
            )?;
        }
        if op == "lookup" || op == "prepare" || r.meta.record.approved {
            let state = if r.meta.record.approved {
                "approved"
            } else if p.record.terminal == "cancelled" || r.ordinary.record.terminal == "cancelled"
            {
                "cancelled"
            } else if now >= r.meta.record.expires_at
                || p.stage_expired(&now)?
                || p.record.terminal == "expired"
            {
                "expired"
            } else if r.ordinary.record.approved {
                "invalidated"
            } else {
                match inspect(p, true).and_then(|v| current(r, p, &v)) {
                    Ok(_) => "review",
                    Err(e)
                        if matches!(e.code, "expired" | "review_expired" | "authority_expired") =>
                    {
                        "expired"
                    }
                    Err(_) => "invalidated",
                }
            };
            return Ok((wrapper(store, p, scope, Some(r), &now, state)?, false));
        }
    } else if op == "lookup" {
        return Ok((wrapper(store, p, scope, None, &now, "review")?, false));
    } else {
        require(op == "prepare", "machine_requester_consent_unavailable")?;
    }

    if op == "prepare" {
        let evidence = inspect(p, false)?;
        require(
            expected == Some(inspection_id(&evidence["review"]).as_str()),
            "review_changed",
        )?;
        let stage = context(c, store, p)?;
        let ordinary = new_intent(c, p, &stage)?;
        check_current(p, &ordinary, &stage)?;
        let mut meta = Intent {
            id: crate::store::new_id("dint").map_err(|_| Error::new("internal"))?,
            network_id: ordinary.network_id.clone(),
            context_id: ordinary.context_id.clone(),
            kind: "machine_requester_review".into(),
            secret: None,
            record: ordinary.record.clone(),
        };
        let review = make_review(&meta, &ordinary, &evidence["review"])?;
        meta.record = record(&ordinary, &review, false, "-")?;
        let (count,total,size):(i64,i64,i64)=c.query_row("SELECT COUNT(*),(SELECT COUNT(*) FROM dec_intents),COALESCE(SUM(length(CAST(record AS BLOB))),0) FROM dec_intents WHERE kind='machine_requester_review'",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(db)?;
        let length =
            bytes(&serde_json::to_value(&meta.record).map_err(|_| Error::new("internal"))?)?.len();
        require(
            count < 256
                && total < 4095
                && (size as usize)
                    .checked_add(length)
                    .is_some_and(|n| n <= 8 << 20),
            "quota_exceeded",
        )?;
        ordinary.save(c)?;
        meta.save(c)?;
        receipt = Some(Receipt {
            meta,
            ordinary,
            review,
        });
    }
    let r = receipt
        .as_mut()
        .ok_or_else(|| Error::new("state_conflict"))?;
    let mut effective = current(r, p, &inspect(p, true)?)?;
    let stage = context(c, store, p)?;
    check_current(p, &r.ordinary, &stage)?;
    if op == "approve" {
        observer::owned_device(store, c, p)?;
        budget(c, store, p, &stage)?;
        effective = current(r, p, &inspect(p, true)?)?;
        r.ordinary.record.approved = true;
        r.ordinary.record.approved_at = effective.clone();
        p.record.commit_approved = true;
        p.record.commit_intent_id = r.ordinary.id.clone();
        r.meta.record = record(&r.ordinary, &r.review, true, &effective)?;
        r.ordinary.save(c)?;
        requests::save(c, p)?;
        r.meta.save(c)?;
    }
    // Recheck wall/guarded/project/authority after every write, before commit.
    let last = inspect(p, true)?;
    require(last["review"] == r.review["inspection"], "review_changed")?;
    let at = text(object(&last)?, "observed_at")?;
    require(
        stamp(at)? >= stamp(&effective)? && at < r.meta.record.expires_at.as_str(),
        "review_expired",
    )?;
    controls::remember_decision(c, &r.ordinary.network_id, at)?;
    Ok((
        wrapper(
            store,
            p,
            scope,
            Some(r),
            at,
            if op == "approve" {
                "approved"
            } else {
                "review"
            },
        )?,
        true,
    ))
}
