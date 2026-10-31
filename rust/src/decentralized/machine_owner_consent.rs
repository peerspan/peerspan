//! Unsigned immutable project receipt; authority stays in the ordinary owner intent.
use super::{
    ceremony,
    codec::*,
    controls,
    intents::{Intent, Record},
    requests::{self, Pending},
    transcript::Packet,
};
use crate::{
    onboarding_adapter::AdapterContext, onboarding_machine::Inspect,
    onboarding_machine_consent::Input, store::Store,
};
use rusqlite::{Connection, OptionalExtension};
use serde_json::{Value, json};

fn db(_: rusqlite::Error) -> Error {
    Error::new("internal")
}
fn bytes(v: &Value) -> Result<Vec<u8>> {
    serde_json::to_vec(v).map_err(|_| Error::new("internal"))
}
fn digest(domain: &str, v: &Value) -> String {
    format!(
        "review_{}",
        hash(format!("{domain}\n{}", crate::canonical::value_text(v)).as_bytes())
    )
}
fn review_id(v: &Value) -> String {
    digest("peerspan-machine-owner-consent-v1", v)
}
fn inspection_id(v: &Value) -> String {
    digest("peerspan-machine-owner-inspection-v1", v)
}
fn key_for(store: &Store, p: &Pending) -> String {
    format!(
        "mrev_{}",
        hash(
            format!(
                "peerspan-machine-owner-review-key-v1\n{}",
                crate::canonical::value_text(
                    &json!({"host_id":store.identity().id,"request_id":p.id})
                )
            )
            .as_bytes()
        )
    )
}
fn latest(c: &Connection, store: &Store, p: &Pending) -> Result<Option<String>> {
    c.query_row("SELECT intent_id FROM dec_intents WHERE kind='machine_owner_review' AND json_extract(record,'$.operation_id')=?1 ORDER BY rowid DESC LIMIT 1",[key_for(store,p)],|r|r.get(0)).optional().map_err(db)
}
fn context(v: &Value) -> Result<AdapterContext> {
    let x: AdapterContext =
        serde_json::from_value(v.clone()).map_err(|_| Error::new("state_conflict"))?;
    x.validate().map_err(|_| Error::new("state_conflict"))?;
    Ok(x)
}
fn parent(c: &Connection, x: &AdapterContext, now: &str) -> Result<(Value, bool)> {
    x.project(c, stamp(now)?)
        .map_err(|_| Error::new("review_changed"))
}
fn first(i: &Intent) -> Result<Packet> {
    let t = i
        .record
        .templates
        .first()
        .ok_or_else(|| Error::new("state_conflict"))?;
    require(t.object_type == "owner_offer_packet", "state_conflict")?;
    Packet::read_template(&b64(&t.template_base64, MAX_OBJECT)?)
}
fn effects(inspection: &Value) -> Value {
    json!({"approve_owner_intent":true,"authorize_owner_offer_signature":true,
        "publish_owner_offer_after_signatures":true,"authorize_owner_finalization":true,
        "authorize_binding_and_device_signatures":true,
        "authorize_host_admission_if_folded":inspection["host_admission"]=="owner_may_fold",
        "grant_membership_now":false,"grant_machine_powers_now":false,"grant_agent_access":false,
        "authorize_requester_selection":false,"commit_request":false,"share_files":false,
        "share_conversation":false,"capability_calls":false})
}
fn inspection_effects() -> Value {
    json!({"verify_request_signature":true,"inspect_current_owner_authority":true,
        "prepare_owner_intent":false,"approve_owner_intent":false,"sign_owner_offer":false,
        "publish_owner_offer":false,"grant_membership":false,"grant_machine_powers":false,
        "grant_agent_access":false,"commit_request":false,"share_files":false,
        "share_conversation":false,"capability_calls":false})
}
// Bind the frozen public terms to the retained signed request and immutable
// first offer, never to the mutable finalization-stage review/root field.
fn bindings(store: &Store, p: &Pending, i: &Intent, v: &Value) -> Result<()> {
    fields(
        object(v)?,
        "version kind host_id context agent network root_state_id request_id request_packet_id person_public_key host_public_key device_public_key member person_lease_id local_host provider provider_id signature_format scopes not_after host_admission created_at expires_at effects",
    )?;
    let r = &i.record;
    let offer = first(i)?;
    let request = p.packet()?;
    let o = object(v)?;
    let provider = object(&v["provider"])?;
    fields(
        provider,
        "kind person_public_key host_public_key device_public_key lease_id root_state_id scopes not_after",
    )?;
    let network = object(&v["network"])?;
    fields(network, "id name context_id genesis_root_public_key")?;
    let d = ceremony::descriptor(p)?;
    let device = r.provider.kind == "device";
    let expected_id = if device {
        &r.provider.lease_id
    } else {
        &r.person_public_key
    };
    let mut issuer_ids = vec![text(o, "person_lease_id")?.to_owned()];
    if device {
        issuer_ids.push(r.provider.lease_id.clone());
    }
    issuer_ids.sort();
    require(
        v["version"] == 1
            && v["kind"] == "inspect_existing_person_machine"
            && v["host_id"] == store.identity().id
            && v["request_id"] == p.id
            && v["request_packet_id"] == request.id
            && r.person_public_key == p.record.expected_person_public_key
            && d.network_id == p.record.expected_network_id
            && d.context_id() == p.record.expected_context_id
            && (device || r.provider.signer_public_key == r.person_public_key)
            && v["person_public_key"] == r.person_public_key
            && v["host_public_key"] == r.host_public_key
            && v["device_public_key"] == r.device_public_key
            && v["network"]
                == json!({"id":d.network_id,"name":d.name,"context_id":d.context_id(),"genesis_root_public_key":d.genesis_root_public_key})
            && v["root_state_id"] == offer.payload["root_state_id"]
            && ident(text(o, "root_state_id")?, "ds_")
            && v["person_lease_id"] == offer.payload["person_lease_id"]
            && offer.payload["issuer_lease_ids"] == json!(issuer_ids)
            && v["member"] == offer.payload["member"]
            && v["provider_id"] == *expected_id
            && v["signature_format"] == r.provider.signature_format
            && v["scopes"] == 7
            && r.scopes == 7
            && v["not_after"] == r.not_after
            && v["created_at"] == request.payload["created_at"]
            && v["expires_at"] == p.deadline
            && v["effects"] == inspection_effects()
            && provider["kind"] == if device { "device" } else { "original_person" }
            && provider["person_public_key"] == r.person_public_key
            && provider["host_public_key"] == store.identity().public_key
            && provider["device_public_key"]
                == if device {
                    r.provider.signer_public_key.as_str()
                } else {
                    "-"
                }
            && provider["lease_id"]
                == if device {
                    r.provider.lease_id.as_str()
                } else {
                    text(o, "person_lease_id")?
                }
            && provider["root_state_id"] == v["root_state_id"]
            && num(provider, "scopes")? & 7 == 7
            && v["host_admission"]
                == if num(provider, "scopes")? & 8 == 8 {
                    "owner_may_fold"
                } else {
                    "separate_administrator_required"
                }
            && stamp(text(o, "not_after")?)?
                == (stamp(text(&request.payload, "created_at")?)? + chrono::TimeDelta::days(7))
                    .min(stamp(text(provider, "not_after")?)?),
        "state_conflict",
    )?;
    let local = object(&v["local_host"])?;
    require(
        local.get("host_public_key") == Some(&json!(store.identity().public_key))
            && local.get("person_public_key") == Some(&json!(r.person_public_key)),
        "state_conflict",
    )?;
    context(&v["context"])?;
    Ok(())
}
fn matching(c: &Connection, store: &Store, p: &Pending, inspection: &Value) -> Result<Intent> {
    let i = ceremony::owner_intent(c, p)?;
    require(
        !i.record.approved
            && i.record.signatures.is_empty()
            && !i.record.completed
            && i.record.terminal == "-"
            && ceremony::read_review(&i)?["stage"] == "owner",
        "state_conflict",
    )?;
    bindings(store, p, &i, inspection)?;
    require(
        ceremony::read_review(&i)?["provider"] == inspection["provider"],
        "state_conflict",
    )?;
    Ok(i)
}
fn current(c: &Connection, store: &Store, input: &Input, p: &Pending, now: &str) -> Result<Value> {
    let v = crate::onboarding_machine::inspect_in(
        c,
        store,
        &Inspect {
            context: input.context.clone(),
            request_id: p.id.clone(),
        },
        p,
        Some(now),
    )
    .map_err(|_| Error::new("review_changed"))?;
    if p.record.owner_intent_id != "-" {
        matching(c, store, p, &v["review"])?;
    }
    Ok(json!({"review_id":v["review_id"],"review":v["review"]}))
}
fn make_review(
    store: &Store,
    p: &Pending,
    owner: &Intent,
    meta: &Intent,
    inspection: &Value,
    replaces: &str,
    stage_deadline: &str,
) -> Result<Value> {
    let end = (stamp(&owner.record.created_at)? + chrono::TimeDelta::seconds(300))
        .min(stamp(&p.deadline)?)
        .min(stamp(stage_deadline)?)
        .min(stamp(&owner.record.not_after)?);
    let expires = end.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    require(stamp(&meta.record.created_at)? < end, "review_expired")?;
    Ok(
        json!({"version":1,"kind":"approve_existing_person_machine","consent_id":meta.id,
        "host_id":store.identity().id,"context":inspection["context"],"agent":inspection["agent"],
        "request_id":p.id,"request_packet_id":p.packet()?.id,
        "inspection_review_id":inspection_id(inspection),"inspection":inspection,
        "intent_id":owner.id,"proposed_owner_offer_id":first(owner)?.id,
        "replaces_consent_id":replaces,"created_at":meta.record.created_at,
        "expires_at":expires,"request_stage_deadline":stage_deadline,"effects":effects(inspection)}),
    )
}
fn meta_record(
    store: &Store,
    p: &Pending,
    owner: &Intent,
    review: &Value,
    approved: bool,
    approved_at: &str,
) -> Result<Record> {
    let mut r = owner.record.clone();
    r.operation_id = key_for(store, p);
    r.approved = approved;
    r.approved_at = approved_at.into();
    r.review_base64 = encode(crate::canonical::value_text(review).as_bytes());
    // The ordinary root field may advance at finalization. The reviewed root
    // belongs to the original immutable offer.
    r.root_state_id = text(&first(owner)?.payload, "root_state_id")?.into();
    r.created_at = text(object(review)?, "created_at")?.into();
    r.expires_at = text(object(review)?, "expires_at")?.into();
    r.templates.clear();
    r.signatures.clear();
    r.completed = true;
    r.terminal = "-".into();
    r.result_base64 = "-".into();
    Ok(r)
}
struct Receipt {
    meta: Intent,
    owner: Intent,
    review: Value,
}
fn load(c: &Connection, store: &Store, p: &Pending, id: &str, now: &str) -> Result<Receipt> {
    let meta = Intent::load(c, id)?;
    require(
        meta.kind == "machine_owner_review" && meta.record.operation_id == key_for(store, p),
        "not_found",
    )?;
    let owner = ceremony::owner_intent(c, p).map_err(|_| Error::new("state_conflict"))?;
    let v = parse(&b64(&meta.record.review_base64, 1 << 20)?, 1 << 20)?;
    let o = object(&v)?;
    fields(
        o,
        "version kind consent_id host_id context agent request_id request_packet_id inspection_review_id inspection intent_id proposed_owner_offer_id replaces_consent_id created_at expires_at request_stage_deadline effects",
    )?;
    bindings(store, p, &owner, &v["inspection"])?;
    let ctx = context(&v["context"])?;
    let (retained_parent, _) = parent(c, &ctx, now).map_err(|_| Error::new("state_conflict"))?;
    require(
        retained_parent["agent"] == v["agent"] && now >= meta.record.created_at.as_str(),
        "state_conflict",
    )?;
    let stage = text(o, "request_stage_deadline")?;
    let signed_created = stamp(text(&p.packet()?.payload, "created_at")?)?;
    require(
        stamp(stage)? >= signed_created + chrono::TimeDelta::seconds(600)
            && stamp(stage)? <= stamp(&meta.record.created_at)? + chrono::TimeDelta::seconds(600),
        "state_conflict",
    )?;
    let replaces = text(o, "replaces_consent_id")?;
    if replaces != "-" {
        let old = Intent::load(c, replaces).map_err(|_| Error::new("state_conflict"))?;
        let row = |id: &str| {
            c.query_row(
                "SELECT rowid FROM dec_intents WHERE intent_id=?1",
                [id],
                |r| r.get::<_, i64>(0),
            )
            .map_err(db)
        };
        require(
            old.kind == meta.kind
                && old.record.operation_id == meta.record.operation_id
                && row(replaces)? < row(id)?,
            "state_conflict",
        )?;
    }
    let expected = make_review(store, p, &owner, &meta, &v["inspection"], replaces, stage)?;
    require(
        v == expected
            && meta.network_id == owner.network_id
            && meta.context_id == owner.context_id
            && serde_json::to_value(&meta.record).map_err(|_| Error::new("internal"))?
                == serde_json::to_value(meta_record(
                    store,
                    p,
                    &owner,
                    &v,
                    meta.record.approved,
                    &meta.record.approved_at,
                )?)
                .map_err(|_| Error::new("internal"))?,
        "state_conflict",
    )?;
    if meta.record.approved {
        require(
            owner.record.approved && owner.record.approved_at == meta.record.approved_at,
            "state_conflict",
        )?;
    }
    Ok(Receipt {
        meta,
        owner,
        review: v,
    })
}
fn live(
    c: &Connection,
    store: &Store,
    input: &Input,
    p: &Pending,
    r: &Receipt,
    now: &str,
) -> Result<()> {
    require(
        r.review["context"]
            == serde_json::to_value(&input.context).map_err(|_| Error::new("internal"))?,
        "review_changed",
    )?;
    require(now >= r.meta.record.created_at.as_str(), "review_changed")?;
    require(now < r.meta.record.expires_at.as_str(), "review_expired")?;
    let inspection = current(c, store, input, p, now)?;
    require(
        inspection["review_id"] == r.review["inspection_review_id"],
        "review_changed",
    )?;
    Ok(())
}
fn state(
    c: &Connection,
    store: &Store,
    input: &Input,
    p: &Pending,
    r: &Receipt,
    latest: Option<&str>,
    now: &str,
) -> Result<&'static str> {
    if r.meta.record.approved {
        return Ok("approved");
    }
    if p.record.terminal == "cancelled" || r.owner.record.terminal == "cancelled" {
        return Ok("cancelled");
    }
    if now >= r.meta.record.expires_at.as_str() || now >= p.deadline.as_str() {
        return Ok("expired");
    }
    let mut recorded = input.clone();
    recorded.context = context(&r.review["context"])?;
    if latest != Some(r.meta.id.as_str()) || live(c, store, &recorded, p, r, now).is_err() {
        return Ok("invalidated");
    }
    Ok("review")
}
fn view(
    c: &Connection,
    store: &Store,
    input: &Input,
    p: &Pending,
    r: &Receipt,
    latest: Option<&str>,
    now: &str,
) -> Result<Value> {
    let s = state(c, store, input, p, r, latest, now)?;
    Ok(
        json!({"consent_id":r.meta.id,"review_id":review_id(&r.review),"review":r.review,"state":s,
        "next_action":match s {"review"=>"approve_machine_owner_intent","approved"=>"follow_machine_link",_=>"inspect_machine_link"}}),
    )
}
fn wrapper(
    c: &Connection,
    store: &Store,
    input: &Input,
    p: &Pending,
    r: Option<&Receipt>,
    latest: Option<&str>,
    now: &str,
) -> Result<Value> {
    // Even a historically authorized reader sees only a currently verifiable
    // inspection; history does not fabricate current authority/readiness.
    let inspection = current(c, store, input, p, now).unwrap_or(Value::Null);
    let consent = r
        .map(|r| view(c, store, input, p, r, latest, now))
        .transpose()?
        .unwrap_or(Value::Null);
    let v = json!({"version":1,"host_id":store.identity().id,"context":input.context,
        "observed_at":now,"request":p.view(now)?,"inspection":inspection,"consent":consent});
    require(
        crate::onboarding_admission::safe(&v) && bytes(&v)?.len() <= 2 << 20,
        "state_conflict",
    )?;
    Ok(v)
}
pub(crate) fn run(c: &Connection, store: &Store, op: &str, input: &Input) -> Result<(Value, bool)> {
    let mut p = requests::load(c, &input.request_id)?;
    let raw = controls::local_decision_time()?;
    let now = controls::guarded_decision(c, &p.record.expected_network_id, &raw)?;
    let latest = latest(c, store, &p)?;
    let id = if op == "lookup" {
        input.consent_id.as_deref().or(latest.as_deref())
    } else if op == "approve" {
        input.consent_id.as_deref()
    } else {
        latest.as_deref()
    };
    let mut receipt = id.map(|id| load(c, store, &p, id, &now)).transpose()?;
    let same_context = receipt
        .as_ref()
        .is_some_and(|r| r.review["context"] == json!(input.context));
    require(
        same_context || parent(c, &input.context, &now)?.1,
        "review_changed",
    )?;
    if op == "lookup" {
        return Ok((
            wrapper(
                c,
                store,
                input,
                &p,
                receipt.as_ref(),
                latest.as_deref(),
                &now,
            )?,
            false,
        ));
    }
    if op == "approve" {
        let r = receipt.as_mut().ok_or_else(|| Error::new("not_found"))?;
        require(
            latest.as_deref() == Some(r.meta.id.as_str())
                && same_context
                && input.consent_review_id.as_deref() == Some(review_id(&r.review).as_str()),
            "review_changed",
        )?;
        let changed = !r.meta.record.approved;
        if changed {
            require(!r.owner.record.approved, "review_changed")?;
            live(c, store, input, &p, r, &now)?;
            ceremony::validate_owner_live(c, store, &p, &r.owner)
                .map_err(|_| Error::new("review_changed"))?;
            r.owner.record.approved = true;
            r.owner.record.approved_at = now.clone();
            r.meta.record.approved = true;
            r.meta.record.approved_at = now.clone();
            r.owner.save(c)?;
            r.meta.save(c)?;
            controls::remember_decision(c, &r.owner.network_id, &now)?;
        }
        return Ok((
            wrapper(c, store, input, &p, Some(r), latest.as_deref(), &now)?,
            changed,
        ));
    }
    require(op == "prepare", "invalid")?;
    if let Some(r) = &receipt {
        let same = same_context
            && input.inspection_review_id.as_deref() == r.review["inspection_review_id"].as_str();
        match input.replace_consent_id.as_deref() {
            None => {
                require(same, "review_changed")?;
                return Ok((
                    wrapper(c, store, input, &p, Some(r), latest.as_deref(), &now)?,
                    false,
                ));
            }
            Some(old) if r.review["replaces_consent_id"] == old => {
                require(same, "review_changed")?;
                return Ok((
                    wrapper(c, store, input, &p, Some(r), latest.as_deref(), &now)?,
                    false,
                ));
            }
            Some(old) if old == r.meta.id => {
                require(
                    !r.meta.record.approved
                        && !r.owner.record.approved
                        && state(c, store, input, &p, r, latest.as_deref(), &now)? != "review",
                    "review_changed",
                )?;
            }
            _ => return Err(Error::new("review_changed")),
        }
    } else {
        require(input.replace_consent_id.is_none(), "review_changed")?;
    }
    let inspection = current(c, store, input, &p, &now)?;
    require(
        input.inspection_review_id.as_deref() == inspection["review_id"].as_str(),
        "review_changed",
    )?;
    let frozen = &inspection["review"];
    let owner = if p.record.owner_intent_id != "-" {
        let owner = matching(c, store, &p, frozen)?;
        ceremony::validate_owner_live(c, store, &p, &owner)
            .map_err(|_| Error::new("review_changed"))?;
        owner
    } else {
        let code = p
            .code(c, &now)?
            .ok_or_else(|| Error::new("state_conflict"))?;
        ceremony::owner_in(
            store,
            c,
            object(&json!({"code":code,"network_id":frozen["network"]["id"],
            "person_public_key":frozen["person_public_key"],"provider_id":frozen["provider_id"],
            "signature_format":frozen["signature_format"],"scopes":7,"not_after":frozen["not_after"],
            "expected_host_public_key":frozen["host_public_key"],"expected_device_public_key":frozen["device_public_key"],"approve":false}))?,
            |_| Ok(()),
        )?;
        p = requests::load(c, &p.id)?;
        matching(c, store, &p, frozen)?
    };
    if let Some(old) = &receipt {
        require(
            old.owner.id == owner.id && first(&old.owner)?.id == first(&owner)?.id,
            "review_changed",
        )?;
    }
    let stage = if p.record.stage_at == "-" {
        text(&p.packet()?.payload, "created_at")?.to_owned()
    } else {
        p.record.stage_at.clone()
    };
    let stage_deadline = (stamp(&stage)? + chrono::TimeDelta::seconds(600))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let mut meta = Intent {
        id: crate::store::new_id("dint").map_err(|_| Error::new("internal"))?,
        network_id: owner.network_id.clone(),
        context_id: owner.context_id.clone(),
        kind: "machine_owner_review".into(),
        secret: None,
        record: owner.record.clone(),
    };
    meta.record.created_at = now.clone();
    let review = make_review(
        store,
        &p,
        &owner,
        &meta,
        frozen,
        input.replace_consent_id.as_deref().unwrap_or("-"),
        &stage_deadline,
    )?;
    meta.record = meta_record(store, &p, &owner, &review, false, "-")?;
    let (count,total,size):(i64,i64,i64)=c.query_row("SELECT COUNT(*),(SELECT COUNT(*) FROM dec_intents),COALESCE(SUM(length(CAST(record AS BLOB))),0) FROM dec_intents WHERE kind='machine_owner_review'",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(db)?;
    require(
        count < 256
            && total < 4096
            && (size as usize)
                .checked_add(
                    bytes(
                        &serde_json::to_value(&meta.record).map_err(|_| Error::new("internal"))?,
                    )?
                    .len(),
                )
                .is_some_and(|s| s <= 16 << 20),
        "quota_exceeded",
    )?;
    meta.save(c)?;
    controls::remember_decision(c, &owner.network_id, &now)?;
    let id = meta.id.clone();
    let r = Receipt {
        meta,
        owner,
        review,
    };
    Ok((
        wrapper(c, store, input, &p, Some(&r), Some(&id), &now)?,
        true,
    ))
}
