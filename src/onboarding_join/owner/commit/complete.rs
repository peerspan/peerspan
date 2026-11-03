//! One bounded continuation of existing exact approval, with pure applied replay.
use super::*;
use crate::decentralized::{self as dec, completion, controls, storage::Snapshot};
use std::time::{Duration, Instant};

#[derive(Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Decision {
    CompleteRequesterCommit,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Input {
    pub(super) context: AdapterContext,
    pub(super) join_review_id: String,
    commit_review_id: String,
    #[serde(rename = "decision")]
    _decision: Decision,
}
fn unavailable() -> Error {
    coded("commit_completion_unavailable")
}
pub(super) fn parse(value: Value) -> Result<Input, Error> {
    let input: Input = serde_json::from_value(value).map_err(|_| invalid())?;
    input.context.validate().map_err(|_| invalid())?;
    if !crate::peer_store::valid_id(&input.join_review_id, "review", 32)
        || !crate::peer_store::valid_id(&input.commit_review_id, "review", 32)
    {
        return Err(invalid());
    }
    Ok(input)
}
fn domain(e: codec::Error) -> Error {
    match e.code {
        "review_changed" => coded("review_changed"),
        "review_expired" | "expired" => coded("review_expired"),
        _ => unavailable(),
    }
}
fn into_domain(e: Error) -> codec::Error {
    let code = match e {
        Error::Coded {
            code: "review_changed",
            ..
        } => "review_changed",
        Error::Coded {
            code: "review_expired",
            ..
        } => "review_expired",
        _ => "commit_completion_unavailable",
    };
    codec::Error::new(code)
}
struct Bound {
    pending: requests::Pending,
    public: Value,
    attached: bool,
    now: DateTime<Utc>,
}
#[derive(Clone)]
struct Attempt {
    flow: String,
    input: Input,
    until: Instant,
    machine: bool,
}
impl Attempt {
    fn bound(&self, store: &Store, c: &Connection) -> Result<Bound, Error> {
        let input = OwnerContext {
            context: self.input.context.clone(),
            join_review_id: self.input.join_review_id.clone(),
        };
        if self.machine {
            let (f, mut p, attached, now) =
                bind_history(store, c, &self.flow, &input).map_err(controlled)?;
            let scope = json!({"context":f.proposal.context,"agent":f.review["agent"],
                "flow_id":f.id,"join_review_id":f.review_id});
            let (public, changed) = dec::machine_requester_consent_in(
                c,
                store,
                &mut p,
                &scope,
                "lookup",
                None,
                |p, prepared| {
                    super::super::machine_commit::inspection_in(c, store, &f, p, &input, prepared)
                        .map_err(into_domain)
                },
            )
            .map_err(domain)?;
            if changed || public["consent"].is_null() {
                return Err(unavailable());
            }
            if public["consent"]["review_id"] != self.input.commit_review_id {
                return Err(coded("review_changed"));
            }
            if public["consent"]["state"] != "approved" {
                return Err(unavailable());
            }
            return Ok(Bound {
                pending: p,
                public,
                attached,
                now,
            });
        }
        let (f, p, attached, now) = bind(store, c, &self.flow, &input).map_err(|e| match e {
            Error::NotFound | Error::Invalid(_) => e,
            Error::Coded {
                code: "review_changed" | "state_conflict" | "request_unavailable",
                ..
            } => e,
            _ => unavailable(),
        })?;
        let public = response(store, c, &f, &p, attached, now).map_err(|_| unavailable())?;
        if public["commit"].is_null() {
            return Err(unavailable());
        }
        if public["commit"]["review_id"] != self.input.commit_review_id {
            return Err(coded("review_changed"));
        }
        if public["commit"]["state"] != "approved" {
            return Err(unavailable());
        }
        Ok(Bound {
            pending: p,
            public,
            attached,
            now,
        })
    }
    fn terms<'a>(&self, public: &'a Value) -> &'a Value {
        if self.machine {
            &public["consent"]["review"]["inspection"]
        } else {
            &public["commit"]["review"]
        }
    }
    fn consent<'a>(&self, public: &'a Value) -> &'a Value {
        if self.machine {
            &public["consent"]["review"]
        } else {
            &public["commit"]["review"]
        }
    }
    fn result(&self, store: &Store, c: &Connection, b: Bound) -> Result<Option<Value>, Error> {
        if !completion::local_recorded(c, store, &b.pending).map_err(domain)? {
            return Ok(None);
        }
        let mut v = b.public;
        let p = &v["request"];
        v["completion"] = json!({"state":"locally_applied","review_id":self.input.commit_review_id,
            "manifest_id":p["manifest_id"],"activation_id":p["activation_id"],"outcome_id":p["outcome_id"],
            "participant_delivery":"not_verified","agent_access":"not_verified","connection_readiness":"not_verified"});
        if !crate::onboarding_admission::safe(&v)
            || self.machine && serde_json::to_vec(&v).map_err(|_| unavailable())?.len() > 2 << 20
        {
            return Err(unavailable());
        }
        Ok(Some(v))
    }
    /// own_application is only supplied inside the existing application TX,
    /// after its initial no-adoption check and before outcome/final commit.
    fn check(
        &self,
        store: &Store,
        c: &Connection,
        p: &requests::Pending,
        own_application: bool,
    ) -> Result<(), Error> {
        if Instant::now() >= self.until {
            return Err(unavailable());
        }
        let b = self.bound(store, c)?;
        if b.pending.id != p.id || !b.attached {
            return Err(coded("review_changed"));
        }
        let p = &b.pending;
        let r = self.terms(&b.public);
        let consent = self.consent(&b.public);
        let raw = time(&controls::local_decision_time().map_err(domain)?)?;
        if raw < time(field(&b.public["request"], "created_at")?)?
            || raw < time(field(consent, "created_at")?)?
            || p.record.stage_at != "-" && raw < time(&p.record.stage_at)?
        {
            return Err(unavailable());
        }
        let now = if self.machine {
            let guarded = controls::guarded_decision(c, field(&r["network"], "id")?, &stamp(raw))
                .map_err(domain)?;
            raw.max(b.now).max(time(&guarded)?)
        } else {
            raw.max(b.now)
        };
        if now >= time(&p.deadline)?
            || now >= time(field(r, "not_after")?)?
            || p.record.commit_packet_base64 == "-"
                && p.stage_expired(&stamp(now)).map_err(domain)?
        {
            return Err(coded("review_expired"));
        }
        if !p.record.selection_approved
            || !p.record.commit_approved
            || p.record.commit_intent_id != field(consent, "intent_id")?
            || !matches!(p.record.terminal.as_str(), "-" | "applied")
            || p.record.terminal == "applied" && !own_application
        {
            return Err(unavailable());
        }
        let mut prefix = vec!["request_created", "owner_offered", "owner_selected"];
        if !self.machine || p.record.administrator_packet_base64 != "-" {
            prefix.push("administrator_offered");
        }
        prefix.push("owner_finalized");
        if p.record.commit_packet_base64 != "-" {
            prefix.push("commit_persisted");
        }
        if p.record.terminal == "applied" {
            prefix.push("locally_applied");
        }
        if b.public["request"]["completed"] != json!(prefix) {
            return Err(unavailable());
        }
        let network = field(&r["network"], "id")?;
        if network_exists(c, network)? {
            if !own_application {
                return Err(unavailable());
            }
            let snapshot =
                Snapshot::load(c, network, &store.identity().public_key).map_err(domain)?;
            if snapshot.network.context_id != field(&r["network"], "context_id")?
                || snapshot.network.own_identity.person_public_key != field(r, "person_public_key")?
                || snapshot.network.own_identity.host_public_key != field(r, "host_public_key")?
                || snapshot
                    .project(&stamp(now))
                    .map_err(domain)?
                    .root_state_id()
                    .map_err(domain)?
                    != field(r, "root_state_id")?
            {
                return Err(coded("review_changed"));
            }
        } else if own_application {
            return Err(unavailable());
        }
        if Instant::now() >= self.until {
            return Err(unavailable());
        }
        Ok(())
    }
    fn prepare(&self, store: &Store) -> Result<(String, Option<Value>), Error> {
        let mut c = store.connection().map_err(|_| unavailable())?;
        let tx = c.transaction().map_err(|_| unavailable())?;
        let b = self.bound(store, &tx)?;
        let id = b.pending.id.clone();
        if b.pending.record.terminal == "applied" {
            return Ok((id, self.result(store, &tx, b)?));
        }
        self.check(store, &tx, &b.pending, false)?;
        Ok((id, None))
    }
    fn ready(&self, store: &Store) -> Result<Option<Value>, Error> {
        let mut c = store.connection().map_err(|_| unavailable())?;
        let tx = c.transaction().map_err(|_| unavailable())?;
        let b = self.bound(store, &tx)?;
        if b.pending.record.terminal == "applied" {
            return self.result(store, &tx, b);
        }
        self.check(store, &tx, &b.pending, false)?;
        if b.pending.record.commit_packet_base64 == "-" {
            return Err(unavailable());
        }
        let root = completion::local_current(&tx, store, &b.pending).map_err(domain)?;
        if root != field(self.terms(&b.public), "root_state_id")? {
            return Err(coded("review_changed"));
        }
        self.check(store, &tx, &b.pending, false)?;
        Ok(None)
    }
    fn can_publish(&self, store: &Store) -> Result<(), Error> {
        let mut c = store.connection().map_err(|_| unavailable())?;
        let tx = c.transaction().map_err(|_| unavailable())?;
        let b = self.bound(store, &tx)?;
        self.check(store, &tx, &b.pending, true)
    }
    fn recorded(&self, store: &Store) -> Result<Value, Error> {
        let mut c = store.connection().map_err(|_| unavailable())?;
        let tx = c.transaction().map_err(|_| unavailable())?;
        self.result(store, &tx, self.bound(store, &tx)?)?
            .ok_or_else(unavailable)
    }
}
async fn run(store: Arc<Store>, attempt: Attempt) -> Result<Value, Error> {
    let a = attempt.clone();
    let (id, cached) = blocking(store.clone(), move |s| a.prepare(s)).await?;
    if let Some(cached) = cached {
        return Ok(cached);
    }
    let a = attempt.clone();
    let request = id.clone();
    blocking(store.clone(), move |s| {
        dec::resume_commit_guarded(s, &request, Some(4), |c, p| {
            a.check(s, c, p, false).map_err(into_domain)
        })
        .map_err(domain)
    })
    .await?;
    let a = attempt.clone();
    if let Some(cached) = blocking(store.clone(), move |s| a.ready(s)).await? {
        return Ok(cached);
    }
    // Carrier failure cannot grant or prevent independently verified local apply.
    let _ = tokio::time::timeout(
        Duration::from_secs(30),
        dec::publish_request(store.clone(), &id),
    )
    .await;
    let a = attempt.clone();
    if let Some(cached) = blocking(store.clone(), move |s| a.ready(s)).await? {
        return Ok(cached);
    }
    let a = attempt.clone();
    let request = id.clone();
    blocking(store.clone(), move |s| {
        completion::apply_local_guarded(s, &request, |c, p, own| {
            a.check(s, c, p, own).map_err(into_domain)
        })
        .map_err(domain)
    })
    .await?;
    let a = attempt.clone();
    if blocking(store.clone(), move |s| a.can_publish(s))
        .await
        .is_ok()
    {
        let _ = tokio::time::timeout(
            Duration::from_secs(30),
            dec::publish_request(store.clone(), &id),
        )
        .await;
    }
    blocking(store, move |s| attempt.recorded(s)).await
}
fn controlled(error: Error) -> Error {
    match error {
        Error::NotFound => error,
        Error::Coded {
            code:
                "review_changed"
                | "state_conflict"
                | "request_unavailable"
                | "review_expired"
                | "commit_completion_unavailable",
            ..
        } => error,
        _ => unavailable(),
    }
}
async fn complete(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    if !crate::peer_store::valid_id(&id, "flow", 16) {
        return Err(invalid());
    }
    let value = decode_commit_input(&body.map_err(|_| invalid())?, "complete", false)?;
    let attempt = Attempt {
        flow: id,
        input: parse(value)?,
        until: Instant::now() + Duration::from_secs(90),
        machine: false,
    };
    tokio::time::timeout(Duration::from_secs(90), run(store, attempt))
        .await
        .map_err(|_| unavailable())?
        .map_err(controlled)
        .map(Json)
}
async fn machine_complete(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    if !crate::peer_store::valid_id(&id, "flow", 16) {
        return Err(invalid());
    }
    let value = super::super::machine_commit::decode_machine_commit_input(
        &body.map_err(|_| invalid())?,
        "complete",
        false,
    )?;
    let attempt = Attempt {
        flow: id,
        input: Input {
            context: serde_json::from_value(value["context"].clone()).map_err(|_| invalid())?,
            join_review_id: field(&value, "join_review_id")?.into(),
            commit_review_id: field(&value, "consent_review_id")?.into(),
            _decision: Decision::CompleteRequesterCommit,
        },
        until: Instant::now() + Duration::from_secs(90),
        machine: true,
    };
    tokio::time::timeout(Duration::from_secs(90), run(store, attempt))
        .await
        .map_err(|_| coded("machine_commit_completion_unavailable"))?
        .map_err(|e| match controlled(e) {
            Error::Coded {
                code: "commit_completion_unavailable",
                ..
            } => coded("machine_commit_completion_unavailable"),
            e => e,
        })
        .map(Json)
}
pub(super) fn routes() -> Router<Arc<Store>> {
    Router::new()
        .route(
            "/v1/onboarding/join-flows/{id}/commit/complete",
            post(complete),
        )
        .route(
            "/v1/onboarding/join-flows/{id}/machine-commit/complete",
            post(machine_complete),
        )
}
