//! Fixed native action review/signing; planning proposes payloads, never authority.
use crate::{admin::Local, cli::encoded};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, TimeDelta, Utc};
use peerspan_host::{
    decentralized::{
        Catalog, Descriptor, FixedStatement, Statement, decision_clock, local_decision_time,
    },
    persons::PersonSigner,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::{BufRead, IsTerminal, Write},
    path::Path,
};

pub(crate) fn text<'a>(v: &'a Value, field: &str) -> Result<&'a str> {
    v[field]
        .as_str()
        .with_context(|| format!("invalid native action {field}"))
}
pub(crate) fn decode(v: &str) -> Result<Vec<u8>> {
    let b = STANDARD.decode(v)?;
    ensure!(
        STANDARD.encode(&b) == v,
        "non-canonical native action bytes"
    );
    Ok(b)
}
pub(crate) fn shape(v: &Value, fields: &str) -> Result<()> {
    let o = v.as_object().context("invalid native action object")?;
    let fields: Vec<_> = fields.split_whitespace().collect();
    ensure!(
        o.len() == fields.len() && fields.iter().all(|f| o.contains_key(*f)),
        "unexpected native action fields"
    );
    Ok(())
}
pub(crate) fn stamp(v: &str) -> Result<DateTime<Utc>> {
    let t = DateTime::parse_from_rfc3339(v)?.to_utc();
    ensure!(
        t.format("%Y-%m-%dT%H:%M:%SZ").to_string() == v,
        "invalid native action UTC time"
    );
    Ok(t)
}
pub(crate) fn ident(v: &str, prefix: &str) -> bool {
    v.len() == prefix.len() + 64
        && v.starts_with(prefix)
        && v[prefix.len()..]
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
pub(crate) struct Plan {
    pub value: Value,
    pub descriptor: Descriptor,
    pub catalog: Catalog,
}
impl Plan {
    pub async fn read(local: &Local<'_>, network: &Value) -> Result<Self> {
        let id = text(network, "id")?;
        let v = local
            .get(format!("/v2/networks/{}/planning", encoded(id)))
            .await?;
        shape(&v, "network decision_time catalog streams restriction_ids")?;
        let n = &v["network"];
        ensure!(
            n["id"] == id
                && n["context_id"] == network["context_id"]
                && n["mode"] == "decentralized",
            "network changed during native review"
        );
        let d = Descriptor::read(&serde_json::to_vec(
            &json!({"format":1,"protocol":"peerspan-decentralized-v1","network_id":id,"name":n["name"],"genesis_root_public_key":n["genesis_root_public_key"]}),
        )?)?;
        ensure!(
            d.context_id() == text(n, "context_id")?,
            "native context changed"
        );
        let catalog = Catalog::read(&d, &serde_json::to_vec(&v["catalog"])?)?;
        stamp(text(&v, "decision_time")?)?;
        Ok(Self {
            value: v,
            descriptor: d,
            catalog,
        })
    }
    pub fn network(&self) -> &Value {
        &self.value["network"]
    }
    pub fn stream(&self, kind: &str, subject: &str) -> Result<(u64, Vec<String>)> {
        let streams = self.value["streams"]
            .as_array()
            .context("missing native streams")?;
        let Some(s) = streams
            .iter()
            .find(|s| s["stream_kind"] == kind && s["subject"] == subject)
        else {
            return Ok((0, Vec::new()));
        };
        let version = s["version"].as_u64().context("invalid native maximum")?;
        let ids = s["head_ids"]
            .as_array()
            .context("missing exact stream heads")?
            .iter()
            .map(|v| {
                let id = v.as_str().context("invalid native head")?;
                ensure!(ident(id, "ds_"), "invalid exact head");
                Ok(id.to_owned())
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            ids.windows(2).all(|x| x[0] < x[1]),
            "unordered native heads"
        );
        Ok((version, ids))
    }
    pub fn head(&self, kind: &str, subject: &str) -> Result<String> {
        let (_, ids) = self.stream(kind, subject)?;
        ensure!(
            ids.len() == 1,
            "missing or conflicting exact {kind} heads; repair this network"
        );
        Ok(ids[0].clone())
    }
}
pub(crate) struct Authority {
    pub provider_id: String,
    pub format: String,
    pub signer: Option<PersonSigner>,
    pub provider: Value,
    pub issuer: Value,
    pub parents: Vec<Value>,
    pub now: DateTime<Utc>,
    pub until: DateTime<Utc>,
    pub needed: u64,
    pub key: String,
}
impl Authority {
    #[allow(clippy::too_many_arguments)]
    pub async fn read(
        local: &Local<'_>,
        p: &Plan,
        selector: &str,
        original: Option<&Path>,
        root: Option<&Path>,
        needed: u64,
        root_allowed: bool,
        days: i64,
    ) -> Result<Self> {
        ensure!(
            original.is_none() || root.is_none(),
            "choose one exact root or original key"
        );
        ensure!(
            selector == "auto"
                || selector == "network_root"
                || ident(selector, "ds_")
                || decode(selector).is_ok_and(|b| b.len() == 32),
            "--signer must identify the exact original/device/root provider"
        );
        let now = stamp(&decision_clock(
            &local_decision_time()?,
            text(&p.value, "decision_time")?,
        )?)?;
        let mut until = now + TimeDelta::days(days);
        let mut id = selector.to_owned();
        let mut format = "auto".to_owned();
        let mut signer = None;
        if root.is_some() {
            ensure!(
                selector == "auto" || selector == "network_root",
                "root key conflicts with explicit non-root provider"
            );
            id = "network_root".into();
        }
        let n = p.network();
        let mut parents = Vec::new();
        let (provider, issuer, key) = if id == "network_root" {
            ensure!(
                root_allowed && original.is_none(),
                "root cannot substitute for this owner authority"
            );
            let key = text(n, "root_public_key")?.to_owned();
            ensure!(
                ident(text(n, "root_state_id")?, "ds_") && decode(&key)?.len() == 32,
                "unique current root required"
            );
            if let Some(path) = root {
                let s = PersonSigner::open(Some(path))?;
                ensure!(
                    s.public_key_b64() == key,
                    "external root key does not match the current root"
                );
                signer = Some(s);
                format = "sshsig".into();
            }
            (
                json!({"kind":"network_root","person_public_key":"-","host_public_key":"-","device_public_key":"-","lease_id":"-","root_state_id":n["root_state_id"],"scopes":8,"not_after":"-"}),
                json!({"kind":"root","person_public_key":"-"}),
                key,
            )
        } else {
            if let Some(path) = original {
                let s = PersonSigner::open(Some(path))?;
                let key = s.public_key_b64();
                ensure!(
                    id == "auto" || id == key,
                    "original key conflicts with explicit provider"
                );
                id = key;
                signer = Some(s);
                format = "sshsig".into();
            }
            let provider = if id == "auto" {
                ensure!(
                    n["provider_state"]["state"] == "available",
                    "selected provider requires repair; no fallback"
                );
                n["provider"].clone()
            } else {
                let v=local.post(format!("/v2/networks/{}/provider",encoded(&p.descriptor.network_id)),json!({"provider_id":id,"person_public_key":n["person_public_key"],"host_public_key":n["host_public_key"],"approve":false})).await?;
                shape(&v, "network provider provider_state")?;
                v["provider"].clone()
            };
            shape(
                &provider,
                "kind person_public_key host_public_key device_public_key lease_id root_state_id scopes not_after",
            )?;
            let kind = text(&provider, "kind")?;
            ensure!(
                matches!(kind, "original_person" | "device")
                    && provider["person_public_key"] == n["person_public_key"]
                    && provider["host_public_key"] == n["host_public_key"]
                    && provider["root_state_id"] == n["root_state_id"]
                    && provider["scopes"]
                        .as_u64()
                        .is_some_and(|s| s & needed == needed),
                "exact provider lacks current required authority"
            );
            let person = text(&provider, "person_public_key")?;
            parents.push(json!({"role":"issuer_person","id":p.head("person",person)?}));
            if needed == 8 {
                parents.push(json!({"role":"issuer_admin","id":p.head("admin",person)?}));
                until = until.min(stamp(text(&provider, "not_after")?)?);
            }
            let key = if kind == "device" {
                let d = text(&provider, "lease_id")?;
                ensure!(ident(d, "ds_"), "invalid selected device");
                parents.push(json!({"role":"issuer_device","id":d}));
                text(&provider, "device_public_key")?.to_owned()
            } else {
                person.to_owned()
            };
            let issuer = json!({"kind":if kind=="device"{"device"}else{"person"},"person_public_key":person});
            (provider, issuer, key)
        };
        fn cap(
            p: &Plan,
            id: &str,
            seen: &mut BTreeSet<String>,
            depth: usize,
            until: &mut DateTime<Utc>,
        ) -> Result<()> {
            ensure!(depth <= 32, "action ancestry exceeds bound");
            if !seen.insert(id.into()) {
                return Ok(());
            }
            let s = p.catalog.get(id)?;
            ensure!(
                s.kind.ends_with("_lease"),
                "exact finite issuer ancestry required"
            );
            let v = Value::Object(s.payload.clone());
            *until = (*until).min(stamp(text(&v, "not_after")?)?);
            for parent in v["parents"].as_array().context("missing issuer parents")? {
                cap(p, text(parent, "id")?, seen, depth + 1, until)?;
            }
            Ok(())
        }
        let mut seen = BTreeSet::new();
        for parent in &parents {
            cap(p, text(parent, "id")?, &mut seen, 0, &mut until)?;
        }
        ensure!(until > now, "authority expired");
        parents.sort_by(|a, b| a["role"].as_str().cmp(&b["role"].as_str()));
        Ok(Self {
            provider_id: id,
            format,
            signer,
            provider,
            issuer,
            parents,
            now,
            until,
            needed,
            key,
        })
    }
}
fn exact_signer(public: &str) -> Result<PersonSigner> {
    if let Some(path) = peerspan_host::persons::generated_key_path()
        && path.exists()
    {
        let signer = PersonSigner::open(Some(&path))?;
        if signer.public_key_b64() == public {
            return Ok(signer);
        }
    }
    Ok(PersonSigner::agent_with(public)?)
}
fn comparable(review: &Value) -> Value {
    let mut r = review.clone();
    r.as_object_mut().map(|o| o.remove("authority_warning"));
    r
}
fn review(v: &Value, p: &Plan, a: &Authority, s: &FixedStatement) -> Result<String> {
    shape(
        v,
        "action_id review signing_requests statement_base64 proof_id catalog delivery committed",
    )?;
    let r = &v["review"];
    shape(
        r,
        "kind statement_id provider subject sequence not_after authority_warning",
    )?;
    let typed = s.typed();
    let payload = Value::Object(typed.payload.clone());
    let seq = payload["sequence"].as_u64().unwrap_or(0);
    let subject = if payload.get("subject").is_some() {
        payload["subject"].clone()
    } else if typed.kind == "group" {
        let b: Value = serde_json::from_slice(&decode(text(&payload, "body_base64")?)?)?;
        json!({"name":b["name"]})
    } else {
        payload["target"].clone()
    };
    ensure!(
        r["kind"] == typed.kind
            && r["statement_id"] == s.statement_id()
            && r["sequence"] == seq
            && r["subject"] == subject
            && r["not_after"] == payload.get("not_after").cloned().unwrap_or(json!("-"))
            && !text(r, "authority_warning")?.is_empty(),
        "action review changes the exact typed payload"
    );
    shape(
        &r["provider"],
        "kind person_public_key host_public_key device_public_key lease_id root_state_id scopes not_after",
    )?;
    let provider = &r["provider"];
    ensure!(
        provider["root_state_id"] == p.network()["root_state_id"]
            && provider["scopes"]
                .as_u64()
                .is_some_and(|s| s & a.needed == a.needed),
        "action root or power changed"
    );
    for field in [
        "kind",
        "person_public_key",
        "host_public_key",
        "device_public_key",
        "lease_id",
    ] {
        ensure!(
            provider[field] == a.provider[field],
            "action changed provider {field}"
        );
    }
    if a.provider_id == "network_root" {
        ensure!(
            provider["scopes"] == 8 && provider["not_after"] == "-",
            "root review claims owner powers"
        );
    }
    let expected = format!(
        "act_{:x}",
        Sha256::digest(
            [
                "peerspan-decentralized-action-intent-v1",
                &p.descriptor.context_id(),
                &typed.kind,
                s.statement_id(),
                if a.provider_id == "auto" {
                    if a.provider["kind"] == "device" {
                        text(&a.provider, "lease_id")?
                    } else {
                        text(&a.provider, "person_public_key")?
                    }
                } else {
                    &a.provider_id
                }
            ]
            .join("\n")
        )
    );
    ensure!(
        v["action_id"] == expected,
        "action ID changed typed provider/payload"
    );
    Ok(expected)
}
/// Set by an administration command's `--approve` before it runs its action.
pub(crate) static APPROVED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
pub(crate) async fn run(
    local: &Local<'_>,
    p: &Plan,
    a: &Authority,
    kind: &str,
    payload: Value,
    prompt: &str,
) -> Result<Value> {
    let bytes = serde_json::to_vec(&payload)?;
    let raw = serde_json::to_vec(
        &json!({"format":1,"kind":kind,"context_id":p.descriptor.context_id(),"payload_base64":STANDARD.encode(&bytes),"signatures":[{"role":"issuer","public_key":a.key,"format":if a.format=="sshsig"||a.provider["kind"]=="original_person"{"sshsig"}else{"ed25519"},"signature":"-"}]}),
    )?;
    let fixed = FixedStatement::read(&p.descriptor, &raw)?;
    let base = format!("/v2/networks/{}/actions", encoded(&p.descriptor.network_id));
    let mut request = json!({"kind":kind,"provider_id":a.provider_id,"signature_format":a.format,"payload_base64":STANDARD.encode(&bytes),"approve":false});
    let mut value = local.post(base.clone(), request.clone()).await?;
    let id = review(&value, p, a, &fixed)?;
    eprintln!(
        "Action {id}; exact statement {}; kind {kind}\nProvider {} key {}; root {}; lease {}\nSubject {}; finite deadline {}\nExact issuer parents {}; exact payload {}\n{}",
        fixed.statement_id(),
        text(&value["review"]["provider"], "kind")?,
        a.key,
        text(p.network(), "root_state_id")?,
        text(&value["review"]["provider"], "lease_id")?,
        value["review"]["subject"],
        value["review"]["not_after"],
        json!(a.parents),
        payload,
        text(&value["review"], "authority_warning")?
    );
    eprintln!("Exact provider {}", value["review"]["provider"]);
    // `--approve` approves the displayed typed action (spec 11 "Approval
    // first"); otherwise the user answers at a terminal.
    let flagged = APPROVED.load(std::sync::atomic::Ordering::Relaxed);
    if !flagged {
        eprint!("{prompt} [y/N] ");
        std::io::stderr().flush()?;
    }
    let mut answer = String::new();
    if !flagged && !std::io::stdin().is_terminal()
        || !flagged && {
            std::io::stdin().lock().read_line(&mut answer)?;
            !answer.trim().eq_ignore_ascii_case("y") && !answer.trim().eq_ignore_ascii_case("yes")
        }
    {
        println!("{}", serde_json::to_string_pretty(&value)?);
        anyhow::bail!("action not approved; retain its exact action ID");
    }
    let original_review = value["review"].clone();
    request["approve"] = json!(true);
    let outcome=async {
        let approved=local.post(base.clone(),request).await?;
        ensure!(comparable(&approved["review"])==comparable(&original_review),"approval changed exact action review");
        review(&approved,p,a,&fixed)?;value=approved;
        let slots=value["signing_requests"].as_array().context("invalid action signing requests")?;
        if !slots.is_empty() {
            ensure!(slots.len()==1,"unexpected action signature roles");let slot=slots[0].clone();
            shape(&slot,"intent_id slot_id object_type object_id role public_key format template_base64 message_base64")?;
            ensure!(slot["slot_id"]==1 && slot["role"]=="issuer" && slot["format"]=="sshsig" && slot["public_key"]==a.key && slot["object_id"]==fixed.statement_id() && slot["object_type"]==kind,"action requested a different typed signer");
            let template=FixedStatement::read(&p.descriptor,&decode(text(&slot,"template_base64")?)?)?;
            ensure!(template.typed().payload_bytes==bytes && template.statement_id()==fixed.statement_id(),"action changed the fixed payload");
            let pending=template.pending();ensure!(pending.len()==1 && pending[0].role=="issuer" && pending[0].public_key==a.key && pending[0].signature_format=="sshsig" && pending[0].message_base64==text(&slot,"message_base64")?,"typed action message differs");
            let current=stamp(&local_decision_time()?)?;ensure!(current>=a.now && current<=a.now+TimeDelta::seconds(300) && current<a.until,"action signing window expired; preserve exact action");
            let auto;let signer=if let Some(s)=&a.signer {s}else{auto=exact_signer(&a.key)?;&auto};
            ensure!(signer.public_key_b64()==a.key,"signer lookup changed exact provider");
            let message=String::from_utf8(decode(&pending[0].message_base64)?)?;
            let signature=signer.sign(&message.split('\n').collect::<Vec<_>>())?;template.fill(&p.descriptor,"issuer",&signature)?;
            let signed=local.post(format!("{base}/{id}/signed"),json!({"intent_id":slot["intent_id"],"signatures":[{"slot_id":1,"role":"issuer","signature":signature}]})).await?;
            value=signed;
        }
        ensure!(value["action_id"]==id && value["committed"]==true && value["signing_requests"].as_array().is_some_and(|s|s.is_empty()),"action remains pending; retain its exact ID");
        ensure!(comparable(&value["review"])==comparable(&original_review),"completed action changed review");
        let final_statement=Statement::read(&p.descriptor,&decode(text(&value,"statement_base64")?)?)?;
        ensure!(final_statement.id==fixed.statement_id() && final_statement.payload_bytes==bytes && value["proof_id"]==final_statement.proof_id && final_statement.signatures.get("issuer").is_some_and(|s|s.public_key==a.key),"completed action changed exact statement/signer");
        Ok::<(),anyhow::Error>(())
    }.await;
    if let Err(e) = outcome {
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Err(e);
    }
    Ok(value)
}
