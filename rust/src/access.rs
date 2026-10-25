//! Owner access policy commands that sign. The CLI fetches the owner's
//! current policy from the daemon, edits its rules, and signs the next
//! version with the person key; the daemon verifies and submits it and never
//! sees the key.
use crate::{
    admin::{Local, person_key},
    cli::{AccessCommand, Command, encoded, resolved},
    integration::DaemonError,
};
use anyhow::{Context, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, SecondsFormat, TimeDelta, Utc};
use peerspan_host::{
    persons::{self, PersonSigner},
    policy::{ACTION, ALL_AGENTS, Content, DELEGATE_ACTION, EditEntry, Policy, Rule, TASK_ACTION},
};
use serde_json::{Value, json};
use std::path::Path;

pub(crate) fn failed(e: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("{e}")
}

/// Device-backed policy commands keep original person authority distinct.
pub(crate) trait PolicySigning {
    fn public_key(&self) -> Vec<u8>;
    fn original(&self) -> Option<&PersonSigner>;
    fn device(&self) -> Option<(&str, &str)> {
        None
    }
    fn public_key_b64(&self) -> String {
        STANDARD.encode(self.public_key())
    }
}
impl PolicySigning for PersonSigner {
    fn public_key(&self) -> Vec<u8> {
        self.public_key().to_vec()
    }
    fn original(&self) -> Option<&PersonSigner> {
        Some(self)
    }
}
pub(crate) enum PolicySigner {
    Original(PersonSigner),
    Device {
        person: Vec<u8>,
        certificate: String,
        not_after: String,
    },
}
impl PolicySigner {
    pub async fn open(
        local: &Local<'_>,
        network: &str,
        path: Option<&Path>,
    ) -> anyhow::Result<Self> {
        Self::open_inner(local, network, path, false).await
    }
    pub async fn for_binding(
        local: &Local<'_>,
        network: &str,
        path: Option<&Path>,
    ) -> anyhow::Result<Self> {
        Self::open_inner(local, network, path, true).await
    }
    async fn open_inner(
        local: &Local<'_>,
        network: &str,
        path: Option<&Path>,
        allow_unbound: bool,
    ) -> anyhow::Result<Self> {
        if path.is_none() {
            match local
                .get(format!("/v1/networks/{}/link-signer", encoded(network)))
                .await
            {
                Ok(v) => {
                    let person = STANDARD.decode(
                        v["person_public_key"]
                            .as_str()
                            .context("invalid selected person")?,
                    )?;
                    anyhow::ensure!(person.len() == 32, "invalid selected person");
                    return Ok(Self::Device {
                        person,
                        certificate: v["certificate_id"]
                            .as_str()
                            .context("invalid selected certificate")?
                            .into(),
                        not_after: v["not_after"]
                            .as_str()
                            .context("invalid selected expiry")?
                            .into(),
                    });
                }
                Err(e)
                    if e.downcast_ref::<DaemonError>()
                        .is_some_and(|d| d.status == 404) => {}
                Err(e) => {
                    return Err(e).context(
                        "repair selected device authority for this person before continuing",
                    );
                }
            }
        }
        let original = PersonSigner::open(path).map_err(failed)?;
        if path.is_some() {
            match local
                .get(format!("/v1/networks/{}/link-catalog", encoded(network)))
                .await
            {
                Ok(_) => {
                    let own = local.get("/v1/host".into()).await?;
                    let members = local
                        .get(format!("/v1/networks/{}/members", encoded(network)))
                        .await?;
                    let member = members
                        .as_array()
                        .into_iter()
                        .flatten()
                        .find(|m| m["host_id"] == own["id"]);
                    let bound = member.and_then(|m| m["person_id"].as_str());
                    if allow_unbound && member.is_some() && bound.is_none() {
                        // First binding is available to host-only members. A
                        // selected but unusable device still requires repair.
                        match local
                            .get(format!("/v1/networks/{}/link-signer", encoded(network)))
                            .await
                        {
                            Err(e)
                                if e.downcast_ref::<DaemonError>()
                                    .is_some_and(|d| d.status == 404) => {}
                            Err(e) => {
                                return Err(e).context(
                                    "repair selected device authority before changing the binding",
                                );
                            }
                            Ok(_) => anyhow::bail!(
                                "repair the selected device binding before continuing"
                            ),
                        }
                    } else {
                        anyhow::ensure!(
                            bound == Some(persons::person_id(&original.public_key()).as_str()),
                            "explicit original person key must match this host's bound person"
                        );
                    }
                }
                Err(e)
                    if e.downcast_ref::<DaemonError>()
                        .is_some_and(|d| d.status == 426) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(Self::Original(original))
    }
}
impl PolicySigning for PolicySigner {
    fn public_key(&self) -> Vec<u8> {
        match self {
            Self::Original(s) => s.public_key().to_vec(),
            Self::Device { person, .. } => person.clone(),
        }
    }
    fn original(&self) -> Option<&PersonSigner> {
        match self {
            Self::Original(s) => Some(s),
            Self::Device { .. } => None,
        }
    }
    fn device(&self) -> Option<(&str, &str)> {
        match self {
            Self::Device {
                certificate,
                not_after,
                ..
            } => Some((certificate, not_after)),
            _ => None,
        }
    }
}

/// A submission refused because the stored policy or the newest
/// reservation changed since the edit started.
pub(crate) fn edit_conflict(e: &anyhow::Error) -> bool {
    e.downcast_ref::<DaemonError>()
        .is_some_and(|d| d.status == 409 && d.message.contains("edit_conflict"))
}
/// A refused edit starts again from the edit route, at most 3 times.
pub(crate) const EDIT_ATTEMPTS: usize = 4;

/// Signs policy edits for one network (coordination contract, concurrent
/// edits). On a host bound to the signer's person, each edit starts from
/// `GET /v1/networks/{id}/policy/edit` and records its reserved number in
/// `edits`. On any other host the owner's edit cannot be numbered there,
/// and it starts from the owner's stored policy instead.
pub(crate) struct Editor {
    pub network: String,
    pub host: String,
    pub person_id: String,
    numbered: bool,
    device_certificate: Option<String>,
}
/// Where one edit starts.
pub(crate) struct Start {
    pub policy: Option<Policy>,
    pub version: u64,
    seq: Option<u64>,
}
impl Editor {
    pub async fn new(
        local: &Local<'_>,
        network: &str,
        signer: &dyn PolicySigning,
    ) -> anyhow::Result<Self> {
        let me = persons::person_id(&signer.public_key());
        let host = local.get("/v1/host".into()).await?["id"]
            .as_str()
            .context("invalid daemon response")?
            .to_owned();
        let members = local
            .get(format!("/v1/networks/{}/members", encoded(network)))
            .await?;
        let numbered = members.as_array().into_iter().flatten().any(|m| {
            m["host_id"].as_str() == Some(host.as_str())
                && m["person_id"].as_str() == Some(me.as_str())
        });
        Ok(Self {
            network: network.to_owned(),
            host,
            person_id: me,
            numbered,
            device_certificate: signer.device().map(|(id, _)| id.into()),
        })
    }
    /// The starting point of the next edit.
    pub async fn start(&self, local: &Local<'_>) -> anyhow::Result<Start> {
        if self.numbered {
            let v = local
                .get(format!(
                    "/v1/networks/{}/policy/edit",
                    encoded(&self.network)
                ))
                .await?;
            return Ok(Start {
                policy: match &v["policy"] {
                    Value::Null => None,
                    p => Some(serde_json::from_value(p.clone())?),
                },
                version: v["version"].as_u64().context("invalid daemon response")?,
                seq: Some(v["seq"].as_u64().context("invalid daemon response")?),
            });
        }
        let path = format!(
            "/v1/networks/{}/policy?person={}",
            encoded(&self.network),
            encoded(&self.person_id)
        );
        let policy: Option<Policy> = match local.get(path).await {
            Ok(value) => Some(serde_json::from_value(strip_view(value))?),
            Err(e)
                if e.downcast_ref::<DaemonError>()
                    .is_some_and(|d| d.status == 404) =>
            {
                None
            }
            Err(e) => return Err(e),
        };
        Ok(Start {
            version: policy.as_ref().map_or(0, |p| p.version),
            policy,
            seq: None,
        })
    }
    /// Whether the edit route's starting policy differs in content from
    /// the stored policy, because it folded in unsettled edits.
    pub async fn folds_in(
        &self,
        local: &Local<'_>,
        start: &Option<Policy>,
    ) -> anyhow::Result<bool> {
        if !self.numbered {
            return Ok(false);
        }
        let path = format!(
            "/v1/networks/{}/policy?person={}",
            encoded(&self.network),
            encoded(&self.person_id)
        );
        let stored: Option<Policy> = match local.get(path).await {
            Ok(value) => Some(serde_json::from_value(strip_view(value))?),
            Err(e)
                if e.downcast_ref::<DaemonError>()
                    .is_some_and(|d| d.status == 404) =>
            {
                None
            }
            Err(e) => return Err(e),
        };
        let content = |p: &Option<Policy>| {
            p.as_ref().map(|p| {
                let mut c = p.content();
                c.trusted_hosts.sort();
                c
            })
        };
        Ok(content(start) != content(&stored))
    }
    /// Signs `content` as the next version after `start`, valid for
    /// `duration` or the starting policy's duration. An edit sets this
    /// host's `edits` entry to its reserved number; a renewal (`edit`
    /// false) copies the entries.
    pub fn sign(
        &self,
        signer: &dyn PolicySigning,
        start: &Start,
        mut content: Content,
        duration: Option<TimeDelta>,
        edit: bool,
    ) -> anyhow::Result<Policy> {
        // Identical duplicate rules of a version 1 policy become one.
        content.dedup_rules();
        let duration = match (duration, &start.policy) {
            (Some(d), _) => d,
            (None, Some(p)) => duration_of(p)?,
            (None, None) => TimeDelta::days(peerspan_host::policy::DEFAULT_VALID_DAYS),
        };
        let edits = match (&start.policy, start.seq) {
            (Some(p), Some(seq)) if edit => p.edits_with(&self.host, seq),
            (None, Some(seq)) if edit => vec![EditEntry {
                host: self.host.clone(),
                seq,
            }],
            (Some(p), _) => p.edits().to_vec(),
            (None, _) => Vec::new(),
        };
        let now = Utc::now();
        let version = start
            .version
            .checked_add(1)
            .context("access version exhausted")?;
        if let Some(original) = signer.original() {
            return Policy::sign_v2(
                original,
                &self.network,
                version,
                &at(now),
                &at(now + duration),
                content,
                edits,
            )
            .map_err(failed);
        }
        let (_, not_after) = signer.device().context("missing selected provider")?;
        let until =
            (now + duration).min(DateTime::parse_from_rfc3339(not_after)?.with_timezone(&Utc));
        anyhow::ensure!(
            until > now,
            "selected device authority has expired; renew this person's device"
        );
        Ok(Policy {
            format: Some(2),
            network_id: self.network.clone(),
            person_public_key: signer.public_key_b64(),
            version,
            issued_at: at(now),
            valid_until: at(until),
            rules: content.rules,
            capability_rules: Some(content.capability_rules),
            trusted_hosts: Some(content.trusted_hosts),
            edits: Some(edits),
            signature: "-".into(),
        })
    }
    /// Submits a signed policy.
    pub async fn submit(&self, local: &Local<'_>, policy: &Policy) -> anyhow::Result<Value> {
        if let Some(certificate) = &self.device_certificate {
            let mut payload = serde_json::to_value(policy)?;
            payload
                .as_object_mut()
                .context("invalid policy")?
                .remove("signature");
            local.post(format!("/v1/networks/{}/link-actions", encoded(&self.network)), json!({"kind":"peerspan-policy-v2","payload_base64":STANDARD.encode(serde_json::to_vec(&payload)?),"certificate_id":certificate})).await?;
            return local
                .get(format!(
                    "/v1/networks/{}/policy?person={}",
                    encoded(&self.network),
                    encoded(&self.person_id)
                ))
                .await;
        }
        local
            .post(
                format!("/v1/networks/{}/policy", encoded(&self.network)),
                json!({ "policy": policy }),
            )
            .await
    }
}

pub async fn command(command: &AccessCommand, socket: &Path) -> anyhow::Result<Option<Value>> {
    let (network, person_key_path) = match command {
        AccessCommand::Allow {
            network,
            person_key,
            ..
        }
        | AccessCommand::Deny {
            network,
            person_key,
            ..
        }
        | AccessCommand::Renew {
            network,
            person_key,
        } => (network, person_key),
        _ => return Ok(None),
    };
    let network = resolved(network);
    let local = Local(socket);
    let signer = PolicySigner::open(&local, network, person_key_path.as_deref()).await?;
    // Principals resolve once; the edit itself may start again.
    let mut resolved_principals = Vec::new();
    match command {
        AccessCommand::Allow { principal, .. } | AccessCommand::Deny { principal, .. } => {
            for given in principal {
                let r = resolve(&local, network, given).await?;
                if !resolved_principals.contains(&r) {
                    resolved_principals.push(r);
                }
            }
        }
        _ => {}
    }
    let editor = Editor::new(&local, network, &signer).await?;
    let mut attempt = 0;
    loop {
        attempt += 1;
        let start = editor.start(&local).await?;
        let current = &start.policy;
        let mut duration = None;
        let mut rules = current
            .as_ref()
            .map(|p| p.rules.clone())
            .unwrap_or_default();
        let mut edit = true;
        match command {
            AccessCommand::Allow {
                agent,
                max_message_bytes,
                allow_disconnected,
                valid_days,
                actions,
                max_artifact_bytes,
                ..
            } => {
                let rule = Rule {
                    agent: agent.clone(),
                    principals: resolved_principals.clone(),
                    actions: if actions.is_empty() {
                        vec![ACTION.into()]
                    } else {
                        let mut unique = Vec::new();
                        for a in actions {
                            if !unique.contains(a) {
                                unique.push(a.clone());
                            }
                        }
                        unique
                    },
                    max_message_bytes: *max_message_bytes,
                    allow_disconnected: *allow_disconnected,
                    max_artifact_bytes: *max_artifact_bytes,
                };
                // Several rules for the agent become one, at the first's place.
                match rules.iter().position(|r| r.agent == *agent) {
                    Some(first) => {
                        rules[first] = rule;
                        let mut index = 0;
                        rules.retain(|r| {
                            index += 1;
                            index - 1 == first || r.agent != *agent
                        });
                    }
                    None => rules.push(rule),
                }
                duration = Some(TimeDelta::days(*valid_days));
            }
            AccessCommand::Deny {
                agent, principal, ..
            } => {
                if current.is_none() {
                    bail!("you have no policy in this network");
                }
                if !rules.iter().any(|r| r.agent == *agent) {
                    bail!("your policy has no rule for agent {agent:?}");
                }
                if principal.is_empty() {
                    rules.retain(|r| r.agent != *agent);
                } else {
                    for rule in rules.iter_mut().filter(|r| r.agent == *agent) {
                        rule.principals.retain(|p| !resolved_principals.contains(p));
                    }
                    rules.retain(|r| r.agent != *agent || !r.principals.is_empty());
                }
            }
            AccessCommand::Renew { .. } => {
                if current.is_none() {
                    bail!("you have no policy in this network");
                }
                // A renewal is not an edit, but it starts from the edit
                // route: when that folded in unsettled edits, it re-applies
                // them as an edit, so this host's entry advances and they
                // settle.
                edit = editor.folds_in(&local, current).await?;
            }
            _ => unreachable!("not a signing access command"),
        }
        let policy = editor.sign(&signer, &start, kept(current, rules), duration, edit)?;
        match editor.submit(&local, &policy).await {
            Err(e) if edit_conflict(&e) && attempt < EDIT_ATTEMPTS => continue,
            outcome => return Ok(Some(outcome?)),
        }
    }
}

/// New rules with the current policy's tool rules and trusted hosts.
pub(crate) fn kept(current: &Option<Policy>, rules: Vec<Rule>) -> Content {
    let mut content = current.as_ref().map(Policy::content).unwrap_or_default();
    content.rules = rules;
    content
}

pub(crate) fn at(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// `access show` adds `expires_soon` beside the policy fields.
pub(crate) fn strip_view(mut value: Value) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.remove("expires_soon");
        object.remove("authorization_base64");
    }
    value
}

pub(crate) fn duration_of(p: &Policy) -> anyhow::Result<TimeDelta> {
    let issued = DateTime::parse_from_rfc3339(&p.issued_at)?;
    let until = DateTime::parse_from_rfc3339(&p.valid_until)?;
    Ok(until - issued)
}

/// Resolves `person:LABEL` (or a public key) to `person:<ID>`, erroring on an
/// ambiguous label. Other principals pass through for the daemon to check.
async fn resolve(local: &Local<'_>, network: &str, given: &str) -> anyhow::Result<String> {
    let Some(person) = given.strip_prefix("person:") else {
        return Ok(given.to_owned());
    };
    if is_person_id(person) {
        return Ok(given.to_owned());
    }
    let key = synced_person_key(local, network, person).await?;
    Ok(format!(
        "person:{}",
        persons::person_id_of(&key).map_err(failed)?
    ))
}

/// Resolves a person as `person_key` does, but when it is not a current
/// person, syncs the network once and resolves again before failing: a
/// person admitted moments ago elsewhere may not have reached this host yet.
async fn synced_person_key(
    local: &Local<'_>,
    network: &str,
    given: &str,
) -> anyhow::Result<String> {
    let first = person_key(local, network, given).await;
    match &first {
        Err(e) if e.to_string().starts_with("no current person") => {
            // A failed sync leaves the first answer.
            if local
                .post(format!("/v1/networks/{}/sync", encoded(network)), json!({}))
                .await
                .is_err()
            {
                return first;
            }
            person_key(local, network, given).await
        }
        _ => first,
    }
}

fn is_person_id(value: &str) -> bool {
    value.strip_prefix("person_").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// The largest `--files` bound: 1 GiB.
const SIZE_LIMIT: i64 = peerspan_host::artifact::MAX_BOUND;

/// A byte count with an optional `K`, `M`, or `G` suffix (powers of 1024),
/// from 1 byte to 1 GiB.
pub fn parse_size(value: &str) -> anyhow::Result<i64> {
    let invalid = || {
        anyhow::anyhow!(
            "invalid size {value:?}: give 1 to {SIZE_LIMIT} bytes, with an optional K, M, or G suffix"
        )
    };
    let (digits, unit) = match value.as_bytes().last() {
        Some(b'K') => (&value[..value.len() - 1], 1i64 << 10),
        Some(b'M') => (&value[..value.len() - 1], 1 << 20),
        Some(b'G') => (&value[..value.len() - 1], 1 << 30),
        _ => (value, 1),
    };
    if digits.is_empty() || digits.len() > 10 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    let n: i64 = digits.parse().map_err(|_| invalid())?;
    if n < 1 || n > SIZE_LIMIT / unit {
        return Err(invalid());
    }
    Ok(n * unit)
}

/// The PRINCIPAL of `allow` and `deny`: `everyone` or `network`,
/// `group:NAME`, `agent:HOST/AGENT`, or `person:PERSON` or a bare PERSON,
/// resolved among the network's current persons.
pub(crate) async fn top_principal(
    local: &Local<'_>,
    network: &str,
    given: &str,
) -> anyhow::Result<String> {
    if given == "everyone" || given == "network" {
        return Ok("network".into());
    }
    if given.starts_with("group:") || given.starts_with("agent:") {
        return Ok(given.to_owned());
    }
    let person = given.strip_prefix("person:").unwrap_or(given);
    let key = synced_person_key(local, network, person).await?;
    Ok(format!(
        "person:{}",
        persons::person_id_of(&key).map_err(failed)?
    ))
}

/// A `--with` value of `share` and `unshare`, or the PRINCIPAL of `allow`
/// and `deny`: an agent address (`PERSON/AGENT` or `HOST_ID/AGENT`)
/// resolved through the daemon's lookup route, syncing the network once
/// when the person or host is not known yet, or any other principal.
/// Returns the principal and, for an agent address, the lookup's answer.
pub(crate) async fn recipient(
    local: &Local<'_>,
    network: &str,
    given: &str,
) -> anyhow::Result<(String, Option<Value>)> {
    match peerspan_host::agent_lookup::split_agent_address(given) {
        Err(e) => bail!(e),
        Ok(None) => Ok((top_principal(local, network, given).await?, None)),
        Ok(Some(_)) => {
            let path = format!(
                "/v1/agent-lookup?address={}&network={}",
                encoded(given),
                encoded(network)
            );
            let found = match local.get(path.clone()).await {
                Err(e)
                    if e.downcast_ref::<DaemonError>().is_some_and(|d| {
                        d.code == "unknown_person" || d.code == "unknown_host"
                    }) =>
                {
                    local
                        .post(format!("/v1/networks/{}/sync", encoded(network)), json!({}))
                        .await?;
                    local.get(path).await?
                }
                other => other?,
            };
            let principal = found["principal"]
                .as_str()
                .context("invalid daemon response")?
                .to_owned();
            Ok((principal, Some(found)))
        }
    }
}

/// Whether two rules have the same actions, as sets, and the same bounds.
fn same_settings(a: &Rule, b: &Rule) -> bool {
    a.max_message_bytes == b.max_message_bytes
        && a.max_artifact_bytes == b.max_artifact_bytes
        && a.allow_disconnected == b.allow_disconnected
        && a.actions.len() == b.actions.len()
        && b.actions.iter().all(|x| a.actions.contains(x))
}

/// The top-level `allow` and `deny`. `allow` sets a principal's access for
/// one agent scope (`--agent`, default `*`): it removes the principal from
/// every rule of that scope, adds it to the first rule of the scope with
/// identical settings or appends a new rule, drops rules left without
/// principals, and signs the next version, valid for 7 days. `deny` removes
/// the principal from every rule of the scope, or of every scope without
/// `--agent`.
pub async fn top_command(command: &Command, socket: &Path) -> anyhow::Result<Option<Value>> {
    let (given, agent, network, person_key_path, allow) = match command {
        Command::Allow {
            principal,
            agent,
            network,
            person_key,
            ..
        } => (principal, Some(agent), network, person_key, true),
        Command::Deny {
            principal,
            agent,
            network,
            person_key,
            ..
        } => (principal, agent.as_ref(), network, person_key, false),
        _ => return Ok(None),
    };
    let network = resolved(network);
    let scope = agent.cloned().unwrap_or_else(|| ALL_AGENTS.to_owned());
    if peerspan_host::membership::label(&scope).is_err() {
        bail!("invalid agent name {scope:?}");
    }
    let mut rule = Rule {
        agent: scope.clone(),
        principals: Vec::new(),
        actions: vec![ACTION.into()],
        max_message_bytes: 65536,
        max_artifact_bytes: 0,
        allow_disconnected: false,
    };
    if let Command::Allow {
        no_tasks,
        files,
        delegate,
        ..
    } = command
    {
        if *no_tasks && (*delegate || files.is_some()) {
            bail!("--delegate and --files need tasks; drop --no-tasks");
        }
        if !*no_tasks {
            rule.actions.push(TASK_ACTION.into());
        }
        if *delegate {
            rule.actions.push(DELEGATE_ACTION.into());
        }
        if let Some(files) = files {
            rule.max_artifact_bytes = parse_size(files)?;
        }
    }
    let local = Local(socket);
    let signer = PolicySigner::open(&local, network, person_key_path.as_deref()).await?;
    let owner = signer.public_key_b64();
    let persons = local
        .get(format!("/v1/networks/{}/persons", encoded(network)))
        .await?;
    let me = persons
        .as_array()
        .into_iter()
        .flatten()
        .find(|p| p["public_key"].as_str() == Some(owner.as_str()))
        .and_then(|p| p["person_id"].as_str())
        .map(str::to_owned)
        .with_context(|| {
            format!(
                "the person key {} is not a current person of that network",
                persons::person_id(&signer.public_key())
            )
        })?;
    let (principal, _) = recipient(&local, network, given).await?;
    let _ = me;
    let editor = Editor::new(&local, network, &signer).await?;
    let mut attempt = 0;
    let (stored, removed) = loop {
        attempt += 1;
        let start = editor.start(&local).await?;
        let current = &start.policy;
        let scoped = allow || agent.is_some();
        let mut removed = 0;
        let mut rules: Vec<Rule> = current
            .as_ref()
            .map(|p| p.rules.clone())
            .unwrap_or_default();
        for r in &mut rules {
            if (!scoped || r.agent == scope) && r.principals.contains(&principal) {
                r.principals.retain(|p| *p != principal);
                removed += 1;
            }
        }
        if allow {
            match rules
                .iter_mut()
                .find(|r| r.agent == scope && same_settings(r, &rule))
            {
                Some(existing) => existing.principals.push(principal.clone()),
                None => {
                    let mut new = rule.clone();
                    new.principals = vec![principal.clone()];
                    rules.push(new);
                }
            }
        }
        rules.retain(|r| !r.principals.is_empty());
        let mut duration = Some(TimeDelta::days(peerspan_host::policy::DEFAULT_VALID_DAYS));
        if !allow {
            if removed == 0 {
                return Ok(Some(json!({
                    "policy": current,
                    "removed": 0,
                    "note": format!("no rule of your policy names {principal}; access through a group or everyone is unaffected, and block stops a person at once"),
                })));
            }
            duration = None;
        }
        let policy = editor.sign(&signer, &start, kept(current, rules), duration, true)?;
        match editor.submit(&local, &policy).await {
            Err(e) if edit_conflict(&e) && attempt < EDIT_ATTEMPTS => continue,
            outcome => break (outcome?, removed),
        }
    };
    Ok(Some(if allow {
        json!({
            "policy": stored,
            "principal": principal,
            "agent": scope,
            "actions": rule.actions,
            "max_artifact_bytes": rule.max_artifact_bytes,
        })
    } else {
        json!({"policy": stored, "removed": removed})
    }))
}
