//! Owner access policy (milestone 2b slice 3). An owner signs one policy per
//! network with their person key (`SSHSIG`); every host bound to that owner
//! enforces it for its local agents, next to manual grants. A host-local
//! block list overrides both. Daemons renew policies by asking the owner's
//! `ssh-agent` for a signature and never hold the key.
use crate::api::{blocking, decode};
use crate::{
    admins::group_name,
    membership::{check_network, invalid, time},
    model::Error,
    network::Member,
    peer_store::{Authz, Bounds, json},
    persons::{PersonSigner, person_id_of, verify_sshsig},
    store::{Store, append_event, now, rfc3339},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, Query, State, rejection::BytesRejection},
    http::StatusCode,
    routing::{get, post},
};
use base64::Engine;
use chrono::{DateTime, TimeDelta, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Deserializer, Serialize};
use std::sync::Arc;

/// Database version 8: the host-local block list.
pub(crate) const SCHEMA: &str = "
CREATE TABLE access_blocks (kind TEXT NOT NULL, subject TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(kind, subject));
PRAGMA user_version = 8;
";

pub const ACTION: &str = "message.append";
/// Submitting a task (milestone 6) to an agent.
pub const TASK_ACTION: &str = "task.submit";
/// Submitting a task and letting the receiving agent pass it on (milestone
/// 6 slice 4); implies `task.submit`.
pub const DELEGATE_ACTION: &str = "task.delegate";
/// The actions grants and policy rules may name.
pub const ACTIONS: [&str; 3] = [ACTION, TASK_ACTION, DELEGATE_ACTION];
/// The actions adapter routes may name.
pub const ROUTE_ACTIONS: [&str; 2] = [ACTION, TASK_ACTION];
/// Whether a granted action authorizes a requested one: `task.delegate`
/// implies `task.submit`.
pub(crate) fn allows(granted: &str, requested: &str) -> bool {
    granted == requested || (granted == DELEGATE_ACTION && requested == TASK_ACTION)
}
/// Whether actions include a task action, which artifact bounds need.
pub(crate) fn task_actions<'a>(mut actions: impl Iterator<Item = &'a str>) -> bool {
    actions.any(|a| a == TASK_ACTION || a == DELEGATE_ACTION)
}
pub const DEFAULT_VALID_DAYS: i64 = 7;
const MAX_RULES: usize = 64;
const MAX_PRINCIPALS: usize = 64;
/// Clock skew allowed before `issued_at`.
const SKEW: TimeDelta = TimeDelta::minutes(5);

/// One rule: who may perform which actions on one of the owner's agents.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub agent: String,
    pub principals: Vec<String>,
    pub actions: Vec<String>,
    pub max_message_bytes: i64,
    /// The total input and result artifact bytes a task may carry; 0 (the
    /// default, omitted in JSON) allows none.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub max_artifact_bytes: i64,
    pub allow_disconnected: bool,
}
fn is_zero(n: &i64) -> bool {
    *n == 0
}

const MAX_CAPABILITY_RULES: usize = 256;
const MAX_TRUSTED: usize = 64;
const MAX_EDITS: usize = 256;
/// The largest edit number: 2^53 - 1.
pub const MAX_EDIT_SEQ: u64 = (1 << 53) - 1;
/// The largest `max_input_bytes`, which self access also allows.
pub const MAX_INPUT_BYTES: i64 = 262_144;
pub const MAX_CALLS_PER_HOUR: i64 = 10_000;

/// A capability rule (capabilities contract, policy version 2): who may
/// call the operations of one capability on the host that serves it. A rule
/// without principals is a claim: it binds the name to the host and
/// authorizes no one.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRule {
    /// The host ID of the host that serves the capability.
    pub host: String,
    pub capability: String,
    pub principals: Vec<String>,
    pub max_input_bytes: i64,
    pub allow_disconnected: bool,
    pub max_calls_per_hour: i64,
}
impl CapabilityRule {
    /// A claim for `name` on `host`, with the default bounds.
    pub fn claim(host: &str, name: &str) -> Self {
        Self {
            host: host.into(),
            capability: name.into(),
            principals: Vec::new(),
            max_input_bytes: 65536,
            allow_disconnected: false,
            max_calls_per_hour: 100,
        }
    }
}

/// One `edits` entry (coordination contract, concurrent edits): the
/// highest number of `host`'s edits the policy reflects.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EditEntry {
    pub host: String,
    pub seq: u64,
}

/// An owner-signed access policy. Version 1 statements carry no `format`,
/// capability rules, or trusted hosts; version 2 statements carry all three.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// 2 for a `peerspan-policy-v2` statement; absent for version 1.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub format: Option<u8>,
    pub network_id: String,
    pub person_public_key: String,
    pub version: u64,
    pub issued_at: String,
    pub valid_until: String,
    pub rules: Vec<Rule>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub capability_rules: Option<Vec<CapabilityRule>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub trusted_hosts: Option<Vec<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub edits: Option<Vec<EditEntry>>,
    pub signature: String,
}

/// What a policy grants: its rules, capability rules, and trusted hosts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Content {
    pub rules: Vec<Rule>,
    pub capability_rules: Vec<CapabilityRule>,
    pub trusted_hosts: Vec<String>,
}
impl Content {
    /// Combines rules with the same agent and settings into the first of
    /// them, uniting their principals, as a version 2 policy holds at most
    /// one rule per key. Only a version 1 policy can hold such duplicates;
    /// access is unchanged.
    pub fn dedup_rules(&mut self) {
        let mut out: Vec<Rule> = Vec::new();
        for r in std::mem::take(&mut self.rules) {
            match out.iter_mut().find(|k| k.same_key(&r)) {
                Some(k) => {
                    for p in r.principals {
                        if !k.principals.contains(&p) {
                            k.principals.push(p);
                        }
                    }
                }
                None => out.push(r),
            }
        }
        self.rules = out;
    }
}

/// The owner policy a request relies on: the owner and the newest version the
/// sender has verified.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyRef {
    pub person_id: String,
    pub version: u64,
}

/// Self access (launch slice 3): the sender's bound person, which the
/// receiver must also be bound to in a shared network.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SelfRef {
    pub person_id: String,
}
/// A request's `grant_id`, `policy`, and `self` fields.
pub(crate) type RequestAuthorization = (Option<String>, Option<PolicyRef>, Option<SelfRef>);
/// What a request without a grant cites.
pub(crate) enum Citation {
    SelfAccess(SelfRef),
    Policy(Box<Policy>),
}
impl Citation {
    /// The request fields `policy` and `self`.
    pub(crate) fn fields(&self) -> (Option<PolicyRef>, Option<SelfRef>) {
        match self {
            Self::SelfAccess(s) => (None, Some(s.clone())),
            Self::Policy(p) => (Some(p.reference()), None),
        }
    }
    /// The cited policy's end, which caps a default deadline.
    pub(crate) fn valid_until(&self) -> Option<&str> {
        match self {
            Self::SelfAccess(_) => None,
            Self::Policy(p) => Some(&p.valid_until),
        }
    }
}
/// The rule agent meaning every agent of the owner. A receiver applies the
/// rules naming an agent if there are any, and otherwise the `*` rules.
pub const ALL_AGENTS: &str = "*";
/// Self access bounds: every action, up to 1 GiB of artifacts.
pub(crate) const SELF_BOUNDS: Bounds = Bounds {
    max_message_bytes: 65536,
    max_artifact_bytes: crate::artifact::MAX_BOUND,
    allow_disconnected: true,
    delegate: true,
};

/// Rejects an explicit `null`; an absent field defaults to `None`.
pub(crate) fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

pub(crate) fn person_id_shape(id: &str) -> bool {
    id.strip_prefix("person_").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
/// `agent:<host ID>/<agent ID>`, split into its host and agent.
pub(crate) fn agent_principal(value: &str) -> Option<(&str, &str)> {
    let (host, agent) = value.strip_prefix("agent:")?.split_once('/')?;
    (crate::peer_store::valid_id(host, "host", 32)
        && crate::peer_store::valid_id(agent, "agent", 16))
    .then_some((host, agent))
}
/// `person:<person ID>`, `group:<name>`, `network`, or
/// `agent:<host ID>/<agent ID>`.
pub fn principal(value: &str) -> Result<(), Error> {
    let ok = value == "network"
        || agent_principal(value).is_some()
        || value.strip_prefix("person:").is_some_and(person_id_shape)
        || value
            .strip_prefix("group:")
            .is_some_and(|g| group_name(g).is_ok());
    if ok {
        Ok(())
    } else {
        Err(invalid(&format!(
            "invalid principal {value:?}: use person:<person ID>, group:<name>, network, or agent:<host ID>/<agent ID>"
        )))
    }
}
/// Whether a principal matches an authenticated sender, its groups, and the
/// origin it asserts.
pub(crate) fn principal_matches(
    p: &str,
    sender: &Member,
    groups: &[crate::admins::Group],
    origin: Option<&crate::peer_store::Origin>,
) -> bool {
    if p == "network" {
        true
    } else if let Some(id) = p.strip_prefix("person:") {
        sender.person_id.as_deref() == Some(id)
    } else if let Some(name) = p.strip_prefix("group:") {
        sender.person_id.as_ref().is_some_and(|person| {
            groups
                .iter()
                .any(|g| g.name == name && g.members.contains(person))
        })
    } else if let Some((host, agent)) = agent_principal(p) {
        // The authenticated host asserts which of its agents originated the
        // request; it can never speak for another host's agents.
        host == sender.host_id && origin.is_some_and(|o| o.agent_id == agent)
    } else {
        false
    }
}
/// Agent names in rules are valid labels.
pub fn agent_name(value: &str) -> Result<(), Error> {
    crate::membership::label(value)
        .map_err(|_| invalid(&format!("invalid agent name {value:?} in a policy rule")))
}

impl Rule {
    /// Whether two rules have the same merge key: the agent and the
    /// settings (actions as a set, `max_message_bytes`,
    /// `max_artifact_bytes`, and `allow_disconnected`).
    pub fn same_key(&self, other: &Rule) -> bool {
        fn actions(r: &Rule) -> Vec<&str> {
            let mut a: Vec<&str> = r.actions.iter().map(String::as_str).collect();
            a.sort_unstable();
            a.dedup();
            a
        }
        self.agent == other.agent
            && self.max_message_bytes == other.max_message_bytes
            && self.max_artifact_bytes == other.max_artifact_bytes
            && self.allow_disconnected == other.allow_disconnected
            && actions(self) == actions(other)
    }
    fn check(&self) -> Result<(), Error> {
        agent_name(&self.agent)?;
        if self.principals.is_empty() || self.principals.len() > MAX_PRINCIPALS {
            return Err(invalid("a rule has 1-64 principals"));
        }
        for p in &self.principals {
            principal(p)?;
        }
        if self.actions.is_empty() || self.actions.iter().any(|a| !ACTIONS.contains(&a.as_str())) {
            return Err(invalid(
                "policy actions are message.append, task.submit, and task.delegate",
            ));
        }
        if !(1..=65536).contains(&self.max_message_bytes) {
            return Err(invalid("max_message_bytes must be 1-65536"));
        }
        crate::artifact::check_bound(
            self.max_artifact_bytes,
            task_actions(self.actions.iter().map(String::as_str)),
        )
    }
}

/// A server or capability name: `[a-z0-9][a-z0-9_-]{0,62}`.
pub fn name_shape(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-')
}
impl CapabilityRule {
    fn check(&self) -> Result<(), Error> {
        if !crate::peer_store::valid_id(&self.host, "host", 32) {
            return Err(invalid("a capability rule's host is a host ID"));
        }
        if !name_shape(&self.capability) {
            return Err(invalid(&format!(
                "invalid capability name {:?}",
                self.capability
            )));
        }
        if self.principals.len() > MAX_PRINCIPALS {
            return Err(invalid("a capability rule has 0-64 principals"));
        }
        for p in &self.principals {
            principal(p)?;
        }
        if !(1..=MAX_INPUT_BYTES).contains(&self.max_input_bytes) {
            return Err(invalid("max_input_bytes must be 1-262144"));
        }
        if !(1..=MAX_CALLS_PER_HOUR).contains(&self.max_calls_per_hour) {
            return Err(invalid("max_calls_per_hour must be 1-10000"));
        }
        Ok(())
    }
}

impl Policy {
    fn lines(&self) -> Vec<String> {
        let header = match self.format {
            Some(2) => "peerspan-policy-v2",
            _ => "peerspan-policy-v1",
        };
        let mut lines = vec![
            header.to_owned(),
            self.network_id.clone(),
            self.person_public_key.clone(),
            self.version.to_string(),
            self.issued_at.clone(),
            self.valid_until.clone(),
        ];
        for r in &self.rules {
            lines.push("rule".into());
            lines.push(r.agent.clone());
            lines.push(r.principals.join(" "));
            lines.push(r.actions.join(" "));
            // A nonzero artifact bound is appended, so policies without one
            // sign and verify unchanged.
            let mut bounds = format!("{} {}", r.max_message_bytes, r.allow_disconnected);
            if r.max_artifact_bytes != 0 {
                bounds.push_str(&format!(" {}", r.max_artifact_bytes));
            }
            lines.push(bounds);
        }
        if self.format == Some(2) {
            for r in self.capability_rules() {
                lines.push("capability_rule".into());
                lines.push(r.host.clone());
                lines.push(r.capability.clone());
                lines.push(r.principals.join(" "));
                lines.push(format!(
                    "{} {} {}",
                    r.max_input_bytes, r.allow_disconnected, r.max_calls_per_hour
                ));
                lines.push("end".into());
            }
            let mut trusted: Vec<&str> = self.trusted_hosts().iter().map(String::as_str).collect();
            trusted.sort_unstable();
            lines.push(
                std::iter::once("trusted")
                    .chain(trusted)
                    .collect::<Vec<_>>()
                    .join(" "),
            );
            let mut edits: Vec<String> = self
                .edits()
                .iter()
                .map(|e| format!("{}:{}", e.host, e.seq))
                .collect();
            edits.sort_unstable();
            lines.push(
                std::iter::once("edits".to_owned())
                    .chain(edits)
                    .collect::<Vec<_>>()
                    .join(" "),
            );
        }
        lines
    }
    /// The `edits` entries; none in a version 1 policy.
    pub fn edits(&self) -> &[EditEntry] {
        self.edits.as_deref().unwrap_or_default()
    }
    /// The highest edit number of `host` this policy reflects, or 0.
    pub fn edit_seq(&self, host: &str) -> u64 {
        self.edits()
            .iter()
            .find(|e| e.host == host)
            .map_or(0, |e| e.seq)
    }
    /// Its `edits` with `host`'s entry set to `seq`, sorted by host.
    pub fn edits_with(&self, host: &str, seq: u64) -> Vec<EditEntry> {
        let mut out: Vec<EditEntry> = self
            .edits()
            .iter()
            .filter(|e| e.host != host)
            .cloned()
            .collect();
        out.push(EditEntry {
            host: host.into(),
            seq,
        });
        out.sort_by(|a, b| a.host.cmp(&b.host));
        out
    }
    /// The signed statement's lines, as the test vectors list them.
    pub fn statement_lines(&self) -> Vec<String> {
        self.lines()
    }
    /// The capability rules; none in a version 1 policy.
    pub fn capability_rules(&self) -> &[CapabilityRule] {
        self.capability_rules.as_deref().unwrap_or_default()
    }
    /// The trusted hosts; none in a version 1 policy.
    pub fn trusted_hosts(&self) -> &[String] {
        self.trusted_hosts.as_deref().unwrap_or_default()
    }
    /// Its rules, tool rules, and trusted hosts.
    pub fn content(&self) -> Content {
        Content {
            rules: self.rules.clone(),
            capability_rules: self.capability_rules().to_vec(),
            trusted_hosts: self.trusted_hosts().to_vec(),
        }
    }
    pub(crate) fn check_shape(&self) -> Result<(), Error> {
        self.check_shape_window(86_400, 90 * 86_400)
    }
    /// New-context access windows keep all resource rules, with finite DEC bounds.
    pub(crate) fn check_decentralized_shape(&self) -> Result<(), Error> {
        self.check_shape_window(1, 86_400)
    }
    fn check_shape_window(&self, minimum: i64, maximum: i64) -> Result<(), Error> {
        if self.version < 1 {
            return Err(invalid("policy versions start at 1"));
        }
        let duration = time(&self.valid_until)? - time(&self.issued_at)?;
        if duration < TimeDelta::seconds(minimum) || duration > TimeDelta::seconds(maximum) {
            return Err(invalid(if minimum == 86_400 {
                "a policy is valid for 1-90 days"
            } else {
                "policy validity outside context window"
            }));
        }
        if self.rules.len() > MAX_RULES {
            return Err(invalid("a policy has at most 64 rules"));
        }
        for r in &self.rules {
            r.check()?;
        }
        match (
            self.format,
            &self.capability_rules,
            &self.trusted_hosts,
            &self.edits,
        ) {
            (None, None, None, None) => {}
            (Some(2), Some(capability_rules), Some(trusted), Some(edits)) => {
                if self
                    .rules
                    .iter()
                    .enumerate()
                    .any(|(i, r)| self.rules[..i].iter().any(|k| k.same_key(r)))
                {
                    return Err(invalid(
                        "a version 2 policy has no two rules with the same agent and settings",
                    ));
                }
                if capability_rules.len() > MAX_CAPABILITY_RULES {
                    return Err(invalid("a policy has at most 256 capability rules"));
                }
                if edits.len() > MAX_EDITS {
                    return Err(invalid("a policy has at most 256 edits entries"));
                }
                for e in edits {
                    if !crate::peer_store::valid_id(&e.host, "host", 32) {
                        return Err(invalid("an edits entry's host is a host ID"));
                    }
                    if !(1..=MAX_EDIT_SEQ).contains(&e.seq) {
                        return Err(invalid("an edits entry's seq is 1 to 2^53 - 1"));
                    }
                }
                let mut hosts: Vec<&str> = edits.iter().map(|e| e.host.as_str()).collect();
                hosts.sort_unstable();
                if hosts.windows(2).any(|w| w[0] == w[1]) {
                    return Err(invalid("an edits entry's host appears once"));
                }
                for r in capability_rules {
                    r.check()?;
                }
                // A name is bound to one host, by at most one rule.
                let mut names: Vec<&str> = capability_rules
                    .iter()
                    .map(|r| r.capability.as_str())
                    .collect();
                names.sort_unstable();
                if names.windows(2).any(|w| w[0] == w[1]) {
                    return Err(invalid("a policy has at most one rule per capability name"));
                }
                if trusted.len() > MAX_TRUSTED {
                    return Err(invalid("a policy has at most 64 trusted hosts"));
                }
                if trusted
                    .iter()
                    .any(|h| !crate::peer_store::valid_id(h, "host", 32))
                {
                    return Err(invalid("trusted hosts must be host IDs"));
                }
                // The statement lists them sorted; each appears once.
                let mut sorted: Vec<&String> = trusted.iter().collect();
                sorted.sort();
                if sorted.windows(2).any(|w| w[0] == w[1]) {
                    return Err(invalid("trusted hosts must be unique"));
                }
            }
            _ => {
                return Err(invalid(
                    "a version 2 policy has format 2, capability_rules, trusted_hosts, and edits; a version 1 policy has none of them",
                ));
            }
        }
        Ok(())
    }
    /// Signs a version 2 policy as `signer`, the owner. Trusted hosts and
    /// edits are stored sorted; duplicates are refused.
    pub fn sign_v2(
        signer: &PersonSigner,
        network: &str,
        version: u64,
        issued_at: &str,
        valid_until: &str,
        content: Content,
        mut edits: Vec<EditEntry>,
    ) -> Result<Self, Error> {
        let mut trusted = content.trusted_hosts;
        trusted.sort();
        edits.sort_by(|a, b| a.host.cmp(&b.host));
        let mut p = Self {
            format: Some(2),
            network_id: network.into(),
            person_public_key: signer.public_key_b64(),
            version,
            issued_at: issued_at.into(),
            valid_until: valid_until.into(),
            rules: content.rules,
            capability_rules: Some(content.capability_rules),
            trusted_hosts: Some(trusted),
            edits: Some(edits),
            signature: String::new(),
        };
        p.check_shape()?;
        let lines = p.lines();
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        p.signature = signer.sign(&refs)?;
        Ok(p)
    }
    /// Signs a version 1 policy, as older software did. Only tests still
    /// make them: the CLI and renewal always sign version 2.
    #[cfg(test)]
    pub fn sign(
        signer: &PersonSigner,
        network: &str,
        version: u64,
        issued_at: &str,
        valid_until: &str,
        rules: Vec<Rule>,
    ) -> Result<Self, Error> {
        let mut p = Self {
            format: None,
            network_id: network.into(),
            person_public_key: signer.public_key_b64(),
            version,
            issued_at: issued_at.into(),
            valid_until: valid_until.into(),
            rules,
            capability_rules: None,
            trusted_hosts: None,
            edits: None,
            signature: String::new(),
        };
        p.check_shape()?;
        let lines = p.lines();
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        p.signature = signer.sign(&refs)?;
        Ok(p)
    }
    /// The shape and the owner's signature; not the validity window.
    pub fn verify(&self, network: &str) -> Result<(), Error> {
        check_network(&self.network_id, network)?;
        self.check_shape()?;
        let lines = self.lines();
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        verify_sshsig(&self.person_public_key, &refs, &self.signature)
    }
    pub fn person_id(&self) -> String {
        person_id_of(&self.person_public_key).unwrap_or_default()
    }
    fn times(&self) -> (DateTime<Utc>, DateTime<Utc>) {
        let issued = time(&self.issued_at).unwrap_or(DateTime::<Utc>::MIN_UTC);
        let until = time(&self.valid_until).unwrap_or(DateTime::<Utc>::MIN_UTC);
        (issued, until)
    }
    /// Within its validity window, allowing 5 minutes of skew before `issued_at`.
    pub fn in_window(&self, at: DateTime<Utc>) -> bool {
        let (issued, until) = self.times();
        at >= issued - SKEW && at < until
    }
    /// Less than a quarter of its validity remains.
    pub fn expires_soon(&self, at: DateTime<Utc>) -> bool {
        let (issued, until) = self.times();
        until - at < (until - issued) / 4
    }
    /// The same rules and `edits` at version + 1, with the same duration
    /// from `at`, always signed as version 2.
    pub fn renewal(&self, signer: &PersonSigner, at: DateTime<Utc>) -> Result<Self, Error> {
        self.renewal_with(signer, at, self.edits().to_vec())
    }
    /// A renewal with the given `edits`: the stored ones without retired
    /// entries.
    pub fn renewal_with(
        &self,
        signer: &PersonSigner,
        at: DateTime<Utc>,
        edits: Vec<EditEntry>,
    ) -> Result<Self, Error> {
        let (issued, until) = self.times();
        // Identical duplicate rules of a version 1 policy become one.
        let mut content = self.content();
        content.dedup_rules();
        Self::sign_v2(
            signer,
            &self.network_id,
            self.version + 1,
            &rfc3339(at),
            &rfc3339(at + (until - issued)),
            content,
            edits,
        )
    }
    /// Its `edits` without retired entries: those of hosts for which `keep`
    /// is false.
    pub fn kept_edits(&self, keep: impl Fn(&str) -> bool) -> Vec<EditEntry> {
        self.edits()
            .iter()
            .filter(|e| keep(&e.host))
            .cloned()
            .collect()
    }
    /// Its validity duration.
    pub fn duration(&self) -> TimeDelta {
        let (issued, until) = self.times();
        until - issued
    }
    /// The lowercase hex SHA-256 of the signed statement (its lines), which
    /// breaks ties between equal versions.
    pub fn sha256(&self) -> String {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(self.lines().join("\n").as_bytes()))
    }
    /// The acceptance rule against a stored policy: a higher version, or an
    /// equal version whose statement has a lower SHA-256.
    pub fn supersedes(&self, stored: &Policy) -> bool {
        self.version > stored.version
            || (self.version == stored.version && self.sha256() < stored.sha256())
    }
    pub fn reference(&self) -> PolicyRef {
        PolicyRef {
            person_id: self.person_id(),
            version: self.version,
        }
    }
}

/// A host-local block: a person or a host refused under both grants and
/// policy, without coordination.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessBlock {
    pub kind: String,
    pub subject: String,
    pub created_at: String,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockRequest {
    #[serde(default)]
    pub person: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
}

/// The outcome of the acceptance rule.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Accepted {
    Stored,
    /// The same policy is already stored.
    Identical,
    /// The stored policy wins: a higher version, or the tie-break.
    Kept(Box<Policy>),
}

/// The newest verified policy, plus whether it needs renewal soon.
#[derive(Debug, Serialize)]
pub struct PolicyView {
    #[serde(flatten)]
    pub policy: Policy,
    pub expires_soon: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_base64: Option<String>,
}

impl Store {
    /// The newest verified policy of `person_key` in a network.
    pub(crate) fn stored_policy(
        &self,
        connection: &Connection,
        network: &str,
        person_key: &str,
    ) -> Result<Option<Policy>, Error> {
        let n = self.network_record(connection, network)?;
        if let Some(p) = self
            .linking_projection(connection, &n)
            .map_err(crate::link_runtime::support::model_error)?
        {
            return Ok(p.policies.get(person_key).cloned());
        }
        connection
            .query_row(
                "SELECT record FROM network_statements WHERE network_id = ?1 AND kind = 'policy' AND subject = ?2",
                params![network, person_key],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            .map(json)
            .transpose()
    }
    /// This host's member records, one per network.
    pub(crate) fn own_members(
        &self,
        connection: &Connection,
    ) -> Result<Vec<(String, Member)>, Error> {
        self.members_of(connection, &self.identity().id)
    }
    fn members_of(
        &self,
        connection: &Connection,
        host: &str,
    ) -> Result<Vec<(String, Member)>, Error> {
        let mut statement = connection.prepare(
            "SELECT network_id, record FROM network_members WHERE host_id = ?1 ORDER BY network_id",
        )?;
        let rows = statement
            .query_map([host], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter().map(|(n, m)| Ok((n, json(m)?))).collect()
    }
    /// The key of a current person in a network.
    pub(crate) fn person_key(
        &self,
        connection: &Connection,
        network: &str,
        person_id: &str,
    ) -> Result<Option<String>, Error> {
        Ok(self
            .stored_persons(connection, network)?
            .into_iter()
            .find(|p| p.person_id == person_id)
            .map(|p| p.person_public_key))
    }
    /// Whether the block list refuses this sender host: blocked by host ID,
    /// or bound to a blocked person in any network.
    pub(crate) fn blocked(&self, connection: &Connection, sender: &str) -> Result<bool, Error> {
        let host: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM access_blocks WHERE kind = 'host' AND subject = ?1)",
            [sender],
            |r| r.get(0),
        )?;
        if host {
            return Ok(true);
        }
        for (_, m) in self.members_of(connection, sender)? {
            if let Some(person) = &m.person_id {
                let blocked: bool = connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM access_blocks WHERE kind = 'person' AND subject = ?1)",
                    [person],
                    |r| r.get(0),
                )?;
                if blocked {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
    /// Authorizes a request under the cited owner's policy. Final denials are
    /// `Forbidden`; a receiver behind the cited version is `Unavailable`.
    pub(crate) fn policy_bounds(
        &self,
        connection: &Connection,
        sender: &str,
        r: &Authz<'_>,
        cited: &PolicyRef,
        require_deadline: bool,
    ) -> Result<Bounds, Error> {
        let at = Utc::now();
        let deadline = time(r.deadline)?;
        if require_deadline && deadline <= at {
            return Err(Error::Forbidden);
        }
        let agent: Option<String> = connection
            .query_row(
                "SELECT name FROM agents WHERE id = ?1",
                [r.target_agent_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(agent) = agent else {
            return Err(Error::Forbidden);
        };
        let mut behind = false;
        let mut allowed: Option<Bounds> = None;
        // A named agent's rules override the `*` rules.
        let applies = |policy: &Policy, rule: &Rule| {
            if policy.rules.iter().any(|r| r.agent == agent) {
                rule.agent == agent
            } else {
                rule.agent == ALL_AGENTS
            }
        };
        for (network, own) in self.own_members(connection)? {
            if own.person_id.as_deref() != Some(cited.person_id.as_str()) {
                continue;
            }
            let Some(key) = self.person_key(connection, &network, &cited.person_id)? else {
                continue;
            };
            let Some(policy) = self.stored_policy(connection, &network, &key)? else {
                behind = true;
                continue;
            };
            if policy.version < cited.version {
                behind = true;
                continue;
            }
            // Withdrawals of this host's unsettled edits apply at once.
            let policy = self.enforced(connection, &network, policy)?;
            // The receiver evaluates its own newest version.
            if !policy.in_window(at) || deadline > time(&policy.valid_until)? {
                continue;
            }
            let Some(sender_member) = self
                .stored_members(connection, &network)?
                .into_iter()
                .find(|m| m.host_id == sender && m.host_id != self.identity().id)
            else {
                continue;
            };
            let groups = self.stored_groups(connection, &network)?;
            let matches = |p: &str| principal_matches(p, &sender_member, &groups, r.origin);
            for rule in &policy.rules {
                if !applies(&policy, rule)
                    || !rule.actions.iter().any(|a| allows(a, r.action))
                    || r.size as i64 > rule.max_message_bytes
                    || !crate::peer_store::artifacts_fit(r.artifacts, rule.max_artifact_bytes)
                    || !rule.principals.iter().any(|p| matches(p))
                {
                    continue;
                }
                let bounds = allowed.get_or_insert(Bounds {
                    max_message_bytes: 0,
                    max_artifact_bytes: 0,
                    allow_disconnected: false,
                    delegate: false,
                });
                bounds.delegate |= rule.actions.iter().any(|a| a == DELEGATE_ACTION);
                bounds.max_message_bytes = bounds.max_message_bytes.max(rule.max_message_bytes);
                bounds.max_artifact_bytes = bounds.max_artifact_bytes.max(rule.max_artifact_bytes);
                bounds.allow_disconnected |= rule.allow_disconnected;
            }
        }
        match allowed {
            Some(b) => Ok(b),
            None if behind => Err(Error::Unavailable(
                "this host has not yet received the cited policy version".into(),
            )),
            None => Err(Error::Forbidden),
        }
    }
    /// Whether `host` is another current member bound to `person` in a
    /// network where this host is also bound to `person`.
    pub(crate) fn self_bound(
        &self,
        connection: &Connection,
        host: &str,
        person: &str,
    ) -> Result<bool, Error> {
        if host == self.identity().id {
            return Ok(false);
        }
        for (network, own) in self.own_members(connection)? {
            if own.person_id.as_deref() != Some(person) {
                continue;
            }
            if crate::chain::member(connection, &network, host)?
                .is_some_and(|m| m.person_id.as_deref() == Some(person))
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
    /// The self access a request to `peer` cites: this host's person, when
    /// `peer` is bound to it in a shared network (the lowest network ID).
    pub(crate) fn self_citation(
        &self,
        connection: &Connection,
        peer: &str,
    ) -> Result<Option<SelfRef>, Error> {
        if peer == self.identity().id {
            return Ok(None);
        }
        for (network, own) in self.own_members(connection)? {
            let Some(person) = own.person_id else {
                continue;
            };
            if crate::chain::member(connection, &network, peer)?
                .is_some_and(|m| m.person_id.as_deref() == Some(person.as_str()))
            {
                return Ok(Some(SelfRef { person_id: person }));
            }
        }
        Ok(None)
    }
    /// Authorizes a request under self access: this host and `subject` are
    /// both bound to the cited person in a shared network. It needs no grant
    /// or policy, and the block list does not apply.
    pub(crate) fn self_bounds(
        &self,
        connection: &Connection,
        subject: &str,
        r: &Authz<'_>,
        cited: &SelfRef,
        require_deadline: bool,
    ) -> Result<Bounds, Error> {
        let deadline = time(r.deadline)?;
        if require_deadline && deadline <= Utc::now() {
            return Err(Error::Forbidden);
        }
        let agent: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM agents WHERE id = ?1)",
            [r.target_agent_id],
            |row| row.get(0),
        )?;
        if !agent
            || !self.self_bound(connection, subject, &cited.person_id)?
            || r.size as i64 > SELF_BOUNDS.max_message_bytes
            || !crate::peer_store::artifacts_fit(r.artifacts, SELF_BOUNDS.max_artifact_bytes)
        {
            return Err(Error::Forbidden);
        }
        Ok(SELF_BOUNDS)
    }
    /// What a request to `peer` without a grant cites: self access when
    /// `peer` is bound to this host's person in a shared network, and
    /// otherwise the target owner's newest verified policy.
    pub(crate) fn citation(&self, connection: &Connection, peer: &str) -> Result<Citation, Error> {
        if let Some(cited) = self.self_citation(connection, peer)? {
            return Ok(Citation::SelfAccess(cited));
        }
        Ok(Citation::Policy(Box::new(
            self.cited_policy(connection, peer)?,
        )))
    }
    /// What a request by address to `peer` cites for the chosen
    /// authorization: a grant, or else a citation. Self access falls back
    /// to the usual citation if this host no longer shares a person with
    /// `peer`.
    pub(crate) fn chosen(
        &self,
        connection: &Connection,
        peer: &str,
        choice: &crate::directory::Choice,
    ) -> Result<Result<String, Citation>, Error> {
        use crate::directory::Choice;
        Ok(match choice {
            Choice::Grant(id) => Ok(id.clone()),
            Choice::SelfAccess => Err(self.citation(connection, peer)?),
            Choice::Policy => Err(Citation::Policy(Box::new(
                self.cited_policy(connection, peer)?,
            ))),
        })
    }
    /// The request fields `grant_id`, `policy`, and `self` for a choice.
    pub(crate) fn chosen_citation(
        &self,
        connection: &Connection,
        peer: &str,
        choice: &crate::directory::Choice,
    ) -> Result<RequestAuthorization, Error> {
        Ok(match self.chosen(connection, peer, choice)? {
            Ok(grant) => (Some(grant), None, None),
            Err(cited) => {
                let (policy, self_access) = cited.fields();
                (None, policy, self_access)
            }
        })
    }
    /// What a forward to `peer` without a grant cites: past one link the
    /// authorization is the originator's, so self access when `peer` is bound
    /// to the originator host's person in the chain's network, and otherwise
    /// the target owner's policy.
    pub(crate) fn chain_citation(
        &self,
        connection: &Connection,
        chain: &[crate::chain::Link],
        peer: &str,
    ) -> Result<Citation, Error> {
        if let Some(first) = chain.first() {
            let network = &first.network_id;
            let person = crate::chain::member(connection, network, &first.issuer_host_id)?
                .and_then(|m| m.person_id);
            if let Some(person) = person
                && crate::chain::member(connection, network, &self.identity().id)?.is_some()
                && crate::chain::member(connection, network, peer)?
                    .is_some_and(|m| m.person_id.as_deref() == Some(person.as_str()))
            {
                return Ok(Citation::SelfAccess(SelfRef { person_id: person }));
            }
        }
        Ok(Citation::Policy(Box::new(
            self.cited_policy(connection, peer)?,
        )))
    }
    /// The policy a request to `peer` cites, whose `valid_until` also caps a
    /// default deadline.
    pub(crate) fn cited_policy(
        &self,
        connection: &Connection,
        peer: &str,
    ) -> Result<Policy, Error> {
        let mut owner = None;
        for (network, m) in self.members_of(connection, peer)? {
            let Some(person) = &m.person_id else {
                continue;
            };
            owner = Some(person.clone());
            let Some(key) = self.person_key(connection, &network, person)? else {
                continue;
            };
            if let Some(p) = self.stored_policy(connection, &network, &key)? {
                return Ok(p);
            }
        }
        Err(Error::Invalid(match owner {
            None => format!(
                "no grant given, and host {peer} is not bound to a person in any shared network; ask its owner for a grant"
            ),
            Some(owner) => format!(
                "no grant given, and the owner of host {peer} ({owner}) has no access policy; ask them to run access allow, or give a grant"
            ),
        }))
    }

    /// The `ssh-agent` socket the daemon asks to renew policies.
    pub fn set_person_agent(&self, socket: Option<std::path::PathBuf>) {
        if let Ok(mut agent) = self.person_agent.write() {
            *agent = socket;
        }
    }
    /// The generated person key file the daemon may renew with.
    pub fn set_person_key_file(&self, path: Option<std::path::PathBuf>) {
        if let Ok(mut file) = self.person_key_file.write() {
            *file = path;
        }
    }
    /// A signer for `key`'s renewals: the agent at the daemon's socket when it
    /// holds the key, otherwise the generated key file when it holds that key.
    /// Without either, the reason.
    pub(crate) fn renewal_signer(&self, key: [u8; 32]) -> Result<PersonSigner, String> {
        let socket = self.person_agent.read().ok().and_then(|s| s.clone());
        let mut reason =
            "the daemon has no ssh-agent (--person-agent) to renew your access policy".to_owned();
        if let Some(socket) = socket {
            match PersonSigner::agent_at(socket.clone(), key) {
                Ok(signer) => return Ok(signer),
                Err(e) => {
                    reason = format!(
                        "the daemon cannot renew your access policy through its ssh-agent {}: {e}",
                        socket.display()
                    )
                }
            }
        }
        let file = self.person_key_file.read().ok().and_then(|f| f.clone());
        if let Some(path) = file
            && let Ok(text) = std::fs::read_to_string(&path)
            && let Ok(signing) = crate::persons::parse_openssh_private_key(&text)
            && signing.verifying_key().to_bytes() == key
        {
            return Ok(PersonSigner::File(signing));
        }
        Err(reason)
    }
    /// The newest verified policy of a person (this host's own person by
    /// default) in a network.
    pub fn policy(&self, network: &str, person: Option<&str>) -> Result<PolicyView, Error> {
        let connection = self.connection()?;
        self.network_record(&connection, network)?;
        let person = match person {
            Some(p) => {
                let persons = self.stored_persons(&connection, network)?;
                crate::admins::resolve_person(&persons, p)?
                    .person_id
                    .clone()
            }
            None => self
                .own_members(&connection)?
                .into_iter()
                .find(|(n, _)| n == network)
                .and_then(|(_, m)| m.person_id)
                .ok_or(Error::NotFound)?,
        };
        let key = self
            .person_key(&connection, network, &person)?
            .ok_or(Error::NotFound)?;
        let policy = self
            .stored_policy(&connection, network, &key)?
            .ok_or(Error::NotFound)?;
        let expires_soon = policy.expires_soon(Utc::now());
        Ok(PolicyView {
            policy,
            expires_soon,
            authorization_base64: self
                .linking_projection(&connection, &self.network_record(&connection, network)?)
                .map_err(crate::link_runtime::support::model_error)?
                .and_then(|p| {
                    p.policy_authorizations
                        .get(&key)
                        .filter(|s| s.as_str() != "-")
                        .cloned()
                }),
        })
    }
    /// Applies the acceptance rule to a policy from any source (the
    /// coordinator, a sibling, or the owner's CLI): it must verify, have a
    /// current owner, and be inside its validity window, and is stored when
    /// its version is higher than the stored one's, or equal with a lower
    /// statement SHA-256. A stored policy of this host's own person is
    /// queued for delivery to its siblings and the coordinator.
    pub(crate) fn accept_policy(
        &self,
        tx: &rusqlite::Transaction<'_>,
        network: &str,
        p: &Policy,
        at: DateTime<Utc>,
    ) -> Result<Accepted, Error> {
        p.verify(network)?;
        if !p.in_window(at) {
            return Err(invalid("the policy is not within its validity window"));
        }
        if self.person_key(tx, network, &p.person_id())?.as_deref()
            != Some(p.person_public_key.as_str())
        {
            return Err(Error::Forbidden);
        }
        let mut n = self.network_record(tx, network)?;
        if let Some(before) = self
            .linking_projection(tx, &n)
            .map_err(crate::link_runtime::support::model_error)?
        {
            let body = serde_json::to_vec(p)?;
            let added = crate::link_runtime::crypto::json(&crate::link_runtime::catalog::Catalog {
                format: 1,
                network_id: network.into(),
                objects: vec![crate::link_runtime::catalog::Entry {
                    id: crate::link_runtime::catalog::proof_id("policy", &body),
                    kind: "policy".into(),
                    body_base64: base64::engine::general_purpose::STANDARD.encode(&body),
                }],
            })
            .map_err(crate::link_runtime::support::model_error)?;
            let union = crate::link_runtime::catalog::merge(network, &[&before.catalog, &added])
                .map_err(crate::link_runtime::support::model_error)?;
            if union == before.catalog {
                return Ok(Accepted::Identical);
            }
            let selected = crate::link_runtime::catalog::verify(tx, &n, &union, at)
                .map_err(crate::link_runtime::support::model_error)?;
            if selected.policies.get(&p.person_public_key) != Some(p) {
                return match selected.policies.get(&p.person_public_key) {
                    Some(old) => Ok(Accepted::Kept(Box::new(old.clone()))),
                    None => Err(Error::Conflict(
                        "a higher access version remains selected".into(),
                    )),
                };
            }
            let old = self.stored_members(tx, network)?;
            let at = at.format("%Y-%m-%dT%H:%M:%SZ").to_string();
            let mut members = crate::link_runtime::map::projected_members(&selected, &old, &at)
                .map_err(crate::link_runtime::support::model_error)?;
            crate::link_runtime::map::persist(self, tx, &mut n, &selected, &mut members, &at)
                .map_err(crate::link_runtime::support::model_error)?;
            return Ok(Accepted::Stored);
        }
        match self.stored_policy(tx, network, &p.person_public_key)? {
            Some(old) if old == *p => return Ok(Accepted::Identical),
            Some(old) if !p.supersedes(&old) => return Ok(Accepted::Kept(Box::new(old))),
            _ => {}
        }
        tx.execute(
            "INSERT OR REPLACE INTO network_statements VALUES (?1, 'policy', ?2, ?3)",
            params![network, p.person_public_key, serde_json::to_string(p)?],
        )?;
        append_event(tx, "network.policy_updated", &p.person_id(), &rfc3339(at))?;
        self.queue_policy_deliveries(tx, network, p)?;
        self.settle_edits(tx, network, p)?;
        Ok(Accepted::Stored)
    }
    /// The policies this host should renew: its own person's, in networks
    /// where less than a quarter of the validity remains.
    pub(crate) fn renewable_policies(&self) -> Result<Vec<Policy>, Error> {
        let connection = self.connection()?;
        let at = Utc::now();
        let mut out = Vec::new();
        for (network, own) in self.own_members(&connection)? {
            let selected: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM link_signers WHERE network_id=?1)",
                [&network],
                |row| row.get(0),
            )?;
            let at = if selected
                && crate::link_runtime::catalog::feature(&connection, &network)
                    .map_err(crate::link_runtime::support::model_error)?
                    .0
                    != "-"
            {
                crate::link_runtime::support::now()
                    .map_err(|e| crate::link_runtime::support::model_error(e.into()))?
            } else {
                at
            };
            let Some(person) = &own.person_id else {
                continue;
            };
            let Some(key) = self.person_key(&connection, &network, person)? else {
                continue;
            };
            if let Some(p) = self.stored_policy(&connection, &network, &key)?
                && p.expires_soon(at)
                && time(&p.valid_until)? > at
            {
                out.push(p);
            }
        }
        Ok(out)
    }

    pub fn access_blocks(&self) -> Result<Vec<AccessBlock>, Error> {
        crate::peer_store::records(
            &*self.connection()?,
            "SELECT record FROM access_blocks ORDER BY kind, subject",
        )
    }
    /// Resolves a block request to `(kind, subject)`: a host ID, or a person
    /// given by ID, key, or unambiguous label in any network.
    fn block_subject(&self, r: &BlockRequest) -> Result<(String, String), Error> {
        match (&r.person, &r.host) {
            (Some(person), None) => {
                let connection = self.connection()?;
                let networks: Vec<String> = {
                    let mut statement = connection.prepare("SELECT id FROM networks")?;
                    statement
                        .query_map([], |r| r.get(0))?
                        .collect::<Result<_, _>>()?
                };
                let mut persons = Vec::new();
                for n in networks {
                    persons.extend(self.stored_persons(&connection, &n)?);
                }
                persons.sort_by(|a, b| a.person_id.cmp(&b.person_id));
                persons.dedup_by(|a, b| a.person_id == b.person_id);
                let id = match crate::admins::resolve_person(&persons, person) {
                    Ok(p) => p.person_id.clone(),
                    Err(Error::NotFound) if person_id_shape(person) => person.clone(),
                    Err(e) => return Err(e),
                };
                Ok(("person".into(), id))
            }
            (None, Some(host)) => {
                if !crate::peer_store::valid_id(host, "host", 32) {
                    return Err(invalid("invalid host ID"));
                }
                Ok(("host".into(), host.clone()))
            }
            _ => Err(invalid("give exactly one of person or host")),
        }
    }
    pub fn block(&self, r: BlockRequest) -> Result<AccessBlock, Error> {
        let (kind, subject) = self.block_subject(&r)?;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let old: Option<String> = tx
            .query_row(
                "SELECT record FROM access_blocks WHERE kind = ?1 AND subject = ?2",
                params![kind, subject],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(old) = old {
            return json(old);
        }
        let block = AccessBlock {
            kind: kind.clone(),
            subject: subject.clone(),
            created_at: now(),
        };
        tx.execute(
            "INSERT INTO access_blocks VALUES (?1, ?2, ?3)",
            params![kind, subject, serde_json::to_string(&block)?],
        )?;
        append_event(&tx, "access.blocked", &subject, &block.created_at)?;
        tx.commit()?;
        Ok(block)
    }
    pub fn unblock(&self, r: BlockRequest) -> Result<AccessBlock, Error> {
        let (kind, subject) = self.block_subject(&r)?;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let old: Option<String> = tx
            .query_row(
                "SELECT record FROM access_blocks WHERE kind = ?1 AND subject = ?2",
                params![kind, subject],
                |r| r.get(0),
            )
            .optional()?;
        let Some(old) = old else {
            return Err(Error::NotFound);
        };
        tx.execute(
            "DELETE FROM access_blocks WHERE kind = ?1 AND subject = ?2",
            params![kind, subject],
        )?;
        append_event(&tx, "access.unblocked", &subject, &now())?;
        tx.commit()?;
        json(old)
    }
}

/// Renews this host's own person's policies that are close to expiry, by
/// asking the owner's `ssh-agent` (`run --person-agent`, or the daemon's
/// `SSH_AUTH_SOCK`) for a signature. Without an agent holding the key,
/// access lapses at `valid_until`. Several of an owner's hosts may renew at
/// once; they converge on one version by the tie-break of the acceptance rule.
pub(crate) async fn renew(store: Arc<Store>) {
    let due = blocking(store.clone(), |s| s.renewable_policies())
        .await
        .unwrap_or_default();
    for policy in due {
        let Ok(key) = crate::membership::canonical(&policy.person_public_key, 32) else {
            continue;
        };
        let Ok(key) = <[u8; 32]>::try_from(key) else {
            continue;
        };
        let network = policy.network_id.clone();
        // Unsettled edits are re-applied instead, which also renews.
        let n = network.clone();
        if blocking(store.clone(), move |s| s.has_unsettled(&n))
            .await
            .unwrap_or(false)
            && crate::policy_edit::reapply(store.clone(), network.clone()).await
        {
            continue;
        }
        let (run, lookup, old) = (store.clone(), network.clone(), policy.clone());
        let edits = blocking(run, move |s| {
            s.unretired_edits(&*s.connection()?, &lookup, &old)
        })
        .await
        .unwrap_or_else(|_| policy.edits().to_vec());
        match crate::link_runtime::provider::automatic_policy(
            store.clone(),
            network.clone(),
            policy.clone(),
            policy.content(),
            edits,
            policy.duration(),
            None,
        )
        .await
        {
            Ok(Some(_)) => continue,
            Err(e) => {
                eprintln!("policy device renewal requires repair: {e}");
                continue;
            }
            Ok(None) => {}
        }
        let signer = {
            let store = store.clone();
            match tokio::task::spawn_blocking(move || store.renewal_signer(key)).await {
                Ok(Ok(signer)) => signer,
                _ => continue,
            }
        };
        // A renewal copies `edits`, except retired entries.
        let n = network.clone();
        let p = policy.clone();
        let Ok(edits) = blocking(store.clone(), move |s| {
            s.unretired_edits(&*s.connection()?, &n, &p)
        })
        .await
        else {
            continue;
        };
        let renewed = match policy.renewal_with(&signer, Utc::now(), edits) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("policy renewal signing failed: {e}");
                continue;
            }
        };
        match crate::policy_sync::submit(store.clone(), network, renewed).await {
            Ok(_) => {}
            // A sibling's concurrent renewal of the same version may win the
            // tie-break; this host keeps that one.
            Err(Error::Conflict(_)) => {}
            Err(e) => eprintln!("policy renewal failed: {e}"),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmitPolicy {
    policy: Policy,
}
#[derive(Deserialize)]
struct PolicyQuery {
    #[serde(default)]
    person: Option<String>,
}
pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route(
            "/v1/networks/{id}/policy",
            get(show_route).post(submit_route),
        )
        .route("/v1/access-blocks", get(blocks_route).post(block_route))
        .route("/v1/access-blocks/remove", post(unblock_route))
        .merge(crate::policy_sync::local_routes())
        .merge(crate::policy_edit::local_routes())
}
async fn show_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    Query(q): Query<PolicyQuery>,
) -> Result<Json<PolicyView>, Error> {
    Ok(Json(
        blocking(store, move |s| s.policy(&id, q.person.as_deref())).await?,
    ))
}
async fn submit_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<Policy>), Error> {
    let request: SubmitPolicy = decode(body)?;
    Ok((
        StatusCode::CREATED,
        Json(crate::policy_sync::submit(store, id, request.policy).await?),
    ))
}
async fn blocks_route(State(store): State<Arc<Store>>) -> Result<Json<Vec<AccessBlock>>, Error> {
    Ok(Json(blocking(store, |s| s.access_blocks()).await?))
}
/// Syncs every network once when a block's person does not resolve, since a
/// person admitted moments ago elsewhere may not have reached this host.
async fn sync_unresolved(store: &Arc<Store>, request: &BlockRequest) -> Result<(), Error> {
    let r = request.clone();
    let networks = blocking(store.clone(), move |s| {
        Ok(match s.block_subject(&r) {
            Err(Error::NotFound) => s.networks()?.into_iter().map(|n| n.id).collect(),
            _ => Vec::new(),
        })
    })
    .await?;
    for id in networks {
        let _ = crate::network::sync_network(store.clone(), id).await;
    }
    Ok(())
}
async fn block_route(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<AccessBlock>), Error> {
    let request: BlockRequest = decode(body)?;
    sync_unresolved(&store, &request).await?;
    Ok((
        StatusCode::CREATED,
        Json(blocking(store, move |s| s.block(request)).await?),
    ))
}
async fn unblock_route(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<AccessBlock>, Error> {
    let request: BlockRequest = decode(body)?;
    sync_unresolved(&store, &request).await?;
    Ok(Json(blocking(store, move |s| s.unblock(request)).await?))
}

/// Merges a map's offered policies into the persisted ones by the acceptance
/// rule: an offered policy of a current person that verifies and is inside
/// its window replaces the held one when its version is higher, or equal
/// with a lower statement SHA-256. A lower version never replaces a higher one.
pub(crate) fn verify_policies(
    network: &str,
    persons: &[String],
    persisted: Vec<Policy>,
    offered: Vec<serde_json::Value>,
    at: DateTime<Utc>,
) -> Vec<Policy> {
    let mut best: std::collections::BTreeMap<String, Policy> = std::collections::BTreeMap::new();
    for p in persisted {
        best.insert(p.person_public_key.clone(), p);
    }
    for p in offered
        .into_iter()
        .filter_map(|v| serde_json::from_value::<Policy>(v).ok())
    {
        if !persons.contains(&p.person_public_key) || p.verify(network).is_err() || !p.in_window(at)
        {
            continue;
        }
        if best
            .get(&p.person_public_key)
            .is_none_or(|old| p.supersedes(old))
        {
            best.insert(p.person_public_key.clone(), p);
        }
    }
    best.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};

    const NETWORK: &str = "net_34750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e";
    const PERSON_SEED: &str = "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU=";
    const SECOND_ID: &str =
        "person_72456720412037a6b339f884ce6d91bb4cc163a7dc3e4c58c658e6c2097b92a2";
    const POLICY_SIG: &str = "U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgbnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/EAAAAScGVlcnNwYW4tcGVyc29uLXYxAAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5AAAAQI7LAL0jJtpQWmoMSHjIs49S3ZgRu1H8/I7LHRJ/N58B81ZTDeV854NluBUedCUW8GgzjOOTHLEM5pfE/iGPog8=";

    fn owner() -> PersonSigner {
        PersonSigner::File(ed25519_dalek::SigningKey::from_bytes(
            &STANDARD.decode(PERSON_SEED).unwrap().try_into().unwrap(),
        ))
    }
    fn rules() -> Vec<Rule> {
        vec![
            Rule {
                agent: "reviewer".into(),
                principals: vec![format!("person:{SECOND_ID}"), "group:backend".into()],
                actions: vec![ACTION.into()],
                max_message_bytes: 65536,
                allow_disconnected: false,
                max_artifact_bytes: 0,
            },
            Rule {
                agent: "triage".into(),
                principals: vec!["network".into()],
                actions: vec![ACTION.into()],
                max_message_bytes: 4096,
                allow_disconnected: true,
                max_artifact_bytes: 0,
            },
        ]
    }
    fn vector() -> Policy {
        Policy::sign(
            &owner(),
            NETWORK,
            1,
            "2026-10-10T00:00:00Z",
            "2026-10-17T00:00:00Z",
            rules(),
        )
        .unwrap()
    }

    #[test]
    fn policy_reproduces_the_vector_and_rejects_tampering() {
        let p = vector();
        assert_eq!(p.signature, POLICY_SIG);
        p.verify(NETWORK).unwrap();
        let encoded = serde_json::to_value(&p).unwrap();
        assert_eq!(
            encoded
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            [
                "issued_at",
                "network_id",
                "person_public_key",
                "rules",
                "signature",
                "valid_until",
                "version"
            ]
        );
        let mut t = p.clone();
        t.rules[0].max_message_bytes = 65535;
        assert!(t.verify(NETWORK).is_err());
        let mut t = p.clone();
        t.rules[1].principals = vec!["group:backend".into()];
        assert!(t.verify(NETWORK).is_err());
        let mut t = p.clone();
        t.version = 2;
        assert!(t.verify(NETWORK).is_err());
        let mut t = p.clone();
        t.rules.swap(0, 1);
        assert!(t.verify(NETWORK).is_err());
        assert!(p.verify(&format!("net_{}", "0".repeat(64))).is_err());
        assert!(serde_json::from_value::<Policy>(json_extra(&encoded)).is_err());
    }
    #[test]
    fn artifact_bounds_extend_the_signed_rule_line_only_when_nonzero() {
        const ARTIFACT_SIG: &str = "U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgbnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/EAAAAScGVlcnNwYW4tcGVyc29uLXYxAAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5AAAAQM53FmawC5CSxjCe7Vko24T8Nwgm7KauP0HIie0h+zrLpWGllaBfSB0oOJVnL/hZamrfIgt6wJiBJWwRA5JnogM=";
        let rules = vec![
            Rule {
                agent: "reviewer".into(),
                principals: vec![format!("person:{SECOND_ID}")],
                actions: vec![ACTION.into(), TASK_ACTION.into()],
                max_message_bytes: 65536,
                max_artifact_bytes: 1_048_576,
                allow_disconnected: false,
            },
            Rule {
                agent: "triage".into(),
                principals: vec!["network".into()],
                actions: vec![TASK_ACTION.into()],
                max_message_bytes: 4096,
                max_artifact_bytes: 0,
                allow_disconnected: true,
            },
        ];
        let p = Policy::sign(
            &owner(),
            NETWORK,
            2,
            "2026-10-10T00:00:00Z",
            "2026-10-17T00:00:00Z",
            rules,
        )
        .unwrap();
        let lines = p.lines();
        assert_eq!(lines[10], "65536 false 1048576");
        assert_eq!(lines[15], "4096 true");
        assert_eq!(p.signature, ARTIFACT_SIG);
        p.verify(NETWORK).unwrap();
        let encoded = serde_json::to_string(&p.rules[0]).unwrap();
        assert_eq!(
            encoded,
            format!(
                r#"{{"agent":"reviewer","principals":["person:{SECOND_ID}"],"actions":["message.append","task.submit"],"max_message_bytes":65536,"max_artifact_bytes":1048576,"allow_disconnected":false}}"#
            )
        );
        assert!(
            serde_json::to_value(&p.rules[1])
                .unwrap()
                .get("max_artifact_bytes")
                .is_none()
        );
        // An explicit 0 reads as absent; the bound is signed.
        let mut zero = serde_json::to_value(&p.rules[1]).unwrap();
        zero["max_artifact_bytes"] = serde_json::json!(0);
        assert_eq!(serde_json::from_value::<Rule>(zero).unwrap(), p.rules[1]);
        let mut t = p.clone();
        t.rules[0].max_artifact_bytes = 1_048_575;
        assert!(t.verify(NETWORK).is_err());
        // Bounds are 0 to 1 GiB and need task.submit.
        let sign = |rule: Rule| {
            Policy::sign(
                &owner(),
                NETWORK,
                1,
                "2026-10-10T00:00:00Z",
                "2026-10-17T00:00:00Z",
                vec![rule],
            )
        };
        for (actions, bound, ok) in [
            (vec![TASK_ACTION], 1 << 30, true),
            (vec![TASK_ACTION], (1 << 30) + 1, false),
            (vec![TASK_ACTION], -1, false),
            (vec![ACTION], 1, false),
            (vec![ACTION], 0, true),
        ] {
            let rule = Rule {
                actions: actions.into_iter().map(Into::into).collect(),
                max_artifact_bytes: bound,
                ..p.rules[0].clone()
            };
            assert_eq!(sign(rule).is_ok(), ok, "{bound}");
        }
    }
    /// The version 2 test vector (capabilities contract, amended on
    /// 2026-10-18): the earlier owner and the two rules of the version 1
    /// vector, plus two capability rules, a claim, and two trusted hosts and
    /// two edits entries given unsorted.
    fn vector_v2() -> Policy {
        let capability_rules = vec![
            CapabilityRule {
                host: format!("host_{}", "a".repeat(64)),
                capability: "github-issues".into(),
                principals: vec![format!("person:{SECOND_ID}")],
                max_input_bytes: 65536,
                allow_disconnected: false,
                max_calls_per_hour: 100,
            },
            CapabilityRule {
                host: format!("host_{}", "b".repeat(64)),
                capability: "docs".into(),
                principals: vec!["group:backend".into()],
                max_input_bytes: 4096,
                allow_disconnected: true,
                max_calls_per_hour: 10,
            },
            CapabilityRule::claim(&format!("host_{}", "a".repeat(64)), "notes"),
        ];
        Policy::sign_v2(
            &owner(),
            NETWORK,
            1,
            "2026-10-10T00:00:00Z",
            "2026-10-17T00:00:00Z",
            Content {
                rules: rules(),
                capability_rules,
                trusted_hosts: vec![
                    format!("host_{}", "b".repeat(64)),
                    format!("host_{}", "a".repeat(64)),
                ],
            },
            vec![
                EditEntry {
                    host: format!("host_{}", "b".repeat(64)),
                    seq: 1,
                },
                EditEntry {
                    host: format!("host_{}", "a".repeat(64)),
                    seq: 3,
                },
            ],
        )
        .unwrap()
    }

    #[test]
    fn policy_v2_reproduces_its_vector() {
        let p = vector_v2();
        const V2_SIG: &str = "U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgbnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/EAAAAScGVlcnNwYW4tcGVyc29uLXYxAAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5AAAAQOZL7vRHm5jeIFxS6jfoD4z/QKQyTtlJ7PRIFsOn4lXricgtmZvYKWXJOjbTLVtSKJ6xeGoFdxIsUMvLP8g7lAI=";
        let lines = p.statement_lines();
        assert_eq!(p.signature, V2_SIG);
        assert_eq!(
            p.sha256(),
            "56a3bc8a6ab3df290823e1b9777e43ff82fc8a24d9f0c7c5a1ff57e582b28fd0"
        );
        assert_eq!(lines.len(), 36);
        assert_eq!(lines[0], "peerspan-policy-v2");
        assert_eq!(lines[31], "");
        assert!(lines[35].starts_with(&format!("edits host_{}:3 ", "a".repeat(64))));
        p.verify(NETWORK).unwrap();
        // A version 1 policy reads as version 2 with nothing more.
        let v1 = vector();
        assert!(v1.capability_rules().is_empty() && v1.trusted_hosts().is_empty());
        let mut t = p.clone();
        t.capability_rules.as_mut().unwrap()[1].capability = "github-issues".into();
        assert!(t.verify(NETWORK).is_err());
        let mut t = p.clone();
        let first = t.trusted_hosts().first().unwrap().clone();
        t.trusted_hosts.as_mut().unwrap().push(first);
        assert!(t.verify(NETWORK).is_err());
    }

    fn json_extra(v: &serde_json::Value) -> serde_json::Value {
        let mut v = v.clone();
        v["extra"] = serde_json::json!(1);
        v
    }

    #[test]
    fn shapes_and_windows_are_checked() {
        let sign = |issued: &str, until: &str, rules: Vec<Rule>| {
            Policy::sign(&owner(), NETWORK, 1, issued, until, rules)
        };
        assert!(sign("2026-10-10T00:00:00Z", "2026-10-10T23:59:59Z", rules()).is_err());
        assert!(sign("2026-10-10T00:00:00Z", "2027-01-08T00:00:01Z", rules()).is_err());
        sign("2026-10-10T00:00:00Z", "2027-01-08T00:00:00Z", rules()).unwrap();
        sign("2026-10-10T00:00:00Z", "2026-10-11T00:00:00Z", vec![]).unwrap();
        // Rules may allow task submission, alone or with messages.
        for actions in [vec![TASK_ACTION], vec![ACTION, TASK_ACTION]] {
            let rule = Rule {
                actions: actions.into_iter().map(Into::into).collect(),
                ..rules()[0].clone()
            };
            sign("2026-10-10T00:00:00Z", "2026-10-17T00:00:00Z", vec![rule]).unwrap();
        }
        for bad in [
            Rule {
                principals: vec![],
                ..rules()[0].clone()
            },
            Rule {
                principals: vec!["person:bob".into()],
                ..rules()[0].clone()
            },
            Rule {
                principals: vec!["group:Backend".into()],
                ..rules()[0].clone()
            },
            Rule {
                actions: vec!["shell.exec".into()],
                ..rules()[0].clone()
            },
            Rule {
                max_message_bytes: 65537,
                ..rules()[0].clone()
            },
            Rule {
                agent: "bad\nname".into(),
                ..rules()[0].clone()
            },
        ] {
            assert!(sign("2026-10-10T00:00:00Z", "2026-10-17T00:00:00Z", vec![bad]).is_err());
        }
        let too_many = vec![rules()[1].clone(); 65];
        assert!(sign("2026-10-10T00:00:00Z", "2026-10-17T00:00:00Z", too_many).is_err());
        let p = vector();
        let at = |s: &str| time(s).unwrap();
        assert!(!p.in_window(at("2026-10-09T23:54:59Z")));
        assert!(p.in_window(at("2026-10-09T23:55:00Z")));
        assert!(p.in_window(at("2026-10-16T23:59:59Z")));
        assert!(!p.in_window(at("2026-10-17T00:00:00Z")));
        // A quarter of seven days is 42 hours.
        assert!(!p.expires_soon(at("2026-10-15T06:00:00Z")));
        assert!(p.expires_soon(at("2026-10-15T06:00:01Z")));
        let renewed = p.renewal(&owner(), at("2026-10-15T12:00:00Z")).unwrap();
        assert_eq!(renewed.version, 2);
        assert_eq!(renewed.rules, p.rules);
        assert_eq!(renewed.issued_at, "2026-10-15T12:00:00Z");
        assert_eq!(renewed.valid_until, "2026-10-22T12:00:00Z");
        renewed.verify(NETWORK).unwrap();
    }

    #[test]
    fn offered_policies_never_roll_back() {
        let v1 = vector();
        let v2 = v1
            .renewal(&owner(), time("2026-10-12T00:00:00Z").unwrap())
            .unwrap();
        let persons = vec![v1.person_public_key.clone()];
        let at = time("2026-10-13T00:00:00Z").unwrap();
        let offer = |p: &Policy| vec![serde_json::to_value(p).unwrap()];
        let kept = verify_policies(NETWORK, &persons, vec![v2.clone()], offer(&v1), at);
        assert_eq!(kept, vec![v2.clone()]);
        let kept = verify_policies(NETWORK, &persons, vec![v1.clone()], offer(&v2), at);
        assert_eq!(kept, vec![v2.clone()]);
        // A forged or non-person policy is ignored.
        let mut forged = v2.clone();
        forged.version = 3;
        assert_eq!(
            verify_policies(NETWORK, &persons, vec![], offer(&forged), at),
            vec![]
        );
        assert_eq!(
            verify_policies(NETWORK, &[], vec![], offer(&v2), at),
            vec![]
        );
        // An offered policy outside its window is not accepted.
        let late = time("2026-10-20T00:00:00Z").unwrap();
        assert_eq!(
            verify_policies(NETWORK, &persons, vec![v1.clone()], offer(&v2), late),
            vec![v1.clone()]
        );
        // An equal version replaces the held one only with a lower SHA-256.
        let (low, high) = tie();
        let kept = verify_policies(NETWORK, &persons, vec![high.clone()], offer(&low), at);
        assert_eq!(kept, vec![low.clone()]);
        let kept = verify_policies(NETWORK, &persons, vec![low.clone()], offer(&high), at);
        assert_eq!(kept, vec![low]);
    }

    /// Two different policies of the same version, by statement SHA-256.
    fn tie() -> (Policy, Policy) {
        let a = Policy::sign(
            &owner(),
            NETWORK,
            2,
            "2026-10-12T00:00:00Z",
            "2026-10-19T00:00:00Z",
            rules(),
        )
        .unwrap();
        let b = Policy::sign(
            &owner(),
            NETWORK,
            2,
            "2026-10-12T00:00:01Z",
            "2026-10-19T00:00:01Z",
            rules(),
        )
        .unwrap();
        if a.sha256() < b.sha256() {
            (a, b)
        } else {
            (b, a)
        }
    }

    #[test]
    fn acceptance_rule_orders_versions_then_statement_hashes() {
        let v1 = vector();
        assert_eq!(
            v1.sha256(),
            hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
                v1.lines().join("\n").as_bytes()
            ))
        );
        assert_eq!(v1.sha256().len(), 64);
        assert!(v1.sha256().bytes().all(|b| !b.is_ascii_uppercase()));
        let v2 = v1
            .renewal(&owner(), time("2026-10-12T00:00:00Z").unwrap())
            .unwrap();
        assert!(v2.supersedes(&v1));
        assert!(!v1.supersedes(&v2));
        assert!(!v1.supersedes(&v1));
        let (low, high) = tie();
        assert_ne!(low.sha256(), high.sha256());
        assert!(low.supersedes(&high));
        assert!(!high.supersedes(&low));
        // A higher version wins whatever its hash.
        assert!(low.supersedes(&v1) && high.supersedes(&v1));
    }

    #[test]
    fn principals_have_four_shapes() {
        principal("network").unwrap();
        principal(&format!("person:{SECOND_ID}")).unwrap();
        principal("group:backend").unwrap();
        for bad in [
            "Network",
            "person:",
            "group:",
            "group:-x",
            "host:x",
            "person:person_abc",
            "agent:",
            "agent:host_x/agent_y",
            &format!("agent:host_{}", "a".repeat(64)),
            &format!("agent:host_{}/agent_{}", "A".repeat(64), "b".repeat(32)),
            &format!("agent:host_{}/agent_{}/x", "a".repeat(64), "b".repeat(32)),
            &format!("agent:agent_{}", "b".repeat(32)),
        ] {
            assert!(principal(bad).is_err(), "{bad}");
        }
        principal(&format!(
            "agent:host_{}/agent_{}",
            "a".repeat(64),
            "b".repeat(32)
        ))
        .unwrap();
    }

    #[test]
    fn agent_principals_match_only_that_hosts_asserted_agent() {
        use crate::peer_store::Origin;
        let host = format!("host_{}", "a".repeat(64));
        let agent = format!("agent_{}", "b".repeat(32));
        let principal = format!("agent:{host}/{agent}");
        let member = |id: &str| Member {
            host_id: id.into(),
            public_key: String::new(),
            member: "m".into(),
            address: String::new(),
            candidates: vec![],
            updated_at: String::new(),
            membership: None,
            admission: None,
            person_id: Some(SECOND_ID.into()),
            person_member: None,
        };
        let origin = |a: &str| Origin {
            agent_id: a.into(),
            session_id: None,
        };
        let sender = member(&host);
        assert!(principal_matches(
            &principal,
            &sender,
            &[],
            Some(&origin(&agent))
        ));
        // No origin, another agent, or another host asserting the same agent.
        assert!(!principal_matches(&principal, &sender, &[], None));
        let other_agent = format!("agent_{}", "c".repeat(32));
        assert!(!principal_matches(
            &principal,
            &sender,
            &[],
            Some(&origin(&other_agent))
        ));
        let other_host = member(&format!("host_{}", "d".repeat(64)));
        assert!(!principal_matches(
            &principal,
            &other_host,
            &[],
            Some(&origin(&agent))
        ));
        // The other shapes ignore origin.
        assert!(principal_matches("network", &sender, &[], None));
        assert!(principal_matches(
            &format!("person:{SECOND_ID}"),
            &sender,
            &[],
            None
        ));
    }

    #[test]
    fn block_list_is_idempotent_and_persisted() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("host");
        let store = Store::open(&path).unwrap();
        let host = format!("host_{}", "a".repeat(64));
        let by_host = || BlockRequest {
            person: None,
            host: Some(host.clone()),
        };
        let first = store.block(by_host()).unwrap();
        assert_eq!(first.kind, "host");
        assert_eq!(store.block(by_host()).unwrap().created_at, first.created_at);
        let person = store
            .block(BlockRequest {
                person: Some(SECOND_ID.into()),
                host: None,
            })
            .unwrap();
        assert_eq!(
            (person.kind.as_str(), person.subject.as_str()),
            ("person", SECOND_ID)
        );
        assert!(
            store
                .block(BlockRequest {
                    person: Some("nobody".into()),
                    host: None,
                })
                .is_err()
        );
        assert!(
            store
                .block(BlockRequest {
                    person: Some(SECOND_ID.into()),
                    host: Some(host.clone()),
                })
                .is_err()
        );
        assert!(store.blocked(&store.connection().unwrap(), &host).unwrap());
        drop(store);
        let store = Store::open(&path).unwrap();
        let kinds: Vec<String> = store
            .access_blocks()
            .unwrap()
            .into_iter()
            .map(|b| b.kind)
            .collect();
        assert_eq!(kinds, ["host", "person"]);
        store.unblock(by_host()).unwrap();
        assert!(matches!(store.unblock(by_host()), Err(Error::NotFound)));
        assert!(!store.blocked(&store.connection().unwrap(), &host).unwrap());
    }

    #[test]
    fn requests_carry_exactly_one_authorization() {
        use crate::peer_store::{MessageRequest, OutboundMessage};
        let base = serde_json::json!({
            "request_id": format!("request_{}", "0".repeat(32)),
            "target_agent_id": format!("agent_{}", "0".repeat(32)),
            "deadline": "2026-10-10T00:00:00Z",
            "content": "hi",
            "policy": {"person_id": SECOND_ID, "version": 1},
        });
        let request: MessageRequest = serde_json::from_value(base.clone()).unwrap();
        assert!(request.grant_id.is_none());
        let wire = serde_json::to_value(&request).unwrap();
        assert!(wire.get("grant_id").is_none());
        let mut null = base.clone();
        null["grant_id"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<MessageRequest>(null).is_err());
        let mut no_policy = base.clone();
        no_policy["policy"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<MessageRequest>(no_policy).is_err());
        let record = OutboundMessage {
            peer_host_id: format!("host_{}", "a".repeat(64)),
            request,
            state: "unknown".into(),
            receipt: None,
            error: None,
            attempts: 0,
            next_attempt_at: None,
            receipt_queries: 0,
            to: None,
        };
        let shown = serde_json::to_value(&record).unwrap();
        assert!(
            shown["request"]["grant_id"].is_null() && shown["request"].get("grant_id").is_some()
        );
        let back: OutboundMessage = serde_json::from_value(shown).unwrap();
        assert_eq!(back.request, record.request);
    }
}
