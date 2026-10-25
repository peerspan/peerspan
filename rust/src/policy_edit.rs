//! Concurrent policy edits (coordination contract). Each policy edit signed
//! by a CLI command on this host gets a number, unique and increasing per
//! network and policy owner, recorded in the policy's `edits` line. The
//! host keeps its edits until a stored policy reflects them, and re-applies
//! any that a concurrent policy displaced, by a three-way merge in which a
//! withdrawal wins over a concurrent addition. The coordinator is not
//! involved.
use crate::{
    api::blocking,
    model::Error,
    peer_store::json,
    policy::{CapabilityRule, Content, EditEntry, MAX_EDIT_SEQ, Policy, Rule},
    store::{Store, append_event, now, rfc3339},
};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::get,
};
use chrono::{DateTime, TimeDelta, Utc};
use rusqlite::{Connection, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Digest;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

/// Database version 17: edit records per network and policy owner.
pub(crate) const SCHEMA: &str = "
CREATE TABLE policy_edits (network_id TEXT NOT NULL, person_id TEXT NOT NULL, seq INTEGER NOT NULL, record TEXT NOT NULL, PRIMARY KEY(network_id, person_id, seq));
PRAGMA user_version = 17;
";

/// A reservation not used within this long lapses.
const RESERVATION: TimeDelta = TimeDelta::minutes(10);
/// A closed record is deleted after this long, and a dropped addition is
/// listed in status this long.
const KEPT: TimeDelta = TimeDelta::days(7);
/// An edit unsettled longer than this draws attention.
const UNSETTLED_ATTENTION: TimeDelta = TimeDelta::minutes(1);
/// Re-applying waits a random delay up to this long.
const JITTER_MS: u64 = 2000;

pub const RESERVED: &str = "reserved";
pub const SETTLED: &str = "settled";
pub const UNSETTLED: &str = "unsettled";
pub const CLOSED: &str = "closed";

/// One edit record.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct EditRecord {
    pub seq: u64,
    /// `reserved`, `settled`, `unsettled`, or `closed`.
    pub state: String,
    /// The policy returned with the reservation; null without one.
    pub start: Option<Policy>,
    /// The submitted policy; null while reserved.
    pub signed: Option<Policy>,
    pub signed_version: Option<u64>,
    /// Additions the merge dropped, each named.
    pub dropped: Vec<String>,
    pub reserved_at: String,
    pub signed_at: Option<String>,
    /// When the state last became `unsettled` or `closed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed_at: Option<String>,
    /// When the merge last dropped an addition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dropped_at: Option<String>,
}

/// An edit in `access sync --status`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EditView {
    pub seq: u64,
    pub state: String,
    pub signed_version: Option<u64>,
    pub dropped: Vec<String>,
}

pub(crate) fn edit_conflict(message: &str) -> Error {
    Error::Coded {
        status: 409,
        code: "edit_conflict",
        message: format!("{message} (edit_conflict); start again from the edit route"),
        extra: Default::default(),
    }
}

fn time(text: &str) -> Option<DateTime<Utc>> {
    crate::membership::time(text).ok()
}

// ---------------------------------------------------------------------
// The merge.

fn minus<'a>(a: &'a [String], b: &[String]) -> Vec<&'a String> {
    a.iter().filter(|x| !b.contains(x)).collect()
}

/// A bound O changed relative to B: O's value if S still has B's value,
/// otherwise the more restrictive (lower) one. Withdrawals alone apply only
/// a lowered bound.
fn bound(s: i64, b: Option<i64>, o: i64, additions: bool) -> i64 {
    if b == Some(o) {
        return s;
    }
    if !additions {
        return match b {
            Some(b) if o < b => s.min(o),
            _ => s,
        };
    }
    if b == Some(s) { o } else { s.min(o) }
}
fn flag(s: bool, b: Option<bool>, o: bool, additions: bool) -> bool {
    if b == Some(o) {
        return s;
    }
    if !additions {
        return if b == Some(true) && !o { false } else { s };
    }
    if b == Some(s) { o } else { s && o }
}

struct Merge<'a> {
    additions: bool,
    skip: &'a [String],
    dropped: Vec<String>,
}
impl Merge<'_> {
    /// Merges set members: added ones, unless skipped, and removed ones.
    fn members(&mut self, s: &mut Vec<String>, b: &[String], o: &[String], what: &str, of: &str) {
        if self.additions {
            for m in minus(o, b) {
                if !self.skip.contains(&format!("{what} {m} of {of}")) && !s.contains(m) {
                    s.push(m.clone());
                }
            }
        }
        for m in minus(b, o) {
            s.retain(|x| x != m);
        }
    }
    /// Names the additions of a rule that S removed, as dropped.
    fn drop_members(&mut self, b: &[String], o: &[String], what: &str, of: &str) {
        if !self.additions {
            return;
        }
        for m in minus(o, b) {
            let name = format!("{what} {m} of {of}");
            if !self.skip.contains(&name) {
                self.dropped.push(name);
            }
        }
    }
    /// A rule's bounds are part of its key, so only its principals merge.
    fn rule(&mut self, s: &mut Rule, b: Option<&Rule>, o: &Rule) {
        let of = format!("rule {}", o.agent);
        let empty = Vec::new();
        self.members(
            &mut s.principals,
            b.map_or(&empty, |b| &b.principals),
            &o.principals,
            "principal",
            &of,
        );
    }
    fn capability_rule(
        &mut self,
        s: &mut CapabilityRule,
        b: Option<&CapabilityRule>,
        o: &CapabilityRule,
    ) {
        let of = format!("capability rule {}", o.capability);
        let empty = Vec::new();
        self.members(
            &mut s.principals,
            b.map_or(&empty, |b| &b.principals),
            &o.principals,
            "principal",
            &of,
        );
        let a = self.additions;
        s.max_input_bytes = bound(
            s.max_input_bytes,
            b.map(|b| b.max_input_bytes),
            o.max_input_bytes,
            a,
        );
        s.max_calls_per_hour = bound(
            s.max_calls_per_hour,
            b.map(|b| b.max_calls_per_hour),
            o.max_calls_per_hour,
            a,
        );
        s.allow_disconnected = flag(
            s.allow_disconnected,
            b.map(|b| b.allow_disconnected),
            o.allow_disconnected,
            a,
        );
    }
}

/// Re-applies an edit with starting point `b` and signed content `o` to the
/// stored content `s`. With `additions` false, only its withdrawals apply,
/// as this host enforces them while the edit is unsettled. Additions named
/// in `skip` were dropped earlier and are never re-applied. Returns the
/// content and the additions dropped now.
pub(crate) fn merge(
    s: &Content,
    b: &Content,
    o: &Content,
    skip: &[String],
    additions: bool,
) -> (Content, Vec<String>) {
    let mut m = Merge {
        additions,
        skip,
        dropped: Vec::new(),
    };
    let mut out = s.clone();
    // Trusted hosts.
    m.members(
        &mut out.trusted_hosts,
        &b.trusted_hosts,
        &o.trusted_hosts,
        "trusted host",
        "the policy",
    );
    out.trusted_hosts.sort();
    // Rules, keyed by agent name and settings: changing a rule's settings
    // removes the old rule and adds the new one.
    let first = |rules: &[Rule], key: &Rule| rules.iter().position(|r| r.same_key(key));
    let mut seen: Vec<&Rule> = Vec::new();
    for or in &o.rules {
        if seen.iter().any(|r| r.same_key(or)) {
            continue;
        }
        seen.push(or);
        let br = first(&b.rules, or).map(|i| &b.rules[i]);
        let si = first(&out.rules, or);
        match (br, si) {
            (Some(br), Some(si)) => m.rule(&mut out.rules[si], Some(br), or),
            (Some(br), None) => {
                let of = format!("rule {}", or.agent);
                m.drop_members(&br.principals, &or.principals, "principal", &of);
            }
            (None, _) if !additions => {}
            (None, _) if skip.contains(&format!("rule {}", or.agent)) => {}
            (None, Some(si)) => m.rule(&mut out.rules[si], None, or),
            (None, None) => out.rules.push(or.clone()),
        }
    }
    for br in &b.rules {
        if first(&o.rules, br).is_none() {
            out.rules.retain(|r| !r.same_key(br));
        }
    }
    out.rules.retain(|r| !r.principals.is_empty());
    // Capability rules, keyed by capability name; a name is bound to one
    // host.
    let find =
        |rules: &[CapabilityRule], name: &str| rules.iter().position(|r| r.capability == name);
    let mut seen: Vec<&str> = Vec::new();
    for or in &o.capability_rules {
        if seen.contains(&or.capability.as_str()) {
            continue;
        }
        seen.push(&or.capability);
        let br = find(&b.capability_rules, &or.capability)
            .map(|i| &b.capability_rules[i])
            .filter(|br| br.host == or.host);
        let si = find(&out.capability_rules, &or.capability);
        let here = si.filter(|i| out.capability_rules[*i].host == or.host);
        match (br, here) {
            (Some(br), Some(si)) => m.capability_rule(&mut out.capability_rules[si], Some(br), or),
            (Some(br), None) => m.drop_members(
                &br.principals,
                &or.principals,
                "principal",
                &format!("capability rule {}", or.capability),
            ),
            (None, _) if !additions => {}
            (None, here) => {
                let name = if or.principals.is_empty() {
                    format!("claim {}", or.capability)
                } else {
                    format!("capability rule {}", or.capability)
                };
                if skip.contains(&name) {
                    continue;
                }
                match (here, si) {
                    (Some(i), _) => m.capability_rule(&mut out.capability_rules[i], None, or),
                    // S binds the name to another host: the claim is dropped.
                    (None, Some(_)) => m.dropped.push(name),
                    (None, None) => out.capability_rules.push(or.clone()),
                }
            }
        }
    }
    for br in &b.capability_rules {
        let kept = o
            .capability_rules
            .iter()
            .any(|r| r.capability == br.capability && r.host == br.host);
        if !kept {
            out.capability_rules
                .retain(|r| !(r.capability == br.capability && r.host == br.host));
        }
    }
    (out, m.dropped)
}

/// Content compared as the statement signs it: trusted hosts sorted.
fn normalized(c: &Content) -> Content {
    let mut c = c.clone();
    c.trusted_hosts.sort();
    c
}
fn content_of(p: &Option<Policy>) -> Content {
    p.as_ref().map(Policy::content).unwrap_or_default()
}
fn with_content(p: &Policy, c: Content) -> Policy {
    let mut out = p.clone();
    out.rules = c.rules;
    out.capability_rules = Some(c.capability_rules);
    out.trusted_hosts = Some(c.trusted_hosts);
    out
}

// ---------------------------------------------------------------------
// Records.

fn records(conn: &Connection, network: &str, person: &str) -> Result<Vec<EditRecord>, Error> {
    let mut statement = conn.prepare(
        "SELECT record FROM policy_edits WHERE network_id = ?1 AND person_id = ?2 ORDER BY seq",
    )?;
    let rows = statement
        .query_map(params![network, person], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter().map(json).collect()
}
fn put(conn: &Connection, network: &str, person: &str, r: &EditRecord) -> Result<(), Error> {
    conn.execute(
        "INSERT OR REPLACE INTO policy_edits VALUES (?1, ?2, ?3, ?4)",
        params![network, person, r.seq as i64, serde_json::to_string(r)?],
    )?;
    Ok(())
}
fn groups(conn: &Connection) -> Result<Vec<(String, String)>, Error> {
    let mut statement = conn.prepare(
        "SELECT DISTINCT network_id, person_id FROM policy_edits ORDER BY network_id, person_id",
    )?;
    let rows = statement
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// What one re-application signs.
#[derive(Clone)]
pub(crate) struct Plan {
    network: String,
    key: String,
    stored: Policy,
    content: Content,
    edits: Vec<EditEntry>,
    duration: TimeDelta,
    dropped: Vec<(u64, Vec<String>)>,
}

impl Store {
    /// The hosts whose membership in a network ended for good: revoked
    /// by a root signature, by host key or by the invite they joined with,
    /// or with a valid leave statement. Signers drop their `edits` entries.
    pub(crate) fn retired_hosts(
        &self,
        conn: &Connection,
        network: &str,
    ) -> Result<Vec<String>, Error> {
        let record = self.network_record(conn, network)?;
        let roots = self.roots(conn, &record)?;
        let statements = crate::network::Statements::load(conn, network)?;
        let id = |key: &str| {
            crate::membership::canonical(key, 32)
                .ok()
                .map(|k| format!("host_{}", hex::encode(sha2::Sha256::digest(k))))
        };
        let mut out: Vec<String> = Vec::new();
        for h in &statements.hosts {
            if h.verify(network, &roots).is_ok() {
                out.extend(id(&h.host_public_key));
            }
        }
        for l in &statements.leaves {
            if l.verify(network).is_ok() {
                out.extend(id(&l.host_public_key));
            }
        }
        let invites: Vec<&str> = statements
            .invites
            .iter()
            .filter(|i| i.verify(network, &roots).is_ok())
            .map(|i| i.invite_public_key.as_str())
            .collect();
        if !invites.is_empty() {
            for m in self.stored_members(conn, network)? {
                if m.membership
                    .as_ref()
                    .is_some_and(|ms| invites.contains(&ms.invite_public_key.as_str()))
                {
                    out.push(m.host_id);
                }
            }
            // Hosts that joined with a revoked invite and have since left
            // the view, from their kept membership statements.
            let mut statement = conn.prepare(
                "SELECT subject, record FROM network_statements WHERE network_id = ?1 AND kind = 'membership'",
            )?;
            let joins = statement
                .query_map([network], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            for (key, record) in joins {
                let joined: crate::membership::Membership = json(record)?;
                if invites.contains(&joined.invite_public_key.as_str()) {
                    out.extend(id(&key));
                }
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }
    /// `p`'s `edits` without retired entries.
    pub(crate) fn unretired_edits(
        &self,
        conn: &Connection,
        network: &str,
        p: &Policy,
    ) -> Result<Vec<EditEntry>, Error> {
        let retired = self.retired_hosts(conn, network)?;
        Ok(p.kept_edits(|h| !retired.iter().any(|r| r == h)))
    }
    /// Whether `person` is this host's current person in a network. Edits
    /// of any other person are suspended: kept, but neither re-applied nor
    /// deleted, until that binding is current again.
    fn current_owner(&self, conn: &Connection, network: &str, person: &str) -> Result<bool, Error> {
        Ok(self.network_record(conn, network).is_ok()
            && self.own_person(conn, network)?.as_deref() == Some(person))
    }
    /// The stored policy with this host's unsettled edits re-applied, and
    /// the additions each dropped.
    fn merged(stored: &Policy, recs: &[EditRecord]) -> (Content, Vec<(u64, Vec<String>)>) {
        let mut content = stored.content();
        let mut dropped = Vec::new();
        for r in recs.iter().filter(|r| r.state == UNSETTLED) {
            let Some(signed) = &r.signed else { continue };
            let (next, d) = merge(
                &content,
                &content_of(&r.start),
                &signed.content(),
                &r.dropped,
                true,
            );
            content = next;
            dropped.push((r.seq, d));
        }
        (content, dropped)
    }

    /// `GET /v1/networks/{id}/policy/edit`: the starting point of an edit
    /// and its reserved number.
    pub fn edit_start(&self, network: &str) -> Result<Value, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        self.network_record(&tx, network)?;
        let person = self.own_person(&tx, network)?.ok_or(Error::NotFound)?;
        let key = self
            .person_key(&tx, network, &person)?
            .ok_or(Error::NotFound)?;
        if self
            .linking_projection(&tx, &self.network_record(&tx, network)?)
            .map_err(crate::link_runtime::support::model_error)?
            .is_some_and(|p| {
                p.access.policies.iter().any(|s| {
                    s.person_public_key == key && s.selection.high_water.version == u64::MAX
                })
            })
        {
            return Err(crate::link_runtime::support::model_error(
                crate::link_runtime::support::Failure {
                    error: "access version exhausted".into(),
                    ..crate::link_runtime::support::Failure::new("quota_exceeded", "-", "version")
                }
                .into(),
            ));
        }
        let stored = self.stored_policy(&tx, network, &key)?;
        let recs = records(&tx, network, &person)?;
        // The view leaves out retired `edits` entries, which the CLI drops.
        let retired = self.retired_hosts(&tx, network)?;
        let policy = stored.as_ref().map(|s| {
            let mut view = s.clone();
            if recs.iter().any(|r| r.state == UNSETTLED) {
                let (content, _) = Self::merged(s, &recs);
                view = with_content(s, content);
                view.signature = String::new();
            }
            let edits = s.kept_edits(|h| !retired.iter().any(|r| r == h));
            if edits.len() != s.edits().len() {
                view.edits = Some(edits);
                view.signature = String::new();
            }
            view
        });
        let me = self.identity().id;
        let highest = recs
            .iter()
            .map(|r| r.seq)
            .chain(stored.as_ref().map(|s| s.edit_seq(&me)))
            .max()
            .unwrap_or(0);
        if highest >= MAX_EDIT_SEQ {
            return Err(Error::Invalid("edit numbers are exhausted".into()));
        }
        let seq = highest + 1;
        put(
            &tx,
            network,
            &person,
            &EditRecord {
                seq,
                state: RESERVED.into(),
                start: policy.clone(),
                signed: None,
                signed_version: None,
                dropped: Vec::new(),
                reserved_at: now(),
                signed_at: None,
                changed_at: None,
                dropped_at: None,
            },
        )?;
        let version = self
            .linking_projection(&tx, &self.network_record(&tx, network)?)
            .map_err(crate::link_runtime::support::model_error)?
            .and_then(|p| {
                p.access
                    .policies
                    .iter()
                    .find(|p| p.person_public_key == key)
                    .map(|p| p.selection.high_water.version)
            })
            .unwrap_or_else(|| stored.as_ref().map_or(0, |s| s.version));
        tx.commit()?;
        Ok(json!({
            "policy": policy,
            "version": version,
            "seq": seq,
        }))
    }

    /// Checks a policy this host's CLI submitted for this host's person.
    /// An edit, one raising this host's `edits` entry, must cite the newest
    /// unlapsed reservation and build on the stored version. Returns its
    /// number, or None for a submission that is not an edit.
    pub(crate) fn check_edit(
        &self,
        tx: &Transaction<'_>,
        network: &str,
        p: &Policy,
    ) -> Result<Option<u64>, Error> {
        let person = p.person_id();
        if self.own_person(tx, network)?.as_deref() != Some(person.as_str()) {
            return Ok(None);
        }
        let me = self.identity().id;
        let stored = self.stored_policy(tx, network, &p.person_public_key)?;
        let seq = p.edit_seq(&me);
        if seq <= stored.as_ref().map_or(0, |s| s.edit_seq(&me)) || stored.as_ref() == Some(p) {
            return Ok(None);
        }
        let recs = records(tx, network, &person)?;
        let Some(r) = recs.iter().find(|r| r.seq == seq) else {
            return Err(Error::Invalid(format!(
                "the policy cites an unknown edit number {seq} for this host"
            )));
        };
        // A recorded edit submitted again is no new edit: the acceptance
        // rule decides, as for any policy.
        if r.state != RESERVED && r.signed.as_ref() == Some(p) {
            return Ok(None);
        }
        if r.state != RESERVED {
            return Err(Error::Invalid(format!(
                "edit number {seq} was already used"
            )));
        }
        let newest = recs
            .iter()
            .filter(|r| r.state == RESERVED)
            .map(|r| r.seq)
            .max();
        if newest != Some(seq) {
            return Err(edit_conflict("a newer edit was started on this host"));
        }
        if time(&r.reserved_at).is_none_or(|t| t + RESERVATION < Utc::now()) {
            return Err(Error::Invalid(format!(
                "the reservation of edit number {seq} lapsed"
            )));
        }
        let high_water = self
            .linking_projection(tx, &self.network_record(tx, network)?)
            .map_err(crate::link_runtime::support::model_error)?
            .and_then(|projection| {
                projection
                    .access
                    .policies
                    .iter()
                    .find(|selected| selected.person_public_key == p.person_public_key)
                    .map(|p| p.selection.high_water.version)
            })
            .unwrap_or_else(|| stored.as_ref().map_or(0, |s| s.version));
        let expected = high_water
            .checked_add(1)
            .ok_or_else(|| Error::Invalid("access version exhausted".into()))?;
        if p.version != expected {
            return Err(edit_conflict(&format!(
                "the stored policy changed: the edit must be version {expected}"
            )));
        }
        Ok(Some(seq))
    }
    /// Records a stored edit as settled.
    pub(crate) fn record_edit(
        &self,
        tx: &Transaction<'_>,
        network: &str,
        seq: u64,
        p: &Policy,
    ) -> Result<(), Error> {
        let person = p.person_id();
        let Some(mut r) = records(tx, network, &person)?
            .into_iter()
            .find(|r| r.seq == seq)
        else {
            return Ok(());
        };
        r.state = SETTLED.into();
        r.signed = Some(p.clone());
        r.signed_version = Some(p.version);
        r.signed_at = Some(now());
        put(tx, network, &person, &r)
    }
    /// After a policy of this host's person is stored: each recorded edit
    /// is settled while the policy reflects it, and unsettled otherwise.
    /// Schedules a re-application when any is unsettled.
    pub(crate) fn settle_edits(
        &self,
        tx: &Transaction<'_>,
        network: &str,
        p: &Policy,
    ) -> Result<(), Error> {
        let person = p.person_id();
        if self.own_person(tx, network)?.as_deref() != Some(person.as_str()) {
            return Ok(());
        }
        let me = self.identity().id;
        let reflected = p.edit_seq(&me);
        let mut unsettled = false;
        for mut r in records(tx, network, &person)? {
            if r.state != SETTLED && r.state != UNSETTLED {
                continue;
            }
            let state = if r.seq <= reflected {
                SETTLED
            } else {
                UNSETTLED
            };
            unsettled |= state == UNSETTLED;
            if r.state != state {
                r.state = state.into();
                if state == UNSETTLED {
                    r.changed_at = Some(now());
                }
                put(tx, network, &person, &r)?;
            }
        }
        if unsettled {
            self.schedule_reapply(network);
        }
        Ok(())
    }
    /// Schedules a re-application in `network` after a random 0 to 2
    /// seconds, unless one is already scheduled.
    pub(crate) fn schedule_reapply(&self, network: &str) {
        let mut buf = [0u8; 8];
        let _ = getrandom::fill(&mut buf);
        let delay = Duration::from_millis(u64::from_le_bytes(buf) % (JITTER_MS + 1));
        if let Ok(mut due) = self.edit_due.lock() {
            due.entry(network.to_owned())
                .or_insert_with(|| Instant::now() + delay);
        }
        self.policy_wake.notify_one();
    }
    /// Networks whose re-application is due now.
    pub(crate) fn due_reapplies(&self) -> Vec<String> {
        let Ok(mut due) = self.edit_due.lock() else {
            return Vec::new();
        };
        let at = Instant::now();
        let ready: Vec<String> = due
            .iter()
            .filter(|(_, t)| **t <= at)
            .map(|(n, _)| n.clone())
            .collect();
        for n in &ready {
            due.remove(n);
        }
        ready
    }
    /// Schedules every network with unsettled edits, as at each sync.
    pub(crate) fn schedule_unsettled(&self) -> Result<(), Error> {
        let networks = {
            let conn = self.connection()?;
            let mut out = Vec::new();
            for (network, person) in groups(&conn)? {
                if self.current_owner(&conn, &network, &person)?
                    && records(&conn, &network, &person)?
                        .iter()
                        .any(|r| r.state == UNSETTLED)
                {
                    out.push(network);
                }
            }
            out
        };
        for n in networks {
            self.schedule_reapply(&n);
        }
        Ok(())
    }
    /// Whether this host has unsettled edits in a network.
    pub(crate) fn has_unsettled(&self, network: &str) -> Result<bool, Error> {
        let conn = self.connection()?;
        let Some(person) = self.own_person(&conn, network)? else {
            return Ok(false);
        };
        Ok(records(&conn, network, &person)?
            .iter()
            .any(|r| r.state == UNSETTLED))
    }
    fn note_dropped(
        &self,
        tx: &Transaction<'_>,
        network: &str,
        person: &str,
        dropped: &[(u64, Vec<String>)],
        close: bool,
    ) -> Result<(), Error> {
        let at = now();
        for mut r in records(tx, network, person)? {
            let Some((_, d)) = dropped.iter().find(|(s, _)| *s == r.seq) else {
                continue;
            };
            if !d.is_empty() {
                for name in d {
                    if !r.dropped.contains(name) {
                        r.dropped.push(name.clone());
                    }
                }
                r.dropped_at = Some(at.clone());
                append_event(
                    tx,
                    "network.policy_edit_dropped",
                    &format!("{person}/{}", r.seq),
                    &at,
                )?;
            }
            if close && r.state == UNSETTLED {
                r.state = CLOSED.into();
                r.changed_at = Some(at.clone());
            }
            put(tx, network, person, &r)?;
        }
        Ok(())
    }
    /// The first step of re-applying: merges the unsettled edits into the
    /// stored policy. Unchanged content closes them here; otherwise the
    /// plan to sign.
    pub(crate) fn reapply_plan(&self, network: &str) -> Result<Option<Plan>, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let Some(person) = self.own_person(&tx, network)? else {
            tx.commit()?;
            return Ok(None);
        };
        let Some(key) = self.person_key(&tx, network, &person)? else {
            return Ok(None);
        };
        let Some(stored) = self.stored_policy(&tx, network, &key)? else {
            return Ok(None);
        };
        let recs = records(&tx, network, &person)?;
        let unsettled: Vec<&EditRecord> = recs.iter().filter(|r| r.state == UNSETTLED).collect();
        let Some(last) = unsettled.last() else {
            tx.commit()?;
            return Ok(None);
        };
        let (mut content, dropped) = Self::merged(&stored, &recs);
        // Identical duplicate rules of a version 1 policy become one.
        content.dedup_rules();
        if normalized(&content) == normalized(&stored.content()) {
            self.note_dropped(&tx, network, &person, &dropped, true)?;
            tx.commit()?;
            return Ok(None);
        }
        let me = self.identity().id;
        let mut kept = stored.clone();
        kept.edits = Some(self.unretired_edits(&tx, network, &stored)?);
        let edits = kept.edits_with(&me, last.seq);
        let duration = last
            .signed
            .as_ref()
            .map_or_else(|| stored.duration(), Policy::duration);
        tx.commit()?;
        Ok(Some(Plan {
            network: network.into(),
            key,
            stored,
            content,
            edits,
            duration,
            dropped,
        }))
    }
    /// Stores a signed re-application, unless the stored policy changed
    /// meanwhile; whether it was stored.
    fn commit_reapply(&self, plan: &Plan, p: &Policy) -> Result<bool, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let current = self.stored_policy(&tx, &plan.network, &plan.stored.person_public_key)?;
        if current.as_ref() != Some(&plan.stored) {
            return Ok(false);
        }
        let stored = self.accept_policy(&tx, &plan.network, p, Utc::now())?
            == crate::policy::Accepted::Stored;
        if stored {
            self.note_dropped(&tx, &plan.network, &p.person_id(), &plan.dropped, false)?;
        }
        tx.commit()?;
        Ok(stored)
    }

    /// The policy this host enforces for its own person: the stored one
    /// with the withdrawals of this host's unsettled edits applied.
    pub(crate) fn enforced(
        &self,
        conn: &Connection,
        network: &str,
        p: Policy,
    ) -> Result<Policy, Error> {
        let person = p.person_id();
        if self.own_person(conn, network)?.as_deref() != Some(person.as_str()) {
            return Ok(p);
        }
        let recs = records(conn, network, &person)?;
        if !recs.iter().any(|r| r.state == UNSETTLED) {
            return Ok(p);
        }
        let mut content = p.content();
        for r in recs.iter().filter(|r| r.state == UNSETTLED) {
            let Some(signed) = &r.signed else { continue };
            content = merge(
                &content,
                &content_of(&r.start),
                &signed.content(),
                &[],
                false,
            )
            .0;
        }
        Ok(with_content(&p, content))
    }

    /// Notes that `target`, a sibling or the coordinator, holds a policy
    /// reflecting this host's edits up to `seq` in a network.
    pub(crate) fn note_edit_ack(&self, network: &str, target: &str, seq: u64) {
        if let Ok(mut acks) = self.edit_acks.lock() {
            let entry = acks
                .entry((network.to_owned(), target.to_owned()))
                .or_insert(0);
            *entry = (*entry).max(seq);
        }
    }
    /// Deletes records no longer needed: lapsed reservations, closed records
    /// after 7 days, and settled ones every current sibling and the
    /// coordinator hold. The newest record of each network and owner stays.
    pub(crate) fn prune_edits(&self) -> Result<(), Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let at = Utc::now();
        let acks = self.edit_acks.lock().map(|a| a.clone()).unwrap_or_default();
        for (network, person) in groups(&tx)? {
            // Suspended edits are not deleted.
            if !self.current_owner(&tx, &network, &person)? {
                continue;
            }
            let recs = records(&tx, &network, &person)?;
            let newest = recs.iter().map(|r| r.seq).max().unwrap_or(0);
            let siblings = Some(self.siblings(&tx, &network, &person)?);
            let acked = |target: &str, seq: u64| {
                acks.get(&(network.clone(), target.to_owned()))
                    .is_some_and(|a| *a >= seq)
            };
            for r in recs.iter().filter(|r| r.seq != newest) {
                let delete = match r.state.as_str() {
                    RESERVED => time(&r.reserved_at).is_none_or(|t| t + RESERVATION < at),
                    CLOSED => r
                        .changed_at
                        .as_deref()
                        .and_then(time)
                        .is_none_or(|t| t + KEPT < at),
                    SETTLED => siblings.as_ref().is_some_and(|s| {
                        acked(crate::policy_sync::COORDINATOR, r.seq)
                            && s.iter().all(|h| acked(h, r.seq))
                    }),
                    _ => false,
                };
                if delete {
                    tx.execute(
                        "DELETE FROM policy_edits WHERE network_id = ?1 AND person_id = ?2 AND seq = ?3",
                        params![network, person, r.seq as i64],
                    )?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }
    /// The recorded edits of this host's person in a network, for `access
    /// sync --status`.
    pub(crate) fn edit_views(
        &self,
        conn: &Connection,
        network: &str,
        person: &str,
    ) -> Result<Vec<EditView>, Error> {
        Ok(records(conn, network, person)?
            .into_iter()
            .filter(|r| r.state != RESERVED)
            .map(|r| EditView {
                seq: r.seq,
                state: r.state,
                signed_version: r.signed_version,
                dropped: r.dropped,
            })
            .collect())
    }
    /// Status items 16 and 17: `(kind, subject, detail, command)`.
    pub(crate) fn edit_attention(&self) -> Result<Vec<(String, String, String, String)>, Error> {
        let conn = self.connection()?;
        let at = Utc::now();
        let mut out = Vec::new();
        for (network, person) in groups(&conn)? {
            if !self.current_owner(&conn, &network, &person)? {
                continue;
            }
            let recs = records(&conn, &network, &person)?;
            let mine = true;
            let late: Vec<u64> = recs
                .iter()
                .filter(|r| {
                    mine && r.state == UNSETTLED
                        && r.changed_at
                            .as_deref()
                            .and_then(time)
                            .is_none_or(|t| t + UNSETTLED_ATTENTION < at)
                })
                .map(|r| r.seq)
                .collect();
            if !late.is_empty() {
                out.push((
                    "policy_edit_unsettled".to_owned(),
                    network.clone(),
                    format!(
                        "policy edits {} of this host in network {network} have not settled for more than a minute, usually because the daemon has no person key to re-apply them",
                        late.iter().map(u64::to_string).collect::<Vec<_>>().join(", ")
                    ),
                    format!("peerspan access renew --network {network}"),
                ));
            }
            for r in &recs {
                if r.dropped.is_empty()
                    || r.dropped_at
                        .as_deref()
                        .and_then(time)
                        .is_none_or(|t| t + KEPT < at)
                {
                    continue;
                }
                out.push((
                    "policy_edit_dropped".to_owned(),
                    format!("{network}/{}", r.seq),
                    format!(
                        "a concurrent withdrawal won over edit {} of this host, which dropped: {}",
                        r.seq,
                        r.dropped.join(", ")
                    ),
                    format!("peerspan access show --network {network}"),
                ));
            }
        }
        Ok(out)
    }
}

/// Re-applies this host's unsettled edits in a network, signing with the
/// renewal key. Returns whether a policy was signed and stored.
pub(crate) async fn reapply(store: Arc<Store>, network: String) -> bool {
    let Some(_claim) = crate::policy_sync::Claim::take(&store, format!("reapply {network}")) else {
        return false;
    };
    let n = network.clone();
    let plan = match blocking(store.clone(), move |s| s.reapply_plan(&n)).await {
        Ok(Some(plan)) => plan,
        Ok(None) => return false,
        Err(e) => {
            eprintln!("policy edit re-application failed: {e}");
            return false;
        }
    };
    match crate::link_runtime::provider::automatic_policy(
        store.clone(),
        network.clone(),
        plan.stored.clone(),
        plan.content.clone(),
        plan.edits.clone(),
        plan.duration,
        Some(plan.clone()),
    )
    .await
    {
        Ok(Some(done)) => return done,
        Err(e) => {
            eprintln!("policy device re-application requires repair: {e}");
            return false;
        }
        Ok(None) => {}
    }
    let Ok(key) = crate::membership::canonical(&plan.key, 32) else {
        return false;
    };
    let Ok(key) = <[u8; 32]>::try_from(key) else {
        return false;
    };
    let signer = {
        let store = store.clone();
        let lookup = tokio::task::spawn_blocking(move || store.renewal_signer(key));
        match tokio::time::timeout(Duration::from_secs(10), lookup).await {
            Ok(Ok(Ok(signer))) => signer,
            // Without a key the edits stay unsettled.
            _ => return false,
        }
    };
    let at = Utc::now();
    // An ssh-agent answers over a blocking socket: sign off the runtime's
    // worker threads, bounded in time.
    let (n, version, content, edits, duration) = (
        network.clone(),
        match plan.stored.version.checked_add(1) {
            Some(v) => v,
            None => return false,
        },
        plan.content.clone(),
        plan.edits.clone(),
        plan.duration,
    );
    let signing = tokio::task::spawn_blocking(move || {
        Policy::sign_v2(
            &signer,
            &n,
            version,
            &rfc3339(at),
            &rfc3339(at + duration),
            content,
            edits,
        )
    });
    let signed = match tokio::time::timeout(Duration::from_secs(10), signing).await {
        Ok(Ok(Ok(p))) => p,
        Ok(Ok(Err(e))) => {
            eprintln!("policy edit re-application signing failed: {e}");
            return false;
        }
        _ => {
            eprintln!("policy edit re-application signing did not finish");
            return false;
        }
    };
    let p = signed.clone();
    match blocking(store.clone(), move |s| s.commit_reapply(&plan, &p)).await {
        Ok(true) => {
            crate::policy_sync::after_store(store, network, signed).await;
            true
        }
        Ok(false) => {
            // The stored policy changed meanwhile; try again on it.
            store.schedule_reapply(&network);
            false
        }
        Err(e) => {
            eprintln!("policy edit re-application failed: {e}");
            store.schedule_reapply(&network);
            false
        }
    }
}

pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new().route("/v1/networks/{id}/policy/edit", get(edit_route))
}
async fn edit_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, Error> {
    Ok(Json(blocking(store, move |s| s.edit_start(&id)).await?))
}

impl Store {
    pub(crate) fn reapply_unchanged(
        &self,
        tx: &rusqlite::Transaction<'_>,
        plan: &Plan,
    ) -> Result<bool, Error> {
        let Some(stored) = self.stored_policy(tx, &plan.network, &plan.key)? else {
            return Ok(false);
        };
        if stored != plan.stored {
            return Ok(false);
        }
        let recs = records(tx, &plan.network, &stored.person_id())?;
        let Some(last) = recs.iter().rfind(|r| r.state == UNSETTLED) else {
            return Ok(false);
        };
        let (mut content, dropped) = Self::merged(&stored, &recs);
        content.dedup_rules();
        let mut kept = stored.clone();
        kept.edits = Some(self.unretired_edits(tx, &plan.network, &stored)?);
        let edits = kept.edits_with(&self.identity().id, last.seq);
        let duration = last
            .signed
            .as_ref()
            .map_or_else(|| stored.duration(), Policy::duration);
        Ok(content == plan.content
            && edits == plan.edits
            && duration == plan.duration
            && dropped == plan.dropped)
    }
    pub(crate) fn note_device_reapply(
        &self,
        tx: &rusqlite::Transaction<'_>,
        plan: &Plan,
    ) -> Result<(), Error> {
        self.note_dropped(
            tx,
            &plan.network,
            &plan.stored.person_id(),
            &plan.dropped,
            false,
        )
    }
}
