//! Product authorization reads verified DEC state, never a signer or a receipt.
//! Unsigned rule bodies and their exact statements remain separate values.
use super::{
    codec::*,
    controls, edits,
    state::Projection,
    statement::{Descriptor, Statement, access_body},
    storage::Snapshot,
};
use crate::{
    model::Error as ModelError,
    network::Member,
    peer_store::key_id,
    policy::{Policy as LegacyPolicy, PolicyBody},
    store::Store,
};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension};
use serde_json::Value;
use std::{cell::RefCell, ops::Deref};
thread_local! {
    static READ_TIME: RefCell<Option<String>> = const { RefCell::new(None) };
}
/// A synchronous status read samples authority time once. This cannot affect
/// controller/signing clocks, and never survives an await or worker handoff.
pub(crate) fn with_read_time<T>(time: &str, read: impl FnOnce() -> T) -> T {
    struct Restore(Option<String>);
    impl Drop for Restore {
        fn drop(&mut self) {
            READ_TIME.with(|t| {
                t.replace(self.0.take());
            });
        }
    }
    let _restore = Restore(READ_TIME.with(|t| t.replace(Some(time.to_owned()))));
    read()
}
fn read_time() -> Result<String> {
    READ_TIME
        .with(|t| t.borrow().clone())
        .map_or_else(controls::local_decision_time, Ok)
}
fn status_unavailable(error: &Error) -> bool {
    READ_TIME.with(|t| t.borrow().is_some())
        && matches!(
            error.code,
            "clock_rollback"
                | "proof_required"
                | "state_conflict"
                | "migration_pending"
                | "forbidden"
                | "person_removed"
                | "authority_expired"
                | "expired"
                | "device_revoked"
                | "not_yet_valid"
        )
}
pub(crate) fn model(e: Error) -> ModelError {
    let status = match e.code {
        "invalid" => 400,
        "forbidden" | "authority_expired" | "device_revoked" | "not_yet_valid" => 403,
        "not_found" => 404,
        "internal" => 500,
        _ => 409,
    };
    ModelError::Coded {
        status,
        code: e.code,
        message: e.code.replace('_', " "),
        extra: serde_json::json!({"required_ids":e.required_ids})
            .as_object()
            .cloned()
            .unwrap_or_default(),
    }
}
pub(crate) fn is_decentralized(
    c: &Connection,
    network: &str,
) -> std::result::Result<bool, ModelError> {
    let mode: Option<String> = c
        .query_row(
            "SELECT json_extract(record,'$.mode') FROM networks WHERE id=?1",
            [network],
            |r| r.get(0),
        )
        .optional()?
        .flatten();
    Ok(mode.as_deref() == Some("decentralized"))
}
struct Context {
    snapshot: Snapshot,
    projection: std::sync::Arc<Projection>,
}
/// Projections of recent snapshots, keyed by network, own host key, the
/// snapshot's revision (a hash of every row it was loaded from) and the
/// decision time. A product read rebuilds the same projection many times per
/// request (membership, persons, policy, chain checks); the projection is a
/// pure function of these inputs, so an identical key reuses it.
type ProjectionKey = (String, String, String, String);
static PROJECTIONS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<ProjectionKey, std::sync::Arc<Projection>>>,
> = std::sync::LazyLock::new(Default::default);
const PROJECTION_CACHE: usize = 32;
impl Context {
    fn read(store: &Store, c: &Connection, network: &str) -> Result<Self> {
        let snapshot = Snapshot::load(c, network, &store.identity().public_key)?;
        require(
            !snapshot
                .migrations
                .iter()
                .any(|m| m.fenced && m.state != "adopted"),
            "migration_pending",
        )?;
        let now = read_time()?;
        let key = (
            network.to_owned(),
            store.identity().public_key,
            snapshot.revision.clone(),
            now.clone(),
        );
        let cached = if snapshot.revision.is_empty() {
            None
        } else {
            PROJECTIONS.lock().ok().and_then(|m| m.get(&key).cloned())
        };
        let projection = match cached {
            Some(p) => p,
            None => {
                let p = std::sync::Arc::new(snapshot.project(&now)?);
                if !snapshot.revision.is_empty()
                    && let Ok(mut m) = PROJECTIONS.lock()
                {
                    if m.len() >= PROJECTION_CACHE {
                        m.clear();
                    }
                    m.insert(key, p.clone());
                }
                p
            }
        };
        Ok(Self {
            snapshot,
            projection,
        })
    }
    fn members(&self, c: &Connection) -> Result<Vec<Member>> {
        let mut members = Vec::new();
        for member in self.projection.members()? {
            let host_id = key_id(&b64(&member.host_public_key, 32)?);
            let person = if member.person_public_key == "-" {
                None
            } else {
                Some(crate::persons::person_id(&b64(
                    &member.person_public_key,
                    32,
                )?))
            };
            let label = if member.person_lease_id == "-" {
                None
            } else {
                Some(
                    text(
                        self.projection
                            .catalog
                            .get(&member.person_lease_id)?
                            .subject()?,
                        "member",
                    )?
                    .to_owned(),
                )
            };
            let addresses = super::peer::product_addresses(
                c,
                &self.snapshot.descriptor.network_id,
                &self.snapshot.network.context_id,
                &member.host_public_key,
                &self.projection.decision_time,
            )?;
            members.push(Member {
                host_id,
                public_key: member.host_public_key,
                member: member.member,
                address: addresses.first().cloned().unwrap_or_default(),
                candidates: addresses,
                updated_at: self.projection.decision_time.clone(),
                membership: None,
                admission: None,
                person_id: person,
                person_member: label,
            });
        }
        Ok(members)
    }
}
enum Source {
    Legacy(LegacyPolicy),
    Decentralized(Statement),
}
pub(crate) struct Policy {
    body: PolicyBody,
    source: Source,
    pub valid_until: String,
}
impl Deref for Policy {
    type Target = PolicyBody;
    fn deref(&self) -> &PolicyBody {
        &self.body
    }
}
impl Policy {
    pub fn person_id(&self) -> String {
        crate::persons::person_id_of(&self.body.person_public_key).unwrap_or_default()
    }
    pub fn reference(&self) -> crate::policy::PolicyRef {
        crate::policy::PolicyRef {
            person_id: self.person_id(),
            version: self.body.version,
        }
    }
    pub fn in_window(&self, now: DateTime<Utc>) -> bool {
        match &self.source {
            Source::Legacy(p) => p.in_window(now),
            Source::Decentralized(s) => s.kind == "policy",
        }
    }
}
pub(crate) struct Person {
    pub person_id: String,
    pub person_public_key: String,
    pub member: String,
}
pub(crate) fn resolve_person<'a>(
    persons: &'a [Person],
    given: &str,
) -> std::result::Result<&'a Person, ModelError> {
    if let Some(p) = persons
        .iter()
        .find(|p| p.person_id == given || p.person_public_key == given)
    {
        return Ok(p);
    }
    if let Ok(key) = crate::persons::normalize_person_key(given)
        && let Some(p) = persons.iter().find(|p| p.person_public_key == key)
    {
        return Ok(p);
    }
    let matches: Vec<_> = persons
        .iter()
        .filter(|p| crate::network::labels_conflict(&p.member, given))
        .collect();
    match matches.as_slice() {
        [p] => Ok(p),
        [] => Err(ModelError::NotFound),
        many => Err(ModelError::Invalid(format!(
            "label {given:?} is ambiguous: {}",
            many.iter()
                .map(|p| format!("{} ({})", p.member, p.person_id))
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}
pub(crate) struct Group {
    pub name: String,
    pub members: Vec<String>,
}
impl Store {
    /// Durable network IDs are discovery scope only; every consumer checks
    /// the current native authority before using any membership or policy.
    pub(crate) fn product_network_ids(
        &self,
        c: &Connection,
    ) -> std::result::Result<Vec<String>, ModelError> {
        let mut q = c.prepare("SELECT id FROM networks WHERE ?1=0 OR json_extract(record,'$.mode')='decentralized' ORDER BY id")?;
        Ok(q.query_map([self.decentralized_runtime()], |r| r.get(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }
    pub(crate) fn product_network_names(
        &self,
        c: &Connection,
    ) -> std::result::Result<Vec<(String, String)>, ModelError> {
        let mut result = Vec::new();
        for id in self.product_network_ids(c)? {
            let name = if is_decentralized(c, &id)? {
                let raw: String =
                    c.query_row("SELECT record FROM networks WHERE id=?1", [&id], |r| {
                        r.get(0)
                    })?;
                let v = parse(raw.as_bytes(), 32 << 20).map_err(model)?;
                let row: super::storage::NetworkRecord = serde_json::from_value(v)?;
                let descriptor =
                    Descriptor::read(&b64(&row.descriptor_base64, MAX_OBJECT).map_err(model)?)
                        .map_err(model)?;
                require(
                    row.format == 2
                        && row.mode == "decentralized"
                        && row.context_id == descriptor.context_id()
                        && id == descriptor.network_id,
                    "state_conflict",
                )
                .map_err(model)?;
                descriptor.name
            } else {
                self.network_record(c, &id)?.name
            };
            result.push((id, name));
        }
        Ok(result)
    }
    pub(crate) fn product_persons(
        &self,
        c: &Connection,
        network: &str,
    ) -> std::result::Result<Vec<Person>, ModelError> {
        if !is_decentralized(c, network)? {
            return if self.decentralized_runtime() {
                Ok(Vec::new())
            } else {
                Ok(self
                    .stored_persons(c, network)?
                    .into_iter()
                    .map(|p| Person {
                        person_id: p.person_id,
                        person_public_key: p.person_public_key,
                        member: p.member,
                    })
                    .collect())
            };
        }
        let s = Context::read(self, c, network).map_err(model)?;
        let mut result = Vec::new();
        for stream in s
            .projection
            .streams
            .values()
            .filter(|r| r.key[0] == "person")
        {
            let statement = match s.projection.current_statement(&stream.key) {
                Ok((s, _)) => s,
                Err(e)
                    if matches!(
                        e.code,
                        "authority_expired"
                            | "not_yet_valid"
                            | "forbidden"
                            | "device_revoked"
                            | "person_removed"
                    ) =>
                {
                    continue;
                }
                Err(e) => return Err(model(e)),
            };
            result.push(Person {
                person_id: crate::persons::person_id(&b64(&stream.key[1], 32).map_err(model)?),
                person_public_key: stream.key[1].clone(),
                member: text(statement.subject().map_err(model)?, "member")
                    .map_err(model)?
                    .into(),
            });
        }
        result.sort_by(|a, b| a.person_id.cmp(&b.person_id));
        Ok(result)
    }
    /// Person keys with a current admin grant on a coordinator-free network.
    pub(crate) fn product_admins(
        &self,
        c: &Connection,
        network: &str,
    ) -> std::result::Result<std::collections::BTreeSet<String>, ModelError> {
        let s = Context::read(self, c, network).map_err(model)?;
        Ok(s.projection
            .streams
            .values()
            .filter(|r| r.key[0] == "admin" && r.key.len() == 2)
            .filter(|r| s.projection.current_statement(&r.key).is_ok())
            .map(|r| r.key[1].clone())
            .collect())
    }
    pub(crate) fn product_members(
        &self,
        c: &Connection,
        network: &str,
    ) -> std::result::Result<Vec<Member>, ModelError> {
        if is_decentralized(c, network)? {
            return match Context::read(self, c, network).and_then(|s| s.members(c)) {
                Ok(members) => Ok(members),
                Err(e) if status_unavailable(&e) => Ok(Vec::new()),
                Err(e) => Err(model(e)),
            };
        }
        if self.decentralized_runtime() {
            return Ok(Vec::new());
        }
        self.stored_members(c, network)
    }
    pub(crate) fn product_person_key(
        &self,
        c: &Connection,
        network: &str,
        person: &str,
    ) -> std::result::Result<Option<String>, ModelError> {
        if !is_decentralized(c, network)? {
            return if self.decentralized_runtime() {
                Ok(None)
            } else {
                self.person_key(c, network, person)
            };
        }
        Ok(self
            .product_persons(c, network)?
            .into_iter()
            .find(|p| p.person_id == person)
            .map(|p| p.person_public_key))
    }

    pub(crate) fn product_policy(
        &self,
        c: &Connection,
        network: &str,
        person: &str,
    ) -> std::result::Result<Option<Policy>, ModelError> {
        if !is_decentralized(c, network)? {
            if self.decentralized_runtime() {
                return Ok(None);
            }
            let Some(original) = self.stored_policy(c, network, person)? else {
                return Ok(None);
            };
            let applied = self.enforced(c, network, original.clone())?;
            return Ok(Some(Policy {
                body: applied.unsigned_body(),
                valid_until: applied.valid_until,
                source: Source::Legacy(original),
            }));
        }
        let s = match Context::read(self, c, network) {
            Ok(s) => s,
            // A status summary reports this exact failure in NETWORK_VIEW.
            // Its common shared/call/name counters cannot count unavailable
            // membership as usable or fail the entire owner diagnostic.
            Err(e) if status_unavailable(&e) => return Ok(None),
            Err(e) => return Err(model(e)),
        };
        let stream = vec!["policy".into(), person.into()];
        if !s.projection.streams.contains_key(&stream) {
            return Ok(None);
        }
        let statement = match s.projection.current_statement(&stream) {
            Ok(s) => s,
            Err(e) if status_unavailable(&e) => return Ok(None),
            Err(e)
                if matches!(
                    e.code,
                    "not_found"
                        | "authority_expired"
                        | "expired"
                        | "not_yet_valid"
                        | "forbidden"
                        | "device_revoked"
                ) =>
            {
                return Ok(None);
            }
            Err(e) => return Err(model(e)),
        };
        let mut body: PolicyBody = serde_json::from_value(Value::Object(
            access_body(&statement.0.payload).map_err(model)?,
        ))?;
        if s.snapshot.network.own_identity.person_public_key == person {
            let content =
                edits::enforced(c, &s.projection, person, body.content()).map_err(model)?;
            body.rules = content.rules;
            body.capability_rules = Some(content.capability_rules);
            body.trusted_hosts = Some(content.trusted_hosts);
        }
        Ok(Some(Policy {
            body,
            source: Source::Decentralized(statement.0.clone()),
            valid_until: statement.1,
        }))
    }
    pub(crate) fn product_groups(
        &self,
        c: &Connection,
        network: &str,
    ) -> std::result::Result<Vec<Group>, ModelError> {
        if !is_decentralized(c, network)? {
            return if self.decentralized_runtime() {
                Ok(Vec::new())
            } else {
                Ok(self
                    .stored_groups(c, network)?
                    .into_iter()
                    .map(|g| Group {
                        name: g.name,
                        members: g.members,
                    })
                    .collect())
            };
        }
        let s = Context::read(self, c, network).map_err(model)?;
        let mut groups = Vec::new();
        for stream in s
            .projection
            .streams
            .values()
            .filter(|r| r.key[0] == "group")
        {
            let statement = match s.projection.current_statement(&stream.key) {
                Ok((s, _)) => s,
                Err(e)
                    if matches!(
                        e.code,
                        "authority_expired" | "not_yet_valid" | "forbidden" | "device_revoked"
                    ) =>
                {
                    continue;
                }
                Err(e) => return Err(model(e)),
            };
            let body = access_body(&statement.payload).map_err(model)?;
            groups.push(Group {
                name: text(&body, "name").map_err(model)?.into(),
                members: ids(&body, "members", "person_").map_err(model)?,
            });
        }
        Ok(groups)
    }
    pub(crate) fn product_member(
        &self,
        c: &Connection,
        network: &str,
        host: &str,
    ) -> std::result::Result<Option<Member>, ModelError> {
        Ok(self
            .product_members(c, network)?
            .into_iter()
            .find(|m| m.host_id == host))
    }
    pub(crate) fn product_members_of(
        &self,
        c: &Connection,
        host: &str,
    ) -> std::result::Result<Vec<(String, Member)>, ModelError> {
        let ids = if self.decentralized_runtime() {
            self.product_network_ids(c)?
        } else {
            let mut q=c.prepare("SELECT network_id FROM network_members WHERE host_id=?1 UNION SELECT id FROM networks ORDER BY 1")?;
            q.query_map([host], |r| r.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        let own = self.identity().id;
        let mut result = Vec::new();
        for id in ids {
            let members = self.product_members(c, &id)?;
            if members.iter().any(|m| m.host_id == own)
                && let Some(member) = members.into_iter().find(|m| m.host_id == host)
            {
                result.push((id, member));
            }
        }
        Ok(result)
    }
    pub(crate) fn decentralized_own_members(
        &self,
        c: &Connection,
    ) -> std::result::Result<Vec<(String, Member)>, ModelError> {
        let ids = {
            let mut q=c.prepare("SELECT id FROM networks WHERE json_extract(record,'$.mode')='decentralized' ORDER BY id")?;
            q.query_map([], |r| r.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        let own = self.identity().id;
        let mut rows = Vec::new();
        for network in ids {
            if let Some(member) = self
                .product_members(c, &network)?
                .into_iter()
                .find(|m| m.host_id == own)
            {
                rows.push((network, member));
            }
        }
        Ok(rows)
    }
}
pub(crate) fn principal_matches(
    principal: &str,
    sender: &Member,
    groups: &[Group],
    origin: Option<&crate::peer_store::Origin>,
) -> bool {
    crate::policy::principal_matches_with_group(
        principal,
        sender,
        |name, person| {
            groups
                .iter()
                .any(|g| g.name == name && g.members.iter().any(|m| m == person))
        },
        origin,
    )
}
