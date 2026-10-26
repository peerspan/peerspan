//! Signed enrollment and the coordination client. Coordination distributes
//! membership chains and addresses; this host verifies every chain itself and
//! persists the verified map so known members keep working during outages.
use crate::{
    admins::{self, AdminDelegation, AdminRemoval, Authority, Group, GroupView},
    api::{blocking, decode},
    membership::{
        self, Attestation, ChainRelation, CoordinatorPending, HostRevocation, InviteRevocation,
        InviteToken, KeySigner, Leave, Membership, Rotation,
    },
    model::Error,
    peer::{https, pinned_client_config},
    peer_store::{Peer, json, key_id, read, records},
    persons::{
        self, Descriptor, HostAdmission, HostBinding, HostUnbinding, MEMBER_TOKEN_PREFIX,
        MemberInviteToken, PersonAdmission, PersonInviteToken, PersonMembership, PersonRemoval,
    },
    store::{Store, append_event, now, rfc3339},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, Query, State, rejection::BytesRejection},
    http::StatusCode,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use hyper::Method;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json as json_value};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

pub(crate) const SCHEMA: &str = "
CREATE TABLE networks (id TEXT PRIMARY KEY, record TEXT NOT NULL, root_seed BLOB);
CREATE TABLE network_members (network_id TEXT NOT NULL, host_id TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(network_id, host_id));
PRAGMA user_version = 3;
";
/// Database version 7: every verified root rotation, current attestation, and
/// sticky revocation per network.
pub(crate) const STATEMENT_SCHEMA: &str = "
CREATE TABLE network_statements (network_id TEXT NOT NULL, kind TEXT NOT NULL, subject TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(network_id, kind, subject));
PRAGMA user_version = 7;
";

const MAX_INVITE_LIFETIME: chrono::TimeDelta = chrono::TimeDelta::days(30);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Network {
    pub id: String,
    pub name: String,
    pub root_public_key: String,
    pub member: String,
    pub coordinator_address: String,
    pub coordinator_public_key: String,
    pub administrator: bool,
    pub last_sync_at: Option<String>,
    pub last_sync_error: Option<String>,
    /// Epoch of the current root; 0 until the root is rotated.
    #[serde(default)]
    pub root_epoch: u64,
    /// The current root, which signs new invites, revocations, and
    /// attestations. `root_public_key` stays the genesis key that derives `id`.
    #[serde(default)]
    pub current_root_public_key: String,
    /// True when the current root is an SSH key (it signs with `SSHSIG`), so
    /// root actions go through the CLI's `--root-key`.
    #[serde(default)]
    pub root_ssh: bool,
    /// A verified successor of the pinned coordinator, followed once a sync
    /// with it succeeds; null when nothing is pending.
    #[serde(default)]
    pub coordinator_pending: Option<CoordinatorPending>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Member {
    pub host_id: String,
    pub public_key: String,
    pub member: String,
    pub address: String,
    /// Path-discovery hints published by the member; never dial addresses.
    #[serde(default)]
    pub candidates: Vec<String>,
    pub updated_at: String,
    /// The invite chain, for a host that joined with an invite token.
    #[serde(default)]
    pub membership: Option<Membership>,
    /// The administrator's admission, for a host admitted by public key.
    #[serde(default)]
    pub admission: Option<HostAdmission>,
    /// The person this host is bound to, if any.
    #[serde(default)]
    pub person_id: Option<String>,
    #[serde(default)]
    pub person_member: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateNetwork {
    pub name: String,
    pub member: String,
    /// With `coordinator_public_key`, the coordinator; both empty or absent
    /// select the build's default coordinator.
    #[serde(default, deserialize_with = "empty_if_null")]
    pub coordinator_address: String,
    #[serde(default, deserialize_with = "empty_if_null")]
    pub coordinator_public_key: String,
    /// The creator's person key, found by the CLI; admitted with the new root
    /// under the creator's member label once the network is registered.
    #[serde(default)]
    pub person_public_key: Option<String>,
}
fn empty_if_null<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    Ok(Option::<String>::deserialize(d)?.unwrap_or_default())
}

/// The coordinator this build uses when `network create` names none, from
/// `PEERSPAN_COORDINATOR` and `PEERSPAN_COORDINATOR_KEY` at build time. A build
/// with only one of the two has no default.
pub fn default_coordinator() -> Option<(&'static str, &'static str)> {
    match (
        option_env!("PEERSPAN_COORDINATOR"),
        option_env!("PEERSPAN_COORDINATOR_KEY"),
    ) {
        (Some(address), Some(key)) if !address.is_empty() && !key.is_empty() => {
            Some((address, key))
        }
        _ => None,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateInvite {
    #[serde(default)]
    pub member: String,
    #[serde(default)]
    pub expires_at: String,
    /// Issue a host-only invite instead of the default member invite.
    #[serde(default)]
    pub host_only: bool,
    /// A token an administrator signed through the CLI; the daemon checks the
    /// signer, records the invite, and returns it.
    #[serde(default)]
    pub token: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinNetwork {
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub descriptor: Option<String>,
    /// The joining person's key and the binding the CLI signed for this host;
    /// the daemon never sees the person key itself.
    #[serde(default)]
    pub person_public_key: Option<String>,
    #[serde(default)]
    pub binding: Option<HostBinding>,
}
/// What the one-command flows did about the person. A skipped step never
/// undoes the host join; `next` names the exact command that finishes it.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct PersonOutcome {
    pub person_id: Option<String>,
    pub admitted: bool,
    pub bound: bool,
    pub skipped: Option<String>,
    pub next: Option<String>,
}
/// A network record plus the person outcome of create or join.
#[derive(Debug, Serialize)]
pub struct Joined {
    #[serde(flatten)]
    pub network: Network,
    pub person: Option<PersonOutcome>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmitPerson {
    #[serde(default)]
    pub person_public_key: String,
    #[serde(default)]
    pub member: String,
    /// Signed already, by an administrator's SSH key through the CLI.
    #[serde(default)]
    pub admission: Option<PersonAdmission>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmitHost {
    #[serde(default)]
    pub host_public_key: String,
    #[serde(default)]
    pub member: String,
    /// Signed already, by an administrator's SSH key through the CLI.
    #[serde(default)]
    pub admission: Option<HostAdmission>,
}
#[derive(Debug, Serialize)]
pub struct AdmittedPerson {
    pub person_id: String,
    pub descriptor: String,
}
#[derive(Debug, Serialize)]
pub struct AdmittedHost {
    pub host_id: String,
    pub descriptor: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedeemPerson {
    pub token: String,
    pub person_public_key: String,
}
#[derive(Debug, Serialize)]
pub struct RedeemedPerson {
    pub person_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bind {
    pub binding: HostBinding,
}
#[derive(Debug, Serialize)]
pub struct Bound {
    pub network_id: String,
    pub host_id: String,
    pub person_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Unbind {
    pub unbinding: HostUnbinding,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemovePerson {
    #[serde(default)]
    pub person_id: String,
    /// A removal an administrator signed through the CLI.
    #[serde(default)]
    pub removal: Option<PersonRemoval>,
}
/// `network delegate-admin`: root only. Either the person to delegate (this
/// host signs with the root seed) or a delegation the CLI signed with an SSH
/// root key.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegateAdmin {
    #[serde(default)]
    pub person: Option<String>,
    #[serde(default)]
    pub delegation: Option<AdminDelegation>,
}
#[derive(Debug, Serialize)]
pub struct Delegated {
    pub network_id: String,
    pub person_id: String,
}
/// `network remove-admin`: root only, sticky and local-first.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoveAdmin {
    #[serde(default)]
    pub person: Option<String>,
    #[serde(default)]
    pub revoke_admitted: bool,
    #[serde(default)]
    pub removal: Option<AdminRemoval>,
}
/// `network group set`: the root (this host signs) or a group version an
/// administrator signed through the CLI.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetGroup {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub members: Vec<String>,
    #[serde(default)]
    pub group: Option<Group>,
}
/// A rotation to an SSH root: the CLI signs everything the new root signs;
/// the rotation itself is signed here with the root seed, or by the CLI with
/// the current SSH root.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotateToSsh {
    pub root_public_key: String,
    #[serde(default)]
    pub rotation: Option<Rotation>,
    #[serde(default)]
    pub attestations: Vec<Attestation>,
    #[serde(default)]
    pub admissions: Vec<Value>,
    #[serde(default)]
    pub groups: Vec<Group>,
}
/// A verified person: its admission or invite chain under the current root.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersonEntry {
    pub person_id: String,
    pub person_public_key: String,
    pub member: String,
    #[serde(default)]
    pub admission: Option<PersonAdmission>,
    #[serde(default)]
    pub membership: Option<PersonMembership>,
}
/// The stored form of a verified person (`network_statements` kind
/// `person`): exactly one of an admission or an invite chain, the one that
/// verified under the current root.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersonProof {
    #[serde(default)]
    admission: Option<PersonAdmission>,
    #[serde(default)]
    membership: Option<PersonMembership>,
}
impl PersonEntry {
    fn proof(&self) -> PersonProof {
        match &self.admission {
            Some(a) => PersonProof {
                admission: Some(a.clone()),
                membership: None,
            },
            None => PersonProof {
                admission: None,
                membership: self.membership.clone(),
            },
        }
    }
    fn from_proof(proof: PersonProof) -> Result<Self, Error> {
        let (key, member) = match (&proof.admission, &proof.membership) {
            (Some(a), _) => (a.person_public_key.clone(), a.member.clone()),
            (None, Some(m)) => (m.person_public_key.clone(), m.member.clone()),
            (None, None) => {
                return Err(Error::Internal(anyhow::anyhow!(
                    "stored person has no admission"
                )));
            }
        };
        Ok(Self {
            person_id: persons::person_id_of(&key)?,
            person_public_key: key,
            member,
            admission: proof.admission,
            membership: proof.membership,
        })
    }
}
#[derive(Debug, Serialize)]
pub struct PersonView {
    pub person_id: String,
    pub public_key: String,
    pub member: String,
    pub hosts: Vec<String>,
    /// A current administrator of the network.
    pub administrator: bool,
    /// Set when another current person holds a conflicting label, which only a
    /// misbehaving coordinator can produce; both persons stay valid.
    pub label_conflict: bool,
}
/// Person labels conflict when equal after mapping ASCII A–Z to a–z; other
/// bytes compare exactly, so Go and Rust agree without Unicode case folding.
pub(crate) fn labels_conflict(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}
#[derive(Debug, Serialize)]
pub struct IssuedInvite {
    pub network_id: String,
    pub member: String,
    pub invite_public_key: String,
    pub invite_expires_at: String,
    pub token: String,
}
#[derive(Deserialize)]
pub(crate) struct WireMap {
    #[serde(skip)]
    pub(crate) active_map: Option<Vec<u8>>,
    pub(crate) network_id: String,
    pub(crate) root_public_key: String,
    pub(crate) members: Vec<Value>,
    #[serde(default)]
    pub(crate) rotations: Vec<Value>,
    #[serde(default)]
    pub(crate) attestations: Vec<Value>,
    #[serde(default)]
    pub(crate) revocations: Vec<Value>,
    #[serde(default)]
    pub(crate) persons: Vec<Value>,
    #[serde(default)]
    pub(crate) admins: Vec<Value>,
    #[serde(default)]
    pub(crate) groups: Vec<Value>,
    #[serde(default)]
    pub(crate) policies: Vec<Value>,
    /// Register, join, and sync responses: the coordinator's successors.
    #[serde(default)]
    pub(crate) successors: Value,
    /// The network's current coordinator move, or null.
    #[serde(default, rename = "move")]
    pub(crate) r#move: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revoke {
    #[serde(default)]
    pub host_id: Option<String>,
    #[serde(default)]
    pub invite_public_key: Option<String>,
    /// A host or invite revocation an administrator signed through the CLI.
    #[serde(default)]
    pub revocation: Option<Value>,
}
#[derive(Debug, Serialize)]
pub struct Revoked {
    pub network_id: String,
    pub kind: String,
    pub subject: String,
    pub submitted: bool,
}
#[derive(Debug, Serialize)]
pub struct Left {
    pub network_id: String,
    pub submitted: bool,
}

/// What a removal without `revoke_admitted` keeps.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdminRemovalPlan {
    pub person_public_key: String,
    pub kept: Vec<String>,
}
/// What a new root signs at a rotation, as `GET .../rotation-plan` serves it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RotationPlan {
    pub network_id: String,
    pub epoch: u64,
    pub current_root_public_key: String,
    pub attestations: Vec<PlannedItem>,
    pub host_admissions: Vec<PlannedItem>,
    pub person_admissions: Vec<PlannedItem>,
    /// Current administrators' person keys, whose delegations are re-signed.
    pub admins: Vec<String>,
    /// Root-signed groups (deleted ones too), renewed at the same version.
    #[serde(default)]
    pub groups: Vec<PlannedGroup>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlannedGroup {
    pub name: String,
    pub version: u64,
    pub members: Vec<String>,
}
/// What the next root signs for a rotation.
pub struct SignedPlan {
    pub attestations: Vec<Attestation>,
    pub admissions: Vec<Value>,
    pub groups: Vec<Group>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlannedItem {
    pub public_key: String,
    pub member: String,
}
impl RotationPlan {
    /// Signs the plan with the next root: the attestations, and the
    /// admissions and delegations for the rotation's `admissions`.
    pub fn sign(&self, next: &KeySigner, at: &str) -> Result<SignedPlan, Error> {
        let (id, epoch) = (self.network_id.as_str(), self.epoch);
        let attestations = self
            .attestations
            .iter()
            .map(|i| Attestation::sign_with(next, id, epoch, &i.public_key, &i.member, at))
            .collect::<Result<Vec<_>, _>>()?;
        let mut admissions = Vec::new();
        for i in &self.host_admissions {
            admissions.push(serde_json::to_value(HostAdmission::sign_with(
                next,
                id,
                epoch,
                &i.public_key,
                &i.member,
                at,
            )?)?);
        }
        for i in &self.person_admissions {
            admissions.push(serde_json::to_value(PersonAdmission::sign_with(
                next,
                id,
                epoch,
                &i.public_key,
                &i.member,
                at,
            )?)?);
        }
        for key in &self.admins {
            admissions.push(serde_json::to_value(AdminDelegation::sign(
                next, id, epoch, key, at,
            )?)?);
        }
        let groups = self
            .groups
            .iter()
            .map(|g| Group::sign(next, id, &g.name, g.version, &g.members, at))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SignedPlan {
            attestations,
            admissions,
            groups,
        })
    }
}
/// A signed rotation not yet accepted by the coordinator, persisted before
/// submission as `network_statements` kind `pending_rotation` (subject: the
/// epoch). `root_seed` is the new root's seed in standard Base64; the state
/// directory protects it like `networks.root_seed`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PendingRotation {
    pub(crate) rotation: Rotation,
    pub(crate) attestations: Vec<Attestation>,
    /// Host and person admissions re-signed at the new epoch.
    #[serde(default)]
    pub(crate) admissions: Vec<Value>,
    /// Root-signed groups renewed by the new root under the active version rules.
    #[serde(default)]
    pub(crate) groups: Vec<Group>,
    pub(crate) root_seed: String,
}
#[derive(Debug)]
enum PendingOutcome {
    None,
    Committed,
    Discarded,
    Resubmit(Box<PendingRotation>),
}

/// Every verified statement this host holds for one network.
#[derive(Default)]
pub(crate) struct Statements {
    pub(crate) rotations: Vec<Rotation>,
    pub(crate) attestations: Vec<Attestation>,
    pub(crate) hosts: Vec<HostRevocation>,
    pub(crate) invites: Vec<InviteRevocation>,
    pub(crate) leaves: Vec<Leave>,
    pub(crate) person_removals: Vec<PersonRemoval>,
    pub(crate) unbindings: Vec<HostUnbinding>,
    /// Current administrator delegations (replaced by each map).
    pub(crate) admins: Vec<AdminDelegation>,
    /// Sticky administrator removals.
    pub(crate) admin_removals: Vec<AdminRemoval>,
    /// The applicable version of each group, deleted ones included.
    pub(crate) groups: Vec<Group>,
    /// The newest verified policy of each person.
    pub(crate) policies: Vec<crate::policy::Policy>,
}
impl Statements {
    pub(crate) fn load(connection: &Connection, network: &str) -> Result<Self, Error> {
        let mut statement = connection.prepare(
            "SELECT kind, subject, record FROM network_statements WHERE network_id = ?1",
        )?;
        let rows = statement
            .query_map([network], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut out = Self::default();
        for (kind, _, record) in rows {
            match kind.as_str() {
                "rotation" => out.rotations.push(json(record)?),
                "attestation" => out.attestations.push(json(record)?),
                "host" => out.hosts.push(json(record)?),
                "invite" => out.invites.push(json(record)?),
                "leave" => out.leaves.push(json(record)?),
                "person_removal" => out.person_removals.push(json(record)?),
                "unbind" => out.unbindings.push(json(record)?),
                "admin" => out.admins.push(json(record)?),
                "admin_removal" => out.admin_removals.push(json(record)?),
                "group" => out.groups.push(json(record)?),
                "policy" => out.policies.push(json(record)?),
                _ => {}
            }
        }
        out.rotations.sort_by_key(|r| r.epoch);
        Ok(out)
    }
}
/// A map verified against this host's persisted statements.
struct VerifiedMap {
    members: Vec<Member>,
    persons: Vec<PersonEntry>,
    bindings: Vec<HostBinding>,
    rotations: Vec<Rotation>,
    roots: Vec<String>,
    statements: Statements,
}
/// Keeps each member's membership statement (`membership`, by host public
/// key), so a root-signed revocation of its invite can still be matched
/// once the member has left the view.
fn remember_joins(tx: &Connection, store: &Store, network: &str) -> Result<(), Error> {
    remember_memberships(tx, network, &store.stored_members(tx, network)?)
}
fn remember_memberships(tx: &Connection, network: &str, members: &[Member]) -> Result<(), Error> {
    for m in members {
        if let Some(membership) = &m.membership
            && membership.host_public_key == m.public_key
        {
            insert_statement(tx, network, "membership", &m.public_key, membership)?;
        }
    }
    Ok(())
}
fn insert_statement(
    tx: &Connection,
    network: &str,
    kind: &str,
    subject: &str,
    record: &impl Serialize,
) -> Result<bool, Error> {
    Ok(tx.execute(
        "INSERT OR IGNORE INTO network_statements VALUES (?1, ?2, ?3, ?4)",
        params![network, kind, subject, serde_json::to_string(record)?],
    )? > 0)
}
#[derive(Deserialize)]
struct WireMember {
    host_id: String,
    #[serde(default)]
    membership: Option<Membership>,
    #[serde(default)]
    admission: Option<Value>,
    #[serde(default)]
    binding: Option<Value>,
    address: String,
    #[serde(default)]
    candidates: Value,
    updated_at: String,
}

/// Keeps at most `MAX_ENDPOINTS` distinct literal `IP:PORT` candidates with
/// nonzero ports; anything else is dropped rather than the member.
fn valid_candidates(value: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for item in value.as_array().into_iter().flatten() {
        let Some(text) = item.as_str() else {
            continue;
        };
        match text.parse::<std::net::SocketAddr>() {
            Ok(addr) if addr.port() != 0 && !out.iter().any(|c| c == text) => {
                out.push(text.to_owned())
            }
            _ => {}
        }
        if out.len() == crate::disco::MAX_ENDPOINTS {
            break;
        }
    }
    out
}

fn random_seed() -> Result<SigningKey, Error> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|e| Error::Internal(anyhow::anyhow!("random source: {e}")))?;
    Ok(SigningKey::from_bytes(&seed))
}

pub(crate) fn load_member_pins(
    connection: &Connection,
    self_id: &str,
) -> anyhow::Result<BTreeMap<String, Vec<u8>>> {
    let members = records::<Member>(connection, "SELECT record FROM network_members")
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut pins = BTreeMap::new();
    for m in members.into_iter().filter(|m| m.host_id != self_id) {
        let key = membership::canonical(&m.public_key, 32).map_err(|e| anyhow::anyhow!("{e}"))?;
        if key_id(&key) != m.host_id {
            anyhow::bail!("persisted network member key does not match its ID");
        }
        pins.insert(m.host_id, key);
    }
    Ok(pins)
}

/// Verifies a coordinator map against this host's persisted statements.
///
/// The root chain must equal or extend the persisted one; a fork or a stale
/// chain is refused. Revocations from the map are added to the persisted ones
/// (sticky) when they verify under any root in the chain. At epoch 0 a member
/// is valid by its invite chain under the genesis root; after a rotation only
/// an invite chain under the current root or a current-epoch attestation
/// counts. Entries whose chain fails, whose ID mismatches, whose key or invite
/// is revoked, or whose invite key was used by more than one host key are
/// dropped. A forged member cannot be introduced without the invite secret.
fn verify_map(
    network: &Network,
    map: WireMap,
    persisted: Statements,
) -> Result<VerifiedMap, Error> {
    if map.network_id != network.id || map.root_public_key != network.root_public_key {
        return Err(Error::Unavailable(
            "coordinator map does not match this network".into(),
        ));
    }
    let offered: Vec<Rotation> = map
        .rotations
        .into_iter()
        .map(serde_json::from_value)
        .collect::<Result<_, _>>()
        .map_err(|_| Error::Unavailable("malformed root chain".into()))?;
    let roots = membership::verify_chain(&network.id, &network.root_public_key, &offered)
        .map_err(|_| Error::Unavailable("invalid root chain".into()))?;
    match membership::chain_relation(&persisted.rotations, &offered) {
        ChainRelation::Fork => return Err(Error::Unavailable("root chain conflict".into())),
        ChainRelation::Behind => {
            return Err(Error::Unavailable(CHAIN_BEHIND.into()));
        }
        ChainRelation::Extends => {}
    }
    let epoch = (roots.len() - 1) as u64;
    let current = roots.last().expect("chain has a genesis root").clone();
    let mut statements = persisted;
    // Attestations only count for the current epoch, under the current root.
    let mut attestations: Vec<Attestation> = Vec::new();
    for a in statements.attestations.drain(..).chain(
        map.attestations
            .into_iter()
            .filter_map(|v| serde_json::from_value(v).ok()),
    ) {
        if a.verify(&network.id, epoch, &current).is_ok()
            && !attestations
                .iter()
                .any(|b| b.host_public_key == a.host_public_key)
        {
            attestations.push(a);
        }
    }
    statements.attestations = attestations;
    // Administrator removals are root-only and sticky; they decide whose
    // statements still count before anything an administrator signed.
    let mut offered_revocations: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for entry in map.revocations {
        let kind = entry["kind"].as_str().unwrap_or_default().to_owned();
        offered_revocations
            .entry(kind)
            .or_default()
            .push(entry["statement"].clone());
    }
    for statement in offered_revocations.remove("admin").unwrap_or_default() {
        let Ok(r) = serde_json::from_value::<AdminRemoval>(statement) else {
            continue;
        };
        if r.verify(&network.id, &roots).is_err() {
            continue;
        }
        // One removal per key; one with revoke_admitted supersedes one without.
        match statements
            .admin_removals
            .iter_mut()
            .find(|a| a.person_public_key == r.person_public_key)
        {
            None => statements.admin_removals.push(r),
            Some(old) if r.revoke_admitted && !old.revoke_admitted => *old = r,
            Some(_) => {}
        }
    }
    let removed_admins: BTreeSet<String> = statements
        .admin_removals
        .iter()
        .map(|r| r.person_public_key.clone())
        .collect();
    // Delegations are kept, like the coordinator serves them, even for
    // removed administrators: a plain removal leaves their statements valid.
    let delegations = admins::latest_delegations(
        &network.id,
        &roots,
        std::mem::take(&mut statements.admins).into_iter().chain(
            map.admins
                .into_iter()
                .filter_map(|v| serde_json::from_value::<AdminDelegation>(v).ok()),
        ),
    );
    let mut authority = Authority::new(roots.clone(), &delegations, &statements.admin_removals);
    // Statements signed by an administrator removed with revoke_admitted no
    // longer count, including sticky revocations they signed.
    statements
        .hosts
        .retain(|r| !authority.is_cascaded(&r.signature));
    statements
        .invites
        .retain(|r| !authority.is_cascaded(&r.signature));
    statements
        .person_removals
        .retain(|r| !authority.is_cascaded(&r.signature));
    merge_revocations(network, &authority, &offered_revocations, &mut statements);
    let persons = verify_persons(network, epoch, &authority, &map.persons, &statements);
    let person_keys: BTreeSet<&str> = persons
        .iter()
        .map(|p| p.person_public_key.as_str())
        .collect();
    authority.admins = delegations
        .iter()
        .filter(|d| {
            d.epoch == epoch
                && !removed_admins.contains(&d.person_public_key)
                && person_keys.contains(d.person_public_key.as_str())
        })
        .map(|d| d.person_public_key.clone())
        .collect();
    statements.admins = delegations;
    let revoked_hosts: BTreeSet<&str> = statements
        .hosts
        .iter()
        .map(|h| h.host_public_key.as_str())
        .chain(statements.leaves.iter().map(|l| l.host_public_key.as_str()))
        .collect();
    let revoked_invites: BTreeSet<&str> = statements
        .invites
        .iter()
        .map(|i| i.invite_public_key.as_str())
        .collect();
    let attested: BTreeSet<&str> = statements
        .attestations
        .iter()
        .map(|a| a.host_public_key.as_str())
        .collect();
    let unbound: BTreeSet<String> = statements
        .unbindings
        .iter()
        .map(HostUnbinding::subject)
        .collect();
    let mut bindings = Vec::new();
    let mut candidates = Vec::new();
    for entry in map.members {
        let Ok(entry) = serde_json::from_value::<WireMember>(entry) else {
            continue;
        };
        let admission = entry
            .admission
            .filter(|v| !v.is_null())
            .and_then(|v| serde_json::from_value::<HostAdmission>(v).ok());
        let (host_id, key, member, membership, admission) = if let Some(m) = entry.membership {
            if m.network_id != network.id || revoked_invites.contains(m.invite_public_key.as_str())
            {
                continue;
            }
            let verified =
                if let Some(admin) = authority.admin_signer(&m.invite_signature, &m.digest()) {
                    // An administrator's invite needs no re-signing at a rotation.
                    m.verify_under(&admin)
                } else if authority.is_cascaded(&m.invite_signature) {
                    Err(Error::Forbidden)
                } else if epoch == 0 {
                    m.verify(&network.root_public_key)
                } else {
                    m.verify_under(&current).or_else(|error| {
                        if attested.contains(m.host_public_key.as_str()) {
                            roots
                                .iter()
                                .find_map(|root| m.verify_under(root).ok())
                                .ok_or(error)
                        } else {
                            Err(error)
                        }
                    })
                };
            let Ok(host_id) = verified else {
                continue;
            };
            (
                host_id,
                m.host_public_key.clone(),
                m.member.clone(),
                Some(m),
                None,
            )
        } else if let Some(a) = admission {
            let verified = match authority.admin_signer(&a.signature, &a.digest()) {
                Some(_) if a.epoch > epoch => Err(Error::Forbidden),
                Some(admin) => a.verify_signed_by(&network.id, &admin),
                None => a.verify(&network.id, epoch, &current),
            };
            let Ok(host_id) = verified else {
                continue;
            };
            (
                host_id,
                a.host_public_key.clone(),
                a.member.clone(),
                None,
                Some(a),
            )
        } else {
            continue;
        };
        if host_id != entry.host_id || revoked_hosts.contains(key.as_str()) {
            continue;
        }
        // A binding counts when its person is valid, it binds this host, and
        // that person has not unbound this host.
        let binding = entry
            .binding
            .filter(|v| !v.is_null())
            .and_then(|v| serde_json::from_value::<HostBinding>(v).ok())
            .filter(|b| {
                b.host_public_key == key
                    && b.verify(&network.id).is_ok()
                    && !unbound.contains(&format!("{} {}", b.person_public_key, key))
            });
        let person = binding.as_ref().and_then(|b| {
            persons
                .iter()
                .find(|p| p.person_public_key == b.person_public_key)
        });
        let (person_id, person_member) = match person {
            Some(p) => (Some(p.person_id.clone()), Some(p.member.clone())),
            None => (None, None),
        };
        if person.is_some()
            && let Some(b) = binding
        {
            bindings.push(b);
        }
        let address = if membership::advertised(&entry.address).is_ok() {
            entry.address
        } else {
            String::new()
        };
        candidates.push(Member {
            host_id,
            public_key: key,
            member,
            address,
            candidates: valid_candidates(&entry.candidates),
            updated_at: entry.updated_at,
            membership,
            admission,
            person_id,
            person_member,
        });
    }
    let mut invite_hosts: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    let mut host_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for m in &candidates {
        if let Some(membership) = &m.membership {
            invite_hosts
                .entry(&membership.invite_public_key)
                .or_default()
                .insert(&m.host_id);
        }
        *host_counts.entry(&m.host_id).or_default() += 1;
    }
    let rejected: BTreeSet<String> = candidates
        .iter()
        .filter(|m| {
            m.membership
                .as_ref()
                .is_some_and(|ms| invite_hosts[ms.invite_public_key.as_str()].len() > 1)
                || host_counts[m.host_id.as_str()] > 1
        })
        .map(|m| m.host_id.clone())
        .collect();
    let mut members: Vec<Member> = candidates
        .into_iter()
        .filter(|m| !rejected.contains(&m.host_id))
        .collect();
    members.sort_by(|a, b| a.host_id.cmp(&b.host_id));
    bindings.retain(|b| members.iter().any(|m| m.public_key == b.host_public_key));
    statements.groups = verify_groups(
        network,
        &authority,
        std::mem::take(&mut statements.groups),
        map.groups,
    );
    let person_keys: Vec<String> = persons
        .iter()
        .map(|p| p.person_public_key.clone())
        .collect();
    statements.policies = crate::policy::verify_policies(
        &network.id,
        &person_keys,
        std::mem::take(&mut statements.policies),
        map.policies,
        chrono::Utc::now(),
    );
    Ok(VerifiedMap {
        members,
        persons,
        bindings,
        rotations: offered,
        roots,
        statements,
    })
}

/// Adds the map's revocations to the persisted ones (sticky) when they verify
/// under any root of the chain or an acceptable administrator.
fn merge_revocations(
    network: &Network,
    authority: &Authority,
    offered: &BTreeMap<String, Vec<Value>>,
    statements: &mut Statements,
) {
    let roots = &authority.roots;
    for (kind, list) in offered {
        for statement in list.iter().cloned() {
            match kind.as_str() {
                "host" => {
                    if let Ok(r) = serde_json::from_value::<HostRevocation>(statement)
                        && r.verify(
                            &network.id,
                            &authority.any_root_or_admin(&r.signature, &r.digest()),
                        )
                        .is_ok()
                        && !statements
                            .hosts
                            .iter()
                            .any(|h| h.host_public_key == r.host_public_key)
                    {
                        statements.hosts.push(r);
                    }
                }
                "invite" => {
                    if let Ok(r) = serde_json::from_value::<InviteRevocation>(statement)
                        && r.verify(
                            &network.id,
                            &authority.any_root_or_admin(&r.signature, &r.digest()),
                        )
                        .is_ok()
                        && !statements
                            .invites
                            .iter()
                            .any(|i| i.invite_public_key == r.invite_public_key)
                    {
                        statements.invites.push(r);
                    }
                }
                "leave" => {
                    if let Ok(r) = serde_json::from_value::<Leave>(statement)
                        && r.verify(&network.id).is_ok()
                        && !statements
                            .leaves
                            .iter()
                            .any(|l| l.host_public_key == r.host_public_key)
                    {
                        statements.leaves.push(r);
                    }
                }
                "person" => {
                    if let Ok(r) = serde_json::from_value::<PersonRemoval>(statement)
                        && r.verify(
                            &network.id,
                            &authority.any_root_or_admin(&r.signature, &r.digest()),
                        )
                        .is_ok()
                        && !statements
                            .person_removals
                            .iter()
                            .any(|p| p.person_public_key == r.person_public_key)
                    {
                        statements.person_removals.push(r);
                    }
                }
                "unbind" => {
                    if let Ok(r) = serde_json::from_value::<HostUnbinding>(statement)
                        && r.verify(&network.id).is_ok()
                        && !statements
                            .unbindings
                            .iter()
                            .any(|u| u.subject() == r.subject())
                    {
                        statements.unbindings.push(r);
                    }
                }
                _ => {}
            }
        }
    }
    let _ = roots;
}

/// Persons: an admission or an invite chain under the current root at the
/// current epoch, or signed by an acceptable administrator at any epoch;
/// removal is sticky. A person invite used by more than one person key
/// discredits all of them.
fn verify_persons(
    network: &Network,
    epoch: u64,
    authority: &Authority,
    offered: &[Value],
    statements: &Statements,
) -> Vec<PersonEntry> {
    let current = authority.current().to_owned();
    let revoked_invites: BTreeSet<&str> = statements
        .invites
        .iter()
        .map(|i| i.invite_public_key.as_str())
        .collect();
    let removed_persons: BTreeSet<&str> = statements
        .person_removals
        .iter()
        .map(|p| p.person_public_key.as_str())
        .collect();
    let mut person_candidates: Vec<PersonEntry> = Vec::new();
    for entry in offered {
        let admission = entry
            .get("admission")
            .filter(|v| !v.is_null())
            .and_then(|v| serde_json::from_value::<PersonAdmission>(v.clone()).ok());
        let membership = entry
            .get("membership")
            .filter(|v| !v.is_null())
            .and_then(|v| serde_json::from_value::<PersonMembership>(v.clone()).ok());
        let admission =
            admission.filter(
                |a| match authority.admin_signer(&a.signature, &a.digest()) {
                    Some(admin) => {
                        a.epoch <= epoch && a.verify_signed_by(&network.id, &admin).is_ok()
                    }
                    None => a.verify(&network.id, epoch, &current).is_ok(),
                },
            );
        let membership = membership.filter(|m| {
            admission.is_none()
                && !revoked_invites.contains(m.invite_public_key.as_str())
                && match authority.admin_signer(&m.invite_signature, &m.digest()) {
                    Some(admin) => {
                        m.invite_epoch <= epoch && m.verify_signed_by(&network.id, &admin).is_ok()
                    }
                    None => m.verify(&network.id, epoch, &current).is_ok(),
                }
        });
        let (key, member) = match (&admission, &membership) {
            (Some(a), _) => (a.person_public_key.clone(), a.member.clone()),
            (None, Some(m)) => (m.person_public_key.clone(), m.member.clone()),
            (None, None) => continue,
        };
        let Ok(person_id) = persons::person_id_of(&key) else {
            continue;
        };
        if removed_persons.contains(key.as_str())
            || entry["person_id"]
                .as_str()
                .is_some_and(|id| id != person_id)
            || person_candidates.iter().any(|p| p.person_public_key == key)
        {
            continue;
        }
        person_candidates.push(PersonEntry {
            person_id,
            person_public_key: key,
            member,
            admission,
            membership,
        });
    }
    let mut person_invites: BTreeMap<String, usize> = BTreeMap::new();
    for p in &person_candidates {
        if let Some(m) = &p.membership
            && p.admission.is_none()
        {
            *person_invites
                .entry(m.invite_public_key.clone())
                .or_default() += 1;
        }
    }
    let mut persons: Vec<PersonEntry> = person_candidates
        .into_iter()
        .filter(|p| match (&p.admission, &p.membership) {
            (None, Some(m)) => person_invites[&m.invite_public_key] == 1,
            _ => true,
        })
        .collect();
    persons.sort_by(|a, b| a.person_id.cmp(&b.person_id));
    persons
}

/// Picks each group's applicable version. A version counts while it is signed
/// by the current root or an acceptable administrator (one not removed with
/// `revoke_admitted`); a new version from the map must be higher than the
/// persisted one. If the persisted version no longer counts, the map's version
/// replaces it even when lower: the group reverts.
fn verify_groups(
    network: &Network,
    authority: &Authority,
    persisted: Vec<Group>,
    offered: Vec<Value>,
) -> Vec<Group> {
    let valid = |g: &Group| {
        authority
            .current_or_admin(&g.signature, &g.digest())
            .iter()
            .any(|k| g.verify_signed_by(&network.id, k).is_ok())
    };
    let mut kept: BTreeMap<String, (Group, bool)> = BTreeMap::new();
    for g in persisted {
        let valid = valid(&g);
        kept.insert(g.name.clone(), (g, valid));
    }
    for g in offered
        .into_iter()
        .filter_map(|v| serde_json::from_value::<Group>(v).ok())
    {
        if !valid(&g) {
            continue;
        }
        match kept.get(&g.name) {
            // A renewal at a rotation: same version, same members.
            Some((old, true)) if old.version == g.version && old.members == g.members => {
                kept.insert(g.name.clone(), (g, true));
            }
            Some((old, true)) if old.version >= g.version => {}
            Some((old, false)) if old.version == g.version && *old == g => {}
            _ => {
                kept.insert(g.name.clone(), (g, true));
            }
        }
    }
    kept.into_values()
        .filter_map(|(g, valid)| valid.then_some(g))
        .collect()
}

pub(crate) fn time_after(a: &str, b: &str) -> bool {
    match (membership::time(a), membership::time(b)) {
        (Ok(a), Ok(b)) => a > b,
        (Ok(_), Err(_)) => true,
        _ => false,
    }
}

impl Store {
    pub(crate) fn network_record(
        &self,
        connection: &Connection,
        id: &str,
    ) -> Result<Network, Error> {
        let (record, administrator): (String, bool) = connection.query_row(
            "SELECT record, root_seed IS NOT NULL FROM networks WHERE id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let mut network: Network = json(record)?;
        network.administrator = administrator;
        if network.current_root_public_key.is_empty() {
            network
                .current_root_public_key
                .clone_from(&network.root_public_key);
        }
        Ok(network)
    }
    pub fn networks(&self) -> Result<Vec<Network>, Error> {
        let connection = self.connection()?;
        let ids = {
            let mut statement = connection.prepare("SELECT id FROM networks ORDER BY id")?;
            statement
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        ids.iter()
            .map(|id| self.network_record(&connection, id))
            .collect()
    }
    pub fn network(&self, id: &str) -> Result<Network, Error> {
        self.network_record(&*self.connection()?, id)
    }
    pub fn members(&self, id: &str) -> Result<Vec<Member>, Error> {
        let connection = self.connection()?;
        self.network_record(&connection, id)?;
        let mut statement = connection
            .prepare("SELECT record FROM network_members WHERE network_id = ?1 ORDER BY host_id")?;
        statement
            .query_map([id], |r| r.get::<_, String>(0))?
            .map(|r| json(r?))
            .collect()
    }
    /// True if the key belongs to a manual peer or a verified network member.
    pub(crate) fn knows(&self, key: &[u8]) -> Result<bool, Error> {
        let id = key_id(key);
        let poisoned = || Error::Internal(anyhow::anyhow!("peer pins lock poisoned"));
        let pinned =
            |pins: &BTreeMap<String, Vec<u8>>| pins.get(&id).map(Vec::as_slice) == Some(key);
        Ok(pinned(&*self.peer_pins.read().map_err(|_| poisoned())?)
            || pinned(&*self.member_pins.read().map_err(|_| poisoned())?))
    }
    pub(crate) fn known_host(&self, connection: &Connection, id: &str) -> Result<bool, Error> {
        let count: i64 = connection.query_row(
            "SELECT (SELECT COUNT(*) FROM peers WHERE id = ?1) + (SELECT COUNT(*) FROM network_members WHERE host_id = ?1 AND host_id != ?2)",
            params![id, self.identity().id],
            |r| r.get(0),
        )?;
        Ok(count > 0)
    }
    /// Coordination counts as connected for a requester that is a member of a
    /// network this host synced within three coordination intervals.
    pub(crate) fn connected(&self, connection: &Connection, host: &str) -> Result<bool, Error> {
        if host == self.identity().id {
            return Ok(false);
        }
        let window = chrono::TimeDelta::seconds(
            3 * self.coordination_interval.load(Ordering::Relaxed) as i64,
        );
        let mut statement = connection.prepare(
            "SELECT n.record FROM networks n JOIN network_members m ON m.network_id = n.id WHERE m.host_id = ?1",
        )?;
        let networks = statement
            .query_map([host], |r| r.get::<_, String>(0))?
            .map(|r| json::<Network>(r?))
            .collect::<Result<Vec<_>, _>>()?;
        let at = chrono::Utc::now();
        Ok(networks.iter().any(|n| {
            n.last_sync_at
                .as_deref()
                .and_then(|t| membership::time(t).ok())
                .is_some_and(|t| at - t <= window)
        }))
    }
    /// A manual peer's address takes precedence; otherwise the member entry with
    /// the latest update and a nonempty address. Members without an address are
    /// returned with an empty one, so a send records an unknown outcome.
    pub fn dial_target(&self, id: &str) -> Result<Peer, Error> {
        let connection = self.connection()?;
        if let Some(record) = connection
            .query_row("SELECT record FROM peers WHERE id = ?1", [id], |r| {
                r.get::<_, String>(0)
            })
            .optional()?
        {
            return json(record);
        }
        if id == self.identity().id {
            return Err(Error::NotFound);
        }
        let mut statement =
            connection.prepare("SELECT record FROM network_members WHERE host_id = ?1")?;
        let members = statement
            .query_map([id], |r| r.get::<_, String>(0))?
            .map(|r| json::<Member>(r?))
            .collect::<Result<Vec<_>, _>>()?;
        let best = members
            .into_iter()
            .fold(None::<Member>, |best, m| match best {
                None => Some(m),
                Some(b) => {
                    let better = (!m.address.is_empty() && b.address.is_empty())
                        || (m.address.is_empty() == b.address.is_empty()
                            && time_after(&m.updated_at, &b.updated_at));
                    Some(if better { m } else { b })
                }
            });
        let m = best.ok_or(Error::NotFound)?;
        Ok(Peer {
            id: m.host_id,
            public_key: m.public_key,
            address: m.address,
        })
    }
    /// The relay for `host`: the coordinator of the lowest-ID network that both
    /// this host and `host` belong to, or none if they share no network.
    pub(crate) fn relay_coordinator(&self, host: &str) -> Result<Option<(String, String)>, Error> {
        if host == self.identity().id {
            return Ok(None);
        }
        let record: Option<String> = self
            .connection()?
            .query_row(
                "SELECT n.record FROM networks n JOIN network_members m ON m.network_id = n.id WHERE m.host_id = ?1 ORDER BY n.id LIMIT 1",
                [host],
                |r| r.get(0),
            )
            .optional()?;
        let Some(record) = record else {
            return Ok(None);
        };
        let value: Value = serde_json::from_str(&record).map_err(|e| Error::Internal(e.into()))?;
        let field = |name: &str| value[name].as_str().map(str::to_owned);
        Ok(field("coordinator_address").zip(field("coordinator_public_key")))
    }
    /// Every coordinator of a network this host belongs to.
    pub(crate) fn coordinators(&self) -> Result<Vec<(String, String)>, Error> {
        let mut all: Vec<_> = self
            .networks()?
            .into_iter()
            .map(|n| (n.coordinator_address, n.coordinator_public_key))
            .collect();
        all.sort();
        all.dedup();
        Ok(all)
    }
    pub(crate) fn refresh_member_pins(&self, connection: &Connection) -> Result<(), Error> {
        let pins = load_member_pins(connection, &self.identity().id).map_err(Error::Internal)?;
        *self
            .member_pins
            .write()
            .map_err(|_| Error::Internal(anyhow::anyhow!("member pins lock poisoned")))? = pins;
        Ok(())
    }
    pub fn set_coordination_interval(&self, seconds: u64) {
        self.coordination_interval.store(seconds, Ordering::Relaxed);
    }
    pub fn set_advertised(&self, address: String) {
        if let Ok(mut advertise) = self.advertise.write() {
            *advertise = address;
        }
    }
    pub(crate) fn advertised(&self) -> String {
        self.advertise.read().map(|a| a.clone()).unwrap_or_default()
    }
    /// The candidates this host most recently published.
    pub(crate) fn published_candidates(&self) -> Vec<std::net::SocketAddr> {
        self.candidates
            .read()
            .map(|c| c.clone())
            .unwrap_or_default()
    }
    /// A member's published candidates across this host's networks, and its
    /// advertised direct addresses, which path discovery never reroutes.
    pub(crate) fn member_candidates(
        &self,
        host: &str,
    ) -> Result<(Vec<std::net::SocketAddr>, Vec<std::net::SocketAddr>), Error> {
        if host == self.identity().id {
            return Ok((Vec::new(), Vec::new()));
        }
        let connection = self.connection()?;
        let manual: Option<String> = connection
            .query_row("SELECT record FROM peers WHERE id = ?1", [host], |r| {
                r.get(0)
            })
            .optional()?;
        let mut statement =
            connection.prepare("SELECT record FROM network_members WHERE host_id = ?1")?;
        let members = statement
            .query_map([host], |r| r.get::<_, String>(0))?
            .map(|r| json::<Member>(r?))
            .collect::<Result<Vec<_>, _>>()?;
        let mut candidates = Vec::new();
        let mut advertised = Vec::new();
        if let Some(record) = manual {
            let peer: Peer = json(record)?;
            if let Ok(addr) = peer.address.parse() {
                advertised.push(crate::disco::normalize(addr));
            }
        }
        for m in members {
            if let Ok(addr) = m.address.parse() {
                advertised.push(crate::disco::normalize(addr));
            }
            for c in m.candidates.iter().filter_map(|c| c.parse().ok()) {
                let c = crate::disco::normalize(c);
                if !candidates.contains(&c) {
                    candidates.push(c);
                }
            }
        }
        Ok((candidates, advertised))
    }

    pub fn create_network(&self, mut r: CreateNetwork) -> Result<Network, Error> {
        match (
            r.coordinator_address.is_empty(),
            r.coordinator_public_key.is_empty(),
        ) {
            (true, true) => {
                let (address, key) = default_coordinator().ok_or_else(|| {
                    Error::Invalid(
                        "this build has no default coordinator; pass --coordinator and --coordinator-key".into(),
                    )
                })?;
                r.coordinator_address = address.into();
                r.coordinator_public_key = key.into();
            }
            (false, false) => {}
            _ => {
                return Err(Error::Invalid(
                    "give both --coordinator and --coordinator-key, or neither".into(),
                ));
            }
        }
        membership::label(&r.name)?;
        membership::label(&r.member)?;
        membership::split_host_port(&r.coordinator_address)?;
        membership::public_key(&r.coordinator_public_key)?;
        let root = random_seed()?;
        let invite = random_seed()?;
        let joined = now();
        let expires = rfc3339(chrono::Utc::now() + MAX_INVITE_LIFETIME);
        let signed = membership::sign_invite(&root, &invite, &r.member, &expires);
        let own = membership::sign_member(
            signed,
            &invite,
            self.signing_key.verifying_key().as_bytes(),
            &joined,
        );
        let network = Network {
            id: own.network_id.clone(),
            name: r.name,
            root_public_key: STANDARD.encode(root.verifying_key().as_bytes()),
            member: r.member,
            coordinator_address: r.coordinator_address,
            coordinator_public_key: r.coordinator_public_key,
            administrator: true,
            last_sync_at: None,
            last_sync_error: None,
            root_epoch: 0,
            current_root_public_key: STANDARD.encode(root.verifying_key().as_bytes()),
            root_ssh: false,
            coordinator_pending: None,
        };
        let me = Member {
            host_id: self.identity().id,
            public_key: own.host_public_key.clone(),
            member: own.member.clone(),
            address: self.advertised(),
            candidates: Vec::new(),
            updated_at: joined.clone(),
            membership: Some(own),
            admission: None,
            person_id: None,
            person_member: None,
        };
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        tx.execute(
            "INSERT INTO networks VALUES (?1, ?2, ?3)",
            params![
                network.id,
                serde_json::to_string(&network)?,
                root.to_bytes().to_vec()
            ],
        )?;
        tx.execute(
            "INSERT INTO network_members VALUES (?1, ?2, ?3)",
            params![network.id, me.host_id, serde_json::to_string(&me)?],
        )?;
        append_event(&tx, "network.created", &network.id, &joined)?;
        tx.commit()?;
        Ok(network)
    }

    pub fn issue_invite(&self, id: &str, r: CreateInvite) -> Result<IssuedInvite, Error> {
        let mut r = r;
        if r.token.is_none() {
            let c = self.connection()?;
            if crate::link_runtime::catalog::feature(&c, id)
                .map_err(crate::link_runtime::support::model_error)?
                .0
                != "-"
            {
                r.expires_at = membership::time(&r.expires_at)?
                    .format("%Y-%m-%dT%H:%M:%SZ")
                    .to_string();
            }
        }
        if let Some(token) = r.token {
            return self.record_signed_invite(id, &token, false);
        }
        membership::label(&r.member)?;
        let expires = membership::time(&r.expires_at)?;
        let at = {
            let c = self.connection()?;
            if crate::link_runtime::catalog::feature(&c, id)
                .map_err(crate::link_runtime::support::model_error)?
                .0
                != "-"
            {
                crate::link_runtime::support::now()
                    .map_err(|e| crate::link_runtime::support::model_error(e.into()))?
            } else {
                chrono::Utc::now()
            }
        };
        if expires <= at || expires > at + MAX_INVITE_LIFETIME {
            return Err(Error::Invalid(
                "invite expiry must be in the future and at most 30 days ahead".into(),
            ));
        }
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let network = self.network_record(&tx, id)?;
        let seed: Option<Vec<u8>> =
            tx.query_row("SELECT root_seed FROM networks WHERE id = ?1", [id], |r| {
                r.get(0)
            })?;
        let root: [u8; 32] = seed
            .ok_or(Error::Forbidden)?
            .try_into()
            .map_err(|_| Error::Internal(anyhow::anyhow!("invalid persisted root seed")))?;
        let root = SigningKey::from_bytes(&root);
        let invite = random_seed()?;
        let signed =
            membership::sign_invite_for(&network.id, &root, &invite, &r.member, &r.expires_at);
        // A member invite (the default) also admits the joiner's person under
        // the same label. Its label is checked when redeemed rather than now,
        // so a second machine for an already-admitted person can be invited
        // under that person's own label.
        if !r.host_only {
            let token = MemberInviteToken::issue(
                &root,
                &invite,
                &network.id,
                &network.name.clone(),
                network.root_epoch,
                &r.member,
                &r.expires_at,
                &network.coordinator_address.clone(),
                &network.coordinator_public_key.clone(),
            );
            append_event(&tx, "network.invite_issued", &network.id, &now())?;
            let wrapped = crate::link_runtime::invite::wrap_legacy(
                &tx,
                &network,
                &token.encode(),
                &KeySigner::Raw(&root),
            )
            .map_err(crate::link_runtime::support::model_error)?;
            tx.commit()?;
            return Ok(IssuedInvite {
                network_id: network.id,
                member: signed.member,
                invite_public_key: signed.invite_public_key,
                invite_expires_at: signed.invite_expires_at,
                token: wrapped,
            });
        }
        let token = InviteToken {
            network_id: network.id.clone(),
            network_name: network.name.clone(),
            // The current root signed the invite; after a rotation it no longer
            // derives the network ID, and the joiner checks it against the chain.
            root_public_key: network.current_root_public_key.clone(),
            coordinator_address: network.coordinator_address.clone(),
            coordinator_public_key: network.coordinator_public_key.clone(),
            member: signed.member.clone(),
            invite_public_key: signed.invite_public_key.clone(),
            invite_seed: STANDARD.encode(invite.to_bytes()),
            invite_expires_at: signed.invite_expires_at.clone(),
            invite_signature: signed.invite_signature,
        };
        append_event(&tx, "network.invite_issued", &network.id, &now())?;
        let wrapped = crate::link_runtime::invite::wrap_legacy(
            &tx,
            &network,
            &token.encode(),
            &KeySigner::Raw(&root),
        )
        .map_err(crate::link_runtime::support::model_error)?;
        tx.commit()?;
        Ok(IssuedInvite {
            network_id: network.id,
            member: signed.member,
            invite_public_key: signed.invite_public_key,
            invite_expires_at: signed.invite_expires_at,
            token: wrapped,
        })
    }

    /// Replaces a network's verified member set with a coordinator map and
    /// persists the union of verified statements. When `joined` is set, the
    /// network itself is inserted in the same transaction.
    fn apply_map(&self, network: Network, map: WireMap, joined: bool) -> Result<Network, Error> {
        self.apply_map_at(network, map, joined, None)
    }
    /// `apply_map` for a map from `switch`, a pending coordinator, which
    /// replaces the pinned coordinator in the same transaction.
    fn apply_map_at(
        &self,
        network: Network,
        map: WireMap,
        joined: bool,
        switch: Option<CoordinatorPending>,
    ) -> Result<Network, Error> {
        if let Some(raw) = map.active_map {
            return self
                .apply_link_map(network, &raw, joined, switch)
                .map_err(crate::link_runtime::support::model_error);
        }
        {
            let c = self.connection()?;
            if crate::link_runtime::catalog::feature(&c, &network.id)
                .map_err(crate::link_runtime::support::model_error)?
                .0
                != "-"
            {
                return Err(crate::link_runtime::support::model_error(
                    crate::link_runtime::support::Failure::new("upgrade_required", "-", "map")
                        .into(),
                ));
            }
        }
        // The first accepted map (a join, or a created network's registration)
        // means the coordinator now knows this host, so its relay will accept it.
        let first = joined || network.last_sync_at.is_none();
        let own_id = self.identity().id;
        let own_key = STANDARD.encode(self.signing_key.verifying_key().as_bytes());
        let at = now();
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let persisted = if joined {
            Statements::default()
        } else {
            Statements::load(&tx, &network.id)?
        };
        let verified = verify_map(&network, map, persisted)?;
        let mut members = verified.members;
        if !members.iter().any(|m| m.host_id == own_id) {
            return Err(Error::Unavailable("coordinator map omits this host".into()));
        }
        let mut network = if joined {
            let exists: i64 = tx.query_row(
                "SELECT COUNT(*) FROM networks WHERE id = ?1",
                [&network.id],
                |r| r.get(0),
            )?;
            if exists != 0 {
                return Err(Error::Conflict("network already joined".into()));
            }
            tx.execute(
                "INSERT INTO networks VALUES (?1, ?2, NULL)",
                params![network.id, serde_json::to_string(&network)?],
            )?;
            append_event(&tx, "network.joined", &network.id, &at)?;
            network
        } else {
            self.network_record(&tx, &network.id)?
        };
        if let Some(pending) = switch {
            if let Some(sequence) = pending.move_sequence.filter(|_| pending.is_move()) {
                crate::coordinator_move::record_applied(&tx, &network.id, sequence)?;
            }
            network.coordinator_address = pending.address;
            network.coordinator_public_key = pending.public_key;
            network.coordinator_pending = None;
        }
        let id = network.id.clone();
        for rotation in &verified.rotations {
            insert_statement(&tx, &id, "rotation", &rotation.epoch.to_string(), rotation)?;
        }
        // Only the current epoch's attestations are kept.
        tx.execute(
            "DELETE FROM network_statements WHERE network_id = ?1 AND kind = 'attestation'",
            [&id],
        )?;
        let statements = verified.statements;
        for a in &statements.attestations {
            insert_statement(&tx, &id, "attestation", &a.host_public_key, a)?;
        }
        for r in &statements.hosts {
            insert_statement(&tx, &id, "host", &r.host_public_key, r)?;
        }
        for r in &statements.invites {
            insert_statement(&tx, &id, "invite", &r.invite_public_key, r)?;
        }
        for r in &statements.leaves {
            if insert_statement(&tx, &id, "leave", &r.host_public_key, r)?
                && r.host_public_key != own_key
                && let Ok(key) = membership::canonical(&r.host_public_key, 32)
            {
                append_event(&tx, "network.member_left", &key_id(&key), &at)?;
            }
        }
        for r in &statements.person_removals {
            if insert_statement(&tx, &id, "person_removal", &r.person_public_key, r)?
                && let Ok(person) = persons::person_id_of(&r.person_public_key)
            {
                append_event(&tx, "network.person_removed", &person, &at)?;
            }
        }
        for u in &statements.unbindings {
            insert_statement(&tx, &id, "unbind", &u.subject(), u)?;
        }
        // Persons, bindings, and host admissions are the coordinator's current
        // verified sets; removals and unbindings above are the sticky part.
        let replace = |kind: &str| -> Result<BTreeSet<String>, Error> {
            let old: BTreeSet<String> = {
                let mut statement = tx.prepare(
                    "SELECT subject FROM network_statements WHERE network_id = ?1 AND kind = ?2",
                )?;
                statement
                    .query_map(params![id, kind], |r| r.get::<_, String>(0))?
                    .collect::<Result<_, _>>()?
            };
            tx.execute(
                "DELETE FROM network_statements WHERE network_id = ?1 AND kind = ?2",
                params![id, kind],
            )?;
            Ok(old)
        };
        for r in &statements.admin_removals {
            if r.revoke_admitted {
                // It may supersede a stored removal without revoke_admitted.
                tx.execute(
                    "DELETE FROM network_statements WHERE network_id = ?1 AND kind = 'admin_removal' AND subject = ?2 AND record NOT LIKE '%\"revoke_admitted\":true%'",
                    params![id, r.person_public_key],
                )?;
            }
            if insert_statement(&tx, &id, "admin_removal", &r.person_public_key, r)? {
                append_event(
                    &tx,
                    "network.admin_removed",
                    &crate::admins::person_of(&r.person_public_key),
                    &at,
                )?;
            }
        }
        let old_admins = replace("admin")?;
        for d in &statements.admins {
            insert_statement(&tx, &id, "admin", &d.person_public_key, d)?;
            if !old_admins.contains(&d.person_public_key) {
                append_event(
                    &tx,
                    "network.admin_delegated",
                    &crate::admins::person_of(&d.person_public_key),
                    &at,
                )?;
            }
        }
        let old_groups: BTreeMap<String, u64> = Statements::load(&tx, &id)?
            .groups
            .into_iter()
            .map(|g| (g.name, g.version))
            .collect();
        replace("group")?;
        for g in &statements.groups {
            insert_statement(&tx, &id, "group", &g.name, g)?;
            if old_groups.get(&g.name) != Some(&g.version) {
                append_event(&tx, "network.group_updated", &g.name, &at)?;
            }
        }
        let old_policies: BTreeMap<String, String> = Statements::load(&tx, &id)?
            .policies
            .into_iter()
            .map(|p| (p.person_public_key.clone(), p.sha256()))
            .collect();
        replace("policy")?;
        let mut stored_policies = Vec::new();
        for p in &statements.policies {
            insert_statement(&tx, &id, "policy", &p.person_public_key, p)?;
            if old_policies.get(&p.person_public_key) != Some(&p.sha256()) {
                append_event(&tx, "network.policy_updated", &p.person_id(), &at)?;
                stored_policies.push(p.clone());
            }
        }
        let old_persons = replace("person")?;
        for p in &verified.persons {
            insert_statement(&tx, &id, "person", &p.person_public_key, &p.proof())?;
            if !old_persons.contains(&p.person_public_key) {
                append_event(&tx, "network.person_admitted", &p.person_id, &at)?;
            }
        }
        // Served admissions update the stored ones; admissions this host
        // issued for hosts not joined yet stay, so a rotation renews them.
        for m in &members {
            if let Some(a) = &m.admission {
                let fresh = tx
                    .query_row(
                        "SELECT 1 FROM network_statements WHERE network_id = ?1 AND kind = 'host_admission' AND subject = ?2",
                        params![id, a.host_public_key],
                        |_| Ok(()),
                    )
                    .optional()?
                    .is_none();
                tx.execute(
                    "INSERT OR REPLACE INTO network_statements VALUES (?1, 'host_admission', ?2, ?3)",
                    params![id, a.host_public_key, serde_json::to_string(a)?],
                )?;
                if fresh {
                    append_event(&tx, "network.host_admitted", &m.host_id, &at)?;
                }
            }
        }
        let old_bindings = replace("binding")?;
        for b in &verified.bindings {
            insert_statement(&tx, &id, "binding", &b.host_public_key, b)?;
        }
        let new_bindings: BTreeSet<&str> = verified
            .bindings
            .iter()
            .map(|b| b.host_public_key.as_str())
            .collect();
        for m in &members {
            let bound = new_bindings.contains(m.public_key.as_str());
            let was = old_bindings.contains(&m.public_key);
            if bound && !was {
                append_event(&tx, "network.host_bound", &m.host_id, &at)?;
            } else if was && !bound {
                append_event(&tx, "network.host_unbound", &m.host_id, &at)?;
            }
        }
        let old: BTreeSet<String> = {
            let mut statement =
                tx.prepare("SELECT host_id FROM network_members WHERE network_id = ?1")?;
            statement
                .query_map([&id], |r| r.get::<_, String>(0))?
                .collect::<Result<_, _>>()?
        };
        // Members leaving the view keep their join statement, so a root's
        // revocation of their invite still retires their `edits` entries.
        remember_joins(&tx, self, &id)?;
        // A map's members keep their membership statements as listed.
        remember_memberships(&tx, &id, &members)?;
        tx.execute("DELETE FROM network_members WHERE network_id = ?1", [&id])?;
        for m in &mut members {
            if m.host_id == own_id {
                // The coordinator's address for us may lag; record our own.
                m.address = self.advertised();
                m.candidates = self
                    .published_candidates()
                    .iter()
                    .map(ToString::to_string)
                    .collect();
            }
            tx.execute(
                "INSERT INTO network_members VALUES (?1, ?2, ?3)",
                params![id, m.host_id, serde_json::to_string(&m)?],
            )?;
        }
        let current_key = verified.roots.last().cloned().unwrap_or_default();
        let by_current =
            |sig: &str| crate::persons::sshsig_signer(sig).as_deref() == Some(current_key.as_str());
        let admitted_by_ssh_root = members.iter().any(|m| {
            m.admission
                .as_ref()
                .is_some_and(|a| by_current(&a.signature))
        });
        let new: BTreeSet<String> = members.into_iter().map(|m| m.host_id).collect();
        for added in new.difference(&old).filter(|id| **id != own_id) {
            append_event(&tx, "network.member_added", added, &at)?;
        }
        for removed in old.difference(&new).filter(|id| **id != own_id) {
            append_event(&tx, "network.member_removed", removed, &at)?;
        }
        let epoch = (verified.roots.len() - 1) as u64;
        // The current root signs with SSHSIG if any of its current statements
        // does; a raw root never does. An unchanged epoch keeps what this host
        // already knew (the administrator records it when committing).
        let detected = statements.admins.iter().any(|d| by_current(&d.signature))
            || statements
                .attestations
                .iter()
                .any(|a| by_current(&a.signature))
            || verified.persons.iter().any(|p| {
                p.admission
                    .as_ref()
                    .is_some_and(|a| by_current(&a.signature))
            })
            || admitted_by_ssh_root;
        network.root_ssh = detected || (network.root_ssh && network.root_epoch == epoch);
        network.root_epoch = epoch;
        network.current_root_public_key = current_key.clone();
        network.last_sync_at = Some(at);
        network.last_sync_error = None;
        tx.execute(
            "UPDATE networks SET record = ?1 WHERE id = ?2",
            params![serde_json::to_string(&network)?, id],
        )?;
        // Policies of this host's own person, newly stored from the map, go to
        // its siblings (as now seen) and back to the coordinator.
        for p in &stored_policies {
            self.queue_policy_deliveries(&tx, &id, p)?;
            // A newer policy may settle this host's edits, or displace them.
            self.settle_edits(&tx, &id, p)?;
        }
        tx.commit()?;
        if !stored_policies.is_empty() {
            self.policy_wake.notify_one();
        }
        self.refresh_member_pins(&connection)?;
        if first {
            self.relay_wake.notify_one();
        }
        Ok(network)
    }

    /// The verified persons this host holds for a network.
    pub(crate) fn stored_persons(
        &self,
        connection: &Connection,
        id: &str,
    ) -> Result<Vec<PersonEntry>, Error> {
        let n = self.network_record(connection, id)?;
        if let Some(p) = self
            .linking_projection(connection, &n)
            .map_err(crate::link_runtime::support::model_error)?
        {
            let mut people = Vec::new();
            for (key, state) in &p.network.facts.state.persons {
                if state.admitted {
                    people.push(PersonEntry {
                        person_id: persons::person_id_of(key)?,
                        person_public_key: key.clone(),
                        member: p.network.facts.person_labels.get(key).cloned().ok_or_else(
                            || Error::Internal(anyhow::anyhow!("verified person label absent")),
                        )?,
                        admission: None,
                        membership: None,
                    });
                }
            }
            people.sort_by(|a, b| a.person_id.cmp(&b.person_id));
            return Ok(people);
        }
        let mut statement = connection.prepare(
            "SELECT record FROM network_statements WHERE network_id = ?1 AND kind = 'person' ORDER BY subject",
        )?;
        let mut persons: Vec<PersonEntry> = statement
            .query_map([id], |r| r.get::<_, String>(0))?
            .map(|r| PersonEntry::from_proof(json(r?)?))
            .collect::<Result<_, _>>()?;
        persons.sort_by(|a, b| a.person_id.cmp(&b.person_id));
        Ok(persons)
    }
    pub(crate) fn stored_members(
        &self,
        connection: &Connection,
        id: &str,
    ) -> Result<Vec<Member>, Error> {
        let mut statement =
            connection.prepare("SELECT record FROM network_members WHERE network_id = ?1")?;
        statement
            .query_map([id], |r| r.get::<_, String>(0))?
            .map(|r| json(r?))
            .collect()
    }
    /// Ends a host's binding locally: drops the binding and clears the
    /// member's person, with `network.host_unbound`.
    fn drop_binding_locally(
        &self,
        tx: &rusqlite::Transaction,
        id: &str,
        host_key: &str,
        at: &str,
    ) -> Result<(), Error> {
        let removed = tx.execute(
            "DELETE FROM network_statements WHERE network_id = ?1 AND kind = 'binding' AND subject = ?2",
            params![id, host_key],
        )?;
        for mut m in self.stored_members(tx, id)? {
            if m.public_key == host_key && (removed > 0 || m.person_id.is_some()) {
                m.person_id = None;
                m.person_member = None;
                tx.execute(
                    "UPDATE network_members SET record = ?1 WHERE network_id = ?2 AND host_id = ?3",
                    params![serde_json::to_string(&m)?, id, m.host_id],
                )?;
                append_event(tx, "network.host_unbound", &m.host_id, at)?;
            }
        }
        Ok(())
    }
    /// Removes a person locally with all of its bindings.
    fn drop_person_locally(
        &self,
        tx: &rusqlite::Transaction,
        id: &str,
        person_key: &str,
        at: &str,
    ) -> Result<(), Error> {
        tx.execute(
            "DELETE FROM network_statements WHERE network_id = ?1 AND kind = 'person' AND subject = ?2",
            params![id, person_key],
        )?;
        let bound: Vec<HostBinding> = {
            let mut statement = tx.prepare(
                "SELECT record FROM network_statements WHERE network_id = ?1 AND kind = 'binding'",
            )?;
            statement
                .query_map([id], |r| r.get::<_, String>(0))?
                .map(|r| json(r?))
                .collect::<Result<_, _>>()?
        };
        for b in bound.iter().filter(|b| b.person_public_key == person_key) {
            self.drop_binding_locally(tx, id, &b.host_public_key, at)?;
        }
        Ok(())
    }

    /// The current root seed of a network this host administers.
    pub(crate) fn current_root(
        &self,
        connection: &Connection,
        id: &str,
    ) -> Result<SigningKey, Error> {
        let seed: Option<Vec<u8>> =
            connection.query_row("SELECT root_seed FROM networks WHERE id = ?1", [id], |r| {
                r.get(0)
            })?;
        let seed: [u8; 32] = seed
            .ok_or(Error::Forbidden)?
            .try_into()
            .map_err(|_| Error::Internal(anyhow::anyhow!("invalid persisted root seed")))?;
        Ok(SigningKey::from_bytes(&seed))
    }

    /// The root chain this host has verified for a network, genesis first.
    pub(crate) fn roots(
        &self,
        connection: &Connection,
        network: &Network,
    ) -> Result<Vec<String>, Error> {
        if let Some(p) = self
            .linking_projection(connection, network)
            .map_err(crate::link_runtime::support::model_error)?
        {
            return p.roots().map_err(crate::link_runtime::support::model_error);
        }
        let mut roots = vec![network.root_public_key.clone()];
        roots.extend(
            Statements::load(connection, &network.id)?
                .rotations
                .into_iter()
                .map(|r| r.root_public_key),
        );
        Ok(roots)
    }
    /// The signers this host accepts for a network, from its verified state.
    pub(crate) fn authority(
        &self,
        connection: &Connection,
        network: &Network,
    ) -> Result<Authority, Error> {
        if let Some(p) = self
            .linking_projection(connection, network)
            .map_err(crate::link_runtime::support::model_error)?
        {
            return Ok(Authority {
                roots: p
                    .roots()
                    .map_err(crate::link_runtime::support::model_error)?,
                admins: p
                    .network
                    .facts
                    .state
                    .persons
                    .iter()
                    .filter(|(_, state)| state.admitted && state.administrator)
                    .map(|(key, _)| key.clone())
                    .collect(),
                ..Authority::default()
            });
        }
        let statements = Statements::load(connection, &network.id)?;
        let mut roots = vec![network.root_public_key.clone()];
        roots.extend(
            statements
                .rotations
                .iter()
                .map(|r| r.root_public_key.clone()),
        );
        let removed: BTreeSet<&str> = statements
            .admin_removals
            .iter()
            .map(|r| r.person_public_key.as_str())
            .collect();
        let persons: BTreeSet<String> = self
            .stored_persons(connection, &network.id)?
            .into_iter()
            .map(|p| p.person_public_key)
            .collect();
        let mut authority = Authority::new(roots, &statements.admins, &statements.admin_removals);
        authority.admins = statements
            .admins
            .iter()
            .filter(|d| {
                d.epoch == network.root_epoch
                    && !removed.contains(d.person_public_key.as_str())
                    && persons.contains(&d.person_public_key)
            })
            .map(|d| d.person_public_key.clone())
            .collect();
        Ok(authority)
    }
    /// The signer of a statement the CLI signed: a current administrator or
    /// the current (SSH) root; anyone else is refused with 403.
    fn accept_signer(
        &self,
        connection: &Connection,
        network: &Network,
        signature: &str,
    ) -> Result<String, Error> {
        let signer = persons::sshsig_signer(signature)
            .ok_or_else(|| Error::Invalid("expected an SSHSIG signature".into()))?;
        let authority = self.authority(connection, network)?;
        if authority.admins.contains(&signer) || signer == authority.current() {
            Ok(signer)
        } else {
            Err(Error::Forbidden)
        }
    }
    /// The applicable version of every group, deleted ones included.
    pub(crate) fn stored_groups(
        &self,
        connection: &Connection,
        id: &str,
    ) -> Result<Vec<Group>, Error> {
        let n = self.network_record(connection, id)?;
        if let Some(p) = self
            .linking_projection(connection, &n)
            .map_err(crate::link_runtime::support::model_error)?
        {
            return Ok(p.groups.into_values().collect());
        }
        let mut groups = Statements::load(connection, id)?.groups;
        groups.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(groups)
    }

    /// Signs and persists a revocation with the current root, enforced locally
    /// at once. Returns the response and the `{kind, statement}` to submit.
    pub fn revoke(&self, id: &str, r: Revoke) -> Result<(Revoked, Value), Error> {
        let mut connection = self.connection()?;
        let presigned = match r.revocation {
            Some(statement) => {
                let network = self.network_record(&connection, id)?;
                let signature = statement["signature"].as_str().unwrap_or_default();
                let signer = self.accept_signer(&connection, &network, signature)?;
                if statement.get("host_public_key").is_some() {
                    let rev: HostRevocation = serde_json::from_value(statement.clone())
                        .map_err(|_| Error::Invalid("invalid host revocation".into()))?;
                    rev.verify(&network.id, std::slice::from_ref(&signer))?;
                    Some((
                        "host",
                        key_id(&membership::canonical(&rev.host_public_key, 32)?),
                        statement,
                    ))
                } else {
                    let rev: InviteRevocation = serde_json::from_value(statement.clone())
                        .map_err(|_| Error::Invalid("invalid invite revocation".into()))?;
                    rev.verify(&network.id, std::slice::from_ref(&signer))?;
                    Some(("invite", rev.invite_public_key.clone(), statement))
                }
            }
            None => None,
        };
        let (kind, subject) = match (&presigned, r.host_id, r.invite_public_key) {
            (Some((kind, subject, _)), None, None) => (*kind, subject.clone()),
            (None, Some(host), None) => ("host", host),
            (None, None, Some(invite)) => ("invite", invite),
            _ => {
                return Err(Error::Invalid(
                    "give exactly one of host_id, invite_public_key, or revocation".into(),
                ));
            }
        };
        let at = now();
        let own_id = self.identity().id;
        let tx = connection.transaction()?;
        let network = self.network_record(&tx, id)?;
        // A pre-signed revocation needs no root seed on this host.
        let root = match presigned {
            Some(_) => None,
            None => Some(self.current_root(&tx, id)?),
        };
        let sign = |kind: &str, key: &str| -> Result<Value, Error> {
            let Some(root) = &root else {
                return Ok(presigned.as_ref().map(|p| p.2.clone()).unwrap_or_default());
            };
            Ok(if kind == "host" {
                serde_json::to_value(HostRevocation::sign(root, &network.id, key, &at))?
            } else {
                serde_json::to_value(InviteRevocation::sign(root, &network.id, key, &at))?
            })
        };
        let members: Vec<Member> = {
            let mut statement =
                tx.prepare("SELECT record FROM network_members WHERE network_id = ?1")?;
            statement
                .query_map([id], |r| r.get::<_, String>(0))?
                .map(|r| json(r?))
                .collect::<Result<_, _>>()?
        };
        let (key, statement, dropped) = if kind == "host" {
            if subject == own_id {
                return Err(Error::Conflict("cannot revoke this host itself".into()));
            }
            let key = match members.iter().find(|m| m.host_id == subject) {
                Some(m) => m.public_key.clone(),
                None => Statements::load(&tx, id)?
                    .hosts
                    .into_iter()
                    .map(|h| h.host_public_key)
                    .find(|k| membership::canonical(k, 32).is_ok_and(|b| key_id(&b) == subject))
                    .ok_or(Error::NotFound)?,
            };
            let statement = sign("host", &key)?;
            (key, statement, vec![subject.clone()])
        } else {
            membership::public_key(&subject)?;
            if members.iter().any(|m| {
                m.host_id == own_id
                    && m.membership
                        .as_ref()
                        .is_some_and(|ms| ms.invite_public_key == subject)
            }) {
                return Err(Error::Conflict(
                    "cannot revoke the invite this host joined with".into(),
                ));
            }
            let statement = sign("invite", &subject)?;
            let dropped = members
                .iter()
                .filter(|m| {
                    m.membership
                        .as_ref()
                        .is_some_and(|ms| ms.invite_public_key == subject)
                })
                .map(|m| m.host_id.clone())
                .collect();
            // Persons admitted with this invite lose their admission too.
            for person in self.stored_persons(&tx, id)? {
                if person.admission.is_none()
                    && person
                        .membership
                        .as_ref()
                        .is_some_and(|m| m.invite_public_key == subject)
                {
                    self.drop_person_locally(&tx, id, &person.person_public_key, &at)?;
                }
            }
            (subject.clone(), statement, dropped)
        };
        let existing: Option<String> = tx
            .query_row(
                "SELECT record FROM network_statements WHERE network_id = ?1 AND kind = ?2 AND subject = ?3",
                params![id, kind, key],
                |r| r.get(0),
            )
            .optional()?;
        let statement = match existing {
            Some(record) => serde_json::from_str(&record)?,
            None => {
                tx.execute(
                    "INSERT INTO network_statements VALUES (?1, ?2, ?3, ?4)",
                    params![id, kind, key, serde_json::to_string(&statement)?],
                )?;
                let event_subject = if kind == "host" { &subject } else { &key };
                append_event(&tx, &format!("network.{kind}_revoked"), event_subject, &at)?;
                statement
            }
        };
        remember_joins(&tx, self, id)?;
        for host in &dropped {
            if tx.execute(
                "DELETE FROM network_members WHERE network_id = ?1 AND host_id = ?2",
                params![id, host],
            )? > 0
            {
                append_event(&tx, "network.member_removed", host, &at)?;
            }
        }
        tx.commit()?;
        self.refresh_member_pins(&connection)?;
        Ok((
            Revoked {
                network_id: network.id,
                kind: kind.into(),
                subject: key,
                submitted: false,
            },
            json_value!({"kind": kind, "statement": statement}),
        ))
    }

    /// Signs a person admission with the current root (administrator only).
    pub fn sign_person_admission(
        &self,
        id: &str,
        r: AdmitPerson,
    ) -> Result<(Network, PersonAdmission), Error> {
        let connection = self.connection()?;
        let network = self.network_record(&connection, id)?;
        // An administrator signs through the CLI; otherwise this host signs
        // with the root seed.
        let (key, member, presigned) = match r.admission {
            Some(a) => {
                let signer = self.accept_signer(&connection, &network, &a.signature)?;
                if signer == network.current_root_public_key {
                    a.verify(&network.id, network.root_epoch, &signer)?;
                } else if a.epoch > network.root_epoch {
                    return Err(Error::Invalid(
                        "an administrator's admission must be for at most the current epoch".into(),
                    ));
                } else {
                    a.verify_signed_by(&network.id, &signer)?;
                }
                (a.person_public_key.clone(), a.member.clone(), Some(a))
            }
            None => {
                // Only a host holding the root seed signs here.
                self.current_root(&connection, id)?;
                (
                    persons::normalize_person_key(&r.person_public_key)?,
                    r.member,
                    None,
                )
            }
        };
        membership::label(&member)?;
        if Statements::load(&connection, id)?
            .person_removals
            .iter()
            .any(|r| r.person_public_key == key)
        {
            return Err(Error::Forbidden);
        }
        self.check_label_free(&connection, id, &member, Some(&key))?;
        let admission = match presigned {
            Some(a) => a,
            None => PersonAdmission::sign(
                &self.current_root(&connection, id)?,
                &network.id,
                network.root_epoch,
                &key,
                &member,
                &now(),
            ),
        };
        Ok((network, admission))
    }
    /// Signs a host admission with the current root (administrator only).
    pub fn sign_host_admission(
        &self,
        id: &str,
        r: AdmitHost,
    ) -> Result<(Network, HostAdmission), Error> {
        let connection = self.connection()?;
        let network = self.network_record(&connection, id)?;
        let presigned = match r.admission.clone() {
            Some(a) => {
                let signer = self.accept_signer(&connection, &network, &a.signature)?;
                if signer == network.current_root_public_key {
                    a.verify(&network.id, network.root_epoch, &signer)?;
                } else if a.epoch > network.root_epoch {
                    return Err(Error::Invalid(
                        "an administrator's admission must be for at most the current epoch".into(),
                    ));
                } else {
                    a.verify_signed_by(&network.id, &signer)?;
                }
                Some(a)
            }
            None => {
                self.current_root(&connection, id)?;
                None
            }
        };
        let r = match &presigned {
            Some(a) => AdmitHost {
                host_public_key: a.host_public_key.clone(),
                member: a.member.clone(),
                admission: None,
            },
            None => r,
        };
        membership::label(&r.member)?;
        let key = membership::public_key(&r.host_public_key)?;
        if key_id(key.as_bytes()) == self.identity().id {
            return Err(Error::Conflict("this host is already a member".into()));
        }
        let statements = Statements::load(&connection, id)?;
        if statements
            .hosts
            .iter()
            .map(|h| &h.host_public_key)
            .chain(statements.leaves.iter().map(|l| &l.host_public_key))
            .any(|k| *k == r.host_public_key)
        {
            return Err(Error::Forbidden);
        }
        let admission = match presigned {
            Some(a) => a,
            None => HostAdmission::sign(
                &self.current_root(&connection, id)?,
                &network.id,
                network.root_epoch,
                &r.host_public_key,
                &r.member,
                &now(),
            ),
        };
        Ok((network, admission))
    }
    /// Records an invite token an administrator signed through the CLI: the
    /// daemon checks the token and its signer, then records the invite.
    fn record_signed_invite(
        &self,
        id: &str,
        token: &str,
        person_only: bool,
    ) -> Result<IssuedInvite, Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let network = self.network_record(&tx, id)?;
        let token = token.trim();
        if token.starts_with(crate::link_runtime::invite::PREFIX) {
            let (feature, _) = crate::link_runtime::catalog::feature(&tx, id)
                .map_err(crate::link_runtime::support::model_error)?;
            if feature == "-" {
                return Err(crate::link_runtime::support::model_error(
                    crate::link_runtime::support::Failure::new("upgrade_required", "-", "feature")
                        .into(),
                ));
            }
            let decoded = crate::link_runtime::invite::decode(
                token,
                crate::link_runtime::support::now()
                    .map_err(|e| crate::link_runtime::support::model_error(e.into()))?,
                &feature,
            )
            .map_err(crate::link_runtime::support::model_error)?;
            if decoded.network.id != network.id
                || decoded.network.name != network.name
                || decoded.network.coordinator_address != network.coordinator_address
                || decoded.network.coordinator_public_key != network.coordinator_public_key
                || (person_only && decoded.token.mode != "person")
                || (!person_only && decoded.token.mode == "person")
            {
                return Err(Error::Invalid("invitation pins differ".into()));
            }
            let prior = crate::link_runtime::catalog::read(&tx, id)
                .map_err(crate::link_runtime::support::model_error)?;
            let union = crate::link_runtime::catalog::merge(
                id,
                &[&prior, decoded.token.catalog.get().as_bytes()],
            )
            .map_err(crate::link_runtime::support::model_error)?;
            let p = crate::link_runtime::catalog::verify(
                &tx,
                &network,
                &union,
                crate::link_runtime::support::now()
                    .map_err(|e| crate::link_runtime::support::model_error(e.into()))?,
            )
            .map_err(crate::link_runtime::support::model_error)?;
            crate::linking::select_stored_proof_catalog(
                crate::linking::CatalogFactContext {
                    network: &p.descriptor,
                    epoch: p.network.epoch,
                    known_feature_id: &feature,
                    now: crate::link_runtime::support::now()
                        .map_err(|e| crate::link_runtime::support::model_error(e.into()))?,
                },
                &union,
                &[crate::linking::ProofSeed {
                    kind: "invite_feature".into(),
                    body: crate::link_runtime::invite::seed_body(&decoded.token)
                        .map_err(crate::link_runtime::support::model_error)?,
                }],
            )
            .map_err(crate::link_runtime::support::model_error)?;
            append_event(&tx, "network.invite_issued", id, &now())?;
            tx.commit()?;
            return Ok(IssuedInvite {
                network_id: network.id,
                member: decoded.member,
                invite_public_key: STANDARD.encode(decoded.seed.verifying_key().as_bytes()),
                invite_expires_at: decoded.expires,
                token: token.into(),
            });
        }
        let (network_id, member, invite, expires, signatures) = if person_only {
            let t = PersonInviteToken::decode(token)?;
            self.check_label_free(&tx, id, &t.member, None)?;
            (
                t.network_id,
                t.member,
                t.invite_public_key,
                t.invite_expires_at,
                vec![t.invite_signature],
            )
        } else if token.starts_with(MEMBER_TOKEN_PREFIX) {
            let t = MemberInviteToken::decode(token)?;
            (
                t.network_id,
                t.member,
                t.invite_public_key,
                t.invite_expires_at,
                vec![t.invite_signature, t.person_invite_signature],
            )
        } else {
            let t = InviteToken::decode(token)?;
            (
                t.network_id,
                t.member,
                t.invite_public_key,
                t.invite_expires_at,
                vec![t.invite_signature],
            )
        };
        if network_id != network.id {
            return Err(Error::Invalid("token is for another network".into()));
        }
        let expiry = membership::time(&expires)?;
        if expiry > chrono::Utc::now() + MAX_INVITE_LIFETIME {
            return Err(Error::Invalid(
                "invite expiry must be in the future and at most 30 days ahead".into(),
            ));
        }
        for signature in &signatures {
            self.accept_signer(&tx, &network, signature)?;
        }
        append_event(&tx, "network.invite_issued", &network.id, &now())?;
        tx.commit()?;
        Ok(IssuedInvite {
            network_id: network.id,
            member,
            invite_public_key: invite,
            invite_expires_at: expires,
            token: token.to_owned(),
        })
    }
    /// Issues a one-time person invite signed by the current root.
    pub fn issue_person_invite(&self, id: &str, r: CreateInvite) -> Result<IssuedInvite, Error> {
        let mut r = r;
        if r.token.is_none() {
            let c = self.connection()?;
            if crate::link_runtime::catalog::feature(&c, id)
                .map_err(crate::link_runtime::support::model_error)?
                .0
                != "-"
            {
                r.expires_at = membership::time(&r.expires_at)?
                    .format("%Y-%m-%dT%H:%M:%SZ")
                    .to_string();
            }
        }
        if let Some(token) = r.token {
            return self.record_signed_invite(id, &token, true);
        }
        membership::label(&r.member)?;
        let expires = membership::time(&r.expires_at)?;
        let at = {
            let c = self.connection()?;
            if crate::link_runtime::catalog::feature(&c, id)
                .map_err(crate::link_runtime::support::model_error)?
                .0
                != "-"
            {
                crate::link_runtime::support::now()
                    .map_err(|e| crate::link_runtime::support::model_error(e.into()))?
            } else {
                chrono::Utc::now()
            }
        };
        if expires <= at || expires > at + MAX_INVITE_LIFETIME {
            return Err(Error::Invalid(
                "invite expiry must be in the future and at most 30 days ahead".into(),
            ));
        }
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let network = self.network_record(&tx, id)?;
        let root = self.current_root(&tx, id)?;
        self.check_label_free(&tx, id, &r.member, None)?;
        let invite = random_seed()?;
        let token = PersonInviteToken::issue(
            &root,
            &invite,
            &network.id,
            &network.name,
            network.root_epoch,
            &r.member,
            &r.expires_at,
            &network.coordinator_address,
            &network.coordinator_public_key,
        );
        append_event(&tx, "network.invite_issued", &network.id, &now())?;
        let wrapped = crate::link_runtime::invite::wrap_legacy(
            &tx,
            &network,
            &token.encode(),
            &KeySigner::Raw(&root),
        )
        .map_err(crate::link_runtime::support::model_error)?;
        tx.commit()?;
        Ok(IssuedInvite {
            network_id: network.id,
            member: token.member.clone(),
            invite_public_key: token.invite_public_key.clone(),
            invite_expires_at: token.invite_expires_at.clone(),
            token: wrapped,
        })
    }
    /// Removes a person (administrator only): signed by the current root,
    /// persisted, and enforced locally at once, ending its bindings.
    pub fn remove_person(&self, id: &str, r: RemovePerson) -> Result<(Revoked, Value), Error> {
        let at = now();
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let network = self.network_record(&tx, id)?;
        let r = match r.removal {
            Some(removal) => {
                let signer = self.accept_signer(&tx, &network, &removal.signature)?;
                removal.verify(&network.id, std::slice::from_ref(&signer))?;
                RemovePerson {
                    person_id: persons::person_id_of(&removal.person_public_key)?,
                    removal: Some(removal),
                }
            }
            None => {
                self.current_root(&tx, id)?;
                r
            }
        };
        let stored = Statements::load(&tx, id)?;
        let existing = stored
            .person_removals
            .iter()
            .find(|p| persons::person_id_of(&p.person_public_key).ok() == Some(r.person_id.clone()))
            .cloned();
        let removal = match existing {
            Some(removal) => removal,
            None => {
                let person = self
                    .stored_persons(&tx, id)?
                    .into_iter()
                    .find(|p| p.person_id == r.person_id)
                    .ok_or(Error::NotFound)?;
                // What happens to a current administrator's statements is
                // decided by removing the administrator role first.
                if self
                    .authority(&tx, &network)?
                    .admins
                    .contains(&person.person_public_key)
                {
                    return Err(Error::Conflict(
                        "that person is a current administrator; remove the administrator role first"
                            .into(),
                    ));
                }
                let removal = match r.removal {
                    Some(removal) => removal,
                    None => PersonRemoval::sign(
                        &self.current_root(&tx, id)?,
                        &network.id,
                        &person.person_public_key,
                        &at,
                    ),
                };
                insert_statement(
                    &tx,
                    id,
                    "person_removal",
                    &removal.person_public_key,
                    &removal,
                )?;
                append_event(&tx, "network.person_removed", &r.person_id, &at)?;
                self.drop_person_locally(&tx, id, &removal.person_public_key, &at)?;
                removal
            }
        };
        tx.commit()?;
        Ok((
            Revoked {
                network_id: network.id,
                kind: "person".into(),
                subject: removal.person_public_key.clone(),
                submitted: false,
            },
            json_value!({"kind": "person", "statement": removal}),
        ))
    }
    /// Records a person's unbinding of a host: verified, persisted, and
    /// enforced locally at once.
    pub fn record_unbinding(
        &self,
        id: &str,
        unbinding: HostUnbinding,
    ) -> Result<(Revoked, Value), Error> {
        let at = now();
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let network = self.network_record(&tx, id)?;
        unbinding.verify(&network.id)?;
        let subject = unbinding.subject();
        let existing: Option<String> = tx
            .query_row(
                "SELECT record FROM network_statements WHERE network_id = ?1 AND kind = 'unbind' AND subject = ?2",
                params![id, subject],
                |r| r.get(0),
            )
            .optional()?;
        let unbinding = match existing {
            Some(record) => json(record)?,
            None => {
                insert_statement(&tx, id, "unbind", &subject, &unbinding)?;
                let bound: Option<String> = tx
                    .query_row(
                        "SELECT record FROM network_statements WHERE network_id = ?1 AND kind = 'binding' AND subject = ?2",
                        params![id, unbinding.host_public_key],
                        |r| r.get(0),
                    )
                    .optional()?;
                if let Some(record) = bound
                    && json::<HostBinding>(record)?.person_public_key == unbinding.person_public_key
                {
                    self.drop_binding_locally(&tx, id, &unbinding.host_public_key, &at)?;
                }
                unbinding
            }
        };
        tx.commit()?;
        Ok((
            Revoked {
                network_id: network.id,
                kind: "unbind".into(),
                subject: unbinding.host_public_key.clone(),
                submitted: false,
            },
            json_value!({"kind": "unbind", "statement": unbinding}),
        ))
    }
    /// Valid persons with the hosts bound to them.
    /// Stores this host's accepted binding, its member's person, and
    /// `network.host_bound`, each only if not already recorded, so a map that
    /// later carries the same binding adds no second event.
    pub(crate) fn record_own_binding(&self, id: &str, binding: &HostBinding) -> Result<(), Error> {
        let own_key = self.identity().public_key;
        if binding.host_public_key != own_key {
            return Err(Error::Invalid("binding does not name this host".into()));
        }
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        self.network_record(&tx, id)?;
        if insert_statement(&tx, id, "binding", &own_key, binding)? {
            let person_id = persons::person_id_of(&binding.person_public_key)?;
            let person_member = self
                .stored_persons(&tx, id)?
                .into_iter()
                .find(|p| p.person_public_key == binding.person_public_key)
                .map(|p| p.member);
            let own_id = self.identity().id;
            let record: Option<String> = tx
                .query_row(
                    "SELECT record FROM network_members WHERE network_id = ?1 AND host_id = ?2",
                    params![id, own_id],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(record) = record {
                let mut member: Member = json(record)?;
                member.person_id = Some(person_id);
                member.person_member = person_member;
                tx.execute(
                    "UPDATE network_members SET record = ?1 WHERE network_id = ?2 AND host_id = ?3",
                    params![serde_json::to_string(&member)?, id, own_id],
                )?;
            }
            append_event(&tx, "network.host_bound", &own_id, &now())?;
        }
        tx.commit()?;
        Ok(())
    }
    /// Refuses a label that conflicts with a current person's (409). A removed
    /// person no longer holds its label; re-admitting the same key is allowed.
    fn check_label_free(
        &self,
        connection: &Connection,
        id: &str,
        label: &str,
        key: Option<&str>,
    ) -> Result<(), Error> {
        let taken = self.stored_persons(connection, id)?.into_iter().any(|p| {
            Some(p.person_public_key.as_str()) != key && labels_conflict(&p.member, label)
        });
        if taken {
            return Err(Error::Conflict(format!(
                "person label {label:?} is already used in this network"
            )));
        }
        Ok(())
    }
    /// Signs (with the root seed) or checks (a statement the CLI signed with
    /// an SSH root) a delegation of administrator rights to a current person.
    pub fn sign_delegation(
        &self,
        id: &str,
        r: DelegateAdmin,
    ) -> Result<(Network, AdminDelegation), Error> {
        let connection = self.connection()?;
        let network = self.network_record(&connection, id)?;
        let persons = self.stored_persons(&connection, id)?;
        let delegation = match (r.delegation, r.person) {
            (Some(d), None) => {
                d.verify(
                    &network.id,
                    network.root_epoch,
                    &network.current_root_public_key,
                )
                .map_err(|_| Error::Forbidden)?;
                d
            }
            (None, Some(person)) => {
                let person = admins::resolve_person(&persons, &person)?;
                AdminDelegation::sign(
                    &KeySigner::Raw(&self.current_root(&connection, id)?),
                    &network.id,
                    network.root_epoch,
                    &person.person_public_key,
                    &now(),
                )?
            }
            _ => {
                return Err(Error::Invalid(
                    "give exactly one of person or delegation".into(),
                ));
            }
        };
        if !persons
            .iter()
            .any(|p| p.person_public_key == delegation.person_public_key)
        {
            return Err(Error::Invalid(
                "only a current person can be an administrator".into(),
            ));
        }
        if Statements::load(&connection, id)?
            .admin_removals
            .iter()
            .any(|r| r.person_public_key == delegation.person_public_key)
        {
            return Err(Error::Forbidden);
        }
        Ok((network, delegation))
    }

    /// Signs or checks an administrator removal and persists it at once:
    /// sticky and enforced locally before the coordinator hears of it.
    pub fn remove_admin(&self, id: &str, r: RemoveAdmin) -> Result<(Revoked, Value), Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let network = self.network_record(&tx, id)?;
        let removal = match (r.removal, r.person) {
            (Some(removal), None) => {
                removal
                    .verify(&network.id, &self.roots(&tx, &network)?)
                    .map_err(|_| Error::Forbidden)?;
                removal
            }
            (None, Some(person)) => {
                let root = self.current_root(&tx, id)?;
                let key = self.resolve_admin(&tx, id, &person)?;
                let kept = if r.revoke_admitted {
                    Vec::new()
                } else {
                    self.kept_digests(&tx, &network, &key)?
                };
                AdminRemoval::sign(
                    &KeySigner::Raw(&root),
                    &network.id,
                    &key,
                    r.revoke_admitted,
                    &kept,
                    &now(),
                )?
            }
            _ => {
                return Err(Error::Invalid(
                    "give exactly one of person or removal".into(),
                ));
            }
        };
        let statements = Statements::load(&tx, id)?;
        if !statements
            .admins
            .iter()
            .any(|d| d.person_public_key == removal.person_public_key)
        {
            return Err(Error::NotFound);
        }
        let existing = statements
            .admin_removals
            .iter()
            .find(|r| r.person_public_key == removal.person_public_key);
        let removal = match existing {
            // One removal per key: a second plain one is refused; a repeated
            // revoke_admitted resubmits the stored one.
            Some(_) if !removal.revoke_admitted => {
                return Err(Error::Conflict(
                    "that administrator has already been removed".into(),
                ));
            }
            Some(old) if old.revoke_admitted => old.clone(),
            Some(_) => {
                // Escalation to revoke_admitted, recorded again.
                append_event(
                    &tx,
                    "network.admin_removed",
                    &admins::person_of(&removal.person_public_key),
                    &now(),
                )?;
                tx.execute(
                    "DELETE FROM network_statements WHERE network_id = ?1 AND kind = 'admin_removal' AND subject = ?2",
                    params![id, removal.person_public_key],
                )?;
                insert_statement(
                    &tx,
                    id,
                    "admin_removal",
                    &removal.person_public_key,
                    &removal,
                )?;
                removal
            }
            None => {
                insert_statement(
                    &tx,
                    id,
                    "admin_removal",
                    &removal.person_public_key,
                    &removal,
                )?;
                append_event(
                    &tx,
                    "network.admin_removed",
                    &admins::person_of(&removal.person_public_key),
                    &now(),
                )?;
                removal
            }
        };
        if removal.revoke_admitted {
            self.cascade_locally(&tx, id, &removal.person_public_key)?;
        }
        tx.commit()?;
        Ok((
            Revoked {
                network_id: network.id,
                kind: "admin".into(),
                subject: removal.person_public_key.clone(),
                submitted: false,
            },
            json_value!({"kind": "admin", "statement": removal}),
        ))
    }

    /// Resolves a person ID, key, or label to a person key, including an
    /// administrator who is no longer a current person.
    pub(crate) fn resolve_admin(
        &self,
        connection: &Connection,
        id: &str,
        given: &str,
    ) -> Result<String, Error> {
        let persons = self.stored_persons(connection, id)?;
        match admins::resolve_person(&persons, given) {
            Ok(p) => Ok(p.person_public_key.clone()),
            Err(Error::NotFound) => Statements::load(connection, id)?
                .admins
                .iter()
                .map(|d| d.person_public_key.clone())
                .find(|k| *k == given || persons::person_id_of(k).is_ok_and(|id| id == given))
                .ok_or(Error::NotFound),
            Err(e) => Err(e),
        }
    }
    /// The digests of every statement this host has verified as signed by the
    /// administrator `key`: members' invites and admissions, persons'
    /// admissions and invites, revocations and person removals, and the newest
    /// group versions. A removal without `revoke_admitted` keeps exactly these.
    fn kept_digests(
        &self,
        connection: &Connection,
        network: &Network,
        key: &str,
    ) -> Result<Vec<String>, Error> {
        let id = &network.id;
        let mut digests = BTreeSet::new();
        let mut add = |signature: &str, digest: String| {
            if persons::sshsig_signer(signature).as_deref() == Some(key) {
                digests.insert(digest);
            }
        };
        for m in self.stored_members(connection, id)? {
            if let Some(c) = &m.membership {
                add(&c.invite_signature, c.digest());
            }
            if let Some(a) = &m.admission {
                add(&a.signature, a.digest());
            }
        }
        for a in self.issued_admissions(connection, id)? {
            add(&a.signature, a.digest());
        }
        let statements = Statements::load(connection, id)?;
        for p in self.stored_persons(connection, id)? {
            match (&p.admission, &p.membership) {
                (Some(a), _) => add(&a.signature, a.digest()),
                (None, Some(m)) => add(&m.invite_signature, m.digest()),
                (None, None) => {}
            }
        }
        for r in &statements.hosts {
            add(&r.signature, r.digest());
        }
        for r in &statements.invites {
            add(&r.signature, r.digest());
        }
        for r in &statements.person_removals {
            add(&r.signature, r.digest());
        }
        for g in &statements.groups {
            add(&g.signature, g.digest());
        }
        Ok(digests.into_iter().collect())
    }
    /// What a removal without `revoke_admitted` keeps, for the CLI to sign
    /// with `--root-key`.
    pub fn admin_removal_plan(&self, id: &str, person: &str) -> Result<AdminRemovalPlan, Error> {
        let connection = self.connection()?;
        let network = self.network_record(&connection, id)?;
        let key = self.resolve_admin(&connection, id, person)?;
        Ok(AdminRemovalPlan {
            kept: self.kept_digests(&connection, &network, &key)?,
            person_public_key: key,
        })
    }

    /// Enforces a removal with `revoke_admitted` at once: members and persons
    /// the administrator admitted are dropped, with their bindings, and the
    /// groups they signed. The next map restores any reverted group version.
    fn cascade_locally(
        &self,
        tx: &rusqlite::Transaction,
        id: &str,
        admin: &str,
    ) -> Result<(), Error> {
        let by = |signature: &str| persons::sshsig_signer(signature).as_deref() == Some(admin);
        let at = now();
        for m in self.stored_members(tx, id)? {
            let signed = m.admission.as_ref().is_some_and(|a| by(&a.signature))
                || m.membership
                    .as_ref()
                    .is_some_and(|c| by(&c.invite_signature));
            if signed {
                tx.execute(
                    "DELETE FROM network_members WHERE network_id = ?1 AND host_id = ?2",
                    params![id, m.host_id],
                )?;
                append_event(tx, "network.member_removed", &m.host_id, &at)?;
            }
        }
        let mut dropped = BTreeSet::new();
        for p in self.stored_persons(tx, id)? {
            let signed = p.admission.as_ref().is_some_and(|a| by(&a.signature))
                || p.membership
                    .as_ref()
                    .is_some_and(|m| by(&m.invite_signature));
            if signed {
                tx.execute(
                    "DELETE FROM network_statements WHERE network_id = ?1 AND kind = 'person' AND subject = ?2",
                    params![id, p.person_public_key],
                )?;
                dropped.insert(p.person_public_key);
            }
        }
        let bindings: Vec<(String, String)> = {
            let mut statement = tx.prepare(
                "SELECT subject, record FROM network_statements WHERE network_id = ?1 AND kind = 'binding'",
            )?;
            statement
                .query_map([id], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<_, _>>()?
        };
        for (host, record) in bindings {
            let Ok(b) = json::<HostBinding>(record) else {
                continue;
            };
            if dropped.contains(&b.person_public_key) {
                tx.execute(
                    "DELETE FROM network_statements WHERE network_id = ?1 AND kind = 'binding' AND subject = ?2",
                    params![id, host],
                )?;
                if let Ok(key) = membership::canonical(&host, 32) {
                    append_event(tx, "network.host_unbound", &key_id(&key), &at)?;
                }
            }
        }
        for g in self.stored_groups(tx, id)? {
            if by(&g.signature) {
                tx.execute(
                    "DELETE FROM network_statements WHERE network_id = ?1 AND kind = 'group' AND subject = ?2",
                    params![id, g.name],
                )?;
                append_event(tx, "network.group_updated", &g.name, &at)?;
            }
        }
        Ok(())
    }

    /// Signs the next version of a group with the root seed, or checks one an
    /// administrator (or SSH root) signed through the CLI. The version must
    /// be higher than the newest this host has verified.
    pub fn sign_group(&self, id: &str, r: SetGroup) -> Result<(Network, Group), Error> {
        let connection = self.connection()?;
        let network = self.network_record(&connection, id)?;
        let stored = self.stored_groups(&connection, id)?;
        let projection = self
            .linking_projection(&connection, &network)
            .map_err(crate::link_runtime::support::model_error)?;
        let water = |name: &str| {
            projection
                .as_ref()
                .and_then(|p| {
                    p.access
                        .groups
                        .iter()
                        .find(|g| g.name == name)
                        .map(|g| g.selection.high_water.version)
                })
                .unwrap_or_else(|| {
                    stored
                        .iter()
                        .find(|g| g.name == name)
                        .map_or(0, |g| g.version)
                })
        };
        let group = match (r.group, r.name) {
            (Some(g), None) => {
                let signer = self.accept_signer(&connection, &network, &g.signature)?;
                g.verify_signed_by(&network.id, &signer)?;
                g
            }
            (None, Some(name)) => {
                admins::group_name(&name)?;
                let persons = self.stored_persons(&connection, id)?;
                let members = r
                    .members
                    .iter()
                    .map(|m| admins::resolve_person(&persons, m).map(|p| p.person_id.clone()))
                    .collect::<Result<Vec<_>, _>>()?;
                let version = water(&name).checked_add(1).ok_or_else(|| {
                    crate::link_runtime::support::model_error(
                        crate::link_runtime::support::Failure {
                            error: "access version exhausted".into(),
                            ..crate::link_runtime::support::Failure::new(
                                "quota_exceeded",
                                "-",
                                "version",
                            )
                        }
                        .into(),
                    )
                })?;
                Group::sign(
                    &KeySigner::Raw(&self.current_root(&connection, id)?),
                    &network.id,
                    &name,
                    version,
                    &members,
                    &now(),
                )?
            }
            _ => {
                return Err(Error::Invalid("give exactly one of name or group".into()));
            }
        };
        if projection.is_some() && group.version <= water(&group.name) {
            return Err(Error::Conflict(
                "a higher group version remains selected".into(),
            ));
        }
        if let Some(old) = stored.iter().find(|g| g.name == group.name)
            && old.version >= group.version
        {
            return Err(Error::Conflict(format!(
                "group {} is already at version {}",
                group.name, old.version
            )));
        }
        Ok((network, group))
    }

    /// Current groups sorted by name; deleted groups (no members) are left
    /// out unless `all`, and so are members that are not current persons.
    pub fn groups(&self, id: &str, all: bool) -> Result<Vec<GroupView>, Error> {
        let connection = self.connection()?;
        let network = self.network_record(&connection, id)?;
        if let Some(p) = self
            .linking_projection(&connection, &network)
            .map_err(crate::link_runtime::support::model_error)?
        {
            let people: BTreeSet<_> = p
                .network
                .facts
                .state
                .persons
                .iter()
                .filter(|(_, s)| s.admitted)
                .map(|(key, _)| persons::person_id_of(key))
                .collect::<Result<_, _>>()?;
            let mut groups = Vec::new();
            for (name, group) in &p.groups {
                if !all && group.members.is_empty() {
                    continue;
                }
                let mut view = GroupView::of(group, &p.network.root_public_key);
                view.members.retain(|id| people.contains(id));
                if let Some(auth) = p
                    .group_authorizations
                    .get(name)
                    .filter(|s| s.as_str() != "-")
                {
                    let raw = crate::link_runtime::crypto::bytes(auth, crate::linking::MAX_OBJECT)
                        .map_err(crate::link_runtime::support::model_error)?;
                    let record: Value = serde_json::from_slice(&raw)?;
                    view.signer =
                        persons::sshsig_signer(record["signature"].as_str().unwrap_or("-"))
                            .ok_or_else(|| {
                                Error::Internal(anyhow::anyhow!("verified group signer absent"))
                            })?;
                    view.authorization_base64 = Some(auth.clone());
                }
                groups.push(view);
            }
            return Ok(groups);
        }
        let persons: BTreeSet<String> = self
            .stored_persons(&connection, id)?
            .into_iter()
            .map(|p| p.person_id)
            .collect();
        let root = self.roots(&connection, &network)?;
        let current = root.last().cloned().unwrap_or_default();
        Ok(self
            .stored_groups(&connection, id)?
            .iter()
            .filter(|g| all || !g.members.is_empty())
            .map(|g| {
                let mut view = GroupView::of(g, &current);
                view.members.retain(|m| persons.contains(m));
                view
            })
            .collect())
    }

    pub fn persons(&self, id: &str) -> Result<Vec<PersonView>, Error> {
        let connection = self.connection()?;
        let network = self.network_record(&connection, id)?;
        let members = self.stored_members(&connection, id)?;
        let stored = self.stored_persons(&connection, id)?;
        let admins = self.authority(&connection, &network)?.admins;
        let labels: Vec<String> = stored.iter().map(|p| p.member.clone()).collect();
        Ok(stored
            .into_iter()
            .map(|p| {
                let mut hosts: Vec<String> = members
                    .iter()
                    .filter(|m| m.person_id.as_deref() == Some(p.person_id.as_str()))
                    .map(|m| m.host_id.clone())
                    .collect();
                hosts.sort();
                let label_conflict = labels
                    .iter()
                    .filter(|l| labels_conflict(l, &p.member))
                    .count()
                    > 1;
                PersonView {
                    administrator: admins.contains(&p.person_public_key),
                    person_id: p.person_id,
                    public_key: p.person_public_key,
                    member: p.member,
                    hosts,
                    label_conflict,
                }
            })
            .collect())
    }

    /// This host's own revocations of a kind the coordinator has not yet listed.
    fn pending_revocations(
        &self,
        id: &str,
        listed: &BTreeSet<(String, String)>,
    ) -> Result<Vec<Value>, Error> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT kind, subject, record FROM network_statements WHERE network_id = ?1 AND kind IN ('host', 'invite', 'person_removal', 'unbind', 'admin_removal','link_admin_removal_v2')",
        )?;
        let rows = statement
            .query_map([id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows
            .into_iter()
            .filter(|(kind, subject, _)| !listed.contains(&(kind.clone(), subject.clone())))
            .filter_map(|(kind, _, record)| {
                let statement: Value = serde_json::from_str(&record).ok()?;
                let kind = if kind == "admin_removal" || kind == "link_admin_removal_v2" {
                    "admin"
                } else if kind == "person_removal" {
                    "person"
                } else {
                    kind.as_str()
                };
                Some(json_value!({"kind": kind, "statement": statement}))
            })
            .collect())
    }

    /// Removes a network and everything learned from it, with `network.left`.
    fn forget_network(&self, id: &str) -> Result<(), Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        self.network_record(&tx, id)?;
        tx.execute("DELETE FROM network_members WHERE network_id = ?1", [id])?;
        tx.execute("DELETE FROM network_statements WHERE network_id = ?1", [id])?;
        tx.execute("DELETE FROM networks WHERE id = ?1", [id])?;
        append_event(&tx, "network.left", id, &now())?;
        tx.commit()?;
        self.refresh_member_pins(&connection)
    }

    /// The rotation this administrator has signed but not yet seen accepted.
    pub(crate) fn pending_rotation(
        &self,
        connection: &Connection,
        id: &str,
    ) -> Result<Option<PendingRotation>, Error> {
        connection
            .query_row(
                "SELECT record FROM network_statements WHERE network_id = ?1 AND kind = 'pending_rotation' ORDER BY CAST(subject AS INTEGER) DESC LIMIT 1",
                [id],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            .map(json)
            .transpose()
    }

    /// Returns the pending rotation, creating and persisting one first if none
    /// exists. The old root stays current locally until the coordinator
    /// accepts, so a crash after acceptance can always be completed.
    fn prepare_rotation(
        &self,
        id: &str,
        ssh: Option<RotateToSsh>,
    ) -> Result<(Network, PendingRotation), Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let network = self.network_record(&tx, id)?;
        if let Some(pending) = self.pending_rotation(&tx, id)? {
            return Ok((network, pending));
        }
        let epoch = Statements::load(&tx, id)?.rotations.len() as u64 + 1;
        if let Some(r) = ssh {
            let pending = self.ssh_rotation(&tx, &network, epoch, r)?;
            insert_statement(&tx, id, "pending_rotation", &epoch.to_string(), &pending)?;
            tx.commit()?;
            return Ok((network, pending));
        }
        let root = self.current_root(&tx, id)?;
        let next = random_seed()?;
        let next_key = STANDARD.encode(next.verifying_key().as_bytes());
        let at = now();
        let rotation = Rotation::sign(&root, id, epoch, &next_key, &at);
        let plan = self.plan_rotation(&tx, &network, epoch)?;
        let SignedPlan {
            attestations,
            admissions,
            groups,
        } = plan.sign(&KeySigner::Raw(&next), &at)?;
        let pending = PendingRotation {
            rotation,
            attestations,
            admissions,
            groups,
            root_seed: STANDARD.encode(next.to_bytes()),
        };
        insert_statement(&tx, id, "pending_rotation", &epoch.to_string(), &pending)?;
        tx.commit()?;
        Ok((network, pending))
    }

    /// What the next root signs: attestations for invite-chain members,
    /// host and person admissions, and current administrators' delegations.
    /// Statements an administrator signed stay valid and are not renewed.
    fn plan_rotation(
        &self,
        connection: &Connection,
        network: &Network,
        epoch: u64,
    ) -> Result<RotationPlan, Error> {
        if let Some(plan) = crate::link_runtime::rotation::plan(connection, network, epoch)
            .map_err(crate::link_runtime::support::model_error)?
        {
            return Ok(plan);
        }
        let id = &network.id;
        let authority = self.authority(connection, network)?;
        let admin_signed = |signature: &str| {
            persons::sshsig_signer(signature).is_some_and(|k| !authority.roots.contains(&k))
        };
        let item = |public_key: &str, member: &str| PlannedItem {
            public_key: public_key.to_owned(),
            member: member.to_owned(),
        };
        let mut plan = RotationPlan {
            network_id: id.clone(),
            epoch,
            current_root_public_key: authority.current().to_owned(),
            attestations: Vec::new(),
            host_admissions: Vec::new(),
            person_admissions: Vec::new(),
            admins: authority.admins.iter().cloned().collect(),
            groups: Vec::new(),
        };
        let statements = Statements::load(connection, id)?;
        for g in &statements.groups {
            if g.signer().is_none() || g.signer().as_deref() == Some(authority.current()) {
                plan.groups.push(PlannedGroup {
                    name: g.name.clone(),
                    version: g.version,
                    members: g.members.clone(),
                });
            }
        }
        let members: Vec<Member> = {
            let mut statement = connection.prepare(
                "SELECT record FROM network_members WHERE network_id = ?1 ORDER BY host_id",
            )?;
            statement
                .query_map([id], |r| r.get::<_, String>(0))?
                .map(|r| json::<Member>(r?))
                .collect::<Result<Vec<_>, _>>()?
        };
        let revoked: BTreeSet<&str> = statements
            .hosts
            .iter()
            .map(|r| r.host_public_key.as_str())
            .chain(statements.leaves.iter().map(|l| l.host_public_key.as_str()))
            .collect();
        // Root-signed admissions this host issued for hosts not joined yet.
        for a in self.issued_admissions(connection, id)? {
            if !admin_signed(&a.signature)
                && !revoked.contains(a.host_public_key.as_str())
                && a.verify(id, network.root_epoch, authority.current())
                    .is_ok()
                && !members.iter().any(|m| m.public_key == a.host_public_key)
            {
                plan.host_admissions
                    .push(item(&a.host_public_key, &a.member));
            }
        }
        for m in &members {
            match (&m.admission, &m.membership) {
                (Some(a), _) if !admin_signed(&a.signature) => {
                    plan.host_admissions.push(item(&m.public_key, &m.member))
                }
                (None, Some(chain)) if !admin_signed(&chain.invite_signature) => {
                    plan.attestations.push(item(&m.public_key, &m.member))
                }
                // This host's own membership has no stored chain.
                (None, None) => plan.attestations.push(item(&m.public_key, &m.member)),
                _ => {}
            }
        }
        for p in self.stored_persons(connection, id)? {
            let signature = match (&p.admission, &p.membership) {
                (Some(a), _) => a.signature.as_str(),
                (None, Some(m)) => m.invite_signature.as_str(),
                (None, None) => "",
            };
            if !admin_signed(signature) {
                plan.person_admissions
                    .push(item(&p.person_public_key, &p.member));
            }
        }
        Ok(plan)
    }
    /// Stored host admissions (`network_statements` kind `host_admission`,
    /// subject: host key): served ones and those this host issued, joined or
    /// not, so a rotation can renew hosts that have not joined yet.
    fn issued_admissions(
        &self,
        connection: &Connection,
        id: &str,
    ) -> Result<Vec<HostAdmission>, Error> {
        let mut statement = connection.prepare(
            "SELECT record FROM network_statements WHERE network_id = ?1 AND kind = 'host_admission' ORDER BY subject",
        )?;
        statement
            .query_map([id], |r| r.get::<_, String>(0))?
            .map(|r| json::<HostAdmission>(r?))
            .collect()
    }
    /// Records an admission the coordinator accepted, with
    /// `network.host_admitted` the first time.
    pub fn record_issued_admission(&self, id: &str, a: &HostAdmission) -> Result<(), Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let record = serde_json::to_string(a)?;
        let fresh = tx.execute(
            "INSERT OR IGNORE INTO network_statements VALUES (?1, 'host_admission', ?2, ?3)",
            params![id, a.host_public_key, record],
        )? > 0;
        if fresh {
            let host = key_id(&membership::canonical(&a.host_public_key, 32)?);
            append_event(&tx, "network.host_admitted", &host, &now())?;
        } else {
            tx.execute(
                "UPDATE network_statements SET record = ?3 WHERE network_id = ?1 AND kind = 'host_admission' AND subject = ?2",
                params![id, a.host_public_key, record],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
    /// The rotation plan, for the CLI to sign with an SSH root.
    pub fn rotation_plan(&self, id: &str) -> Result<RotationPlan, Error> {
        let connection = self.connection()?;
        let network = self.network_record(&connection, id)?;
        let epoch = Statements::load(&connection, id)?.rotations.len() as u64 + 1;
        self.plan_rotation(&connection, &network, epoch)
    }

    /// A rotation to an SSH root. The CLI signed the new root's attestations,
    /// admissions, and delegations; the rotation itself is signed here with
    /// the root seed, or came signed by the current SSH root. No seed is
    /// stored: `root_seed` stays empty.
    fn ssh_rotation(
        &self,
        connection: &Connection,
        network: &Network,
        epoch: u64,
        r: RotateToSsh,
    ) -> Result<PendingRotation, Error> {
        let root = persons::normalize_person_key(&r.root_public_key)?;
        let rotation = match r.rotation {
            Some(rotation) => {
                rotation
                    .verify_from(&network.id, epoch, &network.current_root_public_key)
                    .map_err(|_| Error::Forbidden)?;
                if rotation.root_public_key != root {
                    return Err(Error::Invalid("rotation names a different root key".into()));
                }
                rotation
            }
            None => Rotation::sign(
                &self.current_root(connection, &network.id)?,
                &network.id,
                epoch,
                &root,
                &now(),
            ),
        };
        for a in &r.attestations {
            a.verify(&network.id, epoch, &root)?;
        }
        for value in &r.admissions {
            let checked = if value.get("delegated_at").is_some() {
                serde_json::from_value::<AdminDelegation>(value.clone())
                    .map_err(|_| Error::Invalid("invalid delegation".into()))?
                    .verify(&network.id, epoch, &root)
            } else if value.get("person_public_key").is_some() {
                serde_json::from_value::<PersonAdmission>(value.clone())
                    .map_err(|_| Error::Invalid("invalid person admission".into()))?
                    .verify(&network.id, epoch, &root)
            } else {
                serde_json::from_value::<HostAdmission>(value.clone())
                    .map_err(|_| Error::Invalid("invalid host admission".into()))?
                    .verify(&network.id, epoch, &root)
                    .map(drop)
            };
            checked?;
        }
        for g in &r.groups {
            g.verify_signed_by(&network.id, &root)?;
        }
        Ok(PendingRotation {
            rotation,
            attestations: r.attestations,
            admissions: r.admissions,
            groups: r.groups,
            root_seed: String::new(),
        })
    }

    /// Makes an accepted pending rotation current, atomically: the new root
    /// seed, the rotation, and the new epoch's attestations, with
    /// `network.root_rotated`. A no-op if the rotation is already current.
    fn commit_rotation(&self, id: &str, pending: &PendingRotation) -> Result<(), Error> {
        // An SSH root leaves no seed here: this host deletes the one it had.
        let next: Option<Vec<u8>> = if pending.root_seed.is_empty() {
            None
        } else {
            Some(membership::canonical(&pending.root_seed, 32)?)
        };
        let rotation = &pending.rotation;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let mut network = self.network_record(&tx, id)?;
        network.root_ssh = next.is_none();
        tx.execute(
            "UPDATE networks SET root_seed = ?1 WHERE id = ?2",
            params![next, id],
        )?;
        for g in &pending.groups {
            tx.execute(
                "DELETE FROM network_statements WHERE network_id = ?1 AND kind = 'group' AND subject = ?2",
                params![id, g.name],
            )?;
            insert_statement(&tx, id, "group", &g.name, g)?;
        }
        for value in &pending.admissions {
            if value.get("host_public_key").is_some()
                && let Ok(a) = serde_json::from_value::<HostAdmission>(value.clone())
            {
                tx.execute(
                    "UPDATE network_statements SET record = ?3 WHERE network_id = ?1 AND kind = 'host_admission' AND subject = ?2",
                    params![id, a.host_public_key, serde_json::to_string(&a)?],
                )?;
            }
            if value.get("delegated_at").is_some()
                && let Ok(d) = serde_json::from_value::<AdminDelegation>(value.clone())
            {
                tx.execute(
                    "DELETE FROM network_statements WHERE network_id = ?1 AND kind = 'admin' AND subject = ?2",
                    params![id, d.person_public_key],
                )?;
                insert_statement(&tx, id, "admin", &d.person_public_key, &d)?;
            }
        }
        insert_statement(&tx, id, "rotation", &rotation.epoch.to_string(), rotation)?;
        tx.execute(
            "DELETE FROM network_statements WHERE network_id = ?1 AND kind IN ('attestation', 'pending_rotation')",
            [id],
        )?;
        for a in &pending.attestations {
            insert_statement(&tx, id, "attestation", &a.host_public_key, a)?;
        }
        network.root_epoch = rotation.epoch;
        network.current_root_public_key = rotation.root_public_key.clone();
        tx.execute(
            "UPDATE networks SET record = ?1 WHERE id = ?2",
            params![serde_json::to_string(&network)?, id],
        )?;
        append_event(&tx, "network.root_rotated", id, &now())?;
        tx.commit()?;
        Ok(())
    }

    /// Drops a pending rotation that can no longer be accepted.
    fn discard_rotation(&self, id: &str) -> Result<(), Error> {
        self.connection()?.execute(
            "DELETE FROM network_statements WHERE network_id = ?1 AND kind = 'pending_rotation'",
            [id],
        )?;
        Ok(())
    }
    /// Drops a pending rotation the coordinator rejected for good, recording
    /// `root rotation discarded: REASON` as the network's sync error.
    fn discard_rotation_with_error(&self, id: &str, reason: &str) -> Result<Network, Error> {
        self.discard_rotation(id)?;
        self.record_sync_error(id, format!("root rotation discarded: {reason}"))
    }

    /// Decides what to do with a pending rotation given the chain a
    /// coordinator served: commit it if the chain already holds it (the
    /// coordinator accepted it before a crash), discard it if the chain has a
    /// different rotation at that epoch or has moved past it, or resubmit it.
    fn resolve_rotation(&self, id: &str, offered: &[Rotation]) -> Result<PendingOutcome, Error> {
        let Some(pending) = self.pending_rotation(&*self.connection()?, id)? else {
            return Ok(PendingOutcome::None);
        };
        let epoch = pending.rotation.epoch as usize;
        match offered.get(epoch - 1) {
            Some(r) if *r == pending.rotation => {
                self.commit_rotation(id, &pending)?;
                Ok(PendingOutcome::Committed)
            }
            Some(_) => {
                self.discard_rotation(id)?;
                Ok(PendingOutcome::Discarded)
            }
            None if offered.len() + 1 < epoch => Ok(PendingOutcome::None),
            None => Ok(PendingOutcome::Resubmit(Box::new(pending))),
        }
    }

    fn set_coordinator_pending(
        &self,
        id: &str,
        pending: CoordinatorPending,
    ) -> Result<Network, Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let mut network = self.network_record(&tx, id)?;
        // A successor never replaces a pending move.
        if network
            .coordinator_pending
            .as_ref()
            .is_some_and(CoordinatorPending::is_move)
            && !pending.is_move()
        {
            return Ok(network);
        }
        network.coordinator_pending = Some(pending);
        tx.execute(
            "UPDATE networks SET record = ?1 WHERE id = ?2",
            params![serde_json::to_string(&network)?, id],
        )?;
        tx.commit()?;
        Ok(network)
    }

    pub(crate) fn record_sync_error(&self, id: &str, error: String) -> Result<Network, Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let mut network = self.network_record(&tx, id)?;
        network.last_sync_error = Some(error);
        tx.execute(
            "UPDATE networks SET record = ?1 WHERE id = ?2",
            params![serde_json::to_string(&network)?, id],
        )?;
        tx.commit()?;
        Ok(network)
    }

    /// This host's invite chain, used to register an administered network.
    /// A host admitted by public key has none.
    fn own_membership(&self, id: &str) -> Result<Option<Membership>, Error> {
        let m: Member = read(
            &*self.connection()?,
            "SELECT record FROM network_members WHERE network_id = ?1 AND host_id = ?2",
            params![id, self.identity().id],
        )?;
        Ok(m.membership)
    }
}

/// Status and body of one coordinator call; transport failures are `Err`.
pub(crate) async fn coordinator(
    store: Arc<Store>,
    address: &str,
    key: &str,
    path: String,
    body: Value,
) -> anyhow::Result<(u16, Vec<u8>)> {
    let key = membership::canonical(key, 32).map_err(|e| anyhow::anyhow!("{e}"))?;
    let (host, _) = membership::split_host_port(address).map_err(|e| anyhow::anyhow!("{e}"))?;
    let config = pinned_client_config(store, key, b"http/1.1")?;
    let name = rustls::pki_types::ServerName::try_from(host)?;
    tokio::time::timeout(
        Duration::from_secs(8),
        crate::peer::https_link(
            config,
            address,
            name,
            Method::POST,
            &path,
            serde_json::to_vec(&body)?,
        ),
    )
    .await
    .map_err(|_| anyhow::anyhow!("coordinator request timed out"))?
    .map(|(status, _, body)| (status, body))
}
/// A coordinator GET over the same pinned client.
async fn coordinator_get(
    store: Arc<Store>,
    address: &str,
    key: &str,
    path: String,
) -> anyhow::Result<(u16, Vec<u8>)> {
    let key = membership::canonical(key, 32).map_err(|e| anyhow::anyhow!("{e}"))?;
    let (host, _) = membership::split_host_port(address).map_err(|e| anyhow::anyhow!("{e}"))?;
    let config = pinned_client_config(store, key, b"http/1.1")?;
    let name = rustls::pki_types::ServerName::try_from(host)?;
    tokio::time::timeout(
        Duration::from_secs(8),
        https(config, address, name, Method::GET, &path, Vec::new()),
    )
    .await
    .map_err(|_| anyhow::anyhow!("coordinator request timed out"))?
}

/// Limits a coordinator reports a network has reached.
#[derive(Clone, Debug, Default)]
pub(crate) struct CoordinatorLimits {
    /// From the usage fetched after the latest successful sync.
    reached: Vec<String>,
    /// From the latest 429, until the next successful sync or join.
    refused: Option<String>,
}

/// The limit name and recorded message of a coordinator's 429 refusal.
fn limit_refusal(status: u16, body: &[u8]) -> Option<(String, String)> {
    if status != 429 {
        return None;
    }
    let value: Value = serde_json::from_slice(body).ok()?;
    let limit = value["limit"]
        .as_str()
        .filter(|l| !l.is_empty())?
        .to_owned();
    let error = value["error"].as_str().unwrap_or_default();
    let message = format!("coordination unavailable: coordinator limit {limit} reached: {error}");
    Some((limit, message))
}

impl Store {
    fn update_limits(&self, network: &str, f: impl FnOnce(&mut CoordinatorLimits)) {
        if let Ok(mut limits) = self.coordinator_limits.lock() {
            let entry = limits.entry(network.to_owned()).or_default();
            f(entry);
            if entry.reached.is_empty() && entry.refused.is_none() {
                limits.remove(network);
            }
        }
    }
    /// `(network, limit)` for every limit reached, sorted and without
    /// repeats: from usage for the `joined` networks, and from any 429, which
    /// may name a network a join was refused for.
    pub(crate) fn reached_limits(&self, joined: &[String]) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = match self.coordinator_limits.lock() {
            Ok(limits) => limits
                .iter()
                .flat_map(|(network, l)| {
                    let usage = if joined.contains(network) {
                        l.reached.as_slice()
                    } else {
                        &[]
                    };
                    usage
                        .iter()
                        .chain(l.refused.iter())
                        .map(move |limit| (network.clone(), limit.clone()))
                })
                .collect(),
            Err(_) => Vec::new(),
        };
        out.sort();
        out.dedup();
        out
    }
}

/// After a successful sync or join: forgets a 429 and fetches the network's
/// usage. A 404 is an older coordinator without limits; other failures keep
/// the usage last seen.
async fn refresh_usage(store: &Arc<Store>, network: &Network) {
    store.update_limits(&network.id, |l| l.refused = None);
    let response = coordinator_get(
        store.clone(),
        &network.coordinator_address,
        &network.coordinator_public_key,
        format!("/coord/v1/networks/{}/usage", network.id),
    )
    .await;
    let reached = match response {
        Ok((200, body)) => {
            let Ok(usage) = serde_json::from_slice::<Value>(&body) else {
                return;
            };
            let at = |count: &str, max: &str| {
                let max = usage[max].as_u64().unwrap_or(0);
                max > 0 && usage[count].as_u64().unwrap_or(0) >= max
            };
            let mut reached = Vec::new();
            if at("members", "max_members") {
                reached.push("members".to_owned());
            }
            if at("relay_bytes", "max_relay_bytes") {
                reached.push("relay_bytes".to_owned());
            }
            reached
        }
        Ok((404, _)) => Vec::new(),
        _ => return,
    };
    store.update_limits(&network.id, |l| l.reached = reached);
}

/// A rejected join: a 429 is remembered as the network's limit.
fn join_refused(store: &Store, network: &str, status: u16, body: &[u8]) -> Error {
    match limit_refusal(status, body) {
        Some((limit, message)) => {
            store.update_limits(network, |l| l.refused = Some(limit.clone()));
            Error::Limit { limit, message }
        }
        None => coordinator_status(status, body),
    }
}

pub(crate) fn coordinator_error(status: u16, body: &[u8]) -> String {
    let message = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v["error"].as_str().map(str::to_owned))
        .unwrap_or_default();
    format!("coordinator returned HTTP {status}: {message}")
}
fn parse_map(body: &[u8]) -> Result<WireMap, Error> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| Error::Unavailable("malformed coordinator map".into()))?;
    if value.get("format").is_some() {
        let map = crate::link_runtime::map::Map::decode(body)
            .map_err(crate::link_runtime::support::model_error)?;
        let descriptor: crate::link_runtime::map::Descriptor = crate::linking::decode_mutation(
            map.network.get().as_bytes(),
            "network_id name genesis_root_public_key coordinator_address coordinator_public_key",
        )
        .map_err(crate::link_runtime::support::model_error)?;
        return Ok(WireMap {
            active_map: Some(body.to_vec()),
            network_id: descriptor.network_id,
            root_public_key: descriptor.genesis_root_public_key,
            members: Vec::new(),
            rotations: Vec::new(),
            attestations: Vec::new(),
            revocations: Vec::new(),
            persons: Vec::new(),
            admins: Vec::new(),
            groups: Vec::new(),
            policies: Vec::new(),
            successors: Value::Null,
            r#move: Value::Null,
        });
    }
    serde_json::from_slice(body).map_err(|_| Error::Unavailable("malformed coordinator map".into()))
}

/// This host's candidates for a network: its reflexive address as seen by
/// that network's coordinator, then its non-loopback interface addresses with
/// the bound peer port, at most `MAX_ENDPOINTS`. Empty unless listening.
async fn publish_candidates(store: &Arc<Store>, coordinator: &str) -> Vec<String> {
    let Some(bound) = store.peer_bound.read().ok().and_then(|b| *b) else {
        return Vec::new();
    };
    let mut out: Vec<std::net::SocketAddr> = Vec::new();
    if let Some(discovery) = crate::quic::discovery(store)
        && let Some(reflexive) = discovery
            .reflexive_within(
                coordinator,
                Duration::from_secs(store.coordination_interval.load(Ordering::Relaxed)),
            )
            .await
    {
        out.push(reflexive);
    }
    for ip in interface_ips(bound) {
        let candidate = std::net::SocketAddr::new(ip, bound.port());
        if !out.contains(&candidate) {
            out.push(candidate);
        }
    }
    out.truncate(crate::disco::MAX_ENDPOINTS);
    if let Ok(mut published) = store.candidates.write() {
        published.clone_from(&out);
    }
    out.iter().map(ToString::to_string).collect()
}
/// Addresses a socket bound to `bound` receives on, excluding loopback,
/// unspecified, multicast, and IPv6 link-local addresses.
fn interface_ips(bound: std::net::SocketAddr) -> Vec<std::net::IpAddr> {
    let usable = |ip: &std::net::IpAddr| {
        !ip.is_loopback()
            && !ip.is_unspecified()
            && !ip.is_multicast()
            && !matches!(ip, std::net::IpAddr::V6(v6) if v6.segments()[0] & 0xffc0 == 0xfe80)
    };
    if !bound.ip().is_unspecified() {
        return Some(bound.ip()).filter(usable).into_iter().collect();
    }
    interface_addresses()
        .into_iter()
        .filter(|ip| bound.is_ipv6() || ip.is_ipv4())
        .filter(usable)
        .collect()
}
fn interface_addresses() -> Vec<std::net::IpAddr> {
    let mut out = Vec::new();
    // SAFETY: getifaddrs allocates a list that is only read here and released
    // with freeifaddrs; each address is read according to its family.
    unsafe {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            return out;
        }
        let mut cursor = head;
        while !cursor.is_null() {
            let entry = &*cursor;
            if !entry.ifa_addr.is_null() {
                match i32::from((*entry.ifa_addr).sa_family) {
                    libc::AF_INET => {
                        let sin = &*(entry.ifa_addr as *const libc::sockaddr_in);
                        out.push(std::net::IpAddr::from(
                            u32::from_be(sin.sin_addr.s_addr).to_be_bytes(),
                        ));
                    }
                    libc::AF_INET6 => {
                        let sin6 = &*(entry.ifa_addr as *const libc::sockaddr_in6);
                        out.push(std::net::IpAddr::from(sin6.sin6_addr.s6_addr));
                    }
                    _ => {}
                }
            }
            cursor = entry.ifa_next;
        }
        libc::freeifaddrs(head);
    }
    out.sort();
    out.dedup();
    out
}

/// Registers an unregistered administered network, or syncs any other one.
/// A pending coordinator is synced first, and the pinned one only if that
/// fails. Failures are recorded on the network rather than returned.
/// Fresh current pinned map for a typed expansion; never follows a move mid-ceremony.
pub(crate) async fn sync_link_network(store: Arc<Store>, id: String) -> Result<Network, Error> {
    let restriction_failure =
        crate::link_runtime::restrictions::resume_for_sync(store.clone(), &id)
            .await
            .map_err(crate::link_runtime::support::model_error)?;
    let lookup = id.clone();
    let (network, registration, pending) = blocking(store.clone(), move |s| {
        let c = s.connection()?;
        let n = s.network_record(&c, &lookup)?;
        drop(c);
        let own = if n.administrator && n.last_sync_at.is_none() {
            s.own_membership(&lookup)?
        } else {
            None
        };
        let c = s.connection()?;
        let pending = if crate::link_runtime::catalog::feature(&c, &lookup)
            .map_err(crate::link_runtime::support::model_error)?
            .0
            != "-"
        {
            s.pending_rotation(&c, &lookup)?
        } else {
            None
        };
        Ok((n, own, pending))
    })
    .await?;
    if pending.is_some()
        && let Some(error) = restriction_failure
    {
        return Err(crate::link_runtime::support::model_error(
            crate::link_runtime::restrictions::rotation_refusal(error),
        ));
    }
    if let Some(pending) = pending
        && let Some(completed) =
            crate::link_runtime::rotation::complete_locked(store.clone(), network.clone(), pending)
                .await?
    {
        return Ok(completed);
    }
    let current = network;
    let network = blocking(store.clone(), move |s| {
        crate::link_runtime::map::refresh_transport(s, current)
    })
    .await?;
    let map = if let Some(raw) = crate::link_runtime::restrictions::repair_at(
        store.clone(),
        &id,
        &network.coordinator_address,
        &network.coordinator_public_key,
    )
    .await
    .map_err(crate::link_runtime::support::model_error)?
    {
        parse_map(&raw)?
    } else {
        fetch_map(
            &store,
            &network,
            &network.coordinator_address,
            &network.coordinator_public_key,
            registration,
        )
        .await
        .map_err(|(error, _)| error)?
    };
    blocking(store, move |s| s.apply_map_at(network, map, false, None)).await
}

pub async fn sync_network(store: Arc<Store>, id: String) -> Result<Network, Error> {
    let restriction_failure =
        crate::link_runtime::restrictions::resume_for_sync(store.clone(), &id)
            .await
            .map_err(crate::link_runtime::support::model_error)?;
    let lookup = id.clone();
    let (network, own) = blocking(store.clone(), move |s| {
        Ok((s.network(&lookup)?, s.own_membership(&lookup)?))
    })
    .await?;
    let (run, lookup) = (store.clone(), id.clone());
    let pending_rotation = blocking(run, move |s| {
        let c = s.connection()?;
        if crate::link_runtime::catalog::feature(&c, &lookup)
            .map_err(crate::link_runtime::support::model_error)?
            .0
            == "-"
        {
            return Ok(None);
        }
        s.pending_rotation(&c, &lookup)
    })
    .await?;
    if pending_rotation.is_some()
        && let Some(error) = restriction_failure
    {
        return Err(crate::link_runtime::support::model_error(
            crate::link_runtime::restrictions::rotation_refusal(error),
        ));
    }
    if let Some(pending) = pending_rotation
        && let Some(completed) =
            crate::link_runtime::rotation::complete(store.clone(), network.clone(), pending).await?
    {
        return Ok(completed);
    }
    let (run, current) = (store.clone(), network);
    let network = blocking(run, move |s| {
        crate::link_runtime::map::refresh_transport(s, current)
    })
    .await?;
    let registration = own.filter(|_| network.administrator && network.last_sync_at.is_none());
    let mut failed = None;
    if let Some(pending) = network.coordinator_pending.clone()
        && registration.is_none()
    {
        match switch_coordinator(&store, network.clone(), pending.clone()).await {
            Ok(network) => {
                crate::coordinator_move::synced(&store, &network.id);
                return Ok(network);
            }
            Err(Error::Internal(error)) => return Err(Error::Internal(error)),
            Err(error) => failed = Some((pending, error)),
        }
    }
    let outcome = sync_at(
        &store,
        &network,
        &network.coordinator_address,
        &network.coordinator_public_key,
        registration,
        None,
    )
    .await;
    match outcome {
        Ok(synced) => {
            crate::coordinator_move::synced(&store, &synced.network.id);
            match follow(
                &store,
                synced.network,
                &synced.moved,
                &synced.successors,
                failed,
            )
            .await?
            {
                Followed::Switched(network) => Ok(network),
                Followed::Stayed(network) => {
                    let repaired = if synced.active {
                        false
                    } else {
                        crate::coordinator_move::repair(
                            &store,
                            &network,
                            &synced.served,
                            synced.held,
                        )
                        .await
                    };
                    after_sync(store, network, synced.listed, synced.offered, repaired).await
                }
            }
        }
        Err(Error::Internal(error)) => Err(Error::Internal(error)),
        Err(error) => {
            let message = sync_message(error);
            let network =
                blocking(store.clone(), move |s| s.record_sync_error(&id, message)).await?;
            crate::coordinator_move::sync_failed(&store, network).await
        }
    }
}

/// The message of a map whose root chain is shorter than this host's.
const CHAIN_BEHIND: &str = "coordinator root chain is behind this host";

/// A map fetched and applied, with what the caller still follows.
struct Synced {
    network: Network,
    active: bool,
    successors: Value,
    moved: Value,
    served: crate::coordinator_move::MapSummary,
    held: Option<crate::coordinator_move::Held>,
    listed: BTreeSet<(String, String)>,
    offered: Vec<Rotation>,
}
/// Fetches the map from the coordinator at `address` with `key` and
/// applies it; `switch` makes that coordinator the pin in the same
/// transaction. What this host held before is kept for repair. A map whose
/// root chain is behind this host's imports the network there (at most once
/// per interval) and is fetched once more.
async fn sync_at(
    store: &Arc<Store>,
    network: &Network,
    address: &str,
    key: &str,
    registration: Option<Membership>,
    switch: Option<CoordinatorPending>,
) -> Result<Synced, Error> {
    let registering = registration.is_some();
    let mut map = if let Some(raw) =
        crate::link_runtime::restrictions::repair_at(store.clone(), &network.id, address, key)
            .await
            .map_err(crate::link_runtime::support::model_error)?
    {
        parse_map(&raw)?
    } else {
        coordinator_map(store, network, address, key, registration).await?
    };
    let mut retried = registering;
    loop {
        let active = map.active_map.is_some();
        let mut successors = std::mem::take(&mut map.successors);
        let mut moved = std::mem::take(&mut map.r#move);
        let served = crate::coordinator_move::MapSummary::of(&map);
        let listed = listed_revocations(&map);
        let offered = offered_rotations(&map);
        let lookup = network.id.clone();
        let held = blocking(store.clone(), move |s| s.held_snapshot(&lookup))
            .await
            .ok();
        let (applied, pending) = (network.clone(), switch.clone());
        match blocking(store.clone(), move |s| {
            s.apply_map_at(applied, map, false, pending)
        })
        .await
        {
            Ok(network) => {
                if active {
                    let (run, current) = (store.clone(), network.clone());
                    (moved, successors) = tokio::task::spawn_blocking(move || {
                        crate::link_runtime::map::transport_evidence(&run, &current)
                    })
                    .await
                    .map_err(|e| Error::Internal(e.into()))?
                    .map_err(crate::link_runtime::support::model_error)?;
                }
                return Ok(Synced {
                    network,
                    active,
                    successors,
                    moved,
                    served,
                    held,
                    listed,
                    offered,
                });
            }
            Err(Error::Unavailable(message))
                if message == CHAIN_BEHIND
                    && !retried
                    && crate::coordinator_move::import_unknown(store, network, address, key)
                        .await =>
            {
                retried = true;
                map = fetch_map(store, network, address, key, None)
                    .await
                    .map_err(|(error, _)| error)?;
            }
            Err(error) => return Err(error),
        }
    }
}

fn sync_message(error: Error) -> String {
    match error {
        Error::Unavailable(message) => message,
        other => other.to_string(),
    }
}

fn offered_rotations(map: &WireMap) -> Vec<Rotation> {
    map.rotations
        .iter()
        .filter_map(|r| serde_json::from_value::<Rotation>(r.clone()).ok())
        .collect()
}

/// One register or sync request to the coordinator at `address` with `key`,
/// and the map it returns. A sync refused with 403 or 404, because the
/// coordinator lacks this host or the network, imports the network there
/// (at most once per interval) and syncs once more.
async fn coordinator_map(
    store: &Arc<Store>,
    network: &Network,
    address: &str,
    key: &str,
    registration: Option<Membership>,
) -> Result<WireMap, Error> {
    let registering = registration.is_some();
    match fetch_map(store, network, address, key, registration).await {
        Ok(map) => Ok(map),
        Err((error, Some(403 | 404)))
            if !registering
                && crate::coordinator_move::import_unknown(store, network, address, key).await =>
        {
            let _ = error;
            fetch_map(store, network, address, key, None)
                .await
                .map_err(|(error, _)| error)
        }
        Err((error, _)) => Err(error),
    }
}

/// One register or sync request; a refusal carries its status.
async fn fetch_map(
    store: &Arc<Store>,
    network: &Network,
    address: &str,
    key: &str,
    registration: Option<Membership>,
) -> Result<WireMap, (Error, Option<u16>)> {
    let advertised = store.advertised();
    let candidates = publish_candidates(store, address).await;
    let (path, body, accepted): (_, _, &[u16]) = if let Some(own) = registration {
        (
            "/coord/v2/networks".to_owned(),
            json_value!({"name": network.name, "root_public_key": network.root_public_key, "membership": own, "address": advertised, "candidates": candidates, "linking_version":1}),
            &[200, 201],
        )
    } else {
        (
            format!("/coord/v2/networks/{}/sync", network.id),
            json_value!({"address": advertised, "candidates": candidates, "linking_version":1}),
            &[200],
        )
    };
    match coordinator(store.clone(), address, key, path, body).await {
        Ok((status, body)) if accepted.contains(&status) => parse_map(&body).map_err(|e| (e, None)),
        Ok((status, body)) => match limit_refusal(status, &body) {
            Some((limit, message)) => {
                store.update_limits(&network.id, |l| l.refused = Some(limit));
                Err((Error::Unavailable(message), Some(status)))
            }
            None => Err((
                Error::Unavailable(coordinator_error(status, &body)),
                Some(status),
            )),
        },
        Err(error) => Err((Error::Unavailable(format!("{error:#}")), None)),
    }
}

/// After a successful sync: refreshes usage, resubmits revocations the map
/// does not list yet, and settles a pending rotation.
async fn after_sync(
    store: Arc<Store>,
    network: Network,
    listed: BTreeSet<(String, String)>,
    offered: Vec<Rotation>,
    repaired: bool,
) -> Result<Network, Error> {
    refresh_usage(&store, &network).await;
    // Revocations this host made stay pending until the coordinator
    // lists them; they are resubmitted on every successful sync, unless a
    // repair import just carried them.
    let lookup = network.id.clone();
    let pending = if repaired {
        Vec::new()
    } else {
        blocking(store.clone(), move |s| {
            s.pending_revocations(&lookup, &listed)
        })
        .await
        .unwrap_or_default()
    };
    for body in pending {
        let _ = submit_revocation(store.clone(), &network, body).await;
    }
    // A rotation left pending, for example by a crash after the
    // coordinator accepted it, is completed or resubmitted here.
    let network = settle_rotation(store.clone(), network, offered).await?;
    let _ = crate::link_runtime::feature::resume(store, &network).await;
    Ok(network)
}

/// Syncs a network at its pending coordinator. On success the pending
/// coordinator replaces the pin, and the relay connection and STUN move to
/// it; on failure nothing is recorded and the error is returned.
pub(crate) async fn switch_coordinator(
    store: &Arc<Store>,
    network: Network,
    pending: CoordinatorPending,
) -> Result<Network, Error> {
    let synced = sync_at(
        store,
        &network,
        &pending.address,
        &pending.public_key,
        None,
        Some(pending.clone()),
    )
    .await?;
    let mut network = synced.network;
    store.relay_wake.notify_one();
    // A move or a chain served by the new coordinator is recorded and
    // followed on the next sync, so one sync never follows coordinators in
    // a loop.
    if !synced.moved.is_null() {
        let (id, moved) = (network.id.clone(), synced.moved);
        if let Ok((n, _)) = blocking(store.clone(), move |s| s.accept_move(&id, &moved)).await {
            network = n;
        }
    }
    let network = match successors_outcome(&network, &synced.successors) {
        Chain::None => network,
        Chain::Invalid => invalid_successor(store, network.id).await?,
        Chain::Valid(next) => {
            let id = network.id;
            blocking(store.clone(), move |s| s.set_coordinator_pending(&id, next)).await?
        }
    };
    let repaired = if synced.active {
        false
    } else {
        crate::coordinator_move::repair(store, &network, &synced.served, synced.held).await
    };
    after_sync(
        store.clone(),
        network,
        synced.listed,
        synced.offered,
        repaired,
    )
    .await
}

enum Chain {
    None,
    Invalid,
    Valid(CoordinatorPending),
}
/// A response's `successors`, verified from the pinned coordinator key.
fn successors_outcome(network: &Network, successors: &Value) -> Chain {
    match successors {
        Value::Null => Chain::None,
        Value::Array(chain) if chain.is_empty() => Chain::None,
        Value::Array(chain) => {
            match membership::verify_successors(&network.coordinator_public_key, chain) {
                Ok(last) => Chain::Valid(last),
                Err(_) => Chain::Invalid,
            }
        }
        _ => Chain::Invalid,
    }
}
async fn invalid_successor(store: &Arc<Store>, id: String) -> Result<Network, Error> {
    blocking(store.clone(), move |s| {
        s.record_sync_error(&id, "invalid coordinator successor".into())
    })
    .await
}

/// The sync error for a pending coordinator that could not be synced.
pub(crate) fn pending_error(pending: &CoordinatorPending, error: Error) -> String {
    let kind = if pending.is_move() {
        "move"
    } else {
        "successor"
    };
    format!(
        "coordinator {kind} {}: {}",
        pending.address,
        sync_message(error)
    )
}

enum Followed {
    /// The network now pins the pending coordinator, whose sync completed.
    Switched(Network),
    Stayed(Network),
}
/// After a register, join, or sync response's map is applied: a valid move
/// newer than the applied one becomes pending and is synced at once, and
/// takes precedence over successors; otherwise successors are followed.
async fn follow(
    store: &Arc<Store>,
    network: Network,
    moved: &Value,
    successors: &Value,
    failed: Option<(CoordinatorPending, Error)>,
) -> Result<Followed, Error> {
    let mut network = network;
    if !moved.is_null() {
        let (id, value) = (network.id.clone(), moved.clone());
        if let Ok((n, pending)) = blocking(store.clone(), move |s| s.accept_move(&id, &value)).await
        {
            network = n;
            if let Some(pending) = pending {
                return match switch_coordinator(store, network.clone(), pending.clone()).await {
                    Ok(network) => Ok(Followed::Switched(network)),
                    Err(Error::Internal(error)) => Err(Error::Internal(error)),
                    Err(error) => {
                        let message = pending_error(&pending, error);
                        let id = network.id;
                        Ok(Followed::Stayed(
                            blocking(store.clone(), move |s| s.record_sync_error(&id, message))
                                .await?,
                        ))
                    }
                };
            }
        }
    }
    follow_successors(store, network, successors, failed).await
}

/// Records a valid chain's last entry as pending and syncs it, or records
/// an invalid chain as the sync error. `failed` is a pending coordinator
/// this sync already tried, which is not tried again. While a move is
/// pending, successors are not followed.
async fn follow_successors(
    store: &Arc<Store>,
    network: Network,
    successors: &Value,
    failed: Option<(CoordinatorPending, Error)>,
) -> Result<Followed, Error> {
    let id = network.id.clone();
    let record = |message: String| {
        let id = id.clone();
        async move { blocking(store.clone(), move |s| s.record_sync_error(&id, message)).await }
    };
    let moving = network
        .coordinator_pending
        .as_ref()
        .is_some_and(CoordinatorPending::is_move);
    let outcome = if moving {
        Chain::None
    } else {
        successors_outcome(&network, successors)
    };
    match outcome {
        Chain::None => match failed {
            Some((pending, error)) => Ok(Followed::Stayed(
                record(pending_error(&pending, error)).await?,
            )),
            None => Ok(Followed::Stayed(network)),
        },
        Chain::Invalid => Ok(Followed::Stayed(invalid_successor(store, id).await?)),
        Chain::Valid(pending) => {
            let lookup = id.clone();
            let next = pending.clone();
            let network = blocking(store.clone(), move |s| {
                s.set_coordinator_pending(&lookup, next)
            })
            .await?;
            if let Some((tried, error)) = failed
                && tried == pending
            {
                return Ok(Followed::Stayed(
                    record(pending_error(&pending, error)).await?,
                ));
            }
            match switch_coordinator(store, network, pending.clone()).await {
                Ok(network) => Ok(Followed::Switched(network)),
                Err(Error::Internal(error)) => Err(Error::Internal(error)),
                Err(error) => Ok(Followed::Stayed(
                    record(pending_error(&pending, error)).await?,
                )),
            }
        }
    }
}

/// The stored `(kind, subject)` of every revocation a map lists that this
/// host would otherwise resubmit.
fn listed_revocations(map: &WireMap) -> BTreeSet<(String, String)> {
    map.revocations
        .iter()
        .filter_map(|entry| {
            let statement = &entry["statement"];
            let (kind, subject) = match entry["kind"].as_str()? {
                "host" => ("host", statement["host_public_key"].as_str()?.to_owned()),
                "invite" => (
                    "invite",
                    statement["invite_public_key"].as_str()?.to_owned(),
                ),
                "person" => (
                    "person_removal",
                    statement["person_public_key"].as_str()?.to_owned(),
                ),
                "admin" => (
                    "admin_removal",
                    statement["person_public_key"].as_str()?.to_owned(),
                ),
                "unbind" => (
                    "unbind",
                    format!(
                        "{} {}",
                        statement["person_public_key"].as_str()?,
                        statement["host_public_key"].as_str()?
                    ),
                ),
                _ => return None,
            };
            Some((kind.to_owned(), subject))
        })
        .collect()
}

/// Submits one `{kind, statement}` revocation; true once the coordinator accepts.
async fn submit_revocation(
    store: Arc<Store>,
    network: &Network,
    body: Value,
) -> Result<bool, Error> {
    let kind = match body["kind"].as_str() {
        Some("host") => Some("host_revocation"),
        Some("invite") => Some("invite_revocation"),
        Some("person") => Some("person_removal"),
        Some("binding") => Some("host_unbinding"),
        Some("admin") => Some("admin_removal"),
        _ => None,
    };
    if let Some(kind) = kind
        && let Some(result) = crate::link_runtime::legacy::submit(
            store.clone(),
            network,
            kind,
            body["statement"].clone(),
            true,
        )
        .await?
    {
        return Ok(result.submitted);
    }
    Ok(matches!(
        coordinator(
            store,
            &network.coordinator_address,
            &network.coordinator_public_key,
            format!("/coord/v1/networks/{}/revocations", network.id),
            body
        )
        .await,
        Ok((200, _))
    ))
}

/// Maps a coordinator rejection to the matching local status.
fn coordinator_status(status: u16, body: &[u8]) -> Error {
    let message = coordinator_error(status, body);
    match status {
        400 => Error::Invalid(message),
        403 => Error::Forbidden,
        404 => Error::NotFound,
        409 => Error::Conflict(message),
        426 => {
            let mut failure =
                crate::link_runtime::support::Failure::new("upgrade_required", "-", "feature");
            failure.details.next=vec!["Request a fresh feature-bound invitation for this network.".into(),"Ask the current root owner to review and approve exact feature recovery when needed.".into()];
            crate::link_runtime::support::model_error(failure.into())
        }
        _ => Error::Unavailable(message),
    }
}

/// Revokes a host or invite: enforced locally first, then submitted now and on
/// every later sync until the coordinator lists it.
pub async fn revoke(store: Arc<Store>, id: String, request: Revoke) -> Result<Revoked, Error> {
    let lookup = id.clone();
    let (mut revoked, body) = blocking(store.clone(), move |s| s.revoke(&lookup, request)).await?;
    let network = blocking(store.clone(), move |s| s.network(&id)).await?;
    revoked.submitted = submit_revocation(store, &network, body).await?;
    Ok(revoked)
}

/// Signs a leave statement, tries the coordinator once, then forgets the
/// network locally whether or not the coordinator accepted.
pub async fn leave(store: Arc<Store>, id: String) -> Result<Left, Error> {
    let lookup = id.clone();
    let network = blocking(store.clone(), move |s| s.network(&lookup)).await?;
    if network.administrator {
        return Err(Error::Conflict(
            "the administrator cannot leave its own network".into(),
        ));
    }
    let statement = Leave::sign(&store.signing_key, &network.id, &now());
    if let Some(result) = crate::link_runtime::legacy::submit(
        store.clone(),
        &network,
        "host_leave",
        serde_json::to_value(&statement)?,
        true,
    )
    .await?
    {
        blocking(store, move |s| s.forget_network(&id)).await?;
        return Ok(Left {
            network_id: network.id,
            submitted: result.submitted,
        });
    }
    let submitted = matches!(
        coordinator(
            store.clone(),
            &network.coordinator_address,
            &network.coordinator_public_key,
            format!("/coord/v1/networks/{}/leave", network.id),
            json_value!({"statement": statement}),
        )
        .await,
        Ok((200, _))
    );
    blocking(store, move |s| s.forget_network(&id)).await?;
    Ok(Left {
        network_id: network.id,
        submitted,
    })
}

/// What submitting a pending rotation achieved.
enum Submitted {
    /// Accepted; carries the coordinator's map.
    Accepted(Box<WireMap>),
    /// Will never be accepted: the coordinator holds a different rotation at
    /// that epoch (409) or rejects the rotation as invalid (400).
    Rejected(Error),
    /// Not settled (403, 5xx, unreachable); the rotation stays pending.
    Unsettled(Error),
}
/// How a coordinator status settles a pending rotation submission.
#[derive(Debug, PartialEq, Eq)]
enum RotationResponse {
    Accept,
    Discard,
    Keep,
}
fn rotation_response(status: u16) -> RotationResponse {
    match status {
        200 => RotationResponse::Accept,
        400 | 409 => RotationResponse::Discard,
        _ => RotationResponse::Keep,
    }
}
async fn submit_rotation(
    store: Arc<Store>,
    network: &Network,
    pending: &PendingRotation,
) -> Submitted {
    let response = coordinator(
        store,
        &network.coordinator_address,
        &network.coordinator_public_key,
        format!("/coord/v1/networks/{}/rotations", network.id),
        json_value!({"rotation": pending.rotation, "attestations": pending.attestations, "admissions": pending.admissions, "groups": pending.groups}),
    )
    .await;
    match response {
        Ok((status, body)) => match rotation_response(status) {
            RotationResponse::Accept => match parse_map(&body) {
                Ok(map) => Submitted::Accepted(Box::new(map)),
                Err(error) => Submitted::Unsettled(error),
            },
            RotationResponse::Discard => Submitted::Rejected(coordinator_status(status, &body)),
            RotationResponse::Keep => Submitted::Unsettled(coordinator_status(status, &body)),
        },
        Err(error) => Submitted::Unsettled(Error::Unavailable(format!("{error:#}"))),
    }
}

/// Commits an accepted rotation and applies the coordinator's map.
async fn accept_rotation(
    store: Arc<Store>,
    id: String,
    pending: PendingRotation,
    map: WireMap,
) -> Result<Network, Error> {
    let commit = id.clone();
    blocking(store.clone(), move |s| s.commit_rotation(&commit, &pending)).await?;
    let network = blocking(store.clone(), move |s| s.network(&id)).await?;
    match blocking(store, {
        let network = network.clone();
        move |s| s.apply_map(network, map, false)
    })
    .await
    {
        Ok(network) => Ok(network),
        Err(Error::Internal(error)) => Err(Error::Internal(error)),
        Err(_) => Ok(network),
    }
}

/// Rotates the root. The signed rotation, its attestations, and the new seed
/// are persisted as pending before submission, with the old root still
/// current; they become current only once the coordinator accepts. A pending
/// rotation is resubmitted by a repeated command and on every sync.
pub async fn rotate(
    store: Arc<Store>,
    id: String,
    ssh: Option<RotateToSsh>,
) -> Result<Network, Error> {
    let lookup = id.clone();
    let (network, pending) =
        blocking(store.clone(), move |s| s.prepare_rotation(&lookup, ssh)).await?;
    if let Some(completed) =
        crate::link_runtime::rotation::complete(store.clone(), network.clone(), pending.clone())
            .await?
    {
        return Ok(completed);
    }
    match submit_rotation(store.clone(), &network, &pending).await {
        Submitted::Accepted(map) => accept_rotation(store, id, pending, *map).await,
        Submitted::Rejected(error) => {
            let reason = error.to_string();
            blocking(store, move |s| s.discard_rotation_with_error(&id, &reason)).await?;
            Err(error)
        }
        Submitted::Unsettled(error) => Err(error),
    }
}

/// Settles a pending rotation after a successful sync against `offered`, the
/// chain the coordinator served.
async fn settle_rotation(
    store: Arc<Store>,
    network: Network,
    offered: Vec<Rotation>,
) -> Result<Network, Error> {
    let id = network.id.clone();
    let lookup = id.clone();
    let outcome = blocking(store.clone(), move |s| {
        s.resolve_rotation(&lookup, &offered)
    })
    .await?;
    match outcome {
        PendingOutcome::None => Ok(network),
        PendingOutcome::Committed => blocking(store, move |s| s.network(&id)).await,
        PendingOutcome::Discarded => {
            blocking(store, move |s| {
                s.record_sync_error(
                    &id,
                    "root rotation discarded: the chain holds a different rotation at that epoch"
                        .into(),
                )
            })
            .await
        }
        PendingOutcome::Resubmit(pending) => {
            match submit_rotation(store.clone(), &network, &pending).await {
                Submitted::Accepted(map) => accept_rotation(store, id, *pending, *map).await,
                Submitted::Rejected(error) => {
                    let reason = error.to_string();
                    blocking(store, move |s| s.discard_rotation_with_error(&id, &reason)).await
                }
                Submitted::Unsettled(_) => Ok(network),
            }
        }
    }
}

/// Joins only after the coordinator accepts and its map verifies; nothing is
/// persisted otherwise.
pub async fn join(store: Arc<Store>, token: String) -> Result<Network, Error> {
    join_token(store, InviteToken::decode(&token)?).await
}
/// Joins with a decoded host invite (or a member invite's host part).
async fn join_token(store: Arc<Store>, token: InviteToken) -> Result<Network, Error> {
    let id = token.network_id.clone();
    let exists = blocking(store.clone(), move |s| match s.network(&id) {
        Ok(_) => Ok(true),
        Err(Error::NotFound) => Ok(false),
        Err(e) => Err(e),
    })
    .await?;
    if exists {
        return Err(Error::Conflict("network already joined".into()));
    }
    let invite = membership::seed(&token.invite_seed)?;
    let own = membership::sign_member(
        token.invite(),
        &invite,
        store.signing_key.verifying_key().as_bytes(),
        &now(),
    );
    let candidates = publish_candidates(&store, &token.coordinator_address).await;
    let response = coordinator(
        store.clone(),
        &token.coordinator_address,
        &token.coordinator_public_key,
        format!("/coord/v1/networks/{}/members", token.network_id),
        json_value!({"membership": own, "address": store.advertised(), "candidates": candidates}),
    )
    .await
    .map_err(|e| Error::Unavailable(format!("{e:#}")))?;
    let map = match response {
        (200 | 201, body) => parse_map(&body)?,
        (status, body) => return Err(join_refused(&store, &token.network_id, status, &body)),
    };
    // The token carries the root that signed the invite, which is the current
    // root after a rotation. The map's genesis root must derive the network ID,
    // and this host's membership must verify under the map's verified chain,
    // so a coordinator cannot substitute another network.
    let network = Network {
        id: token.network_id,
        name: token.network_name,
        root_public_key: map.root_public_key.clone(),
        member: token.member,
        coordinator_address: token.coordinator_address,
        coordinator_public_key: token.coordinator_public_key,
        administrator: false,
        last_sync_at: None,
        last_sync_error: None,
        root_epoch: 0,
        current_root_public_key: String::new(),
        root_ssh: false,
        coordinator_pending: None,
    };
    joined(store, network, map).await
}

/// Applies a join response's map, then follows its successors as a sync
/// would; the joined network is kept whatever happens to them.
async fn joined(store: Arc<Store>, network: Network, mut map: WireMap) -> Result<Network, Error> {
    let successors = std::mem::take(&mut map.successors);
    let moved = std::mem::take(&mut map.r#move);
    let network = blocking(store.clone(), move |s| s.apply_map(network, map, true)).await?;
    match follow(&store, network, &moved, &successors, None).await? {
        Followed::Switched(network) | Followed::Stayed(network) => Ok(network),
    }
}

/// The non-secret descriptor that lets a key an administrator admitted find
/// and pin this network.
fn descriptor(network: &Network) -> String {
    Descriptor {
        network_id: network.id.clone(),
        network_name: network.name.clone(),
        root_public_key: network.root_public_key.clone(),
        coordinator_address: network.coordinator_address.clone(),
        coordinator_public_key: network.coordinator_public_key.clone(),
    }
    .encode()
}

/// Submits a statement to a coordinator endpoint and applies the map it
/// returns; a rejection maps to the matching local status.
async fn submit_statement(
    store: Arc<Store>,
    network: &Network,
    endpoint: &str,
    body: Value,
) -> Result<Network, Error> {
    let candidate = match (endpoint, body.as_object()) {
        ("persons", Some(o)) if o.contains_key("admission") => {
            Some(("person_admission", o["admission"].clone()))
        }
        ("persons", Some(o)) if o.contains_key("membership") => {
            Some(("person_membership", o["membership"].clone()))
        }
        ("hosts", Some(o)) => o.get("admission").map(|p| ("host_admission", p.clone())),
        ("admins", Some(o)) => o.get("delegation").map(|p| ("admin_delegation", p.clone())),
        ("groups", Some(o)) => o.get("group").map(|p| ("group", p.clone())),
        ("bindings", Some(o)) => o.get("binding").map(|p| ("host_binding", p.clone())),
        _ => None,
    };
    if let Some((kind, record)) = candidate
        && let Some(result) =
            crate::link_runtime::legacy::submit(store.clone(), network, kind, record, false).await?
    {
        return Ok(result.network);
    }
    let response = coordinator(
        store.clone(),
        &network.coordinator_address,
        &network.coordinator_public_key,
        format!("/coord/v1/networks/{}/{endpoint}", network.id),
        body,
    )
    .await
    .map_err(|e| Error::Unavailable(format!("{e:#}")))?;
    let map = match response {
        (200 | 201, body) => parse_map(&body)?,
        (status, body) => return Err(coordinator_status(status, &body)),
    };
    let network = network.clone();
    blocking(store, move |s| s.apply_map(network, map, false)).await
}

/// Admits a person by public key (administrator only).
pub async fn admit_person(
    store: Arc<Store>,
    id: String,
    request: AdmitPerson,
) -> Result<AdmittedPerson, Error> {
    let (network, admission) = blocking(store.clone(), move |s| {
        s.sign_person_admission(&id, request)
    })
    .await?;
    let person_id = persons::person_id_of(&admission.person_public_key)?;
    let network = submit_statement(
        store,
        &network,
        "persons",
        json_value!({"admission": admission}),
    )
    .await?;
    Ok(AdmittedPerson {
        person_id,
        descriptor: descriptor(&network),
    })
}
/// Delegates administrator rights to a current person (root only).
pub async fn delegate_admin(
    store: Arc<Store>,
    id: String,
    request: DelegateAdmin,
) -> Result<Delegated, Error> {
    let (network, delegation) =
        blocking(store.clone(), move |s| s.sign_delegation(&id, request)).await?;
    let person_id = persons::person_id_of(&delegation.person_public_key)?;
    let network = submit_statement(
        store,
        &network,
        "admins",
        json_value!({"delegation": delegation}),
    )
    .await?;
    Ok(Delegated {
        network_id: network.id,
        person_id,
    })
}
/// Removes an administrator (root only): persisted and enforced locally
/// first, then submitted; a later sync resubmits it if needed.
pub async fn remove_admin(
    store: Arc<Store>,
    id: String,
    request: RemoveAdmin,
) -> Result<Revoked, Error> {
    if request.removal.is_none()
        && let Some(result) = crate::link_runtime::withdrawal::submit(
            store.clone(),
            id.clone(),
            request.person.clone(),
            request.revoke_admitted,
            None,
        )
        .await?
    {
        return Ok(result);
    }
    let lookup = id.clone();
    let (mut revoked, body) =
        blocking(store.clone(), move |s| s.remove_admin(&lookup, request)).await?;
    let network = blocking(store.clone(), {
        let id = id.clone();
        move |s| s.network(&id)
    })
    .await?;
    revoked.submitted = submit_revocation(store.clone(), &network, body).await?;
    if revoked.submitted {
        // Apply the cascade (dropped members, reverted groups) at once.
        let _ = sync_network(store, id).await;
    }
    Ok(revoked)
}
/// Defines the next version of a group (the root or an administrator).
pub async fn set_group(
    store: Arc<Store>,
    id: String,
    request: SetGroup,
) -> Result<GroupView, Error> {
    let (network, group) = blocking(store.clone(), move |s| s.sign_group(&id, request)).await?;
    let network =
        submit_statement(store, &network, "groups", json_value!({"group": group})).await?;
    Ok(GroupView::of(&group, &network.current_root_public_key))
}
/// Applies a map the coordinator returned with an accepted statement; a
/// malformed one is ignored.
pub(crate) async fn apply_returned_map(
    store: Arc<Store>,
    network: Network,
    body: &[u8],
) -> Result<(), Error> {
    if let Ok(map) = parse_map(body) {
        blocking(store, move |s| s.apply_map(network, map, false)).await?;
    }
    Ok(())
}
/// Admits a host by public key (administrator only); it joins with the
/// returned descriptor.
pub async fn admit_host(
    store: Arc<Store>,
    id: String,
    request: AdmitHost,
) -> Result<AdmittedHost, Error> {
    let (network, admission) =
        blocking(store.clone(), move |s| s.sign_host_admission(&id, request)).await?;
    let host_id = key_id(&membership::canonical(&admission.host_public_key, 32)?);
    let network = submit_statement(
        store.clone(),
        &network,
        "hosts",
        json_value!({"admission": admission}),
    )
    .await?;
    let id = network.id.clone();
    blocking(store, move |s| s.record_issued_admission(&id, &admission)).await?;
    Ok(AdmittedHost {
        host_id,
        descriptor: descriptor(&network),
    })
}
/// Redeems a person invite on a member host: the invite seed signs the
/// person's key, and the coordinator admits it.
pub async fn redeem_person(
    store: Arc<Store>,
    request: RedeemPerson,
) -> Result<RedeemedPerson, Error> {
    if request
        .token
        .trim()
        .starts_with(crate::link_runtime::invite::PREFIX)
    {
        crate::link_runtime::redemption::redeem(
            store,
            request.token,
            Some(request.person_public_key.clone()),
            true,
        )
        .await?;
        return Ok(RedeemedPerson {
            person_id: persons::person_id_of(&persons::normalize_person_key(
                &request.person_public_key,
            )?)?,
        });
    }
    let token = persons::decode_person_invite(&request.token)?;
    let key = persons::normalize_person_key(&request.person_public_key)?;
    let id = token.network_id.clone();
    let network = blocking(store.clone(), move |s| s.network(&id)).await?;
    let membership = token.redeem(&key, &now())?;
    submit_statement(
        store,
        &network,
        "persons",
        json_value!({"membership": membership}),
    )
    .await?;
    Ok(RedeemedPerson {
        person_id: persons::person_id_of(&key)?,
    })
}
/// Submits a person's binding of this host; the host's own submission is its
/// consent.
pub async fn bind(store: Arc<Store>, id: String, request: Bind) -> Result<Bound, Error> {
    let lookup = id.clone();
    let network = blocking(store.clone(), move |s| s.network(&lookup)).await?;
    // The CLI supplies the person's signature; this daemon adds its own
    // consent, and only for its own key.
    let mut binding = request.binding;
    binding.verify_person(&network.id)?;
    binding.sign_host(&store.signing_key)?;
    binding.verify(&network.id)?;
    let person_id = persons::person_id_of(&binding.person_public_key)?;
    submit_statement(
        store.clone(),
        &network,
        "bindings",
        json_value!({"binding": binding.clone()}),
    )
    .await?;
    // Accepted: record it now, so success means this host has the binding
    // whatever a later sync brings. The map just applied may already hold it.
    let lookup = network.id.clone();
    blocking(store.clone(), move |s| {
        s.record_own_binding(&lookup, &binding)
    })
    .await?;
    Ok(Bound {
        network_id: network.id,
        host_id: store.identity().id,
        person_id,
    })
}
/// Records a person's unbinding of a host locally, then submits it now and
/// on every later sync until the coordinator lists it.
pub async fn unbind(store: Arc<Store>, id: String, request: Unbind) -> Result<Revoked, Error> {
    let lookup = id.clone();
    let (mut revoked, body) = blocking(store.clone(), move |s| {
        s.record_unbinding(&lookup, request.unbinding)
    })
    .await?;
    let network = blocking(store.clone(), move |s| s.network(&id)).await?;
    revoked.submitted = submit_revocation(store, &network, body).await?;
    Ok(revoked)
}
/// Removes a person (administrator only): enforced locally first, then
/// submitted until the coordinator lists it.
pub async fn remove_person(
    store: Arc<Store>,
    id: String,
    request: RemovePerson,
) -> Result<Revoked, Error> {
    let lookup = id.clone();
    let (mut revoked, body) =
        blocking(store.clone(), move |s| s.remove_person(&lookup, request)).await?;
    let network = blocking(store.clone(), move |s| s.network(&id)).await?;
    revoked.submitted = submit_revocation(store, &network, body).await?;
    Ok(revoked)
}
/// Joins with an administrator's admission of this host's key. The
/// coordinator holds the admission; this host proves its key over TLS.
pub async fn join_with_descriptor(store: Arc<Store>, text: String) -> Result<Network, Error> {
    let d = Descriptor::decode(&text)?;
    let id = d.network_id.clone();
    let exists = blocking(store.clone(), move |s| match s.network(&id) {
        Ok(_) => Ok(true),
        Err(Error::NotFound) => Ok(false),
        Err(e) => Err(e),
    })
    .await?;
    if exists {
        return Err(Error::Conflict("network already joined".into()));
    }
    let candidates = publish_candidates(&store, &d.coordinator_address).await;
    let response = coordinator(
        store.clone(),
        &d.coordinator_address,
        &d.coordinator_public_key,
        format!("/coord/v1/networks/{}/members", d.network_id),
        json_value!({"address": store.advertised(), "candidates": candidates}),
    )
    .await
    .map_err(|e| Error::Unavailable(format!("{e:#}")))?;
    let map = match response {
        (200 | 201, body) => parse_map(&body)?,
        (status, body) => return Err(join_refused(&store, &d.network_id, status, &body)),
    };
    let own = store.identity().id;
    let member = map
        .members
        .iter()
        .find(|m| m["host_id"].as_str() == Some(own.as_str()))
        .and_then(|m| {
            m["admission"]["member"]
                .as_str()
                .or(m["membership"]["member"].as_str())
        })
        .unwrap_or_default()
        .to_owned();
    let network = Network {
        id: d.network_id,
        name: d.network_name,
        root_public_key: d.root_public_key,
        member,
        coordinator_address: d.coordinator_address,
        coordinator_public_key: d.coordinator_public_key,
        administrator: false,
        last_sync_at: None,
        last_sync_error: None,
        root_epoch: 0,
        current_root_public_key: String::new(),
        root_ssh: false,
        coordinator_pending: None,
    };
    joined(store, network, map).await
}

/// The follow-up command that finishes a skipped person step, for display.
fn bind_command(network: &str) -> String {
    format!("peerspan-host network bind --network {network}")
}
fn admit_command(network: &str, person: &str, member: &str) -> String {
    let line = persons::parse_ssh_public_line(person)
        .map(|k| persons::ssh_public_line(&k))
        .or_else(|_| {
            membership::canonical(person, 32).map(|k| {
                let mut key = [0u8; 32];
                key.copy_from_slice(&k);
                persons::ssh_public_line(&key)
            })
        })
        .unwrap_or_else(|_| person.to_owned());
    format!(
        "an administrator runs: peerspan-host network admit --network {network} --person '{line}' --member {member}; then: {}",
        bind_command(network)
    )
}

/// The person step of `network join`: admit the person if needed (from a
/// member invite's person part), then bind this host. Failures are reported,
/// never returned, so they cannot undo the host join that preceded them.
pub(crate) async fn person_step(
    store: Arc<Store>,
    network: &Network,
    member_token: Option<(&str, &MemberInviteToken)>,
    person_public_key: &str,
    binding: Option<HostBinding>,
) -> PersonOutcome {
    let mut outcome = PersonOutcome::default();
    let key = match persons::normalize_person_key(person_public_key) {
        Ok(key) => key,
        Err(e) => {
            outcome.skipped = Some(format!("invalid person key: {e}"));
            return outcome;
        }
    };
    outcome.person_id = persons::person_id_of(&key).ok();
    let id = network.id.clone();
    let lookup = key.clone();
    let admitted = blocking(store.clone(), move |s| {
        Ok(s.persons(&id)?.iter().any(|p| p.public_key == lookup))
    })
    .await
    .unwrap_or(false);
    if admitted {
        outcome.admitted = true;
    } else if let Some((text, token)) = member_token {
        let result = match token.person().redeem(&key, &now()) {
            Ok(membership) => {
                submit_statement(
                    store.clone(),
                    network,
                    "persons",
                    json_value!({"membership": membership}),
                )
                .await
            }
            Err(e) => Err(e),
        };
        match result {
            Ok(_) => outcome.admitted = true,
            Err(e) => {
                outcome.next = Some(match e {
                    Error::Conflict(_) => admit_command(&network.id, &key, "OTHER_LABEL"),
                    _ => format!(
                        "peerspan-host network redeem-person --token {text}; then: {}",
                        bind_command(&network.id)
                    ),
                });
                outcome.skipped = Some(format!("person admission failed: {e}"));
                return outcome;
            }
        }
    } else {
        outcome.skipped = Some("this person is not admitted in the network".into());
        outcome.next = Some(admit_command(&network.id, &key, "LABEL"));
        return outcome;
    }
    let Some(binding) = binding else {
        outcome.skipped = Some("no binding was supplied".into());
        outcome.next = Some(bind_command(&network.id));
        return outcome;
    };
    if binding.person_public_key != key {
        outcome.skipped = Some("the binding names a different person".into());
        outcome.next = Some(bind_command(&network.id));
        return outcome;
    }
    match bind(store, network.id.clone(), Bind { binding }).await {
        Ok(_) => outcome.bound = true,
        Err(e) => {
            outcome.skipped = Some(format!("binding failed: {e}"));
            outcome.next = Some(bind_command(&network.id));
        }
    }
    outcome
}

/// `network join`: joins the host (a failure here fails the request), then
/// runs the person step when the CLI supplied a person key.
pub async fn join_network(store: Arc<Store>, request: JoinNetwork) -> Result<Joined, Error> {
    if request
        .token
        .as_ref()
        .is_some_and(|t| t.trim().starts_with(crate::link_runtime::invite::PREFIX))
    {
        return crate::link_runtime::redemption::join(store, request).await;
    }
    let mut member = None;
    let network = match (&request.token, &request.descriptor) {
        (Some(text), None) if text.trim().starts_with(MEMBER_TOKEN_PREFIX) => {
            let token = MemberInviteToken::decode(text)?;
            let network = join_token(store.clone(), token.host()).await?;
            member = Some((text.as_str(), token));
            network
        }
        (Some(text), None) => join(store.clone(), text.clone()).await?,
        (None, Some(descriptor)) => join_with_descriptor(store.clone(), descriptor.clone()).await?,
        _ => {
            return Err(Error::Invalid(
                "give exactly one of token or descriptor".into(),
            ));
        }
    };
    refresh_usage(&store, &network).await;
    let person = match &request.person_public_key {
        Some(key) => Some(
            person_step(
                store,
                &network,
                member.as_ref().map(|(text, token)| (*text, token)),
                key,
                request.binding,
            )
            .await,
        ),
        None => None,
    };
    Ok(Joined { network, person })
}

/// `network create`: once the network is registered, admits the creator's
/// person with the new root under the creator's label. The CLI then signs
/// and submits the binding, so the person key never reaches the daemon.
async fn create_person_step(
    store: Arc<Store>,
    network: &Network,
    person_public_key: &str,
) -> PersonOutcome {
    let mut outcome = PersonOutcome::default();
    let key = match persons::normalize_person_key(person_public_key) {
        Ok(key) => key,
        Err(e) => {
            outcome.skipped = Some(format!("invalid person key: {e}"));
            return outcome;
        }
    };
    outcome.person_id = persons::person_id_of(&key).ok();
    if network.last_sync_at.is_none() {
        outcome.skipped = Some("the network is not registered with its coordinator yet".into());
        outcome.next = Some(admit_command(&network.id, &key, &network.member));
        return outcome;
    }
    match admit_person(
        store.clone(),
        network.id.clone(),
        AdmitPerson {
            person_public_key: key.clone(),
            member: network.member.clone(),
            admission: None,
        },
    )
    .await
    {
        Ok(_) => {
            outcome.admitted = true;
            outcome.next = Some(bind_command(&network.id));
            // The creator's person is also the first administrator.
            let delegated = delegate_admin(
                store,
                network.id.clone(),
                DelegateAdmin {
                    person: Some(key.clone()),
                    delegation: None,
                },
            )
            .await;
            if let Err(e) = delegated {
                eprintln!("administrator delegation failed: {e}");
            }
        }
        Err(e) => {
            outcome.skipped = Some(format!("person admission failed: {e}"));
            outcome.next = Some(admit_command(&network.id, &key, &network.member));
        }
    }
    outcome
}

/// Handles the coordinator's `changed` notification for a network: syncs
/// it as the interval sync does, then wakes the directory worker. At most
/// one notified sync per network runs; a notification during it causes one
/// more sync after it.
pub(crate) fn changed(store: &Arc<Store>, network: String) {
    let Ok(mut running) = store.changed_syncs.lock() else {
        return;
    };
    if let Some(again) = running.get_mut(&network) {
        *again = true;
        return;
    }
    running.insert(network.clone(), false);
    drop(running);
    let store = store.clone();
    tokio::spawn(async move {
        loop {
            let known = {
                let id = network.clone();
                blocking(store.clone(), move |s| s.network(&id))
                    .await
                    .is_ok()
            };
            if known && let Err(error) = sync_network(store.clone(), network.clone()).await {
                eprintln!("coordination sync error: {error}");
            }
            store.directory_wake.notify_one();
            let Ok(mut running) = store.changed_syncs.lock() else {
                return;
            };
            match running.get_mut(&network) {
                Some(again) if *again => *again = false,
                _ => {
                    running.remove(&network);
                    return;
                }
            }
        }
    });
}

/// Background registration and sync for every network until shutdown.
/// Shutdown abandons a round in progress, as a stop between rounds would, so
/// a slow coordinator does not hold the daemon past its stop.
pub async fn coordinate(store: Arc<Store>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    loop {
        let round = async {
            let ids = blocking(store.clone(), |s| {
                Ok(s.networks()?.into_iter().map(|n| n.id).collect::<Vec<_>>())
            })
            .await
            .unwrap_or_default();
            for id in ids {
                if let Err(error) = sync_network(store.clone(), id).await {
                    eprintln!("coordination sync error: {error}");
                }
            }
            crate::policy::renew(store.clone()).await;
        };
        tokio::select! {
            _ = round => {}
            _ = shutdown.changed() => return,
        }
        let interval = store.coordination_interval.load(Ordering::Relaxed);
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(interval)) => {}
            _ = shutdown.changed() => return,
        }
    }
}

pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/networks", get(list).post(create))
        .route("/v1/networks/join", post(join_route))
        .route("/v1/networks/{id}/members", get(members))
        .route("/v1/networks/{id}/invites", post(invite))
        .route("/v1/networks/{id}/sync", post(sync))
        .route("/v1/networks/{id}/revocations", post(revoke_route))
        .route("/v1/networks/{id}/leave", post(leave_route))
        .route("/v1/networks/{id}/rotate", post(rotate_route))
        .route(
            "/v1/networks/{id}/persons",
            get(persons_route).post(admit_person_route),
        )
        .route("/v1/networks/{id}/hosts", post(admit_host_route))
        .route(
            "/v1/networks/{id}/person-invites",
            post(person_invite_route),
        )
        .route("/v1/networks/redeem-person", post(redeem_person_route))
        .route("/v1/networks/{id}/bindings", post(bind_route))
        .route("/v1/networks/{id}/unbindings", post(unbind_route))
        .route(
            "/v1/networks/{id}/person-removals",
            post(remove_person_route),
        )
        .route("/v1/networks/{id}/admins", post(delegate_admin_route))
        .route("/v1/networks/{id}/rotation-plan", get(rotation_plan_route))
        .route(
            "/v1/networks/{id}/admin-removal-plan",
            get(admin_removal_plan_route),
        )
        .route("/v1/networks/{id}/admin-removals", post(remove_admin_route))
        .route(
            "/v1/networks/{id}/groups",
            get(groups_route).post(set_group_route),
        )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanQuery {
    person: String,
    format: Option<String>,
}
async fn admin_removal_plan_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    query: Result<Query<PlanQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Value>, Error> {
    let Query(query) = query.map_err(|_| Error::Invalid("invalid removal plan query".into()))?;
    match query.format.as_deref() {
        None => Ok(Json(serde_json::to_value(
            blocking(store, move |s| s.admin_removal_plan(&id, &query.person)).await?,
        )?)),
        Some("2") => Ok(Json(
            blocking(store, move |s| {
                crate::link_runtime::withdrawal::plan(s, &id, &query.person)
                    .map_err(crate::link_runtime::support::model_error)
            })
            .await?,
        )),
        _ => Err(Error::Invalid("invalid removal plan format".into())),
    }
}
async fn rotation_plan_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<RotationPlan>, Error> {
    Ok(Json(blocking(store, move |s| s.rotation_plan(&id)).await?))
}
async fn delegate_admin_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<Delegated>), Error> {
    let request = decode(body)?;
    Ok((
        StatusCode::CREATED,
        Json(delegate_admin(store, id, request).await?),
    ))
}
async fn remove_admin_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<Revoked>), Error> {
    let raw = body.map_err(|_| Error::Invalid("invalid request".into()))?;
    let shape: Value = serde_json::from_slice(&raw)?;
    if shape.get("removal_base64").is_some() {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Signed {
            removal_base64: String,
        }
        let signed: Signed = crate::linking::decode_mutation(&raw, "removal_base64")
            .map_err(|_| Error::Invalid("invalid signed removal".into()))?;
        let raw =
            crate::link_runtime::crypto::bytes(&signed.removal_base64, crate::linking::MAX_OBJECT)
                .map_err(crate::link_runtime::support::model_error)?;
        let result = crate::link_runtime::withdrawal::submit(store, id, None, false, Some(raw))
            .await?
            .ok_or_else(|| Error::Invalid("active feature required".into()))?;
        return Ok((StatusCode::CREATED, Json(result)));
    }
    let request = decode(Ok(raw))?;
    Ok((
        StatusCode::CREATED,
        Json(remove_admin(store, id, request).await?),
    ))
}
async fn set_group_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<GroupView>), Error> {
    let request = decode(body)?;
    Ok((
        StatusCode::CREATED,
        Json(set_group(store, id, request).await?),
    ))
}
#[derive(Deserialize)]
struct GroupsQuery {
    /// Include deleted groups, so the CLI can sign the next version.
    #[serde(default)]
    all: bool,
}
async fn groups_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    Query(query): Query<GroupsQuery>,
) -> Result<Json<Vec<GroupView>>, Error> {
    Ok(Json(
        blocking(store, move |s| s.groups(&id, query.all)).await?,
    ))
}
async fn persons_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Vec<PersonView>>, Error> {
    Ok(Json(blocking(store, move |s| s.persons(&id)).await?))
}
async fn admit_person_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<AdmittedPerson>), Error> {
    let request = decode(body)?;
    Ok((
        StatusCode::CREATED,
        Json(admit_person(store, id, request).await?),
    ))
}
async fn admit_host_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<AdmittedHost>), Error> {
    let request = decode(body)?;
    Ok((
        StatusCode::CREATED,
        Json(admit_host(store, id, request).await?),
    ))
}
async fn person_invite_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<IssuedInvite>), Error> {
    let request = decode(body)?;
    Ok((
        StatusCode::CREATED,
        Json(blocking(store, move |s| s.issue_person_invite(&id, request)).await?),
    ))
}
async fn redeem_person_route(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<RedeemedPerson>), Error> {
    let request = decode(body)?;
    Ok((
        StatusCode::CREATED,
        Json(redeem_person(store, request).await?),
    ))
}
async fn bind_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<Bound>), Error> {
    let request = decode(body)?;
    Ok((StatusCode::CREATED, Json(bind(store, id, request).await?)))
}
async fn unbind_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<Revoked>), Error> {
    let request = decode(body)?;
    Ok((StatusCode::CREATED, Json(unbind(store, id, request).await?)))
}
async fn remove_person_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<Revoked>), Error> {
    let request = decode(body)?;
    Ok((
        StatusCode::CREATED,
        Json(remove_person(store, id, request).await?),
    ))
}
async fn revoke_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<Revoked>), Error> {
    let request: Revoke = decode(body)?;
    Ok((StatusCode::CREATED, Json(revoke(store, id, request).await?)))
}
async fn leave_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Left>, Error> {
    Ok(Json(leave(store, id).await?))
}
async fn rotate_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Network>, Error> {
    // An empty body rotates to a fresh raw root held here.
    let ssh = match body {
        Ok(bytes) if bytes.iter().all(u8::is_ascii_whitespace) => None,
        body => Some(decode(body)?),
    };
    Ok(Json(rotate(store, id, ssh).await?))
}
async fn list(State(store): State<Arc<Store>>) -> Result<Json<Vec<Network>>, Error> {
    Ok(Json(blocking(store, Store::networks).await?))
}
async fn create(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<Joined>), Error> {
    let mut request: CreateNetwork = decode(body)?;
    let person_public_key = request.person_public_key.take();
    let network = blocking(store.clone(), move |s| s.create_network(request)).await?;
    let network = sync_network(store.clone(), network.id).await?;
    let person = match person_public_key {
        Some(key) => Some(create_person_step(store, &network, &key).await),
        None => None,
    };
    Ok((StatusCode::CREATED, Json(Joined { network, person })))
}
async fn join_route(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<Joined>), Error> {
    let request: JoinNetwork = decode(body)?;
    Ok((
        StatusCode::CREATED,
        Json(join_network(store, request).await?),
    ))
}
async fn members(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Vec<Member>>, Error> {
    Ok(Json(blocking(store, move |s| s.members(&id)).await?))
}
async fn invite(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<IssuedInvite>), Error> {
    let request = decode(body)?;
    Ok((
        StatusCode::CREATED,
        Json(blocking(store, move |s| s.issue_invite(&id, request)).await?),
    ))
}
async fn sync(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Network>, Error> {
    let check = id.clone();
    blocking(store.clone(), move |s| s.network(&check)).await?;
    Ok(Json(sync_network(store, id).await?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member_entry(root: &SigningKey, host: &SigningKey, invite: &SigningKey) -> Value {
        let signed = membership::sign_invite(root, invite, "m", "2099-01-01T00:00:00Z");
        let m = membership::sign_member(
            signed,
            invite,
            host.verifying_key().as_bytes(),
            "2026-10-05T00:00:00Z",
        );
        json_value!({"host_id": key_id(host.verifying_key().as_bytes()), "membership": m, "address": "127.0.0.1:9", "updated_at": "2026-10-05T00:00:00Z"})
    }

    #[test]
    fn map_verification_drops_forged_and_reused_entries() {
        let root = random_seed().unwrap();
        let network = Network {
            id: membership::network_id(root.verifying_key().as_bytes()),
            name: "n".into(),
            root_public_key: STANDARD.encode(root.verifying_key().as_bytes()),
            member: "m".into(),
            coordinator_address: "127.0.0.1:1".into(),
            coordinator_public_key: String::new(),
            administrator: true,
            last_sync_at: None,
            last_sync_error: None,
            root_epoch: 0,
            current_root_public_key: String::new(),
            root_ssh: false,
            coordinator_pending: None,
        };
        let hosts: Vec<SigningKey> = (0..5).map(|_| random_seed().unwrap()).collect();
        let shared = random_seed().unwrap();
        let forger = random_seed().unwrap();
        let mut forged = member_entry(&forger, &hosts[2], &random_seed().unwrap());
        forged["membership"]["network_id"] = json_value!(network.id);
        let mut wrong_id = member_entry(&root, &hosts[4], &random_seed().unwrap());
        wrong_id["host_id"] = json_value!(key_id(hosts[0].verifying_key().as_bytes()));
        let map = WireMap {
            admins: Vec::new(),
            groups: Vec::new(),
            policies: Vec::new(),
            successors: Value::Null,
            r#move: Value::Null,
            active_map: None,
            rotations: vec![],
            attestations: vec![],
            revocations: vec![],
            network_id: network.id.clone(),
            root_public_key: network.root_public_key.clone(),
            members: vec![
                member_entry(&root, &hosts[0], &random_seed().unwrap()),
                forged,
                member_entry(&root, &hosts[1], &shared),
                member_entry(&root, &hosts[3], &shared),
                wrong_id,
                json_value!({"host_id": "junk"}),
            ],
            persons: Vec::new(),
        };
        let members = verify_map(&network, map, Statements::default())
            .unwrap()
            .members;
        let ids: Vec<_> = members.iter().map(|m| m.host_id.clone()).collect();
        assert_eq!(ids, vec![key_id(hosts[0].verifying_key().as_bytes())]);
        let other = WireMap {
            admins: Vec::new(),
            groups: Vec::new(),
            policies: Vec::new(),
            successors: Value::Null,
            r#move: Value::Null,
            active_map: None,
            network_id: network.id.clone(),
            root_public_key: STANDARD.encode(forger.verifying_key().as_bytes()),
            members: vec![],
            rotations: vec![],
            attestations: vec![],
            revocations: vec![],
            persons: Vec::new(),
        };
        assert!(verify_map(&network, other, Statements::default()).is_err());
    }

    #[test]
    fn created_network_issues_verifiable_invites_and_persists() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("host");
        let store = Store::open(&path).unwrap();
        let coordinator = STANDARD.encode(random_seed().unwrap().verifying_key().as_bytes());
        let network = store
            .create_network(CreateNetwork {
                name: "team".into(),
                member: "alice".into(),
                coordinator_address: "coord.example:7400".into(),
                coordinator_public_key: coordinator,
                person_public_key: None,
            })
            .unwrap();
        assert!(network.administrator);
        let members = store.members(&network.id).unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(
            members[0]
                .membership
                .as_ref()
                .unwrap()
                .verify(&network.root_public_key)
                .unwrap(),
            store.identity().id
        );
        let expires = rfc3339(chrono::Utc::now() + chrono::TimeDelta::days(1));
        let issued = store
            .issue_invite(
                &network.id,
                CreateInvite {
                    token: None,
                    member: "bob".into(),
                    expires_at: expires.clone(),
                    host_only: true,
                },
            )
            .unwrap();
        let token = InviteToken::decode(&issued.token).unwrap();
        assert_eq!(token.member, "bob");
        assert_eq!(token.invite_expires_at, expires);
        let too_late = rfc3339(chrono::Utc::now() + chrono::TimeDelta::days(31));
        assert!(
            store
                .issue_invite(
                    &network.id,
                    CreateInvite {
                        token: None,
                        member: "bob".into(),
                        expires_at: too_late,
                        host_only: true,
                    }
                )
                .is_err()
        );
        drop(store);
        let reopened = Store::open(&path).unwrap();
        assert_eq!(reopened.networks().unwrap(), vec![network]);
        let kinds: Vec<_> = reopened
            .events(0, 100)
            .unwrap()
            .into_iter()
            .map(|e| e.kind)
            .collect();
        assert_eq!(kinds, vec!["network.created", "network.invite_issued"]);
    }

    #[test]
    fn joined_networks_reject_invites_and_members_become_known() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(&temporary.path().join("host")).unwrap();
        let root = random_seed().unwrap();
        let invite = random_seed().unwrap();
        let other = random_seed().unwrap();
        let network = Network {
            id: membership::network_id(root.verifying_key().as_bytes()),
            name: "team".into(),
            root_public_key: STANDARD.encode(root.verifying_key().as_bytes()),
            member: "bob".into(),
            coordinator_address: "127.0.0.1:1".into(),
            coordinator_public_key: STANDARD
                .encode(random_seed().unwrap().verifying_key().as_bytes()),
            administrator: false,
            last_sync_at: None,
            last_sync_error: None,
            root_epoch: 0,
            current_root_public_key: String::new(),
            root_ssh: false,
            coordinator_pending: None,
        };
        let me = membership::sign_member(
            membership::sign_invite(&root, &invite, "bob", "2099-01-01T00:00:00Z"),
            &invite,
            store.signing_key.verifying_key().as_bytes(),
            "2026-10-05T00:00:00Z",
        );
        let map = || WireMap {
            admins: Vec::new(),
            groups: Vec::new(),
            policies: Vec::new(),
            successors: Value::Null,
            r#move: Value::Null,
            active_map: None,
            rotations: vec![],
            attestations: vec![],
            revocations: vec![],
            network_id: network.id.clone(),
            root_public_key: network.root_public_key.clone(),
            members: vec![
                json_value!({"host_id": store.identity().id, "membership": me, "address": "", "updated_at": "2026-10-05T00:00:00Z"}),
                member_entry(&root, &other, &random_seed().unwrap()),
            ],
            persons: Vec::new(),
        };
        // A map that omits this host is not applied.
        let mut missing = map();
        missing.members.remove(0);
        assert!(store.apply_map(network.clone(), missing, true).is_err());
        assert!(store.networks().unwrap().is_empty());
        let joined = store.apply_map(network.clone(), map(), true).unwrap();
        assert!(joined.last_sync_at.is_some());
        assert!(matches!(
            store.apply_map(network.clone(), map(), true),
            Err(Error::Conflict(_))
        ));
        let other_key = other.verifying_key().to_bytes();
        let other_id = key_id(&other_key);
        assert!(store.knows(&other_key).unwrap());
        assert_eq!(store.dial_target(&other_id).unwrap().address, "127.0.0.1:9");
        assert!(store.dial_target(&store.identity().id).is_err());
        let connection = store.connection().unwrap();
        assert!(store.known_host(&connection, &other_id).unwrap());
        assert!(store.connected(&connection, &other_id).unwrap());
        store.coordination_interval.store(0, Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(5));
        assert!(!store.connected(&connection, &other_id).unwrap());
        drop(connection);
        assert!(matches!(
            store.issue_invite(
                &network.id,
                CreateInvite {
                    token: None,
                    member: "x".into(),
                    expires_at: rfc3339(chrono::Utc::now() + chrono::TimeDelta::days(1)),
                    host_only: true,
                },
            ),
            Err(Error::Forbidden)
        ));
        // Removal from the map removes the member and its pin.
        let mut shrunk = map();
        shrunk.members.truncate(1);
        store.apply_map(network.clone(), shrunk, false).unwrap();
        assert!(!store.knows(&other_key).unwrap());
        let kinds: Vec<_> = store
            .events(0, 100)
            .unwrap()
            .into_iter()
            .map(|e| e.kind)
            .collect();
        assert_eq!(
            kinds,
            vec![
                "network.joined",
                "network.member_added",
                "network.member_removed"
            ]
        );
    }

    /// A member entry whose invite is signed by `root`, which may be a rotated
    /// root that does not derive `network`.
    fn rooted_entry(network: &str, root: &SigningKey, host: &SigningKey) -> Value {
        use ed25519_dalek::Signer;
        let invite = random_seed().unwrap();
        let mut signed = membership::sign_invite(root, &invite, "m", "2099-01-01T00:00:00Z");
        signed.network_id = network.into();
        let statement = membership::invite_statement(
            network,
            &signed.invite_public_key,
            "m",
            "2099-01-01T00:00:00Z",
        );
        signed.invite_signature = STANDARD.encode(root.sign(statement.as_bytes()).to_bytes());
        let m = membership::sign_member(
            signed,
            &invite,
            host.verifying_key().as_bytes(),
            "2026-10-05T00:00:00Z",
        );
        json_value!({"host_id": key_id(host.verifying_key().as_bytes()), "membership": m, "address": "", "updated_at": "2026-10-05T00:00:00Z"})
    }
    fn key(k: &SigningKey) -> String {
        STANDARD.encode(k.verifying_key().as_bytes())
    }
    fn wire(
        network: &Network,
        members: Vec<Value>,
        rotations: Vec<Value>,
        attestations: Vec<Value>,
        revocations: Vec<Value>,
    ) -> WireMap {
        WireMap {
            admins: Vec::new(),
            groups: Vec::new(),
            policies: Vec::new(),
            successors: Value::Null,
            r#move: Value::Null,
            active_map: None,
            network_id: network.id.clone(),
            root_public_key: network.root_public_key.clone(),
            members,
            rotations,
            attestations,
            revocations,
            persons: Vec::new(),
        }
    }

    fn person_entry(admission: &PersonAdmission) -> Value {
        json_value!({
            "person_id": persons::person_id_of(&admission.person_public_key).unwrap(),
            "person_public_key": admission.person_public_key,
            "member": admission.member,
            "admission": admission,
        })
    }
    fn admitted_entry(admission: &HostAdmission) -> Value {
        let key = membership::canonical(&admission.host_public_key, 32).unwrap();
        json_value!({"host_id": key_id(&key), "admission": admission, "address": "", "updated_at": "2026-10-05T00:00:00Z"})
    }
    fn events(store: &Store) -> Vec<(String, String)> {
        store
            .events(0, 1000)
            .unwrap()
            .into_iter()
            .map(|e| (e.kind, e.subject_id))
            .collect()
    }

    #[test]
    fn invites_are_member_invites_unless_host_only() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(&temporary.path().join("host")).unwrap();
        let network = store
            .create_network(CreateNetwork {
                name: "team".into(),
                member: "alice".into(),
                coordinator_address: "127.0.0.1:1".into(),
                coordinator_public_key: key(&random_seed().unwrap()),
                person_public_key: None,
            })
            .unwrap();
        let expires = rfc3339(chrono::Utc::now() + chrono::TimeDelta::days(1));
        let member = store
            .issue_invite(
                &network.id,
                CreateInvite {
                    token: None,
                    member: "bob".into(),
                    expires_at: expires.clone(),
                    host_only: false,
                },
            )
            .unwrap();
        let token = MemberInviteToken::decode(&member.token).unwrap();
        assert_eq!(token.network_id, network.id);
        assert_eq!(token.invite_public_key, member.invite_public_key);
        let host = store
            .issue_invite(
                &network.id,
                CreateInvite {
                    token: None,
                    member: "bob".into(),
                    expires_at: expires,
                    host_only: true,
                },
            )
            .unwrap();
        assert!(InviteToken::decode(&host.token).is_ok());
        assert!(MemberInviteToken::decode(&host.token).is_err());
        // The default is a member invite.
        let request: CreateInvite =
            serde_json::from_str(r#"{"member":"bob","expires_at":"2026-11-01T00:00:00Z"}"#)
                .unwrap();
        assert!(!request.host_only);
    }

    #[tokio::test]
    async fn the_person_step_reports_and_never_fails_the_join() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(&temporary.path().join("host")).unwrap());
        let r0 = random_seed().unwrap();
        let id = membership::network_id(r0.verifying_key().as_bytes());
        let network = Network {
            id: id.clone(),
            name: "team".into(),
            root_public_key: key(&r0),
            member: "bob".into(),
            // Nothing listens here: every coordinator call fails.
            coordinator_address: "127.0.0.1:1".into(),
            coordinator_public_key: key(&random_seed().unwrap()),
            administrator: false,
            last_sync_at: None,
            last_sync_error: None,
            root_epoch: 0,
            current_root_public_key: String::new(),
            root_ssh: false,
            coordinator_pending: None,
        };
        let at = "2026-10-08T00:00:00Z";
        let me = SigningKey::from_bytes(&store.signing_key.to_bytes());
        let pat = persons::PersonSigner::File(random_seed().unwrap());
        let stranger = persons::PersonSigner::File(random_seed().unwrap());
        let admission = PersonAdmission::sign(&r0, &id, 0, &pat.public_key_b64(), "pat", at);
        let mut map = wire(
            &network,
            vec![rooted_entry(&id, &r0, &me)],
            vec![],
            vec![],
            vec![],
        );
        map.persons = vec![person_entry(&admission)];
        let network = store.apply_map(network, map, true).unwrap();
        let pid = persons::person_id(&pat.public_key());

        // A person who is not admitted, without a member invite: skipped, with
        // the exact admit-then-bind follow-up.
        let outcome = person_step(
            store.clone(),
            &network,
            None,
            &stranger.public_key_b64(),
            None,
        )
        .await;
        assert!(!outcome.admitted && !outcome.bound);
        assert_eq!(
            outcome.skipped.as_deref(),
            Some("this person is not admitted in the network")
        );
        let next = outcome.next.unwrap();
        assert!(
            next.contains("network admit") && next.contains("ssh-ed25519 "),
            "{next}"
        );
        assert!(next.ends_with(&bind_command(&id)), "{next}");

        // Admitted already: admission is skipped. Without a binding, the step
        // stops at the bind follow-up.
        let outcome = person_step(store.clone(), &network, None, &pat.public_key_b64(), None).await;
        assert_eq!(outcome.person_id.as_deref(), Some(pid.as_str()));
        assert!(outcome.admitted && !outcome.bound);
        assert_eq!(outcome.skipped.as_deref(), Some("no binding was supplied"));
        assert_eq!(outcome.next.as_deref(), Some(bind_command(&id).as_str()));

        // A binding for a different person than the one supplied is refused.
        let other = HostBinding::sign(&stranger, &id, &key(&me), at).unwrap();
        let outcome = person_step(
            store.clone(),
            &network,
            None,
            &pat.public_key_b64(),
            Some(other),
        )
        .await;
        assert_eq!(
            outcome.skipped.as_deref(),
            Some("the binding names a different person")
        );

        // A valid binding the coordinator cannot accept: reported, and the
        // host stays joined.
        let binding = HostBinding::sign(&pat, &id, &key(&me), at).unwrap();
        let outcome = person_step(
            store.clone(),
            &network,
            None,
            &pat.public_key_b64(),
            Some(binding),
        )
        .await;
        assert!(outcome.admitted && !outcome.bound);
        assert!(outcome.skipped.unwrap().starts_with("binding failed"));
        assert_eq!(outcome.next.as_deref(), Some(bind_command(&id).as_str()));
        assert!(store.network(&id).is_ok());

        // A member invite whose person part cannot be redeemed now (the
        // coordinator is down): the follow-up redeems the same token later.
        let invite = random_seed().unwrap();
        let expires = rfc3339(chrono::Utc::now() + chrono::TimeDelta::days(1));
        let token = MemberInviteToken::issue(
            &r0,
            &invite,
            &id,
            "team",
            0,
            "sam",
            &expires,
            "127.0.0.1:1",
            &network.coordinator_public_key,
        );
        let text = token.encode();
        let outcome = person_step(
            store.clone(),
            &network,
            Some((text.as_str(), &token)),
            &stranger.public_key_b64(),
            None,
        )
        .await;
        assert!(!outcome.admitted);
        assert!(
            outcome
                .skipped
                .unwrap()
                .starts_with("person admission failed")
        );
        let next = outcome.next.unwrap();
        assert!(
            next.contains("network redeem-person --token") && next.contains(&text),
            "{next}"
        );
        assert_eq!(store.persons(&id).unwrap().len(), 1);

        // An invalid key is reported, not returned as an error.
        let outcome = person_step(store, &network, None, "not a key", None).await;
        assert!(outcome.skipped.unwrap().starts_with("invalid person key"));
    }

    #[tokio::test]
    async fn create_admits_the_creator_only_once_registered() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(&temporary.path().join("host")).unwrap());
        let network = store
            .create_network(CreateNetwork {
                name: "team".into(),
                member: "alice".into(),
                coordinator_address: "127.0.0.1:1".into(),
                coordinator_public_key: key(&random_seed().unwrap()),
                person_public_key: None,
            })
            .unwrap();
        let alice = persons::PersonSigner::File(random_seed().unwrap());
        // Registration has not succeeded: the person step is skipped, and the
        // follow-up admits the creator under its own member label.
        let outcome = create_person_step(store, &network, &alice.public_key_b64()).await;
        assert!(!outcome.admitted && !outcome.bound);
        assert_eq!(
            outcome.person_id.as_deref(),
            Some(persons::person_id(&alice.public_key()).as_str())
        );
        assert!(outcome.skipped.unwrap().contains("not registered"));
        let next = outcome.next.unwrap();
        assert!(
            next.contains("--member alice") && next.contains(&network.id),
            "{next}"
        );
        // The create response flattens the network and adds `person`.
        let value = serde_json::to_value(Joined {
            network: network.clone(),
            person: None,
        })
        .unwrap();
        assert_eq!(value["id"], serde_json::json!(network.id));
        assert_eq!(value["person"], serde_json::Value::Null);
    }

    #[test]
    fn an_accepted_binding_is_recorded_once_before_any_sync() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(&temporary.path().join("host")).unwrap();
        let r0 = random_seed().unwrap();
        let id = membership::network_id(r0.verifying_key().as_bytes());
        let network = Network {
            id: id.clone(),
            name: "team".into(),
            root_public_key: key(&r0),
            member: "bob".into(),
            coordinator_address: "127.0.0.1:1".into(),
            coordinator_public_key: key(&random_seed().unwrap()),
            administrator: false,
            last_sync_at: None,
            last_sync_error: None,
            root_epoch: 0,
            current_root_public_key: String::new(),
            root_ssh: false,
            coordinator_pending: None,
        };
        let at = "2026-10-08T00:00:00Z";
        let me = SigningKey::from_bytes(&store.signing_key.to_bytes());
        let pat = persons::PersonSigner::File(random_seed().unwrap());
        let admission = PersonAdmission::sign(&r0, &id, 0, &pat.public_key_b64(), "pat", at);
        // Joined, with the person admitted, but no binding in the map yet.
        let mut map = wire(
            &network,
            vec![rooted_entry(&id, &r0, &me)],
            vec![],
            vec![],
            vec![],
        );
        map.persons = vec![person_entry(&admission)];
        store.apply_map(network.clone(), map, true).unwrap();
        let mut binding = HostBinding::sign(&pat, &id, &key(&me), at).unwrap();
        binding.sign_host(&me).unwrap();
        let bound_events = || {
            store
                .events(0, 1000)
                .unwrap()
                .into_iter()
                .filter(|e| e.kind == "network.host_bound")
                .count()
        };
        // Recorded on acceptance, before any later sync; repeating is a no-op.
        store.record_own_binding(&id, &binding).unwrap();
        store.record_own_binding(&id, &binding).unwrap();
        assert_eq!(bound_events(), 1);
        let own = store.identity().id;
        let mine = store
            .members(&id)
            .unwrap()
            .into_iter()
            .find(|m| m.host_id == own)
            .unwrap();
        assert_eq!(mine.person_id, Some(persons::person_id(&pat.public_key())));
        assert_eq!(mine.person_member.as_deref(), Some("pat"));
        // A later map carrying the same binding adds no second event.
        let mut entry = rooted_entry(&id, &r0, &me);
        entry["binding"] = serde_json::to_value(&binding).unwrap();
        let mut map = wire(&network, vec![entry], vec![], vec![], vec![]);
        map.persons = vec![person_entry(&admission)];
        store.apply_map(network.clone(), map, false).unwrap();
        assert_eq!(bound_events(), 1);
        // Only this host's own binding can be recorded this way.
        let other = random_seed().unwrap();
        let mut theirs = HostBinding::sign(&pat, &id, &key(&other), at).unwrap();
        theirs.sign_host(&other).unwrap();
        assert!(store.record_own_binding(&id, &theirs).is_err());
    }

    #[test]
    fn persons_bind_hosts_and_removals_and_unbindings_are_sticky() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(&temporary.path().join("host")).unwrap();
        let r0 = random_seed().unwrap();
        let id = membership::network_id(r0.verifying_key().as_bytes());
        let network = Network {
            id: id.clone(),
            name: "team".into(),
            root_public_key: key(&r0),
            member: "bob".into(),
            coordinator_address: "127.0.0.1:1".into(),
            coordinator_public_key: key(&random_seed().unwrap()),
            administrator: false,
            last_sync_at: None,
            last_sync_error: None,
            root_epoch: 0,
            current_root_public_key: String::new(),
            root_ssh: false,
            coordinator_pending: None,
        };
        let at = "2026-10-08T00:00:00Z";
        let me = SigningKey::from_bytes(&store.signing_key.to_bytes());
        let [carol, dave] = [(); 2].map(|_| random_seed().unwrap());
        let [p_key, q_key, x_key] = [(); 3].map(|_| random_seed().unwrap());
        let (p, q, x) = (
            persons::PersonSigner::File(p_key.clone()),
            persons::PersonSigner::File(q_key.clone()),
            persons::PersonSigner::File(x_key),
        );
        // P by admission, Q by person invite; X was never admitted.
        let admit_p = PersonAdmission::sign(&r0, &id, 0, &p.public_key_b64(), "pat", at);
        let token = PersonInviteToken::issue(
            &r0,
            &random_seed().unwrap(),
            &id,
            "team",
            0,
            "quinn",
            "2099-01-01T00:00:00Z",
            "127.0.0.1:1",
            &key(&r0),
        );
        let q_membership = token.redeem(&q.public_key_b64(), at).unwrap();
        let q_entry = json_value!({
            "person_id": persons::person_id(&q.public_key()),
            "person_public_key": q.public_key_b64(),
            "member": "quinn",
            "membership": q_membership,
        });
        // A forged admission (not the root) is ignored.
        let forged = PersonAdmission::sign(
            &random_seed().unwrap(),
            &id,
            0,
            &x.public_key_b64(),
            "xavier",
            at,
        );
        let persons_wire = || {
            vec![
                person_entry(&admit_p),
                q_entry.clone(),
                person_entry(&forged),
            ]
        };
        // Carol is admitted by public key; dave joined with an invite.
        let carol_admission = HostAdmission::sign(&r0, &id, 0, &key(&carol), "carol", at);
        let consented = |person: &persons::PersonSigner, host: &SigningKey| {
            let mut b = HostBinding::sign(person, &id, &key(host), at).unwrap();
            b.sign_host(host).unwrap();
            b
        };
        let bind_me = consented(&p, &me);
        let bind_carol = consented(&q, &carol);
        // A binding naming another host, one by an unadmitted person, and one
        // carrying only the person's signature (no host consent).
        let misdirected = consented(&p, &carol);
        let by_stranger = consented(&x, &dave);
        let unconsented = HostBinding::sign(&p, &id, &key(&dave), at).unwrap();
        let members = |bindings: bool| {
            let mut mine = rooted_entry(&id, &r0, &me);
            let mut carol_entry = admitted_entry(&carol_admission);
            let mut dave_entry = rooted_entry(&id, &r0, &dave);
            if bindings {
                mine["binding"] = serde_json::to_value(&bind_me).unwrap();
                carol_entry["binding"] = serde_json::to_value(&bind_carol).unwrap();
                dave_entry["binding"] = serde_json::to_value(&by_stranger).unwrap();
            } else {
                dave_entry["binding"] = serde_json::to_value(&misdirected).unwrap();
            }
            vec![mine, carol_entry, dave_entry]
        };
        let mut map = wire(&network, members(true), vec![], vec![], vec![]);
        map.persons = persons_wire();
        store.apply_map(network.clone(), map, true).unwrap();
        let known = |k: &SigningKey| store.knows(&k.verifying_key().to_bytes()).unwrap();
        assert!(
            known(&carol) && known(&dave),
            "a key-admitted host is a member"
        );
        let person_of = |host: &SigningKey| {
            store
                .members(&id)
                .unwrap()
                .into_iter()
                .find(|m| m.public_key == key(host))
                .map(|m| (m.person_id, m.person_member))
                .unwrap()
        };
        let pid = persons::person_id(&p.public_key());
        let qid = persons::person_id(&q.public_key());
        assert_eq!(person_of(&me), (Some(pid.clone()), Some("pat".into())));
        assert_eq!(person_of(&carol), (Some(qid.clone()), Some("quinn".into())));
        assert_eq!(
            person_of(&dave),
            (None, None),
            "an unadmitted person binds nothing"
        );
        let mut no_consent = members(true);
        no_consent[2]["binding"] = serde_json::to_value(&unconsented).unwrap();
        let mut map = wire(&network, no_consent, vec![], vec![], vec![]);
        map.persons = persons_wire();
        store.apply_map(network.clone(), map, false).unwrap();
        assert_eq!(
            person_of(&dave),
            (None, None),
            "a binding without the host's signature binds nothing"
        );
        let listed = store.persons(&id).unwrap();
        assert_eq!(listed.len(), 2, "the forged admission is ignored");
        let view = |pid: &str| listed.iter().find(|v| v.person_id == pid).unwrap();
        assert_eq!(
            view(&pid).hosts,
            vec![key_id(me.verifying_key().as_bytes())]
        );
        assert_eq!(
            view(&qid).hosts,
            vec![key_id(carol.verifying_key().as_bytes())]
        );
        assert_eq!(view(&qid).member, "quinn");
        let kinds = events(&store);
        assert!(kinds.contains(&("network.person_admitted".into(), pid.clone())));
        assert!(kinds.contains(&(
            "network.host_admitted".into(),
            key_id(carol.verifying_key().as_bytes())
        )));
        assert!(kinds.contains(&(
            "network.host_bound".into(),
            key_id(carol.verifying_key().as_bytes())
        )));

        // Q unbinds carol locally: enforced at once and sticky even though the
        // coordinator still serves the binding.
        let unbind = HostUnbinding::sign(&q, &id, &key(&carol), at).unwrap();
        let (revoked, body) = store.record_unbinding(&id, unbind.clone()).unwrap();
        assert_eq!(
            (revoked.kind.as_str(), revoked.subject.as_str()),
            ("unbind", key(&carol).as_str())
        );
        assert_eq!(body["kind"], "unbind");
        assert_eq!(person_of(&carol), (None, None));
        let mut map = wire(&network, members(true), vec![], vec![], vec![]);
        map.persons = persons_wire();
        store.apply_map(network.clone(), map, false).unwrap();
        assert_eq!(person_of(&carol), (None, None), "unbinding is sticky");
        assert_eq!(person_of(&me), (Some(pid.clone()), Some("pat".into())));
        // A forged unbinding is refused.
        let mut tampered = unbind.clone();
        tampered.host_public_key = key(&me);
        assert!(store.record_unbinding(&id, tampered).is_err());

        // The root removes P: it disappears with its binding, stickily.
        let removal = PersonRemoval::sign(&r0, &id, &p.public_key_b64(), at);
        let mut map = wire(
            &network,
            members(true),
            vec![],
            vec![],
            vec![json_value!({"kind": "person", "statement": removal})],
        );
        map.persons = persons_wire();
        store.apply_map(network.clone(), map, false).unwrap();
        assert_eq!(person_of(&me), (None, None));
        let mut map = wire(&network, members(true), vec![], vec![], vec![]);
        map.persons = persons_wire();
        store.apply_map(network.clone(), map, false).unwrap();
        assert_eq!(person_of(&me), (None, None), "removal is sticky");
        assert_eq!(
            store
                .persons(&id)
                .unwrap()
                .iter()
                .map(|v| v.person_id.clone())
                .collect::<Vec<_>>(),
            vec![qid.clone()]
        );
        assert!(events(&store).contains(&("network.person_removed".into(), pid.clone())));

        // After a rotation, epoch-0 admissions and person invites no longer
        // count; re-signed admissions at the new epoch do.
        let r1 = random_seed().unwrap();
        let rotation = Rotation::sign(&r0, &id, 1, &key(&r1), at);
        let attest_me = Attestation::sign(&r1, &id, 1, &key(&me), "bob", at);
        let attest_dave = Attestation::sign(&r1, &id, 1, &key(&dave), "dave", at);
        let stale = |carol_entry: Value| {
            let mut map = wire(
                &network,
                vec![
                    rooted_entry(&id, &r0, &me),
                    carol_entry,
                    rooted_entry(&id, &r0, &dave),
                ],
                vec![serde_json::to_value(&rotation).unwrap()],
                vec![
                    serde_json::to_value(&attest_me).unwrap(),
                    serde_json::to_value(&attest_dave).unwrap(),
                ],
                vec![],
            );
            map.persons = vec![q_entry.clone()];
            map
        };
        store
            .apply_map(
                network.clone(),
                stale(admitted_entry(&carol_admission)),
                false,
            )
            .unwrap();
        assert!(
            !known(&carol),
            "an epoch-0 host admission lapses after rotation"
        );
        assert!(
            store.persons(&id).unwrap().is_empty(),
            "an epoch-0 person invite lapses"
        );
        let readmit_carol = HostAdmission::sign(&r1, &id, 1, &key(&carol), "carol", at);
        let readmit_q = PersonAdmission::sign(&r1, &id, 1, &q.public_key_b64(), "quinn", at);
        let mut map = stale(admitted_entry(&readmit_carol));
        map.persons = vec![person_entry(&readmit_q)];
        store.apply_map(network.clone(), map, false).unwrap();
        assert!(known(&carol));
        assert_eq!(store.persons(&id).unwrap().len(), 1);
    }

    #[test]
    fn person_labels_are_unique_ignoring_ascii_case() {
        assert!(labels_conflict("bob", "BOB"));
        assert!(labels_conflict("Bob.Smith", "bob.smith"));
        assert!(!labels_conflict("bob", "bob2"));
        // Only ASCII letters fold; other bytes compare exactly.
        assert!(!labels_conflict("bób", "BÓB"));
        assert!(labels_conflict("bób", "BóB"));
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(&temporary.path().join("host")).unwrap();
        let network = store
            .create_network(CreateNetwork {
                name: "team".into(),
                member: "alice".into(),
                coordinator_address: "127.0.0.1:1".into(),
                coordinator_public_key: key(&random_seed().unwrap()),
                person_public_key: None,
            })
            .unwrap();
        let id = network.id.clone();
        let admit = |label: &str, signer: &persons::PersonSigner| {
            store.sign_person_admission(
                &id,
                AdmitPerson {
                    admission: None,
                    person_public_key: signer.public_key_b64(),
                    member: label.into(),
                },
            )
        };
        let store_person = |admission: PersonAdmission| {
            let key = admission.person_public_key.clone();
            let proof = PersonProof {
                admission: Some(admission),
                membership: None,
            };
            store
                .connection()
                .unwrap()
                .execute(
                    "INSERT INTO network_statements VALUES (?1, 'person', ?2, ?3)",
                    params![id, key, serde_json::to_string(&proof).unwrap()],
                )
                .unwrap();
            key
        };
        let bob = persons::PersonSigner::File(random_seed().unwrap());
        let other = persons::PersonSigner::File(random_seed().unwrap());
        let bob_key = store_person(admit("bob", &bob).unwrap().1);
        // A conflicting label is refused for admissions and person invites.
        assert!(matches!(admit("BOB", &other), Err(Error::Conflict(_))));
        let invite = |label: &str| {
            store.issue_person_invite(
                &id,
                CreateInvite {
                    token: None,
                    member: label.into(),
                    expires_at: rfc3339(chrono::Utc::now() + chrono::TimeDelta::hours(1)),
                    host_only: true,
                },
            )
        };
        assert!(matches!(invite("Bob"), Err(Error::Conflict(_))));
        assert!(invite("bób").is_ok());
        // Re-admitting the same key under its own label is not a conflict.
        assert!(admit("bob", &bob).is_ok());
        assert!(
            store
                .persons(&id)
                .unwrap()
                .iter()
                .all(|p| !p.label_conflict)
        );
        // A conflicting person from a misbehaving coordinator is kept, and both
        // are reported.
        let other_admission = PersonAdmission::sign(
            &store
                .current_root(&store.connection().unwrap(), &id)
                .unwrap(),
            &id,
            0,
            &other.public_key_b64(),
            "Bob",
            &now(),
        );
        store_person(other_admission);
        let listed = store.persons(&id).unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.iter().all(|p| p.label_conflict));
        // Removing a person frees its label.
        let mut connection = store.connection().unwrap();
        let tx = connection.transaction().unwrap();
        store
            .drop_person_locally(&tx, &id, &bob_key, &now())
            .unwrap();
        store
            .drop_person_locally(&tx, &id, &other.public_key_b64(), &now())
            .unwrap();
        tx.commit().unwrap();
        drop(connection);
        let third = persons::PersonSigner::File(random_seed().unwrap());
        assert!(admit("bob", &third).is_ok());
        assert!(invite("BOB").is_ok());
    }

    /// A network with an administrator `alice` (a person the root admitted
    /// and delegated), who admitted the host `carol` and the person `bob` and
    /// defined `backend` v2 over the root's v1.
    struct AdminSetup {
        store: Store,
        network: Network,
        root: SigningKey,
        admin: persons::PersonSigner,
        bob: persons::PersonSigner,
        alice_admission: PersonAdmission,
        bob_admission: PersonAdmission,
        delegation: AdminDelegation,
        carol: HostAdmission,
        root_group: Group,
        admin_group: Group,
        own: Value,
        _temporary: tempfile::TempDir,
    }
    impl AdminSetup {
        fn new() -> Self {
            let temporary = tempfile::tempdir().unwrap();
            let store = Store::open(&temporary.path().join("host")).unwrap();
            let network = store
                .create_network(CreateNetwork {
                    name: "team".into(),
                    member: "host".into(),
                    coordinator_address: "127.0.0.1:1".into(),
                    coordinator_public_key: key(&random_seed().unwrap()),
                    person_public_key: None,
                })
                .unwrap();
            let id = network.id.clone();
            let root = store
                .current_root(&store.connection().unwrap(), &id)
                .unwrap();
            let admin = persons::PersonSigner::File(random_seed().unwrap());
            let bob = persons::PersonSigner::File(random_seed().unwrap());
            let ssh = KeySigner::Ssh(&admin);
            let at = now();
            let alice_admission =
                PersonAdmission::sign(&root, &id, 0, &admin.public_key_b64(), "alice", &at);
            let delegation =
                AdminDelegation::sign(&KeySigner::Raw(&root), &id, 0, &admin.public_key_b64(), &at)
                    .unwrap();
            let bob_admission =
                PersonAdmission::sign_with(&ssh, &id, 0, &bob.public_key_b64(), "bob", &at)
                    .unwrap();
            let carol =
                HostAdmission::sign_with(&ssh, &id, 0, &key(&random_seed().unwrap()), "carol", &at)
                    .unwrap();
            let members = vec![
                persons::person_id_of(&admin.public_key_b64()).unwrap(),
                persons::person_id_of(&bob.public_key_b64()).unwrap(),
            ];
            let root_group = Group::sign(
                &KeySigner::Raw(&root),
                &id,
                "backend",
                1,
                &members[..1],
                &at,
            )
            .unwrap();
            let admin_group = Group::sign(&ssh, &id, "backend", 2, &members, &at).unwrap();
            let own = store.own_membership(&id).unwrap().unwrap();
            let own = json_value!({"host_id": store.identity().id, "membership": own, "address": "", "updated_at": "2026-10-05T00:00:00Z"});
            Self {
                store,
                network,
                root,
                admin,
                bob,
                alice_admission,
                bob_admission,
                delegation,
                carol,
                root_group,
                admin_group,
                own,
                _temporary: temporary,
            }
        }
        fn map(&self, revocations: Vec<Value>, groups: Vec<&Group>) -> WireMap {
            WireMap {
                admins: vec![json_value!(self.delegation)],
                groups: groups.into_iter().map(|g| json_value!(g)).collect(),
                persons: vec![
                    person_entry(&self.alice_admission),
                    person_entry(&self.bob_admission),
                ],
                ..wire(
                    &self.network,
                    vec![self.own.clone(), admitted_entry(&self.carol)],
                    vec![],
                    vec![],
                    revocations,
                )
            }
        }
        fn apply(&self, map: WireMap) {
            self.store
                .apply_map(self.store.network(&self.network.id).unwrap(), map, false)
                .unwrap();
        }
        fn hosts(&self) -> Vec<String> {
            let mut members: Vec<String> = self
                .store
                .members(&self.network.id)
                .unwrap()
                .into_iter()
                .map(|m| m.member)
                .collect();
            members.sort();
            members
        }
        fn persons(&self) -> Vec<(String, bool)> {
            self.store
                .persons(&self.network.id)
                .unwrap()
                .into_iter()
                .map(|p| (p.member, p.administrator))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        }
        fn group(&self) -> Option<(u64, usize)> {
            self.store
                .groups(&self.network.id, true)
                .unwrap()
                .into_iter()
                .find(|g| g.name == "backend")
                .map(|g| (g.version, g.members.len()))
        }
        fn removal(&self, revoke_admitted: bool) -> Value {
            let removal = AdminRemoval::sign(
                &KeySigner::Raw(&self.root),
                &self.network.id,
                &self.admin.public_key_b64(),
                revoke_admitted,
                &if revoke_admitted {
                    Vec::new()
                } else {
                    self.store
                        .admin_removal_plan(&self.network.id, "alice")
                        .unwrap()
                        .kept
                },
                &now(),
            )
            .unwrap();
            json_value!({"kind": "admin", "statement": removal})
        }
    }

    #[test]
    fn administrator_statements_count_while_their_signer_does() {
        let s = AdminSetup::new();
        let id = s.network.id.clone();
        s.apply(s.map(vec![], vec![&s.root_group, &s.admin_group]));
        assert_eq!(s.hosts(), vec!["carol", "host"]);
        assert_eq!(
            s.persons(),
            vec![("alice".into(), true), ("bob".into(), false)]
        );
        let view = s.store.groups(&id, false).unwrap();
        assert_eq!(view.len(), 1);
        assert_eq!((view[0].version, view[0].members.len()), (2, 2));
        assert_eq!(view[0].signer, s.admin.public_key_b64());
        // A lower version from the map never replaces a valid higher one.
        s.apply(s.map(vec![], vec![&s.root_group]));
        assert_eq!(s.group(), Some((2, 2)));
        assert!(events(&s.store).contains(&(
            "network.admin_delegated".into(),
            persons::person_id_of(&s.admin.public_key_b64()).unwrap()
        )));
        assert!(events(&s.store).contains(&("network.group_updated".into(), "backend".into())));

        // The daemon takes statements the administrator signed through the
        // CLI, and refuses anyone else's with 403.
        let ssh = KeySigner::Ssh(&s.admin);
        let members = vec![persons::person_id_of(&s.bob.public_key_b64()).unwrap()];
        let next = Group::sign(&ssh, &id, "backend", 3, &members, &now()).unwrap();
        let (_, accepted) = s
            .store
            .sign_group(
                &id,
                SetGroup {
                    name: None,
                    members: vec![],
                    group: Some(next.clone()),
                },
            )
            .unwrap();
        assert_eq!(accepted, next);
        let stale = Group::sign(&ssh, &id, "backend", 2, &members, &now()).unwrap();
        assert!(matches!(
            s.store.sign_group(
                &id,
                SetGroup {
                    name: None,
                    members: vec![],
                    group: Some(stale)
                }
            ),
            Err(Error::Conflict(_))
        ));
        let by_bob =
            Group::sign(&KeySigner::Ssh(&s.bob), &id, "backend", 3, &members, &now()).unwrap();
        assert!(matches!(
            s.store.sign_group(
                &id,
                SetGroup {
                    name: None,
                    members: vec![],
                    group: Some(by_bob)
                }
            ),
            Err(Error::Forbidden)
        ));
        let dana = persons::PersonSigner::File(random_seed().unwrap());
        let admission =
            PersonAdmission::sign_with(&ssh, &id, 0, &dana.public_key_b64(), "dana", &now())
                .unwrap();
        let (_, checked) = s
            .store
            .sign_person_admission(
                &id,
                AdmitPerson {
                    person_public_key: String::new(),
                    member: String::new(),
                    admission: Some(admission.clone()),
                },
            )
            .unwrap();
        assert_eq!(checked, admission);
        // The root signs the next version by name, resolving labels.
        let (_, by_root) = s
            .store
            .sign_group(
                &id,
                SetGroup {
                    name: Some("backend".into()),
                    members: vec!["BOB".into()],
                    group: None,
                },
            )
            .unwrap();
        assert_eq!((by_root.version, by_root.members.clone()), (3, members));
        assert!(by_root.signer().is_none());

        // A plain removal keeps what the administrator had signed, as listed
        // in it: bob, carol, and backend v2.
        let plain = s.removal(false);
        assert_eq!(plain["statement"]["kept"].as_array().unwrap().len(), 3);
        s.apply(s.map(vec![plain.clone()], vec![&s.admin_group]));
        assert_eq!(s.hosts(), vec!["carol", "host"]);
        // A statement the removed key signs afterwards is not listed: refused.
        let late = HostAdmission::sign_with(
            &ssh,
            &id,
            0,
            &key(&random_seed().unwrap()),
            "erin",
            "2026-01-01T00:00:00Z",
        )
        .unwrap();
        let mut map = s.map(vec![plain], vec![&s.admin_group]);
        map.members.push(admitted_entry(&late));
        s.apply(map);
        assert_eq!(s.hosts(), vec!["carol", "host"]);
        assert_eq!(
            s.persons(),
            vec![("alice".into(), false), ("bob".into(), false)]
        );
        assert_eq!(s.group(), Some((2, 2)));
        let after = Group::sign(&ssh, &id, "backend", 4, &[], &now()).unwrap();
        assert!(matches!(
            s.store.sign_group(
                &id,
                SetGroup {
                    name: None,
                    members: vec![],
                    group: Some(after)
                }
            ),
            Err(Error::Forbidden)
        ));
        assert!(matches!(
            s.store.sign_delegation(
                &id,
                DelegateAdmin {
                    person: Some("alice".into()),
                    delegation: None
                }
            ),
            Err(Error::Forbidden)
        ));
    }

    #[test]
    fn renewals_epochs_and_one_removal_per_administrator() {
        let s = AdminSetup::new();
        let id = s.network.id.clone();
        s.apply(s.map(vec![], vec![&s.root_group]));
        // A same-version definition with the same members replaces the stored
        // one (a rotation's renewal); different members at that version do not.
        let renewal = Group::sign(
            &KeySigner::Ssh(&s.admin),
            &id,
            "backend",
            1,
            &s.root_group.members,
            &now(),
        )
        .unwrap();
        s.apply(s.map(vec![], vec![&renewal]));
        assert_eq!(
            s.store.groups(&id, false).unwrap()[0].signer,
            s.admin.public_key_b64()
        );
        let other = Group::sign(&KeySigner::Raw(&s.root), &id, "backend", 1, &[], &now()).unwrap();
        s.apply(s.map(vec![], vec![&other]));
        assert_eq!(s.group(), Some((1, 1)));
        // An administrator's admission for a future epoch is refused.
        let future = PersonAdmission::sign_with(
            &KeySigner::Ssh(&s.admin),
            &id,
            1,
            &persons::PersonSigner::File(random_seed().unwrap()).public_key_b64(),
            "zed",
            &now(),
        )
        .unwrap();
        assert!(matches!(
            s.store.sign_person_admission(
                &id,
                AdmitPerson {
                    person_public_key: String::new(),
                    member: String::new(),
                    admission: Some(future.clone()),
                },
            ),
            Err(Error::Invalid(_))
        ));
        let mut map = s.map(vec![], vec![]);
        map.persons.push(person_entry(&future));
        s.apply(map);
        assert!(!s.persons().iter().any(|(m, _)| m == "zed"));
        // A current administrator cannot be removed as a person.
        let alice = persons::person_id_of(&s.admin.public_key_b64()).unwrap();
        assert!(matches!(
            s.store.remove_person(
                &id,
                RemovePerson {
                    person_id: alice.clone(),
                    removal: None
                }
            ),
            Err(Error::Conflict(_))
        ));
        // One removal per key: a second plain one is 409; revoke_admitted
        // escalates once, recorded again.
        let plain = RemoveAdmin {
            person: Some("alice".into()),
            revoke_admitted: false,
            removal: None,
        };
        s.store.remove_admin(&id, plain).unwrap();
        let again = RemoveAdmin {
            person: Some("alice".into()),
            revoke_admitted: false,
            removal: None,
        };
        assert!(matches!(
            s.store.remove_admin(&id, again),
            Err(Error::Conflict(_))
        ));
        let escalate = || RemoveAdmin {
            person: Some("alice".into()),
            revoke_admitted: true,
            removal: None,
        };
        let (_, body) = s.store.remove_admin(&id, escalate()).unwrap();
        assert_eq!(body["statement"]["revoke_admitted"], true);
        let (_, repeat) = s.store.remove_admin(&id, escalate()).unwrap();
        assert_eq!(repeat, body);
        let removed = events(&s.store)
            .into_iter()
            .filter(|e| *e == ("network.admin_removed".to_owned(), alice.clone()))
            .count();
        assert_eq!(removed, 2);
        assert_eq!(s.hosts(), vec!["host"], "the escalation applies at once");
    }

    #[test]
    fn revoke_admitted_drops_members_and_reverts_groups() {
        let s = AdminSetup::new();
        let id = s.network.id.clone();
        s.apply(s.map(vec![], vec![&s.admin_group]));
        assert_eq!(s.group(), Some((2, 2)));
        // Local-first: the removal is stored and its submission prepared.
        let (revoked, body) = s
            .store
            .remove_admin(
                &id,
                RemoveAdmin {
                    person: Some("alice".into()),
                    revoke_admitted: true,
                    removal: None,
                },
            )
            .unwrap();
        assert_eq!(revoked.kind, "admin");
        assert_eq!(body["kind"], "admin");
        assert_eq!(body["statement"]["revoke_admitted"], true);
        assert!(
            s.store
                .pending_revocations(&id, &BTreeSet::new())
                .unwrap()
                .contains(&body)
        );
        // Bob's admission, carol's admission, and backend v2 no longer count;
        // the group reverts to the root's v1 even though it is lower.
        s.apply(s.map(vec![body.clone()], vec![&s.root_group]));
        assert_eq!(s.hosts(), vec!["host"]);
        assert_eq!(s.persons(), vec![("alice".into(), false)]);
        assert_eq!(s.group(), Some((1, 1)));
        assert!(events(&s.store).contains(&(
            "network.admin_removed".into(),
            persons::person_id_of(&s.admin.public_key_b64()).unwrap()
        )));
        // Sticky: a later map without the removal changes nothing.
        s.apply(s.map(vec![], vec![&s.admin_group]));
        assert_eq!(s.hosts(), vec!["host"]);
        assert_eq!(s.group(), Some((1, 1)));
        assert!(
            listed_revocations(&s.map(vec![body], vec![]))
                .contains(&("admin_removal".into(), s.admin.public_key_b64()))
        );
    }

    #[test]
    fn rotation_resigns_delegations_and_an_ssh_root_keeps_no_seed() {
        let s = AdminSetup::new();
        let id = s.network.id.clone();
        s.apply(s.map(vec![], vec![&s.root_group]));
        // A host admitted by key that has not joined yet is renewed too.
        let unjoined = HostAdmission::sign(
            &s.root,
            &id,
            0,
            &key(&random_seed().unwrap()),
            "erin",
            &now(),
        );
        // Stored as `host_admission` with no member, as either
        // implementation records an admission it issued; a later map
        // without that host keeps it.
        s.store
            .connection()
            .unwrap()
            .execute(
                "INSERT INTO network_statements VALUES (?1, 'host_admission', ?2, ?3)",
                params![
                    id,
                    unjoined.host_public_key,
                    serde_json::to_string(&unjoined).unwrap()
                ],
            )
            .unwrap();
        s.apply(s.map(vec![], vec![&s.root_group]));
        let plan = s.store.rotation_plan(&id).unwrap();
        assert!(
            plan.host_admissions
                .iter()
                .any(|i| i.public_key == unjoined.host_public_key)
        );
        assert!(
            !plan.host_admissions.iter().any(|i| i.member == "carol"),
            "an administrator's admission is not renewed"
        );
        assert_eq!(
            plan.groups,
            vec![PlannedGroup {
                name: "backend".into(),
                version: 1,
                members: s.root_group.members.clone(),
            }]
        );
        let (_, pending) = s.store.prepare_rotation(&id, None).unwrap();
        let next = membership::seed(&pending.root_seed).unwrap();
        // Root-signed groups are renewed by the new root at the same version.
        assert_eq!(pending.groups.len(), 1);
        let renewed = &pending.groups[0];
        assert_eq!(
            (renewed.version, &renewed.members),
            (1, &s.root_group.members)
        );
        renewed.verify_signed_by(&id, &key(&next)).unwrap();
        assert!(
            pending
                .admissions
                .iter()
                .any(|v| v["host_public_key"] == unjoined.host_public_key.as_str())
        );
        let delegations: Vec<AdminDelegation> = pending
            .admissions
            .iter()
            .filter(|v| v.get("delegated_at").is_some())
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .collect();
        assert_eq!(delegations.len(), 1);
        delegations[0].verify(&id, 1, &key(&next)).unwrap();
        s.store.discard_rotation(&id).unwrap();

        // To an SSH root: the CLI signs the new root's statements.
        let ssh_root = persons::PersonSigner::File(random_seed().unwrap());
        let signer = KeySigner::Ssh(&ssh_root);
        let at = now();
        let own_key = s.store.identity().public_key;
        let request = RotateToSsh {
            root_public_key: persons::ssh_public_line(&ssh_root.public_key()),
            rotation: None,
            attestations: vec![
                Attestation::sign_with(&signer, &id, 1, &own_key, "host", &at).unwrap(),
            ],
            admissions: vec![json_value!(
                AdminDelegation::sign(&signer, &id, 1, &s.admin.public_key_b64(), &at).unwrap()
            )],
            groups: vec![
                Group::sign(&signer, &id, "backend", 1, &s.root_group.members, &at).unwrap(),
            ],
        };
        let (_, pending) = s.store.prepare_rotation(&id, Some(request)).unwrap();
        assert!(
            pending.root_seed.is_empty(),
            "no seed is stored for an SSH root"
        );
        assert_eq!(pending.rotation.root_public_key, ssh_root.public_key_b64());
        pending
            .rotation
            .verify_from(&id, 1, &s.network.root_public_key)
            .unwrap();
        s.store.commit_rotation(&id, &pending).unwrap();
        let network = s.store.network(&id).unwrap();
        assert!(network.root_ssh);
        let groups = s.store.groups(&id, false).unwrap();
        assert_eq!(
            (groups[0].version, &groups[0].signer),
            (1, &ssh_root.public_key_b64())
        );
        assert!(!network.administrator, "the root seed is deleted");
        assert!(matches!(
            s.store.current_root(&s.store.connection().unwrap(), &id),
            Err(Error::Forbidden)
        ));
        // A forged statement for the new root is refused.
        let bad = RotateToSsh {
            root_public_key: key(&random_seed().unwrap()),
            rotation: None,
            attestations: vec![Attestation::sign(&s.root, &id, 2, &own_key, "host", &at)],
            admissions: vec![],
            groups: vec![],
        };
        assert!(s.store.prepare_rotation(&id, Some(bad)).is_err());
    }

    #[test]
    fn administrators_admit_persons_and_hosts_and_rotation_readmits_them() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(&temporary.path().join("host")).unwrap();
        let network = store
            .create_network(CreateNetwork {
                name: "team".into(),
                member: "alice".into(),
                coordinator_address: "127.0.0.1:1".into(),
                coordinator_public_key: key(&random_seed().unwrap()),
                person_public_key: None,
            })
            .unwrap();
        let id = network.id.clone();
        let person = persons::PersonSigner::File(random_seed().unwrap());
        let ssh = persons::ssh_public_line(&person.public_key());
        let (_, admission) = store
            .sign_person_admission(
                &id,
                AdmitPerson {
                    admission: None,
                    person_public_key: format!("{ssh} bob@laptop"),
                    member: "bob".into(),
                },
            )
            .unwrap();
        assert_eq!(admission.person_public_key, person.public_key_b64());
        admission.verify(&id, 0, &network.root_public_key).unwrap();
        let carol = random_seed().unwrap();
        let (_, host) = store
            .sign_host_admission(
                &id,
                AdmitHost {
                    admission: None,
                    host_public_key: key(&carol),
                    member: "carol".into(),
                },
            )
            .unwrap();
        assert_eq!(
            host.verify(&id, 0, &network.root_public_key).unwrap(),
            key_id(carol.verifying_key().as_bytes())
        );
        assert!(matches!(
            store.sign_host_admission(
                &id,
                AdmitHost {
                    admission: None,
                    host_public_key: key(&store.signing_key),
                    member: "me".into(),
                },
            ),
            Err(Error::Conflict(_))
        ));
        let invite = store
            .issue_person_invite(
                &id,
                CreateInvite {
                    token: None,
                    member: "dana".into(),
                    expires_at: rfc3339(chrono::Utc::now() + chrono::TimeDelta::days(1)),
                    host_only: true,
                },
            )
            .unwrap();
        let token = PersonInviteToken::decode(&invite.token).unwrap();
        assert_eq!(token.invite_epoch, 0);
        let d = Descriptor::decode(&descriptor(&network)).unwrap();
        assert_eq!(d.root_public_key, network.root_public_key);

        // Persist the admitted person and host as a coordinator map would.
        let own = store.own_membership(&id).unwrap().unwrap();
        let map = WireMap {
            admins: Vec::new(),
            groups: Vec::new(),
            policies: Vec::new(),
            successors: Value::Null,
            r#move: Value::Null,
            active_map: None,
            network_id: id.clone(),
            root_public_key: network.root_public_key.clone(),
            members: vec![
                json_value!({"host_id": store.identity().id, "membership": own, "address": "", "updated_at": "2026-10-05T00:00:00Z"}),
                admitted_entry(&host),
            ],
            rotations: vec![],
            attestations: vec![],
            revocations: vec![],
            persons: vec![person_entry(&admission)],
        };
        store
            .apply_map(store.network(&id).unwrap(), map, false)
            .unwrap();
        let (_, pending) = store.prepare_rotation(&id, None).unwrap();
        assert_eq!(
            pending.attestations.len(),
            1,
            "the invite-chain member is attested"
        );
        assert_eq!(
            pending.admissions.len(),
            2,
            "the host and person are re-admitted"
        );
        let next = pending.rotation.root_public_key.clone();
        for a in &pending.admissions {
            if a.get("host_public_key").is_some() {
                let a: HostAdmission = serde_json::from_value(a.clone()).unwrap();
                a.verify(&id, 1, &next).unwrap();
            } else {
                let a: PersonAdmission = serde_json::from_value(a.clone()).unwrap();
                a.verify(&id, 1, &next).unwrap();
            }
        }

        // Removing the person is local first and idempotent.
        let pid = persons::person_id(&person.public_key());
        let (first, body) = store
            .remove_person(
                &id,
                RemovePerson {
                    removal: None,
                    person_id: pid.clone(),
                },
            )
            .unwrap();
        assert_eq!(body["kind"], "person");
        assert!(store.persons(&id).unwrap().is_empty());
        let (again, _) = store
            .remove_person(
                &id,
                RemovePerson {
                    removal: None,
                    person_id: pid.clone(),
                },
            )
            .unwrap();
        assert_eq!(first.subject, again.subject);
        assert_eq!(
            events(&store)
                .iter()
                .filter(|e| *e == &("network.person_removed".to_owned(), pid.clone()))
                .count(),
            1
        );
        assert!(matches!(
            store.sign_person_admission(
                &id,
                AdmitPerson {
                    admission: None,
                    person_public_key: ssh,
                    member: "bob".into(),
                },
            ),
            Err(Error::Forbidden)
        ));
    }

    #[test]
    fn revocations_are_sticky_and_rotation_requires_the_current_root() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(&temporary.path().join("host")).unwrap();
        let r0 = random_seed().unwrap();
        let id = membership::network_id(r0.verifying_key().as_bytes());
        let network = Network {
            id: id.clone(),
            name: "team".into(),
            root_public_key: key(&r0),
            member: "bob".into(),
            coordinator_address: "127.0.0.1:1".into(),
            coordinator_public_key: key(&random_seed().unwrap()),
            administrator: false,
            last_sync_at: None,
            last_sync_error: None,
            root_epoch: 0,
            current_root_public_key: String::new(),
            root_ssh: false,
            coordinator_pending: None,
        };
        let me = SigningKey::from_bytes(&store.signing_key.to_bytes());
        let [carol, dave, erin, frank] = [(); 4].map(|_| random_seed().unwrap());
        let mine = rooted_entry(&id, &r0, &me);
        let carol_entry = rooted_entry(&id, &r0, &carol);
        let dave_entry = rooted_entry(&id, &r0, &dave);
        let erin_entry = rooted_entry(&id, &r0, &erin);
        let base = || {
            vec![
                mine.clone(),
                carol_entry.clone(),
                dave_entry.clone(),
                erin_entry.clone(),
            ]
        };
        let known = |k: &SigningKey| store.knows(&k.verifying_key().to_bytes()).unwrap();
        store
            .apply_map(
                network.clone(),
                wire(&network, base(), vec![], vec![], vec![]),
                true,
            )
            .unwrap();
        assert!(known(&carol) && known(&dave) && known(&erin));

        // Revoking carol's key and dave's invite drops both.
        let at = "2026-10-07T00:00:00Z";
        let revoke_carol = HostRevocation::sign(&r0, &id, &key(&carol), at);
        let dave_invite = dave_entry["membership"]["invite_public_key"]
            .as_str()
            .unwrap()
            .to_owned();
        let revoke_dave = InviteRevocation::sign(&r0, &id, &dave_invite, at);
        let forged = HostRevocation::sign(&random_seed().unwrap(), &id, &key(&erin), at);
        let revocations = vec![
            json_value!({"kind": "host", "statement": revoke_carol}),
            json_value!({"kind": "invite", "statement": revoke_dave}),
            json_value!({"kind": "host", "statement": forged}),
        ];
        store
            .apply_map(
                network.clone(),
                wire(&network, base(), vec![], vec![], revocations),
                false,
            )
            .unwrap();
        assert!(!known(&carol) && !known(&dave));
        assert!(
            known(&erin),
            "a revocation not signed by a network root is ignored"
        );
        // Sticky: a map that omits the revocations does not restore them.
        store
            .apply_map(
                network.clone(),
                wire(&network, base(), vec![], vec![], vec![]),
                false,
            )
            .unwrap();
        assert!(!known(&carol) && !known(&dave) && known(&erin));

        // Rotation: only the current root's invites or attestations count.
        let r1 = random_seed().unwrap();
        let rotation = Rotation::sign(&r0, &id, 1, &key(&r1), at);
        let attest_me = Attestation::sign(&r1, &id, 1, &key(&me), "bob", at);
        let attest_carol = Attestation::sign(&r1, &id, 1, &key(&carol), "carol", at);
        let frank_entry = rooted_entry(&id, &r1, &frank);
        let mut members = base();
        members.push(frank_entry.clone());
        let rotated = store
            .apply_map(
                network.clone(),
                wire(
                    &network,
                    members.clone(),
                    vec![json_value!(rotation)],
                    vec![json_value!(attest_me), json_value!(attest_carol)],
                    vec![],
                ),
                false,
            )
            .unwrap();
        assert_eq!(rotated.root_epoch, 1);
        assert_eq!(rotated.current_root_public_key, key(&r1));
        assert!(known(&frank), "an invite under the current root is valid");
        assert!(!known(&erin), "an old-root chain alone no longer counts");
        assert!(!known(&carol), "an attestation does not undo a revocation");
        assert_eq!(store.network(&id).unwrap().root_epoch, 1);

        // A fork at a persisted epoch, or a stale chain, is refused.
        let r2 = random_seed().unwrap();
        let fork = Rotation::sign(&r0, &id, 1, &key(&r2), at);
        let refused = store.apply_map(
            network.clone(),
            wire(
                &network,
                members.clone(),
                vec![json_value!(fork)],
                vec![],
                vec![],
            ),
            false,
        );
        assert!(matches!(refused, Err(Error::Unavailable(m)) if m == "root chain conflict"));
        assert!(
            store
                .apply_map(
                    network.clone(),
                    wire(&network, members.clone(), vec![], vec![], vec![]),
                    false
                )
                .is_err()
        );
        assert!(known(&frank));
        assert_eq!(
            store.network(&id).unwrap().current_root_public_key,
            key(&r1)
        );

        // A leave seen in a map drops that member, with network.member_left.
        let leave = Leave::sign(&frank, &id, at);
        store
            .apply_map(
                network.clone(),
                wire(
                    &network,
                    members,
                    vec![json_value!(rotation)],
                    vec![json_value!(attest_me)],
                    vec![json_value!({"kind": "leave", "statement": leave})],
                ),
                false,
            )
            .unwrap();
        assert!(!known(&frank));
        let kinds: Vec<_> = store
            .events(0, 100)
            .unwrap()
            .into_iter()
            .map(|e| e.kind)
            .collect();
        assert!(kinds.contains(&"network.member_left".to_owned()));
    }

    #[test]
    fn administrators_revoke_rotate_and_members_leave() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(&temporary.path().join("admin")).unwrap();
        let network = store
            .create_network(CreateNetwork {
                name: "team".into(),
                member: "alice".into(),
                coordinator_address: "127.0.0.1:1".into(),
                coordinator_public_key: key(&random_seed().unwrap()),
                person_public_key: None,
            })
            .unwrap();
        let id = network.id.clone();
        let root = store
            .current_root(&store.connection().unwrap(), &id)
            .unwrap();
        let me = SigningKey::from_bytes(&store.signing_key.to_bytes());
        let own = json_value!({"host_id": store.identity().id, "membership": store.own_membership(&id).unwrap(), "address": "", "updated_at": "2026-10-05T00:00:00Z"});
        let [carol, dave] = [(); 2].map(|_| random_seed().unwrap());
        let carol_entry = rooted_entry(&id, &root, &carol);
        let dave_entry = rooted_entry(&id, &root, &dave);
        let map = || {
            wire(
                &network,
                vec![own.clone(), carol_entry.clone(), dave_entry.clone()],
                vec![],
                vec![],
                vec![],
            )
        };
        store.apply_map(network.clone(), map(), false).unwrap();
        let known = |k: &SigningKey| store.knows(&k.verifying_key().to_bytes()).unwrap();
        assert!(known(&carol) && known(&dave));
        let revoke = |host: Option<String>, invite: Option<String>| {
            store.revoke(
                &id,
                Revoke {
                    revocation: None,
                    host_id: host,
                    invite_public_key: invite,
                },
            )
        };
        assert!(matches!(
            revoke(Some(store.identity().id), None),
            Err(Error::Conflict(_))
        ));
        assert!(matches!(
            revoke(Some("host_unknown".into()), None),
            Err(Error::NotFound)
        ));
        assert!(matches!(revoke(None, None), Err(Error::Invalid(_))));
        let carol_id = key_id(carol.verifying_key().as_bytes());
        let (revoked, body) = revoke(Some(carol_id.clone()), None).unwrap();
        assert_eq!(
            (revoked.kind.as_str(), revoked.subject.clone()),
            ("host", key(&carol))
        );
        assert_eq!(body["kind"], "host");
        assert!(!known(&carol));
        // Pending until the coordinator lists it; a repeat returns the same statement.
        assert_eq!(
            store
                .pending_revocations(&id, &BTreeSet::new())
                .unwrap()
                .len(),
            1
        );
        let listed = BTreeSet::from([("host".to_owned(), key(&carol))]);
        assert!(store.pending_revocations(&id, &listed).unwrap().is_empty());
        assert_eq!(
            revoke(Some(carol_id), None).unwrap().1["statement"],
            body["statement"]
        );
        // A coordinator map that still lists carol cannot restore her.
        store.apply_map(network.clone(), map(), false).unwrap();
        assert!(!known(&carol) && known(&dave));
        // Revoking an invite drops the host that joined with it; not our own invite.
        let own_invite = store
            .own_membership(&id)
            .unwrap()
            .unwrap()
            .invite_public_key;
        assert!(matches!(
            revoke(None, Some(own_invite)),
            Err(Error::Conflict(_))
        ));
        let dave_invite = dave_entry["membership"]["invite_public_key"]
            .as_str()
            .unwrap()
            .to_owned();
        revoke(None, Some(dave_invite)).unwrap();
        assert!(!known(&dave));

        // Rotation persists the new seed, epoch, and attestations; new invites
        // are signed by the new root and still decode.
        let (_, pending) = store.prepare_rotation(&id, None).unwrap();
        let (rotation, attestations) = (pending.rotation.clone(), pending.attestations.clone());
        let next = membership::seed(&pending.root_seed).unwrap();
        assert_eq!(rotation.epoch, 1);
        assert_eq!(
            attestations.len(),
            1,
            "only current valid members are attested"
        );
        assert_eq!(attestations[0].host_public_key, key(&me));
        store.commit_rotation(&id, &pending).unwrap();
        let rotated = store.network(&id).unwrap();
        assert_eq!(
            (rotated.root_epoch, rotated.current_root_public_key.clone()),
            (1, key(&next))
        );
        assert_eq!(rotated.root_public_key, key(&root));
        let issued = store
            .issue_invite(
                &id,
                CreateInvite {
                    token: None,
                    member: "erin".into(),
                    expires_at: rfc3339(chrono::Utc::now() + chrono::TimeDelta::days(1)),
                    host_only: true,
                },
            )
            .unwrap();
        let token = InviteToken::decode(&issued.token).unwrap();
        assert_eq!(token.root_public_key, key(&next));
        assert_eq!(token.network_id, id);
        // The rotated chain still accepts our own attested membership.
        store
            .apply_map(
                network.clone(),
                wire(
                    &network,
                    vec![own.clone()],
                    vec![json_value!(rotation)],
                    vec![json_value!(attestations[0])],
                    vec![],
                ),
                false,
            )
            .unwrap();

        // A member leaves locally; the administrator cannot.
        store.forget_network(&id).unwrap();
        assert!(store.networks().unwrap().is_empty());
        let kinds: Vec<_> = store
            .events(0, 100)
            .unwrap()
            .into_iter()
            .map(|e| e.kind)
            .collect();
        for kind in [
            "network.host_revoked",
            "network.invite_revoked",
            "network.root_rotated",
            "network.left",
        ] {
            assert!(kinds.contains(&kind.to_owned()), "{kind}");
        }
        let joined = Store::open(&temporary.path().join("member")).unwrap();
        let member_network = Network {
            administrator: false,
            ..network.clone()
        };
        let member_own = rooted_entry(
            &id,
            &root,
            &SigningKey::from_bytes(&joined.signing_key.to_bytes()),
        );
        joined
            .apply_map(
                member_network.clone(),
                wire(&member_network, vec![member_own], vec![], vec![], vec![]),
                true,
            )
            .unwrap();
        assert!(matches!(
            joined.revoke(
                &id,
                Revoke {
                    revocation: None,
                    host_id: Some(store.identity().id),
                    invite_public_key: None
                }
            ),
            Err(Error::Forbidden)
        ));
    }

    #[test]
    fn pending_rotation_survives_a_crash_after_acceptance() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("admin");
        let store = Store::open(&path).unwrap();
        let network = store
            .create_network(CreateNetwork {
                name: "team".into(),
                member: "alice".into(),
                coordinator_address: "127.0.0.1:1".into(),
                coordinator_public_key: key(&random_seed().unwrap()),
                person_public_key: None,
            })
            .unwrap();
        let id = network.id.clone();
        let root = store
            .current_root(&store.connection().unwrap(), &id)
            .unwrap();
        let own = json_value!({"host_id": store.identity().id, "membership": store.own_membership(&id).unwrap(), "address": "", "updated_at": "2026-10-05T00:00:00Z"});
        store
            .apply_map(
                network.clone(),
                wire(&network, vec![own.clone()], vec![], vec![], vec![]),
                false,
            )
            .unwrap();
        // Signed and persisted as pending; the old root stays current locally.
        let (_, pending) = store.prepare_rotation(&id, None).unwrap();
        let (_, again) = store.prepare_rotation(&id, None).unwrap();
        assert_eq!(
            again.rotation, pending.rotation,
            "a repeated command resubmits the same rotation"
        );
        assert_eq!(
            store.network(&id).unwrap().current_root_public_key,
            key(&root)
        );
        assert_eq!(
            store
                .current_root(&store.connection().unwrap(), &id)
                .unwrap()
                .to_bytes(),
            root.to_bytes()
        );
        let stored: String = store
            .connection()
            .unwrap()
            .query_row(
                "SELECT record FROM network_statements WHERE network_id = ?1 AND kind = 'pending_rotation' AND subject = '1'",
                [&id],
                |r| r.get(0),
            )
            .unwrap();
        let stored: Value = serde_json::from_str(&stored).unwrap();
        assert_eq!(stored["root_seed"], pending.root_seed);
        // The coordinator accepted it, then this host crashed before committing.
        drop(store);
        let store = Store::open(&path).unwrap();
        let accepted = wire(
            &network,
            vec![own.clone()],
            vec![json_value!(pending.rotation)],
            pending
                .attestations
                .iter()
                .map(|a| json_value!(a))
                .collect(),
            vec![],
        );
        store.apply_map(network.clone(), accepted, false).unwrap();
        // The served chain already holds the pending rotation, so the next sync commits it.
        assert!(matches!(
            store
                .resolve_rotation(&id, std::slice::from_ref(&pending.rotation))
                .unwrap(),
            PendingOutcome::Committed
        ));
        let next = membership::seed(&pending.root_seed).unwrap();
        let rotated = store.network(&id).unwrap();
        assert_eq!(
            (rotated.root_epoch, rotated.current_root_public_key),
            (1, key(&next))
        );
        assert_eq!(
            store
                .current_root(&store.connection().unwrap(), &id)
                .unwrap()
                .to_bytes(),
            next.to_bytes()
        );
        assert!(
            store
                .pending_rotation(&store.connection().unwrap(), &id)
                .unwrap()
                .is_none()
        );
        let kinds: Vec<_> = store
            .events(0, 100)
            .unwrap()
            .into_iter()
            .map(|e| e.kind)
            .collect();
        assert_eq!(
            kinds
                .iter()
                .filter(|k| *k == "network.root_rotated")
                .count(),
            1
        );
        assert!(matches!(
            store
                .resolve_rotation(&id, std::slice::from_ref(&pending.rotation))
                .unwrap(),
            PendingOutcome::None
        ));

        // A pending rotation the coordinator has not seen is resubmitted; one
        // superseded by a different rotation at that epoch is discarded.
        let (_, second) = store.prepare_rotation(&id, None).unwrap();
        assert_eq!(second.rotation.epoch, 2);
        assert!(matches!(
            store.resolve_rotation(&id, std::slice::from_ref(&pending.rotation)).unwrap(),
            PendingOutcome::Resubmit(p) if p.rotation == second.rotation
        ));
        let other = Rotation::sign(
            &next,
            &id,
            2,
            &key(&random_seed().unwrap()),
            "2026-10-07T00:00:00Z",
        );
        assert!(matches!(
            store
                .resolve_rotation(&id, &[pending.rotation.clone(), other])
                .unwrap(),
            PendingOutcome::Discarded
        ));
        assert!(
            store
                .pending_rotation(&store.connection().unwrap(), &id)
                .unwrap()
                .is_none()
        );
        assert_eq!(store.network(&id).unwrap().root_epoch, 1);

        // 400 and 409 discard for good; 403, 5xx, and unreachable keep it pending.
        assert_eq!(rotation_response(200), RotationResponse::Accept);
        for status in [400, 409] {
            assert_eq!(
                rotation_response(status),
                RotationResponse::Discard,
                "{status}"
            );
        }
        for status in [403, 404, 500, 502, 503] {
            assert_eq!(
                rotation_response(status),
                RotationResponse::Keep,
                "{status}"
            );
        }
        store.prepare_rotation(&id, None).unwrap();
        let discarded = store
            .discard_rotation_with_error(&id, "invalid request: bad attestation")
            .unwrap();
        assert_eq!(
            discarded.last_sync_error.as_deref(),
            Some("root rotation discarded: invalid request: bad attestation")
        );
        assert!(
            store
                .pending_rotation(&store.connection().unwrap(), &id)
                .unwrap()
                .is_none()
        );
        assert_eq!(store.network(&id).unwrap().root_epoch, 1);
    }

    #[test]
    fn version_two_state_migrates_to_latest() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("host");
        let identity = Store::open(&path).unwrap().identity();
        let connection = Connection::open(path.join("host.db")).unwrap();
        connection
            .execute_batch(
                "DROP TABLE oauth_credentials; DROP TABLE oauth_clients; DROP TABLE dec_contexts; DROP TABLE dec_objects; DROP TABLE dec_admissions; DROP TABLE dec_restrictions; DROP TABLE dec_activations; DROP TABLE dec_heads; DROP TABLE dec_highwater; DROP TABLE dec_signers; DROP TABLE dec_clock; DROP TABLE dec_intents; DROP TABLE dec_pending; DROP TABLE dec_frames; DROP TABLE dec_operations; DROP TABLE dec_outbox; DROP TABLE dec_migrations; DROP TABLE dec_contacts; DROP TABLE dec_helpers; DROP TABLE builtin_sources; DROP TABLE approval_notices; DROP TABLE call_approvals; DROP TABLE link_signers; DROP TABLE link_highwater; DROP TABLE link_features; DROP TABLE link_objects; DROP TABLE link_operations; DROP TABLE link_frames; DROP TABLE link_pending; DROP TABLE link_device_keys; DROP TABLE call_update_notifications; DROP TABLE adapter_calls; DROP TABLE policy_edits; DROP TABLE outbound_calls; DROP TABLE received_calls; DROP TABLE source_access; DROP TABLE capabilities; DROP TABLE tool_values; DROP TABLE tool_servers; DROP TABLE directory_sends; DROP TABLE policy_deliveries; DROP TABLE task_children; DROP TABLE task_artifacts; DROP TABLE artifact_files; DROP TABLE task_update_notifications; DROP TABLE task_deliveries; DROP TABLE outbound_task_events; DROP TABLE outbound_tasks; DROP TABLE task_events; DROP TABLE received_tasks; DROP TABLE access_blocks; DROP TABLE network_statements; DROP TABLE adapter_connections; DROP TABLE adapter_outbound; DROP TABLE adapter_routes; DROP TABLE outbound_replies; DROP TABLE received_replies; DROP TABLE deliveries; DROP TABLE adapter_credentials; DROP TABLE network_members; DROP TABLE networks; PRAGMA user_version = 2;",
            )
            .unwrap();
        drop(connection);
        let store = Store::open(&path).unwrap();
        assert_eq!(store.identity(), identity);
        assert!(store.networks().unwrap().is_empty());
        let version: i64 = store
            .connection()
            .unwrap()
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, 23);
        drop(store);
        Connection::open(path.join("host.db"))
            .unwrap()
            .execute_batch("PRAGMA user_version = 24;")
            .unwrap();
        assert!(Store::open(&path).is_err());
    }
}
