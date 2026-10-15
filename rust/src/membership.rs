//! Signed network membership: root key → one-time invite key → host key.
//! Every host verifies these chains itself; coordination only distributes them.
use crate::{model::Error, peer_store::key_id};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const TOKEN_PREFIX: &str = "peerspan-invite-v1.";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Membership {
    pub network_id: String,
    pub member: String,
    pub invite_public_key: String,
    pub invite_expires_at: String,
    pub invite_signature: String,
    pub host_public_key: String,
    pub joined_at: String,
    pub host_signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InviteToken {
    pub network_id: String,
    pub network_name: String,
    pub root_public_key: String,
    pub coordinator_address: String,
    pub coordinator_public_key: String,
    pub member: String,
    pub invite_public_key: String,
    pub invite_seed: String,
    pub invite_expires_at: String,
    pub invite_signature: String,
}

pub(crate) fn invalid(message: &str) -> Error {
    Error::Invalid(message.into())
}

/// Decodes canonical standard Base64 of exactly `len` bytes.
pub fn canonical(value: &str, len: usize) -> Result<Vec<u8>, Error> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| invalid("invalid Base64"))?;
    if bytes.len() != len || STANDARD.encode(&bytes) != value {
        return Err(invalid("non-canonical Base64 or wrong length"));
    }
    Ok(bytes)
}
pub fn public_key(value: &str) -> Result<VerifyingKey, Error> {
    let bytes: [u8; 32] = canonical(value, 32)?.try_into().expect("checked length");
    VerifyingKey::from_bytes(&bytes).map_err(|_| invalid("invalid public key"))
}
pub fn seed(value: &str) -> Result<SigningKey, Error> {
    let bytes: [u8; 32] = canonical(value, 32)?.try_into().expect("checked length");
    Ok(SigningKey::from_bytes(&bytes))
}
fn signature(value: &str) -> Result<Signature, Error> {
    let bytes: [u8; 64] = canonical(value, 64)?.try_into().expect("checked length");
    Ok(Signature::from_bytes(&bytes))
}
pub fn network_id(root: &[u8]) -> String {
    format!("net_{}", hex::encode(Sha256::digest(root)))
}
pub fn coordinator_id(key: &[u8]) -> String {
    format!("coord_{}", hex::encode(Sha256::digest(key)))
}
pub fn label(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > 128
        || value.trim() != value
        || value.chars().any(|c| c < ' ' || c == '\u{7f}')
    {
        return Err(invalid(
            "labels must be trimmed, 1-128 bytes, without control characters",
        ));
    }
    Ok(())
}
pub fn time(value: &str) -> Result<chrono::DateTime<chrono::Utc>, Error> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|t| t.to_utc())
        .map_err(|_| invalid("invalid RFC3339 time"))
}
/// `HOST:PORT` where HOST is an IP literal (IPv6 bracketed) or a DNS name.
pub fn split_host_port(address: &str) -> Result<(String, u16), Error> {
    let (host, port) = address
        .rsplit_once(':')
        .ok_or_else(|| invalid("address must be HOST:PORT"))?;
    let port: u16 = port
        .parse()
        .ok()
        .filter(|p| *p != 0 && !port.starts_with('+'))
        .ok_or_else(|| invalid("address must have a nonzero port"))?;
    let host = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        Some(v6) => {
            v6.parse::<std::net::Ipv6Addr>()
                .map_err(|_| invalid("invalid IPv6 address"))?;
            v6.to_owned()
        }
        None => {
            if host.is_empty()
                || host.contains(':')
                || !host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
            {
                return Err(invalid("invalid coordinator host"));
            }
            host.to_owned()
        }
    };
    Ok((host, port))
}
/// Advertised peer addresses are `""` or a literal `IP:PORT` with nonzero port.
pub fn advertised(address: &str) -> Result<(), Error> {
    if address.is_empty() {
        return Ok(());
    }
    match address.parse::<std::net::SocketAddr>() {
        Ok(a) if a.port() != 0 => Ok(()),
        _ => Err(invalid("address must be empty or IP:port")),
    }
}

/// A statement digest: lowercase hex SHA-256 of the signed lines joined with
/// `\n`, as an administrator removal lists the statements it keeps.
pub fn statement_digest(lines: &[&str]) -> String {
    hex::encode(Sha256::digest(lines.join("\n").as_bytes()))
}

pub fn invite_statement(network: &str, invite: &str, member: &str, expires: &str) -> String {
    ["peerspan-invite-v1", network, invite, member, expires].join("\n")
}
pub fn member_statement(network: &str, invite: &str, host: &str, joined: &str) -> String {
    ["peerspan-member-v1", network, invite, host, joined].join("\n")
}

/// Root-signed invite fields, before an invite key signs a host.
pub struct Invite {
    pub network_id: String,
    pub member: String,
    pub invite_public_key: String,
    pub invite_expires_at: String,
    pub invite_signature: String,
}
pub fn sign_invite(root: &SigningKey, invite: &SigningKey, member: &str, expires: &str) -> Invite {
    sign_invite_for(
        &network_id(root.verifying_key().as_bytes()),
        root,
        invite,
        member,
        expires,
    )
}
/// Signs an invite with the network's current root, which after a rotation
/// no longer derives the network ID.
pub fn sign_invite_for(
    network: &str,
    root: &SigningKey,
    invite: &SigningKey,
    member: &str,
    expires: &str,
) -> Invite {
    sign_invite_with(network, &KeySigner::Raw(root), invite, member, expires)
        .expect("raw signing cannot fail")
}
/// Signs an invite with a root or an administrator's SSH key.
pub fn sign_invite_with(
    network: &str,
    signer: &KeySigner,
    invite: &SigningKey,
    member: &str,
    expires: &str,
) -> Result<Invite, Error> {
    let network = network.to_owned();
    let invite_public_key = STANDARD.encode(invite.verifying_key().as_bytes());
    let statement = invite_statement(&network, &invite_public_key, member, expires);
    let lines: Vec<&str> = statement.split('\n').collect();
    Ok(Invite {
        invite_signature: signer.sign(&lines)?,
        network_id: network,
        member: member.into(),
        invite_public_key,
        invite_expires_at: expires.into(),
    })
}
pub fn sign_member(invite: Invite, key: &SigningKey, host: &[u8], joined: &str) -> Membership {
    let host_public_key = STANDARD.encode(host);
    let statement = member_statement(
        &invite.network_id,
        &invite.invite_public_key,
        &host_public_key,
        joined,
    );
    Membership {
        network_id: invite.network_id,
        member: invite.member,
        invite_public_key: invite.invite_public_key,
        invite_expires_at: invite.invite_expires_at,
        invite_signature: invite.invite_signature,
        host_public_key,
        joined_at: joined.into(),
        host_signature: STANDARD.encode(key.sign(statement.as_bytes()).to_bytes()),
    }
}
/// Verifies an invite signed by a root that need not derive the network ID:
/// after rotation, invites are signed by the current root of the chain.
fn verify_invite_under(
    root: &str,
    network: &str,
    invite: &str,
    member: &str,
    expires: &str,
    sig: &str,
) -> Result<(), Error> {
    label(member)?;
    time(expires)?;
    public_key(invite)?;
    let statement = invite_statement(network, invite, member, expires);
    let lines: Vec<&str> = statement.split('\n').collect();
    verify_lines(root, &lines, sig).map_err(|_| invalid("invalid invite signature"))
}

impl Membership {
    /// The digest of the invite statement `invite_signature` signs.
    pub fn digest(&self) -> String {
        statement_digest(&[
            "peerspan-invite-v1",
            &self.network_id,
            &self.invite_public_key,
            &self.member,
            &self.invite_expires_at,
        ])
    }
    /// Verifies the full chain under the genesis root, which must derive the
    /// network ID; returns the member's host ID.
    pub fn verify(&self, root_public_key: &str) -> Result<String, Error> {
        if network_id(public_key(root_public_key)?.as_bytes()) != self.network_id {
            return Err(invalid("network ID does not match root key"));
        }
        self.verify_under(root_public_key)
    }
    /// Verifies the chain under any root of the network's root chain.
    /// The signer may also be an administrator's key, for an invite an
    /// administrator signed with `SSHSIG`.
    pub fn verify_under(&self, root_public_key: &str) -> Result<String, Error> {
        public_key(root_public_key)?;
        verify_invite_under(
            root_public_key,
            &self.network_id,
            &self.invite_public_key,
            &self.member,
            &self.invite_expires_at,
            &self.invite_signature,
        )?;
        let invite = public_key(&self.invite_public_key)?;
        let host = public_key(&self.host_public_key)?;
        let statement = member_statement(
            &self.network_id,
            &self.invite_public_key,
            &self.host_public_key,
            &self.joined_at,
        );
        verify_strict_cached(
            &invite,
            statement.as_bytes(),
            &signature(&self.host_signature)?,
        )
        .map_err(|_| invalid("invalid host signature"))?;
        if time(&self.joined_at)? > time(&self.invite_expires_at)? {
            return Err(invalid("joined after invite expiry"));
        }
        Ok(key_id(host.as_bytes()))
    }
}

impl InviteToken {
    pub fn encode(&self) -> String {
        let json = serde_json::to_vec(self).expect("token serializes");
        format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(json))
    }
    /// Decodes and fully checks a token without any network contact.
    pub fn decode(token: &str) -> Result<Self, Error> {
        let body = token
            .strip_prefix(TOKEN_PREFIX)
            .ok_or_else(|| invalid("not a peerspan invite token"))?;
        let json = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| invalid("invalid invite token encoding"))?;
        if URL_SAFE_NO_PAD.encode(&json) != body {
            return Err(invalid("invalid invite token encoding"));
        }
        let token: Self =
            serde_json::from_slice(&json).map_err(|_| invalid("invalid invite token"))?;
        // After a root rotation the invite is signed by the current root, which
        // does not derive the network ID; the joiner checks it against the
        // coordinator's verified root chain before persisting anything.
        // An administrator may sign the invite with `SSHSIG`; the joiner checks
        // the signature now and the signer's authority against the map.
        public_key(&token.root_public_key)?;
        let issuer = crate::persons::sshsig_signer(&token.invite_signature)
            .unwrap_or_else(|| token.root_public_key.clone());
        verify_invite_under(
            &issuer,
            &token.network_id,
            &token.invite_public_key,
            &token.member,
            &token.invite_expires_at,
            &token.invite_signature,
        )?;
        label(&token.network_name)?;
        if STANDARD.encode(seed(&token.invite_seed)?.verifying_key().as_bytes())
            != token.invite_public_key
        {
            return Err(invalid("invite seed does not match invite key"));
        }
        if time(&token.invite_expires_at)? <= chrono::Utc::now() {
            return Err(invalid("invite has expired"));
        }
        public_key(&token.coordinator_public_key)?;
        split_host_port(&token.coordinator_address)?;
        Ok(token)
    }
    pub fn invite(&self) -> Invite {
        Invite {
            network_id: self.network_id.clone(),
            member: self.member.clone(),
            invite_public_key: self.invite_public_key.clone(),
            invite_expires_at: self.invite_expires_at.clone(),
            invite_signature: self.invite_signature.clone(),
        }
    }
}

/// Strict Ed25519 verification, remembering signatures that verified. Every
/// sync re-verifies the whole network map, so without this a map of a few
/// dozen statements costs hundreds of milliseconds per sync (seconds under
/// load in debug builds) for signatures already checked. Verification is a
/// pure function of the key, message, and signature, so a hit is exact.
pub(crate) fn verify_strict_cached(
    key: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), ed25519_dalek::SignatureError> {
    use std::{
        collections::HashSet,
        sync::{Mutex, OnceLock},
    };
    const LIMIT: usize = 16_384;
    static VERIFIED: OnceLock<Mutex<HashSet<[u8; 32]>>> = OnceLock::new();
    let mut digest = Sha256::new();
    digest.update(key.as_bytes());
    digest.update(signature.to_bytes());
    digest.update(message);
    let id: [u8; 32] = digest.finalize().into();
    let verified = VERIFIED.get_or_init(Default::default);
    if verified.lock().is_ok_and(|v| v.contains(&id)) {
        return Ok(());
    }
    key.verify_strict(message, signature)?;
    if let Ok(mut v) = verified.lock() {
        if v.len() >= LIMIT {
            v.clear();
        }
        v.insert(id);
    }
    Ok(())
}

pub(crate) fn sign_lines(key: &SigningKey, lines: &[&str]) -> String {
    STANDARD.encode(key.sign(lines.join("\n").as_bytes()).to_bytes())
}
/// Verifies a signature by `key` over statement lines, in either form: raw
/// Ed25519 (64 bytes) or an `SSHSIG` blob whose embedded key is `key`. Roots
/// may sign either way; administrators always sign with `SSHSIG`.
pub(crate) fn verify_lines(key: &str, lines: &[&str], sig: &str) -> Result<(), Error> {
    match signature(sig) {
        Ok(raw) => verify_strict_cached(&public_key(key)?, lines.join("\n").as_bytes(), &raw)
            .map_err(|_| invalid("invalid statement signature")),
        Err(_) => crate::persons::verify_sshsig(key, lines, sig),
    }
}
/// Verifies an issuer's signature without knowing yet whether the issuer is
/// authorized: a raw signature must be by `root`; an `SSHSIG` is checked
/// against its own embedded key, whose authority the network map settles.
pub(crate) fn verify_issuer(root: &str, lines: &[&str], sig: &str) -> Result<(), Error> {
    match crate::persons::sshsig_signer(sig) {
        Some(signer) => verify_lines(&signer, lines, sig),
        None => verify_lines(root, lines, sig),
    }
}
/// What signs a root or administrator statement: a raw root seed held by this
/// host, or an SSH key (an agent identity or key file) held by the CLI.
pub enum KeySigner<'a> {
    Raw(&'a SigningKey),
    Ssh(&'a crate::persons::PersonSigner),
}
impl KeySigner<'_> {
    pub fn sign(&self, lines: &[&str]) -> Result<String, Error> {
        match self {
            Self::Raw(key) => Ok(sign_lines(key, lines)),
            Self::Ssh(signer) => signer.sign(lines),
        }
    }
    pub fn public_key_b64(&self) -> String {
        match self {
            Self::Raw(key) => STANDARD.encode(key.verifying_key().as_bytes()),
            Self::Ssh(signer) => signer.public_key_b64(),
        }
    }
}
pub(crate) fn check_network(network: &str, expected: &str) -> Result<(), Error> {
    if network != expected {
        return Err(invalid("statement is for another network"));
    }
    Ok(())
}

/// The first line of a coordinator successor statement.
pub const SUCCESSOR_CONTEXT: &str = "peerspan-coordinator-successor-v1";

/// A coordinator identity signed by the previous identity's key, as a
/// coordinator serves it in `successors`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Successor {
    sequence: u64,
    previous_public_key: String,
    address: String,
    public_key: String,
    signed_at: String,
    signature: String,
}

/// The coordinator a network follows once a sync with it succeeds.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoordinatorPending {
    pub address: String,
    pub public_key: String,
    /// The successor's sequence, or the move's sequence for a move.
    pub sequence: u64,
    /// `move` for an administrator-signed move, `successor` for a
    /// coordinator-signed successor chain.
    #[serde(default = "successor_source")]
    pub source: String,
    /// The move's sequence; null for a successor.
    #[serde(default)]
    pub move_sequence: Option<u64>,
}
fn successor_source() -> String {
    SOURCE_SUCCESSOR.to_owned()
}
pub const SOURCE_SUCCESSOR: &str = "successor";
pub const SOURCE_MOVE: &str = "move";
impl CoordinatorPending {
    pub fn is_move(&self) -> bool {
        self.source == SOURCE_MOVE
    }
}

/// Verifies a chain of successors from the pinned coordinator key and
/// returns its last entry. Each signature is by the previous key, sequences
/// increase by exactly 1, and every address is a coordinator address.
pub fn verify_successors(
    pinned: &str,
    chain: &[serde_json::Value],
) -> Result<CoordinatorPending, Error> {
    let bad = || invalid("invalid coordinator successor");
    let mut previous = pinned.to_owned();
    let mut last: Option<CoordinatorPending> = None;
    for value in chain {
        let s: Successor = serde_json::from_value(value.clone()).map_err(|_| bad())?;
        if s.previous_public_key != previous
            || s.sequence == 0
            || last
                .as_ref()
                .is_some_and(|l| l.sequence.checked_add(1) != Some(s.sequence))
        {
            return Err(bad());
        }
        split_host_port(&s.address).map_err(|_| bad())?;
        public_key(&s.public_key).map_err(|_| bad())?;
        let sequence = s.sequence.to_string();
        let lines = [
            SUCCESSOR_CONTEXT,
            &sequence,
            &s.previous_public_key,
            &s.address,
            &s.public_key,
            &s.signed_at,
        ];
        let raw = signature(&s.signature).map_err(|_| bad())?;
        verify_strict_cached(
            &public_key(&s.previous_public_key).map_err(|_| bad())?,
            lines.join("\n").as_bytes(),
            &raw,
        )
        .map_err(|_| bad())?;
        previous.clone_from(&s.public_key);
        last = Some(CoordinatorPending {
            address: s.address,
            public_key: s.public_key,
            sequence: s.sequence,
            source: successor_source(),
            move_sequence: None,
        });
    }
    last.ok_or_else(bad)
}

/// A root-signed revocation of a member host key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostRevocation {
    pub network_id: String,
    pub host_public_key: String,
    pub revoked_at: String,
    pub signature: String,
}
impl HostRevocation {
    pub fn digest(&self) -> String {
        statement_digest(&self.lines())
    }
    fn lines(&self) -> [&str; 4] {
        [
            "peerspan-revoke-host-v1",
            &self.network_id,
            &self.host_public_key,
            &self.revoked_at,
        ]
    }
    pub fn sign(root: &SigningKey, network: &str, host: &str, at: &str) -> Self {
        Self::sign_with(&KeySigner::Raw(root), network, host, at).expect("raw signing")
    }
    pub fn sign_with(
        signer: &KeySigner,
        network: &str,
        host: &str,
        at: &str,
    ) -> Result<Self, Error> {
        let mut r = Self {
            network_id: network.into(),
            host_public_key: host.into(),
            revoked_at: at.into(),
            signature: String::new(),
        };
        r.signature = signer.sign(&r.lines())?;
        Ok(r)
    }
    /// Valid when signed by any root of the chain.
    pub fn verify(&self, network: &str, roots: &[String]) -> Result<(), Error> {
        check_network(&self.network_id, network)?;
        public_key(&self.host_public_key)?;
        time(&self.revoked_at)?;
        roots
            .iter()
            .find_map(|root| verify_lines(root, &self.lines(), &self.signature).ok())
            .ok_or_else(|| invalid("revocation not signed by a network root"))
    }
}

/// A root-signed revocation of an invite key, which also discredits any host
/// that joined with it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InviteRevocation {
    pub network_id: String,
    pub invite_public_key: String,
    pub revoked_at: String,
    pub signature: String,
}
impl InviteRevocation {
    pub fn digest(&self) -> String {
        statement_digest(&self.lines())
    }
    fn lines(&self) -> [&str; 4] {
        [
            "peerspan-revoke-invite-v1",
            &self.network_id,
            &self.invite_public_key,
            &self.revoked_at,
        ]
    }
    pub fn sign(root: &SigningKey, network: &str, invite: &str, at: &str) -> Self {
        Self::sign_with(&KeySigner::Raw(root), network, invite, at).expect("raw signing")
    }
    pub fn sign_with(
        signer: &KeySigner,
        network: &str,
        invite: &str,
        at: &str,
    ) -> Result<Self, Error> {
        let mut r = Self {
            network_id: network.into(),
            invite_public_key: invite.into(),
            revoked_at: at.into(),
            signature: String::new(),
        };
        r.signature = signer.sign(&r.lines())?;
        Ok(r)
    }
    pub fn verify(&self, network: &str, roots: &[String]) -> Result<(), Error> {
        check_network(&self.network_id, network)?;
        public_key(&self.invite_public_key)?;
        time(&self.revoked_at)?;
        roots
            .iter()
            .find_map(|root| verify_lines(root, &self.lines(), &self.signature).ok())
            .ok_or_else(|| invalid("revocation not signed by a network root"))
    }
}

/// A member's own signed departure.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Leave {
    pub network_id: String,
    pub host_public_key: String,
    pub left_at: String,
    pub signature: String,
}
impl Leave {
    fn lines(&self) -> [&str; 4] {
        [
            "peerspan-leave-v1",
            &self.network_id,
            &self.host_public_key,
            &self.left_at,
        ]
    }
    pub fn sign(host: &SigningKey, network: &str, at: &str) -> Self {
        let mut r = Self {
            network_id: network.into(),
            host_public_key: STANDARD.encode(host.verifying_key().as_bytes()),
            left_at: at.into(),
            signature: String::new(),
        };
        r.signature = sign_lines(host, &r.lines());
        r
    }
    pub fn verify(&self, network: &str) -> Result<(), Error> {
        check_network(&self.network_id, network)?;
        time(&self.left_at)?;
        verify_lines(&self.host_public_key, &self.lines(), &self.signature)
    }
}

/// The previous root's signature over its successor.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Rotation {
    pub network_id: String,
    pub epoch: u64,
    pub previous_root_public_key: String,
    pub root_public_key: String,
    pub rotated_at: String,
    pub signature: String,
}
impl Rotation {
    fn verify_with(&self, epoch: &str) -> Result<(), Error> {
        verify_lines(
            &self.previous_root_public_key,
            &[
                "peerspan-root-rotate-v1",
                &self.network_id,
                epoch,
                &self.previous_root_public_key,
                &self.root_public_key,
                &self.rotated_at,
            ],
            &self.signature,
        )
    }
    /// Checks a rotation to `epoch` signed by `previous`, the current root.
    pub fn verify_from(&self, network: &str, epoch: u64, previous: &str) -> Result<(), Error> {
        check_network(&self.network_id, network)?;
        if self.epoch != epoch || self.previous_root_public_key != previous {
            return Err(invalid("rotation does not follow the current root"));
        }
        public_key(&self.root_public_key)?;
        time(&self.rotated_at)?;
        self.verify_with(&epoch.to_string())
    }
    pub fn sign(previous: &SigningKey, network: &str, epoch: u64, root: &str, at: &str) -> Self {
        Self::sign_with(&KeySigner::Raw(previous), network, epoch, root, at).expect("raw signing")
    }
    /// Signed by the previous root, raw or SSH.
    pub fn sign_with(
        previous: &KeySigner,
        network: &str,
        epoch: u64,
        root: &str,
        at: &str,
    ) -> Result<Self, Error> {
        let previous_root_public_key = previous.public_key_b64();
        let epoch_text = epoch.to_string();
        let signature = previous.sign(&[
            "peerspan-root-rotate-v1",
            network,
            &epoch_text,
            &previous_root_public_key,
            root,
            at,
        ])?;
        Ok(Self {
            network_id: network.into(),
            epoch,
            previous_root_public_key,
            root_public_key: root.into(),
            rotated_at: at.into(),
            signature,
        })
    }
}

/// A current root's attestation that a host key is a member at an epoch.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    pub network_id: String,
    pub epoch: u64,
    pub host_public_key: String,
    pub member: String,
    pub attested_at: String,
    pub signature: String,
}
impl Attestation {
    pub fn sign(
        root: &SigningKey,
        network: &str,
        epoch: u64,
        host: &str,
        member: &str,
        at: &str,
    ) -> Self {
        Self::sign_with(&KeySigner::Raw(root), network, epoch, host, member, at)
            .expect("raw signing")
    }
    pub fn sign_with(
        root: &KeySigner,
        network: &str,
        epoch: u64,
        host: &str,
        member: &str,
        at: &str,
    ) -> Result<Self, Error> {
        let epoch_text = epoch.to_string();
        Ok(Self {
            signature: root.sign(&[
                "peerspan-attest-v1",
                network,
                &epoch_text,
                host,
                member,
                at,
            ])?,
            network_id: network.into(),
            epoch,
            host_public_key: host.into(),
            member: member.into(),
            attested_at: at.into(),
        })
    }
    pub fn verify(&self, network: &str, epoch: u64, root: &str) -> Result<(), Error> {
        check_network(&self.network_id, network)?;
        if self.epoch != epoch {
            return Err(invalid("attestation is for another epoch"));
        }
        label(&self.member)?;
        time(&self.attested_at)?;
        public_key(&self.host_public_key)?;
        let epoch_text = epoch.to_string();
        verify_lines(
            root,
            &[
                "peerspan-attest-v1",
                network,
                &epoch_text,
                &self.host_public_key,
                &self.member,
                &self.attested_at,
            ],
            &self.signature,
        )
    }
}

/// Verifies a root chain from the genesis root, which must derive `network`,
/// and returns its roots in epoch order: index `e` is the root of epoch `e`.
pub fn verify_chain(
    network: &str,
    genesis: &str,
    rotations: &[Rotation],
) -> Result<Vec<String>, Error> {
    if network_id(public_key(genesis)?.as_bytes()) != network {
        return Err(invalid("network ID does not match root key"));
    }
    let mut roots = vec![genesis.to_owned()];
    for (index, rotation) in rotations.iter().enumerate() {
        let epoch = index as u64 + 1;
        check_network(&rotation.network_id, network)?;
        if rotation.epoch != epoch
            || rotation.previous_root_public_key != roots[index]
            || roots.contains(&rotation.root_public_key)
        {
            return Err(invalid("root chain is not consecutive"));
        }
        public_key(&rotation.root_public_key)?;
        time(&rotation.rotated_at)?;
        rotation.verify_with(&epoch.to_string())?;
        roots.push(rotation.root_public_key.clone());
    }
    Ok(roots)
}

/// How a coordinator's root chain relates to the chain this host persisted.
#[derive(Debug, PartialEq, Eq)]
pub enum ChainRelation {
    /// Equal to, or extending, the persisted chain.
    Extends,
    /// A consistent prefix: the coordinator is behind this host.
    Behind,
    /// A different rotation at an epoch this host already persisted.
    Fork,
}
pub fn chain_relation(persisted: &[Rotation], offered: &[Rotation]) -> ChainRelation {
    if persisted.iter().zip(offered).any(|(a, b)| a != b) {
        ChainRelation::Fork
    } else if offered.len() < persisted.len() {
        ChainRelation::Behind
    } else {
        ChainRelation::Extends
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT_SEED: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const ROOT: &str = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=";
    const NETWORK: &str = "net_34750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e";
    const INVITE_SEED: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
    const INVITE: &str = "gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=";
    const HOST_SEED: &str = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=";
    const HOST: &str = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY/k2NsFGFKyHN9E=";
    const HOST_ID: &str = "host_b62e867fa2f33afe62d5d6b1642e1621d543307846b2a57b897e710919b76709";
    const INVITE_SIG: &str =
        "jCdKpz/36wwIgHnZmbIALehw0KPuFefRlkKMmgIv3f1aJfCpfqf4bDJm/WUbI2ONX5oW+ZN4i08YSsCWwusCAg==";
    const HOST_SIG: &str =
        "V5T2OGpQUQ7F6923mnjWVeyYGopVhMNz6eLP4V0WQSqlPJHS59w+YE1CSDapAAA3w8dxKqxmVFm0R55l7W8SBw==";

    fn vector() -> Membership {
        let root = seed(ROOT_SEED).unwrap();
        let invite = seed(INVITE_SEED).unwrap();
        let host = seed(HOST_SEED).unwrap();
        let signed = sign_invite(&root, &invite, "alice", "2026-11-01T00:00:00Z");
        sign_member(
            signed,
            &invite,
            host.verifying_key().as_bytes(),
            "2026-10-05T12:00:00Z",
        )
    }

    #[test]
    fn reproduces_contract_test_vectors() {
        let root = seed(ROOT_SEED).unwrap();
        assert_eq!(STANDARD.encode(root.verifying_key().as_bytes()), ROOT);
        assert_eq!(network_id(root.verifying_key().as_bytes()), NETWORK);
        let m = vector();
        assert_eq!(m.network_id, NETWORK);
        assert_eq!(m.invite_public_key, INVITE);
        assert_eq!(m.host_public_key, HOST);
        assert_eq!(m.invite_signature, INVITE_SIG);
        assert_eq!(m.host_signature, HOST_SIG);
        assert_eq!(m.verify(ROOT).unwrap(), HOST_ID);
    }

    #[test]
    fn rejects_each_tampered_field() {
        let other = STANDARD.encode(seed(HOST_SEED).unwrap().verifying_key().as_bytes());
        let tampers: Vec<fn(&mut Membership)> = vec![
            |m| m.network_id = format!("net_{}", "0".repeat(64)),
            |m| m.member = "mallory".into(),
            |m| m.invite_public_key = HOST.into(),
            |m| m.invite_expires_at = "2026-11-02T00:00:00Z".into(),
            |m| m.invite_expires_at = "2026-11-01T00:00:00.0Z".into(),
            |m| m.invite_signature = HOST_SIG.into(),
            |m| m.host_public_key = INVITE.into(),
            |m| m.joined_at = "2026-10-05T12:00:01Z".into(),
            |m| m.host_signature = INVITE_SIG.into(),
        ];
        for tamper in tampers {
            let mut m = vector();
            tamper(&mut m);
            assert!(m.verify(ROOT).is_err(), "{m:?}");
        }
        assert!(vector().verify(&other).is_err());
        // A late join, even when correctly signed, is rejected.
        let invite = seed(INVITE_SEED).unwrap();
        let signed = sign_invite(
            &seed(ROOT_SEED).unwrap(),
            &invite,
            "alice",
            "2026-11-01T00:00:00Z",
        );
        let late = sign_member(signed, &invite, &[3; 32], "2026-11-01T00:00:01Z");
        assert!(late.verify(ROOT).is_err());
    }

    #[test]
    fn rejects_non_canonical_base64_and_bad_labels() {
        // Same bytes with nonzero trailing bits, and missing padding.
        assert!(canonical("iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1x=", 32).is_err());
        assert!(canonical("iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w", 32).is_err());
        assert!(canonical(ROOT, 32).is_ok());
        let mut m = vector();
        m.host_signature = HOST_SIG.replace("==", "");
        assert!(m.verify(ROOT).is_err());
        for bad in ["", " a", "a ", "a\nb", "a\u{7f}", &"x".repeat(129)] {
            assert!(label(bad).is_err(), "{bad:?}");
        }
        assert!(label("alice").is_ok());
    }

    #[test]
    fn token_round_trip_and_tampering() {
        let root = seed(ROOT_SEED).unwrap();
        let invite = seed(INVITE_SEED).unwrap();
        let expires = crate::store::rfc3339(chrono::Utc::now() + chrono::Duration::days(1));
        let signed = sign_invite(&root, &invite, "bob", &expires);
        let token = InviteToken {
            network_id: signed.network_id,
            network_name: "team".into(),
            root_public_key: ROOT.into(),
            coordinator_address: "coord.example:7400".into(),
            coordinator_public_key: HOST.into(),
            member: signed.member,
            invite_public_key: signed.invite_public_key,
            invite_seed: INVITE_SEED.into(),
            invite_expires_at: signed.invite_expires_at,
            invite_signature: signed.invite_signature,
        };
        let encoded = token.encode();
        assert_eq!(InviteToken::decode(&encoded).unwrap(), token);
        let mut wrong_seed = token.clone();
        wrong_seed.invite_seed = HOST_SEED.into();
        let mut wrong_member = token.clone();
        wrong_member.member = "mallory".into();
        let mut bad_address = token.clone();
        bad_address.coordinator_address = "coord.example".into();
        for bad in [wrong_seed, wrong_member, bad_address] {
            assert!(InviteToken::decode(&bad.encode()).is_err());
        }
        assert!(InviteToken::decode(&encoded[1..]).is_err());
        assert!(InviteToken::decode(&format!("{encoded}A")).is_err());
        let expired = sign_invite(&root, &invite, "bob", "2020-01-01T00:00:00Z");
        let mut old = token;
        old.invite_expires_at = expired.invite_expires_at;
        old.invite_signature = expired.invite_signature;
        assert!(InviteToken::decode(&old.encode()).is_err());
    }

    const NEW_ROOT_SEED: &str = "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=";
    const NEW_ROOT: &str = "ypOsFwUYcHHWe4PH/w7+gQjo7EUwV113JoeTM9vavnw=";
    const AT: &str = "2026-10-07T00:00:00Z";

    #[test]
    fn reproduces_statement_test_vectors() {
        let root = seed(ROOT_SEED).unwrap();
        let new_root = seed(NEW_ROOT_SEED).unwrap();
        assert_eq!(
            STANDARD.encode(new_root.verifying_key().as_bytes()),
            NEW_ROOT
        );
        let roots = vec![ROOT.to_owned()];
        let host = HostRevocation::sign(&root, NETWORK, HOST, AT);
        assert_eq!(
            host.signature,
            "jclqdyH6N8H3WoO07mGA1trPc7WpmmvKIH1zibL1m9+zFoIK6ppGXuC7k8oXFhF8IWYtmuGGy70xBTsvkYzSCw=="
        );
        host.verify(NETWORK, &roots).unwrap();
        let invite = InviteRevocation::sign(&root, NETWORK, INVITE, AT);
        assert_eq!(
            invite.signature,
            "pF9qtTO3npiuO+rf47SQ5PpgiSlq6dWYlIQPT+DTFO0PN9Yxf1bmacK83dinaY4qu+KMyk3JNnZW8v1CxZiJCA=="
        );
        invite.verify(NETWORK, &roots).unwrap();
        let leave = Leave::sign(&seed(HOST_SEED).unwrap(), NETWORK, AT);
        assert_eq!(leave.host_public_key, HOST);
        assert_eq!(
            leave.signature,
            "36abHHiIjCXzpVFnssBQAEV+guYtiZGp3hsd5JmpBSH9f8VnZun74fql4G622oBx4aQHZ733k+nSdAfI1xPmDg=="
        );
        leave.verify(NETWORK).unwrap();
        let rotation = Rotation::sign(&root, NETWORK, 1, NEW_ROOT, AT);
        assert_eq!(rotation.previous_root_public_key, ROOT);
        assert_eq!(
            rotation.signature,
            "gbWynmghmMqYfKSbPS5tnw20vNrvq8QqugZ4pJQ1IvhSUy0aO2VLtB7+VPFMJpinw7q+zyG52lMGyfaCSWPbCQ=="
        );
        assert_eq!(
            verify_chain(NETWORK, ROOT, std::slice::from_ref(&rotation)).unwrap(),
            vec![ROOT.to_owned(), NEW_ROOT.to_owned()]
        );
        let attestation = Attestation::sign(&new_root, NETWORK, 1, HOST, "alice", AT);
        assert_eq!(
            attestation.signature,
            "oqBN8M8UY8e9c41wKnms8ZwWoH9zoHjMc0lwYi8iYWtLykbyts25SRgt+s1agJmbBIfGAx8nJp0QaP3yzx1IAw=="
        );
        attestation.verify(NETWORK, 1, NEW_ROOT).unwrap();
        // Strict JSON shapes.
        let value = serde_json::to_value(&rotation).unwrap();
        assert_eq!(value["epoch"], 1);
        let mut extra = value.clone();
        extra["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<Rotation>(extra).is_err());
    }

    #[test]
    fn statements_reject_tampering() {
        let root = seed(ROOT_SEED).unwrap();
        let new_root = seed(NEW_ROOT_SEED).unwrap();
        let roots = vec![ROOT.to_owned()];
        let other = format!("net_{}", "0".repeat(64));
        let mut host = HostRevocation::sign(&root, NETWORK, HOST, AT);
        assert!(host.verify(&other, &roots).is_err());
        host.host_public_key = INVITE.into();
        assert!(host.verify(NETWORK, &roots).is_err());
        // Signed by a key outside the chain.
        let rogue = HostRevocation::sign(&new_root, NETWORK, HOST, AT);
        assert!(rogue.verify(NETWORK, &roots).is_err());
        assert!(
            rogue
                .verify(NETWORK, &[ROOT.into(), NEW_ROOT.into()])
                .is_ok()
        );
        let mut invite = InviteRevocation::sign(&root, NETWORK, INVITE, AT);
        invite.revoked_at = "2026-10-07T00:00:01Z".into();
        assert!(invite.verify(NETWORK, &roots).is_err());
        let mut leave = Leave::sign(&seed(HOST_SEED).unwrap(), NETWORK, AT);
        leave.host_public_key = INVITE.into();
        assert!(leave.verify(NETWORK).is_err());
        let rotation = Rotation::sign(&root, NETWORK, 1, NEW_ROOT, AT);
        let tampers: Vec<fn(&mut Rotation)> = vec![
            |r| r.epoch = 2,
            |r| r.root_public_key = HOST.into(),
            |r| r.previous_root_public_key = HOST.into(),
            |r| r.rotated_at = "2026-10-07T00:00:01Z".into(),
            |r| r.network_id = format!("net_{}", "0".repeat(64)),
        ];
        for tamper in tampers {
            let mut r = rotation.clone();
            tamper(&mut r);
            assert!(verify_chain(NETWORK, ROOT, &[r]).is_err());
        }
        // A rotation signed by the new root itself does not extend the chain.
        let selfsigned = Rotation::sign(&new_root, NETWORK, 1, NEW_ROOT, AT);
        assert!(verify_chain(NETWORK, ROOT, &[selfsigned]).is_err());
        // The genesis root must derive the network ID.
        assert!(verify_chain(NETWORK, NEW_ROOT, &[]).is_err());
        let attestation = Attestation::sign(&new_root, NETWORK, 1, HOST, "alice", AT);
        assert!(attestation.verify(NETWORK, 2, NEW_ROOT).is_err());
        assert!(attestation.verify(NETWORK, 1, ROOT).is_err());
        let mut relabeled = attestation;
        relabeled.member = "mallory".into();
        assert!(relabeled.verify(NETWORK, 1, NEW_ROOT).is_err());
    }

    #[test]
    fn chain_relations_and_rotated_invites() {
        let root = seed(ROOT_SEED).unwrap();
        let new_root = seed(NEW_ROOT_SEED).unwrap();
        let one = Rotation::sign(&root, NETWORK, 1, NEW_ROOT, AT);
        let third = seed(HOST_SEED).unwrap();
        let third_key = STANDARD.encode(third.verifying_key().as_bytes());
        let two = Rotation::sign(&new_root, NETWORK, 2, &third_key, AT);
        let fork = Rotation::sign(&root, NETWORK, 1, &third_key, AT);
        assert_eq!(
            chain_relation(&[], std::slice::from_ref(&one)),
            ChainRelation::Extends
        );
        assert_eq!(
            chain_relation(std::slice::from_ref(&one), std::slice::from_ref(&one)),
            ChainRelation::Extends
        );
        assert_eq!(
            chain_relation(std::slice::from_ref(&one), &[one.clone(), two.clone()]),
            ChainRelation::Extends
        );
        assert_eq!(
            chain_relation(&[one.clone(), two], std::slice::from_ref(&one)),
            ChainRelation::Behind
        );
        assert_eq!(chain_relation(&[one], &[fork]), ChainRelation::Fork);
        // An invite signed by the current root verifies only under that root.
        let invite = seed(INVITE_SEED).unwrap();
        let mut signed = sign_invite(&new_root, &invite, "bob", "2099-01-01T00:00:00Z");
        signed.network_id = NETWORK.into();
        let statement = invite_statement(
            NETWORK,
            &signed.invite_public_key,
            "bob",
            "2099-01-01T00:00:00Z",
        );
        signed.invite_signature = STANDARD.encode(new_root.sign(statement.as_bytes()).to_bytes());
        let m = sign_member(signed, &invite, &[3; 32], "2026-10-07T00:00:00Z");
        assert!(m.verify_under(NEW_ROOT).is_ok());
        assert!(m.verify(NEW_ROOT).is_err());
        assert!(m.verify(ROOT).is_err());
    }

    #[test]
    fn host_port_forms() {
        assert_eq!(
            split_host_port("coord.example:7400").unwrap(),
            ("coord.example".into(), 7400)
        );
        assert_eq!(split_host_port("[::1]:1").unwrap(), ("::1".into(), 1));
        assert_eq!(
            split_host_port("127.0.0.1:9").unwrap(),
            ("127.0.0.1".into(), 9)
        );
        for bad in ["coord", "coord:0", ":80", "::1:80", "a b:80", "c:+80"] {
            assert!(split_host_port(bad).is_err(), "{bad}");
        }
    }
}
