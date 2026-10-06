//! Persons: OpenSSH `ssh-ed25519` keys that administrators admit and that
//! bind already-admitted hosts. Root and invite statements use raw Ed25519;
//! person statements use OpenSSH `SSHSIG` so a key can stay in `ssh-agent`.
//! Daemons only verify person signatures; the CLI produces them.
use crate::{
    membership::{
        self, check_network, invalid, label, public_key, sign_lines, split_host_port, time,
        verify_lines,
    },
    model::Error,
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256, Sha512};
use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    time::Duration,
};

pub const NAMESPACE: &str = "capsule-person-v1";
pub const PERSON_TOKEN_PREFIX: &str = "capsule-person-invite-v1.";
pub const DESCRIPTOR_PREFIX: &str = "capsule-network-v1.";
const KEY_TYPE: &str = "ssh-ed25519";

pub fn person_id(key: &[u8]) -> String {
    format!("person_{}", hex::encode(Sha256::digest(key)))
}
/// The person ID for a canonical Base64 person key.
pub fn person_id_of(key: &str) -> Result<String, Error> {
    Ok(person_id(public_key(key)?.as_bytes()))
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}
/// Reads length-prefixed SSH wire fields.
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.0.len() < n {
            return Err(invalid("truncated SSH data"));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }
    fn string(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    fn done(&self) -> Result<(), Error> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(invalid("trailing SSH data"))
        }
    }
}

/// The OpenSSH public key blob for an Ed25519 key.
pub fn ssh_public_blob(key: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    put_string(&mut out, KEY_TYPE.as_bytes());
    put_string(&mut out, key);
    out
}
fn parse_public_blob(blob: &[u8]) -> Result<[u8; 32], Error> {
    let mut r = Reader(blob);
    if r.string()? != KEY_TYPE.as_bytes() {
        return Err(invalid("person keys must be ssh-ed25519"));
    }
    let key: [u8; 32] = r
        .string()?
        .try_into()
        .map_err(|_| invalid("invalid ssh-ed25519 key length"))?;
    r.done()?;
    VerifyingKey::from_bytes(&key).map_err(|_| invalid("invalid ssh-ed25519 key"))?;
    Ok(key)
}
/// `ssh-ed25519 AAAA… [comment]` for a raw Ed25519 key.
pub fn ssh_public_line(key: &[u8]) -> String {
    format!("{KEY_TYPE} {}", STANDARD.encode(ssh_public_blob(key)))
}
/// Parses an OpenSSH public key line; only `ssh-ed25519` is accepted.
pub fn parse_ssh_public_line(line: &str) -> Result<[u8; 32], Error> {
    let mut parts = line.split_whitespace();
    if parts.next() != Some(KEY_TYPE) {
        return Err(invalid("person keys must be ssh-ed25519"));
    }
    let blob = STANDARD
        .decode(
            parts
                .next()
                .ok_or_else(|| invalid("missing SSH key data"))?,
        )
        .map_err(|_| invalid("invalid SSH key data"))?;
    parse_public_blob(&blob)
}
/// Accepts a person key as canonical Base64 of the raw 32 bytes or as an
/// OpenSSH `ssh-ed25519` public key line, and returns canonical Base64.
pub fn normalize_person_key(value: &str) -> Result<String, Error> {
    let value = value.trim();
    if value.starts_with(KEY_TYPE) {
        return Ok(STANDARD.encode(parse_ssh_public_line(value)?));
    }
    public_key(value)?;
    Ok(value.to_owned())
}

/// The bytes an `SSHSIG` signature covers for `message`.
pub fn signed_data(message: &[u8]) -> Vec<u8> {
    let mut out = b"SSHSIG".to_vec();
    put_string(&mut out, NAMESPACE.as_bytes());
    put_string(&mut out, b"");
    put_string(&mut out, b"sha512");
    put_string(&mut out, &Sha512::digest(message));
    out
}
/// Standard Base64 of the binary `SSHSIG` blob for an Ed25519 signature.
fn sshsig_blob(key: &[u8], ed25519_signature: &[u8]) -> String {
    let mut sig = Vec::new();
    put_string(&mut sig, KEY_TYPE.as_bytes());
    put_string(&mut sig, ed25519_signature);
    let mut out = b"SSHSIG".to_vec();
    out.extend_from_slice(&1u32.to_be_bytes());
    put_string(&mut out, &ssh_public_blob(key));
    put_string(&mut out, NAMESPACE.as_bytes());
    put_string(&mut out, b"");
    put_string(&mut out, b"sha512");
    put_string(&mut out, &sig);
    STANDARD.encode(out)
}
/// Verifies a person's `SSHSIG` over `lines` joined with `\n`.
pub fn verify_sshsig(person_key: &str, lines: &[&str], signature_b64: &str) -> Result<(), Error> {
    let expected = public_key(person_key)?;
    let blob = STANDARD
        .decode(signature_b64)
        .map_err(|_| invalid("invalid SSHSIG encoding"))?;
    if STANDARD.encode(&blob) != signature_b64 {
        return Err(invalid("non-canonical SSHSIG encoding"));
    }
    let mut r = Reader(&blob);
    if r.take(6)? != b"SSHSIG" || r.u32()? != 1 {
        return Err(invalid("not an SSHSIG version 1 signature"));
    }
    if parse_public_blob(r.string()?)? != *expected.as_bytes() {
        return Err(invalid("SSHSIG key is not the person key"));
    }
    if r.string()? != NAMESPACE.as_bytes() {
        return Err(invalid("wrong SSHSIG namespace"));
    }
    if !r.string()?.is_empty() {
        return Err(invalid("SSHSIG reserved field is not empty"));
    }
    if r.string()? != b"sha512" {
        return Err(invalid("SSHSIG hash must be sha512"));
    }
    let mut sig = Reader(r.string()?);
    r.done()?;
    if sig.string()? != KEY_TYPE.as_bytes() {
        return Err(invalid("SSHSIG signature must be ssh-ed25519"));
    }
    let raw: [u8; 64] = sig
        .string()?
        .try_into()
        .map_err(|_| invalid("invalid Ed25519 signature length"))?;
    sig.done()?;
    expected
        .verify_strict(
            &signed_data(lines.join("\n").as_bytes()),
            &ed25519_dalek::Signature::from_bytes(&raw),
        )
        .map_err(|_| invalid("invalid person signature"))
}

/// Produces person `SSHSIG` signatures from an agent identity or a key file.
pub enum PersonSigner {
    /// An `ssh-agent` identity, by its public key blob.
    Agent {
        socket: std::path::PathBuf,
        key: [u8; 32],
    },
    /// An unencrypted OpenSSH private key file.
    File(SigningKey),
}
impl PersonSigner {
    /// Without a path, the only `ssh-ed25519` identity in `SSH_AUTH_SOCK`.
    /// A path names a public key (select that agent identity) or an
    /// unencrypted OpenSSH private key (sign without an agent).
    pub fn open(path: Option<&Path>) -> Result<Self, Error> {
        let socket = || {
            std::env::var_os("SSH_AUTH_SOCK")
                .filter(|s| !s.is_empty())
                .map(std::path::PathBuf::from)
                .ok_or_else(|| invalid("no ssh-agent: SSH_AUTH_SOCK is not set; use --person-key"))
        };
        match path {
            Some(path) => {
                let text = std::fs::read_to_string(path)
                    .map_err(|e| invalid(&format!("cannot read person key: {e}")))?;
                if text.contains("BEGIN OPENSSH PRIVATE KEY") {
                    Ok(Self::File(parse_openssh_private_key(&text)?))
                } else {
                    let key = parse_ssh_public_line(text.trim())?;
                    let socket = socket()?;
                    if !agent_identities(&socket)?.contains(&key) {
                        return Err(invalid("the ssh-agent does not hold that person key"));
                    }
                    Ok(Self::Agent { socket, key })
                }
            }
            None => {
                let socket = socket()?;
                let keys = agent_identities(&socket)?;
                match keys.as_slice() {
                    [key] => Ok(Self::Agent { socket, key: *key }),
                    [] => Err(invalid("the ssh-agent holds no ssh-ed25519 identity")),
                    _ => Err(invalid(
                        "the ssh-agent holds several ssh-ed25519 identities; choose one with --person-key",
                    )),
                }
            }
        }
    }
    pub fn public_key(&self) -> [u8; 32] {
        match self {
            Self::Agent { key, .. } => *key,
            Self::File(key) => key.verifying_key().to_bytes(),
        }
    }
    pub fn public_key_b64(&self) -> String {
        STANDARD.encode(self.public_key())
    }
    /// The `SSHSIG` for `lines` joined with `\n`, as standard Base64.
    pub fn sign(&self, lines: &[&str]) -> Result<String, Error> {
        let data = signed_data(lines.join("\n").as_bytes());
        let raw = match self {
            Self::File(key) => key.sign(&data).to_bytes().to_vec(),
            Self::Agent { socket, key } => agent_sign(socket, key, &data)?,
        };
        Ok(sshsig_blob(&self.public_key(), &raw))
    }
}

fn agent_error(e: impl std::fmt::Display) -> Error {
    invalid(&format!("ssh-agent: {e}"))
}
fn agent_call(socket: &Path, request: &[u8]) -> Result<Vec<u8>, Error> {
    let mut stream = UnixStream::connect(socket).map_err(agent_error)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(agent_error)?;
    let mut framed = (request.len() as u32).to_be_bytes().to_vec();
    framed.extend_from_slice(request);
    stream.write_all(&framed).map_err(agent_error)?;
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).map_err(agent_error)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > 256 * 1024 {
        return Err(agent_error("invalid response length"));
    }
    let mut response = vec![0u8; length];
    stream.read_exact(&mut response).map_err(agent_error)?;
    Ok(response)
}
/// The agent's `ssh-ed25519` identities (SSH2_AGENTC_REQUEST_IDENTITIES).
fn agent_identities(socket: &Path) -> Result<Vec<[u8; 32]>, Error> {
    let response = agent_call(socket, &[11])?;
    let mut r = Reader(&response);
    if r.take(1)? != [12] {
        return Err(agent_error("identities request failed"));
    }
    let count = r.u32()?;
    let mut keys = Vec::new();
    for _ in 0..count {
        let blob = r.string()?;
        r.string()?;
        if let Ok(key) = parse_public_blob(blob)
            && !keys.contains(&key)
        {
            keys.push(key);
        }
    }
    Ok(keys)
}
/// An Ed25519 signature over `data` from the agent (SSH2_AGENTC_SIGN_REQUEST).
fn agent_sign(socket: &Path, key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut request = vec![13];
    put_string(&mut request, &ssh_public_blob(key));
    put_string(&mut request, data);
    request.extend_from_slice(&0u32.to_be_bytes());
    let response = agent_call(socket, &request)?;
    let mut r = Reader(&response);
    if r.take(1)? != [14] {
        return Err(agent_error("the agent refused to sign"));
    }
    let mut sig = Reader(r.string()?);
    if sig.string()? != KEY_TYPE.as_bytes() {
        return Err(agent_error("unexpected signature type"));
    }
    let raw = sig.string()?;
    if raw.len() != 64 {
        return Err(agent_error("invalid signature length"));
    }
    Ok(raw.to_vec())
}
/// Parses an unencrypted OpenSSH `ssh-ed25519` private key file.
pub fn parse_openssh_private_key(text: &str) -> Result<SigningKey, Error> {
    let body: String = text
        .lines()
        .map(str::trim)
        .skip_while(|l| *l != "-----BEGIN OPENSSH PRIVATE KEY-----")
        .skip(1)
        .take_while(|l| *l != "-----END OPENSSH PRIVATE KEY-----")
        .collect();
    let data = STANDARD
        .decode(body)
        .map_err(|_| invalid("invalid OpenSSH private key encoding"))?;
    let mut r = Reader(&data);
    if r.take(15)? != b"openssh-key-v1\0" {
        return Err(invalid("not an OpenSSH private key"));
    }
    if r.string()? != b"none" || r.string()? != b"none" {
        return Err(invalid(
            "encrypted OpenSSH private keys are not supported; use ssh-agent",
        ));
    }
    r.string()?;
    if r.u32()? != 1 {
        return Err(invalid("OpenSSH private key must hold exactly one key"));
    }
    let public = parse_public_blob(r.string()?)?;
    let mut private = Reader(r.string()?);
    if private.u32()? != private.u32()? {
        return Err(invalid("corrupt OpenSSH private key"));
    }
    if private.string()? != KEY_TYPE.as_bytes() {
        return Err(invalid("person keys must be ssh-ed25519"));
    }
    if private.string()? != public {
        return Err(invalid("corrupt OpenSSH private key"));
    }
    let pair = private.string()?;
    let seed: [u8; 32] = pair
        .get(..32)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| invalid("corrupt OpenSSH private key"))?;
    let key = SigningKey::from_bytes(&seed);
    if key.verifying_key().to_bytes() != public || pair.get(32..) != Some(&public[..]) {
        return Err(invalid("corrupt OpenSSH private key"));
    }
    Ok(key)
}

/// A root's admission of a person key at an epoch.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PersonAdmission {
    pub network_id: String,
    pub epoch: u64,
    pub person_public_key: String,
    pub member: String,
    pub admitted_at: String,
    pub signature: String,
}
impl PersonAdmission {
    fn lines<'a>(&'a self, epoch: &'a str) -> [&'a str; 6] {
        [
            "capsule-person-admit-v1",
            &self.network_id,
            epoch,
            &self.person_public_key,
            &self.member,
            &self.admitted_at,
        ]
    }
    pub fn sign(
        root: &SigningKey,
        network: &str,
        epoch: u64,
        person: &str,
        member: &str,
        at: &str,
    ) -> Self {
        let mut s = Self {
            network_id: network.into(),
            epoch,
            person_public_key: person.into(),
            member: member.into(),
            admitted_at: at.into(),
            signature: String::new(),
        };
        let epoch_text = epoch.to_string();
        s.signature = sign_lines(root, &s.lines(&epoch_text));
        s
    }
    /// Valid only at the current epoch under the current root.
    pub fn verify(&self, network: &str, epoch: u64, root: &str) -> Result<(), Error> {
        check_network(&self.network_id, network)?;
        if self.epoch != epoch {
            return Err(invalid("admission is for another epoch"));
        }
        label(&self.member)?;
        time(&self.admitted_at)?;
        public_key(&self.person_public_key)?;
        let epoch_text = epoch.to_string();
        verify_lines(root, &self.lines(&epoch_text), &self.signature)
    }
}

/// A root's admission of a host key at an epoch, in place of an invite chain.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostAdmission {
    pub network_id: String,
    pub epoch: u64,
    pub host_public_key: String,
    pub member: String,
    pub admitted_at: String,
    pub signature: String,
}
impl HostAdmission {
    fn lines<'a>(&'a self, epoch: &'a str) -> [&'a str; 6] {
        [
            "capsule-host-admit-v1",
            &self.network_id,
            epoch,
            &self.host_public_key,
            &self.member,
            &self.admitted_at,
        ]
    }
    pub fn sign(
        root: &SigningKey,
        network: &str,
        epoch: u64,
        host: &str,
        member: &str,
        at: &str,
    ) -> Self {
        let mut s = Self {
            network_id: network.into(),
            epoch,
            host_public_key: host.into(),
            member: member.into(),
            admitted_at: at.into(),
            signature: String::new(),
        };
        let epoch_text = epoch.to_string();
        s.signature = sign_lines(root, &s.lines(&epoch_text));
        s
    }
    /// Returns the admitted host ID; valid only at the current epoch.
    pub fn verify(&self, network: &str, epoch: u64, root: &str) -> Result<String, Error> {
        check_network(&self.network_id, network)?;
        if self.epoch != epoch {
            return Err(invalid("admission is for another epoch"));
        }
        label(&self.member)?;
        time(&self.admitted_at)?;
        let host = public_key(&self.host_public_key)?;
        let epoch_text = epoch.to_string();
        verify_lines(root, &self.lines(&epoch_text), &self.signature)?;
        Ok(crate::peer_store::key_id(host.as_bytes()))
    }
}

fn person_invite_lines<'a>(
    network: &'a str,
    epoch: &'a str,
    invite: &'a str,
    member: &'a str,
    expires: &'a str,
) -> [&'a str; 6] {
    [
        "capsule-person-invite-v1",
        network,
        epoch,
        invite,
        member,
        expires,
    ]
}
/// A person admitted through a one-time invite: root → invite key → person.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PersonMembership {
    pub network_id: String,
    pub member: String,
    pub invite_public_key: String,
    pub invite_expires_at: String,
    pub invite_epoch: u64,
    pub invite_signature: String,
    pub person_public_key: String,
    pub joined_at: String,
    pub person_signature: String,
}
impl PersonMembership {
    fn member_lines(&self) -> [&str; 5] {
        [
            "capsule-person-member-v1",
            &self.network_id,
            &self.invite_public_key,
            &self.person_public_key,
            &self.joined_at,
        ]
    }
    /// Valid only when the invite was signed by the current root at the
    /// current epoch.
    pub fn verify(&self, network: &str, epoch: u64, root: &str) -> Result<(), Error> {
        check_network(&self.network_id, network)?;
        if self.invite_epoch != epoch {
            return Err(invalid("person invite is for another epoch"));
        }
        label(&self.member)?;
        public_key(&self.person_public_key)?;
        let epoch_text = epoch.to_string();
        verify_lines(
            root,
            &person_invite_lines(
                &self.network_id,
                &epoch_text,
                &self.invite_public_key,
                &self.member,
                &self.invite_expires_at,
            ),
            &self.invite_signature,
        )?;
        verify_lines(
            &self.invite_public_key,
            &self.member_lines(),
            &self.person_signature,
        )?;
        if time(&self.joined_at)? > time(&self.invite_expires_at)? {
            return Err(invalid("joined after invite expiry"));
        }
        Ok(())
    }
}

/// A root-signed, permanent removal of a person key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PersonRemoval {
    pub network_id: String,
    pub person_public_key: String,
    pub removed_at: String,
    pub signature: String,
}
impl PersonRemoval {
    fn lines(&self) -> [&str; 4] {
        [
            "capsule-person-remove-v1",
            &self.network_id,
            &self.person_public_key,
            &self.removed_at,
        ]
    }
    pub fn sign(root: &SigningKey, network: &str, person: &str, at: &str) -> Self {
        let mut s = Self {
            network_id: network.into(),
            person_public_key: person.into(),
            removed_at: at.into(),
            signature: String::new(),
        };
        s.signature = sign_lines(root, &s.lines());
        s
    }
    /// Valid when signed by any root of the chain.
    pub fn verify(&self, network: &str, roots: &[String]) -> Result<(), Error> {
        check_network(&self.network_id, network)?;
        public_key(&self.person_public_key)?;
        time(&self.removed_at)?;
        roots
            .iter()
            .find_map(|root| verify_lines(root, &self.lines(), &self.signature).ok())
            .ok_or_else(|| invalid("removal not signed by a network root"))
    }
}

/// A binding of a host to a person, signed by both: the person's `SSHSIG`
/// in `signature`, and the bound host's raw Ed25519 in `host_signature` over
/// the same statement. The host signature makes the host's consent verifiable
/// by every other host, not just asserted by the coordinator.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostBinding {
    pub network_id: String,
    pub person_public_key: String,
    pub host_public_key: String,
    pub bound_at: String,
    pub signature: String,
    /// Empty only between the CLI's person signature and the daemon's own.
    #[serde(default)]
    pub host_signature: String,
}
impl HostBinding {
    fn lines(&self) -> [&str; 5] {
        [
            "capsule-host-bind-v1",
            &self.network_id,
            &self.person_public_key,
            &self.host_public_key,
            &self.bound_at,
        ]
    }
    pub fn sign(signer: &PersonSigner, network: &str, host: &str, at: &str) -> Result<Self, Error> {
        let mut s = Self {
            network_id: network.into(),
            person_public_key: signer.public_key_b64(),
            host_public_key: host.into(),
            bound_at: at.into(),
            signature: String::new(),
            host_signature: String::new(),
        };
        s.signature = signer.sign(&s.lines())?;
        Ok(s)
    }
    /// The person's signature alone, as the CLI hands it to the daemon.
    pub fn verify_person(&self, network: &str) -> Result<(), Error> {
        check_network(&self.network_id, network)?;
        public_key(&self.host_public_key)?;
        time(&self.bound_at)?;
        verify_sshsig(&self.person_public_key, &self.lines(), &self.signature)
    }
    /// Adds the bound host's consent. Refuses a binding of any other key.
    pub fn sign_host(&mut self, host: &SigningKey) -> Result<(), Error> {
        if STANDARD.encode(host.verifying_key().as_bytes()) != self.host_public_key {
            return Err(invalid("the binding names another host"));
        }
        self.host_signature = sign_lines(host, &self.lines());
        Ok(())
    }
    /// Both signatures: the person's `SSHSIG` and the host's Ed25519.
    pub fn verify(&self, network: &str) -> Result<(), Error> {
        self.verify_person(network)?;
        verify_lines(&self.host_public_key, &self.lines(), &self.host_signature)
            .map_err(|_| invalid("invalid host signature on binding"))
    }
}

/// A person's `SSHSIG` statement withdrawing a host, sticky and permanent for
/// that person and host.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostUnbinding {
    pub network_id: String,
    pub person_public_key: String,
    pub host_public_key: String,
    pub unbound_at: String,
    pub signature: String,
}
impl HostUnbinding {
    fn lines(&self) -> [&str; 5] {
        [
            "capsule-host-unbind-v1",
            &self.network_id,
            &self.person_public_key,
            &self.host_public_key,
            &self.unbound_at,
        ]
    }
    pub fn sign(signer: &PersonSigner, network: &str, host: &str, at: &str) -> Result<Self, Error> {
        let mut s = Self {
            network_id: network.into(),
            person_public_key: signer.public_key_b64(),
            host_public_key: host.into(),
            unbound_at: at.into(),
            signature: String::new(),
        };
        s.signature = signer.sign(&s.lines())?;
        Ok(s)
    }
    pub fn verify(&self, network: &str) -> Result<(), Error> {
        check_network(&self.network_id, network)?;
        public_key(&self.host_public_key)?;
        time(&self.unbound_at)?;
        verify_sshsig(&self.person_public_key, &self.lines(), &self.signature)
    }
    /// The `network_statements` subject: one unbinding per person and host.
    pub fn subject(&self) -> String {
        format!("{} {}", self.person_public_key, self.host_public_key)
    }
}

fn encode_prefixed(prefix: &str, value: &impl Serialize) -> String {
    let json = serde_json::to_vec(value).expect("token serializes");
    format!("{prefix}{}", URL_SAFE_NO_PAD.encode(json))
}
fn decode_prefixed<T: DeserializeOwned>(prefix: &str, text: &str, what: &str) -> Result<T, Error> {
    let body = text
        .trim()
        .strip_prefix(prefix)
        .ok_or_else(|| invalid(&format!("not a capsule {what}")))?;
    let json = URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|_| invalid(&format!("invalid {what} encoding")))?;
    if URL_SAFE_NO_PAD.encode(&json) != body {
        return Err(invalid(&format!("invalid {what} encoding")));
    }
    serde_json::from_slice(&json).map_err(|_| invalid(&format!("invalid {what}")))
}

/// A non-secret pointer to a network: enough to find and pin it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub network_id: String,
    pub network_name: String,
    pub root_public_key: String,
    pub coordinator_address: String,
    pub coordinator_public_key: String,
}
impl Descriptor {
    pub fn encode(&self) -> String {
        encode_prefixed(DESCRIPTOR_PREFIX, self)
    }
    /// Decodes and checks a descriptor; the genesis root must derive the ID.
    pub fn decode(text: &str) -> Result<Self, Error> {
        let d: Self = decode_prefixed(DESCRIPTOR_PREFIX, text, "network descriptor")?;
        if membership::network_id(public_key(&d.root_public_key)?.as_bytes()) != d.network_id {
            return Err(invalid("network ID does not match root key"));
        }
        label(&d.network_name)?;
        public_key(&d.coordinator_public_key)?;
        split_host_port(&d.coordinator_address)?;
        Ok(d)
    }
}

/// A one-time person invite token, in the host-invite format plus its epoch.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PersonInviteToken {
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
    pub invite_epoch: u64,
}
impl PersonInviteToken {
    /// Signs a person invite with the current root.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        root: &SigningKey,
        invite: &SigningKey,
        network: &str,
        network_name: &str,
        epoch: u64,
        member: &str,
        expires: &str,
        coordinator_address: &str,
        coordinator_public_key: &str,
    ) -> Self {
        let invite_public_key = STANDARD.encode(invite.verifying_key().as_bytes());
        let epoch_text = epoch.to_string();
        let invite_signature = sign_lines(
            root,
            &person_invite_lines(network, &epoch_text, &invite_public_key, member, expires),
        );
        Self {
            network_id: network.into(),
            network_name: network_name.into(),
            root_public_key: STANDARD.encode(root.verifying_key().as_bytes()),
            coordinator_address: coordinator_address.into(),
            coordinator_public_key: coordinator_public_key.into(),
            member: member.into(),
            invite_public_key,
            invite_seed: STANDARD.encode(invite.to_bytes()),
            invite_expires_at: expires.into(),
            invite_signature,
            invite_epoch: epoch,
        }
    }
    pub fn encode(&self) -> String {
        encode_prefixed(PERSON_TOKEN_PREFIX, self)
    }
    /// Decodes and checks a token without network contact. Its root is the
    /// one that signed the invite: the current root at issue time.
    pub fn decode(text: &str) -> Result<Self, Error> {
        let t: Self = decode_prefixed(PERSON_TOKEN_PREFIX, text, "person invite token")?;
        label(&t.member)?;
        label(&t.network_name)?;
        let epoch_text = t.invite_epoch.to_string();
        verify_lines(
            &t.root_public_key,
            &person_invite_lines(
                &t.network_id,
                &epoch_text,
                &t.invite_public_key,
                &t.member,
                &t.invite_expires_at,
            ),
            &t.invite_signature,
        )?;
        if STANDARD.encode(membership::seed(&t.invite_seed)?.verifying_key().as_bytes())
            != t.invite_public_key
        {
            return Err(invalid("invite seed does not match invite key"));
        }
        if time(&t.invite_expires_at)? <= chrono::Utc::now() {
            return Err(invalid("invite has expired"));
        }
        public_key(&t.coordinator_public_key)?;
        split_host_port(&t.coordinator_address)?;
        Ok(t)
    }
    /// The invite key's signature over a person, completing the chain.
    pub fn redeem(&self, person: &str, joined: &str) -> Result<PersonMembership, Error> {
        public_key(person)?;
        let invite = membership::seed(&self.invite_seed)?;
        let mut m = PersonMembership {
            network_id: self.network_id.clone(),
            member: self.member.clone(),
            invite_public_key: self.invite_public_key.clone(),
            invite_expires_at: self.invite_expires_at.clone(),
            invite_epoch: self.invite_epoch,
            invite_signature: self.invite_signature.clone(),
            person_public_key: person.into(),
            joined_at: joined.into(),
            person_signature: String::new(),
        };
        m.person_signature = sign_lines(&invite, &m.member_lines());
        Ok(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT_SEED: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const NETWORK: &str = "net_34750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e";
    const ROOT: &str = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=";
    const INVITE_SEED: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
    const INVITE: &str = "gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=";
    const HOST: &str = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY/k2NsFGFKyHN9E=";
    const PERSON_SEED: &str = "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU=";
    const PERSON: &str = "bnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/E=";
    const PERSON_SSH: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG56HN0psLeP0Tr0xVmP7/TvKpcWbjym8uT7/M2AUFvx";
    const PERSON_ID: &str =
        "person_7599776c3085e3f9da0d13071eb0b4ab50fd2bf64c06dd92c2365af3a328eca3";
    const AT: &str = "2026-10-08T00:00:00Z";
    const EXPIRES: &str = "2026-11-01T00:00:00Z";
    const ADMIT_SIG: &str =
        "57pOZqduTPBJKqC2gEAjW23pzd7zwul08CTAxX2KBRSlI36JJfb5WNf8x9LOlaLKK1jBL2r72mLJXIkpTYi+BA==";
    const INVITE_SIG: &str =
        "DOs/7yFxVmC3IuPAcfqlF1EDczkw0++1gRZOjIQNCcK7d3nOPFDZoWcnrhMpBIzdLlEF6fR52K45m8TXGKNVAQ==";
    const MEMBER_SIG: &str =
        "FP3SdKMjbdMcRQIsfMffRb6mnyqnDnX4hxj/cTz6DHyWeozcrRxdGU+/lYLEakp8tiS/jwOiCLJA/7DXhfOrDw==";
    const REMOVE_SIG: &str =
        "gIGBRuXaZVCyEU+jkM1JUxo88yDrpZ8k7JbmKGObmeF14QeY2//Wdrn4CgetByjN4szTFbssvtuS6ynt3O8jBA==";
    const HOST_ADMIT_SIG: &str =
        "fYyNXrDCWJs61KeT2macWLkh/D+WVMI1i10iiC2mpFoQ9fz7EhDhy8KXAr+zjRfpdRzhzpGfAfEF4dBcMYGUCw==";
    const BIND_SIG: &str = "U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgbnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/EAAAARY2Fwc3VsZS1wZXJzb24tdjEAAAAAAAAABnNoYTUxMgAAAFMAAAALc3NoLWVkMjU1MTkAAABADAULCAWp02fy0fuxtv6fhaI8PHqxyBPr6SzVcTupgU0xsTYIMciLKFSVOaqYIOshUcKvNhgbAmBsiz6Cbe7UBw==";
    const HOST_SEED: &str = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=";
    const BIND_HOST_SIG: &str =
        "xv+sVNH6/g1gJrknO2ImE97qrROduO2Oe0U4gvqcddbHibmhzR28SRWf7RtYUDizWnWE4Eufy3F1aijw6uvSDg==";
    const UNBIND_SIG: &str = "U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgbnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/EAAAARY2Fwc3VsZS1wZXJzb24tdjEAAAAAAAAABnNoYTUxMgAAAFMAAAALc3NoLWVkMjU1MTkAAABAkiK02ZWdpz63BExI0ccVmkrPSaSUJEVrherPRCB7IWIDjvE6x1VieH2UJnMuWmp5tiXmTHuTs4mxDyehsUr4AA==";

    fn root() -> SigningKey {
        membership::seed(ROOT_SEED).unwrap()
    }
    fn person() -> PersonSigner {
        PersonSigner::File(membership::seed(PERSON_SEED).unwrap())
    }
    fn roots() -> Vec<String> {
        vec![ROOT.to_owned()]
    }

    #[test]
    fn person_keys_ids_and_ssh_lines() {
        assert_eq!(person().public_key_b64(), PERSON);
        assert_eq!(person_id_of(PERSON).unwrap(), PERSON_ID);
        assert_eq!(
            ssh_public_line(&STANDARD.decode(PERSON).unwrap()),
            PERSON_SSH
        );
        assert_eq!(normalize_person_key(PERSON_SSH).unwrap(), PERSON);
        assert_eq!(
            normalize_person_key(&format!("{PERSON_SSH} bob@laptop")).unwrap(),
            PERSON
        );
        assert_eq!(normalize_person_key(PERSON).unwrap(), PERSON);
        assert!(normalize_person_key("ssh-rsa AAAAB3NzaC1yc2E=").is_err());
        // An ssh-ed25519 header with a key blob of another type is refused.
        let mut blob = Vec::new();
        put_string(&mut blob, b"ecdsa-sha2-nistp256");
        put_string(&mut blob, &[0u8; 32]);
        assert!(parse_ssh_public_line(&format!("ssh-ed25519 {}", STANDARD.encode(blob))).is_err());
    }

    #[test]
    fn root_statements_reproduce_the_vectors() {
        let admission = PersonAdmission::sign(&root(), NETWORK, 0, PERSON, "bob", AT);
        assert_eq!(admission.signature, ADMIT_SIG);
        admission.verify(NETWORK, 0, ROOT).unwrap();
        assert!(admission.verify(NETWORK, 1, ROOT).is_err());
        assert!(admission.verify("net_other", 0, ROOT).is_err());
        let mut forged = admission.clone();
        forged.member = "mallory".into();
        assert!(forged.verify(NETWORK, 0, ROOT).is_err());

        let host = HostAdmission::sign(&root(), NETWORK, 0, HOST, "carol", AT);
        assert_eq!(host.signature, HOST_ADMIT_SIG);
        assert_eq!(
            host.verify(NETWORK, 0, ROOT).unwrap(),
            "host_b62e867fa2f33afe62d5d6b1642e1621d543307846b2a57b897e710919b76709"
        );
        let mut forged = host.clone();
        forged.admitted_at = "2026-10-09T00:00:00Z".into();
        assert!(forged.verify(NETWORK, 0, ROOT).is_err());

        let removal = PersonRemoval::sign(&root(), NETWORK, PERSON, AT);
        assert_eq!(removal.signature, REMOVE_SIG);
        removal.verify(NETWORK, &roots()).unwrap();
        assert!(
            removal
                .verify(NETWORK, &[STANDARD.encode([9u8; 32])])
                .is_err()
        );

        let invite = membership::seed(INVITE_SEED).unwrap();
        let token = PersonInviteToken::issue(
            &root(),
            &invite,
            NETWORK,
            "team",
            0,
            "bob",
            EXPIRES,
            "127.0.0.1:7400",
            ROOT,
        );
        assert_eq!(token.invite_public_key, INVITE);
        assert_eq!(token.invite_signature, INVITE_SIG);
        let membership = token.redeem(PERSON, AT).unwrap();
        assert_eq!(membership.person_signature, MEMBER_SIG);
        membership.verify(NETWORK, 0, ROOT).unwrap();
        assert!(membership.verify(NETWORK, 1, ROOT).is_err());
        let mut forged = membership.clone();
        forged.person_public_key = HOST.into();
        assert!(forged.verify(NETWORK, 0, ROOT).is_err());
        let mut late = membership.clone();
        late.joined_at = "2026-12-01T00:00:00Z".into();
        assert!(late.verify(NETWORK, 0, ROOT).is_err());
        let decoded = PersonInviteToken::decode(&token.encode()).unwrap();
        assert_eq!(decoded, token);
        assert!(
            PersonInviteToken::decode(&token.encode().replace("capsule-person", "capsule-host"))
                .is_err()
        );
    }

    #[test]
    fn person_statements_reproduce_the_sshsig_vectors() {
        let mut bind = HostBinding::sign(&person(), NETWORK, HOST, AT).unwrap();
        assert_eq!(bind.signature, BIND_SIG);
        bind.verify_person(NETWORK).unwrap();
        assert!(
            bind.verify(NETWORK).is_err(),
            "a binding without host consent is refused"
        );
        // A host refuses to sign a binding of another key.
        let other = membership::seed(INVITE_SEED).unwrap();
        assert!(bind.clone().sign_host(&other).is_err());
        bind.sign_host(&membership::seed(HOST_SEED).unwrap())
            .unwrap();
        assert_eq!(bind.host_signature, BIND_HOST_SIG);
        bind.verify(NETWORK).unwrap();
        // An invalid or another key's host signature is refused.
        let mut wrong = bind.clone();
        wrong.host_signature = STANDARD.encode(other.sign(b"x").to_bytes());
        assert!(wrong.verify(NETWORK).is_err());
        let mut garbage = bind.clone();
        garbage.host_signature = "AAAA".into();
        assert!(garbage.verify(NETWORK).is_err());
        let unbind = HostUnbinding::sign(&person(), NETWORK, HOST, AT).unwrap();
        assert_eq!(unbind.signature, UNBIND_SIG);
        unbind.verify(NETWORK).unwrap();
        // Tampering with any field fails.
        let mut forged = bind.clone();
        forged.host_public_key = INVITE.into();
        assert!(forged.verify(NETWORK).is_err());
        let mut forged = bind.clone();
        forged.person_public_key = ROOT.into();
        assert!(forged.verify(NETWORK).is_err());
        // An unbinding signature does not verify as a binding.
        let mut swapped = bind.clone();
        swapped.signature = unbind.signature.clone();
        assert!(swapped.verify(NETWORK).is_err());
    }

    fn reencode(blob_b64: &str, edit: impl FnOnce(&mut Vec<u8>)) -> String {
        let mut blob = STANDARD.decode(blob_b64).unwrap();
        edit(&mut blob);
        STANDARD.encode(blob)
    }

    #[test]
    fn sshsig_rejects_wrong_namespace_hash_and_key_type() {
        let lines = ["capsule-host-bind-v1", NETWORK, PERSON, HOST, AT];
        verify_sshsig(PERSON, &lines, BIND_SIG).unwrap();
        // A signature made under another namespace, with the same key.
        let key = membership::seed(PERSON_SEED).unwrap();
        let mut other = b"SSHSIG".to_vec();
        put_string(&mut other, b"file");
        put_string(&mut other, b"");
        put_string(&mut other, b"sha512");
        put_string(&mut other, &Sha512::digest(lines.join("\n").as_bytes()));
        let raw = key.sign(&other).to_bytes();
        let blob = sshsig_blob(&STANDARD.decode(PERSON).unwrap(), &raw);
        let renamed = reencode(&blob, |b| {
            // Swap the namespace field to "file" so the namespace check fails
            // before the signature check.
            let ns = NAMESPACE.as_bytes();
            let at = b.windows(ns.len()).position(|w| w == ns).unwrap();
            b.splice(at - 4..at + ns.len(), {
                let mut v = Vec::new();
                put_string(&mut v, b"file");
                v
            });
        });
        assert!(verify_sshsig(PERSON, &lines, &renamed).is_err());
        assert!(verify_sshsig(PERSON, &lines, &blob).is_err());
        // Wrong hash algorithm name.
        let sha256 = reencode(BIND_SIG, |b| {
            let at = b.windows(6).position(|w| w == b"sha512").unwrap();
            b[at..at + 6].copy_from_slice(b"sha256");
        });
        assert!(verify_sshsig(PERSON, &lines, &sha256).is_err());
        // Wrong embedded key type.
        let rsa = reencode(BIND_SIG, |b| {
            let at = b.windows(11).position(|w| w == b"ssh-ed25519").unwrap();
            b[at..at + 11].copy_from_slice(b"ssh-ed25518");
        });
        assert!(verify_sshsig(PERSON, &lines, &rsa).is_err());
        // Another person's key.
        assert!(verify_sshsig(HOST, &lines, BIND_SIG).is_err());
        // Trailing bytes and non-canonical encodings.
        let trailing = reencode(BIND_SIG, |b| b.push(0));
        assert!(verify_sshsig(PERSON, &lines, &trailing).is_err());
        assert!(verify_sshsig(PERSON, &lines, &format!("{BIND_SIG}=")).is_err());
    }

    #[test]
    fn openssh_private_keys_round_trip_and_reject_encryption() {
        let seed: [u8; 32] = STANDARD.decode(PERSON_SEED).unwrap().try_into().unwrap();
        let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let file = |cipher: &[u8]| {
            let mut private = Vec::new();
            private.extend_from_slice(&[1, 2, 3, 4, 1, 2, 3, 4]);
            put_string(&mut private, b"ssh-ed25519");
            put_string(&mut private, &public);
            put_string(&mut private, &[&seed[..], &public[..]].concat());
            put_string(&mut private, b"test");
            let mut pad = 1u8;
            while private.len() % 8 != 0 {
                private.push(pad);
                pad += 1;
            }
            let mut body = b"openssh-key-v1\0".to_vec();
            put_string(&mut body, cipher);
            put_string(&mut body, b"none");
            put_string(&mut body, b"");
            body.extend_from_slice(&1u32.to_be_bytes());
            put_string(&mut body, &ssh_public_blob(&public));
            put_string(&mut body, &private);
            let encoded = STANDARD.encode(body);
            let lines: Vec<&str> = encoded
                .as_bytes()
                .chunks(70)
                .map(|c| std::str::from_utf8(c).unwrap())
                .collect();
            format!(
                "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
                lines.join("\n")
            )
        };
        let key = parse_openssh_private_key(&file(b"none")).unwrap();
        assert_eq!(key.verifying_key().to_bytes(), public);
        assert!(parse_openssh_private_key(&file(b"aes256-ctr")).is_err());
    }

    #[test]
    fn descriptors_round_trip_and_bind_the_genesis_root() {
        let d = Descriptor {
            network_id: NETWORK.into(),
            network_name: "team".into(),
            root_public_key: ROOT.into(),
            coordinator_address: "127.0.0.1:7400".into(),
            coordinator_public_key: ROOT.into(),
        };
        let encoded = d.encode();
        assert!(encoded.starts_with(DESCRIPTOR_PREFIX));
        assert_eq!(Descriptor::decode(&encoded).unwrap(), d);
        let mut wrong = d.clone();
        wrong.root_public_key = HOST.into();
        assert!(Descriptor::decode(&wrong.encode()).is_err());
        assert!(Descriptor::decode("capsule-network-v1.e30").is_err());
    }

    #[test]
    fn agent_signing_matches_file_signing() {
        // A minimal in-process ssh-agent: identities and Ed25519 signing.
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let key = membership::seed(PERSON_SEED).unwrap();
        let blob = ssh_public_blob(key.verifying_key().as_bytes());
        let server = std::thread::spawn(move || {
            for stream in listener.incoming().take(3) {
                let mut stream = stream.unwrap();
                let mut len = [0u8; 4];
                stream.read_exact(&mut len).unwrap();
                let mut req = vec![0u8; u32::from_be_bytes(len) as usize];
                stream.read_exact(&mut req).unwrap();
                let mut out = Vec::new();
                match req[0] {
                    11 => {
                        out.push(12);
                        out.extend_from_slice(&1u32.to_be_bytes());
                        put_string(&mut out, &blob);
                        put_string(&mut out, b"bob@laptop");
                    }
                    13 => {
                        let mut r = Reader(&req[1..]);
                        assert_eq!(r.string().unwrap(), &blob[..]);
                        let data = r.string().unwrap();
                        let mut sig = Vec::new();
                        put_string(&mut sig, b"ssh-ed25519");
                        put_string(&mut sig, &key.sign(data).to_bytes());
                        out.push(14);
                        put_string(&mut out, &sig);
                    }
                    _ => out.push(5),
                }
                let mut framed = (out.len() as u32).to_be_bytes().to_vec();
                framed.extend_from_slice(&out);
                stream.write_all(&framed).unwrap();
            }
        });
        let signer = PersonSigner::Agent {
            key: agent_identities(&socket).unwrap()[0],
            socket: socket.clone(),
        };
        assert_eq!(signer.public_key_b64(), PERSON);
        let bind = HostBinding::sign(&signer, NETWORK, HOST, AT).unwrap();
        assert_eq!(bind.signature, BIND_SIG);
        let unbind = HostUnbinding::sign(&signer, NETWORK, HOST, AT).unwrap();
        assert_eq!(unbind.signature, UNBIND_SIG);
        server.join().unwrap();
    }
}
