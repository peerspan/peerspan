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

pub const TOKEN_PREFIX: &str = "capsule-invite-v1.";

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

fn invalid(message: &str) -> Error {
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

pub fn invite_statement(network: &str, invite: &str, member: &str, expires: &str) -> String {
    ["capsule-invite-v1", network, invite, member, expires].join("\n")
}
pub fn member_statement(network: &str, invite: &str, host: &str, joined: &str) -> String {
    ["capsule-member-v1", network, invite, host, joined].join("\n")
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
    let network = network_id(root.verifying_key().as_bytes());
    let invite_public_key = STANDARD.encode(invite.verifying_key().as_bytes());
    let statement = invite_statement(&network, &invite_public_key, member, expires);
    Invite {
        invite_signature: STANDARD.encode(root.sign(statement.as_bytes()).to_bytes()),
        network_id: network,
        member: member.into(),
        invite_public_key,
        invite_expires_at: expires.into(),
    }
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
fn verify_invite(
    root: &VerifyingKey,
    network: &str,
    invite: &str,
    member: &str,
    expires: &str,
    sig: &str,
) -> Result<(), Error> {
    if network_id(root.as_bytes()) != network {
        return Err(invalid("network ID does not match root key"));
    }
    label(member)?;
    time(expires)?;
    public_key(invite)?;
    root.verify_strict(
        invite_statement(network, invite, member, expires).as_bytes(),
        &signature(sig)?,
    )
    .map_err(|_| invalid("invalid invite signature"))
}

impl Membership {
    /// Verifies the full chain; returns the member's host ID.
    pub fn verify(&self, root_public_key: &str) -> Result<String, Error> {
        let root = public_key(root_public_key)?;
        verify_invite(
            &root,
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
        invite
            .verify_strict(statement.as_bytes(), &signature(&self.host_signature)?)
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
            .ok_or_else(|| invalid("not a capsule invite token"))?;
        let json = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| invalid("invalid invite token encoding"))?;
        if URL_SAFE_NO_PAD.encode(&json) != body {
            return Err(invalid("invalid invite token encoding"));
        }
        let token: Self =
            serde_json::from_slice(&json).map_err(|_| invalid("invalid invite token"))?;
        let root = public_key(&token.root_public_key)?;
        verify_invite(
            &root,
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
        "3WTE8i0clTO4PNMXiWiCgVkYWUzS8nCySGhYZWXDwBmz7K416+cmh5Qb6mSrCU+MNDuSudNWXklbsCc8m+Y4Cw==";
    const HOST_SIG: &str =
        "YD6gwCNa6yQT1ofoSqCR4iDpvG4887BtCcZsGXebPSfX4siZx6z6XnzY2AYM5GoAzdX1SsNIAG4I/kkkIQLWCg==";

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
