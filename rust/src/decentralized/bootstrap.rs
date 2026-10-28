//! New-context contact and opaque frame primitives. Transport possession and
//! successful decryption never admit a host or establish an authority head.
use super::{codec::*, statement::Descriptor, transcript::Packet};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use ring::{aead, hkdf};
use serde_json::{Value, json, value::RawValue};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const ALPN: &[u8] = b"peerspan-bootstrap/1";
pub const MAX_FRAME_PLAIN: usize = 4 << 20;
pub const MAX_FRAME_POST: usize = 8 << 20;

fn bytes(v: &Value) -> Result<Vec<u8>> {
    serde_json::to_vec(v).map_err(|_| Error::new("internal"))
}
pub fn endpoint(value: &str) -> Result<()> {
    check(value.is_ascii() && !value.is_empty())?;
    require(value.len() <= 260, "quota_exceeded")?;
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (ip, port) = rest.split_once("]:").ok_or_else(|| Error::new("invalid"))?;
        let ip: Ipv6Addr = ip.parse().map_err(|_| Error::new("invalid"))?;
        check(
            !ip.is_unspecified()
                && ip.to_ipv4_mapped().is_none()
                && ip.to_string() == rest[..rest.len() - port.len() - 2],
        )?;
        (None, port)
    } else {
        let (host, port) = value
            .rsplit_once(':')
            .ok_or_else(|| Error::new("invalid"))?;
        check(!host.contains(':'))?;
        (Some(host), port)
    };
    check(
        !port.is_empty() && port.as_bytes()[0] != b'0' && port.bytes().all(|b| b.is_ascii_digit()),
    )?;
    check(port.parse::<u16>().is_ok_and(|p| p > 0))?;
    if let Some(host) = host {
        check(!host.is_empty() && host.len() <= 253)?;
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            check(!ip.is_unspecified() && ip.to_string() == host)?;
        } else {
            // A malformed dotted numeric address is not a DNS spelling alias.
            check(!host.bytes().all(|c| c.is_ascii_digit() || c == b'.'))?;
            for label in host.split('.') {
                check(
                    !label.is_empty()
                        && label.len() <= 63
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                        && label
                            .bytes()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'),
                )?;
            }
            check(host.parse::<IpAddr>().is_err())?;
        }
    }
    Ok(())
}
pub fn helpers(value: &Value) -> Result<Vec<Value>> {
    let list = value.as_array().ok_or_else(|| Error::new("invalid"))?;
    require(list.len() <= 4, "quota_exceeded")?;
    let mut prior = None;
    for entry in list {
        let o = object(entry)?;
        fields(o, "address public_key")?;
        let pair = (text(o, "address")?, text(o, "public_key")?);
        endpoint(pair.0)?;
        check(key(pair.1) && prior.is_none_or(|p| p < pair))?;
        prior = Some(pair);
    }
    Ok(list.clone())
}
/// A contact's window: at most 300 seconds.
fn hint_window(issued: &str, expires: &str, now: &str) -> Result<()> {
    window(issued, expires, now, 1, 300)
}
/// The link request window: `expires_at = created_at + 3600` (wire formats
/// 9.1, DEC-S4/DEC-Q1).
pub(crate) const REQUEST_WINDOW: i64 = 3600;
/// An invite's default lifetime and its bounds (wire formats 10.1, DEC-Q2).
pub(crate) const INVITE_DEFAULT: i64 = 3600;
pub(crate) const INVITE_MIN: i64 = 60;
pub(crate) const INVITE_MAX: i64 = 86400;
/// `issued..expires` lasts `min..=max` seconds, has started (30 seconds of
/// skew) and has not ended at `now`.
fn window(issued: &str, expires: &str, now: &str, min: i64, max: i64) -> Result<()> {
    let issued = stamp(issued)?;
    let expires = stamp(expires)?;
    let now = stamp(now)?;
    check(
        expires > issued
            && expires - issued >= chrono::TimeDelta::seconds(min)
            && expires - issued <= chrono::TimeDelta::seconds(max),
    )?;
    require(
        issued <= now + chrono::TimeDelta::seconds(30),
        "not_yet_valid",
    )?;
    require(now < expires, "expired")
}
#[derive(Clone, Debug)]
pub struct Contact {
    pub body: Vec<u8>,
    pub context_id: String,
    pub host_public_key: String,
    pub sequence: u64,
    pub issued_at: String,
    pub expires_at: String,
    pub payload: Value,
}
impl Contact {
    pub fn read(raw: &[u8]) -> Result<Self> {
        let v = parse(raw, 8 << 10)?;
        let o = object(&v)?;
        fields(
            o,
            "format context_id host_public_key sequence issued_at expires_at payload_base64 signature",
        )?;
        version(o)?;
        let context = text(o, "context_id")?;
        check(context == "-" || ident(context, "ctx_"))?;
        let host = text(o, "host_public_key")?;
        check(key(host))?;
        let seq = num(o, "sequence")?;
        let issued = text(o, "issued_at")?;
        let expires = text(o, "expires_at")?;
        let duration = stamp(expires)? - stamp(issued)?;
        check(duration > chrono::TimeDelta::zero() && duration <= chrono::TimeDelta::seconds(300))?;
        let body = b64(text(o, "payload_base64")?, 8 << 10)?;
        let payload = parse(&body, 8 << 10)?;
        let p = object(&payload)?;
        fields(p, "quic_addresses bootstrap_addresses relays")?;
        let mut count = 0;
        for field in ["quic_addresses", "bootstrap_addresses"] {
            let list = array(p, field)?;
            require(list.len() <= 8, "quota_exceeded")?;
            count += list.len();
            let mut previous = None;
            for addr in list {
                let addr = addr.as_str().ok_or_else(|| Error::new("invalid"))?;
                endpoint(addr)?;
                check(previous.is_none_or(|old| old < addr))?;
                previous = Some(addr);
            }
        }
        let relays = array(p, "relays")?;
        require(relays.len() <= 8, "quota_exceeded")?;
        count += relays.len();
        let mut previous = None;
        for relay in relays {
            let r = object(relay)?;
            fields(r, "address public_key")?;
            let pair = (text(r, "address")?, text(r, "public_key")?);
            endpoint(pair.0)?;
            check(key(pair.1) && previous.is_none_or(|p| p < pair))?;
            previous = Some(pair);
        }
        require(count <= 16, "quota_exceeded")?;
        raw_signature(
            host,
            &lines(&[
                "peerspan-decentralized-contact-v1",
                context,
                host,
                &seq.to_string(),
                issued,
                expires,
                &hash(&body),
            ]),
            text(o, "signature")?,
        )?;
        Ok(Self {
            body: raw.into(),
            context_id: context.into(),
            host_public_key: host.into(),
            sequence: seq,
            issued_at: issued.into(),
            expires_at: expires.into(),
            payload,
        })
    }
    pub fn valid_at(&self, now: &str) -> Result<()> {
        hint_window(&self.issued_at, &self.expires_at, now)
    }
    /// The contact's window shape and start, without its expiry: for an
    /// address hint inside a current invite or request code.
    fn started_by(&self, now: &str) -> Result<()> {
        let issued = stamp(&self.issued_at)?;
        let expires = stamp(&self.expires_at)?;
        check(expires > issued && expires - issued <= chrono::TimeDelta::seconds(300))?;
        require(
            issued <= stamp(now)? + chrono::TimeDelta::seconds(30),
            "not_yet_valid",
        )
    }
    pub fn create(
        key: &SigningKey,
        context: &str,
        sequence: u64,
        issued: &str,
        payload: &Value,
    ) -> Result<Self> {
        let end = (stamp(issued)? + chrono::TimeDelta::seconds(300))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let host = encode(key.verifying_key().as_bytes());
        let raw = bytes(payload)?;
        let message = lines(&[
            "peerspan-decentralized-contact-v1",
            context,
            &host,
            &sequence.to_string(),
            issued,
            &end,
            &hash(&raw),
        ]);
        Self::read(&bytes(
            &json!({"format":1,"context_id":context,"host_public_key":host,"sequence":sequence,"issued_at":issued,"expires_at":end,"payload_base64":encode(&raw),"signature":encode(&key.sign(&message).to_bytes())}),
        )?)
    }
}
/// `hints`: the contacts are address hints inside an invite or request code
/// that is itself within its window. They are used even after their own
/// 300-second expiry (DEC-Q25, DEC-Q33), but must still be well-formed,
/// signed, at most 300 seconds long and not issued in the future.
fn contacts(
    raw: &[u8],
    now: &str,
    writer: Option<&str>,
    context: Option<&str>,
    hints: bool,
) -> Result<Vec<Contact>> {
    let value = parse_array(raw, (32 << 10) + 5)?;
    let list = value.as_array().ok_or_else(|| Error::new("invalid"))?;
    require(list.len() <= 4, "quota_exceeded")?;
    let originals: Vec<&RawValue> =
        serde_json::from_slice(raw).map_err(|_| Error::new("invalid"))?;
    let mut result = Vec::new();
    let mut prior = None;
    let mut semantics = std::collections::BTreeMap::new();
    for (entry, original) in list.iter().zip(originals) {
        let raw = original.get().as_bytes();
        let contact = Contact::read(raw)?;
        if hints {
            contact.started_by(now)?;
        } else {
            contact.valid_at(now)?;
        }
        check(
            writer.is_none_or(|w| w == contact.host_public_key)
                && context.is_none_or(|c| c == contact.context_id),
        )?;
        let ordering = (
            contact.context_id.clone(),
            contact.host_public_key.clone(),
            contact.sequence,
            hash(raw),
        );
        check(prior.as_ref().is_none_or(|p| p < &ordering))?;
        prior = Some(ordering);
        let semantic = (
            contact.context_id.clone(),
            contact.host_public_key.clone(),
            contact.sequence,
        );
        let signed = object(entry)?;
        let identity = (
            text(signed, "issued_at")?.to_owned(),
            text(signed, "expires_at")?.to_owned(),
            text(signed, "payload_base64")?.to_owned(),
        );
        if let Some(old) = semantics.insert(semantic, identity.clone()) {
            check(old == identity)?;
        }
        result.push(contact);
    }
    Ok(result)
}
fn token_body(token: &str, prefix: &str) -> Result<Vec<u8>> {
    require(token.len() <= 32 << 10, "quota_exceeded")?;
    let encoded = token
        .strip_prefix(prefix)
        .ok_or_else(|| Error::new("invalid"))?;
    let raw = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| Error::new("invalid"))?;
    check(URL_SAFE_NO_PAD.encode(&raw) == encoded)?;
    Ok(raw)
}
#[derive(Clone, Debug)]
pub struct Invitation {
    pub body: Vec<u8>,
    pub id: String,
    pub descriptor: Descriptor,
    pub inviter_host_public_key: String,
    pub expected_person_public_key: String,
    pub member: String,
    pub contacts: Vec<Contact>,
    pub helpers: Vec<Value>,
    pub issued_at: String,
    pub expires_at: String,
}
impl Invitation {
    pub fn create(key: &SigningKey, payload: &Value, now: &str) -> Result<(Self, String)> {
        let p = object(payload)?;
        let descriptor =
            Descriptor::from_value(p.get("descriptor").ok_or_else(|| Error::new("invalid"))?)?;
        let context = descriptor.context_id();
        let host = encode(key.verifying_key().as_bytes());
        let raw = bytes(payload)?;
        let message = lines(&[
            "peerspan-decentralized-contact-invitation-v1",
            &context,
            &host,
            &hash(&raw),
        ]);
        let body = bytes(
            &json!({"format":1,"context_id":context,"inviter_host_public_key":host,"payload_base64":encode(&raw),"signature":encode(&key.sign(&message).to_bytes())}),
        )?;
        let token = format!("psi2-{}", URL_SAFE_NO_PAD.encode(&body));
        require(token.len() <= 32 << 10, "quota_exceeded")?;
        Ok((Self::read(&body, now)?, token))
    }
    pub fn read_token(token: &str, now: &str) -> Result<Self> {
        Self::read(&token_body(token, "psi2-")?, now)
    }
    pub fn read(raw: &[u8], now: &str) -> Result<Self> {
        let v = parse(raw, 32 << 10)?;
        let o = object(&v)?;
        fields(
            o,
            "format context_id inviter_host_public_key payload_base64 signature",
        )?;
        version(o)?;
        let host = text(o, "inviter_host_public_key")?;
        check(key(host))?;
        let payload = b64(text(o, "payload_base64")?, 32 << 10)?;
        let p = object(&parse(&payload, 32 << 10)?)?.clone();
        fields(
            &p,
            "descriptor expected_person_public_key member issued_at expires_at contacts helpers",
        )?;
        let descriptor =
            Descriptor::from_value(p.get("descriptor").ok_or_else(|| Error::new("invalid"))?)?;
        let context = descriptor.context_id();
        check(text(o, "context_id")? == context)?;
        let person = text(&p, "expected_person_public_key")?;
        check(person == "-" || key(person))?;
        let member = text(&p, "member")?;
        label(member)?;
        let issued = text(&p, "issued_at")?;
        let expires = text(&p, "expires_at")?;
        window(issued, expires, now, INVITE_MIN, INVITE_MAX)?;
        let contacts = contacts(
            &super::catalog::raw_field(&payload, "contacts")?,
            now,
            Some(host),
            Some(&context),
            true,
        )?;
        let helpers = helpers(p.get("helpers").ok_or_else(|| Error::new("invalid"))?)?;
        let message = lines(&[
            "peerspan-decentralized-contact-invitation-v1",
            &context,
            host,
            &hash(&payload),
        ]);
        raw_signature(host, &message, text(o, "signature")?)?;
        Ok(Self {
            body: raw.into(),
            id: format!("di_{}", hash(&message)),
            descriptor,
            inviter_host_public_key: host.into(),
            expected_person_public_key: person.into(),
            member: member.into(),
            contacts,
            helpers,
            issued_at: issued.into(),
            expires_at: expires.into(),
        })
    }
}
#[derive(Clone)]
pub struct PairingToken {
    pub body: Vec<u8>,
    pub request_id: String,
    pub secret: [u8; 16],
    pub request_packet: Vec<u8>,
    pub contacts: Vec<Contact>,
    pub helpers: Vec<Value>,
}
impl PairingToken {
    /// Identity of the exact signed request carried by this validated token.
    /// Reading it supplies no consent, membership or signer authority.
    pub fn request_packet_id(&self) -> Result<String> {
        Ok(Packet::read(&self.request_packet)?.id)
    }
    pub fn read(token: &str, now: &str) -> Result<Self> {
        let raw = token_body(token, "psl2-")?;
        let v = parse(&raw, 32 << 10)?;
        let o = object(&v)?;
        fields(
            o,
            "format request_id secret_base64 request_packet_base64 contacts helpers",
        )?;
        version(o)?;
        let request = text(o, "request_id")?;
        let secret = b64(text(o, "secret_base64")?, 16)?
            .try_into()
            .map_err(|_| Error::new("invalid"))?;
        let request_packet = b64(text(o, "request_packet_base64")?, 8 << 10)?;
        let packet = Packet::read(&request_packet)?;
        check(
            text(&packet.object, "role")? == "request"
                && text(&packet.object, "request_id")? == request,
        )?;
        window(
            text(&packet.payload, "created_at")?,
            text(&packet.payload, "expires_at")?,
            now,
            REQUEST_WINDOW,
            REQUEST_WINDOW,
        )?;
        let context = text(&packet.payload, "expected_context_id")?;
        let contacts = contacts(
            &super::catalog::raw_field(&raw, "contacts")?,
            now,
            Some(text(&packet.object, "writer_host_public_key")?),
            Some(context),
            true,
        )?;
        let helpers = helpers(o.get("helpers").ok_or_else(|| Error::new("invalid"))?)?;
        Ok(Self {
            body: raw,
            request_id: request.into(),
            secret,
            request_packet,
            contacts,
            helpers,
        })
    }
    pub fn encode(
        secret: &[u8; 16],
        request: &[u8],
        contacts: &[Contact],
        helpers: &[Value],
        now: &str,
    ) -> Result<String> {
        let packet = Packet::read(request)?;
        let originals = contacts
            .iter()
            .map(|contact| {
                let raw =
                    String::from_utf8(contact.body.clone()).map_err(|_| Error::new("invalid"))?;
                RawValue::from_string(raw).map_err(|_| Error::new("invalid"))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut fields = std::collections::BTreeMap::new();
        for (field, value) in [
            ("format", json!(1)),
            ("request_id", json!(text(&packet.object, "request_id")?)),
            ("secret_base64", json!(encode(secret))),
            ("request_packet_base64", json!(encode(request))),
            ("helpers", json!(helpers)),
        ] {
            fields.insert(
                field,
                serde_json::value::to_raw_value(&value).map_err(|_| Error::new("internal"))?,
            );
        }
        fields.insert(
            "contacts",
            serde_json::value::to_raw_value(&originals).map_err(|_| Error::new("internal"))?,
        );
        let raw = serde_json::to_vec(&fields).map_err(|_| Error::new("internal"))?;
        let token = format!("psl2-{}", URL_SAFE_NO_PAD.encode(raw));
        Self::read(&token, now)?;
        Ok(token)
    }
}
pub fn locator(secret: &[u8; 16]) -> String {
    hash(&lines(&[
        "peerspan-decentralized-locator-v1",
        &encode(secret),
    ]))
}
pub fn read_cap(secret: &[u8; 16]) -> String {
    hash(&lines(&[
        "peerspan-decentralized-read-cap-v1",
        &encode(secret),
    ]))
}

#[derive(Clone, Debug)]
pub struct Frame {
    pub body: Vec<u8>,
    pub request_id: String,
    pub locator: String,
    pub role: String,
    pub writer_host_public_key: String,
    pub frame_id: String,
    pub created_at: String,
    pub expires_at: String,
    pub ciphertext: Vec<u8>,
}
/// Which request windows a carrier accepts: the request window of a `link_`
/// request (3600 seconds) or of an invite's return mailbox, named by its
/// `di_` invitation ID (60 to 86400 seconds). Hosts' own first-contact
/// mailboxes and the optional helper (spec 9.2, wire section 12) both carry
/// these; neither can tell which a mailbox is, so both accept 60 to 86400.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Window {
    Request,
}
impl Window {
    pub fn request_id(self, id: &str) -> bool {
        ident(id, "link_") || ident(id, "di_")
    }
    fn lifetime(self, created: &str, expires: &str) -> Result<()> {
        let seconds = (stamp(expires)? - stamp(created)?).num_seconds();
        check((INVITE_MIN..=INVITE_MAX).contains(&seconds))
    }
    /// The mailbox creation/append window: syntax, `created_at <= now + 30`
    /// (else invalid) and `now < expires_at` (else expired).
    pub fn check_at(self, created: &str, expires: &str, now: &str) -> Result<()> {
        self.lifetime(created, expires)?;
        let now = stamp(now)?;
        check(stamp(created)? <= now + chrono::TimeDelta::seconds(30))?;
        require(now < stamp(expires)?, "expired")
    }
    /// Whether a stored mailbox's ID and window still satisfy this rule.
    pub fn stored(self, request_id: &str, created: &str, expires: &str) -> bool {
        self.request_id(request_id) && self.lifetime(created, expires).is_ok()
    }
}
impl Frame {
    pub fn read(raw: &[u8]) -> Result<Self> {
        Self::read_in(raw, Window::Request)
    }
    pub fn read_in(raw: &[u8], window: Window) -> Result<Self> {
        let v = parse(raw, MAX_FRAME_POST)?;
        let o = object(&v)?;
        fields(
            o,
            "format request_id locator role writer_host_public_key frame_id created_at expires_at ciphertext_base64 signature",
        )?;
        version(o)?;
        let f = Self {
            body: raw.into(),
            request_id: text(o, "request_id")?.into(),
            locator: text(o, "locator")?.into(),
            role: text(o, "role")?.into(),
            writer_host_public_key: text(o, "writer_host_public_key")?.into(),
            frame_id: text(o, "frame_id")?.into(),
            created_at: text(o, "created_at")?.into(),
            expires_at: text(o, "expires_at")?.into(),
            ciphertext: b64(text(o, "ciphertext_base64")?, MAX_FRAME_PLAIN + 16)?,
        };
        check(
            window.request_id(&f.request_id)
                && digest(&f.locator)
                && digest(&f.frame_id)
                && key(&f.writer_host_public_key)
                && matches!(
                    f.role.as_str(),
                    "request"
                        | "owner"
                        | "selection"
                        | "administrator"
                        | "owner_finalization"
                        | "commit"
                        | "outcome"
                        | "proofs"
                )
                && f.ciphertext.len() >= 16,
        )?;
        window.lifetime(&f.created_at, &f.expires_at)?;
        raw_signature(
            &f.writer_host_public_key,
            &lines(&[
                "peerspan-decentralized-frame-envelope-v1",
                &String::from_utf8(f.ad()).map_err(|_| Error::new("invalid"))?,
                &hash(&f.ciphertext),
            ]),
            text(o, "signature")?,
        )?;
        Ok(f)
    }
    pub fn valid_at(&self, now: &str) -> Result<()> {
        Window::Request.check_at(&self.created_at, &self.expires_at, now)
    }
    fn ad(&self) -> Vec<u8> {
        lines(&[
            "peerspan-decentralized-frame-v1",
            &self.request_id,
            &self.locator,
            &self.role,
            &self.writer_host_public_key,
            &self.frame_id,
            &self.created_at,
            &self.expires_at,
        ])
    }
    fn key(&self, secret: &[u8; 16]) -> Result<aead::LessSafeKey> {
        check(self.locator == locator(secret))?;
        let salt = Sha256::digest(lines(&[
            "peerspan-decentralized-frame-salt-v1",
            &self.request_id,
        ]));
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt).extract(secret);
        let info = lines(&[
            "peerspan-decentralized-frame-key-v1",
            &self.request_id,
            &self.role,
            &self.writer_host_public_key,
        ]);
        let parts = [info.as_slice()];
        let mut key = [0u8; 32];
        prk.expand(&parts, hkdf::HKDF_SHA256)
            .map_err(|_| Error::new("invalid"))?
            .fill(&mut key)
            .map_err(|_| Error::new("invalid"))?;
        Ok(aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, &key).map_err(|_| Error::new("invalid"))?,
        ))
    }
    fn nonce(&self) -> aead::Nonce {
        let hash = Sha256::digest(lines(&[
            "peerspan-decentralized-frame-nonce-v1",
            &self.frame_id,
        ]));
        aead::Nonce::assume_unique_for_key(hash[..12].try_into().expect("SHA256 nonce size"))
    }
    pub fn seal(
        secret: &[u8; 16],
        request: &str,
        role: &str,
        key: &SigningKey,
        window: (&str, &str),
        now: &str,
        plain: &Value,
    ) -> Result<Self> {
        let (created, expires) = window;
        let mut ciphertext = bytes(plain)?;
        require(ciphertext.len() <= MAX_FRAME_PLAIN, "quota_exceeded")?;
        let mut random = [0u8; 32];
        getrandom::fill(&mut random).map_err(|_| Error::new("internal"))?;
        let mut f = Self {
            body: Vec::new(),
            request_id: request.into(),
            locator: locator(secret),
            role: role.into(),
            writer_host_public_key: encode(key.verifying_key().as_bytes()),
            frame_id: hex::encode(random),
            created_at: created.into(),
            expires_at: expires.into(),
            ciphertext: Vec::new(),
        };
        f.validate_plain(&ciphertext, now)?;
        f.key(secret)?
            .seal_in_place_append_tag(f.nonce(), aead::Aad::from(f.ad()), &mut ciphertext)
            .map_err(|_| Error::new("invalid"))?;
        f.ciphertext = ciphertext;
        let message = lines(&[
            "peerspan-decentralized-frame-envelope-v1",
            &String::from_utf8(f.ad()).map_err(|_| Error::new("invalid"))?,
            &hash(&f.ciphertext),
        ]);
        Self::read(&bytes(
            &json!({"format":1,"request_id":request,"locator":f.locator,"role":role,"writer_host_public_key":f.writer_host_public_key,"frame_id":f.frame_id,"created_at":created,"expires_at":expires,"ciphertext_base64":encode(&f.ciphertext),"signature":encode(&key.sign(&message).to_bytes())}),
        )?)
    }
    pub fn open(&self, secret: &[u8; 16], now: &str) -> Result<Value> {
        parse(&self.open_bytes(secret, now)?, MAX_FRAME_PLAIN)
    }
    pub fn open_bytes(&self, secret: &[u8; 16], now: &str) -> Result<Vec<u8>> {
        let mut ciphertext = self.ciphertext.clone();
        let plain = self
            .key(secret)?
            .open_in_place(self.nonce(), aead::Aad::from(self.ad()), &mut ciphertext)
            .map_err(|_| Error::new("invalid"))?;
        self.validate_plain(plain, now)?;
        Ok(plain.to_vec())
    }
    fn validate_plain(&self, raw: &[u8], now: &str) -> Result<Value> {
        let value = parse(raw, MAX_FRAME_PLAIN)?;
        let p = object(&value)?;
        fields(p, "packet_base64 catalog_base64 contacts")?;
        let packet = text(p, "packet_base64")?;
        let catalog = text(p, "catalog_base64")?;
        check(packet != "-" || catalog != "-")?;
        if packet != "-" {
            let packet = Packet::read(&b64(packet, MAX_OBJECT)?)?;
            check(
                text(&packet.object, "request_id")? == self.request_id
                    && text(&packet.object, "role")? == self.role
                    && text(&packet.object, "writer_host_public_key")?
                        == self.writer_host_public_key,
            )?;
            if self.role == "request" {
                check(
                    text(&packet.payload, "created_at")? == self.created_at
                        && text(&packet.payload, "expires_at")? == self.expires_at,
                )?;
            }
        } else {
            check(self.role == "proofs")?;
        }
        if catalog != "-" {
            let value = parse(&b64(catalog, 2 << 20)?, 2 << 20)?;
            let c = object(&value)?;
            fields(c, "format context_id objects")?;
            version(c)?;
            check(ident(text(c, "context_id")?, "ctx_"))?;
            let entries = array(c, "objects")?;
            require(entries.len() <= MAX_ITEMS, "quota_exceeded")?;
            let mut previous = "";
            let mut decoded = 0usize;
            for entry in entries {
                let entry = object(entry)?;
                fields(entry, "id kind body_base64")?;
                let id = text(entry, "id")?;
                check(ident(id, "dp_") && id > previous)?;
                previous = id;
                let body = b64(text(entry, "body_base64")?, MAX_OBJECT)?;
                decoded = decoded
                    .checked_add(body.len())
                    .ok_or_else(|| Error::new("quota_exceeded"))?;
                require(decoded <= MAX_DECODED, "quota_exceeded")?;
                check(super::statement::proof_id(text(entry, "kind")?, &body) == id)?;
            }
        }
        contacts(
            &super::catalog::raw_field(raw, "contacts")?,
            now,
            None,
            None,
            false,
        )?;
        Ok(value)
    }
}
