//! Exact pairing-code and immutable frame primitives from transaction section 5.
use anyhow::{Result, anyhow, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::{aead, hkdf};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PLAIN_LIMIT: usize = 64 << 10;
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Frame {
    pub format: u64,
    pub request_id: String,
    pub locator: String,
    pub role: String,
    pub writer_public_key: String,
    pub frame_id: String,
    pub ciphertext: String,
}

pub fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn id(value: &str, prefix: &str) -> bool {
    value.len() == prefix.len() + 64
        && value.starts_with(prefix)
        && value[prefix.len()..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn bytes(value: &str, limit: usize) -> Result<Vec<u8>> {
    ensure!(value.len() <= limit.div_ceil(3) * 4, "invalid encoding");
    let b = STANDARD.decode(value)?;
    ensure!(
        b.len() <= limit && STANDARD.encode(&b) == value,
        "invalid encoding"
    );
    Ok(b)
}

pub fn public_key(value: &str) -> bool {
    let Ok(b) = bytes(value, 32) else {
        return false;
    };
    let Ok(mut y): Result<[u8; 32], _> = b.try_into() else {
        return false;
    };
    y[31] &= 127;
    let mut modulus = [255u8; 32];
    modulus[0] = 237;
    modulus[31] = 127;
    y.iter().rev().cmp(modulus.iter().rev()).is_lt()
        && crate::membership::public_key(value).is_ok_and(|k| !k.is_weak())
}

/// Newly constructed records use sorted compact JSON, retaining u64 exactly.
pub fn json(value: &impl Serialize) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&serde_json::to_value(value)?)?)
}

fn base32(secret: &[u8; 16]) -> String {
    let mut out = String::new();
    let (mut accumulator, mut bits) = (0u32, 0u32);
    for b in secret {
        accumulator = (accumulator << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((accumulator >> bits) & 31) as usize] as char);
        }
        accumulator &= (1 << bits) - 1;
    }
    if bits != 0 {
        out.push(ALPHABET[((accumulator << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn display_code(secret: &[u8; 16]) -> String {
    let s = base32(secret);
    format!(
        "psl1-{}-{}-{}-{}-{}",
        &s[..5],
        &s[5..10],
        &s[10..15],
        &s[15..20],
        &s[20..]
    )
}

pub fn parse_code(value: &str) -> Result<[u8; 16]> {
    ensure!(value.is_ascii(), "invalid linking code");
    let mut upper = value.to_ascii_uppercase();
    if upper.len() == 35 && upper.starts_with("PSL1-") {
        let groups: Vec<_> = upper[5..].split('-').collect();
        ensure!(
            groups.len() == 5 && groups.iter().map(|p| p.len()).eq([5, 5, 5, 5, 6]),
            "invalid linking code"
        );
        upper = groups.concat();
    }
    ensure!(upper.len() == 26, "invalid linking code");
    let (mut accumulator, mut bits) = (0u32, 0u32);
    let mut decoded = Vec::new();
    for b in upper.bytes() {
        let digit = ALPHABET
            .iter()
            .position(|x| *x == b)
            .ok_or_else(|| anyhow!("invalid linking code"))?;
        accumulator = (accumulator << 5) | digit as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            decoded.push(((accumulator >> bits) & 255) as u8);
        }
        accumulator &= (1 << bits) - 1;
    }
    let secret: [u8; 16] = decoded
        .try_into()
        .map_err(|_| anyhow!("invalid linking code"))?;
    ensure!(base32(&secret) == upper, "invalid linking code");
    Ok(secret)
}

pub fn locator(secret: &[u8; 16]) -> String {
    hash(&[b"peerspan-link-locator-v1\x00".as_slice(), secret].concat())
}

fn frame_key(
    secret: &[u8; 16],
    coordinator: &str,
    f: &Frame,
) -> Result<(aead::LessSafeKey, Vec<u8>)> {
    ensure!(
        f.format == 1
            && id(&f.request_id, "link_")
            && id(&f.locator, "")
            && id(&f.frame_id, "")
            && public_key(coordinator)
            && public_key(&f.writer_public_key)
            && f.locator == locator(secret)
            && matches!(
                f.role.as_str(),
                "request" | "owner" | "selection" | "administrator" | "commit" | "result"
            ),
        "invalid linking frame"
    );
    let coordinator_bytes = bytes(coordinator, 32)?;
    let salt = Sha256::digest(
        [
            b"peerspan-link-extract-v1\x00".as_slice(),
            &coordinator_bytes,
        ]
        .concat(),
    );
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt).extract(secret);
    let context = [
        "peerspan-link-frame-v1",
        &f.request_id,
        &f.locator,
        coordinator,
        &f.role,
        &f.writer_public_key,
        &f.frame_id,
    ]
    .join("\n")
    .into_bytes();
    let info = [context.as_slice()];
    let mut key = [0u8; 32];
    prk.expand(&info, hkdf::HKDF_SHA256)
        .map_err(|_| anyhow!("invalid linking frame"))?
        .fill(&mut key)
        .map_err(|_| anyhow!("invalid linking frame"))?;
    let key = aead::UnboundKey::new(&aead::AES_256_GCM, &key)
        .map_err(|_| anyhow!("invalid linking frame"))?;
    Ok((aead::LessSafeKey::new(key), context))
}

/// Allocates a fresh frame ID. Persist the returned exact bytes before publish.
/// Retries must reuse those bytes, never call seal with the previous frame ID.
pub fn seal(
    secret: &[u8; 16],
    coordinator: &str,
    request: &str,
    role: &str,
    writer: &str,
    plaintext: &[u8],
) -> Result<(Frame, Vec<u8>)> {
    ensure!(
        plaintext.len() <= PLAIN_LIMIT,
        "frame plaintext exceeds limit"
    );
    let mut frame_id = [0u8; 32];
    getrandom::fill(&mut frame_id).map_err(|_| anyhow!("random source failed"))?;
    let mut f = Frame {
        format: 1,
        request_id: request.into(),
        locator: locator(secret),
        role: role.into(),
        writer_public_key: writer.into(),
        frame_id: hex::encode(frame_id),
        ciphertext: String::new(),
    };
    let (key, context) = frame_key(secret, coordinator, &f)?;
    let mut ciphertext = plaintext.to_vec();
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key([0; 12]),
        aead::Aad::from(context),
        &mut ciphertext,
    )
    .map_err(|_| anyhow!("invalid linking frame"))?;
    f.ciphertext = STANDARD.encode(ciphertext);
    let raw = json(&f)?;
    Ok((f, raw))
}

pub fn open(secret: &[u8; 16], coordinator: &str, f: &Frame) -> Result<Vec<u8>> {
    let (key, context) = frame_key(secret, coordinator, f)?;
    let mut ciphertext = bytes(&f.ciphertext, PLAIN_LIMIT + 16)?;
    ensure!(ciphertext.len() >= 16, "invalid linking frame");
    let plaintext = key
        .open_in_place(
            aead::Nonce::assume_unique_for_key([0; 12]),
            aead::Aad::from(context),
            &mut ciphertext,
        )
        .map_err(|_| anyhow!("invalid linking frame"))?;
    Ok(plaintext.to_vec())
}

/// Sorted new outer object with accepted nested JSON bytes retained verbatim.
pub fn raw_object(fields: Vec<(&str, Vec<u8>)>) -> Result<Vec<u8>> {
    let mut object = std::collections::BTreeMap::new();
    for (key, body) in fields {
        anyhow::ensure!(
            object
                .insert(
                    key,
                    serde_json::from_slice::<Box<serde_json::value::RawValue>>(&body)?
                )
                .is_none(),
            "duplicate field"
        );
    }
    Ok(serde_json::to_vec(&object)?)
}
