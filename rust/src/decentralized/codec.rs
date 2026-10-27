use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fmt};

pub const MAX_OBJECT: usize = 1 << 20;
pub const MAX_PAYLOAD: usize = 256 << 10;
pub const MAX_CATALOG: usize = 16 << 20;
pub const MAX_DECODED: usize = 8 << 20;
pub const MAX_ITEMS: usize = 4096;
pub type Obj = Map<String, Value>;
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub code: &'static str,
    pub required_ids: BTreeSet<String>,
    pub(crate) stage: Option<&'static str>,
    pub(crate) retry_after: Option<u64>,
}
impl Error {
    pub fn new(code: &'static str) -> Self {
        Self {
            code,
            required_ids: BTreeSet::new(),
            stage: None,
            retry_after: None,
        }
    }
    pub fn missing(id: &str) -> Self {
        Self {
            code: "proof_required",
            required_ids: BTreeSet::from([id.into()]),
            stage: None,
            retry_after: None,
        }
    }
    pub fn response(&self) -> Value {
        serde_json::json!({"ok":false,"code":self.code,"required_ids":self.required_ids})
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code)
    }
}
impl std::error::Error for Error {}
pub fn check(value: bool) -> Result<()> {
    require(value, "invalid")
}
pub fn require(value: bool, code: &'static str) -> Result<()> {
    if value { Ok(()) } else { Err(Error::new(code)) }
}
pub fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn lines(parts: &[&str]) -> Vec<u8> {
    parts.join("\n").into_bytes()
}
pub fn ident(s: &str, prefix: &str) -> bool {
    s.len() == prefix.len() + 64
        && s.starts_with(prefix)
        && s[prefix.len()..]
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
pub fn digest(s: &str) -> bool {
    ident(s, "")
}
pub fn b64(s: &str, limit: usize) -> Result<Vec<u8>> {
    require(s.len() <= limit.div_ceil(3) * 4, "quota_exceeded")?;
    let bytes = STANDARD.decode(s).map_err(|_| Error::new("invalid"))?;
    require(bytes.len() <= limit, "quota_exceeded")?;
    check(STANDARD.encode(&bytes) == s)?;
    Ok(bytes)
}
pub fn encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}
pub fn key(s: &str) -> bool {
    let Ok(b) = b64(s, 32) else { return false };
    if b.len() != 32 {
        return false;
    }
    let mut y: [u8; 32] = b.as_slice().try_into().expect("checked size");
    y[31] &= 127;
    let mut p = [255; 32];
    p[0] = 237;
    p[31] = 127;
    y.iter().rev().cmp(p.iter().rev()).is_lt()
        && crate::membership::public_key(s).is_ok_and(|k| !k.is_weak())
}
pub fn stamp(value: &str) -> Result<DateTime<Utc>> {
    check(
        value.len() == 20
            && value.is_ascii()
            && value.as_bytes()[4] == b'-'
            && &value[..4] != "0000",
    )?;
    let t = DateTime::parse_from_rfc3339(value)
        .map_err(|_| Error::new("invalid"))?
        .to_utc();
    check(t.timestamp_subsec_nanos() == 0 && t.format("%Y-%m-%dT%H:%M:%SZ").to_string() == value)?;
    Ok(t)
}
pub fn decision_clock(now: &str, guard: &str) -> Result<String> {
    let current = stamp(now)?;
    if guard == "-" {
        return Ok(now.into());
    }
    let retained = stamp(guard)?;
    require(
        retained.signed_duration_since(current).num_seconds() <= 300,
        "clock_rollback",
    )?;
    Ok(if current >= retained { now } else { guard }.into())
}
pub fn object(value: &Value) -> Result<&Obj> {
    value.as_object().ok_or_else(|| Error::new("invalid"))
}
pub fn fields(o: &Obj, shape: &str) -> Result<()> {
    let expected: BTreeSet<_> = shape.split_whitespace().collect();
    check(o.len() == expected.len() && o.keys().all(|k| expected.contains(k.as_str())))
}
pub fn text<'a>(o: &'a Obj, name: &str) -> Result<&'a str> {
    let value = o
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new("invalid"))?;
    check(!value.contains(['\r', '\n', '\0']))?;
    Ok(value)
}
pub fn num(o: &Obj, name: &str) -> Result<u64> {
    o.get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| Error::new("invalid"))
}
pub fn version(o: &Obj) -> Result<()> {
    check(num(o, "format")? == 1)
}
pub fn array<'a>(o: &'a Obj, name: &str) -> Result<&'a [Value]> {
    let values = o
        .get(name)
        .and_then(Value::as_array)
        .ok_or_else(|| Error::new("invalid"))?;
    require(values.len() <= MAX_ITEMS, "quota_exceeded")?;
    Ok(values)
}
pub fn strings(o: &Obj, name: &str) -> Result<Vec<String>> {
    array(o, name)?
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or_else(|| Error::new("invalid"))
        })
        .collect()
}
pub fn sorted(values: &[String]) -> bool {
    values.windows(2).all(|w| w[0] < w[1])
}
pub fn ids(o: &Obj, name: &str, prefix: &str) -> Result<Vec<String>> {
    let values = strings(o, name)?;
    check(sorted(&values) && values.iter().all(|s| ident(s, prefix)))?;
    Ok(values)
}
pub fn label(s: &str) -> Result<()> {
    check(!s.is_empty() && s.len() <= 128 && s.trim() == s && !s.chars().any(char::is_control))
}
pub fn raw_signature(public: &str, message: &[u8], signature: &str) -> Result<()> {
    check(key(public))?;
    let bytes = b64(signature, 64)?;
    let sig = ed25519_dalek::Signature::from_slice(&bytes).map_err(|_| Error::new("invalid"))?;
    let vk = crate::membership::public_key(public).map_err(|_| Error::new("invalid"))?;
    crate::membership::verify_strict_cached(&vk, message, &sig).map_err(|_| Error::new("invalid"))
}
pub fn signature(public: &str, format: &str, message: &[u8], sig: &str) -> Result<()> {
    match format {
        "ed25519" => raw_signature(public, message, sig),
        "sshsig" => {
            check(key(public))?;
            let message = std::str::from_utf8(message).map_err(|_| Error::new("invalid"))?;
            crate::persons::verify_sshsig(public, &message.split('\n').collect::<Vec<_>>(), sig)
                .map_err(|_| Error::new("invalid"))
        }
        _ => Err(Error::new("invalid")),
    }
}

struct Seed(usize);
struct Strict(usize);
impl<'de> DeserializeSeed<'de> for Seed {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> std::result::Result<Value, D::Error> {
        if self.0 > 64 {
            return Err(de::Error::custom("decentralized_quota"));
        }
        d.deserialize_any(Strict(self.0))
    }
}
impl<'de> Visitor<'de> for Strict {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("strict non-null JSON")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> std::result::Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(v) = a.next_element_seed(Seed(self.0 + 1))? {
            values.push(v);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> std::result::Result<Value, A::Error> {
        let mut values = Obj::new();
        while let Some(k) = a.next_key::<String>()? {
            if values.contains_key(&k) {
                return Err(de::Error::custom("duplicate key"));
            }
            values.insert(k, a.next_value_seed(Seed(self.0 + 1))?);
        }
        Ok(Value::Object(values))
    }
}
fn parse_json(bytes: &[u8], limit: usize) -> Result<Value> {
    require(bytes.len() <= limit, "quota_exceeded")?;
    std::str::from_utf8(bytes).map_err(|_| Error::new("invalid"))?;
    let mut d = serde_json::Deserializer::from_slice(bytes);
    let value = Seed(0).deserialize(&mut d).map_err(|e| {
        Error::new(if e.to_string().contains("decentralized_quota") {
            "quota_exceeded"
        } else {
            "invalid"
        })
    })?;
    d.end().map_err(|_| Error::new("invalid"))?;
    Ok(value)
}
pub fn parse(bytes: &[u8], limit: usize) -> Result<Value> {
    let value = parse_json(bytes, limit)?;
    object(&value)?;
    Ok(value)
}
pub(crate) fn parse_array(bytes: &[u8], limit: usize) -> Result<Value> {
    let value = parse_json(bytes, limit)?;
    check(value.is_array())?;
    Ok(value)
}
