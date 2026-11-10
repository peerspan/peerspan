//! `peerspan-verify`: checks a signed Peerspan release before anything from it
//! runs, as specified in docs/install-contract.md (Release verifier, INST-10).
//!
//! ```text
//! peerspan-verify --keys "KEY1 KEY2" --manifest release.json --signature release.json.sig \
//!   [--version VERSION] [--file NAME[=PATH] ...]
//! ```
//!
//! It succeeds, printing the manifest's version, only when a listed key is
//! usable, the signature verifies under one with strict Ed25519 verification,
//! the manifest is valid (with the requested version), and every requested
//! file is listed and, given a path, has its signed SHA-256. It reads nothing
//! else, writes nothing and makes no network requests.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::process::ExitCode;

const MANIFEST_LIMIT: u64 = 64 * 1024;
const SIGNATURE_LIMIT: u64 = 1024;
const PREFIX: &str = "peerspan-verify";

/// A failure: the file it concerns and the reason, printed as one line.
struct Failure {
    file: String,
    reason: String,
}

fn fail(file: &str, reason: impl Into<String>) -> Failure {
    Failure {
        file: file.to_owned(),
        reason: reason.into(),
    }
}

struct Args {
    keys: String,
    manifest: String,
    signature: String,
    version: Option<String>,
    files: Vec<(String, Option<String>)>,
}

fn parse_args() -> Option<Args> {
    let mut args = std::env::args().skip(1);
    let (mut keys, mut manifest, mut signature, mut version) = (None, None, None, None);
    let mut files = Vec::new();
    while let Some(flag) = args.next() {
        let value = args.next()?;
        let slot = match flag.as_str() {
            "--keys" => &mut keys,
            "--manifest" => &mut manifest,
            "--signature" => &mut signature,
            "--version" => &mut version,
            "--file" => {
                let (name, path) = match value.split_once('=') {
                    Some((name, path)) if !path.is_empty() => (name, Some(path.to_owned())),
                    Some(_) => return None,
                    None => (value.as_str(), None),
                };
                if name.is_empty() {
                    return None;
                }
                files.push((name.to_owned(), path));
                continue;
            }
            _ => return None,
        };
        if slot.replace(value).is_some() {
            return None;
        }
    }
    Some(Args {
        keys: keys?,
        manifest: manifest?,
        signature: signature?,
        version,
        files,
    })
}

/// Reads at most `limit` bytes; more is refused rather than truncated.
fn read_limited(path: &str, limit: u64) -> Result<Vec<u8>, &'static str> {
    let file = File::open(path).map_err(|_| "missing or unreadable")?;
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "missing or unreadable")?;
    if bytes.len() as u64 > limit {
        return Err("larger than its limit");
    }
    Ok(bytes)
}

/// p = 2^255 - 19, little-endian.
const P: [u8; 32] = {
    let mut p = [0xff; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    p
};

/// The y-coordinates, little-endian with the top bit cleared, of the points of
/// order 1, 2, 4 and 8: y = 1, p - 1, 0, and the two order-8 values.
fn small_order(y: &[u8; 32]) -> bool {
    let one = {
        let mut b = [0u8; 32];
        b[0] = 1;
        b
    };
    let p_minus_one = {
        let mut b = P;
        b[0] = 0xec;
        b
    };
    let order8 = [
        hex32("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
        hex32("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    ];
    *y == [0u8; 32] || *y == one || *y == p_minus_one || order8.contains(y)
}

fn hex32(text: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("constant");
    }
    out
}

/// Whether the little-endian value is below p.
fn below_p(y: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if y[i] != P[i] {
            return y[i] < P[i];
        }
    }
    false
}

/// A listed value that is a usable release key, or None (ignored, never trusted).
fn usable_key(text: &str) -> Option<VerifyingKey> {
    if text.len() != 43
        || !text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    let bytes: [u8; 32] = URL_SAFE_NO_PAD.decode(text).ok()?.try_into().ok()?;
    if URL_SAFE_NO_PAD.encode(bytes) != text {
        return None;
    }
    let mut y = bytes;
    y[31] &= 0x7f;
    if !below_p(&y) || small_order(&y) {
        return None;
    }
    let key = VerifyingKey::from_bytes(&bytes).ok()?;
    (!key.is_weak()).then_some(key)
}

fn usable_keys(list: &str) -> Vec<VerifyingKey> {
    let listed: Vec<&str> = list.split_ascii_whitespace().collect();
    if !(1..=4).contains(&listed.len()) {
        return Vec::new();
    }
    listed.into_iter().filter_map(usable_key).collect()
}

/// The signature file: one line of standard base64 (with padding) of 64 bytes.
fn signature(path: &str) -> Result<Signature, Failure> {
    let bytes = read_limited(path, SIGNATURE_LIMIT)
        .map_err(|reason| fail("release.json.sig", format!("bad signature ({reason})")))?;
    let malformed = || {
        fail(
            "release.json.sig",
            "bad signature (not one base64 line of 64 bytes)",
        )
    };
    let text = std::str::from_utf8(&bytes).map_err(|_| malformed())?;
    let line = text.strip_suffix('\n').ok_or_else(malformed)?;
    if line.len() != 88
        || !line.ends_with("==")
        || !line[..86]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
    {
        return Err(malformed());
    }
    let raw: [u8; 64] = STANDARD
        .decode(line)
        .map_err(|_| malformed())?
        .try_into()
        .map_err(|_| malformed())?;
    if STANDARD.encode(raw) != line {
        return Err(malformed());
    }
    Ok(Signature::from_bytes(&raw))
}

fn version_valid(v: &str) -> bool {
    let (core, pre) = match v.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (v, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        && pre.is_none_or(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        })
}

fn lower_hex(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Checks the manifest as a reader does; returns its version and assets.
fn manifest(bytes: &[u8]) -> Result<(String, serde_json::Map<String, Value>), Failure> {
    let invalid = |why: &str| fail("release.json", format!("invalid manifest ({why})"));
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("not UTF-8 JSON"))?;
    let value: Value = serde_json::from_str(text).map_err(|_| invalid("not UTF-8 JSON"))?;
    let object = value
        .as_object()
        .ok_or_else(|| invalid("not a JSON object"))?;
    for member in ["format", "name", "version", "source_revision", "assets"] {
        if !object.contains_key(member) {
            return Err(invalid(&format!("no {member}")));
        }
    }
    if object["format"].as_u64() != Some(1) || !object["format"].is_u64() {
        return Err(invalid("format is not 1"));
    }
    if object["name"].as_str() != Some("peerspan") {
        return Err(invalid("name is not \"peerspan\""));
    }
    let version = object["version"]
        .as_str()
        .filter(|v| version_valid(v))
        .ok_or_else(|| invalid("malformed version"))?;
    if !object["source_revision"]
        .as_str()
        .is_some_and(|r| lower_hex(r, 40))
    {
        return Err(invalid("malformed source_revision"));
    }
    let assets = object["assets"]
        .as_object()
        .ok_or_else(|| invalid("assets is not an object"))?;
    for (name, digest) in assets {
        let name_ok = !name.is_empty()
            && name != "."
            && name != ".."
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'));
        if !name_ok {
            return Err(invalid("malformed asset name"));
        }
        if !digest.as_str().is_some_and(|d| lower_hex(d, 64)) {
            return Err(invalid(&format!("malformed digest for {name}")));
        }
    }
    Ok((version.to_owned(), assets.clone()))
}

/// The SHA-256 of a file, read as a stream.
fn sha256(path: &str) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 16];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

fn run(args: &Args) -> Result<String, Failure> {
    let keys = usable_keys(&args.keys);
    let data = read_limited(&args.manifest, MANIFEST_LIMIT)
        .map_err(|reason| fail("release.json", format!("invalid manifest ({reason})")))?;
    let signature = signature(&args.signature)?;
    if keys.is_empty() {
        return Err(fail("release.json.sig", "no usable release key"));
    }
    if !keys
        .iter()
        .any(|key| key.verify_strict(&data, &signature).is_ok())
    {
        return Err(fail(
            "release.json.sig",
            "bad signature (not made by a listed release key)",
        ));
    }
    let (version, assets) = manifest(&data)?;
    if let Some(want) = &args.version
        && *want != version
    {
        return Err(fail(
            "release.json",
            format!("version mismatch (manifest names {version}, wanted {want})"),
        ));
    }
    for (name, path) in &args.files {
        let Some(signed) = assets.get(name).and_then(Value::as_str) else {
            return Err(fail("release.json", format!("not listed ({name})")));
        };
        if let Some(path) = path {
            let actual = sha256(path).map_err(|_| fail(name, "missing or unreadable"))?;
            if actual != signed {
                return Err(fail(
                    name,
                    format!("digest mismatch (signed {signed}, got {actual})"),
                ));
            }
        }
    }
    Ok(version)
}

fn main() -> ExitCode {
    let Some(args) = parse_args() else {
        eprintln!(
            "usage: {PREFIX} --keys \"KEY ...\" --manifest FILE --signature FILE [--version VERSION] [--file NAME[=PATH] ...]"
        );
        return ExitCode::from(2);
    };
    match run(&args) {
        Ok(version) => {
            println!("{version}");
            ExitCode::SUCCESS
        }
        Err(Failure { file, reason }) => {
            eprintln!("{PREFIX}: {file}: {reason}");
            ExitCode::from(1)
        }
    }
}
