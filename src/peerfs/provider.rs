//! Activation's probe of a PeerFS provider: its server inside the pinned private
//! directory must be the host-backed provider of exactly this binding.
//!
//! The socket is reached through the pinned directory's descriptor, never a pathname a
//! caller chose: it must be a real socket owned by this account with mode 0600, its peer
//! process must run as this account, and its `GET /v1/host-bridge` identity must match the
//! binding exactly. Connecting is bounded to 1 second and the whole probe to the operation.
use super::{Operation, View, conflict, directory::Pinned, forbidden, too_large, unavailable};
use crate::model::Error;
use serde::Deserialize;
use std::{
    ffi::CString,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::net::UnixStream,
    },
    time::{Duration, Instant},
};

/// The provider's socket, inside the space's directory.
const SOCKET: &str = "peerfs.sock";
/// Connecting may take at most this long of the operation.
const CONNECT: Duration = Duration::from_secs(1);
/// The largest identity body accepted.
const MAX_BODY: usize = 8 << 10;

/// Verifies the provider serving `view`'s space in the pinned directory `dir`.
pub(super) fn probe(dir: &Pinned, view: &View, op: &Operation) -> Result<(), Error> {
    let (status, body) = get(dir, "/v1/host-bridge", MAX_BODY, op)?;
    if status != 200 {
        // A file-key provider has no bridge identity (404): incompatible, not unavailable.
        return Err(conflict());
    }
    // A struct refuses unknown and duplicated fields, which a generic value would not.
    let identity: Identity = serde_json::from_slice(&body).map_err(|_| conflict())?;
    let matches = identity.format == 1
        && identity.protocol == "peerfs-host-v1"
        && identity.space_id == view.space_id
        && identity.binding_id == view.binding_id
        && identity.network_id == view.network_id
        && identity.context_id == view.context_id
        && identity.host_id == view.host_id
        && identity.public_key == view.public_key
        && identity.directory == view.directory;
    if !matches {
        return Err(conflict());
    }
    op.check()
}

/// A provider's identity: exactly these fields, each once.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    format: u8,
    protocol: String,
    space_id: String,
    binding_id: String,
    network_id: String,
    context_id: String,
    host_id: String,
    public_key: String,
    directory: String,
}

/// The socket must be a real socket owned by this account, mode 0600.
fn check_socket(dir: &Pinned) -> Result<(), Error> {
    let name = CString::new(SOCKET).expect("no NUL");
    // SAFETY: the descriptor is the live pinned directory, name is NUL-terminated and
    // stat is a valid out-pointer.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let found = unsafe {
        libc::fstatat(
            dir.raw_fd(),
            name.as_ptr(),
            &raw mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if found != 0 {
        return Err(unavailable());
    }
    if stat.st_mode & libc::S_IFMT != libc::S_IFSOCK || stat.st_mode & 0o7777 != 0o600 {
        return Err(conflict());
    }
    if stat.st_uid != dir.stamp.uid {
        return Err(forbidden());
    }
    Ok(())
}

/// Connects to the socket through the pinned directory, within [`CONNECT`].
fn connect(dir: &Pinned, op: &Operation) -> Result<UnixStream, Error> {
    let path = format!("/proc/self/fd/{}/{SOCKET}", dir.raw_fd());
    // SAFETY: plain socket creation; the result is checked before use.
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(unavailable());
    }
    // SAFETY: socket returned a new descriptor this function owns.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: sockaddr_un is plain data; zeroed is its empty value.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    if path.len() >= address.sun_path.len() {
        return Err(unavailable());
    }
    for (slot, byte) in address.sun_path.iter_mut().zip(path.bytes()) {
        *slot = byte as libc::c_char;
    }
    let length = (std::mem::size_of::<libc::sa_family_t>() + path.len() + 1) as libc::socklen_t;
    let deadline = Instant::now() + CONNECT;
    loop {
        op.check()?;
        // SAFETY: fd is a live socket and address a valid sockaddr_un of `length` bytes.
        let done = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                (&raw const address).cast::<libc::sockaddr>(),
                length,
            )
        };
        if done == 0 {
            break;
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::EAGAIN | libc::EINTR) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => return Err(unavailable()),
        }
    }
    // Back to blocking for the exchange, which read and write timeouts bound.
    // SAFETY: fd is a live socket; F_GETFL/F_SETFL take no pointers.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK) } < 0
    {
        return Err(unavailable());
    }
    Ok(UnixStream::from(fd))
}

/// The provider process must run as this account.
fn check_peer(stream: &UnixStream, uid: u32) -> Result<(), Error> {
    // SAFETY: ucred is plain data; getsockopt fills at most `length` bytes of it.
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let found = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut credentials).cast(),
            &raw mut length,
        )
    };
    if found != 0 || length as usize != std::mem::size_of::<libc::ucred>() {
        return Err(unavailable());
    }
    if credentials.uid != uid {
        return Err(forbidden());
    }
    Ok(())
}

/// A branch as the provider reports it: its head and the number of commits in its
/// history (`GET /v1/branches/{name}/log`, first parents, newest first).
pub(super) struct Branch {
    pub head: String,
    pub commits: usize,
}
/// The largest branch list accepted.
const MAX_BRANCHES: usize = 1 << 20;
/// The largest history accepted.
const MAX_LOG: usize = 16 << 20;

/// One entry of `GET /v1/branches`.
#[derive(Deserialize)]
struct BranchInfo {
    name: String,
}
/// One entry of a branch's log; only its ID is read.
#[derive(Deserialize)]
struct CommitInfo {
    id: String,
}

/// Reads branch `name` from the provider serving `view`'s space, after the activation
/// probe: its head and history length, or `None` when the space has no such branch.
/// Read-only; the provider is never started.
pub(super) fn branch(
    dir: &Pinned,
    view: &View,
    name: &str,
    op: &Operation,
) -> Result<Option<Branch>, Error> {
    probe(dir, view, op)?;
    let (status, body) = get(dir, "/v1/branches", MAX_BRANCHES, op)?;
    if status != 200 {
        return Err(unavailable());
    }
    let branches: Vec<BranchInfo> = serde_json::from_slice(&body).map_err(|_| conflict())?;
    if !branches.iter().any(|b| b.name == name) {
        return Ok(None);
    }
    let (status, body) = get(
        dir,
        &format!("/v1/branches/{}/log", segment(name)),
        MAX_LOG,
        op,
    )?;
    match status {
        200 => {}
        404 => return Ok(None),
        _ => return Err(unavailable()),
    }
    let log: Vec<CommitInfo> = serde_json::from_slice(&body).map_err(|_| conflict())?;
    // The branch may have moved since the list: its head is the log's newest commit.
    let head = log.first().ok_or_else(conflict)?.id.clone();
    op.check()?;
    Ok(Some(Branch {
        head,
        commits: log.len(),
    }))
}

/// Reads branch `name`'s current head from the provider serving `view`'s space, after
/// the activation probe, or `None` when the space has no such branch. Read-only.
pub(super) fn head(
    dir: &Pinned,
    view: &View,
    name: &str,
    op: &Operation,
) -> Result<Option<String>, Error> {
    /// One entry of `GET /v1/branches`, with its head.
    #[derive(Deserialize)]
    struct Headed {
        name: String,
        head: String,
    }
    probe(dir, view, op)?;
    let (status, body) = get(dir, "/v1/branches", MAX_BRANCHES, op)?;
    if status != 200 {
        return Err(unavailable());
    }
    let branches: Vec<Headed> = serde_json::from_slice(&body).map_err(|_| conflict())?;
    let Some(found) = branches.into_iter().find(|b| b.name == name) else {
        return Ok(None);
    };
    if object_id(&found.head).is_none() {
        return Err(conflict());
    }
    op.check()?;
    Ok(Some(found.head))
}

/// An object ID's encoded bytes: its algorithm code (1, BLAKE3) and 32-byte digest, as
/// 66 lowercase hex digits; `None` when the text is not one.
pub(super) fn object_id(text: &str) -> Option<[u8; OBJECT_ID]> {
    if text.len() != 2 * OBJECT_ID
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut id = [0u8; OBJECT_ID];
    hex::decode_to_slice(text, &mut id).ok()?;
    (id[0] == 1).then_some(id)
}
/// Bytes in an encoded object ID.
pub(super) const OBJECT_ID: usize = 33;

/// What the provider answered a fetch within a branch.
pub(super) enum Fetched {
    /// The branch is absent, or its current head does not reach every object.
    NotReached,
    /// The leading objects, in request order, whose encoding fits the bound: a PeerFS
    /// object batch (`peerfs_core::encode_objects`).
    Batch(Vec<u8>),
}

/// Fetches `ids` (each an [`object_id`]) from the provider serving `view`'s space, after
/// the activation probe, with `within: branch`, so it answers only when the branch's
/// current head reaches every one. The answer holds the leading objects whose batch
/// encoding stays within `max` bytes; the rest of the provider's answer is not read.
/// The provider must return exactly the requested objects, in order: one missing makes
/// the whole fetch [`Fetched::NotReached`]; any other difference is a conflict.
pub(super) fn fetch(
    dir: &Pinned,
    view: &View,
    branch: &str,
    ids: &[String],
    max: usize,
    op: &Operation,
) -> Result<Fetched, Error> {
    let wanted: Vec<[u8; OBJECT_ID]> = ids
        .iter()
        .map(|id| object_id(id).ok_or_else(conflict))
        .collect::<Result<_, _>>()?;
    probe(dir, view, op)?;
    let body = serde_json::to_vec(&serde_json::json!({"ids": ids, "within": branch}))
        .map_err(|_| conflict())?;
    let mut reply = send(dir, "POST", "/v1/objects/fetch", Some(&body), op)?;
    match reply.status {
        200 => {}
        404 => return Ok(Fetched::NotReached),
        // An older provider refuses `within` as an unknown field.
        _ => return Err(unavailable()),
    }
    let mut consumed = 0;
    let count = reply.varint(&mut consumed)?;
    if count < wanted.len() as u64 {
        return Ok(Fetched::NotReached);
    }
    if count != wanted.len() as u64 {
        return Err(conflict());
    }
    let mut objects = Vec::new();
    let mut taken = 0usize;
    for id in &wanted {
        let mut found = [0u8; OBJECT_ID];
        reply.exact(&mut found, &mut consumed)?;
        if &found != id {
            return Err(conflict());
        }
        let mut kind = [0u8; 1];
        reply.exact(&mut kind, &mut consumed)?;
        if !(1..=4).contains(&kind[0]) {
            return Err(conflict());
        }
        let length = reply.varint(&mut consumed)?;
        let length = usize::try_from(length).map_err(|_| conflict())?;
        let mut entry = Vec::with_capacity(OBJECT_ID + 11);
        entry.extend_from_slice(&found);
        entry.push(kind[0]);
        varint(&mut entry, length as u64);
        let size = entry.len().checked_add(length).ok_or_else(conflict)?;
        let total = varint_len(taken as u64 + 1) + objects.len() + size;
        if total > max {
            if taken == 0 {
                // Even the first object alone does not fit the answer's bound.
                return Err(too_large());
            }
            break;
        }
        let start = entry.len();
        entry.resize(size, 0);
        reply.exact(&mut entry[start..], &mut consumed)?;
        objects.extend_from_slice(&entry);
        taken += 1;
    }
    if taken == wanted.len() && Some(consumed) != reply.length {
        return Err(conflict());
    }
    op.check()?;
    let mut batch = Vec::with_capacity(varint_len(taken as u64) + objects.len());
    varint(&mut batch, taken as u64);
    batch.extend_from_slice(&objects);
    Ok(Fetched::Batch(batch))
}

/// What a provider's `POST /v1/pull` did.
pub(super) enum Pulled {
    /// The pull completed: the tracking reference `<remote>/<branch>` is at `head`.
    Done(PullAnswer),
    /// The provider refused or failed the pull, with its status, code and message.
    Refused {
        status: u16,
        code: String,
        message: String,
    },
}
/// A provider's pull answer: exactly these fields, each once.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PullAnswer {
    pub remote: String,
    pub branch: String,
    pub head: String,
    // Read for the answer's shape; the host reports what its proxy served.
    #[serde(rename = "objects")]
    _objects: u64,
    #[serde(rename = "bytes")]
    _bytes: u64,
}
/// A provider's error body.
#[derive(Deserialize)]
struct Refusal {
    code: String,
    error: String,
}
/// The largest pull answer or error body accepted.
const MAX_PULL_BODY: usize = 64 << 10;

/// Has the provider serving `view`'s space pull `branch` from the PeerFS server at the
/// socket `from` (`POST /v1/pull`), after the activation probe. The provider's answer
/// arrives when its pull ends, so `op` bounds it, not this call.
pub(super) fn pull(
    dir: &Pinned,
    view: &View,
    from: &str,
    branch: &str,
    op: &Operation,
) -> Result<Pulled, Error> {
    probe(dir, view, op)?;
    let body = serde_json::to_vec(&serde_json::json!({"from": from, "branch": branch}))
        .map_err(|_| conflict())?;
    let mut reply = send(dir, "POST", "/v1/pull", Some(&body), op)?;
    let status = reply.status;
    let body = reply.body(MAX_PULL_BODY)?;
    if status == 200 {
        let answer: PullAnswer = serde_json::from_slice(&body).map_err(|_| conflict())?;
        return Ok(Pulled::Done(answer));
    }
    let refusal = serde_json::from_slice::<Refusal>(&body).unwrap_or(Refusal {
        code: String::new(),
        error: String::new(),
    });
    Ok(Pulled::Refused {
        status,
        code: refusal.code,
        message: refusal.error,
    })
}

/// Appends `value` as PeerFS encodes integers: unsigned LEB128.
fn varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let low = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(low);
            return;
        }
        out.push(low | 0x80);
    }
}
/// The encoded length of `value` as [`varint`] writes it.
fn varint_len(value: u64) -> usize {
    let mut out = Vec::new();
    varint(&mut out, value);
    out.len()
}

/// A path segment, percent-encoded except for unreserved bytes.
pub(super) fn segment(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Sends `GET path` over a new checked connection to the provider's socket and returns
/// the status and a body of at most `max` bytes. Chunked bodies are refused.
fn get(dir: &Pinned, path: &str, max: usize, op: &Operation) -> Result<(u16, Vec<u8>), Error> {
    let mut reply = send(dir, "GET", path, None, op)?;
    let status = reply.status;
    Ok((status, reply.body(max)?))
}

/// A provider's response whose head was read: its status, its declared length, and a
/// reader of the rest of its body within the operation's deadline.
struct Reply<'a> {
    status: u16,
    length: Option<usize>,
    /// Body bytes already read with the head.
    pending: Vec<u8>,
    stream: UnixStream,
    op: &'a Operation,
}
/// The largest response head accepted.
const MAX_HEAD: usize = 16 << 10;

/// Sends one request over a new checked connection to the provider's socket and reads
/// the response's head. Chunked bodies are refused.
fn send<'a>(
    dir: &Pinned,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    op: &'a Operation,
) -> Result<Reply<'a>, Error> {
    op.check()?;
    check_socket(dir)?;
    let mut stream = connect(dir, op)?;
    check_peer(&stream, dir.stamp.uid)?;
    stream
        .set_write_timeout(Some(left(op)?))
        .map_err(|_| unavailable())?;
    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    if let Some(body) = body {
        request.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    request.push_str("\r\n");
    let mut request = request.into_bytes();
    request.extend_from_slice(body.unwrap_or_default());
    stream.write_all(&request).map_err(|_| unavailable())?;
    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    let split = loop {
        if let Some(split) = response.windows(4).position(|w| w == b"\r\n\r\n") {
            break split;
        }
        if response.len() > MAX_HEAD {
            return Err(conflict());
        }
        match read(&mut stream, &mut buf, op)? {
            0 => return Err(conflict()),
            n => response.extend_from_slice(&buf[..n]),
        }
    };
    let head = std::str::from_utf8(&response[..split]).map_err(|_| conflict())?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.strip_prefix("HTTP/1.1 "))
        .and_then(|rest| rest.get(..3))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(conflict)?;
    let mut length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(conflict());
        };
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(conflict());
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err(conflict());
            }
            length = Some(value.trim().parse::<usize>().map_err(|_| conflict())?);
        }
    }
    Ok(Reply {
        status,
        length,
        pending: response[split + 4..].to_vec(),
        stream,
        op,
    })
}

/// The time left of the operation, or 503 when none is.
fn left(op: &Operation) -> Result<Duration, Error> {
    op.0.at
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or_else(unavailable)
}

/// One read from the provider within the operation's deadline; 0 at its end.
fn read(stream: &mut UnixStream, buf: &mut [u8], op: &Operation) -> Result<usize, Error> {
    loop {
        stream
            .set_read_timeout(Some(left(op)?))
            .map_err(|_| unavailable())?;
        match stream.read(buf) {
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(unavailable()),
        }
    }
}

impl Reply<'_> {
    /// The whole body, at most `max` bytes: its declared length, or up to the end of the
    /// stream when none is declared.
    fn body(&mut self, max: usize) -> Result<Vec<u8>, Error> {
        if self.length.is_some_and(|length| length > max) {
            return Err(conflict());
        }
        let mut body = std::mem::take(&mut self.pending);
        let mut buf = [0u8; 4096];
        loop {
            if let Some(length) = self.length
                && body.len() >= length
            {
                body.truncate(length);
                return Ok(body);
            }
            if body.len() > max {
                return Err(conflict());
            }
            match read(&mut self.stream, &mut buf, self.op)? {
                0 if self.length.is_none() => return Ok(body),
                0 => return Err(conflict()),
                n => body.extend_from_slice(&buf[..n]),
            }
        }
    }

    /// Exactly `out.len()` more body bytes, within the declared length.
    fn exact(&mut self, out: &mut [u8], consumed: &mut usize) -> Result<(), Error> {
        let length = self.length.ok_or_else(conflict)?;
        if consumed
            .checked_add(out.len())
            .is_none_or(|end| end > length)
        {
            return Err(conflict());
        }
        let mut filled = 0;
        while filled < out.len() {
            if !self.pending.is_empty() {
                let n = self.pending.len().min(out.len() - filled);
                out[filled..filled + n].copy_from_slice(&self.pending[..n]);
                self.pending.drain(..n);
                filled += n;
                continue;
            }
            let n = read(&mut self.stream, &mut out[filled..], self.op)?;
            if n == 0 {
                return Err(conflict());
            }
            filled += n;
        }
        *consumed += out.len();
        Ok(())
    }

    /// One unsigned LEB128 integer, canonical as PeerFS encodes it.
    fn varint(&mut self, consumed: &mut usize) -> Result<u64, Error> {
        read_varint(|| {
            let mut byte = [0u8; 1];
            self.exact(&mut byte, consumed)?;
            Ok(byte[0])
        })
    }
}

/// One unsigned LEB128 integer read a byte at a time by `next`, canonical as PeerFS
/// encodes it: no trailing zero byte, no bits past 64.
fn read_varint(mut next: impl FnMut() -> Result<u8, Error>) -> Result<u64, Error> {
    let mut value: u64 = 0;
    for shift in (0..64).step_by(7) {
        let byte = next()?;
        let low = u64::from(byte & 0x7f);
        if shift == 63 && low > 1 {
            return Err(conflict());
        }
        value |= low << shift;
        if byte & 0x80 == 0 {
            if byte == 0 && shift > 0 {
                return Err(conflict());
            }
            return Ok(value);
        }
    }
    Err(conflict())
}

/// Splits a complete PeerFS object batch another host sent into the byte ranges of its
/// entries (each an object's ID, kind, length and bytes, as encoded), which must be the
/// leading objects of `wanted`, in order, at least one; `None` when the batch is anything
/// else.
pub(super) fn split_batch(
    data: &[u8],
    wanted: &[[u8; OBJECT_ID]],
) -> Option<Vec<std::ops::Range<usize>>> {
    let mut at = 0usize;
    let count = usize::try_from(slice_varint(data, &mut at)?).ok()?;
    if count == 0 || count > wanted.len() {
        return None;
    }
    let mut entries = Vec::with_capacity(count);
    for id in &wanted[..count] {
        let start = at;
        if data.get(at..at + OBJECT_ID)? != id {
            return None;
        }
        at += OBJECT_ID;
        if !(1..=4).contains(data.get(at)?) {
            return None;
        }
        at += 1;
        let length = usize::try_from(slice_varint(data, &mut at)?).ok()?;
        let end = at.checked_add(length).filter(|end| *end <= data.len())?;
        at = end;
        entries.push(start..end);
    }
    (at == data.len()).then_some(entries)
}

/// One canonical varint of `data` at `*at`, advancing past it.
fn slice_varint(data: &[u8], at: &mut usize) -> Option<u64> {
    read_varint(|| {
        let byte = *data.get(*at).ok_or_else(conflict)?;
        *at += 1;
        Ok(byte)
    })
    .ok()
}

/// A PeerFS object batch of `entries`, each already encoded, as [`split_batch`] finds
/// them.
pub(super) fn join_batch(entries: &[&[u8]]) -> Vec<u8> {
    let size: usize = entries.iter().map(|e| e.len()).sum();
    let mut batch = Vec::with_capacity(varint_len(entries.len() as u64) + size);
    varint(&mut batch, entries.len() as u64);
    for entry in entries {
        batch.extend_from_slice(entry);
    }
    batch
}
