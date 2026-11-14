//! Activation's probe of a PeerFS provider: its server inside the pinned private
//! directory must be the host-backed provider of exactly this binding.
//!
//! The socket is reached through the pinned directory's descriptor, never a pathname a
//! caller chose: it must be a real socket owned by this account with mode 0600, its peer
//! process must run as this account, and its `GET /v1/host-bridge` identity must match the
//! binding exactly. Connecting is bounded to 1 second and the whole probe to the operation.
use super::{Operation, View, conflict, directory::Pinned, forbidden, unavailable};
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

/// A path segment, percent-encoded except for unreserved bytes.
fn segment(text: &str) -> String {
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
    op.check()?;
    check_socket(dir)?;
    let mut stream = connect(dir, op)?;
    check_peer(&stream, dir.stamp.uid)?;
    let left = || {
        op.0.at
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or_else(unavailable)
    };
    stream
        .set_write_timeout(Some(left()?))
        .map_err(|_| unavailable())?;
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .map_err(|_| unavailable())?;
    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        stream
            .set_read_timeout(Some(left()?))
            .map_err(|_| unavailable())?;
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                response.extend_from_slice(&buf[..n]);
                if response.len() > max + 4096 {
                    return Err(conflict());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(unavailable()),
        }
    }
    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(conflict)?;
    let head = std::str::from_utf8(&response[..split]).map_err(|_| conflict())?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.strip_prefix("HTTP/1.1 "))
        .and_then(|rest| rest.get(..3))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(conflict)?;
    let mut body = &response[split + 4..];
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(conflict());
        };
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(conflict());
        }
        if name.eq_ignore_ascii_case("content-length") {
            let length: usize = value.trim().parse().map_err(|_| conflict())?;
            if length > max || body.len() < length {
                return Err(conflict());
            }
            body = &body[..length];
        }
    }
    if body.len() > max {
        return Err(conflict());
    }
    Ok((status, body.to_vec()))
}
