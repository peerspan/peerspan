//! The helper's private state directory, transport identity and optional
//! resource accounts. Nothing here reads or writes host state.
use crate::decentralized::{
    codec::{self, encode},
    mailbox::{Accounts, account_id, resource_token},
};
use ed25519_dalek::SigningKey;
use std::{
    ffi::CString,
    fs::File,
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::DirBuilderExt},
    },
    path::{Path, PathBuf},
};

/// Malformed private state or configuration. Diagnostics never name secrets.
#[derive(Debug)]
pub(crate) struct Invalid;
impl std::fmt::Display for Invalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid private helper state")
    }
}
impl std::error::Error for Invalid {}

/// `$XDG_STATE_HOME/peerspan/helper`, else `$HOME/.local/state/peerspan/helper`.
pub fn default_state() -> Option<PathBuf> {
    if let Some(directory) = std::env::var_os("XDG_STATE_HOME").filter(|d| !d.is_empty()) {
        return Some(PathBuf::from(directory).join("peerspan/helper"));
    }
    std::env::var_os("HOME")
        .filter(|d| !d.is_empty())
        .map(|home| PathBuf::from(home).join(".local/state/peerspan/helper"))
}

fn c_path(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| io::ErrorKind::InvalidInput.into())
}
fn fstat(file: &File) -> io::Result<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(file.as_raw_fd(), &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st)
}
fn owner() -> libc::uid_t {
    unsafe { libc::getuid() }
}
fn invalid() -> io::Error {
    io::Error::other(Invalid)
}

/// An owner-only 0700 directory, never a symlink.
pub(crate) fn private_directory(path: &Path, create: bool) -> io::Result<File> {
    if create {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
    }
    let name = c_path(path)?;
    let fd = unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let directory = unsafe { File::from_raw_fd(fd) };
    let st = fstat(&directory)?;
    if st.st_uid != owner() || st.st_mode & 0o777 != 0o700 {
        return Err(invalid());
    }
    Ok(directory)
}
/// An owner-only regular file opened relative to `directory` (or the working
/// directory), never through a final symlink.
pub(crate) fn protected_file(
    directory: Option<&File>,
    name: &Path,
    flags: libc::c_int,
) -> io::Result<File> {
    let at = directory.map_or(libc::AT_FDCWD, |d| d.as_raw_fd());
    let path = c_path(name)?;
    let fd = unsafe {
        libc::openat(
            at,
            path.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let st = fstat(&file)?;
    if st.st_mode & libc::S_IFMT != libc::S_IFREG || st.st_uid != owner() || st.st_mode & 0o077 != 0
    {
        return Err(invalid());
    }
    Ok(file)
}
fn bounded(mut file: File, limit: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(invalid());
    }
    Ok(bytes)
}
fn mode_0600(file: &File) -> io::Result<()> {
    if fstat(file)?.st_mode & 0o777 != 0o600 {
        return Err(invalid());
    }
    Ok(())
}

fn read_identity(directory: &File) -> io::Result<SigningKey> {
    let file = protected_file(Some(directory), Path::new("identity.json"), libc::O_RDONLY)?;
    mode_0600(&file)?;
    let bytes = bounded(file, 4096)?;
    let value = codec::parse(&bytes, 4096).map_err(|_| invalid())?;
    let o = codec::object(&value).map_err(|_| invalid())?;
    codec::fields(o, "format seed public_key").map_err(|_| invalid())?;
    if codec::num(o, "format").ok() != Some(1) {
        return Err(invalid());
    }
    let seed = codec::text(o, "seed")
        .and_then(|s| codec::b64(s, 32))
        .map_err(|_| invalid())?;
    let seed: [u8; 32] = seed.try_into().map_err(|_| invalid())?;
    let key = SigningKey::from_bytes(&seed);
    if codec::text(o, "public_key").ok() != Some(encode(key.verifying_key().as_bytes()).as_str()) {
        return Err(invalid());
    }
    Ok(key)
}

/// The public transport key, read-only: a missing directory or identity stays
/// missing and is reported as `NotFound`.
pub(crate) fn public_identity(path: &Path) -> io::Result<String> {
    let directory = private_directory(path, false)?;
    let key = read_identity(&directory)?;
    Ok(encode(key.verifying_key().as_bytes()))
}

/// The exclusively owned state directory of one serving helper.
pub(crate) struct OwnedState {
    pub(crate) path: PathBuf,
    pub(crate) key: SigningKey,
    _directory: File,
    _lock: File,
}

/// Creates (0700) and locks the state directory, then reads its identity or,
/// only when none exists, creates one atomically before anything listens.
pub(crate) fn own_state(path: &Path) -> anyhow::Result<OwnedState> {
    let path = std::path::absolute(path)?;
    let directory = private_directory(&path, true)?;
    let lock = protected_file(
        Some(&directory),
        Path::new("helper.lock"),
        libc::O_RDWR | libc::O_CREAT,
    )?;
    mode_0600(&lock)?;
    if fs2::FileExt::try_lock_exclusive(&lock).is_err() {
        anyhow::bail!("helper state already owned");
    }
    let key = match read_identity(&directory) {
        Ok(key) => key,
        Err(e) if e.kind() == io::ErrorKind::NotFound => create_identity(&directory)?,
        Err(e) => return Err(e.into()),
    };
    Ok(OwnedState {
        path,
        key,
        _directory: directory,
        _lock: lock,
    })
}
fn create_identity(directory: &File) -> anyhow::Result<SigningKey> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|_| anyhow::anyhow!("no randomness"))?;
    let key = SigningKey::from_bytes(&seed);
    let body = format!(
        "{{\"format\":1,\"seed\":\"{}\",\"public_key\":\"{}\"}}\n",
        encode(&seed),
        encode(key.verifying_key().as_bytes())
    );
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| anyhow::anyhow!("no randomness"))?;
    let temporary = format!(".identity-{}", hex::encode(nonce));
    let mut file = protected_file(
        Some(directory),
        Path::new(&temporary),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
    )?;
    struct Remove<'a>(&'a File, CString);
    impl Drop for Remove<'_> {
        fn drop(&mut self) {
            unsafe { libc::unlinkat(self.0.as_raw_fd(), self.1.as_ptr(), 0) };
        }
    }
    let _remove = Remove(directory, CString::new(temporary.clone())?);
    file.write_all(body.as_bytes())?;
    file.sync_all()?;
    drop(file);
    // Atomic, and never replaces an unexpected existing identity.
    let from = CString::new(temporary)?;
    let to = CString::new("identity.json")?;
    let fd = directory.as_raw_fd();
    if unsafe { libc::linkat(fd, from.as_ptr(), fd, to.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    directory.sync_all()?;
    Ok(key)
}

/// The optional tokens file: an owner-only regular file of at most 1 MiB,
/// exactly `{format:1, accounts:[{id, tokens:[BASE64]}]}` (wire section 18).
pub(crate) fn load_accounts(path: &Path) -> anyhow::Result<Accounts> {
    let file = protected_file(None, path, libc::O_RDONLY)?;
    let bytes = bounded(file, 1 << 20)?;
    accounts(&bytes).ok_or_else(|| Invalid.into())
}
fn accounts(bytes: &[u8]) -> Option<Accounts> {
    let value = codec::parse(bytes, 1 << 20).ok()?;
    let o = codec::object(&value).ok()?;
    codec::fields(o, "format accounts").ok()?;
    (codec::num(o, "format").ok()? == 1).then_some(())?;
    let list = codec::array(o, "accounts").ok()?;
    (list.len() <= 1024).then_some(())?;
    let mut accounts = Accounts::new();
    let mut previous = String::new();
    for account in list {
        let a = codec::object(account).ok()?;
        codec::fields(a, "id tokens").ok()?;
        let id = codec::text(a, "id").ok()?;
        (account_id(id) && id > previous.as_str()).then_some(())?;
        previous = id.into();
        let tokens = a.get("tokens")?.as_array()?;
        (1..=8).contains(&tokens.len()).then_some(())?;
        let mut before: Option<Vec<u8>> = None;
        for token in tokens {
            let token = codec::b64(token.as_str()?, 1024).ok()?;
            (!token.is_empty()
                && resource_token(&token)
                && before.as_ref().is_none_or(|b| *b < token))
            .then_some(())?;
            if accounts.insert(token.clone(), id.into()).is_some() {
                return None;
            }
            before = Some(token);
        }
    }
    Some(accounts)
}
