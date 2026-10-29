//! Atomic, non-replacing persistence of an explicitly approved local original.
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use peerspan_host::persons;
use std::{
    ffi::CString,
    fs::{File, Permissions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::PermissionsExt},
    },
    path::Component,
};

fn error() -> anyhow::Error {
    anyhow::anyhow!("local person identity persistence unavailable")
}
fn name(bytes: &[u8]) -> Result<CString> {
    CString::new(bytes).map_err(|_| error())
}
fn opened(fd: libc::c_int) -> std::io::Result<File> {
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a successful openat returns an owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn directory(create: bool) -> Result<Option<File>> {
    use std::os::unix::fs::MetadataExt;
    let Some(path) = persons::generated_key_path() else {
        return if create { Err(error()) } else { Ok(None) };
    };
    ensure!(path.is_absolute(), "invalid local identity destination");
    let parent = path.parent().ok_or_else(error)?;
    // Inspect the lexical components before path normalization can hide '..'.
    ensure!(
        !path.components().any(|c| matches!(c, Component::ParentDir)),
        "invalid local identity destination"
    );
    if !create {
        let normal: std::path::PathBuf = path.components().collect();
        ensure!(
            normal.as_os_str().as_bytes() == path.as_os_str().as_bytes(),
            "invalid local identity destination"
        );
    }
    let mut dir = File::open("/")?;
    let components: Vec<_> = parent.components().collect();
    for (i, component) in components.iter().enumerate() {
        let Component::Normal(part) = component else {
            continue;
        };
        let part = name(part.as_bytes())?;
        let open = || {
            // SAFETY: live directory descriptor and a NUL-terminated single name.
            opened(unsafe {
                libc::openat(
                    dir.as_raw_fd(),
                    part.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            })
        };
        let child = match open() {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if !create {
                    return Ok(None);
                }
                // SAFETY: same pinned directory and single name as openat.
                let result = unsafe { libc::mkdirat(dir.as_raw_fd(), part.as_ptr(), 0o700) };
                if result < 0
                    && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
                {
                    return Err(error());
                }
                dir.sync_all()?;
                open()?
            }
            other => other?,
        };
        let m = child.metadata()?;
        // SAFETY: geteuid has no preconditions.
        let uid = unsafe { libc::geteuid() };
        let final_dir = i + 1 == components.len();
        ensure!(
            if final_dir {
                m.uid() == uid && m.mode() & 0o077 == 0
            } else {
                (m.uid() == uid || m.uid() == 0)
                    && (m.mode() & 0o022 == 0 || (m.uid() == 0 && m.mode() & 0o1000 != 0))
            },
            "insecure local identity directory"
        );
        dir = child;
    }
    Ok(Some(dir))
}
struct Temporary<'a> {
    dir: &'a File,
    name: Option<CString>,
}
impl Temporary<'_> {
    fn remove(mut self) -> Result<()> {
        // SAFETY: unlink only our new temporary name in its pinned directory.
        ensure!(
            unsafe {
                libc::unlinkat(
                    self.dir.as_raw_fd(),
                    self.name.as_ref().unwrap().as_ptr(),
                    0,
                )
            } == 0,
            "identity temporary cleanup unavailable"
        );
        self.name = None;
        Ok(())
    }
}
impl Drop for Temporary<'_> {
    fn drop(&mut self) {
        // SAFETY: remove only this attempt's exclusive temporary name relative
        // to its pinned private directory, never the published destination.
        if let Some(name) = &self.name {
            unsafe { libc::unlinkat(self.dir.as_raw_fd(), name.as_ptr(), 0) };
        }
    }
}
pub fn persist() -> Result<String> {
    let dir = directory(true)?.ok_or_else(error)?;
    let destination = name(b"person_ed25519")?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: valid descriptor, name and writable stat buffer; do not follow a
    // symlink, including a dangling symlink. Every existing entry refuses.
    let exists = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            destination.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    ensure!(
        exists < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound,
        "a local identity destination already exists"
    );
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).map_err(|_| error())?;
    let temporary = name(format!(".person_ed25519.{}.tmp", hex::encode(random)).as_bytes())?;
    // SAFETY: exclusive new file in the pinned private directory; never opens
    // an existing name, including a symlink. A guard is created only on success.
    let mut file = opened(unsafe {
        libc::openat(
            dir.as_raw_fd(),
            temporary.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    })?;
    let temporary = Temporary {
        dir: &dir,
        name: Some(temporary),
    };
    file.set_permissions(Permissions::from_mode(0o600))?;
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|_| error())?;
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let text = persons::encode_openssh_private_key(&key, "peerspan").map_err(|_| error())?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    // SAFETY: linkat never replaces an existing destination. The visible
    // original is a complete synced inode even when two creators race.
    ensure!(
        unsafe {
            libc::linkat(
                dir.as_raw_fd(),
                temporary.name.as_ref().unwrap().as_ptr(),
                dir.as_raw_fd(),
                destination.as_ptr(),
                0,
            )
        } == 0,
        "identity publication unavailable"
    );
    temporary.remove()?;
    dir.sync_all()?;
    Ok(STANDARD.encode(key.verifying_key().to_bytes()))
}

/// A bounded non-creating read through the same pinned private directories.
/// Never reopen this key via a path after validating it.
pub(crate) fn read_existing() -> Result<Option<ed25519_dalek::SigningKey>> {
    use std::os::unix::fs::MetadataExt;
    let Some(dir) = directory(false).map_err(|_| error())? else {
        return Ok(None);
    };
    let leaf = name(b"person_ed25519")?;
    // SAFETY: a pinned private directory and fixed leaf, with no symlink/FIFO wait.
    let file = match opened(unsafe {
        libc::openat(
            dir.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    }) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        result => result.map_err(|_| error())?,
    };
    let meta = file.metadata().map_err(|_| error())?;
    // SAFETY: geteuid has no preconditions.
    ensure!(
        meta.is_file()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.mode() & 0o077 == 0
            && meta.len() <= 65536,
        "local original unavailable"
    );
    let mut raw = Vec::new();
    file.take(65537)
        .read_to_end(&mut raw)
        .map_err(|_| error())?;
    ensure!(raw.len() <= 65536, "local original unavailable");
    let key = persons::parse_openssh_private_key(std::str::from_utf8(&raw).map_err(|_| error())?)
        .map_err(|_| error())?;
    Ok(Some(key))
}
