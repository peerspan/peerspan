//! Private directory descriptors, opened component by component without symlinks.
use super::{Operation, conflict, forbidden, invalid};
use crate::model::Error;
use std::{fs::File, os::unix::fs::MetadataExt};

#[derive(Clone, Copy)]
pub(super) struct Stamp {
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
}
pub(super) struct Pinned {
    file: File,
    pub stamp: Stamp,
}

pub(super) fn syntax(path: &str) -> Result<(), Error> {
    if !path.starts_with('/')
        || path.len() > 4096
        || path.len() + "/peerfs.sock".len() > 107
        || path.contains('\0')
        || path[1..]
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn uid() -> u32 {
    // SAFETY: geteuid has no preconditions and does not access Rust memory.
    unsafe { libc::geteuid() }
}

#[cfg(target_os = "linux")]
pub(super) fn open(path: &str, retained: bool, op: &Operation) -> Result<Pinned, Error> {
    use std::{
        ffi::CString,
        fs::OpenOptions,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::OpenOptionsExt,
        },
    };
    syntax(path)?;
    let owner = uid();
    // Ancestors are opened with O_PATH: walking through a directory needs only
    // execute permission, so a private space beneath a root-owned 0711
    // ancestor is accepted. fstat and openat work on these descriptors; only
    // the final directory, whose emptiness is read, is opened for reading.
    let mut current = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")
        .map_err(|_| conflict())?;
    let root = current.metadata().map_err(|_| conflict())?;
    if !(root.uid() == owner || root.uid() == 0)
        || (root.mode() & 0o022 != 0 && !(root.uid() == 0 && root.mode() & 0o1000 != 0))
    {
        return Err(conflict());
    }
    let parts: Vec<_> = path[1..].split('/').collect();
    for (index, part) in parts.iter().enumerate() {
        op.check()?;
        let component = CString::new(*part).map_err(|_| invalid())?;
        let access = if index == parts.len() - 1 {
            libc::O_RDONLY
        } else {
            libc::O_PATH
        };
        // SAFETY: current is an owned live directory descriptor, component is
        // NUL-terminated, and no mode argument is needed without O_CREAT.
        let fd = unsafe {
            libc::openat(
                current.as_raw_fd(),
                component.as_ptr(),
                access | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(conflict());
        }
        // SAFETY: openat returned a new, uniquely owned descriptor above.
        current = unsafe { File::from_raw_fd(fd) };
        let metadata = current.metadata().map_err(|_| conflict())?;
        if index == parts.len() - 1 {
            if metadata.uid() != owner {
                return Err(if retained { conflict() } else { forbidden() });
            }
            if metadata.mode() & 0o7777 != 0o700 {
                return Err(conflict());
            }
        } else if !(metadata.uid() == owner || metadata.uid() == 0)
            || (metadata.mode() & 0o022 != 0
                && !(metadata.uid() == 0 && metadata.mode() & 0o1000 != 0))
        {
            return Err(conflict());
        }
    }
    let metadata = current.metadata().map_err(|_| conflict())?;
    Ok(Pinned {
        file: current,
        stamp: Stamp {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
        },
    })
}

#[cfg(not(target_os = "linux"))]
pub(super) fn open(_: &str, _: bool, _: &Operation) -> Result<Pinned, Error> {
    Err(super::unavailable())
}

impl Pinned {
    pub fn matches(&self, expected: Stamp) -> Result<(), Error> {
        if self.stamp.device != expected.device
            || self.stamp.inode != expected.inode
            || self.stamp.uid != expected.uid
        {
            return Err(conflict());
        }
        Ok(())
    }

    pub fn empty(&self, op: &Operation) -> Result<(), Error> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            op.check()?;
            // This kernel-owned descriptor path refers to the already opened
            // directory. It is not a re-open of the caller's mutable pathname.
            let mut entries = std::fs::read_dir(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
                .map_err(|_| conflict())?;
            if entries.next().is_some() {
                return Err(conflict());
            }
            op.check()
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = op;
            Err(super::unavailable())
        }
    }
}
