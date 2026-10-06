//! Thin typed CLI entry point into the shared Claude setup helper.
use crate::cli::{ClaudeCommand, ClaudeRuntime};
use anyhow::{Context, bail};
use serde::Deserialize;
use serde_json::json;
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Deserialize)]
struct Profile {
    channel: PathBuf,
    node: PathBuf,
}
fn profile(directory: &Path) -> anyhow::Result<Profile> {
    let stat = fs::symlink_metadata(directory).context("private setup directory is missing")?;
    if !stat.is_dir() || stat.mode() & 0o077 != 0 || stat.uid() != unsafe { libc::getuid() } {
        bail!("setup directory must be private and belong to this account");
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(directory.join("profile.json"))
        .context("private setup profile is missing; run claude setup first")?;
    let stat = file.metadata()?;
    if !stat.is_file()
        || stat.mode() & 0o077 != 0
        || stat.uid() != unsafe { libc::getuid() }
        || stat.len() > 1 << 20
    {
        bail!("setup profile must be a private regular file owned by this account");
    }
    let mut bytes = Vec::new();
    file.take(1 << 20).read_to_end(&mut bytes)?;
    serde_json::from_slice(&bytes).context("invalid setup profile")
}
fn executable(path: PathBuf) -> anyhow::Result<PathBuf> {
    if path.components().count() > 1 {
        return fs::canonicalize(path).context("Node 22+ was not found; specify --node PROGRAM");
    }
    for directory in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
        let candidate = directory.join(&path);
        if fs::metadata(&candidate).is_ok_and(|m| m.is_file() && m.mode() & 0o111 != 0) {
            return Ok(fs::canonicalize(candidate)?);
        }
    }
    bail!("Node 22+ was not found; specify --node PROGRAM")
}
pub fn run(command: ClaudeCommand, state: Option<PathBuf>) -> anyhow::Result<()> {
    let (action, runtime, agent, mut channel, expiry, routes, workspace, extra) = match command {
        ClaudeCommand::Setup {
            runtime,
            agent,
            channel,
            expires_at,
            routes,
        } => (
            "setup",
            runtime,
            Some(agent),
            Some(channel),
            Some(expires_at),
            routes,
            None,
            Vec::new(),
        ),
        ClaudeCommand::Start {
            runtime,
            agent,
            channel,
            expires_at,
            routes,
            workspace,
            claude_args,
        } => (
            "start",
            runtime,
            agent,
            channel,
            expires_at,
            routes,
            workspace,
            claude_args,
        ),
        ClaudeCommand::Doctor { runtime } => {
            ("doctor", runtime, None, None, None, None, None, Vec::new())
        }
    };
    let ClaudeRuntime {
        directory,
        mut node,
        claude,
    } = runtime;
    if channel.is_none() {
        let prepared = profile(&directory)?;
        channel = Some(prepared.channel);
        if node.is_none() {
            node = Some(prepared.node);
        }
    }
    let channel = fs::canonicalize(channel.context("channel path is missing")?)
        .context("channel.mjs is missing")?;
    let helper = channel
        .parent()
        .context("invalid channel path")?
        .join("setup.mjs");
    if !helper.is_file() {
        bail!(
            "Capsule setup helper is missing beside channel.mjs; install the complete Claude integration"
        );
    }
    let node = executable(node.unwrap_or_else(|| PathBuf::from("node")))?;
    let options = json!({"action":action,"directory":directory,"state":state,"agent":agent,"channel":channel,"node":node,"claude":claude,"expires_at":expiry,"routes":routes,"workspace":workspace,"claude_args":extra});
    Err(Command::new(&node)
        .arg(helper)
        .arg(options.to_string())
        .exec())
    .context("could not start the Capsule setup helper")
}
