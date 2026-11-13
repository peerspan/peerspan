//! Peerboxes (peerbox contract): the home host's records, the Git commands
//! it runs for them, and the local API. Peer operations are peerbox tasks
//! (`peerbox_task`).
use crate::{
    api::{blocking, decode},
    model::Error,
    store::{Store, append_event, new_id, now},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State, rejection::BytesRejection},
    routing::get,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io::Read,
    os::unix::fs::DirBuilderExt,
    path::{Path as FsPath, PathBuf},
    process::{Command, Output, Stdio},
    sync::{Arc, OnceLock},
};

pub mod contribution;
#[cfg(test)]
mod tests;
pub use contribution::runnable_commit;

/// Database version 32: peerbox records, contributions with their
/// decisions, and pending shares.
pub(crate) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS peerboxes (peerbox_id TEXT PRIMARY KEY, network_id TEXT NOT NULL, record TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS peerbox_contributions (contribution_id TEXT PRIMARY KEY, peerbox_id TEXT NOT NULL, record TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS peerbox_pending_shares (invitation_id TEXT PRIMARY KEY, peerbox_id TEXT NOT NULL, record TEXT NOT NULL);
";

/// The bundle media type (peerbox contract, Requests and Fetch).
pub const BUNDLE_TYPE: &str = "application/x-git-bundle";
/// The artifact contract's limit for one file.
pub const MAX_FILE: i64 = 104_857_600;
/// The oldest Git peerbox commands run with.
const GIT_MINIMUM: (u32, u32) = (2, 34);

/// A peerbox record (peerbox contract, Peerboxes and contributions).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub peerbox_id: String,
    pub network_id: String,
    pub title: String,
    pub repository: String,
    pub branch: String,
    pub created_at: String,
}

/// A failure an operation reports as its final `failed` outcome:
/// `{"error": code, "message": text}`.
#[derive(Debug)]
pub struct Failure {
    pub code: &'static str,
    pub message: String,
}
impl Failure {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
    pub fn output(&self) -> String {
        json!({"error": self.code, "message": self.message}).to_string()
    }
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for Failure {}
fn git_missing() -> Failure {
    Failure::new(
        "git_missing",
        "peerbox commands need git 2.34 or later on PATH",
    )
}

/// Whether `name` is a branch name a peerbox accepts (peerbox contract,
/// Requests): 1 to 64 bytes of `[A-Za-z0-9._-]`, not starting with `-` or
/// `.`, not ending with `.lock` or `/`, without `..`, and one
/// `git check-ref-format --branch` accepts. Within that alphabet Git's
/// further refusals are a name ending with `.` and `HEAD`.
pub fn valid_branch(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && !name.starts_with(['-', '.'])
        && !name.ends_with(".lock")
        && !name.ends_with(['/', '.'])
        && !name.contains("..")
        && name != "HEAD"
}

/// Whether `id` is a commit ID of either object format: 40 or 64
/// lowercase hex digits.
pub fn commit_id(id: &str) -> bool {
    matches!(id.len(), 40 | 64)
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Git as a host runs it for peerboxes: with `core.hooksPath` set to an
/// empty directory the host owns, and no system or global configuration.
#[derive(Clone)]
pub struct Git {
    hooks: PathBuf,
}
impl Git {
    /// Git for the host whose state directory is `state`, after checking
    /// that `git` 2.34 or later is on `PATH` (`git_missing` otherwise).
    pub fn new(state: &FsPath) -> Result<Self, Failure> {
        let hooks = state.join("peerbox-hooks");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&hooks)
            .map_err(|e| {
                Failure::new(
                    "internal",
                    format!("cannot create {}: {e}", hooks.display()),
                )
            })?;
        if std::fs::read_dir(&hooks).is_ok_and(|mut d| d.next().is_some()) {
            return Err(Failure::new(
                "internal",
                format!("{} must be empty", hooks.display()),
            ));
        }
        check_version()?;
        Ok(Self { hooks })
    }
    /// A `git` command in `dir`.
    pub fn command(&self, dir: &FsPath) -> Command {
        let mut c = Command::new("git");
        c.env_clear();
        for name in ["PATH", "HOME", "TMPDIR"] {
            if let Some(value) = std::env::var_os(name) {
                c.env(name, value);
            }
        }
        c.env("LANG", "C")
            .env("LC_ALL", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .arg("-C")
            .arg(dir)
            .arg("-c")
            .arg(format!("core.hooksPath={}", self.hooks.display()))
            .stdin(Stdio::null());
        c
    }
    /// Runs `git ARGS` in `dir`.
    pub fn output(&self, dir: &FsPath, args: &[&str]) -> Result<Output, Failure> {
        self.command(dir).args(args).output().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                git_missing()
            } else {
                Failure::new("internal", format!("git: {e}"))
            }
        })
    }
    /// Runs `git ARGS` in `dir` and returns its trimmed stdout, or `code`
    /// with Git's message.
    pub fn text(&self, dir: &FsPath, args: &[&str], code: &'static str) -> Result<String, Failure> {
        let out = self.output(dir, args)?;
        if !out.status.success() {
            return Err(Failure::new(code, stderr_of(&out)));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    }
    /// The commit `refs/heads/BRANCH` names, or `None`.
    pub fn head(&self, repo: &FsPath, branch: &str) -> Result<Option<String>, Failure> {
        let spec = format!("refs/heads/{branch}^{{commit}}");
        let out = self.output(
            repo,
            &["rev-parse", "--verify", "-q", "--end-of-options", &spec],
        )?;
        Ok(out
            .status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
            .filter(|s| commit_id(s)))
    }
    /// The length of a commit ID in `repo`'s object format.
    pub fn id_length(&self, repo: &FsPath) -> Result<usize, Failure> {
        let format = self.text(repo, &["rev-parse", "--show-object-format"], "unavailable")?;
        Ok(if format == "sha256" { 64 } else { 40 })
    }
    /// Whether `commit` names a commit of `repo` that is an ancestor of
    /// (or equal to) `head`.
    pub fn reachable(&self, repo: &FsPath, commit: &str, head: &str) -> Result<bool, Failure> {
        let out = self.output(repo, &["merge-base", "--is-ancestor", commit, head])?;
        Ok(out.status.success())
    }
    /// Whether `repo` is a Git repository whose top level or Git directory
    /// is exactly `repo`.
    pub fn is_repository(&self, repo: &FsPath) -> Result<bool, Failure> {
        let out = self.output(
            repo,
            &["rev-parse", "--absolute-git-dir", "--show-toplevel"],
        )?;
        if !out.status.success() {
            return Ok(false);
        }
        let given = std::fs::canonicalize(repo).ok();
        Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .any(|line| std::fs::canonicalize(line).ok() == given))
    }
    /// Creates a bundle of `refs/heads/BRANCH` at `out`, without history
    /// reachable from `exclude`. Returns the head the bundle holds.
    pub fn bundle(
        &self,
        repo: &FsPath,
        branch: &str,
        exclude: &[String],
        out: &FsPath,
    ) -> Result<String, Failure> {
        let file = out.to_string_lossy().into_owned();
        let reference = format!("refs/heads/{branch}");
        let mut args: Vec<String> = vec![
            "-c".into(),
            "pack.threads=1".into(),
            "bundle".into(),
            "create".into(),
            "-q".into(),
            file.clone(),
            reference.clone(),
        ];
        args.extend(exclude.iter().map(|c| format!("^{c}")));
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        self.text(repo, &refs, "unavailable")?;
        let heads = self.text(repo, &["bundle", "list-heads", &file], "unavailable")?;
        match heads.lines().collect::<Vec<_>>().as_slice() {
            [line] => match line.split_once(' ') {
                Some((sha, name)) if name == reference && commit_id(sha) => Ok(sha.to_owned()),
                _ => Err(Failure::new("unavailable", "the bundle names another ref")),
            },
            _ => Err(Failure::new("unavailable", "the bundle names another ref")),
        }
    }
}
pub(crate) fn stderr_of(out: &Output) -> String {
    let text = String::from_utf8_lossy(&out.stderr);
    let text = text.trim();
    let mut cut: String = text.chars().take(1000).collect();
    if cut.is_empty() {
        cut = format!("git exited with {}", out.status);
    }
    cut
}
/// Checks once per process that `git` is 2.34 or later.
fn check_version() -> Result<(), Failure> {
    static OK: OnceLock<()> = OnceLock::new();
    if OK.get().is_some() {
        return Ok(());
    }
    let out = Command::new("git")
        .arg("--version")
        .env("LANG", "C")
        .stdin(Stdio::null())
        .output()
        .map_err(|_| git_missing())?;
    let text = String::from_utf8_lossy(&out.stdout);
    let version = text
        .split_whitespace()
        .find(|w| w.starts_with(|c: char| c.is_ascii_digit()))
        .unwrap_or_default();
    let mut parts = version.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
    let found = (parts.next().unwrap_or(0), parts.next().unwrap_or(0));
    if !out.status.success() || found < GIT_MINIMUM {
        return Err(git_missing());
    }
    let _ = OK.set(());
    Ok(())
}

/// What a read of a peerbox discloses (peerbox contract, CLI: create).
#[derive(Clone, Debug, Serialize)]
pub struct Disclosure {
    pub branch: String,
    pub head: String,
    pub commits: u64,
    pub authors: Vec<String>,
    pub committers: Vec<String>,
    pub bundle_bytes: u64,
}
impl Disclosure {
    pub fn text(&self) -> String {
        let list = |people: &[String]| {
            people
                .iter()
                .map(|p| format!("    {p}\n"))
                .collect::<String>()
        };
        format!(
            "A read of this peerbox discloses:\n  branch: {}\n  head: {}\n  commits reachable from it: {}\n  authors:\n{}  committers:\n{}  bundle size: {} bytes\n",
            self.branch,
            self.head,
            self.commits,
            list(&self.authors),
            list(&self.committers),
            self.bundle_bytes
        )
    }
}
/// Reads what a read of `branch` in `repo` discloses, bundling it into a
/// temporary file to measure it.
pub fn disclosure(
    git: &Git,
    repo: &FsPath,
    branch: &str,
    scratch: &FsPath,
) -> Result<Disclosure, Failure> {
    if !git.is_repository(repo)? {
        return Err(Failure::new(
            "invalid",
            format!("{} is not a Git repository", repo.display()),
        ));
    }
    let head = git.head(repo, branch)?.ok_or_else(|| {
        Failure::new(
            "invalid",
            format!("the repository has no branch {branch:?}"),
        )
    })?;
    let commits = git
        .text(repo, &["rev-list", "--count", &head], "unavailable")?
        .parse()
        .unwrap_or(0);
    let people = git.text(
        repo,
        &["log", "--format=%an <%ae>%x00%cn <%ce>", &head],
        "unavailable",
    )?;
    let mut authors = std::collections::BTreeSet::new();
    let mut committers = std::collections::BTreeSet::new();
    for line in people.lines() {
        if let Some((a, c)) = line.split_once('\0') {
            authors.insert(a.to_owned());
            committers.insert(c.to_owned());
        }
    }
    let dir = Scratch::new(scratch)?;
    let out = dir.path().join("peerbox.bundle");
    git.bundle(repo, branch, &[], &out)?;
    let bundle_bytes = std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0);
    Ok(Disclosure {
        branch: branch.into(),
        head,
        commits,
        authors: authors.into_iter().collect(),
        committers: committers.into_iter().collect(),
        bundle_bytes,
    })
}

/// A private temporary directory under `base`, removed when dropped.
pub struct Scratch(PathBuf);
impl Scratch {
    pub fn new(base: &FsPath) -> Result<Self, Failure> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|e| Failure::new("internal", e.to_string()))?;
        let path = base.join(format!("tmp-{}", hex::encode(bytes)));
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&path)
            .map_err(|e| {
                Failure::new("internal", format!("cannot create {}: {e}", path.display()))
            })?;
        Ok(Self(path))
    }
    pub fn path(&self) -> &FsPath {
        &self.0
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// SHA-256 and size of a file.
pub fn digest_file(path: &FsPath) -> std::io::Result<(String, i64)> {
    use sha2::{Digest, Sha256};
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0; 1 << 16];
    let mut total = 0i64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as i64;
    }
    Ok((hex::encode(hasher.finalize()), total))
}

// ---------------------------------------------------------------------
// Records.

pub(crate) fn record(conn: &Connection, id: &str) -> Result<Option<Record>, Error> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT record FROM peerboxes WHERE peerbox_id = ?1",
            [id],
            |r| r.get(0),
        )
        .optional()?;
    raw.map(|r| Ok(serde_json::from_str(&r)?)).transpose()
}
/// Every peerbox record, in ascending ID order.
pub(crate) fn records(conn: &Connection) -> Result<Vec<Record>, Error> {
    let mut statement = conn.prepare("SELECT record FROM peerboxes ORDER BY peerbox_id")?;
    let rows = statement
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|r| Ok(serde_json::from_str(&r)?))
        .collect()
}
/// The contribution records of a peerbox as results return them, newest
/// first.
fn contributions(conn: &Connection, id: &str) -> Result<Vec<Value>, Error> {
    Ok(contribution::of_peerbox(conn, id)?
        .iter()
        .map(contribution::Contribution::view)
        .collect())
}

/// A record as `show` lists it: the record, its rules in this host's
/// owner's current policy, and its pending contribution count.
fn shown(store: &Store, conn: &Connection, r: &Record) -> Result<Value, Error> {
    let own = store.identity().id;
    let mut rules = Vec::new();
    for (network, member) in store.decentralized_own_members(conn)? {
        if network != r.network_id {
            continue;
        }
        let Some(person) = member.person_id else {
            continue;
        };
        let Some(key) = store.product_person_key(conn, &network, &person)? else {
            continue;
        };
        if let Some(policy) = store.product_policy(conn, &network, &key)? {
            rules.extend(
                policy
                    .peerbox_rules()
                    .iter()
                    .filter(|rule| rule.host == own && rule.peerbox == r.peerbox_id)
                    .cloned(),
            );
        }
    }
    let pending: i64 = conn.query_row(
        "SELECT COUNT(*) FROM peerbox_contributions WHERE peerbox_id = ?1 AND json_extract(record, '$.state') = 'pending'",
        [&r.peerbox_id],
        |row| row.get(0),
    )?;
    let mut value = serde_json::to_value(r)?;
    value["rules"] = serde_json::to_value(rules)?;
    value["pending"] = pending.into();
    Ok(value)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    repository: String,
    branch: String,
    #[serde(default)]
    title: Option<String>,
    network_id: String,
}

impl Store {
    /// Creates a peerbox record after checking its repository, branch and
    /// network (peerbox contract, CLI: create).
    fn create_peerbox(&self, c: Create) -> Result<Value, Error> {
        let repository = PathBuf::from(&c.repository);
        if !repository.is_absolute() {
            return Err(Error::Invalid("repository must be an absolute path".into()));
        }
        if !valid_branch(&c.branch) {
            return Err(Error::Invalid("branch".into()));
        }
        let title = match c.title {
            Some(t) => t,
            None => repository
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| c.branch.clone()),
        };
        if title.is_empty() || title.len() > 200 {
            return Err(Error::Invalid("title is 1 to 200 bytes".into()));
        }
        let git = Git::new(self.state_directory()).map_err(coded)?;
        if !git.is_repository(&repository).map_err(coded)? {
            return Err(Error::Invalid(format!(
                "repository: {} is not a Git repository",
                repository.display()
            )));
        }
        if git.head(&repository, &c.branch).map_err(coded)?.is_none() {
            return Err(Error::Invalid(format!(
                "branch: the repository has no branch {:?}",
                c.branch
            )));
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        // A network this host holds is one it is in.
        if !crate::decentralized::product::is_decentralized(&tx, &c.network_id)? {
            return Err(Error::Invalid(
                "network_id: peerboxes are served in a coordinator-free network this host is in"
                    .into(),
            ));
        }
        let r = Record {
            peerbox_id: new_id("pbx")?,
            network_id: c.network_id,
            title,
            repository: c.repository,
            branch: c.branch,
            created_at: now(),
        };
        tx.execute(
            "INSERT INTO peerboxes VALUES (?1, ?2, ?3)",
            params![r.peerbox_id, r.network_id, serde_json::to_string(&r)?],
        )?;
        append_event(&tx, "peerbox.created", &r.peerbox_id, &r.created_at)?;
        tx.commit()?;
        Ok(serde_json::to_value(&r)?)
    }
    /// Deletes a peerbox's record and its member and contribution refs;
    /// contribution records stay.
    fn delete_peerbox(&self, id: &str) -> Result<Value, Error> {
        let r = record(&*self.connection()?, id)?.ok_or(Error::NotFound)?;
        let git = Git::new(self.state_directory()).map_err(coded)?;
        let repo = PathBuf::from(&r.repository);
        let prefix = format!("refs/peerbox/{id}/");
        if let Ok(listed) = git.text(
            &repo,
            &["for-each-ref", "--format=delete %(refname)", &prefix],
            "unavailable",
        ) && !listed.is_empty()
        {
            let mut child = git
                .command(&repo)
                .args(["update-ref", "--stdin"])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| Error::Internal(e.into()))?;
            if let Some(mut stdin) = child.stdin.take() {
                use std::io::Write;
                stdin
                    .write_all(format!("{listed}\n").as_bytes())
                    .map_err(|e| Error::Internal(e.into()))?;
            }
            let out = child
                .wait_with_output()
                .map_err(|e| Error::Internal(e.into()))?;
            if !out.status.success() {
                return Err(Error::Unavailable(stderr_of(&out)));
            }
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM peerboxes WHERE peerbox_id = ?1", [id])?;
        tx.execute(
            "DELETE FROM peerbox_pending_shares WHERE peerbox_id = ?1",
            [id],
        )?;
        append_event(&tx, "peerbox.deleted", id, &now())?;
        tx.commit()?;
        Ok(json!({"peerbox_id": id, "deleted": true}))
    }
}

/// A Git failure on a local route: `git_missing` and the others as coded
/// refusals.
pub(crate) fn coded(f: Failure) -> Error {
    let status = match f.code {
        "git_missing" | "unavailable" => 503,
        "invalid" => 400,
        _ => 500,
    };
    Error::Coded {
        status,
        code: f.code,
        message: f.message,
        extra: Default::default(),
    }
}

pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/peerboxes", get(list).post(create))
        .route("/v1/peerboxes/{id}", get(show).delete(delete))
        .route("/v1/peerboxes/{id}/contributions", get(list_contributions))
        .route(
            "/v1/peerboxes/contributions/{id}/decision",
            axum::routing::post(decide),
        )
}
async fn list(State(store): State<Arc<Store>>) -> Result<Json<Vec<Value>>, Error> {
    Ok(Json(
        blocking(store, |s| {
            let conn = s.connection()?;
            records(&conn)?.iter().map(|r| shown(s, &conn, r)).collect()
        })
        .await?,
    ))
}
async fn create(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let request: Create = decode(body)?;
    Ok(Json(
        blocking(store, move |s| s.create_peerbox(request)).await?,
    ))
}
async fn show(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, Error> {
    Ok(Json(
        blocking(store, move |s| {
            let conn = s.connection()?;
            let r = record(&conn, &id)?.ok_or(Error::NotFound)?;
            shown(s, &conn, &r)
        })
        .await?,
    ))
}
async fn delete(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, Error> {
    Ok(Json(blocking(store, move |s| s.delete_peerbox(&id)).await?))
}
async fn list_contributions(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Vec<Value>>, Error> {
    Ok(Json(
        blocking(store, move |s| {
            let conn = s.connection()?;
            record(&conn, &id)?.ok_or(Error::NotFound)?;
            contributions(&conn, &id)
        })
        .await?,
    ))
}
async fn decide(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let request: contribution::DecisionRequest = decode(body)?;
    Ok(Json(
        blocking(store, move |s| s.decide(&id, request)).await?,
    ))
}
