//! Contributions (peerbox contract, Peerboxes and contributions, Submit,
//! Status and withdraw, Review): their records, the checks a submitted
//! bundle passes before anything is stored, member and contribution refs,
//! the 30-day retention of contribution refs, and the owner's decisions.
use super::{Failure, Git, Record, Scratch, commit_id, record, stderr_of};
use crate::{
    model::Error,
    store::{Store, append_event},
};
use chrono::{DateTime, SecondsFormat, TimeDelta, Utc};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Stdio,
};

/// How long a contribution ref stays after its contribution becomes
/// `rejected` or `superseded`.
pub const RETENTION: TimeDelta = TimeDelta::days(30);
/// The latest runs a returned record keeps.
pub const RUNS_SHOWN: usize = 8;
/// The longest decision reason, in bytes.
pub const MAX_REASON: usize = 4096;
/// The ref a bundle is fetched to inside the scratch repositories.
const STAGED: &str = "refs/peerbox-quarantine/head";

pub const PENDING: &str = "pending";
pub const ACCEPTED: &str = "accepted";
pub const REJECTED: &str = "rejected";
pub const SUPERSEDED: &str = "superseded";

/// The submitting person and host, and the task's `origin` agent and
/// session.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Contributor {
    pub person_id: Option<String>,
    pub host_id: Option<String>,
    pub agent_id: Option<String>,
    pub session_id: Option<String>,
}

/// An owner's decision on a contribution.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub decision: String,
    pub reason: String,
    pub decided_at: String,
    pub decided_by: String,
    pub old_head: String,
    pub new_head: String,
}

/// One peerbox run on a contribution's head.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunEntry {
    pub task_id: String,
    pub state: String,
    pub exit_code: Option<i64>,
    pub created_at: String,
    /// The host that sent the run's task: with `task_id`, the received
    /// task's identity (task contract). Stored, never returned.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sender: String,
}

/// A run as a returned record lists it (peerbox contract, Peerboxes and
/// contributions: `runs`).
#[derive(Serialize)]
struct RunView<'a> {
    task_id: &'a str,
    state: &'a str,
    exit_code: Option<i64>,
    created_at: &'a str,
}

/// A contribution as stored: the contract's record and, never returned,
/// when it stopped being `pending` or `accepted` and whether its
/// contribution ref is gone.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Contribution {
    pub contribution_id: String,
    pub peerbox_id: String,
    pub contributor: Contributor,
    pub branch: String,
    pub base: String,
    pub head: String,
    pub bundle_sha256: String,
    pub submitted_at: String,
    pub state: String,
    pub decision: Option<Decision>,
    /// Every run, oldest first.
    pub runs: Vec<RunEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ref_deleted: bool,
}

/// A record as every result returns it, keys in the contract's order.
#[derive(Serialize)]
struct View<'a> {
    contribution_id: &'a str,
    peerbox_id: &'a str,
    contributor: &'a Contributor,
    branch: &'a str,
    base: &'a str,
    head: &'a str,
    bundle_sha256: &'a str,
    submitted_at: &'a str,
    state: &'a str,
    decision: &'a Option<Decision>,
    runs: Vec<RunView<'a>>,
    runs_total: usize,
}

impl Contribution {
    /// The returned record: `runs` cut to the latest 8, with `runs_total`.
    pub fn view(&self) -> Value {
        let cut = self.runs.len().saturating_sub(RUNS_SHOWN);
        serde_json::to_value(View {
            contribution_id: &self.contribution_id,
            peerbox_id: &self.peerbox_id,
            contributor: &self.contributor,
            branch: &self.branch,
            base: &self.base,
            head: &self.head,
            bundle_sha256: &self.bundle_sha256,
            submitted_at: &self.submitted_at,
            state: &self.state,
            decision: &self.decision,
            runs: self.runs[cut..]
                .iter()
                .map(|r| RunView {
                    task_id: &r.task_id,
                    state: &r.state,
                    exit_code: r.exit_code,
                    created_at: &r.created_at,
                })
                .collect(),
            runs_total: self.runs.len(),
        })
        .unwrap_or(Value::Null)
    }
    /// Whether the owner decided it.
    pub fn decided(&self) -> bool {
        matches!(self.state.as_str(), ACCEPTED | REJECTED)
    }
    /// Whether its contribution ref is still kept at `now`: while pending
    /// or accepted, and for 30 days after it became rejected or superseded.
    pub fn ref_kept(&self, now: DateTime<Utc>) -> bool {
        if self.ref_deleted {
            return false;
        }
        match self.state.as_str() {
            PENDING | ACCEPTED => true,
            _ => self
                .ended_at
                .as_deref()
                .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
                .is_none_or(|t| t.with_timezone(&Utc) + RETENTION > now),
        }
    }
    /// Ends a pending contribution as superseded at `at`.
    pub fn supersede(&mut self, at: &str) {
        self.state = SUPERSEDED.into();
        self.ended_at = Some(at.into());
    }
}

/// A timestamp with whole seconds, so that `submitted_at` orders as text.
pub fn stamp(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Secs, true)
}

pub fn contribution_ref(peerbox: &str, id: &str) -> String {
    format!("refs/peerbox/{peerbox}/contributions/{id}")
}
pub fn member_ref(peerbox: &str, person: &str, branch: &str) -> String {
    format!("refs/peerbox/{peerbox}/members/{person}/{branch}")
}
/// Whether a person ID can name a member ref component.
fn ref_safe(person: &str) -> bool {
    (1..=128).contains(&person.len())
        && person
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

// ---------------------------------------------------------------------
// Storage.

pub(crate) fn load(conn: &Connection, id: &str) -> Result<Option<Contribution>, Error> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT record FROM peerbox_contributions WHERE contribution_id = ?1",
            [id],
            |r| r.get(0),
        )
        .optional()?;
    raw.map(|r| Ok(serde_json::from_str(&r)?)).transpose()
}
/// Saves a record. An update keeps the row, so its rowid stays the order
/// in which this host stored its contributions (rows are never deleted,
/// so no rowid is reused); startup recovery relies on that order.
pub(crate) fn save(conn: &Connection, c: &Contribution) -> Result<(), Error> {
    conn.execute(
        "INSERT INTO peerbox_contributions (contribution_id, peerbox_id, record) VALUES (?1, ?2, ?3) ON CONFLICT (contribution_id) DO UPDATE SET peerbox_id = excluded.peerbox_id, record = excluded.record",
        params![c.contribution_id, c.peerbox_id, serde_json::to_string(c)?],
    )?;
    Ok(())
}
fn query(
    conn: &Connection,
    sql: &str,
    args: impl rusqlite::Params,
) -> Result<Vec<Contribution>, Error> {
    let mut statement = conn.prepare(sql)?;
    let rows = statement
        .query_map(args, |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|r| Ok(serde_json::from_str(&r)?))
        .collect()
}
/// A peerbox's contributions, newest first by `(submitted_at,
/// contribution_id)`.
pub(crate) fn of_peerbox(conn: &Connection, peerbox: &str) -> Result<Vec<Contribution>, Error> {
    query(
        conn,
        "SELECT record FROM peerbox_contributions WHERE peerbox_id = ?1 ORDER BY json_extract(record, '$.submitted_at') DESC, contribution_id DESC",
        [peerbox],
    )
}
/// One person's contributions to a peerbox, newest first.
pub(crate) fn of_person(
    conn: &Connection,
    peerbox: &str,
    person: &str,
) -> Result<Vec<Contribution>, Error> {
    query(
        conn,
        "SELECT record FROM peerbox_contributions WHERE peerbox_id = ?1 AND json_extract(record, '$.contributor.person_id') = ?2 ORDER BY json_extract(record, '$.submitted_at') DESC, contribution_id DESC",
        params![peerbox, person],
    )
}
/// Contributions whose contribution ref may be due for deletion.
fn ended(conn: &Connection) -> Result<Vec<Contribution>, Error> {
    query(
        conn,
        "SELECT record FROM peerbox_contributions WHERE json_extract(record, '$.state') IN ('rejected', 'superseded') AND json_extract(record, '$.ref_deleted') IS NULL",
        [],
    )
}

// ---------------------------------------------------------------------
// Git plumbing.

/// Runs `git ARGS` in `dir` with `input` on stdin; returns stdout, or
/// `code` with Git's message.
fn piped(
    git: &Git,
    dir: &Path,
    args: &[&str],
    input: Vec<u8>,
    code: &'static str,
) -> Result<Vec<u8>, Failure> {
    let mut child = git
        .command(dir)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Failure::new("internal", format!("git: {e}")))?;
    let mut stdin = child.stdin.take();
    let writer = std::thread::spawn(move || {
        if let Some(s) = stdin.as_mut() {
            let _ = s.write_all(&input);
        }
    });
    let out = child
        .wait_with_output()
        .map_err(|e| Failure::new("internal", format!("git: {e}")))?;
    let _ = writer.join();
    if !out.status.success() {
        return Err(Failure::new(code, stderr_of(&out)));
    }
    Ok(out.stdout)
}

/// A bare scratch repository of `repo`'s object format that borrows
/// `repo`'s objects.
fn borrowing(git: &Git, repo: &Path, at: &Path, sha256: bool) -> Result<(), Failure> {
    let format = if sha256 {
        "--object-format=sha256"
    } else {
        "--object-format=sha1"
    };
    git.text(
        at.parent().unwrap_or(at),
        &["init", "-q", "--bare", format, &at.to_string_lossy()],
        "unavailable",
    )?;
    let objects = git.text(repo, &["rev-parse", "--git-path", "objects"], "unavailable")?;
    let objects = std::path::absolute(repo.join(objects))
        .map_err(|e| Failure::new("internal", e.to_string()))?;
    std::fs::write(
        at.join("objects/info/alternates"),
        format!("{}\n", objects.display()),
    )
    .map_err(|e| Failure::new("internal", e.to_string()))
}

/// Git's fsck checks a submitted bundle passes, with `hasDotgit` and the
/// `gitmodules*` checks raised from warnings to errors.
const FSCK_RAISED: [&str; 10] = [
    "hasDotgit",
    "gitmodulesBlob",
    "gitmodulesLarge",
    "gitmodulesMissing",
    "gitmodulesName",
    "gitmodulesParse",
    "gitmodulesPath",
    "gitmodulesSymlink",
    "gitmodulesUpdate",
    "gitmodulesUrl",
];
/// `git -c ... fetch` options: fsck on every received object, with the
/// raised checks, and no maintenance afterwards.
fn strict_fetch(source: &Path, refspec: &str) -> Vec<String> {
    let mut args = vec![
        "-c".to_owned(),
        "transfer.fsckObjects=true".to_owned(),
        "-c".to_owned(),
        "gc.auto=0".to_owned(),
        "-c".to_owned(),
        "maintenance.auto=false".to_owned(),
        "-c".to_owned(),
        "fetch.writeCommitGraph=false".to_owned(),
    ];
    for id in FSCK_RAISED {
        for scope in ["fetch.fsck", "fsck"] {
            args.push("-c".into());
            args.push(format!("{scope}.{id}=error"));
        }
    }
    args.extend(
        [
            "fetch",
            "-q",
            "--no-tags",
            "--no-write-fetch-head",
            "--no-recurse-submodules",
        ]
        .map(str::to_owned),
    );
    args.push(source.to_string_lossy().into_owned());
    args.push(refspec.to_owned());
    args
}
fn run(git: &Git, dir: &Path, args: &[String], code: &'static str) -> Result<String, Failure> {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    git.text(dir, &refs, code)
}

/// Whether a tree entry name is `.git` as Git's `hasDotgit` check defines
/// it: in any letter case, and in its HFS+ (ignorable code points) and
/// NTFS (`git~1`, trailing dots and spaces, an alternate stream) spellings.
pub fn is_dotgit(name: &[u8]) -> bool {
    is_ntfs_dotgit(name) || is_hfs_dotgit(name)
}
fn is_ntfs_dotgit(name: &[u8]) -> bool {
    let rest = if name.len() >= 4 && name[..4].eq_ignore_ascii_case(b".git") {
        &name[4..]
    } else if name.len() >= 5 && name[..5].eq_ignore_ascii_case(b"git~1") {
        &name[5..]
    } else {
        return false;
    };
    for &c in rest {
        if matches!(c, b'/' | b'\\' | b':') {
            return true;
        }
        if c != b'.' && c != b' ' {
            return false;
        }
    }
    true
}
/// HFS+ ignores these code points in names.
fn hfs_ignorable(c: char) -> bool {
    matches!(c as u32, 0x200c..=0x200f | 0x202a..=0x202e | 0x206a..=0x206f | 0xfeff)
}
fn is_hfs_dotgit(name: &[u8]) -> bool {
    // As Git reads it: malformed UTF-8 ends the name.
    let mut chars: Vec<char> = Vec::new();
    for chunk in name.utf8_chunks() {
        chars.extend(chunk.valid().chars().filter(|c| !hfs_ignorable(*c)));
        if !chunk.invalid().is_empty() {
            break;
        }
    }
    let lower: Vec<char> = chars.iter().map(|c| c.to_ascii_lowercase()).collect();
    lower.len() >= 4 && lower[..4] == ['.', 'g', 'i', 't'] && lower.get(4).is_none_or(|c| *c == '/')
}

/// Refuses any tree entry named `.git` among the trees reachable from
/// `head` and not from `trusted`, read in `repo`.
fn refuse_dotgit(
    git: &Git,
    repo: &Path,
    head: &str,
    trusted: &str,
    id_bytes: usize,
) -> Result<(), Failure> {
    let listed = git.text(
        repo,
        &[
            "rev-list",
            "--objects",
            "--no-object-names",
            head,
            "--not",
            trusted,
        ],
        "bundle_invalid",
    )?;
    if listed.is_empty() {
        return Ok(());
    }
    let typed = piped(
        git,
        repo,
        &["cat-file", "--batch-check=%(objecttype) %(objectname)"],
        format!("{listed}\n").into_bytes(),
        "bundle_invalid",
    )?;
    let trees: String = String::from_utf8_lossy(&typed)
        .lines()
        .filter_map(|l| l.strip_prefix("tree "))
        .map(|id| format!("{id}\n"))
        .collect();
    if trees.is_empty() {
        return Ok(());
    }
    let raw = piped(
        git,
        repo,
        &["cat-file", "--batch"],
        trees.into_bytes(),
        "bundle_invalid",
    )?;
    let bad = || Failure::new("bundle_invalid", "a tree object could not be read");
    let mut rest = raw.as_slice();
    while !rest.is_empty() {
        let line_end = rest.iter().position(|b| *b == b'\n').ok_or_else(bad)?;
        let header = std::str::from_utf8(&rest[..line_end]).map_err(|_| bad())?;
        let mut parts = header.split(' ');
        let (id, kind, size) = (parts.next(), parts.next(), parts.next());
        let size: usize = size.and_then(|s| s.parse().ok()).ok_or_else(bad)?;
        if kind != Some("tree") || rest.len() < line_end + 1 + size + 1 {
            return Err(bad());
        }
        let mut tree = &rest[line_end + 1..line_end + 1 + size];
        rest = &rest[line_end + 1 + size + 1..];
        while !tree.is_empty() {
            let space = tree.iter().position(|b| *b == b' ').ok_or_else(bad)?;
            let nul = tree.iter().position(|b| *b == 0).ok_or_else(bad)?;
            if nul < space || tree.len() < nul + 1 + id_bytes {
                return Err(bad());
            }
            let name = &tree[space + 1..nul];
            if is_dotgit(name) {
                return Err(Failure::new(
                    "bundle_invalid",
                    format!(
                        "tree {} has an entry named {:?}, which is .git as Git's hasDotgit check defines it",
                        id.unwrap_or_default(),
                        String::from_utf8_lossy(name)
                    ),
                ));
            }
            tree = &tree[nul + 1 + id_bytes..];
        }
    }
    Ok(())
}

/// The prerequisites a bundle file's header names, read as Git reads
/// them: lines starting with `-`, before the blank line.
fn prerequisites(file: &Path) -> Result<Vec<String>, Failure> {
    let invalid = |m: &str| Failure::new("bundle_invalid", m.to_owned());
    let f = std::fs::File::open(file).map_err(|e| Failure::new("internal", e.to_string()))?;
    let mut header = Vec::new();
    f.take(1 << 20)
        .read_to_end(&mut header)
        .map_err(|e| Failure::new("internal", e.to_string()))?;
    let end = header
        .windows(2)
        .position(|w| w == b"\n\n")
        .ok_or_else(|| invalid("the bundle has no header"))?;
    let text = std::str::from_utf8(&header[..end])
        .map_err(|_| invalid("the bundle header is not UTF-8"))?;
    let mut lines = text.lines();
    if !matches!(lines.next(), Some("# v2 git bundle" | "# v3 git bundle")) {
        return Err(invalid("not a version 2 or 3 Git bundle"));
    }
    Ok(lines
        .filter_map(|l| l.strip_prefix('-'))
        .map(|l| l.split(' ').next().unwrap_or_default().to_owned())
        .collect())
}

/// Indexes the pack after `file`'s header into `stage` with `git
/// index-pack --strict`, which checks each object of the pack (and that
/// what they name exists) with the raised checks as errors.
fn index_pack(git: &Git, stage: &Path, file: &Path) -> Result<(), Failure> {
    use std::io::{BufRead, Seek, SeekFrom};
    let invalid = |m: &str| Failure::new("bundle_invalid", m.to_owned());
    let internal = |e: std::io::Error| Failure::new("internal", e.to_string());
    let mut f = std::fs::File::open(file).map_err(internal)?;
    // The header ends with its first empty line.
    let mut offset = 0u64;
    {
        let mut reader = std::io::BufReader::new((&f).take(1 << 20));
        let mut line = Vec::new();
        loop {
            line.clear();
            let n = reader.read_until(b'\n', &mut line).map_err(internal)?;
            if n == 0 || !line.ends_with(b"\n") {
                return Err(invalid("the bundle has no header"));
            }
            offset += n as u64;
            if line == b"\n" {
                break;
            }
        }
    }
    f.seek(SeekFrom::Start(offset)).map_err(internal)?;
    let strict = format!(
        "--strict={}",
        FSCK_RAISED.map(|id| format!("{id}=error")).join(",")
    );
    let out = git
        .command(stage)
        .args(["index-pack", "--stdin", "--fix-thin", &strict])
        .stdin(Stdio::from(f))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| Failure::new("internal", format!("git: {e}")))?;
    if !out.status.success() {
        return Err(Failure::new("bundle_invalid", stderr_of(&out)));
    }
    Ok(())
}

/// What a submission stores once its bundle passed every check.
pub(crate) struct Verified {
    pub head: String,
    /// The scratch directory holding the quarantine; removed when dropped.
    scratch: Scratch,
}
impl Verified {
    fn quarantine(&self) -> PathBuf {
        self.scratch.path().join("quarantine")
    }
}

/// Submit steps 2 and 3 (and the bundle's shape): verifies `file`,
/// fetches it into a quarantine repository with fsck and the raised
/// checks, refuses `.git` entries, and checks `base`. Nothing of `repo`
/// changes.
pub(crate) fn verify(
    git: &Git,
    rec: &Record,
    file: &Path,
    branch: &str,
    base: &str,
    scratch_base: &Path,
) -> Result<Verified, Failure> {
    let repo = PathBuf::from(&rec.repository);
    let protected = git.head(&repo, &rec.branch)?.ok_or_else(|| {
        Failure::new(
            "unavailable",
            format!("the protected branch {} has no head", rec.branch),
        )
    })?;
    let id_length = git.id_length(&repo)?;
    // The quarantine has the repository's object format; a bundle of
    // another format is refused before Git reads it.
    let format = if id_length == 64 { "sha256" } else { "sha1" };
    if super::bundle_object_format(file)? != format {
        return Err(Failure::new(
            "bundle_invalid",
            format!("the bundle's object format is not the peerbox repository's ({format})"),
        ));
    }
    let scratch = Scratch::new(scratch_base)?;
    let stage = scratch.path().join("quarantine");
    borrowing(git, &repo, &stage, id_length == 64)?;
    let file_text = file.to_string_lossy().into_owned();
    // The single ref refs/heads/BRANCH, read before the bundle reaches any
    // other Git command.
    let wanted = format!("refs/heads/{branch}");
    let heads = git.text(
        &stage,
        &["bundle", "list-heads", &file_text],
        "bundle_invalid",
    )?;
    let head = match heads.lines().collect::<Vec<_>>().as_slice() {
        [line] => line
            .split_once(' ')
            .filter(|(sha, name)| *name == wanted && commit_id(sha) && sha.len() == id_length)
            .map(|(sha, _)| sha.to_owned()),
        _ => None,
    }
    .ok_or_else(|| {
        Failure::new(
            "bundle_invalid",
            format!("the bundle's single ref must be {wanted}"),
        )
    })?;
    for prerequisite in prerequisites(file)? {
        if !commit_id(&prerequisite)
            || prerequisite.len() != id_length
            || !git.reachable(&repo, &prerequisite, &protected)?
        {
            return Err(Failure::new(
                "bundle_invalid",
                "the bundle's prerequisites must be reachable from the protected head",
            ));
        }
    }
    git.text(
        &stage,
        &["bundle", "verify", "-q", &file_text],
        "bundle_invalid",
    )?;
    // The bundle's pack is indexed into the quarantine with Git's fsck
    // checks on every object it holds, the raised ones as errors. Only
    // those objects are checked: the home repository's own objects, seen
    // through the alternates, are not (a fetch from a bundle file applies
    // no fsck before Git 2.46, and `git fsck` there would check the whole
    // repository).
    index_pack(git, &stage, file)?;
    git.text(&stage, &["update-ref", STAGED, &head], "bundle_invalid")?;
    let quarantine = stage;
    if git.head_of(&quarantine, STAGED)?.as_deref() != Some(head.as_str()) {
        return Err(Failure::new(
            "bundle_invalid",
            "the bundle's ref names another commit",
        ));
    }
    refuse_dotgit(git, &quarantine, &head, &protected, id_length / 2)?;
    // Step 3.
    if !git.reachable(&repo, base, &protected)? {
        return Err(Failure::new(
            "base_unknown",
            format!("{base} is not reachable from the protected head"),
        ));
    }
    if !git.reachable(&quarantine, base, &head)? {
        return Err(Failure::new(
            "base_not_ancestor",
            format!("{base} is not an ancestor of {head}"),
        ));
    }
    Ok(Verified { head, scratch })
}

/// Submit step 4: moves the verified objects into the repository under the
/// contribution ref, then sets the member ref.
pub(crate) fn store_refs(
    git: &Git,
    rec: &Record,
    verified: &Verified,
    contribution: &str,
    person: &str,
    branch: &str,
) -> Result<(), Failure> {
    if !ref_safe(person) {
        return Err(Failure::new("invalid", "the sender's person ID"));
    }
    let repo = PathBuf::from(&rec.repository);
    let target = contribution_ref(&rec.peerbox_id, contribution);
    run(
        git,
        &repo,
        &strict_fetch(&verified.quarantine(), &format!("+{STAGED}:{target}")),
        "unavailable",
    )?;
    git.text(
        &repo,
        &[
            "update-ref",
            &member_ref(&rec.peerbox_id, person, branch),
            &verified.head,
        ],
        "unavailable",
    )?;
    Ok(())
}

impl Git {
    /// The commit a full ref name names, or `None`.
    pub fn head_of(&self, repo: &Path, name: &str) -> Result<Option<String>, Failure> {
        let spec = format!("{name}^{{commit}}");
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
    /// Deletes `name` when it still names `old` (or whatever it names when
    /// `old` is `None`); a ref already gone is not an error.
    pub fn delete_ref(&self, repo: &Path, name: &str, old: Option<&str>) -> Result<(), Failure> {
        let Some(current) = self.head_of(repo, name)? else {
            return Ok(());
        };
        if old.is_some_and(|o| o != current) {
            return Ok(());
        }
        self.text(repo, &["update-ref", "-d", name, &current], "unavailable")?;
        Ok(())
    }
}

/// Whether `commit` may be run on this peerbox by `person` (peerbox
/// contract, Runs): the protected head, or the head of a contribution the
/// person may read (their own, or one accepted) whose contribution ref
/// still exists at `now`. Otherwise `commit_unknown`. A `run` checks this
/// before anything else of the run.
///
/// It takes the store's connection only for its query, never while Git
/// runs.
pub fn runnable_commit(
    store: &Store,
    git: &Git,
    rec: &Record,
    person: Option<&str>,
    commit: &str,
    now: DateTime<Utc>,
) -> Result<(), Failure> {
    let unknown = || {
        Failure::new(
            "commit_unknown",
            format!("{commit} is neither the protected head nor a contribution you may run"),
        )
    };
    let repo = PathBuf::from(&rec.repository);
    if git.head(&repo, &rec.branch)?.as_deref() == Some(commit) {
        return Ok(());
    }
    let found = query(
        &*store.connection().map_err(|e| Failure::new("internal", e.to_string()))?,
        "SELECT record FROM peerbox_contributions WHERE peerbox_id = ?1 AND json_extract(record, '$.head') = ?2",
        params![rec.peerbox_id, commit],
    )
    .map_err(|e| Failure::new("internal", e.to_string()))?;
    for c in found {
        let readable = c.state == ACCEPTED
            || (person.is_some() && c.contributor.person_id.as_deref() == person);
        if !readable || !c.ref_kept(now) {
            continue;
        }
        let name = contribution_ref(&rec.peerbox_id, &c.contribution_id);
        if git.head_of(&repo, &name)?.as_deref() == Some(commit) {
            return Ok(());
        }
    }
    Err(unknown())
}

/// Deletes the contribution refs whose 30 days after `rejected` or
/// `superseded` have passed at `now`; their records stay, marked.
pub fn sweep(store: &Store, now: DateTime<Utc>) -> Result<(), Error> {
    let due: Vec<Contribution> = ended(&*store.connection()?)?
        .into_iter()
        .filter(|c| !c.ref_kept(now))
        .collect();
    if due.is_empty() {
        return Ok(());
    }
    let git = Git::new(store.state_directory()).map_err(super::coded)?;
    for mut c in due {
        let found = record(&*store.connection()?, &c.peerbox_id)?;
        // A ref that cannot be deleted now is tried again on a later sweep.
        if let Some(rec) = found
            && git
                .delete_ref(
                    Path::new(&rec.repository),
                    &contribution_ref(&c.peerbox_id, &c.contribution_id),
                    None,
                )
                .is_err()
        {
            continue;
        }
        let mut conn = store.connection()?;
        let tx = conn.transaction()?;
        if let Some(current) = load(&tx, &c.contribution_id)?
            && current.state == c.state
        {
            c = current;
            c.ref_deleted = true;
            save(&tx, &c)?;
        }
        tx.commit()?;
    }
    Ok(())
}

/// Startup recovery (peerbox contract): deletes contribution refs that no
/// record names, and sets every member ref to what the latest recorded
/// submission of that person on that branch requires, both left by a
/// submission interrupted between its refs and its record.
pub fn sweep_orphans(store: &Store) -> Result<(), Error> {
    let records = super::records(&*store.connection()?)?;
    if records.is_empty() {
        return Ok(());
    }
    let git = Git::new(store.state_directory()).map_err(super::coded)?;
    for rec in records {
        let repo = PathBuf::from(&rec.repository);
        let prefix = format!("refs/peerbox/{}/contributions/", rec.peerbox_id);
        let Ok(listed) = git.text(
            &repo,
            &["for-each-ref", "--format=%(refname)", &prefix],
            "unavailable",
        ) else {
            continue;
        };
        for name in listed.lines() {
            let Some(id) = name.strip_prefix(&prefix) else {
                continue;
            };
            if load(&*store.connection()?, id)?.is_none() {
                let _ = git.delete_ref(&repo, name, None);
            }
        }
        // Every member ref is set to what the latest recorded submission of
        // that person on that branch requires: its head, or no ref when it
        // was withdrawn or there is none (peerbox contract, Startup
        // recovery).
        let prefix = format!("refs/peerbox/{}/members/", rec.peerbox_id);
        let Ok(listed) = git.text(
            &repo,
            &["for-each-ref", "--format=%(refname) %(objectname)", &prefix],
            "unavailable",
        ) else {
            continue;
        };
        let mut actual: std::collections::BTreeMap<String, String> = listed
            .lines()
            .filter_map(|l| l.split_once(' '))
            .map(|(name, head)| (name.to_owned(), head.to_owned()))
            .collect();
        // Latest stored first (submitted_at can tie, and contribution IDs
        // are random): the first record of each person and branch is the
        // latest recorded submission there.
        let mut expected: std::collections::BTreeMap<String, Option<String>> = Default::default();
        let stored = query(
            &*store.connection()?,
            "SELECT record FROM peerbox_contributions WHERE peerbox_id = ?1 ORDER BY rowid DESC",
            [&rec.peerbox_id],
        )?;
        for c in stored {
            let Some(person) = c.contributor.person_id.as_deref() else {
                continue;
            };
            if !ref_safe(person) {
                continue;
            }
            expected
                .entry(member_ref(&rec.peerbox_id, person, &c.branch))
                .or_insert_with(|| (c.state != SUPERSEDED).then(|| c.head.clone()));
        }
        for (name, want) in &expected {
            let have = actual.remove(name);
            match (want, have) {
                (Some(want), Some(have)) if *want == have => {}
                (Some(want), Some(have)) => {
                    let _ = git.text(&repo, &["update-ref", name, want, &have], "unavailable");
                }
                (Some(want), None) => {
                    let _ = git.text(&repo, &["update-ref", name, want, ""], "unavailable");
                }
                (None, Some(have)) => {
                    let _ = git.delete_ref(&repo, name, Some(&have));
                }
                (None, None) => {}
            }
        }
        // Member refs of a person and branch with no record at all.
        for (name, have) in actual {
            let _ = git.delete_ref(&repo, &name, Some(&have));
        }
    }
    Ok(())
}

/// Runs `f` holding `peerbox`'s lock. Every change to a peerbox's
/// contributions and their refs (review, withdrawal, storing a
/// submission) holds it from its state check to its durable record, so
/// two of them never interleave.
pub(crate) fn with_lock<T>(peerbox: &str, f: impl FnOnce() -> T) -> T {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex, OnceLock},
    };
    static LOCKS: OnceLock<Mutex<HashMap<String, Arc<Mutex<()>>>>> = OnceLock::new();
    let lock = LOCKS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry(peerbox.to_owned())
        .or_default()
        .clone();
    let _held = lock.lock().unwrap_or_else(|e| e.into_inner());
    f()
}

// ---------------------------------------------------------------------
// Review (local API and CLI only).

/// The owner's decision request.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DecisionRequest {
    pub decision: String,
    #[serde(default)]
    pub reason: Option<String>,
}

fn conflict(code: &'static str, message: impl Into<String>) -> Error {
    Error::Coded {
        status: 409,
        code,
        message: message.into(),
        extra: Default::default(),
    }
}

/// The worktrees that have `branch` checked out.
fn worktrees(git: &Git, repo: &Path, branch: &str) -> Result<Vec<PathBuf>, Failure> {
    let listed = git.text(repo, &["worktree", "list", "--porcelain"], "unavailable")?;
    let wanted = format!("branch refs/heads/{branch}");
    let mut out = Vec::new();
    let mut current: Option<PathBuf> = None;
    let mut bare = false;
    for line in listed.lines().chain(std::iter::once("")) {
        if let Some(path) = line.strip_prefix("worktree ") {
            current = Some(PathBuf::from(path));
            bare = false;
        } else if line == "bare" {
            bare = true;
        } else if line == wanted
            && !bare
            && let Some(path) = &current
        {
            out.push(path.clone());
        } else if line.is_empty() {
            current = None;
        }
    }
    Ok(out)
}

impl Store {
    /// The owner's person ID in a network, for `decided_by`.
    fn owner_person(&self, conn: &Connection, network: &str) -> Result<Option<String>, Error> {
        Ok(self
            .decentralized_own_members(conn)?
            .into_iter()
            .find(|(n, _)| n == network)
            .and_then(|(_, m)| m.person_id))
    }

    /// Accepts or rejects a pending contribution (peerbox contract,
    /// Review). Accepting fast-forwards the protected branch, and a clean
    /// worktree that has it checked out, with a compare-and-swap.
    pub(crate) fn decide(&self, id: &str, request: DecisionRequest) -> Result<Value, Error> {
        let accept = match request.decision.as_str() {
            "accepted" | "accept" => true,
            "rejected" | "reject" => false,
            _ => return Err(Error::Invalid("decision is accepted or rejected".into())),
        };
        let reason = request.reason.unwrap_or_default();
        if reason.len() > MAX_REASON {
            return Err(Error::Invalid(format!(
                "reason is at most {MAX_REASON} bytes"
            )));
        }
        let (peerbox, rec, by) = {
            let conn = self.connection()?;
            let c = load(&conn, id)?.ok_or(Error::NotFound)?;
            let rec = record(&conn, &c.peerbox_id)?.ok_or(Error::NotFound)?;
            let by = self.owner_person(&conn, &rec.network_id)?;
            (c.peerbox_id, rec, by)
        };
        // The pending check, the Git changes and the decision hold the
        // peerbox's lock, as every change to its contributions does: a
        // competing review, withdrawal or replacement waits, then finds the
        // contribution no longer pending.
        with_lock(&peerbox, || self.decide_locked(id, accept, reason, rec, by))
    }

    fn decide_locked(
        &self,
        id: &str,
        accept: bool,
        reason: String,
        rec: Record,
        by: Option<String>,
    ) -> Result<Value, Error> {
        let c = {
            let conn = self.connection()?;
            // Deleted meanwhile: as for an unknown peerbox.
            record(&conn, &rec.peerbox_id)?.ok_or(Error::NotFound)?;
            load(&conn, id)?.ok_or(Error::NotFound)?
        };
        if c.state != PENDING {
            return Err(conflict(
                "not_pending",
                format!("the contribution is {}, not pending", c.state),
            ));
        }
        let by = by.ok_or_else(|| {
            Error::Unavailable("this host has no person in the peerbox's network".into())
        })?;
        let git = Git::new(self.state_directory()).map_err(super::coded)?;
        let repo = PathBuf::from(&rec.repository);
        let old = git
            .head(&repo, &rec.branch)
            .map_err(super::coded)?
            .ok_or_else(|| Error::Unavailable("the protected branch has no head".into()))?;
        let new = if accept {
            self.fast_forward(&git, &repo, &rec, &old, &c.head)?;
            c.head.clone()
        } else {
            old.clone()
        };
        let at = stamp(crate::clock::now());
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let mut c = load(&tx, id)?.ok_or(Error::NotFound)?;
        if c.state != PENDING {
            return Err(conflict(
                "not_pending",
                format!("the contribution is {}, not pending", c.state),
            ));
        }
        c.state = if accept { ACCEPTED } else { REJECTED }.into();
        c.decision = Some(Decision {
            decision: c.state.clone(),
            reason,
            decided_at: at.clone(),
            decided_by: by,
            old_head: old,
            new_head: new,
        });
        if !accept {
            c.ended_at = Some(at.clone());
        }
        save(&tx, &c)?;
        append_event(
            &tx,
            "peerbox.decided",
            &format!("{}/{}", c.peerbox_id, c.contribution_id),
            &at,
        )?;
        tx.commit()?;
        Ok(c.view())
    }

    /// Review steps 2 to 4 for accepting `new` onto the protected head
    /// `old`.
    fn fast_forward(
        &self,
        git: &Git,
        repo: &Path,
        rec: &Record,
        old: &str,
        new: &str,
    ) -> Result<(), Error> {
        if !git.reachable(repo, old, new).map_err(super::coded)? {
            return Err(conflict(
                "not_fast_forward",
                "the protected head is not an ancestor of the contribution head; the contributor rebases and submits again",
            ));
        }
        let trees = worktrees(git, repo, &rec.branch).map_err(super::coded)?;
        for wt in &trees {
            let status = git
                .text(
                    wt,
                    &["status", "--porcelain", "--untracked-files=no"],
                    "unavailable",
                )
                .map_err(super::coded)?;
            if !status.is_empty() {
                return Err(conflict(
                    "dirty_worktree",
                    format!("the worktree {} has uncommitted changes", wt.display()),
                ));
            }
        }
        let mut moved: Vec<&PathBuf> = Vec::new();
        let undo = |moved: &[&PathBuf]| {
            for wt in moved {
                let _ = git.text(wt, &["read-tree", "-m", "-u", new, old], "unavailable");
            }
        };
        for wt in &trees {
            if let Err(f) = git.text(wt, &["read-tree", "-m", "-u", old, new], "dirty_worktree") {
                undo(&moved);
                return Err(conflict("dirty_worktree", f.message));
            }
            moved.push(wt);
        }
        let name = format!("refs/heads/{}", rec.branch);
        if git
            .text(
                repo,
                &["update-ref", "-m", "peerbox accept", &name, new, old],
                "head_moved",
            )
            .is_err()
        {
            undo(&moved);
            return Err(conflict(
                "head_moved",
                "the protected branch moved during the review",
            ));
        }
        Ok(())
    }
}

/// Saves contributions inside a task's final transaction. A contribution
/// the owner decided meanwhile keeps its decision: superseding or
/// withdrawing changes only a pending one.
pub(crate) fn save_all(tx: &Transaction<'_>, writes: &[Contribution]) -> Result<(), Error> {
    for c in writes {
        let current = load(tx, &c.contribution_id)?;
        if c.state == SUPERSEDED
            && current
                .as_ref()
                .is_some_and(|current| current.state != PENDING)
        {
            continue;
        }
        // Runs recorded meanwhile are the runtime's and stay.
        let mut c = c.clone();
        if let Some(current) = current {
            c.runs = current.runs;
        }
        save(tx, &c)?;
    }
    Ok(())
}
