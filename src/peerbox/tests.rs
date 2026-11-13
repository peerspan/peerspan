//! The owner-requested test (PR #215 review): a contribution whose
//! contribution ref was deleted after the 30-day window is not runnable.
use super::{
    Git, Record,
    contribution::{self, Contribution, Contributor, PENDING},
    runnable_commit,
};
use crate::store::Store;
use chrono::TimeDelta;
use std::{path::Path, process::Command};

fn git(repo: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args(["-c", "user.name=T", "-c", "user.email=t@example.test", "-C"])
        .arg(repo)
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {out:?}");
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

#[test]
fn superseded_contribution_past_retention_is_commit_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("state")).unwrap();
    let repo = dir.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    git(&repo, &["commit", "-q", "--allow-empty", "-m", "main"]);
    let main = git(&repo, &["rev-parse", "HEAD"]);
    let head = git(&repo, &["commit-tree", "HEAD^{tree}", "-p", &main, "-m", "contribution"]);

    let rec = Record {
        peerbox_id: format!("pbx_{}", "1".repeat(32)),
        network_id: "net".into(),
        title: "t".into(),
        repository: repo.to_string_lossy().into_owned(),
        branch: "main".into(),
        created_at: "2026-11-13T00:00:00Z".into(),
    };
    let id = format!("pbc_{}", "2".repeat(32));
    let person = "person_bob";
    let conn = store.connection().unwrap();
    conn.execute(
        "INSERT INTO peerboxes VALUES (?1, ?2, ?3)",
        rusqlite::params![rec.peerbox_id, rec.network_id, serde_json::to_string(&rec).unwrap()],
    )
    .unwrap();
    let start = crate::clock::now();
    let mut c = Contribution {
        contribution_id: id.clone(),
        peerbox_id: rec.peerbox_id.clone(),
        contributor: Contributor {
            person_id: Some(person.into()),
            host_id: Some("host_b".into()),
            agent_id: None,
            session_id: None,
        },
        branch: "feature".into(),
        base: main.clone(),
        head: head.clone(),
        bundle_sha256: "0".repeat(64),
        submitted_at: contribution::stamp(start),
        state: PENDING.into(),
        decision: None,
        runs: Vec::new(),
        ended_at: None,
        ref_deleted: false,
    };
    let name = contribution::contribution_ref(&rec.peerbox_id, &id);
    git(&repo, &["update-ref", &name, &head]);
    c.supersede(&contribution::stamp(start));
    contribution::save(&conn, &c).unwrap();
    let g = Git::new(&dir.path().join("state")).unwrap();

    // Within the 30 days the superseded contribution stays runnable.
    let day29 = start + TimeDelta::days(29);
    runnable_commit(&conn, &g, &rec, Some(person), &head, day29).unwrap();
    contribution::sweep(&store, day29).unwrap();
    assert_eq!(g.head_of(&repo, &name).unwrap().as_deref(), Some(head.as_str()));

    // After them the ref is deleted, the record stays, and a run fails.
    let after = start + contribution::RETENTION + TimeDelta::seconds(1);
    contribution::sweep(&store, after).unwrap();
    assert_eq!(g.head_of(&repo, &name).unwrap(), None);
    let kept = contribution::load(&conn, &id).unwrap().unwrap();
    assert!(kept.ref_deleted && kept.state == "superseded");
    for now in [start, after] {
        let refused = runnable_commit(&conn, &g, &rec, Some(person), &head, now).unwrap_err();
        assert_eq!(refused.code, "commit_unknown");
    }
    // The protected head itself stays runnable.
    runnable_commit(&conn, &g, &rec, Some(person), &main, after).unwrap();
}
