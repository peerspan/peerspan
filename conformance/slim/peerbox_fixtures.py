"""Git fixture builders of the peerbox suites, and a host-free self-check of all of them.

Every case of peerbox.py and peerbox_runs.py stops at the first peerbox command until the contract is implemented,
so fixture code after that point would otherwise never run before review. The cases build their repositories,
commits and bundles only through the functions here, and each suite runs `self_check` as its first case (no
expected-failure marker): a fixture that does not produce what a case expects is a FAIL, never an XFAIL.

Written from docs/peerbox-contract.md only; uses the system `git` and nothing of the host.
"""
import os
import shutil
import sqlite3
import subprocess
import time
from pathlib import Path

from harness import check
from peerbox_common import (bundle, bundle_heads, commit_files, git, init_repo, rename_ref, rev, tree_commit, unbundle)

HOOK = "#!/bin/sh\n[ -n \"$PBX_FIXTURE\" ] || touch \"$(dirname \"$0\")/../../HOOK_RAN\"\n"
CONFIG = b"[core]\n\thooksPath = .\n"
# Submit step 2: a tree entry named `.git` as Git's hasDotgit defines it, at any depth, in any case and in its HFS+
# (ignorable code points) and NTFS (8.3 short name, trailing dot) spellings, whatever its type.
DOTGIT = {".git/hooks": {".git/hooks/post-checkout": ("100755", b"#!/bin/sh\ntouch /tmp/peerbox-hostile-hook\n")},
          ".GIT/config": {".GIT/config": ("100644", CONFIG)},
          "a deep .Git file": {"a/b/.Git": ("100644", b"gitdir: /etc\n")},
          "a .git symlink": {"sub/.git": ("120000", b"/etc")},
          "HFS+ .g\\u200cit": {".g‌it/config": ("100644", CONFIG)},
          "NTFS git~1": {"GIT~1/config": ("100644", CONFIG)},
          "NTFS .git.": {"deep/.git./config": ("100644", CONFIG)}}
# The tables of a schema-31 host.db, read from a fresh host built from main at 13128db.
SCHEMA_TABLES = frozenset("""
access_blocks adapter_calls adapter_connections adapter_credentials adapter_outbound adapter_routes agent_descriptions
agents approval_notices artifact_files builtin_sources call_approvals call_update_notifications capabilities
conversation_events conversation_invites conversation_messages conversation_notifications conversation_reads
conversation_roster_outbound conversation_targets conversations dec_activations dec_admissions dec_clock dec_contacts
dec_contexts dec_frames dec_heads dec_helpers dec_highwater dec_intents dec_migrations dec_objects dec_operations
dec_outbox dec_pending dec_restrictions dec_signers deliveries directory_sends events grants identity link_device_keys
link_features link_frames link_highwater link_objects link_operations link_pending link_signers network_members
network_statements networks oauth_clients oauth_credentials onboarding_adapter_flows onboarding_invitation_flows
onboarding_join_flows onboarding_project_flows outbound_calls outbound_messages outbound_replies outbound_task_events
outbound_tasks peers policy_deliveries policy_edits received_calls received_messages received_replies received_tasks
sessions source_access task_artifacts task_children task_deliveries task_events task_update_notifications tool_servers
tool_values""".split())
# peerbox_runs: the workspace fixture, with an executable, a symbolic link, a submodule and export attributes.
TREE = {"README.md": ("100644", b"hello\n"), "bin/run.sh": ("100755", b"#!/bin/sh\necho run\n"),
        "link": ("120000", b"README.md"), "vendor/lib": ("160000", ("5" * 40).encode()),
        ".gitattributes": ("100644", b"ignored.txt export-ignore\nsubst.txt export-subst\n*.txt text eol=crlf\n"),
        "ignored.txt": ("100644", b"kept\n"), "subst.txt": ("100644", b"$Format:%H$\n"),
        "lines.txt": ("100644", b"a\nb\n"), "sub/dir/deep.txt": ("100644", b"deep\n")}


def owner_repo(path):
    """peerbox.py's repository: main of 3 commits (the first with 1,000 incompressible bytes, so every bundle of
    main exceeds carol's 400-byte read bound), a `secret` branch main never reaches, and a reference-transaction
    hook marking any ref change made with hooks enabled. Returns {repo, main, main_parent, secret}."""
    repo = init_repo(path)
    commit_files(repo, {"README": "project\n", "data.bin": os.urandom(1000)}, "first")
    parent = commit_files(repo, {"lib.txt": "one\n"}, "second")
    git(repo, "checkout", "-q", "-b", "secret")
    git(repo, "commit", "-q", "--allow-empty", "--author", "Sly Secret <sly@example.test>", "-m", "secret")
    secret = rev(repo, "secret")
    git(repo, "checkout", "-q", "main")
    main = commit_files(repo, {"lib.txt": "two\n"}, "third")
    hook = repo / ".git/hooks/reference-transaction"
    hook.write_text(HOOK)
    hook.chmod(0o755)
    return {"repo": repo, "main": main, "main_parent": parent, "secret": secret}


def runs_repo(path):
    """peerbox_runs.py's repository: main is TREE on top of a first commit; `secret` is outside main."""
    repo = init_repo(path)
    first = commit_files(repo, {"README.md": "hello\n"}, "first")
    git(repo, "checkout", "-q", "-b", "secret")
    secret = commit_files(repo, {"secret.txt": "s\n"}, "secret")
    git(repo, "checkout", "-q", "main")
    main = tree_commit(repo, TREE, parent=first, message="the workspace fixture")
    git(repo, "update-ref", "refs/heads/main", main)
    git(repo, "reset", "-q", "--hard", "main")
    return {"repo": repo, "main": main, "secret": secret}


def worktree(clone, wt, pbx, branch="feature"):
    """A worktree of a CLI-fetched repository on BRANCH, started from the fetched `refs/peerbox/PBX/main`."""
    git(clone, "worktree", "add", "-q", wt, "-b", branch, f"refs/peerbox/{pbx}/main")
    return wt


def commit_on(wt, branch, files, start=None):
    """A commit on BRANCH in worktree WT (reset to START when given); returns its ID."""
    git(wt, "checkout", "-q", *(["-B", branch, start] if start else [branch]))
    return commit_files(wt, files, f"{branch}: {sorted(files)}")


def oversized(clone, wt, out, branch, base, limit, size, start=None):
    """A commit of SIZE incompressible bytes on BRANCH and its bundle without BASE, checked to exceed LIMIT."""
    tip = commit_on(wt, branch, {f"{branch}.bin": os.urandom(size)}, start)
    data = bundle(clone, out, tip, exclude=[base], ref=branch)
    check(len(data) > limit, f"fixture: the {branch} bundle has {len(data)} bytes, not over the bound of {limit}")
    return tip, data


def paging_bundles(clone, wt, work, base, count=16):
    """COUNT contributions p00.. on BASE, each bundled alone: [(branch, bundle)]."""
    tips = [(f"p{i:02d}", commit_on(wt, f"p{i:02d}", {f"p{i}.txt": f"{i}\n"}, start=base)) for i in range(count)]
    return [(n, bundle(clone, Path(work) / f"{n}.bundle", t, exclude=[base], ref=n)) for n, t in tips]


def base_error_bundles(clone, wt, work, main, parent):
    """`based` on main (for wrong bases) and `old-base` on main's parent (for base main): (based, old) bundles."""
    tip = commit_on(wt, "based", {"b.txt": "b\n"}, start=main)
    based = bundle(clone, Path(work) / "based.bundle", tip, exclude=[main], ref="based")
    old = commit_on(wt, "old-base", {"o.txt": "o\n"}, start=parent)
    return based, bundle(clone, Path(work) / "old.bundle", old, exclude=[parent], ref="old-base")


def hostile_bundles(clone, wt, work, main, member_ref):
    """The hostile submissions on branch `hostile`: (mutated, by_ref, by_dotgit). MEMBER_REF is a contributor's
    `refs/peerbox/...` member ref to impersonate."""
    work = Path(work)
    tip = commit_on(wt, "hostile", {"h.txt": "h\n"}, start=main)
    good = bundle(clone, work / "hostile.bundle", tip, exclude=[main], ref="hostile")
    header = good.index(b"\n\n") + 2
    middle = header + (len(good) - header) // 2
    mutated = good[:middle] + bytes([good[middle] ^ 0xFF]) + good[middle + 1:]
    by_ref = {"a tag ref": rename_ref(good, "refs/heads/hostile", "refs/tags/hostile"),
              "a peerbox ref": rename_ref(good, "refs/heads/hostile", member_ref),
              "the protected branch": rename_ref(good, "refs/heads/hostile", "refs/heads/main"),
              "an option-like ref": rename_ref(good, "refs/heads/hostile", "--upload-pack=touch"),
              "an option-like branch": rename_ref(good, "refs/heads/hostile", "refs/heads/-hostile")}
    for name in ("one", "two"):
        git(clone, "update-ref", f"refs/fixture-bundle/{name}", tip)
    try:
        git(clone, "bundle", "create", "-q", work / "two.bundle", "refs/fixture-bundle/one", "refs/fixture-bundle/two",
            f"^{main}")
    finally:
        for name in ("one", "two"):
            git(clone, "update-ref", "-d", f"refs/fixture-bundle/{name}")
    two = (work / "two.bundle").read_bytes()
    by_ref["two refs"] = rename_ref(rename_ref(two, "refs/fixture-bundle/one", "refs/heads/hostile"),
                                    "refs/fixture-bundle/two", "refs/heads/second")
    by_dotgit = {}
    for label, entries in DOTGIT.items():
        crafted = tree_commit(clone, {"README": ("100644", b"project\n"), **entries}, parent=main)
        by_dotgit[label] = bundle(clone, work / f"crafted-{crafted[:8]}.bundle", crafted, exclude=[main],
                                  ref="hostile")
    return mutated, by_ref, by_dotgit


def head_mover(work, repo, main):
    """review_conflicts' head_moved: a `git` wrapper directory that, while FLAG exists, first moves REPO's main to
    a new child of MAIN on the first ref-changing git command, then runs it. Returns (wrapper dir, flag, moved)."""
    moved = git(repo, "commit-tree", f"{main}^{{tree}}", "-p", main, "-m", "the owner's own commit")
    wrapper, flag = Path(work) / "gitwrap", Path(work) / "gitwrap.flag"
    wrapper.mkdir(parents=True, exist_ok=True)
    real = shutil.which("git")
    (wrapper / "git").write_text(
        f"#!/bin/sh\nif [ -f {flag} ]; then case \" $* \" in *\" update-ref \"*|*\" merge \"*|*\" fetch \"*|"
        f"*\" push \"*|*\" read-tree \"*|*\" reset \"*) rm -f {flag}; PBX_FIXTURE=1 {real} -C {repo} "
        f"update-ref refs/heads/main {moved};; esac; fi\nexec {real} \"$@\"\n")
    (wrapper / "git").chmod(0o755)
    return wrapper, flag, moved


def requires(repo, data, work):
    """`git bundle verify` of DATA in REPO: (exit status, its output naming the prerequisites)."""
    path = Path(work) / "verify.bundle"
    path.write_bytes(data)
    p = git(repo, "bundle", "verify", path, ok=False)
    return p.returncode, (p.stdout + p.stderr).decode()


def expected_workspace():
    """What a run's workspace must hold for TREE: {path: (kind, mode, content)}, every directory ("dir", None, None)
    except a submodule, an empty directory."""
    want = {}
    for path, (mode, data) in TREE.items():
        parts = path.split("/")
        for i in range(1, len(parts)):
            want.setdefault("/".join(parts[:i]), ("dir", None, None))
        if mode == "120000":
            want[path] = ("link", None, data)
        elif mode == "160000":
            want[path] = ("dir", None, [])
        else:
            want[path] = ("file", 0o755 if mode == "100755" else 0o644, data)
    return want


def predecessor(path, tables, version):
    """Make the host.db at PATH the shape of schema VERSION: drop every table not in TABLES, set user_version."""
    db = sqlite3.connect(str(path))
    try:
        found = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'table' "
                                          "AND name NOT LIKE 'sqlite_%'")}
        check(tables <= found, f"schema-{version} tables missing from the current state: {sorted(tables - found)}")
        for table in sorted(found - tables):
            db.execute(f'DROP TABLE "{table}"')
        db.execute(f"PRAGMA user_version = {version}")
        db.commit()
    finally:
        db.close()


# The self-check.

def self_check(work, schema_tables=SCHEMA_TABLES):
    """Build every fixture of both suites in WORK, as the cases do, and check each is what its case expects."""
    began = time.monotonic()
    work = Path(work)
    work.mkdir(parents=True, exist_ok=True)
    owner = owner_repo(work / "owner")
    repo, main, parent = owner["repo"], owner["main"], owner["main_parent"]
    check(git(repo, "rev-list", "--count", "main") == "3" and not (repo / "HOOK_RAN").exists(),
          "the owner repository: 3 commits on main, the hook silent for the suite's own git")
    full = bundle(repo, work / "full.bundle", main, ref="main")
    check(len(full) > 400 and bundle_heads(full, work) == [(main, "refs/heads/main")],
          f"main's bundle: {len(full)} bytes, heads {bundle_heads(full, work)}")
    check(rev(repo, "refs/heads/main") == main and not git(repo, "for-each-ref", "refs/fixture-bundle"),
          "bundling moved a branch or left a temporary ref")
    # A have bundle, as the home host would make it: main without main's parent.
    git(repo, "bundle", "create", "-q", work / "have.bundle", "main", f"^{parent}")
    clone = work / "clone"
    git(work, "init", "-q", clone)
    git(clone, "fetch", "-q", repo, "main:refs/peerbox/pbx_fixture/main")  # what `peerbox fetch` sets
    status, said = requires(clone, (work / "have.bundle").read_bytes(), work)
    check(status == 0 and parent in said, f"verify of a have bundle names no prerequisite {parent[:12]}: {said[-200:]}")
    wt = worktree(clone, work / "wt", "pbx_fixture")
    # Every bundle below is built with its branch checked out in the worktree, as in the cases.
    tip = commit_on(wt, "feature", {"feature.txt": "bob's change\n"})
    data = bundle(clone, work / "feature.bundle", tip, exclude=[main], ref="feature")
    check(bundle_heads(data, work) == [(tip, "refs/heads/feature")]
          and rev(unbundle(data, work, have_repo=clone), "refs/fetched/feature") == tip, "a contribution bundle")
    _, big = oversized(clone, wt, work / "big.bundle", "big", main, 65536, 96000, start=main)
    based, old = base_error_bundles(clone, wt, work, main, parent)
    check(bundle_heads(based, work)[0][1] == "refs/heads/based" and bundle_heads(old, work)[0][1]
          == "refs/heads/old-base" and parent in requires(clone, old, work)[1], "the base-error bundles")
    mutated, by_ref, by_dotgit = hostile_bundles(clone, wt, work, main, "refs/peerbox/pbx_fixture/members/p/hostile")
    check(len(by_dotgit) == len(DOTGIT) and len(by_ref) == 6, "hostile variants missing")
    # Into a repository holding main only, as the home host's is (bob's clone already has the objects, and a fetch
    # that needs none of the pack never reads it).
    check(unbundle_fails(mutated, work, repo), "the bundle with a mutated byte fetches cleanly")
    heads = {label: [r for _, r in bundle_heads(d, work)] for label, d in by_ref.items()}
    check(heads == {"a tag ref": ["refs/tags/hostile"], "a peerbox ref": ["refs/peerbox/pbx_fixture/members/p/hostile"],
                    "the protected branch": ["refs/heads/main"], "an option-like ref": ["--upload-pack=touch"],
                    "an option-like branch": ["refs/heads/-hostile"], "two refs": ["refs/heads/hostile",
                                                                                   "refs/heads/second"]},
          f"hostile ref variants {heads}")
    for label, d in by_dotgit.items():
        got = unbundle(d, work, have_repo=clone)
        listed = git(got, "ls-tree", "-r", "--name-only", "-z", "refs/fetched/hostile").split("\0")
        check(bundle_heads(d, work)[0][1] == "refs/heads/hostile" and set(DOTGIT[label]) <= set(listed),
              f"the {label} bundle does not carry its entry: {listed}")
    pages = paging_bundles(clone, wt, work, main)
    check([bundle_heads(d, work)[0][1] for _, d in pages] == [f"refs/heads/p{i:02d}" for i in range(16)],
          "the status-paging bundles")
    carol = worktree(clone, work / "carol-wt", "pbx_fixture", branch="carol")
    oversized(clone, carol, work / "carol.bundle", "carol", main, 2000, 6000)
    # peerbox_runs: TREE exactly, and the expected workspace derived from it.
    runs = runs_repo(work / "runs")
    entries = git(runs["repo"], "ls-tree", "-r", "-z", "main").split("\0")
    modes = {e.split("\t", 1)[1]: e.split(" ")[0] for e in entries if e}
    check(modes == {path: mode for path, (mode, _) in TREE.items()}, f"the TREE commit {modes}")
    for path, (mode, content) in TREE.items():
        if mode != "160000":
            blob = git(runs["repo"], "rev-parse", f"main:{path}")
            got = subprocess.run(["git", "cat-file", "blob", blob], cwd=runs["repo"],
                                               capture_output=True).stdout
            check(got == content, f"TREE {path}: {got!r}")
    # review_conflicts: the wrapper moves main under a compare-and-swap update, once.
    git(repo, "switch", "-q", "--detach")
    wrapper, flag, moved = head_mover(work / "mover", repo, main)
    flag.write_text("1")
    fake = commit_on(wt, "cas", {"cas.txt": "x\n"}, start=main)
    swap = subprocess.run([str(wrapper / "git"), "-C", str(repo), "update-ref", "refs/heads/main", fake, main],
                          capture_output=True, env={**os.environ, "PBX_FIXTURE": "1"})
    check(swap.returncode != 0 and rev(repo, "main") == moved and not flag.exists(),
          f"the head mover: exit {swap.returncode}, main {rev(repo, 'main')}, want {moved}")
    git(repo, "update-ref", "refs/heads/main", main)
    git(repo, "switch", "-q", "main")
    want = expected_workspace()
    check(want["vendor/lib"] == ("dir", None, []) and want["sub/dir"] == ("dir", None, None)
          and want["bin/run.sh"][1] == 0o755 and ".git" not in want, "the expected workspace")
    # open_previous_schema: the schema drop on a state shaped like the current one, plus a peerbox table.
    db_path = work / "host.db"
    db = sqlite3.connect(str(db_path))
    for table in sorted(schema_tables) + ["peerbox_fixture_new"]:
        db.execute(f'CREATE TABLE "{table}" (x)')
    db.execute("PRAGMA user_version = 32")
    db.commit()
    db.close()
    predecessor(db_path, schema_tables, 31)
    db = sqlite3.connect(str(db_path))
    left = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    version = db.execute("PRAGMA user_version").fetchone()[0]
    db.close()
    check(left == set(schema_tables) and version == 31, f"the predecessor: version {version}, extra "
                                                        f"{sorted(left - set(schema_tables))}")
    return time.monotonic() - began


def unbundle_fails(data, work, clone):
    try:
        unbundle(data, work, have_repo=clone)
    except AssertionError:
        return True
    return False
