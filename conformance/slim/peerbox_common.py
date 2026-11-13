"""Shared fixtures and helpers of the peerbox slim suites (peerbox.py, peerbox_runs.py).

Written from docs/peerbox-contract.md only (cited as "peerbox <section>"), with the runtime task, task, artifact and
coordinator-free contracts it extends. It builds on runtime_common.py: a suite calls `runtime_common.bind(suite)` and
shares its `state` dictionary. Git fixture repositories are made with the system `git` in the suite's work
directory, with no global or system configuration.
"""
import base64
import hashlib
import json
import os
import pty
import re
import shlex
import signal
import subprocess
import threading
import time
from datetime import timedelta
from pathlib import Path

from harness import (Failure, attention, check, link_view, peer, pull_until, rfc3339, select, commit as link_commit,
                     finalize, join_request, wait_for, wait_linked)
from runtime_common import (cite, learn, new_task_id, policy_statement, policy_version, receiver_events, state, upload)
import runtime_common

REASON = "peerboxes not implemented (peerbox contract)"
PBX_ID = re.compile(r"^pbx_[0-9a-f]{32}$")
PBC_ID = re.compile(r"^pbc_[0-9a-f]{32}$")
PSB1 = re.compile(r"psb1-[A-Za-z0-9_-]+")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
BUNDLE_TYPE = "application/x-git-bundle"
OUTPUT_LIMIT = 65536  # task contract: one final output
DEFAULT_BUNDLE = 104857600
# peerbox Peerbox rules, Policy body: exactly these keys, in this order.
RULE_KEYS = ["host", "peerbox", "principals", "actions", "max_bundle_bytes", "max_pending", "allow_disconnected"]
# peerbox Peerboxes and contributions: the contribution record (runs_total added in every returned record).
RECORD_KEYS = {"contribution_id", "peerbox_id", "contributor", "branch", "base", "head", "bundle_sha256",
               "submitted_at", "state", "decision", "runs", "runs_total"}
ACTIONS = {"read": "peerbox.read", "submit": "peerbox.submit", "run": "peerbox.run"}


def tail(text):
    return " ".join(str(text).strip()[-300:].split())


# Git fixtures.

def git_env(home):
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home), "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull, "GIT_AUTHOR_NAME": "Ada Author", "GIT_AUTHOR_EMAIL": "ada@example.test",
            "GIT_COMMITTER_NAME": "Cy Committer", "GIT_COMMITTER_EMAIL": "cy@example.test", "LANG": "C",
            "PBX_FIXTURE": "1"}  # the owner repository's marker hooks ignore the suite's own git commands


def git(cwd, *args, input=None, ok=True):
    """Run git in CWD; returns its stripped stdout text, or with OK false the completed process."""
    p = subprocess.run(["git", *map(str, args)], cwd=str(cwd), input=input, capture_output=True,
                       env=git_env(runtime_common.suite.work), timeout=60)
    if ok:
        check(p.returncode == 0, f"git {' '.join(map(str, args[:3]))} in {cwd}: {p.stderr.decode(errors='replace')[-300:]}")
    return p if not ok else p.stdout.decode(errors="replace").strip()


def init_repo(path, branch="main"):
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    git(path, "init", "-q", "-b", branch)
    return path


def commit_files(repo, files, message):
    """Write FILES {path: text, bytes or None (delete)} in REPO's worktree and commit them; returns the commit ID."""
    for name, text in files.items():
        target = Path(repo) / name
        if text is None:
            target.unlink(missing_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            target.write_bytes(text)
        else:
            target.write_text(text)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--allow-empty", "-m", message)
    return git(repo, "rev-parse", "HEAD")


def rev(repo, ref):
    """REF's commit in REPO, or None."""
    p = git(repo, "rev-parse", "--verify", "-q", ref + "^{commit}", ok=False)
    return p.stdout.decode().strip() if p.returncode == 0 else None


def refs(repo):
    """Every ref of REPO with its object: {name: sha} (a run or refusal must leave these unchanged)."""
    out = git(repo, "for-each-ref", "--format=%(refname) %(objectname)")
    return dict(line.split(" ", 1) for line in out.splitlines() if line)


def tree_commit(repo, entries, parent=None, message="crafted"):
    """A commit whose tree is ENTRIES {path: (mode, bytes)} exactly, made with plumbing so that names `git add`
    refuses (`.git/...`) can be written. Mode 160000 takes a commit ID as its data."""
    def build(items):
        lines, dirs = [], {}
        for path, (mode, data) in items.items():
            head, _, rest = path.partition("/")
            if rest:
                dirs.setdefault(head, {})[rest] = (mode, data)
            elif mode == "160000":
                lines.append(f"160000 commit {data.decode()}\t{head}")
            else:
                blob = git(repo, "hash-object", "-w", "--stdin", input=data)
                lines.append(f"{mode} blob {blob}\t{head}")
        for name, sub in dirs.items():
            lines.append(f"040000 tree {build(sub)}\t{name}")
        return git(repo, "mktree", input=("\n".join(lines) + "\n").encode())
    tree = build(entries)
    args = ["commit-tree", tree, "-m", message] + (["-p", parent] if parent else [])
    return git(repo, *args)


def bundle(repo, out, tip, exclude=(), ref=None):
    """`git bundle create` of TIP as the single ref `refs/heads/REF` (default: a branch named after OUT), without
    history reachable from EXCLUDE; returns the bundle's bytes."""
    name = ref or Path(out).stem
    if rev(repo, f"refs/heads/{name}") != tip:
        git(repo, "branch", "-f", name, tip)
    git(repo, "bundle", "create", "-q", out, f"refs/heads/{name}", *[f"^{x}" for x in exclude])
    return Path(out).read_bytes()


def rename_ref(data, old, new):
    """DATA, a bundle, with its header's ref OLD renamed NEW (the pack is untouched)."""
    header, sep, pack = data.partition(b"\n\n")
    return header.replace(b" " + old.encode(), b" " + new.encode()) + sep + pack


def bundle_heads(data, work):
    """The refs a bundle names, [(sha, ref)], read with `git bundle list-heads`."""
    path = Path(work) / ("heads-" + hashlib.sha256(data).hexdigest()[:12] + ".bundle")
    path.write_bytes(data)
    out = git(work, "bundle", "list-heads", path)
    return [tuple(line.split(" ", 1)) for line in out.splitlines() if line]


def unbundle(data, work, have_repo=None):
    """Verify DATA with `git bundle verify` and fetch it into a fresh repository (seeded from HAVE_REPO for
    prerequisites); returns that repository."""
    digest = hashlib.sha256(data).hexdigest()[:12]
    path = Path(work) / f"in-{digest}.bundle"
    path.write_bytes(data)
    repo = Path(work) / f"unbundled-{digest}-{os.urandom(3).hex()}"
    if have_repo:
        git(work, "clone", "-q", "--mirror", have_repo, repo)
    else:
        git(work, "init", "-q", "--bare", repo)
    git(repo, "bundle", "verify", "-q", path)
    git(repo, "-c", "transfer.fsckObjects=true", "fetch", "-q", path, "+refs/heads/*:refs/fetched/*")
    return repo


# Policies: peerbox rules (peerbox Peerbox rules, Policy body).

def principal(pid):
    return f"person:{pid}"


def with_peerbox_rules(body, rules):
    """BODY with `peerbox_rules` RULES placed right after `runtime_rules`, or where that would be (after
    `capability_rules`) when the body has none; RULES None leaves the key out."""
    anchor = "runtime_rules" if "runtime_rules" in body else "capability_rules"
    out = {}
    for key, value in body.items():
        if key == "peerbox_rules":
            continue
        out[key] = value
        if key == anchor and rules is not None:
            out["peerbox_rules"] = rules
    return out


def rule(pbx, principals, actions=("read",), max_bundle_bytes=DEFAULT_BUNDLE, max_pending=None,
         allow_disconnected=False, host=None):
    pending = (4 if "submit" in actions else 0) if max_pending is None else max_pending
    return {"host": (host or state["a"]).id, "peerbox": pbx, "principals": list(principals),
            "actions": [ACTIONS[a] for a in actions], "max_bundle_bytes": max_bundle_bytes,
            "max_pending": pending, "allow_disconnected": allow_disconnected}


def pbx_rules(host=None, person_public=None):
    """The `peerbox_rules` of a person's current policy (alice's by default) on HOST, or []."""
    body = policy_statement(host or state["a"], person_public or state["alice_public"])[3]
    return body.get("peerbox_rules") or []


def rules_for(pbx, who, host=None, person_public=None):
    """The rules of peerbox PBX whose principals include WHO."""
    return [r for r in pbx_rules(host, person_public) if r["peerbox"] == pbx and who in r["principals"]]


def learn_everywhere(version, person_public=None, hosts=None):
    person_public = person_public or state["alice_public"]
    for h in hosts if hosts is not None else state.get("learners", []):
        learn(h, person_public, version)


def owner_cli(*args, host=None, key=None, ok=True, timeout=90, **kw):
    """A peerbox command on the home host (alice's by default) with her person key where it signs."""
    host = host or state["a"]
    result = host.cli("--json", "peerbox", *map(str, args), timeout=timeout, **kw)
    if ok:
        check(result.ok, f"{host.name}: peerbox {' '.join(map(str, args[:3]))}: exit {result.code} {tail(result.stderr)}")
    return result


def share(pbx, *principals, actions=("read",), extra=(), host=None, key=None, person_public=None, hosts=None):
    """`peerbox share PBX --for P... --action A...`; returns the new policy version once the other hosts know it."""
    host, key = host or state["a"], key or state["alice_key"]
    args = ["share", pbx]
    for p in principals:
        args += ["--for", p]
    for a in actions:
        args += ["--action", a]
    owner_cli(*args, *extra, "--person-key", key, host=host)
    version = policy_version(host, person_public or state["alice_public"])
    learn_everywhere(version, person_public, hosts)
    return version


def unshare(pbx, *principals, host=None, key=None, person_public=None):
    host, key = host or state["a"], key or state["alice_key"]
    args = ["unshare", pbx]
    for p in principals:
        args += ["--for", p]
    owner_cli(*args, "--person-key", key, host=host)
    version = policy_version(host, person_public or state["alice_public"])
    learn_everywhere(version, person_public)
    return version


def create(repo, branch="main", title=None, host=None, extra=()):
    """`peerbox create --yes --json` on HOST (alice's by default); returns the ID of the record it prints."""
    args = ["create", "--repository", repo, "--branch", branch, "--yes", *extra]
    if title is not None:
        args += ["--title", title]
    result = owner_cli(*args, host=host, timeout=60)
    record = result.json
    check(isinstance(record, dict) and PBX_ID.match(str(record.get("peerbox_id"))) and record.get("branch") == branch,
          f"peerbox create --json printed no peerbox record: {tail(result.stdout)}")
    return record["peerbox_id"]


def shown(host=None, *args):
    """`peerbox show [PEERBOX] --json`: the peerbox records it lists (CLI and local API, --json)."""
    records = owner_cli("show", *args, host=host).json
    check(isinstance(records, list) and all(isinstance(r, dict) and PBX_ID.match(str(r.get("peerbox_id")))
                                            for r in records), f"peerbox show --json is not a list of records: "
                                                               f"{str(records)[:200]}")
    return records


# Peerbox tasks (peerbox Requests, Results).

def submit_op(op, sender=None, receiver=None, artifacts=None, task_id=None):
    """A peerbox task through the sender's POST /v1/tasks (peerbox CLI and local API); returns the task ID."""
    sender, receiver = sender or state["b"], receiver or state["a"]
    task_id = task_id or new_task_id()
    body = {"peer_host_id": receiver.id, "executor": "peerbox", "task_id": task_id, "peerbox": op,
            "input": f"peerbox {op.get('op')}"}
    if artifacts is not None:
        body["artifacts"] = artifacts
    status, record = sender.api("POST", "/v1/tasks", body)
    check(status in (200, 201), f"{sender.name}: POST /v1/tasks (peerbox {op.get('op')}): {status} {record}")
    check(record["request"].get("executor") == "peerbox" and record["request"].get("peerbox") == op,
          f"the local record does not show executor and peerbox: {record['request']}")
    return task_id


def outcome(task_id, sender=None, receiver=None, timeout=60):
    """(final kind, decoded final output or None, final event) of a peerbox task, read from the home host."""
    events = receiver_events(task_id, timeout=timeout, sender=sender or state["b"], receiver=receiver or state["a"])
    last = events[-1]
    value = None
    if last.get("output"):
        try:
            value = json.loads(last["output"])
        except ValueError:
            value = last["output"]
    return last["kind"], value, last


def op_ok(op, sender=None, receiver=None, artifacts=None):
    """A peerbox operation that must succeed; returns (output object, final event, task ID)."""
    task_id = submit_op(op, sender, receiver, artifacts)
    kind, value, last = outcome(task_id, sender, receiver)
    check(kind == "succeeded" and isinstance(value, dict), f"peerbox {op['op']}: {kind} {value}")
    return value, last, task_id


def failed_with(code, task_id, sender=None, receiver=None):
    """The task ended `failed` with exactly {"error": CODE, "message": TEXT} (peerbox Results); returns the output."""
    kind, value, _ = outcome(task_id, sender, receiver)
    check(kind == "failed" and isinstance(value, dict) and set(value) == {"error", "message"}
          and value["error"] == code and isinstance(value["message"], str), f"{kind} {value}, want failed {code}")
    return value


def op_fails(code, op, sender=None, receiver=None, artifacts=None):
    """A peerbox operation that must end `failed` with {"error": CODE, "message"}; returns the output."""
    return failed_with(code, submit_op(op, sender, receiver, artifacts), sender, receiver)


def raw_op(op, sender=None, receiver=None, drop=(), person_public=None, person_id=None, **fields):
    """A raw POST /peer/v1/tasks peerbox task from SENDER's host key; returns (status, body)."""
    sender, receiver = sender or state["b"], receiver or state["a"]
    body = {"task_id": new_task_id(), "executor": "peerbox", "peerbox": op,
            "deadline": rfc3339(receiver.now() + timedelta(minutes=30)), "input": f"peerbox {op.get('op')}",
            "policy": cite(receiver, person_public, person_id)}
    body.update(fields)
    for name in drop:
        body.pop(name, None)
    return peer(sender, receiver, "POST", "/peer/v1/tasks", body)


def upload_bundle(host, data, name="contribution.bundle"):
    return upload(host, data, name=name, media_type=BUNDLE_TYPE)


def submit_bundle(pbx, data, base, branch, sender=None, receiver=None):
    """Upload DATA and submit it (peerbox Submit); returns the task ID."""
    sender = sender or state["b"]
    entry = upload_bundle(sender, data)
    return submit_op({"op": "submit", "peerbox_id": pbx, "base": base, "branch": branch, "bundle": entry["sha256"]},
                     sender, receiver, artifacts=[entry])


def check_record(record, pbx=None):
    check(isinstance(record, dict) and set(record) == RECORD_KEYS, f"contribution record keys "
                                                                   f"{sorted(record or {})}, want {sorted(RECORD_KEYS)}")
    check(PBC_ID.match(record["contribution_id"]) and (pbx is None or record["peerbox_id"] == pbx)
          and set(record["contributor"]) == {"person_id", "host_id", "agent_id", "session_id"}
          and len(record["runs"]) <= 8 and isinstance(record["runs_total"], int)
          and record["runs_total"] >= len(record["runs"]), f"contribution record {record}")
    return record


def status_all(pbx, sender=None, receiver=None, **extra):
    """Every `status` page, following `next` with `before`; returns (records, pages)."""
    records, pages, before = [], [], None
    while True:
        op = {"op": "status", "peerbox_id": pbx, **extra}
        if before:
            op["before"] = before
        value, last, _ = op_ok(op, sender, receiver)
        check(len(last["output"].encode()) <= OUTPUT_LIMIT, f"a status output of {len(last['output'])} bytes")
        check(set(value) == {"contributions", "next"} and len(value["contributions"]) <= 100, f"status {value}")
        pages.append(value)
        records += value["contributions"]
        if value["next"] is None:
            return records, pages
        check(value["next"] == value["contributions"][-1]["contribution_id"], f"next {value['next']} is not the "
                                                                              f"last record returned")
        before = value["next"]


def fetch_bytes(task_id, last, sender=None, receiver=None):
    """The `peerbox.bundle` result of a fetch, as the submitter stored it."""
    arts = last.get("artifacts") or []
    check([a["name"] for a in arts] == ["peerbox.bundle"] and arts[0]["media_type"] == BUNDLE_TYPE,
          f"fetch result artifacts {arts}")
    return runtime_common.local_artifact(task_id, arts[0]["sha256"], sender or state["b"], receiver or state["a"])


# Joining with a peerbox invite (peerbox Invitations for new participants; decentralized-spec 8.1).

def join_with_code(admitter, joiner, code, key, net, not_after=None):
    """The seven-stage join of a new person from CODE (a psb1- code here), as harness.join_new_person drives it;
    ADMITTER signs the administrator stage."""
    request = join_request(joiner, code, key)
    rid, reply = request["request_id"], request.get("display_code")
    check(reply, "join printed no request code")
    terms = ["--not-after", not_after] if not_after else []
    joiner.ok_incomplete("link", "approve", "--network", net, "--person-key", key, "--code-stdin", "--approve",
                         *terms, input=reply + "\n")
    view = pull_until(joiner, rid, "owner_offer_id")
    select(joiner, view)
    view = link_view(joiner, rid)
    admitter.ok_incomplete("link", "admit", "--network", net, "--owner-offer", view["owner_offer_id"],
                           "--selection", view["selection_id"], "--person", view["person_public_key"],
                           "--expect-host-key", view["host_public_key"], "--expect-device-key",
                           view["device_public_key"], "--code-stdin", "--approve", input=reply + "\n")
    view = pull_until(joiner, rid, "administrator_offer_id")
    finalize(joiner, view, key)
    view = pull_until(joiner, rid, "owner_finalization_id")
    link_commit(joiner, view)
    wait_linked(joiner, admitter, rid)
    return rid


class Prompted:
    """One CLI run on a terminal that answers every default-no question `y`, as a person approving would."""

    def __init__(self, host, *args, first_line=None):
        self.master, slave = pty.openpty()
        self.p = subprocess.Popen([str(host.suite.host_bin), "--state", str(host.state), *map(str, args)],
                                  stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=host.env,
                                  start_new_session=True, cwd=str(host.root))
        os.close(slave)
        self.text, self.answered = "", 0
        threading.Thread(target=self._read, daemon=True).start()
        threading.Thread(target=self._drain, daemon=True).start()
        if first_line is not None:
            os.write(self.master, (first_line + "\n").encode())

    def _read(self):
        for chunk in iter(lambda: self.p.stdout.read1(4096), b""):
            self.text += chunk.decode(errors="replace")
            asked = len(re.findall(r"[\[(]y/N[\])]", self.text))
            while self.answered < asked:
                self.answered += 1
                os.write(self.master, b"y\n")

    def _drain(self):
        try:
            while os.read(self.master, 4096):
                pass
        except OSError:
            pass

    def wait(self, timeout):
        try:
            return self.p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(self.p.pid, signal.SIGKILL)
            self.p.wait()
            raise Failure(f"the command did not finish within {timeout}s: {tail(PSB1.sub('<code>', self.text))}")


def admit_waiting(admitter, joiner, timeout=90):
    """Run the `link admit` command the admitter's `link_request_waiting` item gives for the joiner's request."""
    def rid():
        mine = [v for v in joiner.api("GET", "/v2/link/requests")[1] if v["role"] == "requester"]
        return mine[0]["request_id"] if mine else None
    request = wait_for(rid, timeout=60, interval=0.5, message=f"{joiner.name}'s join request")

    def admitted():
        if link_view(joiner, request)["administrator_offer_id"] not in (None, "-"):
            return True
        _, body = attention(admitter)
        for item in body.get("attention") or []:
            command = str(item.get("command") or "")
            if item.get("kind") == "link_request_waiting" and request in command:
                admitter.cli(*shlex.split(command)[1:], tty=True, input="y\n", timeout=90)
        return False
    wait_for(admitted, timeout=timeout, interval=1, message=f"{admitter.name} to admit {joiner.name}")
    return request


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def b64url_json(code, prefix):
    body = code[len(prefix):]
    return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))


def settle(seconds=2.0):
    """Give a background worker (a sweep, a recheck) a moment before asserting that nothing happened."""
    time.sleep(seconds)
