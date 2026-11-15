"""Shared fixtures and helpers of the episode-mode peerbox gate suites (peerbox_gate_episodes.py,
peerbox_gate_paired.py).

Written from docs/peerbox-contract.md only (cited as "peerbox <section>"), Gates, with the runtime task contract's
Linked runs. It builds on runtime_common.py and peerbox_common.py and shares their `state`.

Every gate here is an `episode` gate on conformance/slim/fake_runtime.py's linked pairs. The candidate command
`connect 7000 N f/NAME.txt ; cat claim.txt` opens N connections over the link, sends the measured commit's f/NAME.txt
on each and then prints its claim.txt; the environment `serve 7000 N [; ...]` writes what it received to stdout, so
its result line is the last line of f/NAME.txt as the measured commit holds it. Such an environment trusts what it is
sent, which the contract tells owners never to do; here it lets each case choose the environment's scores through the
commit it submits, the only input of an evaluation that the host does not make. Each case has its own NAME: `main`
holds the frontier's version of every case's file and a contribution changes only its own, so a promotion in one case
leaves the other cases' frontiers as they were. The fake runtime logs each start request, each run's unpacked
workspace and the link's connections, which the cases read as their oracle of what ran where.
"""
import base64
import hashlib
import json
import math
import os
import re
import stat
import tempfile
from decimal import ROUND_HALF_UP, Decimal

from harness import check, wait_for
from runtime_common import make_tar, need, setup_network, state
import runtime_common
from peerbox_common import (bundle, check_record, commit_files, create, git, init_repo, op_ok, outcome, owner_cli, rev,
                            share, submit_bundle)
from peerbox_fixtures import commit_on, worktree

REASON = "peerbox gates not implemented (peerbox contract, Gates; PBX-25 to PBX-33)"
PORT = 7000
RUNTIME = {"max_concurrent_runs": 2, "log_workspaces": 1}  # the fake's options: two slots for a linked pair
HEX64 = re.compile(r"^[0-9a-f]{64}$")
LINK_ID = re.compile(r"^lnk_[0-9a-f]{32}$")
EVALUATION_ID = re.compile(r"^pbe_[0-9a-f]{32}$")
INPUTS = {"seed.txt": "the inputs snapshot\n"}
CHECKER = {"env.txt": "the environment\n", "episodes/holdout.txt": "held-out episode definitions\n"}
DEFAULT_LINK = {"connections": 16, "bytes": 268435456}  # peerbox The gate record, link
DEFAULT_RESOURCES = {"cpus": 2, "memory_mib": 2048, "timeout_seconds": 900}  # Gate CLI defaults
DECISION_KEYS = {"decision", "reason", "decided_at", "decided_by", "old_head", "new_head", "gate"}
# peerbox Verdict: the public result, and What readers see: the public summary.
PUBLIC_RESULT = {"gate_version", "verdict", "code", "checker_reason", "score", "direction", "min_gain", "compare",
                 "frontier_scores", "candidate_scores", "secret_sha256", "paired"}
SUMMARY = {"version", "state", "mode", "command", "score", "direction", "min_gain", "compare", "score_range", "image",
           "link_port", "commitment", "frontier"}
# peerbox Commitment: the record's fields under the salt, in the contract's order (JCS sorts them anyway).
# peerbox Gate CLI and local API, What `gate show` returns.
SHOW_KEYS = {"gate", "queue", "evaluations"}
EVALUATION_KEYS = {"evaluation_id", "contribution_id", "gate_version", "secret", "secret_sha256", "frontier",
                   "started_at", "decided_at", "result", "runs"}
EVALUATION_RUN_KEYS = {"task_id", "side", "kind", "outcome"}
COMMITTED = ("mode", "command", "inputs_sha256", "checker", "checker_sha256", "generator", "score", "direction",
             "min_gain", "repeats", "compare", "score_range", "image", "checker_image", "link", "cpus", "memory_mib",
             "checker_cpus", "checker_memory_mib", "timeout_seconds", "max_changes_bytes")


def sha(data):
    return hashlib.sha256(data.encode() if isinstance(data, str) else data).hexdigest()


def line(score, samples=None, passed=True, reason=""):
    """A result line (peerbox Result line) as one line of a file."""
    value = {"pass": passed, "score": score, "reason": reason}
    if samples is not None:
        value["samples"] = samples
    return "PEERBOX-GATE " + json.dumps(value, separators=(",", ":")) + "\n"


def last_line(text):
    """The result line a `serve` environment prints for TEXT: its last non-empty line, parsed, or None."""
    lines = [x for x in text.splitlines() if x.strip()]
    if not lines or not lines[-1].startswith("PEERBOX-GATE "):
        return None
    try:
        return json.loads(lines[-1][len("PEERBOX-GATE "):])
    except ValueError:
        return None


def pbx():
    return need("pbx")[0]


# Setup (the network, the fake runtime and peerboxes are implemented; gates are not).

def gate_setup(suite, frontier):
    """The network, the fake runtime with linked pairs, the owner's repository whose main holds FRONTIER {NAME: text}
    as f/NAME.txt, the two snapshot directories, and the runtime's local switch on."""
    setup_network(**RUNTIME)
    repo = init_repo(suite.work / "alice-repo")
    files = {"README.md": "a gated peerbox\n", "claim.txt": "no claim\n",
             **{f"f/{name}.txt": text for name, text in frontier.items()}}
    state.update(repo=repo, main=commit_files(repo, files, "every case's frontier"), learners=[state["b"]], pending=[])
    for key, tree in (("inputs", INPUTS), ("checker", CHECKER)):
        root = suite.work / key
        for path, text in tree.items():
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).write_text(text)
        state[key] = root
    a, rt = state["a"], state["rt"]
    status, body = a.api("PUT", "/v1/runtime", {"socket": str(rt.socket)})
    check(status == 200, f"PUT /v1/runtime: {status} {body}")
    status, report = rt.api("GET", "/v1/runtime")
    check(report.get("links") is True and report.get("max_concurrent_runs") == 2, f"the fake's report {report}")
    helper_check(suite.work)


def gate_peerbox(suite):
    """peerbox create on alice's repository, shared with bob for read and submit, fetched into his clone."""
    a, b = need("a", "b")
    state["pbx"] = create(state["repo"], title="gated")
    share(pbx(), state["bob_principal"], actions=("read", "submit"), hosts=[b])
    clone, wt = suite.work / "bob-clone", suite.work / "bob-wt"
    result = b.cli("--json", "peerbox", "fetch", "--peer", a.id, pbx(), "--repository", clone, timeout=90)
    check(result.ok and rev(clone, f"refs/peerbox/{pbx()}/main") == state["main"],
          f"peerbox fetch: exit {result.code} {result.stderr.strip()[-300:]}")
    worktree(clone, wt, pbx(), branch="work")
    state.update(clone=clone, wt=wt)
    # The contribution helpers on an ungated peerbox: submitted, pending, then rejected by hand (Review).
    cid = contribute("warmup", {"warmup.txt": "no gate yet\n"})["contribution_id"]
    check(status_of(cid)["state"] == "pending", "an ungated contribution is not pending")
    tidy()
    rec = decided(cid, timeout=30)
    check(rec["state"] == "rejected" and set(rec["decision"]) == DECISION_KEYS - {"gate"}
          and rev(state["repo"], "main") == state["main"], f"a rejection by hand {rec['decision']}")


def helper_check(work):
    """One linked pair started on the suite's fake runtime as a gate would start it, and read back through `pairs`,
    `check_pair`, `workspace`, `side` and `secret_digest`, so the cases' oracle is checked before any gate exists."""
    rt, since, secret = state["rt"], mark(), "ab" * 32
    trees = {"listen": {**CHECKER, ".peerbox-gate/secret": secret + "\n"},
             "connect": {"f/x.txt": line(7), "claim.txt": line(1)}}
    argv = {"listen": ["serve", str(PORT), "1"], "connect": ["connect", str(PORT), "1", "f/x.txt", ";", "cat",
                                                             "claim.txt"]}
    link = {"id": "lnk_" + os.urandom(16).hex(), "port": PORT, "max_connections": 16, "max_bytes": 268435456}
    runs = {}
    for role in ("listen", "connect"):
        archive = work / f"helper-{role}.tar"
        archive.write_bytes(make_tar({k: v.encode() for k, v in trees[role].items()}))
        runs[role] = "run_" + os.urandom(32).hex()
        status, body = rt.api("POST", "/v1/runs", {
            "run_id": runs[role], "argv": argv[role], "cwd": "/workspace", "env": {}, "resources": DEFAULT_RESOURCES,
            "workspace_archive": str(archive), "peerfs_workspace": None, "results": "output",
            "link": {**link, "role": role}})
        check(status == 201, f"the fake refused a linked {role} run: {status} {body}")
    wait_for(lambda: all(logged("exited", r) for r in runs.values()), timeout=30, message="the helper pair")
    found = pairs(since)
    check(len(found) == 1, f"pairs read {len(found)} pairs from one")
    check_pair(found[0])
    check(side(found[0], "x", line(7), line(8)) == "frontier" and secret_digest(found[0]) == secret_file(secret),
          "side or secret_digest misread the workspaces")
    _, events = rt.api("GET", f"/v1/runs/{runs['listen']}/events?after=0")
    out = b"".join(base64.b64decode(e["data"]) for e in events if e["kind"] == "stdout").decode()
    check(last_line(out) == {"pass": True, "score": 7, "reason": ""} and logged("serve", runs["listen"])[0]["accepted"]
          == 1, f"the environment's result line {out!r}")
    for run_id in runs.values():
        rt.api("DELETE", f"/v1/runs/{run_id}")


# The gate (peerbox Gate CLI and local API).

def gate_args(name, n=1, direction="lower", min_gain=10, env=(), tail=(), extra=()):
    """`gate set` arguments of an episode gate for case NAME: N connections, ENV more environment steps."""
    command = ["connect", str(PORT), str(n), f"f/{name}.txt", ";", "cat", "claim.txt", *tail]
    checker = ["serve", str(PORT), str(n), *env]
    return ["--inputs-dir", state["inputs"], "--command", json.dumps(command), "--checker-dir", state["checker"],
            "--checker", json.dumps(checker), "--score", "checker", "--direction", direction, "--min-gain",
            str(min_gain), "--mode", "episode", "--link-port", str(PORT), *extra]


def tidy():
    """Reject by hand whatever an earlier case left pending, so that it is not evaluated under the next gate."""
    for cid in state.get("pending", []):
        owner_cli("review", cid, "--reject", "--reason", "left by an earlier case", ok=False)
    state["pending"] = []


def set_gate(name, **kw):
    """`peerbox gate set` for case NAME; returns `gate show` after it."""
    tidy()
    owner_cli("gate", "set", pbx(), *gate_args(name, **kw))
    shown = show()
    rec = record(shown)
    check(rec.get("state") == "active" and rec.get("mode") == "episode" and rec.get("frontier") is None,
          f"the gate after gate set: {rec}")
    return shown


def show():
    """`GET /v1/peerboxes/{id}/gate`: 200 with exactly {gate, queue, evaluations} (What `gate show` returns)."""
    status, body = state["a"].api("GET", f"/v1/peerboxes/{pbx()}/gate")
    check(status == 200 and isinstance(body, dict) and set(body) == SHOW_KEYS,
          f"GET /v1/peerboxes/{{id}}/gate: {status} {str(body)[:300]}, want 200 with exactly {sorted(SHOW_KEYS)}")
    check(isinstance(body["gate"], dict) and isinstance(body["queue"], list) and isinstance(body["evaluations"], list)
          and len(body["evaluations"]) <= 20, f"gate show's gate, queue and evaluations {str(body)[:300]}")
    for entry in body["evaluations"]:
        check(isinstance(entry, dict) and set(entry) == EVALUATION_KEYS and EVALUATION_ID.match(entry["evaluation_id"])
              and HEX64.match(entry["secret"]) and entry["secret_sha256"] == secret_sha256(entry["secret"])
              and all(isinstance(r, dict) and set(r) == EVALUATION_RUN_KEYS for r in entry["runs"]),
              f"an evaluation in gate show {str(entry)[:300]}, want exactly {sorted(EVALUATION_KEYS)}")
    return body


def record(shown):
    """The gate record in a `gate show` answer, with its salt as 64 lowercase hex digits."""
    rec = shown["gate"]
    check(isinstance(rec.get("salt"), str) and HEX64.match(rec["salt"]), f"the gate's salt {rec.get('salt')!r}")
    return rec


def evaluation_with(shown, digest):
    """The evaluation in `gate show` whose secret an environment run had (DIGEST: its secret file's SHA-256)."""
    found = [e for e in shown["evaluations"] if secret_file(e["secret"]) == digest]
    check(len(found) == 1, f"{len(found)} evaluations in gate show with the environment runs' secret, want 1")
    return found[0]


def secret_sha256(secret_hex):
    """peerbox Verdict: the SHA-256 of the evaluation's 32 secret bytes."""
    return sha(bytes.fromhex(secret_hex))


def secret_file(secret_hex):
    """peerbox Fresh episodes: `.peerbox-gate/secret` holds 64 lowercase hex digits and a line feed."""
    return sha(secret_hex + "\n")


# Contributions and decisions.

def submit_tip(branch, tip, base=None):
    """Bundle TIP (without the protected head's history) as BRANCH and submit it; returns the record."""
    main = state["main"]
    data = bundle(state["clone"], runtime_common.suite.work / f"{branch}-{tip[:8]}.bundle", tip, exclude=[main],
                  ref=branch)
    kind, value, _ = outcome(submit_bundle(pbx(), data, base or main, branch))
    check(kind == "succeeded", f"submit {branch}: {kind} {value}")
    rec = check_record(value, pbx())
    state["pending"].append(rec["contribution_id"])
    return rec


def contribute(branch, files, start=None):
    """bob's commit of FILES on BRANCH from START (default: the protected head), submitted."""
    return submit_tip(branch, commit_on(state["wt"], branch, files, start=start or state["main"]))


def status_of(cid):
    value, _, _ = op_ok({"op": "status", "peerbox_id": pbx(), "contribution_id": cid})
    return check_record(value["contributions"][0], pbx())


def decided(cid, timeout=90):
    """CID's record through bob's `status` once it is no longer pending."""
    def done():
        rec = status_of(cid)
        return rec if rec["state"] != "pending" else None
    rec = wait_for(done, timeout=timeout, interval=1, message=f"a decision on {cid}")
    if cid in state["pending"]:
        state["pending"].remove(cid)
    if rec["state"] == "accepted":
        state["main"] = rec["head"]
    return rec


def gate_decision(rec, verdict, code=None, checker_reason="", frontier=None):
    """peerbox Verdict: a decision by the gate with the public result; returns that result. CHECKER_REASON is the
    result line's `reason` (every environment here gives "" unless a case says otherwise), None when no result line
    was read."""
    d = rec["decision"]
    check(isinstance(d, dict) and set(d) == DECISION_KEYS and d["decided_by"] == "gate",
          f"the decision {d}, want the gate's with exactly {sorted(DECISION_KEYS)}")
    g = d["gate"]
    check(isinstance(g, dict) and set(g) == PUBLIC_RESULT, f"the public result {g}, want {sorted(PUBLIC_RESULT)}")
    check(g["verdict"] == verdict and isinstance(g["secret_sha256"], str) and HEX64.match(g["secret_sha256"]),
          f"verdict {g['verdict']} secret_sha256 {g['secret_sha256']!r}, want {verdict}")
    code = "promoted" if verdict == "promoted" else code
    # `reason` is the code, then ": " and the checker's reason when it gave one. Whether an empty reason is one given
    # is not settled, so with "" both the bare code and "CODE: " are taken.
    reasons = ({f"{code}: {checker_reason}"} if checker_reason
               else {code, f"{code}: "} if checker_reason == "" else {code})
    check(g["code"] == code and g["checker_reason"] == checker_reason and d["reason"] in reasons
          and g["score"] == "checker", f"code {g['code']!r}, checker_reason {g['checker_reason']!r}, reason "
                                       f"{d['reason']!r}, score {g['score']!r}: want {code!r}, {checker_reason!r}, "
                                       f"one of {sorted(reasons)}, checker")
    if frontier is not None:
        check(d["old_head"] == frontier, f"old_head {d['old_head']}, want the evaluation's frontier {frontier}")
    if verdict == "promoted":
        check(rec["state"] == "accepted" and d["decision"] == "accepted" and d["new_head"] == rec["head"],
              f"a promotion: state {rec['state']} {d}")
        check(rev(state["repo"], "main") == rec["head"], "the protected branch did not move to the candidate")
    else:
        check(rec["state"] == "rejected" and d["decision"] == "rejected" and d["old_head"] == d["new_head"],
              f"a rejection: state {rec['state']}, {d}")
    return g


# The fake runtime's log (fake_runtime.py: `post`, `workspace`, `serve`, `link_*` entries).

def mark():
    return len(state["rt"].entries())


def pairs(since=0, until=None):
    """The linked pairs whose runs the fake accepted between log positions SINCE and UNTIL, in start order:
    [{role: post entry with its log position as `at_index`}]."""
    out, by_id = [], {}
    for index, entry in enumerate(state["rt"].entries()[since:until], start=since):
        if entry.get("event") != "post" or entry.get("status") != 201:
            continue
        link = (entry.get("request") or {}).get("link")
        check(isinstance(link, dict), f"a gate run without a link: {entry['request'].get('argv')}")
        found = by_id.get(link["id"])
        if found is None:
            found = by_id[link["id"]] = {}
            out.append(found)
        check(link["role"] not in found, f"two {link['role']} runs on link {link['id']}")
        found[link["role"]] = {**entry, "at_index": index}
    return out


def check_pair(pair, connections=16, max_bytes=268435456, image=None, checker_image=None, resources=None,
               checker_resources=None):
    """peerbox Evaluation, episode mode; runtime Linked runs: one environment (`listen`) run and one candidate
    (`connect`) run, the listen run started first, both with `results: output`, one link with the gate's port and
    bounds, the gate's images and each side's bounds."""
    check(set(pair) == {"listen", "connect"}, f"a measurement with runs {sorted(pair)}, want listen and connect")
    env, bot = pair["listen"], pair["connect"]
    er, br = env["request"], bot["request"]
    want = {"id": br["link"]["id"], "role": "listen", "port": PORT, "max_connections": connections,
            "max_bytes": max_bytes}
    check(env["at_index"] < bot["at_index"] and LINK_ID.match(br["link"]["id"]) and er["link"] == want
          and br["link"] == {**want, "role": "connect"}, f"the pair's links {er['link']} {br['link']}, want {want}, "
                                                         f"listen first")
    check(er["results"] == "output" and br["results"] == "output" and er["workspace_archive"]
          and br["workspace_archive"], f"results {er['results']} {br['results']}, both want output with an archive")
    check(br.get("image") == image and er.get("image") == checker_image,
          f"images: candidate {br.get('image')}, environment {er.get('image')}, want {image} and {checker_image}")
    resources = resources or DEFAULT_RESOURCES
    check(br["resources"] == resources and er["resources"] == (checker_resources or resources),
          f"resources: candidate {br['resources']}, environment {er['resources']}")


def logged(event, run_id=None, link=None):
    return [e for e in state["rt"].entries(event, run_id) if link is None or e.get("link") == link]


def workspace(run_id):
    """The run's unpacked files {path: SHA-256} (fake `--log-workspaces`; directories left out)."""
    found = logged("workspace", run_id)
    check(len(found) == 1, f"{len(found)} workspace entries for {run_id[:16]}")
    return {k: v for k, v in found[0]["entries"].items() if v != "dir"}


def secret_digest(pair):
    return workspace(pair["listen"]["run_id"]).get(".peerbox-gate/secret")


def side(pair, name, frontier_text, candidate_text):
    """`frontier` or `candidate`: which commit's f/NAME.txt the measurement's candidate run had."""
    got = workspace(pair["connect"]["run_id"]).get(f"f/{name}.txt")
    roles = {sha(frontier_text): "frontier", sha(candidate_text): "candidate"}
    check(got in roles, f"the candidate run's f/{name}.txt is neither the frontier's nor the candidate's")
    return roles[got]


def tree_files(repo, commit):
    """{path: SHA-256} of COMMIT's regular files, without any entry under .peerbox-gate/ (peerbox Evaluation)."""
    out = {}
    for entry in git(repo, "ls-tree", "-r", "-z", commit).split("\0"):
        if not entry:
            continue
        meta, path = entry.split("\t", 1)
        mode, kind, obj = meta.split()
        if kind == "blob" and mode != "120000" and not path.startswith(".peerbox-gate/"):
            out[path] = sha(git(repo, "cat-file", "blob", obj, ok=False).stdout)
    return out


# The commitment (peerbox Commitment, RFC 8785).

def jcs(value):
    """RFC 8785 canonical JSON of VALUE (objects' keys by UTF-16 code units, numbers as ECMAScript prints them)."""
    if value is None or isinstance(value, bool):
        return json.dumps(value)
    if isinstance(value, int) or (isinstance(value, float) and value.is_integer() and abs(value) < 1e21):
        return str(int(value))
    if isinstance(value, float):
        check(math.isfinite(value), f"a non-finite number {value}")
        text = repr(value)
        if 1e-6 <= abs(value) < 1e21:  # ECMAScript Number::toString: fixed notation in this range
            return format(Decimal(text), "f")
        mantissa, exponent = text.split("e")
        return f"{mantissa}e{'+' if int(exponent) > 0 else '-'}{abs(int(exponent))}"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    check(isinstance(value, dict), f"not JSON: {value!r}")
    keys = sorted(value, key=lambda k: k.encode("utf-16-be"))
    return "{" + ",".join(jcs(k) + ":" + jcs(value[k]) for k in keys) + "}"


def digests():
    """{inputs_sha256, checker_sha256} recomputed from the directories the suite passes to `gate set`."""
    return {"inputs_sha256": snapshot_digest(state["inputs"]), "checker_sha256": snapshot_digest(state["checker"])}


def commitment(rec):
    """The commitment of REC with its snapshot digests recomputed (peerbox Snapshots), after checking that the
    record holds those digests."""
    want = digests()
    held = {k: rec.get(k) for k in want}
    check(held == want, f"the record's snapshot digests {held}, want {want}")
    body = {k: rec[k] for k in COMMITTED}
    body.update(want, salt=rec["salt"])
    return sha(b"peerbox-gate-commitment-v1\n" + jcs(body).encode())


# Snapshot digests (peerbox The gate record, Snapshots).

def snapshot_digest(root):
    """The lowercase hex SHA-256 of ROOT's entries in the byte order of their relative paths: `d` PATH NUL for a
    directory; `f` PATH NUL, the permission bits as four octal digits and the 32-byte SHA-256 of the contents for a
    regular file; `l` PATH NUL TARGET NUL for a symbolic link. ROOT itself is not an entry."""
    entries = []
    for base, dirs, files in os.walk(root):
        for name in dirs + files:
            full = os.path.join(base, name)
            rel = os.fsencode(os.path.relpath(full, root))
            mode = os.lstat(full).st_mode
            if stat.S_ISLNK(mode):
                entries.append((rel, b"l" + rel + b"\0" + os.fsencode(os.readlink(full)) + b"\0"))
            elif stat.S_ISDIR(mode):
                entries.append((rel, b"d" + rel + b"\0"))
            else:
                check(stat.S_ISREG(mode), f"{full}: not a directory, regular file or symbolic link")
                with open(full, "rb") as f:
                    contents = hashlib.sha256(f.read()).digest()
                entries.append((rel, b"f" + rel + b"\0" + b"%04o" % (mode & 0o7777) + contents))
    return sha(b"".join(entry for _, entry in sorted(entries)))


def digest_check(work):
    """Host-free: snapshot_digest of a fixed directory against its preimage, written out by hand from the
    definition, and that preimage's SHA-256. `a-b` sorts between `a` and `a/x` (0x2d < 0x2f), which a walk in
    directory order would not give."""
    root = tempfile.mkdtemp(prefix="gate-digest-", dir=work)
    os.mkdir(os.path.join(root, "a"))
    for path, data, mode in (("a/x", b"hi\n", 0o644), ("a-b", b"", 0o755)):
        with open(os.path.join(root, path), "wb") as f:
            f.write(data)
        os.chmod(os.path.join(root, path), mode)
    os.symlink("a/x", os.path.join(root, "l"))
    preimage = (b"da\0" + b"fa-b\0" + b"0755" + hashlib.sha256(b"").digest() + b"fa/x\0" + b"0644"
                + hashlib.sha256(b"hi\n").digest() + b"ll\0a/x\0")
    want = "6ad3cb7430ccca6d64c0da04546021d935f0a913b42bb147a6dba63c3dd350b8"
    got = snapshot_digest(root)
    check(sha(preimage) == want and got == want, f"snapshot_digest {got}, want {want}")


# Paired comparison (peerbox Verdict).

def paired_bound(frontier, candidate, direction, min_gain, compare, score_range=None):
    """FRONTIER and CANDIDATE are each side's measurements' samples. Returns (passes, n, mean_gain_percent,
    margin_bound_percent) unrounded: episodes averaged over the measurements of each side, e = d - min_gain/100 * f."""
    n = len(frontier[0])
    f = [sum(m[i] for m in frontier) / len(frontier) for i in range(n)]
    c = [sum(m[i] for m in candidate) / len(candidate) for i in range(n)]
    d = [fi - ci if direction == "lower" else ci - fi for fi, ci in zip(f, c)]
    k = min_gain / 100
    e = [di - k * fi for di, fi in zip(d, f)]
    mean_e = sum(e) / n
    sd = math.sqrt(sum((x - mean_e) ** 2 for x in e) / (n - 1))
    if compare == "paired_normal":
        left = mean_e - 1.645 * sd / math.sqrt(n)
    else:
        lo, hi = score_range
        big_l, r = math.log(40), (2 + k) * (hi - lo)
        left = mean_e - math.sqrt(2 * sd * sd * big_l / n) - 7 * r * big_l / (3 * (n - 1))
    mean_f = sum(f) / n
    return left >= 0, n, 100 * (sum(d) / n) / mean_f, left * 100 / mean_f


def hundredths(value):
    """peerbox Verdict: VALUE rounded to the nearest hundredth, halves away from zero."""
    return float(Decimal(value).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def near_half(value):
    """VALUE is within 1e-6 of a half-hundredth, where two computations of it could round apart."""
    return abs(abs(value * 100) % 1 - 0.5) < 1e-6


def rounded(got, exact):
    """GOT is EXACT rounded to the nearest hundredth with halves away from zero."""
    return isinstance(got, (int, float)) and not isinstance(got, bool) and abs(got - hundredths(exact)) < 1e-9


def jcs_check(work):
    """Host-free: the canonical JSON of RFC 8785's rules on the values a gate record holds; rounding halves away
    from zero; the snapshot digest."""
    vectors = [({"b": [1, 2.5, None, True], "a": "é\n", "A": {}}, '{"A":{},"a":"é\\n","b":[1,2.5,null,true]}'),
               ([10.0, 0.5, 1e-7, 1e-6, 1e21, 1e16, 333.33], "[10,0.5,1e-7,0.000001,1e+21,10000000000000000,333.33]"),
               # RFC 8785 3.2.3: keys by UTF-16 code units, so U+1F600 (D83D DE00) sorts before U+FB33.
               ({"דּ": 1, "\U0001f600": 2, "€": 3}, '{"€":3,"\U0001f600":2,"דּ":1}')]
    for value, want in vectors:
        check(jcs(value) == want, f"jcs({value!r}) = {jcs(value)!r}, want {want!r}")
    halves = {0.125: 0.13, -0.125: -0.13, 0.375: 0.38, -2.625: -2.63, 1.234: 1.23, -1.236: -1.24}
    check(all(hundredths(v) == w for v, w in halves.items()), f"hundredths {[hundredths(v) for v in halves]}")
    digest_check(work)
