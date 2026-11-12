#!/usr/bin/env python3
"""A fake `peerspan-runtime serve` for the runtime slim suite (RUN-4, DEC-OWN6, DEC-OWN9).

It serves the runtime's local API (docs/runtime-task-contract.md, "The runtime's local API") over a Unix
socket, with no VM. A run's `argv` is read as steps separated by the argument `;` (contract, Verification):

    echo TEXT...      the words and a newline to stdout
    stderr TEXT...    the words and a newline to stderr
    bytes N           N bytes of `x` to stdout
    cat PATH          a workspace file, relative to /workspace, to stdout
    write PATH TEXT   writes TEXT (the remaining words joined by spaces) to a workspace file
    rm PATH           removes a workspace file
    sleep SECONDS     waits
    exit CODE         ends the run with that exit status
    kill SIGNAL       ends the run as killed by that signal

An unknown step writes a line to stderr and ends the run with exit status 127. A run that reaches the end of its
steps exits 0.

The archive is unpacked into a private directory per run, refusing an entry that is absolute, contains `..`, or is
not a directory, regular file or symbolic link. Results are computed as the contract specifies and reported as
files; the daemon, not the runtime, drops empty files, attaches identical ones once (`results_same`) and applies
`max_artifact_bytes`. So every result file of the run's `results` mode is reported, empty ones included, and
`changes.tar` is always a valid tar archive (possibly with no members).

Workspace names given with `--peerfs-workspace NAME` (repeatable) are its peerfs workspaces (RUN-6): each is a
directory under `--dir` kept across runs and across restarts of the fake, and `GET /v1/runtime` reports `peerfs`
true only when some were given. A run on one works on that directory in place. Its `snapshot` (RUN-7) is `01` and
the lowercase hex SHA-256 of the workspace's sorted paths and contents after the command, or null when they are
those it had before the command (or the command never started); every other run has `snapshot` null. The fake
answers 429 `busy` for a workspace one of its runs holds, 422 `unavailable` for a peerfs workspace when it has
none, and fails a run on a name it was not given before `started`. `GET /v1/runs/{id}/events` takes `limit`
(1 to 1,000; without it, all).

Runtime agents (docs/runtime-agent-contract.md, "The runtime's local API" and Verification) add optional fields to
`POST /v1/runs`, each checked as that contract says: `network` (`none`, the default, or `internet`; 422 `too_large`
above `--max-network`, reported as `max_network`), `stdin`, `harness`, `secrets`, `peerfs_fork_from`, `peerfs_agent`,
`peerfs_commit` and `peerfs_commit_message`.
- `secrets` files are read when the run starts; one that cannot be read, or is over 65,536 bytes, fails the run
  before `started` with an `error` naming the secret. Their contents stay in memory and are never logged.
- With `harness` set the fake ignores `argv` and acts as the agent: it fails the run before `started`, with an
  `error` naming the secret, unless `secrets.openai_api_key` names a readable file, and then reads its stdin, the
  prompt, as steps (words split on whitespace, `;` separating steps), so `write PATH TEXT ; echo done` changes the
  workspace and answers `done`.
- `peerfs_fork_from` copies that workspace (one given with `--peerfs-workspace` or an earlier fork) to a new one
  named `peerfs_workspace` before `started`, refusing an existing name or a missing `from`, which fails the run
  before `started`, changing nothing. Forks are kept under `--dir` across restarts of the fake.
- With `peerfs_commit` true, once the run has ended and been snapshotted, the commit's ID is `01` followed by the
  lowercase hex SHA-256 of the workspace's sorted paths and contents and the commit message, or null when nothing
  changed since the fork (or since the run started, without a fork). `--fail-commits 1` makes every commit fail:
  `commit` null and `error` set. The `exited` result carries `commit` for every run.
- `--requests FILE` appends one JSON line per `POST /v1/runs`, `{at, status, body}`, with `body` the request's raw
  text: its fields, `secrets` paths included but never their contents, so a suite can compare resends byte for byte.

Standalone, standard library only. Every request and run step is appended to `--log` as one JSON line, which the
suite reads as its oracle (what was started, resent, cancelled, and whether a command ran).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import signal
import socketserver
import sys
import tarfile
import tempfile
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler

CHUNK = 16384
LOG_CUT = 104_857_600
RUN_ID = re.compile(r"^run_[0-9a-f]{64}$")
ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,255}$")
RUN_FIELDS = ("run_id", "argv", "cwd", "env", "resources", "workspace_archive", "peerfs_workspace", "results")
PEERFS_NAME_BYTES = 255
RESOURCE_FIELDS = ("cpus", "memory_mib", "timeout_seconds")
# runtime-agent-contract, The runtime's local API: optional fields and the value each takes when omitted.
AGENT_DEFAULTS = {"network": "none", "stdin": None, "harness": None, "secrets": None, "peerfs_fork_from": None,
                  "peerfs_agent": "peerspan-runtime", "peerfs_commit": False, "peerfs_commit_message": None}
SECRET_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
AGENT_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
SECRET_BYTES = 65536
STDIN_BYTES = 65536


def now_text():
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


class ApiError(Exception):
    def __init__(self, status, code, error):
        super().__init__(error)
        self.status, self.code, self.error = status, code, error


class RefusedEntry(Exception):
    pass


class Escape(RefusedEntry):
    """A path that resolves outside the run's workspace."""


class Stop(Exception):
    """Ends the step program: exit code or signal."""

    def __init__(self, exit_code=None, sig=None):
        super().__init__()
        self.exit_code, self.sig = exit_code, sig


class Run:
    def __init__(self, runtime, request):
        self.runtime = runtime
        self.request = request
        self.run_id = request["run_id"]
        self.created_at = now_text()
        self.state = "running"  # until the run has exited (runtime local API)
        self.events = []
        self.cancel = threading.Event()
        self.dir = tempfile.mkdtemp(prefix=self.run_id[:16] + "-", dir=runtime.root)
        os.chmod(self.dir, 0o700)
        self.peerfs = request["peerfs_workspace"]
        self.fork_from = request.get("peerfs_fork_from")
        if self.peerfs is None:
            self.workspace = os.path.join(self.dir, "workspace")
            os.mkdir(self.workspace, 0o700)
        elif self.fork_from is not None:
            self.workspace = None  # made by the fork, before started
        else:
            self.workspace = runtime.peerfs.get(self.peerfs)  # None: a name it was not given
        self.secrets = {}  # name -> content, in memory only
        self.stdout = open(os.path.join(self.dir, "stdout.log"), "wb")
        self.stderr = open(os.path.join(self.dir, "stderr.log"), "wb")
        self.stdout_bytes = self.stderr_bytes = 0
        self.started_at = None
        self.thread = threading.Thread(target=self.main, daemon=True)

    def record(self):
        return {"run_id": self.run_id, "state": self.state, "created_at": self.created_at}

    # Events

    def emit(self, kind, **fields):
        with self.runtime.lock:
            event = {"sequence": len(self.events) + 1, "kind": kind, **fields}
            self.events.append(event)
            self.runtime.changed.notify_all()
        return event

    def write(self, stream, data):
        if not data:
            return
        handle = self.stdout if stream == "stdout" else self.stderr
        written = self.stdout_bytes if stream == "stdout" else self.stderr_bytes
        keep = data[:max(0, LOG_CUT - written)]
        handle.write(keep)
        handle.flush()
        if stream == "stdout":
            self.stdout_bytes += len(data)
        else:
            self.stderr_bytes += len(data)
        for i in range(0, len(data), CHUNK):
            self.emit(stream, data=base64.b64encode(data[i:i + CHUNK]).decode())

    # The run

    def main(self):
        error = None
        exit_code = sig = None
        timed_out = False
        started = False
        snapshot = commit = None
        try:
            delay = self.runtime.start_delay
            if delay > 0 and self.cancel.wait(delay):
                raise Stop(sig=9)
            if self.cancel.is_set():
                raise Stop(sig=9)
            self.read_secrets()
            if self.fork_from is not None:
                self.workspace = self.runtime.fork(self.fork_from, self.peerfs)
            if self.peerfs is not None and self.workspace is None:
                raise RefusedEntry(f"no peerfs workspace named {self.peerfs!r}")
            self.unpack()
            self.before = self.snapshot()
            self.before_digest = self.peerfs_digest() if self.peerfs is not None else None
            if self.cancel.is_set():
                raise Stop(sig=9)
            self.started_at = time.monotonic()
            started = True
            self.emit("started")
            self.runtime.log(event="started", run_id=self.run_id)
            timeout = self.request["resources"]["timeout_seconds"]
            self.deadline = self.started_at + timeout
            self.steps()
            exit_code = 0
        except Stop as stop:
            exit_code, sig = stop.exit_code, stop.sig
            if getattr(stop, "timed_out", False):
                timed_out, sig = True, None
        except RefusedEntry as refused:
            error = str(refused)
        except Exception as failure:  # noqa: BLE001 - a run fails outside the command
            error = f"the run failed: {failure}"
        duration = int((time.monotonic() - self.started_at) * 1000) if started else 0
        if started and self.peerfs is not None:
            after = self.peerfs_digest()
            snapshot = None if after == self.before_digest else "01" + after
            if self.request.get("peerfs_commit") and after != self.before_digest:
                if self.runtime.args.fail_commits:
                    error = error or "the commit failed: refused by --fail-commits"
                else:
                    message = self.request["peerfs_commit_message"]
                    commit = "01" + self.peerfs_digest(message)
        result = {"exit_code": exit_code if started else None, "signal": sig, "timed_out": timed_out,
                  "duration_ms": duration, "stdout_bytes": self.stdout_bytes, "stderr_bytes": self.stderr_bytes,
                  "snapshot": snapshot, "error": error, "commit": commit}
        if not started and sig is None and error is None:
            result["error"] = "the run did not start"
        self.stdout.close()
        self.stderr.close()
        artifacts = self.results(started)
        # Logged before the run frees its slot or workspace and before the daemon can see `exited`, so the log's
        # order is the order the daemon could observe.
        self.runtime.log(event="exited", run_id=self.run_id, started=started, result=result,
                         artifacts=[a["name"] for a in artifacts])
        with self.runtime.lock:
            self.state = "exited"
        self.emit("exited", result=result)
        self.emit("results", artifacts=artifacts)

    def read_secrets(self):
        """runtime-agent-contract: each secret file is read when the run starts; one that cannot be fails it."""
        secrets = self.request.get("secrets") or {}
        if self.request.get("harness") is not None and "openai_api_key" not in secrets:
            raise RefusedEntry("the secret openai_api_key is missing")
        for name, path in secrets.items():
            try:
                with open(path, "rb") as f:
                    data = f.read(SECRET_BYTES + 1)
            except OSError as failure:
                raise RefusedEntry(f"the secret {name} cannot be read: {failure.strerror}") from None
            if len(data) > SECRET_BYTES:
                raise RefusedEntry(f"the secret {name} is over {SECRET_BYTES} bytes")
            self.secrets[name] = data
        harness = self.request.get("harness")
        if harness is not None and not os.path.isdir(harness):
            raise RefusedEntry(f"the harness {harness!r} is not a readable directory")

    def unpack(self):
        archive = self.request["workspace_archive"]
        if archive is None:
            return
        with tarfile.open(archive, mode="r:*") as tar:
            for member in tar:
                name = member.name
                parts = [p for p in name.split("/") if p not in ("", ".")]
                if name.startswith("/"):
                    raise RefusedEntry(f"refused archive entry {name!r}: an absolute path")
                if ".." in name.split("/"):
                    raise RefusedEntry(f"refused archive entry {name!r}: a .. component")
                if not (member.isdir() or member.isfile() or member.issym()) or member.islnk():
                    raise RefusedEntry(f"refused archive entry {name!r}: not a directory, regular file or "
                                       f"symbolic link")
                if not parts:
                    continue
                target = os.path.join(self.workspace, *parts)
                self.inside(os.path.dirname(target), create=True)
                if member.isdir():
                    if not os.path.isdir(target):
                        os.mkdir(target, 0o755)
                elif member.issym():
                    if os.path.lexists(target):
                        os.unlink(target)
                    os.symlink(member.linkname, target)
                else:
                    if os.path.islink(target):
                        os.unlink(target)
                    source = tar.extractfile(member)
                    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(fd, "wb") as out:
                        shutil.copyfileobj(source, out)
                    os.chmod(target, member.mode & 0o777)

    def inside(self, path, create=False):
        """PATH, which must resolve inside the run's workspace whatever its symbolic links point at."""
        real = os.path.realpath(path)
        root = os.path.realpath(self.workspace)
        if real != root and not real.startswith(root + os.sep):
            raise Escape(f"a path leaves the workspace: {os.path.relpath(path, self.workspace)!r}")
        if create:
            os.makedirs(real, mode=0o755, exist_ok=True)
        return real

    def resolve(self, text):
        rel = text[len("/workspace/"):] if text.startswith("/workspace/") else text.lstrip("/")
        path = os.path.join(self.workspace, rel)
        self.inside(os.path.dirname(path))
        if os.path.islink(path):
            self.inside(path)
        return path

    def snapshot(self):
        files, links = {}, set()
        for base, dirs, names in os.walk(self.workspace):
            for name in names + [d for d in dirs if os.path.islink(os.path.join(base, d))]:
                full = os.path.join(base, name)
                rel = os.path.relpath(full, self.workspace)
                if os.path.islink(full):
                    links.add(rel)
                elif os.path.isfile(full):
                    with open(full, "rb") as f:
                        files[rel] = hashlib.sha256(f.read()).hexdigest()
        return files, links

    def peerfs_digest(self, message=None):
        """SHA-256 of the workspace's sorted paths and contents (a symbolic link's content is its target), and of
        MESSAGE when given (a commit's ID)."""
        entries = []
        for base, dirs, names in os.walk(self.workspace):
            for name in names + [d for d in dirs if os.path.islink(os.path.join(base, d))]:
                full = os.path.join(base, name)
                rel = os.path.relpath(full, self.workspace)
                if os.path.islink(full):
                    entries.append((rel, b"link:" + os.readlink(full).encode()))
                elif os.path.isfile(full):
                    with open(full, "rb") as f:
                        entries.append((rel, b"file:" + f.read()))
        digest = hashlib.sha256()
        for rel, data in sorted(entries):
            digest.update(rel.encode() + b"\0" + str(len(data)).encode() + b"\0" + data)
        if message is not None:
            digest.update(b"commit\0" + message.encode())
        return digest.hexdigest()

    def steps(self):
        argv = self.request["argv"]
        if self.request.get("harness") is not None:
            # runtime-agent-contract, Verification: with a harness the fake is the agent; argv is ignored and the
            # prompt on stdin is run as steps.
            stdin = self.request.get("stdin")
            prompt = base64.b64decode(stdin).decode("utf-8", "replace") if stdin else ""
            argv = prompt.split()
        program, current = [], []
        for word in argv:
            if word == ";":
                if current:
                    program.append(current)
                current = []
            else:
                current.append(word)
        if current:
            program.append(current)
        for step in program:
            self.check()
            self.runtime.log(event="step", run_id=self.run_id, step=step)
            try:
                self.step(step[0], step[1:])
            except Escape as escape:
                self.write("stderr", f"{step[0]}: {escape}\n".encode())
                raise Stop(exit_code=1)
        self.check()

    def step(self, name, args):
        if name == "echo":
            self.write("stdout", (" ".join(args) + "\n").encode())
        elif name == "stderr":
            self.write("stderr", (" ".join(args) + "\n").encode())
        elif name == "bytes":
            total = int(args[0])
            while total > 0:
                part = min(total, CHUNK)
                self.write("stdout", b"x" * part)
                total -= part
        elif name == "cat":
            path = self.resolve(args[0])
            try:
                with open(path, "rb") as f:
                    self.write("stdout", f.read())
            except OSError as failure:
                self.write("stderr", f"cat: {args[0]}: {failure.strerror}\n".encode())
                raise Stop(exit_code=1)
        elif name == "write":
            path = self.resolve(args[0])
            os.makedirs(os.path.dirname(path), exist_ok=True)
            if os.path.islink(path):
                os.unlink(path)
            with open(path, "wb") as f:
                f.write(" ".join(args[1:]).encode())
        elif name == "rm":
            path = self.resolve(args[0])
            try:
                os.unlink(path)
            except OSError as failure:
                self.write("stderr", f"rm: {args[0]}: {failure.strerror}\n".encode())
                raise Stop(exit_code=1)
        elif name == "sleep":
            end = time.monotonic() + float(args[0])
            while True:
                left = min(end, self.deadline) - time.monotonic()
                if left <= 0:
                    break
                if self.cancel.wait(left):
                    break
            self.check()
        elif name == "exit":
            raise Stop(exit_code=int(args[0]))
        elif name == "kill":
            raise Stop(sig=int(args[0]))
        else:
            self.write("stderr", f"{name}: unknown step\n".encode())
            raise Stop(exit_code=127)

    def check(self):
        if self.cancel.is_set():
            raise Stop(sig=9)
        if time.monotonic() >= self.deadline:
            stop = Stop()
            stop.timed_out = True
            raise stop

    def results(self, started):
        mode = self.request["results"]
        out = []
        if mode == "none":
            return out
        out.append(self.artifact("stdout.log", os.path.join(self.dir, "stdout.log"), "text/plain"))
        out.append(self.artifact("stderr.log", os.path.join(self.dir, "stderr.log"), "text/plain"))
        if mode == "changes":
            before_files, before_links = getattr(self, "before", ({}, set()))
            after_files, after_links = self.snapshot() if started else (before_files, before_links)
            changed = sorted(p for p, digest in after_files.items() if before_files.get(p) != digest)
            removed = sorted(p for p in set(before_files) | before_links
                             if p not in after_files and p not in after_links)
            tar_path = os.path.join(self.dir, "changes.tar")
            with tarfile.open(tar_path, "w", format=tarfile.PAX_FORMAT) as tar:
                for rel in changed:
                    tar.add(os.path.join(self.workspace, rel), arcname=rel, recursive=False)
            deleted_path = os.path.join(self.dir, "deleted.txt")
            with open(deleted_path, "wb") as f:
                f.write("".join(p + "\n" for p in removed).encode())
            out.append(self.artifact("changes.tar", tar_path, "application/x-tar"))
            out.append(self.artifact("deleted.txt", deleted_path, "text/plain"))
        return out

    @staticmethod
    def artifact(name, path, media_type):
        with open(path, "rb") as f:
            data = f.read()
        return {"name": name, "path": path, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                "media_type": media_type}


class Runtime:
    def __init__(self, args):
        self.args = args
        self.root = tempfile.mkdtemp(prefix="fake-runtime-", dir=args.dir)
        self.start_delay = args.start_delay
        self.peerfs = {}
        self.peerfs_root = os.path.join(args.dir or tempfile.gettempdir(), "peerfs")
        for name in args.peerfs_workspace:
            path = os.path.join(self.peerfs_root, name)
            os.makedirs(path, mode=0o700, exist_ok=True)
            self.peerfs[name] = path
        # Forks made by earlier runs (runtime-agent-contract), kept across restarts while a peerfs space is served.
        self.forks_file = os.path.join(self.peerfs_root, ".forks.json")
        if self.peerfs and os.path.exists(self.forks_file):
            with open(self.forks_file) as f:
                for name in json.load(f):
                    self.peerfs.setdefault(name, os.path.join(self.peerfs_root, name))
        self.runs = {}
        self.lock = threading.Lock()
        self.changed = threading.Condition(self.lock)
        self.log_lock = threading.Lock()

    def log(self, **entry):
        if not self.args.log:
            return
        entry = {"at": time.time(), **entry}
        with self.log_lock, open(self.args.log, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def record_request(self, status, raw):
        """`--requests`: the raw body of each POST /v1/runs (secret paths only; contents are never read here)."""
        if not self.args.requests:
            return
        entry = {"at": time.time(), "status": status, "body": raw.decode("utf-8", "replace")}
        with self.log_lock, open(self.args.requests, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def fork(self, source, name):
        """runtime-agent-contract: a new workspace NAME at SOURCE's head; an existing NAME or a missing SOURCE fails
        the run before started, changing nothing."""
        with self.lock:
            path = os.path.join(self.peerfs_root, name)
            if name in self.peerfs or os.path.lexists(path):
                raise RefusedEntry(f"a workspace or branch named {name!r} exists already")
            if source not in self.peerfs:
                raise RefusedEntry(f"no branch named {source!r} to fork from")
            shutil.copytree(self.peerfs[source], path, symlinks=True)
            self.peerfs[name] = path
            forks = sorted(n for n in self.peerfs if n not in self.args.peerfs_workspace)
            with open(self.forks_file + ".new", "w") as f:
                json.dump(forks, f)
            os.replace(self.forks_file + ".new", self.forks_file)
        return path

    def report(self):
        with self.lock:
            running = sum(1 for r in self.runs.values() if r.state != "exited")
        return {"version": "fake-runtime-1", "image": "fake", "max_cpus": self.args.max_cpus,
                "max_memory_mib": self.args.max_memory_mib, "max_seconds": self.args.max_seconds,
                "max_concurrent_runs": self.args.max_concurrent_runs, "running": running,
                "peerfs": bool(self.args.peerfs_workspace), "max_network": self.args.max_network}

    def validate(self, body):
        if not isinstance(body, dict):
            raise ApiError(400, "invalid", "the body is not a JSON object")
        unknown = sorted(set(body) - set(RUN_FIELDS) - set(AGENT_DEFAULTS))
        if unknown:
            raise ApiError(400, "invalid", f"unknown field {unknown[0]}")
        for field in RUN_FIELDS:
            if field not in body:
                raise ApiError(400, "invalid", f"missing field {field}")
        if not isinstance(body["run_id"], str) or not RUN_ID.match(body["run_id"]):
            raise ApiError(400, "invalid", "run_id")
        argv = body["argv"]
        if (not isinstance(argv, list) or not 1 <= len(argv) <= 256
                or not all(isinstance(a, str) and 1 <= len(a.encode()) <= 4096 and "\0" not in a for a in argv)
                or sum(len(a.encode()) for a in argv) > 65536):
            raise ApiError(400, "invalid", "argv")
        cwd = body["cwd"]
        if not isinstance(cwd, str) or not cwd.startswith("/") or len(cwd.encode()) > 4096 or "\0" in cwd:
            raise ApiError(400, "invalid", "cwd")
        env = body["env"]
        if (not isinstance(env, dict) or len(env) > 64
                or not all(ENV_NAME.match(k) and isinstance(v, str) and len(v.encode()) <= 4096 and "\0" not in v
                           for k, v in env.items())):
            raise ApiError(400, "invalid", "env")
        resources = body["resources"]
        if not isinstance(resources, dict) or set(resources) != set(RESOURCE_FIELDS) or not all(
                isinstance(resources[k], int) and not isinstance(resources[k], bool) for k in RESOURCE_FIELDS):
            raise ApiError(400, "invalid", "resources")
        archive = body["workspace_archive"]
        if archive is not None and (not isinstance(archive, str) or not archive.startswith("/")):
            raise ApiError(400, "invalid", "workspace_archive")
        if archive is not None and not os.access(archive, os.R_OK):
            raise ApiError(400, "invalid", "workspace_archive is not readable")
        name = body["peerfs_workspace"]
        if name is not None and (not isinstance(name, str) or not 1 <= len(name.encode()) <= PEERFS_NAME_BYTES
                                 or name in (".", "..") or "/" in name or "\0" in name):
            raise ApiError(400, "invalid", "peerfs_workspace")
        if name is not None and archive is not None:
            raise ApiError(400, "invalid", "workspace_archive and peerfs_workspace are both set")
        if body["results"] not in ("none", "output", "changes"):
            raise ApiError(400, "invalid", "results")
        if name is not None and body["results"] == "changes":
            raise ApiError(400, "invalid", "results changes on a peerfs workspace")
        self.validate_agent_fields(body)

    @staticmethod
    def validate_agent_fields(body):
        """runtime-agent-contract, The runtime's local API: the optional fields (400 invalid naming the field)."""
        for field, default in AGENT_DEFAULTS.items():
            body.setdefault(field, default)
        if body["network"] not in ("none", "internet"):
            raise ApiError(400, "invalid", "network")
        stdin = body["stdin"]
        if stdin is not None:
            try:
                data = base64.b64decode(stdin, validate=True) if isinstance(stdin, str) else None
            except ValueError:
                data = None
            if data is None or len(data) > STDIN_BYTES:
                raise ApiError(400, "invalid", "stdin")
        harness = body["harness"]
        if harness is not None and (not isinstance(harness, str) or not harness.startswith("/") or "\0" in harness):
            raise ApiError(400, "invalid", "harness")
        secrets = body["secrets"]
        if secrets is not None and (
                not isinstance(secrets, dict) or len(secrets) > 16
                or not all(SECRET_NAME.match(k) and k not in (".", "..") and isinstance(v, str) and v.startswith("/")
                           and "\0" not in v for k, v in secrets.items())):
            raise ApiError(400, "invalid", "secrets")
        workspace = body["peerfs_workspace"]
        source = body["peerfs_fork_from"]
        if source is not None and (workspace is None or not isinstance(source, str)
                                   or not 1 <= len(source.encode()) <= PEERFS_NAME_BYTES
                                   or source in (".", "..") or "/" in source or "\0" in source):
            raise ApiError(400, "invalid", "peerfs_fork_from")
        agent = body["peerfs_agent"]
        if agent != AGENT_DEFAULTS["peerfs_agent"] and (
                workspace is None or not isinstance(agent, str) or not AGENT_NAME.match(agent)):
            raise ApiError(400, "invalid", "peerfs_agent")
        commit = body["peerfs_commit"]
        if not isinstance(commit, bool) or (commit and workspace is None):
            raise ApiError(400, "invalid", "peerfs_commit")
        message = body["peerfs_commit_message"]
        if message is not None and (not isinstance(message, str) or not 1 <= len(message.encode()) <= 4096):
            raise ApiError(400, "invalid", "peerfs_commit_message")
        if commit and message is None:
            raise ApiError(400, "invalid", "peerfs_commit_message is required with peerfs_commit")

    def start(self, body):
        self.validate(body)
        run_id = body["run_id"]
        resources = body["resources"]
        with self.lock:
            existing = self.runs.get(run_id)
            if existing is not None:
                if existing.request == body:
                    return 200, existing.record()
                raise ApiError(409, "conflict", "run_id was used with different fields")
            if (resources["cpus"] > self.args.max_cpus or resources["memory_mib"] > self.args.max_memory_mib
                    or resources["timeout_seconds"] > self.args.max_seconds):
                raise ApiError(422, "too_large", "resources exceed the runtime's maximums")
            if body["network"] == "internet" and self.args.max_network != "internet":
                raise ApiError(422, "too_large", "network internet is above the runtime's maximum")
            if body["peerfs_workspace"] is not None and not self.args.peerfs_workspace:
                raise ApiError(422, "unavailable", "this runtime serves no peerfs space")
            if sum(1 for r in self.runs.values() if r.state != "exited") >= self.args.max_concurrent_runs:
                raise ApiError(429, "busy", "every run slot is busy")
            if body["peerfs_workspace"] is not None and any(
                    r.state != "exited" and r.peerfs == body["peerfs_workspace"] for r in self.runs.values()):
                raise ApiError(429, "busy", "another run holds the peerfs workspace")
            run = Run(self, body)
            self.runs[run_id] = run
        run.thread.start()
        return 201, run.record()

    def get(self, run_id):
        with self.lock:
            run = self.runs.get(run_id)
        if run is None:
            raise ApiError(404, "not_found", "no such run")
        return run

    def events(self, run_id, after, wait, limit=None):
        run = self.get(run_id)
        end = time.monotonic() + wait
        with self.lock:
            while True:
                found = [e for e in run.events if e["sequence"] > after]
                left = end - time.monotonic()
                if found or left <= 0 or self.runs.get(run_id) is not run:
                    return found if limit is None else found[:limit]
                self.changed.wait(left)

    def cancel(self, run_id):
        run = self.get(run_id)
        with self.lock:
            if run.state != "exited":
                run.cancel.set()
            return run.record()

    def delete(self, run_id):
        run = self.get(run_id)
        run.cancel.set()
        with self.lock:
            self.runs.pop(run_id, None)
            self.changed.notify_all()
        shutil.rmtree(run.dir, ignore_errors=True)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "fake-runtime"

    def log_message(self, *args):
        pass

    def address_string(self):
        return "unix"

    def body(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            data = b""
            while True:
                size = int(self.rfile.readline().strip().split(b";")[0], 16)
                if size == 0:
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass
                    break
                data += self.rfile.read(size)
                self.rfile.readline()
            return data
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def answer(self, status, value=None):
        data = b"" if value is None else json.dumps(value).encode()
        self.send_response(status)
        if value is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if data:
            self.wfile.write(data)

    def handle_one(self, method):
        runtime = self.server.runtime
        raw = self.body()
        path, _, query = self.path.partition("?")
        params = {}
        for item in query.split("&") if query else []:
            key, _, value = item.partition("=")
            params[key] = value
        parts = [p for p in path.split("/") if p]
        status, value = 500, {"code": "internal", "error": "unhandled"}
        try:
            if method in ("POST", "PUT") and raw.strip():
                try:
                    body = json.loads(raw)
                except ValueError:
                    raise ApiError(400, "invalid", "the body is not JSON")
            else:
                body = None
            if parts == ["v1", "runtime"] and method == "GET":
                status, value = 200, runtime.report()
            elif parts == ["v1", "runs"] and method == "POST":
                sent = json.loads(raw) if isinstance(body, dict) else body  # as sent, before defaults are filled
                try:
                    status, value = runtime.start(body)
                    runtime.log(event="post", run_id=body.get("run_id"), status=status, request=sent)
                    runtime.record_request(status, raw)
                except ApiError as refused:
                    runtime.log(event="post", run_id=(body or {}).get("run_id") if isinstance(body, dict) else None,
                                status=refused.status, request=sent)
                    runtime.record_request(refused.status, raw)
                    raise
            elif len(parts) == 4 and parts[:2] == ["v1", "runs"] and parts[3] == "events" and method == "GET":
                unknown = sorted(set(params) - {"after", "wait", "limit"})
                if unknown:
                    raise ApiError(400, "invalid", f"unknown parameter {unknown[0]}")
                try:
                    after = int(params.get("after", "0"))
                    wait = int(params.get("wait", "0"))
                    limit = int(params["limit"]) if "limit" in params else None
                except ValueError:
                    raise ApiError(400, "invalid", "after, wait or limit")
                if after < 0 or not 0 <= wait <= 25 or (limit is not None and not 1 <= limit <= 1000):
                    raise ApiError(400, "invalid", "after, wait or limit")
                status, value = 200, runtime.events(parts[2], after, wait, limit)
            elif len(parts) == 4 and parts[:2] == ["v1", "runs"] and parts[3] == "cancel" and method == "POST":
                if body not in (None, {}):
                    raise ApiError(400, "invalid", "unknown field")
                status, value = 200, runtime.cancel(parts[2])
                runtime.log(event="cancel", run_id=parts[2], state=value["state"])
            elif len(parts) == 3 and parts[:2] == ["v1", "runs"] and method == "DELETE":
                runtime.delete(parts[2])
                runtime.log(event="delete", run_id=parts[2])
                status, value = 200, {}
            else:
                raise ApiError(404, "not_found", "no such route")
        except ApiError as refused:
            status, value = refused.status, {"code": refused.code, "error": refused.error}
            if refused.status == 404 and len(parts) >= 3:
                runtime.log(event="not_found", method=method, path=self.path)
        self.answer(status, value)

    def do_GET(self):
        self.handle_one("GET")

    def do_POST(self):
        self.handle_one("POST")

    def do_PUT(self):
        self.handle_one("PUT")

    def do_DELETE(self):
        self.handle_one("DELETE")


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def get_request(self):
        conn, _ = super().get_request()
        return conn, ("unix", 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("serve", nargs="?", default="serve", help="the only command, for parity with the runtime")
    parser.add_argument("--socket", required=True)
    parser.add_argument("--dir", default=None, help="where run directories go (default: the system temp dir)")
    parser.add_argument("--log", default=None, help="append one JSON line per request and run step")
    parser.add_argument("--max-cpus", type=int, default=8)
    parser.add_argument("--max-memory-mib", type=int, default=16384)
    parser.add_argument("--max-seconds", type=int, default=86400)
    parser.add_argument("--max-concurrent-runs", type=int, default=1)
    parser.add_argument("--start-delay", type=float, default=0.0, help="seconds each run is held before started")
    parser.add_argument("--peerfs-workspace", action="append", default=[],
                        help="a peerfs workspace name (repeatable); with none, peerfs is false")
    parser.add_argument("--max-network", choices=("none", "internet"), default="internet",
                        help="the most network a run may ask for (runtime agents)")
    parser.add_argument("--fail-commits", type=int, choices=(0, 1), default=0,
                        help="1: every commit fails, with commit null and error set (runtime agents)")
    parser.add_argument("--requests", default=None,
                        help="append each POST /v1/runs body, as sent, as one JSON line (secret paths, no contents)")
    args = parser.parse_args()
    runtime = Runtime(args)
    if os.path.exists(args.socket):
        os.unlink(args.socket)
    old = os.umask(0o177)
    try:
        server = Server(args.socket, Handler)
    finally:
        os.umask(old)
    os.chmod(args.socket, 0o600)
    server.runtime = runtime
    runtime.log(event="serving", socket=args.socket, start_delay=args.start_delay, max_cpus=args.max_cpus,
                peerfs=sorted(runtime.peerfs))

    def stop(*_):
        threading.Thread(target=server.shutdown, daemon=True).start()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()
        try:
            os.unlink(args.socket)
        except OSError:
            pass
        shutil.rmtree(runtime.root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
