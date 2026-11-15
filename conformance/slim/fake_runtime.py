#!/usr/bin/env python3
"""A fake `peerspan-runtime serve` for the runtime slim suite (RUN-4, DEC-OWN6, DEC-OWN9).

It serves the runtime's local API (docs/runtime-task-contract.md, "The runtime's local API") over a Unix
socket, with no VM. A run's `argv` is read as steps separated by the argument `;` (contract, Verification):

    echo TEXT...      the words and a newline to stdout
    stderr TEXT...    the words and a newline to stderr
    bytes N           N bytes of `x` to stdout
    cat PATH          a workspace file, relative to /workspace, to stdout
    write PATH TEXT   writes TEXT (the remaining words joined by spaces) to a workspace file
    fill PATH N       writes N bytes of `x` to a workspace file (changes larger than a command can hold)
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
`peerfs_commit`, `peerfs_commit_message`, `peerfs_discard` (RUN-16) and `image` (RUN-12).
- `image` is 1 to 1,024 bytes of printable ASCII without whitespace (otherwise 400 `invalid`). `GET /v1/runtime` reports
  `images` true unless started with `--images 0`; such a fake answers a run naming an `image` 422 `unavailable`. An
  image named with `--unpullable-image REF` (repeatable) fails the run before `started`, with an `error` saying the
  image cannot be pulled; any other image is "pulled" and the run goes on as on the fake's own image. The request
  file records `image` with the rest of the body.
- `secrets` files are read when the run starts; one that cannot be read, or is over 65,536 bytes, fails the run
  before `started` with an `error` naming the secret. Their contents stay in memory and are never logged.
- With `harness` set the fake ignores `argv` and acts as the agent: it fails the run before `started`, with an
  `error` naming the secret, unless exactly one of `secrets.openai_api_key` and `secrets.anthropic_api_key` is given
  (and its file is readable, as for every secret), and then reads its stdin, the
  prompt, as steps (words split on whitespace, `;` separating steps), so `write PATH TEXT ; echo done` changes the
  workspace and answers `done`.
- `peerfs_fork_from` copies that workspace (one given with `--peerfs-workspace` or an earlier fork) to a new one
  named `peerfs_workspace` before `started`, refusing an existing name or a missing `from`, which fails the run
  before `started`, changing nothing. Forks are kept under `--dir` across restarts of the fake.
- With `peerfs_commit` true, once the run has ended and been snapshotted, the commit's ID is `01` followed by the
  lowercase hex SHA-256 of the workspace's sorted paths and contents and the commit message, or null when nothing
  changed since the fork (or since the run started, without a fork). `--fail-commits 1` makes every commit fail:
  `commit` null and `error` set. The `exited` result carries `commit` for every run.
- `peerfs_discard` is `true` or `false` (the default), and `true` only with `peerfs_commit` true (otherwise 400
  `invalid`). With it true, once the run has started, either the commit was made or nothing changed, and the result
  has no `error`, the fake
  discards the workspace before logging `exited`: its directory under `--dir`/peerfs is moved to
  `--dir`/peerfs/.branches/NAME, kept as the branch's contents, so the name no longer serves as a workspace (a run on
  it fails before `started`, and a fork onto it is refused) while a later `peerfs_fork_from` naming the branch still
  copies them, across restarts of the fake too. A result with `error` set (a failed commit or any other error), or
  a run that never started, removes nothing; a failing exit that was committed is discarded. A discard that fails is logged (`discard_failed`) and changes neither the result nor its `error`.
- `--requests FILE` appends one JSON line per `POST /v1/runs`, `{at, status, body}`, with `body` the request's raw
  text: its fields, `secrets` paths included but never their contents, so a suite can compare resends byte for byte.

Linked pairs (docs/runtime-task-contract.md, "Linked runs"; PBX-26, PBX-27). `GET /v1/runtime` reports `links` true
unless started with `--links 0`; such a fake answers a run with a `link` 422 `unavailable`. `link` is
`{id, role, port, max_connections, max_bytes}`, each checked as that section says (otherwise 400 `invalid` naming
`link`); a run whose `link` takes a role its partner holds, differs from its partner's `port`, `max_connections` or
`max_bytes`, or is the third with that `id`, is 400 `invalid`. An `id` stays taken until both its runs are deleted
(`DELETE /v1/runs/{run_id}`), then is free for a new pair; a `connect` run is accepted before its partner arrives or
after it has ended, its connections refused until the `listen` side's listener is up. The fake stands for each
guest's `127.0.0.1:PORT` with a real loopback port of its own: the link listens on one for the `connect` side, and
the `listen` side's `serve` step listens on another, which the link dials, splicing each connection it accepts to it
as one ordered byte stream each way. A connection is refused at once (a TCP reset) while the `listen` side has no
listener on the link's port, beyond `max_connections` open at once, or once the link is closed. Exactly `max_bytes`
are carried in each direction at most (summed over the pair's connections and its life): the byte past it is not
delivered, every connection is closed and new ones are refused; the link ends, closing its
connections, when either run exits, and the other run goes on. Two steps use it:

    serve PORT COUNT          (listen side) listens on the guest's 127.0.0.1:PORT and reads each accepted connection
                              to its end; once COUNT connections have ended, or the link has ended and every
                              accepted one has, it stops listening and writes each connection's bytes, in accept
                              order, to stdout
    connect PORT COUNT PATH   (connect side) opens COUNT connections to 127.0.0.1:PORT one after the other, keeping
                              each open; until the first is open a refused one is retried every 0.1 s for up to 30 s
                              (the listener may not be up yet), and after it a refused one is counted, not retried.
                              Then it sends PATH's content on each open connection and half-closes it, reads each to
                              its end, writing what came back to stdout, and writes `connect: N open, M refused, K cut`
                              to stderr (K: connections whose send failed)

A connection to any other port, or from a run without a link, is refused at once: nothing else crosses. The log
records `link_open`, `link_refused` (`reason`: `no_listener`, `max_connections` or `closed`), `link_closed` (`reason`
`max_bytes` or `exited`, with the bytes `carried` from each side), `serve` (`accepted`, and `bytes` per connection)
and `connect` (`opened`, `refused`, `cut`). `--log-workspaces 1` adds, once a run's workspace is unpacked, a
`workspace` entry whose `entries` map each path to its file's SHA-256, `dir` or `link:TARGET`.
`python3 fake_runtime.py self-check` checks the linked pair host-free (`self_check`).

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
import socket
import socketserver
import struct
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
                  "peerfs_agent": "peerspan-runtime", "peerfs_commit": False, "peerfs_commit_message": None,
                  "peerfs_discard": False, "image": None}
HARNESS_SECRETS = ("openai_api_key", "anthropic_api_key")  # runtime-agent-contract: one per harness
IMAGE = re.compile(r"^[\x21-\x7e]{1,1024}$")  # printable ASCII without whitespace
SECRET_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
AGENT_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
SECRET_BYTES = 65536
STDIN_BYTES = 65536
# runtime-task-contract, Linked runs.
LINK_ID = re.compile(r"^lnk_[0-9a-f]{32}$")
LINK_FIELDS = ("id", "role", "port", "max_connections", "max_bytes")
LINK_MAX_BYTES = 1_073_741_824
PROBE = 0.2  # seconds a new connection is watched for the link's reset


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
        self.link = None  # its Link, set by Runtime.start
        self.guest_listeners = {}  # guest port -> the real loopback port standing for it (serve)
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
            self.pull()
            self.read_secrets()
            if self.fork_from is not None:
                self.workspace = self.runtime.fork(self.fork_from, self.peerfs)
            if self.peerfs is not None and self.workspace is None:
                raise RefusedEntry(f"no peerfs workspace named {self.peerfs!r}")
            self.unpack()
            if self.runtime.args.log_workspaces and self.workspace is not None:
                self.runtime.log(event="workspace", run_id=self.run_id, entries=self.listing())
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
            if (self.request.get("peerfs_discard") and error is None
                    and (commit is not None or after == self.before_digest)):
                try:
                    self.runtime.discard(self.peerfs)
                except Exception as failure:  # noqa: BLE001 - RUN-16: logged, the result is unchanged
                    self.runtime.log(event="discard_failed", run_id=self.run_id, error=str(failure))
                else:
                    self.runtime.log(event="discarded", run_id=self.run_id, workspace=self.peerfs)
        result = {"exit_code": exit_code if started else None, "signal": sig, "timed_out": timed_out,
                  "duration_ms": duration, "stdout_bytes": self.stdout_bytes, "stderr_bytes": self.stderr_bytes,
                  "snapshot": snapshot, "error": error, "commit": commit}
        if not started and sig is None and error is None:
            result["error"] = "the run did not start"
        self.stdout.close()
        self.stderr.close()
        artifacts = self.results(started)
        if self.link is not None:
            self.link.close("exited")  # Linked runs: either run's exit ends the link
        # Logged before the run frees its slot or workspace and before the daemon can see `exited`, so the log's
        # order is the order the daemon could observe.
        self.runtime.log(event="exited", run_id=self.run_id, started=started, result=result,
                         artifacts=[a["name"] for a in artifacts])
        with self.runtime.lock:
            self.state = "exited"
        self.emit("exited", result=result)
        self.emit("results", artifacts=artifacts)

    def pull(self):
        """runtime-agent-contract: an image the runtime cannot pull fails the run before started."""
        image = self.request.get("image")
        if image is not None and image in self.runtime.args.unpullable_image:
            raise RefusedEntry(f"the image {image} cannot be pulled: refused by --unpullable-image")

    def read_secrets(self):
        """runtime-agent-contract: each secret file is read when the run starts; one that cannot be fails it."""
        secrets = self.request.get("secrets") or {}
        if self.request.get("harness") is not None:
            given = [name for name in HARNESS_SECRETS if name in secrets]
            if not given:
                raise RefusedEntry("the secret openai_api_key or anthropic_api_key is missing")
            if len(given) > 1:
                raise RefusedEntry("the secrets openai_api_key and anthropic_api_key are both given; a harness "
                                   "takes exactly one")
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

    def listing(self):
        """`--log-workspaces`: {path: SHA-256 of a file, `dir`, or `link:TARGET`} of the unpacked workspace."""
        out = {}
        for base, dirs, names in os.walk(self.workspace):
            for name in sorted(dirs + names):
                full = os.path.join(base, name)
                rel = os.path.relpath(full, self.workspace)
                if os.path.islink(full):
                    out[rel] = "link:" + os.readlink(full)
                elif os.path.isdir(full):
                    out[rel] = "dir"
                else:
                    with open(full, "rb") as f:
                        out[rel] = hashlib.sha256(f.read()).hexdigest()
        return out

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
        elif name == "fill":
            path = self.resolve(args[0])
            os.makedirs(os.path.dirname(path), exist_ok=True)
            if os.path.islink(path):
                os.unlink(path)
            with open(path, "wb") as f:
                total = int(args[1])
                while total > 0:
                    part = min(total, 1 << 20)
                    f.write(b"x" * part)
                    total -= part
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
        elif name == "serve":
            self.serve(int(args[0]), int(args[1]))
        elif name == "connect":
            self.connect(int(args[0]), int(args[1]), args[2])
        elif name == "exit":
            raise Stop(exit_code=int(args[0]))
        elif name == "kill":
            raise Stop(sig=int(args[0]))
        else:
            self.write("stderr", f"{name}: unknown step\n".encode())
            raise Stop(exit_code=127)

    # Linked runs: the two steps.

    def serve(self, port, count):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(64)
        listener.settimeout(0.05)
        self.guest_listeners[port] = listener.getsockname()[1]
        received, ended = [], []
        try:
            while True:
                self.check()
                finished = sum(1 for e in ended if e.is_set())
                if finished >= count or (finished == len(ended) and self.link is not None and self.link.ended):
                    break
                try:
                    conn, _ = listener.accept()
                except socket.timeout:
                    continue
                received.append(bytearray())
                ended.append(threading.Event())
                threading.Thread(target=self.drain, args=(conn, received[-1], ended[-1]), daemon=True).start()
        finally:
            self.guest_listeners.pop(port, None)
            listener.close()
        self.runtime.log(event="serve", run_id=self.run_id, port=port, accepted=len(received),
                         bytes=[len(b) for b in received])
        for data in received:
            self.write("stdout", bytes(data))

    @staticmethod
    def drain(conn, buffer, ended):
        conn.settimeout(None)
        try:
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                buffer += data
        except OSError:
            pass
        finally:
            conn.close()
            ended.set()

    def connect(self, port, count, path):
        try:
            with open(self.resolve(path), "rb") as f:
                data = f.read()
        except OSError as failure:
            self.write("stderr", f"connect: {path}: {failure.strerror}\n".encode())
            raise Stop(exit_code=1)
        conns, refused, cut = [], 0, 0
        for _ in range(count):
            conn = self.dial(port, retry=not conns)
            if conn is None:
                refused += 1
            else:
                conns.append(conn)
        for conn in conns:
            try:
                conn.sendall(data)
                conn.shutdown(socket.SHUT_WR)
            except OSError:
                cut += 1
        for conn in conns:
            reply = bytearray()
            try:
                conn.settimeout(max(0.1, self.deadline - time.monotonic()))
                while True:
                    part = conn.recv(65536)
                    if not part:
                        break
                    reply += part
            except OSError:
                pass
            conn.close()
            self.write("stdout", bytes(reply))
        self.runtime.log(event="connect", run_id=self.run_id, port=port, opened=len(conns), refused=refused, cut=cut)
        self.write("stderr", f"connect: {len(conns)} open, {refused} refused, {cut} cut\n".encode())
        self.check()

    def dial(self, port, retry):
        """A connection from this guest to its 127.0.0.1:PORT, or None when refused (retried while RETRY)."""
        link = self.link
        if link is None or self.request["link"]["role"] != "connect" or port != link.port:
            return None  # the guest has no network but its link port
        end = time.monotonic() + (30 if retry else 0)
        while True:
            self.check()
            try:
                conn = socket.create_connection(("127.0.0.1", link.front_port), timeout=2)
            except OSError:
                conn = None
            if conn is not None:
                conn.settimeout(PROBE)
                try:
                    if conn.recv(1, socket.MSG_PEEK) == b"":
                        conn.close()
                        conn = None
                except socket.timeout:
                    pass
                except OSError:
                    conn.close()
                    conn = None
            if conn is not None:
                conn.settimeout(None)
                return conn
            if time.monotonic() >= end or link.ended:
                return None
            self.cancel.wait(0.1)

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


class Link:
    """One linked pair's link (runtime-task-contract, Linked runs): a real loopback port standing for the `connect`
    guest's 127.0.0.1:PORT, spliced to the `listen` side's `serve` listener."""

    def __init__(self, runtime, spec):
        self.runtime = runtime
        self.id, self.port = spec["id"], spec["port"]
        self.max_connections, self.max_bytes = spec["max_connections"], spec["max_bytes"]
        self.shape = {k: spec[k] for k in ("port", "max_connections", "max_bytes")}
        self.runs = {}  # role -> Run
        self.carried = {"connect": 0, "listen": 0}  # bytes each side sent through the link
        self.pairs = []  # open connections: [client, server, directions still open]
        self.ended = False  # a run exited
        self.cut = False  # a direction reached max_bytes
        self.lock = threading.Lock()
        self.front = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.front.bind(("127.0.0.1", 0))
        self.front.listen(64)
        self.front.settimeout(0.1)
        self.front_port = self.front.getsockname()[1]
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self):
        while not self.ended:
            try:
                client, _ = self.front.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.admit(client)
        self.front.close()

    def admit(self, client):
        pair = [client, None, 2]
        with self.lock:
            listen = self.runs.get("listen")
            real = listen.guest_listeners.get(self.port) if listen is not None else None
            if self.ended or self.cut:
                reason = "closed"
            elif real is None:
                reason = "no_listener"
            elif len(self.pairs) >= self.max_connections:
                reason = "max_connections"
            else:
                reason = None
                self.pairs.append(pair)  # counted from here, so two at once cannot pass the bound
        if reason is None:
            try:
                pair[1] = socket.create_connection(("127.0.0.1", real), timeout=2)
            except OSError:
                reason = "no_listener"
                with self.lock:
                    self.pairs.remove(pair)
        if reason is not None:
            client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            client.close()  # a reset: refused at once
            self.runtime.log(event="link_refused", link=self.id, reason=reason)
            return
        pair[1].settimeout(None)
        client.settimeout(None)
        self.runtime.log(event="link_open", link=self.id, open=len(self.pairs))
        threading.Thread(target=self.carry, args=(pair, client, pair[1], "connect"), daemon=True).start()
        threading.Thread(target=self.carry, args=(pair, pair[1], client, "listen"), daemon=True).start()

    def carry(self, pair, src, dst, side):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                with self.lock:
                    if self.ended or self.cut:
                        break
                    part = data[:self.max_bytes - self.carried[side]]
                    self.carried[side] += len(part)
                    full = self.carried[side] >= self.max_bytes
                if part:
                    dst.sendall(part)
                if full:
                    self.close("max_bytes")
                    break
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        finally:
            with self.lock:
                pair[2] -= 1
                last = pair[2] == 0
                if last and pair in self.pairs:
                    self.pairs.remove(pair)
            if last:
                for conn in pair[:2]:
                    conn.close()

    def close(self, reason):
        """`max_bytes`: every connection closed, new ones refused. `exited`: a run exited and the link ends."""
        with self.lock:
            if self.ended or (reason == "max_bytes" and self.cut):
                return
            if reason == "max_bytes":
                self.cut = True
            else:
                self.ended = True
            pairs = list(self.pairs)
            carried = dict(self.carried)
        for pair in pairs:
            for conn in pair[:2]:
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        self.runtime.log(event="link_closed", link=self.id, reason=reason, carried=carried)


class Runtime:
    def __init__(self, args):
        self.args = args
        self.root = tempfile.mkdtemp(prefix="fake-runtime-", dir=args.dir)
        self.start_delay = args.start_delay
        self.peerfs = {}  # workspaces: name -> directory
        self.branches = {}  # discarded workspaces whose branch stays (RUN-16): name -> directory of its contents
        self.peerfs_root = os.path.join(args.dir or tempfile.gettempdir(), "peerfs")
        for name in args.peerfs_workspace:
            path = os.path.join(self.peerfs_root, name)
            os.makedirs(path, mode=0o700, exist_ok=True)
            self.peerfs[name] = path
        # Forks made by earlier runs (runtime-agent-contract), kept across restarts while a peerfs space is served.
        self.forks_file = os.path.join(self.peerfs_root, ".forks.json")
        self.branches_root = os.path.join(self.peerfs_root, ".branches")
        if self.peerfs and os.path.exists(self.forks_file):
            with open(self.forks_file) as f:
                for name in json.load(f):
                    kept = os.path.join(self.branches_root, name)
                    if os.path.isdir(kept) and name not in self.peerfs:
                        self.branches[name] = kept
                    else:
                        self.peerfs.setdefault(name, os.path.join(self.peerfs_root, name))
        self.runs = {}
        self.links = {}  # link id -> Link, kept until both its runs are deleted so that no third run takes the id
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
            if name in self.peerfs or name in self.branches or os.path.lexists(path):
                raise RefusedEntry(f"a workspace or branch named {name!r} exists already")
            origin = self.peerfs.get(source) or self.branches.get(source)
            if origin is None:
                raise RefusedEntry(f"no branch named {source!r} to fork from")
            shutil.copytree(origin, path, symlinks=True)
            self.peerfs[name] = path
            self.save_forks()
        return path

    def discard(self, name):
        """RUN-16: the workspace NAME goes; its contents stay as the branch's, for later forks."""
        with self.lock:
            os.makedirs(self.branches_root, mode=0o700, exist_ok=True)
            kept = os.path.join(self.branches_root, name)
            shutil.rmtree(kept, ignore_errors=True)
            os.replace(self.peerfs[name], kept)
            del self.peerfs[name]
            self.branches[name] = kept
            self.save_forks()

    def save_forks(self):
        """The forks and discarded branches, for restarts of the fake. Called with the lock held."""
        forks = sorted(n for n in [*self.peerfs, *self.branches] if n not in self.args.peerfs_workspace)
        with open(self.forks_file + ".new", "w") as f:
            json.dump(forks, f)
        os.replace(self.forks_file + ".new", self.forks_file)

    def report(self):
        with self.lock:
            running = sum(1 for r in self.runs.values() if r.state != "exited")
        return {"version": "fake-runtime-1", "image": "fake", "max_cpus": self.args.max_cpus,
                "max_memory_mib": self.args.max_memory_mib, "max_seconds": self.args.max_seconds,
                "max_concurrent_runs": self.args.max_concurrent_runs, "running": running,
                "peerfs": bool(self.args.peerfs_workspace), "max_network": self.args.max_network,
                "images": bool(self.args.images), "links": bool(self.args.links)}

    def validate(self, body):
        if not isinstance(body, dict):
            raise ApiError(400, "invalid", "the body is not a JSON object")
        unknown = sorted(set(body) - set(RUN_FIELDS) - set(AGENT_DEFAULTS) - {"link"})
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
        self.validate_link(body)

    @staticmethod
    def validate_link(body):
        """runtime-task-contract, Linked runs: the optional `link` (400 invalid naming it)."""
        link = body.setdefault("link", None)
        if link is None:
            return

        def number(key, low, high):
            value = link.get(key)
            return isinstance(value, int) and not isinstance(value, bool) and low <= value <= high
        if (not isinstance(link, dict) or set(link) != set(LINK_FIELDS) or not isinstance(link["id"], str)
                or not LINK_ID.match(link["id"]) or link["role"] not in ("listen", "connect")
                or not number("port", 1, 65535) or not number("max_connections", 1, 64)
                or not number("max_bytes", 1, LINK_MAX_BYTES)):
            raise ApiError(400, "invalid", "link")

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
        discard = body["peerfs_discard"]
        if not isinstance(discard, bool) or (discard and commit is not True):
            raise ApiError(400, "invalid", "peerfs_discard")
        image = body["image"]
        if image is not None and (not isinstance(image, str) or not IMAGE.match(image)):
            raise ApiError(400, "invalid", "image")

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
            if body["image"] is not None and not self.args.images:
                raise ApiError(422, "unavailable", "this runtime boots only its own image")
            link = body["link"]
            if link is not None and not self.args.links:
                raise ApiError(422, "unavailable", "this runtime has no linked pairs")
            partner = self.links.get(link["id"]) if link is not None else None
            if partner is not None:
                if len(partner.runs) >= 2:
                    raise ApiError(400, "invalid", "link: a third run with this id")
                if link["role"] in partner.runs:
                    raise ApiError(400, "invalid", "link: its partner has this role")
                if partner.shape != {k: link[k] for k in partner.shape}:
                    raise ApiError(400, "invalid", "link: its fields differ from its partner's")
            if sum(1 for r in self.runs.values() if r.state != "exited") >= self.args.max_concurrent_runs:
                raise ApiError(429, "busy", "every run slot is busy")
            if body["peerfs_workspace"] is not None and any(
                    r.state != "exited" and r.peerfs == body["peerfs_workspace"] for r in self.runs.values()):
                raise ApiError(429, "busy", "another run holds the peerfs workspace")
            run = Run(self, body)
            self.runs[run_id] = run
            if link is not None:
                if partner is None:
                    partner = self.links[link["id"]] = Link(self, link)
                with partner.lock:
                    partner.runs[link["role"]] = run
                run.link = partner
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
            if self.runs.get(run_id) is run:
                del self.runs[run_id]
            link = run.link
            # Linked runs: an `id` stays taken until both its runs are deleted.
            if (link is not None and self.links.get(link.id) is link and len(link.runs) == 2
                    and all(self.runs.get(r.request["run_id"]) is not r for r in link.runs.values())):
                del self.links[link.id]
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
    parser.add_argument("serve", nargs="?", default="serve", choices=("serve", "self-check"),
                        help="serve, for parity with the runtime; self-check checks linked pairs host-free")
    parser.add_argument("--socket", default=None)
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
    parser.add_argument("--images", type=int, choices=(0, 1), default=1,
                        help="0: GET /v1/runtime reports images false and runs may not name an image (RUN-12)")
    parser.add_argument("--unpullable-image", action="append", default=[],
                        help="an image reference it cannot pull (repeatable): such runs fail before started")
    parser.add_argument("--requests", default=None,
                        help="append each POST /v1/runs body, as sent, as one JSON line (secret paths, no contents)")
    parser.add_argument("--links", type=int, choices=(0, 1), default=1,
                        help="0: GET /v1/runtime reports links false and runs may not have a link (Linked runs)")
    parser.add_argument("--log-workspaces", type=int, choices=(0, 1), default=0,
                        help="1: log each run's unpacked workspace (paths and file digests)")
    args = parser.parse_args()
    if args.serve == "self-check":
        print(f"linked pairs checked in {self_check(args.dir):.1f}s")
        return 0
    if not args.socket:
        parser.error("--socket is required")
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


# The linked pair's host-free self-check (runtime-task-contract, Linked runs; its Verification lists the cases).

def self_check(directory=None):
    """Start the fake twice (with and without links) on private sockets and check its linked pairs: `links` in the
    report, a pair joined on its port with several connections, connections refused before the listener and beyond
    `max_connections`, the link closed at `max_bytes` and by either run's exit while the other goes on, other ports
    unreachable, the refusals of a third run, a mismatched partner and malformed fields, an id free again once both
    its runs are deleted, and a connect run accepted before its partner or after it has ended. Returns the seconds."""
    import http.client
    import io
    import subprocess

    began = time.monotonic()
    work = tempfile.mkdtemp(prefix="fake-runtime-links-", dir=directory)
    log = os.path.join(work, "log.jsonl")
    archive = os.path.join(work, "ws.tar")
    with tarfile.open(archive, "w") as tar:
        for name, data in {"msg.txt": b"hello\n", "big.txt": b"0123456789" * 10}.items():
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o644
            tar.addfile(info, io.BytesIO(data))

    class Unix(http.client.HTTPConnection):
        def __init__(self, path):
            super().__init__("localhost", timeout=40)
            self.path = path

        def connect(self):
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(self.path)

    def call(sock, method, path, body=None):
        conn = Unix(sock)
        try:
            data = None if body is None else json.dumps(body).encode()
            conn.request(method, path, body=data, headers={"Content-Type": "application/json"} if data else {})
            response = conn.getresponse()
            raw = response.read()
        finally:
            conn.close()
        return response.status, json.loads(raw) if raw.strip() else None

    def serve(name, *extra):
        sock = os.path.join(work, name + ".sock")
        process = subprocess.Popen([sys.executable, "-I", os.path.abspath(__file__), "serve", "--socket", sock,
                                    "--dir", work, "--log", log, "--max-concurrent-runs", "4", *extra],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 15
        while True:
            try:
                if call(sock, "GET", "/v1/runtime")[0] == 200:
                    return process, sock
            except OSError:
                pass
            if time.monotonic() > deadline:
                raise AssertionError(f"the fake runtime {name} did not start")
            time.sleep(0.05)

    def want(condition, message):
        if not condition:
            raise AssertionError(f"linked pairs: {message}")

    counter = [0]

    def body(argv, link=None):
        counter[0] += 1
        out = {"run_id": "run_" + hashlib.sha256(f"self-check/{counter[0]}".encode()).hexdigest(), "argv": argv,
               "cwd": "/workspace", "env": {}, "resources": {"cpus": 1, "memory_mib": 256, "timeout_seconds": 40},
               "workspace_archive": archive, "peerfs_workspace": None, "results": "output"}
        if link is not None:
            out["link"] = link
        return out

    def new_link(side, **fields):
        return {"id": "lnk_" + os.urandom(16).hex(), "role": side, "port": 7000, "max_connections": 16,
                "max_bytes": 1 << 20, **fields}

    def start(sock, argv, link=None, status=201):
        request = body(argv, link)
        got, answer = call(sock, "POST", "/v1/runs", request)
        want(got == status, f"POST /v1/runs {argv} {link}: {got} {answer}, want {status}")
        return request["run_id"], answer

    def finish(sock, run_id):
        """(stdout, stderr, exit_code) once the run has its results."""
        events, deadline = [], time.monotonic() + 45
        while not events or events[-1]["kind"] != "results":
            want(time.monotonic() < deadline, f"{run_id[:12]} did not end: {[e['kind'] for e in events]}")
            events += call(sock, "GET", f"/v1/runs/{run_id}/events?after={len(events)}&wait=20")[1]
        text = {k: b"".join(base64.b64decode(e["data"]) for e in events if e["kind"] == k)
                for k in ("stdout", "stderr")}
        result = next(e["result"] for e in events if e["kind"] == "exited")
        return text["stdout"], text["stderr"], result["exit_code"]

    def pair(sock, listen_argv, connect_argv, **fields):
        link = new_link("listen", **fields)
        env, _ = start(sock, listen_argv, link)
        bot, _ = start(sock, connect_argv, {**link, "role": "connect"})
        return link["id"], finish(sock, env), finish(sock, bot)

    def logged(event, link_id):
        with open(log) as f:
            return [e for e in map(json.loads, f) if e.get("event") == event and e.get("link") == link_id]

    process, sock = serve("links")
    try:
        want(call(sock, "GET", "/v1/runtime")[1].get("links") is True, "GET /v1/runtime does not report links true")
        # Joined on the port: three connections reach the listener, each a byte stream, and nothing else is changed.
        lid, env, bot = pair(sock, ["serve", "7000", "3"], ["connect", "7000", "3", "msg.txt"])
        want(env[0] == b"hello\n" * 3 and env[2] == 0 and bot[2] == 0 and b"3 open, 0 refused" in bot[1],
             f"a joined pair: env {env}, connect {bot}")
        want([e["reason"] for e in logged("link_closed", lid)] == ["exited"], "the link did not end once")
        # Before the listener: refused at once, then joined once the listener is up.
        lid, env, bot = pair(sock, ["sleep", "1", ";", "serve", "7000", "1"], ["connect", "7000", "1", "msg.txt"])
        refusals = [e["reason"] for e in logged("link_refused", lid)]
        want(env[0] == b"hello\n" and refusals and set(refusals) == {"no_listener"},
             f"before the listener: env {env[0]!r}, refusals {refusals}")
        # Another guest port than the link's: refused at once, and the listener sees nothing.
        lid, env, bot = pair(sock, ["serve", "7000", "1", ";", "echo", "done"], ["connect", "7001", "1", "msg.txt"])
        want(env[0] == b"done\n" and b"0 open, 1 refused" in bot[1], f"a connection to another port: {env} {bot}")
        # Beyond max_connections: refused while the others go on.
        lid, env, bot = pair(sock, ["serve", "7000", "3"], ["connect", "7000", "3", "msg.txt"], max_connections=2)
        refusals = [e["reason"] for e in logged("link_refused", lid)]
        want(env[0] == b"hello\n" * 2 and refusals == ["max_connections"] and b"2 open, 1 refused" in bot[1],
             f"max_connections 2: env {env[0]!r}, refusals {refusals}, connect {bot[1]!r}")
        # max_bytes: exactly that many bytes carried, then every connection closed.
        lid, env, bot = pair(sock, ["serve", "7000", "1"], ["connect", "7000", "1", "big.txt"], max_bytes=10)
        closed = logged("link_closed", lid)
        want(env[0] == b"0123456789" and closed and closed[0]["reason"] == "max_bytes"
             and closed[0]["carried"]["connect"] == 10, f"max_bytes 10: env {env[0]!r}, closed {closed}")
        # The connect side exits first: the link ends and the listen side goes on.
        lid, env, bot = pair(sock, ["serve", "7000", "2", ";", "echo", "went on"], ["connect", "7000", "1", "msg.txt"])
        want(env[0] == b"hello\nwent on\n" and [e["reason"] for e in logged("link_closed", lid)] == ["exited"],
             f"the connect side exiting: {env}")
        # The listen side exits first: the link ends, the connect side's connection is refused and it goes on.
        lid, env, bot = pair(sock, ["exit", "0"], ["sleep", "0.5", ";", "connect", "7000", "1", "msg.txt", ";",
                                                    "echo", "went on"])
        want(bot[0] == b"went on\n" and b"0 open, 1 refused" in bot[1] and bot[2] == 0,
             f"the listen side exiting: {bot}")
        # No link, or another port: nothing crosses, at once.
        alone, _ = start(sock, ["connect", "7000", "1", "msg.txt"])
        out = finish(sock, alone)
        want(b"0 open, 1 refused" in out[1], f"a run without a link: {out}")
        # Refusals: a third run, a partner with another port or bounds or the same role, malformed fields.
        link = new_link("listen")
        first, _ = start(sock, ["sleep", "3"], link)
        for changed in ({"port": 7001}, {"max_connections": 3}, {"max_bytes": 5}, {"role": "listen"}):
            start(sock, ["echo", "x"], {**link, "role": "connect", **changed}, status=400)
        second, _ = start(sock, ["echo", "x"], {**link, "role": "connect"})
        start(sock, ["echo", "x"], {**link, "role": "connect"}, status=400)
        start(sock, ["echo", "x"], {**link, "role": "listen"}, status=400)
        for bad in ({"id": "lnk_" + "A" * 32}, {"id": "lnk_" + "a" * 31}, {"role": "both"}, {"port": 0},
                    {"port": 65536}, {"max_connections": 0}, {"max_connections": 65}, {"max_bytes": 0},
                    {"max_bytes": LINK_MAX_BYTES + 1}, {"port": True}, {"extra": 1}):
            got, answer = call(sock, "POST", "/v1/runs", body(["echo", "x"], new_link("listen", **bad)))
            want(got == 400 and answer.get("code") == "invalid", f"link {bad}: {got} {answer}")
        finish(sock, first)
        finish(sock, second)
        # The id stays taken until both its runs are deleted: with one deleted a third run is still refused (either
        # role); with both deleted the id is free and a new pair on it is joined.
        got, _ = call(sock, "DELETE", f"/v1/runs/{first}")
        want(got == 200, f"DELETE the listen run: {got}")
        start(sock, ["echo", "x"], {**link, "role": "listen"}, status=400)
        start(sock, ["echo", "x"], {**link, "role": "connect"}, status=400)
        got, _ = call(sock, "DELETE", f"/v1/runs/{second}")
        want(got == 200, f"DELETE the connect run: {got}")
        env, _ = start(sock, ["serve", "7000", "1"], link)
        bot, _ = start(sock, ["connect", "7000", "1", "msg.txt"], {**link, "role": "connect"})
        want(finish(sock, env)[0] == b"hello\n" and finish(sock, bot)[2] == 0, "a pair on an id freed by deletes")
        start(sock, ["echo", "x"], {**link, "role": "connect"}, status=400)
        # A connect run before its partner: accepted, refused until the listener is up, then joined.
        link = new_link("connect")
        bot, _ = start(sock, ["connect", "7000", "1", "msg.txt"], link)
        time.sleep(0.5)
        env, _ = start(sock, ["serve", "7000", "1"], {**link, "role": "listen"})
        env_out, bot_out = finish(sock, env), finish(sock, bot)
        refusals = [e["reason"] for e in logged("link_refused", link["id"])]
        want(env_out[0] == b"hello\n" and b"1 open, 0 refused" in bot_out[1] and set(refusals) == {"no_listener"},
             f"connect before listen: env {env_out}, connect {bot_out}, refusals {refusals}")
        # A connect run after its partner has ended: accepted, its connection refused, and it goes on.
        link = new_link("listen")
        env, _ = start(sock, ["exit", "0"], link)
        finish(sock, env)
        bot, _ = start(sock, ["connect", "7000", "1", "msg.txt", ";", "echo", "went on"], {**link, "role": "connect"})
        out = finish(sock, bot)
        want(out[0] == b"went on\n" and b"0 open, 1 refused" in out[1], f"connect after the listen side ended: {out}")
    finally:
        process.kill()
        process.wait()
    process, sock = serve("no-links", "--links", "0")
    try:
        want(call(sock, "GET", "/v1/runtime")[1].get("links") is False, "--links 0 does not report links false")
        got, answer = call(sock, "POST", "/v1/runs", body(["echo", "x"], new_link("listen")))
        want(got == 422 and answer.get("code") == "unavailable", f"a link on --links 0: {got} {answer}")
        plain, _ = start(sock, ["echo", "plain"])
        want(finish(sock, plain)[0] == b"plain\n", "a run without a link on --links 0")
    finally:
        process.kill()
        process.wait()
    shutil.rmtree(work, ignore_errors=True)
    return time.monotonic() - began


if __name__ == "__main__":
    sys.exit(main())
