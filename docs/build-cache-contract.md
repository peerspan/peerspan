# Build cache contract

A runtime agent's task forks a fresh workspace from its profile's branch and builds the
repository from cold: nothing is shared between tasks, not the dependencies downloaded and not
the build output. A **build cache** is the derived files (dependencies and build output) of one
build of the profile's branch, kept by peerfs and shown read-only under the derived paths of each
new task's workspace, so a task's build only redoes what its own changes touch.

The decisions are RUN-17 to RUN-20 in the
[decision log](decision-log.md#run-17-to-run-20-a-build-cache-shared-between-tasks-2026-11-15),
from issue [peerspan/runtime#15](https://github.com/peerspan/runtime/issues/15). This contract
extends the [runtime agent contract](runtime-agent-contract.md) and the
[runtime task contract](runtime-task-contract.md), and specifies the peerfs side that the runtime
and host rely on. Where it doesn't say otherwise, those contracts apply. It changes nothing for
senders.

Not in this contract:
- caches for runtime tasks (only runtime agents' profiles have one);
- replicating a cache to another host, or sharing one between spaces;
- a cache built from a branch other than the profile's `from_branch`;
- a size cap per space, and expiring caches no profile uses.

## Why the dates matter

Measured on 2026-11-15, building this repository (`cargo build --tests`, 4 vCPUs, 12 to 16 GiB,
`rust:1.97.1-bookworm`) on a loaded 8-core server, with cargo's own reported times:

| Workspace | cargo's time |
| --- | --- |
| Cold | 428 to 473 s |
| Fresh checkout of the cache's commit, cache copied, every file newly dated | 135 s |
| The same, with unchanged files dated before the cache's output | 0.32 s |
| Then a one-line change in `src/lib.rs` | 123 s |
| 291 commits after the cache's commit, cache copied, every file newly dated | 268 s at 16 GiB; killed for memory at 12 GiB, twice, where a cold build fit |

Cargo, like `make`, decides what to rebuild by comparing file dates, not contents. A cache alone
saves the dependencies; the repository's own crates rebuild whenever their sources look newer
than the cache's output, as a fresh checkout's do. So the cache only works with the dating rule
of [the workspace](#a-workspace-with-a-cache) below, and only while it stays close to the
branch's head, which is why it is refreshed as the branch moves (RUN-20).

## peerfs: caches

A **cache** belongs to one space and has a name: 1 to 128 characters of lowercase ASCII letters,
digits, `.`, `_` and `-`, starting with a letter or digit. It is a set of **versions**, of which
the newest is **current**. A version holds:
- `files`: derived files and directories, at their workspace paths, with their modes and dates;
- `commit`: the commit whose tree the files were built from;
- `dates`: for each file of that commit's tree, the date the building workspace showed it.

A version never changes once saved. Saving a new one makes it current; an earlier version is
removed once no workspace holds it, by `gc` or at the next save. Caches are local to the host:
they are never pushed, pulled or replicated, and they are not in any commit or snapshot.

| CLI | API | Behavior |
| --- | --- | --- |
| `cache save NAME --from WORKSPACE` | `POST /v1/caches/{name}` with `{workspace}` | Moves the workspace's derived files into a new version of the cache, which becomes current, then discards the workspace. `commit` is the workspace's base commit, and `dates` are the dates the workspace shows its base files. The version holds the derived files as the workspace shows them, its overlay's and those of a version it holds. Secret-class paths are never taken; a secret file inside a derived directory goes with it, which a [refresh run](#the-host-refresh) never has. Refused with 409 when the workspace has uncommitted source changes, since its output may then come from sources other than `commit`'s, or when it is borrowed. Atomic: a crash leaves the earlier version current. |
| `cache ls [--json]` | `GET /v1/caches` | Each cache: `name`, and its current version's `commit`, `saved_at`, `bytes`, and the number of versions held. |
| `cache rm NAME` | `DELETE /v1/caches/{name}` | Removes the cache. Versions that workspaces hold stay until those workspaces end, and new workspaces can no longer name it. |
| `ws create NAME --from BRANCH --cache CACHE` | `POST /v1/workspaces` with `cache` | Creates the workspace holding the cache's current version. A cache that does not exist is no error: the workspace has none, and `ws status` says so. |

No MCP tool and no agent route reaches caches: only the space's owner, through the CLI or the
API on the space's socket, and the runtime, which is the owner's.

### A workspace with a cache

A workspace holding a version reads it as a third layer, under its overlay and over nothing:
- **Derived paths only.** A derived-class path that is neither in the overlay nor removed shows
  the version's file. A source or secret path never shows a cache file, and a cache never hides
  the base.
- **Read-only.** The first write to a cached file copies it into the overlay, as for a base file.
  Removing or renaming one leaves a whiteout, so it stays gone.
- **Dates.** A base file whose content is the same as in the version's `commit` at the same path
  is dated as `dates` has it, not with the date the workspace first saw it. Every other base file
  is dated as before. Every cached file keeps the date it had when the version was saved, so an
  unchanged source is older than the output built from it, and a changed one is newer.
- **Discarding** the workspace, or `peerfs_discard`, drops its overlay and releases its version.
  The cache is unchanged.

The served workspace's process (`ws vhost-user`, `ws mount`) sees the version read-only beside
the space's objects, and nothing else of the cache.

The rule is only correct if the version's output is newer than the sources it was built from,
which holds for a refresh: the refresh workspace dates each base file either when it was
created, before its build writes anything, or, for a file unchanged since the version it
holds, as that version did, which is older than that version's output. Its saved `dates` are
those dates, so the chain holds from version to version. A build that rewrites a source file
is never saved (below), so a version's output is always built from its `commit`'s sources.

## Runtime: two run fields

`POST /v1/runs` gains two optional fields, each defaulting to null. Runtime tasks never set them.

| Field | Rules |
| --- | --- |
| `peerfs_cache` | A cache name, with `peerfs_fork_from` set: the fork's workspace is created holding the cache's current version, as `ws create --cache` does. A cache that does not exist is no error. |
| `peerfs_cache_save` | A cache name, with `peerfs_fork_from` set and `peerfs_commit` false. This run is a refresh: once the command has ended, if it exited 0, the result has no `error` and the command changed no source path, the runtime saves the workspace's derived files as a new version of this cache, and discards the workspace; then it removes the fork's branch. A run that changed source saves nothing, and its result's `error` is `the build changed source files: PATH`, naming the first such path in byte order, since its output may have been built from them. A run that failed or changed source leaves the cache as it was, but still discards the workspace and removes the branch. |

`peerfs_cache` and `peerfs_cache_save` may be set together, so a refresh builds on the current
version (incrementally) and saves the result as the next. Both are 400 when the runtime's
peerfs has no caches (`GET /v1/runtime` gains `peerfs_caches`, true when it has).

The `exited` event's result gains `cache_saved`: true when a version was saved, false otherwise,
including for runs without `peerfs_cache_save`. A save that fails sets `error`.

**Package caches.** Downloads live outside the repository by default (`~/.cargo/registry`,
`~/.npm`, pip's and Go's caches), in the VM's throwaway root. For a run with either field, the
runtime sets these in the command's environment, under the run's `env`, which can override them:

| Variable | Value |
| --- | --- |
| `CARGO_HOME` | `/workspace/.peerspan/cache/cargo` |
| `npm_config_cache` | `/workspace/.peerspan/cache/npm` |
| `PIP_CACHE_DIR` | `/workspace/.peerspan/cache/pip` |
| `GOMODCACHE` | `/workspace/.peerspan/cache/go/mod` |
| `GOCACHE` | `/workspace/.peerspan/cache/go/build` |

peerfs's built-in derived paths gain `.peerspan/cache/`, so these are derived files: kept out of
commits, and saved with the cache. The image's own tools stay where the image put them: `cargo`
and `rustup` find their toolchains through `RUSTUP_HOME` and `PATH`, which these do not change.

## Host: the profile's build cache

The launch profile gains one field:

| Field | Rules | Default |
| --- | --- | --- |
| `build_cache` | Null, or `{command, interval_seconds}`. `command` is 1 to 4,096 bytes of UTF-8, run as `["/bin/sh", "-c", command]` in `/workspace`, such as `cargo build --tests`. `interval_seconds` is 60 to 86,400: the least time between the starts of two refreshes. | null; `interval_seconds` 600 |

CLI: `agent runtime set AGENT ... [--build-cache COMMAND] [--build-cache-interval DURATION]`;
`--build-cache-interval` takes a duration as `--timeout` does and needs `--build-cache`. A
profile with `build_cache` needs a runtime that reports `peerfs_caches` true (otherwise 409
`runtime_unavailable`).

**The cache's name** is `bc-` and the first 32 hex digits of the SHA-256 of the profile's
`from_branch`, a NUL byte, and its `image` (empty when null). So it is keyed by space (the
runtime's), branch and image (RUN-19): profiles of the same branch and image share one cache, and
a profile whose image changes gets a new one. Pin the image by digest
([What the image must hold](runtime-agent-contract.md#what-the-image-must-hold)), since a moved
tag gives the same name to another toolchain's output; cargo then rebuilds what the new
compiler needs, and the next refresh replaces it.

### Tasks

A task of a profile with `build_cache` is dispatched as before, with `peerfs_cache` set to the
cache's name. Nothing else changes: the stored body, the resend rules, the output and the branch
are those of the runtime agent contract. A task does not wait for a refresh.

### The host refresh

Only a **refresh run** writes a cache (RUN-18). The host starts one for a profile with
`build_cache` when all of these hold, checking every 60 seconds:
- the profile's `from_branch` head is not the cache's current `commit`, or the cache does not
  exist;
- at least `interval_seconds` have passed since the profile's last refresh started;
- no refresh of that cache is dispatched or running;
- the runtime has a free slot, no task of any runtime agent is queued, and fewer than the
  profile's `max_runs` of its tasks and refreshes are dispatched or running.

A refresh run has:
- `run_id` `cache_` and 32 random lowercase hex digits;
- `argv` `["/bin/sh", "-c", command]`, `cwd` `/workspace`, `env` `{}`, and `stdin` null;
- the profile's `resources`, `network` and `image`;
- `peerfs_workspace` the cache's name, `.refresh.`, and the run ID's hex; `peerfs_fork_from`
  the profile's `from_branch`;
- `peerfs_cache` and `peerfs_cache_save` both the cache's name;
- `peerfs_commit` false, `results` `none`, `workspace_archive` null;
- no `harness` and no `secrets`: no agent, and no key, is in the VM.

So the cache is built only from the owner's branch, in the owner's image, by the owner's
command, and a task's output never becomes cache. The refresh runs whatever the branch's build
runs, such as Cargo build scripts, as every task's build does.

The host stores each profile's last refresh: `started_at`, `run_id`, `commit` (the branch's head
when it was dispatched), and once it ends, `ended_at`, `saved` and, when nothing was saved, a
`reason` (`exit N`, `signal N`, `timed out`, `cancelled`, or the run result's `error`). A refresh
lost to a runtime restart counts as ended with `the runtime restarted`. A host restart resumes
the stored run as for a runtime task.

| CLI after `--state DIR` | Local API | Behavior |
| --- | --- | --- |
| `agent runtime cache show [AGENT] [--json]` | `GET /v1/agents/{agent_id}/runtime/cache`, `GET /v1/agents/runtime/cache` | The cache's `name`, its current `commit`, `saved_at` and `bytes` from the runtime's peerfs (null fields when it has none), and the last refresh. 404 for an agent without `build_cache`. |
| `agent runtime cache refresh AGENT` | `POST /v1/agents/{agent_id}/runtime/cache/refresh` | Starts a refresh at the next check, ignoring `interval_seconds` and an unchanged head, but not the other conditions. 409 `busy` when one is dispatched or running. Returns `{}`. |
| `agent runtime cache clear AGENT` | `DELETE /v1/agents/{agent_id}/runtime/cache` | Removes the cache from the runtime's peerfs (`cache rm`), so tasks build cold until the next refresh. Returns `{}`. |

Removing `build_cache` from a profile, or the profile, stops refreshes; the cache stays until
`cache clear` or `cache rm`, since another profile may share it. Activity:
`runtime.cache_refreshed` with the agent, the commit and `saved`, when a refresh ends.

### Disk

A cache costs one build's derived files per branch and image, plus the versions that running
tasks still hold: for this repository, about 11 GB and 170 MB of crates. A task's workspace then
holds only what its build rewrote, which `peerfs_discard` removes when it ends. `cache show`
reports `bytes`, and `cache clear` removes it.

## Verification

- **peerfs:** its own tests, for the dating rule (an unchanged file dated as `dates` has it, a changed one
  not, a cached file's date kept), copy-up and whiteouts of cached files, saving and versions
  held by a workspace, and no cache files at source or secret paths. A `cargo build` in a mount
  with a cache of the same commit rebuilds nothing.
- **Runtime:** `scripts/check-serve.py` cases for both fields, `cache_saved`, a failed refresh
  and one that changed a source file, each leaving the cache, the branch removed after a refresh, and the package-cache variables.
- **Host:** the `runtime_agents` suite, written from this contract by an author who does not read
  `src/`, `tests/` or `integrations/` (DEC-OWN6, DEC-OWN9), gains cases for the profile field,
  the cache's name, `peerfs_cache` on tasks, when a refresh starts and what it sends, `cache
  show`, `refresh` and `clear`, and a lost refresh. The fake runtime gains both fields, checking
  them as above, `peerfs_caches` in `GET /v1/runtime`, and `cache_saved`; it records the cache a
  fork was given, and `cache_saved` is true for a refresh whose command exited 0 and wrote no source path.
- **Measured:** on the box, a task of this repository with a current cache against one without,
  repeating the table above through the runtime and peerfs, recorded in docs-internal
  `runtime.md`.
