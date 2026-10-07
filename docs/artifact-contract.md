# Task artifact contract

Roadmap milestone 6, slice 3: files attached to tasks. The design and its settled decisions are in the [delegation proposal](delegation-proposal.md) (decision 7). This contract extends the [task contract](task-contract.md); delegation chains (slice 4) extend it later.

## Model

An **artifact** is a file attached to a task, either as an **input** by the submitter or as a **result** by the receiving agent. Artifacts are content-addressed: the host that holds a file advertises it in a manifest, and the other party of that task pulls it over the peer connection and verifies its SHA-256 digest. Task traffic, artifacts included, never passes through coordination.

A **manifest** is a list of at most 64 entries `{name, size, sha256, media_type}`:
- `name`: 1 to 255 bytes of UTF-8, with no `/`, `\`, NUL, or control characters, and not `.` or `..`; names are unique within a manifest;
- `size`: bytes, 0 to 104,857,600 (100 MiB);
- `sha256`: 64 lowercase hex digits; digests are unique within a manifest;
- `media_type`: 1 to 255 bytes of printable ASCII; the CLI's default is `application/octet-stream`.

All four fields are required. On the peer wire a manifest has 1 to 64 entries and `artifacts: []` is a 400; on the local and adapter APIs an empty list means no artifacts.

Artifacts are **off unless allowed**. A `task.submit` grant or policy rule carries `max_artifact_bytes`, from 0 (the default) to 1,073,741,824 (1 GiB). It bounds the total size of a task's input and result artifacts together. With 0, any task with artifacts in either direction is refused, even a zero-byte file. An agent attaching a file to a result acts under its own local permissions, so a manipulated agent could otherwise exfiltrate files; the receiving owner opts in.

## Authorization

- **Grants** gain `max_artifact_bytes` (default 0), set with `grant create --max-artifact-bytes N`. A nonzero value requires the action `task.submit`.
- **Policy rules** gain `max_artifact_bytes` (default 0), set with `access allow --max-artifact-bytes N`. A nonzero value requires `task.submit` in `actions`. In the rule JSON it is omitted when 0; grant records always show it. In the signed statement, a nonzero value is appended to the rule's fifth line as a third space-separated value, so existing policies sign and verify unchanged.

  **Test vector.** The person and network are those of the policy vector in the coordination contract, with version 2, issued `2026-10-10T00:00:00Z`, valid until `2026-10-17T00:00:00Z`. It has two rules:
  - `reviewer` for `person:person_72456720412037a6b339f884ce6d91bb4cc163a7dc3e4c58c658e6c2097b92a2`, `message.append task.submit`, line 5 `65536 false 1048576`;
  - `triage` for `network`, `task.submit`, line 5 `4096 true`.

  Its `signature` is `U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgbnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/EAAAARY2Fwc3VsZS1wZXJzb24tdjEAAAAAAAAABnNoYTUxMgAAAFMAAAALc3NoLWVkMjU1MTkAAABAGaZoSLXB4mfYtcitytb/FSRHPWfWO9ccCJCeCjSHNdTcKmOAqDW7dIY4AQIIaVkOU0M+rQMJGDYfvkT+5dnQBw==`.
- **Submission:** a request whose input manifest total exceeds the authorizing bound returns 403, as an oversized input does.
- **Results:** the bound is the one checked when the agent accepted the task. It is stored as an internal `max_artifact_bytes` key in the received task's record and never served. A completion whose result total, plus the input total, exceeds it returns 403 and changes nothing. Later revocation does not affect an accepted task, as for its other results.

## Peer wire

- `POST /peer/v1/tasks` accepts an optional `artifacts` input manifest. It is part of the request for idempotency, and the receiver stores it as received. When the receiver lacks quota (below) for the manifest, it returns 507, which the submitter treats as uncertain and retries.
- The final `succeeded` or `failed` event gains `artifacts`, the result manifest, or null without results. Every other event carries `artifacts: null`.
- `GET /peer/v1/tasks/{task_id}/artifacts/{sha256}` returns the file as `application/octet-stream` with an exact `Content-Length`. A host serves an artifact only to the other party of that task:
  - the submitter serves an input listed in its outbound task to that receiver;
  - the receiver serves a result listed in its received task's final event to that submitter.

  Anyone else, an unlisted digest, or a pruned file gets 404. Fetching authorizes no new work, so it remains available after revocation, as status lookup does.

## Transfer

Hosts fetch eagerly, without range requests, and verify both size and digest before storing; a mismatch discards the download and counts as a failed attempt. Failed fetches retry with backoff from 1 second to 60 seconds and share the 4 concurrent task jobs. Each stored artifact records a `task.artifact_fetched` activity with the subject `<peer>/<task_id>/<sha256>`. A host serves only files it has stored.
- **Inputs:** the receiver fetches every input after persisting the task. The task stays `queued` and is not handed to an agent until all inputs are stored, so an agent never sees a partial input. If the deadline passes first, the task expires as usual.
- **Results:** the submitter fetches result artifacts after it stores the final event. The local record shows each artifact's state.

## Storage, quota, and retention

Artifact files are private files under `artifacts/` in the state directory, named by digest and shared across tasks.
- **Quota:** 10 GiB per host by default, set with `daemon --artifact-quota BYTES`. Stored files plus the declared sizes of pending fetches count toward it. A receiver admits a manifest when stored plus pending bytes plus its digests not already stored or pending fit; otherwise it returns 507 (`insufficient_storage`). An upload over quota also returns 507, and a fetch waits and retries while stored bytes plus its size would exceed the quota.
- **Uploads** not yet referenced by a task are kept for 24 hours.
- **Retention:** a task keeps its artifacts until 7 days after the `updated_at` of its final status record, on either side; pending fetches of a final task are released with it. An outbound task never accepted keeps them until 7 days after its deadline. A file is deleted once nothing keeps it.
- `artifact prune` (`POST /v1/artifacts/prune`) releases artifacts of every final task now, including pending result fetches, and of uploads, and deletes the files nothing else keeps, each with an `artifact.pruned` activity (subject `<sha256>`). It returns `{files_deleted, bytes_freed}`.
- `artifact list` (`GET /v1/artifacts`) returns `{quota, stored_bytes, pending_bytes, files}`, each file `{sha256, size, created_at, upload_until, tasks}`.

## Submitter

| CLI after `--state DIR` | Local API | Behavior |
| --- | --- | --- |
| (used by `task submit --artifact PATH`) | `POST /v1/artifacts?name=N&media_type=M` with the raw file | Stores the upload and returns its manifest entry. A file over 100 MiB returns 413 (`too_large`) once 104,857,601 bytes have been read; a host may close the connection without reading the rest, so clients must tolerate a broken pipe before reading the status. |
| `task submit ... [--artifact PATH ...] [--artifact-type TYPE ...]` | `POST /v1/tasks` with `artifacts` | The CLI uploads each file, named after its base name, with the `--artifact-type` at the same position (default `application/octet-stream`), then submits the manifest. Every entry must name a stored file of that size and digest, or the request returns 400. |
| `task artifact --peer HOST ID SHA256 --out PATH` | `GET /v1/tasks/{peer}/{id}/artifacts/{sha256}` | Writes an input or fetched result to a new file at `PATH`, created exclusively with mode 0600, and prints `{path, sha256, size}`. A result not yet fetched returns 409. |

The local record gains `artifacts`, a list of `{direction, name, size, sha256, media_type, state}`, where `direction` is `input` or `result` and `state` is `stored`, `pending`, or `pruned`.

## Agents

The adapter reads and writes files under the agent's own permissions; the daemon never opens agent-supplied paths.

| Adapter API | Behavior |
| --- | --- |
| `POST /adapter/v1/artifacts?name=N&media_type=M` with the raw file | Uploads, as the local API does. |
| `POST /adapter/v1/delegations` with optional `artifacts` | Submits input artifacts, as `POST /v1/tasks` does. |
| `GET /adapter/v1/delegations/{task_id}/artifacts/{sha256}` | An input or fetched result of a task this credential submitted. |
| `POST /adapter/v1/tasks/{task_id}/complete` with optional `artifacts` | Attaches result artifacts, each a stored upload. |
| `GET /adapter/v1/tasks/{task_id}/artifacts/{sha256}` | An input or result of a task this session claimed. |

The handoff's `task` includes the input manifest, and `task_update` events for a final event include the result manifest. MCP:
- `delegate_task` and `task_complete` accept `artifacts`, a list of file paths that the adapter uploads first;
- the `task` event and final `task_update` events carry the manifest in `meta.artifacts`;
- `artifact_save {task_id, sha256, path}` writes an artifact of a task the agent submitted or claimed to a new file at `path`, never overwriting one.

## Persistence

Database version 10 adds:

```sql
CREATE TABLE artifact_files (sha256 TEXT PRIMARY KEY, record TEXT NOT NULL);
CREATE TABLE task_artifacts (side TEXT NOT NULL, peer TEXT NOT NULL, task_id TEXT NOT NULL, direction TEXT NOT NULL, sha256 TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(side, peer, task_id, direction, sha256));
PRAGMA user_version = 10;
```

`side` is `sent` or `received`. Records are JSON, as elsewhere; files are written to a temporary name and renamed after verification, so a crash never leaves a partial file under its digest. Older binaries reject version 10. New activity kinds are `task.artifact_fetched` and `artifact.pruned`.

## Task deadline default

When a submission cites a policy, the default deadline is 1 hour or the cited policy's `valid_until`, whichever is sooner. A grant's expiry is known only to the receiver, so under a grant that expires within the hour `--deadline` remains required.

## Verification

`conformance/artifacts.py` runs every Go/Rust pairing, with deterministic adapter consumers and no model calls. It covers:
- artifacts refused under a bound of 0, by grant and by policy, in both directions;
- inputs fetched, verified, and handed off only once stored; results fetched by the submitter;
- the combined bound, per-artifact size limit, and manifest validation;
- a corrupted served file, rejected by digest and the task kept queued;
- non-party fetches returning 404, and fetches after revocation succeeding;
- quota refusal with a small `--artifact-quota`, and `artifact prune`;
- MCP `delegate_task`, `task_complete`, and `artifact_save` with files on both sides;
- restart during pending fetches, resuming them;
- a policy with `max_artifact_bytes` signed and verified across implementations, and the capped default deadline;
- migration from version 9 to version 10.
