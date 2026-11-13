# Peerbox contract

A **peerbox** is a Git repository that its **home host** serves to people in a network it
belongs to, for fetching, contributing, and running checks on exact commits. The design is
in the [peerbox proposal](peerbox-proposal.md), and its decisions are PBX-1 to PBX-6 in the
[decision log](decision-log.md#pbx-1-to-pbx-6-peerboxes-2026-11-13). This contract extends
the [task contract](task-contract.md), the [artifact contract](artifact-contract.md) and the
[runtime task contract](runtime-task-contract.md); what it does not change is as specified
there. Membership, policies and their signing are those of the
[coordinator-free spec](decentralized-spec.md) and its
[wire appendix](decentralized-wire-formats.md); peerboxes work only in coordinator-free
networks. The Rust host at the repository root is the only host (DEC-OWN5).

Not in this contract: strangers admitted by link, several branches or path filtering in one
peerbox, merging, replicas of the home host, PeerFS-backed peerboxes, signed run receipts,
agent tools, and grants for peerbox operations.

Both hosts need `git` 2.34 or later on `PATH` for peerbox commands; without it they fail
with `git_missing`. Every Git command a host runs for a peerbox runs with
`core.hooksPath` set to an empty directory the host owns, and with no configuration taken
from received data.

## Peerboxes and contributions

A **peerbox record** is kept on its home host:

| Field | Rules |
| --- | --- |
| `peerbox_id` | `pbx_` followed by 16 random bytes in lowercase hex. |
| `network_id` | The coordinator-free network it is served in. |
| `title` | 1 to 200 bytes of UTF-8. |
| `repository` | An absolute path to a local Git repository. Never sent to peers. |
| `branch` | The **protected branch**: a branch name of that repository, as for `branch` below. |
| `created_at` | RFC3339. |

A **commit ID** is the lowercase hex object name in the repository's object format: 40 digits
for SHA-1, 64 for SHA-256. Any other length is 400 `invalid`.

A **contribution** is a commit a peer submitted, with this record:

| Field | Meaning |
| --- | --- |
| `contribution_id` | `pbc_` followed by 16 random bytes in lowercase hex. |
| `peerbox_id` | Its peerbox. |
| `contributor` | `{person_id, host_id, agent_id, session_id}`: the submitting person and host, and the task's `origin` agent and session, each null when absent. |
| `branch` | The contributor's branch name. |
| `base` | The commit the contribution builds on. |
| `head` | The submitted commit. |
| `bundle_sha256` | The submitted bundle's digest. |
| `submitted_at` | RFC3339. |
| `state` | `pending`, `accepted`, `rejected` or `superseded`. |
| `decision` | Null, or `{decision, reason, decided_at, decided_by, old_head, new_head}`: `accepted` or `rejected`, the owner's reason (0 to 4,096 bytes), the time, the deciding person, and the protected head before and after (equal for a rejection). |
| `runs` | The peerbox runs on this contribution's head, oldest first: `{task_id, state, exit_code, created_at}`. |

The home host stores each contribution's head under
`refs/peerbox/PEERBOX_ID/members/PERSON_ID/BRANCH`, its **member ref**. Peer requests never
write the protected branch or another person's member ref.

## Requests

`POST /peer/v1/tasks` accepts **peerbox tasks**. A peerbox task has exactly `task_id`,
`executor`, `peerbox`, `deadline`, `input`, `policy`, optional `origin`, and optional
`artifacts`.
- `executor` is `"peerbox"`. A runtime task's `"runtime"` and agent tasks are unchanged.
- A peerbox task has no `target_agent_id`, `grant_id`, `run`, `self` or `delegation`; any of
  them, or any other field not listed here, is 400 naming it.
- `policy` cites the home host owner's policy, as for runtime tasks.
- The whole request is part of idempotency by `(sender, task_id)`.

`peerbox` is an object whose `op` selects the operation:

| `op` | Other fields | Artifacts | Result |
| --- | --- | --- | --- |
| `list` | none | none | `{"peerboxes": [...]}` |
| `fetch` | `peerbox_id`; optional `have`, 0 to 32 distinct commit IDs | none | `{"head", "bundle_sha256", "size"}` and the result artifact `peerbox.bundle` |
| `submit` | `peerbox_id`, `base`, `branch`, `bundle` (a digest) | the bundle | the contribution record |
| `status` | `peerbox_id`; optional `contribution_id` | none | `{"contributions": [...]}` |
| `run` | `peerbox_id`, `commit`, `run` | none | the run result (runtime task contract) |
| `withdraw` | `peerbox_id`, `contribution_id` | none | the contribution record |

Any other `op`, a missing or extra field, or a field out of range is 400 `invalid` naming
it. `branch` is 1 to 64 bytes of `[A-Za-z0-9._-]`, not starting with `-` or `.`, not ending
with `.lock` or `/`, without `..`, and accepted by `git check-ref-format --branch`. `bundle`
must appear in the request's `artifacts` with media type `application/x-git-bundle`. `run`
is a runtime task's `run` without `workspace`, which is 400.

**Results.** `list`, `fetch`, `submit`, `status` and `withdraw` end `succeeded` with the
result as their final `output`, a JSON object written as text, or `failed` with
`{"error": CODE, "message": TEXT}`. A `run` follows the runtime task contract from its
checks on (Runs, below). An entry of `peerboxes` is `{peerbox_id, title, branch, head,
actions}`, where `actions` are the caller's.

## Authorization

A peerbox task is authorized by a **peerbox rule** in the home host owner's policy. Network
membership, an agent rule, a capability rule, a runtime rule, a grant or a conversation
authorizes no peerbox operation, and a peerbox rule authorizes nothing else.

### Peerbox rules

A peerbox rule is `{host, peerbox, principals, actions, max_bundle_bytes, max_pending,
allow_disconnected}`. A host honours only rules naming itself.

| Field | Range |
| --- | --- |
| `host` | The home host's ID. |
| `peerbox` | A `peerbox_id`. |
| `principals` | 1 to 64, as for rules. |
| `actions` | 1 to 3 of `peerbox.read`, `peerbox.submit`, `peerbox.run`, distinct, in that order. `peerbox.submit` and `peerbox.run` each need `peerbox.read` in the same rule. |
| `max_bundle_bytes` | 1 to 104,857,600: bounds each fetched and each submitted bundle. |
| `max_pending` | 0 to 64: pending contributions per contributing person. 0 when `peerbox.submit` is absent, at least 1 when present. |
| `allow_disconnected` | As for runtime rules. |

At most 64 peerbox rules per policy, and at most one per `(host, peerbox)`; two are 400.

**Policy body.** The `peerspan-policy-v2` body gains `peerbox_rules`, after `runtime_rules`,
omitted when empty, so a policy without peerbox rules has the same body as before. Each rule
is an object with exactly the keys above, in that order. For example:

```json
"peerbox_rules":[{"host":"host_aaaa…","peerbox":"pbx_0f1e…","principals":["person:person_7245…"],"actions":["peerbox.read","peerbox.submit","peerbox.run"],"max_bundle_bytes":52428800,"max_pending":4,"allow_disconnected":false}]
```

- **Reading.** As for `runtime_rules`: a host refuses the statement as `invalid` when
  `peerbox_rules` is present but empty, a rule has a missing, unknown or duplicate key, or a
  value is out of range or breaks a rule above.
- **Renewal and edits.** As for `runtime_rules`, with each `(host, peerbox)` rule one unit:
  renewal and edits that do not touch it copy it, and when unsettled edits are re-applied a
  withdrawal wins. The wire appendix's dropped-addition keys gain `peerbox rule PEERBOX on
  HOST` and `principal PRINCIPAL in peerbox rule PEERBOX on HOST`.
- **Compatibility.** Hosts built before this contract, every Go host included, refuse a
  policy whose body has `peerbox_rules`, as for `runtime_rules` (RUN-5). An owner adds one only
  once every host in the network runs software that implements this contract; `peerbox share`
  says so before it signs.

### Checks

At submission the home host checks, in order:
1. `peerbox_id` names a peerbox record on this host in a network the sender shares, and the
   sender matches a rule for it with `peerbox.read`, as runtime rules are matched (cited
   policy, deadline within its `valid_until`, membership unless `allow_disconnected`).
   Failure, or an unknown ID, is 404 `unknown`, so a caller cannot learn which peerboxes
   exist. `list` needs no `peerbox_id` and returns only the peerboxes the sender may read.
2. The operation's action: `submit` and `withdraw` need `peerbox.submit`, `run` needs
   `peerbox.run`; `fetch` and `status` need only `peerbox.read`. Failure is 403.
3. For `submit`, the manifest's bundle size at most `max_bundle_bytes`: 403 otherwise.
4. For `run`, everything the runtime task contract checks (the local switch, a runtime rule
   matching the sender, its bounds), with the request's `run` in place of a runtime task's.
   A peerbox rule with `peerbox.run` and no runtime rule for the sender authorizes no run.

The task is then persisted `queued`. The home host checks 1 and 2 again before it serves a
bundle, before it stores a contribution, and before a run starts; a final failure then ends
the task `rejected` with the reason, and a recoverable one leaves it queued.

### Withdrawal

The owner withdraws by signing a policy version without the rule or without an action. From
that version on, new and queued operations fail the checks. In addition, when the home host
stores a policy version under which the sender of a started peerbox run no longer matches
`peerbox.run`, it cancels that run as an owner's cancel would (PBX-4); the final event's
`message` is `access withdrawn`. A policy only lapsing, a ban or a runtime rule's withdrawal
stop queued starts and not a started run, as for runtime tasks.

Withdrawal cannot recall a bundle already delivered. Stored contributions stay for review,
and their contributor keeps `status` on them.

## Operations

### Fetch

The home host reads the protected branch's head and creates a bundle (version 2, or 3 for a
SHA-256 repository) with the single ref `refs/heads/BRANCH` at that head. With `have`, it
keeps the `have` commits that are reachable from that head and leaves out every commit
reachable from them; it ignores every other ID, so the bundle reveals nothing about history
outside the protected branch. A bundle larger than `max_bundle_bytes` or the artifact
file limit fails the task with `too_large` and its size in `message` (PBX-3); with no `have`
the caller cannot fetch that peerbox.

The bundle is the task's result artifact `peerbox.bundle`, media type
`application/x-git-bundle`, transferred and kept as result artifacts are. The fetching host
verifies its digest, verifies it with `git bundle verify`, and fetches it into a quarantine
repository with `transfer.fsckObjects=true` before it changes any local ref; an interrupted
or failed fetch changes none.

### Submit

The bundle's single ref must be `refs/heads/BRANCH` and its prerequisites reachable from the
protected head. Before storing, in order, the home host:
1. checks the sender's pending contributions against `max_pending` (`pending_limit`);
2. verifies the bundle and fetches it into a quarantine repository with
   `transfer.fsckObjects=true` (`bundle_invalid`, with Git's message);
3. checks that `base` is reachable from the protected head (`base_unknown`) and an ancestor of
   the bundle's head (`base_not_ancestor`);
4. moves the objects into the repository and sets the member ref.

A failed step stores nothing. A submission whose member ref already holds a pending
contribution replaces it and marks the earlier one `superseded`.

### Status and withdraw

`status` returns the sender's own contributions to that peerbox, newest first, at most 100,
or the one named; another person's contribution is 404 `unknown`. `withdraw` marks the
sender's pending contribution `superseded` and deletes its member ref; a decided one is 409
`decided`.

### Runs

`commit` must be the protected head or the head of a contribution the sender may read
(their own, or one accepted): otherwise the task fails with `commit_unknown`. The home host
builds the workspace archive itself from that commit's tree with `git archive`, never from
bytes a peer sent; the archive has no `.git`, is subject to the runtime rule's
`max_artifact_bytes`, and is not an input artifact. The run then follows the runtime task
contract: queueing, the recheck at start, output events, the run result, `results`, result
artifacts, cancellation and restarts. A run never changes a ref. Its outcome is recorded in
the contribution's `runs`.

## Review

Review is the home host owner's, through the local API and CLI only. Accepting a
contribution:
1. requires it `pending`;
2. requires the protected head to be an ancestor of the contribution head (409
   `not_fast_forward`: the contributor rebases and submits again);
3. when the protected branch is checked out in a worktree, requires that worktree clean (409
   `dirty_worktree`) and fast-forwards it;
4. updates the protected branch from the head read in 2 to the contribution head with a
   compare-and-swap (409 `head_moved` when it changed).

Peerspan never merges. Rejecting records the reason and changes no ref. Both record the
decision durably; the contributor reads it with `status`.

## CLI and local API

| CLI after `--state DIR` | Behavior |
| --- | --- |
| `peerbox create --repository PATH --branch NAME [--title TEXT] [--network ID] [--yes]` | Shows what a read discloses (the branch and head, the commits reachable from it, their distinct author and committer names and addresses, and the bundle size) and asks to confirm, defaulting to no; `--yes` skips the question. Creates the record and prints its ID. |
| `peerbox share PEERBOX --for PRINCIPAL ... [--action read\|submit\|run ...] [--max-bundle-bytes N] [--max-pending N] [--allow-disconnected] [--person-key PATH]` | Adds or replaces the peerbox's rule and signs the next policy version as `runtime enable` does, saying first that hosts on software without peerbox rules will stop accepting this person's policy. `--action` defaults to `read`; defaults are 104,857,600 bytes and 4 pending. |
| `peerbox unshare PEERBOX [--person-key PATH]` | Removes the rule, signing as above. |
| `peerbox delete PEERBOX [--person-key PATH]` | Removes the rule, the record and its member refs; contribution records stay. |
| `peerbox show [PEERBOX] [--json]` | Records, rules and pending counts. |
| `peerbox review [PEERBOX] [--json]` | Pending contributions with contributor, base, head, `git diff --stat` and runs. |
| `peerbox review CONTRIBUTION (--accept \| --reject) [--reason TEXT]` | Records the decision (Review); exits 1 with the code on a 409. |
| `peerbox list --peer HOST [--json]` | Submits `list` and prints the peerboxes. |
| `peerbox fetch --peer HOST PEERBOX --repository DIR` | Submits `fetch` with `have` from DIR's refs for that peerbox, verifies as above and sets `refs/peerbox/PEERBOX/BRANCH` in DIR, initializing DIR when absent. |
| `peerbox submit --peer HOST PEERBOX --repository DIR --branch NAME [--base COMMIT]` | Bundles NAME in DIR, excluding history reachable from `--base` (default: the merge base of NAME and the fetched ref), uploads it and submits. |
| `peerbox status --peer HOST PEERBOX [CONTRIBUTION] [--json]` | Submits `status` and prints it. |
| `peerbox withdraw --peer HOST PEERBOX CONTRIBUTION` | Submits `withdraw`. |
| `peerbox run --peer HOST PEERBOX --commit COMMIT [runtime flags] -- COMMAND...` | Submits `run`, with `task run`'s flags except `--workspace` and `--peerfs-workspace`, and follows it as `task run` does, with its exit codes. |

Peer-side commands that submit a task wait for its final event and exit 0 when it succeeded,
1 when it failed or was rejected, printing the code; `--detach` prints the local record
instead. The local API is `GET|POST /v1/peerboxes`, `GET|DELETE /v1/peerboxes/{id}`,
`PUT|DELETE /v1/peerboxes/{id}/rule`, `GET /v1/peerboxes/{id}/contributions` and
`POST /v1/peerboxes/contributions/{id}/decision`; peer-side operations use `POST /v1/tasks`
with `executor: "peerbox"`.

## Persistence

The host schema version increments by one: the next free version on `main` when the
implementing PR merges. New tables hold peerbox records and contributions with their
decisions; received and outbound task records of peerbox tasks gain `executor` and `peerbox`
as runtime tasks gain `run`; a peerbox run's received record also has the runtime fields.
Older binaries reject the new version. New activity kinds are `peerbox.created`,
`peerbox.shared`, `peerbox.fetched`, `peerbox.submitted`, `peerbox.decided` and
`peerbox.deleted`.

## Verification

Two suites are written from this contract by a separate author who does not read `src/`,
`tests/` or `integrations/` (DEC-OWN6, DEC-OWN9). They drive two or three real Rust hosts
with `conformance/slim/harness.py`, Git fixture repositories and its test clock, without KVM
and without model calls, each under 2 minutes: `peerbox` in the per-push tier if it fits the
budget (DEC-OWN14), and `peerbox_runs`, with the fake runtime, in the second tier.

`peerbox` covers:
- the policy body: peerbox rules admitted by the owner's other host and another person's
  host; an empty `peerbox_rules`, an unknown key, two rules for one peerbox, `submit` without
  `read`, and `max_pending` 0 with `submit` refused; rules kept across a renewal;
- authorization: an unknown peerbox and one the sender may not read, both 404 `unknown`;
  `list` showing only readable peerboxes; `submit` without `peerbox.submit` 403; a lapsed
  sender with and without `allow_disconnected`; a grant or `target_agent_id` 400;
- create: the disclosure summary, refusal by default, and `--yes`;
- fetch: the bundle verifies and holds exactly the protected head; `have` shortens it; a
  `have` outside the protected branch changes nothing; `too_large`;
- submit: a valid contribution stored under the member ref; `pending_limit`; branch names
  refused; `base_unknown` and `base_not_ancestor`; hostile bundles (a mutated byte, a ref
  outside `refs/heads/`, an option-like ref name, a tree with `.git` paths or hooks) storing
  nothing; superseding; a peer unable to write the protected branch or another member's ref;
- review: accept fast-forwarding, `not_fast_forward`, `head_moved`, `dirty_worktree`, reject
  with a reason, and the decision visible through `status`;
- withdrawal: new fetches and submissions refused, stored contributions and `status` kept;
- restarts of both hosts during a fetch and a submit, and records kept;
- opening a database of the previous schema version.

`peerbox_runs` covers: a run needing both rules and the switch; bounds from the runtime rule;
the workspace equal to the commit's tree with no `.git`; `commit_unknown`; a run changing no
ref; withdrawal cancelling a started run with `access withdrawn`, while a runtime rule's
withdrawal does not; the run recorded in the contribution's `runs`.

A live two-owner run on two machines with `peerspan-runtime` and real agents records the
experience separately (proposal, plan step 8).
