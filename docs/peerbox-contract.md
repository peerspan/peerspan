# Peerbox contract

A **peerbox** is a Git repository that its **home host** serves to people in a network it
belongs to, for fetching, contributing, and running checks on exact commits. The design is
in the [peerbox proposal](peerbox-proposal.md), and its decisions are PBX-1 to PBX-8 in the
[decision log](decision-log.md#pbx-1-to-pbx-8-peerboxes-2026-11-13); gates are in the
[gate proposal](peerbox-gate-proposal.md), PBX-9 to PBX-15. This contract extends
the [task contract](task-contract.md), the [artifact contract](artifact-contract.md) and the
[runtime task contract](runtime-task-contract.md); what it does not change is as specified
there. Membership, policies and their signing are those of the
[coordinator-free spec](decentralized-spec.md) and its
[wire appendix](decentralized-wire-formats.md); peerboxes work only in coordinator-free
networks. The Rust host at the repository root is the only host (DEC-OWN5).

Not in this contract: a membership class other than full member for invited people, several branches or path filtering in one
peerbox, merging, replicas of the home host, PeerFS-backed peerboxes, signed run receipts,
agent tools for review or invitations, and grants for peerbox operations.

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
| `decision` | Null, or `{decision, reason, decided_at, decided_by, old_head, new_head, gate}`: `accepted` or `rejected`, the owner's reason (0 to 4,096 bytes), the time, the deciding person's `person_id` or `"gate"`, the protected head before and after (equal for a rejection), and for a gate's decision its public result (Gates), else null. |
| `runs` | The peerbox runs on this contribution's head, oldest first: `{task_id, state, exit_code, created_at}`. Every result that returns a record (`submit`, `status`, `withdraw`) keeps the latest 8 and adds `runs_total`, so one record always fits the task output. |

The home host stores each contribution's head under
`refs/peerbox/PEERBOX_ID/members/PERSON_ID/BRANCH`, its **member ref**, which always names
the latest submission on that branch, and also under
`refs/peerbox/PEERBOX_ID/contributions/CONTRIBUTION_ID`, its **contribution ref**, which keeps
that exact commit reachable whatever later happens to the member ref. A contribution ref is
kept while the contribution is `pending` or `accepted`, and for 30 days after it becomes
`rejected` or `superseded`; then the home host deletes it, the record stays, and the commit
can no longer be run. Peer requests never write the protected branch or any `refs/peerbox/`
ref directly.

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
| `list` | optional `after` (a peerbox ID) | none | `{"peerboxes": [...], "next"}` |
| `fetch` | `peerbox_id`; optional `have`, 0 to 32 distinct commit IDs | none | `{"head", "bundle_sha256", "size"}` and the result artifact `peerbox.bundle`, or no artifact when the caller has the head |
| `submit` | `peerbox_id`, `base`, `branch`, `bundle` (a digest) | the bundle | the contribution record |
| `status` | `peerbox_id`; optional `contribution_id` or `before` (a contribution ID) | none | `{"contributions": [...], "next"}` |
| `run` | `peerbox_id`, `commit`, `run` | none | the run result (runtime task contract) |
| `withdraw` | `peerbox_id`, `contribution_id` | none | the contribution record |

Any other `op`, a missing or extra field, or a field out of range is 400 `invalid` naming
it. `branch` is 1 to 64 bytes of `[A-Za-z0-9._-]`, not starting with `-` or `.`, not ending
with `.lock` or `/`, without `..`, and accepted by `git check-ref-format --branch`. `bundle`
must appear in the request's `artifacts` with media type `application/x-git-bundle`. `run`
is a runtime task's `run` without `workspace`, which is 400.

**Results.** `list`, `fetch`, `submit`, `status` and `withdraw` end `succeeded` with the
result as their final `output`, a JSON object written as text, or `failed` with
`{"error": CODE, "message": TEXT}`; a `run` that fails before it starts ends the same way.
HTTP statuses (400, 403, 404, 503) come only from the checks at submission (Checks); every
error code named in Operations is such a final `failed` outcome. A `run` follows the runtime task contract from its
checks on (Runs, below). An entry of `peerboxes` is `{peerbox_id, title, branch, head,
actions, gate}`, where `actions` are the caller's and `gate` is the gate's public summary or
null (Gates). Entries are in ascending `peerbox_id` order,
after `after` when given; the home host returns as many whole entries as fit the task
contract's 65,536-byte output, and `next` is the last returned ID when more remain, else
null.

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

At most 256 peerbox rules per policy. One peerbox may have several rules, so different people
can hold different actions and bounds, but a principal appears in at most one rule per
`(host, peerbox)`; a repeat is 400. A sender matching several rules of one peerbox (for
example `person:` and `network`) holds the union of their actions, and for an action each
bound is the largest among the matching rules that grant it.

**Policy body.** The `peerspan-policy-v2` body gains `peerbox_rules`, immediately after
`runtime_rules`, or where `runtime_rules` would be when that is omitted; it is omitted when
empty, so a policy without peerbox rules has the same body as before. Each rule
is an object with exactly the keys above, in that order. For example:

```json
"peerbox_rules":[{"host":"host_aaaa…","peerbox":"pbx_0f1e…","principals":["person:person_7245…"],"actions":["peerbox.read","peerbox.submit","peerbox.run"],"max_bundle_bytes":52428800,"max_pending":4,"allow_disconnected":false}]
```

- **Reading.** As for `runtime_rules`: a host refuses the statement as `invalid` when
  `peerbox_rules` is present but empty, a rule has a missing, unknown or duplicate key, or a
  value is out of range or breaks a rule above.
- **Renewal and edits.** As for `runtime_rules`, with each `(host, peerbox, principal)` one
  unit, its actions and bounds included: renewal and edits that do not touch it copy it, and
  when unsettled edits are re-applied a withdrawal wins. The wire appendix's dropped-addition
  keys gain `peerbox PEERBOX on HOST for PRINCIPAL`.
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
   The one exception is `status`: a sender with no current rule who submitted contributions
   to that peerbox passes this check for `status` only, and sees only those contributions
   (Withdrawal); a sender with neither is 404 `unknown`.
2. The operation's action: `submit` and `withdraw` need `peerbox.submit`, `run` needs
   `peerbox.run`; `fetch` needs `peerbox.read`, and `status` needs `peerbox.read` or the
   exception in 1. Failure is 403.
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

### Invitations for new participants

A person outside the network joins it and gets a peerbox's access through one **peerbox
invite** (PBX-7, PBX-8). It is a network invite with the peerbox attached: accepting it makes
them an ordinary member through the existing join flow (spec section 8.1), with the
administrator's admission unchanged, and the home host then signs their peerbox rule. A
person already in the network gets access through `peerbox share` instead.

1. **Create.** On the home host, the peerbox's owner runs `peerbox invite PEERBOX LABEL
   [--action read|submit|run ...] [--max-bundle-bytes N] [--max-pending N] [--expires-in D |
   --expires-at T]`. It creates a network invite as `peerspan invite LABEL` does, with the
   same expiry rules, in the peerbox's network, and stores a **pending share** keyed by that
   invite's invitation ID: the peerbox, the actions and the bounds, which the owner reviews
   before it prints. It prints a `psb1-` code: `psb1-` followed by unpadded Base64URL of the
   JSON object `{"invite": PSI2_CODE, "peerbox_id", "title", "home_host_id", "actions"}`, with
   `actions` the full action names (`peerbox.read`, ...) in rule order.
   Everything outside `invite` is a hint for the joiner's display; only the signed rule
   grants access.
2. **Join.** On the new machine, `peerbox join [--repository DIR] [--as LABEL]
   [--person-key-file PATH]` reads the code from a
   hidden prompt or `--invite-stdin`, never from a command argument, shows the peerbox's
   title, home host and offered actions beside the network invite's review, and runs `join`
   with the inner `psi2-` code. `peerspan join` and `up --join` also accept a `psb1-` code
   and behave the same. A machine already in that network refuses the code and says to ask
   the owner for `peerbox share`.
3. **Admission.** As for any join: the joiner approves their machine, a network
   administrator admits the request (the owner, when they are one), and the joiner commits.
   An owner who is not an administrator sends the admin the request as today.
4. **Share.** When the home host admits the admission of the person whose request came
   through that invitation ID, it grants `person:` that person the pending share's actions and
   bounds exactly as `peerbox share --for` would (CLI, below), leaving every other
   principal's rule as it is, and signs the next policy version as `peerbox share` does. When the network's provider for the owner needs the owner's interaction (an SSH
   person key, for example), status shows `peerbox_share_waiting` with the command
   `peerbox share --pending INVITATION_ID` instead, and the pending share is kept, across
   restarts, until that command signs it. The pending share is deleted only once a policy
   version granting it is signed.
5. **Fetch.** The joiner's `peerbox join` keeps running after the commit: it submits `list`
   to the home host until the peerbox appears or 10 minutes pass, then prints it, and with
   `--repository` fetches it there.

A pending share also ends with its invite's expiry when no request came through it, or when
the request is refused or abandoned, and at most 7 days after the invite was created, even
while it waits for the owner. `peerbox invite --list` and `peerbox
invite --cancel INVITATION_ID` show and delete pending shares; cancelling one leaves the
network invite itself in place, since invite codes cannot be revoked (spec section 5), so
the person can still join the network but receives no peerbox access. Removing the person
from the network stays `person remove`; `peerbox unshare` ends only their peerbox access.

## Operations

### Fetch

The home host reads the protected branch's head and creates a bundle (version 2, or 3 for a
SHA-256 repository) with the single ref `refs/heads/BRANCH` at that head. With `have`, it
keeps the `have` commits that are reachable from that head and leaves out every commit
reachable from them; it ignores every other ID, so the bundle reveals nothing about history
outside the protected branch. A bundle larger than `max_bundle_bytes` or the artifact
file limit fails the task with `too_large` and its size in `message` (PBX-3); with no `have`
the caller cannot fetch that peerbox.

When `have` contains the head, nothing is new: the task succeeds with `bundle_sha256` null
and `size` 0 and attaches no artifact, and the fetching host changes no ref.

The bundle is the task's result artifact `peerbox.bundle`, media type
`application/x-git-bundle`, transferred and kept as result artifacts are. The fetching host
verifies its digest, verifies it with `git bundle verify`, and fetches it into a quarantine
repository with `transfer.fsckObjects=true` before it changes any local ref; an interrupted
or failed fetch changes none.

### Submit

The bundle's single ref must be `refs/heads/BRANCH` and its prerequisites reachable from the
protected head. Before storing, in order, the home host:
1. checks that the sender's pending contributions after this submission, not counting a
   pending one it replaces at the same member ref, number at most `max_pending`
   (`pending_limit`);
2. verifies the bundle and fetches it into a quarantine repository with
   `transfer.fsckObjects=true` and Git's `hasDotgit` and `gitmodules*` checks raised from
   warnings to errors, and refuses any tree entry, at any depth, named `.git` as Git's
   `hasDotgit` check defines it (any letter case, and the HFS+ and NTFS spellings), whatever
   its type (`bundle_invalid`, with Git's message);
3. checks that `base` is reachable from the protected head (`base_unknown`) and an ancestor of
   the bundle's head (`base_not_ancestor`);
4. moves the objects into the repository and sets the member ref.

A failed step stores nothing. A submission whose member ref already holds a pending
contribution replaces it and marks the earlier one `superseded`.

### Status and withdraw

`status` returns the sender's own contributions to that peerbox, or the one named, ordered
newest first by `(submitted_at, contribution_id)`, both descending, a total order; another person's contribution, or an unknown one, ends the task `failed` with `unknown`. The final `output` must fit the task
contract's 65,536 bytes, so the home host returns as many whole records as fit, at most 100,
with each record's `runs` cut to its latest 8 and `runs_total` added; `next` is the ID of the
last record returned when older ones remain, else null, and a request with `before` returns
the contributions after that one in the same order, so contributions sharing a
`submitted_at` are neither skipped nor repeated. One record always fits: its variable fields
are bounded (a 4,096-byte reason, 8 runs). `withdraw` marks the
sender's pending contribution `superseded` and deletes its member ref, keeping its
contribution ref as above; a decided one ends the task `failed` with `decided`.

### Runs

`commit` must be the protected head or the head of a contribution the sender may read
(their own, or one accepted) whose contribution ref still exists: otherwise the task ends
`failed` with `commit_unknown` before any run, with no run result. The home host
builds the workspace archive itself from that commit's tree, never from bytes a peer sent,
and never with `git archive`, whose `export-ignore` and `export-subst` attributes would let
a commit's own `.gitattributes` drop or rewrite tracked files. It reads the tree's entries
(`git ls-tree -r -z`) and their blobs (`git cat-file`): each blob as a regular file, mode
0755 when executable and 0644 otherwise, each symbolic link as a link, and each submodule
entry as an empty directory. No attribute, filter or configuration from the commit applies.
The archive is the commit's tree byte for byte, has no `.git`, and is not an input artifact;
when it is larger than the runtime rule's `max_artifact_bytes`, the task ends `failed` with
`too_large` before any run, with no run result. The run then follows the runtime task
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
| `peerbox share PEERBOX --for PRINCIPAL ... [--action read\|submit\|run ...] [--max-bundle-bytes N] [--max-pending N] [--allow-disconnected] [--person-key PATH]` | Gives each `--for` principal exactly these actions and bounds on the peerbox: it removes the principal from any other rule of that peerbox, then adds it to a rule with the same actions and bounds or to a new rule, leaving other principals unchanged; then it signs the next policy version as `runtime enable` does, saying first that hosts on software without peerbox rules will stop accepting this person's policy. `--action` defaults to `read`; `--max-bundle-bytes` defaults to 104,857,600; `--max-pending` defaults to 4 with `submit` and is 0 without it, where any other value is refused. |
| `peerbox unshare PEERBOX [--for PRINCIPAL ...] [--person-key PATH]` | Removes those principals from the peerbox's rules, or every rule of the peerbox without `--for`, dropping rules left with no principal; signs as above. |
| `peerbox invite PEERBOX LABEL [--action ...] [--max-bundle-bytes N] [--max-pending N] [--expires-in D \| --expires-at T]` | Creates a network invite and a pending share and prints the `psb1-` code (Invitations for new participants). |
| `peerbox invite --list`, `peerbox invite --cancel INVITATION_ID` | Shows or deletes pending shares. |
| `peerbox share --pending INVITATION_ID [--person-key PATH]` | Signs the rule of a pending share whose person was admitted, when automatic signing needed the owner. |
| `peerbox delete PEERBOX [--person-key PATH]` | Removes its rules, the record, and its member and contribution refs; contribution records stay. |
| `peerbox show [PEERBOX] [--json]` | Records, rules and pending counts. |
| `peerbox review [PEERBOX] [--json]` | Pending contributions with contributor, base, head, `git diff --stat` and runs. |
| `peerbox review CONTRIBUTION (--accept \| --reject) [--reason TEXT]` | Records the decision (Review); exits 1 with the code on a 409. |
| `peerbox join [--repository DIR] [--invite-stdin]` | Joins the network from a `psb1-` code, then waits for the peerbox and fetches it (Invitations for new participants). |
| `peerbox list --peer HOST [--json]` | Submits `list`, following `next` until null, and prints the peerboxes. |
| `peerbox fetch --peer HOST PEERBOX --repository DIR` | Submits `fetch` with `have` from DIR's refs for that peerbox, verifies as above and sets `refs/peerbox/PEERBOX/BRANCH` in DIR, initializing DIR when absent. |
| `peerbox submit --peer HOST PEERBOX --repository DIR --branch NAME [--base COMMIT]` | Bundles NAME in DIR, excluding history reachable from `--base` (default: the merge base of NAME and the fetched ref), uploads it and submits. |
| `peerbox status --peer HOST PEERBOX [CONTRIBUTION] [--before CONTRIBUTION] [--limit N] [--json]` | Submits `status` and prints it. Without a contribution it follows `next` until null or until `--limit` records (default 100) have been printed, newest first; `--before` starts below that contribution. |
| `peerbox withdraw --peer HOST PEERBOX CONTRIBUTION` | Submits `withdraw`. |
| `peerbox run --peer HOST PEERBOX --commit COMMIT [runtime flags] -- COMMAND...` | Submits `run`, with `task run`'s flags except `--workspace` and `--peerfs-workspace`, and follows it as `task run` does, with its exit codes. |

Peer-side commands that submit a task wait for its final event and exit 0 when it succeeded,
1 when it failed or was rejected, printing the code; `--detach` prints the local record
instead. With `--json`, a peer-side command prints the operation's result object (for
`list` and `status`, the pages merged into one `peerboxes` or `contributions` array);
`create` prints the peerbox record; `invite` prints `{code, invitation_id, expires_at}`;
`show` and `review` print the records they list. The local API is `GET|POST /v1/peerboxes`, `GET|DELETE /v1/peerboxes/{id}`,
`PUT|DELETE /v1/peerboxes/{id}/rule`, `GET /v1/peerboxes/{id}/contributions` and
`POST /v1/peerboxes/contributions/{id}/decision`; peer-side operations use `POST /v1/tasks`
with `executor: "peerbox"`.

## Gates

A **gate** is an optional evaluator on one peerbox that promotes contributions by a measured
result (PBX-9 to PBX-15). It is local configuration on the home host, like review: no policy
field and no peer route changes. A peerbox without a gate is reviewed only by its owner, as
above; a gated peerbox can still be reviewed by hand.

### The gate record

| Field | Rules |
| --- | --- |
| `version` | 1 for the first gate on the peerbox, plus one each time it is set again. |
| `state` | `active`, or `paused` with `paused_reason` (`owner`, `frontier_failed`, `runtime_disabled` or `dirty_worktree`). |
| `command` | The candidate command: `argv` as for a runtime task's `run`. |
| `inputs_sha256` | The digest of the inputs snapshot (below). |
| `checker` | The checker command: `argv` as above. |
| `checker_sha256` | The digest of the checker snapshot. |
| `score` | `time` (the candidate run's `duration_ms`) or `checker` (the checker's `score`). |
| `direction` | `lower` or `higher`: which scores are better. |
| `min_gain` | 0 to 1,000: the percentage by which a candidate must beat the frontier, with at most two decimals. |
| `repeats` | 1 to 5. |
| `cpus`, `memory_mib`, `timeout_seconds` | Each run's bounds, as a runtime task's `resources`, at most what the runtime reports. |
| `max_output_bytes` | 1 to 104,857,600: bounds the candidate run's outputs. |
| `frontier` | Null, or `{commit, scores, measured_at}` from the latest evaluation. |

**Snapshots.** `peerbox gate set` copies `--inputs-dir` and `--checker-dir` into the home host's
state, packed as for a runtime workspace (regular files with their mode, directories and
symbolic links, sorted paths, no `..`), and stores their SHA-256. Later changes to those
directories change nothing until the gate is set again. The checker directory holds the
checker's files and the held-out expected outputs; the inputs directory holds the held-out
inputs only. Neither is ever sent to a peer.

**What readers see.** `list` and `status` carry the gate's public summary, `{version, state,
command, score, direction, min_gain, frontier}` with `frontier` as `{commit, score}` (its best
score), to every caller who may read the peerbox: never the snapshots, their digests, the
checker command or any run's output.

### Evaluation

A contribution is **queued** for the gate when it becomes `pending` on a gated peerbox. The
home host evaluates queued contributions one at a time, oldest first by `(submitted_at,
contribution_id)` (PBX-14), each against the protected head when its evaluation starts. A
contribution superseded or withdrawn while queued or under evaluation leaves the queue, and
its runs are cancelled. While the gate is paused, evaluations wait; review by hand works.

An evaluation measures the **frontier** (the protected head) and the **candidate** (the
contribution head), `repeats` times each, in the order frontier, candidate, frontier,
candidate, and so on (PBX-12). Each measurement is two runs on the home host's own runtime,
under the gate's bounds, submitted by the home host to itself; neither needs a peer's runtime
rule (PBX-15):

1. **Candidate run.** The workspace is the commit's tree, read as for a peerbox run, without
   any entry under `.peerbox-gate/`, plus the inputs snapshot under `.peerbox-gate/inputs/`.
   The run executes `command` with `results: changes`. Its **outputs** are the regular files
   and directories its changes hold under `.peerbox-gate/out/`; everything else it wrote,
   printed or returned is ignored. Its time is the run result's `duration_ms` (at least 1).
   A run that fails, times out or is cancelled, or whose outputs exceed `max_output_bytes` or
   were dropped, is a **failed measurement** with the code `run_failed` or
   `outputs_too_large`.
2. **Check run.** The workspace is the checker snapshot plus the outputs under
   `.peerbox-gate/out/`; the run executes `checker` with `results: output`. No candidate
   code runs in it. Its result is its last non-empty stdout line, which must be
   `PEERBOX-GATE ` followed by a JSON object with exactly `pass` (boolean), `score` (a
   positive finite number, or null when the gate's `score` is `time`) and `reason` (UTF-8, at
   most 200 bytes). A missing or malformed line, a failed or timed-out run, or `pass` false
   is a failed measurement with the code `check_failed` and the checker's `reason` when it
   gave one.

A measurement's **score** is the candidate run's `duration_ms` for `score: time`, or the
checker's `score` for `score: checker`.

**Verdict.**
- If any frontier measurement failed, the evaluation stops, the gate pauses with
  `frontier_failed`, and the contribution stays queued: a broken frontier is the owner's to
  fix, not the contributor's fault.
- If any candidate measurement failed, the contribution is **rejected** with that
  measurement's code and reason.
- Otherwise the candidate's worst score is compared with the frontier's best: for `lower`,
  the largest candidate score must be at most the smallest frontier score times
  `(1 - min_gain / 100)`; for `higher`, the smallest candidate score must be at least the
  largest frontier score times `(1 + min_gain / 100)`. Failing that is **rejected** with
  `below_margin`.
- A candidate that passes is **promoted** as an accept (Review, steps 1 to 4) by the gate.
  `not_fast_forward` and `head_moved` reject the contribution with that code (its contributor
  rebases and submits again, PBX-11); `dirty_worktree` pauses the gate with `dirty_worktree`
  and leaves the contribution queued.

The gate's `frontier` becomes the evaluation's frontier measurements, or the candidate's on a
promotion. A decision by the gate has `decided_by` `"gate"`, `reason` the code (and the
checker's reason after a colon, when there is one), and `gate` set to its **public result**:
`{gate_version, verdict, code, checker_reason, score, direction, min_gain, frontier_scores,
candidate_scores}`, with `verdict` `promoted` or `rejected`. The home host also keeps, for
its owner only, each run's task ID and outcome and the snapshot digests, through
`peerbox gate show` and the local API. A contributor sees only the public result through
`status`, never a run's output, logs or artifacts.

When the runtime's local switch is off, evaluations wait and the gate shows `paused` with
`runtime_disabled` until it is on again. After a restart, an evaluation that had not decided
starts again from its first measurement; runs it had started are cancelled.

### Gate CLI and local API

| CLI after `--state DIR` | Local API | Behavior |
| --- | --- | --- |
| `peerbox gate set PEERBOX --inputs-dir DIR --command JSON_ARGV --checker-dir DIR --checker JSON_ARGV --score time\|checker --direction lower\|higher --min-gain PERCENT [--repeats N] [--cpus N] [--memory-mib N] [--timeout DURATION] [--max-output-bytes N]` | `PUT /v1/peerboxes/{id}/gate` | Snapshots the directories and sets the gate, active, with the next version and `frontier` null. `--command` and `--checker` take one argument each, a JSON array of strings. Defaults: 1 repeat, 2 vCPUs, 2,048 MiB, 15 minutes, 104,857,600 output bytes. Refused while an evaluation runs (409 `gate_busy`). |
| `peerbox gate pause PEERBOX`, `peerbox gate resume PEERBOX` | `POST /v1/peerboxes/{id}/gate/pause`, `.../resume` | Pause with `owner`, or resume; resume clears any paused reason. |
| `peerbox gate clear PEERBOX` | `DELETE /v1/peerboxes/{id}/gate` | Removes the gate, cancelling a running evaluation; queued contributions stay pending for review by hand. |
| `peerbox gate show PEERBOX [--json]` | `GET /v1/peerboxes/{id}/gate` | The gate record, the queue, and recent evaluations with their runs. |

`peerbox review` shows each contribution's gate state (queued, under evaluation, or its
public result).

## Agents

Agents use peerboxes through the adapter, as they use runtime tasks: an owner-defined route
names the home host, and the adapter does the local Git work under the agent's own
permissions. Review and invitations stay with people: no agent tool accepts or rejects a
contribution, shares a peerbox or creates an invite.

**Routes.** Routes accept the actions `peerbox.read`, `peerbox.submit` and `peerbox.run`,
set with `adapter route add --action` or in session setup, and shown in route records and
destinations. A peerbox route names a host, not an agent, and cites the host owner's policy,
as a `runtime.run` route does. Through a route, `list`, `fetch` and `status` need any of the
three; `submit` and `withdraw` need `peerbox.submit`; `run` needs `peerbox.run`. Any other
use is 403. A route's `max_messages` budget counts each peerbox task. The home host still
checks its own rules; a route only limits what the agent may ask.

| Adapter API | Behavior |
| --- | --- |
| `POST /adapter/v1/peerbox` with `{destination, task_id, peerbox, input?, bundle?}` | Submits a peerbox task through the named route; `bundle` is a digest the adapter uploaded, required for `submit`. Ownership, repeats and the deadline follow `POST /adapter/v1/delegations`. Returns the local record. |

MCP tools, each taking `destination`, a peerbox route's name:

| Tool | Arguments | Behavior |
| --- | --- | --- |
| `peerbox_list` | none | Submits `list`, following `next`, and returns the merged `peerboxes`. |
| `peerbox_fetch` | `peerbox_id`, `repository_path` | As `peerbox fetch` with `--repository`: sends `have` from that repository's refs for the peerbox, verifies the bundle as Fetch says, and sets `refs/peerbox/PEERBOX/BRANCH` there. Returns `{head, ref}`; a repeat with nothing new returns the same head. |
| `peerbox_submit` | `peerbox_id`, `repository_path`, `branch`, `base?` | As `peerbox submit`: bundles the branch under the agent's permissions, uploads it and submits. Returns the contribution record when the task ends, or `{error, message}`. |
| `peerbox_status` | `peerbox_id`, `contribution_id?`, `before?` | Submits `status` and returns its result. |
| `peerbox_withdraw` | `peerbox_id`, `contribution_id` | Submits `withdraw` and returns its result. |
| `peerbox_run` | `peerbox_id`, `commit`, `argv`, `cwd?`, `env?`, `resources?`, `results?`, `input?` | Submits `run` and returns the task ID. Output notifications, `task_status` and `artifact_save` work as for `run_task`. |

The tools wait for a task's final event up to its deadline, except `peerbox_run`, and return
`{error, message}` for a failed one. `repository_path` is a local path the agent can write;
the adapter never writes outside it and never changes its checked-out branch or worktree.

## Persistence

The host schema version increments by one: the next free version on `main` when the
implementing PR merges. New tables hold peerbox records and contributions with their
decisions; received and outbound task records of peerbox tasks gain `executor` and `peerbox`
as runtime tasks gain `run`; a peerbox run's received record also has the runtime fields.
Older binaries reject the new version. New tables also hold pending shares. Route records accept the three peerbox actions. New tables hold gates, their snapshots' metadata and evaluations; the snapshots are files in the host's state directory. New activity kinds are `peerbox.gate_set`, `peerbox.gate_paused`, `peerbox.gate_evaluated`, `peerbox.created`,
`peerbox.shared`, `peerbox.invited`, `peerbox.fetched`, `peerbox.submitted`, `peerbox.decided` and
`peerbox.deleted`.

## Verification

Two suites are written from this contract by a separate author who does not read `src/`,
`tests/` or `integrations/` (DEC-OWN6, DEC-OWN9). They drive two or three real Rust hosts
with `conformance/slim/harness.py`, Git fixture repositories and its test clock, without KVM
and without model calls, each under 2 minutes: `peerbox` in the per-push tier if it fits the
budget (DEC-OWN14), and `peerbox_runs`, with the fake runtime, in the second tier.

`peerbox` covers:
- the policy body: peerbox rules admitted by the owner's other host and another person's
  host; an empty `peerbox_rules`, an unknown key, one principal in two rules of one peerbox, `submit` without
  `read`, and `max_pending` 0 with `submit` refused; rules kept across a renewal;
- authorization: an unknown peerbox and one the sender may not read, both 404 `unknown`;
  `list` showing only readable peerboxes, and paging with `after` and `next` when they do not
  fit one output; `submit` without `peerbox.submit` 403; a lapsed
  sender with and without `allow_disconnected`; a grant or `target_agent_id` 400;
- create: the disclosure summary, refusal by default, and `--yes`;
- fetch: the bundle verifies and holds exactly the protected head; `have` shortens it; a
  repeat fetch with the head in `have` succeeding with no artifact; a
  `have` outside the protected branch changes nothing; `too_large`;
- submit: a valid contribution stored under the member ref; `pending_limit`, and a replacement at the same member ref accepted at the limit; branch names
  refused; `base_unknown` and `base_not_ancestor`; hostile bundles (a mutated byte, a ref
  outside `refs/heads/`, an option-like ref name, a tree with `.git` paths or hooks) storing
  nothing; superseding, with a superseded contribution still runnable through its contribution ref
  until 30 days pass (test clock) and `commit_unknown` after; a peer unable to write the protected branch or another member's ref;
- review: accept fast-forwarding, `not_fast_forward`, `head_moved`, `dirty_worktree`, reject
  with a reason, and the decision visible through `status`;
- `status` paging: more contributions than fit in one output, several with the same
  `submitted_at` (test clock), read completely and without repeats with `before` and `next`, each record's `runs` cut to 8 with `runs_total`;
- withdrawal: new fetches and submissions refused; `status` still answering the former
  contributor with only their own contributions, and 404 `unknown` for a former reader who
  never submitted;
- several rules on one peerbox: two people with different actions and bounds; `share` for one
  leaving the other unchanged; a principal in two rules of one peerbox refused; a sender
  matching `person:` and `network` rules getting the union; an invitation completing while
  another person's rule exists, leaving it unchanged; `share` read-only defaulting
  `max_pending` to 0;
- invitations: `peerbox invite` printing a `psb1-` code that `peerbox join` and `join` accept; after admission, the rule signed for exactly the admitted person with the pending share's actions and bounds, and the joiner listing and fetching the peerbox; an expired or cancelled pending share giving membership and no access; a joiner already in the network refused; a code given as a command argument refused; a share waiting for the owner's signature kept
across a restart and completed by `peerbox share --pending`; the pending share kept across a restart of the home host;
- restarts of both hosts during a fetch and a submit, and records kept;
- opening a database of the previous schema version.

`peerbox_agents` (second tier) covers, through the adapter socket and MCP as the runtime
suites do: routes with each peerbox action, a `peerbox.read` route refused for `submit` and
`run` (403), the route budget; `peerbox_list`, `peerbox_fetch` into a repository (the ref set,
the checked-out branch untouched, a repeat with nothing new), `peerbox_submit` and
`peerbox_status`, `peerbox_withdraw`, and `peerbox_run` with output notifications; no tool
that reviews, shares or invites.

`peerbox_gate` (second tier) covers, with the fake runtime: a candidate writing outputs and a
checker echoing a `PEERBOX-GATE` line; promotion with enough gain and the frontier moved,
`below_margin` for less, in both directions and for both score sources; `check_failed` for a
missing or malformed line, `pass` false and a failed check run, and `run_failed` and
`outputs_too_large` for the candidate; a candidate printing its own `PEERBOX-GATE` line and
writing outside `.peerbox-gate/out/` changing nothing; a candidate's own `.peerbox-gate/`
entries removed; the expected outputs never in a candidate run's workspace; `frontier_failed`
pausing the gate; `not_fast_forward` and `head_moved` rejecting, `dirty_worktree` pausing;
evaluation order and one at a time; superseding while queued; pause, resume, clear and
review by hand while paused; `runtime_disabled`; the public result in `status` and the
summary in `list`, with no run output, checker command or digest; restart during an
evaluation; `gate set` refused while busy.

`peerbox_runs` covers: a run needing both rules and the switch; bounds from the runtime rule;
the workspace equal to the commit's tree with no `.git`, including a commit whose
`.gitattributes` marks files `export-ignore` or `export-subst`; `commit_unknown`; a run changing no
ref; withdrawal cancelling a started run with `access withdrawn`, while a runtime rule's
withdrawal does not; the run recorded in the contribution's `runs`.

A live two-owner run on two machines with `peerspan-runtime` and real agents records the
experience separately (proposal, plan step 8).
