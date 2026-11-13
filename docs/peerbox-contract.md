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
agent tools for review, agent tools that create, share or invite without the owner's approval
(see [Agent proposals](#agent-proposals)), and grants for peerbox operations.

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

The home host reads the protected branch's head; when the branch no longer exists, the
task fails with `unavailable`, and `list` shows its `head` as null. Otherwise it creates a bundle (version 2, or 3 for a
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
| `peerbox create --repository PATH --branch NAME [--title TEXT] [--network ID] [--yes]` | Shows what a read discloses (the branch and head, the commits reachable from it, their distinct author and committer names and addresses, and the bundle size) and asks to confirm, defaulting to no; `--yes` skips the question. Creates the record and prints its ID. `--title` defaults to the repository directory's name. A branch with no commit is refused with `branch_unknown`. |
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
`GET /v1/peerboxes/{id}/contributions` and
`POST /v1/peerboxes/contributions/{id}/decision`; peer-side operations use `POST /v1/tasks`
with `executor: "peerbox"`. `share`, `unshare` and `delete` change the rules through the
existing policy routes, as `runtime enable` does; there is no separate rule route.

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
| `command` | The candidate command: `argv` as for a runtime task's `run`, but 1 to 64 strings of at most 4,096 bytes summed, so the public summary always fits a `list` entry. |
| `inputs_sha256` | The digest of the inputs snapshot (below). |
| `checker` | The checker command: `argv` as for `command`. |
| `checker_sha256` | The digest of the checker snapshot. |
| `score` | `time` (the candidate run's `duration_ms`) or `checker` (the checker's `score`). |
| `direction` | `lower` or `higher`: which scores are better. |
| `min_gain` | 0 to 1,000: the percentage by which a candidate must beat the frontier, with at most two decimals. |
| `repeats` | 1 to 5. |
| `cpus`, `memory_mib`, `timeout_seconds` | Each run's bounds, as a runtime task's `resources`, at most what the runtime reports. |
| `max_changes_bytes` | 1 to 104,857,600: bounds everything the candidate run changes in its workspace, not only its outputs, because the run's changes come back as one `changes.tar` and the runtime drops it whole above its limit. Builds should write outside the workspace (a runner script in the inputs can arrange that). |
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
contribution_id)` (PBX-14), each against the protected head when its evaluation starts: that commit is the evaluation's
**frontier**, fixed for the whole evaluation. A candidate that is not a descendant of the
frontier is rejected with `not_fast_forward` before any run. A
contribution superseded, withdrawn, or accepted or rejected by hand while queued or under
evaluation leaves the queue, and its runs are cancelled: a gate never overrides a decision
already made. While the gate is paused, evaluations wait; review by hand works.

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
   A run that fails, times out or is cancelled, or whose changes exceed `max_changes_bytes` or
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
- Every decision by the gate first checks, atomically with recording it, that the
  contribution is still `pending`; if it is not, the gate records nothing.
- A candidate that passes is **promoted** as an accept by the gate (Review, steps 3 and 4),
  except that the compare-and-swap is against the evaluation's frontier, never a head read
  again: the protected branch moves from exactly the measured frontier to the candidate. If
  the protected head is no longer the frontier, nothing is promoted and the contribution
  returns to the front of the queue, to be evaluated again against the new head: a head
  that moved is not the contributor's fault. `dirty_worktree` pauses the gate with
  `dirty_worktree` and leaves the contribution queued.

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
| `peerbox gate set PEERBOX --inputs-dir DIR --command JSON_ARGV --checker-dir DIR --checker JSON_ARGV --score time\|checker --direction lower\|higher --min-gain PERCENT [--repeats N] [--cpus N] [--memory-mib N] [--timeout DURATION] [--max-changes-bytes N]` | `PUT /v1/peerboxes/{id}/gate` | Snapshots the directories and sets the gate, active, with the next version and `frontier` null. `--command` and `--checker` take one argument each, a JSON array of strings. Defaults: 1 repeat, 2 vCPUs, 2,048 MiB, 15 minutes, 104,857,600 bytes of changes. Refused while an evaluation runs (409 `gate_busy`). |
| `peerbox gate pause PEERBOX`, `peerbox gate resume PEERBOX` | `POST /v1/peerboxes/{id}/gate/pause`, `.../resume` | Pause with `owner`, or resume; resume clears any paused reason. |
| `peerbox gate clear PEERBOX` | `DELETE /v1/peerboxes/{id}/gate` | Removes the gate, cancelling a running evaluation; queued contributions stay pending for review by hand. |
| `peerbox gate show PEERBOX [--json]` | `GET /v1/peerboxes/{id}/gate` | The gate record, the queue, and recent evaluations with their runs. |

`peerbox review` shows each contribution's gate state (queued, under evaluation, or its
public result).

## Agents

Agents use peerboxes through the adapter, as they use runtime tasks: an owner-defined route
names the home host, and the adapter does the local Git work under the agent's own
permissions. Review and invitations stay with people: no agent tool accepts or rejects a
contribution, shares a peerbox or creates an invite by itself. Under
[Agent proposals](#agent-proposals), an agent can prepare a create, share or invite that runs
only after the owner approves it at a terminal.

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

### Agent proposals

Accepted 2026-11-13: PBX-16 to PBX-21 in the
[decision log](decision-log.md#pbx-16-to-pbx-21-agent-proposed-owner-confirmed-peerbox-changes-2026-11-13),
each chosen as recommended.

An agent can **prepare** a `peerbox create`, `peerbox share` or `peerbox invite` on its own
host; the person confirms it with one approval at a terminal on that host; only then does the
host carry it out, exactly as prepared, and the agent receives the result. A prepared change is
a **proposal**. It reuses the per-call approval of the
[capabilities contract](capabilities-contract.md#per-call-approval-slice-3): the same
`approvals`, `approve` and `deny` commands, the same terminal rule, single use, expiry, and the
call-update notification pattern for telling the agent the outcome. Review (accept and
reject), `unshare`, `delete`, gates, `invite --cancel` and `share --pending` stay owner-only;
no agent tool prepares them.

A proposal is local to the host whose adapter made it, and that host is the peerbox's home
host: `create` makes this host the home host, and `share` and `invite` name a peerbox whose
record is on this host. No peer route creates, lists or decides a proposal, and no message,
task, reply or call another host sends is ever turned into one.

#### Who may propose

The adapter credential gains `peerbox_proposals`, a boolean, default false (PBX-17).
`POST /v1/adapters/setup` takes it, and the adapter record shows it. `attach` gains
`--peerbox-proposals` and `--no-peerbox-proposals`, with exactly the prompt, terminal and
re-attach rules of `--calls`, and the prompt
`Let this agent prepare peerbox changes (create, share, invite) for you to approve? [y/N] `.
Its output gains `peerbox_proposals`, as on the adapter record, as it gains `calls`.
A credential created any other way has it false. Every route below answers 403
`{code: "no_peerbox_proposals", error}` without it. Routes, grants and peerbox route actions
neither give nor need it.

#### The proposal record

| Field | Rules |
| --- | --- |
| `proposal_id` | `pbp_` followed by 32 lowercase hex digits, chosen by the adapter (Repeats). |
| `op` | `create`, `share` or `invite`. |
| `args` | The operation's arguments with every default filled in (below), so the record states the whole change. |
| `review` | Facts the host computed itself when the proposal was made (below). Never text the agent supplied, other than the fields of `args` it repeats. |
| `proposal_sha256` | SHA-256 of `{"op", "args", "review"}` in the call view's result-text encoding (keys sorted by UTF-8 bytes, no whitespace), as lowercase hex. |
| `origin` | `{adapter_id, agent_id, session_id}` of the proposing session. |
| `state` | `pending`, `approved`, `executed`, `failed`, `denied`, `expired` or `cancelled`. |
| `requested_at`, `expires_at`, `decided_at` | RFC3339. `expires_at` is `requested_at` plus 1 hour (PBX-19). `decided_at` is when `state` left `pending`, else null. |
| `reason` | The person's denial reason (0 to 1,024 bytes of UTF-8), else null. |
| `result` | Null, or on `executed` the operation's result (Execution). |
| `error` | Null, or on `failed` `{code, message}`. |

The record holds no free-text note from the agent (PBX-20): the agent explains itself to the
person in the session, not in the approval.

**`args` and `review` by operation.** Each argument has the range of the CLI flag it stands for.

| `op` | `args` | `review` |
| --- | --- | --- |
| `create` | `{repository, branch, title, network_id}`: `repository` the path given, made absolute and resolved through symbolic links when proposed, at most 4,096 bytes; `title` defaulting to the directory's name; `network_id`, when absent or null, the host's only coordinator-free network; absent or null when the host is in none or in several is 400 `invalid` with `field: "network_id"`. | `create`'s disclosure: `{head, commits, identities, identities_total, bundle_bytes}`, with `identities` the distinct `{name, email}` author and committer pairs sorted by `name`, then by `email`, each compared as UTF-8 bytes, the first 100 of that order, and `identities_total` their number. |
| `share` | `{peerbox_id, principals, actions, max_bundle_bytes, max_pending, allow_disconnected}`, with `share`'s defaults. `principals` is 1 to 64 distinct `person:PERSON_ID` (PBX-18), in any order; the host sorts them by UTF-8 bytes. | `{title, network_id, people, before}`: `people` is `[{principal, person_id, label}]` from the network's signed membership map; `before` is, per principal in the same order, its current `{actions, max_bundle_bytes, max_pending, allow_disconnected}` on this peerbox, or null. |
| `invite` | `{peerbox_id, label, actions, max_bundle_bytes, max_pending, expires_in_seconds}`: `label` as for `peerspan invite`; `expires_in_seconds` 60 to 86,400, default 3,600, counted from execution. | `{title, network_id}`. |

`actions` takes the short names `read`, `submit` and `run`, as `--action` and the MCP tools
take them, never `peerbox.read`; they are distinct, the host writes them in the order `read`,
`submit`, `run`, and the default is `["read"]`. The host fills defaults, sorts `principals`,
orders `actions`, resolves `repository` (and `title` from it) and fills `network_id` at step 1
of Proposing; the record's `args` is that result.

#### Adapter routes

They require the adapter's credential and lease, as `/adapter/v1/next` does, and work before
the channel is verified, except `proposal-updates/next`.

| Adapter request | Behavior |
| --- | --- |
| `POST /adapter/v1/peerbox/proposals` with `{proposal_id, op, args}` | Checks and persists one proposal (Proposing) and returns 200 with the proposal view. It never waits for a decision. |
| `GET /adapter/v1/peerbox/proposals/{id}` | The proposal view. Answers for proposals made through any credential of this session's agent on this host; any other ID is 404. |
| `POST /adapter/v1/peerbox/proposals/{id}/cancel` with `{}` | A `pending` proposal becomes `cancelled`; any other state is 409 `{code: "conflict", error: "the proposal is no longer pending", proposal: VIEW}`. Same scope and 404 as the `GET`. |
| `POST /adapter/v1/peerbox/proposal-updates/next` with `{}`, `POST /adapter/v1/peerbox/proposal-updates/{id}/forwarded` with `{}` | As `call-updates/next` and its `forwarded`, for proposal-update notifications (Telling the agent): `next` returns `{delivery, proposal, redelivered}`, where `delivery` is the notification record and `proposal` the proposal view, or `null`. |

**Proposing.** `POST /adapter/v1/peerbox/proposals` takes these steps, in order; a refusal
persists nothing:
1. **Shape.** `proposal_id`, `op` and `args` as above, `args` with exactly that operation's
   keys, optional ones absent or null; otherwise 400 `{code: "invalid", field}`. `field` is
   `proposal_id`, `op` or `args` for the request's own keys (`args` when it is not an object);
   for an argument it is the key inside `args` alone, as in `field: "repository"` (step 4):
   `principals`, `expires_in_seconds`, an unknown key's own name, and the array's key, never an
   index, for a bad element. A `network` principal, any other principal that is not `person:`
   and a person ID, a repeated principal, and more than 64 principals are each 400 `invalid`
   with `field: "principals"` (PBX-18). Then the host normalizes `args` (above).
2. **Repeat.** A `proposal_id` already used on this host returns the existing view, whatever its
   state, when it was made by this agent with the same `op` and with `args`, normalized as in
   step 1, equal to the record's; otherwise 409 `{code: "conflict"}`. Neither counts against the
   limits.
3. **Limits.** At most 5 proposals `pending` per credential and 20 per host: 429
   `{code: "limit", error: "too many proposals are waiting for approval", limit:
   "max_pending_proposals"}`. At most 20 proposals made through one credential in the
   preceding 60 minutes: 429 `{code: "rate_limited", error, retry_after}` as for calls. When
   both apply, the pending limit answers.
4. **Target.** For `share` and `invite`, `peerbox_id` must name a peerbox record on this host:
   404 `{code: "unknown"}`. For `share`, every principal must be a person in the current signed
   membership of the peerbox's network: 400 `{code: "unknown_principal", principal}`. For
   `create`, `git` must be present (503 `git_missing`) and the branch must have a commit (400
   `branch_unknown`); a path that is not a Git repository is 400 `{code: "invalid", field:
   "repository"}`.
5. **Review.** The host computes `review`. When that cannot finish within the
   [wait limit](capabilities-contract.md#the-wait-limit) of receipt, 503
   `{code: "timeout", error}`: such a repository is created by the person with `peerbox create`.
6. **Duplicate.** A `pending` proposal of the same agent with the same `proposal_sha256` is 409
   `{code: "duplicate", proposal_id: ITS_ID}`, so the person is not asked twice.
7. **Persist.** In one transaction: the record as `pending` and the activity `peerbox.proposed` (subject: the proposal ID).

**The proposal view** is the record without `origin`, plus `note`, one of these exact texts,
with `PROPOSAL_ID` replaced by the proposal's ID:
- `pending`: `The person must approve this in a terminal on this machine (peerspan approve PROPOSAL_ID); it has not been done, and you cannot approve it. Tell the person what you prepared and why. Its outcome arrives as a kind=peerbox_proposal_update event; peerbox_proposal_status reports it at any time. Do not propose it again.`
- `approved`: `The person approved this; it is being carried out.`
- `executed` for `invite`: `The invite was created. Give the code only to the person it is for, privately: whoever holds it can ask to join the network and receive this access once an administrator admits them.`; for `create` and `share`: null.
- `failed`: `The person approved this, but it could not be carried out (see error). Nothing was changed.`
- `denied`, `expired`, `cancelled`: `This was not done, and nothing was changed. Proposing again makes a new proposal.`

#### MCP tools

The shared adapter adds five tools, listed whatever the credential, and refused with the
`no_peerbox_proposals` refusal without it. Each generates `proposal_id` when it is absent;
an agent that lost a response calls again with the same `proposal_id` (Repeat).

| Tool | Arguments | Behavior |
| --- | --- | --- |
| `peerbox_propose_create` | `repository_path`, `branch`, `title?`, `network_id?`, `proposal_id?` | Posts `op: "create"`. Returns the proposal view. |
| `peerbox_propose_share` | `peerbox_id`, `principals`, `actions?`, `max_bundle_bytes?`, `max_pending?`, `allow_disconnected?`, `proposal_id?` | Posts `op: "share"`. `actions` are `read`, `submit`, `run`, as `--action` takes them. |
| `peerbox_propose_invite` | `peerbox_id`, `label`, `actions?`, `max_bundle_bytes?`, `max_pending?`, `expires_in_seconds?`, `proposal_id?` | Posts `op: "invite"`. |
| `peerbox_proposal_status` | `proposal_id` | `GET .../proposals/{id}`. A 404 returns, without an error, `{proposal_id, state: "not_recorded", note: "The host has no record of this proposal for this agent; nothing was done."}`. |
| `peerbox_proposal_cancel` | `proposal_id` | `POST .../proposals/{id}/cancel`. |

Schemas have `additionalProperties: false`. Refusals return a tool error
`{proposal_id, code, error, recovery}` with `recovery` `Nothing was proposed or recorded.`, as
call refusals do; `no_peerbox_proposals` uses exactly `This session may not prepare peerbox
changes. The person enables it with peerspan attach --peerbox-proposals.` A proposal view is
never a tool error, whatever its state.

#### Approving

The person decides with the per-call approval commands, which accept a third `ID` form,
`pbp_` and 32 lowercase hex digits (PBX-16). `deny` treats such an argument as a proposal, as
it treats call IDs.

| CLI | Local API | Behavior |
| --- | --- | --- |
| `approvals [--all] [--json]` | `GET /v1/peerbox-proposals?state=pending\|all`, beside `GET /v1/approvals` | Also lists proposals, in a second block after the calls. The route returns `{peerbox_proposals: [RECORD]}`: `state` defaults to `pending`, any other value is 400; `pending` lists the pending proposals and `all` adds every other one whose `decided_at` is within the last 7 days; sorted oldest first by `requested_at`, then `proposal_id`. `--json` prints `{approvals: [...], peerbox_proposals: [RECORD]}`, the two routes' lists side by side. One readable line each: the ID, `op`, the peerbox title or repository, the people or invite label, the actions, the proposing agent, the age and the time left. |
| `approvals show pbp_… [--json]` | `GET /v1/peerbox-proposals/{id}` | The whole record, readable (below). |
| `approve pbp_… [--person-key PATH]` | `POST /v1/peerbox-proposals/{id}/approve` with `{proposal_sha256, person_key}`: `person_key` is null, or a string, the absolute path of the OpenSSH private-key file `--person-key` names (the CLI makes it absolute); the daemon reads it for this signing only and never stores it, and with null signs through the network's provider as `peerbox share` without `--person-key` does | Needs a terminal, has no `--yes`, and refuses as call `approve` does. Prints what `approvals show` prints to stderr, then asks the operation's question (below), reading one line; on `y` or `yes` (any case) sends the digest it displayed. The route holds until execution ends and returns 200 with the record, `executed` or `failed`; the CLI prints it as JSON and exits 0 for `executed`, 1 for `failed`. |
| `deny pbp_… [--reason TEXT]` | `POST /v1/peerbox-proposals/{id}/deny` with `{reason}` | As call `deny`: no prompt, terminal or not; the proposal becomes `denied`. |

**Route refusals.** An unknown ID is 404. A proposal not `pending`, or past `expires_at`, is 409
`{code: "conflict", error: "the proposal is no longer pending", proposal: RECORD}`, so
approving twice changes nothing. A `proposal_sha256` other than the record's is 409
`{code: "proposal_changed"}`. For `share` and `invite`, when signing would need the person's
interaction and `person_key` does not provide it, 409 `{code: "person_key_needed", error}`,
checked before anything changes: the proposal stays `pending` and the CLI says to run
`approve` again with `--person-key`. `reason` over 1,024 bytes is 400.

**What the person sees.** `approvals show` and `approve` print, in this order:
1. `Prepared by agent AGENT_ID in session SESSION_ID. It may be acting on what other people told it; only the lines below are what will happen.`
2. The operation: for `create`, the repository, branch, head, commit count, every identity (all
   of `identities`, then `and N more` when `identities_total` is larger), the bundle size and
   the network; for `share`, the peerbox, then per person their label, `person_id`, and the
   access before and after; for `invite`, the peerbox, network, label, actions, bounds and how
   long the code works.
3. For `share`, the compatibility line `peerbox share` prints before signing.
4. The question, exactly: `Create this peerbox? [y/N] `, `Sign a policy giving these people this access? [y/N] `, or
   `Create this invite? Your agent will receive the code and choose who gets it. [y/N] `.

Every piece of text the host did not choose itself is written **quoted**: a `"`, then the text
with each `\` written as `\\` and each `"` as `\"`, and each character below U+0020 (line
breaks included), U+007F and U+0080 to U+009F written as `\u` and four lowercase hex digits,
as [Showing untrusted text](capabilities-contract.md#approving) writes them, then a `"`. So
a value can neither close its quotes early nor print an escape that reads as one the host
wrote. This covers values the agent supplied
(`repository`, `branch`, `title`, `label`), labels from the membership map, and text read from
the repository, which is each identity's `name` and `email` in the `create` disclosure. IDs, hashes and numbers are printed whole.

**Telling the person.** `GET /v1/status` gains, at the top level, `peerbox_proposals_pending`, the number of
`pending` proposals, and the attention item `peerbox_proposal_pending`, numbered after the
last item in use when this merges: one item while any proposal is pending; subject the number
as a decimal string; detail the oldest one's `op`, peerbox or repository and `expires_at`;
command `peerspan approvals`. No notice event is sent: the proposing session already has the
`pending` note, which tells the agent to ask the person.

#### Execution

`approve` moves the proposal `pending` to `approved` in one transaction with the activity
`peerbox.proposal_approved`, then carries out exactly `args`:

| `op` | Carried out as | `result` |
| --- | --- | --- |
| `create` | `peerbox create --yes` with `args`, after computing the disclosure again: when it differs from `review` in any field (the branch moved, for example), the proposal fails with `review_changed`. | `{peerbox_id}` |
| `share` | `peerbox share PEERBOX --for ...` with `args` and `person_key`. The whole share review is computed again from the policy the signature will build on: each `person_id` must still be a member with the same principal, and each principal's `before` access must equal the reviewed `before`; any difference fails with `review_changed`, so an approval never overwrites access that changed after the person saw it. A `state_conflict` reloads, computes the review again from the reloaded policy (failing with `review_changed` on any difference) and tries again, at most 3 times, then fails with `state_conflict`. When every principal already holds exactly this access, nothing is signed. | `{policy_version}`: the version signed, or the current one when nothing was signed |
| `invite` | `peerbox invite PEERBOX LABEL ...` with `args`, the expiry counted from now. | `{code, invitation_id, expires_at}`: the `psb1-` code |

- **All or nothing.** The operation's own stored change (the peerbox record, the signed policy
  version, or the network invite with its pending share) and the proposal's `executed` state
  with `result` are written in one transaction, with `peerbox.proposal_executed`. A failure
  writes `failed` with `error` and `peerbox.proposal_failed`, and nothing else. A peerbox
  removed before execution fails with `unknown`; other codes are those the command returns
  (`git_missing`, `branch_unknown`, signing failures as the network's provider reports them).
- **Restart.** A proposal found `approved` when the daemon starts becomes `failed` with
  `interrupted`: by the rule above, its change was not stored.
- **Single use.** One approval executes once. A proposal never returns to `pending`; the same
  change again needs a new proposal and a new approval.
- **Provenance.** The peerbox record and the pending share gain `proposal_id`, null when the
  person ran the command; `peerbox show` and `invite --list` show it.
- **Expiry.** A `pending` proposal past `expires_at` becomes `expired`, with
  `peerbox.proposal_expired`; the daemon checks at least every 5 seconds. Denial records
  `peerbox.proposal_denied`, cancellation `peerbox.proposal_cancelled`. Activity holds no
  argument values and no reason.
- **The code.** `result.code` is set to null at the invite's `expires_at`. Only the proposing
  agent's sessions (through the view) and the person (`approvals show`) read it.

#### Telling the agent

When a proposal becomes `executed`, `failed`, `denied` or `expired`, the daemon creates, in the
same transaction, a **proposal-update notification**, a call-update notification in all but
name: same record shape with `proposal_id` in place of `call_id`, same seen, redelivery and
late-arrival rules, and seen when the holding session gets a final view through
`peerbox_proposal_status` or calls `mark_seen` with the proposal ID. The event has
`meta.kind` `peerbox_proposal_update` and `meta` `{proposal_id, notification_id, op, state,
error_code, session_id, redelivered}`; its content is the proposal view as JSON text. A
cancellation makes none. `pending_work`, `GET /adapter/v1/pending` and
`GET /v1/sessions/{id}/pending` gain `peerbox_proposals`, `{proposal_id, op, state,
expires_at, session_id, redelivered}`, listed as `calls` are: those not final, and those whose
notification this session holds unseen.

#### Routes and budgets

A proposal uses no route and counts against no route's `max_messages`, no
`max_sends_per_hour` and no `max_calls_per_hour`; its only bounds are the limits under
Proposing. Executing a `share` changes the policy only: it creates no adapter route, so another
person's agent still needs its own owner's `peerbox.*` route to use the access, and the home
host still checks its peerbox rules on every task. An `invite` changes nothing about
admission: an administrator admits the joiner as for any peerbox invite, and the rule is signed
then (Invitations for new participants).

#### Why text from others cannot approve

- Only `POST /v1/peerbox-proposals/{id}/approve` on the local administration socket moves a
  proposal out of `pending` towards execution, and `approve`, its only CLI, needs a terminal and
  has no `--yes`. No adapter route, MCP tool, peer route or channel event approves, and a
  proposal-update event carries no input from anyone but the person.
- A proposal comes only from an adapter credential with `peerbox_proposals`; nothing a peer
  sends is parsed into one.
- The approval names the digest of what was displayed, and execution uses only `args`, with
  `review` rechecked, so what runs is what the person saw.
- The approval display is built from `args` and Peerspan's own lookups, with agent-supplied
  values quoted and escaped, and carries no agent-written explanation.
- The remaining limit is that of call approvals: a process running as the same OS user can
  reach the administration socket itself.

#### Not in this amendment

Agent proposals for review, `unshare`, `delete`, gates, `invite --cancel` or
`share --pending`; principals other than `person:`; proposals from another host of the person;
approving from another machine; one approval covering several proposals.

#### Decisions

The owner chose each recommendation on 2026-11-13 (decision log PBX-16 to PBX-21).

1. **PBX-16. Where the person approves.** (a) The existing `approvals`, `approve` and `deny`
   commands, with a `pbp_` ID form. (b) New `peerbox proposals`, `peerbox approve` and
   `peerbox decline` commands. **Chosen (a):** one place to look, and the terminal rule and
   its tests already exist; the local API stays separate, so `GET /v1/approvals` is unchanged.
2. **PBX-17. What lets an agent propose.** (a) A credential flag, `peerbox_proposals`, asked at
   `attach` and default no, like `calls`. (b) A route action `peerbox.propose` naming this
   host. (c) Every credential. **Chosen (a):** routes name a peer and cite its policy, and a
   proposal has neither; (c) puts approval requests in front of people who never chose them.
3. **PBX-18. Whom an agent may propose to share with.** (a) `person:` principals that are
   current members, at most 64. (b) Every principal a rule accepts, `network` included.
   **Chosen (a):** each person is named and resolved in the review; giving the whole network
   access stays a deliberate command.
4. **PBX-19. How long a proposal waits.** (a) 1 hour, fixed. (b) Chosen by the agent, up to
   24 hours. (c) 15 minutes, as a call. **Chosen (a):** the person is usually in the session
   that asked; a longer wait leaves stale requests in the list, and `review_changed` already
   covers a repository that moved.
5. **PBX-20. An explanation from the agent.** (a) None in the record; the agent explains in its
   session. (b) A `note` of up to 1,024 bytes, shown quoted and marked as the agent's.
   **Chosen (a):** the agent may be repeating another person's text, and the approval screen
   should show only what will happen.
6. **PBX-21. When the review changes before approval.** (a) Recompute at execution and fail
   with `review_changed` on any difference. (b) Show the new facts in the `approve` prompt and
   execute on them. **Chosen (a):** the approval then covers exactly what the person saw; (b)
   turns the digest into a check of the arguments only.

## Persistence

The host schema version increments by one: the next free version on `main` when the
implementing PR merges. New tables `peerboxes`, `peerbox_contributions` and
`peerbox_pending_shares` hold peerbox records, contributions with their decisions, and
pending shares; received and outbound task records of peerbox tasks gain `executor` and `peerbox`
as runtime tasks gain `run`; a peerbox run's received record also has the runtime fields.
Older binaries reject the new version. Route records accept the three peerbox actions. New tables hold gates, their snapshots' metadata and evaluations; the snapshots are files in the host's state directory. New activity kinds are `peerbox.gate_set`, `peerbox.gate_paused`, `peerbox.gate_evaluated`, `peerbox.created`,
`peerbox.invited`, `peerbox.fetched`, `peerbox.submitted`, `peerbox.decided` and
`peerbox.deleted`, each recorded on the home host: when a record is created or deleted, an
invite created, a bundle served, a contribution stored, and a decision recorded. A share
is a policy edit and shows as one.

The [Agent proposals](#agent-proposals) amendment, when accepted, adds in the same or the
next schema version: a table `peerbox_proposals` (`proposal_id` primary key, `adapter_id`,
`agent_id`, `session_id`, `op`, `state`, `expires_at`, `record`), indexed by
`(state, expires_at)`; proposal-update notifications stored as call-update notifications are;
`peerbox_proposals` on adapter credentials, false for existing ones; and a nullable
`proposal_id` on peerbox records and pending shares. Final proposals are kept 30 days after
`decided_at`, then deleted. New activity kinds are `peerbox.proposed`,
`peerbox.proposal_approved`, `peerbox.proposal_executed`, `peerbox.proposal_failed`,
`peerbox.proposal_denied`, `peerbox.proposal_expired` and `peerbox.proposal_cancelled`.

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
that reviews, shares or invites by itself.

`peerbox_proposals` (second tier), when the [Agent proposals](#agent-proposals) amendment is
accepted, covers through the adapter socket, MCP and a pseudo-terminal for `approve`: the
credential flag and `no_peerbox_proposals`; each operation proposed, approved and executed,
with the invite's `psb1-` code reaching the agent and joining as `peerbox join` does; `deny`,
expiry (test clock) and cancel, each changing nothing; `approve` without a terminal, with a
wrong digest, twice, and after expiry; `review_changed` for a branch moved, a person
removed, and a recipient's access changed (granted, revoked or altered) before approval, with
the newer policy left in place; `person_key_needed` leaving the proposal pending; repeats, conflicts,
`duplicate` and the pending and hourly limits, the pending limit answering when both apply;
`unknown_principal`, and `network` and 65 principals refused as `invalid` naming
`principals`; principals given out of order stored sorted;
a restart while `approved` giving `interrupted` with nothing stored; one
`peerbox_proposal_update` event per final state and none for a cancel; `pending_work`; the
attention item; the untrusted text a test can reach, each shown quoted and escaped by
`approvals show` and `approve`: the repository path and the default title (its directory's
name) holding control characters, terminal escapes, `"` and `\`, and a repository author's
and committer's name and email holding control characters and terminal escapes (Git refnames,
`peerspan invite` labels and membership labels cannot hold control characters, so `branch`,
`label` and membership labels are covered by the rule, not by a case); no route budget consumed; and no adapter or peer route that
approves.

`peerbox_gate` (second tier) covers, with the fake runtime: a candidate writing outputs and a
checker echoing a `PEERBOX-GATE` line; promotion with enough gain and the frontier moved,
`below_margin` for less, in both directions and for both score sources; `check_failed` for a
missing or malformed line, `pass` false and a failed check run, and `run_failed` and
`outputs_too_large` for the candidate; a candidate printing its own `PEERBOX-GATE` line and
writing outside `.peerbox-gate/out/` changing nothing; a candidate's own `.peerbox-gate/`
entries removed; the expected outputs never in a candidate run's workspace; `frontier_failed`
pausing the gate; `not_fast_forward` rejecting before any run; the owner accepting a
different contribution during an evaluation, so the promotion swaps nothing and the
candidate is evaluated again against the new head; the owner rejecting the candidate itself
during its evaluation, which cancels the evaluation, keeps the owner's rejection and
evaluates it no more; a candidate whose changes exceed `max_changes_bytes` failing with
`outputs_too_large`; `dirty_worktree` pausing; a gate command over 4,096
bytes refused;
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
