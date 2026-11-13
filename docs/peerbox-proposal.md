# Peerboxes: sharing a repository for review and checks

Status: **accepted on 2026-11-13.** The owner chose the recommendation of each of the six
[decisions](#decisions), recorded as
[PBX-1 to PBX-6](decision-log.md#pbx-1-to-pbx-6-peerboxes-2026-11-13). The
[peerbox contract](peerbox-contract.md) specifies the result. Nothing is implemented yet.

A **peerbox** is a Git repository that one owner's host serves to other people already in the
same Peerspan network. Their agents, still on their own hosts, fetch an exact revision, submit
a contribution branch, and ask for checks to run on the exact submitted commit in a microVM on
the peerbox's host. The owner reviews each contribution with its run results and accepts or
rejects it; the contributor sees the decision. The peerbox's host serves its repository,
review queue and runs; it does not become a coordinator or an identity authority for other
hosts.

This is the first slice: known peers (already admitted to the network), one repository and
one protected branch per peerbox, one home host. It extends the [task contract](task-contract.md),
the [artifact contract](artifact-contract.md) and the [runtime task contract](runtime-task-contract.md).
The [Playbox](https://github.com/Epistetechnician/playbox) project's rooms are the reference
for the experience: member-only refs, bundle verification, fast-forward-only review with a
rebase request, and its hostile-input cases. Its transport, grant and wire formats are not
used.

## Story

Alice keeps a project on her workstation, which also runs the Peerspan runtime. Bob, in the
same network, works on his own laptop.

1. Alice creates a peerbox for her repository's `main`. Peerspan shows what a read discloses
   (the branch, its head, the reachable commit count, the authors' names and addresses, the
   bundle size) and asks her to confirm.
2. Alice shares it with Bob for read, submit and run. That signs a new version of her policy.
3. Bob's agent lists Alice's peerboxes, fetches `main` into a local repository, makes a change
   on a branch and submits it.
4. Bob's agent asks for `cargo test` on the submitted commit. Alice's host builds the
   workspace from that commit's tree and runs it in a microVM under her runtime rule.
5. Alice reviews the contribution, its diff and the run, and accepts it; `main` fast-forwards.
   Bob's agent sees the decision.
6. Either host restarts at any point and both continue. When Alice withdraws Bob's access, no
   new fetch, submission or run is accepted from him, and a run of his that has started is
   cancelled.

## Goals and non-goals

Goals: an exact revision and its history fetched and verified; contributions confined to the
contributor's own refs; runs that execute exactly the submitted commit under both the peerbox
and the runtime authorization; a durable review decision visible to the contributor;
recovery across restarts on both sides; withdrawal that stops new work.

Not in this slice: admitting strangers through a link; several protected branches or path
filtering in one peerbox; merging (accept only fast-forwards); replicas or failover of the
home host; PeerFS-backed peerboxes; signed run receipts or attestation; agent tools (a later
amendment, after the CLI); the Go host (DEC-OWN5).

## Decisions

### 1. Where the contract lives

**Recommendation.** (a) "In peerspan/peerspan `docs/` once agreed, like every other host
contract; the public repository then names peerboxes before launch."

**Not chosen.** (b) "Here until the feature is demonstrated, then moved" (in the internal
design repository). Suites and Codex review need the contract next to the code.

### 2. How peer operations travel

**Recommendation.** (a) "Peerbox tasks (`executor: "peerbox"`), inheriting task durability,
idempotency, artifacts and restart."

**Not chosen.** (b) "New peer routes for each operation." It would re-specify everything
tasks already guarantee.

### 3. Repositories larger than one artifact

The artifact file limit is 100 MiB.

**Recommendation.** (a) "Fail with `too_large` and rely on `have` for later fetches; a first
fetch of a large history is refused." For the first slice; this repository's own history is
the case to measure.

**Not chosen.** (b) "Raise the per-file limit for peerbox bundles." (c) "Split bundles."

### 4. A started run when access is withdrawn

**Recommendation.** (a) "The home host cancels it." The run is the owner's own machine
executing someone else's code, and Playbox stops it too.

**Not chosen.** (b) "It runs to completion, as runtime tasks do today."

### 5. Invitation

**Recommendation.** (a) "The signed rule is the invitation; the peer sees the peerbox in
`list` and fetches when they choose." For known peers.

**Not chosen.** (b) "A separate invitation the peer accepts first." It belongs with stranger
admission, which is out of this slice.

### 6. Runtime release

Product acceptance needs the runtime installed on the home host, and `peerspan/runtime` has
no release.

**Recommendation.** (a) "Publish a first runtime release before" the two-owner product
acceptance.

**Not chosen.** (b) "Accept a source-built runtime for acceptance and record it."

## Plan

1. This proposal, the contract and the decision-log entries.
2. The `peerbox` and `peerbox_runs` suites, written from the contract by the separate
   conformance author, landing as strict `XFAIL` cases.
3. Slice A: peerbox records, the rule, `list` and `fetch`, with the CLI.
4. Slice B: `submit`, member refs, `status`, review, withdrawal and restarts.
5. Slice C: `run` from a commit's tree.
6. Agent tools for Claude Code, Codex and OpenCode, as a contract amendment.
7. A first `peerspan/runtime` release (PBX-6).
8. Product acceptance on two machines owned by different people, with real agents and a KVM
   home host: create, share, fetch, edit, submit, run, review, restart and withdraw, recording
   commands, revisions, outputs, refusals and manual repairs.
