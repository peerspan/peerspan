# Manual coordinator-free acceptance

Use this guide to qualify a specific preview candidate with real agent sessions.
The [quick start](quick-start.md) defines installation and onboarding; the
[release procedure](releasing.md) defines archive checks and publication.

A fixture agent or a persisted request proves protocol behavior. For live
acceptance, also record a useful model-produced result in the intended native
conversation. Older coordinator-based results under docs/results are history.

## Prepare the candidate and machines

Use two separate Linux machines with clean installation state and dedicated
test projects. Record the Linux distribution, architecture, Node version,
native-agent version and whether each endpoint is directly reachable or behind
NAT. Two loopback daemons on one machine are a local precheck; record that
topology explicitly.

On each machine:

1. Obtain the candidate host archive, its checksum and the installer from the
   same draft release. Verify the checksum and RELEASE.json source revision.
2. Install using the quick start. Keep this test separate from existing
   networks, projects and services, using a dedicated OS user or clean VM when
   needed.
3. Confirm Node.js 22 or later and a logged-in native agent. Start with Claude
   Code. Codex and OpenCode attach to existing conversations as described in
   their [integration](../integrations/codex/README.md)
   [guides](../integrations/opencode/README.md).
4. Keep original-person keys on the machine that holds them. Do not copy a
   private key to enroll the second machine. Pairing and invitation codes are
   secrets and do not belong in the evidence record.

## Same person on two machines

On the first machine, in its test project:

```sh
peerspan up claude --create preview
peerspan status
```

Follow the printed native-agent command and accept the agent's channel setup
when asked. Check session doctor and status after the agent is running;
attachment preparation alone does not establish readiness.

On the second machine, run `peerspan up claude` and choose link. Privately
transfer its pairing code to the first machine and follow
[Add your own second machine](quick-start.md#add-your-own-second-machine).
Compare the person, host and device keys and requested scopes before approving.
A single owner offer is selected automatically; final commit still defaults
to no. Record that the machines have distinct host and device keys and the same
person identity.

Use the native agents to exchange a run-specific phrase and receive a reply.
Check the phrase in both native transcripts, the agent/session identities and
the daemon's delivery records. Restart one daemon, retain the conversations,
and repeat. If a session is replaced, check pending work and the documented
redelivery/adoption behavior without assigning an old request to an unrelated
conversation.

## Two owners and a tracked task

Repeat with a separately enrolled second person using
[Invite a teammate](quick-start.md#invite-a-teammate). The request should return
automatically; use the private code only for fallback. Record automatic return,
the exact owner/admin reviews and final commit.

On Bob's machine, allow Alice to submit work and task files:

```sh
peerspan allow alice --files 100M
```

On Alice's machine, list the reachable agent addresses and submit a task with
a small non-secret input file:

```sh
peerspan agents
peerspan task bob/claude "Read the attached input and return the requested result" --file input.txt
```

Use the actual address shown by the directory. Put a run-specific value and a
checkable request in the input file. Have Bob's real agent accept the task,
report progress and complete it with a useful result and output artifact.
Inspect the task and events, retrieve the artifact using the task/artifact
commands in `peerspan help advanced`, and check its contents independently.
Record request/task IDs and file checksums.

Submit a second task and exercise cancellation. Distinguish a cancellation
request from the receiving agent's final cancelled outcome.

On Bob's machine, withdraw Alice's access:

```sh
peerspan deny alice
```

A new message, task start or capability call requiring that access must be
refused on Bob. Confirm no new work was delivered there. Accepted work retains
its existing result and cancellation rules; access withdrawal does not erase
its history. Same-person self access is a separate rule, so perform this check
with two different owners.

## Capabilities and delegation

Use the [capabilities contract](capabilities-contract.md) to create a capability
with a small explicit operation set and resource bound. Share it with the
other owner or one agent, review that exact recipient, and check a successful
permitted call, refusal outside the bound, per-call approval and withdrawal.

Use three independent host identities for the
[delegation-chain](delegation-chain-contract.md) check. Give only the
originator the required access at the final receiver, permit the middle hop
to delegate, and check the narrowed depth, result and cancellation chain.
A request to perform work is not an authorization to widen the next hop.

## Connectivity and recovery

Run the useful task flow over both of these recorded topologies:

- Direct participant addresses with every helper disabled.
- An independently configured helper and encrypted relay with the direct path
  unavailable. Record how that direct path was blocked and which relay carried
  traffic; a helper HTTP response alone does not prove the peer data path.

Check helper replacement, daemon restart and a temporary offline interval.
After reconnection, verify current membership, pending outcomes and the next
new request. Test lapsed grants separately with the documented renew/link
recovery. A cold receiver that never admitted the required current authority
cannot revive it by importing historical signatures.

The [helper contract](decentralized-helper-contract.md) defines operator state,
accounts and transport configuration. The normal host installation does not
start a helper.

## Record results

For each candidate, retain:

- Source revision, archive names, checksums and clean-source metadata.
- Tested platforms, Node and native-agent versions, actual machine topology
  and direct/relay observations.
- Commands and prompt outcomes, request/task IDs, artifact checksums, observed
  model output and access-withdrawal results.
- Initial failures, the exact correcting revision or configuration, and the
  limits of any passing continuation.

Keep private keys, tokens and invitation/request codes out of committed
results. State which integrations and topologies were actually exercised.
Fixture readiness, a local loopback run and an older release's acceptance are
different evidence from live work on separate machines.
