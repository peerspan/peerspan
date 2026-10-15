# Delegation chain contract

Roadmap milestone 6, slice 4: multi-hop delegation. The design and its settled decisions are in the [delegation proposal](delegation-proposal.md) (decisions 1, 3, 4, 5, and 6). This contract extends the [task contract](task-contract.md) and the [artifact contract](artifact-contract.md).

## Model

Alice's agent on host A submits task t0 to Bob's agent on host B. Bob's agent passes part of the work on as task t1 to Carol's agent on host C. Host C must learn that the work originated with A, and must verify that B passed on only authority A gave it, narrowed or equal.

A **chain** is an ordered list of **links** carried with a task request. Link k is signed by its **issuer**, the host sending the hop-k task, and names its **audience**, the host receiving it:
- **link 0**: A to B, for t0, created by A;
- **link 1**: B to C, for t1, created by B when it forwards;
- and so on.

A task without a chain cannot be passed on. A submitter creates link 0 only when it allows delegation. Chains have at most 3 links: 3 hops past the originator (decision 4). Delegation stays within one network.

## Links

A link is a strict JSON object with exactly these fields:

| Field | Meaning |
| --- | --- |
| `network_id` | The shared network. The same in every link. |
| `index` | k, from 0. |
| `previous` | `none` for link 0; otherwise the lowercase hex SHA-256 of the UTF-8 bytes of link k−1's signed statement, a `\n`, and its `signature` as Base64 text. |
| `issuer_host_id` | The host that signs this link and sends this hop's task. |
| `audience_host_id` | The host that receives this hop's task. |
| `task_id` | The task this link accompanies. |
| `originator_agent_id` | The originating agent on link 0's issuer. The same in every link. |
| `principals` | The hosts the audience may pass the task on to: one or more of `network`, `person:<person_id>`, or `host:<host_id>`, sorted and without duplicates, at most 16. |
| `deadline` | The deadline of this link's task, UTC RFC3339 ending in `Z`. Hosts normalize a chained task's deadline to this form before signing. |
| `depth` | How many further hops the audience may create: 1 or 2 on link 0, and one less on each later link, down to 0. |
| `signature` | Ed25519 by the issuer's host key over the signed statement, in canonical standard Base64. |

The **signed statement** uses the coordination contract's encoding: lines joined by `\n`, with no trailing newline. The lines are `peerspan-delegation-v1`, then every field above except `signature`, in table order, with `index` and `depth` in decimal and `principals` space-separated.

A principal **covers** another principal as follows:
- `network` covers every principal;
- `person:P` covers itself and `host:H` for any host bound to P;
- `host:H` covers only itself.

Bindings are read from the verifier's current membership view.

**Test vector.** Host key seeds are bytes `0x00`–`0x1f` (host `host_56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c`) and `0x20`–`0x3f` (host `host_24f6ed6acbfe1009c030d7ca567c33ca4830911498236b5561a6c82abec5de28`).
- **Link 0:** signed by the first key, with the following fields:
  - network `net_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`;
  - index 0, previous `none`;
  - issuer the first host, audience the second;
  - task `task_00112233445566778899aabbccddeeff`;
  - originator agent `agent_0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f`;
  - principals `network`, deadline `2026-10-10T00:00:00Z`, depth 2.

  Its signature is `S2sFkjmIIkmXC6D4qNIerxRpeYZ0GNL22iWGjG2TPLCX1PnV+x0sGr7rG8BfOHS4hzyQRiSh//2Rh8ZwhhliCQ==`, and its hash is `bc5f57c2363071701a685c896296288dbb90d293604e20ee6ca38153bbc474a3`.
- **Link 1:** signed by the second key, with the following fields:
  - the same network and originator agent;
  - index 1, with that hash as `previous`;
  - issuer the second host, audience `host_fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210`;
  - task `task_ffeeddccbbaa99887766554433221100`;
  - principals `network`, deadline `2026-10-09T12:00:00Z`, depth 1.

  Its signature is `p084GJDwcslS5CxDwZqspuxecXittC3XEV2UyGHMSX26xoCN49NAOFeWdfzKpRNfYoSBYaEe5nO4AGAXqyzuDA==`.

## Verification

A receiver R verifies a request from the authenticated sender S that carries `delegation`, a list of 1 to 3 links. A malformed chain returns 400. That covers a shape or ID format error, `[]` or more than 3 links, unsorted or duplicate principals or more than 16, a negative index or depth, a deadline not ending in `Z`, or a non-canonical signature. Any failed check below returns 403, including a link whose deadline has passed:
1. Every link verifies with its issuer's host key. Every issuer and audience is a current, unrevoked member of `network_id`, and so is R.
2. `index` matches each link's position, and each `previous` matches the link before it.
3. For each link k ≥ 1:
   - its issuer is link k−1's audience;
   - its audience and every one of its principals are covered by link k−1's principals;
   - its `deadline` is no later than link k−1's;
   - its `depth` is link k−1's minus 1, and not below 0.
4. The last link's issuer is S, its audience is R, its `task_id` is the request's `task_id`, and its `deadline` equals the request's `deadline` as a string.
5. Link 0 has `depth` 1 or 2, and its issuer is the **originator host**. Its `originator_agent_id` equals the originating agent, and for a single-link chain it equals the request's `origin.agent_id`, so `origin` is required.
6. No participant is blocked locally, whether by host or by bound person. Participants are every issuer, plus the originator's person.

**Authorization (decision 1).** With one link, the sender is the originator and authorization is unchanged. With two or more, R authorizes the **originator** for `task.submit`, with every other predicate of the [task contract](task-contract.md) unchanged:
- a cited grant must have the originator host as its requester host. Its `requester_agent_id`, if set, must equal `originator_agent_id`;
- a cited policy rule's principals must match the originator host, its bound person or that person's groups, or `agent:<originator host>/<originator_agent_id>`.

The sender needs no rule of its own: a valid chain that reaches it is enough. The handoff and acceptance rechecks include the chain. A failure is final: a revoked or blocked participant rejects a queued task with the reason `authorization lapsed before acceptance`. A revoked sender is refused earlier, by the peer transport.

## Who may delegate (decision 3)

The action `task.delegate` on a grant or policy rule implies `task.submit`, and also lets the receiving agent pass that task on. A nonzero `max_artifact_bytes` may pair with it alone. Routes never carry `task.delegate` (400). A host forwards a received task only when all of these hold:
- the task's request carried a chain, and its last link has `depth` ≥ 1;
- the authorization checked at acceptance included `task.delegate`. Like the artifact bound, this is stored with the task as the internal `delegable` key and never served;
- the task is `running`, claimed by the forwarding session, and has no cancellation requested;
- the new audience is a member covered by the last link's principals;
- an explicit deadline is no later than the parent's.

Depth makes a fourth link impossible, since link 0's depth is at most 2. Checks run in this order:
1. 409 when a cancellation was requested;
2. 403 when not running;
3. 403 without a chain or with a depth below 1;
4. 403 when not `delegable`;
5. 403 for an audience not covered;
6. 403 for a later deadline.

An unknown parent returns 404, and an adapter parent claimed by another session or credential returns 403.

The new link copies the last link's principals and `originator_agent_id`, with `depth` one less. The forwarded request carries the whole chain plus the new link, `origin` set to the forwarding agent, and the authorization cited by the forwarding route or the owner. A forward that fails any check returns 403, and 409 when a cancellation has been requested.

## Creating chains

- **Owner:** `task submit ... [--delegation-depth N] [--delegate-to P ...] [--parent-sender HOST --parent-task ID]`.
  - `--delegation-depth` (0 to 2, default 0) creates link 0 with that depth. `--delegate-to` sets its principals, default `network`, sorted and de-duplicated. Link 0 needs `--from-agent`, and it uses the lowest network ID the two hosts share; a missing origin or no shared network is a 400. A delegation by address instead uses the network the address resolved in ([launch contract](launch-contract.md), slice 5).
  - An owner forward's origin defaults to the parent task's target agent, and any other agent is a 403.
  - `--parent-sender` and `--parent-task` forward a running received task instead.
  - In `POST /v1/tasks`, these are `delegation_depth`, `delegation_principals`, and `parent: {sender_host_id, task_id}`.
- **Adapter routes** gain `delegation_depth` (0 to 2, default 0, nonzero only with `task.submit`), set with `adapter route add --delegation-depth`; session setup files do not set it. Route records always show it. Tasks submitted through such a route carry link 0 with that depth and `network` principals. A forward with `parent_task_id` ignores the route's depth.
- **MCP:** `delegate_task` accepts `parent_task_id`, which is sent to `POST /adapter/v1/delegations` as `parent_task_id`. It names a task this session claimed. Forwarding also requires the route to have action `task.submit`.

The local record gains `parent` (`{sender_host_id, task_id}` or null) and `delegation`, the chain it sent. The default deadline of a forwarded task is the earliest of 1 hour, the route's expiry, the cited policy's `valid_until`, and the parent's deadline. Each forward records `task.submitted` and then `task.delegated` on the forwarding host, with the subject `<peer>/<task_id>`.

## Cancellation (decision 6)

When a received task gains `cancel_requested`, its host sends a cancellation request to every task forwarded from it, using the outbound cancel rules, including retries. Each child reports its own outcome through its events, and nothing is assumed. The parent's agent decides when to confirm `cancelled` or finish anyway. Further hops propagate in the same way.

## What agents see

The receiving adapter's `task` handoff includes the request's `delegation`, and gains `originator_person_id` and `delegable`. The `task` MCP event's `meta` gains:
- `originator_host_id`, `originator_agent_id`, and `originator_person_id` (the bound person or null), all null without a chain;
- `chain_hosts`, the issuers in order, or `[]` without a chain;
- `delegable`, which is true when the task may be passed on.

## Persistence

Database version 11 adds:

```sql
CREATE TABLE task_children (sender TEXT NOT NULL, task_id TEXT NOT NULL, peer TEXT NOT NULL, child_task_id TEXT NOT NULL, PRIMARY KEY(sender, task_id, peer, child_task_id));
PRAGMA user_version = 11;
```

Older binaries reject version 11.

## Verification

`conformance/delegation.py` runs three-host and four-host chains across Go/Rust mixes, covering every implementation in each position. `peerspan-peer-probe` signs arbitrary links with a host's key, to forge adversarial chains. The suite covers:
- a two-hop and a three-hop chain, authorized by the originator's policy at the final receiver, and refused when only the sender is allowed;
- refusal of forwarding:
  - without `task.delegate`;
  - with link 0 absent or at depth 0;
  - to a host outside the principals;
  - a four-link chain (400);
  - with a later deadline;
- adversarial chains:
  - widened principals, depth, or deadline;
  - a spliced or reordered link;
  - a wrong `previous`, a bad signature, or a mismatched task ID or audience;
  - a chain replayed under a different task or to a different host;
  - an expired link;
- a blocked middle hop or originator person, and a revoked originator, both at submission and at handoff;
- cancellation propagating two hops down, with each hop's outcome reported;
- MCP `delegate_task` with `parent_task_id`, and the originator fields in `meta`;
- a link test vector signed and verified by both implementations;
- migration from version 10 to version 11.
