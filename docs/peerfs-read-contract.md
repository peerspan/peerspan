# PeerFS whole-branch read (PF-2)

Status: proposed contract for owner review, following the [delivery plan](peerfs-host-contract.md)
(PF-2) and the [local contract](peerfs-local-contract.md) (PF-1). Decisions PF-03, PF-04 and
PF-05 in the [decision log](decision-log.md). It adds a signed policy rule family, three peer
routes and one PeerFS local API option. The verified cross-host pull that uses them is PF-3.

## 1. Scope

A person shares **one branch of one host-backed space** on one of their hosts, for reading,
with principals they name. A reader's host can then list what is shared with it, learn the
branch's current head, and fetch the objects that head reaches. It is read-only and covers the
whole branch: its current tree and every signed commit and tree its history reaches.

Not here: writes, forks, commits or publishing to the branch (PF-5); path-filtered sharing (a
request to narrow fails rather than widening); durability receipts; mounts; the reader's pull
and its tracking reference (PF-3). Membership, an agent grant, a capability share, project
attachment and knowing an object's hash still grant no filesystem access, including between one
person's own machines.

## 2. The policy rule (PF-03, PF-04)

The `peerspan-policy-v2` body gains `fs_rules`, immediately after `peerbox_rules`, or where
`peerbox_rules` would be when that is omitted. It is omitted when empty, so a policy without
filesystem rules has the same body as before. Each rule is an object with exactly these keys, in
this order:

```json
"fs_rules":[{"host":"host_aaaa…","space":"space_0f1e…","branch":"main","principals":["person:person_7245…"],"actions":["fs.read"],"allow_disconnected":false}]
```

| Key | Rule |
| --- | --- |
| `host` | The serving host: `host_` and 64 lowercase hex digits. A host honours only rules naming itself. |
| `space` | The logical space: `space_` and 32 lowercase hex digits, as in a PF-1 binding. |
| `branch` | A PeerFS branch name: 1 to 255 bytes of UTF-8, not `.` or `..`, without `/` or NUL. |
| `principals` | 1 to 64, as for rules (`person:`, `group:`, `network` and `agent:HOST/AGENT`), distinct, in ascending byte order. |
| `actions` | Exactly `["fs.read"]`. Other actions are reserved for PF-5 and are `invalid` until a contract defines them. |
| `allow_disconnected` | `true` or `false`, as for capability rules: with `true`, a reader whose membership lapsed still matches while the policy is current. |

At most 64 filesystem rules per policy, in ascending order of `(host, space, branch)`, and at
most one per `(host, space, branch)`.

- **Reading.** A host admits a policy statement whose body has the existing fields with or
  without `fs_rules`. It refuses the statement as `invalid` when `fs_rules` is present but empty,
  a rule has a missing, unknown or duplicate key, a value is out of range, or the rules are out
  of order or repeat a `(host, space, branch)`.
- **Renewal and edits.** Automatic renewal copies `fs_rules` unchanged. An edit that does not
  touch filesystem rules copies them too. When unsettled edits are re-applied (spec section
  12.1), each rule is one unit, keyed by `(host, space, branch)`, and a withdrawal wins.
- **Compatibility.** Hosts built before this contract refuse a policy whose body has `fs_rules`,
  as they refuse any unknown field (as for `runtime_rules`, RUN-5). An owner adds a filesystem
  rule only once every host in the network runs software that implements this contract, and
  `fs share` says so before it signs.
- **What it does not bind.** A rule names a space ID and a branch name on one host. It does not
  bind the space's directory, its binding, or any commit: the serving host checks those at each
  request (section 3). PeerFS commit signatures carry no space, network or branch, so a commit
  being validly signed says nothing about whether it may be read.

The implementing PR adds public vectors for the policy body with and without `fs_rules`, and
for each refused shape above, which every host implementation reproduces.

## 3. Authorization, at every request

The serving host S answers a `head` or `objects` request from an authenticated peer R about
`(space, branch)` only when all of these hold, checked in this order at each request. Discovery
is narrower (section 5): it applies step 2 and the binding's state, and contacts no provider.

1. **A live, registered binding.** S holds a PF-1 binding for `space` in state `registered`,
   its pinned directory is unchanged, and the provider answers activation's identity check
   (section 4). A `prepared` or `released` binding, or a changed directory, is refused.
2. **A current rule.** R cites a policy, `{person_id, version}`, that is the current policy of
   the binding's owner P in the binding's network, and it has a filesystem rule naming S,
   `space` and `branch`, with the action `fs.read` and a principal that matches R, as for
   runtime rules. Without `allow_disconnected`, R must also be a current member of that
   network.
3. **The branch exists** in the provider's space.

A request failing step 2 or 3, or naming a space S does not hold, is **404**, the same answer in
every case, so a peer without a rule learns nothing about which spaces or branches exist. A
request failing step 1 for a space R has a rule for is **503** (the space is not serving).
Malformed requests are **400**. Withdrawal, a rule's removal, the policy's expiry or R's lapsed
membership stops every later request and batch. It cannot recall bytes already delivered or
erase R's copies.

## 4. The provider check

Before answering a read, S checks its provider as PF-1 activation does (local contract
section 4): the same socket, account, `SO_PEERCRED` and exact `GET /v1/host-bridge` identity,
over the pinned directory. A provider that is stopped, or does not answer within the request's
bound, makes the request 503. S never starts or restarts the provider.

## 5. Peer routes (PF-05)

All on the authenticated peer router, under mutual TLS, never on the owner-local or agent
routers. Bodies and results have exactly the stated fields.

| Route | Request | Answer |
| --- | --- | --- |
| `GET /peer/v1/fs/branches?network=ID` | No body. `network` is required: a network ID. | `{network, branches:[{host, space, branch, policy:{person_id, version}}]}`: every `(space, branch)` in that network that R may read on S, sorted by `(space, branch)`. |
| `POST /peer/v1/fs/spaces/{space}/branches/{branch}/head` | `{policy:{person_id, version}}` | `{host, space, branch, head}`, where `head` is the branch's current commit, read from the provider. |
| `POST /peer/v1/fs/spaces/{space}/branches/{branch}/objects` | `{policy:{person_id, version}, ids:[ID, …]}`: 1 to 256 distinct object IDs | `application/octet-stream`: the objects, in the PeerFS object batch encoding of `peerfs pull`, in request order, with an exact `Content-Length`. |

**Discovery** lists, for the named network, each rule in the current policy of S's person P
that names S, `fs.read` and a principal matching R (step 2 of section 3, with
`allow_disconnected` as there), whose space has a binding on S in that network in state
`registered`. It applies step 2 and the binding's state only: it contacts no provider, checks no
directory, and does not say whether the branch exists or the provider is running, which `head`
answers. Each host's bindings belong to its own person, so in one network only P's policy can
name S, and the answer has at most 64 entries. A reader that shares several networks with S asks
once for each. A network R does not share with S, or one with no matching rule, answers an
empty list, so the listing reveals no membership.

**What a branch reaches.** An object is readable when the branch's **current** head reaches it:
the head commit, its parents and their history, and from each commit its tree, the trees and
file entries under it, and their chunk lists and chunks. A commit's `predecessor` (its local
snapshot) is a weak link and is not followed, so snapshots are never readable remotely, nor are
objects only a snapshot reaches. Objects held in the space but not reached, and objects in other
spaces, are not readable.

**When the branch moves.** PeerFS moves a branch only by compare-and-swap fast-forward, so a
head R was given stays reached by every later head. R may therefore keep fetching the closure
of an earlier `head` answer while the branch moves on. If the branch disappears, or no longer
reaches what R asks for, the request is 404 and R's pull fails without publishing a reference
(PF-3).

**Objects batches.** The whole request is refused when any ID is malformed (400), or is not
reached by the current head (404, naming none), so a batch cannot be used to probe which
objects exist. S asks its provider for the batch with the `within` option (section 6). The
answer is at most 16 MiB, streamed past the peer router's 1 MiB default as task artifacts are;
an object that would take the answer past 16 MiB is left for the next request, and the answer
then holds the leading objects that fit. When the first requested object alone is over
16 MiB, the request is 503, since no answer within the bound can hold it (PF-06); such an object
would be a tree or chunk list of about half a million entries. R verifies each object's identity and
kind as PeerFS pull already does.

**Bounds.** At most 4 concurrent `objects` requests per reader host; more are 429. Each request
is bounded to 30 seconds, `branches` and `head` to 5. A request that exceeds its bound is 503.
Transport failure is never reported as an empty or complete answer.

## 6. The PeerFS local API

`POST /v1/objects/fetch` gains an optional `within`, a branch name. With it, the provider
returns the requested objects only if the branch's current head reaches every one (as defined
in section 5), and otherwise refuses the whole request with 404 naming none. Without it, the
existing behaviour is unchanged, for local pulls between spaces on one host. A provider older
than this contract rejects the unknown field, and S then answers 503.

`within` is evaluated by the provider, which holds the graph; S enforces the rule and
membership before any bytes leave the machine (delivery plan, read authorization).

## 7. Owner commands

| Command | Does |
| --- | --- |
| `fs share SPACE BRANCH --with PRINCIPAL ... [--network ID] [--allow-disconnected]` | Reviews, then adds or replaces this host's rule for `(SPACE, BRANCH)` in the person's policy and signs the next version through the network's provider, as a policy edit with a version check (spec section 12.1). The review names the space, the branch, its current head and the number of commits its history holds, each principal, and that the whole history is readable. It refuses a space without a registered binding on this host. |
| `fs unshare SPACE BRANCH [--network ID]` | Removes the rule, as a policy edit. Bytes already fetched stay with the reader. |
| `fs shares [--network ID]` | This host's rules, from the current policy. |
| `fs branches --peer HOST` | On a reader: what `HOST` shares with this host (`GET /peer/v1/fs/branches`). |

The reader's `fs pull` is PF-3.

## 8. Verification

A separate author writes one compact suite from this contract (under 120 s and about 1,000
lines, second tier), using a fake provider in the style of `peerfs_activation` where a real one
is not needed, and genuine hosts in a shared network:

- **Policy:** the vectors; `fs_rules` accepted with exact keys and order, and each refused shape
  `invalid`; renewal and an unrelated edit keep the rules; an older host refuses the policy.
- **Share and unshare:** the review's fields; a space without a registered binding refused;
  `fs shares` after each.
- **Discovery:** R sees exactly its rules' branches in the named network; a peer without a rule,
  a network it does not share, and a missing or malformed `network` (400) behave as specified;
  a prepared or released binding is not listed; a stopped provider's registered branch is still
  listed, with no provider contact; two networks are listed separately.
- **Head and objects:** the head matches the provider; a batch of reached objects returns them
  in order and verifies; an unreached object, a snapshot reached only through `predecessor`, an
  object of another space and a malformed ID refuse the whole batch; the 256-ID and 16 MiB bounds
  and one over; the 4-request limit.
- **Authority:** a lapsed member refused, and admitted again with `allow_disconnected`; a
  withdrawal refuses the next batch while bytes fetched stay; another host's rule, another
  space's or branch's rule, and a `fs.read` absent from the rule all refused as 404.
- **Provider:** a released binding, a changed directory, a stopped provider and a provider older
  than `within` each refuse with their status; nothing is started.
- **Interfaces:** the three routes are absent (404) on the owner-local, adapter, pairing and
  helper routers.

## Decisions and discarded options

- PF-03: permission is a new signed policy rule family, `fs_rules`. Discarded: a grant action
  `fs.read` (manual, per recipient, and weaker at binding the signed context the plan requires);
  both a rule family and grants (more to specify, for a case nobody needs yet).
- PF-04: one branch per rule. Discarded: a list of branches per space (withdrawing one edits a
  list); a whole space (shares branches the owner has not seen).
- PF-05: discovery through `GET /peer/v1/fs/branches`. Discarded: out-of-band names only
  (every pull needs them passed by hand).
- Contract choices within them: reads authorized against the branch's current head, since
  branches only move forward; one 404 for every unauthorized or absent resource; snapshots never
  readable remotely; heads not shown in listings, so listing touches no provider.
