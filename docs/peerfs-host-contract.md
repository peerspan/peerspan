# PeerFS host integration

Status: boundary and delivery plan merged in #116 for milestone3b. No filesystem
routes, signing adapter or sharing commands described here are available yet.
Each implementation slice needs its exact wire/storage contract and independent
conformance before it can claim completion.

Tracking: [daemon bridge issue137](https://github.com/peerspan/peerspan-internal/issues/137).
The [real-machine qualification](real-network-acceptance.md) landed in
[#109](https://github.com/peerspan/peerspan/pull/109). It establishes independent
hosts and one actual managed NAT with encrypted relay, with the documented
home/mobile, two-NAT and changed-attachment limits.

## First useful result

An agent on machine B reads an explicitly shared branch from machine A in its
own local PeerFS workspace. A's owner reviews the space, branch, recipient and
read permission. B obtains a verified local tracking reference only after the
complete object closure and commit signatures verify. The same flow works over
the qualified direct and relay transports without a coordinator.

The first network slice is read-only and covers a whole branch and its history.
It does not claim path-filtered sharing. Later slices add remote writes,
home-host compare-and-swap, durability receipts and offline catch-up.

## Existing pieces and ownership

The PeerFS baseline inspected for this plan is
[6d65976](https://github.com/peerspan/peerfs/tree/6d65976f69f901f9c126edb5d90256a9ac81bef6).
Its local API, pull/push, signed commits, snapshots and mounts already exist.
The [PeerFS README](https://github.com/peerspan/peerfs/blob/6d65976f69f901f9c126edb5d90256a9ac81bef6/README.md)
describes those capabilities and the missing host integration.

| Component | Responsibility |
| --- | --- |
| PeerFS | Objects, canonical encodings, closure/integrity checks, branch/workspace state, replication algorithm, mounts |
| Peerspan host | Host identity and keys, current membership, owner-signed resource access, peer authentication, transport and encrypted relays |
| Local integration | Explicit space registration, typed signing/key lookup, and a bounded transport adapter between the two processes |
| Optional helper | Encrypted transport only; no filesystem grant or signing authority |

PeerFS stays a separate local process per space, serving its private Unix
socket. Rust is the default host implementation here; the separately maintained
Go host implements the same external contract. Replication and filesystem code
remain in PeerFS rather than being duplicated in the two host implementations.

The current PeerFS CLI/API uses local sockets for pull and push. Its
[Remote interface](https://github.com/peerspan/peerfs/blob/6d65976f69f901f9c126edb5d90256a9ac81bef6/crates/peerfs-core/src/sync.rs)
already separates branch lookup and object fetch. An adapter through the daemon
and changes to the local API still need implementing; the existing local-socket
pull is not cross-host evidence.

## Local boundary

### Explicit registration and process lifetime

The owner explicitly registers one local space with one selected network and
an opaque space identity. The host retains a private mapping to the space's
Unix socket. Shared requests carry a space identity, never an absolute local
path or a caller-selected socket.

Registration verifies an owner-controlled socket and space directory, the
serving process's local account where the platform exposes it, and the expected
PeerFS identity/protocol. Replacement must not silently redirect an existing
registration to a different space. Exact registration identity, replacement,
permissions and response shapes are the first wire-contract slice.

Registration alone grants no remote access and no access to an agent. It
does not import files, scan projects, create a filesystem, or start another
owner's process. Existing guided project attachment still has
`share_files:false`; a later explicit filesystem review supplies that consent.

The processes have independent lifetimes. A stopped or incompatible PeerFS
provider produces a bounded unavailable result without losing registration,
changing grants or restarting the host. A host restart preserves committed
registration; recovery revalidates the selected local provider. Neither daemon
holds its database/space lock while waiting for the other process.

The local administration boundary remains the owner account, as for
`admin.sock` and `peerfs.sock`. The host must expose only the selected filesystem
operations over the authenticated peer router. The private administration,
signing, import/export, workspace and mount APIs are never proxied wholesale.

### Host-backed signing and key lookup

Use PeerFS's existing
[Signer and HostKeys interfaces](https://github.com/peerspan/peerfs/blob/6d65976f69f901f9c126edb5d90256a9ac81bef6/crates/peerfs-core/src/sign.rs).
The host signs; PeerFS receives public keys and signatures only. A host-backed
space must fail when the selected signer is unavailable, without falling back
to a per-space key file or creating a new identity.

The local signing operation is typed for a registered space's canonical
unsigned PeerFS commit. It validates the complete current commit encoding,
domain, bounds and exact local author host before signing. A domain prefix alone
is insufficient. It is not an arbitrary-byte signing endpoint. Commit
`author.host` is the actual `host_` ID derived from the Ed25519 public key;
free-form names and labels do not establish identity.

A host signature attests those commit bytes. It does not independently prove
the caller's agent/session identity, a trusted timestamp, branch access or
remote acceptance. No person-original, device, root or transport credential is
exported. Existing file-key spaces remain local spaces until an explicit
migration contract; integration must not silently rewrite their history or
reinterpret an old alias as a Peerspan host.

Host-key lookup uses verified retained identity/key bindings. Its result is
distinct from current membership and resource authorization. Historical
signature verification must not require that every author be online or acquire
new access rights for a removed host. Unknown bindings fail without automatic
trust-on-first-use. The exact historical-proof rules belong in the signing/key
wire contract before implementation.

Signing and key lookup must not call back into the PeerFS server that is waiting
for them. This avoids a synchronous signing request deadlocking the space server.

## Read authorization and transport

Membership, an agent-message grant, an MCP capability share, project attachment
and knowledge of an object hash do not grant filesystem access. This applies to
one person's other machines as well: sharing a space remains explicit.

The first read contract binds the signed permission to the verified network
context, owner, serving host, logical space, branch and recipient. Recipient
selection must use existing verified principal rules. Filesystem authorization
must remain distinct from an MCP capability with a similar name. The signed
encoding, canonical vectors, policy-version compatibility, issuer authority,
withdrawal and principal resolution must be settled together before peer code.
No existing policy body may gain unsigned resource metadata.

A pull selects one concrete authorized branch head. Each object fetch is
authorized against that selected branch/commit closure, within the registered
space. Objects held in another space, unrelated commits, local unsigned
snapshots and weak predecessor links are not made readable by hash knowledge.
PeerFS computes/validates the graph; the host enforces the current grant before
bytes leave the machine. Exact head-pinning and reachability operations are part
of the read wire contract, including behavior when a branch moves or disappears.

Whole-branch access includes reachable signed parent history, not only current
file contents. Path restrictions require a separate representation and filtering
contract; unsupported narrowing fails rather than expanding to the whole branch.
Withdrawal stops subsequent authorized requests/batches; it cannot recall bytes
already delivered or erase the recipient's existing local copies.

The adapter reuses Peerspan's authenticated peer transport and encrypted relay
paths. It does not open a PeerFS network listener, tunnel administration through
SSH or use helper credentials as access permission. The wire contract must set
batch/body/operation and overall pull bounds, cancellation, interruption behavior
and typed errors. Transport failure must not be reported as ready or as an empty
successful pull.

PeerFS preserves its closed-store invariant and writes the tracking reference
last. A failed or interrupted pull must not publish an incomplete reference.
Resumption fetches remaining objects under current permission, without repeating
consent or silently widening the original request.

## Delivery tasks and gates

| Slice | Reviewable result | Required evidence |
| --- | --- | --- |
| PF-0 | Boundary and delivery plan in this document | Owner review; existing behavior distinguished from proposals |
| PF-1 | [Exact local registration, signer and key-lookup contract](peerfs-local-contract.md); corresponding host/PeerFS adapters | Canonical signing vectors, strict decoding and bounds, key isolation, unavailable/restart/replacement behavior |
| PF-2 | Exact signed whole-branch `fs.read` policy and selected-head/closure protocol ([read contract](peerfs-read-contract.md), proposed) | Shared signed-policy vectors, current authority and withdrawal, denied unrelated objects and unsupported narrowing |
| PF-3 | One read-only pull through both daemons into B's local workspace | Real content/kind/hash/signature verification, complete tracking reference, interruption/resume and receiver denial |
| PF-4 | Installed direct and managed-NAT/relay acceptance on named final revisions | Same-person and distinct-person explicit sharing, withdrawal, capture/path evidence and cleanup |
| PF-5 | Remote fork/commit/publish, home CAS and durability | Separate contracts and independent acceptance; no write/durability claim from PF-3 |

PF-1 and PF-2 can be reviewed as small contracts; implementation follows each
settled contract. The first usable cross-host result requires both. Each runtime
change gets its own small PR and affected independent checks, with the same
host contract supplied to the Go repository. The tracking PR must not claim the
whole milestone complete when only a local adapter exists.

Current main uses schema29 for runtime tasks; the conversations track also has
pending storage proposals. This plan reserves no schema number and changes no
signed policy or database format. Each storage change
allocates its additive schema against current main and tests upgrade/restore;
it must not take a version reserved by another accepted track.

## Verification

New executable cases come from the settled slice contract, written by a separate
author who reads contracts rather than product implementation. Existing tests
remain. Before a feature claims completion, its cases must include:

- Registration: unregistered, replaced, wrong-account, malformed and unavailable
  providers; persistence and bounded recovery without implicit sharing.
- Signing: valid canonical commit, wrong domain/author/space, malformed or
  oversized encoding, unavailable signer, no key-file fallback or key export.
- Key lookup: exact host/key binding, unknown host, historical author verification
  and no inference of current membership or access.
- Authorization: membership-only and message/capability-only denial, exact read
  grant, wrong network/owner/space/branch/recipient, expired authority, withdrawal
  and unsupported path restriction.
- Reachability: authorized head and ancestors, a known unrelated object in the
  same or another space, unsigned snapshots and weak predecessor targets.
- Pull integrity: corrupt hash/kind/signature, missing object, changed head,
  interruption/cancellation, unchanged tracking reference on failure and
  completion after fetching only the missing closure.
- Real machines: qualified direct and actual managed-NAT/relay paths, explicit
  same-person and cross-person sharing, no SSH data path or original-key copy,
  and refusal after withdrawal. No new model turns are needed for this slice.

Exact requests, expected errors, counters and deadlines belong to each slice's
Verification section before its independent suite is written. The table above
is a delivery gate, not evidence that those cases have run.

## Decisions and discarded options

- Selected: reuse PeerFS replication/storage and keep the host as the network
  and authorization edge. Discarded: filesystem implementations inside both
  hosts; these duplicate existing code and couple mount failures to networking.
- Selected: typed local host-backed signing. Discarded: copying host/person keys
  into PeerFS or accepting arbitrary bytes after a prefix check; both broaden
  the signing boundary beyond a registered commit.
- Selected: explicit whole-branch read first, with history shown in the review.
  Discarded: implicit same-owner access, treating attachment as sharing, or
  promising path isolation through unfiltered content-addressed trees.
- Selected: small contracts, implementations and independent gates.
  Discarded: one change combining sync, mounts, policy migration, write access
  and durability; failures would be harder to isolate and review.
