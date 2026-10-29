# Coordinator-free networks

Status: **Current coordinator-free contract.** This spec takes the
coordinator-free design of 2026-10-26 (the nine `docs/decentralized-*.md`
files) and applies the owner's decisions of 2026-10-27, logged as
[DEC-S1 to DEC-S17](decision-log.md#dec-s-simplifying-the-coordinator-free-design-2026-10-27),
and the owner's answers to the 25 questions the first draft left open, logged
as [DEC-Q1 to DEC-Q25](decision-log.md#dec-q-answers-to-the-open-questions-of-the-first-draft-2026-10-27).
Exact bytes, IDs and sizes are in the
[wire-format appendix](decentralized-wire-formats.md).

- **Decided.** Every point in this spec is decided. Section 19 lists how each
  question of the first draft was resolved.
- **Earlier contracts.** This spec and its wire appendix supersede conflicting
  behavior in the nine 2026-10-26 contracts. Those files retain detailed
  implementation references and historical verification plans. The active
  implementation is Rust; Go/Rust pairing gates were retired by DEC-OWN5.
- **What this does not change.** Tasks, messages, capabilities, sources,
  agents, sessions, attachments, per-call approvals (schema 20), resource bounds
  and the `gh` source (schema 21), and remote MCP and OAuth (schema 22) keep
  their contracts and their `/v1` routes. Only how a host decides that another
  host or person belongs to a network, and what they may do in it, changes.

## 1. Overview

A network has no central server. Each network has a **root key**. The root,
administrators and people sign short-lived **grants**. Every host keeps a copy
of the signed records it knows, checks them itself, and passes them to the
other members. A host lets a peer in only if that peer's grants, checked
locally, are valid now.

- **Grants are short.** Most last at most 7 days. Policies and groups last at
  most 24 hours. Hosts renew them automatically about 2 days before they
  expire.
- **No quorum.** Ordinary work never waits for another host. A host that cannot
  reach anyone keeps working until its grants expire or it learns of a ban.
- **Joining** uses an invite code. The new machine's request travels back to
  the inviter by itself. One prompt on the new machine confirms the link.
- **Helpers are optional.** A helper is a small server that holds encrypted
  mailboxes and forwards encrypted packets. It cannot admit anyone, sign
  anything or read traffic. Nothing Peerspan operates is required.
- **Old coordinator networks** stay as read-only history. Their members move by
  being invited to a new network with `network reinvite`.

## 2. Terms

Each term is defined once here and used with this meaning throughout.

| Term | Meaning |
| --- | --- |
| **Network** | A set of hosts and people that share signed records under one descriptor. |
| **Descriptor** | The fixed description of a network: protocol, network ID, name and genesis root key. It has no address. |
| **Context ID** | `ctx_` plus a hash of the descriptor. Every signed record names it, so a record cannot be replayed in another network. |
| **Network ID** | `net_` plus the lowercase hex SHA-256 of the genesis root public key, as in the [coordination contract](coordination-contract.md). |
| **Root key** | The key at the top of a network. The first one is the **genesis root key**. It may be rotated. |
| **Root state** | A signed record naming the current root key and its epoch (a counter starting at 0). |
| **Host** | One `peerspan-host` daemon, identified by its **host key** (Ed25519). |
| **Person** | A human identity, identified by an **original person key**: an `ssh-ed25519` key that stays on the person's own machine and signs in OpenSSH SSHSIG format. |
| **Device key** | A per-machine Ed25519 key that acts for a person on one host after linking. The daemon holds it. |
| **Administrator (admin)** | A person holding an admin grant from the root. Admins admit people and hosts. |
| **Grant** | A signed, time-limited permission: admin, person, host, binding, device, policy or group. The 2026-10-26 files call these *leases*. |
| **Binding** | The grant that says "this person owns this host". |
| **Scope** | A bit mask on a device grant: 1 edit policy, 2 bind hosts, 4 approve, renew and revoke devices, 8 network admin. 15 is all four. |
| **Restriction (ban)** | A signed record that withdraws a role, removes a person, revokes a host or device, or unbinds a host. |
| **Statement** | Any signed record above, in the common envelope. |
| **Statement ID** | `ds_…`, a hash of a statement's kind, context and payload, leaving out the signatures. |
| **Proof ID** | `dp_…`, a hash of a statement's exact bytes, signatures included. |
| **Stream** | The sequence of generations of one grant, for example the device grants of one device. Each generation has a higher sequence number. |
| **Head** | A stream generation that no other known generation replaces. One head is normal. Two or more is a **fork**. |
| **Catalog** | A list of exact signed records exchanged between hosts. |
| **Invite code** | A `psi2-` code made by the inviter. It introduces the network and the inviter and carries a return path. It grants nothing. |
| **Request code** | A `psl2-` code made by the new machine. It carries its join request and a 128-bit pairing secret. For an invite-based join it is printed only when the automatic return fails; `link` without an invite always prints it. |
| **Join (link) request** | The six- or seven-stage signed exchange that admits a new machine or renews a device. |
| **Activation** | The finished, complete record of a join request. Any host can check it. |
| **Helper** | An optional `peerspan-helper` server that offers mailboxes and a relay. |
| **Mailbox** | A short-lived store of encrypted frames for one join request, on a host's first-contact listener or a helper. |
| **Signing plan** | A stored, typed list of exactly what the daemon or the CLI will sign for one operation. Its ID is `dint_…`. |
| **Provider** | The signer a host uses for a person's grants: the original person key or one owned device key. |
| **Decision time** | The time a host uses for every check: the later of its clock and the latest time it has recorded. |
| **Legacy network** | A network created with a coordinator before this design. |

## 3. Processes, keys and files

| Item | What it is |
| --- | --- |
| `peerspan-host` | The host daemon. It keeps the state database, checks records, serves the listeners below and signs with keys it owns. |
| `peerspan` | The CLI. It talks to the daemon over the private Unix administration socket. It signs with an original person key or an external root key on the user's machine, never inside the daemon. |
| `peerspan-helper` | The optional Rust mailbox and encrypted relay helper. |
| Host key | The daemon's existing Ed25519 identity. It signs contacts, packets, frames and its own role in host grants and bindings. |
| Device key | 32-byte seed in the existing `link_device_keys` table. One per person per host after linking. |
| Root seed | The existing `networks.root_seed` column, when the root key is a raw key held by this host. A root moved to an SSH key is not stored. |
| Original person key | An SSH key file or `ssh-agent` key on the person's machine. It never enters the database, a helper or another machine. Automatic renewals never need it: they use device keys (DEC-Q21). |
| State database | SQLite, schema 23 (17 `dec_*` tables, section 17). |
| Transport file | Optional JSON file given with `serve --transport-config PATH`, naming helpers and advertised addresses. |
| Helper state | `$XDG_STATE_HOME/peerspan/helper`, else `$HOME/.local/state/peerspan/helper`. |

Listeners and protocols:

| Listener / ALPN | Who may connect | What it serves |
| --- | --- | --- |
| Administration socket | The local owner | All `/v2` and existing `/v1` owner routes. |
| Peer QUIC (existing) | Hosts that are current members | `/peer/v2/...` catalog and contact routes, plus existing task and capability peer routes. |
| `peerspan-state-repair/1` | Hosts this host once admitted and has not revoked | One read-only catalog route for repair. |
| `peerspan-bootstrap/1` (HTTP/1.1 over TLS) | Any key | Mailbox routes and the two completion routes. Nothing else. |
| `peerspan-completion/1` (QUIC) | Participants of one join request | The two completion routes only. |
| `peerspan-relay/4` | Any key, subject to helper quotas | Forwarding of encrypted QUIC datagrams. |

Unknown keys never reach the administration socket, peer routes, repair route,
tasks, capabilities or signing. A listener that shares a physical port selects
its router by ALPN before reading any application bytes.

## 4. Records and how a host checks them

### 4.1 Statements

Every grant, root state and restriction is a **statement**: an envelope holding
the kind, context ID, the exact payload bytes (Base64) and a list of
signatures, one per role. The appendix gives the envelope, the signing message
and the ID formulas.

- **Signature formats.** An original person key always signs SSHSIG with
  namespace `peerspan-person-v1`. Host and device keys sign raw Ed25519. The root
  may use either.
- **Exact bytes.** A writer serializes a payload once and keeps those bytes.
  Retries resend the same bytes. Nobody re-serializes signed JSON.
- **Aliases.** Two envelopes with the same statement ID but different exact
  bytes (for example, a different but valid signature encoding) are aliases.
  Both are kept under their own proof IDs. They add no authority and no extra
  head. Every alias present must verify: a valid signature by the wrong key
  makes the statement invalid. Two different payload serializations are two
  different statements.
- **Strict parsing.** Unknown, missing or duplicate fields, nulls, floats,
  negative numbers, non-canonical Base64 and wrong types are rejected before
  any signature check. Numbers declared u64 accept the full range.
- **Limits** are in the appendix (statement 1 MiB, payload 256 KiB, catalog
  16 MiB and 4096 objects, device depth 8).

### 4.2 Streams, heads and forks

Each grant belongs to a stream: `admin/PERSON`, `person/PERSON`, `host/HOST`,
`binding/HOST`, `device/PERSON/DEVICE`, `policy/PERSON` or `group/NAME`. The
root has its own chain of root states.

- A new generation names the head it replaces in `predecessors` and has a
  higher `sequence`. The first generation has sequence 1 and no predecessors.
- **Fork.** Two valid generations, neither replacing the other, form a fork,
  even if their sequence numbers differ. A fork freezes positive authority in
  that stream: nothing in it grants anything until a **resolver** replaces every
  known head. A resolver lists all known heads in both `predecessors` and
  `resolves`, has a higher sequence, and is signed by someone with current
  authority over the stream. A higher write on one branch does not end a fork.
  Learning a new branch reopens it. No hash, timestamp or sequence picks a
  winner.
- **Root forks** are different: they cannot be resolved (section 13.2).
- **Per stream.** A fork, or a missing record, affects only its own stream. A
  valid ban in another stream is still learned and applied.
- **High-water.** A host remembers the highest admitted sequence of each stream
  forever. An older generation never becomes active again, even when the newest
  one expires. A fresh generation at sequence 2^64−1 cannot be made
  (`version_exhausted`).
- **First admission.** A host admits a new statement only if its signer's
  authority is valid now, at decision time, through records the host already
  trusted. Records arriving in the same batch cannot authorize each other. A
  backdated statement from an expired or revoked signer is kept as inert
  evidence only.

### 4.3 Decision time

Each host keeps, per network, the latest time it has used (table `dec_clock`).
Decision time is the later of the local UTC clock and that stored time.

- If the local clock is more than 300 seconds behind the stored time, every
  signing and admission is refused with `clock_rollback`. Smaller steps back
  use the stored time.
- The stored time only moves forward, and only from the local clock. Times in
  records from peers or helpers never move it.
- Reads and status never write it. A refused mutation may still store the new
  time and nothing else.
- Statements whose `issued_at` is later than decision time are kept but have no
  effect until then.
- Restoring a whole backup also restores an older stored time. The design does
  not protect against that.

### 4.4 Validity windows

Each grant has `issued_at`, `not_before` and `not_after`, in whole UTC seconds.

- `issued_at ≤ not_before < not_after`.
- `not_after − issued_at` is at most 604,800 seconds (7 days) for admin, person,
  host, binding and device grants, and at most 86,400 seconds (24 hours) for
  policies and groups.
- `not_after` is at most the `not_after` of every parent (section 5), except
  that a deadline-only renewal signed by a device is not capped by that
  device's grant (section 7.1, DEC-Q7, DEC-Q27).
- A grant is usable when `not_before ≤ decision time < not_after`. There is no
  grace period.

## 5. Grants and who signs them

| Grant | Who may sign | Parents (all must be current) | Extra signature |
| --- | --- | --- | --- |
| Admin (scopes 8) | The current root only | None | — |
| Person (scopes 0, member label) | The root, or an admin acting through a scope-8 path | For an admin signer: the admin's person and admin grants, plus the admin's device grant if a device signs | — |
| Host (scopes 0, member label) | The root, or an admin | As for person | The host itself (target consent) |
| Binding (scopes 2) | The person's original key, or the person's device with scope 2; a renewal may also be signed by a scope-4 device (DEC-S9, DEC-Q10) | The person grant, the host grant, and the signing device's grant | The host itself |
| Device (scopes 1–15, at most the signer's) | The person's original key, or the person's device with scope 4 | Person, host and binding grants, and the signing device's grant | Target host and device prove possession inside the join request |
| Policy (24 h) | The person's original key, or the person's device with scope 1 | Person grant (and signing device's grant) | — |
| Group (24 h) | The root, or an admin | As for person | — |

Rules that apply to the whole table:

- **Admin is not owner.** The root and admins cannot sign a binding, device
  grant or policy for another person. Only that person can, with the original
  key or their own devices.
- **Member labels** are 1–128 bytes of trimmed UTF-8 with no control
  characters. A person's grant and that person's hosts' grants carry the same
  label. Labels never replace keys.
- **Device chains.** A device can sign a grant for another device of the same
  person. The chain from the original key is at most 8 devices deep and may not
  repeat a device key. A device's scopes are at most its signer's scopes.
- **Using a grant requires its whole chain.** A device is usable only while its
  person, host and binding grants, every signing ancestor, and the root state
  are current and not banned. For an ancestor device, "current" means its device
  stream has a current, unrevoked head (DEC-Q29).
- **Original-key ceilings.** An original-person signature is capped by its
  declared person ancestry and, for administrator work, its admin ancestry.
  The unrelated host or binding grant on the machine holding that key does
  not shorten the new statement. The signing host still needs current local
  membership when it approves and signs.
- **New-person exception.** A brand-new person has no person grant until an
  admin issues one inside the join request. Within that one request, the new
  person's original key may use that pending person grant to sign its own
  binding and device grant. It authorizes nothing else, and nothing in the
  request takes effect until the requester's final commit.
- **Operation binding.** A grant signed inside a join request names the
  request ID in `operation_id` and stays inert until the complete request is
  verified. Other grants use `operation_id` `-`. The only device grants with
  `-` are the creator device grant (section 6) and deadline-only renewals
  (section 7.1).
- **Manual grants are separate.** An owner's manual grant to a peer
  (`allow_disconnected: true`) works on its own terms after a network grant
  expires. With `allow_disconnected` false or omitted it still needs current
  network membership. Marking a peer as known proves identity only.
- **Accepted work.** Expiry or a ban stops new task starts, queued starts,
  delegation hops and calls. Work already accepted keeps its existing outcome,
  result and cancellation rules.

### 5.1 Bans (restrictions)

| Kind | Who signs | Effect |
| --- | --- | --- |
| `admin_withdraw` | The root | Ends one admin grant generation. Its `kept_statement_ids` lists the person and host grants that admin issued which stay valid; the CLI keeps every eligible one by default (DEC-Q13). A new admin grant may later list the withdrawal in `resolves`. |
| `person_remove` | The root or an admin | Permanent. The person loses admission, bindings, devices and policies in this network. |
| `host_revoke` | The root or an admin | Permanent. The host loses membership. |
| `host_unbind` | The person (original key or scope-2 device) | Ends one binding. A new binding signed by person and host may list the unbind in `resolves`; old device chains do not come back. |
| `device_revoke` | The person's original key, or a scope-4 device that is an ancestor of the target | Permanent. The device and every device below it stop. A device cannot revoke itself, an ancestor or a sibling. |

- A host admits a ban only if its signer is current at decision time. Once
  admitted, a ban stays in force forever, even after its signer expires.
- A ban from a signer that is no longer current can be **ratified**: a current
  signer with the same power signs a new ban whose `ratifies` names the old
  one, with the same target and kept list.
- A host stores and applies its own bans before it tries to send them.
- Invite codes are not grants, so there is no invite revocation.

### 5.2 Known limits

- A stolen root key or original person key can sign fresh grants with no time
  limit until the theft is known.
- The 7-day limit bounds one generation of grants. It does not promise that a
  ban reaches every host within 7 days: a signer who has not heard of a ban can
  still sign a new grant.
- A stolen scope-4 device can keep its siblings renewed until it is revoked. It
  cannot renew itself (DEC-Q8), so it expires unless a sibling renews it. The
  creator device can renew itself while it is the creator's only current device
  (DEC-Q27, DEC-Q30) and is then stopped only by a ban.

## 6. Creating a network

`peerspan network create NAME [--as MEMBER] [--person-key-file PATH]` runs
locally. It needs no coordinator, helper or peer.

1. The daemon creates a raw root seed and the genesis root state.
2. The root signs an admin grant, a person grant and a host grant for the
   creator. The host signs its own role in the host grant.
3. The creator's original person key signs the binding (the host also signs
   it), the first policy and a **creator device grant**. The key is chosen by
   the existing rules: the explicit file, the configured owner key, or a newly
   generated protected key the user approves.
4. One transaction stores the network, its records, the new device key, the
   device provider and one `network.created` event.

**Creator device grant (DEC-Q21).** The daemon generates a device key for the
creator's host. The original key signs a device grant for it with scopes 15,
sequence 1 and `operation_id` `-`, with the genesis person, host and binding
grants as parents. The creation approval is the device's consent; there is no
join exchange. This is the only new device grant made without one. The device
renews the creator's policy and other devices like any scope-4 device. As the
one exception to the no-self-renewal rule, it also renews its own device grant
and the creator's binding (DEC-Q27), but only while it is the creator's only
current device. Once the creator has another current device, normal sibling
renewal applies (DEC-Q30). Adding the creator's other machines
uses the join request like everyone else. `--coordinator` and `--coordinator-key` are
refused on `create`, `join`, `link` and `up`.

The API is `POST /v2/networks` with `{name,member,person_public_key,approve}`,
then signatures through `POST /v2/network-creations/{id}/signed`. A preview
(`approve:false`) creates nothing usable. At most 8 unfinished creations exist
per host.

## 7. Renewal

### 7.1 Who renews what

Grants are renewed **automatically** by hosts that hold a suitable signer,
at the thresholds below. Nobody runs a renew command.

| Grant | Renewed by |
| --- | --- |
| Admin | The root. The host holding the root seed renews every current admin grant. |
| Person, host | The root or an admin. A deadline-only renewal needs only the issuer's signature, not the target host's (DEC-Q28). |
| Device, binding | The person's original key, or any other of that person's devices with scope 4. Scope 2 also renews a binding. A deadline-only binding renewal needs only the issuer's signature and, when a device signs it, is capped by the person and host grants only (DEC-Q27, DEC-Q28). |
| Policy | The person's original key, or the person's scope-1 device. |
| Group | The root or an admin. |

**Thresholds.** A host starts renewing a 7-day grant when 2 days (172,800
seconds) remain, and a 24-hour policy or group when 8 hours (28,800 seconds)
remain (DEC-Q24). The root host starts renewing root-signed grants (admin
grants and root-signed person and host grants) when 4 days (345,600 seconds)
remain (DEC-Q12).

- A renewal is a new generation of the same stream: same subject, same or
  fewer scopes, a later `not_after`. More scopes or a higher grant need the
  original key or a new join request. A scope-4 device still approves a
  brand-new device through the join request (DEC-Q9).
- **Deadline-only renewal (DEC-Q6).** When only the deadline moves (same
  person, host and device keys, same or fewer scopes, target grant still
  current) the renewal is an ordinary signed statement with `operation_id` `-`,
  not a join request, and needs no target consent. An expired device needs a
  join request in `renew` mode (section 8.6).
  An original-person signature also preserves the target device's existing
  `issuer_device` parent, if any, and its ordinary ancestor deadline caps.
  Automatic renewal never resets the device's delegation ancestry.
- **Sibling renewal (DEC-Q7).** A device grant renewed by another device of the
  same person keeps the target's existing `issuer_device` parent; the renewer
  appears only as the `issuer` signer. The renewer must be current, the same
  person and hold scope 4 when it signs, but its own deadline does not cap the
  renewal. The renewal is capped by the person, host and binding grants. Depth,
  the no-repeated-key rule and revoke rights follow the target's original
  chain. A device may not renew its own grant (DEC-Q8), except the creator
  device while it is the creator's only current device (section 6, DEC-Q27,
  DEC-Q30). An ancestor device counts as current while its
  device stream has a current, unrevoked head, not only the exact generation
  named as parent, so renewing A keeps a device that A first issued alive; a ban
  on A still stops it (DEC-Q29). A verifier finds the signer's own grant as the
  current head of the device stream `device/PERSON/SIGNING_KEY`, and checks it is
  current, unbanned and holds scope 4 (DEC-Q31).
- **Who runs it (DEC-Q11).** Each host checks every 60 seconds, with its sync,
  which grants it may renew are inside their threshold. Hosts able to renew a
  grant take turns in a ranked order: the original key's host first, then
  devices by host key. With K ranked signers and a renewal window W, signer
  number i (from 0) starts at i × W ÷ (K + 1) into the window, so the last
  one still starts before expiry. Each syncs with known peers (30-second bound)
  before signing and skips grants already renewed. If two plain renewals with
  the same subject and scopes still fork a stream, the next renewal resolves
  the fork automatically; any other fork waits for the owner.
- **Warnings.** For person-signed grants, status warns only when a grant this
  host needs is inside its renewal threshold and no host able to renew it has been
  reachable; the attention item is `person_device_signer_unavailable`.
  Root-signed grants use the countdown in section 7.3 instead.
- **Approval (DEC-Q22).** A deadline-only renewal is approved by the approval
  that created the grant. The daemon makes and signs its plan with no new
  review. There is no switch to turn this off.

### 7.2 Keeping children (retention)

Renewing a grant does not by itself keep the grants signed under it. Each
renewal lists the children it keeps in `retained_statement_ids`. The record
format is unchanged from 2026-10-26.

- **Automatic list.** The signer fills the list with every child it knows that
  is current and not banned, plus each older record those children still need.
  The user never edits it.
- **Removing a child** is done only with a ban: revoke (permanent) or unbind
  (undoable). Leaving a child off the list is not a way to remove it.
- **Unknown children.** A child the signer has not seen is not on the list. It
  becomes inert as soon as the renewal is admitted, not at its own deadline,
  and must be issued again. Hosts sync before
  automatic renewal to make this rare.
- **What a host checks** for each listed child: it was valid just before the
  renewal, its whole chain is listed or still current, and it fits the replaced
  grant's role and scopes. A listed child keeps its original deadline; the list
  never extends it.
- **Narrowing carries down.** A retained child's effective scopes are the
  intersection of its own scopes with those of every retaining device
  generation, so narrowing a device on renewal removes the same powers from its
  retained children and policies. With DEC-Q29, the current head of each
  ancestor device stream also caps them. Person, host and admin grants are
  checked by role, not as scope masks. Retention cannot revive a child that was missing, banned,
  forked or expired, and cannot list the renewal itself.
- **Root rotation** lists the grants it keeps in the same way (section 13.1).
  The previous root states are not listed; they are part of the root chain.

### 7.3 When the root is offline

Admin grants come only from the root, so a network whose root host stays
offline stops when the last admin grant, and everything signed under it,
expires.

- The host holding the root seed renews admin grants automatically. Run it on
  an always-on machine. `network rotate-root` moves the root to another key
  (section 13.1).
- Because the root host renews root-signed grants 4 days early, the countdown
  appears only when a renewal was missed. When N ≤ 3, every host's status
  shows the attention item `network_root_unreachable` with the text
  `root unreachable: network stops in N days`. N is the number of whole days,
  rounded up, until the latest `not_after` among all current admin grants and
  root-signed person and host grants; after that nobody can renew without the
  root (DEC-Q12).
- A root held as an external SSH key renews automatically only when that key is
  usable by the root host's daemon, for example through `ssh-agent`.

## 8. Joining and linking

### 8.1 The flow

1. **Invite.** On a member host: `peerspan invite MEMBER [--expires-in D |
   --expires-at T] [--network ID]`. It prints a `psi2-` invite code. The code is
   valid for 1 hour by default, at least 60 seconds and at most 24 hours
   (DEC-Q2). The inviter sends it to the new person by any private channel.
2. **Join.** On the new machine: `peerspan join`. The code is read from a hidden
   prompt or `--invite-stdin`, never from a command argument. The CLI shows the
   network name, root fingerprint, inviter host, proposed member label and any
   pinned person key. The user picks an existing person identity or approves
   creating a new key on this machine. This is a choice, not a consent prompt,
   and it is skipped when the invite pins a key that exists here or `--as` or
   `--person-key-file` is given (DEC-Q23). A pinned key must match; nothing
   replaces an existing identity.
3. **Request.** The daemon creates the join request, with fresh keys (a device
   key, and the host key if new), a random nonce and a 128-bit pairing secret.
4. **Automatic return (DEC-Q3).** The invite carries a 16-byte return secret.
   The inviter stores it in a `dec_pending` row keyed by the invitation ID
   until the invite expires (DEC-Q26). These rows do not count toward the 8
   active requests (DEC-Q32).
   The daemon seals its request code as one frame under keys derived from that
   secret and posts it to the mailbox at a locator derived from it: first on
   the inviter's first-contact address, then on each helper in the invite. The
   inviter's daemon keeps the return secret with the invite and reads those
   mailboxes until the invite expires. Inside a valid invite, its contacts are
   used as address hints even after their own 300-second expiry; the inviter's
   key is pinned by the invite's signature (DEC-Q25). If every path fails
   within one 30-second attempt, `join` prints the `psl2-` request code, which
   the user sends to the inviter by hand.
5. **Approval.** The inviter's status shows `link_request_waiting`. The owner
   and the admin review and approve it with `link approve REQUEST_ID` and `link
   admit REQUEST_ID` (section 8.3).
6. **Commit.** The new machine shows everything it is about to accept and asks
   once: `Commit this exact machine link? [y/N]`.
7. **Apply.** Each participant checks the complete request and applies it.

Linking another machine of an existing person uses `peerspan link` on the new
machine instead of `join`. It prints a request code, which the person enters on
a machine that can approve (`link approve`). There is no invite and so no
automatic return path. While the request is within its window, the approver
uses the code's contacts as address hints even after their 300-second expiry;
the requester's key is pinned by the signed request packet (DEC-Q33).

### 8.2 Stages

The signed exchange has seven stages, or six when the owner is also the admin.
Each stage is a signed **packet** (appendix section 9).

| # | Stage | Signed by | What it does |
| --- | --- | --- | --- |
| 1 | Request | The new machine's host and device keys | States the keys and the expected network and person. |
| 2 | Owner offer | The owner: the person's original key or a scope-4 device | Proposes the exact host, device, scopes and deadline. For a new person, the new machine's own original key signs a possession-only offer. |
| 3 | Selection | The new machine | Locks one owner offer. Automatic when there is one offer (section 8.4). |
| 4 | Admin offer | The root or an admin | Signs the person and host grants. Folded into stage 5 when the owner is also an admin; skipped when a renewal keeps unchanged person and host grants. |
| 5 | Owner finalization | The owner | Signs the binding and device grants. |
| 6 | Commit | The new machine | Adds the host's signature to the binding, fixes the final list of records (the manifest) and consents. |
| 7 | Apply | Each participant | Checks everything and applies it in one transaction. Writes a signed outcome. |

- **Fold (six stages).** When the person approving as owner can also sign the
  person and host grants (their own admin grant, or the root seed on that host),
  one approval covers both. Owner finalization then carries the person and host
  grants, signed with the request ID as `operation_id`; their bodies travel in
  the commit catalog and the manifest pins them. There is no admin packet; the
  activation's admin field is `-` (DEC-Q4). The root seed on the owner's host
  counts when the same reviewer approves with `network_root`.
- **Root-seed owner approval.** `link approve --signer network_root` uses the
  host's selected owner provider for the owner stages and its current local
  root seed for the folded host grant. It does not change the selected owner
  provider. The review explicitly names the additional root use and pins the
  exact host grant under the same approval. Losing either authority before
  signing refuses; approval does not select a replacement signing path.
- **Separate admin.** Otherwise a different person, or the root, approves stage
  4 with `peerspan link admit`. Its CLI default signer is `network_root`, shown
  in the review; `--signer auto` uses the admin's own current path.
- **Preapproval.** An owner's approval at stage 2 also approves its own stage-5
  signatures under the same terms. It does not approve admin work unless the
  owner's path has admin authority.
- **The manifest** lists every record the device grant depends on (the
  complete closure, including every ID in any `retained_statement_ids`,
  `resolves`, ban target, `ratifies` and kept list reached) and every exact
  proof. It is at most 16 KiB; a larger closure fails with `quota_exceeded`
  rather than being cut.
- **Activation.** The complete exchange is the activation (`da_…`). A third
  host can check it from public records alone. A participant's signed outcome
  is its own local receipt, not a global one.

### 8.3 Reviews on the approving side

- The owner reviews with `peerspan link approve` (API `POST /v2/link/approvals`),
  given either the request ID of a request that arrived through the return path
  or a request code.
  For an admitted owner, scopes default to 15 capped by the owner's path. For a
  new person, the proposed scopes default to 7. The deadline defaults to the
  request's `created_at` plus 7 days, capped by every parent.
- The admin reviews with `peerspan link admit` (API `POST /v2/link/admissions`).
- Owner finalization runs with `peerspan link finalize REQUEST_ID`, or
  automatically under the stage-2 preapproval.
- Each review shows the exact network, person, host and device keys, scopes,
  deadline and signer. Previews sign nothing. There is no `--yes`.

### 8.4 Prompts on the new machine

- **One prompt.** The only consent prompt is at commit: `Commit this exact
  machine link? [y/N]`. Blank means no; only `y` or `yes` (any case) means yes.
  The review shows the network, inviter, owner, person, admin, scopes,
  deadline and every grant being accepted.
- **Selection** is signed without a prompt when exactly one valid owner offer
  matching the invite is present. If two or more are present, the user must
  choose one; there is no default. "Present" means valid offers matching the
  invite that the daemon holds when it first processes offers; an offer that
  arrives after selection is ignored (DEC-Q5).
- A "no" leaves the request pending and the command exits nonzero. `up` does not
  fall through to another create or join.

### 8.5 Time limits

- **Invite**: 1 hour by default, at most 24 hours. An expired invite cannot start
  a new join. It does not cancel a request that already started.
- **Stages**: each stage times out after 10 minutes of inactivity. A host refuses
  to sign the next stage of a request if more than 600 seconds have passed since
  it recorded the request's latest stage, and marks the request `expired`.
  The signed request window is `created_at` + 3600 seconds, a backstop equal to
  six 10-minute stages (DEC-Q1).
- **After commit** there is no timeout. A persisted final commit stays until its
  outcome is known.
- Later learning of a complete activation is accepted whenever its grants are
  current, however long ago it was signed.

### 8.6 Renew mode

A device whose grant has expired joins again with `peerspan link` in `renew`
mode: same host, device and person keys, new nonce and secret, and the prior
device grant ID. If the person, host and binding grants are still current and
unchanged, the admin stage is skipped and the binding is referenced, not signed
again. The new device grant still needs owner finalization and the commit
prompt. An expired device grant proves the key but signs nothing.

### 8.7 Durability, retries and cancellation

- **Order on disk.** The daemon stores the approval before it signs, each
  signature before it encrypts, and each encrypted frame before it sends it.
  The final commit is stored before it is first published.
- **Apply** is one transaction: records, bans, high-water marks, the selected
  provider, the outcome, and one `network.link_applied` event. The pairing
  secret is erased in the same transaction.
- **Retries** resend the exact same bytes. A different packet for the same stage
  of the same request is `operation_conflict`. An old request cannot replace a
  newer device, root, grant or policy.
- **Cancel** (`POST /v2/link/requests/{id}/cancel`) works before commit. It
  erases the secret and frames and keeps a public tombstone.
- **Limits**: 8 active and 4096 total requests per host (invite rows count only
  toward the 4096, DEC-Q32); 64 frames and 32 MiB of
  ciphertext per request; 4096 outcomes per network.

## 9. Delivery paths

All five paths are kept (DEC-S14). Each carries the same signed bytes; a path
adds no authority, and a failed path leaves the request intact for another.

| Path | Used for | Where |
| --- | --- | --- |
| **1. First-contact listener** | Reaching a host that does not know the caller yet | `serve --bootstrap-listen HOST:PORT`, ALPN `peerspan-bootstrap/1`, HTTP/1.1 over TLS |
| **2. Opaque mailbox** | Carrying encrypted stage frames between machines that are not online together | On a first-contact listener or a helper |
| **3. QUIC completion** | Sending the finished activation over QUIC, directly or through a relay | ALPN `peerspan-completion/1` |
| **4. HTTP activation** | Sending the finished activation over the first-contact listener | `POST /bootstrap/v1/activations`, `GET /bootstrap/v1/operations/{request_id}` |
| **5. Resume** | Re-sending a finished activation on request, after a helper change or failure | `POST /v2/link/requests/{id}/resume` |

### 9.1 First-contact listener

- It accepts any client key that proves possession at TLS. It serves only the
  four mailbox routes and the two completion routes.
- Without `--bootstrap-listen`, a peer-enabled daemon listens on its peer
  interface with a separate random port; with no peer listener it listens on
  loopback only. It never rewrites an existing service unit to add a listener;
  it reports the repair step instead.
- Advertised addresses travel only inside signed **contacts** (a host-signed
  list of QUIC, first-contact and relay addresses, valid at most 300 seconds).
  There is no public member list.
- Bounds: 16 pending TLS handshakes per source and 128 in total, 5-second
  handshake, one HTTP request per connection, 5-second headers, 10-second body
  and response. The exact limits are in the appendix.

### 9.2 Opaque mailbox

- A mailbox is named by a **locator** derived from the pairing secret and
  opened with a bearer **read capability** derived from it. Its frames are
  encrypted with AES-256-GCM under keys derived from the secret. Anyone with the
  secret can read and write the mailbox but cannot forge any signature.
- No helper key enters the encryption, so the same ciphertext works on any
  mailbox.
- A host serves the same mailbox routes as a helper. A participant may host it.
- The mailbox's lifetime equals the request window (DEC-Q1). At expiry or
  `DELETE` all ciphertext is erased and a small tombstone is kept for 24 hours.
- Limits: 64 frames per mailbox, 32 MiB ciphertext per mailbox, 4 active
  mailboxes per client host, 2 writes per second (burst 8), 1 read per second
  (burst 4).

### 9.3 QUIC completion

- It serves only the two completion routes, over one QUIC stream with one HTTP
  request per connection, within 30 seconds.
- The client pins the exact participant host key from the stored request before
  sending anything. The server accepts only actual participants of that request.
- It can run through a relay. Until the inner TLS proves the claimed host, a
  relayed source is untrusted, with at most 16 such routes per helper and 128 in
  total.
- A key accepted here is never added as a peer or member.

### 9.4 HTTP activation

- `POST /bootstrap/v1/activations` takes the activation and its catalog. A
  participant checks everything, applies it if it has not, and returns its
  signed outcome. `GET /bootstrap/v1/operations/{request_id}` returns a stored
  outcome.
- Both the client and the server must be participants of the request; anyone
  else gets 403. A helper does not serve these routes.
- A repeated call for an applied request returns the stored outcome unchanged,
  even after the grants expire.

### 9.5 Resume

- `POST /v2/link/requests/{id}/resume` advances approved work and publishes.
- For an applied request it sends the stored activation to every other
  participant, through paths 3 or 4, within 30 seconds, even if delivery was
  acknowledged before. Failures show as transport attention; the local result
  stands.
- Resume never approves, signs anew, re-encrypts or makes keys.

### 9.6 Relay (`peerspan-relay/4`)

- A helper forwards encrypted QUIC datagrams addressed by the host ID derived
  from the host key. It cannot read or end the peer's QUIC.
- After TLS the client sends AUTH within 5 seconds; AUTH_OK gives a 300-second
  registration, renewed by 240 seconds. An idle connection closes after 60
  seconds; clients ping every 15 seconds.
- Two NATed hosts need a relay both can reach. Hosts may list several relays
  and switch on failure without any change to identity or records.

### 9.7 Helper (`peerspan-helper`)

```text
peerspan-helper --state DIR serve --listen HOST:PORT [--tokens-file PATH]
peerspan-helper --state DIR info
```

- It serves mailboxes on `peerspan-bootstrap/1` and the relay on
  `peerspan-relay/4`, and nothing else.
- On first `serve` it creates and stores a transport key. On listen it prints
  one JSON line: `{public_key,address,protocols}`. `info` prints the key and
  protocols and creates nothing.
- Without a tokens file it serves anyone within quotas. With one, a client
  must present a configured token.
- It never opens a host database. It holds no network records.
- `scripts/package-helper.sh VERSION [OUTPUT_DIR]` builds
  `peerspan-helper-VERSION-linux-ARCH.tar.gz` and a `.sha256`. Host bundles
  neither include nor start it.

### 9.8 Transport configuration

`serve --transport-config PATH` names advertised addresses, mailbox helpers
and relays (appendix section 17). Its `publish_contacts` field must be `false`;
contacts travel only inside codes and between members (DEC-Q20). No file and no
helper is valid: then only direct paths are used.

## 10. Sync and repair

- **Peer routes** (members only): `GET` and `POST
  /peer/v2/networks/{id}/catalog` exchange catalogs; `GET .../contacts` and
  `POST .../contact` exchange signed contacts.
- **Merging.** A host checks the sender against what it already trusted, checks
  every received record, then admits the allowed ones, its outbox and its
  projection in one transaction. Nothing received can erase a known ban, fork or
  high-water mark. A host can send its own ban even if that ban ends its
  membership.
- **Timing.** Background sync runs every 60 seconds with up to 10 seconds of
  jitter. New outgoing records are tried at once and then every 2 seconds,
  backing off to 60 seconds. `POST /v2/networks/{id}/sync` (`peerspan network
  sync`) contacts known peers, 4 at a time, 5 seconds each, 30 seconds in total,
  and returns what it learned and which peers were unreachable.
- **Repair.** A host whose grants lapsed can still fetch records from a peer
  that once admitted it and has not revoked it, on `peerspan-state-repair/1`,
  `GET /repair/v1/networks/{id}/catalog`, at most 1 request per second (burst
  4). The bytes are untrusted until checked. Repair grants nothing.
- **Outbox.** At most 4096 deliveries, 512 MiB of bodies and 1 GiB of records per
  host. A change that would not fit is refused before signing.

## 11. Signing plans

The daemon never asks for a signature over arbitrary bytes (DEC-S15).

- **Plan.** Each operation (create, action, policy claim, root rotation, link
  stage) first becomes a stored plan (`dint_…`, table `dec_intents`): the exact
  typed unsigned records, with each missing signature as a numbered slot.
- **Slots.** A ready slot is returned as a signing request naming the plan, slot,
  record type, record ID, role, public key, format, the unsigned record and the
  message to sign. At most 16 slots are returned per batch.
- **The CLI checks** the record type, key, format and role, rebuilds the message
  from the record itself, and only then asks the original key or external root
  key to sign. Signatures come back through the matching `.../signed` route.
- **Keys the daemon owns** (host, device, raw root) sign only slots in an
  approved plan, after the same checks. Automatic renewals are approved as in
  section 7.1.
- **No clock on plans.** A plan does not go stale with age. Before every
  signature and again when applying, the daemon checks that the plan's records
  are still valid against current state: the heads they replace, their parents,
  root state, bans and deadlines. If they are, signing continues, however old
  the plan. If not (a record it replaces or depends on is no longer current,
  or its fixed deadline passed), the operation is refused with
  `review_required`, the plan becomes terminal (`expired`), and a new plan must
  be prepared and reviewed. Terminal plans that were never applied are removed
  after 24 hours (DEC-Q17).
- **Approval first.** `approve:true` stores the approval before anything is
  signed. A preview signs nothing.
- **Retries** return the stored result. A completed plan keeps its exact
  response bytes for later reads.
- **Selected provider.** A person's grants are signed through the persisted
  provider: the original key or one owned device. A broken device provider is
  reported for repair; the daemon never falls back to the original key. Root
  signing is always explicit.

## 12. Policy edits and capability claims

### 12.1 Edits with a version check

DEC-S16 removes edit reservations.

- **Version check.** An edit is an ordinary policy statement whose
  `predecessors` names the current policy head and whose sequence is that
  version plus 1. When it is applied, the daemon checks that the named head is
  still the current one. If the policy changed in between, the edit fails with
  `state_conflict` and the CLI reloads and starts again.
- **Removed.** There is no reservation route, no reservation table state and no
  10-minute reservation expiry.
- **Edit records.** The policy body's existing `edits:[{host,seq}]` line names
  this host's next local edit number, chosen when the plan is made and checked
  for uniqueness when it is applied. The edit record keeps its shape; the
  `reserved` state is no longer written (DEC-Q18). `GET
  /v2/networks/{id}/policy-edits` lists this owner's edits and their states.
- **Concurrent edits on two hosts** still produce a fork or a displaced edit, as
  before. A displaced edit stays *unsettled*. `POST
  /v2/networks/{id}/policy-edits/reapply-preview` returns the exact unsigned
  policy that re-applies unsettled edits on top of the current one, with
  withdrawals winning. The CLI signs it through the ordinary action route. A new
  edit is refused while any of this owner's edits is unsettled.
- **Dropped additions** are recorded with the fixed keys in the appendix.
- **Policy fork.** An owner can resolve a policy fork with a resolver that copies
  one existing branch exactly. Then unsettled edits are re-applied.

### 12.2 Capability claims

- `POST /v2/networks/{id}/policy-claims` prepares and signs a policy that claims
  a capability name for this host. It applies nothing: the result always has
  `committed:false`.
- Capability create then checks the signed claim, the current policy head and
  every other condition and, in one transaction, admits the policy, creates the
  capability, settles the edit and queues delivery, or does none of it.

## 13. Root rotation and root split

### 13.1 Rotation

- `peerspan network rotate-root ID` (or `--to-ssh --root-key PATH`) makes a new
  root state signed by the current root and the new root.
- `GET /v2/networks/{id}/root-retention` lists the grants the rotation can keep
  and those it cannot, with reasons. The rotation keeps all of the keepable ones
  (section 7.2). `--retain` and `--retain-none` are removed (DEC-Q13).
- On apply, a new raw root seed is installed and the old one cleared in the same
  transaction. An SSH root leaves the seed column empty.

### 13.2 Root split

Two valid root states that do not replace each other are a **root split**.

- **Changes freeze.** Every grant depends on the root, so no new grant, renewal
  or root action is possible. Existing grants keep working until they expire.
  Bans are still learned and applied.
- **Status explains it.** `network_state_conflict` with the detail `root split:
  changes are frozen; create a new network and run network reinvite`. The
  network view shows `root_state_id` as `-`.
- **No repair.** There is no root resolution record and no `network
  resolve-root`; readers reject a root state with predecessors from two
  branches (DEC-Q19). Recovery is a new network plus `network reinvite` (section
  14.2).

## 14. Old networks

### 14.1 Legacy networks stay as history

DEC-S12 drops in-place migration.

- A legacy network stays in the database as read-only history. Its status entry
  keeps its old fields and `migration_required:true`, adds
  `mode:"legacy_history"`, and its guidance names `network reinvite`
  (DEC-Q15).
- Its old write routes return 426 `upgrade_required`, with guidance to create a
  new network and run `network reinvite`.
- A legacy link request that already has a durably signed final commit can still
  be settled with `/v1/link/requests/{id}/resume`. Nothing new is signed.

### 14.2 `network reinvite OLD NEW`

`peerspan network reinvite OLD NEW [--expires-in D | --expires-at T]` prints one
invite into network NEW for each member machine of network OLD (DEC-Q16). It is
a CLI loop over existing routes; there is no new daemon route. Invites last 24
hours by default.

- **OLD** is a legacy network, or a coordinator-free network frozen by a root
  split. **NEW** is a coordinator-free network on which this host is a current
  member.
- **Members** are read from this host's stored `network_members` cache of OLD,
  which also works for a root-split network whose current member view is empty.
  It skips this host, hosts with a known revocation, and removed persons.
- **Each invite** is made with the ordinary invitation route, with the old
  member label, and pins the member's person key when OLD knows it (`-`
  otherwise).
- **Output.** JSON on stdout: an array of `{member, host_id,
  person_public_key, invitation_id, invitation, expires_at}`. The codes are
  secret: they are never logged or shown in status.
- **After it.** OLD is unchanged and stays history. Each old member joins NEW
  with `peerspan join` using the existing person key. The usual admin approval
  is still needed.

## 15. Owner-local API and CLI

All routes are on the administration socket. Request and response shapes are in
the appendix.

| Route | Purpose |
| --- | --- |
| `GET /v2/info`, `GET /v2/status` | Info and status (section 16). |
| `GET /v2/networks`, `GET /v2/networks/{id}` | Network views. |
| `GET /v2/networks/{id}/members`, `.../persons`, `.../groups`, `.../policy/{person}`, `.../access-versions` | Current verified facts. |
| `GET/POST /v2/networks/{id}/provider` | Read or explicitly change the selected provider. |
| `GET /v2/networks/{id}/catalog`, `.../planning` | Public records; planning summary for the CLI. |
| `POST /v2/networks` | Create. |
| `GET /v2/network-creations/{id}`, `POST .../approve`, `POST .../signed` | Creation plan. |
| `POST /v2/networks/{id}/actions`, `GET .../actions/{action_id}`, `POST .../actions/{action_id}/signed` | Ordinary signed actions: grants (not new devices), policy, group, bans, root transition. |
| `POST /v2/networks/{id}/policy-claims`, `GET .../policy-claims/{action_id}`, `POST .../signed` | Capability claim preparation. |
| `GET /v2/networks/{id}/policy-edits`, `POST .../policy-edits/reapply-preview` | Edit summary; re-apply candidate. |
| `GET /v2/networks/{id}/root-retention`, `POST .../root-transitions` | Root rotation. |
| `POST /v2/networks/{id}/invitations` | Make an invite code. |
| `POST /v2/networks/{id}/sync` | Bounded sync. |
| `GET /v2/link/requests`, `GET/POST /v2/link/requests[/{id}]` | Join requests. |
| `POST /v2/link/requests/{id}/selection`, `.../commit`, `.../finalization`, `.../resume`, `.../cancel`, `.../signed`, `GET .../approval` | Stages. |
| `POST /v2/link/approvals`, `POST /v2/link/admissions` | Owner and admin reviews. |

CLI commands in the Rust host:

| Command | Does |
| --- | --- |
| `network create NAME [--as MEMBER] [--person-key-file PATH]` | Section 6. |
| `invite MEMBER [--expires-in D \| --expires-at T] [--network ID]` | Section 8.1. |
| `join [--invite-stdin]` | Section 8.1. |
| `link`, `link approve [REQUEST_ID] [--signer network_root\|auto]`, `link admit [REQUEST_ID] [--signer network_root\|auto]`, `link finalize REQUEST_ID`, `link resume`, `link status`, `link cancel` | Section 8. Without a request ID, codes come from a hidden prompt, `--code-stdin` or a private file. |
| `network list`, `network members`, `network groups`, `network sync` | Views and sync. |
| `network rotate-root ID [--to-ssh --root-key PATH]` | Section 13.1. |
| `network reinvite OLD NEW [--expires-in D \| --expires-at T]` | Section 14.2. |
| `serve --bootstrap-listen HOST:PORT --transport-config PATH` | Sections 9.1, 9.8. |
| Existing access and capability commands | Unchanged, signing through the provider. |

Removed: `network migrate …`, `network resolve-root`, and every
`/v2/networks/{id}/migration…` and `/peer/v2/networks/{id}/migration` route.

`up` uses the same routes. A fresh create needs no coordinator. A fresh join
waits until the request is applied and the provider is usable before attaching
an agent. Pending `up` never shows a code again.

Release builds: normal Rust bundles need no coordinator address or
key, and a build that still passes the old mandatory coordinator option fails
with guidance. `network move` and coordinator successor settings remain only
as legacy history.

## 16. Status and errors

- **Info** sets `default_coordinator` to null and adds
  `network_protocols:["peerspan-decentralized-v1"]`.
- **Status** lists each coordinator-free network's view, including `authority`
  (usable, unbound, authority_expired, proof_required, state_conflict,
  forbidden, device_revoked, not_yet_valid or clock_rollback, with the
  deadline) and `provider_state`. Legacy networks appear as in section 14.1.
  Status reads one snapshot and writes nothing.
- **Attention items**, after the existing network items, in this order:
  `network_authority_expired`, `network_proof_required`,
  `network_state_conflict`, `network_clock_rollback`,
  `network_root_unreachable`, `person_device_signer_unavailable`, then
  `link_request_waiting`. Each gives the network, the cause and the
  command to run. A clock rollback tells the user to fix the clock or wait;
  there is no command to lower the stored time.
- **Errors** are `{code,error,details:{network_id,context_id,request_id,stage,
  required_ids,conflict_ids,next}}` with the status codes in the appendix.
  `proof_required` names the exact missing IDs.

## 17. Storage

Schema 23 is unchanged (DEC-Q14). It adds 17 tables; opening the database
never joins, renews or migrates anything, and older binaries refuse it.

| Table | Holds |
| --- | --- |
| `dec_contexts` | The adopted descriptor of each network. |
| `dec_objects` | Exact public record bytes, by proof ID. |
| `dec_admissions`, `dec_restrictions`, `dec_activations` | Why each statement, ban and activation was admitted, and when (local time). |
| `dec_heads`, `dec_highwater` | Current heads and highest admitted sequence of each stream. |
| `dec_signers` | The selected provider. |
| `dec_clock` | The stored decision time. |
| `dec_intents` | Signing plans. |
| `dec_pending`, `dec_frames` | Join requests in progress and their encrypted frames. |
| `dec_operations` | Applied join outcomes. |
| `dec_outbox` | Deliveries to peers. |
| `dec_contacts`, `dec_helpers` | Peer contacts and configured helpers. |
| `dec_migrations` | Unused; a schema-24 cleanup may drop it later (DEC-Q14). |

Existing tables keep their data. `networks.record` holds a tagged format-2
record for a coordinator-free network; `network_members` holds a derived cache
of verified members, rebuilt from records and never trusted on its own. Records
are strict JSON with no nulls; absent values are `-`.

## 18. What changed from the 2026-10-26 spec

| Change | Decision |
| --- | --- |
| Grants keep their 7-day and 24-hour limits. Permanent grants with spreading revocations were not adopted. | DEC-S1 |
| Invite valid 1 hour by default, at most 24 hours, instead of 300 seconds. | DEC-S4 |
| Each join stage times out after 10 minutes of inactivity, instead of one 300-second window for the whole join. | DEC-S4 |
| One default-no prompt on the new machine, at commit. Selection is automatic unless offers compete. | DEC-S5 |
| The join request returns to the inviter automatically through the invite's return path; the `psl2-` code is a fallback. | DEC-S6 |
| The admin stage is folded into the owner's approval when the owner is also an admin: six stages instead of seven. | DEC-S7 |
| Hosts renew grants automatically about 2 days before expiry. There is no manual renew command. Status warns only when no signer is reachable. | DEC-S8 |
| Any of a person's scope-4 devices may renew that person's device and binding grants. The original key is still needed for anything new or higher. The root or an admin renews person and host grants. | DEC-S9 |
| A renewal keeps every current, non-banned child automatically. Removal is only by revoke or unbind. The record format is unchanged. | DEC-S10 |
| The root's host renews admin grants automatically. Status counts down `root unreachable: network stops in N days` from 3 days out. | DEC-S11 |
| In-place migration is removed: its routes, commands, statement kinds, migration composite, fence, migrated root form and `migration_pending` states. `network reinvite OLD NEW` replaces it; old networks stay read-only history. | DEC-S12 |
| A root split freezes the network for good. Root fork resolution and `network resolve-root` are removed; recovery is a new network plus re-invite. | DEC-S13 |
| All five delivery paths are kept, now described plainly. | DEC-S14 |
| Signing plans have no 5-minute clock. A plan is reviewed again only when what it signs is no longer valid. This removes the 300-second honest-signing age rule, the creation re-approval window and the 300-second action-plan expiry. | DEC-S15 |
| Policy edits use a version check. Reservations, their route and their 10-minute expiry are removed. Capability create still updates the policy in the same transaction. | DEC-S16 |
| One spec and one wire appendix replace nine files. | DEC-S17 |
| The creator's host gets a scope-15 device grant at `network create`, made without a join exchange. | DEC-Q21 |
| Deadline-only device renewals are ordinary actions; a sibling renewal is not capped by the renewer's deadline. | DEC-Q6, DEC-Q7 |
| The invite carries a return secret; inviter approval can name a request ID. | DEC-Q3 |
| `rotate-root --retain` and `--retain-none` are removed; readers reject root fork resolutions. | DEC-Q13, DEC-Q19 |

Also removed with migration: the `migration` request kind of the
`--decentralized-verify` carrier, the `LEGACY_PRIOR` input, the migration test
barriers, the `migration_identity` plan kind, the `migration_prepared` and
`migration_adopted` link states, the `migration` error stage and the
`network_migration_pending` attention item.

Not carried over as text, because they restated rules given elsewhere or
described the process of writing the old files: the delivery-slice table, the
"selected / discarded" tables (they stay in the git history of the old files;
owner decisions are in the decision log), the status
lines about review gates, and the schema-22 allocation history.

## 19. Resolved questions

The first draft of this spec left 25 questions open, and applying the answers
raised eight more (Q26 to Q33). The owner answered all 33 on 2026-10-27; the
options are in the decision log. No question is open.

| Q | Decision | Log |
| --- | --- | --- |
| Q1 | Request window `created_at` + 3600 s; mailboxes and frames use it; the 10-minute stage rule is enforced locally. | DEC-Q1 |
| Q2 | The invitations route takes `expires_at`, 60 s to 24 h after now; the CLI sends now + 1 h by default. | DEC-Q2 |
| Q3 | Return secret in the invite; the request is sealed into a mailbox on the inviter's address, then the helpers; `psl2-` after 30 s of failure; `link_request_waiting`; approval by `REQUEST_ID`. | DEC-Q3 |
| Q4 | Folded admin: no admin packet; owner finalization names the person and host grants, carried in the commit catalog; the root seed on the owner's host counts. | DEC-Q4 |
| Q5 | Offers compete when two or more are held when offers are first processed; later offers are ignored. | DEC-Q5 |
| Q6 | A deadline-only device renewal is an ordinary action with `operation_id` `-`. | DEC-Q6 |
| Q7 | A sibling renewal keeps the target's `issuer_device` parent, records the renewer only as `issuer` signer, and is capped by person, host and binding grants. | DEC-Q7 |
| Q8 | A device may not renew its own grant. | DEC-Q8 |
| Q9 | A scope-4 device still approves a brand-new device; "new" means new or higher scopes. | DEC-Q9 |
| Q10 | Scope 2 or scope 4 renews a binding. | DEC-Q10 |
| Q11 | Ranked turns spaced across the window, sync before signing, automatic resolution of forks between identical plain renewals. | DEC-Q11 |
| Q12 | The root renews root-signed grants 4 days early; the countdown shows at N ≤ 3, with N to the latest admin or root-signed person/host deadline. | DEC-Q12 |
| Q13 | `--retain` and `--retain-none` removed; `admin_withdraw` keeps every eligible grant by default. | DEC-Q13 |
| Q14 | Migration fields stay, always `-`; `dec_migrations` stays unused; schema 24 may clean up later. | DEC-Q14 |
| Q15 | The legacy status entry keeps its shape; guidance names `network reinvite`. | DEC-Q15 |
| Q16 | `network reinvite`: one invite per machine, a CLI loop with no new route, the stored `network_members` cache, 24-hour default expiry. | DEC-Q16 |
| Q17 | A plan needs review only when a record it replaces or depends on is no longer current or its deadline passed; such a plan becomes terminal; unapplied terminal plans are removed after 24 h; plan `expires_at` is `-` except for link stages. | DEC-Q17 |
| Q18 | The policy edit record keeps its shape; `reserved` is no longer written. | DEC-Q18 |
| Q19 | Readers reject root fork-resolution records. | DEC-Q19 |
| Q20 | `publish_contacts` must be `false`. | DEC-Q20 |
| Q21 | `network create` gives the creator's host a scope-15 device grant held by the daemon. | DEC-Q21 |
| Q22 | A deadline-only renewal is approved by the approval that created the grant; no off switch. | DEC-Q22 |
| Q23 | The identity choice at `join` is a choice, not a consent prompt, skipped when the key is pinned or given. | DEC-Q23 |
| Q24 | 24-hour grants renew when 8 hours remain. | DEC-Q24 |
| Q25 | Contacts inside a valid invite are used as address hints after their 300-second expiry. | DEC-Q25 |
| Q26 | The inviter keeps an invite's return secret in a `dec_pending` row keyed by the invitation ID. | DEC-Q26 |
| Q27 | The creator device may renew its own grant and the creator's binding, the one exception to Q8; a device-signed binding renewal is capped by the person and host grants only. | DEC-Q27 |
| Q28 | A deadline-only renewal of a host grant or binding needs only the issuer's signature. | DEC-Q28 |
| Q29 | An ancestor device counts as current while its device stream has a current, unrevoked head. | DEC-Q29 |
| — | Only the creator device grant and deadline-only renewals may be device grants with `operation_id` `-` (confirmed). | DEC-Q21a |
| Q30 | The creator device's self-renewal holds only while it is the creator's only current device. | DEC-Q30 |
| Q31 | A verifier finds a renewer's own grant as the current head of `device/PERSON/SIGNING_KEY`; no format change. | DEC-Q31 |
| Q32 | Invite rows do not count toward the 8 active pending requests, only toward the 4096 total. | DEC-Q32 |
| Q33 | Inside a request code still within its window, expired contacts are used as address hints. | DEC-Q33 |

## 20. Verification

A separate test author writes the cases from this spec and the appendix alone.
Each item states an observable outcome. "Refuses" means the exact error code
named, with no change to stored state other than the stored decision time.

**Records**

1. A descriptor's context ID matches the appendix formula; a changed name,
   genesis key or protocol gives a different ID.
2. Each statement kind accepts only its declared roles and formats; an original
   key signing raw Ed25519 is invalid; a valid signature by the wrong key in
   any alias makes the statement invalid.
3. Two aliases of one statement keep both proof IDs and add no head; a
   re-serialized payload is a different statement.
4. Strict parsing rejects unknown, duplicate and null fields, floats, negative
   numbers and non-canonical Base64; u64 values up to 2^64−1 round-trip.
5. Every size limit in the appendix accepts its maximum and refuses one byte or
   one item more with `quota_exceeded`.

**Authority**

6. Each grant kind: wrong signer refuses; `not_after` 1 second past 7 days (24
   hours for policy and group) is invalid; a child past any parent's deadline is
   invalid, except a deadline-only sibling renewal (item 19); at `not_after`
   exactly the grant is unusable.
7. The root or an admin cannot sign a binding, device grant or policy for
   another person.
8. Device chains of depth 8 work; depth 9 or a repeated key fails.
9. A device B with scope 4 approves a new device C through a join request while
   the original-key host is offline.
10. Two incomparable generations of a stream freeze it; a higher write on one
    branch does not unfreeze it; a resolver naming all heads does; a newly
    learned branch reopens it.
11. A policy fork for one person does not stop a valid ban of another person
    from being admitted.
12. An admitted ban stays after its signer expires; a backdated ban from an
    expired signer is inert until ratified.
13. A new admin grant listing an `admin_withdraw` in `resolves` restores the role
    but not unkept children; nothing restores a revoked device, host or removed
    person.
14. Clock: 300 seconds back works with the stored time; 301 seconds refuses
    `clock_rollback`; status writes nothing; remote times never move the stored
    time.
15. A manual `allow_disconnected:true` grant works after the network grant
    expires; with it false the request is refused; accepted tasks keep their
    outcome after expiry.

**Creation and renewal**

16. `network create` produces a scope-15 device grant for the creator's host,
    with `operation_id` `-`, sequence 1 and the genesis person, host and binding
    grants as parents, and selects that device as provider. Any other device
    grant with `operation_id` `-` that is not a deadline-only renewal refuses.
17. With all hosts online and no SSH key unlocked, every grant is renewed
    before it expires with no user action and no attention item. This includes
    the creator's device grant and binding, renewed by the creator device
    itself while it is the creator's only current device, and other hosts' host grants
    and bindings renewed with only the issuer's signature.
18. Renewal starts at the thresholds: 2 days left for 7-day grants, 8 hours for
    policies and groups, 4 days for root-signed grants; a policy is not renewed
    again until its new generation reaches 8 hours left.
19. A deadline-only renewal of device D by scope-4 sibling S is an ordinary
    action that keeps D's `issuer_device` parent A, has S as `issuer` signer,
    and stays usable past S's own deadline and past A's original generation,
    up to the person, host and binding deadlines, while A's stream has a
    current head. A ban on A stops D. D signing its own renewal refuses (unless
    D is the creator device and the creator's only current device); a renewal
    with more scopes refuses; renewing an
    expired D refuses and needs renew mode.
20. After the creator links a second current device, the creator device's
    renewal of its own grant refuses and the second device's renewal of it
    succeeds; if the second device is revoked, self-renewal works again.
    A renewal whose signing key has no current, unbanned scope-4 head in
    `device/PERSON/SIGNING_KEY` refuses.
21. A binding renewal signed by a scope-2 device and one signed by a scope-4
    device both succeed with only the issuer's signature, and each lasts past
    the signing device's deadline up to the person and host deadlines. A host
    grant renewed by an admin succeeds without the target host's signature.
22. A person or host grant renewed by a non-admin device refuses; by an admin
    (original key or scope-8 device path) or the root works.
    With the root host offline, a host without the root seed automatically
    renews eligible person and host grants through each supported admin path,
    and renews a 24-hour group when 8 hours remain, within its parents' caps.
23. Renewing a scope-15 device as scope 7 leaves its retained child device and
    policy unable to use scope 8.
    A renewal's `retained_statement_ids` lists every current non-banned child
    known to the signer; children keep their original deadlines; a banned child
    is not listed; a child unknown to the signer is inert once the renewal is
    admitted.
24. With every renewer of a person-signed grant offline, status shows
    `person_device_signer_unavailable` inside the renewal threshold and not
    before.
25. With the root host online, `network_root_unreachable` never appears. With it
    offline, the attention item appears when N ≤ 3 with the text `root
    unreachable: network stops in N days` and the right N; renewal resumes when
    the root host returns.
    With an external SSH root available only through the daemon's SSH agent,
    root-signed grants renew automatically without storing the root seed.
26. Three hosts able to renew one grant, the first two offline: the third renews
    it before expiry. With all three online, one new generation results; if two
    identical plain renewals fork the stream, the next renewal resolves it.
27. A renewal plan is signed with no approval prompt.

**Joining**

28. Create, invite and join with the Rust CLI and daemon, no coordinator and
    no helper; the joiner sees exactly one default-no
    consent prompt, at commit; with a pinned key that exists locally there is
    no identity choice.
29. The request reaches the inviter without a code over a direct address, and
    through a helper when the inviter has no reachable address; the inviter's
    status shows `link_request_waiting` and `link approve REQUEST_ID` works.
    With neither path, `join` prints a `psl2-` code within about 30 seconds and
    the manual path completes.
30. An invite used 30 minutes after issue, whose contacts are past their own
    300-second expiry, still returns the request over the inviter's address.
    A direct-only `link` request code approved 9 minutes after it was made
    still delivers the owner offer over the requester's address.
31. `network reinvite` for 20 old members on a host with 8 active join
    requests succeeds and every invite's return path works.
32. An invite is accepted at `expires_at` − 1 second and refused at
    `expires_at`; expiry defaults to 1 hour; lifetimes of 59 seconds and of 24
    hours plus 1 second are refused.
33. A stage that waits 600 seconds can still be signed; at 601 seconds the
    request is `expired`; a request's signed `expires_at` is `created_at` + 3600;
    a persisted final commit never expires.
34. Two owner offers held when offers are first processed force a choice; one
    offer is selected without a prompt; an offer after selection is ignored.
35. An owner who is also an admin, or whose host holds the root seed, links a
    new machine in six stages with no admin packet and the person and host
    grants in the commit catalog; a non-admin owner needs a separate admin
    approval.
    After the owner's admin grant is withdrawn, `link approve --signer
    network_root` explicitly reviews the root-seed fold, retains the selected
    owner provider and completes with no administrator packet.
36. Answering blank or `n` at commit leaves the request pending and exits
    nonzero; nothing is applied.
37. Crash at each durable point (approval, signature, frame, final commit,
    apply): restart continues the same request with the same bytes and no
    second event.
38. A renew-mode request with unchanged person, host and binding has no admin
    stage and no new binding signature.
39. A third host learns an activation through sync and verifies it without the
    pairing secret.

**Delivery**

40. The first-contact listener serves only mailbox and completion routes; any
    other route returns 404 and reaches no owner or peer router.
41. Mailbox: create, append, read, delete, expiry at the request window and
    tombstone behave as in the appendix; a wrong read capability is 403; quotas
    and rates refuse with 409 and 429.
42. QUIC completion through a relay with no direct path delivers the activation;
    a non-participant key gets nothing.
43. HTTP activation: a non-participant server returns 403; a repeated call after
    apply returns the stored outcome unchanged.
44. Resume after a helper is replaced re-sends the activation to every
    participant; with no path it reports transport attention and keeps the
    result.
45. Relay: AUTH within 5 seconds, renewal by 240 seconds, idle close at 60
    seconds, replacement connection for the same key, collision refused.
46. Replacing or removing every helper changes no network record; a transport
    file with `publish_contacts:true` is refused.

**Sync and repair**

47. A received catalog cannot erase a known ban, fork or high-water mark.
48. A former member with expired grants fetches records on the repair ALPN; an
    unknown or revoked key gets nothing; repair grants nothing.

**Signing plans**

49. No route signs bytes that are not a typed record of a stored plan.
50. An action or creation plan approved and left for an hour signs when nothing
    it depends on changed. When a head it replaces changed, it refuses
    `review_required`, becomes terminal, and is gone 24 hours later.

**Policy**

51. An edit naming an old policy head fails with `state_conflict`; no
    reservation route exists and no edit record is written in state
    `reserved`.
52. Capability create with a stale claim changes nothing; a successful create
    admits the policy, creates the capability and settles the edit together.
53. A displaced withdrawal is re-applied before any new edit is accepted.

**Root**

54. Rotation keeps every keepable grant and installs the new seed in the same
    transaction; `--retain` and `--retain-none` are refused as unknown flags.
55. A root split freezes new grants and root actions; existing grants work until
    expiry; status shows the root-split detail; a root state with predecessors
    from two branches is invalid; there is no resolve route.
56. `admin_withdraw` from the CLI keeps every eligible grant by default.

**Old networks**

57. A legacy network appears as `legacy_history` with `migration_required:true`
    and guidance naming `network reinvite`; its write routes return 426.
58. `network reinvite OLD NEW` prints one invite per eligible old member
    machine, valid 24 hours by default, pins known person keys, skips revoked
    hosts and this host, and changes nothing in OLD; it works for a root-split
    OLD from the stored member cache; each old member can join NEW with its
    existing person key.

**Storage**

59. A schema 21 or 22 database opens to schema 23 with all old data intact; an
    old binary refuses schema 23; schema 24 is refused; `dec_migrations` stays
    empty.
60. After a Rust daemon restart, an unfinished join and an unfinished signing
    plan continue with identical approved bytes and no duplicate events.

**Installed**

61. The installed Rust bundles create, join and run a real agent task
    across two machines with no coordinator, then lose access after a ban.
