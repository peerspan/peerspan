# Signed enrollment and coordination contract

Status: specification for roadmap milestone 1 ([roadmap](production-roadmap.md)). The Go and Rust host daemons implement the host side, and a Go-only `capsule-coord` binary implements coordination. This builds on the [known-host messaging contract](peer-messaging-contract.md). Manual `peer add` remains supported, and nothing here changes the peer router.

## Trust model

A network is identified by its **root key**, an Ed25519 key generated on the creator's host and stored only in that host's database. Membership is a signed chain that every host verifies itself:

```text
root key ──signs invite statement──▶ invite key (one-time) ──signs member statement──▶ host key
```

The coordinator stores chains, enforces single use of each invite key, records advertised addresses, and serves maps. It is trusted for availability only. It can withhold members, serve stale maps, or refuse service. It cannot introduce a host, because it never sees an invite private key. Hosts reject any map entry whose chain does not verify against the network root they hold. If two different host keys appear under one invite key, the host rejects all of them, so even a coordinator that obtained a leaked invite cannot reuse it silently.

Membership does not grant access. Grants remain receiver-owned and local, as in the messaging contract. Membership replaces manual key and address exchange, and it defines the connected state for grants. The `member` label is the name an administrator gives an invitee. It is signed but descriptive, and it authorizes nothing.

Invite expiry is enforced by the coordinator at join time and by the joining host. A host that verifies a chain later also requires `joined_at` ≤ `invite_expires_at`, but `joined_at` is asserted by the joiner. Membership revocation is roadmap milestone 2. Until then, a member removed by the coordinator simply disappears from maps.

## Encodings and signed statements

- Public keys and seeds: canonical standard Base64 of 32 bytes. Signatures: canonical standard Base64 of 64 bytes. Decoders reject non-canonical encodings.
- `network_id` is `net_` followed by the lowercase hex SHA-256 of the root public key. Coordinator IDs are `coord_` followed by the lowercase hex SHA-256 of the coordinator public key. Host IDs are unchanged.
- Labels (`name`, `member`) must already be trimmed, contain 1–128 UTF-8 bytes, and contain no control characters (U+0000–U+001F, U+007F).
- Times are UTC RFC3339. A signature covers the exact signed string, and verifiers never re-spell it.

A signed statement is its lines, encoded as UTF-8 and joined with a single `\n`, with no trailing newline:

| Statement | Signed by | Lines |
| --- | --- | --- |
| Invite | root key | `capsule-invite-v1`, `network_id`, `invite_public_key`, `member`, `invite_expires_at` |
| Member | invite key | `capsule-member-v1`, `network_id`, `invite_public_key`, `host_public_key`, `joined_at` |

A **membership** is a strict JSON object with exactly these fields: `network_id`, `member`, `invite_public_key`, `invite_expires_at`, `invite_signature`, `host_public_key`, `joined_at`, and `host_signature`. To verify it against a root public key:

1. Check that `network_id` is derived from the root key.
2. Verify `invite_signature` over the invite statement with the root key.
3. Verify `host_signature` over the member statement with the invite key.
4. Check that `joined_at` ≤ `invite_expires_at`.

The member's host ID is derived from `host_public_key`.

### Test vectors

Ed25519 is deterministic. Both implementations must reproduce these exactly:

| Item | Value |
| --- | --- |
| Root seed / public | `AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=` / `iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=` |
| Network ID | `net_34750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e` |
| Invite seed / public | `AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=` / `gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=` |
| Host seed / public | `AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=` / `7UkoxijRwsbq6QM4kFmVYSlZJzpcY/k2NsFGFKyHN9E=` |
| Host ID | `host_b62e867fa2f33afe62d5d6b1642e1621d543307846b2a57b897e710919b76709` |
| Member, expiry, joined | `alice`, `2026-11-01T00:00:00Z`, `2026-10-05T12:00:00Z` |
| `invite_signature` | `3WTE8i0clTO4PNMXiWiCgVkYWUzS8nCySGhYZWXDwBmz7K416+cmh5Qb6mSrCU+MNDuSudNWXklbsCc8m+Y4Cw==` |
| `host_signature` | `YD6gwCNa6yQT1ofoSqCR4iDpvG4887BtCcZsGXebPSfX4siZx6z6XnzY2AYM5GoAzdX1SsNIAG4I/kkkIQLWCg==` |

### Invite token

A token is `capsule-invite-v1.` followed by unpadded base64url of a strict JSON object. The object has exactly these fields: `network_id`, `network_name`, `root_public_key`, `coordinator_address`, `coordinator_public_key`, `member`, `invite_public_key`, `invite_seed`, `invite_expires_at`, and `invite_signature`. The token is a bearer secret, because it contains the invite private seed. Owners deliver it out of band. Before contacting the coordinator, a joining host checks five things: the network ID matches the root key, the invite signature verifies, the seed matches `invite_public_key`, the invite has not expired, and the coordinator key is canonical. A failed check returns local 400 and makes no network contact.

## Coordinator service: `capsule-coord`

`capsule-coord [--state DIR] run --listen HOST:PORT` serves coordination in the foreground. `capsule-coord [--state DIR] info` prints `{id, public_key}` and works while the service is running. State defaults to `$XDG_STATE_HOME/capsule/coord`, or `$HOME/.local/state/capsule/coord`. The private-directory, file-mode, and single-process rules are the same as for hosts. The coordinator generates its Ed25519 identity once and keeps it across restarts. Its database schema is internal.

Transport is HTTP/1.1 over TLS 1.3. The coordinator presents a self-signed Ed25519 certificate for its own key, built the same way as host certificates and renewed the same way. It requires a client certificate that proves possession of an Ed25519 key, and the caller's host ID is derived from that key. Hosts pin the coordinator public key from network creation or the invite token. `coordinator_address` is `HOST:PORT`, where HOST may be an IP literal or a DNS name. DNS is safe here because the key is pinned. Peer addresses remain IP literals.

Request bodies are strict flat JSON (nested only where shown), at most 1 MiB. Unknown or null fields are rejected. Errors use the usual `{code, error}` bodies. Advertised `address` is either `""` (not directly reachable) or a literal `IP:PORT` with a nonzero port. `candidates` is an array of at most 8 distinct literal `IP:PORT` strings with nonzero ports (path-discovery hints, see below), possibly empty. A host verifying a map drops invalid candidates rather than the member.

| Endpoint | Body | Behavior |
| --- | --- | --- |
| `POST /coord/v1/networks` | `name`, `root_public_key`, `membership`, `address`, `candidates` | Register a network. `membership` must verify under the root, and its host key must be the caller. Returns 201 with the map. If the network exists and the caller is already a member, returns 200 with the map. Any other existing network ID returns 409. |
| `POST /coord/v1/networks/{network_id}/members` | `membership`, `address`, `candidates` | Join. Returns 404 for an unknown network and 400 for a chain that does not verify. Returns 403 if the host key is not the caller or the invite has expired by the coordinator's clock. If this host already used the invite key, returns 200 with the map and keeps the originally stored membership. If another host used it, returns 409. Otherwise returns 201 with the map. |
| `POST /coord/v1/networks/{network_id}/sync` | `address`, `candidates` | The caller must be a member, otherwise 403, including for unknown networks. Records the address and candidates and returns 200 with the map. |

A **map** is `{network_id, name, root_public_key, members}`. `members` is an array of `{host_id, membership, address, candidates, updated_at}` sorted by `host_id`, and `updated_at` is the coordinator's time of that member's last join or sync. Registration never checks invite expiry, so a network that stayed unregistered for a while can still register. On join, reuse by the same host is checked before expiry, so a retried join succeeds after expiry. Every listed body field is required. Abuse limits on registration are deferred and listed below.

## Host changes

### Persistence

Database version 3 atomically adds these tables to version 2:

```sql
CREATE TABLE networks (id TEXT PRIMARY KEY, record TEXT NOT NULL, root_seed BLOB);
CREATE TABLE network_members (network_id TEXT NOT NULL, host_id TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(network_id, host_id));
PRAGMA user_version = 3;
```

`root_seed` is non-null only on the creator's host, and `administrator` is derived from it rather than trusted from a record. `networks.record` holds the network view below. `network_members` holds one member view per row, including this host's own row, which carries its own membership. Readers tolerate extra record fields. Records are JSON. Either implementation can open the other's version 3 state. Older binaries reject version 3. Invite seeds are never stored.

### Local API and CLI

| CLI after `--state DIR` | Local API | Behavior |
| --- | --- | --- |
| `network create --name NAME --member LABEL --coordinator HOST:PORT --coordinator-key BASE64` | `POST /v1/networks` | Generate a root key and a self-membership whose invite expires 30 days after creation, persist them with `network.created`, then attempt registration once. Returns 201 even if registration fails, because the sync loop retries it. |
| `network invite --network ID --member LABEL --expires-at TIME` | `POST /v1/networks/{id}/invites` | Administrator only, otherwise 403 `forbidden`. Expiry must be in the future and at most 30 days ahead. Returns 201 `{network_id, member, invite_public_key, invite_expires_at, token}` and records `network.invite_issued`. |
| `network join --token TOKEN` | `POST /v1/networks/join` | Verify the token. Returns 409 if this network has already been joined. Sign the membership and call the coordinator. Only after it accepts and its map verifies, persist the network, its members, and `network.joined` together. A host already in the network through another invite gets 409. Coordinator 400/403/404/409 map to the same local status. A returned map that omits this host or does not match the network returns 503; unreachable or 5xx return 503 `unavailable`, and nothing is persisted. |
| `network list` | `GET /v1/networks` | Networks sorted by ID. |
| `network members ID` | `GET /v1/networks/{id}/members` | Verified members, including this host, sorted by host ID. |
| `network sync ID` | `POST /v1/networks/{id}/sync` | Register or sync now. Returns 200 with the network record; a failure appears in `last_sync_error`. |

A network record is `{id, name, root_public_key, member, coordinator_address, coordinator_public_key, administrator, last_sync_at, last_sync_error}`. The last two are nullable, and `last_sync_at` is the time of the last successful sync. A member record is `{host_id, public_key, member, address, candidates, updated_at, membership}`.

`run` gains `--advertise IP:PORT`, which requires `--peer-listen`. It defaults to the bound peer address when that IP is not unspecified, and otherwise to `""`. `run` also gains `--coordination-interval SECONDS`, from 1 to 3600 with a default of 30. Each interval, the daemon registers each unregistered administered network (one with no `last_sync_at`) and syncs every other network. Registration and sync send the current advertised address.

### Applying a map

A host applies a map only if all of the following hold: its network ID and root key match the stored network, its own host appears with its own membership, and the request completed over the pinned coordinator. It drops any entry whose chain fails or whose `host_id` does not match its key, and every entry that shares an invite key with a different host key. It then replaces that network's member set in one transaction. Its own entry may carry any validly signed membership for its key, because the coordinator keeps the original membership on a re-join. An entry with an invalid address is kept with address `""`, and all entries sharing a `host_id` are dropped. Member events exclude this host. A join records `network.joined` followed by one `network.member_added` for each other member. That transaction updates `last_sync_at` and records `network.member_added` / `network.member_removed` (subject: host ID) only for actual changes. A failed sync leaves the members untouched and records `last_sync_error`, without an event. Members persist across restarts, so known peers keep working while coordination is unavailable.

### Peer resolution and grants

- A host is **known** if it is a manually configured peer or a verified member of any network, other than this host. Inbound TLS authentication, `grant create`, and the peer router accept known hosts. `peer list` still shows only manually configured peers.
- For outbound dialing, a manual peer's address takes precedence. Otherwise the daemon uses the nonempty address of the member entry with the latest `updated_at`. A member with no address can authenticate inbound but cannot be dialed. A send to it records `unknown` with an error.
- The **connected** state for a grant: a grant without `allow_disconnected` permits a new append only if the requester is currently a member of some network whose `last_sync_at` is within three coordination intervals of now. Otherwise only `allow_disconnected` grants work, as before. The receiver checks the final grant bounds first. If only the connected state fails and the requester is a verified member of a network this host has not synced recently, it returns 503 `unavailable` rather than 403, so the sender records `unknown` and may retry the same request ID later. A requester that is not a member of any network gets 403, because that does not recover. Adapter handoff leaves such a message queued, and a reply to already-delivered content needs only the final bounds (see the [adapter contract](agent-adapter-contract.md)). Receipt lookup is unchanged.

New activity kinds are `network.created`, `network.joined`, `network.invite_issued`, `network.member_added`, and `network.member_removed`.

Hosts give each coordinator call an 8-second timeout and accept responses up to 16 MiB.

## Revocation, leaving, and root rotation

Roadmap milestone 2a. The roles are explained in the [access model](access-model.md): the network administrator, meaning the host holding the current root seed, controls membership only. Revocations are signed and sticky. A host persists every valid revocation it sees and keeps enforcing it, even if a coordinator later omits it or serves an older map. Multiple administrators are milestone 2b.

### Statements

These use the encoding rules above: lines joined by `\n`, with no trailing newline. `epoch` is a decimal integer, starting at 0 for the genesis root, whose key derives `network_id`.

| Statement | Signed by | Lines |
| --- | --- | --- |
| Host revocation | a root in the network's root chain | `capsule-revoke-host-v1`, `network_id`, `host_public_key`, `revoked_at` |
| Invite revocation | a root in the root chain | `capsule-revoke-invite-v1`, `network_id`, `invite_public_key`, `revoked_at` |
| Leave | the leaving host's key | `capsule-leave-v1`, `network_id`, `host_public_key`, `left_at` |
| Root rotation | the root of epoch `epoch − 1` | `capsule-root-rotate-v1`, `network_id`, `epoch`, `previous_root_public_key`, `root_public_key`, `rotated_at` |
| Attestation | the root of epoch `epoch` | `capsule-attest-v1`, `network_id`, `epoch`, `host_public_key`, `member`, `attested_at` |

Each is carried as a strict JSON object of its named fields plus `signature`; `epoch` is a JSON number, signed as its decimal spelling. Test vectors use the network, root, invite, and host keys of the earlier vectors, a new root with seed `BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=` (public `ypOsFwUYcHHWe4PH/w7+gQjo7EUwV113JoeTM9vavnw=`), time `2026-10-07T00:00:00Z`, epoch `1`, and member `alice`:

| Statement | `signature` |
| --- | --- |
| Host revocation of the host key, by the genesis root | `651E7LldaU/s+qQra4F9e6uJ5sDvFfYI0Nc+x4WdmfciBtVME9wp+fNq034EGTB2utFOLkPxhOg3k8gujAI7Ag==` |
| Invite revocation of the invite key, by the genesis root | `XyB3LsP1IaDW5saYFuHlIr4IVvrELl9hmDW9sX3PNAVeUfJaOzx5gnv6YSkGScAR+8ymDzYLYZ+VQ4leDNBhCQ==` |
| Leave, by the host key | `xM3Wn7Rl4G9jcG0fRUbbXjyFmWz1WcO4IC/tg8MrFOe9zEwWroQuSjo5Xhh92Mkwimg45gxfRCeOoxZC6/OeAA==` |
| Rotation to the new root at epoch 1, by the genesis root | `etkSBT7+to1vTCpIt+m5PMyO93tht5QhAmnxVMNCwmreGUrXmCcI4YWqxfznXx6WHe8rNZ/jK7N2FWUiy9N2Bw==` |
| Attestation of the host key at epoch 1, by the new root | `TBfNG88UlHWcSV6f79Ie1RApfqPr36hehooyjGebNB50FTB1tl9neEm42Ja13jXniAc+hU1YpRxcFVzfsF+iBg==` |

### Root chain and member validity

The **root chain** is the genesis root followed by verified rotations in epoch order. Each rotation is signed by the previous root, names it as `previous_root_public_key`, and increments `epoch` by exactly one. The **current root** is the last root in the chain.

- **Sticky chain:** a host persists the longest root chain it has verified. It applies a map only if that map's chain extends the persisted chain, or equals it. A different rotation at an already persisted epoch is a **fork**. The host refuses that map, records `last_sync_error` (`root chain conflict`), and keeps its state until an owner resolves it out of band.
- **Membership at epoch 0:** a member is valid by its invite chain under the genesis root, as before.
- **Membership at epoch > 0:** a member is valid only if one of these holds:
  - its invite chain verifies under the **current** root, for invites issued after the rotation;
  - there is an attestation of its host key, signed by the current root, at the current epoch.

  Chains under older roots alone no longer count, so a compromised old root cannot enroll hosts after a rotation.
- **Revocations:** a revocation verifies under **any** root in the chain. Revocations fail closed: a compromised old root can remove members but never add them. A member is dropped if its host key is revoked, if a valid leave statement exists for it, or if its invite key is revoked. Revoking an invite blocks joins with it and also drops any host that already joined with it.
- **Effect:** a dropped host is no longer known through that network. It fails peer authentication unless an owner configured it as a manual peer, and it loses relay access, as specified for members in general. Per-request authentication applies to already-open connections. A revoked host or invite cannot be reinstated in this milestone. A revoked or departed host key can never rejoin, even with a fresh invite: the coordinator returns 403. Rejoining therefore means a new host identity, with a new state directory and key, plus a new invite.

### Coordinator

The map gains `rotations`, `attestations`, and `revocations`. `rotations` lists the chain's rotations in epoch order. `attestations` lists those for the current epoch. `revocations` lists every accepted host revocation, invite revocation, and leave, each as `{kind, statement}` with `kind` one of `host`, `invite`, or `leave`. The coordinator verifies everything it accepts and stores it permanently. It excludes revoked and departed hosts from `members`. It refuses their sync, relay registration, and re-registration with 403, and refuses joins with a revoked invite with 403.

| Endpoint | Body | Behavior |
| --- | --- | --- |
| `POST /coord/v1/networks/{network_id}/revocations` | `kind` (`host` or `invite`), `statement` | Accepts a revocation that verifies under any root in the chain. The caller must be a member. Returns 200 with the map; an identical repeat returns 200. |
| `POST /coord/v1/networks/{network_id}/leave` | `statement` | The leave statement's host key must be the caller. Returns 200 with `{}`. |
| `POST /coord/v1/networks/{network_id}/rotations` | `rotation`, `attestations` | The caller must be a member. The rotation must extend the coordinator's chain by exactly one epoch. An identical resubmission of an accepted rotation returns 200, and a different rotation at an existing epoch returns 409. `attestations` must cover every current member except revoked or departed ones, each signed by the new root. Returns 200 with the map. |

On these endpoints, an unknown network returns 403, as for sync. A `leave` kind sent to the revocations endpoint returns 400. The coordinator database moves to version 3. Its schema stays internal.

### Host

Database version 7 adds `CREATE TABLE network_statements (network_id TEXT NOT NULL, kind TEXT NOT NULL, subject TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(network_id, kind, subject))`. `kind` is one of `rotation` (subject: the epoch), `attestation` (subject: the host key), `host`, `invite`, or `leave` (subject: the revoked key). The table holds every verified statement for the network. On the administrator host, `networks.root_seed` holds the **current** root seed. The network record gains `root_epoch` and `current_root_public_key`, while `root_public_key` remains the genesis key that derives the ID. Older binaries reject version 7.

| CLI after `--state DIR` | Local API | Behavior |
| --- | --- | --- |
| `network revoke --network ID --host HOST_ID` | `POST /v1/networks/{id}/revocations` with `{host_id}` | Administrator only (403 otherwise). Revoking this host itself returns 409. Signs a host revocation with the current root and persists it with `network.host_revoked`, enforced locally at once. It is submitted to the coordinator now and on every later sync until accepted. Returns 201 with `{network_id, kind, subject, submitted}`. |
| `network revoke-invite --network ID --invite INVITE_PUBLIC_KEY` | `POST /v1/networks/{id}/revocations` with `{invite_public_key}` | Same rules as host revocation, for an invite. Records `network.invite_revoked`. |
| `network leave ID` | `POST /v1/networks/{id}/leave` | Not allowed for the administrator, which returns 409. Signs a leave statement and tries the coordinator once. It then removes the network, its members, and its statements locally with `network.left`, whether or not the coordinator accepted. Returns 200 with `{network_id, submitted}`. |
| `network rotate-root ID` | `POST /v1/networks/{id}/rotate` | Administrator only. Generates a new root and signs the rotation with the current root. Signs attestations for every current valid member, including this host. **Before submitting,** it persists all of this as a pending rotation. The old root stays current locally until the coordinator accepts; then the new seed, rotation, and attestations become current atomically, with `network.root_rotated`. If the coordinator is unreachable, it returns 503 and keeps the rotation pending. Returns 200 with the network record. |

**Pending rotation.** A pending rotation is a `network_statements` row of kind `pending_rotation`. Its subject is the new epoch in decimal, and its record is `{rotation, attestations, root_seed}`, where `root_seed` is the new seed in standard Base64. The state directory is private, as for `networks.root_seed`. On restart and on every sync, the administrator resubmits a pending rotation until it is accepted. The coordinator returns 200 for a resubmission identical to a rotation it already accepted. If the coordinator returns 409 (a different rotation at that epoch) or 400 (it can never accept this rotation), or its chain has moved past that epoch, the host discards the pending rotation and records the sync error `root rotation discarded: <reason>`. Any other failure keeps the rotation pending. Persisting before submitting closes the window in which a crash right after acceptance would leave the coordinator on a root whose seed no host holds.

**Additional rules:**
- **Invite tokens after a rotation** carry the current root, the signer, in `root_public_key`. Decoding no longer requires that key to derive `network_id`. On join, the genesis root comes from the map and must derive the ID, and the membership must verify under the verified chain.
- **A coordinator chain shorter than the persisted one** is refused with the sync error `coordinator root chain is behind this host`.
- **Storage:** `network_statements` rows hold the bare statement JSON. A revoke response's `subject` is the revoked public key.
- **Revoke errors:** revoking an unknown host returns 404, and revoking the invite this host itself joined with returns 409. Repeating a revocation returns the stored statement, even after the revoked host has been dropped locally, with no second event; it is resubmitted if not yet accepted. Leaves are not resubmitted by other hosts, because the coordinator accepts a leave only from the departing host. Null fields in the revoke body are treated as absent.
- **Resubmission:** any host, not only the administrator, resubmits valid revocations it holds that the coordinator does not list.
- **Already-open connections:** a request from a host that is no longer known gets 403 on an already-open connection; the connection is not closed.

Network and member records report the effect: a revoked or departed member disappears from `network members`. New activity kinds: `network.host_revoked` (subject: host ID), `network.invite_revoked` (subject: invite key), `network.member_left` (another host's leave, seen in a map), `network.left`, and `network.root_rotated`. A dropped host also produces `network.member_removed`.

## Persons and host binding

Roadmap milestone 2b, slice 1. The design is in the [person identity proposal](person-identity-proposal.md), and its decisions apply. Administrators keep admitting hosts. Persons are an optional layer: an administrator admits a person, and the person binds hosts that are already admitted. Until slice 2 adds delegated administrators, the administrator is the host holding the current root seed. Persons authorize nothing yet; slice 3's owner policy builds on them.

### Person keys and signatures

A person key is an OpenSSH `ssh-ed25519` key. Only the CLI uses it. Daemons never read or store person keys, and receive only signed statements. One exception: a person key that the CLI generated, as specified in slice 3 of the [launch contract](launch-contract.md), may be read from the user's configuration by the daemon to renew policies.

- **Agent signing (default):** the CLI signs through `ssh-agent` at `SSH_AUTH_SOCK`, using the only `ssh-ed25519` identity in the agent. It is an error if there are none or several.
- **Choosing a key:** `--person-key PATH` names either a public key file, which selects that identity in the agent, or an unencrypted OpenSSH private key file, which signs locally without an agent.
- **Format:** person statements are signed in OpenSSH `SSHSIG` format, with namespace `capsule-person-v1` and hash `sha512`. The JSON `signature` field is standard Base64 of the binary `SSHSIG` blob: the bytes inside an armored `-----BEGIN SSH SIGNATURE-----` block, without the armor.
- **Verification:** a verifier checks the `SSHSIG` magic and version 1, that the embedded public key is `ssh-ed25519` with the expected person key, the namespace, an empty reserved field, hash `sha512`, and the Ed25519 signature over the `SSHSIG` signed data. `ssh-keygen -Y verify -n capsule-person-v1` accepts these signatures.
- **Keys and IDs:** person public keys in statements are canonical standard Base64 of the 32 raw key bytes. A person ID is `person_` followed by the lowercase hex SHA-256 of those bytes.

`capsule-host person show [--person-key PATH]` needs no daemon. It prints `{person_id, public_key, ssh_public_key}`.

### Statements

| Statement | Signed by | Lines |
| --- | --- | --- |
| Person admission | root of `epoch` (raw Ed25519) | `capsule-person-admit-v1`, `network_id`, `epoch`, `person_public_key`, `member`, `admitted_at` |
| Person invite | root of `epoch` (raw Ed25519) | `capsule-person-invite-v1`, `network_id`, `epoch`, `invite_public_key`, `member`, `invite_expires_at` |
| Person membership | the person invite key (raw Ed25519) | `capsule-person-member-v1`, `network_id`, `invite_public_key`, `person_public_key`, `joined_at` |
| Person removal | any root in the chain (raw Ed25519) | `capsule-person-remove-v1`, `network_id`, `person_public_key`, `removed_at` |
| Host admission | root of `epoch` (raw Ed25519) | `capsule-host-admit-v1`, `network_id`, `epoch`, `host_public_key`, `member`, `admitted_at` |
| Host binding | the person (`SSHSIG`) **and** the host (raw Ed25519, `host_signature`) | `capsule-host-bind-v1`, `network_id`, `person_public_key`, `host_public_key`, `bound_at` |
| Host unbinding | the person (`SSHSIG`) | `capsule-host-unbind-v1`, `network_id`, `person_public_key`, `host_public_key`, `unbound_at` |

Each statement is carried as a strict JSON object of its fields plus `signature`, with `epoch` as a JSON number. A person **membership** object nests its invite: `{network_id, member, invite_public_key, invite_expires_at, invite_epoch, invite_signature, person_public_key, joined_at, person_signature}`. The person invite statement's lines use `invite_epoch` as their `epoch`.

**Test vectors.** These use the network, root, invite, and host keys of the earlier vectors. The person seed is `BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU=`, its public key `bnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/E=` (OpenSSH `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG56HN0psLeP0Tr0xVmP7/TvKpcWbjym8uT7/M2AUFvx`), and its ID `person_7599776c3085e3f9da0d13071eb0b4ab50fd2bf64c06dd92c2365af3a328eca3`. Times are `2026-10-08T00:00:00Z`, and the invite expires `2026-11-01T00:00:00Z`. Epochs are 0. The person member label is `bob` and the host member label is `carol`.

| Statement | `signature` |
| --- | --- |
| Person admission | `57pOZqduTPBJKqC2gEAjW23pzd7zwul08CTAxX2KBRSlI36JJfb5WNf8x9LOlaLKK1jBL2r72mLJXIkpTYi+BA==` |
| Person invite | `DOs/7yFxVmC3IuPAcfqlF1EDczkw0++1gRZOjIQNCcK7d3nOPFDZoWcnrhMpBIzdLlEF6fR52K45m8TXGKNVAQ==` |
| Person membership | `FP3SdKMjbdMcRQIsfMffRb6mnyqnDnX4hxj/cTz6DHyWeozcrRxdGU+/lYLEakp8tiS/jwOiCLJA/7DXhfOrDw==` |
| Person removal | `gIGBRuXaZVCyEU+jkM1JUxo88yDrpZ8k7JbmKGObmeF14QeY2//Wdrn4CgetByjN4szTFbssvtuS6ynt3O8jBA==` |
| Host admission | `fYyNXrDCWJs61KeT2macWLkh/D+WVMI1i10iiC2mpFoQ9fz7EhDhy8KXAr+zjRfpdRzhzpGfAfEF4dBcMYGUCw==` |
| Host binding `host_signature` (host key) | `xv+sVNH6/g1gJrknO2ImE97qrROduO2Oe0U4gvqcddbHibmhzR28SRWf7RtYUDizWnWE4Eufy3F1aijw6uvSDg==` |
| Host binding (`SSHSIG`) | `U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgbnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/EAAAARY2Fwc3VsZS1wZXJzb24tdjEAAAAAAAAABnNoYTUxMgAAAFMAAAALc3NoLWVkMjU1MTkAAABADAULCAWp02fy0fuxtv6fhaI8PHqxyBPr6SzVcTupgU0xsTYIMciLKFSVOaqYIOshUcKvNhgbAmBsiz6Cbe7UBw==` |
| Host unbinding (`SSHSIG`) | `U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgbnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/EAAAARY2Fwc3VsZS1wZXJzb24tdjEAAAAAAAAABnNoYTUxMgAAAFMAAAALc3NoLWVkMjU1MTkAAABAkiK02ZWdpz63BExI0ccVmkrPSaSUJEVrherPRCB7IWIDjvE6x1VieH2UJnMuWmp5tiXmTHuTs4mxDyehsUr4AA==` |

Ed25519 is deterministic, so an implementation holding the person seed must reproduce these `SSHSIG` blobs byte for byte.

### Validity

The rules below apply at the network's current epoch *e* and current root, as defined in milestone 2a.

- **Hosts.** A host is a member if its invite chain is valid, as before, or if a host admission of its key is signed by the current root at epoch *e*. The admission at epoch 0 is signed by the genesis root. In either case, the host must not be revoked or departed.
- **Persons.** A person is admitted in either of two ways:
  - a person admission of its key, signed by the current root at epoch *e*;
  - a person membership whose invite is signed by the current root at epoch *e*, whose invite has not been revoked, and whose `joined_at` ≤ `invite_expires_at`.

  It must also have no valid person removal, under any root in the chain. Removal is sticky and permanent: the key can never be readmitted, and a new key is needed.
- **Unique person labels.** Two person `member` labels conflict if they are equal after mapping ASCII `A`–`Z` to `a`–`z`; other characters compare exactly. A team may well have two people called Bob, and they must be admitted under different labels, such as `bob.smith` and `bob-platform`.
  - The coordinator refuses a person admission, or a person invite redemption, with 409 if a current person (admitted and not removed) holds a conflicting label.
  - An administrator host checks the same rule before signing a person admission or issuing a person invite.
  - A removed person's label becomes available again.
  - Labels are for people only. Nothing authorizes by label: identity is the person key, and signed statements name keys or person IDs.
  - If a verified map nonetheless contains conflicting labels, which only a misbehaving coordinator can produce, hosts keep both persons and report `label_conflict: true` for each in `network persons`. They do not drop either.
- **Bindings.** A host is bound to a person if four things hold:
  - both are currently valid;
  - a host binding exists that carries both a valid `SSHSIG` signature by that person and a valid `host_signature` by that host's key over the same statement;
  - no valid host unbinding by that person for that host exists, which is sticky.

  The host signature is the host's consent, and every host verifies it. Other hosts therefore need not trust the coordinator's claim about who submitted a binding. A coordinator colluding with a person key cannot bind someone else's host to that person, which matters once a person's policy governs their hosts' agents (slice 3). The coordinator additionally requires the bound host to submit the binding itself.

  A host is bound to at most one person: the coordinator refuses a second binding with 409 until the first is unbound. If the person is removed, all of their bindings end.
- **Rotation.** When the root rotates, the administrator re-signs a host admission or a person admission at the new epoch for every currently valid key admitted by public key or person invite. These are submitted with the rotation as `admissions`. Bindings need nothing new.

### Network descriptor

`capsule-network-v1.` followed by unpadded base64url of strict JSON `{network_id, network_name, root_public_key, coordinator_address, coordinator_public_key}`. `root_public_key` is the **genesis** root, which derives `network_id`. A descriptor is not a secret. It lets a host or person whose key an administrator admitted find and pin the network, and it grants nothing by itself.

### Coordinator

The map gains `persons`: an array of `{person_id, person_public_key, member, admission | membership}`, sorted by `person_id`. Each members entry gains `admission` (nullable), set when the host joined by public key and replacing `membership`. It also gains `binding` (nullable), the host's current binding statement. `revocations` gains the kinds `person` (removal) and `unbind`. The rotation endpoint gains a required `admissions` array, which may be empty.

| Endpoint | Body | Behavior |
| --- | --- | --- |
| `POST /coord/v1/networks/{network_id}/persons` | exactly one of `admission`, `membership` | The caller must be a member. Admits a person after verification; an identical repeat returns 200. A removed person key returns 403, and a reused person invite 409. Returns 200 with the map. |
| `POST /coord/v1/networks/{network_id}/hosts` | `admission` | The caller must be a member. Records a host admission. The admitted host then joins with it. Returns 200 with the map. |
| `POST /coord/v1/networks/{network_id}/members` | `membership` or `admission`, plus `address`, `candidates` | Join, as before. With `admission`, the admitted host key must be the caller. |
| `POST /coord/v1/networks/{network_id}/bindings` | `binding` | The caller must be the bound host and a member. The person must be admitted. Returns 409 if the host is already bound, 403 if the binding was unbound before (unbinding is permanent for that host and person), and otherwise 200 with the map. |
| `POST /coord/v1/networks/{network_id}/revocations` | adds the kinds `person` and `unbind` | Person removal (root-signed) or host unbinding (person-signed, submitted by any member), with the same sticky and idempotent rules as other revocations. |

### Host

There is no schema change. The statements are stored in `network_statements` (database version 7), alongside the existing revocation kinds:
- `person` (subject: person key), holding `{admission, membership}` with exactly one non-null;
- `host_admission` (subject: host key);
- `binding` (subject: host key);
- `person_removal` (subject: person key), which a map lists as revocation kind `person`;
- `unbind` (subject: `<person key> <host key>`).

Member records make `membership` nullable, and gain `admission`, `person_id`, and `person_member`, also nullable. In maps, members and persons carry both `membership` and `admission`, with one of them null, and a member's `binding` is null when it is unbound.

Further rules:
- **Joining by descriptor** sends `{address, candidates}` to the members endpoint, and the coordinator uses its recorded admission. An explicit `admission` is also accepted.
- **Rotation `admissions`** holds bare host and person admissions, told apart by which key field is present. A pending rotation record gains `admissions`, which is empty when absent. At a rotation, the administrator re-signs only admissions still valid at its epoch, and an admission that is not re-signed lapses.
- **Coordinator acceptance:** admitting a person or a host requires the coordinator to accept, and otherwise returns 503 with nothing persisted. Unbinding and person removal are local-first and idempotent, and return the revocation shape `{network_id, kind, subject, submitted}`.
- **Person keys in the local API:** `person_public_key` accepts canonical Base64 or an `ssh-ed25519` line, and the CLI also accepts a path to a `.pub` file.
- **Invite revocation** also drops persons admitted only through that invite.
- **Admission rules:** binding to an unadmitted person returns 403, and an already admitted person keeps its original admission.

| CLI after `--state DIR` | Local API | Behavior |
| --- | --- | --- |
| `network admit --network ID --person SSH_PUBLIC_KEY --member LABEL` | `POST /v1/networks/{id}/persons` with `{person_public_key, member}` | Administrator only. Signs and submits a person admission. Returns 201 with `{person_id, descriptor}`. `SSH_PUBLIC_KEY` is an `ssh-ed25519` public key line or a path to one. |
| `network admit --network ID --host HOST_PUBLIC_KEY --member LABEL` | `POST /v1/networks/{id}/hosts` with `{host_public_key, member}` | Administrator only. Signs and submits a host admission. Returns 201 with `{host_id, descriptor}`. |
| `network invite-person --network ID --member LABEL --expires-at TIME` | `POST /v1/networks/{id}/person-invites` | Administrator only. Returns 201 with a token in the host-invite format, `capsule-person-invite-v1.` followed by unpadded base64url JSON with the host-invite fields plus `invite_epoch`. |
| `network redeem-person --token TOKEN [--person-key PATH]` | `POST /v1/networks/redeem-person` with `{token, person_public_key}` | Run on any member host of that network. The CLI supplies the person's public key, and the daemon signs the membership with the invite seed and submits it. Returns 201 with `{person_id}`. |
| `network join --descriptor DESCRIPTOR` | `POST /v1/networks/join` with `{descriptor}` | Joins with an administrator's admission of this host's key, otherwise as an invite join. Returns 403 if no admission for this host exists. |
| `network bind --network ID [--person-key PATH]` | `POST /v1/networks/{id}/bindings` with `{binding}` | The CLI fetches this host's key from the daemon and signs the binding as the person. The daemon then adds its own `host_signature` and submits it as itself. A daemon refuses a binding of any key other than its own. After the coordinator accepts, the daemon stores the binding and its `network.host_bound` event locally before responding, so success means this host has the binding, regardless of any later sync. Returns 201 with `{network_id, host_id, person_id}`. |
| `network unbind --network ID --host HOST_ID [--person-key PATH]` | `POST /v1/networks/{id}/unbindings` with `{unbinding}` | Can be run on any member host, signed by the person. Persisted, enforced, and submitted until accepted, like a revocation. Returns 201. |
| `network remove-person --network ID --person PERSON_ID` | `POST /v1/networks/{id}/person-removals` with `{person_id}` | Administrator only. Same rules as host revocation. Returns 201. |
| `network persons ID` | `GET /v1/networks/{id}/persons` | Valid persons sorted by ID: `{person_id, public_key, member, hosts, label_conflict}`, where `hosts` lists their bound host IDs and `label_conflict` is normally false. |

`network members` reports each host's `person_id` and `person_member`, or null. New activity kinds, recorded on every host when its verified map changes, except `network.host_admitted`, which only the administrator records:
- `network.person_admitted` (subject: person ID);
- `network.person_removed` (subject: person ID);
- `network.host_admitted` (subject: host ID);
- `network.host_bound` (subject: host ID);
- `network.host_unbound` (subject: host ID).

### One-command flows

Agreed on 2026-10-07, to keep administration simple for launch. The commands above remain for unusual setups, but the default flows hide the person layer. Every flow still produces exactly the statements specified above. Nothing new is trusted, and the daemon never sees a person key.

**Person key discovery.** `network create` and `network join` look for a person key unless given `--no-person`. They use `--person-key PATH` if given; otherwise, the only `ssh-ed25519` identity in `ssh-agent`. If there is no agent, or no such key, or several, the person part is skipped and the reason is reported. That is never an error. An explicit `--person-key` that cannot be used, because it is unreadable, encrypted, not Ed25519, or not in the agent, is an error before anything else happens, so no host joins.

**Member invite (default).** `network invite --network ID --member LABEL --expires-at TIME` now issues a member invite. `--host-only` issues the previous host-only invite. A member invite is `capsule-member-invite-v1.` followed by unpadded base64url of strict JSON: the host invite token's fields plus `invite_epoch` and `person_invite_signature`. One invite key is signed twice by the current root: as a host invite (`invite_signature`) and as a person invite with the same member label and expiry (`person_invite_signature`, over the person invite statement at `invite_epoch`). The host part and the person part are each single-use under the existing rules. Issuing a member invite does not check person-label uniqueness, so a person's further machine can be invited under that person's own label. Uniqueness is checked when the person part is redeemed, and a conflict is reported as `skipped`. The person part can also be redeemed later with `network redeem-person --token`, until the invite expires.

**`network join --token TOKEN [--person-key PATH] [--no-person]`** accepts host-only and member tokens. `network join --descriptor` follows the same steps, without an admission.

1. If a person key was found, the CLI asks the daemon for this host's key (`GET /v1/host`). It then signs a host binding for the token's network as the person, and sends `{token, person_public_key, binding}` (or the descriptor) to `POST /v1/networks/join`.
2. The daemon joins the host exactly as before. A failure here fails the command, and nothing else happens.
3. If a person key was supplied, the daemon continues with the person part:
   - If that person is already admitted in the network, it skips admission.
   - Otherwise, for a member token, it signs the person membership with the invite seed and submits it.
   - It then adds its host signature to the binding, submits it, and stores it as for `network bind`.
4. The response is the network record plus `person`: `{person_id, admitted, bound, skipped, next}`, or null if no person key reached the daemon. `admitted` means the person is admitted after the command, whether newly or already. `skipped` is null or a human-readable reason, and `next` is null or the follow-up command or commands. Their wording is guidance for people, so implementations may phrase it differently and suites check only its presence. A failure in the person part, such as a taken label, no admission, or the coordinator refusing, does not undo the host join, and the command still succeeds.

**`network create ... [--person-key PATH] [--no-person]`.** If a person key was found, then after registering the network, the creator's daemon signs a person admission for the creator's key with the new root, under the creator's `--member` label. It also binds this host using the binding the CLI signed. The response gains `person` with the same shape. If registration has not succeeded yet, for example because the coordinator is unreachable, the person part is skipped and `next` names the commands to finish it. The network ID is not known until create returns, so the CLI binds in a second request. An API-only caller sees `admitted: true`, `bound: false`, and the bind command in `next`.

**Further machines.** For a person's second host, the administrator issues a member or host-only invite, or admits the host by public key. The person runs `network join`. That person is already admitted, so the join binds the new host to them, with no admission step.

Activity events are those of the individual operations.

## Administrators and groups

Roadmap milestone 2b, slice 2. Decided on 2026-10-07:

- **Delegated administrators** do everything except govern the root. They admit and remove hosts and persons, issue invites, revoke, and define groups. Only the root delegates or removes administrators and rotates.
- **Removing an administrator** keeps what they admitted, unless the removal says otherwise.
- **The root can go offline** by rotating to an SSH key.
- **`network create`** makes the creator's person the first administrator.

### Signatures

A root signature is either raw Ed25519, the 64-byte signature used until now, or an `SSHSIG` blob whose embedded key is the root. Verifiers accept both forms for every root-signed statement. An **administrator signature** is an `SSHSIG` blob (namespace `capsule-person-v1`) whose embedded key is a current administrator.

These statements may carry either a root signature or an administrator signature:
- host invite and person invite (`invite_signature`, `person_invite_signature`);
- host admission and person admission;
- host revocation, invite revocation, and person removal;
- group definition.

Delegation, administrator removal, rotation, and attestation remain root-only.

**Map `admins`** serves the latest verified delegation for every person key, including removed administrators, so their kept statements still verify on hosts that join later. A person who is a current administrator cannot be removed as a person until their administrator role has been removed, with either `revoke_admitted` choice. The person removal otherwise returns 409, so what happens to their statements is always explicit.

### Statements

| Statement | Signed by | Lines |
| --- | --- | --- |
| Administrator delegation | root of `epoch` | `capsule-admin-delegate-v1`, `network_id`, `epoch`, `person_public_key`, `delegated_at` |
| Administrator removal | any root in the chain | `capsule-admin-remove-v1`, `network_id`, `person_public_key`, `revoke_admitted` (`true` or `false`), `removed_at`, then, only when `revoke_admitted` is `false`, one line per kept statement digest in ascending order |
| Group definition | root or administrator | `capsule-group-v1`, `network_id`, `name`, `version`, `defined_at`, then one line per member person ID, in ascending byte order with no duplicates |

Group names are 1–64 bytes of lowercase ASCII letters, digits, `.`, `_`, and `-`, starting with a letter or digit. `version` is a decimal integer of at least 1. A definition with no member lines deletes the group. Group members are always person IDs, never labels.

**Test vectors.** These use the earlier root, host, and person keys, with the person as the administrator. A second person has seed `BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY=` (public key `iodf/x6zhFFXes1a/uQFRWVo3XyJ4JCGOgVXvHr0nxc=`, ID `person_72456720412037a6b339f884ce6d91bb4cc163a7dc3e4c58c658e6c2097b92a2`). Times are `2026-10-09T00:00:00Z`, and the epoch is 0.

| Statement | `signature` |
| --- | --- |
| Delegation of the person, by the genesis root (raw) | `lmKnLMD6XXbYk4pExnNpxbFHR9bZccZWHmlTq7Yssam9dkzfeE7n/2rKom9raC5FmPM7HY7P/TLzx1Vn43zlAg==` |
| Removal of the person as administrator with `revoke_admitted` `true`, by the genesis root (raw) | `R1qwK9h6ZU+QyzpsXKf5fZWFzqDo0CoTYyi3S/KReuGQn6Dbr0KRGaMDwsciCb6ANbAF5Ye2Vs6V/qBnWwoABA==` |
| Host admission (member `carol`) signed by the administrator (`SSHSIG`) | `U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgbnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/EAAAARY2Fwc3VsZS1wZXJzb24tdjEAAAAAAAAABnNoYTUxMgAAAFMAAAALc3NoLWVkMjU1MTkAAABAGcn2mQsdrkxxBpUyZFanSkCt4bNXYd5C9IjqaLeEs9HxQBscBZYl7WlhEUHuoffN6pW+hZDICMZH5jTfbs4mAg==` |
| Group `backend`, version 1, with both persons, signed by the administrator (`SSHSIG`) | `U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgbnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/EAAAARY2Fwc3VsZS1wZXJzb24tdjEAAAAAAAAABnNoYTUxMgAAAFMAAAALc3NoLWVkMjU1MTkAAABAVIvTT/9fTeKaYW0R9edFKS2bknw2Pu/MYty3zhnrayKHhm+lT0xtwfNsdawnv4hFr7UW5PDYaHTIflrZ/f9MAA==` |

### Validity

- **Administrators.** A person is an administrator at epoch *e* if four things hold:
  - they are a valid person;
  - a delegation of their key exists at epoch *e*, signed by the current root;
  - no administrator removal of them exists;
  - no person removal of them exists.

  Removal is sticky and permanent for that key. A root rotation re-signs every current administrator's delegation at the new epoch, alongside the other admissions.
- **Administrator-signed statements** are valid while their signer is a current administrator. They need no re-signing at a rotation. A **statement digest** is the lowercase hex SHA-256 of a statement's signed lines, joined with `\n` exactly as signed. A removal with `revoke_admitted: false` lists the digests of every statement that administrator had signed, as verified by the host issuing the removal. After it, only the listed statements stay valid. Signing times are asserted by the signer and cannot order statements, so without this list a removed key could keep signing backdated statements that a misbehaving coordinator might serve. After a removal with `revoke_admitted: true`, every statement that administrator signed becomes invalid, as if never issued. This includes invites, so members who joined through them are dropped too. It also includes group versions, so each affected group reverts to its newest version signed by a signer that is still valid, or ceases to exist.
- **Groups.** For each name, the valid definition with the highest `version` applies. The coordinator refuses a definition whose version is not higher than the current one, with 409. Hosts persist the highest version they have verified and never accept a lower one, except for the revert caused by `revoke_admitted`. Members that are not current persons are ignored.

### Which key signs

The same commands as before (`network invite`, `invite-person`, `admit`, `revoke`, `revoke-invite`, `remove-person`) and the new group commands choose a signer automatically:
- If this host holds the current root seed, the daemon signs with the root, as today.
- Otherwise, the CLI signs with the person key (discovered as in the one-command flows), and that person must be a current administrator; otherwise the command returns 403. The daemon still never sees person keys. It receives the statement already signed.

The root-only commands sign with the root seed when this host holds it. Otherwise they sign through the CLI with `--root-key PATH`, a `.pub` file selecting an agent identity, or an OpenSSH private key file.

### Commands

| CLI after `--state DIR` | Local API | Behavior |
| --- | --- | --- |
| `network delegate-admin --network ID --person PERSON [--root-key PATH]` | `POST /v1/networks/{id}/admins` | Root only. `PERSON` is a person ID or a label, resolved with an error on ambiguity. Signs and submits a delegation. Returns 201. |
| `network remove-admin --network ID --person PERSON [--revoke-admitted] [--root-key PATH]` | `POST /v1/networks/{id}/admin-removals` | Root only. It is sticky and local-first, like a revocation. Returns 201 in the revocation shape. |
| `network group set --network ID --group NAME [--person PERSON ...]` | `POST /v1/networks/{id}/groups` | Administrator or root. Resolves labels to person IDs, with an error on ambiguity. Signs the next version, one higher than the newest this host has verified, and submits it. Giving no `--person` deletes the group. Returns 201 with the group. |
| `network groups ID` | `GET /v1/networks/{id}/groups` | Current groups sorted by name: `{name, version, members, signer}`. |
| `network rotate-root ID --to-ssh --root-key PATH` | `POST /v1/networks/{id}/rotate` | Rotates to the SSH key named by `PATH`. The CLI signs the new root's admissions, attestations, and delegations through `PATH`. After the rotation is accepted, this host deletes its root seed. Later root actions use `--root-key`. Rotating from an SSH root to another SSH root works the same way. |

**Further rules:**
- **Rotation:** a rotation renews only root-signed members, admissions, and person invites, plus the delegations of current administrators. Administrator-signed statements are kept as they are.
- **SSH to SSH rotation:** when the current root is already an SSH key, the CLI finds it in `ssh-agent`.
- **`root_ssh`** is true once the current root has signed any current-epoch statement as `SSHSIG`, or after this host's own `--to-ssh` rotation.
- **Group versions:** the next version accounts for deleted versions too. `GET /v1/networks/{id}/groups?all=true` includes deleted groups.
- **Ambiguous labels:** the error says `ambiguous` and lists the matching person IDs; key fingerprints are optional.
- **Coordinator request bodies:** `POST .../admins` takes `{delegation}`, `POST .../admin-removals` takes `{statement}`, and `POST .../groups` takes `{group}`.

- **Root-signed groups at a rotation:** the new root re-signs them at the same version, with the same members. The coordinator accepts such a renewal, and hosts treat it as the same version. Without renewal they would lapse. Accepting groups signed by old roots instead would let a compromised old root add members.
- **One removal per administrator key:** a second plain removal returns 409. A removal with `revoke_admitted: true` may replace an earlier plain one, as an escalation that is sticky and recorded with another `network.admin_removed`. Kept lists are never merged.
- **Epochs:** an administrator-signed admission's `epoch` must be at most the current epoch.
- **Unjoined hosts:** hosts admitted by public key that have not joined yet are renewed at a rotation like other admissions. A host stores every host admission it issues under the kind `host_admission`, whether the host has joined or not, so either implementation can reopen the other's state.
- **Group renewal format:** rotation plans list root-signed groups as `{name, version, members}`, including deleted ones. Both rotate requests, local and coordinator, carry the renewed definitions as a `groups` array, with `defined_at` set to the rotation time.
- **Several person keys:** administrator-signed commands accept an optional `--person-key PATH` for choosing a key when the agent holds several. The default flows need no flag.
- **Local API endpoints:**
  - `GET /v1/networks/{id}/rotation-plan` returns what a rotation must re-sign.
  - `GET /v1/networks/{id}/admin-removal-plan?person=ID` returns the kept-digest list a removal would carry.
  - `POST /v1/networks/{id}/admins` returns `{network_id, person_id}`.

`network persons` reports `administrator` (bool) for each person. A network record keeps `administrator` with its old meaning: this host holds the root seed. The record gains `root_ssh` (bool), which is true when the current root is an SSH key.

**Default.** When `network create` admits the creator's person (see One-command flows), the root also delegates that person as an administrator. `--no-person` skips both. The creator can then administer from any of their machines with their SSH key, and can move the root offline with `rotate-root --to-ssh` whenever they choose.

**Coordinator.** The map gains `admins`, the current delegations, and `groups`, the current group definitions. `revocations` gains the kind `admin`. The coordinator accepts administrator-signed statements on the existing endpoints, plus `POST .../admins`, `POST .../admin-removals`, and `POST .../groups`, verifying signers against its own view. The rotation endpoint's `admissions` also carries delegations.

**Storage.** Hosts store the statements in `network_statements` under the kinds `admin` (subject: person key), `admin_removal` (subject: person key), and `group` (subject: name, holding the newest verified version). A pending rotation to an SSH root stores no seed. New activity kinds: `network.admin_delegated`, `network.admin_removed`, and `network.group_updated` (subject: group name).

## Owner access policy

Roadmap milestone 2b, slice 3. Decided on 2026-10-07:
- **Policy and grants combine:** a request is authorized by a manual grant **or** by the target agent owner's policy. A host-local block list overrides both.
- **Renewal:** daemons renew policies by asking the owner's `ssh-agent` for a signature, and never hold the key, except a CLI-generated key (see the [launch contract](launch-contract.md), slice 3).
- **Visibility:** every member sees every policy.
- **Propagation:** an owner's hosts also pass policies to each other directly (roadmap 2c; see [Direct propagation](#direct-propagation)).

Policies name persons by ID, never by label, per the naming rules.

### Policy statement

A policy is signed by its owner (`SSHSIG`, namespace `capsule-person-v1`). Its lines are:
- the header: `capsule-policy-v1`, `network_id`, `person_public_key`, `version`, `issued_at`, `valid_until`;
- then, for each rule in order, five lines:
  1. `rule`;
  2. the agent name;
  3. the principals, space-separated;
  4. the actions, space-separated;
  5. `max_message_bytes` and `allow_disconnected` (`true` or `false`), space-separated.

The JSON is `{network_id, person_public_key, version, issued_at, valid_until, rules, signature}`, where each rule is `{agent, principals, actions, max_message_bytes, allow_disconnected}`. Lines follow the JSON order.

- **Agent:** an agent name on any host bound to the owner. Names in rules must not contain control characters.
- **Principals:** each is one of:
  - `person:<person ID>`;
  - `group:<name>`, a group defined by an administrator;
  - `network`, meaning every member host;
  - `agent:<host_id>/<agent_id>`, which matches only requests from that authenticated host whose asserted `origin.agent_id` is that agent (see Agent origin in the [messaging contract](peer-messaging-contract.md)).
- **Actions:** `message.append`, `task.submit` (see the [task contract](task-contract.md)), and `task.delegate`, which implies `task.submit` (see the [delegation chain contract](delegation-chain-contract.md)).
- **`max_message_bytes`:** 1 to 65,536.
- **`max_artifact_bytes`:** optional, 0 to 1,073,741,824, for task artifacts; see the [artifact contract](artifact-contract.md), which also defines its signed encoding.
- **Validity:** `valid_until` minus `issued_at` must be between 1 and 90 days. The CLI's default is 7 days, set with `--valid-days`.
- **At most** 64 rules and 64 principals per rule.

**Test vector.** The person is the earlier one, as owner. Version 1, issued `2026-10-10T00:00:00Z`, valid until `2026-10-17T00:00:00Z`. It has two rules:
- `reviewer` for `person:person_72456720412037a6b339f884ce6d91bb4cc163a7dc3e4c58c658e6c2097b92a2 group:backend`, `message.append`, `65536 false`;
- `triage` for `network`, `message.append`, `4096 true`.

Its `signature` is `U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgbnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/EAAAARY2Fwc3VsZS1wZXJzb24tdjEAAAAAAAAABnNoYTUxMgAAAFMAAAALc3NoLWVkMjU1MTkAAABAy54wZKMJ5nBPfB3XakG7muQtkw2rjuhFVU+oWwluflHQKmEqNNa3l4MB1x5cdPmyXJduUMs9R24za8w4kW0bDg==`.

**Versions.** A policy is valid if its owner is a current person, its signature verifies, and it falls within its validity window. Allow 5 minutes of clock skew before `issued_at`. For each owner, the highest valid version applies. The coordinator refuses a version that is not higher with 409. Hosts persist the highest version they have verified and never accept a lower one. A renewal is a new version with the same rules and a new validity window. The map gains `policies`: the newest valid policy of every person, visible to every member.

### Authorization

A receiving host bound to person P authorizes a message to its local agent named N in either of two ways:
- **Manual grant:** the request names a grant that this host holds, as before.
- **Policy:** P's newest verified policy is within its window, and has a rule for agent N with the requested action (`message.append` for messages) whose principals match the sender. The sender matches `person:<id>` if it is bound to that person. It matches `group:<name>` if it is bound to a member of that group. It matches `network` if it is a member host.

  Policy authorization also applies the rule's bounds:
  - the content is within `max_message_bytes`;
  - the deadline is at most `valid_until`;
  - the connected-state rule applies unless `allow_disconnected` is set, with 503 when it can recover, as for grants.

The **block list** is host-local, set by the owner with the commands below. A sender host blocked by host ID, or bound to a person blocked by person ID, is refused with 403 under both kinds of authorization, at once and without coordination.

Handoff and reply recheck authorization the same way. A lapsed or narrowed policy is final, like an expired or revoked grant. A recoverable connected state behaves as specified for grants.

**Request form.** A message names either `grant_id`, as before, or `policy`, which is `{person_id, version}`: the owner and the newest version the sender has verified. If the receiver's newest verified version for that owner is lower than the cited one, it returns 503 `unavailable`, and the sender retries once the receiver syncs. Otherwise the receiver evaluates its own newest version. The citation therefore never lets an older policy apply after a withdrawal.

### Renewal

`run [--person-agent SOCKET]` gives the daemon an agent socket. It defaults to the `SSH_AUTH_SOCK` the daemon started with. When the agent holds the bound person's key, and that person's current policy has less than a quarter of its validity left, the daemon asks the agent to sign a renewal. A renewal has the same rules, version + 1, the same duration, and `issued_at` set to now. The daemon submits it, and never stores the key. If several of the owner's hosts renew at once, they converge on one version by the tie-break in [Direct propagation](#direct-propagation). If no agent is available, access lapses at `valid_until`. Hosts report `expires_soon` in `access show` once less than a quarter remains.

### Commands

| CLI after `--state DIR` | Local API | Behavior |
| --- | --- | --- |
| `access allow --network ID --agent NAME --principal P [--principal P ...] [--action A [--action A ...]] [--max-message-bytes N] [--allow-disconnected] [--valid-days D] [--person-key PATH]` | `POST /v1/networks/{id}/policy` with `{policy}` | The CLI fetches the owner's current policy from the daemon. It adds or replaces the rule for NAME, with actions from `--action` (default `message.append`), resolving `person:LABEL` to an ID with an error on ambiguity, and signs version + 1. The daemon verifies and submits it. Returns 201 with the policy. |
| `access deny --network ID --agent NAME [--principal P ...] [--person-key PATH]` | same | Removes those principals, or the whole rule when none are given. It signs and submits a new version. |
| `access renew --network ID [--person-key PATH]` | same | Re-signs the current rules now. |
| `access show --network ID [--person PERSON]` | `GET /v1/networks/{id}/policy?person=ID` | The newest verified policy, mine by default, plus `expires_soon`. |
| `access block --person PERSON` / `--host HOST_ID` | `POST /v1/access-blocks` | Host-local, immediate, persisted. Returns 201. |
| `access unblock --person PERSON` / `--host HOST_ID` | `POST /v1/access-blocks/remove` | Host-local. |
| `access blocks` | `GET /v1/access-blocks` | Sorted list of `{kind, subject, created_at}`. |
| `access sync --network ID [--status]` | `/v1/networks/{id}/policy/sync` | Policy propagation among the owner's hosts; see [Direct propagation](#direct-propagation). |

**Further rules:**
- **Block requests:** a block takes `{person}` or `{host}`, exactly one. A person ID that no network knows may still be blocked. Blocking returns 201, and blocking again returns the existing entry. Unblocking returns the removed entry, or 404 if nothing was blocked.
- **`access show`** returns the policy's fields plus a top-level `expires_soon`, or 404 when the owner has no policy.
- **Policy submission:**
  - An identical resubmission of the stored policy returns 200 from the coordinator, as for other statements, and 201 from the local API. A lower version returns 409. An equal, different version returns 409 from the coordinator; the local API returns 201 when it wins the tie-break in [Direct propagation](#direct-propagation) and 409 otherwise. A policy outside its validity window returns 400.
  - The host records a verified policy before submitting it, then submits it to the coordinator and its sibling hosts (see [Direct propagation](#direct-propagation)), and returns 201 whether or not the coordinator is reachable.
- **Rule shape:** a rule has at least one principal and one action, and agent names must be valid labels. A policy with no rules is valid, and withdraws all access.
- **Expired policies:** renewal skips a policy that has already expired; only `access renew` revives it.
- **Several networks:**
  - A receiver bound to the cited person in several networks evaluates each. A rule matches only if the message fits its own size limit. Matching rules combine, and `allow_disconnected` holds if any matching rule sets it.
  - It returns 503 only when nothing authorizes and some network's policy is behind the cited version, or missing.
  - A send without a grant cites the first network, by ID, in which the target's person has a policy.
- **One authorization field:** a request carries exactly one of `grant_id` or `policy`, never both and never an empty `grant_id`, on the peer wire and in local send requests alike. A route or outbound record without a grant has `grant_id: null`.
- **Durations:** `access allow` uses `--valid-days`, default 7. `access deny` and `access renew` keep the current policy's duration.
- **`access deny`:** with no policy, or no rule for that agent, it is an error. If removing principals leaves a rule empty, the whole rule is removed.
- **Persons named in `access` commands** are resolved with the same errors as other person arguments: unknown, or ambiguous with candidates.
- **Refusal messages** for policy-cited requests may include an explanation. Their codes are as specified.

**Sending without a grant ID.** `message send` and adapter routes no longer require a grant. Given `--grant`, a request names it, as before. Otherwise the daemon cites the target host's bound person's newest verified policy. With no bound person, or no policy, the send is refused locally with 400 before anything is persisted.

**Storage.** Policies go in `network_statements` with kind `policy` (subject: person key), holding the newest version. Database version 8 adds `CREATE TABLE access_blocks (kind TEXT NOT NULL, subject TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(kind, subject))`, with `kind` either `person` or `host`, and older binaries reject version 8. New activity kinds:
- `network.policy_updated` (subject: person ID);
- `access.blocked` (subject: the blocked ID);
- `access.unblocked` (subject: the unblocked ID).

The coordinator gains `POST /coord/v1/networks/{network_id}/policies` with `{policy}`. The caller must be a member, and the owner must be a current person.

### Direct propagation

Roadmap 2c. Decided on 2026-10-08: only the owner's own hosts receive policies directly, by push plus periodic sync; block lists stay host-local.

A coordinator could otherwise withhold a newer policy, such as a withdrawal, from the owner's other hosts until the older one expires. With direct propagation, withholding it also requires partitioning those hosts from one another.

**Siblings.** In a network, the siblings of a host bound to person P are the other current, unrevoked member hosts bound to P in the host's membership view. A host propagates only policies of its own bound person, only to its siblings, and only over the peer transport.

**Accepting a policy.** A host stores a policy delivered by the coordinator, by a peer, or by its owner's CLI when the policy verifies (owner a current person, valid signature, inside its validity window), and either:
- its version is higher than the stored one; or
- its version is equal and its signed statement has a lower lowercase hex SHA-256 than the stored one's. The hash covers the UTF-8 bytes of the signed statement's lines, not the JSON; the policy test vector above hashes to `fc64a927a0308568c0a24cb48cd4d659ed8efebc8816b086bba465067a74a834`.

The tie-break lets hosts converge without coordination when siblings sign the same version concurrently, as simultaneous renewals do. The coordinator keeps refusing an equal version with 409, so it may hold the tie-break's loser; receivers always evaluate their own newest stored version. A host never accepts a lower version. Each stored policy records `network.policy_updated`.

**Peer routes**, on the peer router:

| Route | Body | Behavior |
| --- | --- | --- |
| `POST /peer/v1/networks/{network_id}/policies` | `{policy}` | Malformed JSON, a policy for another network, or an unknown owner key returns 400. Then, unless both sender and receiver are siblings for the policy's owner, 403. A policy that fails verification returns 400. Otherwise the receiver applies the acceptance rule and returns 200 with `{person_id, version, sha256}` for its stored policy afterwards, also when it kept a newer one, so the sender learns whether it is behind or ahead. |
| `GET /peer/v1/networks/{network_id}/policies/{person_id}` | none | The receiver's stored policy object for that person, for a sibling of that person only; otherwise 403. 404 when it holds none. |

**Push.** When a host stores a policy of its own bound person, from any source, it queues a delivery of that policy to each sibling and to the coordinator, superseding older queued deliveries. A delivery is done when a sibling answers 200 with the same or a higher version, or when the coordinator answers 200, 201, or 409. Any other answer, including a coordinator 400 or 403, retries at the backoff cap until a newer policy supersedes the delivery. It retries with backoff from 1 second to 5 minutes with ±20% jitter. A delivery to a host that is no longer a sibling is dropped. A policy of a person other than the bound one, submitted through the local API, gets a coordinator delivery only, which the status below does not list. A sibling ahead of this host is handled by the next sync.

**Sync.** On start, every 5 minutes (fixed), when its membership view gains a sibling, and when the host binds to a person, a host asks each sibling for its stored policy of their person, and applies the acceptance rule to the answer. A reachable sibling therefore delivers a missed policy within one interval.

**Commands:**

| CLI after `--state DIR` | Local API | Behavior |
| --- | --- | --- |
| `access sync --network ID` | `POST /v1/networks/{id}/policy/sync` | Runs one sync with every sibling now and retries pending deliveries, waiting for any attempt already in progress, so the status below reports their outcomes. |
| `access sync --network ID --status` | `GET /v1/networks/{id}/policy/sync` | `{person_id, version, sha256, deliveries}`, where `version` and `sha256` are null without a stored policy, and deliveries are sorted by `target`. Each delivery is `{target, version, state, attempts, next_attempt_at, error, delivered_at}`, where `target` is a sibling host ID or `coordinator`, and `state` is `pending` or `delivered`. An unknown network, or a host not bound in it, returns 404. |

**Storage.** Database version 12 adds:

```sql
CREATE TABLE policy_deliveries (network_id TEXT NOT NULL, person_id TEXT NOT NULL, target TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(network_id, person_id, target));
PRAGMA user_version = 12;
```

A delivery's `record` is its status fields plus `policy`, the policy being delivered. Older binaries reject version 12. New activity kinds:
- `network.policy_delivered`, with the subject `<person_id>/<target>`;
- `network.policy_synced`, recorded when a sync stored a newer policy, with the subject `<person_id>/<sibling>`.

**Verification.** `conformance/policy_sync.py` runs every Go/Rust combination of an owner's two hosts, plus a third host as a sender. It covers:
- a withdrawal signed on one host while the coordinator is stopped: the sibling stores it by direct push, refuses the sender under the withdrawn rule, and the coordinator receives it once restarted;
- a sibling offline during the push, catching up on restart and by sync;
- concurrent same-version policies from both siblings converging on the tie-break winner;
- refusal of pushes and fetches from a non-sibling, and of lower versions;
- `access sync` and its status;
- migration from version 11 to version 12.

## Relay

Roadmap milestone 3b ([proposal](quic-relay-proposal.md)). Every `capsule-coord` relays peer QUIC packets between members of the networks it serves. It relays on its existing TLS listener and address, under its existing pinned key, so the network map needs no relay fields. A relay forwards already-encrypted QUIC packets addressed by host ID. It cannot read them, and it cannot impersonate either host, because the end-to-end peer TLS pins still apply.

### Connection

A host connects over TCP to the coordinator address and completes TLS 1.3 with its host certificate as the client certificate, pinning the coordinator key as for the coordination API. It offers ALPN `capsule-relay/1`; the coordination API negotiates `http/1.1`, and the coordinator dispatches on the negotiated protocol. The caller's host ID is derived from its client key. The coordinator allows 10 seconds for the TLS handshake before routing the connection by ALPN. A caller that is not a member of any network on this coordinator is refused: the connection closes after the handshake, before any frame is processed. One relay connection per host is current. A new connection from the same host replaces the older one, which the coordinator closes.

### Frames

After the handshake, both directions carry frames: one type byte, a 2-byte big-endian payload length, then the payload. A host ID in a frame is the 32 raw bytes of the SHA-256 digest that the `host_` form spells in hex.

| Type | Direction | Payload | Meaning |
| --- | --- | --- | --- |
| `0x01` send | host → relay | destination host ID, then one QUIC datagram | Forward this datagram. |
| `0x02` receive | relay → host | source host ID, then one QUIC datagram | A datagram from that host. |
| `0x03` unreachable | relay → host | destination host ID | The destination has no current relay connection, or the two hosts share no network. Sent at most once per second per destination. |
| `0x04` ping | either | empty | Keepalive; ignored on receipt. |

This table is version 1 (`capsule-relay/1`). Version 2 adds `0x05 changed` and version 3 adds `0x06 presence`; both are specified in the [launch contract](launch-contract.md), slices 5 and 6.

A datagram is 1 to 1,500 bytes; a host drops a larger outgoing datagram locally instead of sending it. A send frame addressed to the sender itself is treated as unreachable. An unknown frame type, an oversized or truncated frame, or a frame of a type invalid for its direction closes the connection. Hosts send a ping after 15 seconds without sending any frame. The coordinator closes a relay connection after 45 seconds without receiving one.

### Forwarding and limits

The coordinator forwards a send frame only if both the source and the destination are currently members of a common network it serves. It checks that against its own member records, on every frame or from a cache refreshed at least every 5 seconds. Forwarding is best effort, with datagram semantics: frames may be dropped, but are never reordered within one source→destination pair or modified. The coordinator drops frames when a destination's outbound buffer exceeds 1 MiB. It also drops frames from a source that exceeds 8 MiB/s, using a token bucket with an 8 MiB burst. It allows at most 4,096 concurrent relay connections. A dropped frame produces no error frame, since QUIC recovers loss.

The listener allows at most 128 simultaneous TLS handshakes across its identities, closing excess arrivals before allocating a worker; relay admission separately allows at most 128 pending membership lookups. Membership caching retains only hosts with live relay registrations and removes their entries on disconnect; rejected hosts are not cached. Each relay connection remembers at most 64 unavailable destination IDs for one second. Further distinct unavailable destinations receive no notification until space becomes available, preserving best-effort delivery while bounding memory and response amplification.

### Host behavior

- A host that runs with `--peer-listen` and is a member of at least one network keeps one relay connection to each of its networks' coordinators. It opens that connection as soon as it creates or joins a network, rather than waiting for a periodic refresh, so a newly joined host is reachable at once. It reconnects with backoff from 1 to 30 seconds. Through these connections it accepts inbound peer QUIC connections, the same way as on its UDP socket.
- A host without `--peer-listen` never accepts inbound peer connections. It may open a relay connection on demand to dial out, and receives only datagrams for the connections it initiated.
- Each relay connection carries packets for the host's single peer QUIC endpoint. Relayed peers appear to that endpoint as synthetic addresses, one per peer host ID, that are never sent on the real UDP socket. The synthetic scheme is internal to each implementation; for example, Rust uses IPv4 addresses in the reserved 240.0.0.0/4 block, because `quinn` rejects IPv6 destinations on an IPv4 socket.
- A host closes its relay connection to a coordinator that no longer serves any of its networks. An on-demand relay connection closes after 60 seconds with no relayed peer connection using it, and reopens on the next demand. The peer protocol is unchanged: every peer TLS check and per-request authentication applies to relayed connections.
- **Path choice:**
  - For a manual peer or a member with a nonempty address, the dialer first tries the direct UDP address. The handshake bound is 2 seconds when a relay fallback exists, and the usual 5 seconds when it doesn't.
  - It falls back to the relay of a coordinator for a network both hosts belong to, choosing the lowest network ID, after a failed direct attempt or immediately for a member with an empty address.
  - A peer that shares no network has no relay path.
  - The 8-second request bound covers the whole request: the direct attempt, waiting up to 2 seconds for an on-demand relay connection, and the relayed handshake. A host may fail a pending relayed dial early when it receives `unreachable` for that destination.
  - A relayed connection stays on the relay until it closes. Moving it to a direct path is milestone 4.
- **Return path:** a relayed connection's packets return through the relay connection on which that peer's datagrams arrived.

## Direct paths through NAT

Roadmap milestone 4. The relay keeps every pair reachable. Hosts also try to open a direct UDP path between relayed peers and move their traffic onto it below QUIC (see Path discovery in the [messaging contract](peer-messaging-contract.md)). The [proposal](quic-relay-proposal.md) explains why QUIC's own connection migration cannot do this.

### Reflexive addresses

`capsule-coord` also listens for UDP on the same IP and port as its TLS listener. It answers STUN Binding requests (RFC 8489): the 20-byte header with magic cookie `0x2112A442` and a 12-byte transaction ID. The success response carries `XOR-MAPPED-ADDRESS` with the request's observed source address and port. It ignores every other datagram, sends no other attributes, and does not authenticate. A forged or wrong mapping can only cause a failed path attempt, because peer TLS pins still apply.

A host with a peer socket sends a Binding request from that socket to each of its coordinators. It sends at startup, after creating or joining a network, and at least once per coordination interval. It accepts a response only with a matching transaction ID from the coordinator address it asked. The mapped address is its reflexive candidate for that network.

### Published candidates

A host reports `candidates` on registration, join, and sync. If it runs with `--peer-listen`, candidates are its reflexive address and its non-loopback interface addresses paired with its bound peer port, in that order, up to 8. Otherwise the list is empty. Only listening hosts send STUN requests. A dial-only host publishes no candidates and lists none in its call-me-maybe; it can still reach a direct path, because the peer learns its source from its pings. The coordinator stores and serves them unchanged. Candidates are hints for path discovery, not dial addresses: `address` keeps its meaning, and a host still never dials a candidate as an ordinary peer address.

## Verification

Language tests must reproduce the test vectors, reject each tampered field, and reject non-canonical encodings. `conformance/coordination.py` runs one Go coordinator with Go and Rust hosts in every creator/joiner pairing:

- create, invite, and join;
- message exchange without `peer add`, using a grant without `allow_disconnected`;
- rejected invite reuse, locally expired invites, and tampered tokens (no network contact; the token points at a closed port and must fail with 400 rather than 503). Coordinator-side expiry is covered by Go unit tests, since the suite shares one clock;
- a member row injected directly into the coordinator database, simulating a compromised coordinator, which hosts must ignore;
- coordinator outage: connected-only sends get 503 and `unknown` after three intervals and succeed on retry after reconnection, while `allow_disconnected` grants still work; a reply to already-delivered content succeeds during the outage;
- host restart with persisted members;
- coordinator restart, after which syncing resumes.

`conformance/persons.py` runs the Go coordinator with Go and Rust hosts in every creator/joiner pairing. It signs through a real `ssh-agent` and also through `--person-key` with a key file, and checks every person signature it produces with `ssh-keygen -Y verify`. It covers:

- admitting persons by public key and by invite, including invite reuse and expiry, and refusing a label that conflicts, ignoring ASCII case, with a current person's until that person is removed. A conflicting person injected into the coordinator database is kept, and both are reported with `label_conflict`;
- admitting a host by public key and joining with the descriptor, and refusing a host without an admission;
- binding with host consent, and refusing a binding submitted by another host or signed by an unadmitted person, as well as a second binding;
- sticky unbinding and person removal that survive the coordinator dropping them, and host restart;
- re-signing admissions at a root rotation;
- `network members` and `network persons` reporting persons and bound hosts.

Each language reproduces the test vectors, including the `SSHSIG` blobs.

`conformance/persons.py` also covers the one-command flows in every pairing:

- `network create` with an agent admits and binds the creator;
- a member invite joined with an agent yields host, person, and binding in one command;
- a second machine joined with a new invite binds to the existing person;
- the person part is skipped, with a reason and a `next` command, when there is no agent, when there are several keys, or under `--no-person`, and the host still joins;
- the person part of the same token is then redeemable with `network redeem-person`;
- a taken label is skipped without undoing the host join;
- `--host-only` invites behave as before.

`conformance/admins.py` runs the Go coordinator with Go and Rust hosts in every pairing, using real `ssh-agent`s. It covers:

- `network create` delegating the creator, who then administers from a second machine with only their SSH key;
- an administrator admitting hosts and persons and issuing invites;
- a non-administrator refused with 403;
- the root delegating and removing administrators;
- removal with and without `--revoke-admitted`, including a group reverting and members dropping;
- groups: version increase, a stale version refused, deletion, and label resolution failing on ambiguity;
- `rotate-root --to-ssh`, after which the host holds no seed, administrators keep working, and further root actions work through `--root-key`;
- a forged administrator signature, or one by a removed administrator, injected into the coordinator database and ignored by hosts.

Each language reproduces the new test vectors.

`conformance/policy.py` runs every pairing with real `ssh-agent`s. It covers:

- an owner allowing a person, then a group, then `network`;
- a sender with no grant ID authorized by policy;
- denial after `access deny`, applied at handoff as well;
- a stale policy injected into the coordinator database ignored;
- a version below the cited one returning 503 and then succeeding;
- the block list overriding both a grant and the policy without coordination;
- automatic renewal through the agent before expiry, using a short validity in tests;
- lapse without an agent;
- bounds: size, deadline, and `allow_disconnected` with the coordinator stopped.

Each language reproduces the policy vector.

`conformance/revocation.py` runs the Go coordinator with Go and Rust hosts in every creator/joiner pairing:

- A revoked host loses peer access, including on an already-open connection, and loses relay access.
- The revocation stays enforced after the coordinator database drops it, simulating an omitting or rolled-back coordinator, and after host restart.
- A revoked invite blocks joins, and drops a host that already used it.
- A member that leaves disappears from other hosts' member lists.
- A leave takes effect locally while the coordinator is down.
- After root rotation, existing members keep working through attestations. An invite signed by the old root is refused, and a member injected with only an old-root chain is ignored.
- A forked rotation is refused with a sync error, and the persisted chain is kept.
- Each language reproduces the statement test vectors.

`conformance/relay.py` runs the Go coordinator with Go and Rust hosts in every pairing. It covers:

- two members that advertise no direct address exchange messages, receipts, and adapter replies through the relay;
- a dead direct address falls back to the relay;
- a non-member's relay connection is refused;
- forwarding is refused between hosts that share no network;
- hosts reconnect after a coordinator restart, and relayed exchanges resume;
- a host without `--peer-listen` can send through the relay but accepts no inbound connections.

`conformance/nat_lab.py` needs root. It places each host behind its own nftables NAT router in Linux network namespaces, with no route between the private networks, and runs every pairing behind three kinds of NAT: port-preserving masquerade, fully random masquerade, and masquerade that drops all forwarded UDP. In each, both directions exchange messages through the relay. A negative control shows no path exists while the coordinator is stopped, and the same request succeeds once it restarts.

For milestone 4, `nat_lab.py` also checks path discovery in each pairing:
- **Port-preserving NAT on both sides:** `peer path` reports `direct` within 15 seconds of the first relayed exchange. A send under an `allow_disconnected` grant then succeeds with the coordinator stopped, which proves the traffic no longer depends on the relay.
- **Fully random NAT on both sides, and UDP blocked:** the path stays `relay`, and messages still flow.

Language tests cover message encoding, signature and freshness checks, replayed transaction IDs, the rule that only one's own pong validates an endpoint, falling back after 15 seconds without pongs, and STUN encoding.

## Deferred

Multiple administrators and the person identity they share with owner-managed access (milestone 2b). Reinstating a revoked host or invite. Registration rate limits and quotas on the coordinator. Long-poll or streamed map updates in place of interval polling. Port prediction for NATs that allocate a new port per destination, so two such NATs stay on the relay. A NAT that accepts unsolicited packets addressed to itself, such as a Linux router masquerading with no input filter, can deadlock hole punching. A peer's early probe creates a connection-tracking entry on the router, and the host's own outbound probe is then remapped to a different public port. Such pairs stay on the relay. Path discovery for peers reached by an advertised direct address. IPv6 candidates beyond what interfaces and STUN report. Per-network relay selection and relays other than the network's coordinator.
