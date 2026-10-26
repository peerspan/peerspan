# Optional rendezvous and relay operator

Status: DEC-01/04/06 shared contract candidate, 2026-10-26. The complete contract
set must be reviewed and merged before implementation or executable cases.
Read with the exact
[bootstrap/helper wire](decentralized-bootstrap-contract.md) and
[runtime](decentralized-runtime-contract.md) contracts. This document makes the
optional operator process buildable and testable; it does not configure or
deploy a Peerspan-operated service. No helper is required for local creation or
direct reachable pairing/work.

## Process and authority boundary

Provide an optional Go binary, `peerspan-helper`. Go is selected for this small
operator process because it already supplies the standalone server/tooling and
produces a native binary without libc dependencies. Both Go and Rust **hosts**
remain fully supported clients and participant endpoints; Rust remains the
recommended host installation. A second implementation of this resource-only
operator is not a launch requirement. The public wire permits replacements.

The helper serves only opaque mailboxes and relay4. It owns a persistent
transport Ed25519 key and local resource state. It has no network descriptors,
root/person/device signing authority, membership roster, policy, consumed
membership invitations, participant outcomes or host administration API.
Receiving or forwarding a public key/packet cannot create those powers.

Use TLS ALPN `peerspan-bootstrap/1` for only section7 mailbox routes and
`peerspan-relay/4` for the exact relay stream. A shared physical TCP listener
selects strict independent routers/state machines by negotiated ALPN. Reject
unknown ALPN before application bytes; no HTTP/2 or default HTTP fallback.
Unknown client keys may prove possession on this isolated transport under its
resource limits. They never reach ordinary peer, repair, local-admin, filesystem,
task, capability or signing routes. Participant activation/outcome routes are
absent (404), even if a request supplies valid network proof bytes.

## Operator commands and identity

```text
peerspan-helper --state DIR serve --listen HOST:PORT [--tokens-file PATH]
peerspan-helper --state DIR info
```

`--listen` is explicit for serve. Local bind syntax permits wildcard IPs and
port0; operator handoff/configuration uses the actual bound endpoint and public
key under the common advertised endpoint grammar. This command starts no
system service, changes no firewall or DNS, and provisions no cloud resource.
The process runs as an ordinary account on an unprivileged configured port.

The default state directory is `$XDG_STATE_HOME/peerspan/helper`, otherwise
`$HOME/.local/state/peerspan/helper`; it is separate from host/coordinator state.
Private directory/file and process-lock rules match the host:0700 directory,
0600 mutable files, no identity/database/lock symlinks, exclusive server owner,
atomic creation and cleanup only of this process's own resources. A malformed
existing key/state refuses rather than generating a replacement identity.

Generate the transport key only on first explicit serve with missing identity.
Persist it before listening, retain it across restart, and validate the owned
32-byte seed/public-key relation. An explicitly separate state directory is a
different operator identity; clients must review/configure that new transport
pin. This does not rotate any network's root.

On successful listen, stdout emits one JSON line exactly
`{public_key,address,protocols:["peerspan-bootstrap/1","peerspan-relay/4"]}`.
`address` is the actual local bound address, not a claim of Internet reachability.
Thereafter stdout contains no application logs. Info is read-only and returns
exactly `{public_key,protocols:["peerspan-bootstrap/1","peerspan-relay/4"]}`;
it creates no key/state and makes no availability claim. Missing identity exits
nonzero with `not_found`. Private operator diagnostics go to stderr without
tokens, bearer capabilities, ciphertext, packet/catalog bodies or private keys.
Malformed flags/config/state and listen failure exit nonzero.

## Optional resource accounts

Without a tokens file, accept anonymous resources under all fixed wire quotas.
With it, require one configured credential for mailbox/relay resource access.
The file is protected regular owner-local configuration (no symlink, no
group/other permissions), at most1MiB, strict JSON exactly:

```text
{format:1,accounts:[{id,tokens:[BASE64]}]}
```

Account IDs are unique1..128-byte ASCII `[a-z0-9_-]` labels, sorted by ID;
there are at most1024 accounts and1..8 tokens/account. Tokens are canonical
standard Base64 of1..1024 UTF-8 bytes, without CR/LF/NUL. They are sorted by
their decoded bytes and globally unique. All independent file/count limits
apply; no successful partial load. Prefer randomly generated high-entropy
tokens. Restart reloads the exact validated file; no remote credential-edit API
or unreviewed automatic token/key rotation is provided.

Mailbox uses the exact `X-Peerspan-Resource-Token` header and relay AUTH uses
the same decoded token bytes. The server maps a valid token to its configured
account; it never trusts an asserted account name. Account aggregation is in
addition to the actual TLS key/source buckets, not a way to reset them. Wrong
or missing required credentials fail before allocating a mailbox/registration.
No credential enters a signed descriptor, contact/display token, lease, packet,
catalog, participant outcome or public log. Owner-local host configuration
stores/loads its transport credential under the storage/runtime rules.

## Durability, limits and packaging

Persist exact mailbox creation identity/frames, expiry/deletion tombstones and
quota ownership atomically before acknowledging durable local storage. Keep
those records across an ordinary server restart. Apply the exact ciphertext,
metadata, time, per-key/source/account and aggregate queue/worker bounds in the
wire contract. No arbitrary server response is an authority receipt. Clock or
disk failure can make this optional carrier unavailable; it cannot renew or
withdraw participant authority. Relay connections/queues are ephemeral and
clients reconnect using the fixed independent TLS pin.

This operator additionally bounds summed exact stored FRAME body bytes to512MiB,
with409 quota_exceeded before an overflowing mutation. Ciphertext and raw-body
limits apply independently; deleting/expiring a record releases both atomically.
This accounts for retained original JSON whitespace and envelope overhead that
the fixed256MiB decoded-ciphertext ceiling alone cannot bound tightly. Ordinary
maximal ciphertext remains representable. Selected: a finite operator disk
budget for exact portable frames. Discarded: normalizing signed frame bytes,
unbounded whitespace storage, or silently truncating accepted content.

The helper uses separate internal resource storage; it never opens or upgrades
the host's schema23 database. No public contract depends on its SQL table layout.
Resource expiry/deletion frees ciphertext within the pinned tombstone rules;
history/authority lives on participants. Restoring or replacing a helper need
not preserve a network-global log because it has no such authority. Clients
retain exact ciphertext/intents and can choose another carrier.

Provide `scripts/package-helper.sh VERSION [OUTPUT_DIR]`, native validated
Linux only, producing `peerspan-helper-VERSION-linux-ARCH.tar.gz` and adjacent
`.sha256`. Include the binary, this operator guide and `RELEASE.json` with
version, source_revision, source_dirty, os and architecture. Apply the host
packager's version/path/no-overwrite/atomic archive/checksum rules. No Node,
host integration bundle, coordinator address/key, network root, vendor pin or
mandatory deployment variable enters this archive. It is a separate optional
operator artifact; the normal host bundles do not require or launch it.

## Independent verification

From this contract and the wire alone, test both host implementations against
two helpers with different identities/resource accounts. Verify exact encrypted
mailbox delivery/retry/restart/tombstones, all caps and bad credentials, relay4
framing/directions/renewal/replacement/source attribution, actual TLS endpoint
substitution and no privileged routes. Disable/replace each operator while
retaining participant keys/intent/ciphertext. Verify total helper outage with
reachable direct participants and separately truthful unavailable behavior
when restrictive NAT leaves no path. Packaging checks use actual archives.
These deterministic operator processes are not evidence of independent real
companies or a completed separate-machine/live-agent run; record actual
topology and results separately.

Selected: a small optional transport-only Go server and portable open wire.
Discarded: a renamed coordinator, helper enrollment/signing powers, a mandatory
vendor endpoint, requiring helper deployment for every host, and a second
operator implementation without a launch requirement.
