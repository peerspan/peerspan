# Approved linking runtime verification

The accepted [transaction contract](machine-linking-transactions.md) supplies the
wire protocol, schema 19/7, consent and recovery rules. This implementation
milestone completes UP-06c and UP-06d in Go, Rust and the coordinator, followed by
installed Linux bundle acceptance. Rust remains the recommended install.
Release/coordinator configuration and macOS validation remain separate tasks.

## Coordinator transport foundation

The coordinator migrates atomically from schema 6 to 7, preserving existing
identity/network/membership data. Schema 7 contains the five required categories:
`link_mailboxes`, `link_frames`, `link_operations`, `link_objects`, `link_features`.
Physical coordinator columns and rate/poll bookkeeping remain internal. Opening
or restoring a newer unsupported schema is refused. Backup/restore retains all
categories and existing private-file permissions.

The first runtime slice implements only the four mailbox routes under
`/coord/v2/link-mailboxes`, exactly as transaction section 4 specifies. This
does not enable delegated network writers or feature readiness. Every request
uses existing authenticated host TLS; an enrolled network is not necessary for
transport. A request frame's writer key must be the TLS creator's host key.
Later code holders may send frames under other writer keys; the coordinator
cannot decrypt them or infer person authority from them.

Envelopes are strict UTF-8 JSON with all required fields, no nulls, unknowns,
duplicates or trailing data. The frame shape is exactly the primitive contract:
format 1, `link_` request ID, 64 lowercase-hex locator/frame ID, six allowed
roles, valid canonical Ed25519 writer key and canonical padded Base64 ciphertext
of 16 through 65,552 bytes. No seed/code/plaintext field is accepted. The outer
create body additionally supplies exact UTC-second created/expiry strings with
`expires_at - created_at = 300 seconds` and `created_at <= now < expires_at`.
The creation frame's role is request. Other route shapes/responses are unchanged
from the transaction contract; sequence numbers start at 1.

Store immutable original frame JSON bytes. An identical tuple/byte retry returns
its original sequence and consumes rate budget but no capacity. Different bytes
under `(request_id, role, writer, frame_id)` are `operation_conflict`. The locator,
request, creator and fixed deadline are immutable; a conflicting create is
`operation_conflict`. Frame metadata must name its mailbox's locator/request.
No committed network proof is removed by deleting transport.
Capacity counts exact serialized frame JSON bytes, excluding the outer request
envelope. Frame whitespace changes conflict under the same tuple; outer-envelope
whitespace changes with an identical frame are idempotent.

Apply every fixed section-4 private-preview limit: creation 5/IP/hour and
1,000/global/hour; 8 open/IP and 256 global; 4,096 retained boxes; 256 MiB total
frame bytes; 64 frames and 512 KiB per box; write 60/IP/minute and 12,000 global;
poll 120/IP/minute and 12,000 global, with 2 seconds per TLS-host/locator.
IP is the actual authenticated connection source address, without forwarded
headers or IPv6 prefix aggregation. UTC fixed windows and counters survive
restart. A rate-rejected request is not charged to a second unrelated bucket.
Successful/idempotent requests consume rate budget. Capacity failure is atomic.

At the exact deadline a box is expired. POST writes return 410 for expired/deleted
boxes; retained reads show the terminal state. DELETE is creator-only and
idempotent while retained, returning 200 and deleted for an open, expired or
already deleted box (404 when absent).

DELETE immediately removes encrypted frames and releases their byte capacity.
Its retained tombstone preserves creator, request, locator, deadline and the
original next unused sequence; deleted views have an empty frames array.
Expired boxes retain encrypted frames until terminal cleanup.

After deadline plus 24 hours, clean transport/frame and locator/poll bookkeeping;
retain public operations/proofs separately.
Cleanup occurs before evaluating a mailbox request, so expired rows cannot
consume open slots or survive terminal retention through inactivity followed by
a new request. Poll/write rates use persistent fixed windows; no busy loop is
required. Responses use section-7 error/details shapes, with integer
`Retry-After` for rate limits. Internal errors/logs do not expose body contents.
Error details always contain scalar `request_id`/`stage` (absent values `-`) and
string arrays `required_ids`/`next` (absent values empty arrays).

## Deterministic runtime test controls

Production behavior uses the normal UTC clock. For independent black-box
conformance only, processes honor `PEERSPAN_LINK_TEST_CLOCK_FILE` and
`PEERSPAN_LINK_TEST_BARRIER_DIR` only when `PEERSPAN_LINK_TEST_MODE=1` is also
explicitly present. No route, request body or peer can enable these controls.
They are not CLI options or persisted configuration. The clock file contains
exactly an RFC3339 UTC-second string plus an optional final newline. Test time
affects linking protocol decisions only; harness timeout/wait deadlines use
monotonic real time. Invalid configured test time fails closed with `internal`.

An armed barrier is an existing file `<name>.arm` in the configured directory.
At that point write `<name>.entered` containing only the public request ID and
wait for `<name>.continue`; conformance kills/restarts the process to model a
crash or writes continue to resume. Disabled/unarmed barriers do no work. A
cancelled process context ends the wait. No barrier file contains private code,
seed, plaintext packet or ciphertext. Initial coordinator barrier names are
`coord.mailbox.after_commit` and `coord.frame.after_commit`, after durable commit
and before HTTP response. Further ceremony/operation barriers will be pinned
before their corresponding conformance cases, using the same mechanism.

## Verification

An independent author uses contracts and public fixtures, without implementation:

- Strict mTLS creator/frame identity, exact envelopes, canonical encodings,
  arbitrary opaque ciphertext transport and absence of inferred authority.
- Sequence/order/after pagination, immutable create/tuple retries and conflicts,
  creator-only deletion, terminal reads/writes, exact 300-second boundaries.
- Persistent per-IP/global rate limits, Retry-After/poll intervals, every count
  and byte capacity boundary, failed additions leaving existing frames intact.
- Restart and lost-response retry at both post-commit barriers, terminal cleanup,
  old-schema refusal, and backup/restore of encrypted transport without secrets.
- Existing coordinator/host enrollment/relay/operations regressions required by
  AGENTS, plus both language gates. All later signed-state/ceremony changes add
  their corresponding shared four-pairing and installed-bundle checks.
