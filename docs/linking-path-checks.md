# Machine-linking certificate-path evaluation

This is the first part of UP-06c.2, following the signed-object readers accepted
in [PR #44](https://github.com/peerspan/peerspan-internal/pull/44). It implements
the certificate-path rules in the [signing contract](machine-linking-contract.md).
Both languages evaluate the exact path named by an operation. There is no
automatic substitution of another certificate for the same device key.

The [recorded results](results/linking-paths.json) include both implementations'
conformance results and full language-test limitations.

## Trust boundary

The reusable evaluator takes a coherent, independently verified network-state
snapshot, the expected original person, the exact certificate ID (`root` for
the original person), required scope mask, and current UTC time. The snapshot
contains current person admission/administrator roles, host membership and
bindings, verified certificate activation IDs, and all known sticky device-key
revocations. These facts must come from verified durable state, never unsigned
coordinator fields. Missing state is incomplete authority, not permission.

Certificate bytes in the snapshot are candidates. The evaluator resolves each
exact parent ID, checks every signature using that parent or original person,
and derives each certificate ID itself. It does not trust an asserted index.
It checks at most eight certificates, same network/person, delegation scope on
each issuer, child scope/time bounds, unique device/host keys and disjoint device
and host keys across the complete path. Each device differs from the original
person. All path certificates must be currently valid and activated; every path
host must remain admitted and bound to that person. Revocation follows the
device key for the network/person across certificate IDs. Bit 8 additionally
requires the person's current administrator role. The original person has all
person scopes and no certificate expiry, but still needs current person admission
and the administrator role for bit 8.

Success describes a usable signing path under this snapshot. It is not approval
of a mutation or proof that the snapshot was correctly constructed. The caller
must still check freshness, current root/epoch, feature state, operation payload,
self-invalidation, retained history and transactional revalidation. Catalog-to-
state verification and complete activation verification remain pending. No
daemon/coordinator route or `link` command accepts this snapshot format.

## Conformance probe

From the repository root:

```sh
GOCACHE=/tmp/peerspan-link-readers-cache/go \
  go -C go build -o /tmp/peerspan-link-path-go ./cmd/peerspan-link-probe
CARGO_TARGET_DIR=/tmp/peerspan-link-reader-rust-target \
  cargo build --locked --manifest-path rust/Cargo.toml --bin peerspan-link-probe
python3 conformance/linking_paths.py \
  --go-probe /tmp/peerspan-link-path-go \
  --rust-probe /tmp/peerspan-link-reader-rust-target/debug/peerspan-link-probe
python3 conformance/linking_readers.py \
  --go-probe /tmp/peerspan-link-path-go \
  --rust-probe /tmp/peerspan-link-reader-rust-target/debug/peerspan-link-probe
```

The existing state-free `peerspan-link-probe` executables additionally accept:

```json
{"kind":"path","state_base64":"BASE64_OF_STATE_JSON","person_public_key":"EXPECTED_PERSON","certificate_id":"dc_...","required_scopes":1,"now":"2026-10-24T12:00:00Z"}
```

All fields are required; no others are allowed. `required_scopes` is a positive
mask within 15. `now` uses the signing contract's exact UTC-second spelling.
The outer line limit remains 2 MiB. Decoded state is at most 1 MiB with depth
at most 64. The probe injects verified facts solely to test this evaluator;
the production integration must obtain them by verification.

State is strict JSON, exactly:

```text
format: 1
network_id: net_...
persons: [{public_key, state: admitted|removed, administrator: boolean}]
hosts: [{public_key, state: admitted|removed}]
bindings: [{host_public_key, person_public_key: key|"-"}]
certificates: [{id: dc_..., body_base64: exact certificate JSON bytes}]
activated_certificates: [dc_...]
revoked_devices: [{person_public_key, device_public_key}]
```

Every array is required, may be empty, and has at most 4,096 entries. Array order
does not matter. Reject duplicate persons, hosts, bindings, certificate IDs,
activation IDs and person/device revocation pairs, including identical entries.
Keys, IDs, scalar types and Base64 encodings are strict. Certificate candidate
bytes are bounded but checked only when their exact path is requested; an
unrelated damaged path does not disable an independent usable path.

An absent person/host/binding entry means unknown proof. `removed` is known
loss of admission; a binding with person `"-"` means known unbound. A binding
to another person does not satisfy this path. Activated IDs are verified facts,
not candidate intent. An absent activation requires the certificate's `link_`
request ID. A revocation for another original person does not affect this
person. State belongs only to its named network.

Success is exactly:

```json
{"ok":true,"certificate_id":"dc_...","person_public_key":"KEY","signer_public_key":"DEVICE_KEY","scopes":15,"not_after":"2027-01-21T12:00:00Z","certificate_ids":["dc_..."],"host_public_keys":["HOST_KEY"]}
```

Path arrays are oldest first, leaf last. The leaf supplies signer, scope mask,
and expiry. The returned mask is certificate metadata; it does not authorize
every listed operation. Evaluate each operation's actual required bits against
current state. A root-person result uses `certificate_id: "root"`, person as signer,
scopes 15, `not_after: "-"`, and empty arrays. Scope 8 is conditional on the
current role even when other requested bits are present.

Failure is exactly:

```json
{"ok":false,"code":"proof_required","required_ids":["dc_..."]}
```

Only `proof_required` includes `required_ids`; other failures, including malformed
outer requests/lines, use exactly `{"ok":false,"code":"CODE"}`. This preserves
the existing probe's rejection format before a request kind can be determined.
Codes are `invalid` for malformed inputs, bad signatures/IDs, context mismatch,
cycles, depth/key collisions or child scope/time expansion; `proof_required`
for missing certificate/person/host/binding/activation proof; `device_revoked`
for a known device revocation; `authority_expired` when now precedes issuance
or is at/after expiry; and `forbidden` for known removed/unbound/mismatched
identity, insufficient requested/issuer-delegation scope or absent current
administrator role. Required IDs
are sorted and distinct; use the missing `dc_` or activation request's `link_`
when known, otherwise an empty array.
Multiple simultaneous faults need not have a fixed error precedence.

## Verification cases

The separately authored suite derives signatures and expectations from the
contracts/public fixtures, without reading implementations. It checks:

- Original person and one/eight-certificate paths; nine-certificate rejection.
- Exact parent/signer resolution, wrong ID/network/person/key/signature, missing
  parent, cycles, repeated host/device keys and device/host cross-collisions.
- Scope masks/subsets, issuer delegation scope, per-certificate 90-day intervals,
  child issuance/expiry bounds and exact half-open current-time boundaries.
- Current person/host admission and same-person binding; missing versus known
  removed/unbound state; pending activation and explicit missing request IDs.
- Sticky revocation across renewed IDs, ancestor revocation, unrelated-person
  revocation and independent-path isolation.
- Every required scope and conditional administrator role for root/device paths.
- Strict snapshot/probe JSON, types, fields, duplicate entries, canonical
  encodings, bounds and continued stream framing after rejections.
- Unchanged signed-object reader conformance.

These checks do not establish activation transcript, catalog, checkpoint,
freshness, mutation, persistence or end-to-end linking acceptance.
Cycle cases use deliberately inconsistent asserted IDs and check bounded
rejection; they do not claim independently hash-consistent cyclic certificates.
