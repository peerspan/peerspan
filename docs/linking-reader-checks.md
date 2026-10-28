# Machine-linking signed-object reader checks

This is the bounded UP-06c reader slice. Its independently authored suite is
[`conformance/linking_readers.py`](../conformance/linking_readers.py), derived
from the machine-linking contracts and public vectors. It uses only Python's
standard library. It does not inspect either implementation.
The existing policy and group payloads also follow the referenced
[coordination](coordination-contract.md) and
[capabilities](capabilities-contract.md) contracts.

The [recorded run](results/linking-readers.json) contains the implementation
results and the existing Go discovery-test failure reproduced on merged main.

The same conformance executables also support the separately specified
[certificate-path checks](linking-path-checks.md). Their injected state is a
test adapter; it is not a daemon or coordinator input format.

## Conformance-only probe

From the repository root, build each implementation's reader probe and pass both
executable paths. These temporary cache/output paths also work in the workspace
sandbox:

`$PEERSPAN_GO` is a checkout of [peerspan/peerspan-go](https://github.com/peerspan/peerspan-go), which builds the Go probe.

```sh
GOCACHE=/tmp/peerspan-link-readers-cache/go \
  go -C "$PEERSPAN_GO" build -o /tmp/peerspan-link-readers-go ./cmd/peerspan-link-probe
CARGO_TARGET_DIR=/tmp/peerspan-link-reader-rust-target \
  cargo build --locked --manifest-path rust/Cargo.toml --bin peerspan-link-probe
python3 conformance/linking_readers.py \
  --go-probe /tmp/peerspan-link-readers-go \
  --rust-probe /tmp/peerspan-link-reader-rust-target/debug/peerspan-link-probe
```

The suite can also use probes built at other paths:

```sh
python3 conformance/linking_readers.py --go-probe /absolute/go-probe --rust-probe /absolute/rust-probe
```

Each probe reads one JSON request per stdin line and emits one JSON response per
stdout line, continuing after rejected inputs. Diagnostics belong on stderr.
Requests have exactly these required fields:

```json
{"kind":"certificate","object_base64":"BASE64_OF_ORIGINAL_JSON_BYTES","signer_public_key":"INDEPENDENTLY_EXPECTED_KEY","device_public_key":"-"}
```

Kinds are `certificate`, `person_record`, `root_record`, `device_revocation`,
`checkpoint`, `packet`, `feature_proposal`, `feature_ack`, `feature`, and
`admin_removal_v2`. `object_base64` uses canonical padded standard Base64 and
retains the object's original bytes, including intentionally invalid UTF-8.
`signer_public_key` is the independently resolved expected signing key. For
request, selection and commit packets, `device_public_key` is the independently
expected new device key; for all other cases it is `"-"`. A packet's visible
writer must match the expected signer. Root-person records and person-signed
owner/administrator packets with certificate `root` must also match their named
original person. The probe must never resolve the expected key from SSHSIG.

Success has exactly:

```json
{"ok":true,"message_base64":"BASE64_OF_UNSIGNED_MESSAGE","id":"DERIVED_ID_OR_-","payload_base64":"RETAINED_PAYLOAD_OR_-"}
```

The message and ID follow the contract: `dc_`, `ar_`, `rr_`, `dr_`, `lp_`, or
`lf_`. Checkpoints, feature acknowledgments and administrator removals have no
specified semantic ID and return `"-"`. An aggregate feature returns its
proposal message and `lf_` ID. `payload_base64` is the exact input field for
person records, root records and packets; other kinds return `"-"`.

Failure has exactly `{"ok":false,"code":"invalid"}`. This includes malformed
probe requests and unsupported kinds. Reject extra outer fields and missing or
ill-typed context. The conformance transport line limit is 2 MiB, allowing for
Base64 overhead; the protocol object limit remains 1 MiB, and decoded signed
payloads are limited to 256 KiB. Readers bound JSON nesting to 64 levels before
recursive traversal. Unsigned integer readers use the shared `uint64`
representation bound, 0 through 18,446,744,073,709,551,615; each field's own
constraints still apply, including strictly positive policy and group versions.
Depth 64 and `uint64` are shared reader representation/resource bounds, not new
wire encodings. Reader success for a large version does not establish that
future live storage or version progression accepts it. Oversized lines must be
drained before processing the next request.

## Checked behavior and boundaries

Readers enforce the strict required field sets, field types, integer spellings,
identifiers, timestamps, canonical encodings, and signature formats. They reject
duplicate or unknown fields, nulls, invalid UTF-8, trailing JSON, bad keys and
signatures, malformed SSHSIG contexts, and resource-limit violations. Packet
payloads use their role's fixed field set; nested JSON remains strict, but a
valid wrapper does not assert that nested authority has been resolved. A
standalone person binding requires valid raw host consent; an owner packet may
contain the explicitly specified binding draft.

Signed type-rejection cases cover every payload field in all six packet roles,
including request expectations and coordinator fields, owner network descriptor,
certificate and binding-draft fields, selection and administrator references,
commit references and deadline, and result activation/catalog containers and
catalog entry fields. They replace individual values with wrong JSON types and
sign the changed retained bytes with the independently expected wrapper keys.
The explicit `"-"` alternatives remain allowed types where the schema defines
them; these cases do not decide whether a reference or absent value is correct
for an activation, or resolve the signatures inside nested proof objects.
Valid boundary cases include the absent string written as `"\u002d"` in packet
JSON and retained packet payload bytes; scalar checks decode that string while
payload hashes and returned bytes retain its original spelling.

Certificates enforce their own scope mask and nonempty interval of at most 90
days, without checking the current clock or a parent chain. A complete feature
checks its root signature and exactly one valid acknowledgment per sorted
proposal host; it does not establish that the roster is the current membership.

The suite checks public fixture objects, including signed objects extracted from
semantic transaction rejection cases. Those are only cryptographic reader
successes. In particular, pending certificates, expired historical packets,
missing activation, wrong references, absent administrator roles, and a child
scope or expiry exceeding its parent are not reported as live authorization or
successful transactions. Chain validation, roles, revocation effect, activation,
retained-history authority, invitations, storage, mutation atomicity, recovery,
pairing codes, HKDF and AEAD are outside this slice.

The suite also signs generated adversarial inputs using only public fixture
seeds and independent standard-library Ed25519 arithmetic. This makes strict
payload rejection and exact byte retention observable independently of whether
the original fixture signature was invalidated by an edit. These seeds are
public test material, never deployment credentials.
