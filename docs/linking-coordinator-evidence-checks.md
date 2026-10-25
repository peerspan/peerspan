# Coordinator transport evidence in signed catalogs

The exact version-2 map has no move/successor side fields. It carries their
existing signed public statements in the catalog under `coordinator_move` and
`coordinator_successor`. These are transport evidence only. They never admit a
host/person, activate a certificate/feature, bind ownership, authorize an action,
or establish a coordinator pin merely by appearing in a catalog.

## Exact existing shapes

`coordinator_move` has exactly `network_id`, `sequence`, `address`, `public_key`,
`moved_at`, `signer`, `signature`. Its existing message is
`L("peerspan-coordinator-move-v1", network_id, sequence, address, public_key,
moved_at)`. The network must match the catalog. `signer` is literal `root` or a
canonical original-person public key. Root signature verifies under any root in
the exact verified chain. An administrator signature is SSHSIG by that exact
named person with independently verified historical administrator delegation.
Historical recognition of removed administrators records signed evidence only;
it cannot restore current role or make a move currently followable.

`coordinator_successor` has exactly `sequence`, `previous_public_key`, `address`,
`public_key`, `signed_at`, `signature`. Its existing message is
`L("peerspan-coordinator-successor-v1", sequence, previous_public_key, address,
public_key, signed_at)`, signed with raw Ed25519 by `previous_public_key`.
The shape has no network or source address; catalog storage cannot invent one.

For both kinds, sequence is a positive integer in the existing interoperable
range through `2^63-1`; coordinator addresses, canonical strong Ed25519 keys,
UTC-second timestamps and signature encodings obey existing linking strictness.
Every exact body is transported under its ordinary kind-specific `pf_` ID and
the unchanged object/catalog/depth limits. Unknown, duplicate or null fields,
network mismatches and invalid signatures fail `invalid`; a named administrator
without verified historical delegation fails `forbidden`.

Equivalent aliases are permitted. Different move bodies at the same network and
sequence, or successor bodies at the same previous key and sequence, are
`state_conflict`; no catalog order chooses one. The same successor sequence under
different predecessor keys remains independently verifiable transport evidence.

## Shared coordinator address syntax

Catalog move/successor addresses and every linking network descriptor use the
existing Go coordinator-address contract identically. Split HOST:PORT using
Go net.SplitHostPort structure: an unbracketed host contains no colon; a host
beginning `[` ends at the first `]` immediately before the final colon, with no
other brackets. The extracted host is nonempty, contains none of space, `/`,
backslash, `@`, `?`, `#` or `%`, and has no Unicode scalar at or below U+0020 or
U+007F. Hostnames are opaque transport evidence: underscores and other otherwise
permitted characters are accepted without DNS resolution or hostname-label
normalization. Brackets need not establish IP validity for this signed-evidence
parser. Actual network connection handling remains independently pinned.

Port is the canonical decimal representation of an integer 1 through 65535:
ASCII digits only, no leading zero, plus/minus sign, whitespace, service name or
empty value. In particular `next.example:0443` is invalid, while
`coord_internal.example:443` is valid. Apply the same syntax to both the current
context descriptor and an original historical owner descriptor. Address syntax
never establishes current coordinator trust or authority to follow a move.

## Following remains separate

Current host pin switching preserves the existing protocol: a currently
authorized root/admin move with the highest applicable sequence has precedence;
successors must start at the independently known actual pin and be consecutive
under the existing previous-key rules. A successor elsewhere in the catalog
does not authorize following it. Historical move recognition does not bypass
administrator removal/kept rules or current root/role checks for a live switch.
No source pin is inferred from a move's target.

Complete historical activations retain the separate original-descriptor rule
in [historical coordinator checks](linking-coordinator-history-checks.md).
First/live ceremonies continue to require the exact actual address/key and never
follow a move mid-ceremony. A current descriptor remains independently pinned.

## Verification

A separate author derives a bounded suite from this contract and existing public
signers without either implementation source. Cases cover valid raw/SSH root
moves, recognized historical administrator moves and successor signatures;
strict fields/encoding/network/sequence/time/signature failures; missing
administrator delegation; equivalent aliases and conflicting same-sequence
evidence; and otherwise identical verified membership/role/feature projections
with or without transport-only objects. Exercise normal and fixed stored modes.
Existing host move/successor suites separately verify actual pin following,
precedence, monotonic sequences and no first-ceremony pin substitution.

The [recorded results](results/linking-coordinator-evidence.json) include 134
independent transport checks, 42 historical-pin checks and the prior 3,245-check
reader stack per implementation. The address review fix additionally passes the
248 activation and 73 root-chain regressions.
Builds, vet, format and clippy pass. Final composed full Go failed only the
known unchanged discovery assertion; full Rust passes. Actual runtime
pin following remains a separate gate.

Prior composed reader-stack gates are complete: all 3,245 probe checks per
implementation pass; full Rust passes (138 library, 10 main, 6 integration;
2 ignored). Full Go fails only the documented unchanged discovery packet-routing
assertion; every other test/package passes. Exact logs and prior evidence are
retained in the result file. Runtime acceptance remains separate.
