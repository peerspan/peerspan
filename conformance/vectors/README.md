# Machine-linking primitive vectors

[machine-linking-v1.json](machine-linking-v1.json) accompanies the accepted
[shared signing contract](../../docs/machine-linking-contract.md). All seeds and
the pairing secret are public deterministic fixtures. Never use them in a real
network. Certificate objects are signature examples, without activation proofs;
the frame plaintext is a minimal encryption example, without request possession
proofs. Neither is a complete valid linking transaction.

## Contents

- Eight distinct Ed25519 seed/public-key pairs, using repeated seed bytes
  `0x11` through `0x18` in the named role order.
- Five SSHSIG examples: certificates for B and C, a binding authorized by B,
  B's revocation of C, and a root-person checkpoint retaining the binding and
  revocation. Each includes the application message and SSHSIG signed preimage.
- One raw host signature consenting to the exact binding authorization.
- Base32 code/locator, two request IDs, HKDF intermediates and a one-message
  AES-256-GCM frame, with separate ciphertext and tag for inspection.

JSON strings named `*_utf8` are exact byte inputs after JSON string decoding.
No LF is appended. `message_base64` offers the same bytes in Base64. The binding
payload's original JSON bytes are retained, including their field order; they
must not be reserialized during signature verification. All fixture certificates
have scopes `15` and the interval `2026-10-23T12:00:00Z` through (but excluding)
`2027-01-21T12:00:00Z`. No activation or current-authority result is implied.

## Primitive checks recorded on 2026-10-23

Generated from the contract's inputs with Go 1.27.1's standard library. A
separate temporary Rust program using `ring` 0.17.14 independently reproduced
public keys, all five Ed25519 signatures and SSHSIG preimages, certificate and
binding IDs, request IDs, HKDF and AES-GCM outputs. It verified the raw host
consent and rejected a changed tag and changed authenticated data.

OpenSSH 9.2p1 accepted all five SSHSIGs using `ssh-keygen -Y verify`, namespace
`peerspan-person-v1`, principal `fixture`, and an allowed-signers entry containing
each expected signer key. It rejected each with a trailing LF added to the
message and with a wrong namespace. Python's standard library independently
checked Base32 encoding and the locator hash. A second Go generation matched
the fixture bytes exactly.

Fixture file SHA-256:
`a412cf177d3d98ba6de023e9a5c0b83f731826d672df899ac942aa8ac3769b23`.

These one-off primitive checks are not a new conformance suite, protocol security
review, or runtime acceptance result. The separately authored protocol suite
follows the completed transaction contract, as required by
[AGENTS.md](../../AGENTS.md). Existing runtime behavior is unchanged.

## Transaction fixtures (UP-06b)

[machine-linking-transactions-v1.json](machine-linking-transactions-v1.json)
accompanies the proposed [transaction contract](../../docs/machine-linking-transactions.md).
It adds public bootstrap person/host/admin proofs and a fully acknowledged feature,
then 15 isolated inputs: six expected successful transactions and nine expected
rejections. Each case starts from exactly its own catalog and no committed
operation; do not combine cases. Multiple cases deliberately reuse a request ID
with different authorization in independent starting states.

The successful examples cover original-person linking, delegated B → C, separate
nonadministrator owner and administrator, network-root admission, and same-key
renewal both before and after old-certificate expiry. Rejected examples have
missing or insufficient administrator authority, wrong network or selection,
an expired first commit, child scope/expiry expansion, a pending parent, or a
revoked device key. Their expected semantic outcomes are specification data;
no running verifier has established those results yet.

Go 1.27.1 standard-library generation was repeated byte for byte. A temporary
Rust `ring` 0.17.14 program independently reproduced all 107 SSHSIGs/preimages
and verified all 78 raw signatures. OpenSSH 9.2p1 accepted all 107 SSHSIGs and
rejected each after its message bytes changed. A separate Python standard-library
artifact check reconstructed packet, certificate, record, feature and catalog
IDs, checked the signed-preimage references, and confirmed each operation input
fits 512 KiB (largest 38,507 bytes). These checks cover fixture integrity and
cryptographic bytes, not the proposed semantic outcomes or running recovery.
The original primitive fixture is unchanged.

Transaction fixture SHA-256:
`a495eb6d6d574b04a357f4c775199879c37699741eb6e8426ad00a6f2a170d64`.

The documented host migration SQL was parsed with Python SQLite, checked to
preserve an existing identity row, and rolled back after an injected SQL failure.
This checks the proposed DDL/transaction boundary, not either host migration runner.

## Invite-redemption review fixtures

[machine-linking-invite-redemptions-v1.json](machine-linking-invite-redemptions-v1.json)
fixes the caller and explicit `person_action` rules raised in PR #43's review.
It references the unchanged transaction fixture's `delegated_b_links_c` catalog
by file hash. Each case starts independently, before any use of its invitation.
Combine a case's redemption, address, candidates and acknowledgment with that
catalog to form the exact route body; fixture metadata is not sent to the API.

Four intended successes cover host-only, person-only from a current member,
member with new person admission, and member explicitly skipping an already
admitted person. Six intended rejections cover an outsider redeeming person-only,
the wrong joining TLS host, skip without a person admission, an incomplete admit
that must not imply skip, an invalid mode/action pair, and a skipped person's
label mismatch. Counts in `expected` specify intended mutations; `person_result`
describes the requested outcome and is not an extra v2 map response field.
An explicit skip retains the person key, omits the person invite/signature,
consumes no person invite and creates no host binding.

Go standard-library generation repeated byte for byte. Rust `ring` independently
reproduced four new SSHSIGs/preimages and verified four raw signatures; OpenSSH
accepted all four SSHSIGs and rejected altered messages. A Python artifact check
matched authorization/member/acknowledgment inputs to those signatures, checked
the authority catalog reference and required field combinations, and confirmed
both earlier fixture hashes are unchanged. These are fixture integrity checks;
the separately authored runtime suite must still establish the semantic results.

Invite-redemption fixture SHA-256:
`5ca2c0ac88bddaeffb97c59ff4b5db886e0d834bf10799cd4513c1bea2cec9e5`.
