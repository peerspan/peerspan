# Machine-linking primitive vectors

[machine-linking-v1.json](machine-linking-v1.json) accompanies the proposed
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
