# Coordinator pins and historical signed linking grants

The [transaction contract](machine-linking-transactions.md) makes a complete
signed activation durable consent while keeping live ceremonies pinned to one
actual coordinator. After a separately verified coordinator move or successor,
the same complete activation must remain verifiable without rewriting its
original signed owner descriptor. This extension applies to the normal and
[stored-snapshot](linking-stored-checks.md) verifiers with identical authority
rules and unchanged public input/output shapes.

## First operations

First-finalization verification remains pinned to the exact caller descriptor,
including its coordinator address and key. The signed request must name that
actual coordinator. A live ceremony never follows a move or substitutes a new
descriptor after consent: start another request at the new pin. Existing request
interval, current epoch/feature/role/path and conflict checks remain mandatory.

## Historical signed grants

For historical verification, the exact signed owner descriptor must name the
same caller-pinned network ID, genesis root and immutable network name. Its
coordinator address and key may differ from the caller's current pin. The
descriptor is strict with the same exact five fields, canonical key and valid
coordinator address as a current descriptor. The request's coordinator address
and key must equal that original owner descriptor, and its derived request ID
must still bind that exact coordinator key, host, device and nonce. Verify all
original request/owner/selection/administrator/commit signatures and locked IDs;
their references bind the remaining packets to this exact descriptor. Mixed
request/owner pins or substituted network identity remain `invalid`.

This verifies complete signed grants without asserting that the historical
coordinator was ever trusted. A coordinator signature, receipt, address,
successor or move supplies no person, host-binding or admission authority.
No result receipt alone can activate a certificate or supply a missing
administrator/owner signature. Root lineage, administrator recognition/current
role/kept-record rules, original-person and ancestor consent, checkpoints,
host/new-device possession, feature identity, sticky restrictions and final
history revalidation remain unchanged. An old-root admission still needs a
matching current attestation before it supplies current host membership.

Dependency resolution may therefore activate an otherwise usable certificate
from its complete historical transcript after the current coordinator pin
changed. This does not relax the present path evaluation: removed persons,
revoked devices/hosts, expired paths and withdrawn role authority still fail
under their existing exact rules. No original signed descriptor is reconstructed
or replaced with a current descriptor before hashing or signature verification.

Current-pin changes continue to require the existing independently verified
move/successor transport rules. This extension adds no map proof kind, pin switch,
runtime route, writer or claim that a move authenticates an unsigned source pin.

## Verification

An independent author derives a bounded shared suite from this contract and the
accepted signing, transaction and hosted-coordinator contracts, never either
implementation:

- An unchanged historical activation remains valid under a caller descriptor
  with a separately changed coordinator address, key, or both; first verification
  of the same transcript still rejects the mismatch.
- A current action can resolve its selected device path through that complete
  old-pin activation, with all original signatures and bytes unchanged.
- Wrong network ID/genesis/name, malformed historical descriptor, mixed
  request/owner pins and substituted locked packet references reject.
- Missing or coordinator-forged owner/admin authority, known revocation/role
  loss and stale-root admission remain rejected despite a coordinator change.
- Existing linking suites, stored budget checks and language/build gates remain
  regression requirements. Runtime tests separately prove actual pin migration
  and the rule that live ceremonies never follow a move.

[Recorded results](results/linking-coordinator-history.json) include both modes
and the shared final reader-stack gate, without asserting runtime pin following.

Final composed reader-stack gates are complete: all 3,245 probe checks per
implementation pass; full Rust passes (138 library, 10 main, 6 integration;
2 ignored). Full Go fails only the documented unchanged discovery packet-routing
assertion; every other test/package passes. Exact logs and prior evidence are
retained in the result file. Runtime acceptance remains separate.
