# Ordinary restrictive catalog records

This part of UP-06c.2 extends the [ordinary grant resolver](linking-record-checks.md)
accepted in [PR #50](https://github.com/peerspan/peerspan-internal/pull/50).
It implements the retained restrictions in the accepted
[signing](machine-linking-contract.md#4-revocation-and-retained-history),
[transaction](machine-linking-transactions.md) and
[history](linking-history-checks.md) contracts. Both hosts expose the same
stateless catalog facts; no runtime route, writer, storage or CLI is added.

## Supported evidence

Accept strict ordinary `person_record` envelopes (`operation_id: "-"`) for:

| Kind | Scope and authority | Restriction |
| --- | --- | --- |
| `peerspan-host-unbind-v1` | Bit 2, or original person; payload person equals signer person | Permanently unbind this person/host pair. |
| `peerspan-person-remove-v1` | Bit 8 and root-issued administrator authority | Remove the payload person; the subject can differ from the signer. |
| `peerspan-revoke-host-v1` | Bit 8 and root-issued administrator authority | Revoke the payload host. |
| `peerspan-revoke-invite-v1` | Bit 8 and root-issued administrator authority | Revoke the payload invite key. |

The exact envelope, payload, signature, context, structural certificate and scope
rules remain those of the strict reader and ordinary grant resolver. Only epoch
zero is supported; a supported record's mismatched network/epoch is `invalid`.
Original-person signatures are SSHSIG; no legacy signature can substitute for
an envelope signature. These records require `host_signature: "-"`.

Restrictions override all otherwise valid legacy/ordinary admissions, bindings
and complete activations, independent of catalog order, byte aliases or asserted
timestamps. Removal never grants authority. Person removal disables admission
and administration, and clears that person's bindings; its hosts' memberships
remain separate. Host revocation disables that host and clears its binding.
Unbinding is scoped to the named person/host and cannot erase another person's
binding. Invite revocation disables only legacy memberships derived from that
invite key, including both host and person halves; independent admissions remain.
No old/new admission restores a known removed person/host or unbound pair.

All candidate restrictions must be considered while resolving admission,
binding, activation, checkpoint and current-action dependencies. No traversal
order may preserve an issuer path disabled by another known restriction. A
successful projection requires every effective record to have independently
verified authority against the final restrictive view. A failure exposes no
partially checked state. Existing dependency/cycle bounds still apply.

## Historical authority

Original-person unbinding is durable. Administrator restrictions follow the
same role-history rules as ordinary admissions: recognized root delegation and
current admitted signer, or the root's exact format-2 `record:ar_...` kept entry
after administrator removal. An explicit withdrawal excluding the exact record
makes it inert; format 1 retains no new envelopes. Unknown administrator signers
are `forbidden`. An inert restriction does not create a false subject or erase
independent authority. Its signature, context, structural certificate and scope
must still verify; it need not activate an unusable issuer.

Device-signed restrictions need their exact issuer's complete activation and
either its currently usable path or a checkpoint retaining the exact `ar_` ID.
Extend checkpoint member checks to all four kinds (scope 2 for unbinding, 8 for
the administrator kinds). The original signer person or an unaffected live
strict ancestor can endorse them under the existing rules. Both the root kept
list and the person checkpoint are required if both role and device authority
were lost. No checkpoint creates live authority, restores membership or rewinds
a known restriction. Missing retention names the affected `ar_` ID.

An effective device-signed record that unbinds/revokes any host in its own exact structural
issuer chain, or removes its own original person, is `forbidden` as catalog
history, even with a checkpoint. V1 refuses such delegated mutations before
writing; alleged signing/receipt time cannot legitimize them later. The separate
current-action API retains its `authority_would_be_invalidated` response with the
exact selected path. Original-person alternatives remain subject to the normal
role/history rules. For example, preserving a removed administrator's own
person-removal record requires the root's exact kept-record authorization;
without that authorization, its final missing admission makes it `forbidden`.

Revalidate every materialized ordinary record after all known device revocations
and restrictions. The activation, feature and current-action APIs share this
resolver; historical verification cannot satisfy a first operation's deadline,
current authority or target preconditions. The first-feature activation gate
still refuses person envelopes as circular linking evidence.

## Projection and remaining boundary

Reuse the exact `catalog_facts` request/success/error shapes and 512 KiB decoded
bound from the [record contract](linking-record-checks.md#state-only-catalog-projection).
Removed people/hosts are known false subjects even without admission evidence.
Verified member labels may remain after removal and confer no authority.
Sole invite-derived memberships disabled by invite revocation have member `-`
unless an independent usable admission established a label.
Unbinding affects an existing matching binding row; by itself it creates no
host, person or binding row. Invite revocation has no separate projection array;
its effect is visible in derived membership and authorization. Arrays remain
sorted, and no state appears on error.

Completed invitation/redemption evidence follows the
[redemption checks](linking-redemption-checks.md). Policies/groups follow the
[access-state checks](linking-policy-checks.md). Standalone
live invitation tokens,
high-water/freshness rules and durable feature/storage/maps/propagation remain
pending. Other ordinary kinds still return `upgrade_required`. The network-root
companion remains restricted to complete linking admissions. These stateless
checks cannot remember a restriction omitted from a later input; future storage
must persist known restrictive state and refuse rollback before writers ship.

## Verification

A separate author uses only accepted contracts/public vectors and independent
signing helpers, without either implementation:

- All four kinds with original-person and activated device signers; exact scopes,
  administrator role, owner/subject separation and strict signatures/contexts.
- Permanent removal/unbinding/revocation across legacy and ordinary grants and
  complete activations; unrelated subjects/pairs, both invite halves and
  independent admissions; reordered catalogs, byte aliases and backdated times.
- Final issuer restrictions, expiry and device revocation; exact missing,
  partial, wrong-person, self/sibling/descendant and unaffected-ancestor/root
  checkpoints. Both retention dimensions and inert withdrawals.
- Refuse self-invalidating device history even when checkpointed; original
  person alternatives use normal role/history rules. No dependency self-bootstrap.
- Catalog projection including false subjects/labels, feature coverage for live
  hosts, and existing action/activation consumers refusing restricted paths.
- Existing strictness, limits, framing and all linking regressions. Update only
  old unsupported expectations for these four newly supported kinds.

```sh
python3 conformance/linking_restrictions.py \
  --go-probe /absolute/go-probe --rust-probe /absolute/rust-probe
```

Recorded commands, results and limitations are in the
[implementation results](results/linking-restrictions.json).

Verified root rotation and nonzero-epoch catalogs now follow the
[root-chain checks](linking-root-checks.md), including current attestations
and historical transcript preservation.
