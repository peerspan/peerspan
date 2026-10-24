# Ordinary management action authorization

This part of UP-06c.2 checks a newly submitted signed management action against
the [signing contract](machine-linking-contract.md) and a signed current catalog.
It composes the existing strict readers, catalog/activation verifier and exact
path evaluator. Both Go and Rust expose a reusable authorization gate; no
daemon/coordinator route, writer, storage change or CLI command is added.

This gate checks **current signing authority**, rather than applying the action
or deriving historical state from it. General catalogs containing ordinary
records, retained ordinary history, invite redemptions, policy/group high-water
handling and durable propagation remain required before writers. The current
catalog input retains the [activation/history support boundary](linking-activation-checks.md),
including epoch zero. A candidate action is supplied separately and cannot
establish its own membership, binding, activation or administrator authority.

## Pins and reader gate

The caller pins the exact network descriptor, current epoch, a previously
persisted feature ID, expected original person, **exact selected certificate**
(`root` or `dc_...`), and current time. These pins must come from independently
verified local state and signer selection, never from an unsigned remote index.
The original-person key is never copied or replaced by a device key.

The known feature must be a valid `lf_` ID. `-` means the reader upgrade has not
been durably enabled and returns `upgrade_required`, even if a complete feature
appears in the catalog. A different catalog feature is `state_conflict`.
Nonzero pinned/bootstrap epochs remain `upgrade_required`; a candidate record
whose epoch/network differs from the pinned context is `invalid`.

Verify the catalog's existing signed memberships, bindings, complete ancestor
activations, feature acknowledgments, known restrictive statements and retained
link history. Resolve exactly the pinned signer path at current time. Do not
fall back to another certificate, a replacement key, or a historical cached
result. A checkpoint may establish durable catalog history; it cannot revive
current signing authority. Missing exact dependencies retain their existing
`proof_required` IDs. No network fetch, injected admission flag, clock or disk
state supplies missing authority.

## Supported actions

`action_kind` is exactly `person_record` or `device_revocation`.

For `person_record`, require a strict format-1 person envelope, ordinary
`operation_id: "-"`, matching network/epoch/person/certificate pins, the exact
unsigned payload registry, and SSHSIG by the selected signer. Root-only
companion records and operation-bound link records cannot pass this route.
Bindings require the payload host's raw consent over the authorization message;
no other action accepts a host signature. Owner payloads name the signer person;
administrator payload subjects may be a different person.

| Record kind after `peerspan-` | Required scope | Additional authorization checks |
| --- | --- | --- |
| `policy-v1`, `policy-v2` | 1 | Payload owner equals signer person; `valid_until` cannot exceed the selected path's expiry. Preserve the existing 1-to-90-day payload window and strict rule shape. |
| `host-bind-v1`, `host-unbind-v1` | 2 | Payload person equals signer person; binding has exact host consent. |
| `host-admit-v1`, `person-admit-v1`, `person-remove-v1`, `revoke-host-v1`, `revoke-invite-v1`, `invite-v1`, `person-invite-v1`, `group-v1` | 8 | Signer person must have a current root-issued administrator role in addition to a live path. |

The original-person `root` selection supplies all person scopes, but requires
current person admission and the administrator role for scope 8. It does not
become the network-root signer. Device paths require every certificate's
activation, admission/binding, validity, unrevoked key, parent authority and
scope/time subset under the existing exact-path rules.

For both invite kinds, require `now < invite_expires_at <= now + 30 days` and
an expiry no later than the selected path's expiry. The exclusive current-time
boundary is `expired`; exceeding 30 days is `invalid`; exceeding signer authority
is `forbidden`. Equal path expiry and the inclusive 30-day endpoint are allowed.
An original-person signer has no device expiry cap. Policy current-window use,
including existing clock skew, remains a policy-access/publication concern;
this authority gate does not claim that a policy currently grants access.

For `device_revocation`, require the existing strict signed revocation shape,
matching expected person/issuer and network, SSHSIG by the pinned current signer,
and scope 4. Verify the exact target certificate structurally and require its
device key, person and network to match the action. The target need not be live
or activated: an original person can revoke a pending or expired device. A
device issuer must be a strict ancestor of the target. A sibling or unrelated
issuer is `forbidden`; a missing target certificate names its exact `dc_` ID.

## Refuse self-invalidating delegated changes

After verifying signatures and the live selected path, refuse a delegated action
that would disable that named path:

- `host-unbind-v1` for any path host under the signer person;
- `revoke-host-v1` for any path host;
- `person-remove-v1` for the signer person;
- device revocation of any device key in that person's selected path, including
  an alias certificate for the same key. Revocation sticks to the key.

Return `authority_would_be_invalidated` and the full affected selected
`certificate_ids`, ordered from oldest ancestor to selected leaf. Require the
original person or an unaffected authorized path. A checkpoint never authorizes
such a new operation. The original-person root selection is permitted to make
these restrictive changes, subject to its normal scopes/administrator role.
For a structurally matching revocation target and valid signature/live path,
this self-invalidation guard takes precedence over the strict-descendant check
for self, ancestor and same-key alias targets.
Other-person/host targets do not trigger this guard; they retain their ordinary
operation-specific state checks in the future writer.

## Result and remaining writer obligations

Success returns the exact checked action ID (`ar_` or `dr_`), network/feature,
expected original person/certificate, required scope and the selected path's
`not_after` (`-` for the original person). It does not insert any target fact,
revoke a key, publish a policy, redeem an invite or commit a management action.
Success under one supplied snapshot is not freshness or permission to skip
transaction-time checks.

Future writers must recheck current authority and reader gates atomically with
operation-specific admission/binding/conflict preconditions, invite single-use,
policy/group versions and high-water state, quotas, propagation and durable
results. Exact committed retries are a separate storage operation and must not
use this first-authorization path to restore removed authority. A successful
policy authorization does not imply that a policy has been selected/applied or
that access is allowed.

## Conformance transport

The state-free probes accept exactly:

```text
kind: "action_authorization"
action_kind: "person_record" | "device_revocation"
network_base64: exact pinned descriptor JSON
catalog_base64: exact signed catalog JSON
action_base64: exact signed candidate JSON
epoch: 0
known_feature_id: "-" | lf_...
person_public_key: expected original person key
certificate_id: "root" | dc_...
now: exact UTC-second timestamp
```

All fields are required. The decoded descriptor/catalog/action sum is at most
512 KiB, with existing object, JSON, Base64 and 2 MiB framing rules. Success is
exactly `{ok: true, action_kind, record_id, network_id, feature_id,
person_public_key, certificate_id, required_scope, not_after}`. Existing path
errors retain their exact shape, with `required_ids` only for `proof_required`.
The self-invalidation error is exactly `{ok: false,
code: "authority_would_be_invalidated", certificate_ids: [...]}`. Multiple faults
have no precedence. Unsupported action kinds are `invalid`.

## Verification

The [recorded results](results/linking-actions.json) include 313 action cases,
the existing five linking suites and language checks, including the full Go
race gate's discovery-test limitation.

A separate author works from the accepted contracts and independent public
fixture signers, never either implementation:

- Every person record kind using original-person and active device signers;
  nonadmin owner actions versus administrator actions; exact required scope,
  selected certificate and original identity. All scope bits and narrowed paths.
- Complete ancestor activations, missing certificates/activations/membership,
  pending candidates, issuer expiry/revocation/removal/unbinding, retained
  historical proofs never reviving current authority and alternate live paths
  never replacing the selected certificate.
- Owner/subject distinction, operation-bound records refused, strict unsigned
  payload registry, legacy-domain/device masquerading, record/consent/signature
  tampering and network/epoch/pin mismatches.
- Policy v1/v2 shape and path expiry bounds; both invite kinds at current-time,
  30-day and certificate endpoints, insufficient scope/role, and original-person
  expiry-cap independence.
- Device revocation by original person or live strict ancestor, pending/expired
  targets, unrelated/sibling/ancestor/self targets, target person/key/network,
  exact missing target proof and same-key alias self-invalidation.
- Self-invalidating person/host removal and unbinding, unaffected targets,
  original-person alternatives, full ordered path repair IDs and sticky known
  restrictions. No derived state is exposed or mutated on failure.
- A catalog feature cannot substitute the durable pin; feature conflict;
  strict fields/types/encodings, inclusive size boundary, framing/recovery.
- Existing reader, path, activation, history and feature conformance regressions.

```sh
python3 conformance/linking_actions.py \
  --go-probe /absolute/go-probe --rust-probe /absolute/rust-probe
```
