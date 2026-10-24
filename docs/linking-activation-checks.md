# Signed catalog and activation verification

This bounded part of UP-06c.2 derives certificate-path state from signed public
evidence and verifies complete new-machine and same-key renewal transcripts in
both implementations. It follows the [transaction contract](machine-linking-transactions.md)
and [signing contract](machine-linking-contract.md). It does not install state,
commit a transaction, enable a feature, or expose a daemon/coordinator route.
The initial slice was accepted in [PR #46](https://github.com/peerspan/peerspan-internal/pull/46).
The [history checks](linking-history-checks.md) extend it with legacy invite
membership, sticky restrictions, administrator removals and retained records.

## Supported evidence and trust boundary

The caller pins a network descriptor (exactly `network_id`, `name`,
`genesis_root_public_key`, `coordinator_address`, `coordinator_public_key`), epoch,
optional previously known feature ID, authenticated caller host key, optional
expected original person, current time, and first-finalization versus historical
verification. The network ID must derive from the genesis root. Pins must match
the signed owner descriptor and request coordinator; no discovery value supplies
authority. Caller host must equal the request host even in historical mode.

This slice supports epoch **0**, and these catalog kinds:

- `admin_delegation`, `person_admission`, `host_admission`, `host_binding`:
  legacy genesis proofs, with exact canonical messages and signatures. Root
  delegation supplies administrator authority; admission by a person requires
  that person's root-issued delegation. A binding requires both person SSHSIG
  and host raw consent over the legacy binding message.
- `feature`: complete root-signed feature and every roster acknowledgment.
  Every legacy admitted host must occur in its frozen roster or prove the same
  feature through `join_ack` or a complete activation. First enablement's
  24-hour window and exact roster are checked separately by the
  [feature activation checker](linking-feature-checks.md). Fresh roster
  observation and durable high-water persistence remain transactional gates;
  this activation checker verifies historical feature evidence.
- `certificate`, `activation`, `person_record`, `root_record`: exact candidate
  objects and complete activations. Operation-bound records only become facts
  through their matching activation. Supported ordinary admission/binding
  records with operation `-` follow the [record checks](linking-record-checks.md).
  Certificate candidates alone never activate authority.
- `device_revocation`: original-person-root or strict-ancestor sticky revocations. The exact
  target certificate must verify structurally and identify the same device key.
  Delegated revocations follow the history checks, including exact retention
  when their issuer is no longer usable.
- Legacy membership, removal, unbinding/leave, `admin_removal`, `join_ack` and
  `checkpoint` evidence follow the [history checks](linking-history-checks.md).

The remaining *known* unsupported catalog kinds fail closed with `upgrade_required`:
rotation, policy, group and invite redemption. Unsupported epochs and
other ordinary records also return `upgrade_required`. Unknown kinds are `invalid`.
This deliberate support boundary means this is not yet a general v1 mutation
verifier and must not advertise writer readiness or `linking_version: 1`.
An offer or record epoch that differs from the pinned verification epoch is a
context mismatch (`invalid`); unsupported caller/bootstrap epochs require an
upgrade. Malformed numeric fields remain `invalid`.

The catalog has strict format, network, sorted/distinct `pf_` IDs and at most
4,096 entries. Verify each ID from kind and **exact decoded body bytes**.
Index certificates, final binding records and administrator admission records
also from the exact JSON slices inside activation payloads. Draft bindings are
never indexed as authorized records. Preserve byte identity for renewal `pf_`
references. Equivalent decoded semantic aliases are allowed; conflicting bodies
under one certificate/record/feature/operation ID are `state_conflict` (a different
commit manifest under an existing request is `operation_conflict`). All top-level
bodies are strict JSON. Relevant signed objects are cryptographically verified
before use; irrelevant certificate candidates do not supply facts.

Verify ancestor activations recursively before resolving owner/administrator
paths. Never insert the proposed certificate's activation while checking its
issuer. Exact owner path needs bits 6 for new, 4 for renew; administration needs
bit 8 and the person's current role, or the pinned network root. Check every
packet, signature, request ID, reference, epoch, feature, original person,
certificate issuer/host/device/request, proposed scope/time subset, selected
person's membership label and final consent. A binding draft and final record
must differ only in host consent. Root-record admission has the same exact
operation and host/label checks. New requests cannot supply renewal references;
renewals supply no binding/admission and must reference the exact existing,
activated membership and binding proofs and old certificate's same keys.
The old certificate must itself have been activated, though it need not be live.
Any positive proposed scope subset is allowed; activation does not implicitly
require bit 1 or make bit 8 an unconditional administrator grant.

First verification requires `created_at <= now < expires_at`, with exactly a
300-second request interval, live issuer paths, a live proposed certificate,
unrevoked target key and no existing host/binding conflict. Verification also
resolves other supplied new-host activations for the same
host before a new admission, even outside the issuer path. Renewals supply no
new admission and are not competing admissions for this purpose. Historical
verification skips the request deadline and target certificate's *own* present
expiry/revocation, preserving durable membership/binding for root-authorized
renewal after expiry. Historical durable records require currently usable
authority or the exact endorsements specified by the history checks. Structural
historical packet verification supplies no present signing authority. It never asserts
the target can currently sign. Ancestor depth and certificate paths are bounded
at eight. A revoked target key prevents first verification of a fresh certificate
with that same key. Existing path evaluator rules remain unchanged.

Missing exact certificate, activation, or renewal proof returns `proof_required`
with its `dc_`, `link_` or `pf_` ID; history endorsements additionally name exact
`ar_`/`dr_` IDs. Unknown person/host/binding/feature evidence
uses an empty list. IDs are sorted and distinct. Other codes: `invalid` for
malformed data/signatures/context/references, `forbidden` for insufficient
authority or proposed issuer scope/time expansion, `expired` for a request
outside its first-finalization interval, `authority_expired` for a nonlive path,
`device_revoked`, `state_conflict`, `operation_conflict`, `upgrade_required`.
Multiple faults do not have a fixed precedence.

## Conformance transport

Build the existing probes as described in the
[reader checks](linking-reader-checks.md), then run:

```sh
python3 conformance/linking_activations.py \
  --go-probe /absolute/go-probe --rust-probe /absolute/rust-probe
```

The [recorded results](results/linking-activations.json) include the activation
suite, reader/path regressions, language checks and their limitations.

The existing state-free probes additionally accept exactly:

```text
kind: "activation"
network_base64: exact pinned descriptor JSON
catalog_base64: exact catalog JSON
activation_base64: exact activation JSON
epoch: 0
known_feature_id: "-" | lf_...
caller_host_public_key: authenticated expected host key
expected_person_public_key: "-" | original person key
now: exact UTC-second timestamp
verification: "first" | "historical"
```

All fields are required. The sum of decoded network/catalog/activation bytes is
at most 512 KiB, each uses strict JSON, and the existing outer 2 MiB framing limit
applies. Catalog and activation have the existing transaction-contract shapes.
Success is exactly:

```text
ok: true
request_id: link_...
manifest_id: lp_... (commit packet ID)
certificate_id: dc_...
network_id: net_...
feature_id: lf_...
person_public_key: original person
host_public_key: target host
device_public_key: target device
mode: "new" | "renew"
```

Success establishes transcript eligibility under the supplied signed evidence
and pins. It does not mean committed, linked, persisted, fresh, or ready. The
reusable verifier returns its derived path state to a future transactional caller;
the probe only returns the checked identity and manifest. Failure uses the path
probe's exact `{ok:false,code:...}` shape, including `required_ids` only for
`proof_required`. No disk, network, private keys, clocks or injected admission
booleans are consulted.

## Verification cases

A separate suite author works only from these contracts and published fixtures:

- All 15 transaction fixture cases, with their exact success/error expectations;
  root new, delegated B to C, independent administrator, root admission, renewal,
  renewal after old expiry, missing admin, nonadmin signer, context/reference
  mismatch, deadline, issuer scope/time expansion, pending parent and sticky key
  revocation.
- Cryptographically signed adversarial changes to pins, caller, expected person,
  request mode/ID/lifetime, packet roles/signers/references, feature/epoch,
  certificate association, label, binding draft/final consent and renewal proofs.
- Catalog exact-byte IDs, sorted/distinct entries, equivalent aliases, semantic
  conflicts, nested-only renewal proofs, missing ancestor activation and records
  supplied alone without activation.
- Forged bootstrap admission/delegation/binding/feature, unsupported proof kinds,
  strict fields/types/JSON/Base64/size/depth and continued stream framing.
- Existing signed-object reader and exact-path suites remain regression gates.

Persistence, freshness/high-water, rotations, retention, coordinator fan-out,
recovery, ceremony commands and installed `up` acceptance remain subsequent work.
