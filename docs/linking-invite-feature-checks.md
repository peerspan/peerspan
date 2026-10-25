# Fresh feature consent for private invitations

This extends the accepted invitation formats with an explicit signed feature
choice. An unsigned token catalog, server preview or a joining host's self-ack
does not establish a previously persisted feature. Existing inner legacy and
authorized invitation bytes and redemption signatures stay exact.

## Local decision clock

CLI creation and validation of the new feature-bound invitation format use the
same fixed whole-second UTC decision clock as the daemon. Production uses local
UTC. Independent conformance configures the existing opt-in runtime clock
controls explicitly for each participating CLI process, without enabling frame
barriers in the CLI. No request, token or coordinator response can select this
clock. Legacy invitation timestamps and monotonic transport deadlines retain
their existing behavior; invalid explicitly configured test time fails closed.

## Exact wrapper and binding

A newly issued post-feature private token uses `peerspan-feature-invite-v1.`
followed by canonical unpadded base64url of exactly `{format: 1, network,
token, mode, host_invite_base64, person_invite_base64, feature_binding,
catalog}`. `network` is the exact five-field descriptor; `token` is the original
complete legacy or authorized private invitation string, including its existing
seed. Public invite bytes are canonical padded Base64 of the exact public
legacy invite object or person authorization envelope, or literal `"-"` for an
absent half. Host/person/member require the existing exact half combinations.
Decode the inner token independently and require its key, label, expiry, mode,
network and public signatures to match these exact public halves. No private
seed enters a public catalog, binding or redemption.

`feature_binding` is exactly `{format: 1, network_id, network_name,
genesis_root_public_key, epoch, feature_id, coordinator_address,
coordinator_public_key, mode, host_invite_sha256, person_invite_sha256,
issuer_kind, person_public_key, certificate_id, signer_public_key, issued_at,
expires_at, signature}`. Hashes are lowercase SHA-256 of the exact decoded
public invite bytes; an absent half's hash is literal `"-"`. `issuer_kind` is
`network_root` or `person`. Network-root fields use person/certificate `"-"` and
the current root public key. Person fields name the original admitted person,
`root` or exact `dc_` issuer and its exact signing public key. The binding and
both public invite halves use that same authority, including the same epoch
where the original grant format carries one.

Sign exactly:

```text
L("peerspan-link-invite-feature-v1", network_id, network_name,
  genesis_root_public_key, decimal(epoch), feature_id, coordinator_address,
  coordinator_public_key, mode, host_invite_sha256, person_invite_sha256,
  issuer_kind, person_public_key, certificate_id, signer_public_key,
  issued_at, expires_at)
```

Use the existing current-root raw/SSHSIG convention or person/device SSHSIG.
Times are strict whole UTC seconds; `issued_at <= now < expires_at`, with
nonempty duration no greater than 30 days. `expires_at` equals the inner invite
expiry and is no later than the current signing path's expiry. A 300-second
binding is not imposed on invitations. Current issuer path, exact current root
or admitted administrator role and invite expiry are rechecked on first use.

The issuing daemon must already hold the exact durable LF and a complete current
verified projection. It signs only the fixed binding for an explicitly requested
invitation after checking its exact grant bytes and live issuer, never an
arbitrary message. The binding is not a public catalog kind or an admission.
The recipient verifies this fresh signed choice and all public grant authority
before using the resulting LF for cold feature adoption. It still independently
verifies the returned complete feature, restrictions, root chain and map; no
coordinator pin substitution follows from the unsigned wrapper.

Old tokens without a binding may use only the original first-feature adoption
rules when their complete independently verified evidence is available. An old
unwrapped token alone cannot establish those proofs, including within the first
24 hours. The current client returns structured `426 upgrade_required` with
fresh feature-bound invite/current-root repair guidance on an activated
coordinator when the evidence is unavailable, preserving existing state. This
milestone adds no join-preview route and makes no positive legacy-bootstrap
claim from an unwrapped token alone. Existing pre-feature legacy joins remain
supported; new post-feature root, person and device invitations use the signed
wrapper and durable public redemption intent below.

## Local integration

Owner-local `GET /v1/networks/{id}/link-catalog` has no body/query and returns
exactly `{catalog}` after verifying the current durable feature and complete
projection. The fixed 16 MiB response bound applies. It performs no sync, sign
or mutation and grants no authority. The original CLI provider can construct
and sign the fixed invitation binding from this verified local state while its
key stays in the CLI/SSH provider.

`link-actions` gains explicit variant `invite_feature`. Its unsigned payload is
the binding above without `signature`, plus exact `host_invite_base64` and
`person_invite_base64`; those bytes must agree with its hash fields. Existing
`certificate_id` outer selection must match the payload's exact person/issuer,
even under `auto`. The daemon checks actual network descriptor, durable feature,
current path/role, matching grant authority and lifetime before any signature.
It returns the existing HTTP-200 result with `record_id: "-"`, `proof_id: "-"`,
`record_base64` equal to the exact signed binding, a sufficient public authority
catalog and `committed: false`. It never inserts that binding as a public object.

Root-held invitation creation and original-key CLI creation wrap their existing
tokens with the same signed binding. Existing local invitation recording accepts
the wrapper only after full validation and preserves existing issued events.

The shared Go helpers are `VerifyStoredInviteFeature(ctx, catalog, binding,
hostInvite, personInvite)` and `VerifyStoredInviteFeatureIntent(ctx, catalog,
unsigned)`, with a `CatalogFactContext`. The signed helper's absent public half
is an empty byte slice. The intent contains the two Base64 half fields above;
it requires a previously durable non-`-` feature matching the unsigned binding.
Both return only the fixed signing message and checked feature, epoch, issuer,
signer and lifetime metadata. An unsigned result establishes no signature or
published authority. Signed cold verification may begin with known feature `-`:
verify the binding signature under its exact declared signer and independent
current root chain before using that signed feature choice to verify the full
catalog and current issuer/grant authority. A retained non-`-` feature must match.
Invite consumption remains a separate atomic redemption check.

The sufficient-proof selector accepts seed-only kind `invite_feature`, whose
public body is exactly `{binding: SIGNED_BINDING, host_invite_base64,
person_invite_base64}`. It contains no inner token or private seed. Validate the
binding and exact decoded halves with the shared signed verifier against the
full source; discover their exact LF/root-chain, issuer role/path, public grant
subjects and sticky restrictions. Revalidate this seed against the selected
output before returning it. The seed never becomes a catalog object: output
remains an exact original top-level subset under the existing bounds. No
fabricated redemption or unsupported legacy public catalog kind is introduced.

## Durable public redemption intent

Before the first redemption POST, persist the exact public request in existing
`network_statements`, kind `link_invite_redemption_intent`, subject `lri_` plus
SHA-256 of `L("peerspan-invite-redemption-intent-v1", network_id, mode,
host_public_key-or-"-", person_public_key-or-"-", invite_public_key)`.
The subject pins the explicit requested original-person key when supplied,
including a host-only public redemption that cannot itself admit that person;
the subject is bookkeeping and grants no person admission or binding.
Its strict record is exactly `{format: 1, network_base64, feature_id,
feature_binding_base64, redemption_base64, request_base64, submitted,
result_map_base64}`. Base64 fields retain public bytes only; the exact request
contains the public redemption/catalog/address/candidates/join_ack. No private
inner token, seed or key is stored. Result is literal `"-"` until verified.
`feature_binding_base64` encodes the exact public `invite_feature` seed wrapper
`{binding, host_invite_base64, person_invite_base64}`, retaining both original
public halves even when an explicit member/skip redemption omits the unused
person half. This is private public-proof bookkeeping, not invite consumption or
a standalone catalog entry.
The explicit join/redeem command authorizes this fixed intent; retries cannot
change joined_at, signatures, public request or operation identity.

At most eight retained intent rows per network and 32 per host may exist,
including completed outcomes that retain large exact receipt maps. Capacity is
checked before any new intent, signature or submission. A
different person/mode for the same host and invitation while its outcome is
unknown or completed returns `operation_conflict`, never identity replacement.
A definitive authenticated first-attempt noncommit rejection may retire a
failed intent so a later explicit member/admit-to-skip rebuild remains possible.
Timeout, 500, rate refusal, or an expired response after an uncertain submission
cannot replace an unknown outcome. Never silently rebuild a submitted request.

An exact committed retry may verify the frozen signed binding at the original
public redemption's joined_at, then independently verify the immutable complete
receipt, exact descriptor/LF/original PFs and its exact redemption/join proof.
Retain that exact receipt and union all current local evidence through the
historical repair/current projection. Preserve current coordinator pin, feature,
operations, restrictions, epoch/high-water and newer local reachability hints.
Apply local membership, public proofs, feature/high-water and outcome atomically;
an old outcome does not establish current coordinator freshness or readiness.
A late delegated-token committed retry still requires the exact paired invitation
AR(s) and redemption PF to have usable retained authority at the current clock.
The original joined_at, signed LF binding and immutable receipt prove commitment;
they do not supply missing checkpoint retention or revive an expired delegated
signer. Without that exact retention, return `proof_required` and preserve the
submitted intent, request and chosen person without signing, redeeming again,
selecting a new person or partially installing a network/LF. After an exact
checkpoint or root repair supplies the required retention, the same immutable
outcome may complete. Independently check the frozen response descriptor, LF,
required PFs and complete historical snapshot as of the original joined_at,
solely as evidence of the fixed commitment. Then union all current local
checkpoint/proof evidence and verify historical repair and the current
projection at NOW before atomically applying any network, LF or signer state.
This permits exact later retention to satisfy a frozen outcome without treating
that historical receipt as present authority. Generic live maps retain their
existing complete-current-snapshot and omission checks. A root-held legacy
invitation may complete its late retry when its independently verified current
authority remains usable.
Completed or never-submitted expired intents may be cleaned after invite expiry
plus 24 hours, preserving public proof. Submitted unknown outcomes remain.

## Verification

The existing conformance-only normal/stored probe commands accept two additional
kinds. `invite_feature` is exactly `{kind, network_base64, catalog_base64,
binding_base64, host_invite_base64, person_invite_base64, epoch,
known_feature_id, now}`; an absent public half is literal `"-"`, otherwise its
canonical padded Base64 encodes nonempty exact public bytes. The
`invite_feature_intent` kind is exactly `{kind, network_base64, catalog_base64,
unsigned_base64, epoch, known_feature_id, now}`; the unsigned object includes its
two half Base64 fields as above. Times use strict whole UTC seconds. Normal
probes retain their 512 KiB aggregate decoded-input bound; stored probes retain
the fixed stored catalog/object bounds. No caller-controlled budget is added.
Success is exactly `{ok: true, feature_id, epoch, issuer_kind,
person_public_key, certificate_id, signer_public_key, issued_at, expires_at,
not_after, message_base64}`. Failures keep existing `{ok: false, code}`, with
exact `required_ids` only for `proof_required`. Neither probe signs, publishes,
stores nor admits anything; intent success asserts no signature.
`not_after` is literal `"-"` for a network root or original-person `root`
issuer; a delegated issuer reports the exact minimum expiry of its selected
verified signing path. An intent with known feature `"-"` returns
`upgrade_required`, matching existing typed signing intents; an unsigned
payload's feature is never promoted into missing authority evidence.

Error categories follow the existing typed action boundary: elapsed binding
expiry is `expired`; future issuance, duration over 30 days, unequal public-grant
expiry, malformed shape, hash, descriptor or binding signature are `invalid`.
Binding expiry beyond the selected path expiry is `forbidden`. An expired
certificate is `authority_expired`, a revoked device is `device_revoked`, and
withdrawn administrator role or revoked invitation is `forbidden`. A retained
feature mismatch is `state_conflict`; missing path proofs keep the existing
`proof_required` IDs.
For `issuer_kind: "network_root"`, person/certificate literal `"-"` and the
exact current tip root signer are strict typed root fields. Substitution of any
of those fields, including a retired root signer, is `invalid`.

Independent cases cover exact hash/descriptor/LF/issuer/time binding, substituted
old LF or coordinator pin, preserved inner bytes/seeds, member-half mismatch,
expired or withdrawn admin/device and old-root refusal, original first-feature
rules for old tokens, and cold activated joins after the original 24-hour window
using a valid fresh signed binding. No partial local state, admission or private
signature is returned for rejected intent. All Go/Rust token/CLI/daemon pairings
use the same exact signing lines and wrapper format.

### Original-person CLI identity before an uncertain join

After full local verification of the signed feature binding and inner invite
and the explicit join identity choice, the CLI persists a newly generated
original-person key before the first join POST. Existing joined identity and
selected-device conflicts are checked first; an existing bound identity never
causes generation or substitution of a new person. The key stays CLI-side in
its existing private directory with mode 0600 and is never included in the
public redemption intent or sent to the daemon. Saving uses the existing
exclusive creation path, so an interrupted response reuses the same identity
on retry rather than changing the frozen public redemption request.

After an exact invitation outcome is verified, an independently verified current
binding of the same stable person to this same host makes the follow-up binding
a no-op. Do not sign/publish a gratuitous replacement. Exact LRI/request/receipt
bytes and all old public proofs remain retained. A separate legitimate verified
sync may add unrelated evidence; it cannot replace identity, restore authority
or roll back restrictions, feature, operations or high-water.

### Repairing an exact outcome before any local network exists

If a frozen successful LRI outcome has never been applied locally, first verify
its exact target host, original reviewed descriptor and LF, all required PFs,
and complete historical snapshot at the original `joined_at`. This establishes
only the immutable commitment. If current projection still needs retention
evidence, the admitted host may fetch `GET /coord/v2/networks/{id}/map` using
its host mTLS identity and only the exact coordinator address/key independently
pinned in that LRI. Bound and validate the response descriptor's network ID,
immutable name, genesis root, and exact coordinator pins; require the same LF.
Treat its catalog solely as untrusted repair evidence and union it with the
original receipt and every current local proof before historical repair and
complete current NetworkState/AccessState validation. No received membership
hint, coordinator pin or freshness assertion is applied by this repair. Verify
the original receipt member proof references at the original `joined_at` before
current repair. After current verification, derive membership, binding and join
references from the verified current facts, even when the immutable receipt
references an earlier binding. Preserve prior local reachability hints and use
only independently verified original-receipt hints when no newer local hint is
known; the proof-repair GET never supplies reachability. The exact original
receipt remains unchanged. Generic live-map proof-reference and omission checks
remain unchanged.

Preserve the exact original receipt, request, redemption and feature choice.
There is no new redemption or signature, no first-feature inference from the
repair response, and no partial network, LF, provider or projection on refusal.
Known-network live maps retain their normal omission rules. Independent cases
cover expired delegated admission repaired by an exact later paired checkpoint
when no local network exists, unchanged LRI bytes, and malformed/mismatched
repair response or absent retention leaving all local authority unapplied.

### Guided invitation preflight

The existing `up --join` path accepts the same signed feature invitation as
explicit `join`. Before key generation, redemption, service/network mutation or
token rewriting, decode and fully verify the wrapper at the shared local
decision clock. Project only reviewed network ID/name, coordinator address/key
and member metadata for the existing guided flow. Preserve the exact original
token and descriptor/LF choice for the daemon's independent current-authority
and durable-retry checks. Metadata projection creates no legacy invitation,
first-feature authority or admission. Pre-feature legacy invitations retain their
existing parser and timestamp behavior. Independent installed/guided acceptance
covers valid feature invitations plus malformed, substituted and expired
preflight refusal without new keys or redemption.

## Known-local retention proof learning

When a previously joined network's complete local projection returns only
`proof_required`, and there is no pending root rotation or restriction marker,
ordinary sync may make its bounded v2 request to the independently persisted
actual coordinator pin to learn missing public retention evidence. It cannot
follow a move or successor from the incomplete source. The normal live response
verifier must retain every local PF, the exact durable feature and high-water
state, and verify the complete current union before any atomic state or
freshness update. A known forbidden result, local malformed state, missing
pending-rotation proof or marker failure remains a refusal. This permits an
already published exact checkpoint to repair a late immutable invitation retry;
it supplies no new signing authority, feature adoption or omission exception.

The same late-retention requirement applies to a raw owner-local join retry of
a completed LRI, independently of any CLI preflight. Before returning the fixed
retained result, verify the complete current local projection, feature and
retention evidence. This read performs no new redemption, signing, freshness or
pin update. Known current removal may remain a valid inactive historical
commitment; returning it cannot revive membership or change the exact intent,
receipt or access maxima. Independent late-retry checks cover raw requests
before and after the exact paired checkpoint is learned.

Successful owner-local `POST /v1/networks/join` keeps HTTP `201` for both first
feature-bound completion and an exact completed retry. The raw retry uses the
exact token and redemption person key; an already verified matching host/person
binding needs no new binding signature. Missing required retention returns the
existing structured `409 proof_required` and preserves the retained outcome.
