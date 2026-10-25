# Stored catalog verification budgets

Runtime writers verify the entire merged durable public catalog. A valid map
must never be truncated to fit a conformance-only request budget. The accepted
[transaction contract](machine-linking-transactions.md#1-common-types) allows
4,096 objects and 8 MiB of decoded public object bodies in a full map, within
the existing 16 MiB response bound.

## Fixed runtime entry points

Go exposes `VerifyStoredCatalogFacts`, `VerifyStoredActivation`,
`VerifyStoredActionAuthority`, `VerifyStoredFeature`, and
`VerifyStoredAccessState`; Rust exposes their snake_case equivalents. Their
contexts, arguments, verified outcomes and authority rules match the existing
stateless APIs. They differ only in the catalog budget:

- At most 16 MiB of exact UTF-8 catalog JSON, including wrappers and Base64.
- At most 4,096 top-level catalog entries.
- At most 8 MiB total decoded bodies of those entries, counted before indexing.
  This sum is not recursive: decoded nested payload bytes are not added again
  inside the same entry body. Equivalent aliases and nested material supplied
  as additional top-level entries each count their exact supplied body bytes.
- Existing individual public object (1 MiB), payload (256 KiB), JSON depth and
  semantic/dependency limits remain unchanged. The 64 KiB ceremony frame
  plaintext limit is separate from the public object limit.
- The network descriptor plus separately supplied activation, feature or action
  retains the existing 512 KiB aggregate bound independently of the stored
  catalog. A network-only stored-catalog/access-state request has the same
  descriptor bound. Context and high-water state retain their exact shapes.

Every boundary is inclusive. An exceeded bound is `invalid`, with no partial
facts exposed. Runtime routes additionally enforce their existing incoming
mutation and response limits before combining incoming proof with durable
state. A caller cannot select an arbitrary limit. Stored verification provides
no freshness or persistence by itself.

The existing exported APIs, probes and their 512 KiB aggregate request budget
remain unchanged. Runtime code uses the distinctly named stored entry points
only after loading its complete durable catalog and independent descriptor,
epoch, feature and high-water pins.

## Independent probe mode

The existing conformance executable accepts `--stored-snapshot` explicitly on
its process command line. Its normal mode remains unchanged, including the
2 MiB line framing cap. Stored mode uses a fixed 24 MiB line framing cap and
dispatches only catalog-consuming kinds (`catalog_facts`, `activation`,
`feature_activation`, `action_authorization`, and `access_state`) to the stored
entry points. Request/success/error JSON shapes are identical. No request field
can enable stored mode. Other kinds in stored mode are `invalid`. Oversized
lines are discarded through their newline and subsequent requests still work.
Both mode caps count the complete framed line including its delimiter LF:
cap-minus-one content bytes followed by LF is inclusive; cap content bytes plus
LF is oversized. A final unterminated line counts its raw content bytes alone.
The executable remains a conformance adapter and is not installed in bundles.

## Verification

An independent author derives `conformance/linking_stored.py` from this contract
without reading either implementation. The suite exercises both process modes:

- A cryptographically valid complete catalog beyond 512 KiB succeeds in stored
  mode and fails in normal mode; all current authority rules still apply.
- Exact decoded-body, catalog JSON, entry-count and framing limits, inclusive
  boundaries, oversized values, strict Base64/JSON/depth/object/payload limits,
  and stream recovery. Padding uses strict JSON whitespace in public records,
  preserving exact content addresses and signatures where the format permits.
- Missing/revoked authority and malformed late entries in a large catalog fail
  the whole verification, proving that no prefix is silently selected.
- Each stored entry point is exercised with a large valid catalog and its
  normal counterpart retains the original request budget; stored mode never
  enables injected-state `path` or raw signed-object kinds.
- The complete pre-existing linking suites and required language/build gates
  remain regression checks. Runtime persistence and installed ceremony checks
  separately exercise these APIs through the real daemon/coordinator boundary.

The [recorded results](results/linking-stored.json) distinguish focused budget
checks and isolated language gates from the shared final reader-stack integration
gate. Stored verification alone does not provide a live linking runtime.

Final composed reader-stack gates are complete: all 3,245 probe checks per
implementation pass; full Rust passes (138 library, 10 main, 6 integration;
2 ignored). Full Go fails only the documented unchanged discovery packet-routing
assertion; every other test/package passes. Exact logs and prior evidence are
retained in the result file. Runtime acceptance remains separate.
