# Implementation instructions

## Managed product tracking

Managed product work has a standing [upstream draft PR #186](https://github.com/peerspan/peerspan/pull/186).
The working repository is `maschad96/peerspan-managed` (`origin/main`); its review
branch is `maschad96/peerspan:managed` (`review/managed`). When publishing managed
changes, keep those branches aligned: `git push origin main` and
`git push review main:managed`. The `review` remote is
`https://github.com/maschad96/peerspan.git`. Keep the PR summary current at meaningful
milestones, with comments only for notable decisions or blockers. Leave it in
draft unless the owner changes that plan; no per-commit progress ledger is needed.

## Host implementation

The Rust host service (the crate at the repository root: `src/` and `tests/`) is the only host implementation in this repository ([DEC-OWN5](docs/decision-log.md)). The Go implementation is maintained separately at https://github.com/peerspan/peerspan-go and is not built, tested or packaged here. Shared specifications are in `docs/`; binary tests and build measurements are in `conformance/`. The broader architecture is maintained in the `mesh-new` design repository.

Coordination remains outside the collaboration data path. Hosts enforce permissions and own execution and local state. Agent identities are distinct from sessions. Membership, ownership, and access are separate.

The administration API is owner-local over a private Unix socket. The opt-in peer API has a separate router and authenticates host keys over mutual TLS; never expose local administration through it. Peers receive only explicitly granted message access. Owner labels, capabilities, and registry attachments do not establish network authority or integration readiness.

Implement working slices rather than empty modules. SQLite operations belong on blocking workers. Keep `Cargo.lock` tracked, and add dependencies only for a concrete need. The CLI uses Clap with typed commands and arguments; keep parsing separate from daemon lifecycle and local request execution, and preserve the shared command contract when extending it. Record shared external behavior in `docs/host-service-contract.md`; record broader product decisions in the system design.

## Coordinator-free redesign stream

For DEC-01 through DEC-07 only, the owner delegated completion on 2026-10-26.
Choose the recommended options, document each decision, rationale and discarded
alternatives, and continue through concrete contracts, Rust implementation,
independent conformance and reviewed PRs without routine clarification requests.
Reuse the Rust agent and the separate contract-only conformance author.
This delegation is specific to this work stream and does not change other
tracks. Existing authority boundaries and independent-test requirements remain.

## Tests

Tests come from the specification, not from an implementation. Agent-written tests that restate an implementation add cost without catching errors.

- **No new unit tests by default.** Implementers do not add unit or integration tests unless the contract or the owner asks for a specific one. Existing tests stay, and implementers keep running them.
- **Conformance cases come from the contract.** Each contract's Verification section lists the cases, settled with the owner along with the rest of the spec. Write concrete cases there when intent is subtle.
- **A separate author writes each new suite.** The suite's author works from the contract alone, never from the implementation, and is not the implementer. Ambiguities go back to the contract, not into the implementation's choices.
- **End-to-end checks stay.** Live runs and installed-bundle checks are separate from this rule.

From the repository root, run the language checks (CI runs the same):

- `cargo fmt --check`, `cargo test --locked`, and `cargo clippy --locked --all-targets -- -D warnings`.

Conformance is the [slim suites](conformance/slim/) ([DEC-OWN6](docs/decision-log.md), DEC-OWN9, DEC-OWN10): one small black-box suite per area, written from the spec by a separate author who never reads the implementation, each under 2 minutes and at most about 1,000 lines, split by area rather than by phase when it needs more. The per-push Conformance workflow stays within 15 job-minutes; a new suite states its lines and seconds in its PR, and one that would take the workflow over budget goes to the second tier or to the owner ([DEC-OWN14](docs/decision-log.md), [budget proposal](docs/conformance-budget-proposal.md)). CI builds `peerspan-host`, `peerspan-peer-probe` and `peerspan-helper` once and runs the suites in parallel, in two tiers (DEC-OWN15): every push runs one suite per area plus `onboarding` and `guided_machine` (`.github/workflows/conformance.yml`); the per-section guided suites run nightly, by hand, and on a pull request labelled `full-conformance` (`.github/workflows/conformance-full.yml`). The installed bundle, terminal, upgrade and participant checks are not in CI ([DEC-OWN18](docs/decision-log.md)); `scripts/installed-acceptance.sh` runs them locally. When external behavior changes, run the suite for that area locally with the debug binaries in one directory, for example `python3 conformance/slim/join.py --bin DIR`:

- `join`: create, invite, link a second machine, stage folds, refusals and time limits (spec 6, 8).
- `join_teammate`: a new person joining: the request's return path, single-offer selection, the two prompts on the joining machine, the inviter's `link_request_waiting`, `next` and exit status (spec 8.1, 8.3, 8.4, 16; ML-3, ML-4).
- `policy`: allow, deny, block, bans, policy edits and capability claims (spec 5, 12).
- `work`: messages, tasks, delegation chains, agent lookup.
- `renewal`: leases, automatic renewal, retention, root offline, expiry (spec 7); uses the debug-build test clock.
- `sync`: propagation and repair between hosts (spec 10).
- `delivery`: first-contact listener, mailboxes, QUIC completion, the helper and relay (spec 9).
- `root`: root rotation, root split and reinvite (spec 13, 14.2).
- `live`: live delivery (readiness, seen, redelivery, adoption, pending work).
- `capabilities`: sources, sharing, calls, approval, bounds, remote MCP servers and the built-in `gh` source.
- `basics`: info, status, errors, storage and restart (spec 14 to 17).
- `onboarding`: the owner-local guided-onboarding observation, request privacy,
  adapter readiness and read-only behavior (guided session contract section 1).
- `project_onboarding`: exact local project reviews, atomic metadata attachment,
  replay/replacement and schema24 boundaries (guided session contract section3).
- `adapter_onboarding`: exact guided adapter authorization, private credential
  recovery, scope/replacement boundaries and additive schema25 (section5).
- `invitation_onboarding`: exact contact-invitation reviews, atomic issuance,
  private handoff/recovery and additive schema26 (section9), plus read-only
  recipient signed-invitation inspection and privacy boundaries (section11).
- `join_onboarding`: exact recipient public-key/publication consent, atomic
  ordinary join-request creation, replay/privacy and additive schema27 (section12).
  Its launcher observes genuine own-request publication before the unchanged
  section15 strict read-only progress baseline (section49).

- `owner_onboarding`: exact new-original owner review, ordinary-intent atomic
  approval, rollback/history and consent boundaries (guided session contract section16).
- `owner_signing`: bounded local original owner-offer signing, exact generated/
  SSH-agent selection, typed-slot faults and pure replay (section18).
- `admission_onboarding`: read-only incoming new-original request/owner/selection
  inspection before administrator consent, purity and privacy (section20).
- `admission_consent`: exact durable root administrator intent preparation/approval,
  atomic rollback, public privacy and pure historical recovery (section21).
- `incoming_progress`: explicit bounded pinned GET/atomic incoming original and
  selection evidence retention, before/after IO guards and no consent (section22).
- `naming`: the default agent names from `attach` (launch contract, DEC-OWN12).
- `runtime`, `runtime_policy`, `runtime_renewal`, `runtime_runs`, `runtime_results`, `runtime_peerfs`:
  runtime tasks against `conformance/slim/fake_runtime.py` (runtime task contract, RUN-1 to RUN-7);
  second tier only.

A product gap is a strict expected failure (`XFAIL`) with its reason; a fix makes the case pass, CI reports `XPASS` and fails, and the fix removes that marker. Never weaken a case to make it pass.

Packaging, installer, upgrade and onboarding-integration changes require `scripts/installed-acceptance.sh` on a Linux machine (Node.js 22, Python 3.12 or newer, about 20 minutes): it packages a fresh bundle and runs `conformance/installed_bundle.py`, `onboarding_bundle.py`, `installed_terminal.py`, `installed_upgrade.py` and `installed_participants.py` against it, plus `test_package_release.py` and `test_onboarding_package.py`. State the result and the commit it ran on in the pull request. The Draft Linux release workflow still runs the bundle and onboarding checks on each architecture. Live runs with real models are separate manual checks.

- `owner_finalization`: pure original finalization eligibility/administrator
  root/P/H snapshot, exact original consent and privacy (guided section24).

- `owner_finalization_signing`: bounded original B/D/F signing under exact
  original consent/verified administrator parents and key/privacy (section25).

- `requester_commit`: exact durable requester final-commit review, ordinary
  intent/request atomic approval, rollback, privacy and pure history (section27).

- `requester_completion`: bounded exact approved requester signing/publication/
  local application and pure verified replay, without new consent (section28).


- `access_onboarding`: pure exact project-bound selected-person membership and
  signed/enforced policy inspection before agent-access consent (section30).

- `access_consent`: exact project/person policy-action review, nonsigning receipt,
  atomic ordinary-action approval, replacement/history and privacy (section31).

- `access_signing`: bounded exact dual-approved policy issuer signature storage,
  configured signer boundaries, atomic rollback and pure recovery (section32).

- `access_application`: exact signed policy local publication/application,
  atomic ordinary proof/edit/queue/result/event and pure recovery (section33).

- `readiness`: current exact-project membership, receiver-advertised access and
  exact-session adapter evidence, read purity and owner-router isolation
  (guided session contract section36). No peer/model readiness inference.

- `peer_reachability`: explicit one-machine pinned outbound peer observation,
  current project/authority guards around IO, no contact-learning sync or
  durable observation, privacy and owner-router isolation (section38).

- `machine_owner`: pure current existing-computer owner authority and incoming
  machine-request review, selected public provider, finite powers, privacy and
  owner-router isolation (guided session contract section41).

- `machine_owner_consent`: exact project-bound ordinary owner intent and unsigned
  receipt, atomic dual approval, replacement/history and router/privacy boundaries
  (guided session contract section42).

- `machine_owner_signing`: bounded exact dual-approved initial owner/fold signatures,
  configured original/owned device, atomic storage/history and owner-route privacy
  (guided session contract section43).


- `machine_requester_inspection`: pure exact join-flow-bound received existing-
  owner/selection/admission/finalization evidence on the new computer, finite7/2,
  folded admission, fixed windows and no consent/adoption (guided section45).

- `machine_requester_consent`: exact frozen remote machine inspection, unsigned
  project receipt, atomic ordinary/pending/receipt approval and pure history
  (guided section46). No signing/application.

- `machine_requester_completion`: bounded exact approved machine requester
  signing/publication/local application and pure verified replay (guided47).

- `guided_machine`: combined genuine two-host guided pinned machine request,
  selected owner consent/signing and automatic selection/finalization; one
  requester completion with lost reply/Lookup recovery, actual application and
  separate membership/access/readiness (guided session contract section49).

- `completion_rate_limit`: genuine two-person completion under a brief real
  authenticated rate-limit burst; separate first-result application from exact
  post-pressure repair, verify signed authority and unchanged requester consent
  (guided final acceptance contract, exact completion publication).
