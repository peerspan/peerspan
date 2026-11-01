# Guided onboarding from an existing agent session

Status: feature plan. The owner accepted the experience below on 2026-10-28.
Implementation is in progress on the isolated feature branch. Working slices
provide the read-only observation API, native Claude entry,
local delivery check, owner-local project review backend and native human
project review controls, native adapter review, a scoped local lease and an
explicit incoming-message and assigned-task paths. The full interactive
flow and its installed/live-session validation remain pending.

## Accepted experience

1. **Connect this project** from inside the existing agent session.
2. **Invite someone** or **connect my other computer**.
3. Each participant reviews the relevant identity and permissions in their own
   guided flow.
4. Peerspan completes the intermediate steps and shows actual connection
   readiness.

The normal flow uses people, machines, projects and named permissions. Peerspan
carries network IDs, key bindings, approval references, signer selection and
ceremony stages. Existing explicit commands remain available for diagnosis.

Connecting a project does not share its files, conversation, tools or agents
with another person. Sharing and access changes require their own reviews. The
first version composes the existing host, membership, access and attachment
contracts; it does not promise shared conversations or PeerFS integration.

## Branch and review model

- Tracking PR: [#35](https://github.com/peerspan/peerspan/pull/35).
- Integration branch: `codex/guided-session-onboarding` in `peerspan/peerspan`.
- Baseline: `2719d9978ddb86fba003675217fd04922de77a9f` from `main`.
- One tracking PR compares that branch with `main` throughout development.
- Each implementation slice has a small PR whose base is the integration
  branch. Reviews and fixes land there. Main receives the complete feature
  through the tracking PR after the acceptance gates below pass.
- New work uses separate branches and checkouts. Existing runtime, PeerFS and
  other host work continues independently.
- The tracking PR records each slice's PR, reviewed commit and verification.
  A merged slice is not evidence that the complete feature is ready.

## Requirements

### Start in the current conversation

The entry point works in the current project and preserves the current agent
conversation. It detects existing attachment and pending setup before making
changes. It does not start a replacement conversation to claim success.

Claude Code is the first frontend. Host operations must stay separate from
frontend presentation so Codex and OpenCode can use the same flow later. Their
existing integrations continue to work.

Installation and session attachment are distinct. A plugin can become
available after a plugin reload without proving that incoming events reach the
current session. Claude's channel mode currently requires launch-time opt-in;
plain MCP registration is not incoming-channel readiness. GU.impl2 selects the
native Claude mod API for the existing-session frontend, with a separate
explicit prompt/tool check. The frontend slice must test that route with the current session.
An unsupported path is a named blocker, never a successful connection.

### One guided flow per participant

The flow offers the next meaningful action for the current participant and
waits when another participant must decide. Requests return to the inviter
automatically where transport supports that. A private manual handoff remains a
fallback, with an explanation of who should receive it.

The original owner, administrator and requesting machine retain their separate
authority and consent. The same person may perform more than one role only
when their actual current authority permits it. Peerspan transports the exact
references between those roles; users do not copy them between commands.

Reviews identify the person, machine, network and requested permissions in
plain language. Public fingerprints remain inspectable. Powers such as managing
access, trusting a machine or approving more machines are stated explicitly.
Admission and permission to reach an agent remain separate decisions.

### Automatic steps, bounded approvals

Continue deterministic protocol work after the relevant exact approval. Retain
the existing durable ordering of consent, signing, encryption and publication.
Changed identity, permissions, signer or expiry requires a new review. An
ambiguous network, identity or offer requires selection; do not choose by list
order or silently fall back to another signing key.

Owner administration stays on the private local control interface. The
credential-scoped agent adapter and authenticated peer interface do not acquire
owner administration powers. Incoming peer content is never owner consent.

Original person keys stay on their original machines. Invitations, pairing
secrets and adapter credentials stay out of command arguments, routine logs and
model context. Decide the private handoff and human-review interface in the
contract slice before implementing it.

### Resume the same work

Keep the request, chosen identity and exact reviewed terms after interruption.
Re-entering setup resumes that request instead of creating another identity or
network. Repeated actions must not duplicate membership, attachment or grants.
Cancellation and expiry leave a clear outcome and next action.

Transport failure reports what is unreachable. This feature creates no required
Peerspan-operated service and does not imply that a handoff makes unreachable
machines reachable. Optional discovery and relay helpers remain replaceable.

### Report observed readiness

Distinguish service available, membership approved, attachment prepared,
adapter connected, incoming delivery verified, and peer reachable. Show waiting
and blocked states with the next participant action. A generated config, an
accepted notification or a live lease alone does not prove model receipt.

## Implementation slices

These are implementation tasks, not separate releases. Each slice lands only
on the integration branch through a small PR.

The [flow contract](guided-session-contract.md) starts with GU-01a/GU-02a:
a read-only owner-local onboarding snapshot. Mutation APIs, participant reviews
and existing-session delivery remain later work; this foundation is not the
complete four-step experience.

### First slice: owner-local observation

GU-01a/GU-02a implements `GET /v1/onboarding` and the advanced
`peerspan onboarding` diagnostic command. The response combines current
networks, agent/session connection evidence and retained public connection
requests in one database snapshot. It performs no setup or approval and carries
no pairing secrets. Existing status and adapter APIs retain their behavior.

The independent slim suite covers the response, request privacy, read-only
behavior, connection evidence, owner-only routing and unavailable-daemon
behavior. This slice does not complete GU-01 or GU-02.

GU-01b/GU-03a adds the [native Claude entry](../integrations/claude-onboarding/README.md):
`/peerspan` reads this observation in the current conversation and offers an
explicit local delivery check. Native callbacks are the chosen direction for
human reviews; their exact immutable terms and owner-local mutation contract
remain next work. This entry creates no project attachment or authority. Native
runtime fixtures do not replace the outstanding live model check, whose first
inference attempt hit the account's weekly usage limit. Native pane opening,
close, reload and reopening worked in one running Claude 2.1.303 process.

GU-01c/GU-02b adds an [exact local project review](guided-session-contract.md#3-exact-local-project-review-gu-01c--gu-02b).
The host prepares a durable immutable review, resumes it without refreshing its
expiry, and accepts an exact explicit decision. Approval atomically records
local agent/session metadata. It issues no credential, grant or channel proof.
Schema24 adds one private flow table; existing DEC records are retained.
The advanced `onboarding project prepare/inspect/decide` commands carry mutation
payloads on stdin. GU-02c/GU-03b wires the native pane to this flow with private
context lookup, explicit agent selection, exact terms and human callbacks.
The pane rechecks the native root/conversation and captured review before each
decision, resumes retained work, and offers explicit replacement after expiry
or invalidation. It reports attachment metadata separately from the still-pending
adapter connection. Existing startup detaches metadata sessions,
so an approved flow becomes invalidated after host restart and cannot be
silently resurrected. Pending reviews and declined outcomes remain resumable.

GU-01d/GU-02d adds the separate [exact adapter authorization](guided-session-contract.md#5-exact-local-adapter-authorization-gu-01d--gu-02d)
for an attached project's existing session. Approval issues a fixed 24-hour
credential to handle already authorized work, with no directory access,
outbound routes or capability calls. Read-only flow views contain no secret;
an exact private retrieval can recover the approved credential after a lost
response without another approval or plaintext token storage. Schema25 adds
one child-flow table. The advanced `onboarding adapter` stdin interface is for
integration work. Issuance is separate from a lease, channel proof or model receipt.

GU-02e/GU-03c adds [native credential review and a scoped local lease](guided-session-contract.md#6-native-credential-review-and-scoped-lease-gu-02e--gu-03c).
Explicit Approve/Decline captures the exact project and credential review;
explicit Connect privately retrieves transport material and renews a local
adapter lease. Close preserves an established runtime, Stop halts renewal, and
reload requires explicit reconnect with the original instance. No credentials
enter model context. A real terminal/temporary-host smoke exercised those
actions without inference. Incoming work, native data tools and exact model
receipt remain separate from the lease: a lease alone is not delivery verification.

GU-03d adds [native incoming messages](guided-session-contract.md#7-native-incoming-messages-and-exact-model-acknowledgment-gu-03d).
Explicit enable starts a bounded model readiness challenge; only its exact
current-main-model acknowledgment and host confirmation permit message claims.
Scoped tools mark held messages seen or save a response to their original
sender, with independent submitted/seen/replied counts. No task/update is
consumed. A real terminal submitted the readiness prompt, but inference hit
the account's weekly limit; actual model receipt/reply remains an acceptance
gate. The feature still needs guided teammate/device/access flows and the
installed two-machine exchange.

GU-03e adds [native assigned tasks and cancellation](guided-session-contract.md#8-native-assigned-tasks-and-cancellation-gu-03e)
after an additional explicit enable under the current native delivery proof.
Scoped task tools accept/reject, report progress, complete text output and
confirm requested cancellation. Adopted tasks retain their running state and
progress; task and cancellation submissions remain separate from successful
model lifecycle calls. Task failure preserves messages/lease; context or native
proof loss stops task authority. File transfer, outgoing delegation and its
notifications remain future slices. Actual task/model and installed acceptance
remain pending; the unchanged account-quota refusal is not another task test.

GU-01e/GU-02f/GU-04a adds the [exact contact-invitation backend](guided-session-contract.md#9-exact-contact-invitation-review-gu-01e--gu-02f--gu-04a).
An attached project selects an explicit network, member label and optional
person-key pin. The host retains exact human-review terms before minting one
introduction and its automatic return path atomically. Codes are retrieved only
through the private handoff operation; inspection/decision/status contain no
code. Fixed expiry, explicit additional invitations and exact retry preserve
consent. Schema26 adds a private flow table and no membership/access authority.
Native invitation controls are added by GU-03f/GU-04b below. Joining identity
review, participant approval and agent-access review remain subsequent slices. This backend is not the complete
Invite someone flow or evidence of peer/model readiness.

GU-03f/GU-04b adds the [native invitation pane](guided-session-contract.md#10-native-invite-someone-review-and-private-reveal-gu-03f--gu-04b).
After attachment, explicitly choose a network, label and optional person-key
pin; review every public identity/hint/effect, then approve or decline exactly.
A separate explicit reveal retrieves the retained code only into the private
human pane. Hide/navigation/Refresh/context change/expiry clear it; no model
turn, clipboard, file or plugin storage is involved. This is the inviter side;
recipient import, admission and access reviews remain later slices.

GU-01f/GU-02g/GU-04c adds [private recipient inspection](guided-session-contract.md#11-recipient-invitation-inspection-gu-01f--gu-02g--gu-04c).
The local host verifies a privately supplied introduction without retaining it
or creating any identity/request/network. The native pane shows exact signer,
network, pin, contacts/hints, expiry and read-only effects. Signature validity
is distinct from current authority or admission. Recipient identity selection,
native request controls, participant consent and access remain subsequent slices.

The [recipient request-consent backend](guided-session-contract.md#12-exact-recipient-join-request-consent-backend)
reviews an explicitly supplied person public key and the exact verified
introduction. Explicit approval commits the ordinary request and public outcome
together; retries recover that request without issuing another. Schema27 adds
only public review/digest/outcome state. This backend does not select, import or
create a person key. The [native existing-identity flow](guided-session-contract.md#13-native-joining-with-an-existing-local-original-identity)
adds explicit local generated/SSH-agent public-key choice and exact publication
review, private code re-entry and read-only outcome recovery. It creates no
original key and claims no key possession. The [explicit creation slice](guided-session-contract.md#14-explicit-new-original-identity-creation)
adds a separate review and approval for a new original when inventory is empty
and the introduction is unpinned. It saves the key atomically without replacing
an existing identity, then returns to public-key choice before any request.
Publication remains separate from participant approvals and agent access. The
[explicit progress snapshot](guided-session-contract.md#15-read-only-published-request-progress)
shows the exact ordinary request's recorded state and next participant without
advancing it. The [first owner consent backend](guided-session-contract.md#16-exact-new-original-owner-consent-backend)
prepares fixed public profile7 terms for a new original and atomically approves
the existing ordinary intent. It neither collects the original signature nor
advances the request. The [native owner-consent review](guided-session-contract.md#17-native-exact-owner-consent)
adds explicit Review/Approve/Leave and pure Check recovery for those fixed terms.
The [bounded local signing command](guided-session-contract.md#18-bounded-local-original-owner-offer-signing)
adds `onboarding join owner sign --stdin` for one original owner-offer signature
under that exact approved review. It uses the existing private generated key or
the exact SSH-agent identity and submits only the typed original authority slot.
An exact completed-offer replay reads public evidence without key use. Recorded
signature evidence establishes neither admission nor connection readiness.
The [native signing control](guided-session-contract.md#19-native-bounded-original-owner-offer-signing)
adds one explicit Sign original owner offer action after approved consent, strict
public recorded evidence and lookup-only recovery. It reads no keys or signing
bytes itself. The [incoming admission inspection backend](guided-session-contract.md#20-read-only-incoming-administrator-admission-inspection)
verifies an already retained incoming new-original request and its exact selected
owner offer, returning public terms without preparing an intent or choosing a
signer. It adds no native admission control or approval. Administrator consent/
signing, later original finalization, requester final consent and agent access
remain subsequent slices.

The observation suite isolates each automatic invitation return from previous
joins and other invitations, then checks two retained pending requests together.
Its original shared-transport fixture timed out in PR #36 CI. This fixture
correction does not establish concurrent return delivery or retry behavior.
GU-06/GU-08 must cover multiple invitations sharing one first-contact endpoint,
including rate limiting and the manual fallback, before the complete feature
merges to main.

| ID | Deliverable | Depends on | Acceptance |
| --- | --- | --- | --- |
| GU-01 | A concrete flow contract: participant actions, review fields, private handoff, resumable state and readiness meanings; record the decisions and discarded options | This plan | Map every action to existing authority boundaries; specify black-box cases before implementation; settle the existing-session delivery path |
| GU-02 | Owner-local orchestration and a stable presentation model | GU-01 | Derive the next action and exact references without manual copying; reject changed terms and ambiguous identity; preserve interrupted work |
| GU-03 | Entry point inside an existing Claude session | GU-01, GU-02 | Detect project and session, connect or resume through the guided flow, keep the original conversation, and surface actual attachment state |
| GU-04 | Invite a teammate through guided reviews | GU-02, GU-03 | Two people complete owner approval, admission and requester consent; agent access is explicitly reviewed; refused access remains refused |
| GU-05 | Connect another of my computers | GU-02, GU-03 | Approve the exact new machine, retain separate device keys, explain its powers, and complete without copying the original key |
| GU-06 | Progress, recovery and connection feedback | GU-04, GU-05 | Resume after interruption; explain waiting, declined, expired, unavailable and ambiguous cases; verify incoming delivery and peer reachability |
| GU-07 | Installation and a short first-use guide | GU-03, GU-06 | Supported installation has one documented path; normal setup requires no copied UUIDs, scope arithmetic or signer selection; advanced recovery is separate |
| GU-08 | Independent conformance, installed acceptance and live-session validation | Contract cases from GU-01; implementation from GU-02 through GU-07 | Record the exact tested feature head, artifacts, results and limitations; complete the merge gates below |

Independent conformance authoring can run alongside implementation once GU-01
settles the relevant cases. The author works from the contract, not the code,
as required by [AGENTS.md](../AGENTS.md). Keep suites small; run the applicable
existing slim suites as each area changes.

## Verification and final merge gates

- [ ] Every slice is implemented and reviewed, with its PR linked in the tracking
  PR. No unchecked placeholder is treated as completed functionality.
- [ ] Rust formatting, tests and clippy pass, along with existing integration
  tests and the relevant slim conformance suites.
- [ ] A separate author derives conformance from GU-01. Cases cover both normal
  flows; absent and declined permissions; changed review terms; ambiguous
  identity; interruption and retry; expiry; and transport unavailability.
- [ ] Installed artifacts exercise both flows on two machines without a required
  Peerspan service or an original-key copy. The teammate case uses two distinct
  people. Record whether the machines are separate systems or isolated test
  fixtures and test the supported connectivity path explicitly.
- [ ] A real existing Claude session keeps its conversation and completes a
  cross-machine exchange. Record model-observed receipt separately from adapter
  readiness and notification acknowledgment.
- [ ] Fresh setup and resumed setup show observed progress and actionable
  failures. Authorization denial and access withdrawal remain enforced.
- [ ] User guides match the tested commands and supported platforms. State any
  remaining platform or harness limitations.
- [ ] Installed upgrade/recovery acceptance covers current main's schema23
  state through schema27, with preserved identity/authority/history. Record a
  private full-state backup and recovery procedure. An older schema23 binary
  refuses upgraded state: binary-only rollback is unsupported; never rewrite
  user_version or drop flow tables to simulate a downgrade.
- [ ] Review and acceptance use one final feature head and corresponding
  artifacts. Later changes invalidate the affected results until rerun.
- [ ] The tracking PR is ready for review and its final review is accepted before
  merging the complete feature into `main`.

## Decisions and discarded options

### GU-OWN1: experience

Chosen by the owner: the four-step experience under **Accepted experience**.
Rationale: reduce the number of concepts and manual protocol steps needed to
connect a project, a teammate or another computer from an existing agent.
Alternative options were not recorded in the owner's confirmation.

Implementation direction: compose the existing protocol behind participant
reviews. Discarded for this feature: replacing the authority protocol to obtain
fewer visible steps; asking users to pass raw IDs between low-level commands;
using network admission as blanket agent access; and treating prepared
attachment as actual readiness. These are implementation recommendations, not
additional options attributed to the owner.

### GU-OWN2: delivery and merging

Chosen by the owner: a fresh separate branch and tracking PR, small pieces of
work, and one eventual feature PR merged into main after testing.
Rationale: make progress reviewable while the complete flow remains isolated.
Alternative options were not recorded in the owner's instruction.

Implementation choice: small PRs target the feature branch; one draft tracking
PR targets main (the owner has since marked it ready for review). Discarded: landing partial onboarding behavior directly on
main, working in another track's checkout, and an orphan history disconnected
from the intended main-branch merge base.

## References

- [Current quick start](quick-start.md)
- [Guided setup](guided-setup-proposal.md)
- [Coordinator-free specification](decentralized-spec.md)
- [Coordinator-free runtime contract](decentralized-runtime-contract.md)
- [Harness integration](harness-integration-contract.md)
- [Live delivery](live-delivery-contract.md)
- [Delta's Claude plugin flow](https://delta.dev/docs/cli/claude-code)
- [Claude channel startup and opt-in](https://code.claude.com/docs/en/channels)

Administrator consent backend (section21) adds private-stdin lookup, prepare and
approve commands for one exact retained incoming new-original request. The
review pins the current owned network root and ordinary person/host drafts.
Approval authorizes background administrator signing/publication, not requester
finalization/commit or agent access. Native administrator controls follow later.

Incoming proof progress (section22) adds one explicit private-stdin action to
fetch missing original-owner/requester-selection evidence for an already returned
request. It does not prepare or approve administrator work. Native controls
will call this action explicitly before sections20/21's inspection and consent;
ordinary broad link resume is not used as a guided observation.

Native incoming review (section23) composes those backends through explicit
request selection, bounded proof fetch, exact administrator preparation and
approval, with pure Check recovery. Original finalization, requester commit,
device linking and agent-access/readiness reviews remain separate work.

Original finalization inspection (section24) provides a pure
view of the exact original consent and independently verified administrator
root/person/host parents. It does not fetch, materialize drafts, sign or commit.
Bounded original finalization, requester commit and native controls follow.

Independent section24 verification passes all six real-host cases on frozen
production `f34b100`, including same-request advanced original finalization and
separate requester commit. Exact provenance, source/binary hashes and limits:
[verification record](results/guided-owner-finalization-inspection-verification.json).

Original-finalization signing (section25) reuses the existing approved requester
worker for proof progress. One exact explicit CLI decision bounds original B/D/F
signing under the captured section24 digest, using the existing local original
key or exact SSH-agent identity. It permits at most two ordered batches and
three original signatures; requester final commit stays separate. Native
controls follow in another slice.

Independent section25 verification passes all six real-host/fault cases on
frozen production `40d3f7b`; corrected existing inspection and owner-signing
regression suites also pass6/6 each with every original assertion, delay and
timeout retained. The new suite took131s locally and49s in CI. The
[verification record](results/guided-owner-finalization-signing-verification.json)
retains the initial failures, independently authored fixture corrections,
source/binary hashes and cancellation/attribution limits. PR62 records final
combined-head CI and fresh review after that record commit. This is backend
signing evidence; installed, physical-machine and actual-model gates remain open.

Native finalization (section26) adds explicit public review and one bounded
signing control over the existing sections24/25. Fresh exact original/admin
terms, parent/host/flow/native and time checks guard dispatch and display;
lookup-first recovery reports global retained F without signing or attribution.
Leave clears local controls without retracting dispatched work. Requester final
commit remains a separate decision.

Independent native292/292 pass locally in41.51s with all original272 unchanged;
existing real-host inspection6/6 in81s and corrected signing6/6 in145s also pass.
The corrected signing suite passed CI in104s; its local duration remains above
the two-minute target. The [verification record](results/guided-native-finalization-verification.json)
retains initial failures, independent fixture corrections, source/binary hashes
and mock/source/manual limits. PR64 records final combined-head gates after
that evidence commit. Access/readiness, device flow and full acceptance stay open.

Requester-commit consent (section27) prepares or recovers one exact ordinary
final-consent intent and approves it atomically under the captured review.
Lookup and retained preparation/approved replay stay pure. The approved ordinary
worker may sign/publish before the response; local application uses separate
explicit completion. Bounded completion and native controls follow.

Independent requester_commit passes 6/6 on its first local run in 123s and in 92s
in combined-head CI. Existing signing 6/6 in 146s, join 12/12 in 99s, native 292/292
in 42.55s and all required Rust gates pass unchanged. The local new suite is 3s
over the two-minute target; its unchanged CI run meets it. The
[verification record](results/guided-requester-commit-consent-verification.json)
retains exact source/binary/test/log provenance, SQL rollback and worker/source
limits. PR66 records final-head gates after that record commit. Agent access,
observed readiness, device flow and full acceptance remain open.

First final-head CI passed 22 suites, PR checks and fresh review but failed existing
delivery 11/5 on inviter application timeout. One retained unchanged local delivery
run passed 16/16 in 67s; the CI cause remains unclassified. GU.impl27f adds only
independently authored bounded public diagnostics after the original wait fails,
with every assertion/action/delay/timeout preserved. The verification record
keeps both results and source limits; PR66 records subsequent exact-head gates.


Requester completion (section 28) explicitly completes an already approved
requester commit through bounded ordinary signing/publication/local application.
It returns verified local application without implying peer delivery or agent
readiness, and recovers an applied operation purely. Native commit controls
follow separately so both changes stay independently reviewable.

Independent corrected completion6/6 passes in152s on frozen production `baf62ba`, including
genuine post-review-window completion, late application SQL rollback, an actual
application-barrier parent detach and pure API/CLI expiry/detach/restart history.
Existing consent6/6in132s, delivery16/16in70s, native292/292in41.44s and all Rust
gates pass. The local completion/consent durations exceed the two-minute target.
The [verification record](results/guided-requester-completion-verification.json)
retains all earlier new-suite CI failures, the prior unclassified terminal
quiescence failure and old inspection contact-state change, initial native
timeout/load evidence, independent provenance and exact limits. Diagnostic CI
then identified an actual proof retry eight seconds ahead of a five-second
fixture wait. GU.impl28g makes recorded retry eligibility current with one bounded
shared debug-clock step before the unchanged strict retirement/purity checks.
The first corrected full run passes; external compilation overlap and its local
duration remain recorded. The earlier missing-category failure stays unclassified. PR69 records
fresh final-head all24 CI and review after the evidence commit. Native controls,
access/readiness, device flow and installed/physical/model/upgrade acceptance
remain open.

Native requester controls (section29) expose separate requester Review, Approve and
Complete actions over sections27/28, with pure lookup-first recovery. Original
and administrator approvals remain separate. Local application is not delivery,
agent access or connection readiness. Contract GU.impl29 and independent
clarification precede implementation. Independent native312/312 passes locally
in50.48s, including20 new cases and all original292 unchanged. Required Rust
gates pass155/2ignored/fmt/Clippy/shipped bins; existing consent6/6in137s,
completion6/6in135s and one retained inspection diagnosis6/6in82s pass serially.
The [verification record](results/guided-native-requester-commit-verification.json)
preserves the first native308/4 CI result, contract-first independent fixture
corrections, initial P2 fix/regression, old unclassified contact-purity failure,
failure-only observer provenance and exact source/binary/log/resource limits.
Local consent/completion durations exceed the two-minute target. PR73 records
fresh final-head all24 suites/PR checks/review after that record commit.
Installed/physical/model/access-readiness/device/full-feature gates stay open.


### Current project-bound access terms

Section 30 / GU.impl30 adds a pure access inspection for the attached project,
selected network and exact person. It returns verified current membership and
the signed policy separately from ordinary enforced content, without opening a
signer or treating membership as agent access. Exact grant consent/signing,
native controls, observed readiness and other-computer flow remain later work.
The API/private CLI are implemented. Independent access6/6in97s passes on
frozen Rust `e928c4b`, with real two-person membership/policy, exact signed JSON,
missing signer, expiry/revocation and aggregate DB/files plus both original TCP
and additional UDP purity/restart checks. Rust155/2ignored/fmt/Clippy/shipped
bins and native312/312in58.25s pass locally. Old completion6/6in157s passes after
independent genuine delivery/contact retirement and startup-directory setup;
its local duration exceeds the two-minute target, with original waits intact.
The [verification record](results/guided-access-inspection-verification.json)
retains every initial compile/test failure, the fixed review P2, diagnostic
metadata, independent provenance and exact limits. Earlier missing categories
and the specific origin of historical UDP traffic remain unclassified; a
passing correction does not retrospectively establish those causes. PR75 records
final exact-head all25 CI/PR checks and fresh review after the evidence commit.
Exact agent-grant consent/signing is next, followed by native access controls
and observed readiness. Other-computer and installed/physical/actual-model/
schema23→27/full-state upgrade/recovery/final combined acceptance remain open.
Full feature acceptance remains incomplete; tracking PR35 stays unmerged.


### Exact project agent-access consent

Section31 / GU.impl31 freezes the complete existing ordinary policy action and
its exact project/person/provider context before separate explicit approval.
The first profile enables messages/tasks with zero artifacts and ordinary
owner-wide agent-name scope shown explicitly. A nonsigning typed local receipt
reuses dec_intents; no new SQL/schema or signature/publication during consent.
The API/private CLI are implemented. Frozen Rust `3fa769c` passes155 existing
tests/2ignored, formatting, Clippy and shipped-binary build. Independent consent
passes6/6in92s on its first diagnostic run; existing inspection6/6in99s,
policy9/9in40s, unchanged join12/12in98s and native312/312in49.96s plus strict
validation pass serially. Candidate `751ceb8` passes all26 host suites and PR
checks; PR77 records fresh exact-head gates after this evidence commit.

The [verification record](results/guided-access-consent-verification.json)
preserves the parser/clock fixes, initial review P2 and independent regression,
explicit external-signing fixture correction, all first failures and source/
binary/log hashes. The runner's excessive Unix socket path was corrected with
a shorter TMPDIR, preserving every old test. The original combined consent
purity category, earlier QUIC failure and join boundary failure remain
unclassified; later passes do not identify their causes. Diagnostic wrappers
preserve the original complete comparisons, capture order and short-circuiting.
Complex authority/quota/overflow and installed/physical/actual-model/full-state
upgrade/recovery limits remain explicit. Bounded policy signing/publication,
native access controls, observed readiness and other-computer flow follow.
Tracking PR35 stays unmerged; full-feature acceptance remains incomplete.

### Bounded exact policy signature storage

Merged77 (`2a36210`) supplies exact agent-access consent. Section32 / GU.impl32
adds one explicit bounded signer operation and pure signature observation on
that immutable ordinary action; its human receipt remains nonsigning. Device
and exact original daemon signer paths keep current authority checks around IO.
Signature/clock persistence is atomic and does not apply/publish a policy.
Frozen production `fc8cdf4` passes Rust155/2ignored, fmt, Clippy and shipped-bin
build. Independent signing6/6in109.17s, unchanged consent6/6in90.70s and pinned
native312/312in50.27s plus strict validation pass serially. The
[verification record](results/guided-access-signing-verification.json) preserves
the first1/6 run, independently corrected impossible timestamp regex, exact
source/binary/log provenance, preservation audits and remaining source/manual
limits. Original26 host suite assertions/actions/delays/timeouts stay exact;
subsequent independently contracted diagnostics correct the existing unbound
contact row predicate and add bounded daemon-only timing metadata. Removing
those additions restores both old sources by bytes/AST; shared helpers/harness
and native files stay unchanged. First candidate325df66 passes PR checks and
clean review, while old completion/finalization purity failures remain
unclassified. PR79 records final diagnostic-head all27 CI gates and fresh review
separately. Bounded publication/
local application, native access controls, observed readiness and the remaining
full acceptance gates stay separate; PR35 stays unmerged.

### Exact signed policy local application

Merged79 (`830c1ee`) supplies the exact stored issuer signature. Section33 /
GU.impl33 adds explicit owner-local `onboarding access application|apply --stdin`
and private HTTP routes for its ordinary local policy publication. First apply
requires the exact approvals, signed payload and current project/provider/
inspection/authority/edit/time pins in the same final transaction. Ordinary
proof/admission/projection, settled edit, bounded delivery queue, action result,
clock and one event commit atomically. There is no new signing, consent, schema,
journal or direct guided peer request. Pure recovery verifies the retained
ordinary signed result and actual local proof/admission after expiry/detach/
replacement/restart without recreating missing evidence.

An application marker records that local operation; it does not assert that
the historical policy is current. Peer delivery and connection readiness stay
`not_verified`. Native access controls, observed two-way exchange, other-computer
flow and installed/physical/actual-model/schema23-to27/full-state/final combined
acceptance remain separate. The [verification record](results/guided-access-application-verification.json)
records exact source/binary/log provenance and required gates. All original27
host suite assertions/actions/delays/timeouts and shared helpers/native remain; PR79's earlier UDP/
contact purity failures remain unclassified. Tracking PR35 stays unmerged.

Initial production `a8ccff3` passed Rust and local application6/6in109.01s,
plus unchanged signing6/6in112.67s, consent6/6in92.95s and policy9/9in38.46s.
The initial evidence head passed all28 CI suites and PR checks, then fresh bot
review identified missing required admission-reference validation on pure replay.
Contract GU.impl33c and an independent negative regression preceded fix
`4842404`: require the exact signed statement, root and all direct-parent IDs.
The regression reproduces the bug on the original binaries (4/6; the history
case returns200, then a dependent case finds the stopped host). Frozen fixed
source passes Rust155/2ignored, fmt, Clippy, shipped binaries and the same
independent application6/6in106.30s, including both pure refusal routes and exact
restoration. PR80 records final exact-head all28 CI and fresh review separately.

The record retains every first failure, contract-first independent fixture
correction and byte-preservation audit. Those setup corrections did not change
production; the later review fix changes the admission-reference check. Every
full-feature acceptance gate remains incomplete.

First fixed-head78df456 CI passes application6/6in78s and26 other host suites,
all PR checks (native312/312in65.78s) and clean review. Existing section25 F
history fails5/6in102s with only dec_contacts changed. One independent
failure-only bounded contact observer preserves the original entire source
when removed by bytes/AST; the other60 old slim/helper/native files are exact.
One local diagnostic run passes6/6in147.75s without triggering. This exceeds
the120s target and leaves the CI row/caller unclassified; no product/setup
correction or global fence is inferred. Final diagnostic-head gates and review
are recorded separately on PR80/35, with this failure and duration retained.

The nextb937f96 CI identifies the actual changed row as a local bound signed
contact renewed after the old request window, with unchanged transport payload.
An independent genuine unused short invitation/current-own-hint/ordinary cleanup
prerequisite now precedes every original strict history capture and retry.
The initial added empty-QUIC expectation fails5/6in138.67s; an independent exact
actual-listener correction retains all other checks and passes6/6in135.98s.
Both durations exceed120s. No worker, counter, authority, original operation or
runtime behavior changes; old PR79 callers remain unclassified.

That CI separately fails delivery11/16in98s at inviter application after60s,
with four dependent failures. One independent failure-only bounded retained-state/
existing timing observer preserves all16 original cases and entire prior source
on normalization. Its first local run passes16/16in69.56s without triggering;
the original relay cause remains unclassified. A later fixed-category display
prefix correction changes only diagnostic parsing. Original59 other old files
remain byte-exact; both modified old suites restore by bytes/AST when their
contracted additions are removed. The record retains first failures, normalized
preservation and exact test/binary/log provenance. Final combined-head CI and
fresh review are recorded on PR80/35; all full-feature acceptance stays open.

Combinedcfbe31d CI passes27/28 including application6/6in61s, owner history6/6in88s
and delivery16/16in60s, all PR checks (native312/312in59.43s) and clean review.
Existing section31 input_refusal fails5/6in62s with both dec_clock/dec_contacts
changed; actual caller remains unclassified. An independently contracted real
restart of both normal hosts, explicit sync/current authority/member/whole-window
contact lifetimes, successful original directory and transport retirement now
precedes the standalone input case. Its entire case finishes before the normal
first60s periodic-sync boundary, with no clock/timer/worker/path/counter changes.
The first frozen484 local run passes6/6in96.02s. All original cases/actions/checks/
waits remain; removing additions from the three modified old suites restores
their entire original bytes/AST, with58 other old files byte-identical. Earlier
PR79/directory/relay callers and full-feature acceptance remain open. Final new
combined-head CI and review are recorded on PR80/35 after the evidence commit.

### Native access inspection and exact approval

Merged80 (`5dbc4a0`) supplies exact signed-policy application. Section34 /
GU.impl34 adds native explicit network/person selection, complete read-only
inspection and separate lookup-first proposed-grant review/approval. It preserves
public keys as identity and distinguishes machine aliases from person labels.
The exact message/task grant discloses the ordinary owner-agent-name scope.
No native signing/application, provider fallback, automatic replacement, model
action or readiness claim is added; these remain later slices. Contract-first
independent native tests and final combined-head gates are recorded with the PR.
All312 old native tests/all28 host suites and frozen Rust remain unchanged.

The [native access verification record](results/guided-native-access-verification.json)
retains the independent20-case source/corrections and every first runtime result.
Initial new-file registration failed while old312 passed; corrected registration
ran325/332, with six publication-wording expectations and one missing historical
parent prerequisite. Clarified UI verbs and an independent parent-order fix
precede the next run. That run records317/332 with15 default5s timeouts, including
nine unchanged cases, while an external Rust status-fix build overlaps. This is
observed overlap, not established causal attribution; no local retry or larger
timeout follows. Final exact-head CI uses a separate runner and stays required.
Initial draft CI separately retains two unchanged host history/purity failures;
their callers remain unclassified. Final receipts are recorded on PR82/35 after
the evidence commit. No full-feature readiness/acceptance gate is inferred.

Combined03c05f4 CI passes all28 host suites and four PR checks, including
native332/332in77.88s, then fresh review identifies P2: valid inherited matching
actions may have reversed order. GU.impl34a precedes a set-comparison-only fix
and independent21st regression. Raw inherited policy order, default fields,
unrelated terms and digests stay intact; original20 case bodies remain exact.
After observing the known external compiler completed, fixed-source full native
333/333 passes in61.13s on its first run. Earlier timeouts remain unclassified;
this pass does not establish their cause. Final corrected-head CI/review are
recorded on PR82/35, with all full-feature acceptance gates still incomplete.

### Native completion of approved access

After merged82 (`a0ea55d`), section35/GU.impl35 composes existing exact signing
and application through one explicit Finish agent access. It observes retained
state first, skips already recorded work, rechecks fresh immutable/current pins
before each dispatch and stops on unknown outcomes. Check application remains
read-only, retaining proof/state comparison guards through uncertainty. Local
application is historical evidence and never a claim of current permission,
peer delivery, actual model receipt or connection readiness. All333 existing
native cases/all28 host suites and Rust remain unchanged; independent new native
cases and final exact-head CI/review follow. Full-feature acceptance stays open.

The separate author committed16 completion cases before execution. Strict native
validation passes. First local full run347/349 in63.71s retains two new default5s
timeouts, with all333 existing cases passing and no semantic mismatch reported.
No known Cargo/rustc activity overlapped either observation; sampled host load
does not establish a cause. Tests/deadlines remain unchanged, with no unchanged
local retry. The [verification record](results/guided-native-access-completion-verification.json)
preserves hashes/provenance/outcomes/limits; required final all28 CI/four checks
and exact-head fresh bot/root review are recorded on the slice/tracking PR.

### Current project readiness evidence

Section36/GU.impl36 starts after merged85 (`8b20ab5`). One owner-local read binds
the exact attached project/session, explicitly selected network/person, current
verified membership/policy, ordinary receiver-advertised authorization entries
and exact-session adapter connections. A live/verified channel is separate from
peer reachability and this native model's receipt. No native control or network
probe is added in this backend slice; observed/full-feature readiness stays open.
Independent real-host verification and final exact-head CI/review follow.

Readiness conformance passes6/6 in44s on frozen372dfe5 after independent public
fixture corrections; first2/6 setup result stays recorded. Exact state/home/DB
and both TCP/UDP purity, current origin/grant/policy/withdrawal parity, exact
session/unsafe aggregate/refusal/route checks pass. Existing access inspection
6/6 in101s and all Rust local gates pass. Strict native validation passes; first
unchanged native348/349 retains one default5s timeout with unclassified cause,
without changed assertions/deadlines or unchanged local retry. The [verification
record](results/guided-project-readiness-verification.json) records every source,
binary/test/log hash and first outcome. Required final all29/four PR checks and
fresh bot/root review are recorded on the slice/tracking PR after the evidence
commit. Native presentation and actual peer/model readiness remain open.

### Native current connection status

Section37/GU.impl37 follows merged86 (`3e759c9`). An explicit Check connection
status reads the exact current project/network/person observation and displays
separate receiver-advertised entries and exact-session adapter states. Details
retain complete public membership, signed/enforced policy and connection terms.
The earliest membership/policy/grant/lease or 30-second bound clears the view;
errors clear old evidence and require an explicit new Check. Review agent access
returns to ordinary inspection. No implicit status reads, permission evaluation,
peer/model probe or authorized-runtime changes are introduced. Independent new
native cases and final exact-head CI/review follow; actual peer/model and
full-feature acceptance remain open.

The [native status verification record](results/guided-native-readiness-verification.json)
retains first361/365 and corrected363/365 local outcomes. All16 new cases pass
after one public-details encoding correction and independent per-session-start
tool-registration bookkeeping correction; all16 case bodies remain unchanged.
Both runs retain two unchanged old default5s timeouts, whose cause remains
unclassified. No known compiler overlaps were observed, no timeouts were raised,
and no unchanged local retry follows. All57 prior native-test/conformance files
are byte-identical. Strict pinned303 validation passes; final exact-head all29 CI,
four PR checks and fresh bot/root review follow on the slice/tracking PR.

### Explicit selected-machine peer reachability

Section38/GU.impl38 follows merged87 (`c112cdd`). One owner-local check captures
the current project/network/person and exact remote machine key, uses the
existing pinned peer directory GET over current routes, and rechecks complete
inspection/project pins after IO. It does not learn contacts, refresh the
directory or store observations. Only response status is projected, never the
remote body or diagnostics. Authenticated outbound response is separate from
incoming agent delivery, model receipt and overall readiness. Native controls
and complete connection acceptance follow separately.

First local Rust format/test155+2ignored/Clippy/all shipped binaries pass on
frozen1e78059. The unchanged readiness suite passes6/6 in45.60s. Independent
new peer-reachability conformance and final exact-head all30/four CI checks/fresh
review follow. The entire native plugin remains unchanged from merged87; its
strict validation/CI365 and retained local timeout history are reused locally.

Independent peer reachability now passes6/6 in53.07s on exactly those frozen
binaries. All six ordered case ASTs/assertions/actions/delays/timeouts are exact
since the pre-execution error-alternative clarification; all78 prior plugin/
conformance files are byte-identical. Public counted proof drain, authenticated
newer empty-contact withdrawal, actual reference expiry and bootstrap-only
restart establish genuine no-route purity. A measured live target proxy blocked
in upstream receive explains the latest recovery diagnostic; independently
making only this new selector helper nonblocking restores the full check. No
production transport fix is claimed. Earlier uninstrumented outcomes remain
unclassified. The [verification record](results/guided-peer-reachability-verification.json)
retains every local first outcome, source/binary/log hash and initial draft CI:
all four PR jobs pass (native365/365), while new reachability and unchanged owner
finalization fail. The latter immutable-history cause remains unclassified.
Corrected-source final all30/four CI and fresh exact-head bot/root review follow
on PR89/35. No unchanged local rerun or old assertion/deadline edit is used.

### Native selected-machine outbound connection check

Section39/GU.impl39 follows merged89 (`9ca61f5`). A verified connection-status
snapshot supplies a ten-per-page remote machine picker with explicit ID/key
selection; only Check outbound connection sends the private section38 command.
Full current inspection/target/parent validation and separate roster/result
expiry authorities guard before/after IO. The human result reports only outbound
transport status; permissions, incoming delivery, model receipt and overall
readiness stay separate. No Rust/schema/runtime-scope change or new persistence.
Independent16 native cases, unchanged365 old cases/all30 host suites and final
exact-head gates/review follow. Actual terminal/reload/installed/physical/model/
other-computer/schema23-to27/full-state/final combined acceptance stays open.

The [native outbound verification record](results/guided-native-peer-reachability-verification.json)
retains first full379/381 in70.08s: all16 new cases pass, while two unchanged old
access-completion cases hit their existing5s limits. Their cause remains
unclassified; no semantic mismatch is reported and no known compiler is seen
at the before/during/after samples. Strict pinned303 validation passes, and the
unchanged real two-person/two-host peer suite passes6/6 in51.25s on the verified
merged89 binaries. All59 prior test/helper files and Rust treeeac511ee remain
exact. Pre-execution presentation/expiry clarifications, independent committed
source and every source/test/binary/log hash are recorded. No unchanged local
retry or old-test/deadline change follows. Final all30/four checks and fresh
exact-head bot/root review are recorded on the slice/tracking PR after the
evidence commit; all full-feature acceptance limits remain open.

### Request this computer under an existing person

Section40/GU.impl40 follows merged90 (`a0e546b`). Explicit **Connect this
computer** uses a privately entered invitation with an exact existing-person
pin. Identity preview and publication review/approval are separate; the original
key stays on the existing computer. Reuse sections11/12/15 without a new schema,
API or key inventory. Lookup-first recovery, exact-code reentry and fixed expiry
guard the volatile lane. Publication and pure progress never establish machine
powers, membership, access, transport or model receipt. Existing-computer guided
approval is still subsequent work. Independent12 native cases, unchanged381
old cases/all30 host suites, local relevant gates and final exact-head review
follow. Full-feature acceptance remains open.

The [machine-request verification record](results/guided-native-machine-request-verification.json)
retains first full390/393 in72.71s: eleven new cases pass, one requires clearer
pinned-invitation guidance, and the same two unchanged old access-completion
cases hit their5s limits with unclassified cause. After that guidance fix,
all12 affected cases pass in6.18s in a byte-exact plugin artifact (the pinned
CLI has no filename filter). Unchanged real-host join_onboarding passes14/14
in50.53s on verified merged89 binaries. All60 prior native/conformance/helper
files and Rust treeeac511ee are exact; no unchanged old-case local retry or
deadline edit. Strict303 validation passes on the preceding source; final CI
validates the exact final head/full393 plus all30 host suites and Rust gates.
Fresh bot/root review receipts go on the slice/tracking PR after this evidence
commit. Earlier and full-feature acceptance limits remain open.

First exact-head8183a22 CI passes all four PR checks (native393/393in75.27s,
all Rust gates), while28/30 host suites pass. Existing owner-finalization and
requester-completion purity failures remain unclassified. Contract-first
GU.impl40a adds independently authored failure-only metadata, preserving every
original assertion/action/deadline/counter; removal restores both source bytes
and AST. Their retained local diagnostic runs pass6/6in79.45s and6/6in137.39s
respectively, without triggering either observer; the latter exceeds the suite
duration target. No cause or runtime fix is established. Frontend/Rust and
all381 old native cases remain exact; combined-head full CI/review follows.

Combined78668d1 CI passes four PR checks (native393in93.86s) and29/30 host
suites, including both previous diagnostic suites. Existing access-signing
cases5/6 instead fail an unobserved startup-query prerequisite. GU.impl40b adds
only a captured-response failure observer; its first actual local run passes
6/6in109.99s without triggering it. Compiler preflight initially prevented test
execution; that was not a suite failure or rerun. Original CI cause stays
unclassified. Removing these additions restores original bytes/AST, with no
setup/assertion/deadline/counter changes. Other57 old test/helper files,
all381 old native cases and frontend/Rust remain exact. Final full CI/review
receipts follow on the slice/tracking PR; full-feature acceptance remains open.

### Existing computer: current machine-owner review backend

Section41/GU.impl41 follows merged91 (`a034e78`). The owner-local inspection
checks an actual incoming same-person request, current attached project, selected
public original/device authority and P/H/B/D dependencies. It returns exact
requester keys and finite proposed powers7 without key access, approval, signing
or publication. Later slices supply durable consent, bounded signing and native
controls, then requester selection/completion. The complete other-computer flow
and final feature acceptance remain open.

The [machine-owner verification record](results/guided-machine-owner-inspection-verification.json)
retains the first CI0/6, observed missing-device member correction and corrected
local6/6in36.19s. Fresh Rust gates pass; all74 prior conformance/native files and
native393 stay exact. First CI already passes all30 existing host suites/four
checks; final combined-head31-suite matrix/four checks/fresh review follow. The
record preserves earlier resource/orchestration outcomes, source-only coverage
limits and all hashes. It verifies the review backend, not completed machine
admission, native approval, installed/model delivery or full-feature acceptance.


### Existing computer: exact machine-owner consent backend

Section42/GU.impl42 follows merged93 (`737c43b`). The private owner API and
`onboarding machine lookup|prepare|approve --stdin` bind the current project to
the exact inspected request, selected original/device provider, finite powers7,
proposed owner offer and original signing deadline. Preparation reuses ordinary
owner protocol records and adds an unsigned local attribution receipt in schema27.
Approval sets both exact approvals/time atomically. Ordinary background signing
and publication may proceed after approval; requester selection and final commit
still require their own consent. This backend does not complete the native flow.

History retains the original inspection and stage deadline through cancellation,
expiry, project detachment and later protocol progress. Approval through an
advanced interface alone invalidates a pending project receipt. Explicit review
replacement by a current project preserves the ordinary intent's templates,
creation time and powers deadline. Chosen under GU-OWN1; discarded alternatives
and independent verification are recorded in the section42 contract and decision
log. Bounded signer continuation, native controls, requester completion and full
installed/model/combined acceptance remain open.


The [machine-owner consent verification record](results/guided-machine-owner-consent-verification.json)
retains the first failures, independent diagnostic restoration audits and product
corrections. The corrected backend passes local6/6in49.26s, unchanged inspection
6/6in35.26s and Rust gates; all84 old conformance/native files remain exact.
Owner-guard CI passes all32 host suites+build/four checks/native393 and fresh
bot/root review. Final evidence-only-head receipts follow on PR94. Earlier
standalone history-table and requester-completion UDP causes remain unclassified;
a passing sample does not erase them. Full guided/native/installed/model/combined
acceptance stays open.

### Existing computer: bounded initial machine-owner signing backend

Section43/GU.impl43 follows merged94 (`405f879`). Owner-local signing status and
explicit stdin-only Sign bind the exact dual-approved section42 receipt and
recorded project. Only the initial typed owner host/authority and reviewed fold
issuer are eligible, using the selected owned device or exact configured original
file/agent. Fresh checks run before each key dispatch and again before atomic
storage; original consent, stage, request and powers deadlines never restart.
Completed-signature replay is pure history, not proof of publication, admission,
current powers, access or readiness. Native controls remain a later slice.

The [signing verification record](results/guided-machine-owner-signing-verification.json)
retains first compile/runtime/CI failures, independent fixture corrections and
the bot's pre-commit wall-time fix. The corrected new suite passes6/6in68s,
including actual GUIDED device15 signatures, catalog/proof publication and
requester retention after ordinary release. No selection/commit is supplied by
Sign; ordinary single-offer selection follows unchanged spec8.4. Native393 and
84 prior files remain exact; section43b permits only one removable independent
failure observer in requester_completion, restoring its original bytes/AST.
The unchanged consent
suite first passes6/6in38s; its later final-binary sample5/6in49s has an
unclassified TCP-only crossing under externally approved worker activity, with
DB/files unchanged. No old-case edit or unchanged local retry hides it. Final
exact-head full33-suite+build/four checks/native393 and fresh review receipts go
on PR96. First combined CI passes all other32 host suites+build/four checks,
but requester_completion5/6in86s captures issuer UDP during a wrong-review pure
refusal, with requester DB/files unchanged. Its one diagnostic local run passes
6/6in143s without triggering the observer; preserve the over-target duration and
original unclassified cause. No runtime transport fix or weaker assertion is
claimed. Full guided/installed/model/combined acceptance remains open.


### Existing computer: native machine-owner controls

Section44/GU.impl44 follows merged96 (`be198c5`). **Review machine requests**
uses the existing attached project and retained incoming inventory. The native
pane validates the closed host evidence, shows the actual target and selected
public authority, and separates exact review preparation, approval and explicit
initial signing. Pure **Check machine consent** recovers recorded receipt/status
without mutation retry. Fixed windows, project attribution and view-only history
remain authoritative; no key copying or signed-as-ready presentation.

This composes sections41–43 without changing Rust/API/schema/protocol behavior.
Independent native fixtures, root runtime validation, combined-head CI and fresh
review are required before owner review. Requester completion, real terminal/
reload, installed/two-machine/model and full #35 acceptance remain open.

The [native machine-owner verification record](results/guided-native-machine-owner-verification.json)
retains first local413/415, corrected new22/22 with three old runtime failures,
and first CI startup/history failures. Existing393 cases and all64 old test/
conformance files remain unchanged, without timeout overrides or local retries.
The first bot's foreign-project review case is fixed and independently covered.
Final exact-head combined CI and fresh review receipts are attached to PR97;
passing later samples do not classify prior failures.


### New computer: verified machine requester review

Section45/GU.impl45 follows merged97 (`2a503e9`). The private inspection binds
the published machine request to this attached project, then verifies retained
remote owner/selection/admission/finalization and actual P/H/B/D references.
It returns finite7 machine powers and binding scope2 without a local original
key/owner receipt, signer probe, commit intent, approval or adoption. Folded
admission correctly has no separate administrator packet or stage.

This is the read-only backend prerequisite for requester consent/completion and
its native controls. Independent real-host fixtures cover retained authority
after the existing computer goes offline, without claiming both-live worker
attribution. Final combined-head CI/review and full #35 terminal/installed/
two-machine/model acceptance remain required; inspection is not readiness.

The [requester inspection verification record](results/guided-machine-requester-inspection-verification.json)
records first6/6in70s on fresh binaries, Rust gates, source/log/binary hashes and
all65 prior test/native file preservation. It distinguishes actual remote
device/original folded-F and strict measured purity from the explicitly offline
existing computer, source-only complex authority/corruption boundaries, and
unexecuted native/full-feature acceptance. Final exact-head CI/review receipts
are retained on PR98 without an evidence-only CI commit loop.

### New computer: exact requester consent

Section46/GU.impl46 follows merged98 (`19ae9bb`). Prepare freezes the verified
remote machine terms in an unsigned project receipt; Approve records only the
exact retained consent alongside ordinary requester approval. Lookup and exact
replay preserve history without keys, clock saves or transport. Completion and
native controls remain separate. Contract-first independent conformance and
final combined-head CI/review are required before owner review.

The [requester consent verification record](results/guided-machine-requester-consent-verification.json)
retains the first vector-calendar/Clippy/runtime setup failures, independent
corrections, source/test/log/binary hashes and preservation audit. Corrected
real-host6/6in117s and required Rust gates pass; strict history covers expired,
detached and restarted reads, while external approval has only state evidence.
All66 old conformance/native files and native415 remain exact. Final-head CI and
fresh bot/root review receipts follow on the PR without another evidence-only
commit. Bounded completion and native controls remain separate.

The [clock-recovery follow-up](results/guided-machine-requester-consent-clock-verification.json)
records the bot's P2 fix in both flow binding and receipt recovery, genuine
>300s rollback history/refusal regression, fresh31c7e5fa gates and6/6in127s.
The local two-minute target overrun and first CI finalization/TCP-only failures
remain explicit; the passing diagnostic run does not classify those failures.
Fresh authorization still enforces its guarded clock. Final combined-head CI/
review receipts are on PR99; no full-feature readiness claim is made.

The [finalization setup follow-up](results/guided-machine-requester-consent-finalization-verification.json)
records second CI35/36 plus all4 checks, then the independent new46-only
verified two-host signed-F prerequisite. All66 prior files/native415 remain
byte-exact; first measured inspection and all six case bodies stay intact.
Root6/6in126s passes with the two-minute target overrun retained. The rejected
old45 mutation remains unintegrated. Fresh final-head CI/bot/root receipts are
on PR99; completion and full-feature acceptance remain open.

### New computer: bounded requester completion

Section47/GU.impl47 follows merged99 (`a025f28`). One explicit private action
continues only the exact approved machine receipt through ordinary bounded
signing, pinned publication and atomic local application. Verified completed
replay is historical and pure, including detach, expiry and clock rollback.
No original key on the new computer, new consent/schema or readiness claim.
Independent conformance and final-head CI/review are required. Native controls
and full35 terminal/reload/installed/physical/model acceptance stay open.

The [machine completion verification record](results/guided-machine-requester-completion-verification.json)
retains first compile/host fixture failures and independent corrections.
Corrected5/6in95s verifies actual application, lost-response lookup recovery,
SQL rollback and exact expiry/parent guards; historical setup remains pending
a bounded normal-peer diagnostic. All67 prior files/native415 remain exact.
Final exact-head CI and fresh review receipts will follow on the slice PR.

The [phase-specific verification follow-up](results/guided-machine-requester-completion-phase-verification.json)
retains every local and first CI outcome, closed probe diagnostics and independent
inverse audit. All6 cases now pass locally in116s (runner119.54) on unchanged
Rust0047: genuine finite machine application, SQL rollback, lost response recovery,
strict private corpus, actual time/parent refusal and completed history through
expiry/detach/restart/>300s rollback. Supported terminal endpoint replacement
retains all old/new counted UDP paths; unapplied privacy precedes activation.
Earlier contact/UDP/TCP causes remain unclassified. All67 files/native415 stay
exact. Full final-head CI and fresh review receipts follow on PR100; native
controls and full-feature acceptance remain separate.

The [CI diagnostic follow-up](results/guided-machine-requester-completion-ci-verification.json)
retains candidate41c5d66:36/37 conformance jobs pass, all4checks/native415 and
fresh bot pass; unchanged old45 original-finalization setup fails before its
subject inspection. New47passes6/6in93s and old28passes6/6in103s. A separate
independent failure-only launcher preserves the entire old suite; its first
local diagnostic run passes6/6in70s without observer output. The earlier cause
remains unclassified. All67 files/new47/fullnative415 and Rust0047 stay exact;
no product fix or unchanged retry is claimed. Fresh full CI/review is required
on the final pushed candidate; receipt belongs on PR100.

The [finite diagnostic follow-up](results/guided-machine-requester-completion-english-verification.json)
retains d13b3a9:36/37, all4checks/native415/bot pass; old45 repeats original
finalization setup failure with exit1/no JSON/no known public code. New finite
English/field observation uses the same captured stderr and changes no verdict,
call, timeout or state. Its first local6/6in70s emits no failure diagnostic, so
the prior cause remains unknown. All67/new47/native415/Rust0047 remain exact.
Fresh final complete CI/review is required; native/full-feature gates stay open.

The [encrypted diagnostic follow-up](results/guided-machine-requester-completion-encrypted-verification.json)
retains c0e8d12:35/37 with old45unknown CLI error and old24after-expiry contact
refresh, plus all4checks/native415/Rust155+2ignored/clean bot. Independent
bounded failure-only ciphertext capture changes no original test verdict or
product code; root fake/privacy/inverse and real synthetic encryption checks
pass. First changed local6/6in70s produces no failure artifact, leaving earlier
causes unknown. Old67/new47/native415/Rust0047 exact; fresh fullCI/review stays
required, with actual failure diagnosis before any product fix.

The [proof-refusal follow-up](results/guided-machine-requester-completion-proof-verification.json)
records actual2b05ea9 daemon proof_required and the narrow ordinary finalize
CLI incomplete/error context, preserving the underlying refusal/nonzero exit
and adding no IO or success claim. Missing proof/phase and earlier failures
remain unclassified. Temporary capture/publicPEM/upload are removed exactly.
Fresh Rust918d gates pass; old45six/sixin70s and new47six/sixin118s pass with
runner120.55s retained separately. All67/new47/native415 exact; final fullCI
and fresh review receipts follow on PR100. Native/full-feature gates stay open.


### New computer: native requester controls

Section48/GU.impl48 follows merged100 (`1457be6`). The terminal pane composes
verified remote machine review, exact requester consent and bounded completion
with separate explicit controls and pure uncertain-outcome recovery. The
original remains on the existing computer. Local application does not establish
current powers, access, delivery or readiness. No backend/API/schema change.
Contract-only independent native fixtures and root execution precede final-head
CI and fresh bot/root review. Full terminal/reload/installed/physical/model/
schema23→27/full-state/final #35 acceptance remains open.

The [native machine requester verification record](results/guided-native-machine-requester-verification.json)
retains the restricted runner's22 file-load/no-case-report failures, first
435/439 run, independent fixture corrections and changed-source437/440 run
(new25/25 pass). Three unchanged old native cases still fail locally: two
original5s timeouts and one zero connection dispatch; causes remain unclassified.
All69 old test/helper files and Rust918d remain exact. No unchanged local retry
or timeout override is selected. Final exact-head full CI and fresh bot/root
review must pass before this slice is ready; receipts will be on its PR.

The [CI diagnostic follow-up](results/guided-native-machine-requester-ci-verification.json)
retains firstbf76635:36/37 host jobs, all4 PR checks/native440/440in71.85s and
clean bot/root review. Old28 expired/API/wrong-review purity crosses issuer UDP
by2datagrams/2400bytes; caller/cause remain unclassified. One independent
receive-only launcher preserves all70 current test/helper files and native/Rust
trees exactly, adding only bounded failure metadata with no extra IO. Root fake
forwarding/privacy/restoration checks and fresh identical binary hashes pass.
Its first affected local run passes6/6in146s, exceeding the120s target; it emits
no failure metadata and diagnoses no earlier crossing. Final fullCI and fresh
review receipts follow on PR101; full-feature acceptance stays open.

The same [CI verification record](results/guided-native-machine-requester-ci-verification.json)
retains second449c800:35/37 and all4checks/native440. Separate independent
phase prerequisites keep all71 prior files exact: completed actual outbox
attempts before the single original retry alignment, and a genuine current
signed contact/expired temporary-ref cleanup before old owner-history snapshots.
Their first committed-source local runs pass6/6in142s (runner143.62; above120s)
and6/6in82s (runner82.4), with unchanged original5s/whole-state/carrier checks.
No Rust/native product change or earlier-caller diagnosis is claimed. Final
combined-head CI and fresh review receipts follow on PR101.
