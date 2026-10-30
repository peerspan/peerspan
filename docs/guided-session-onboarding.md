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
