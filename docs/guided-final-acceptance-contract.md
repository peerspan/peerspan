# Final acceptance of guided onboarding (#35)

Status: final acceptance contract, 2026-11-02. Freeze feature additions. The
remaining work combines current main and the guided integration branch, fixes
observed blockers, and produces one reviewed candidate and its acceptance
receipt. The owner merges #35. Individual slice receipts are not a substitute
for the combined candidate. Keep failed attempts and their source/artifact/log
hashes; rerun only after a diagnosed correction or a documented external change.

## 1. Integrating both database histories

Main's conversations migration and this feature independently occupied schema
24. The combined schema is **28**, containing conversations and all four guided
flow tables. Support genuine main schema24, the prior common schema23, and
feature schemas24–27. A main24 database has conversations and no guided project
flow table; a feature24 database has the project table and no conversations.
Later feature versions add adapter25, invitation26 and join27. Detect these
actual histories before applying missing migrations, inside one transaction.
Never treat an arbitrary missing required table as a valid history. Validate
all guided schemas and retain existing DEC validation. Schema28 must contain
both histories; it must not accept a malformed schema28 by silently recreating
required tables. Preserve identity, signed authority, policies and history.
Older binaries refuse schema28 without mutating it. Never rewrite user_version
or drop tables to manufacture upgrade/downgrade acceptance fixtures.

Independent verification uses real old binaries to create populated schema23
and current-main schema24 states, plus a real feature27 binary for the third
history. Create a network/person, agent/session and retained history through
public commands/APIs. Feature27 also retains a pending project review with its
original expiry. Stop fixture daemons; privately back up the entire state and
XDG person-key configuration, with file modes and hashes, before upgrading.
Open each with the final installed binary, check version28 and the union of
required tables, public identity/network/agent/history continuity, and a fresh
project review; feature27's pending review must retain its ID/expiry. Stop it;
the corresponding old binary must refuse the upgraded state without database
mutation. Restore the complete preupgrade state/key/config backup into an empty
private fixture location, open it with its old binary, and verify exact original
identity/authority/history. Binary-only rollback is unsupported. The suite may
read SQLite to observe schema/history, not insert/delete/update product rows.
Bound each process/API operation and the complete upgrade suite to 120 seconds,
excluding compilation. Do not copy a person's original key between hosts.

Existing cases remain in place. Where schema assertions conflict solely because
the histories were combined, an independent contract-only author may change
only the expected current version27/24 to28, next unsupported version28/25 to29,
and add conversation tables to the required set. Preserve all other assertions,
case bodies, deadlines and failure handling. Existing Python and Rust synthetic old-schema
fixtures must drop both sets of newer tables before their old-version setup;
this maintains the original migration assertions, and is not real upgrade proof.

## 2. Actual installed terminal lifecycle

Use a verified real archive, relocated prefix with spaces, and its public local
marketplace installation into a fresh private CLAUDE_CONFIG_DIR. Pin actual
installed executable and private host state through public plugin configuration.
Do not use product --plugin-dir, process/API stubs, native SDK mocks, internal
callbacks or private Claude cache/transcript formats to establish this gate.
Use Claude Code2.1.303's real terminal and documented commands. Public initial
trust/key/style prompts may be answered in the isolated fixture only. HOME is
unchanged; isolate person keys with XDG_CONFIG_HOME and explicit host state.
UI-only cases use a dummy API key and a local recording inference endpoint,
asserting no model request. This is not live model receipt.

Open /peerspan in a real conversation with a known --session-id, connect the
current project, enter an agent name and owner, and prepare its exact review.
Record the public project lookup's native session ID, review ID and expiry.
Close the pane, /reload-plugins --force, reopen /peerspan and Connect this
project: the same context/review/expiry returns without duplicated preparation.
Approve through the actual human terminal button, and verify exactly one agent,
one session and recorded attachment. For one isolated case, an executable
wrapper may run the real exact project decision once and then lose its reply;
it must not fake a host result or repeat the mutation. Reopen/Refresh/Lookup
must recover that committed attachment with exactly one decision invocation.
Restart the real daemon: pending review resumes unchanged; an already attached
metadata flow becomes invalidated and cannot auto-reattach. A replacement needs
a fresh explicit review. Failed/declined review grants no attachment. Bound
individual host operations to their existing deadlines, native UI observations
30 seconds and the terminal suite to 10 minutes. No existing timeout increases.
An independently authored public terminal driver may use a pinned terminal
emulator to locate focused button labels and send real keyboard input; it must
not invoke native internals. Private fixture transcripts stay private. Publish
only fixed outcomes/counts/versions and source/artifact/log hashes.

## 3. Installed participant flows and enforced permission

Use the same final installed host artifact on two isolated host fixtures, direct
loopback TCP/UDP connectivity, optional helpers disabled, no coordinator, and
separate private state and person-key configuration. Explicitly record fixtures
versus physical machines. This is the supported direct connectivity path, not
a claim about arbitrary NAT or relay availability.

Exercise the entire public guided teammate flow with two genuinely distinct
people: pinned invitation, private recipient review and approval, automatic
request return, exact original-owner consent/signing, explicit requester consent authorizing exact pinned offer
selection (automatic for a single approved offer), administrator consent/admission, original finalization and requester
commit/completion. Do not create authority by database writes, fake signatures,
advanced protocol driving or copying another person's key. Attach projects;
observe incoming request/evidence checkpoints with bounded reads. A second
invitation on the same first-contact endpoint must retain its distinct request
and destination, and an unavailable/rate-limited endpoint must present the
specified private manual fallback without claiming connectivity.

Membership alone must leave the distinct person's agent message access denied.
Grant access through the guided inspection/consent/signing/application path;
verify actual receiver enforcement permits a message, then withdraw access with
an explicit owner decision and verify a fresh message is denied. Keep absent,
declined, changed terms, ambiguity, interruption, expiry and unavailability
coverage from existing independent suites; no green claim from the happy path
alone. Exercise the guided same-person second-computer path with finite device
powers7 and binding2, no original-person key copy, automatic return and owner
finalization, one requester completion and lost-reply lookup recovery. Verify
separate device identity and actual retained signed/applied authority. Report
adapter connection, incoming acknowledgment, peer observation and model receipt
as distinct evidence. Each installed live-flow suite is bounded to120 seconds;
compilation, installation and actual model acceptance are separate gates.

## 4. Existing conversation and real model receipt

Use an actual authenticated Claude model turn, with a preexisting native
conversation identity retained across attachment/reload. An isolated UI fixture
or scripted provider is not this gate. Send a unique message from the second
real host through the supported Peerspan agent path; the model must use the
actual incoming adapter/tool result and return that nonce. Record host sender,
receiver session, message ID and observed reply privately; publish booleans and
hashes, never credentials or message bodies. Do not read/copy authentication
secrets or change the user's existing plugin configuration. A usage limit or
unsupported live entry path is a named blocker, not a successful model receipt.
Bound the live attempt to5minutes. Document supported startup versus runtime
reload restrictions, without claiming a replacement conversation preserved an
existing one.

## 5. One final head and review

Run the unchanged full native suite, all slim suites from both branches plus
the targeted retained-admission and completion-rate-limit suites, Rust
format/test/Clippy, packaging and real installed acceptance on one final source
candidate. Rebuild affected artifacts after any product change. Record exact
source head, main baseline, archive checksums, independent suite hashes, gate
results and first failures in one repository receipt. No public release workflow
is needed. Request Codex review on the acceptance PR and final #35 head, address
blocking findings, and update #35's existing checklist only where evidence
supports it. Mark merge-ready only when all required gates pass. Preserve the
owner's final merge decision.

Selected: combine main before final acceptance, schema28 for the union, genuine
old-binary fixtures, actual terminal controls, installed distinct-person/device
flows and a separate live model receipt. Discarded: more feature slices, testing
only the stale integration head, overwriting either schema24 migration,
rewriting schema versions as rollback proof, replacing existing suites, mocked
native effects as UI proof, repeating a mutation to recover a lost response,
and presenting loopback fixtures as physical machines.

### Execution notes

The independent installed checks are `conformance/installed_terminal.py`,
`conformance/installed_participants.py` with its independent support module,
and `conformance/installed_upgrade.py`. Their `--help` lists inputs; fixtures
remain private and publish fixed results and hashes. The terminal dependency
pins are in `conformance/requirements-terminal.txt`. The final installed CI job
runs all three checks against its freshly compiled archive; it separately builds
genuine old binaries from the immutable23/main24/feature27 commits. Clear the
local `peerspan-host` Cargo package between old worktrees when sharing a target
directory; cache reuse by source mtimes must not substitute one old binary for
another. The suite independently checks the actual old schema before upgrading.
Actual authenticated model receipt remains a separate manual gate.

### First participant blocker

The first installed distinct-person run reached administrator consent but no
administrator offer appeared within the unchanged15s checkpoint. Retained
ordinary administrator intent was approved and unsigned. The worker scheduled
only requester and approved-owner records; a separate administrator-only record
was excluded. Approved administrator work must also enter the bounded existing
worker pipeline through the ordinary exact signer checks. This adds no consent
or signing authority. The unchanged installed teammate case is its regression
check; the first failed receipt remains retained.

### Combined regression follow-up

A concurrent CLI/worker signing pass for the same exact administrator intent
may observe a verified append-only signature extension. Re-read that same
intent and its current guards; do not overwrite it or repeat human consent.
A changed intent or changed prior signature remains a conflict. Policy denial
must consider a cited owner's policy only in networks shared with the actual
sender; a lower policy in an unrelated network cannot turn withdrawal's denial
into a transient policy-unavailable response. The installed two-invitation
teammate case and unchanged `work`/`join_onboarding` suites cover these findings.

For the two first combined CI read-purity failures (`machine_owner` and
`requester_completion`), a separate contract-only author may add a diagnostic
launcher. It observes only existing before/after snapshots/counters/failure
objects; no new calls, reads, waits, mutations, clock changes or retries. Report
only fixed phase, changed public table names, schema/file/carrier change booleans
and counts, never row values, keys, native refs, paths or packet content. Keep
every original case, snapshot, action, assertion, deadline and verdict exact.
Retain the first run, source and diagnostic hashes. Diagnose the source of the
change before any implementation or fixture correction; a failed combined gate
is not permission to relax global purity.

### CI acceptance receipt retention (review107 P2)

Always publish a sanitized acceptance receipt artifact even if a gate fails.
A small operational collector takes explicit terminal/upgrade/participant fixture
roots, archive directory and output directory. Preserve only closed public
phase/category/check metadata, bounded counts/timings, pass/fail/history flags,
and SHA256 source/archive/private-log hashes. Terminal prompt transition traces
contain only fixed prompt/phase/key enums and timing/selection metadata and may
be retained after strict field/value validation. A failed check's fixed literal
may be reported only from a closed allowlist; otherwise retain its digest.
Do not copy raw native screens, provider errors, transcripts, API/CLI bodies,
state, keys, configuration or credentials. Never recurse arbitrary state to
publish hashes of key files. Private raw evidence remains in owned local runs;
CI retains the sufficient sanitized diagnostic record and discards private
fixtures at teardown. No additional service or secret-export destination is
introduced. Missing/invalid/partial evidence is explicitly labelled; successful
collection does not turn an unsuccessful acceptance gate green.

### Real-model tool output boundary

The first authenticated installed-plugin turn invoked `adapter_ready`, and the
host/native pane recorded readiness, but Claude rejected the returned object as
an invalid `tool.call` result. Successful native tools must return their bounded
public result as JSON **text** in `result`, following Claude's supported string
or content-block wire shape. The parsed fields and all authorization, origin,
context, expiry and exact-once guards remain unchanged. Denial responses retain
their existing shape. Apply the same boundary to the local delivery check,
message readiness/seen/reply and task lifecycle tools. No additional authority,
model retry or owner setup tool is introduced.

Independent native verification must first assert that each successful tool
result is text and parses to an object, then retain every existing semantic
assertion against that decoded object. Preserve all denial/late/stale/origin
cases and their deadlines. Test-kit dispatch alone previously accepted the
unsupported object shape; it is not live-model wire validation. Repeat the
bounded authenticated incoming nonce/reply check only after correcting this
observed fault and rebuilding the installed artifact. Retain the failed
source/archive/terminal evidence, and do not present the pane's readiness as a
successful model receipt.

Reference: [Claude mods API, Add a tool](https://code.claude.com/docs/en/plugins/mods/api#add-a-tool).

### Bounded publication observation

The final combined CI's owner-signing case2 stopped at0.6s with the fixed
"publication witness unavailable" category. Its last successful snapshot had one
saved request frame, one own endpoint and no acknowledgment yet. That does not
identify the following exception's cause. Retain this first failure. The
independent prerequisite observer may retry only SQLite BUSY/LOCKED read
contention inside its existing5s observation deadline and0.1s interval, and add
closed error-class/count diagnostics. Missing/malformed/advanced authority and
all semantic predicates still fail. Preserve the frozen case bodies, assertions
and deadlines. Do not claim lock contention caused this failure without evidence
or treat a repeat run alone as its resolution.


### Observed reload boundary

The authenticated Claude2.1.303 run retained the original native conversation
through `/reload-plugins --force`. An unchanged mod runtime kept its still-valid
approved adapter lease; this was continuation, not an automatic reconnect after
a runtime restart. The operator explicitly stopped and reconnected that same
authorization, enabled incoming messages with a fresh model nonce, then retrieved
the model's exact peer reply on the originating host. Document this distinction
and the explicit Stop/reconnect procedure. Actual mod runtime restart retains
its existing clear-and-no-autoconnect contract. Discarded: claiming the component
reload command necessarily unloads an unchanged mod, or counting its saved
channel as a fresh model acknowledgment. The live model check loads the exact
installed plugin directory on resuming an existing conversation; separate actual
marketplace-installation terminal acceptance proves the normal installed route.

### Retained administrator prefix and carrier rate limits

Final documentation-head CI exposed `link admit --approve` failing with a peer
rate limit after its preview had already retained the exact owner offer and
requester selection. Repeated admission preview/approval must not require
another carrier poll when both requested packet IDs and their packet bytes are
already retained on that exact ordinary request. This is evidence availability,
not authority: ordinary administrator preparation still verifies every packet,
signature, current root/provider/person/host/device, deadline and exact consent.
An absent or different requested prefix still requires bounded polling or fails;
never substitute a different cached offer/selection, suppress arbitrary carrier
errors, replay an approval or loosen rate limits. This matches the retained
prefix treatment already used for original finalization.

Independent verification must retain the exact O/S prefix, make its carrier
unavailable/rate-limited, and exercise administrator preview without another carrier request, then explicit
approval while carriers are unavailable, retaining exact signed-result checks.
Approved ordinary T publication remains permitted and is not classified as a
redundant evidence fetch.
Wrong IDs/missing bytes must not gain this shortcut. Preserve all existing
owner, signing and participant cases/deadlines; a final clean full-head run is
still required after the correction. The first failed CI log remains retained.

### Owned host signing and rollback-fixture dispatch

The last CI run also exposed the advanced CLI trying to find an SSH agent while
an approved signing batch was in flight. The CLI must never look for the current
host's private signing key in a person's SSH agent. Validate every typed slot as
before; leave a matching current-host/host-role slot to the existing daemon
worker. Continue any genuinely external signer slots in the same batch. If only
owned host work remains, return its actual pending request without claiming
completion or changing consent. Keep configured external signer selection and
all wrong-key/message/template/origin refusal cases unchanged.

The machine-requester raw-time fixture sets an integer offset, not a frozen
clock. Its old ceil offset to created_at-1 leaves less than one second before
wall time catches up; quiet/snapshot work runs before dispatch. The first CI
failure did not identify which denial phase returned200, so retain that
uncertainty. An independent test-only launcher may preserve the specific raw
creation precondition at dispatch: only that time fixture's approve/unavailable
branch sets the clock sidecars using floor(target-realUTC) for the same intended
created_at-1 target, asserts raw time is still earlier than creation, and calls
the original API once. Sidecars are outside every frozen DB/schema/state/home
snapshot. No product rows/authority, body, timeout, signed deadline, phase,
assertion or mutation retry changes. All other operations keep their original
clocks. Emit closed phase/precondition diagnostics, never raw private values.

### Terminal-history directory observation prerequisite

Final083c6b9 CI's requester-completion history check had no DB/schema/state/home
change and no TCP change, but observed one1200-byte QUIC Initial from the live
requester to the stopped issuer during the expired API phase. Receive-only
diagnostics identify that direction/header, not its owning call. The retained
directory still reported that stopped issuer as `ok`; no truthful stopped-peer
refresh had completed before this phase's purity baseline. Do not attribute the
packet to the historical read or claim its exact cause from those facts alone.

The independent fixture must finish one ordinary bounded directory observation
after terminal cleanup's clock advance and issuer shutdown, before taking its
strict purity baseline. Reuse the same public refresh/error-state prerequisite
already required after requester restart. Require usable current authority and
exact issuer row with truthful error state. Then retain the frozen quiet and
all original whole-state/carrier comparisons, phases, API/CLI operations and
deadlines. No packet filtering, counter reset, row fabrication, daemon restart,
new approval or mutation retry. Preserve prior failed logs and keep the existing
outbox-attempt prerequisite and receive-only diagnostics composed in order.

### Native validation observation overhead

Finaleeb0987 CI passed the corrected requester-history suite in111seconds but
one unchanged native access-completion validation case hit its5000ms test bound
(5022ms,439/440). Preserve that failure; no claim is made that scheduling caused
it. The independent author identified27 redundant public UI queries across its
nine fault variants. The public mounted UI calls settle their handlers before
returning. In only this file's `uncertain` helper, retain the first complete
rendered text after the unchanged no-Finish check and use it for every existing
text/privacy assertion: no action, clock advance, fixture mutation or held delay
occurs between these observations. In `closePane`, press the already captured
Close key, preserving its defined assertion, single press and unmount. Keep all
case bodies, nine variants, assertions, action order and5000ms deadline exact.
Do not change product code, cache across an action or asynchronous transition,
split a case, add an unsupported runner setting, or retry an unchanged failure
until green. Run the complete440-case native suite after this narrow correction
and retain full final-head CI/review as merge gates.

Reference: [Claude mod public mounted test methods](https://code.claude.com/docs/en/plugins/mods/test#test-a-drawing).

### Native file process isolation

The helper-corrected full local run passed439/440 in84.82seconds: the corrected
case passed, while a different unchanged invitation-preview case reached its
5000ms deadline at5003ms. Preserve both failures and leave their exact causes
unclassified. Stop making further helper changes in response to individual
five-second failures. There is no supported concurrency option in the pinned
public CLI. Execute the complete native suite with explicit file process
isolation through its supported plugin-directory argument instead.

An independently authored operational runner must discover all22 candidate
native test files and execute each exactly once, serially, with the pinned
public `claude plugin test` command. Each private temporary plugin mirror has
byte-identical manifest/hooks and all non-test plugin resources at their original
relative paths, plus that one original test file at its original relative path.
Preserve all sibling non-test helpers if present. Verify source/mirror hashes
and refuse symlinks, missing files, unknown discovery or changed sources. Never
rewrite code, cases, assertions, mocked time, test configuration or5000ms case
deadlines. No product implementation inspection is needed to copy/hash it.
Keep HOME unchanged and isolate CLI configuration outside the mirrors. A failed
file runs no second time; continue other files while recording its original
exit/counts. Require all22 files and440 runtime cases, zero failures/skips and
successful public CLI exits. Bound the complete gate to600seconds, record its
actual elapsed time, and stop if exhausted. Sanitize the receipt to source
hashes, original repo-relative file names, counts, fixed outcomes and elapsed
times; do not copy private config or arbitrary files. Full native CI uses this
same runner against the final candidate; validation, installed acceptance,
all conformance, Rust and final review remain required.

Selected: explicit independent file scheduling with byte-identical inputs and
unchanged individual deadlines. Discarded: unsupported SDK environment knobs,
repeating failed files, increasing test deadlines, dropping variants, splitting
frozen cases, or claiming scheduling explains an unattributed failure.

### Atomic private debug barrier publication

Final7fb4853 CI passed native440 and the terminal-history purity check, but the
requester pre-application barrier case got HTTP409 with an unexpected code. Its
old failure message omitted the code; keep that uncertainty and the original
log. No successful late application was reported. Inspection identified an
independent fixture publication hazard: its `marker` helper creates/writes a
visible file, then chmods it0600. A concurrent strict debug-control reader can
observe the initial umask-derived permissions or incomplete bytes. Debug barrier
markers must be private, complete, single-link regular files when first visible.
Do not claim that this hazard caused the earlier response without its code.

A separate contract-only author may add one launcher around only the literal
pre-application barrier case. Replace only its marker publication helper with
same-directory atomic publication: create a fresh private0600 regular temporary
file, write the exact original bytes completely and flush, then rename it over
the original marker path. Preserve its operation/request match and all original arm/release calls, including
the final cleanup release, barrier entry, parent detach, every whole-state/carrier/application
assertion, error-code requirement and deadline. Temporary publication files
must be gone before returning to the case or taking its snapshots. Compose the
existing directory/outbox/receive-only launchers unchanged. No product code,
control protocol, SQL row, clock, retry, case body or verdict changes.

Capture only the original completion response status and a closed public code
category in this exact case, before its unchanged assertion. Allowed codes:
review_changed, review_expired, commit_completion_unavailable, state_conflict,
request_unavailable, not_found, invalid_request, forbidden, internal; all others
are `other`. No body, detail, path, request ID, key or exception text. Diagnostic
failure never replaces the original response or verdict. Retain source hashes
and the first failed CI alongside final full-head checks/review.

### Complete slim runtime audit and debug compilation

Audit every slim suite's reported elapsed time, not just its CI exit. The7fb4853
renewal suite passed all13 semantic cases but took167seconds; that does not meet
the existing120second suite budget. Preserve this timing failure. Its six real
multi-host worlds perform substantial concurrent setup before their existing
75second renewal windows. Keep those worlds, checks, time windows and all45
suite bodies unchanged.

Build conformance executables with the ordinary debug profile and optimization
level1. Retain debug assertions and debug test-clock/control availability; keep
incremental compilation and debug symbols disabled as before. Record the exact
source, compilation environment and executable hashes. This is an execution
configuration change, not a new authority or altered protocol. Native tests and
installed release artifacts retain their existing build modes. Run the unchanged
renewal suite locally against the new executables once, then all45 suites on the
same final CI build. All must pass and report at most120seconds before readiness.
No rerun of unchanged timing failures, larger semantic deadlines, skipped renewal
windows, fabricated authority, release binaries with disabled controls or new
paid runner requirements. Selected: optimized debug executables with all guards
retained; discarded: changing renewal assertions/windows or ignoring elapsed
suite time because the CI exit was successful.

### Exact completion publication under real rate pressure

The guarded optimized CI build exposed18 failed suites, predominantly the shared
standard new-person setup waiting for the original participant after the
requester's `linked` GET had already succeeded. The exact CI executables pass
locally with ordinary/four-CPU/private memory-backed fixtures. Do not attribute
the CI failures to a compiler, scheduler or rate limit from this alone. Retain
those sources/logs. Source review identifies a concrete hypothesis: stage frame
writes and completion POSTs share the specified2/s burst8 mutation bucket; a
failed one-shot completion publication has no automatic retry after local apply.
The original participant cannot infer its application from mere stored frames.

A separate contract-only author must add one small `completion_rate_limit` suite
from this public contract, before implementation changes. Use two real hosts and
a genuine new-person request through owner/selection/administrator/finalization,
with exact requester commitment still unapproved. Keep both original keys on
owning machines. Through the public peer probe's authenticated QUIC completion ALPN
`peerspan-completion/1` on the participant peer address (wire9.5), apply a bounded
real burst of malformed activation POSTs from the requester to the original
participant. This shares the specified completion mutation bucket with TCP. Require400 invalid/429 rate_limited and no successful
application from these invalid requests. A bounded pressure thread may continue
for at most2seconds while one exact genuine requester commit is approved and
applied. Require observed429; stop pressure on its original deadline, with no
rate-limit configuration changes or artificial delay in the product path.

Record the first real commit result, requester `linked` and original-participant
`linked` separately before any diagnostic repair. Capture only closed public
status/state/attention-code categories and booleans, never keys, handoffs, paths,
packet bytes or arbitrary text. For the initial old-build diagnostic, one exact
ordinary requester resume after pressure ends may distinguish retained-publication
repair; record that separately and never let it satisfy the first-attempt gate.
The one diagnostic repair may await the public positive Retry-After interval
(or the specified1second mailbox refill interval when the public probe exposes
only status/body), strictly after the first-attempt facts were captured. That
wait cannot change the first-attempt verdict or satisfy its application gate.
The final behavior requires the original participant to apply by the first
bounded commit call's return under this brief rate pressure, without another
human decision, new signature/intent, changed exact terms or extra commit call.
Verify genuine signed/applied authority and immutable consent/application IDs;
use existing public/state observations, never fabricate authority. Bound the
complete new suite to120seconds. Represent an observed missing automatic retry
as a strict XFAIL until fixed, then remove only that marker after observed XPASS.
Preserve all existing45 suites, cases and deadlines; with this targeted suite
there are46 slim suites and52 full CI checks.

If evidence confirms the missing429 retry, the recommended implementation is a
bounded exact completion-publication retry in the existing30second attempt:
honor a valid positive `Retry-After` only for actualHTTP429/rate_limited, and only
if the wait fits the original deadline. Reuse the original pinned endpoint,
immutable activation/catalog body and original memory budget; verify the
participant's signed response exactly as before. Do not replan, re-sign, renew
consent/deadlines, suppress other errors, increase mailbox limits, add unbounded
background work or change local historical-read purity. Both TCP and encrypted
QUIC paths must preserve this rule and the existing fallback behavior. Choose
this narrow retry before adding a new durable applied-request worker; no code
change is authorized by this hypothesis alone without the independent diagnostic.


### Receive-only publication response diagnostics

A final CI launcher may observe existing commit/resume API responses through the
independent harness without changing any request, return value, exception, case,
assertion, sleep or deadline. Emit at most64 closed status/state/attention-code
records per complete suite; never keys, request IDs, paths, packet bytes or free
text. This supplies evidence if the original CI cause differs from the confirmed
rate-pressure gap. It must make no extra API request, retry, mutation or read of
product implementation. Diagnostic output never changes a verdict.


### Bootstrap owner-route absence under a charged rate bucket

The corrected ecee08c CI run passed all other slim suites within120seconds, but
access inspection's frozen bootstrap-boundary assertion failed without recording
the actual status. The unchanged suite with receive-only HTTPResponse.begin
metadata passes locally on the exact CI binary and records404. Its original CI
cause remains unclassified. Source review identifies another concrete hypothesis:
rate refusal can precede route absence. Do not attribute that first failure or
change product behavior without an independent real public-wire diagnostic.

Extend the independent completion-rate-limit suite with a small separate
bootstrap-boundary experiment. Use a real host with no coordinator/helper and
two distinct valid self-signed client TLS identities on the same loopback source.
Their certificates establish transport identity only, never network authority.
Bound the total existing suite to120seconds. Through TLS1.3/bootstrap ALPN and
real HTTP requests, require a malformed known activation route to return400/invalid
and exhaust its actual mutation bucket to429/rate_limited within a bounded burst.
During that exhausted bucket, send the exact frozen owner access-inspection path
from the second fresh identity. Freeze its actual status/code; a known activation
request must remain429/rate_limited. Emit only closed status/code/Retry-After
categories and booleans. No configured limit changes, sleeps to repair the
observation, private data, synthetic authority or new owner action. Separate all
fixture/control assertions from one strict known marker for the owner route's
required404/not_found; after verified XPASS remove only that marker. Keep every
prior case/assertion/deadline unchanged.

Selected behavior: every request attempt is still charged under the same
key/source rates and active/header bounds. A successfully parsed genuinely
unknown route, including an owner-local path on the bootstrap listener, returns
404 without invoking an owner handler or reading its body. Known bootstrap and
completion routes, malformed headers, routes classified invalid by the existing
router, and invalid capabilities on known routes retain rate refusal precedence. If the independent experiment confirms a gap,
record charging first, classify only the bounded received header/route, return
404 for an existing not_found route classification, then enforce the recorded rate refusal before
all known-route work. Discard exempting unknown attempts from charging, raising
limits, bypassing known-route rate limits or weakening the frozen404 assertion.


### Signed-request expiry and the carrier-resource purity baseline

The fresh tracking35 run of the same5f7cd90 that passed52 acceptance checks
failed machine_owner's final signed-request-expiry purity phase. Receive-only
metadata shows two unclassified tables changed in owner database index0, with
no changed public tables, files, keys or TCP/UDP counters. Keep that first log;
its original cause is not yet attributed. The fixture snapshots every database
and can call two100ms observations stable immediately after a test-clock jump.
This does not itself establish that independent resource expiry has completed.

A separate contract-only author must inspect the public resource lifecycle and
existing fixture, not product code. Resource expiry erases frames and retains a
small tombstone until expires_at+24h; after that window metadata is removed
(bootstrap contract7, wire9). The known resource-table labels mailboxes, frames
and helper_format may be included in the existing closed diagnostic allowlist;
never emit raw rows, schema strings, IDs, keys or timestamps.

For only the literal final signed-request-expiry phase of the unchanged case,
a prerequisite launcher may require completed due resource expiry before the
strict baseline, inside the original quiet wait's3second deadline. Capture the
unchanged advance_to argument; inspect only the existing predicate's already
held current whole-state snapshot. Identify fields using the public observation
schema in section43 and validate the held schema/row shape; never use product
implementation or private offsets. Require
no due active resource with retained ciphertext and no metadata already beyond
the documented tombstone window. Record only fixed counts/booleans showing any
pending lifecycle completed before the owner inspection starts. No new API,
DB/file/socket observation, mutation, retry, sleep, deadline extension or clock
change. Invoke the original quiet predicate and wait_for with their same args;
keep every original case/helper body, whole-state/carrier assertion and counter.
If the prerequisite cannot settle within its original deadline, retain failure.
Do not ignore any difference after baseline or treat later repair as purity.

Selected: establish the actual pre-call resource lifecycle before attributing a
write to owner inspection. Discard excluding the carrier DB/tables, resetting
counters, adding sleeps, extending settling windows, deleting resource rows or
blindly rerunning the unchanged failure. Product purity must remain intact; a
read-only callgraph audit and observed pre-call transitions distinguish worker
maintenance from an inspection-triggered effect without claiming an unseen
first call site. The final whole-suite limit remains120seconds.

### Requester commit's existing public-prefix observations

Corrected tracking f0b356b passes51/52: all Rust/native/installed gates and45/46
slim suites pass, maximum88seconds. The machine-owner correction passes6/6 in31.
The remaining requester_commit history case's ordinary explicit commit returns
409/state_conflict. Retain its first log; its cause is not yet attributed. The
already-approved requester may independently progress through owned work.

A contract-only author may add a receive-only launcher scoped to that literal
case. Forward every original Host.api call exactly once with unchanged arguments,
response and exceptions. Observe only its existing GET link view and subsequent
POST commit input/response, plus already-held exact shared approved consent.
Emit closed public state/stage/attention/error categories, booleans for public
O/S/T/F, commit/manifest/activation/outcome presence and approval flags, and fixed
pin-equality booleans between the original GET, original commit input and held
approved review. Never emit raw IDs, keys, timestamps, labels, paths, rows,
packets, signatures, tokens or messages. Unknown categories map to other; output
must not replace original errors, verdicts or deadlines. No additional calls,
IO, snapshots, mutation, signing, retry, wait, clock change or fixture assertions.
Every original helper/case and strict history comparison remains unchanged.

Selected: capture the exact already-observed public prefix at this failure before
choosing a correction. Discard treating409 as success, retrying an unexplained
commit, relaxing pins/consent/history, adding production diagnostics for private
state or claiming a concurrency cause from the status alone. If a concrete
same-approved-prefix replay gap is confirmed, preserve exact immutable consent,
all guard/refusal boundaries and transaction serialization while correcting it;
independent deterministic coverage must derive from these same public contracts.

#### Exact replay after durable requester framing

The receive-only local run passes6/6 in81seconds, with its precommit public GET
still needs_commit and no persisted commit/activation. All immutable pins match
held consent; this does not explain the CI conflict. A separate source audit
identifies a definite stable replay gap after real commit framing: preparation
can interpret the retained complete activation as a new candidate and reject its
already-existing authority. The original CI phase remains unattributed.

Selected behavior: an already approved, complete, durably framed exact requester
commit may recover its retained review and progress without constructing another
intent, preparing/signing a new operation, writing a decision clock or replacing
its catalog. Validate the exact retained request/intent/packet and every supplied
network/context/person/host/device/O/S/T/F pin under the existing transaction.
Preserve ordinary preview wildcard rules only where already allowed; an actual
approval requires exact pins. Conflicting pins remain refusal with no mutation.
Subsequent ordinary publication/application still runs all current authority,
expiry, revision, identity and exact-operation guards. This grants no new consent
or readiness and makes no verifier exception for self-referential generations.
Discard broad generation exceptions, treating every state_conflict as successful,
retrying approval, returning a fabricated linked state, or skipping apply guards.

Independent verification: append two narrowly related cases to the new completion
publication suite, preserving all four existing case/helper bodies/assertions and
its120second whole deadline. Use two real distinct-person hosts and a genuine
ordinary approved requester operation. Arm the documented private debug barrier
`dec.frame.after_commit` only for that operation after its real finalization;
observe actual barrier entry and public persisted commit/manifest/activation,
while proving no local application. Hold that real caller outside its completed
transaction. Dispatch exactly one further ordinary `/commit` using the original
reviewed pins. Freeze its actual response before releasing the hold. Require all
original pins, intent/consent and signed commit bytes/IDs unchanged; genuine
application may retire old frames and store its outcome. Assert altered-pin
refusal and no replacement consent/signatures. Do not attribute concurrent
publication/application writes to the preparation or refusal from timing alone. Release in finally and require
both hosts actually apply the same canonical operation with original keys still
owned. No artificial authority, protocol/row edits, private-original copying,
relaxed guards, sleeps instead of phase evidence or extra retry. Controls/proofs
must pass separately from one strict expected-failure gate for replay200 on the
old binary. Observe strict XPASS on the correction before removing that marker.
The first failure and original CI attribution limit remain retained.

The first corrected-binary run passes the four frozen cases and altered-pin
control, then times out waiting for replay while its frame barrier remains
armed; this first fixture failure is retained. That named point covers every
matching newly received/sealed frame, including later completion traffic. After
observing the initial exact entry, disarm it before the two further requests;
the already-entered caller must still be held waiting for continue. Assert that
caller remains held before capturing the unapplied prefix and after freezing
replay. Release only its existing continue marker in finally. This limits the
control to the intended initial durable frame and avoids blocking replay's later
legitimate frames. No deadline, original case or replay200 assertion changes;
rerun the corrected fixture against both old and fixed binaries, retaining all
first failures. Do not treat the timeout as either a verified product regression
or an old replay success.

### Machine completion's moving raw-creation precondition

The bbdc596 tracking run's only failed suite is machine_requester_completion:
its original-provider refusal case returns200 where409 was required, then its
dependent parent case fails. The same message covers two pure_clock_refusal
calls, so the original raw-before-created versus signed-expiry phase is unknown.
Retain its first log. Read-only source audit finds no ordinary-replay branch on
this route and repeated raw creation/signed expiry checks through final apply;
verified applied history alone may return historical200 without fresh checks.

The fixture's raw clock is real UTC plus an integer offset. Its unchanged ceil
advance to created_at-1s can lose that precondition during existing resource
retirement and quiet. A contract-only prerequisite may wrap only this literal
case and its original pure_clock_refusal, labelling both phases. Forward every
original stimulus unchanged. After the original quiet returns, before its whole
state/traffic baseline, sample the raw fixture-clock relation and reapply ONLY
the same captured raw-before-created target with floor rounding to both external
clock sidecars. Verify they are outside both hosts' measured state/home roots.
Assert actual raw remains before the approved consent review creation targeted
by this original stimulus, and record both request/consent boundary booleans;
the earlier request need not be in the future. Emit only closed lost/rearmed/
boundary booleans. At original complete dispatch verify that same
precondition still holds; if lost, fail fixture setup without a second rearm,
retry, wait or deadline extension. Signed-expiry clocks remain untouched.

Observe the original API call exactly once and report closed phase/status/code/
public-state categories. UTC samples are fixture precondition observations only;
never emit times, IDs, paths, offsets, rows, keys, packets or messages. Preserve
all frozen case/helper bodies, baseline/strict state/counter assertions, original
restore/finally, time/parent barriers and the existing history prerequisite chain.
Selected: maintain the actual negative stimulus before blaming the subject.
Discard accepting200 as refusal, changing signed windows, skipping guards/cases,
relaxing purity, changing product clocks or claiming the ambiguous CI cause.
No production/packaging change; all current artifact gates stay attached to d819.
