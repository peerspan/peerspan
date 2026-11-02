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

Run the unchanged full native suite, all slim suites from both branches, Rust
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
