# Guided onboarding contract

Status: feature-branch contract for [tracking PR #35](https://github.com/peerspan/peerspan/pull/35).
The accepted experience and integration policy are in the
[feature plan](guided-session-onboarding.md). Sections 1 and 2 specify the
observation and native Claude entry slices. Section3 specifies the owner-local
project review backend and atomic metadata attachment. Native attachment
controls, authority reviews and automatic protocol continuation remain
subsequent slices.

## Normal experience (full feature target)

The agent's `/peerspan` entry point offers inviting someone or connecting
another computer. It guides project setup when needed. Reviews and progress
appear within that flow. Direct commands remain shortcuts and recovery tools;
the normal user does not have to run separate connect, review and status
commands in order.

Connecting the project attaches its current agent. It does not publish its
conversation, files or tools. Network admission and owner access remain
separate. An invitation is a private contact handoff and grants no authority.

The flow carries exact protocol references for each participant. It never
copies an original key or turns peer content into a local owner's decision.
Ambiguous identity and changed terms require a new explicit choice. Incoming
delivery must be observed independently of configuration or a lease.

## 1. Observation slice (GU-01a / GU-02a)

The first slice provides the common read model for a local frontend. It does
not create a flow or perform any setup, signature, approval or network action.

### Owner-local API

```http
GET /v1/onboarding
```

Serve this endpoint only on the private owner administration socket. Do not
add it to the authenticated peer router, bootstrap listener or scoped adapter
API. No request body, query parameters or credentials are required beyond
access to the private socket. It returns HTTP 200 and a JSON object with
exactly these fields:

| Field | Meaning |
| --- | --- |
| `version` | Integer `1`, the observation format version |
| `observed_at` | The UTC RFC3339 coordinator-free decision time used by this read |
| `host_id` | This daemon's public host ID |
| `networks` | The network views from `GET /v2/status`, with its current-authority, selected-provider and legacy-history semantics |
| `agents` | Local agents and their sessions, as specified below |
| `requests` | All locally retained public `LINK_VIEW` records, as in `GET /v2/link/requests`; never include a display code |
| `attention` | The ordered daemon attention items from `GET /v2/status` |

Collections are arrays, including empty arrays. Network ordering is by network
ID; agents by name then ID; sessions by ID; requests by request ID; attention
uses the existing status order. No arbitrary candidate is selected by this
read. It lists both sides' retained requests, including terminal states, for
the frontend to distinguish work to resume from completed history.

Read all database-backed fields from one SQLite read transaction. Use one
coordinator-free decision time for network authority and request stage expiry.
Use existing adapter lease/credential checks for connection observations; those
checks still apply at the actual read time. The endpoint itself writes no
rows, advances no guard, performs no cleanup or resume, and starts no peer
connection. Background daemon work is independent of this read.

Errors use the existing owner-local API conventions. Failed or unavailable
observations are errors; they are not replaced with an empty successful result.

### Agent and session observations

Each agent is `{id, name, sessions}`. Use the same agent/session inclusion and
ordering rules as status. Each session is exactly:

```json
{
  "id": "session_...",
  "integration": "claude-code",
  "adapter_id": "adapter_...",
  "connection": null,
  "expires_at": "...",
  "renewable": true
}
```

`adapter_id` and `expires_at` may be null, and `renewable` is false when the
session has no credential record. Match status's credential selection: the
most recent unrevoked, unexpired credential, or the most recent historical
credential when none is live. `renewable` describes that record; it does not
establish that renewal is currently authorized. When an adapter exists,
`connection` is its full public
connection record from the existing adapter connection contract:
`{adapter_id, session_id, state, recoverable, lease_expires_at, last_seen_at,
channel, channel_verified_at, protocol_version}`. Without an adapter it is null.
This replaces the status summary's connection-state string only in this new
endpoint; existing status responses do not change.

In particular, `connection.state = ready` means a live adapter connection.
Its `channel` independently says `verified` or `unverified`; it is null when
the adapter has no live connection. Neither observation proves that the model
completed a peer request or that another machine is reachable. An attached
session with no adapter is not a connected agent.

The endpoint contains public local metadata only. It never returns invitation
tokens, pairing codes, adapter tokens/instances, private signing keys, signing
templates, private packets or an executable approval. Public IDs and keys remain
metadata, not an authority grant. Frontends must keep these internal references
out of their routine human-facing presentation.

### CLI

```sh
peerspan [--state DIR] onboarding
```

This advanced command prints the API's JSON object and exits zero after a
successful read, even when setup is incomplete. It uses the selected host's
`admin.sock`. It does not start a daemon, install a service, create state,
register an agent or attach a conversation. A missing/unavailable daemon exits
nonzero. It has no `--approve` flag. The reduced root help remains unchanged;
`help advanced` and `onboarding --help` document the command.

The four-step interactive frontend is not available merely because this
diagnostic command succeeds.

### Verification

A separate author derives black-box cases from this section, using the slim
harness and temporary real hosts. Keep the suite under two minutes.

1. An empty host returns the exact top-level shape, format version, valid time,
   matching host ID and empty collections. CLI and API expose the same shape.
2. A created coordinator-free network appears with usable authority and its
   existing name/identity, matching status. Reads do not create another network.
3. A pending introduction appears on its requesting host and on the inviter
   after the normal return path completes. Compare the public request records
   with the existing request API; reject secret/display-code fields.
4. A registered agent and an attached metadata-only session appear without
   claiming a connected or verified adapter. With a live adapter, preserve the
   distinction between a live lease and verified delivery using the existing
   connection API and fixture protocol.
5. Repeated reads leave durable state, consent and authority unchanged. In a
   bounded quiescent fixture, compare stored logical records before and after;
   control or separately account for background work. Do not mutate protocol
   records to manufacture authority.
6. Multiple networks and pending requests remain distinct and deterministically
   ordered. No default network, identity or offer is adopted by reading.
7. Wrong-method mutation requests are refused. The route is unavailable through
   peer/bootstrap and credential-scoped adapter interfaces.
8. A stopped/missing daemon makes the CLI fail without creating state or
   changing its files.

## 2. Native Claude entry and delivery check (GU-01b / GU-03a)

### Supported route

Use Claude Code's native mod API for the existing-conversation frontend. The
plugin is `integrations/claude-onboarding`, named `peerspan`. This slice targets
Claude Code 2.1.303 or later in the terminal. Other surfaces remain unvalidated.
An installed plugin loads through `/reload-plugins`; a local development plugin
uses `--plugin-dir`. Loading it neither starts another conversation nor opts
the existing session into channel mode.

The official mod API provides commands, native controls and background prompt
submission into the current conversation. Channel startup flags are not needed
for this route. Disabled mods, organization policy, unavailable APIs or refused
prompt submission remain blockers. Neither registration nor successful queuing
establishes model receipt.

### Read-only entry

`/peerspan` opens the native pane `peerspan`, titled **Peerspan**, with the
current project's host observation and controls **Refresh**, **Check this
conversation** and **Close**. While a check is waiting, its control is replaced
by waiting text; stale/double presses still queue no second check. It registers
no invitation, access,
approval or setup tools for the model. It creates no network, agent, attachment
or credential. Loading the plugin alone neither reads the host nor submits a
prompt. Refresh and explicit entry read the observation; there is no recurring
poll or model timer merely because the plugin is installed.

Trusted plugin options are `executable` (default `peerspan`) and `state`
(default empty, retaining normal CLI state discovery). Read the host by running
the literal argument array `[executable, ...stateFlags, 'onboarding']`, with
`stateFlags` either empty or `['--state', state]`, without a shell and with a
five-second timeout. Slash-command arguments cannot supply options or extra
commands. Nonempty arguments return usage without running a process or probe.

Display network names and counts of local agents, pending connection requests,
live adapters and verified adapter channels from a valid version-1 snapshot.
Use the labels **Networks**, **Local agents**, **Pending connections**,
**Live adapters** and **Verified adapter channels**. Pending counts records
whose `state` is `pending`; live counts session connections whose `state` is
`ready`; verified counts live connections whose `channel` is `verified`.
Use **Host: running** or **Host: unavailable**, and **This conversation: STATE**.
Label adapter evidence separately from this plugin's conversation check. Render
names as bounded plain text with terminal controls and bidirectional overrides
removed. Keep routine presentation free of internal IDs, private paths and
known invitation/token formats. Do not echo raw CLI output or diagnostics.
These formats include `psi2-`, `psl2-`, `peerspan-invite-v1.`,
`peerspan-member-invite-v1.`, `peerspan-person-invite-v1.`, `token_` and
`instance_`. Remove terminal/bidirectional controls before detecting these
formats, so decoration cannot hide a token prefix from redaction.
On subprocess failure, malformed JSON, unsupported version or invalid shape,
show an unavailable observation; never turn it into an empty successful host.
Unknown extra fields are not presented. Refresh failure invalidates any previous
successful host view, independently of the conversation check.

Where no native pane can be drawn, return a concise read-only summary through
the command's text. Do not claim a human control exists or run a check there.

### Explicit conversation check

Only **Check this conversation** arms a check. It stores a fresh random
128-bit `probe_id` encoded as 32 lowercase hexadecimal digits, the native
`$.session.id()`, and its start time in memory;
it submits one fixed local check prompt through `$.prompt.submit({text})`
without `asUser`. Its prompt contains only that public challenge and
instructions to call `mcp__peerspan__delivery_acknowledge` with the JSON object
`{"probe_id":"CHALLENGE"}`; it includes no host
snapshot, files, conversation history, pairing material or owner decision.

Register `delivery_acknowledge` with exactly one required string argument,
`probe_id`. The tool grants no authority and performs no host action. It marks
the current check verified only when the supplied challenge matches, less than
60 seconds have elapsed, the native conversation still matches, the call is on
the main agent loop, and the engine is the native call's origin. Plugin-origin
and subagent calls cannot verify a check. Duplicate, stale, unknown and expired
acknowledgments are refused. The acknowledgment's result contains its state,
not the challenge or any host observation.

States are **unverified**, **waiting**, **verified**, **blocked** and
**timed_out**. Queuing leaves the state waiting. A dropped/refused submission
sets blocked; no acknowledgment within 60 seconds sets timed_out. Errors show
controlled text rather than provider diagnostics. A second press while waiting
does not queue another prompt. A later explicit check invalidates the previous
challenge. Late results, timers or failures from an older check cannot change
the newer one. Closing the pane, ending/changing the conversation or reloading
the module clears the check and cancels its timers. These states are not
persisted as authority or restored as verified after interruption.

Verification means this conversation's main model returned the local challenge
through the native tool path. It proves neither an attached Peerspan adapter nor
remote reachability, peer message consumption or authorization. Keep those
observations separate. The complete agent data path is later work.

### Verification

A separate author derives tests from this section using Claude's native
`claude-code/testing` runtime, with filesystem/process/prompt effects stubbed at
their public API boundary. Keep the test run under two minutes. These are
runtime-protocol fixtures, not real-model acceptance.

1. Register the one command and acknowledgment tool without process execution,
   prompt submission or host mutation at plugin load.
2. Entry and refresh run only the exact read-only CLI argv, including paths with
   spaces, and bind the pane to the existing native conversation. Unknown
   arguments run nothing. A headless entry returns a read-only summary.
3. Valid empty and populated snapshots produce accurate, distinct counts and
   safe names. Unknown fields, IDs, token-shaped labels and terminal controls
   do not leak into routine presentation.
4. Failed, timed-out, malformed or unsupported observations show unavailable,
   including after a previous success. Raw stdout/stderr do not reach the UI.
5. Only the explicit control submits one plugin-attributed local prompt. A
   queued prompt remains waiting; a matching main-engine acknowledgment verifies
   the same conversation without calling the host.
6. Reject wrong, reused, expired, plugin-origin and subagent acknowledgments and
   a changed native conversation. Starting a new check rejects the old challenge.
7. Double press queues once. Refused/dropped/throwing submissions and timeout do
   not become verified. Old asynchronous completions cannot overwrite a newer
   result; close/end/reload cannot preserve verified state.
8. Native plugin validation and tests run on the pinned supported Claude build
   in CI without signing in or calling a model. Separately exercise reload and
   delivery in a real existing conversation, recording the exact build and any
   usage/policy blocker; fixture success does not satisfy that live gate.

### Private human-review direction

Later authority reviews use native controls whose callbacks hold the exact
immutable review being shown. Approval is submitted directly from that trusted
local frontend to the owner-local flow interface. The model sees only public
progress, never private handoff text, signing inputs or an executable decision.
The human control must survive neither changed terms nor changed conversation
without a new review. This slice establishes no authority-review API or approval
callback; their exact immutable review and retry contracts remain next work.

### Rationale, alternatives and sources

Selected: a native mod, with a bounded local challenge and explicit evidence,
because it can preserve the current conversation and keep human controls
separate from model tools. Discarded as the default: channel-only delivery that
requires launch-time opt-in; lifecycle hooks that cannot wake an idle session;
model polling loops as installation; and model-authored `approve: true` as
evidence of an owner decision. Existing opted-in channel sessions remain
supported by their current integration.

Sources checked against the installed Claude Code 2.1.303:
[mod loading and reload](https://code.claude.com/docs/en/plugins/mods/overview),
[native controls](https://code.claude.com/docs/en/plugins/mods/interface),
[commands and background prompt submission](https://code.claude.com/docs/en/plugins/mods/api),
[runtime testing](https://code.claude.com/docs/en/plugins/mods/create), and
[channel opt-in](https://code.claude.com/docs/en/channels).

## 3. Exact local project review (GU-01c / GU-02b)

This slice supplies a concrete owner-local review flow for recording a project
and its existing native conversation against a local agent. It does not yet
wire the native pane to this flow. Its outcome is **attachment metadata**, not
an adapter, an admitted network member, shared files, capability permission or
verified delivery. Teammate and other-computer reviews remain separate work.

### Prepare and resume

`POST /v1/onboarding/project-flows` on `admin.sock` accepts exactly:

```json
{
  "project_root": "/absolute/project",
  "native_session_id": "current-native-conversation",
  "integration": "claude-code",
  "agent": {"kind": "new", "name": "project-agent", "owner": "local owner"}
}
```

Alternatively `agent` is exactly `{"kind":"existing","id":"agent_..."}`.
An existing agent must be explicitly selected by ID; never adopt an agent by
name or list order. A well-formed unknown agent ID returns 404 `not_found`; a
malformed ID returns 400 `invalid`. New names/owner labels follow registry validation (trimmed,
nonempty, at most 128 UTF-8 bytes, reserved agent name refused). New agents have
no capability metadata. The integration is exactly `claude-code` in this slice.
Native session IDs are nonempty, at most 256 UTF-8 bytes, with no whitespace or
control characters. Project roots are absolute UTF-8 paths, at most 4096 bytes,
with no control characters, `.` or `..` segments, repeated `/`, or trailing `/`
except `/` itself. No filesystem read, canonicalization, directory creation or
project-file edit occurs. The frontend obtains the root and native ID through
trusted native APIs, and must recheck them before a future decision callback.
A path is local metadata; it is never an authority claim.

The first prepare returns 201; an identical retry/resume returns 200 with the
same flow, exact review, planned IDs and original expiry, including after a
daemon restart. Match the tuple `(integration, native_session_id, project_root)`;
changing the selected agent for an existing attempt returns 409 `flow_conflict`.
Preparation commits only its private flow row. It creates no agent, session,
credential, grant or activity event. It fixes a 15-minute review deadline; a
read or retry never refreshes it. Concurrent identical prepares create one row.

A terminal/expired/invalidated attempt can be explicitly replaced by including
`replace_flow_id` naming the current latest attempt for that context. This
creates a new review with new IDs and expiry; it never changes the old review.
The replacement may change the agent proposal. Replacement of a still-reviewable
or attached attempt, or using a stale/nonmatching ID, returns 409 `flow_conflict`.
Without this explicit field, prepare always resumes the current attempt, even
when its derived state is expired or invalidated. A rejected replacement writes
nothing. Concurrent replacements against one old ID create at most one new row.

### Immutable review and observation

`GET /v1/onboarding/project-flows/FLOW_ID` returns 200, or 404 for an unknown ID.
Prepare, inspect and decision return the same exact top-level fields:

```json
{
  "version": 1,
  "flow_id": "flow_...",
  "state": "review",
  "review_id": "review_...",
  "review": {
    "version": 1,
    "kind": "attach_project",
    "flow_id": "flow_...",
    "host_id": "host_...",
    "project_root": "/absolute/project",
    "native_session_id": "current-native-conversation",
    "integration": "claude-code",
    "create_agent": true,
    "agent": {"id": "agent_...", "name": "project-agent", "owner": "local owner", "capabilities": []},
    "session_id": "session_...",
    "expires_at": "RFC3339 UTC",
    "effects": {
      "register_agent": true,
      "attach_session": true,
      "issue_adapter_credential": false,
      "grant_network_access": false,
      "share_files": false,
      "share_conversation": false,
      "capability_calls": false
    }
  },
  "attachment": null,
  "next_action": "review"
}
```

For an existing agent, `create_agent` and `effects.register_agent` are false;
its ID, name, owner and capability metadata are pinned exactly. All other
explicit effects retain the values above. IDs are allocated during preparation;
`flow_`, `agent_`, and `session_` append 16 random bytes as lowercase hex. A
`review_id` is `review_` plus lowercase SHA256 of UTF-8
`peerspan-project-review-v1\n` followed by the canonical JSON of `review` using
the following canonical JSON rules: recursively sort object keys by UTF-8 byte
order, retain array order, use compact separators without whitespace, and emit
UTF-8 strings without ASCII-escaping non-ASCII characters or escaping `/`.
Escape `"` and `\` with a backslash; use `\b`, `\t`, `\n`, `\f`, `\r`
for those controls and lowercase `\u00xx` for other U+0000..001F characters.
Booleans use `true`/`false`; version is integer `1`. The review contains no
floating-point numbers. There is one newline after the domain prefix, with
no trailing newline after the canonical object. It binds every field, including host,
project, conversation, agent, session, effects and fixed expiry. Review objects
never change; state/evidence is outside them. No invitation, signing input,
adapter token/instance or private key is present.

States and next actions:

| State | Meaning | next_action |
| --- | --- | --- |
| `review` | Exact terms remain current and before the deadline | `review` |
| `attached` | This flow committed its local attachment, still attached | `continue_adapter_setup` |
| `declined` | The owner refused these terms | `restart_review` |
| `expired` | Uncommitted review reached its fixed deadline | `restart_review` |
| `invalidated` | Agent terms changed, a proposed new name was taken, or the committed session was detached | `restart_review` |

Expiry is strict: at or after `expires_at` an uncommitted review is expired.
Before expiry, a conflicting agent proposal makes it invalidated. An attached
flow does not expire as an approval and never recreates a detached session.
`attachment` is null before a commit, otherwise exactly
`{"agent_id":"...","session_id":"..."}`, including if later invalidated.
Inspection and ordinary resume derive current state without durable changes,
including when expired/invalidated. They do not connect, resume an adapter,
approve, repair or renew anything. No flow with private project/native metadata
is added to the public onboarding snapshot, peer router or scoped adapter API.

### Exact decision and atomic attachment

`POST /v1/onboarding/project-flows/FLOW_ID/decision` accepts exactly:

```json
{
  "review_id": "review_...",
  "project_root": "/absolute/project",
  "native_session_id": "current-native-conversation",
  "integration": "claude-code",
  "decision": "approve"
}
```

Successful first decisions and same-decision retries return 200.
`decision` is `approve` or `decline`. Require the exact current flow, review ID
and context. Wrong context or hash returns 409 `review_changed`; expired review
returns 409 `review_expired`; invalidated, superseded or opposite already-decided
state returns 409 `flow_conflict`. Unknown flow is 404. Reject unknown fields,
nulls, malformed JSON, unsupported integrations and invalid proposals with 400
`invalid`. The 1-MiB administration body bound applies. Refusals are atomic.

Approval on a valid current review atomically creates the reviewed new agent
if requested, attaches the preallocated session to that exact agent with
integration `claude-code`, records the decision, and appends the ordinary
`agent.registered` (only if new) and `session.attached` events once. The new
session has the ordinary attached metadata state and no adapter credential or
channel proof. An existing agent's metadata and authority stay untouched.
Decline records only the flow decision, with no registry/activity effects.

An exact same-decision retry returns 200 without duplicate rows/events while
its committed attachment remains attached. A still-attached successful approval
remains idempotent after its old review deadline. Existing host startup detaches
metadata sessions and records `session.disconnected`; after restart this flow
is invalidated and replay returns `flow_conflict`, preserving its outcome IDs
without duplicate rows or resurrection. Uncommitted preparation resumes exactly
after restart. A decline retry remains idempotent after restart. A detached
attachment cannot be resurrected by replaying that approval. Superseded reviews never authorize the replacement.
No approval or human review tool is registered for the model. The trusted
native human callback is the selected future frontend; owner-local API access
continues to trust the local account, as existing administration does. A JSON
boolean or incoming peer content does not prove a human click.

### Advanced CLI and storage

Existing `peerspan onboarding` remains the read-only snapshot command. Add:

```sh
peerspan [--state DIR] onboarding project prepare --stdin
peerspan [--state DIR] onboarding project inspect FLOW_ID
peerspan [--state DIR] onboarding project decide --stdin
```

Prepare reads the exact JSON body above from bounded standard input. Decide
reads that decision body plus required `flow_id`, removes that field, and sends
the exact remaining body to its owner-local route. Input is at most 64 KiB;
stdin must be explicitly selected, with no interactive fallback, raw diagnostic
echo or project/private payload in argv. Successful commands print the response
JSON. No `--approve` shorthand exists. Unsupported/null/extra fields are refused
before mutation. Missing/unavailable daemon fails without creating host state.
Reduced root help stays unchanged; advanced help documents the subcommands.

Schema **24** adds only `onboarding_project_flows`, retaining every existing
schema-23/DEC record. Opening migrates in one transaction without preparing,
attaching, granting or creating activity. Older binaries refuse 24; this binary
refuses 25 and later without rewriting them. A pre-24 database containing an
object of this reserved name is refused atomically; a schema-24 database missing
or altering this table is refused rather than silently repaired.

Normative columns (in order; all TEXT): `flow_id` (primary key, NOT NULL),
`project_root`, `native_session_id`, `integration`, `request`, `review`,
`review_id`, `state`, `created_at`, `expires_at` (all NOT NULL), `session_id`
(nullable foreign key to `sessions.id`), `decided_at` (nullable). `request` holds
the normalized proposal without `replace_flow_id`. `review` holds the immutable
review JSON. Stored state is `review`, `attached` or `declined`; expiry and
invalidation are derived. No existing table changes. Preparation/decision hold
one database transaction across context selection, validation and commit.

### Verification

A separate author writes a slim black-box suite from this section and existing
public contracts, without reading the implementation. Use real temporary hosts;
keep the suite under two minutes. No real model or frontend stub proves a
human review or adapter connection.

1. Prepare a new-agent review, verify exact review/response fields and recompute
   its digest independently. Preparation/inspection/retry create only the flow
   row: no agent, session, credential, event, grant or project file change.
2. Identical preparations (including concurrent ones and after daemon restart)
   preserve one flow, IDs, terms and deadline. Different agent choices conflict;
   different native conversation/project contexts remain distinct.
3. Exact approval commits one reviewed agent/session and ordinary events;
   repeat/concurrent approval creates no duplicates. Restart invalidates the
   metadata attachment; retry cannot resurrect it or duplicate registry/events. No adapter,
   network access, file/conversation sharing or channel evidence appears.
4. Explicit existing-agent selection pins its exact metadata and creates only
   the reviewed session/event. Reject unknown agent IDs and reserved/invalid new
   names, relative/noncanonical paths, invalid native IDs/integration, unknown
   fields/nulls, and malformed or oversized stdin without incidental writes.
5. Altered hash/context and opposite decisions fail atomically. Decline creates
   no registry/events. Fixed expiry is not renewed by reads/retries; exact
   deadline refuses approval. Already-committed retries remain idempotent.
6. Publicly create a name collision after preparation; the old review becomes
   invalidated and cannot approve. Detach a committed session; replay cannot
   resurrect it. Replacing a declined/expired/invalidated attempt preserves the
   old review, requires its exact current ID, and creates a fresh review. Old or
   concurrent stale replacements/decisions cannot affect the new attempt.
7. CLI prepare/inspect/decide match API behavior, keep payloads on stdin, and fail
   inertly with absent/stopped daemon. Routes remain unavailable through peer,
   bootstrap and credential-scoped adapter interfaces.
8. Schema23 to24 migration preserves identity/registry/DEC rows and creates no
   flow or event. Pre-24 reserved-name collisions and malformed/missing schema24
   fail closed; newer-schema refusal checks use25, preserving the refused DB.
   A legacy-layout fixture may stop a real host, remove only the new flow table
   and set its version to23; retain all registry/DEC records unchanged. This
   tests the additive24 migration, not historical binary compatibility.

### Choice and discarded options

Selected: a durable exact local attachment review, with explicit replacement
and atomic metadata commit, as the first concrete orchestration path. This
makes interruption/retry observable before adding credential issuance or the
multi-person protocol. Discarded: minting credentials while displaying a
preview; adopting a same-named agent; rebuilding expiry on retry; overwriting
old terms; treating metadata attachment as ready; and using model output as
owner consent. Later flows compose existing authority protocols after their
own exact permission reviews. This is an implementation choice within GU, not
a new owner decision or a completed four-step flow.

## 4. Remaining flow contract

Teammate/device admission, private handoff, adapter setup and exact permission
grants remain future sections. Section 2's live verification and the complete
attachment/data path must pass before the frontend claims a ready connection.
Plugin reload or this slice's attachment metadata alone does not establish it.

## Implementation choices

- **Selected: read the actual host once.** One owner-local observation with a
  coherent database snapshot supports each frontend without making it join
  several independently changing status and request responses. Discarded:
  using a frontend's copied IDs as current authority, synthesizing a successful
  flow, and adding durable onboarding state just to inspect existing work.
- **Selected: preserve delivery evidence.** Return the full public adapter
  connection alongside its session. Discarded: treating an attached record or
  live lease as verified incoming delivery, and claiming model completion.
- **Selected: existing contracts underneath.** Reuse current network views,
  request views, connection records and status errors. Discarded: a new schema,
  changed signature format, widened access or a peer administration endpoint.

These are implementation choices under the accepted feature scope, not new
options attributed to the owner. Later slices extend this contract through
small PRs against the feature branch.
