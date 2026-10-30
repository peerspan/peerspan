# Guided onboarding contract

Status: feature-branch contract for [tracking PR #35](https://github.com/peerspan/peerspan/pull/35).
The accepted experience and integration policy are in the
[feature plan](guided-session-onboarding.md). Sections 1 and 2 specify the
observation and native Claude entry slices. Section3 specifies the owner-local
project review backend and atomic metadata attachment. Section4 wires trusted
native project selection and exact human callbacks. Authority reviews, adapter
setup and automatic protocol continuation remain subsequent slices.

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

## 4. Native project selection and human review (GU-02c / GU-03b)

This slice connects the terminal pane from section2 to the exact local project
review in section3. It records metadata for the current native conversation;
adapter setup, network admission and sharing remain later reviewed steps.
The pane must say **Project: attachment recorded**, with **Adapter connection
is next**, rather than describing this outcome as a ready connection.

### Private context lookup

Add owner-local `POST /v1/onboarding/project-flows/lookup` and advanced CLI
`peerspan [--state DIR] onboarding project lookup --stdin`. The body is exactly
`{"project_root":"/absolute/project","native_session_id":"native-id","integration":"claude-code"}`,
with section3's context validation. The CLI uses the same explicit 64-KiB stdin
bound and controlled diagnostics as prepare/decide. No project path or native
conversation ID is passed in argv.

Return200 with exactly `version:1`, `host_id`, `context` (the exact request),
`flow` (the latest section3 flow for this tuple, or null), and `agents` (all local
registry Agent records, ordered as `GET /v1/agents`, including each agent's
`id`, `name`, `owner`, `capabilities`, `created_at`). Select the current attempt
and agent list in one read transaction. A missing flow is ordinary empty state,
not a prepared review. Reads, including expired/invalidated flows, change no
logical records, expiry, consent or activity. All three interfaces outside
owner administration refuse this route. No schema or grant changes are needed.

### Entry, choice and resume

Keep section2's snapshot and local conversation check. `/peerspan` and ordinary
Refresh on the initial pane still execute only `peerspan onboarding`; plugin
load, headless entry and slash arguments perform no project action. A successful
snapshot offers **Connect this project**. Only that explicit human control
starts the private project flow, by reading `$.session.root()` and
`$.session.id()` and performing lookup. Root is the native project root, not
an agent-authored command argument or shell working-directory guess.

Project operations use literal argv with trusted `executable` and `state`
options, no shell, and a five-second bound:

- lookup: `[executable,...stateFlags,'onboarding','project','lookup','--stdin']`;
- prepare: the same prefix ending `prepare --stdin`;
- inspect: the same prefix ending `inspect FLOW_ID`;
- decide: the same prefix ending `decide --stdin`.

JSON payloads go only through the process API's `stdin`. They never reach the
model, prompts, command response text, notices, status/log APIs, files, plugin
storage or another session. Existing headless summary remains observation-only.
Only the existing acknowledgment tool is registered; no project/approval tool.
The conversation check prompt remains fixed and contains no project review.

Lookup resumes a retained review/outcome before offering a new choice. No flow
is created merely by opening, refreshing or looking up the pane. With no flow,
show **Project: choose an agent**. Offer a native **New agent name** input,
**Owner label** input (default `local owner`, descriptive metadata), and
**Review new agent**. Default the editable new name to the native root's final
path component when its trimmed UTF-8 length is1..128 and it is not `*`;
otherwise `project-agent`. Input change/submit edits only this draft; explicit
Review new agent prepares it. Show existing agents as individual **Review agent
NAME** buttons, with escaped quoted names and owner labels. Each callback holds
that exact agent ID; never adopt the first or same-named agent. Present at most
10 existing choices per page, with **More agents** / **Previous agents** as
needed. Changing pages is local and does not prepare a review.

A retained `review` is displayed immediately; `attached` shows its outcome;
`declined`, `expired` or `invalidated` shows the reason and offers **Review a
replacement**. That control opens agent choice and retains the old exact
`replace_flow_id`; it does not itself prepare/approve. The subsequent explicit
choice calls prepare with that ID. Never silently replace or renew terms.
**Back to Peerspan** leaves only the project view; **Close** closes the pane.
Neither control declines, cancels or rewrites the host flow. Reopening and
Connect this project look it up again. Refresh while a project view is active
refreshes the observation and its current project lookup, never a mutation.

### Exact human review and decision

Before exposing **Approve attachment** and **Decline attachment**, show all
human-relevant immutable terms: **Project** (full root), **Conversation: current
conversation**, **Agent** (full name), **Owner label** (full descriptive label),
**Agent record: new** or **existing**, the full capability-metadata list, the
fixed **Review expires** time, and these explicit effects:

- **Record this local session attachment**;
- **Register a local agent** when new;
- **Adapter credentials: none**;
- **Network access: none**;
- **File sharing: none**;
- **Conversation sharing: none**;
- **Capability calls: none**.

Keep internal IDs/hash/reference plumbing out of routine text. Render quoted
strings reversibly, using JSON escapes for quote/backslash/controls and explicit
`\\uXXXX` for bidi/invisible formatting characters; do not strip, abbreviate or
truncate reviewed terms. The native pane provides scrolling. If a known private
invitation/token prefix from section2 appears in any reviewed string, including
one split by terminal/bidi controls or inside an OSC title/hyperlink payload,
check both the original content and decoration-free forms (retaining payload
text as well as ordinary terminal-visible text). Show a controlled unavailable review with
no private value or decision controls. Do not turn redaction into approval of
ambiguous hidden terms. Never echo raw stdout/stderr, unknown fields or provider
errors. A capability list over100 entries or strings exceeding their registry
bounds is not representable by this preview and blocks the review explicitly.

The frontend validates response/version/shapes, IDs, context, agent metadata,
known effects, state/next action and attachment bindings before displaying a
review. Reject extra fields in a flow/review/agent/effects envelope or unknown
true effects, rather than approving fields the person never saw. The backend
is authoritative for the review digest; retain its exact review ID and a deep
immutable copy of every reviewed field. A refreshed response cannot silently
change the retained review underneath a previously rendered decision callback.

A decision callback captures that immutable flow, context and UI generation.
On press, synchronously exclude overlapping actions, reread trusted native root
and ID, and inspect the exact flow. Require the same host, flow, review ID,
complete review object, current `review` state and unexpired deadline; recheck
native context after inspection before sending decide. Submit only the captured
flow/review/context and the chosen approve/decline value on stdin. Changed terms,
changed context, stale callbacks, close/end/reload, expiration or failed inspection
send no decision. The person must reopen/refresh and review again. Do not
substitute a newer review and approve it in the old callback.

Only a valid matching decision result updates the pane to attached/declined.
Double presses queue one decision. Late reads, preparations, decisions and old
expiry callbacks cannot replace a newer view or different native context.
Closing/changing context cannot recall a decision already sent; hide stale
results and use the next lookup to report its actual durable outcome. Process
failure shows a controlled outcome-unknown message with Refresh; never auto-retry
an owner decision. An incompatible/malformed/failed lookup or prepare gives no
approval control. A refresh failure invalidates the former actionable review.

Use the native clock to disable decision controls at the exact fixed deadline;
this is only local UI expiry, with the host independently enforcing section3.
An expiry while a decision is in flight says the deadline was reached and asks
for Refresh rather than asserting no commit occurred. Timers cannot renew the
review or expire a newer one. Close/end/conversation/root change/module reload
clears in-memory drafts, private views and timer/callback authority. The native
`classic.CwdChanged` event clears the project view immediately when delivered.
Claude managed environments may suppress classic hooks for a user-installed
plugin; there the preview detects an unsignaled root change on the next native
action/context check. Every callback still rereads root/ID before effects and
cannot rely on the event for authorization. Immediate redraw in that managed
configuration is not validated. Durable host reviews remain. Unsupported/nonterminal surfaces get no private flow.

### Verification

A separate author extends the native runtime conformance from this section,
without production imports or reading implementation. Keep section2's existing
22 cases. Stub only the documented public native API effects; record exact argv,
stdin and context calls. A separate small black-box lookup case extends the
project slim suite. Keep suites below two minutes.

1. Initial/load/headless/unknown-argument behavior remains observation-only.
   Explicit Connect reads trusted root/ID and sends one bounded literal lookup;
   no prepare/decision, prompt, file, log or plugin-store side effects occur.
2. Empty lookup exposes editable defaults and explicit new/existing selection.
   Inputs and paging do not prepare. Existing callbacks carry the selected ID;
   new selection prepares only its reviewed draft. Paths/options with spaces and
   shell metacharacters remain literal; private context stays on stdin.
3. A retained flow resumes regardless of new-name defaults or list order. Exact
   fields/effects are visible; internal IDs, private prefixes and raw diagnostics
   are absent from routine UI. Include raw and decorated private prefixes inside
   OSC payloads in agent names, owner labels and capability metadata; exact
   quoting must not expose a value removed by terminal normalization.
   Malformed, extra-field, context/host-mismatched or
   unexpected-effect responses cannot offer or submit an approval.
4. Only trusted native approve/decline controls send decisions, after matching
   inspection and a second native-context check. Captured hashes/context remain
   exact. Altered review/hash/state, wrong host or any pre-send context change
   prevents decide; no prompt/model tool can approve this flow.
5. Double presses queue once. Lookup/prepare/inspect/decide failures, stale or
   out-of-order results, context change and close/end/reload fail closed. A late
   old callback cannot approve a newly displayed review. Outcome uncertainty is
   resolved by lookup, not an automatic decision retry.
6. Fixed deadline disables controls, including races with pending inspection.
   Old timers cannot expire a newer review. Terminal replacement requires the
   explicit control and later explicit agent choice with the exact old flow ID.
7. Backend lookup is coherent, exact, private and read-only for empty, pending,
   attached and expired contexts. Its CLI matches API, enforces stdin bounds and
   fails inertly when unavailable. Refuse it on peer/bootstrap/scoped interfaces.
8. Exercise the real pinned native runtime with a real temporary host and an
   actual project metadata decision, without inference. Record exact build/head
   and distinguish it from a model acknowledgment or complete adapter delivery.

Selected: private native callbacks over exact owner-local flow references.
Discarded: model approval tools, slash arguments carrying owner decisions,
silent first-agent adoption, frontend-only persisted guesses, preparing during
entry, truncated/redacted consent, and auto-retrying decisions. These are GU
implementation choices; no additional owner decision is attributed here.

## 5. Exact local adapter authorization (GU-01d / GU-02d)

This host slice follows an approved section3 project attachment. It prepares an
exact, durable review before issuing one credential for that same session.
It does not connect an adapter, submit model input, grant inbound access, start
a process, or complete GU-03. Native connection controls are the next slice.

### Scope and immutable terms

The first guided credential has a fixed expiry 24 hours after preparation and
is not renewable. It may receive messages and tasks already authorized for the
selected agent, reply to those messages, handle those tasks and their authorized
artifacts. It gets no directory access, outbound routes or capability-call
permission. Existing remote grants still govern incoming work. Connecting an
existing agent may resume that agent's already authorized work; the review must
say this explicitly. This issues no permission to read or automatically share
the project's files or conversation. Ordinary harness permissions still govern
local actions and files used in task results.

All routes below exist only on owner-local administration, under
`/v1/onboarding/adapter-flows`. Peer, first-contact/bootstrap and credential-scoped
interfaces refuse them. The local account remains the authority boundary;
neither this API nor a JSON decision proves a physical human click.

`AdapterContext` is exactly:

```json
{
  "project_flow_id": "flow_<32 lowercase hex>",
  "project_review_id": "review_<64 lowercase hex>",
  "project_root": "/absolute/project",
  "native_session_id": "native-conversation-id",
  "integration": "claude-code"
}
```

Apply section3's context validation and exact project review binding. An
unknown project returns404. A wrong context/project review returns409
`review_changed`; malformed IDs/context return400 `invalid`, using the existing
[host error contract](host-service-contract.md#api-and-commands). A new
review for a correctly bound but ineligible project returns409 `flow_conflict`.
A new adapter review requires that project to be the latest
attempt for its native context, currently `attached`, with unchanged agent
metadata and its same attached session. Refuse any other unexpired, unrevoked
adapter for this agent whose session is attached or recoverable, including an
unbound setup or offline adapter. No implicit revocation, replacement or
takeover is included in this review. The owner can cancel an old authorization
through existing advanced administration before reviewing again.

`POST /v1/onboarding/adapter-flows` takes exactly
`{"context":AdapterContext,"replace_flow_id":optional-string}`; an explicit
null or unknown field is invalid. It creates a private flow and returns201,
or returns200 for an identical retained request. It creates no credential,
session, agent, grant, connection or activity event. Each project attempt has
one latest adapter attempt. The same request resumes that attempt without
changing its IDs, terms or expiry, including terminal outcomes.
An identical retained prepare after restart returns200 with the same immutable
review and its derived invalidated state, even though the project is detached.
Read-only inspection does not need a current attachment to show the retained
outcome. A new attempt
requires the exact latest `replace_flow_id` and a current outcome of `declined`,
`expired` or `invalidated`; a current valid authorization is not replaceable.
The underlying project must still be attached and eligible. Refuse obsolete
replacement IDs and other conflicts with409 `flow_conflict`.

The immutable review has exactly these fields:

- `version:1`, `kind:"authorize_adapter"`, `flow_id`, `host_id`;
- the five `AdapterContext` fields at the top level;
- `agent`: section3's exact `{id,name,owner,capabilities}` from the project review;
- `session_id`: that already attached session;
- `adapter_id`: a planned `adapter_<32 lowercase hex>`;
- `expires_at`: the fixed review deadline, 15 minutes after preparation;
- `credential_expires_at`: the fixed credential deadline, 24 hours after
  preparation; `renewable:false`;
- `effects` exactly: `issue_adapter_credential:true`,
  `receive_authorized_work:true`, `reply_to_authorized_work:true`,
  `handle_authorized_tasks:true`, `task_artifacts:true`, `register_agent:false`,
  `attach_session:false`, `grant_network_access:false`, `directory_access:false`,
  `outbound_routes:false`, `capability_calls:false`, `share_files:false`,
  `share_conversation:false`.

Times use UTC RFC3339 whole seconds with `Z`. `review_id` is
`review_` plus lowercase SHA256 of UTF-8
`peerspan-adapter-review-v1\n` followed by the review's canonical JSON, with the
same canonicalization as section3. Every term above participates in the hash.

### Inspect, lookup and decisions

`GET /v1/onboarding/adapter-flows/{flow_id}` inspects without mutation.
`POST /v1/onboarding/adapter-flows/lookup` takes `AdapterContext` directly and
returns exactly `{version:1,host_id,context,flow}`, where `flow` is the latest
attempt for that exact project or null. Lookup validates the project binding,
but may report a retained invalidated outcome after detach or restart. Neither
read changes logical records, deadlines, credentials, consent or events. Select
the project and adapter state in one database read transaction.

A flow response has exactly `version:1`, `flow_id`, `state`, `review_id`,
`review`, `authorization`, `connection`, `next_action`. Before approval,
`authorization` and `connection` are null. Once issued, `authorization` retains
exactly `{adapter_id,session_id,agent_id,expires_at,renewable:false}`, even if
later invalidated; `connection` is the existing adapter-connection view.
No view contains a token, instance secret, token hash or derived secret.

States and next actions:

| State | Meaning | Next action |
| --- | --- | --- |
| `review` | exact terms remain current and review deadline has not passed | `review` |
| `authorized` | credential was issued, remains current and has not expired | `connect_adapter` |
| `declined` | explicit refusal, retained | `restart_review` |
| `expired` | pending review deadline or issued credential deadline reached | `restart_review` |
| `invalidated` | project no longer current/attached, metadata changed, conflicting authorization appeared, or issued scope/credential was changed, detached or revoked | `restart_review` |

`POST /v1/onboarding/adapter-flows/{flow_id}/decision` takes exactly
`{context:AdapterContext,review_id,decision:"approve"|"decline"}`. Only the latest
attempt may decide. Wrong immutable references/context give409 `review_changed`;
an expired review gives409 `review_expired`; other terminal/conflicting changes
give409 `flow_conflict`. Approval in one transaction rechecks all terms,
records the exact planned adapter ID for the existing session with fixed
expiry, false directory/calls and no routes, appends the ordinary
`adapter.created` event once, and retains the authorized outcome. It creates no
extra agent or session and never replaces another adapter. Decline changes only
the private flow. Concurrent/repeated identical decisions return the same
outcome with no duplicate effects; opposite decisions conflict. A repeated
approval after issuance does not extend the credential or recheck the old
review deadline; it still requires a currently valid authorization. Reads and
decision responses never return the credential secret.

Expiry/invalidated states are derived at observation. A declined decision stays
declined. A pending review expires at its deadline; otherwise a changed project
or conflicting adapter invalidates it. An issued authorization expires at its
credential deadline; otherwise changed project/session/metadata, revocation,
renewability, scope or routes invalidate it. There is no silent widening or
renewal. Host restart follows the existing session-detach contract: it may
invalidate a guided authorization; this slice does not override restart or
instance recovery rules.

### Private credential retrieval and recovery

`POST /v1/onboarding/adapter-flows/{flow_id}/credential` takes exactly
`{context:AdapterContext,review_id}`. Only the latest, already authorized and
currently valid attempt returns200 with exactly
`{version:1,adapter_id,session_id,token}`. Wrong context/review gives409
`review_changed`; any other ineligible outcome gives409 `flow_conflict` and no
secret. It makes no logical writes or events. A lost decision response can be
resolved by lookup, then the same approved credential retrieved without
replaying approval. A lost retrieval response can be retried. No mutation is
performed by lookup or inspect to enable recovery.

For bounded secret recovery without persisting plaintext tokens, the token is
`token_` plus lowercase HMAC-SHA256, keyed by the host's 32-byte Ed25519 seed,
over UTF-8 `peerspan-guided-adapter-token-v1\n` + `flow_id` + `\n` + `review_id`.
Only its normal SHA256 token hash is stored in `adapter_credentials`. Public
references cannot derive the token. The domain differs from every signing and
review domain. The private retrieval route and normal local administration
already trust the same account. Normal adapter issuance remains random and
unchanged. Revocation/expiry never recreate or reactivate a credential.

The future native frontend must keep retrieved tokens only in private memory
or deliberately managed private artifacts, never in model context, argv,
routine diagnostics or plugin storage. This host slice exposes no model tool
and claims no adapter lease, verified channel or model receipt.

### Advanced CLI and storage

Add `peerspan [--state DIR] onboarding adapter prepare --stdin`,
`lookup --stdin`, `inspect FLOW_ID`, `decide --stdin`, `credential --stdin`.
Prepare/lookup bodies match API. Decide/credential stdin adds `flow_id` for
route selection, removed before posting. Only the explicit `credential`
operation prints the secret response; it is a private integration interface,
never normal user guidance. Reuse the 64-KiB stdin limit, fixed owner-local
socket selection and controlled diagnostics. No payload appears in argv.

Schema25 adds only `onboarding_adapter_flows` with these TEXT columns in order:
`flow_id PRIMARY KEY NOT NULL`, `project_flow_id NOT NULL REFERENCES
onboarding_project_flows(flow_id)`, `request NOT NULL`, `review NOT NULL`,
`review_id NOT NULL`, `state NOT NULL CHECK (state IN
('review','authorized','declined'))`, `created_at NOT NULL`, `expires_at NOT NULL`,
`adapter_id REFERENCES adapter_credentials(id)`, `decided_at`.
Migrate existing schema24 additively in the startup transaction; older supported
schemas pass through their existing migrations. Preserve every existing table,
DEC object, project flow, identity, activity and detached historical session.
Before migration, any object occupying that new name is an error. At schema25,
missing/altered table definitions are errors. All refusal paths leave logical
data, schema and version untouched. Future schema26 is refused. Section3's
schema24 layout remains unchanged; its migration tests now expect the additive
schema25 table as well. Existing version-refusal cases move their future
fixture to26; this is a version update, not weakened refusal behavior.

### Verification

A separate contract-only author writes a small black-box `adapter_onboarding`
slim suite, using real hosts and the public API/CLI. Keep it under two minutes,
with debug clock advancement for expiry. No implementer unit tests are added.

1. Prepare only after an exact attached project; complete immutable terms/hash,
   exact scope/deadlines, no credentials/events/session/agent effects before
   approval; reject missing, wrong, unknown, null and malformed fields.
2. Identical and concurrent preparation/resume preserve one attempt and fixed
   terms across restart; lookup/inspect are coherent and read-only, including
   empty, pending, authorized and terminal outcomes. A restarted detached
   project invalidates the review without resurrecting it.
3. Exact approval creates one planned normal credential/event, no other effects;
   concurrent/repeated approval is idempotent, decline inert and opposite
   decisions conflict. Wrong review/context or changed metadata/session/project
   cannot authorize. Check pending deadline and credential expiry independently.
4. Private retrieval only after approval, exact/current binding, deterministic
   retry, normal verify-credential and scoped connect compatibility. Neither
   persisted records nor ordinary views/decisions contain plaintext token.
   Before ready, work stays gated by the existing channel handshake; a scoped
   credential cannot reach administration, directory sends or capability calls.
5. Another unbound/live/offline/recoverable authorization is never replaced.
   Conflicts discovered after preparation invalidate it atomically. Revocation,
   changed routes, detach and superseded project/adapter attempts cannot
   retrieve or revive a credential; explicit terminal replacement uses the exact
   current ID and keeps previous outcomes.
6. Bounded stdin CLI parity, inert unavailable-daemon behavior and controlled
   diagnostics; all non-owner routers refuse every new route. Secret output
   appears only for explicit successful credential retrieval, including its
   private transport wrapper in section6.
7. Additive schema24-to25 migration, historical preservation, restart, namespace
   collisions, corrupt schema25 and future26 refusal. Update only schema-version
   expectations in existing suites, retaining their original behavior checks.

Scope flags have no public edit endpoint: assert their exact false/fixed values
on issuance, and exercise subsequent scope invalidation through the documented
route-creation API. Do not manufacture private-record mutations to simulate an
unavailable public operation. The token derivation's seed is not a public disk
format contract; verify deterministic retry, normal credential authentication,
different-flow separation and SHA256-only token persistence without reading a
private key layout. Real native connection/model receipt remains a later gate.

Selected: a separate exact credential review, conservative fixed expiry,
existing scoped authorization and recoverable owner-local secret retrieval.
Discarded: folding credential issuance into the metadata approval, blanket
directory/capability access, replacing an offline/unbound adapter without a
review, plaintext token storage, a one-shot secret lost after interruption,
and treating credential issuance as connection or model readiness. These are
implementation choices under GU-OWN1/2, not additional owner confirmations.

## 6. Native credential review and scoped lease (GU-02e / GU-03c)

This slice connects section5 to native human controls and a real credential-
scoped local lease. It does not claim complete incoming delivery: it registers
no new model tool, sends no adapter hello/model prompt, calls no ready/work
route, and consumes no messages or tasks. The existing local conversation check
remains separate. Native data tools, incoming events and their exact model
acknowledgment are the next slice before claiming a ready connection.

### Private transport material

Add advanced `peerspan [--state DIR] onboarding adapter transport --stdin`.
Its exact input is the existing credential CLI input:
`{flow_id,context:AdapterContext,review_id}`. Apply the same 64-KiB bound,
validation, controlled diagnostics and owner-local credential retrieval. The
existing credential API/CLI response remains unchanged. Transport adds no API,
schema, write, event, approval, credential issuance or lease mutation.

Only successful exact retrieval returns this private object, with exactly
`version:1`, `adapter_id`, `session_id`, `token`, `instance_id`, `adapter_socket`.
The first four fields match credential retrieval. `adapter_socket` is the
absolute path to `adapter.sock` beside the administration socket selected by
that CLI invocation. Reject a non-UTF-8 path with a controlled diagnostic.
Never select a socket from model arguments or the project directory.

`instance_id` is `instance_` plus lowercase HMAC-SHA256, keyed by the token's
32 decoded bytes, over UTF-8 `peerspan-guided-adapter-instance-v1\n` + `flow_id`
+ `\n` + `review_id`. This privately reproduces the same original instance after
plugin reload without a secret file. Changed flow/token/review produces a
different instance. It does not reset the host's instance hash, take over a
different instance, or bypass revocation/expiry/recovery. The credential already
authorizes this local consumer; this derivation is no separate authentication
of the native conversation against another process owned by the same account.
Do not persist or display either secret or the socket. The private transport
command is for integrations, not a suggested interactive shell command.

### Native review and consent

Section4's initial, headless and project actions retain their behavior. Only
an attached project offers **Review adapter connection**. Native private
project/adapter controls render only on the terminal surface; another surface
gets no private review or owner decision controls even if a terminal is also
attached. No entry/load, ordinary initial Refresh, input edit or model tool
prepares, decides, retrieves a credential or connects an adapter.

The explicit Review control rechecks trusted root/conversation/host and the
exact attached project via its inspection route, then privately looks up the
section5 flow. It resumes a retained outcome first. If no attempt exists, that
same explicit review intent prepares one; this is preparation, not approval.
An active adapter-view Refresh is read-only and never prepares a missing flow.
An empty refreshed view offers **Review adapter permissions** to prepare.

For a pending flow show every immutable human-relevant term without clipping:
project root, current conversation, exact agent name/owner/capability metadata,
review deadline, credential deadline, nonrenewable lifetime, and its effects:

- issue one credential for this existing local session;
- receive and reply to work already authorized for this agent;
- handle already authorized tasks and their task artifacts;
- existing authorized work may resume when delivery is connected;
- no new agent/session, membership or access grant;
- no directory access, outbound destinations or capability calls;
- no automatic sharing of project files or conversation; ordinary local harness
  permissions still govern local actions and task-result files.

Use section4's reversible quoting, metadata bounds and private-prefix rejection,
including terminal/bidi decoration and OSC payloads. Keep flow/hash/session/
adapter IDs and native conversation ID out of routine review text. Validate
exact response fields/version, known effects, parent context/review/agent/session,
planned IDs, authorization, connection and state/next action before any control.
While the adapter review is open or its runtime is connected, the completed
parent attachment can be summarized as recorded; the child review still shows
the full project/agent identity and all of its current credential effects.
Do not repeat the parent's historical "credentials: none" as current adapter
state or show "connection is next" alongside a connected runtime.
Unknown or inconsistent fields/effects block the view; do not approve hidden
terms. Retain a deeply immutable complete review and exact parent bindings.

**Approve adapter** / **Decline adapter** callbacks synchronously exclude double
presses, capture that review and UI generation, reread native root/ID/host,
inspect the exact parent project and child flow, require their unchanged complete
terms and current eligible states, recheck native context and fixed deadline,
then submit the captured decision on stdin. Changed terms, old callbacks,
expiry, failed inspection or changed context send no decision. Native clock
expiry removes actionable controls; old timers cannot expire newer views.
Approval only records authorization. It never retrieves transport material or
opens a connection implicitly. Decline is flow-only. Decision uncertainty asks
for Refresh; it never auto-retries approval. Invalidated/declined/expired flows
offer **Review a replacement adapter**, which explicitly prepares with the
exact current `replace_flow_id`, followed by a fresh review and decision.

Opening/refreshing/closing the view does not rewrite durable consent. Close,
Back, root/conversation change or module reload invalidates old human callbacks.
Lookup resumes the host outcome, including a lost approval response; a retained
authorized result offers **Connect adapter**, never silently reconnects.

### Explicit scoped connection

**Connect adapter** captures the exact authorized parent and child reviews,
rechecks both inspections and native context, then retrieves private transport
material via literal argv ending `onboarding adapter transport --stdin` with a
five-second process bound. As in section4, all context/decision payloads remain
on stdin. Accept exactly the six transport fields, exact planned adapter/session,
`token_<64 lowercase hex>`, `instance_<64 lowercase hex>` and an absolute local
socket path ending `/adapter.sock`, with at most103 UTF-8 bytes and no controls,
empty components, `.` or `..`. Unsupported paths are a controlled blocker.

After another context check, call the native host HTTP API only at the literal
URL `http://peerspan/adapter/v1/connect`, with `method:'POST'`, the validated
`socketPath`, `Authorization: Bearer TOKEN`, `X-Peerspan-Instance: INSTANCE`,
`Content-Type: application/json`, and body exactly
`{adapter_id,session_id,instance_id,protocol_version:'claude-mod-v1'}`. This
reports the native transport, not an MCP negotiation. No TCP request, owner API
mutation, alternate path, shell or subprocess is used for scoped traffic.

Use a five-second logical deadline for HTTP, since the pinned native HTTP
interface has no per-call timeout option. A timed-out/already-sent request may
finish once; discard its result and schedule no more work. Failures, malformed
responses or denied calls show controlled unavailable/outcome-unknown text;
never expose provider diagnostics or retry a failed connection automatically.
An explicit subsequent Connect can use the same approved original instance.

Accept only the exact existing Connection shape and matching adapter/session,
`state:'ready'`, future lease deadline no later than the credential deadline,
and valid known field types/values. Do not turn its saved `channel:'verified'`
into proof for this native frontend: this slice has no incoming delivery path.
Only after that successful response show **Adapter: connected**, **Incoming
delivery: not verified**, **Peer exchange: not verified**. Never report connected
from a credential, preparation, request submission, or stale/expired response.

While connected, renew the same lease five seconds after each successful
response, with one request in flight. Before every renewal reread native root,
conversation and terminal availability, inspect the exact parent and child
without mutation, require the captured authorized terms/scope, then recheck
context before the scoped call. Failure, invalidation, changed scope/review,
context/host change or credential expiry stops this runtime and forgets private
material. A separate deadline timer invalidates connected status at the last
observed lease expiry, even when inspection/HTTP is pending. Late results and
old timers cannot restart a stopped runtime or change a newer connection.

Connection lifetime belongs to the current native conversation. Closing the
pane or Back clears private review callbacks but keeps an explicitly connected
adapter's runtime/lease. Close or Back while initial connection is pending stops
that pending runtime: a late response cannot start renewal after leaving it. A
previously rendered Stop control cannot stop a newer runtime or act after its
view closes. **Stop adapter** is available separately; it cancels
renewal, clears the local runtime and forgets secrets. It revokes no credential
and detaches no session; the last accepted lease expires within15 seconds unless
an already-sent request completes later. Session end, delivered CwdChanged,
native context change, module reload or loss of terminal support stops renewal.
Managed suppression of CwdChanged is detected at the next callback/renewal.
Plugin reload never auto-connects; reopening and explicit Connect recover the
same currently approved instance under the normal host rules. Host restart may
invalidate the project/authorization as in sections3/5; do not bypass that gate.

Only connection state and controlled status survive in UI text. Tokens,
instances, socket paths, native context and private references remain in the
frontend's current private memory/native API payloads. No files, plugin store,
notices/logs, command-response text, prompts, model tools or other sessions
receive them. New runtime work begins only after explicit Connect. This slice
adds no model-facing tool and never calls ready, work or peer routes.

### Verification

A separate author extends the pinned native runtime cases using only this
contract/public API and effects at their public boundaries. Keep the original
52 cases unchanged. A small black-box extension to adapter_onboarding covers
the private transport CLI. No implementer unit tests are added.

1. Initial/headless/load/unknown arguments remain inert; only attached projects
   expose the adapter review intent. Nonterminal renders expose no private
   reviews or decision controls even with a terminal attached. Keep old tools.
2. Explicit review checks native context and parent, then lookup/resume or
   prepare if absent. Refresh is read-only. Complete exact terms and all effects
   are visible without IDs/secrets; unknown/malformed/changed/private-looking
   metadata blocks controls. Retained terminal replacement is exact and explicit.
3. Exact approve/decline after parent/child inspection and final context check;
   double presses once. Changed hash/terms/scope/context, expiry, failed reads,
   stale/late callbacks, close/reload/end and old timers never decide another view.
   Lost approval is resolved by lookup; approval never connects or retrieves.
4. Connect only after explicit intent and valid matching authorized inspections;
   transport material stays private, argv/stdin are exact, malformed material or
   unsupported socket blocks HTTP. No secret appears in render/command/model/
   storage/files/log output. Never call ready/work/peer/owner-mutation HTTP paths.
5. Exact Unix-scoped connect and protocol reporting; response binding/schema/
   lease validation, five-second timeout, uncertain/denied/failed calls and
   double presses. Healthy renewal is single-flight and repeats only captured
   references. No saved channel state claims incoming or peer/model receipt.
6. Context/host/surface/parent/child changes, revocation/scope changes, expiry,
   lost/late responses and old timers stop renewal. Close/Back retain an approved
   runtime; Stop/end/reload/root change do not. A stale runtime cannot restart or
   replace a new connection. Explicit reconnect uses stable private instance.
7. Real CLI transport: exact six fields, absolute selected socket, standard
   HMAC result, deterministic retrieval/retry with no records/files/events changed;
   no secret on refusal and existing credential API unchanged. Real scoped
   connection/reconnect accepts that instance without another authorization.
8. Real pinned terminal plus temporary host: prepare/review/approve adapter,
   connect, observe live unverified lease and renewal, Close/reopen, Stop,
   reload and explicitly reconnect without duplicate authorization. Record exact
   heads/build and no inference/ready/work claims. Installed/full model delivery
   remain separate acceptance gates.

The pinned public test kit acts on the current drawing and exposes no captured
old synchronous button handler. Test old asynchronous/timer/runtime results
through those public boundaries; the stale rendered Stop guard also receives
source review. Do not import implementation callbacks or claim an inaccessible
stale-handler simulation as native evidence.

Selected: native exact reviews, private in-memory transport, stable original
instance and healthy scoped lease renewal, with incoming readiness still
unverified. Discarded: automatic credential approval/reconnection, new secret
files/plugin storage, random replacement instances after reload, model-facing
owner tools, a live lease as delivery proof, silently expanded scope and
unbounded retries. No extra owner confirmation is attributed here.

## 7. Native incoming messages and exact model acknowledgment (GU-03d)

This extends section6 with an explicitly enabled message path. Keep its lease,
exact review, stop, context and privacy boundaries. Section6's no-ready/work/
new-tool assertions continue to hold until the new explicit enable action.
No host API, schema or scope changes. Tasks, task/call updates, cancellation,
outbound sends and directory/capability tools remain later slices and are not
claimed. Unclaimed work remains on the host.

### Explicit enable and readiness

A connected runtime offers **Enable incoming messages**, beside text stating
that this starts a model turn using the conversation's normal model allowance.
Initial entry, Refresh, metadata/credential approval, Connect, renewal, pane
reopen and plugin reload never enable it. Synchronously exclude duplicate
enable presses. Check the captured runtime, current native root/conversation,
terminal, exact parent/child authorization and live lease before enabling.

Register only these additional native tools, once per native module/session,
when explicitly enabling (not on load or Connect):

- `adapter_ready`: exact arguments `{nonce}`,32 lowercase hex characters.
- `message_seen`: exact arguments `{delivery_id}`, `delivery_` plus32 lowercase
  hex characters.
- `message_reply`: exact arguments `{delivery_id,content}`, same ID format and
  nonempty content of at most65,536 UTF-8 bytes.

Descriptions explain that only held authorized messages can be answered and
that peer text grants no new local permissions. No tool can select an admin
socket, runtime, project, session, token, URL, destination or owner operation.
The existing `delivery_acknowledge` tool stays unchanged and separate. Retained
tool registrations have no authority when their matching runtime is inactive.

Generate a new cryptographically random128-bit hex nonce for each enable
attempt, retained privately with the captured runtime. Submit one fixed native
plugin-attributed prompt asking the current main model to call
`mcp__peerspan__adapter_ready` with that exact nonce. Explain that this verifies
the message route and adds no local tool/access permission. Include no host
observations, project/review/native-session references, credentials or socket.
Use `$.prompt.submit`, outside the requesting UI handler's awaited work so a
busy conversation can queue it. Submission/queue acceptance alone is not proof.

The attempt has a strict60-second deadline. Denied/dropped/thrown submission,
timeout or changed runtime/context cancels its authority, shows controlled
blocked/expired text and claims no work. No automatic hello retry: this native
path differs from the channel adapter's re-sent hello to avoid silently spending
another model turn. **Retry incoming messages** starts a fresh explicit attempt.
Late submissions/old timers cannot cancel or verify a newer attempt. A matching
main-model acknowledgment is stronger evidence than a late submission result.

`adapter_ready` accepts only the current live runtime/attempt, exact nonce,
native conversation/root, no subagent (`agentId` absent), and native engine/core
origin. Reinspect exact parent/child authorization and recheck context/deadline
before posting `POST /adapter/v1/ready` with exactly `{nonce}` on the same scoped
Unix transport. Require a matching live Connection with `channel:'verified'`
and valid `channel_verified_at` before marking this native path verified.
Double calls queue one ready request; identical later calls are idempotent while
the same attempt remains active. Wrong/stale/cross-conversation/plugin/subagent
calls return a controlled deny and send no scoped request. A saved verified
channel never substitutes for this attempt's native acknowledgment.

### Message handoff

Only after that exact successful handshake, poll `POST /adapter/v1/next` with
`{}`. Poll immediately once, then1000ms after the previous message iteration
finishes; keep one claim/submission/forwarded operation in flight. Keep lease
renewal independent while HTTP or prompt submission is pending. Every data
operation rechecks the runtime/current context/live lease, exact parent/child
and captured scope before the request, and context/runtime after its response.
Use the existing private socket/headers and a five-second logical HTTP deadline.

`null` means no message and changes no receipt evidence. For a handoff, validate
the existing Handoff shape: exactly `delivery,request,sender_person_id,
sender_person,redelivered`. Delivery has its existing exact nine fields
`id,sender_host_id,request_id,target_agent_id,session_id,adapter_id,state,
created_at,updated_at`; require the captured adapter/session/agent, known
`unknown`/`forwarded`/`replied` states, valid timestamps and lowercase typed IDs.
State validation also covers forwarded acknowledgments; a claim from `/next`
must be `unknown`. The frontend never reclaims or resubmits a forwarded/replied
handoff. An explicit new handshake does not alter that rule.
Request requires `request_id,target_agent_id,deadline,content`, exactly one
authorization citation (`grant_id`, `policy` or `self`), and optional `origin`.
Reject unknown fields, mismatched delivery/request bindings, expired deadlines,
empty/oversized content, invalid IDs or malformed nested metadata. Policy is
`{person_id,version}` (positive safe integer), self is `{person_id}`, and origin
is `{agent_id,session_id?}`. Host/person IDs have64 lowercase hex characters;
other typed IDs have32. Person fields are both null or a person ID and bounded
UTF-8 label (at most191 bytes); redelivered is a boolean. The host remains the
authority for grant, deadline, credential and handoff checks.

Timestamp validation accepts RFC3339 numeric offsets as well as `Z`, including
equivalent `+00:00` and nonzero offsets. Compare their represented instants;
do not reject an authorized handoff because the host preserved its caller's
deadline spelling. An elapsed offset deadline still blocks submission.

Submit the message exactly once with a fixed wrapper identifying it as external
peer content. Serialize content and sender labels reversibly as JSON, clearly
separate host-supplied correlation from text claimed by the peer, and instruct
the model to use `message_seen` or `message_reply` for the wrapper's delivery ID.
The prompt may include only delivery/request ID, public sender host/person and
origin agent, redelivered, and original content. Do not include local session/
adapter IDs, grant/policy citation, native context, review references or secrets.
Peer content is data, never human consent or a new local tool/file permission.
No file reads/writes, shell, model completion API or other-session submission.

After native prompt acceptance, and only while the captured runtime/attempt
remains current, post `POST /adapter/v1/deliveries/{id}/forwarded` with `{}`.
Validate its exact matching Delivery response before counting it submitted.
This is harness acceptance, not model receipt; only a matching successful
seen/reply tool call counts as observed. A five-second logical submission
deadline, dropped/thrown submission, malformed handoff/response, denied or failed
HTTP stops the message attempt with controlled outcome-unknown/blocked text,
without automatically reclaiming or resubmitting content or replaying a write.
An already-sent operation can finish once; late results cannot affect a newer
runtime/attempt. Leave the independently renewing lease intact. A retry starts
another exact handshake, not automatic recovery of uncertain held work.

### Scoped model tools and readiness display

Message tools require the same current ready native attempt, main-engine origin
and no subagent, current root/conversation/terminal, exact parent/child and live
lease checks. Read arguments strictly, accepting only the tool envelope fields
added by the native engine plus the schema arguments. A valid delivery ID can
refer to an earlier held message of this same authorization after explicit
reconnect; the host enforces its ownership/grant. Do not select a target from
peer text or substitute another session. Serialize message writes so overlapping
calls cannot race counters; while one is pending a concurrent call is refused
with a controlled busy/unavailable result. Changed replies still conflict under
the host API. A failed model write returns a controlled error and leaves the
ready attempt usable; the stopped-attempt rule above applies to the handoff
loop. No failed write is automatically repeated. A successful reply counts the
delivery as both seen and replied, matching the host's receipt behavior.

- `message_seen` posts `/adapter/v1/seen` with exactly `{ids:[delivery_id]}`;
  accept exactly `{seen:[]}` or `{seen:[delivery_id]}`. Return that public result.
- `message_reply` posts `/adapter/v1/deliveries/{delivery_id}/reply` with exactly
  `{content}`. Reply has exactly `sender_host_id,request_id,receiver_host_id,
  target_agent_id,session_id,delivery_id,content,replied_at` and optional `origin`.
  Validate those fields, exact captured local host as `receiver_host_id`,
  agent/session, delivery and content, optional origin bound to this agent/
  session, and valid original sender/request/time. Return only
  `{replied:true,delivery_id}`. Identical explicit retries remain idempotent;
  denied/uncertain writes show controlled error, never an automatic retry.

Never return raw provider diagnostics or private host response fields to model,
pane, command output or logs. All scoped HTTP URLs are fixed allowlisted paths;
only a validated typed delivery ID is interpolated, never model-selected paths.

Before enable, keep section6's **Incoming delivery: not verified**. During the
challenge show **Incoming delivery: waiting for model**; only after exact native
acknowledgment and host ready success show **Incoming delivery: verified
(messages)**. Display submitted, seen and replied counts separately, counting
unique successful delivery IDs. The local challenge remains separate. Keep
**Peer exchange: not verified**: a saved reply has not proved that its sender
retrieved it. No task/capability readiness claim is made.

Counters belong to the connected runtime and survive message-attempt retry;
Stop/reload/new Connect starts fresh counters. A successful `message_seen`
counts its delivery ID even when the host returns an empty `seen` list because
it was already seen. This current main-model tool call is receipt evidence;
never count that ID twice. Ready success returns `{ready:true}`.

Established enabled delivery survives pane Close/Back along with its lease.
Stop/end/reload/root/conversation/surface/host/scope/lease expiry cancels all
message timers and acknowledgment/tool authority. Closing the pane never
replays a prompt or changes consent. Explicit reconnect does not restore the
old nonce or infer readiness from a saved host channel. Expiry of an old view
or acknowledgment cannot change a newer runtime. Pending HTTP/prompts may
complete once; no more data operations are scheduled from them after stopping.

### Verification

A separate author uses this contract and public pinned native API only. Keep
the existing83 native cases unchanged: none enable this new action. Add a small
native message suite, with meaningful boundary cases rather than permutations
of every field. No new Rust tests or host API suite is necessary; run existing
`live` and `adapter_onboarding` black-box suites for underlying behavior.

1. Inert initial/Connect/reopen/reload behavior and explicit enable; exact extra
   tool schemas, no owner powers, single-flight presses, private fixed hello.
2. Matching engine/main acknowledgment and exact scoped ready response; no
   poll on queue acceptance, saved channel, wrong/stale nonce, different native
   context, plugin/subagent origin, deadline or failed ready. Repeated calls
   idempotent. Original local challenge remains separate.
3. Bounded60-second challenge, dropped/thrown/late hello, explicit fresh retry,
   and old timers/results versus a newer attempt. No automatic second prompt.
4. One message claim/submission/forwarded at a time,1000ms idle scheduling,
   independent lease renewal while blocked, exact socket/routes/headers/bodies.
5. Valid handoff -> reversible untrusted wrapper -> native accepted -> forwarded;
   no premature seen/model/peer receipt. Empty polls do not change evidence.
   Cross-session/adapter/agent, malformed/unknown fields, invalid/expired/bounded
   content and nested metadata block prompts and forwarded writes.
6. Exact seen/reply, host-bound original recipient, duplicate idempotent receipt
   counts, non-ASCII UTF-8 reply bounds, wrong context/origin/arguments, controlled
   host denial/timeout, no raw/private response leakage or retry.
7. Dropped/uncertain submission/claim/forwarded/write, Stop/Close/Back/end/reload,
   changed root/surface/scope, lease expiry and old async completions. Unknown
   content is never automatically resubmitted; older attempts cannot poll, mark
   forwarded, verify or overwrite a newer runtime. Existing lease remains live
   on a message-only failure; explicit Stop cancels both.
8. Actual pinned terminal/temporary host smoke: exact enable/challenge behavior,
   actual model acknowledgment/message/reply if the account can run inference.
   Record quota/refusal separately if unavailable. No fixture substitutes for
   model receipt. Full installed/two-machine exchange remains a tracking gate.

Selected: an explicit model-turn start, readiness bound to the current native
conversation, messages first using existing host grants, scoped tools and
conservative uncertain-handoff handling. Discarded: automatic model turns on
lease connect/reload, a saved channel as current proof, peer-authored approval,
fake receipt from prompt acceptance, consuming unsupported tasks, automatic
replay of uncertain content and silently granting outbound/directory access.
This is an implementation choice under GU-OWN1/2, not another owner decision.

## 8. Native assigned tasks and cancellation (GU-03e)

Extend section7 with explicitly enabled assigned tasks, cancellation notices and
task lifecycle reporting. This slice uses existing scoped task routes and adds
no API, schema, credential scope, membership or access grant. Outgoing task
delegation, submitter task-update notifications and artifact transfer remain
later slices. No task file is read, downloaded, uploaded or written locally.

### Enable and lifetime

Only a connected runtime with section7's **current native attempt** ready may
offer **Enable incoming tasks**. A saved host verified channel, the separate
local conversation check or a queued readiness prompt is insufficient. All
entry, Connect, message enable/ready, Refresh, reopen and reload actions remain
task-inert without this additional explicit action. Keep the original104 cases
unchanged. Display that tasks can start model turns under the current normal
model allowance and add no local tool/file permission.

The enable callback captures runtime, ready attempt and UI generation,
synchronously excludes double presses, checks current native root/conversation,
terminal, exact parent/child authorization and live lease, then registers only
the five task tools below, once per native module/session. Recheck context and
captured identities after registration before polling. An explicit restart
shares any still-pending registration in that session; late registration from
an ended conversation cannot populate the next conversation's registry.
A registration failure stops that task attempt and removes only its failed
registration from the captured session registry. Explicit Retry can register
that tool again while retaining successful registrations and sharing pending
ones. An old enable control captures its displayed message-ready proof; it
cannot enable tasks under a replacement proof in the same runtime.
Reuse this native
readiness proof; enabling tasks sends no extra hello or prompt by itself.
Do not infer a model observed a task from the message readiness challenge.

**Stop incoming tasks** cancels task polling and task-tool authority without
stopping messages/lease or changing a task/authorization on the host. Task
failure offers **Retry incoming tasks**, a fresh explicit attempt under the
still-current native ready proof. It never resubmits uncertain held content.
After an explicit Stop or a new message proof, offer **Enable incoming tasks**;
reserve **Retry incoming tasks** for a failed attempt under the same proof.
Close/Back preserve an established enabled task attempt. Stop adapter, lease/
credential expiry, root/conversation/terminal/host/scope change, session end or
reload stops task authority with the runtime. Message-attempt failure/retry
also invalidates tasks because their captured readiness proof is no longer
current. A new message proof requires explicit task enable again.

### Handoffs and validation

Poll sequentially: `POST /adapter/v1/tasks/cancels/next` with `{}`, then
`POST /adapter/v1/tasks/next` with `{}`. After each non-null handoff, validate
and submit it once before claiming another item. Start the first iteration
after successful explicit enable, then1000ms after each completed iteration.
One task/cancel claim/submission is in flight; message polling and lease renewal
remain independent. `null` changes no receipt evidence.

Every scoped task operation requires the same current runtime, task attempt and
captured ready attempt, current context/live lease and exact parent/child scope
before the request, after any asynchronous inspection and after its response.
Stopping tasks during inspection must prevent the request, even if messages
remain ready. Reuse the selected Unix socket/headers, existing authorization
inspection and five-second logical HTTP deadline. Only allowlisted task URLs
are available; only validated typed task IDs may be interpolated.

Validate existing task contracts at the native boundary:

- TaskHandoff has exactly `delivery,task,status,sender_person_id,sender_person,
  originator_person_id,delegable,redelivered,adopted,progress`.
- TaskDelivery has exactly `id,sender_host_id,task_id,target_agent_id,session_id,
  adapter_id,cancel_claimed_at,created_at`. Require the captured local adapter/
  session/agent, lowercase typed IDs, valid RFC3339 times (numeric offsets too),
  and null or valid `cancel_claimed_at`.
- TaskStatus has exactly `task_id,sender_host_id,receiver_host_id,target_agent_id,
  state,cancel_requested,created_at,updated_at,last_event`. Bind the local host/
  agent, task ID and sender across all records; known task states are queued,
  running,rejected,expired,succeeded,failed,cancelled. Cancellation is boolean,
  event sequence is a positive safe integer, and timestamps are valid RFC3339.
- TaskRequest requires `task_id,target_agent_id,deadline,input`, exactly one
  grant/policy/self citation, and optional `origin,artifacts,delegation`, with
  no unknown fields. Use section7's citation/origin and UTF-8 text bounds.
  A queued handoff requires a future deadline and `adopted:false`; an adopted
  running task requires `adopted:true` and remains valid after its acceptance
  deadline. No final-state
  task is submitted. `redelivered`/`delegable`/`adopted` are booleans; progress
  is null or nonempty text of at most65,536 UTF-8 bytes; person fields follow
  section7 and originator person is null or a typed person ID.
- Optional artifacts follow the existing manifest shape and bounds in the
  artifact contract (up to64 exact name/size/sha256/media_type entries, unique
  names/digests; an empty adapter manifest means none). Validate metadata only.
  Optional delegation follows the
  existing strict Link fields/types/bounds (1..3 links, index/depth/principals,
  timestamps, IDs and canonical64-byte Base64 signature); bind its last task,
  issuer/audience and deadline to this handoff. The host verifies signatures,
  current membership, chain narrowing and grants; this frontend gains no onward
  delegation tool. Do not duplicate cryptographic membership verification.
- CancelHandoff has exactly `delivery,status`, bound as above, running state,
  `cancel_requested:true` and a valid non-null `cancel_claimed_at`. Its accepted
  task may be past the original deadline. There is no task/cancel forwarded API.

For a valid task submit one plugin-attributed prompt with original input as
reversible JSON external data and separate host-supplied correlation: task ID,
public sender host/person and origin agent, deadline, state/cancel flag,
adopted/redelivered flags, progress, artifact manifest metadata and public chain
originator/host metadata. Exclude local adapter/session/native/root/review
references, grant/policy citations, chain signatures and transport secrets.
Explain the five scoped task tools and that remote content grants no local
permission. An adopted running task must resume its observed state/progress;
do not ask the model to accept it as queued. For attachments state that this
frontend exposes metadata only and cannot transfer files: do not invent local
paths or assume file contents are available. Onward delegation stays unavailable
even if host metadata says the task is delegable.

For a cancellation submit a fixed notice with separate host-supplied task ID
and sender, explaining that cancellation is requested, not completed: confirm
`task_cancelled` only if work actually stopped, or complete its real outcome.
Never call a lifecycle tool automatically for a claim, submission or notice.

A five-second logical prompt-submission deadline, dropped/thrown submission,
malformed handoff, denied/failed claim or unknown HTTP result stops only the
task attempt with controlled text; message delivery/lease continue. Keep claimed
task and cancellation delivery IDs in memory for this runtime so an explicit
retry cannot resubmit a previously offered item. No background reclaim/write
retry or hidden task cancellation. Already-sent operations may finish once;
late responses cannot start work, update counters or change a newer attempt.

### Scoped lifecycle tools and evidence

Tools are `mcp__peerspan__` plus:

| Tool | Exact arguments | POST route/body |
| --- | --- | --- |
| `task_accept` | `{task_id}` | `/adapter/v1/tasks/{id}/accept`, `{}` |
| `task_reject` | `{task_id,reason?}` | `.../reject`, `{reason}` (default empty) |
| `task_progress` | `{task_id,message}` | `.../progress`, `{message}` |
| `task_complete` | `{task_id,status,output}` | `.../complete`, `{status,output}` |
| `task_cancelled` | `{task_id}` | `.../cancelled`, `{}` |

Typed task IDs have32 lowercase hex characters. Reason is0..65,536 UTF-8 bytes;
message/output are1..65,536 bytes. Complete status is succeeded or failed.
Reject unknown/extra arguments, including file paths/artifacts, target/sender,
session, URL or owner-operation selectors. Keep only pinned native envelope
fields as in section7. Accept calls only from the current native main engine,
without subagent origin, with current enabled task/ready attempts and exact
context/scope/lease checks. One task-tool write may be pending; concurrent calls
receive a controlled busy/unavailable denial. No automatic write retry.

The host owns held-task selection, transitions, grant rechecks and idempotency.
As in the existing task contract, a reused task ID resolves to the oldest held
task of that ID; the frontend has no sender-selection argument. Earlier held
tasks of the same current authorization remain addressable after explicit
enable/reconnect. Acceptance rechecks authorization; accepted work may continue
after its peer grant is revoked, while the native credential/context still
must remain current. Never revoke an accepted task merely from grant expiry.

Validate every successful full TaskStatus response and the expected resulting
state: accept/progress running, reject rejected, complete requested status,
cancelled cancelled with cancellation requested. Return only
`{task_id,state,cancel_requested,last_event}` to the model. No raw provider
diagnostic or private response field belongs in model results, UI or logs.
Refused/uncertain/malformed writes return a controlled error and leave the task
attempt usable; they update no frontend receipt counters.

Display task delivery separately: **Incoming tasks: enabled**, waiting/blocked/
stopped as appropriate, **Tasks submitted**, **Tasks observed**, **Task changes
confirmed**, **Cancellations submitted**. Submitted counts unique accepted
native prompts, observed counts unique sender/task pairs from successful native
lifecycle tools, and changes count unique sender/task/event-sequence results.
Identical tool retries do not inflate evidence. Counts belong to the runtime
and survive task retries, but reset on a new connection/reload. A queued prompt,
host running/final status or readiness proof alone never counts a model receipt
or completed local execution. Keep peer exchange not verified.

Task and cancellation submitted counts/deduplication use separate Delivery.id
sets: a cancellation for an already submitted task can still be offered once.

### Verification

A separate author derives a focused native task suite from this section and
public contracts/API only, preserving the original104 cases. No new host API
suite or implementer unit tests; run existing `work`, `live`, `adapter_onboarding`
black-box suites for underlying task/grant/adoption behavior.

1. Inert entry/Connect/message-ready and unsupported contexts; explicit task
   enable after exact current native proof, narrow tool schemas, no second
   hello, double-enable exclusion and no file/owner/outbound authority.
2. Sequential cancellation/task polling,1000ms scheduling and independent
   messages/lease while task HTTP or submission is pending; exact Unix transport.
3. Queued/redelivered/adopted tasks, numeric-offset deadlines and past-deadline
   running adoption, valid grant/policy/self and bounded artifacts/chain metadata;
   reversible untrusted prompts with no private refs or automatic lifecycle call.
4. Cross-session/adapter/agent/sender/host/task, malformed/unknown/nested/bounded
   handoffs, final states, expired queued task and invalid cancellation must not
   reach a prompt. Correct cancellation is a request, not an automatic stop.
5. Exact five tools, main/current origin and UTF-8/argument boundaries; validated
   bound/redacted statuses, host denial and idempotency, noninflating counters,
   accepted-task progress without a peer-grant read, serialized writes and no
   automatic retry on uncertain or malformed responses.
6. Dropped/uncertain claim/submission, explicit retry without resubmitting old
   delivery IDs, Stop tasks versus Stop adapter, Close/Back, message-proof loss,
   end/reload/root/terminal/scope/lease stops and stale callbacks/timers versus
   newer task/runtime attempts. Stop during inspection must prevent a write.
7. Record actual model task receipt/acceptance/progress/cancellation separately
   from fixtures. The existing quota-refused readiness smoke is no evidence of
   task receipt; do not repeat an unchanged unavailable inference probe. Actual
   task/model and installed two-machine acceptance remain tracking gates.

The pinned public native test kit exposes keys for the current drawing and
omits retained callback closures. Pressing an old key after redraw does not
exercise the old enable callback. Record that displayed-proof binding by source
review; actual stale-render callback refusal remains manual acceptance work,
separate from the current-proof invalidation cases this kit can exercise.

Selected: explicit assigned-task enable under a current native delivery proof,
existing host lifecycle semantics, independent task failures and separate
submission/model/update evidence. Discarded: enabling tasks on message ready,
auto-accept/cancel from peer content, a second verification model turn, artifact
file access without its integration, blanket outward delegation, unsupported
work claims, silent sender selection beyond the existing host contract and
replay of uncertain input. This is an implementation choice under GU-OWN1/2.

## 9. Exact contact-invitation review (GU-01e / GU-02f / GU-04a)

This owner-local slice prepares and decides an invitation for a teammate. It
uses the existing coordinator-free `psi2-` introduction and automatic return
path. It creates no network, person, agent, session, membership or access grant,
performs no participant approval, and exposes no native/model invitation tool.
The native human controls and joining/admission/access flows follow separately.
Use the current wire/spec invitation lifetime (one hour by default, 60 seconds
through24 hours), not the earlier300-second contract draft.

### Context and exact terms

All routes live only on owner administration under
`/v1/onboarding/invitation-flows`. Peer, bootstrap and credential-scoped routers
refuse them. Reuse section5's exact `AdapterContext` as `context`, binding the
latest attached project and its immutable review without needing an adapter
credential or a ready model. An unknown project returns404; mismatched context
or review returns409 `review_changed`.

Prepare takes exactly `{context,network_id,member,expected_person_public_key,
replace_flow_id?}`. Network ID must be an explicit lowercase `net_` plus64 hex;
never select the first network. Member follows the existing DEC label bounds:
trimmed, nonempty, no control characters, at most128 UTF-8 bytes. Expected
person is an exact canonical32-byte Base64 key or `"-"`; it pins identity only,
never possession or admission. Unknown/null fields are invalid.
Trim surrounding Unicode whitespace from member before validating, reviewing
and retaining the proposal; identical retries compare this normalized label.
Prepare returns
201 for a new review,200 for an identical retained attempt. It signs nothing,
generates no pairing secret, changes no contact sequence, and creates only a
private flow row. It neither sends nor publishes an invitation.

An identical retry resumes the original fixed terms and expiry, including a
retained terminal result. A different proposal without explicit replacement
returns409 `flow_conflict`; it cannot silently change the pending invitation.
Lookup takes exactly `{context}` and returns200 exactly
`{version:1,host_id,context,flow}` for the latest attempt for that exact project
flow, or null. Inspection is `GET /{flow_id}`. Reads are coherent and logically
read-only, including expiry/invalidation; no contact, guard, activity or secret
cleanup is a read effect.

Every flow view is exactly
`{version:1,flow_id,state,review_id,review,invitation,next_action}`. Flow IDs use
`flow_` plus32 hex; review IDs use `review_` plus64 hex. `review_id` is SHA256 of
`peerspan-invitation-review-v1\n` plus canonical recursively key-sorted JSON of
`review`, using the same canonicalization as section3. Review is exactly:

- `version:1`, `kind:"create_contact_invitation"`, `flow_id`, `host_id`, `context`;
- `agent`: the exact parent-reviewed `{id,name,owner,capabilities}`;
- `network`: `{id,name,context_id,genesis_root_public_key}`, derived from the
  verified current DEC network and exact owned host membership;
- `inviter_host_public_key`: this actual owned host, never a substituted signer;
- `member`, `expected_person_public_key`;
- `transport`: exact current `{bootstrap_addresses,quic_addresses,relays,helpers}`
  from configured connection hints, with existing bounded/sorted endpoint/key
  forms. Helpers are optional. The subsequent code discloses these reviewed
  public hints; transport success/reachability is not asserted;
- `expires_at`: the fixed review deadline,15 minutes after preparation;
- `invitation_expires_at`: a fixed deadline one hour after preparation, which
  is not extended by later approval, export, retry or lookup;
- `effects`: exactly `{create_contact_invitation:true,receive_join_requests:true,
  grant_membership:false,grant_agent_access:false,approve_machine:false,
  share_files:false,share_conversation:false,capability_calls:false}`.

Invitation labels/pins/hints are human review terms, not adapter or peer
permissions. Current own-host membership and descriptor/context are checked
from verified state. No person, device, root or SSH signer is selected or called
for a contact-only invitation. A network split, unavailable proof, expired or
restricted own-host membership or incompatible network refuses new preparation.
Changing reviewed identity, project, network context or connection hints before
approval invalidates the review; never replace terms automatically. Ordinary
authority renewal preserving these terms does not manufacture a new consent.

### Decision, private handoff and restart

`POST /{flow_id}/decision` takes exactly
`{context,review_id,decision:"approve"|"decline"}`. Check the full retained
binding, latest project attempt, current attached metadata and fixed review
expiry before a first decision. Decline durably records only the outcome.
Approval rechecks verified own-host membership and all exact network/transport
terms, then atomically creates one ordinary invitation plus its automatic-return
`dec_pending` row and records its public invitation ID in the flow. All these
writes commit together. Failure rolls back contact sequence, return secret and
flow decision. No half-issued review or second code on an identical decision.
No other signing or membership/agent/session/activity mutation is included.

The contact is signed at approval with current contact sequence/time; its
address/helper content and the invitation's final expiry are the exact reviewed
terms. The invitation can only be minted while its remaining lifetime satisfies
the existing wire bounds. Existing advanced `/v2/.../invitations` semantics stay
unchanged; it shares the same core creation path.

A valid same-choice decision retry returns the retained outcome without minting
or refreshing anything; an opposite decision conflicts. `review` becomes
`issued` or `declined`. Unissued fixed expiry derives `expired`; changed parent/
network/transport terms derive `invalidated`. An issued invitation derives
`expired` at its own fixed deadline; it need not retain a live project session
after restart, but its exact original context, verified current owned host and
network/transport terms remain required for private retrieval. Missing retained
return material invalidates retrieval; never recreate it.

Public `invitation` is null before issuance, otherwise exactly
`{invitation_id,expires_at}`. It never contains a token, return secret or signed
contact bytes. `next_action` is `review`, `share_private_invitation` for issued,
or `restart_review` for other outcomes. Inspection/lookup/decision/status and
activity never return the code. An issued ID remains visible after expiry or
invalidation, with its observed state, without claiming current usability.

Only explicit `POST /{flow_id}/handoff` with exactly `{context,review_id}`
returns200 exactly `{version:1,flow_id,review_id,network_id,context_id,
invitation_id,invitation,expires_at}`. Require the still-usable issued outcome
and return the same byte-for-byte `psi2-` code from the existing private
return material. No new secret copy is stored in this flow table. Retrieving
it changes no database records or expiry and publishes nothing. It is a private
integration response: do not put it in model context, command arguments, routine
status/logs or another conversation. Native private display/handoff is a later
slice; a code is no evidence of reachability, admission, agent access or model
receipt.

An explicit new proposal may provide the exact latest `replace_flow_id` when
that attempt is declined, expired, invalidated or already issued. This permits
inviting another teammate without waiting an hour. Never supersede a pending
review silently. A new invitation does not revoke an older exported introduction;
it stays bounded by its original expiry and later explicit participant reviews.
An older issued flow retains idempotent decision and exact private retrieval
while usable, even after a newer invitation is prepared. A superseded undecided
review has no decision authority. Do not invent global contact-token revocation.

Validation uses existing host errors:400 `invalid`,404 `not_found`,409
`review_changed`, `review_expired` or `flow_conflict` as appropriate. New
preparation propagates current DEC authority/proof errors without fabricating
membership. Logical current-state failures during view derivation give
`invalidated`; internal/corrupt storage errors remain errors. Expired reviews
return `review_expired` on a first decision. Declining also requires the exact
current, unexpired pending review; there is no implicit owner mutation.
Opposite terminal decisions and superseded undecided reviews return
`flow_conflict`. Handoff of an unissued/declined/expired flow returns
`flow_conflict`; an issued flow with changed current network/transport terms
returns `review_changed`. Same-choice terminal retries return the retained view,
including derived expired/invalidated state, without minting again.

Advanced integration commands are `peerspan onboarding invitation lookup`,
`prepare`, `decide`, `handoff`, each requiring `--stdin`, and
`inspect FLOW_ID`. For decide/handoff, stdin additionally carries `flow_id`
which the CLI removes before the exact route call. Input is at most64 KiB;
reject malformed/extra/null JSON without echoing it. This client starts no
daemon or state directory. Only handoff success prints secret JSON; the other
commands have public/private owner views without a token. None accepts a code
or approval in a positional argument.

### Storage and verification

Schema26 adds only `onboarding_invitation_flows`, with ordered TEXT columns
`flow_id,project_flow_id,request,review,review_id,state,created_at,expires_at,
invitation_id,decided_at`. The first eight are NOT NULL; the last two are nullable.
`flow_id` is primary key; `project_flow_id` references the project flow.
State CHECK is `review`, `issued` or `declined`. No foreign key to expiring return
material; expired invitation metadata remains inspectable. Upgrade through25
atomically adds this table, preserving all existing identity, DEC, registry,
project/adapter flows and events. Reserved-name collisions at an earlier
version, malformed current schema and future versions refuse without mutation.

A separate author writes one focused `invitation_onboarding` slim suite from
this contract and existing public APIs, never production code. Original native
128 cases stay unchanged; no new native test is needed before controls exist.
Update old migration fixtures only to represent the new additive table and
move the future-version boundary to27; preserve their existing assertions.
Keep suites under two minutes. No implementer-written unit tests.

1. Explicit network/context/label/pin review, canonical digest, fixed deadlines,
   prepare/lookup/inspect retry/resume and coherent read-only snapshots. Preparing
   signs/returns no code and changes only its private flow table.
2. Exact approval atomically mints one usable ordinary introduction and return
   material; public views contain no code/secret; repeated/concurrent approval
   returns the same public result, and private retrieval is byte-identical and
   read-only. Use the existing public joining path to establish code validity
   without claiming complete admission or granting agent access.
3. Decline, changed review/context/project/transport, expiration, malformed/
   extra/null input and missing/legacy network cannot mint. Cover fixed-deadline
   races and rollback after mint work if a flow update fails. No secret in errors.
4. Explicit replacement and another teammate; no silent draft change, old-token
   revocation or replayed old pending decision. Retained issued retrieval after
   host restart does not resurrect a project attachment or duplicate invitation.
5. CLI parity, private stdin and bounds, unavailable daemon with no state writes;
   owner-only routing refusal on peer/bootstrap/scoped interfaces.
6. Additive schema25→26, preserved records, reserved table/view/index/trigger,
   malformed-current and future27 refusal. Keep schema24/25 gates intact.

Schema-only rollback fixtures may install a temporary aborting trigger on the
flow decision update; do not fabricate or edit protocol/authority rows. Current
public APIs cannot create an authentic legacy network: absent a retained
historical fixture, legacy-mode refusal is source-reviewed rather than claimed
as a passing black-box case.

Selected: exact durable contact-only review, current own-host signing, fixed
expiry, one atomic return-path publication intent, private explicit retrieval
and explicit additional invitations. Discarded: first-network defaulting,
contact possession as membership/access, hidden admin/root signing, auto-refresh
of consent, showing codes through status/model tools, duplicating plaintext
secrets in a new flow table and pretending a newer invitation revokes an old one.
These are implementation choices under the accepted GU experience.

## 10. Native Invite someone review and private reveal (GU-03f / GU-04b)

This frontend consumes section9 without changing its host APIs, schema or
permissions. It uses the existing terminal pane in the current conversation.
Joining, admission, device approval and agent-access reviews follow separately.
An invitation is a private introduction, not membership, access or readiness.

### Entry, choice and exact review

Only an attached project exposes **Invite someone**, independent of adapter or
model readiness. Initial load, headless entry, ordinary Refresh, project or
adapter approval and model tools never begin an invitation. Explicit entry
checks the current native root/conversation/terminal, exact attached parent and
host, then calls invitation lookup with `{context:AdapterContext}`. Resume the
retained outcome before offering a new proposal. Refresh of an active view is
read-only and hides any revealed code immediately. Every local process uses the
configured literal executable/state argv, a five-second timeout, and stdin for
private bodies. No daemon startup or HTTP shortcut.

For a missing attempt, read a fresh owner onboarding observation, validate the
host and unique canonical network IDs, and offer explicit choices with quoted
names and full public network IDs (to distinguish duplicate names). List ten
per page. No first-network default, no implicit network creation, no arbitrary
ID input. Legacy/unusable selections may be refused by the host; a listed
network is no invitation authority. An empty list explains that a network must
first be created through existing administration. Do not fabricate readiness.

After explicit network choice, offer editable **Invitee label** (initially
empty) and **Expected person public key** (initially `-`, meaning unpinned).
Validate/trim the label using section9's bounds; an invalid draft sends nothing.
A pin is canonical32-byte standard Base64 or `-`. **Review invitation** alone
prepares the explicit proposal. Require the returned review to match the chosen
network ID, normalized label and pin; no silent replacement or preparation on
Refresh. Retained terminal outcomes offer **Invite another person** (issued)
or **Review a replacement invitation** (declined/expired/invalidated). This
returns to explicit network choice with the exact latest `replace_flow_id`;
explain that another invitation does not revoke an older exported code. Back
or failed/uncertain work never prepares or decides automatically.

Validate exact section9 flow/lookup/review shapes, typed IDs, keys, bounds,
state/action/result consistency, fixed deadlines and exact effects. Display all
review terms before controls: project, current conversation, agent and owner
labels/capability metadata, network name and public ID, context ID, genesis and
inviter public keys, invitee label, pin (or unpinned), full public bootstrap/
QUIC/relay/helper hints and keys, both expiries and every effect. These public
identity references are deliberate human review terms, distinct from private
flow/native-session IDs, which remain internal. Quote raw human strings
reversibly, escaping terminal/bidi controls; private-looking prefixes in any
metadata/hint block the review. Never display raw provider output/errors.

**Approve invitation** and **Decline invitation** capture the exact rendered
view/epoch/parent/flow/review. Synchronously exclude double presses. Before a
decision, recheck native context/terminal/host (including a fresh owner
observation), inspect the parent and invitation,
require exact immutable review equality and pending state/unexpired deadline,
and check current context again before sending the captured stdin decision.
Approval must return that same issued flow and public invitation metadata;
decline that same declined flow. Neither action reveals/exports a code.
A lost result shows controlled unknown-outcome text. Refresh looks up what
committed, never replays a decision or creates another invitation.

### Private human handoff

Only an exact issued view offers **Reveal private invitation**. Explain before
reveal: share privately with the intended person; do not paste into this or
another agent conversation; possession grants no membership or agent access.
Recheck current native context, terminal, exact attached parent, exact issued
flow and invitation deadline before calling `handoff --stdin`. Bind the exact
response fields/version to the captured flow/review/network/context/public
invitation ID/expiry; accept only a nonempty unpadded Base64URL `psi2-` code of
at most32KiB. Cryptographic validity remains the host's responsibility, using
its retained verified invitation; the frontend does not implement another
signature verifier. No code is accepted from model arguments or arbitrary URL.

Show the complete returned code only in the current terminal pane after this
explicit reveal, with **Hide private invitation**. No clipboard write, file,
plugin storage, notice, logging, command response, prompt, model tool/result,
telemetry or session message carries the code. It exists only in the current
private UI memory and bounded process response. Hide drops the reference;
reveal again re-inspects and retrieves the original code, never mints another.
The user may select/copy the revealed terminal text through their terminal.
This slice provides no clipboard automation or recipient import control.

Hide and cancel authority on Refresh, Back, Close/Escape, root/conversation/
host/terminal loss, parent change, session end, plugin reload and expiry. A
strict timer removes a revealed code at the original invitation deadline; a
late response, stale callback or old timer cannot reveal/decide another view.
All async completions recheck the captured view, context and clock before
publishing private data. Surface changes detected by render or a subsequent
action fail closed; no background surface subscription is claimed. Existing
established message/task/lease runtimes survive ordinary pane navigation;
existing runtime context/expiry/Stop rules remain unchanged. Opening an
invitation does not submit a model prompt, claim work or change any lease.

### Verification

A separate contract-only author extends the pinned native runtime tests using
public effects only, never production imports. Keep the original128 cases
unchanged; implementers add no unit tests. Reuse the existing real-host
invitation_onboarding suite. Do not invent retained-handler APIs: the pinned
kit only presses the current drawing. Old-render callback refusal receives
source review/manual evidence, while async/timer races use public boundaries.

1. Inert initial/headless/load/Refresh/model actions; attached-only explicit
   entry, exact parent/context/host/terminal checks, lookup before new choice.
   Empty/multiple/duplicate-name networks, ten-per-page explicit selection,
   invalid/duplicate IDs and malicious metadata fail safely.
2. Draft validation, exact literal argv/stdin, no default network, no implicit
   prepare/replacement; returned proposal binding, complete quoted review and
   all effects. Malformed/unknown/private-looking fields, changed scopes and
   mismatched refs expose no approval/reveal controls or raw diagnostics.
3. Exact approve/decline, inspect ordering, double presses, changed parent/
   review/context/deadline, failure/lost result, terminal resume/replacement.
   Refresh is read-only; approval never calls handoff or model APIs.
4. Explicit issued-only reveal after inspections, exact response binding and
   code bounds; repeated reveal returns original host material. Code appears
   only in private terminal drawing, never prompts/tools/logs/store/files/
   notices/command responses/argv. Invalid/error/late results remain private.
5. Hide/Refresh/Back/Close/end/root/session/host/terminal loss and fixed expiry
   clear reveal and invalidate pending work. Old async responses/timers cannot
   restore it or alter a new view. Existing adapter/messages/tasks stay intact.
6. Actual pinned native terminal with a temporary real host: select network,
   prepare/review/approve/reveal/hide, Close/reload/resume without another mint.
   Record exact source and binary provenance, retained public outcomes, private
   code absence from transcript and zero inference; no installed/two-person/
   peer reachability or model receipt claim.

Selected: explicit network choice, exact contact-only human consent, separate
private reveal through the native pane, and read-only recovery. Discarded:
first-network selection, automatic issuance/export/copy, secret files/plugin
storage, model-facing owner tools, frontend signature reimplementation, hidden
recipient admission/access and newer invitations as revocation. These choices
implement the accepted GU flow; no new owner confirmation is attributed.

## 11. Recipient invitation inspection (GU-01f / GU-02g / GU-04c)

This working slice lets a recipient privately inspect an introduction before
choosing an original person or creating a join request. It verifies the existing
wire invitation and displays its exact public terms. It creates no identity,
flow, signing intent, contact, request or network and publishes nothing. Joining
identity consent and the owner/administrator/access reviews follow separately.
A valid signature establishes the signer of the introduction, not its current
membership, authority, reachability or identity verified outside Peerspan.

### Private owner-local preview

`POST /v1/onboarding/invitation-preview` takes exactly `{context,invitation}`.
Context is section5's exact AdapterContext for the latest attached project;
an adapter credential or ready model is unnecessary. Require its current exact
attachment. Invitation is the exact private `psi2-` string, at most32KiB, with
no implicit trimming. Accept only the existing canonical signed wire format,
including its descriptor/context/root-derived network ID, inviter signature,
expected-person pin, label, one-hour default/60s..24h window, bounded sorted
helpers and each signed contact. Old contacts inside a live invitation remain
hints under the existing wire rules; an expired invitation never becomes valid
through those hints. Reuse the core Invitation verifier, not another parser.
Legacy invitations without an automatic-return secret remain inspectable.

Read context and metadata from one SQLite read transaction, with one current
coordinator-free decision time. No network I/O, cleanup, signing, key access,
identity selection, daemon startup or database/file write is an inspection
effect. Invalid code, signature, descriptor, contact, time, private JSON bounds
or context fails closed. Require exactly the request fields: duplicates at any
nesting level, unknown fields, nulls, trailing JSON and a body over64KiB refuse
without echoing private input. Preserve existing host error conventions:
400 invalid input,404 unknown parent,409 review_changed for context/attachment,
and the existing wire409 expired,403 not_yet_valid or409 quota_exceeded
errors. New body/code byte-bound refusals use400 invalid. Errors contain no code,
return secret or signed payload. The route exists only on owner administration;
peer/bootstrap/scoped routers refuse it.

Successful200 is exactly `{version:1,host_id,context,review_id,review,
next_action:"choose_join_identity"}`. Review is exactly:

- `version:1`, `kind:"inspect_contact_invitation"`, `host_id`, `context`;
- `agent`: exact parent-reviewed `{id,name,owner,capabilities}`;
- `network`: `{id,name,context_id,genesis_root_public_key}` from the verified
  signed descriptor;
- `inviter_host_public_key`: the verified actual invitation signer;
- `invitation`: `{id,member,expected_person_public_key,issued_at,expires_at,
  automatic_return}`; id is the verified public `di_` reference,
  automatic_return is a boolean indicating whether return material is present,
  never its value. The pin is canonical Base64 or `-`;
- `contacts`: original verified order, at most4, each exactly
  `{sequence,issued_at,expires_at,quic_addresses,bootstrap_addresses,relays}`.
  Sequence is a canonical decimal u64 STRING (0 through18446744073709551615)
  to preserve all bits through JS.
  Times and all public hints/relay keys are exact verified terms. Host/context
  repeat the invitation signer/context and need not be duplicated here;
- `helpers`: exact verified public `{address,public_key}` pairs;
- `effects`: exactly `{verify_contact_signature:true,create_identity:false,
  create_link_request:false,select_owner:false,grant_membership:false,
  grant_agent_access:false,approve_machine:false,share_files:false,
  share_conversation:false,capability_calls:false}`.

No raw invitation, return secret, payload_base64, signed contact bytes, signing
request, keys or model data are returned. Public signer/root/helper keys are
review terms, never private key material. Preserve signed labels exactly;
frontends must refuse private-looking metadata rather than redact exact reviews.
`review_id` is SHA256 of `peerspan-invitation-preview-v1\n` plus canonical
recursively key-sorted JSON of review, prefixed `review_`. Repeated reads of the
same code/context/parent yield the same review/hash while usable. This hash is
a content reference, not durable consent or an approval capability; no decision
route is added. Inspection does not retain the incoming code in host storage.

Advanced integration command: `peerspan [--state DIR] onboarding invitation
preview --stdin`, with the same exact body/response and strict64KiB stdin
handling. It uses the selected existing owner socket. Input/code is never an
argument or routine diagnostic. Root help and all existing commands stay intact.

### Native private recipient entry

An attached project offers **Review an invitation**, independently of inviter
controls and adapter/model readiness. Initial load, headless entry, Refresh,
project/adapter/inviter approval and model tools never enter or inspect a code.
Explicit entry captures/rechecks the native root/conversation/terminal, host
and exact attached parent before showing an initially empty **Private invitation
code** field. Explain that this is a private human pane, not an agent chat; the
field is visible terminal text (the pinned Input has no masking facility).
No clipboard read, file import or cross-session message is added.

Typing only changes a bounded volatile draft. **Inspect invitation** alone
validates the `psi2-` prefix/Base64URL syntax/32KiB limit, clears the raw code
from the current drawing synchronously, rechecks current native context and
parent plus a fresh owner host observation, and sends exact `{context,
invitation}` through literal `onboarding invitation preview --stdin` argv with
five-second timeout. No code in argv. Input submission/Enter only updates the
draft; it does not inspect or approve. Double presses send at most one request.
Malformed/oversized input clears the draft and sends nothing.

Validate exact response/review/inner shapes, canonical public IDs/keys, bounds,
fixed effects and canonical digest, captured host/context/agent and the current
clock before displaying it. Do not implement a frontend signature verifier.
Render all project/agent metadata, network identity and root, inviter key,
invitation public ID/member/pin/times/return availability, each full contact's
sequence/times/public hints/relay keys, helpers and every effect. Quote raw
human strings reversibly using the existing terminal/bidi escaping; any
private-looking metadata blocks the entire review. Native flow/session IDs
stay internal. No raw provider output, errors, signed bytes or code appear in
the preview, command response, prompt, model tool/result, storage, log, notice,
file or another conversation. The typed code exists only in current private
UI memory and the bounded local process response/request boundary.

The displayed status is **Invitation: signature verified** with clear text
that signer membership/authority, admission, agent access, reachability and
model receipt are not established. Show that identity selection and joining
are subsequent work; offer no Approve/Join/Continue button that cannot perform
that next step. **Inspect another invitation** explicitly starts a fresh empty
private draft after rechecking context/parent. Back/Close leave no retained
recipient draft/review; a later entry starts empty. Existing issued inviter
outcomes remain durable and separate.

Clear the private code/review and pending callback authority on Refresh,
Back, Close/Escape, root/conversation/host/terminal/parent loss, session end,
reload and invitation expiry. Recipient Refresh closes its volatile view; it
never reuses the code or performs another preview. Recheck context/surface on
render/action; no unimplemented background subscription is claimed. A strict
expiry timer hides the verified preview; late responses or old timers cannot
publish into another view. Errors show controlled unavailable text and require
explicit re-entry; no automatic retry. Opening either native inviter/recipient
pane clears the other's volatile human view and pending callback authority,
without revoking its durable outcome or changing an established adapter,
message or task runtime. No new model tool, inference, readiness or work claim.

### Verification

A separate contract-only author extends the existing invitation_onboarding
slim suite and adds focused pinned native runtime cases. Preserve its original9
host cases and original148 native cases. No implementer unit tests. No new
schema or migration fixture changes. Use public APIs/CLI and independently
constructed signed wire fixtures where a negative case requires them; never
fabricate host authority/protocol database rows. Keep each host suite below
two minutes using the debug clock. No signature validity is claimed from stubs.

1. Distinct real inviter/recipient hosts: exact signed network/signer/pin/label/
   contacts/helpers/expiry/return availability, digest, same-code retry,
   read-only snapshots, no new identity/network/link/flow/outbox/events and
   no code/secret/signed blob in responses. Live invitation with stale contact
   hints and legacy no-return invitation inspect correctly without I/O.
2. Bad signature/body/descriptor/context/contact/endpoint/key/order/expiry,
   unknown/mismatched/detached/replaced parent, strict JSON/stdin bounds,
   unavailable daemon and wrong/non-owner methods/routes refuse privately.
   Independent wire fixtures may sign malformed payloads to reach validation.
3. Native attached-only explicit entry, empty draft, no implicit reads or
   clipboard/files, draft-only Enter, exact literal argv/private stdin, one
   explicit request/double press, complete exact quoted preview and effects.
4. Malformed/changed/private-looking response terms, digest/host/context/agent,
   expired and late results cannot display a verified preview. Code appears
   only in the explicit input drawing and bounded stdin, never in prompts/
   tools/output/storage/diagnostics. Rendering does not claim membership.
5. Refresh/Back/Close/end/root/host/terminal changes, fixed expiry, old async/
   timer results and switching inviter/recipient panes clear private state
   without changing durable outcomes or an established delivery runtime.
6. Actual pinned terminal with two temporary distinct hosts: paste privately,
   inspect the real code, observe exact public terms and no identity/request
   creation or model turn; close/reload returns empty. Suppress private input
   capture and record source/binary provenance. Installed, physical-machine,
   two-person admission/access and real-model exchange remain later gates.

Selected: verify and display an incoming introduction before any identity or
request creation, private volatile native input, core wire verification and
explicit separation from consent. Discarded: code in chat/model tools/argv,
automatic key generation/import/join, treating signer possession as authority,
new persistent secret copies, frontend cryptography and a nonfunctional Join
button. These implement the accepted GU flow without a new owner decision.

## 12. Exact recipient join-request consent (backend)

This slice implements owner-local review and publication of a join request for
one explicitly supplied original person public key. It does not discover,
import, generate, persist or sign with a person key. The calling human flow
must select an existing original identity, or explicitly create and safely save
a new original key before publication. A public-key selection is not proof of
possession. Joining an existing person on another computer uses the separate
machine-linking ceremony; never copy an original key to make this flow work.
Native identity selection and this backend's native controls are subsequent
slices. Section11's read-only inspection remains unchanged.

All routes are private owner administration; neither adapter nor peer routers
expose them. Strict exact-field JSON (including nested context, duplicate keys,
nulls and trailing JSON) and a 64KiB bound apply. Tokens remain exact, at most
32KiB and never trimmed: `psi2-` followed by nonempty Base64url characters,
without padding or whitespace. A different well-formed code on approve is
409/review_changed; malformed token syntax is400/invalid. Existing DEC verification
errors retain their codes. No endpoint starts a daemon, chooses a key or makes
an inference. CLI commands take private JSON only through required `--stdin`:

| API | CLI | Exact body |
| --- | --- | --- |
| POST `/v1/onboarding/join-flows` | `onboarding join prepare --stdin` | `{context,invitation,person_public_key}` with optional non-null `replace_flow_id` |
| POST `/v1/onboarding/join-flows/lookup` | `onboarding join lookup --stdin` | `{context}` |
| GET `/v1/onboarding/join-flows/{id}` | `onboarding join inspect ID` | none |
| POST `/v1/onboarding/join-flows/{id}/decision` | `onboarding join decide --stdin` | `{context,review_id,decision}`; approve additionally requires `invitation` |

Legacy invitations without automatic return remain eligible; no return or
delivery is promised. A person-pin mismatch returns400/invalid.

CLI decide additionally takes `flow_id` in stdin and removes it for the route.
`decision` is exactly `approve` or `decline`. Decline forbids `invitation`;
approve requires the same exact code as prepare, including on an outcome retry.
No token, seed, signed packet, return capability or display/reply code appears
in these responses, CLI errors, argv, activity or the new table.

Prepare verifies the ordinary signed invitation and person pin, and requires
an exact current attached project/agent. `person_public_key` is a canonical
Ed25519 public key, never `-`. No automatic person selection is permitted.
Preparation writes only a public review; no request/device key, network,
outbox, invitation-return update or protocol frame is created. Store only the
code's SHA256 digest and the complete public preview from section11, not the
code or signed bytes. This digest is an internal equality binding, not access
or possession proof.

The public response is exactly `{version:1,host_id,flow_id,review_id,state,
review,outcome,next_action}`. Review is exactly `{version:1,
kind:"create_join_request",flow_id,host_id,context,agent,invitation_review_id,
invitation,person_public_key,expires_at,effects}`. `invitation` is the complete
public section11 review; `invitation_review_id` is its section11 digest.
`expires_at` is the earlier of invitation expiry and guarded prepare time plus
15 minutes, fixed on first prepare. Effects are exactly
`{create_identity:false,create_link_request:true,publish_request:true,
select_owner:false,grant_membership:false,grant_agent_access:false,
approve_machine:false,share_files:false,share_conversation:false,
capability_calls:false}`. Publishing permits the ordinary encrypted automatic
return and transport workers after commit, without proving delivery. Digest:
`review_` plus lowercase SHA256 of `peerspan-join-review-v1\n` followed by the
recursively sorted canonical review JSON. A new `flow_` ID uses16 random bytes.

States are `review`, `declined`, `requested`, `expired`, `invalidated` or
`replaced`. `outcome` is null until requested, then exactly the immutable public
`{request_id,network_id,context_id,person_public_key}`. Requested records report
publication consent, never membership, readiness, receipt or current request
completion. The ordinary request inspection supplies later state. Next actions
are respectively `approve_join_request`, `none`, `await_participant_reviews`,
`review_replacement`, `review_replacement`, `review_replacement`.

Validate exact parent context before proposal lookup/resume. After that check,
a different key/code proposal conflicts before new invitation/pin verification;
pin-refusal fixtures use a fresh binding.

One latest flow per project binding is resumed: identical prepare returns200
and the retained view, never extends time or regenerates anything; a different
proposal without explicit replacement returns409/flow_conflict. A first prepare
returns201. Replacement requires the exact latest `replace_flow_id` and refuses
while that flow is effectively `review`; requested/declined outcomes may be
replaced immediately. Replacing a requested outcome does not cancel
or revoke its protocol request. Older reviews become replaced and cannot mutate;
requested/declined outcomes remain recorded. Lookup is read-only and returns
exactly `{version:1,host_id,context,flow}` with null when absent. Inspect, lookup
and retry do no transport I/O or cleanup.

New decisions require exact flow/context/digest, the latest review, its fixed
unexpired deadline and the current attached parent/agent. A changed binding or
parent returns409/review_changed, an expired review409/review_expired, and a
conflicting/already opposite decision409/flow_conflict. Approval re-verifies the
same signed code and person pin before signing. Create the existing new-mode
request with exact network/person, migration `-`, invitation and its signed
helpers, using the existing host/device signing, limits, staging and replay
rules. The ordinary device key, request, encrypted frames/contact and public
flow outcome commit in one SQLite transaction. A storage, quota, protocol,
parent, pin, code or review failure rolls back all of them. Publish only after
commit. No original-person key is read or generated, and no owner selection,
requester selection/commit, admission, trust or agent permission is approved.

An identical live request already created through the ordinary CLI may be
reused under its existing exact-intent rules; the outcome must name that same
request. A recorded approve/decline retry returns the recorded outcome even
after expiry/restart/context loss, without re-running request creation, sending,
cleanup or code validity checks. It still checks exact context/digest and, for
approve, the original code digest. Opposite decisions conflict. Cancelling or
expiring the underlying request does not let an old approval create another;
only a new explicitly prepared and approved flow can do so.

Schema27 adds only `onboarding_join_flows`: public proposal, code digest,
review/digest, parent reference, fixed times, decision and public outcome.
Migration26→27 and validation are atomic and fail closed on reserved names,
malformed retained table or future28, preserving older tables and authority.
The final suite uses latest27/future28; these supersede historical future-version
examples in sections3/5/9 while preserving their original migration sources.
The new table is not a second secret store. Main's older binary cannot reopen
this database; retain the integration's installed-upgrade/recovery merge gate.

### Verification

A separate contract-only author creates a small `join_onboarding` slim suite
and extends the CI matrix. No implementer tests. Preserve prior assertions;
mechanically advance only latest/future schema expectations and account for
the additional empty table in existing migration snapshots. Keep each suite
under two minutes with the debug clock. Use public APIs for protocol authority;
SQLite mutation is limited to migration/failure-injection fixtures.

1. Two distinct real hosts: signed introduction, attached recipient, exact
   public nested preview/key/digests/expiry/effects, no request/key/protocol side
   effects on prepare, identical200 resume, lookup/inspect pure and private.
2. Explicit approve creates exactly one ordinary request with exact pins and
   helpers; immutable sanitized outcome; repeat/lost-response/restart replay
   keeps the same request/device/frames and expiry. Existing exact advanced-CLI
   requests reuse safely. Cancellation followed by old approval creates nothing.
3. Decline/retry, opposite decisions, different key/code, pin mismatch,
   expired/future/bad-signature introduction, wrong/detached/replaced parent,
   digest/context changes and explicit replacement refuse or resume as specified.
4. Inject failure of the public outcome update after protocol writes: all
   request/key/frame/contact and outcome changes roll back. Retrying afterwards
   succeeds once. Protocol quota failures also leave the flow undecided.
5. Strict JSON/stdin/body/code boundaries and route/method/credential separation;
   no code, secret, key seed or signed blob in public replies, errors, activity
   or the new table. CLI is literal stdin, no lifecycle/key setup or hidden I/O.
6. Additive26→27 migration, reserved names, corruption, future28 and rollback;
   original155 Rust tests,162 native cases and all prior slim cases retained.

Selected: durable exact public-key/publication review, no extra secret store,
and one transaction around the existing protocol request and consent outcome.
Discarded: key generation on preview, treating a supplied public key as owner
proof, making admission/access implicit, partially committed approval/request,
a second pairing protocol and retrying an old approval into a new request.

## 13. Native joining with an existing local original identity

This slice connects the section12 backend to an explicit human terminal flow.
It supports original person keys already on this machine: the normal generated
person file and Ed25519 identities available from its SSH agent. It neither
creates/imports/copies a person key nor signs a person ceremony. New-person
creation and same-person device linking remain later separate actions. No
available key is an honest unavailable state, not permission to create one.

### Local identity choices

`peerspan onboarding join identities --stdin` takes exactly `{context}` with
section12's strict64KiB JSON/stdin validation. It has no new API or schema.
Read the exact project flow and public host identity from the existing private
owner API; require attached state and exact flow/review/root/native session/
integration binding before reading local identity sources. Recheck the exact
parent/host after inventory. A missing daemon never starts one or initializes
state. Return only `{version:1,host_id,context,identities}`. Each identity is
exactly `{public_key,sources}`; `sources` is a nonempty ordered subset of
`["generated","ssh_agent"]`. Deduplicate by public key, merge sources, sort by
canonical public key, and bound the list to64 entries, failing closed if larger.
No default selection, comments, filesystem/socket paths, timestamps, private
keys, signatures, secret references or provider diagnostics are returned.

Read only the normal `$XDG_CONFIG_HOME/peerspan/person_ed25519` path, falling
back to `$HOME/.config/peerspan/person_ed25519`. Missing file is not an error.
An existing file must be a regular, non-symlink, current-user-owned private file
(mode has no group/other bits), bounded64KiB and a valid unencrypted OpenSSH
Ed25519 private key. A malformed/insecure/unreadable file fails privately; do
not mask it by falling back to another identity. Never chmod, create, import,
write public sidecars or initialize directories. Agent inventory requests only
public identities, with no signing; use existing bounded agent transport. A
missing/nonanswering agent contributes no available keys, never a fabricated
identity. Ignore unsupported/invalid public keys and omit all agent comments.
The daemon never receives original key bytes or an SSH-agent socket path.
Native identity-inventory processes use a15-second budget around the existing
10-second agent response bound plus owner reads; other native joining process
calls use5 seconds. An outer black-box subprocess deadline must allow those
transport and owner-read budgets.

### Native entry, choice and exact review

Add attached-only **Join a network**, distinct from section11's unchanged
read-only **Review an invitation**. Enter only from the current terminal
conversation/project. Recheck the native context/surface and exact parent/host
around every asynchronous effect. On entry, use section12 lookup before any
private input or local inventory; no implicit preparation or publication.

No flow starts a fresh empty **Private invitation for joining** field. Enter
updates the draft only. **Review joining identities** clears the drawn input
synchronously, verifies the ordinary incoming invitation through section11's
private stdin preview, validates its complete public terms/digest/bindings and
current clock, then explicitly inventories local identities. Only this joining
lane may retain that code in volatile private UI memory for the same attempt;
never render it after submission or put it in a model tool/prompt/result, argv,
files, logs, notices, plugin storage or another conversation. Invalid/oversized
input clears and sends nothing. The older inspection lane still drops its code
without retention and offers no joining controls.

Show the full public signed invitation terms and all available identity keys
and their provenance, quoted with the existing reversible terminal escaping.
List up to10 keys per page, with **More identities** / **Previous identities** pagination, no preselected/default
identity and no silently filtered person pin. Display the invitation's expected
person key and explain mismatches. Only a matching pinned identity is selectable;
unpinned introductions offer each key. Choosing an identity is an explicit
**Review identity KEY** action. No key or no matching key explains that an
existing original identity is required and that new-identity/device workflows
are separate; do not offer an inert Create/Continue/Approve control.

Before prepare, recheck current local inventory and require the selected public
key and its source list to remain identical. Then use section12 private stdin
prepare with exact context/code/key and optional explicit replacement. Validate
all top/review/nested shapes, canonical review digests, captured host/context/
agent/code-public-preview/person pin, fixed effects, next action, immutable
outcome and fixed deadline. Render the complete section12 review, including all
nested section11 terms, selected original public key, expiry and publication
versus authority effects. Native flow/conversation references remain internal.
No key file path or raw provider output is displayed.

**Approve join request** and **Decline join request** are separate human actions.
Both re-inspect exact parent and retained flow before submission, bind the same
review, and refuse changed/expired/non-review terms. Approve additionally
rechecks the exact selected local identity availability/provenance and retains
the code only until the bounded private stdin call completes/fails. A fresh host
observation follows these reads immediately before any decision/private-code
submission. The owner API still performs atomic final authorization. Nothing
selects an owner, approves membership/machine powers, requester selection/commit,
agent access, capabilities, directory or conversation sharing. No model turn,
readiness challenge, scoped tool or inference is added.

Success is **Join request: publication recorded**, showing the immutable public
outcome's network/person and the explicit limit: this records publication only;
participant approval/current link state, access, reachability and model receipt
are not verified. Never call this a connected or joined network. No polling or
hidden protocol advancement. A failed/uncertain decision drops the private code
and offers only reopening/lookup; do not automatically retry or re-sign.

### Resume, replacement and cleanup

Lookup resumes public requested/declined/expired/invalidated outcomes without
inventory, code retrieval, request creation or retries. A retained live review
shows its exact public terms but requires explicit private code re-entry through
**Check invitation for this review**. Call identical section12 prepare and
require exactly the same flow/review/person/public terms; a separate preview
request is not needed on this exact retained-code path. This binds the exact
original code without storing a second copy. Inventory must explicitly confirm
the selected identity before enabling Approve. Decline does not require a code
or an available signer. No original private key or signature is sent to the
host. Ordinary backend public-key selection still is not possession proof.

**Review another join request** is explicit replacement, only for a non-review
retained outcome, preserving the exact latest replace_flow_id. It starts an
empty draft. Replacing publication does not cancel/revoke the earlier request;
show that limit. Refresh clears the private attempt synchronously, then reloads
the public join view through lookup only if the exact host/context/attached
parent remain unchanged and no newer navigation/action superseded its clear.
It performs no inventory; live reviews return with empty private input and no
Approve authority. New lookup/Refresh never reuses a retained code, prepares a
flow, publishes a request, signs or creates a person key.

Clear the private code, review-choice authority and pending callback authority
on Refresh, Back, Close/Escape, session end/reload, invitation/review expiry,
root/conversation/host/surface/parent loss and pane switches. Recheck freshness
on render/action; no unimplemented subscription is claimed. Late responses,
old timers and double presses cannot publish into another view. Preserve
established adapter/message/task runtime and all durable protocol outcomes
through ordinary pane navigation. Context loss stops them under existing rules.
The existing inviter/recipient panes and the new joining pane exclude one
another's volatile views; do not revoke each other's durable outcomes.

### Verification

A separate contract-only author extends `join_onboarding` with small CLI/source
cases and adds focused pinned native runtime cases; preserve all original6 host
cases and162 native cases. No implementer unit tests. No migration change.

1. Real private generated key and real SSH-agent identities: exact sorted,
   deduplicated public keys/provenance, multiple-key choice, comments omitted,
   no key/file/signature/state mutations. Missing daemon, wrong/detached parent,
   malformed/oversized JSON, agent unavailable, bad/symlink/insecure/oversized
   generated file and >64-key bound refuse or report available keys as specified.
2. Native attached-only entry and lookup before input; empty private draft,
   draft-only Enter; explicit preview/inventory, exact argv/stdin, no default
   selection, full quoted terms and pagination; pin/no-key/mismatch conditions
   cannot enable approval. Selecting a key only prepares a public review.
3. Exact review/Approve/Decline, fresh parent/flow/identity/host before effects,
   exact bounded private stdin and no duplicate press. Changed public/digest/
   context/host/identity/provenance/pin/expiry refuses before mutation; altered
   provider/error/private-looking terms never render or reach model context.
4. Public outcome resume/reload, private review re-entry, exact same-code prepare,
   explicit replacement and uncertain response recovery without automatic retry.
   Refresh/Back/Close/end/root/surface/host/parent/expiry and late callbacks/timers
   clear private authority while preserving durable publication/runtime.
5. Actual pinned terminal with distinct temporary hosts and an existing original
   recipient key: private paste, explicit choice/review/approval, one ordinary
   pending request and no person-key writes or participant/access approvals;
   reopen retrieves public outcome without private code or request regeneration.
   Capture source/binary provenance without private input or model activity.
   Installed/physical-machine/new-person/admission/access/model gates stay open.

Selected: an explicit existing-local-key choice and exact durable publication
review, one volatile joining input, read-only recovery and the existing atomic
protocol backend. Discarded: first-key defaults, arbitrary key-path imports,
automatic original-key creation/copy, signing ownership on selection, private
codes in chat/argv/storage, hidden request retries and publication as readiness.

## 14. Explicit new original identity creation

Section13 remains the existing-key path. This additive slice permits a new
person with no available local original identity to explicitly create one,
then separately choose its saved public key for section12. Creation is local
identity persistence, not possession proof, membership, machine linking, request
publication, access or readiness. Schema27 and all owner/peer APIs are unchanged.

### Explicit local command

`peerspan onboarding join create-identity --stdin` takes exactly
`{context,decision:"create_new_identity"}`. Use strict duplicate/unknown-field
rejection at every level, section12 context validation and the64KiB stdin bound.
No private invitation, seed, passphrase, path, label or key argument is accepted.
This owner-invoked command is the consent to generate and save a new original;
there is no preview-time generation. It starts no daemon and initializes no host
state. Recheck section13's exact attached parent and host before local inventory,
again immediately before the write, and after persistence. Read-only inventory
must report zero available identities. An existing generated entry (valid or
invalid, including a dangling symlink) or an available Ed25519 SSH-agent identity
refuses creation; never silently replace, adopt or return an existing original.
Agent unavailability still means no available agent identities under section13.
The command uses the same15-second native budget as inventory.

On success return exactly `{version:1,host_id,context,identity}` where identity is
exactly `{public_key,sources:["generated"]}` with the canonical saved Ed25519
public key. No private bytes, signature, path, comment, timestamps, debug/provider
output or new durable review appears. All failure output is a controlled private
message, including filesystem/agent/owner failures. No original key bytes go to
the daemon. Work that reads/generates/persists identity material runs off the async
worker. The normal file remains consumable by existing original-key discovery.

Persist to the normal generated path from section13 only. Require an absolute
path without parent traversal. Walk/create directories without following any
symlink; existing ancestors must be root/current-user owned and not writable by
another user (root-owned sticky directories such as /tmp are permitted). The
final peerspan directory must be current-user owned with no group/other bits;
new directories use0700. Refuse an insecure existing directory; do not chmod
existing files/directories or repair/import them. Never write a public sidecar.

Write one valid unencrypted OpenSSH Ed25519 private key (no invitation or user
comment) into a unique exclusive0600 temporary file in the pinned private
directory. Sync the complete file, publish it atomically with a no-replacement
hard link to person_ed25519, remove the temporary name, and sync the directory
before reporting success. A concurrent creator cannot overwrite the winner.
Never open/truncate/chmod/remove an existing destination, follow its symlink,
expose a partial destination, or remove a published key on any later failure.
Unsupported filesystem operations fail closed. An interrupted pre-publication
write may leave a private temporary file; inventory ignores temporary names.
It is not an active original and must never be adopted automatically. A crash
between publication and temporary-name cleanup can leave two names for the same
inode. Document owner cleanup of these reserved temporary files; no automated
secret copying/cleanup/recovery protocol is introduced.

Persistence and the daemon's project state are not one transaction. A parent
change, timeout, lost response or navigation after dispatch can leave the approved
key safely saved even if success is not observed. Never erase it to roll back UI
navigation. Creation failure/uncertainty authorizes only read-only inventory on
an explicit fresh attempt; no automatic retry or second key generation. Repeated
creation with an existing destination refuses. Read-only discovery is recovery;
there is no separate creation journal or duplicate active key store.

### Native creation consent and selection

Only an unpinned, verified, unexpired section13 chooser with an empty identity
inventory offers **Create a new original identity**. Existing identities and
pinned invitations never offer it; in particular a missing pinned key requires
its original machine/device ceremony, not a fresh random key. Clicking this
control opens an explicit review; it generates/writes/prepares/publishes nothing.
Show the complete public invitation terms and limits plus these creation effects:
one new original person on this computer, local private-key persistence, no
copy/import/link to an existing person, and no join request, participant approval,
agent permission, sharing or readiness. Explain that the saved original survives
Back/Close and later request decline; it needs a private backup through ordinary
host administration. The reviewed destination is this computer's normal original
identity location, not an arbitrary imported path. The key itself does not exist
at this review stage.

**Create and save identity** is a separate human action. **Cancel identity
creation** clears the attempt without writing. Recheck exact native context,
terminal surface, attached parent, fresh zero inventory, host and invitation
clock immediately before dispatch. Send only the exact context and creation
decision by stdin. Reject double presses, old controls and late callbacks using
the existing generation/attempt checks. Closing while already dispatched can
still save the explicitly approved key; show this limit before approval.

Validate the exact public creation reply and re-inventory the local key. Require
the returned key with generated provenance (an added ssh_agent source is allowed;
other keys remain ordinary choices), then show the ordinary chooser with
**New original identity saved** and its exact public key. Do not automatically
select it, prepare a join review, publish a request, sign or invoke a model.
The human must separately press **Review identity KEY**, inspect section12's
complete public-key/publication review, and **Approve join request**. Existing
section13 choice/recovery and original publication consent remain unchanged.

The invitation remains only in the joining attempt's private volatile memory.
Creation review uses the invitation's fixed expiry. Expiry, Refresh, Back,
Cancel, Close, reload, context/host/parent/surface loss and failed/uncertain
creation drop private input and write-authority callbacks, never the saved key.
An uncertain creation message explains that a key may have been saved and asks
for a fresh read-only lookup/inventory; no retry button. Reopening starts normal
join lookup and requires fresh private input before inventory. No model tool,
chat content, scoped credential or inference is added.

### Verification

A separate contract-only author extends join_onboarding and adds focused native
cases. Preserve the original8 host and184 native cases unchanged. New assertions
must be derived from this section before reading production code.

1. Fresh creation: valid durable0600 original in0700 private directory, exact
   public-only reply, ordinary inventory/discovery agrees; no sidecar, daemon
   secret, protocol request, authority/adapter state or signature. Missing nested
   config directories are created safely; HOME fallback works.
2. Wrong/missing/detached parent, missing daemon, nonzero inventory, existing
   malformed/insecure/dangling-symlink destination, symlink/insecure directory,
   relative/traversing config path and malformed/duplicate/extra/oversized input
   refuse without replacing a key. Existing bytes/modes and symlink targets stay
   unchanged. Native budget allows bounded SSH-agent inventory.
3. Concurrent commands publish at most one complete original; repeat refuses and
   read-only inventory recovers that public key. No partial final key or extra
   active identity. Private temporary names are ignored. Parent change after
   approved persistence never removes/replaces that original.
4. Native empty-unpinned chooser offers review only; exact creation effects and
   separate approval/cancel, no generation on entry/preview/review. Existing or
   pinned identities cannot create. Saved-key reply plus inventory returns a
   public chooser, never automatic prepare/decide. Explicit key choice and
   ordinary publication consent still work independently.
5. Exact argv/stdin/budgets and no secret/model/log/storage leakage. Changed
   host/context/parent/inventory/clock/reply, duplicate press, failures/unknown
   outcomes, navigation, expiry and late callbacks cannot reuse authority.
   Creation uncertainty offers no automatic retry; later read-only inventory
   recognizes the persisted key. No installed/physical-machine/model acceptance
   gate is closed by mocked native effects.

Selected: explicit consent before atomic local persistence, public-key selection
and publication as later independent actions, and normal identity discovery for
uncertain-write recovery. Discarded: hidden generation on paste, overwriting an
existing original, generation for a pinned invitation, a second secret store,
private-key copies for linking, request publication before durable key save,
and filesystem rollback after a lost UI/daemon response.

## 15. Read-only published-request progress

A section12 publication outcome remains historical. This slice adds an explicit
snapshot of that exact ordinary request's locally recorded progress before the
remaining participant-review controls are implemented. It never advances a
ceremony, signs, polls a peer, retrieves a code, grants access or claims current
network authority/readiness. Schema27 and the ordinary LINK_VIEW are unchanged.

### Owner-local snapshot and private CLI

`POST /v1/onboarding/join-flows/{flow_id}/progress` takes exactly
`{context,review_id}`. `peerspan onboarding join progress --stdin` takes exactly
`{flow_id,context,review_id}` and carries no private invitation. Reuse section12
strict64KiB JSON/stdin, duplicate/unknown-field/context/ID validation; no daemon
startup, state initialization or identity inventory. Owner-local only; adapter,
peer and unauthenticated bootstrap surfaces never acquire this route. No GET or
alternate mutation method is supported on this new endpoint.

Within one read transaction and one guarded decision time, load the exact join
flow and original project context. Require the captured review/context, retained
requested state and immutable outcome. Historical requested flows remain readable
after their review expires, replacement, project detachment or host restart when
the original context still matches. Mismatched context/review returns409
review_changed. A valid non-requested flow returns409 state_conflict. Unknown
flow remains404. Use the outcome's request_id only, never newest request, list
order or caller-supplied request IDs. Load/validate the ordinary durable record
and its referenced evidence using the existing read path, in this same snapshot.
Missing original request returns409 request_unavailable; invalid retained evidence
fails closed. Do not repair or advance it. Refuse409 request_mismatch if role is
not requester, mode is not new, migration proposal is not literal '-', state is
outside the ten ordinary states below, or network/context/person/request pins
differ from the historical outcome or host_public_key from this local host.

Return exactly
`{version:1,host_id,flow_id,review_id,context,observed_at,outcome,request,next_participant,next_action}`.
Outcome is unchanged section12 public outcome. Request is exactly the ordinary
public LINK_VIEW (runtime contract section5), including public completed stages,
consent booleans and attention/next strings, never display_code or secret material.
Observed_at is that guarded whole-second UTC decision time. Derive the next role
and action from the locally recorded state using this exact mapping:

| request.state | next_participant | next_action |
| --- | --- | --- |
| pending | person_owner | review_owner_offer |
| needs_selection | requesting_machine | review_owner_selection |
| needs_administrator | network_administrator | review_admission |
| needs_owner_finalization | person_owner | review_owner_finalization |
| needs_commit | requesting_machine | review_final_commit |
| finalizing | host | await_local_application |
| linked | requesting_machine | inspect_access_readiness |
| cancelled | requesting_machine | review_replacement |
| expired | requesting_machine | review_replacement |
| blocked | local_owner | inspect_advanced_status |

The person owner may use their original key or an actually authorized same-person
device under the existing protocol; the label does not choose a signer. Linked
means historical atomic local application only. It does not establish current
membership, agent access, connectivity, adapter verification or model receipt.
Progress observes only already durable evidence, not unprocessed incoming frames.
Reads must not invoke resume/observe/cleanup, network I/O, template materialization,
new keys/intents/frames/outbox updates, authority checks with side effects, or
activity. SQLite/WAL bookkeeping is not a protocol mutation.

### Native explicit observation

A section13 **Join request: publication recorded** outcome gains **Check join
progress**. Entry, ordinary outcome lookup/Refresh and successful publication
remain unchanged and do not automatically request progress. No controls appear
on a draft, identity/creation review, declined, expired or invalidated join flow.
The ordinary request can itself be expired/cancelled even while its join flow
retains requested state; that historical outcome keeps this control.

On explicit Check, clear any older progress confirmation synchronously; keep
historical publication visible. Recheck exact native terminal/project/conversation,
attached parent, fresh host and retained requested flow before the private stdin
call. Bind exact flow/review/context/outcome. Native process budget5 seconds.
Validate the full exact wrapper/LINK_VIEW shapes, host/context/outcome pins, keys,
IDs, UTC times, booleans, ordered unique completed-stage enum, bounded public
attention/next strings and the state-to-next-role mapping before displaying it.
Require host_id to equal host_ plus SHA256 of the32 decoded bytes of the
request host_public_key. Completed starts with request_created and is an ordered
unique subsequence of runtime section5's seven stage names. Attention and next
each contain at most32 nonempty strings, each at most1024 UTF8 bytes and without
raw control characters. Reject private-looking values using existing public-review privacy checks, and
never render raw provider/error text. No second frontend signature verifier.

Display **Join progress: STATE**, the observed-at timestamp, network/person/host/
device public keys, recorded stages and the two distinct requester-consent flags.
Quote public strings reversibly. Describe the mapped participant's next task in
plain language, with an honest note that the remaining approvals use existing
advanced linking until guided controls land. No inert approval or hidden resume
button. State linked as **Local application recorded**, never joined/connected/
ready. State delivery_pending only as a transport observation, not proof of
arrival; do not render arbitrary attention/next text as instructions. Show the
snapshot limit: current authority, agent access, reachability and model receipt
are not verified. A snapshot is not a continuously fresh connection check.

Keep the Check control for explicit subsequent read-only snapshots. Failure or
uncertain read clears previous progress and reports **Join progress unavailable**
while preserving the publication outcome; no automatic retries. Refresh, Back,
Close, reload, session/context/host/parent/surface loss, replacement and navigation
clear progress/its callback authority. Late results/double presses cannot replace
a newer view. Existing saved identity, durable requests, inviter outcomes and
established adapter/message/task runtimes remain unchanged through navigation.
The independent actual-terminal/reopen and installed acceptance gates stay open.

### Verification

A separate contract-only author extends join_onboarding and adds focused native
cases. Preserve original11 host case bodies and all existing native files (200 cases) unchanged.

1. Exact fresh pending snapshot matches ordinary GET and immutable outcome;
   observed time/role/action/context are exact, no secrets, file/DB/protocol
   mutations or outbound transport. Repeats are read-only and do not inventory
   originals. Strict API/CLI body/ID/method/context/review and owner-only bounds.
2. Real protocol transitions observed through existing public administration:
   at least pending, one naturally observable intermediate state and locally
   applied, plus cancellation,
   idle-stage expiry and historical read after review expiry/restart/replacement.
   Keep distinct requester consent and recorded stages; read never advances them.
   The existing single-offer CLI selects without an extra prompt; do not disable
   or freeze that behavior merely to force needs_selection. Native fixtures
   cover all ten mapped states without claiming live protocol
   transitions for their mocked effects. Unknown/mismatched/corrupt record refuses
   without substituting another request; source/fault limits are recorded.
3. Native Check is explicit after publication/outcome resume, exact bounded argv/
   stdin and fresh context/parent/host/flow. Complete public progress/limits and
   separate local application/readiness. Reject altered shapes/pins/state mapping,
   private-looking provider values and unknown states; no model/storage/signing.
4. Recheck/failure/uncertainty discards old confirmation, double press, navigation,
   Refresh/context/surface/parent/host/end and late callbacks; no hidden mutation,
   retry, peer poll or loss of saved keys/durable flows/established runtimes.

Selected: exact read-only ordinary-request snapshot with a derived next role,
explicit human Check and historical publication kept distinct. Discarded: treating
publication as current membership, polling/resume as a read, silently selecting an
offer/signer, fake approval controls, a second progress store/schema and a linked
result as evidence of agent access or model receipt.

## 16. Exact new-original owner consent backend

This working backend slice prepares and explicitly approves the first person's
possession-only owner intent for their own published request. It reuses the
ordinary protocol's durable unapproved owner intent; no schema/table, duplicate
secret store, original-key import, peer API or native control is added. Native
review/signing controls follow separately. Approval records consent; it does not
prove original possession until the exact original signature is supplied.

### Scope, shapes and retained review

Private owner-local POST routes under
`/v1/onboarding/join-flows/{flow_id}/owner/{prepare,lookup,approve}` accept exactly
`{context,join_review_id}` for prepare/lookup and additionally `owner_review_id`
for approve. Every successful action returns HTTP200, including fresh preparation
and exact retained retries; malformed requests use400 invalid. The advanced private-stdin interface is
`peerspan onboarding join owner prepare|lookup|approve --stdin`, adding exactly
flow_id to those shapes. Reuse strict64KiB body/stdin and duplicate/unknown-field,
context and typed-ID validation. No paths, code, scopes, provider, deadline,
private key or signatures can be supplied. CLI starts no daemon/state and never
reads an original key or SSH agent. Only explicit approve changes approval.

Bind the exact requested join flow, publication review/context and immutable
outcome to its validated ordinary requester/new/non-migration request, exact
network/context/person and this host key. Only a new original person's own
request before local network adoption is eligible for a fresh preparation.
No existing-person/device/root-provider fallback. The local person key need not
be available to prepare or record public consent; later signing must check it.

Lookup is pure and returns owner:null when no owner intent exists. Fresh prepare
requires the exact attached parent and a live pending request, with no local
network record. It prepares the ordinary unapproved owner intent atomically,
using the pairing material already held by the ordinary protocol; no code is
returned or stored elsewhere and no resume/poll/signature/publication is invoked.
Preparation may record ordinary unapproved templates, owner role and decision
clock, never a completed owner offer or admitted state. Repeated prepare reuses
that exact existing intent and fixed terms without renewal or another nonce,
key, template set or intent. Existing incompatible owner preparations refuse.

Choose the ordinary new-person profile7: policy editing1, host binding2 and
approving/renewing/revoking eligible own devices4, without network-admin8.
These are proposed future device powers, conditional on admission and final
consent. Set not_after to the signed request.created_at +7 days, matching the
ordinary stable CLI default. Original provider only, SSHSIG, lease/root IDs '-'
and no issuer leases in this possession-only offer. A proposed offer ID is not
a completed signature, published offer or membership proof.

Return exactly
`{version:1,host_id,flow_id,join_review_id,context,observed_at,request,owner}`.
Request is the exact public LINK_VIEW. Owner is null or exactly
`{review_id,review,state,next_action}`. Observed_at is guarded whole-second UTC.
The public review is exactly:

```
{version:1,kind:"approve_new_original_owner",host_id,context,flow_id,
 join_review_id,request_id,intent_id,network,member,person_public_key,
 host_public_key,device_public_key,proposed_owner_offer_id,scopes:7,
 not_after,expires_at,effects}
```

Network is the exact section11 `{id,name,context_id,genesis_root_public_key}`;
member is its exact invitee label. Intent_id is the existing dint_32hex reference.
The other fields bind the retained original owner-offer template, not the mutable
later owner-finalization review. Expires_at is fixed min(request.expires_at,
intent.created_at+15min). Review_id is review_ + SHA256 of
`"peerspan-onboarding-original-owner-review-v1\n" + canonical(review)`.
Effects are exactly:

```
{approve_owner_intent:true,authorize_original_signature:true,
 authorize_bounded_owner_finalization:true,
 auto_select_single_offer_after_signature:true,
 publish_owner_offer_after_signature:true,
 grant_membership:false,grant_agent_access:false,
 approve_network_administrator:false,commit_request:false,
 share_files:false,share_conversation:false,capability_calls:false}
```

This consent permits the existing protocol's exact bounded later self B/D
finalization under independently verified administrator parents, and its normal
single-offer selection after signature. It never chooses another person, widens
powers/lifetime, approves administrator work or supplies requester final commit.
Original private bytes stay on their original machine. New routes never return
signing templates/messages/requests, signatures, code, ciphertext, seeds, socket
paths or provider diagnostics. The existing ordinary private signing interface
remains separate; this slice does not collect an original signature.

### State, exact approval and recovery

Lookup/prepare of an existing compatible intent return its fixed public review.
State is approved if the ordinary owner intent already records approval,
including after signature/finalization/application, expiry or parent detachment.
This reports the global protocol intent, not which frontend/context originally
approved it. It creates no new approval attribution. Before approval, precedence
is cancelled if the request/intent was cancelled; expired if the review, intent
or ordinary request has expired; invalidated if its parent is no longer attached,
local network adoption changed eligibility, or the request left pending; otherwise
review. Approved next_action is provide_original_signature while the completed
owner offer is absent, otherwise follow_join_progress. Review uses
approve_owner_intent; other states use inspect_join_progress. No implicit
replacement/expiry extension or durable decline is added. Leaving a review
unapproved is read-only; cancelling the request remains its existing separate
explicit protocol action.

Approve rechecks the exact join context/review, retained owner review digest,
current attached parent, live pending request, eligibility, fixed provider,
profile and expiry in the same SQLite transaction that sets the ordinary owner
intent's approved/approved_at fields. Recompute and compare before any approval
write, reusing ordinary owner preparation/validation, not a second authority or
signature implementation. Recheck time/request liveness before commit; crossing
expiry rolls back. No gap between frontend approval recording and protocol intent
approval. No explicit resume or original signing after commit in this route.
Ordinary background work may subsequently materialize/sign host-owned slots of
that approved intent; it cannot fabricate the missing original signature.

Unknown flow is404; a non-requested flow409 state_conflict; malformed input400;
wrong join context/review or owner digest409 review_changed; expired owner review
409 review_expired; detached/changed parent409 review_changed; unsupported or
incompatible proposal409 owner_review_unavailable. Invalid retained evidence
fails closed. No route is exposed to scoped adapters, peers or bootstrap callers;
alternate methods are405. Failed decisions expose no raw private diagnostics.

While the underlying ordinary request/intent remains retained, an exact approved
retry returns the recorded approved result read-only, including
after restart/detachment/expiry; it never re-signs, regenerates pairing material,
recreates an intent or advances the link. Wrong context/digest still refuses.
A pruned ordinary request returns409 request_unavailable and a missing/incompatible
intent409 owner_review_unavailable; never recreate approval history. Lookup and
response loss recovery remain pure. Historical review bytes/digest
remain stable even after ordinary owner-finalization changes its mutable review.
No original signature, admission, grant, commit, adapter or readiness is claimed
by this backend's approved state. Installed/terminal/model acceptance stays open.

### Verification

A separate contract-only author adds the small owner_onboarding suite for this
area. Preserve original14 join_onboarding bodies, all212 native cases and155 Rust
tests. Keep each suite under2 minutes; no new implementer tests.

1. Pure lookup before prepare; real pending new-person preparation, exact public
   review/digest/profile/deadline/effects, ordinary unapproved intent/templates
   and one fixed retry. No new key, original signature, completed offer,
   publication, membership/access/adapter state or duplicate secret store.
2. Exact atomic approval and read-only retry/lost response/restart/expiry recovery;
   changed context/review/hash/parent, nonpending/known-network/provider/profile,
   cancellation and malformed/private inputs refuse. Route/CLI/method/credential
   boundaries; public errors/replies contain no secret/template/signature.
3. Schema-only ABORT trigger on the ordinary approved-intent update proves full
   rollback before approval; exact retry after removing it succeeds. Existing
   after-commit barrier can demonstrate unknown response with retained consent
   where a bounded public fixture exists; unavailable intervals remain explicit
   source/fault coverage rather than fabricated protocol rows.
4. Existing advanced original signing/administrator/finalization/commit completes
   the same exact approved intent. Guided lookup after later finalization,
   local application and restart keeps its original public review/digest and
   historical approval, without invoking signing or granting access. Preserve all212 native cases and their assertions. A repeated existing
   delayed-progress fixture timeout may be corrected only by explicitly waiting
   for the old effect to enter its delayed-response interval before navigation,
   then proving the same late completion cannot replace the newer confirmation.
   Do not increase its timeout or retry until green. All16 slim suites/Rust
   gates run on the final head.

Selected: reuse the durable ordinary owner intent, exact context-bound public
review and one atomic approval transaction for the new-original path. Discarded:
a schema28 approval mirror, private-code export, original-key handling in the
daemon, admitted/root/device provider fallback, hidden signing/selection/commit,
profile15 for a new person and metadata attachment as owner consent. Full guided
native approval/signing remains the next slice.

## 17. Native exact owner consent

This slice supplies the human-only native review/approval for section16. It uses
only its existing owner CLI plus existing project/join inspection and observation.
The subsequent local-signing slice will collect the exact original signature;
this slice never reads keys/agent identities, invokes signing/resume/selection,
or approves administrator or requester work. No Rust/API/schema change.

### Entry, preparation and complete review

In an attached project's published joining outcome, offer **Review owner powers**.
Entry, publication, normal joining lookup, Check join progress, global Refresh,
reload and timers never automatically look up, prepare or approve owner work.
Only explicit Review owner powers rechecks the current terminal/root/conversation,
exact attached parent, host observation and immutable requested flow/outcome, then
calls `onboarding join owner lookup --stdin`. If owner is null, that explicit
action may call owner prepare once. A retained owner record is shown without
another preparation. Parent/flow/host changes and unsupported paths stop safely.

Commands use literal configured executable/state argv and exact section16 CLI
stdin shapes (flow_id, context, join_review_id; approval adds owner_review_id),
with timeoutMs5000. Owner-operation references and private payloads enter only
stdin. Existing documented project/join/adapter inspect commands retain their
one exact typed flow-ID argument; this adds no ID argument to an owner command.
No private code, signature, credential or owner payload enters argv or shell.
References/payloads never enter assistant text/prompts/tools, provider diagnostics
or frontend persistence.

Validate the exact section16 wrapper, context/flow/join review and entire ordinary
LINK_VIEW, using the same pins, key-to-host hash, ID types, booleans, stage-order
and bounded public-string rules as section15. Observed_at and request/review dates
are canonical whole-second UTC. Owner is null or its exact four-field shape;
review/effects are exactly section16, including kind, host/context/request/intent,
network and exact invitation member/person, host/device keys, profile7, fixed
request.created_at+7d and proposed offer ID. Compare the network/member with the
retained signed-introduction review; no replacement or shortened display terms.
A completed ordinary owner offer, if present, must equal the proposed offer ID.
Recompute the domain-separated canonical owner review digest. Internal flow,
review, intent, request and proposed-offer references stay private to the native
process. Reject unknown/extra/private fields, malformed/pin-inconsistent data,
private strings (including decorated terminal payloads), and inconsistent action
or state. Valid review state requires pending request, no completed offer, no
selection/commit, observation before expiry and expiry no later than observation
+15min. Every review expiry is after request creation and no later than request
expiry; observation is no earlier than request creation. Approved next_action is
provide_original_signature exactly while owner_offer_id is absent; otherwise
follow_join_progress. Other action/state mappings follow section16. Historical
approved reviews may outlive their original review window; they are never live
approval controls or evidence of current powers.

Display full reversible quoted project/network name, network/context IDs and
genesis key, invitee label, original person public key, host/device public keys,
fixed proposed powers and not_after, review expiry and observation time. Explain
policy editing1, host binding2 and eligible own-device approval/renewal/revocation4,
and no network administrator8. Explain exact original signature consent, later
bounded self B/D finalization under independently verified administrator parents,
normal single-offer selection and publication after signature. Membership,
agent access, network administration, requester final commit, files, conversation,
capability calls, reachability and model receipt remain separate. No truncation,
terminal interpretation, internal IDs or new confirmed progress/readiness.

### Explicit approval, leaving and recovery

Only a validated, unexpired review offers **Approve owner powers**. The first
press synchronously clears old confirmation and sets busy; repeated presses
share no second approval. Before dispatch, recheck native context/terminal,
attached parent, exact published join flow, fresh host observation and pure
owner lookup. The looked-up review ID and complete immutable review must equal
the displayed review, state must still be review and ordinary request pending;
recheck host/context/time immediately before approval. The fixed deadline must
still be future and no more than15min away, and the observed host time cannot
be more than30s in the native clock's future. Changed terms/state or elapsed
review refuse without approval. Backend section16 still enforces the atomic
current authority, time and exact intent binding.

After dispatch, accept only the same exact review with approved state. Display
**Owner consent: recorded**, explicitly as the ordinary protocol record without
attributing it to this pane/frontend. Missing completed owner offer still needs
an original signature; the existing advanced linking path is the next separate
action in this preview. A completed offer points back to explicit progress.
Cancellation/expiry/invalidated records show their observed state and no approve.
A finite review window is not an active grant lifetime or readiness proof.

**Leave owner review** clears local controls without declining, cancelling or
revoking protocol work; it remains available while reads/approval are pending.
Back/Close/Refresh, host/parent/root/conversation/surface changes and session end
clear volatile confirmation and pending callback authority, not durable consent.
Unapproved review expiry removes Approve, preserves publication and never renews
or prepares another intent. Old expiry callbacks cannot expire a newer attempt.
If expiry occurs after approval dispatch, the response may still confirm the
same historical approval; it never claims the command did not commit. Late
responses after navigation/context change cannot restore old terms or controls.

Controlled failures clear actionable terms and preserve publication. Failed or
mismatched approval responses are outcome unknown; never retry a write or sign
automatically. **Check owner consent** does fresh bindings and lookup only,
including when recovering a lost response; it never prepares an intent. Null
recovery reports no recorded owner review, leaving preparation to a later
explicit Review owner powers. Reopening that action also begins with lookup.
All native confirmation remains an explicit observed snapshot, with no polling.
Native reload tests retain an attached parent; actual daemon restart still has
the existing metadata-attachment recovery limits. The owner CLI's detached
historical lookup is not a native attachment bypass.

Established adapter/message/task/lease runtimes and durable inviter state survive
ordinary owner-review navigation. No extra hello, tools, inference or data work.

### Verification

The separate contract-only author adds a small owner-consent native test file,
without importing production modules. Preserve all212 existing case assertions
and their intended stimuli/timeouts. New deterministic delayed effects
synchronize actual dispatch/delay registration before navigation or virtual-clock
advancement. The existing pending-initial-adapter-connection cancellation fixture
may add that same synchronization before Close/Back: establish its intended in-flight
HTTP request first, then retain the actual delayed completion, cancellation,
no-renewal assertions and timeout. A pre-dispatch cancellation is valid product
behavior but does not exercise that fixture's intended pending-response case.

1. Entry/publication/progress/global Refresh are owner-inert; explicit double
   Review does one lookup and at most one preparation; retained records/reentry
   are read-only. Exact literal argv/stdin/5s bounds and no secret/model effects.
2. Full profile/effects/identity/lifetime review, all five states/null recovery,
   historical approved after expiry, original-needed versus completed-offer
   distinction, no attribution, no readiness or later approval claims.
3. Strict wrapper/review/request/digest/pins/IDs/keys/times/effects, UTF-8/private
   and decorated-terminal negative corpus; zero approve on malformed evidence.
4. Double explicit approve pins the same displayed review, performs fresh parent/
   flow/host/lookup/context/deadline checks and sends one exact approval command.
   Any changed review/state/context/host/parent/deadline prevents dispatch.
5. Failed/raw reads and unknown write results remove confirmation; explicit pure
   recovery finds an approval without retry, preparation or signing. Back/Leave/
   Close/Refresh/expiry/context/end and delayed old callbacks never revive an
   attempt. Runtime/inviter invariants and original212 cases remain covered.

Run existing owner_onboarding6 and applicable Rust gates/all16 slim suites on the
final head. Native fixtures do not establish actual installed/terminal/model or
two-person/two-machine acceptance. Carry all previous manual gates; no rejected
terminal action or unchanged quota-refused inference is retried here.

Selected: native exact consent first, reusing section16 and explicit pure
recovery. The next slice adds a bounded local-signing command and native control.
Discarded: combining approval with original signing, using broad advanced link
commands behind a button, collecting keys in the daemon, automatic preparation
on entry/Refresh, inventing a durable decline, and inferring active permissions
from historical approval. These keep each small PR concrete and reviewable.

## 18. Bounded local original owner-offer signing

This backend/CLI slice adds one explicit original-signature action for the
section16 approved new-original intent. Native signing controls follow separately.
The CLI uses the existing owner-local daemon/signature protocol and local
PersonSigner/FixedPacket verification. No new HTTP route, schema, signature
format, duplicate approval/signature store or broad link/resume loop is added.

### Private invocation and exact eligibility

`peerspan onboarding join owner sign --stdin` accepts exactly
`{flow_id,context,join_review_id,owner_review_id,decision:"sign_original_owner_offer"}`.
Use strict64KiB input, duplicate/unknown/null/type rejection and the exact typed
IDs/context from sections12/16. No code, path, key/provider selector, scopes,
deadline, template/message or signature input; no daemon/state/key creation.
Only this explicit decision authorizes local key use, not ordinary prepare,
approve, lookup, entry, recovery or any native control in section17.

Start with pure section16 owner lookup. Validate its complete closed response,
exact captured flow/context/join/owner review and domain-separated digest,
fixed profile7/lifetime/effects and all request/network/person/host/device pins.
The host ID must hash from the canonical request host key. Owner must be
approved; a missing/unapproved/incompatible review refuses before key/agent IO.
A completed owner_offer_id must equal the approved proposed offer ID.

If that exact offer is already recorded, return its historical public result
without key/agent IO, ordinary signing lookup/submission, polling or protocol
advancement, including after parent detachment/request expiry. Approval alone
is not proof that an original signature exists. Before a fresh signature, require
a still-live pending requester/new/nonmigration request, no completed offer,
selection or requester commit, no adopted local network, and current exact
attached parent/host and published join flow/outcome. Recheck the immutable
join review/outcome through existing inspection, not latest-request selection.
The approved15min review window may have elapsed: fresh signing is bounded by
request.expires_at and the fixed not_after, not a renewed approval window.

### One typed original slot

Read the existing private ordinary approval view once. Require exact request/
review/signing_requests shape, same intent and pinned target, owner stage,
possession-only original_person provider (exact original and this host, device/
lease/root '-', scopes0/not_after '-'), profile7 and fixed finite terms. All
selection/administrator/person/host/binding/device lease references stay '-'.

Accept at most the two ordered distinct ready slots of slot1 owner_offer_packet:
its original authority/SSHSIG and/or locally owned host/Ed25519 slot. Validate
every entry with existing typed FixedPacket rules, canonical bounded Base64,
object ID, complete approved payload/descriptor/member/issuer/renewal/mode pins,
exact public key/role/format and exact derived message. No arbitrary bytes,
root/device/administrator/other slot/finalization signing, mixed intentions,
duplicate roles, foreign host or changed profile/lifetime. Reuse the existing
link CLI's typed original-slot validator; keep crypto/authority verification in
the shared protocol types. The host role is never signed by this CLI.

A typed partial host slot with an already valid original authority signature may
report recorded read-only; no key use or submission. If no original slot/proof
is available, one fresh public owner lookup may observe an already completed
offer; otherwise report unavailable rather than poll/resume or guess possession.

### Local key handling and submission

Use only the exact approved original. Prefer the normal generated original when
it holds that key; otherwise select that exact SSH-agent identity, even among
multiple identities. No key import/copy/generation, fallback to another person,
root/device provider, external subprocess signer or arbitrary message signing.
A valid different generated key permits exact-agent selection. A present unsafe
or malformed generated destination refuses; it is not silently bypassed.

Generated-key reading is bounded, owner-only and non-creating: absolute lexical
normal path, no '..' or symlink traversal, pin each directory by descriptor with
no-follow, the same secure ancestor/private final-directory checks as explicit
creation, then open only the normal person_ed25519 leaf no-follow/nonblocking.
Require owner-owned regular file with no group/other permissions and at most
64KiB, parse via the existing OpenSSH parser and match the exact public key.
Missing path/parents are absence, with no mkdir/permission repair/sidecar/temp
file. Do not use the broad discovery/path-based fallback to reopen unvalidated
files. Existing explicit-creation behavior and conformance remain preserved.

After selecting the signer, recheck parent, host, exact owner review and live
request immediately before key use. Produce exactly one SSHSIG for the typed
authority slot, locally verify it with the same FixedPacket, then recheck again
immediately before a single POST to the existing /signed endpoint with exactly
that intent and one {slot_id:1,role:"authority",signature}. No automatic retry,
extra signature batches or later original F work. Generated and agent operations
run off the async executor. Each local daemon HTTP operation has a5s timeout;
there is no polling loop. The next native caller may bound the whole process,
including the existing agent timeouts, and must recover unknown outcomes by read.

The ordinary daemon atomically revalidates/retains that signature and may perform
its already-approved host-owned work, exact single-offer selection and encrypted
offer publication. This is not new administrator or requester consent. Backend
request expiry/cancellation remain enforced. Local key use, metadata changes and
signature submission are not one SQLite transaction: rechecks precede dispatch;
leaving/changing context after dispatch cannot retract a signature already used
or retained. Do not claim cancellation of an already-dispatched key operation.
No original key bytes ever reach the daemon. Returned provider errors/paths,
agent comments, templates/messages, signatures, pairing secrets and seeds never
reach stdout/stderr diagnostics, activity or another persistence journal.

### Public result, idempotence and limits

A success returns exactly section16's public owner wrapper plus
`original_signature:{state:"recorded"}`. It means the exact original authority
signature is durably recorded (or already was), not which frontend signed it,
a completed owner offer, active powers, admission, agent access, requester final
commit, reachability or model receipt. Preserve the exact original review/hash.
Filter ordinary signing responses; never return their raw signing material.
After successful submission, a fresh public lookup must verify the same review
and completed offer before success; otherwise report controlled outcome unknown.

All failures are controlled nonzero CLI results with no raw provider/daemon/key
path diagnostics and no automatic retry. Missing/unavailable signer, expired or
cancelled request, wrong review/parent/host/intent/slot and changed terms refuse.
An uncertain POST may have committed; a subsequent exact invocation first reads
its already recorded offer and returns without signing again. No new durable
signature attribution is created. CLI starts no daemon/state; no new adapter,
peer or bootstrap endpoint. Native/modal signing and final installed/manual
acceptance stay separate.

### Verification

A separate contract-only author adds owner_signing, a compact under2min suite.
Preserve owner_onboarding6, join_onboarding14, all232 native cases and155 Rust tests.
No implementer tests and no fabricated protocol/authority rows.

1. Real approved pending request + matching private generated original: one exact
   original SSHSIG, daemon-verifiable original possession/offer; fixed review,
   no key mutation/creation/agent contact, later admin/commit/access still separate.
2. Exact SSH-agent choice among multiple identities with a different valid
   generated key; missing/wrong keys and unsafe/symlink/traversal/insecure/oversized/
   nonregular destinations refuse without fallback/writes. Existing creation
   and original owner/join suites remain intact.
3. Strict CLI64KiB/typed decision/refs/context/duplicates/unknown/private/path/
   template inputs and no-daemon behavior. Unapproved/mismatched/expired/changed
   state refuses before key use and signature submission; no secret diagnostics.
4. Controlled owner-local socket proxy may replay/alter authentic captured public
   views and signing templates for response-fault tests. Mutated review/digest/
   pins/provider/root/role/slot/intent/descriptor/message/key/format/profile/time,
   duplicates and later F slots refuse with zero original signing/submission.
   These are response faults, not fabricated database authority rows.
5. Bounded dispatch/delay fixtures cover changed parent/request/deadline across
   key use and before submission where public fixtures permit. Lost submission
   response + exact retry recovers once, without another original signature.
   Missing/pruned/corrupt evidence and narrow final-read/POST race intervals stay
   explicit source/fault coverage when no authentic public fixture exists.
   A fresh unoffered request also retains spec8's ten-minute stage-inactivity
   limit: resume does not record a new stage. Do not manufacture a fresh success
   beyond that limit to demonstrate an elapsed fifteen-minute approved review.
   The client distinction between review expiry and signature/request expiry
   remains source coverage when ordinary stage expiry makes it unreachable;
   actual expired-history replay is still exercised after a completed offer.
6. Existing advanced administrator/F/commit finishes the same request/intent;
   this command's exact complete-offer retry stays pure through later application,
   expiry/detachment/restart, with absent keys/agent and no later signing/resume.

Final head runs all17 slim suites, Rust gates and unchanged native232. Record
source/binary/results and limits. Do not retry rejected terminal actions or an
unchanged quota-refused model probe; physical/installed two-machine/distinct-person,
actual native signing and schema23-to27 upgrade/recovery acceptance remain open.
Preserve all232 native assertions/delays/default timeouts. GU.impl18b permits
the separate author to establish the old authentic invitation handoff and its
original delay before navigating in the existing late-reveal fixture; a virtual
clock settle alone does not prove that asynchronous dispatch occurred.

Selected: one explicit local typed original owner-offer signature with fixed
existing consent and pure exact replay. Discarded: broad link CLI automation,
combined approval/signing, original F batches in this command, key copying/import,
unsafe discovery fallback, daemon key handling, new schema/API/journals, poll/
resume loops and historical consent as proof of original possession/readiness.

## 19. Native bounded original owner-offer signing

This human-only native slice calls section18's bounded CLI after section17's
exact owner consent. No Rust/API/schema/key-discovery/signature implementation,
new model tool, prompt, storage journal or automatic ceremony work.

### Explicit action and complete terms

In the attached project's published joining outcome, a validated approved owner
review may offer **Sign original owner offer**. Review/Approve/Check owner consent,
publication, progress, entry, Refresh, reload and timers never invoke sign. A
missing/unapproved/cancelled/invalidated owner record, nonpending request,
completed owner offer, selection/commit approval, any later-stage reference or
recorded local signature confirmation offers no fresh signing action. The
ordinary request must have only request_created completed and no owner/selection/
administrator/F/manifest/activation/outcome reference. Existing new-original,
nonmigration section17 validation and all person/network/host/device pins apply.

Keep the full exact section17 quoted identity, network/member, profile7, finite
terms/effects and review digest validation. Add a clear explanation: this explicit
action uses only the approved original on this computer (normal safe generated
key or exact SSH-agent identity); it creates/copies/imports no key. It submits
one exact original owner-offer signature. Existing approved host work may publish
the offer and select a single matching offer; administrator approval, later
original finalization, requester commit and agent access remain separate. The
CLI handles key selection and verification; the native frontend reads no key,
agent identities, signing template/message/signature or provider diagnostics.

The approved review's old fifteen-minute window is not a fresh signing deadline.
The request expiry and fixed not_after still bound eligibility; ordinary spec8
stage-inactivity rules remain enforced by the CLI/daemon. Show a Sign control
only before the earlier of request.expires_at and review.not_after, according to
the native clock and observed_at. Future host observations beyond30s refuse
dispatch. An authoritative expiry timer removes the Sign control without renewing
terms, preparing an intent, cancelling protocol work or discarding publication.
An expired unapproved review still cannot be approved.

### Fresh checks, one bounded call and strict result

The first explicit press synchronously sets busy and clears old confirmation;
double presses share no second call. Recheck terminal/root/conversation, exact
attached parent/review, host observation and immutable published join flow/outcome,
then pure owner lookup. Require the same displayed owner review ID and complete
review, approved state and exact immutable request pins/created/expiry/packet.
Recheck native context/host and effective request deadline immediately before
dispatch. Refuse changed terms/state/parent/host or expired bounds. A fresh lookup
that already proves the exact completed owner offer may display that public
evidence read-only, sending zero sign commands. A changed or unsupported pending
stage must not be converted into consent or silently refreshed into another write.

Call exactly the configured executable and literal configured --state argv:
onboarding join owner sign --stdin
with timeoutMs45000 and exactly
{flow_id,context,join_review_id,owner_review_id,decision:"sign_original_owner_offer"}
in private stdin. All existing owner read/approval commands retain5s. No owner
references/private payload in argv/shell; no broad link sign/resume/selection,
later F, administrator or requester-commit command. No automatic retry.

Validate the success as exactly section17's owner wrapper plus exactly
original_signature:{state:"recorded"}. Remove only that known extra field before
reusing complete section17 validation. Require approved state and the same exact
captured review/digest and immutable request pins; reject missing/null/unknown/
extra/private fields, invalid marker state and mismatched owner/offer/context/
keys/times/stages. Canonical dates and decorated private-string refusals remain.
Do not accept the bare owner snapshot as a signing success. A valid result may
have no completed offer yet (the CLI can prove an already retained original
signature from a typed partial host slot). Later request stages may be observed
after dispatch; do not require the request still be pending to report durable
historical evidence. A context/parent/host change during the call invalidates its
callback authority; recheck the attached parent, immutable join flow and host
before displaying returned confirmation.

Display **Original signature: recorded**, as global durable evidence, without
attributing signature creation to this pane. Distinguish **Owner offer recorded**
only when that exact completed offer is present; a recorded signature alone
does not establish it. Neither means admission, active powers, requester commit,
agent access, files/conversation sharing, reachability or model receipt. The
public review without a completed offer cannot prove that no partial signature
is retained; use "not confirmed by this public snapshot", not a definitive claim
of missing original possession. A completed exact owner offer is sufficient
public signature evidence, not a claim that the original key is still available.

### Recovery, leaving and volatile authority

**Check owner consent** remains pure fresh bindings plus owner lookup. It never
signs, prepares, approves, polls/resumes or retries, including after a failed,
timed-out or malformed signing result. A completed offer observed by Check may
report recorded original signature evidence. If the public snapshot still has
no completed offer, it cannot settle whether a partial signature was retained;
explain that limit and leave any later sign call to another explicit press.
Section18's CLI will recover existing proof before using a key again. Check
does not invoke the sign command merely to recover that proof. No frontend
signature attribution/state is persisted across reload.

A signing failure before dispatch clears actionable terms with controlled
unavailable text. Any failed/denied/timed-out/raw/mismatched result after dispatch
is outcome unknown; clear old confirmation, preserve publication, offer explicit
Check and never echo process stderr/stdout or retry. Partial/native confirmation
survives only the current exact local view; owner reads replace it with public
evidence. Leave, Back, Close, Refresh, context/host/parent/surface/conversation
change and session end clear it and pending callback authority. **Leave owner
review** stays available during preflight and the pending sign call. Leaving
does not cancel/revoke protocol consent or retract an already-dispatched
signature; say so before key use. If request expiry crosses after dispatch, an
otherwise valid returned result may confirm historical recorded evidence;
never claim the dispatched command could not commit. Old timers/callbacks cannot
disable a newer owner review or restore a departed view.

Established adapter/message/task/lease runtimes and durable inviter state
survive ordinary signing navigation; no new hello, tool, model turn or data work.
Actual native/installed two-machine/distinct-person, model receipt and schema23-
to27 upgrade/recovery acceptance remain separate. Do not retry previous rejected
terminal actions or an unchanged quota-refused probe.

### Verification

A separate contract-only author adds a compact native signing file without
reading/importing implementation modules. Preserve all232 existing native case
assertions, stimuli/delays/default timeouts, owner_signing6, owner_onboarding6,
join_onboarding14 and155 Rust/2ignored. New delayed-effect fixtures explicitly
signal dispatch/delay registration before navigation or virtual-clock advances.

1. Owner-inert entry/publication/progress/approval/Check/Refresh/reload/timers;
   only approved eligible pending original requests show Sign, with full exact
   quoted terms, source/effects/no-key-transfer and no readiness/attribution claims.
2. Double explicit Sign does fresh parent/host/flow/lookup/context/time checks and
   one literal configured45s private-stdin command with exact references/decision.
   Same review and immutable request pins required; changed parents/host/native
   context, review/pins/stages, future host time or expired bounds send zero sign.
   A just-completed exact offer is shown read-only without signing.
3. Strict closed signing-result/marker/owner/request/review/digest/date/key/stage/
   privacy corpus; bare snapshots, extra fields and wrong pinned results cannot
   confirm. Valid partial signature differs from completed offer; later stage/
   historical result can confirm only in the same still-attached native context.
4. Approved review-window expiry alone does not remove an otherwise eligible
   Sign control; effective request deadline does. Preflight crossing blocks
   dispatch; after-dispatch crossing may confirm historical proof. Old expiry
   callbacks cannot disable a newer attempt or automatically sign/renew.
5. Lost/denied/raw/timeout/mismatched results become unknown without retry;
   Check is lookup-only, null recovery stays explicit, completed-offer recovery
   needs no sign call and partial absence is not misreported as no signature.
6. Leave/Back/Close/Refresh/root/conversation/host/parent/surface/end during
   preflight or after sign dispatch clear old callbacks without claiming
   retraction. Current runtime/inviter invariants and original232 stay intact.

Run native validation/full suite, owner_signing6 and existing owner/join suites,
Rust gates and all17 CI suites on one final head. Record source/binary/results
and actual manual/source/mock limits. The test kit invokes current drawings;
old retained callback closures and narrow final-check/dispatch intervals retain
source/manual coverage unless a genuine fixture is available.

Selected: one explicit native action using the existing bounded CLI and exact
approved review, strict public evidence and pure recovery. Discarded: combined
approval/key use, key inventory/selection in the frontend, hidden sign-as-read,
broad advanced-link automation, new API/schema/persistence, write retries and
historical evidence as current authority or readiness.

## 20. Read-only incoming administrator admission inspection

This backend slice supplies verified public inspection before administrator
consent. It handles an existing retained incoming new-original request; automatic
invitation return already records such requests on the inviter. Native controls,
manual code import, durable administrator consent and signing follow separately.
No new schema, flow table, intent, signature format or duplicate secret store.

### Owner-local API and private CLI

POST /v1/onboarding/admission-inspection
peerspan onboarding admission inspect --stdin

Both accept exactly {context,request_id}, with section5's exact AdapterContext.
CLI input is private stdin only; no positional ID, code/file/provider/key/profile/
deadline/packet/template/approval input. Strict64KiB JSON, duplicate/unknown/null/
type refusal and a typed link_ plus64 lowercase-hex request ID. CLI validates
locally before IO, uses one5s local request, redacts daemon/provider/path errors
and starts no daemon/state. Endpoint is only on the private owner-local router;
alternate methods405, absent from scoped adapter/peer/bootstrap administration.

Read the exact current attached project/context/agent and existing ordinary
request in one SQLite read snapshot on a blocking worker. Unknown request404;
malformed input400; changed/detached parent409 review_changed; unavailable/
unsupported/missing/corrupt protocol evidence409 admission_inspection_unavailable.
Failures do not echo input, pairing material or raw verification diagnostics.
No import, network poll, resume, cleanup, proof admission, clock advance, contact
minting, activity event, key inventory/signing or database/file mutation. Capture
one effective observation time from the existing guarded ordinary decision read,
including the adopted network's clock guard without updating it.

### Supported incoming evidence

Require an administrator-side retained request, no requester role, mode new,
no migration and exact adopted network/context/person pins. It must be live and
at needs_administrator, with recorded request/owner/selection packets and no
administrator/F/commit/manifest/activation/outcome result. Request expiry and
ordinary ten-minute stage-inactivity limits apply. Existing unapproved intent
evidence must not be approved, resumed or rewritten by inspection.

Reuse the ordinary typed request, owner-offer, requester-selection and network
projection validators. Verify full signatures, canonical packet IDs, exact
request/owner/selection references, descriptor/genesis-derived network/context,
member and person/host/device tuple. The original owner must prove possession
only: original_person, no person/root/issuer-lease authority, original SSHSIG,
no renewed device, exact profile7, fixed request.created_at+7days not_after,
and a person not already present in adopted prior authority. All target pins
must match the request and selected offer; no default offer or provider choice.
Already-admitted owner, root/device owner provider, folded admin, renewal,
migration, unsupported profile/deadline, missing evidence, cancelled/expired or
later-stage request refuses. Do not fetch missing proof or reconstruct a request.

The inspection does not select or prove a local administrator signer/provider.
A retained incoming role and valid original/requester signatures do not authorize
admission. The later administrator consent must independently freeze and verify
its current root/provider, exact P/H dependencies, signatures and public terms.
Inspection's digest is not an approvable intent or a mutation authorization.

### Closed public result and replay

Return exactly
{version:1,host_id,context,observed_at,request,review_id,review,next_action}
where request is the ordinary public LINK_VIEW with role approver and no
display_code or extra private fields. Its selection_approved/commit_approved
booleans keep ordinary local semantics; a verified requester-selection packet
does not fabricate a local boolean consent. next_action is
review_administrator_consent, a proposed later step, not an available approval
command in this slice.

review contains exactly:
{version:1,kind:"inspect_new_original_admission",host_id,context,agent,
 network:{id,name,context_id,genesis_root_public_key},root_state_id,
 request_id,request_packet_id,owner_offer_id,selection_id,member,
 person_public_key,host_public_key,device_public_key,scopes:7,not_after,
 created_at,expires_at,effects}
with the exact attached parent's public agent metadata and current verified
projection root_state_id. created_at/expires_at are fixed ordinary signed-request
bounds, not a new review window; not_after is the selected owner's fixed proposed
machine lifetime. Canonical whole-second UTC observation and public dates.
Recompute review_id as review_ + SHA256 of
"peerspan-admission-inspection-v1\n" + canonical JSON(review).
Unchanged evidence/context yields the same review/digest; only observed_at and
ordinary mutable observation fields may change on another pure inspection.

effects is exactly:
{verify_request_signature:true,verify_original_owner_signature:true,
 verify_requester_selection:true,prepare_administrator_intent:false,
 approve_administrator_intent:false,sign_admission:false,grant_membership:false,
 grant_agent_access:false,commit_request:false,share_files:false,
 share_conversation:false,capability_calls:false}

Never return code/secrets/seeds, provider key paths, contact/carrier addresses,
raw packet/catalog/template/message/signature bytes, signing requests or mutable
intent records. Reject ambiguous public metadata containing private code/
credential markers, including control/bidi/zero-width decorated forms, rather
than drawing them later. Use existing seven private prefixes. Current authority,
admission, agent access, connection readiness and model receipt are not claimed.
No frontend signature attribution or durable inspection journal.

After explicit advanced admission/finalization/commit, this fresh-only inspection
may refuse its now-unsupported stage. It never resurrects pending work or returns
a retained authorization history. No purity claim includes independently running
transport/background work; settle authentic evidence before whole-DB snapshots.
CLI/API calls themselves perform no mutation in either live or terminal cases.

### Verification

A separate contract-only author adds admission_onboarding, a compact under2min
suite, no implementation imports or fabricated protocol/authority rows. Preserve
all252 native case assertions, owner_signing6/owner6/join14 and155 Rust/2ignored.

1. Two real hosts/persons with an automatic-return invitation, genuine original
   owner signature and selected offer produce an incoming retained admin request.
   Automatic return establishes the request, not delivery of every later packet.
   A public test driver may explicitly resume that retained incoming request
   to fetch/validate its owner and selection during setup, before inspection or
   purity snapshots. It must not use admissions preview or import/preparation.
   Exact response/digest/public identities/profile/fixed times/effects and known
   adopted network/root agree with ordinary public views. Stable pure retry:
   settle transport, compare logical DB/schema/key files before/after, no new
   intent/approval/signature/clock/authority/registry event or secret journal.
2. Parent/context/ID/malformed/strict64KiB CLI/API/duplicate/null/extra/private
   input bounds, missing daemon/no initialization, method and scoped adapter/
   peer/bootstrap boundaries. No raw secret/input/provider/path diagnostics.
3. Pending/no owner or no selection, requester-side, already-admitted/root/device
   owner, renewal/migration, cancellation, request/stage expiry and changed
   unsupported profile/deadline refuse without mutation or signer fallback.
   Use authentic public protocol fixtures; unsupported cases with no bounded
   genuine fixture stay explicit source/fault limits, not fabricated DB rows.
4. Missing/pruned/inconsistent proof fails closed and fetches/signs nothing.
   Existing read-only expiry/debug controls or schema-only aborts are permitted;
   corrupt authority rows are not positive setup. Narrow unavailable retention/
   corruption/race fixtures remain explicit source coverage if needed.
5. Same request proceeds through existing explicit advanced administrator
   admission, original F and requester commit, with no intent created by prior
   inspection. Fresh inspection then refuses later stage read-only, and no
   membership/access/readiness is attributed to the earlier inspection.
6. Restart/context replacement and future/stale clock boundaries preserve pure
   refusal and stable evidence semantics; source-reviewed absence of transport/
   signing calls plus public before/after observations. No new native/model or
   actual-terminal/physical/installed acceptance is inferred.

Run all18 final-head CI suites, Rust gates, native252 and unchanged applicable
host onboarding suites, record source/binary/evidence/limits and fresh bot review.
GU.impl20a permits the independent author to isolate the existing owner_signing
daemon constructors from the CLI's generated original using the documented
absent --person-key-file option. Preserve all six bodies/count/proof/privacy/
history assertions and normal CLI key reads; approved background signing must
not race a fixture claiming exactly one CLI-generated original submission.
Carry existing manual/installed/two-machine/distinct-person/model/schema23-to27
acceptance gates; do not retry rejected terminal actions or unchanged quota probes.

Selected: read-only verification of an existing incoming exact original/selection
prefix before administrator consent. Discarded: using ordinary admissions preview
as an observation (it imports/polls/prepares durable intents), code import in a
read route, automatic provider choice/approval/signing, frontend key access, new
schema/journal and public signature evidence as admission or agent access.

## 21. Durable administrator consent for an incoming new original

This backend slice prepares and approves the existing ordinary administrator
intent for section20's retained incoming original/selection path. No native
control, manual import, external signer selection, signature collection, new
schema or approval mirror. The selected provider is explicitly network_root with
ed25519 using the host's already retained current root seed. No auto/original/
device fallback or key creation/SSH-agent/file access. Missing or mismatched root
seed is unavailable, not an invitation to choose another provider. Preparation
may read existing private signer metadata internally but never signs or exports it.
Approval authorizes ordinary background root/host signing and publication of the
exact administrator offer. It is not a guarantee that no signature is made until
a later frontend action. Original F and requesting-machine commit stay separate.

### Private API and CLI

Owner-local POST routes:

```
/v1/onboarding/admission-consent/lookup
/v1/onboarding/admission-consent/prepare
/v1/onboarding/admission-consent/approve
```

CLI: `peerspan onboarding admission lookup|prepare|approve --stdin`.
Lookup/prepare input is exactly {context,request_id}; approve adds exactly
admission_review_id. Context is section5 AdapterContext; request_id is link_64
lowercase hex; review ID is review_64 lowercase hex. All input is strict64KiB
JSON, no duplicate/unknown/null/type coercion, positional ID or optional provider,
profile, deadline, packet, approval boolean, code/file/key input. Local validation
precedes IO. One literal5s local request, static redacted errors, no daemon/state
initialization. Normal CLI help remains available; rejected arguments never echo
input. Alternate API methods405; absent from scoped adapter, authenticated peer
and bootstrap routers. No secret/template/signing bytes or provider/path errors. Successful operations
return200. Malformed input400 invalid; cancellation or other incompatible live
evidence409 admission_review_unavailable. A schema-abort failure is controlled
non-2xx with full rollback; do not depend on its database diagnostics.

Prepare is explicit work to create an unapproved ordinary administrator intent,
not an approval of section20's inspection digest. The resulting exact review is
what the person must approve. Lookup is read-only and never prepares, imports,
polls, resumes, cleans up, advances clocks or recreates history. Prepare/approve
use one blocking-worker SQLite transaction; ordinary intent creation/validation
and approval fields are reused without another crypto or authority implementation.

### Exact public review

All responses are exactly:

```
{version:1,host_id,context,observed_at,request,admission}
```

Request is the ordinary public LINK_VIEW. Admission is null before preparation,
otherwise exactly {review_id,review,state,next_action}. Observed_at is guarded
whole-second UTC. Review is exactly:

```
{version:1,kind:"approve_new_original_admission",host_id,context,agent,
 network,request_id,request_packet_id,owner_offer_id,selection_id,intent_id,
 root_state_id,root_public_key,person_lease_id,host_lease_id,member,
 person_public_key,host_public_key,device_public_key,scopes:7,not_after,
 request_created_at,request_expires_at,created_at,expires_at,effects}
```

Network is section20's exact {id,name,context_id,genesis_root_public_key}. Root
state/key identify the selected current network root; P/H IDs are the exact
ordinary person/host lease drafts. Intent_id is dint_32hex. Owner/selection,
identity tuple, member and fixed request-created+7day terms match verified
section20 evidence. Created_at is fixed intent creation; expires_at is fixed
min(request.expires_at,intent.created_at+15min). Request bounds are the signed
original request's bounds. All times are canonical whole-second UTC. Review_id
is review_ + SHA256("peerspan-onboarding-original-admission-review-v1\n" +
canonical(review)). Effects are exactly:

```
{approve_administrator_intent:true,authorize_network_root_signature:true,
 authorize_host_packet_signature:true,publish_administrator_offer_after_signatures:true,
 grant_membership:false,grant_agent_access:false,authorize_original_finalization:false,
 commit_request:false,share_files:false,share_conversation:false,capability_calls:false}
```

No raw ordinary review, templates/messages/signing requests, authority signatures,
contact code, seed/key, socket/path or provider inventory. Apply section20's
recursive public-string/private-prefix/control/bidi protections to every response.
Public consent is not usable authority, membership, agent access, reachability,
adapter readiness or model receipt.

### Preparation, exact approval and pure history

Fresh prepare requires the exact attached parent/agent and all section20 live
new-original/profile7/selection/expiry/role/projection conditions, supported
current owned network root and ordinary typed draft validation. It creates only
one ordinary unapproved intent, pins its exact current root/P/H/owner/selection
and returns the review. Failed validation/public redaction rolls back intent,
pending reference and guarded clock writes. Existing compatible intent returns
its fixed review without writes or renewed expiry, including later history;
unsupported retained providers/profiles fail closed. No intent is replaced.

Approve recomputes and compares the entire review digest before any write.
Wrong context/digest409 review_changed; no intent409 admission_review_unavailable.
Before first approval, require attached parent, live needs_administrator request,
unchanged selected original/selection/root/P/H/provider, ordinary current draft
validation, observation no earlier than request/intent/stage creation, unexpired
review/request and ten-minute stage inactivity. For fresh preparation and first
approval, raw local decision time as well as effective guarded time must be no
earlier than request, intent (when present) and stage creation. The ordinary
five-minute rollback clamp cannot satisfy this first-write creation bound by
itself. Refuse409 admission_review_unavailable; do not change the shared ordinary
clock rule or pure historical recovery. Recheck raw/effective time, parent and
liveness before commit: crossing a bound rolls back. Expiry409
review_expired; other incompatible evidence/provider409 admission_review_unavailable.
A schema-only abort on the ordinary approved-intent update must roll back all
writes. No separate frontend approval record or gap before protocol consent.
Ordinary approved/approved_at and clock bookkeeping commit together. Existing
after-intent/after-approval commit barriers remain available. Do not call resume,
signing, packet publication or transport from these routes; background protocol
work may subsequently fulfill the consent using owned keys and later root checks.

Lookup/state precedence: approved if the ordinary intent records approval;
otherwise cancelled if request/intent cancelled, expired if review/request/stage
bounds expired, invalidated if detached or current evidence/root/provider changed,
otherwise review. Next_action is follow_link_progress for approved,
approve_administrator_intent for review, inspect_link_progress for other states.
An approved result reports global ordinary consent, not which project/frontend
originally approved it. Any exact valid project context may inspect the same
ordinary intent; its context/agent changes the public review digest. No stored
frontend attribution or new secret/history table is added.

Exact approved retry, existing prepare and lookup are pure even after restart,
parent detachment, expiry, completed offer, F or commit/application. Preserve
initial root/P/H/creation/review bytes/digest for the same context despite later
mutable ordinary administrator_offer_id. Wrong digest still refuses, even for
approved history. Missing/pruned ordinary request is404; missing/corrupt or
incompatible intent409 admission_review_unavailable, never recreated. Unknown
parent404, changed parent before first write409 review_changed; malformed400.
No approval, signature, completion or connection readiness is inferred from null,
review/expired/invalidated/cancelled state. Actual installed/native/physical/model
and schema23-to27 full-state recovery acceptance remains open.

### Verification

Negative retained-provider setup may explicitly use the ordinary unapproved
admissions preview/link-admit path after a genuine prefix exists, solely to
establish an authentic incompatible intent before the measured guided call.
This is not setup for a positive guided result and is never called by these
routes. Preserve its exact intent and prove guided refusal does not replace it.

Separate contract-only author adds admission_consent6, each suite under2min;
existing admission_onboarding6, signing6/owner6/join14, native252 and Rust155/
2ignored remain intact. No implementer tests or invented protocol authority rows.

1. Genuine two-host/two-person incoming selected original: pure null lookup,
   fixed unapproved ordinary intent, exact public root/P/H/identity/digest/effects,
   one stable prepare and lookup; no signing/publication/extra schema/key/journal.
2. Exact atomic approval and pure approved retry/response-loss/restart/expiry/
   detached history; same ordinary intent and stable public digest despite later
   explicit advanced F/commit. Background signing is allowed after consent and
   must never be attributed to an inspection or a particular frontend.
3. Wrong digest/context/parent, unsupported profile/lifetime/provider, request/
   review/stage time boundaries/cancellation refuse without writes. Genuine
   public fixtures only; unavailable root-rotation/provider/corrupt-proof race
   intervals stay explicit source/fault limits rather than fabricated authority.
4. Strict64KiB API/CLI JSON/positional/missing-daemon/privacy and alternate method,
   scoped adapter/authenticated peer/bootstrap isolation; no provider/secret echo.
5. Schema-only ABORT on first ordinary approved field update proves full rollback,
   then exact retry succeeds after removing it. After-commit response loss may use
   existing debug barriers where bounded; unavailable intervals are source limits.
6. Full same-request ordinary admission/F/requester commit, pure historical lookup/
   exact approval retry and no recreation when ordinary history is absent.

Run all19 final-head CI suites, native252 and Rust gates, record exact source/
binary/independent evidence, every failure and fresh bot review. Earlier signing
historical-purity intermittence remains explicit until diagnosed. Do not retry
rejected terminal actions or unchanged quota-refused model probes.

Selected: reuse one ordinary durable root administrator intent with exact public
consent, atomic approval and pure history. Discarded: schema28 consent mirror,
auto/original/device fallback, hidden signing as preparation, raw admission
preview/import, external key flows, profile15 for the new original, native
controls in this backend slice and consent as membership/access/readiness.

## 22. Explicit incoming original/selection proof progress

This backend action closes the gap between an automatically returned request
and sections20/21's retained owner/selection evidence. It is explicit transport
work, not a read-only observation. No native control, manual code import,
administrator intent/provider choice, approval, local signature, publication,
finalization, requester commit, authority adoption or new schema/journal.
Ordinary pinned TLS authentication is transport work; it does not create a new
protocol signing intent, stage signature, consent or publication.

### Private API and CLI

`POST /v1/onboarding/incoming-progress` and
`peerspan onboarding admission progress --stdin` accept exactly
{context,request_id}, using section20's strict64KiB private stdin/JSON,
duplicate/unknown/null/type/typed-ID/context rules. No codes, files, keys,
endpoints, helpers, provider, deadline or approval input. Validate locally before
IO, use one literal5s owner-local request, start no daemon/state, and keep parser/
daemon/transport errors static and redacted. Only the private owner router;
alternate methods405, absent from scoped adapter/authenticated peer/bootstrap.

Successful200 response is exactly:

```
{version:1,host_id,context,observed_at,request,next_action}
```

Request is the ordinary public LINK_VIEW, observed_at canonical guarded
whole-second UTC. Next_action is wait_for_original_owner while owner_offer_id is
absent, wait_for_requester_selection while selection_id is absent, otherwise
review_administrator_consent only after the entire section20 inspection prefix
verifies. No endpoint/contact/code/seed/frame/catalog/template/signature/signing
request/provider inventory or raw error is returned. Apply section20's recursive
control/decorated private-prefix protection to the full public result. This
indicates a pending consent step, never membership/access/connection/model readiness.
Unknown request/project404; malformed400 invalid; changed/detached parent409
review_changed; unsupported/expired/cancelled/clock/ambiguous/invalid proof,
transport failure or timeout409 incoming_progress_unavailable. A changed exact
request/root/parent pin during IO409 review_changed (including cancellation
after preflight); cancellation already present at entry is unavailable. Actual
request/stage or monotonic deadline expiry is unavailable, not a changed-pin
claim. Schema-only abort failures need only be controlled non-2xx with exact
rollback, without raw database diagnostics. No partial local proof
retention on failure, including public-redaction or schema-only abort failures.
Timeout/response loss cannot prove that an earlier complete retention did not
commit; explicit retry rechecks the real current state.

### Eligibility, bounded fetch and atomic retention

Preflight in one SQLite read snapshot on a blocking worker: exact current
attached AdapterContext/agent, incoming administrator role and no requester
role, new/nonmigration, no owner/administrator/selection/commit local intents,
no approved selection/commit, no administrator/F/commit/manifest/activation/outcome
result, live request and ordinary ten-minute stage bound. Raw local and effective
guarded time must be no earlier than signed request/latest stage creation.
Require exact adopted network/context/person pins, target person not already
admitted, and an external requesting host. Verify the signed ordinary request
and current adopted descriptor/projection; no signer/key availability check.
Capture immutable request/private operation record, parent/agent and current
root-state pins for recheck. Unsupported paths refuse before network IO.

If owner+selection are already retained and section20 verifies, return the exact
current public result without network IO, logical DB/file/event/clock writes,
intent creation or another stage timestamp. It is a pure cached retry, including
when a previously used carrier is unavailable. Do not bypass eligibility after
administrator consent has been prepared: use its existing lookup/history instead.

Otherwise perform one bounded GET pass over at most8 already retained pinned
carrier endpoints for this exact request/locator/read capability. Reuse the
ordinary pinned bootstrap transport, mailbox envelope and exact signed/encrypted
frame validators. At most one GET per saved endpoint, no automatic retry,
resource creation/append, helper registration, new discovery or contact learning.
Fetch endpoints concurrently under one3s monotonic transport budget; retain only
responses completed within it. A valid response can succeed despite another
unreachable/invalid endpoint. No successful valid endpoint means unavailable;
no empty-success claim when there are no carriers. Do not update the ordinary
poll cache. No database connection/transaction is held over network awaits.

After fetch, one blocking-worker writer transaction rechecks the exact attached
parent/agent, request/private operation and current root-state pins, raw/guarded
time and all eligibility. Check a4s monotonic retention deadline before writing
and again before commit; queued/expired work cannot write after that last check.
No detached mutating async task or timer. Existing test controls may pause at
`dec.incoming_progress.before_retain` after IO and before opening this transaction,
with no database lock held, to prove context/time/deadline invalidation.

Atomically merge exact request/owner/selection/proofs frames into existing
private pending storage with its ordinary limits (64 frames/32MiB ciphertext),
never administrator/F/commit/outcome frames. Unsupported later-stage frame roles
make that carrier snapshot unusable rather than silently advancing it. Contacts
inside frames are not learned or used as new endpoints. Decode/verify retained
proofs with the ordinary Evidence/Offer and requester-selection validators.
An unpinned owner needs exactly one valid offer; ambiguous owners or selections
refuse, with no default/arrival-order choice. A previously retained owner is
immutable. Require original_person possession-only SSHSIG, exact target tuple/
invitation/descriptor/member pins, profile7 and request.created_at+7day not_after,
no root/person/issuer/renewed-device authority. Cache only its verified ordinary
owner and exact externally signed selection prefix. Receiving selection is not
a local selection-approved event; preserve all consent/approval booleans false.
No ordinary observe/resume/action engine that may advance later stages.

An honest mailbox may still contain only the request or owner: retain the valid
partial evidence and return the corresponding wait action. Newly verified
owner/selection stages may advance the existing pending stage timestamp once;
no clock-guard advancement, intents, events, peer contacts, registry or adopted
catalog/authority changes. Existing frames are deduplicated; unchanged repeat
cannot extend stage life. All frames, pending references, stage change and safe
public response pass validation before commit; any failure rolls all of it back.
No cross-request cleanup or pairing material reconstruction/export.

### Verification

A separate contract-only author adds incoming_progress6 under2min, preserving
all existing suites/native252/Rust155/2ignored and initial source assertions.
No implementer tests or invented protocol/authority rows.

1. Genuine two-host/two-person automatic incoming request, actual signed original
   and selected offer remain remote; new action alone fetches and verifies the
   exact prefix without ordinary link resume/admissions preview/import as setup
   on the administrator. Section20 inspection/section21 consent then use it.
   Exact public request/action; no administrator intent/approval/signature,
   authority/access/registry/event/new schema/key or secret journal. One frozen
   cached retry with remote stopped proves complete-prefix purity/no IO.
   Carrier counters include independent invitation-return polling every2s.
   A genuine minimum60s contact invitation may expire after automatic return
   and remote original/selection publication: advance both fixture clocks
   together past that invitation deadline, observe ordinary return-row cleanup,
   and retain the independently live3600s request before purity measurement.
   Do not disable the worker, edit storage or count only one saved carrier.
2. Request-only and, where a bounded genuine public fixture exists, owner-only
   mailbox produce waiting actions; unavailable owner-only observation before
   ordinary automatic selection remains explicit source/fault coverage. Repeated
   identical evidence does not renew stage timestamp or create authority. Exact
   retained request remains the same; no endpoint/contact learning or POSTs.
3. Strict CLI/API/64KiB/private-input/method/missing-daemon and scoped adapter/
   authenticated peer/bootstrap isolation; wrong/detached context/unknown IDs,
   requester/renewal/later-intent/cancelled/expired paths refuse without effects.
4. Genuine unsupported profile/lifetime and unavailable/mismatched/ambiguous
   proof fail closed with full rollback. Offline carrier/timeout stays bounded
   and redacted; no false successful progress. Bounded genuine invalid/ambiguous
   carrier fixtures preferred; otherwise explicit source/fault limits, not
   invented authority rows or private-key replacement.
5. Debug pre-retention barrier proves parent replacement/cancellation/deadline
   while IO was in flight causes zero local retention. Schema-only ABORT on
   pending update after fetched frame insertion proves the entire transaction
   rolls back, followed by one exact retry after removing the trigger.
   Parent replacement first detaches through the public session API, then uses
   section3's explicit replacement/approval; attached replacement is forbidden.
6. Same exact fetched prefix proceeds through existing explicit consent and
   ordinary root offer/F/requester commit; progress refuses after a local intent
   or later stage rather than signing/resuming/recreating history. Existing
   administrator lookup remains pure. Broader fresh concurrency/root-rotation/
   corrupt-retention intervals remain explicit source/fault limits if needed.
   After the new action alone obtains the prefix and guided consent is approved,
   the ordinary explicit resume driver may advance that already-approved root
   work. No passive completion deadline or new automatic signing is promised.
   Before terminal no-IO purity measurements, keep genuine participants/carriers
   available and explicitly drain pending final publication to its ordinary
   storage acknowledgment, or use the documented signed-request-deadline
   retirement boundary with the genuine debug clock after completing the whole
   ceremony. Wait for ordinary background frame/secret/capability retirement
   before measuring expired completed history. Linked state alone does not prove
   transport is quiescent. Public attention and documented outbound-storage
   observations may establish that setup; do not weaken measured zero-IO/DB/file
   assertions. Deadline setup does not establish immediate post-application
   scheduling attribution; live cached retry and live post-intent refusal are
   separately measured before that history check.
   After advancing past request expiry, one genuine ordinary unsigned requester
   creation followed immediately by its public cancellation may drive ordinary
   capacity/expiry maintenance before the original retirement observation.
   Use a fresh fixture person pin, no contact invitation/helper or approval;
   all spare device/secret/cancellation setup precedes the measured baseline.
   Do not assume periodic or terminal-resume cleanup; those intervals remain
   explicit coverage limits. No manual protocol rows or timeout extension.

Run all20 final-head CI suites, native252/Rust gates and fresh bot review; record
exact source/binary/results and all failures/limits. Earlier signing historical
purity intermittence remains documented. Actual native/terminal/physical/
installed/model/schema23-to27 full-state acceptance remains open; do not retry
previous rejected terminal actions or unchanged quota-refused model probes.

Selected: one explicit bounded fetch and atomic verified pending-prefix retention,
with exact parent/request/root checks before and after IO. Discarded: hidden
network polling in read APIs, broad link-resume/observer/signing engines,
automatic provider/approval/selection/commit, arbitrary new endpoints/contact
learning, arrival-order choice, half-retained failed results or a new schema.

## 23. Native incoming proof progress and exact administrator consent

This frontend composes sections20–22 in the existing terminal conversation.
No Rust/API/schema, manual code import, key access, new protocol engine or model
tool. It handles retained incoming new-original requests only. Root consent
authorizes ordinary background root/host signing/publication; it does not finish
original F, requester commit, membership application, agent access or readiness.

### Explicit entry, selection and recovery

Only an attached project offers **Review incoming connections**. Initial load,
headless entry, ordinary Refresh, adapter/model work and invitation issuance do
not list, fetch, prepare or approve admissions automatically. Explicit entry
rechecks terminal, native root/conversation, exact attached parent and host and
reads the owner onboarding observation. Validate its host and bounded4096
request collection, unique typed request IDs and exact public LINK_VIEW shapes.
Sort validated rows by request ID before paging; valid unsorted input is accepted,
while duplicate request IDs refuse the inventory as ambiguous.
List only role approver, mode new, nonmigration requests with complete typed
network/context/person pins; keep terminal history selectable for pure lookup.
Requester/renewal/migration records never become admission candidates. No first
candidate, sole-candidate selection or arbitrary ID/code input. Ten per page;
empty/multiple/duplicate-identity candidates remain explicit choices.

Choice labels show the full public network/person/host identity and creation
time, with an ordinal to distinguish otherwise identical records. Do not display
request/intent/flow/session/review IDs or digests. These are retained request
claims, not yet verified admission terms. Selection captures immutable request
ID, network/context/person/host/device tuple, request packet and signed times.
Lookup is always first, using section21's private stdin. A retained consent
review/history is displayed without fetch, inspection or preparation. Null
lookup displays the request snapshot and separate explicit actions below.

**Check administrator consent** calls lookup only after fresh parent/host
checks. It never fetches, prepares, approves, resumes or recreates missing work.
Approved history remains readable even when request/review dates elapsed;
native project must still be current and attached to display owner controls.
Other historical states have no approval control. **Leave incoming review**
clears local selection/confirmation without declining, cancelling or revoking
anything. An already dispatched action cannot be retracted by leaving.
Re-enter through Review incoming connections before choosing another request.
When an established adapter pane is open, its Back to project control returns
to the attached project; the parent's Back to Peerspan leaves that project view.

### Missing proof and exact review actions

**Fetch incoming proofs** is available only for a live early incoming request
with null consent. Recheck parent/host and selected immutable pins in a fresh
observation, then lookup again. If an intent now exists, display that consent
instead of fetching. Otherwise make one literal
`onboarding admission progress --stdin` call with exactly {context,request_id},
five-second timeout and no other command/provider/code/endpoint. Strictly check
section22's entire result and selection pins. Show its waiting action or verified
prefix and invite a separate review; never prepare/approve automatically, poll
or call ordinary link resume. A timeout/failure shows controlled uncertain-result
text and requires explicit lookup or another explicit fetch after revalidation.

**Review administrator consent** first repeats pure lookup. If null, call
section20 inspect, verify its closed shape/digest/exact selected prefix and
current parent/host, then section21 prepare once. The prepared review must match
inspection's network/current root/member/identity/owner/selection/fixed terms.
Existing consent is reused, never replaced. A failed/uncertain preparation is
recovered through Check, not an automatic prepare retry. A prepared intent is
not approval; inspection's digest never goes to approve.
Offer Review only for a live needs_administrator snapshot with owner and
selection IDs already present. An early live null result may offer Fetch;
terminal or unsupported null results offer only Check and Leave. Recorded
approval is labelled **Administrator consent: recorded**.

Before offering **Approve administrator consent**, validate the exact section21
closed response, review digest, kind/version/context/host/agent, all typed public
IDs/keys, current root/key and P/H dependencies, fixed profile7 and
request.created_at+7day lifetime, signed request bounds, intent creation and
min(request expiry,intent creation+15min) review expiry, exact effects and state/
next-action. Incoming selection evidence does not require or fabricate the
requester's local selection_approved boolean on an approver. Reject inconsistent
recorded stages. Recursively reject unknown fields/private code or credential
markers, including control/bidi/zero-width decorated forms, in every result
before presentation. Quote all human strings reversibly. Show the full project,
agent/owner/capabilities, network/genesis/current root, person/host/device/member,
finite powers/times and every effect; public root-state and P/H references may
be shown as exact authority dependencies. No raw diagnostic/provider/key/path/
template/packet/signature data enters drawings, prompts, tools, logs or storage.

### Exact approval and volatile authority

Approve captures the exact rendered review and synchronously excludes double
presses. Freshly recheck native terminal/context, parent and host, then lookup
the same request. Require state review and byte-equivalent canonical review plus
digest and unchanged selected immutable request pins. Check canonical observation
and local time no earlier than request/intent creation, observation at most30s
ahead of local time, and both before review expiry. Recheck context immediately
before one five-second `onboarding admission approve --stdin` with exactly
{context,request_id,admission_review_id}. No signing/transport/resume follows.
Only the same exact approved review confirms recorded global ordinary consent;
it does not attribute approval/signatures to this interface. Malformed, failed,
lost or late results hide approval and show outcome unknown; Check only reads.

Local review expiry removes approval and invalidates in-flight local authority.
Null-consent and fetched-prefix views also expire their Fetch/Review authority
at the signed request deadline. Check remains available for pure history. Before
installing any delayed response view, freshly inspect the authoritative attached
parent and re-observe host identity; cached native parent/host values alone do
not establish that host-side binding still exists after IO.
Back, Leave, Close/Escape, Refresh, terminal/root/conversation/host/parent loss,
session end and reload clear selection/review/timers and reject stale callbacks
or completions. No persisted frontend approval/journal. Opening another flow
cannot retain admission authority. Existing established adapter/message/task
runtime navigation rules remain intact. No admission action calls prompt APIs,
registers model tools or performs filesystem/clipboard/network effects directly.

### Verification

A separate contract-only author adds20 pinned native cases in a new test file,
preserving all original252 assertions/delays/timeouts/files. Public runtime
effects only, no product imports. Cover: (1) inert/headless/Refresh/model paths;
(2) attached entry, bounded sorted unique inventory; (3) empty/filtering;
(4) multiple/page/duplicate identity explicit selection; (5) lookup-first and
historical recovery; (6) one explicit fetch and waiting/complete mapping;
(7) lookup preventing fetch after intent; (8) no automatic prepare after fetch;
(9) inspect-before-explicit-prepare with exact matching; (10) existing review
reuse; (11) complete rendered terms/effects/privacy; (12) exact lookup-before-
approve and one stdin submission/double press; (13) changed review/root/tuple/
parent/context refusal; (14) expiry/raw/future clock bounds; (15) approved
history without fresh expiry veto; (16) malformed/private/decorated/extra-field
responses hide controls; (17) failed/lost results recover lookup-only;
(18) in-flight navigation/context/terminal invalidation; (19) timer/stale async
authority and reload; (20) existing runtime survives permitted navigation and no
prompt/tools/persistence/ordinary resume/signature/secret side effects.
The pinned kit does not retain old drawing callbacks; their exact closure checks
remain source/manual evidence, not fabricated execution coverage.

Run final native272 plus incoming_progress6 and admission_consent6 locally
sequentially against the unchanged frozen host, and all20 final-head CI/native/
Rust checks with fresh bot review. Record every failure, exact source/hash and
explicit gaps. No physical/installed/model/schema23→27 acceptance is inferred;
prior rejected terminal actions and unchanged quota-refused probes stay deferred.

Selected: explicit incoming choice, separate bounded fetch/review/approval and
lookup-only recovery using existing host APIs. Discarded: automatic polling or
consent on entry, raw ID/code input, ordinary broad resume, frontend signing,
provider fallback, duplicate approval storage and consent as connection readiness.

## 24. Read-only original finalization inspection

This backend slice exposes the independently verified administrator parents for
one exact section16 approved new-original owner intent. It precedes bounded
original B/D/F signing and separate requester commit. It never fetches evidence,
prepares finalization templates, signs, resumes, adopts authority or records a
new consent. No schema, provider choice or native control is added.

### Private request and eligibility

Owner-local POST `/v1/onboarding/join-flows/{flow_id}/owner/finalization/inspect`
accepts exactly `{context,join_review_id,owner_review_id}`. Private CLI
`peerspan onboarding join owner finalization inspect --stdin` accepts the same
shape plus exactly `flow_id`. Apply strict64KiB duplicate/unknown/null/type,
context and typed-ID validation. No code, key/path, provider, scopes, deadlines,
packet/message/signature or caller-supplied administrator references. The CLI
performs one bounded5s private daemon call, starts no daemon/state and never
reads a person key or SSH agent. Failed CLI output contains only controlled
public errors, never raw rejected input or provider/daemon diagnostics.

Use one SQLite read transaction on a blocking worker. Bind the exact published
join flow/review/context/outcome and original requester/new/nonmigration request
as section16; the request host must be this host. Recompute section16's immutable
owner review and require its exact supplied digest, approved ordinary intent,
original-only possession profile7 and request-created+7d lifetime. Approval's
15min review window need not remain live; request and offer authority still must.
Require the same attached project and agent, no adopted local network, live
request, completed exact original owner offer, exact approved requester selection
and retained administrator offer. Refuse absent/unapproved/incompatible owner
intent, pending missing evidence, device/existing-person/migration/folded paths,
completed owner finalization, requester commit or terminal/application artifacts.
Previously materialized ordinary finalization drafts are allowed while F is
absent, without changing them. This is fresh inspection, not historical consent
recovery; section16 lookup remains the pure history interface.

Reuse the ordinary protocol's cryptographic request/owner/selection verification,
full administrator preparation and owner-preparation projection at guarded time.
Verify the administrator packet, catalog/current root and exact subject P/H
parents, active issuer authority, profile and finite bounds for this precise
request, selected owner, original person, host and device. Never derive authority
from public IDs alone or treat pending P/H as adopted membership. Do not resolve
or open a signing provider, materialize B/D/F, mutate clocks/records, import/poll,
learn contacts, clean up, create keys, or emit an event. Only retained evidence
is eligible; explicit proof transport is a later slice. Require observed time
at/after request creation and prior stage time and before signed request expiry,
ordinary inactivity deadline and fixed not_after.

### Closed public result

Success is HTTP200 and exactly:

```
{version:1,host_id,flow_id,join_review_id,owner_review_id,context,observed_at,
 request,review_id,review,next_action:"review_original_finalization"}
```

Request is the exact public LINK_VIEW at observed_at. Review is exactly:

```
{version:1,kind:"inspect_new_original_finalization",host_id,context,flow_id,
 join_review_id,owner_review_id,request_id,intent_id,network,member,
 person_public_key,host_public_key,device_public_key,request_packet_id,
 owner_offer_id,selection_id,administrator_offer_id,root_state_id,
 person_lease_id,host_lease_id,administrator,scopes:7,binding_scopes:2,
 not_after,created_at,expires_at,effects}
```

Network is section11's exact public descriptor. Original owner and all target
keys/member/fixed lifetime match section16. Administrator is exactly
`{signer_public_key,host_public_key,signature_format,issuer_id}` from the verified
administrator packet (writer host, authority format and issuer); these identify
its signing authority, not a new consent attribution. Root/P/H are the exact
independently verified administrator parents. B/D/F IDs are deliberately absent:
this action does not create timestamp-dependent drafts. Created_at is exactly
the signed request.created_at, never intent/admin/observation time. Expires_at is the signed
request deadline, not a renewed inspection/consent window. Effects are exactly:

```
{verify_original_owner:true,verify_requester_selection:true,
 verify_administrator_admission:true,verify_owner_finalization_bounds:true,
 prepare_finalization:false,sign_original:false,publish_finalization:false,
 commit_request:false,grant_membership:false,grant_agent_access:false,
 share_files:false,share_conversation:false,capability_calls:false}
```

Review_id is review_ + SHA256 of
`"peerspan-original-finalization-inspection-v1\n" + canonical(review)`.
Repeated inspection with unchanged retained parents/terms has the same review
and digest, excluding observed_at/request stage observations. No templates,
messages, signatures, codes, ciphertext, seeds, sockets/paths or agent comments
are returned. Apply the existing public private-prefix/unsafe-label guard.
Success proves eligible verified retained parents at that observation only;
it is neither a signature, requester commit, adopted powers, access nor readiness.

Malformed input400 invalid, unknown flow404, non-requested flow409 state_conflict,
wrong context/join/owner digest409 review_changed, detached/changed parent409
review_changed, expired request (signed deadline or ordinary10min stage
inactivity)409 review_expired, pruned ordinary request409
request_unavailable. Other unsupported/missing/invalid evidence or incompatible
consent409 finalization_inspection_unavailable. Do not recreate evidence/history.
Only owner-local administration exposes this route; scoped adapters, peers and
bootstrap callers cannot use it. Other HTTP methods405. Failed reads are pure.

### Verification

A separate contract-only author adds a small owner_finalization suite, preserving
all old20 suites and272 native cases/assertions/delays/timeouts. Use genuine
signed invitations/requests, distinct original people and hosts, ordinary
signing/transport and public setup; no fabricated protocol or authority rows.

1. A genuine same-request new-original ceremony reaches retained administrator
   evidence after exact section16 consent/signature/selection and independent
   administrator approval. Inspect via API and CLI: closed shapes, exact pins,
   domain digest, root/P/H/administrator identity, profile7/binding2/fixed end and
   all false effects. No B/D/F materialization or requester commit occurs.
2. Repeat live inspection: stable review/digest and strict logical DB/private-file
   and settled carrier no-IO snapshots remain equal. Restart follows the existing
   project-session detach contract: after startup settles, inspection refuses
   review_changed purely; section16 lookup retains the identical original consent
   and ordinary evidence. No retry, approval replay or adapter reconnect is a
   project resurrection. A substituted fresh project context cannot rebind the old
   published join flow. Isolate independent invitation/transport workers before
   measuring; retain every purity assertion and document setup limits.
3. Missing/unapproved owner consent, absent original/selection/administrator,
   wrong/detached context or altered review IDs refuse without mutation/key IO.
   Use genuine alternative attempts/identities; no evidence-row edits.
4. Signed expiry and ordinary inactivity, cancellation, unsupported device or
   adopted network fail closed. Exercise controllable public fixtures; catalog
   corruption, microscopic crossing and cryptographic internal checks without a
   deterministic public stimulus remain explicit source/fault limits.
5. Strict API/CLI malformed/duplicate/unknown/null/oversized/positional input and
   scope/peer/bootstrap/method boundaries; controlled diagnostics contain no
   supplied private canary. CLI starts no host/key/state and makes no retry.
6. After pure inspection, existing explicit advanced original F and separate
   requester commit complete this same genuine two-person/two-host ceremony.
   Inspection then refuses; section16 exact consent history stays unchanged.
   No agent grant/readiness or installed/physical/model acceptance is inferred.

Selected: reuse ordinary projection under one read snapshot, then separately add
bounded original signing and requester commit. Discarded: using broad resume for
observation, creating draft IDs during inspection, new approval storage, assuming
administrator consent is owner consent or requester commit, and key use on entry.

## 25. Bounded local original finalization signing

This CLI slice completes only the original B/D/F signatures already authorized
by section16, after the exact independently verified section24 inspection. The
ordinary requester/approver worker already fetches mailbox evidence and performs
approved local host work. Reuse that progress; another guided fetch endpoint is
unnecessary. Waiting, inspection and recovery never invoke broad resume or key
use. No new HTTP route, schema, consent/signature journal or native control.

### Explicit private decision and binding

`peerspan onboarding join owner finalization sign --stdin` accepts exactly
`{flow_id,context,join_review_id,owner_review_id,finalization_review_id,
 decision:"sign_original_finalization"}`. Apply strict64KiB input, duplicate/
unknown/null/type/typed-ID/context validation and private-prefix protection as
sections18/24. No key/path/provider selector, codes, scopes, lifetime, supplied
messages/templates/signatures or raw administrator references. CLI starts no
host/state, creates/imports no key and exposes only controlled public errors.

Begin with pure section16 owner lookup and its complete closed/digest/pin checks.
Require approved exact original consent and its completed exact owner offer.
If F is already recorded, refuse read-only before key/agent IO, ordinary signing
lookup or submission; existing owner lookup/progress is recovery. This fresh-only
command does not create signature attribution or make a historical signing
success claim for an unverified caller-supplied finalization digest.

Before fresh key use, obtain pure section24 inspection; require its complete
closed result/review/effects and domain-separated digest equal the captured
finalization_review_id. Bind every original/flow/context/request/network/member/
key/fixed-term pin to section16 and its immutable publication outcome. Exact
requester/new/nonmigration, this host, approved selection, pending original F,
no requester commit/terminal artifacts or adopted network, live signed deadline,
ordinary stage bound and fixed not_after. Use fresh attached parent/agent and
host identity and exact current published flow/outcome, never latest selection.
Recheck these bindings before every original key operation and signature batch
submission; different root/P/H/admin/selection/review or parent refuses. The old
15min approval-review deadline may have elapsed; no renewal of its consent.

### Fixed typed work, never a protocol driver

Read the existing ordinary `/v2/link/requests/{id}/approval` view, validate its
closed request/review/signing_requests, same original intent, target and stage
owner_finalization. Its root/P/H/owner/selection/admin references and profile7/
fixed lifetime must equal the verified section24 review; the provider remains
possession-only original_person for this original and this host, SSHSIG, with
device/lease/root '-', scopes0 and not_after '-'. B/D IDs are nonempty distinct
concrete ordinary ds_ IDs; materialization comes from the existing approved
worker, never this CLI. Missing drafts/ready slots refuse; no polling or resume.

Only slots2 binding_lease issuer,3 device_lease issuer and4
owner_finalization_packet authority are eligible for this nonfolded new-original
profile. Validate every returned ready entry before any key/agent IO for that
batch, including owned F host entries; reject any other slot/stage/role/format,
foreign/mixed intent/key/template, duplicate or out-of-order entry. At most two
B/D issuer entries form the first batch, including a subset if one was already
recorded. An F authority (and optional own host/Ed25519 pending slot) forms the
second batch. Never mix B/D and F in one response/batch. Owned host slots are
verified but never signed by the CLI; binding host consent remains ordinary.

Reuse shared typed FixedStatement/FixedPacket verification, canonical bounded
Base64, object IDs, exact derived messages/public key/SSHSIG and existing typed
link-slot validation. Inspect complete B/D payloads: exact operation/current root,
original issuer kind person and key; person/host/device targets, member '-',
binding scope2/device scope7, exact fixed end; exact subject_person, subject_host,
issuer_person P/H parents, plus D's subject_binding equal reviewed B. No other
issuer/delegation/renewal/retained/resolution authority. Issued_at equals
not_before, at/after signed request creation and no later than current verified
observation/effective local time; expiry remains fixed and live. Standard typed
sequence/predecessor validation remains in shared protocol types and the daemon.
F packet must match selected request, original signer/writer/issuer '-', SSHSIG,
root/P/H/selection/admin and contain the exact reviewed B/D IDs with their same
bounded payloads and valid recorded original issuer signatures. No foreign or
additional embedded grant. Verify all nested typed signatures that are present;
ordinary allowed pending binding-host consent is not fabricated by this CLI.

Use section18's same pinned, non-creating generated-original reader or exact
SSH-agent identity, with unsafe/malformed destination refusal and no provider
fallback. Reuse this implementation, not path-based broad discovery. Run key
selection/signatures off the async executor. Every signature is locally verified
against its exact typed object before submission. Never return/log raw templates,
messages, signatures, keys/paths, agent comments, codes, seeds or private diagnostics.

At most two ordered submission batches and three original SSHSIG operations per
invocation: the remaining B/D issuers, then F authority. A90s asynchronous
orchestration deadline stops further phases/submissions. Already queued or
dispatched blocking key/agent operations can outlive that deadline and may delay
process shutdown; their abandoned results cannot trigger a later submission.
A POST already dispatched may still commit. The future native caller supplies
its separate whole-process bound. No retry, unbounded loop,
extra original offer/administrator/root/device/commit signing. Every daemon call
has5s bound. After the first POST, obtain one fresh ordinary view for the dependent
F batch; the ordinary daemon may have already materialized/signed its approved
host work. If F is not ready or any previous issuer entry reappears, refuse with
controlled outcome-unknown recovery, never re-sign or advance it. An invocation
starting directly at F makes at most one submission. A lost first B/D POST result
stops before any F key use or second POST, even if that batch committed. Initial
already-F refusal applies even to a different well-typed finalization digest,
without invoking section24; no historical digest attribution is made. Rechecks immediately before
each key use and dispatch do not retract an already used key or committed batch.
A failed/lost response may leave B/D or F recorded; recover through pure owner
lookup/progress and a later explicit command signs only remaining typed slots.
No hidden broad action engine call or new public consent is authorized.

### Public outcome and verification

After submitting the typed F authority once, one pure owner lookup must retain
the same immutable review/target/owner/selection/admin and exact typed F packet
ID before success. Return exactly section16's owner wrapper plus
`original_finalization:{state:"recorded",review_id:finalization_review_id,
 packet_id:<typed F ID>}`. It reports the exact original finalization is retained,
not requester commit, current adopted powers, agent access, reachability or model
receipt. An already-completed concurrent F without that verified submission
reports controlled outcome unknown; no extra key operation or automatic retry.
All failures are controlled nonzero CLI results, with pure read recovery.
Original private bytes stay on their original machine; no new scoped/peer/
bootstrap endpoint. Whole-process native controls and installed/manual gates
follow separately; leaving after dispatch cannot cancel a retained signature.

A separate contract-only author adds small owner_finalization_signing coverage;
preserve old21 suites/native272 assertions/delays/timeouts. Use genuine distinct
people/two temporary hosts and ordinary approved worker progress. Typed local
fake-daemon faults derive from genuine public private-signing templates and
contracts, without production imports or fabricated authority DB rows.

1. Exact generated-original B/D then F signing under approved section16 and
   captured section24 digest; at most2 batches/3 signatures, same ordinary intent,
   exact profile/parents/fixed terms. No requester commit, access or new schema.
   If genuine owned work lags, after one controlled unknown and public proof of
   retained B/D the fixture may explicitly wait for ordinary F readiness, then
   make one further explicit Sign for F only. No Sign retry loop or unclassified
   first failure is accepted as setup; preserve per-invocation operation counts.
2. Exact SSH-agent among multiple identities, absent/wrong/unsafe/malformed
   generated sources and agent failure; no original replacement or fallback.
   Full key-source boundary stimulus may reuse section18's independent helpers.
3. Initial already recorded F refuses before any ordinary/key/agent operation,
   including detached/expired/restarted history; pure lookup confirms unchanged
   immutable original consent. Lost response/partial B/D retry signs only the
   remaining typed slots, no duplicate issuer or hidden resume.
4. Genuine missing/unapproved/changed parent/review/key/request/root/P/H/admin,
   expiry/cancellation/adopted/committed or unavailable-ready work fails closed.
   Microscopic races lacking a deterministic public stimulus stay source limits.
5. Genuine-derived typed slot faults: wrong slot/role/intent/key/format/message/
   ID/profile/parent/lifetime, duplicate/order/mixed phase, foreign host or extra
   nested grant. No key/submission for a rejected first batch; no later key use
   or retry after an uncertain first POST. Strict stdin/CLI/privacy/no-startup.
6. Same request reaches retained F via this CLI, then an existing separate
   explicit requester commit completes the real ceremony. Original keys stay
   with their participant; historical lookup/digest stays stable, repeated Sign
   refuses purely. No native/installed/physical/model readiness is inferred.

Selected: existing approved requester-worker progress plus one explicit bounded
original B/D/F action. Discarded: duplicate guided proof-fetch API, historical
success with an unverified finalization digest, per-slot UI prompts, a broad
sign/resume loop, new consent storage, signer/provider fallback and implicit
requester commit. Pure reads remain recoverable independent of key availability.

### Verification fixture isolation clarification

Ordinary unfinished-requester mailbox polling (existing spec8.4/9.5) is independent
of both measured pure reads and the invitation-return worker. Retiring a short
invitation alone does not stop requester polling. A brief no-change traffic gap
is not an attribution boundary. Live read fixtures may use an explicitly observed
in-flight transport fault/barrier outside any DB transaction: establish its
bounded hold before the baseline, keep it held throughout the measured read and
assert it remained held, along with all strict existing DB/file/both-carrier
counter equality checks. No worker disabling, authority/protocol-row edits,
transport-counter filtering or timeout/assertion weakening. Public terminal
expiry/maintenance setup may precede historical baselines as in23e; it must settle
ordinary outbox/journal lifecycle too, never silently omit those effects.

Initial PR62 CI at40d3f7b: old section24 case3 had one additional connection on
each relay with no additional bytes (5/6 in31s). Local old section18 case6 changed
dec_outbox and a host.db-journal path (5/6 in48s). The precise latter lifecycle
cause is unclassified; preserve both observations. Any fixture correction is
independently authored from contracts before final rerun, retaining all original
assertions. These failures are not passing evidence or permission to retry until
green. New section25 suite first ran5/6 in121s: case3 hit a test-helper
NameError because Suite.case executes at definition before a later helper
declaration; no product assertion failed. Move pure mutation helpers above all
case declarations. To retain the slim runtime target, the successful exact
multi-identity agent / valid different generated-key stimulus may share case3
's genuine lost-B/D/F-only recovery ceremony, preserving every original key,
three-signature, batching, no-replacement/home and privacy assertion. Unsafe/
malformed/key-failure cases remain separate; no timeout or assertion is relaxed. No repeated native/host/build load overlap is allowed during diagnosis.

### Confirmed transport and terminal baseline setup

For the section24 live read fixture, the relay may consume/count the genuine TLS
ClientHello and withhold server bytes. Capture an actually live held connection
and its generation before the purity baseline, and require that same generation
to remain live/held after the read. This is outside every DB transaction, without
TLS impersonation/decryption or worker disabling. Refresh/release only outside
measurement. Preserve the exact whole-DB/state/home and BOTH relay counter
assertions, original delays/timeouts; any independent attempt still fails those
assertions. Do not assume all endpoints poll concurrently or treat a stale held
flag as a barrier. A bounded hold that expires before measurement ends is not
valid isolation or passing evidence.

For the section18 terminal fixture, after both participants actually apply keep
both peers online, explicitly register their genuine independently pinned peer
endpoints if needed and attempt one bounded ordinary network sync on each.
Observe actual dec_outbox retirement and absence of the rollback journal before
stopping the issuer and capturing the historical-read baseline. Sync success
alone does not prove acknowledgment. No queued category/journal is omitted and
no original offline/keyless/history assertion, delay or timeout is weakened.
The retained failed fixture later had zero outboxes/journals on both hosts; that
final observation does not identify the earlier baseline change direction or
its exact cause. Preserve unclassified failure attribution and instantaneous
scheduler/source limits. Every changed fixture is independently authored and
committed before its one corrected full run against the same frozen binary.

## 26. Native bounded original finalization

This human-only native slice composes the pure section24 inspection and bounded
section25 CLI after exact approved original consent. No Rust/API/schema change,
key inventory/selection, signing bytes, model tool/turn, persistence journal,
automatic fetch/sign/resume or requester commit. Existing approved worker
progress remains separate from pure human observation.

### Review and exact public terms

In an attached project's published join outcome, an approved owner review with
the exact completed original offer/selection/administrator prefix may offer
**Review original finalization**. It requires requester/new/nonmigration,
needs_owner_finalization, selection approved, commit not approved, all four
request_created/owner_offered/owner_selected/administrator_offered stages and no
F/manifest/activation/outcome. Existing host/person/network/device and immutable
section16 owner review/digest checks apply. It never prepares or approves owner
or administrator intent. Entry/Check owner consent/progress/Refresh/reload do
not implicitly fetch section24 or invoke signing.

The explicit review first checks current native terminal/root/conversation,
authoritative attached parent and host, immutable published join flow/outcome
and pure owner lookup. Require the same displayed approved owner consent and
immutable request pins. If that lookup already records the exact original F,
show global recorded evidence without section24 inspection or signing. Otherwise
one pure finalization inspect binds that exact owner review. Recheck authoritative
parent, flow, host and native context after IO before displaying controls.

Validate the complete closed section24 wrapper/request/review/effects, canonical
dates/IDs/public keys and domain-separated digest. Bind all flow/context/host,
owner/join review, request/intent/network/member/person/host/device/fixed-term
pins to the current approved owner snapshot and published flow. Exact original
offer/selection/administrator references, distinct current root/P/H IDs and
administrator public writer/signer/format/issuer are required. The native view
validates public projections; the daemon owns cryptographic proof verification.
No private prefix, extra/null/unknown field or inconsistent stage is displayed.

Show quoted project/network/member and participant public keys, original consent,
selected original offer/selection/administrator references, current root/P/H,
administrator identity/format/issuer, fixed profile7 with binding scope2, and
fixed expiry. Explain that the explicit action uses this approved original's
safe existing generated key or exact SSH-agent identity, at most two ordered
batches/three original signatures. It creates/copies/imports no key. It records
binding/device/finalization evidence, with requester commit, adopted powers,
agent access, files/conversation sharing, capabilities and readiness separate.
Leaving cannot retract already dispatched signatures or submissions.

### One explicit bounded signing action

Only a validated fresh inspection offers **Sign original finalization**. The
earlier of request.expires_at and fixed not_after bounds review/sign eligibility
using native and observed times; observation more than30s in the future refuses.
The original approved review's old15min window does not renew or remove consent.
An authoritative timer removes Sign at that effective deadline without signing,
renewing, cancelling, committing or replacing retained publication. Ordinary
stage-inactivity/root/P/H checks remain enforced by the daemon.

The first press synchronously sets busy, clears old actionable terms and makes
double presses inert. Recheck native/authoritative parent/host/immutable join,
pure owner lookup and the same approved consent. Already recorded exact F is
read-only recovery with zero inspect/sign calls. Otherwise re-inspect section24
and require exactly the displayed digest and entire review, immutable original
and exact offer/selection/administrator prefix. Recheck authoritative parent/
flow/host/native context and effective deadline immediately before dispatch.
Changed terms/state/context or unready work sends zero sign commands, never
silently rebinds the old press to a new review.

Invoke exactly the configured executable and literal --state argv:
onboarding join owner finalization sign --stdin
with timeoutMs95000 and exactly
{flow_id,context,join_review_id,owner_review_id,finalization_review_id,
 decision:"sign_original_finalization"}
in private stdin. Read calls retain5s; no payload/references in argv/shell,
broad link signing/resume/selection, administrator work, requester commit or
automatic retry. The95s native process bound is separate from section25's90s
asynchronous deadline. Timeout/Leave cannot retract an already used key or
dispatched/committed POST, and partial B/D/F may remain retained.

Accept success only as the complete section16 owner wrapper plus exactly
original_finalization:{state:"recorded",review_id:<captured inspection digest>,
packet_id:<typed F ID>}. Strip only that known marker before reusing full owner
validation. Require the exact approved immutable owner review/request pins,
same original offer/selection/administrator prefix and request F equal packet_id.
Reject bare snapshots, extra/null/malformed/private markers, changed digests,
packet/pins/keys/terms or invalid dates/stages. After dispatch later valid stages
and expired bounds may still show historical retained F; they grant no current
authority. Recheck authoritative attachment/flow/host/native context after IO
before display. No callback may restore a departed view.

### Recovery and volatile authority

**Check original finalization** is explicit pure owner lookup and, only while
still eligible with no F, pure section24 inspection. It neither signs nor
prepares/approves/polls/resumes. A completed F observed by Check is global public
evidence without attributing its creation or a historical inspection digest to
this pane. A missing F does not prove B/D were not partially signed. After a
failed/denied/timed-out/malformed signing result, report outcome unknown, clear
actionable terms, preserve publication and offer Check; another sign requires
a freshly displayed review and another explicit press. Never echo raw process
stdout/stderr, templates/messages/signatures/paths/agent comments or private data.

**Leave finalization review** remains available during preflight and pending
signing, clearing volatile review/digest/error/confirmation and callback
authority without cancelling/revoking protocol consent. Back/Close/Refresh/
root/conversation/host/parent/surface/session change does likewise. Old callbacks
or expiry timers cannot restore departed terms or disable a newer view. Current
adapter/message/task/lease runtime and inviter invariants remain unchanged;
no new prompt, hello, tool or frontend storage. Actual terminal/installed/
physical-machine/model/schema23-to27 acceptance remains separate. Previous
rejected terminal actions and unchanged quota-refused probes are not retried.

### Verification

A separate contract-only author adds one compact native finalization test file,
without reading product hooks/Rust or importing implementation helpers. Preserve
all original272 native files/assertions/stimuli/delays/timeouts and all22 host
suites. Genuine delayed fixtures signal dispatch/registration before navigation
or virtual time advances. Cover:

1. Inert entry/approval/progress/Check owner/Refresh/reload; only the exact live
   approved four-stage prefix offers Review, then explicit inspection displays
   complete quoted terms, bounded effects, separate commit/access/readiness.
2. Double Sign performs fresh authoritative parent/host/flow/owner/inspection
   checks and one exact configured95s stdin call. Changed prefix/consent/digest/
   root/P/H/admin/context/host/stage/deadline refuses; just-recorded F recovers
   read-only with zero inspect/sign. Future observations refuse.
3. Closed inspection/digest/effects/request/review/key/date/private corpus;
   strict success marker/packet/prefix/owner corpus. Bare/changed/private results
   cannot confirm; same-context later valid stages can confirm historical F.
4. Original review-window expiry alone preserves otherwise eligible signing;
   request/fixed end expires controls; preflight crossing blocks dispatch,
   post-dispatch crossing allows historical evidence. Stale timers cannot
   affect a newer view or automatically renew/sign.
5. Lost/denied/raw/timeout/mismatched results stay unknown without retry. Check
   uses only lookup/eligible inspection; missing F acknowledges partial-work
   uncertainty, completed F recovers without sign or historical attribution.
6. Leave/Back/Close/Refresh/root/conversation/host/parent/surface/end in preflight
   or after dispatch clears authority without retraction claims or runtime loss.

Run strict validation/full native suite, existing owner_finalization_signing6/
owner_finalization6, required Rust gates and all22 CI suites on one final head.
Record exact source/binary/test provenance, initial failures/corrections and
source/mock/manual limits. The test kit invokes current drawings; old retained
closures/narrow final-check-to-dispatch intervals remain source limits unless
a genuine deterministic fixture is available.

Selected: explicit pure finalization review, one bounded backend call and
lookup-first recovery. Discarded: more protocol/proof APIs, combined consent/
key use, frontend signer selection, hidden sign-as-read, retries/polling, new
journals and recorded F as requester commit or connection readiness.

## 27. Remaining flow contract

Teammate/device admission, remaining
native data tools/events and exact permission grants remain future sections. Section 2's live verification and the complete
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
