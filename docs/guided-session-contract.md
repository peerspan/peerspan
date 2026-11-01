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
Internal flow/review/intent/session/native identifiers remain private transport
bindings rather than displayed terms. Public network/context, participant keys,
packet/root/P/H references are displayable. Show original consent as the exact
already recorded person/machine/powers, without displaying its internal digest.

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
Use **Original finalization: recorded** for that global public evidence and
display its public F packet reference; this does not identify the signing UI.

**Leave finalization review** remains available during preflight and pending
signing, clearing volatile review/digest/error/confirmation and callback
authority without cancelling/revoking protocol consent. Back/Close/Refresh/
root/conversation/host/parent/surface/session change does likewise. Old callbacks
or expiry timers cannot restore departed terms or disable a newer view. Current
adapter/message/task/lease runtime and inviter invariants remain unchanged;
no new prompt, hello, tool or frontend storage. Actual terminal/installed/
physical-machine/model/schema23-to27 acceptance remains separate. Previous
rejected terminal actions and unchanged quota-refused probes are not retried.
Leave returns to the published joining outcome with no retained owner or
finalization review controls. A later owner/finalization review is explicit.

### Verification

A separate contract-only author adds one compact native finalization test file,
without reading product hooks/Rust or importing implementation helpers. Preserve
all original272 native files/assertions/stimuli/delays/timeouts and all22 host
suites' assertions/stimuli/delays/timeouts. Genuine delayed fixtures signal dispatch/registration before navigation
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

The first PR64 local owner_finalization_signing regression5/6 in93s exposed its
own unisolated case3 pure-inspection traffic baseline: each relay gained one
connection and zero bytes, ((13,69510),(11,61849)) to ((14,69510),(12,61849)).
Exact per-connection attribution remains unclassified; no product source changed
from PR62's passing binary. This suite has its own Relay/quiet helpers rather
than using the corrected section24 fixture. A separate contract-only author may
adapt section25's documented actual consumed-ClientHello/live-generation hold
setup to this suite before its one corrected full run. Keep every original
check, delay, timeout, DB/state/home category and BOTH complete relay counters.
No row edits, worker disabling, inferred stale holds, retry-until-green or omitted
categories. The initial failure remains evidence, not a pass; new native cases
are independently committed before any execution and are not changed to hide it.

First combined native CI275/292 (17 failures,44.82s) retained all original272
passes. Its positive projection used a drs_ root and administrator issuer '-',
instead of section24's verified statement parents and section25's packet issuer.
Here root/P/H are canonical distinct ds_ statement IDs; administrator issuer is
the verified canonical ds_ issuer, never the possession-only provider's '-'.
Fixtures must use those exact existing protocol forms, without broadening the
frontend to accept unsupported parents/providers. An unapproved section16 review
begins with the pending request/no owner prefix, then separate approval and
ordinary approved work may supply the four-stage prefix. A missing-owner negative
must remain missing/unapproved throughout any explicitly requested ordinary
preparation; returning a previous approved owner from that preparation is not
evidence that the frontend offered finalization without approved consent.
Independent setup corrections retain all positive/negative/privacy/dispatch/
timer assertions and original delays/timeouts. The first CI failures remain
recorded; no unchanged local duplicate run is needed before reconciliation.

The corrected host fixture47a050d ran5/6 in132s: original case3 passed, but its
single held TLS generation expired across case5's aggregate23-command typed
corpus (12.9s), causing the new guard to fail. Preserve the original whole-corpus
DB/state/home equality unchanged. Refresh/confirm the transport hold outside
each measured command and add per-command whole-DB/files, BOTH full relay
counters and same-live-generation checks. There was no aggregate corpus IO
assertion to remove. Refresh cannot occur inside an individual measurement;
ordinary writes while refreshing still fail the retained aggregate DB/files
equality. No longer TLS/command/test timeout, weaker guard or unchanged rerun.

Selected: explicit pure finalization review, one bounded backend call and
lookup-first recovery. Discarded: more protocol/proof APIs, combined consent/
key use, frontend signer selection, hidden sign-as-read, retries/polling, new
journals and recorded F as requester commit or connection readiness.

## 27. Exact requester final-commit consent backend

This backend slice records a separate exact requester decision over the existing
ordinary requester_commit intent. Reuse its verified selected original/F/finite
grants, templates, quota and owned-device checks. No new schema/table/journal,
original-key use, signing/transport/apply inside the guided route, native control
or blanket agent access. Bounded completion and native controls follow. The
ordinary approved worker may sign/publish work after durable approval; approval
alone proves neither a persisted commit nor local application/current powers.

### Private actions and fixed terms

Owner-local POST `/v1/onboarding/join-flows/{flow_id}/commit/lookup`, `/prepare`
and `/approve` accept exactly `{context,join_review_id}`; approve additionally
requires exactly `commit_review_id`. Private CLI
`peerspan onboarding join commit lookup|prepare|approve --stdin` accepts exactly
the same fields plus `flow_id`, one bounded5s daemon call each. Apply strict64KiB
duplicate/unknown/null/type/typed-ID/context/private-prefix validation and fixed
diagnostics. No raw IDs in mutation argv, key/provider choice, original-owner
approval, supplied terms/packet/grant/template/signature or automatic host start.
Only owner-local admin exposes these routes, never scoped/peer/bootstrap APIs.

Bind section16's exact published flow/context/outcome, this requester host,
new-original/nonmigration request and immutable approved original consent.
Fresh first preparation/approval requires the attached exact parent/agent, no
already adopted local network, needs_commit with the five exact completed
request_created/owner_offered/owner_selected/administrator_offered/owner_finalized
stages, selection approved, commit unapproved, complete retained original offer,
selection, administrator and F, no manifest/activation/outcome/terminal artifact.
Verify the ordinary full selected ceremony/current-root/catalog/finalization
projection and fixed profile7, binding2, original request-created+7d end. Root,
P/H/B/D are canonical distinct ds_ statement IDs. All pending references must
match the same original, network/member/host/device and approved owner offer.

Prepare creates or reuses exactly one ordinary unapproved requester_commit
intent, deriving its immutable guided review from those exact terms. Copying
the ordinary retained binding template is allowed; no binding-host/commit
signature, commit materialization, ciphertext/publication or local adoption.
An existing intent is found by its ordinary kind/operation, including before
pending.commit_intent_id exists; that reference is recorded only on approval as
the existing protocol requires. Do not introduce another retained reference.
Never replace/refresh an existing review/created_at/digest or duplicate an intent.

### Closed public projection

Return exactly:

```
{version:1,host_id,flow_id,join_review_id,context,observed_at,request,commit}
```

Request is the exact public LINK_VIEW. Commit is null when no ordinary intent
exists, including a valid published request with no F yet; lookup is not fresh
preparation eligibility. Prepare/approve without that required F refuse
commit_review_unavailable. Otherwise commit is exactly
`{review_id,review,state,next_action}`. Review is:

```
{version:1,kind:"approve_new_original_requester_commit",host_id,context,
 flow_id,join_review_id,owner_review_id,request_id,intent_id,network,member,
 person_public_key,host_public_key,device_public_key,request_packet_id,
 owner_offer_id,selection_id,administrator_offer_id,owner_finalization_id,
 root_state_id,person_lease_id,host_lease_id,binding_lease_id,device_lease_id,
 scopes:7,binding_scopes:2,not_after,provider,created_at,expires_at,effects}
```

Network is section11's public descriptor. Provider is exactly
`{kind:"requester",host_public_key,device_public_key,signature_format:"ed25519"}`
for this owned host/device, not a usable provider or original-key possession
claim. Created_at is ordinary intent.created_at; expires_at is the earlier of
that+15min, signed request deadline and fixed not_after. This finite review does
not extend the ordinary ten-minute stage inactivity bound. Review_id is review_
+SHA256(`"peerspan-requester-commit-review-v1\n"+canonical(review)`). Effects:

```
{approve_commit_intent:true,authorize_binding_host_signature:true,
 authorize_requester_commit_signatures:true,authorize_commit_publication:true,
 authorize_local_application:true,grant_agent_access:false,share_files:false,
 share_conversation:false,capability_calls:false}
```

State is approved if exact ordinary commit approval is retained, else cancelled
for cancellation, expired for signed/review/stage/intent expiry, invalidated for
detached/replaced/adopted/ineligible context, otherwise review. Next action is
follow_join_progress for approved, approve_requester_commit for review, otherwise
inspect_join_progress. Historical approval is global protocol evidence without
frontend attribution. It does not establish current authority/access/readiness.
No codes, seeds, private keys/paths, agent comments, templates, messages,
signatures, ciphertext, provider diagnostics or untrusted private strings leak.

### Atomic approval, pure recovery and bounds

Lookup is pure, including null/history. Prepare with an existing intent returns
the same derived review/state purely, including detached/expired history. First
prepare does not create intent on a failed eligibility/parent/time check.
Approve requires a retained intent and exact captured commit_review_id, never
implicitly prepares. Exact approved replay is pure before fresh eligibility or
device-key work, even after detach/restart/expiry/cancellation/application. A
different digest refuses review_changed without updating anything. Pruned
ordinary state returns request_unavailable; never recreate its consent/history.

Fresh approval checks exact attached parent/agent/context, original consent and
full ordinary projection again in one SQLite transaction. Reuse ordinary
owned-device availability and quota checks. Raw local time as well as guarded
time must be at/after request/stage/intent creation and before review/signed/
fixed deadlines; stage inactivity must remain live. Recheck time, parent/agent,
original terms and the derived exact digest before committing. Atomically set
the ordinary intent approval/approved_at and request commit_approved/
commit_intent_id, remembering guarded time in that same transaction. No failed
check leaves a partial intent/approval/reference/clock update. No route-driven
key signature, transport or local application; after-commit ordinary work is
separate and must not be attributed to the pure reader or this transaction.

Malformed400 invalid; unknown flow404; nonrequested flow409 state_conflict;
wrong flow/context/join/commit digest409 review_changed; detached fresh parent
409 review_changed; expired fresh work409 review_expired; pruned request409
request_unavailable; unsupported/missing/corrupt/ambiguous projection or absent
intent409 commit_review_unavailable. Other HTTP methods405. CLI failures are
controlled nonzero, no retry/stdout or stderr echo of supplied private values.
Raw local time before request/stage/intent creation is commit_review_unavailable,
including within the shared clock-clamp allowance; actual elapsed review/signed/
fixed/stage bounds are review_expired. Pure failures never advance the clock.
Successful lookup/prepare/approve are HTTP200. Atomic fault fixtures may install
temporary schema-only BEFORE INSERT requester_commit-intent and BEFORE UPDATE
approval-record ABORT triggers for the genuine operation, then remove them
before exact rollback comparison; require controlled non2xx, not an invented
SQL-error code. Fresh needs_commit has manifest/activation/outcome all '-'; a
mock mapper that invents manifest at that stage does not override real protocol
evidence. Keyless history may use absent original generated/agent sources with
the external original never installed; unavailable owned-device seed lacks a
public deletion operation and remains an explicit source/fault limit.
After-commit worker work may precede the HTTP response; verification must not
assert global post-response signatures/publication are absent or attribute
their creation to the route. A coherent ordinary-intent/request snapshot proves
atomic approval, strict preapproval absence and SQL rollback remain mandatory,
and route-only no-signature/transport/application is a source boundary without
genuine public synchronization. Do not add a pause-worker endpoint to force it.
Ordinary explicit completion/application may follow approval in the fixture;
no automatic local application by this review route is claimed.

### Verification

A separate contract-only author adds small requester_commit6 coverage and the
23rd CI registration. Preserve all old22 host cases/assertions/delays/timeouts
and all292 native files/assertions/stimuli/delays/timeouts. Genuine distinct
people/two temporary hosts reach F through existing approved protocol/signing
before this review; no fabricated authority/protocol rows. Isolate independent
workers with documented confirmed live transport holds around each measured
pure call; preserve strict whole-DB/state/home and BOTH full carrier counters.

1. Exact API/CLI null lookup, unapproved preparation/public digest/parent/provider/
   fixed terms, stable repeated pure prepare/lookup and no new schema/signature/
   commit/publication/adoption before approval.
2. Exact approval atomically records one existing ordinary intent and both
   request pins; no duplicate preparation, hidden signature/transport/apply or
   new journal. Ordinary approved background work is separate global evidence.
3. Missing/unapproved/F-absent/wrong context/review/parent/host/terms/prefix,
   deadline/stage/raw-clock/cancellation/adoption refuse without partial state.
   Inactive/corrupt/unavailable key/root variants without a genuine public
   stimulus remain source/fault limits rather than fabricated authority rows.
4. Genuine SQL write failure rolls back the whole preparation/approval and clock;
   remove the temporary fault trigger before comparison. No new approval is
   inferred from a transport acknowledgment or a created intent alone.
5. Strict JSON/64KiB/CLI/privacy/method/scoped/peer/bootstrap/no-startup boundaries;
   prepared expiry/detachment still has pure stable review/history, no renewal.
6. Exact approved replay is pure after key absence/detach/restart/expiry and
   same-request ordinary explicit completion/application. Immutable review/digest
   stays stable and a wrong digest refuses. No installed/physical/native/model
   readiness is inferred; original private keys stay with their participants.

Run Rust fmt/tests/Clippy/all-bin, native292, existing finalization signing6 and
join12 plus new requester_commit6 serially locally; all23 suites and required PR
checks/fresh review on one final head. Record failures/corrections, hashes and
source/manual limits. Existing transport hold/terminal cleanup isolation rules
remain; no retries until green or assertion/timeout weakening.

The first final-head CI on 9335093 passed 22 suites and standard PR checks but
delivery failed 11/5: join_with_no_direct_path timed out waiting for the inviter
to apply, then four dependent cases failed. The preceding identical runtime/
test/workflow sources passed all 23; this does not classify the timeout. Its
retained runner directory was discarded, leaving no host-state diagnosis.
Keep the failed run in the verification record. A separate contract-only author
may add closed, bounded failure-only diagnostics to this existing delivery
case after its original wait fails. Preserve every original assertion, protocol
action, delay and timeout. Reuse the already returned commit result and at most
one pure request-view GET per participant, each bounded 2s; print one public
summary containing only HTTP status, known stage/state/attention enums and
booleans for retained stage/approval/application presence. Unknown values become
a fixed marker. Never print keys, codes, locators/capabilities, signatures,
templates, paths, labels, raw errors/bodies or database records. Diagnostics
must not sign, resume, publish, apply, retry, change the verdict or mask the
original failure. This improves evidence retention without changing successful
test behavior. A fresh CI run of the changed diagnostic source is not evidence
that the original timeout's cause is known.

Selected: reuse ordinary immutable requester intent for exact durable consent
with pure recovery, then add bounded completion/native controls in the following
slice. Discarded: new consent storage, direct broad commit/resume-as-observation,
combined original/requester approval, hidden key/sign/transport/apply inside the
review route, automatic agent access and approval as connection readiness.

## 28. Bounded completion of approved requester consent

This backend slice completes only the separate exact requester consent retained
by section 27. Native commit controls follow in another small PR. Reuse the
ordinary requester intent, typed host/device signing, finite protocol terms,
sealed frames and participant application. Add no schema, journal, original-key
selection, approval, provider fallback, agent grant or readiness claim.

### Explicit private action

Owner-local POST `/v1/onboarding/join-flows/{flow_id}/commit/complete` accepts
exactly `{context,join_review_id,commit_review_id,decision}` where decision is
exactly `complete_requester_commit`. Private CLI
`peerspan onboarding join commit complete --stdin` accepts the same fields plus
`flow_id`. Apply section 27's strict 64KiB duplicate/unknown/null/type/context/
typed-ID/private-prefix validation and fixed diagnostics. Require explicit
stdin, one daemon call bounded 95s and no automatic host start. Only the private
owner-local admin router exposes this action, never peer/scoped/bootstrap APIs.
No raw mutation IDs, keys, provider choice, grants or supplied terms in argv.

Bind the exact published flow/outcome/requester host, immutable original consent
and captured section 27 review digest before any new work. The ordinary intent
must already be approved, with matching pending commit_approved/commit_intent_id.
Never prepare, approve, replace or extend it. A missing/unapproved intent refuses
purely. A different digest refuses review_changed, including historical replay.

An already locally applied matching operation returns a verified retained
application purely before fresh parent/deadline/device-availability checks,
including detach/restart/expiry/key absence. Validate the immutable application
and its saved consent/catalog at its saved application time; do not infer
current authority from historical consent. A completed replay performs no
signing, publication, cleanup, repair, key selection or clock write. Existing
section 27 lookup remains the pure progress/uncertainty recovery path.

### Bounded work under existing authority

Fresh work requires the same attached project/agent, new-original/nonmigration
request, approved original and requester consent, exact original/selection/
administrator/F and root/P/H/B/D/fixed profile 7 / binding 2 / seven-day end.
Allow the existing approved intent's partial or already signed/sealed commit;
reuse its exact retained objects without recreating signatures or another
intent. Refuse cancellation, pruned/corrupt/ambiguous evidence or incompatible
local network adoption. The existing full ordinary cryptographic projection,
owned-device and quota checks remain authoritative for signing/application.

Fresh raw local time must be at/after request/stage/intent creation; effective
raw plus guarded time must remain before signed request deadline and fixed
powers end. New unsigned work also obeys the ordinary 600s stage inactivity
bound. The 15-minute human approval window does not revoke a previously recorded
approval; it is not extended or rewritten. Already signed/framed work follows
ordinary publication/application eligibility, with fresh signed/fixed bounds.
Check parent/agent, raw/guarded time, exact approval/digest and full ordinary
projection inside each signing transaction, immediately before new key work and
again before committing. Signing is limited to this ordinary requester intent:
remaining binding-host signature, commit materialization, remaining commit
host/device signatures and exact catalog/commit frame retention, at most four
changing phases. No broad ceremony resume, original/administrator signing,
mailbox GET or automatic consent. Existing workers may independently advance
this already authorized work; global observations cannot attribute signatures
or publication to this command.

Make at most one ordinary exact-request publication pass before application,
bounded 30s, then one after application, bounded 30s. No hidden retry/polling or
new addresses/providers: use existing pinned participant/carrier resources and
ordinary per-pass bounds. Carrier failure alone does not prevent otherwise
valid local application. Recheck the exact parent/agent/time/consent immediately
before and after the pre-application IO pass; a changed parent or elapsed bound
stops new application. Existing ordinary workers and already dispatched IO are
separate; leaving/timing out cannot retract their effects.

Local application performs the existing complete verification and one guarded
transaction for network/catalog/operation/event/device-provider/outcome/secret
retirement. Check the exact guided parent/agent/digest/time in that transaction,
before outcome-key use and before commit. An installed network is accepted at
the final check only for this same verified operation applied by this
transaction, never an unrelated adoption. Failed application rolls back its
whole application transaction; earlier independently committed signatures,
frames, approval or transport are not rolled back or falsely called atomic.
After application, changed parent/time may suppress the remaining IO pass;
returning verified retained application is still historical observation.

One server attempt is bounded 90s with a monotonic deadline checked before each
new signing/application phase and final commit. Timeout/refusal may leave prior
authorized phases; report controlled outcome unknown and use pure lookup before
another explicit action. A blocking operation or already dispatched network
request cannot be retracted by client cancellation. Do not start another phase
after the deadline; microscopic final-check-to-key/commit crossings remain a
source limit. No new background job or persistent attempt record.

### Closed result and failures

HTTP 200 means verified local application exists, never only approval, a
signature, carrier ACK or a pending operation. Return section 27's exact closed
public wrapper plus exactly `completion`:

```
{state:"locally_applied",review_id:commit_review_id,manifest_id,activation_id,
 outcome_id,participant_delivery:"not_verified",agent_access:"not_verified",
 connection_readiness:"not_verified"}
```

The three retained packet/operation references equal the returned request's
manifest/activation/outcome references and the verified ordinary application.
Commit remains the exact approved immutable review/state. This is global
retained evidence without command/UI attribution or current powers/readiness.
Repeated completed results have stable commit/completion values; observed_at
and the ordinary public request view remain observations. Do not return private
codes, seeds/keys/paths, templates/messages/signatures/ciphertext, locators/read
capabilities, raw provider/transport/SQL diagnostics or untrusted private values.

Malformed400 invalid; unknown flow404; nonrequested flow409 state_conflict;
wrong flow/context/join/commit digest or changed fresh parent409 review_changed;
pruned request409 request_unavailable; actual fresh signed/fixed/unsigned-stage
expiry409 review_expired; missing/unapproved/unsupported/corrupt projection,
early raw time, timeout or otherwise incomplete work409
commit_completion_unavailable. CLI failures are fixed nonzero diagnostics with
no supplied private value/raw response echo and no retry. Other methods405.

### Verification

A separate contract-only author writes requester_completion6 and registers the
24th CI suite, without reading Rust/hooks or using implementation helpers. Keep
all 23 existing host suite assertions/actions/delays/timeouts and native 292
unchanged, including section 27's failure-only delivery diagnostics. Real
separate people and two temporary hosts reach genuine approved F/requester
consent through public APIs and existing signing. No authority/protocol-row
fabrication, key/seed deletion, worker disabling or retries until green.

1. Exact API/CLI completion of the same approved intent through genuine local
   application, independently verified manifest/activation/outcome references,
   stable immutable review/digest/approval, no new consent/schema/store and no
   original key use. Partial/already signed work is reused; independently
   scheduled worker work has no route attribution.
2. Missing/unapproved/F-absent/wrong captured digest/context/parent, cancellation,
   early raw time and unsigned-stage/signed/fixed expiry refuse without new
   consent/application. Use genuine public stimuli and strict whole DB/files/
   BOTH carrier counters for genuinely pure refusals under confirmed live holds;
   do not assert global postapproval absence while authorized workers advance.
3. Existing deterministic protocol barriers/public parent or clock changes
   exercise checks before fresh application and its final transaction where
   genuine synchronization permits. Changed context stops new guided application
   without claiming to revoke existing worker consent or dispatched IO. Narrow
   key/commit races and nonattributable worker phases remain source limits.
4. A temporary schema-only application INSERT ABORT trigger over genuine
   completion proves no partial adopted network/operation/event/provider/outcome
   or secret retirement. Remove it before comparison. Earlier valid signatures/
   frames/publication may persist; preserve exact ordinary approval/review and
   make no false whole-command rollback claim.
5. Strict JSON/64KiB/CLI/private-prefix/no-startup/method/scoped/peer/bootstrap
   boundaries and closed public projection/privacy; bounded explicit action,
   no repeated call or inline approval. Unavailable devices/root/corrupt/pruned/
   incompatible-adoption variants without a genuine public stimulus are recorded
   as source/fault limits, never fabricated authority rows.
6. Verified applied replay is pure with stable commit/completion after detach,
   restart, expiry and absent external original/generated/SSH-agent sources;
   wrong digest still refuses. Compare whole DB/state/home and BOTH complete
   carrier counters. Actual participant delivery/application can be checked
   separately through existing explicit repair; local application never proves
   agent access, messages, capabilities or physical/installed/model readiness.

Run required Rust fmt/tests/Clippy/all-bin, strict native validation/native292,
existing requester_commit6, delivery16 and new requester_completion6 serially
locally. Run all 24 suites/PR checks and fresh review on one final head. Commit
exact source/binary/test/log provenance, failed runs/corrections and limitations.
Retain the earlier section 27 delivery timeout as unclassified; do not erase it
or weaken its assertions/timeouts. No unchanged retry to hide a failure.

Independent clarification: inject the application fault with a temporary
BEFORE INSERT ON dec_operations ABORT trigger for this canonical request_id.
Its failure occurs late enough to prove the preceding application writes roll
back in the same transaction; do not edit networks or authority rows. If another
already authorized participant application wins while a guided command waits
at an existing barrier, exact retained application takes historical precedence
and may return200 purely despite a subsequently changed parent/time. It is not
evidence of guided application after that change. A guarded-refusal case must
establish no prior application; otherwise report the competing-work source
limit. Do not disable workers or fabricate an unapplied fixture.

A partial-signature barrier is not a transport hold. If parking an already
approved worker prevents a genuine consumed ClientHello from existing, do not
claim live carrier isolation or omit either carrier counter. Preserve exact
already-signed bytes/signatures when completing genuine partial work. Measure
early raw time and signed/fixed expiry under real confirmed holds; the narrow
approved-but-unsigned stage-expiry interval remains an explicit source/barrier
limit without a reliable public stimulus. Existing ordinary join-stage timeout
coverage remains unchanged. Actual application-barrier parent/clock changes and
late INSERT rollback still require real synchronization as specified above.

First section 28 local native validation passed, but the full unchanged suite
passed287/292 in71.32s: five unrelated existing cases hit their 5000ms runtime
timeout while an external Clippy compilation overlapped on the shared host.
Retain that run and the observed load; this is not a product regression finding
or proof of exact per-case attribution. One corrected full run may follow after
the actual external compilation ends and the host is idle, with all292 cases,
source/assertions/stimuli/delays/timeouts unchanged. Verify process isolation
around the run; do not hide a failure by repeated unchanged execution.

Successful ordinary application changes the completed requester intent's
terminal lifecycle value to applied. Its prior record otherwise remains exact,
including immutable consent, templates and signature bytes; do not require the
pre-application terminal value to survive, or omit arbitrary intent fields from
comparison. Application proof-publication dec_outbox state belongs to the
application transaction and must roll back. It is distinct from earlier sealed
carrier frames/acknowledgments; do not exclude the entire proof outbox as an
earlier signing phase. Participant delivery after intentionally unavailable
carriers may need a separate bounded ordinary repair on the already applied
requester before waiting for the recipient. That setup action is neither a
guided completion replay nor evidence of transport performed by a pure reader.
Keep the first independent CI execution before adapting any fixture expectation.

The first independent requester_completion CI run on3ce0fe4 passed4/6 in95s.
Its positive setup dropped every carrier while awaiting ordinary signed/framed
progress, timed out at its existing15s observation bound, and left history's
prerequisite missing. The missing/unapproved/privacy, late fault and actual
parent-barrier cases passed. Preserve this result. To observe genuine ordinary
worker progress, make its authentic retained mailbox carrier reachable before
that bounded wait; drop/stall controls apply later, outside observations. This
adds no signing/resume loop or approval. The independent author may correct this
setup and the lifecycle/outbox/explicit-repair expectations clarified above,
retaining every timeout, private corpus, cryptographic check and rollback/purity
category. No unchanged rerun or production change is inferred from this failure.

Corrected section28 CI c686831 passed5/6 in88s. Historical setup completed the
explicit requester repair, actual recipient application, both pinned peer
registrations and both sync calls with200/unavailable=[], then its unchanged5s
outbox/journal quiescence wait failed. The failed category and cause are unknown;
the runner discarded retained state. Runtime retry eligibility can be scheduled
up to60s ahead; a successful bounded catalog sync is not proof of queued ACK.
Before changing setup, independently add failure-only diagnostics at this wait:
fixed participant role, total outbox count and journal-present boolean; documented
outbox records project only kind enum, attempts, due-now/seconds-until-next,
whitelisted public error code (otherwise unknown), and a boolean indicating
whether the target is the other participant. Reuse existing sync responses for
attempted/unavailable counts. Never emit raw rows, targets/keys, locators, paths,
bodies, signatures, error detail or private state. Diagnostic exceptions must
preserve/rethrow the original failure. Run once locally with retained fixtures
against the frozen binary; preserve all original actions/assertions/timeouts and
strict DB/file/BOTH-carrier categories. Classify only actual retained evidence.
No timeout increase, manual queue edit, worker disabling or unchanged CI retry.

The diagnostic-source final candidate ec4d63d failed historical setup5/6in95s.
Its closed evidence identifies requester outbox_count=1: kind=proofs, attempts=4,
target_is_other_participant=true, due_now=false, seconds_until_next=8. Issuer
outbox_count=0 and both journal_present=false; both prior sync calls attempted
one peer with zero unavailable. Thus that run's five-second baseline wait ended
before the documented ordinary retry was eligible. The previous CI runner's
missing category remains unclassified; the passing local run is not a fix.

For this terminal fixture only, after genuine repair/participant application,
peer registration and both existing bounded sync calls, read the documented
next_attempt_at timestamps from all retained outbox rows on both participants.
Outside any measured purity baseline, set both existing debug clocks once to
the maximum of current participant times and retained retry timestamps, plus
one second. Validate the target is no more than the documented60s retry horizon
plus that one-second margin ahead of current shared time and remains before the
live request/authority bounds. Do not filter out rows/categories, change queued
records, reset attempts, force ACK, disable workers or introduce protocol calls,
clock/poll retry loops, sleeps or larger waits. The ordinary worker must actually
acknowledge and retire every outbox row; preserve the original5s quiescence wait,
closed failure observer, all complete DB/state/home/BOTH-counter assertions and
every original action/delay/timeout. Independently commit this setup before one
corrected full local run against unchanged frozen production.

GU.impl28h diagnostic extension: later CI on a45d70a passed5/6in86s,
with the requester proof row attempts4, due_now=false and11 seconds until retry,
both journals absent and successful prior sync responses. The existing one-time
alignment already followed those responses. This does not identify when the
row was rescheduled or why the ordinary send failed. Before changing setup,
a separate author may capture closed before/after-alignment retry generations
and the failure-time projection: role, opaque row-ID hash, kind, attempts,
due eligibility/seconds-until-next and fixed public error/transport categories.
Reuse existing row reads where possible; at most one bounded extra read-only
capture immediately after alignment, outside every purity baseline. Keep
metadata only in memory and print only on the original failure. No raw rows,
keys, targets, paths, locators, bytes or error detail. Helpers/captures/wrappers
must normalize back to the exact prior source/AST; original assertions, action
order, clock advance count, five-second wait, delays and BOTH-carrier/DB/files
checks remain unchanged. One retained diagnostic run may follow; a passing run
cannot classify the earlier failure or be called a timing fix. No repeated
clock advances, forced ACK, extra protocol calls or unchanged retries.

GU.impl28i terminal transport prerequisite: diagnostic CI4d262bf5/6in84s
identifies the same requester proof row at attempts3/due-now before and after
alignment, then attempts4/transport_unavailable with11s until retry. Thus a real
retry failed after alignment; further clock stepping does not establish
reachability. The diagnostic local6/6in131s is retained without claiming a fix.
The fixture advertised no QUIC path. Bootstrap repair/successful catalog sync
does not establish normal authenticated peer publication or queued ACK.

For terminal_delivery_baseline only, after both genuine participant applications
and all earlier bootstrap hold/barrier cases, configure supported daemon
transport/restart with real advertised normal peer QUIC paths through transparent
counting UDP proxies. Preserve exact identities and original state; before
relying on delivery, observe genuine authenticated peerspan-peer/1 catalog200
in both directions. Exchange genuine signed current contacts through the
documented authenticated participant contact routes so each participant actually
retains the other's newly advertised counted path before retry alignment;
an isolated direct probe200 is not evidence that queued delivery knows that
path. Bounded setup exchanges are outside the historical baseline and never
create authority or replace a host key. A genuine short-lived contact-only
invitation handoff may supply refreshed signed contacts after configuration
restart; import the exact signed contact objects only through authenticated
participant contact routes and verify their actual retention. Its expiry must
remain before the original request deadline used by terminal cleanup; preserve
that cleanup action and observe its ordinary secret/frame/read-cap retirement.
Retain the existing two peer registrations, both syncs,
one bounded retry alignment and unchanged5s strict all-outbox/journal wait.
Ordinary workers must actually acknowledge and retire every queued category.
Keep all earlier transport actions effective. Append all newly enabled UDP
datagram/byte counters to traffic accounting, preserving BOTH original TCP
relay counters and all original DB/state/home/counter assertions, actions,
delays and timeouts. No authority/queue edits, forced ACK, worker controls,
unmeasured bypass, extra retry-clock/protocol loop or unchanged CI retry. A
separate contract-only author commits setup before one corrected retained run
against frozen production. This correction does not classify prior runs that
discarded their missing evidence.

GU.impl28j historical carrier diagnosis: first corrected local access passes
6/6in97s; old completion5/6in131s now passes its genuine delivery/ACK retirement
prerequisite and expired/detached historical replays, then fails the restarted
API replay's carrier assertion. Its immediately preceding whole DB/state/home
assertion passes. The specific carrier, amount and traffic origin were not
captured. Do not infer that replay caused the traffic. Before a further setup
change, a separate author may add a failure-only wrapper over already captured
expected/actual traffic tuples at the original assertions. Print only fixed
phase/mode, participant role, TCP/UDP kind and nonnegative connection/datagram/
byte deltas. No identifiers, endpoints, raw protocol data or paths; no new IO,
actions, waits or mutations. Return the actual tuple unchanged and preserve the
original assertion expression. Removing the helper/wrappers must restore exact
prior source/AST. Commit before one retained diagnostic execution on frozen
production. Keep every original assertion/action/delay/timeout and all TCP/UDP
categories. No unchanged rerun, guessed cause, hidden transport exclusion,
worker control or larger wait.

GU.impl28k startup observation: the retained diagnostic run5/6in154s identifies
only the issuer UDP counter changing during restarted API history:2 received
datagrams/2400 bytes, zero return datagrams/bytes; DB/state/home and both TCP
counters are unchanged. That is evidence of attempted traffic toward the stopped
issuer, not attribution to a specific API or background subsystem. The public
directory contract requires startup peer queries and keeps their results in
memory; owner socket readiness and the fixture's short stable samples do not
establish their completion.

For this fixture's restarted phase only, immediately after the existing requester
restart and before its unchanged quiet check/baseline, issue one owner-local
`POST /v1/directory/refresh?network=EXACT_ID` with `{}`. Await its documented
synchronous result (server at most10s, client bound12s), validate the exact
network and the known issuer's completed non-pending entry; the intentionally
stopped issuer's truthful state is error. Never require successful connection,
invent grants, echo error text, clear peer state or reset authority. Verify
ordinary current authority remains usable at fixture time. Keep all original
actions, waits, sleeps, API/CLI history/refusal/DB/state/home and BOTH TCP plus
all UDP assertions intact. This genuine setup observation establishes that
refresh completion only, not a global transport fence or retrospective cause.
No repeated refresh, larger original wait, arbitrary sleep, worker/path control
or counter exclusion. An independent author commits before one corrected full
run against unchanged frozen production; retain any further failure as evidence.

Selected: a bounded owner-local continuation over already approved ordinary
consent, then separate native controls. Discarded: broad resume as observation,
implicit approval, a new consent/job journal, original-key fallback, carrier
ACK as authority, whole-command rollback claims across prior phases and local
application as a ready connection.

## 29. Native requester consent and completion

This human-only native slice composes sections27/28 after original finalization.
It changes no Rust/API/schema/protocol, key inventory/provider selection, model
tool/prompt/turn, frontend storage or adapter/message/task/lease behavior. Separate
explicit review, approval and completion remain distinct human actions. Existing
authorized workers may sign or publish after approval; no pane attribution or
global absence is inferred. Preserve all24 host suites and292 native tests.

### Entry, exact review and lookup-first recovery

Within the attached project's published requester/new/nonmigration outcome,
the exact approved original consent and recorded original F expose **Review
requester commit**. Offer this beside recorded-F evidence in both the original
finalization pane and owner pane; no original-signature/finalization action
implicitly prepares, approves or completes requester consent. Ordinary entry,
join progress, owner Check, Refresh/reload and original approval/signing remain
inert with respect to these new actions.
Recorded F may expose this explicit entry for expired/cancelled historical
requests as well; only null consent with exact live eligibility can prepare.

An explicit Review checks native terminal/root/conversation, authoritative exact
attached project and host, immutable published join flow/outcome and pure owner
lookup. Require approved original consent and immutable request/person/host/
device/network/offer/selection/administrator/F pins. First call only section27
commit lookup. An existing review, including approved/expired/cancelled/invalid
history, is recovered without preparing or refreshing it. Only this explicit
Review, a null lookup and the exact eligible needs_commit five-stage F prefix
permit one prepare call. Never combine prepare with approval or completion.
After IO recheck authoritative parent/host/flow/native context before display.

Inside the requester pane **Check requester consent** repeats pure owner and
commit lookups, with no prepare/approve/complete/progress/fetch/resume/sign call.
It may report null consent or retained historical states. After lost responses
or reload, reenter through published outcome/owner lookup and explicit Review;
lookup precedes any potential first preparation. No polling or hidden retry.

Validate section27's complete closed wrapper, LINK_VIEW, commit/review/effects,
canonical UTC dates, typed IDs and public keys, fixed profile7/binding2/seven-day
end and requester provider. Verify its domain-separated canonical review digest.
Bind all host/context/flow/join/owner/request/intent/network/member/person/host/
device/packet/offer/selection/administrator/F references to the approved original
and published outcome. Require five distinct canonical root/P/H/B/D statement
IDs, exact provider host/device/ed25519, intent-created>=request-created and
review expiry=min(intent-created+15min, signed request deadline, fixed end).
Review and approved states/actions must agree with exact request approval and
complete prefix. Approved requests may advance through commit retention and
local application between calls without changing immutable consent/F pins.
History can outlive the human review/request/powers bounds; it confers no
current authority. An observation more than30s in the future, malformed/null/
extra/unknown/private value or inconsistent request/state refuses display.
The frontend validates public projections; cryptographic verification remains
the daemon's responsibility. Internal flow/review/intent/native/session IDs are
private transport bindings, not displayed terms.

Show quoted project/network/member, public network/context/genesis root and
person/host/device keys; original consent and exact offer/selection/admin/F;
root/P/H/B/D references; fixed powers and their end; human review and signed
request expiry; owned requester provider/ed25519. Explicitly state profile7 is
policy editing1, host binding2 and eligible own-device approval/renewal/revocation4,
without network administrator8. Approval authorizes existing intent, binding-host
and requester signatures, commit publication and local application. Files,
conversation sharing, capability calls and agent-access grants remain none.
Completion uses owned host/device keys, never selects/creates/copies/imports an
original key. Separate participant approvals remain intact. Leaving cannot
retract durable consent, prior valid signatures/publication or dispatched work.

### Separate approval and bounded completion

Only an exact live state=review offers **Approve requester commit**. The first
press synchronously makes the pane busy and invalidates old callbacks. Repeat
authoritative native/parent/host/flow, pure owner lookup and pure commit lookup;
require exactly the displayed immutable review/digest and original/F pins.
If that exact consent is already approved, recover it read-only with zero
approval calls. Otherwise recheck all attachment/context/host/flow authority and
native time after asynchronous preflight immediately before dispatch. Require
native/observed time>=request/intent creation and before review/request/fixed
bounds. Stage/raw/guarded/root/device eligibility stays enforced by the daemon.
One configured executable/literal --state private-stdin command, timeoutMs5000:

```
onboarding join commit approve --stdin
{flow_id,context,join_review_id,commit_review_id}
```

Accept only the exact approved section27 wrapper with unchanged immutable review
and pins. Recheck authoritative parent/host/flow/native context after IO before
display. Approval never dispatches Complete automatically. It may already have
authorized independent ordinary signatures/publication, without pane attribution.

Only exact approved consent with a live signed request/fixed end, selection/F
and no local application offers **Complete requester commit**. The old15min
review window alone does not revoke durable approval or disable otherwise live
completion. An authoritative timer removes Approve at review/request/fixed end,
and Complete at request/fixed end; it does not renew/read/retry or mutate state.
Before Complete repeat the same authoritative checks and pure owner/commit
lookups, require exactly the displayed approved review/digest and immutable
original/F prefix. A just-recorded local application is read-only recovery,
zero Complete calls. Changed consent/state/prefix/context/time sends zero
mutation calls; never silently rebind an old press to another review. Recheck
native clock after asynchronous preflight before dispatch. One configured
executable/literal --state command, timeoutMs95000, exact private stdin:

```
onboarding join commit complete --stdin
{flow_id,context,join_review_id,commit_review_id,
 decision:"complete_requester_commit"}
```

No private payload/references in argv/shell, broad link commit/resume, original
or administrator signing, polling or automatic retry.95s client/90s server
bounds and partial-work/cancellation limits remain those of section28.

Accept completion success only as the full section27 wrapper plus the exact
section28 completion marker, state=locally_applied, captured commit review ID,
typed manifest/activation/outcome references equal the same linked request,
and all three not_verified delivery/access/readiness values. Require identical
approved immutable review, original/F/request pins and complete seven-stage
prefix. Bare snapshots, wrong/missing/null/extra/private markers or references,
changed review/digest/keys/terms and malformed dates/states cannot confirm.
After dispatch elapsed protocol bounds may show retained historical application;
fresh attachment/context/host/flow/native display guards still apply. Recheck
those authoritative guards and future-time bound after IO before display.

### Volatile state, uncertainty and truthful evidence

After failed/denied/timed-out/raw/malformed/mismatched approval or completion,
show fixed outcome unknown, clear actionable terms and offer Check. Another
mutation requires freshly displayed terms and an explicit press; raw stdout/
stderr/errors and private codes/paths/templates/signatures never reach UI/logs/
model events. Check may report **Requester consent: recorded** and **Local
application: recorded** from exact global public history, without attributing
the approving/completing interface or inventing an old completion marker/digest.
Only a valid explicit completion reply confirms its exact section28 marker.
Both sources may display the literal Local application: recorded and its public
manifest/activation/outcome references. Marker-specific prose stays truthful
to the source; no historical marker/digest attribution is invented by Check.
Neither recorded approval nor application establishes current powers, participant
delivery, agent access, files/conversation/capabilities, connection or model
readiness. Absent application evidence does not prove earlier work is absent.

**Leave requester review** remains available during preflight/pending mutations.
It clears volatile review/digest/error/confirmation and callback/timer authority,
returns to the published join outcome, and does not cancel/decline/revoke
protocol consent. Leave clears owner, finalization and requester panes together;
later owner/requester review is explicit again.
Back/Close/Refresh/project/root/conversation/host/parent/surface/
session changes invalidate old callbacks likewise. Late reads/results/timers
cannot restore a departed pane or disable a newer pane. No new journal/recovery
store, adapter credential, prompt, model tool or message/task/lease change.
Actual terminal/installed/physical/model/schema23-to27/full-state recovery gates
remain open. Do not repeat earlier rejected terminal/quota probes.

### Verification

A separate contract-only author adds one compact independent native test file,
without reading hooks/Rust or importing product helpers. Preserve original292
native files/assertions/stimuli/delays/timeouts and all24 host suites unchanged.
Model exact public backend projections from sections27/28; fresh needs_commit
has no manifest/activation/outcome, and later real prefix advances are separate
fixtures. Retained old callback closure limitations stay source/manual where
the public kit cannot deliver them. Deterministic delayed fixtures must signal
real command dispatch before navigation or clock changes. Cover:

1. Inert entry/owner/progress/Refresh/reload, exact approved original+F entry;
   lookup before explicit first preparation; existing/null/history recovery and
   Check never prepare/approve/complete. Complete public quoted review/effects.
2. Separate fresh approval and completion; double presses produce one exact
   configured5s/95s private-stdin mutation after fresh authoritative checks.
   Already approved/applied preflight recovers read-only with zero mutation.
   No automatic completion after approval, no original key use/frontend storage.
3. Closed wrapper/review/digest/effects/provider/date/ID/private-prefix corpus;
   exact original/F/root/P/H/B/D/request/profile/end binding. Changed preflight
   terms/parents/host/flow/context/native terminal or time sends zero mutation.
4. Strict approved and completion reply corpora, exact marker/reference/not_verified
   values, unknown outcomes on nonzero/timeout/raw/malformed/bare replies, pure
   explicit Check recovery and no interface/historical marker attribution.
5. Review15min expiry disables approval but preserves otherwise live approved
   completion; request/fixed end disables completion. Post-async preflight
   crossing blocks dispatch; post-dispatch expiry permits historical reply;
   future observations/early time refuse, stale timers cannot alter new panes.
6. Leave/Back/Close/Refresh/root/conversation/host/parent/surface/end during
   preflight or pending mutations clears authority without retry/retraction
   claims; original adapter/message/task runtime and old292 remain intact.

Run strict validation/full native suite, unchanged requester_commit6 and
requester_completion6 against frozen merged69 binaries, required Rust gates,
then all24 CI suites/PR checks/fresh review on one final combined head. Serialize
primary-owned builds/native/host runs; record external overlap, every failure/
correction, exact source/binary/test/log provenance and source/manual limits.
No weakened assertions/timeouts or unchanged retries until green.

Initial PR73 CI also repeated section24's earlier final historical-purity
failure:5/6in60s, changed table dec_contacts, no state/home paths changed and
relay_changed=false. All23 other suites and PR checks passed; Rust is unchanged.
The runner discarded retained state, so cause remains unclassified. A separate
contract-only author may add a failure-only observer immediately before the
existing whole-snapshot assertion in section24 inspect, reusing only its already
captured before/after snapshots and carrier counters. Preserve the original
assertion/verdict and every action/delay/timeout/category. Project only fixed
metadata: before/after contact counts; added/removed/changed primary-key counts;
for changed existing rows, sequence-changed, whether the row matches this known
network/context and whether the host is the known other participant; closed
documented record-field changed booleans for format/message_hashes/conflicted/
contacts_base64 plus list lengths and boolean conflicted values when canonical.
Use fixed unknown for malformed diagnostics. Never emit primary keys, record
contents, hashes, contact bytes, locators/addresses, paths, labels, private data
or diagnostic exceptions; no new DB/file/transport calls, writes, waits or retry.
Diagnostic errors cannot mask the existing failure. Independently commit before
one retained first local diagnosis against unchanged merged69 binaries. The
observer is the only permitted old-host-test change; normalized original source
and all original strict DB/files/BOTH-carrier assertions remain identical.
Neither another pass nor this table name alone proves a cause or product fix.

First combined native CI on bfdffd0 ran312 cases:308 passed/4 failed in48.25s.
One original case requires the still-supported advanced-administration fallback;
retain it while directing normal participant approvals to explicit reviews.
Three new fixture failures prevent intended coverage: changed-flow
transport/privacy expectations bind to mutable replacement IDs instead of the
captured requested flow, and short request deadlines retain an owner review
expiry beyond that signed request. Preserve these failures. An authoritative
changed reply must be returned for the captured old inspection request (or a
controlled not-found), never require silent rebinding to the replacement ID.
Fixture original-review expiry follows section16's minimum of its finite human
window and signed request bound before deadline/lifecycle races are exercised.
Independently correct only these invalid setup/expected-binding values, keeping
all20 native cases, all privacy/argv/time/parent/refusal/result assertions, actual
dispatch barriers, original delays/timeouts and all old292 unchanged. Commit
before one corrected full local run; no unchanged retry or weaker validation.

Selected: compose existing exact backends through separate native review,
approval and completion with pure lookup-first recovery. Discarded: combining
consent and completion, blanket agent access, frontend signing/provider choice,
new persistence, retry/polling and local application as connection readiness.

## 30. Project-bound agent-access inspection (GU-01t / GU-02u / GU-04u)

This owner-local read supplies current verified terms for a later explicit
agent-permission review. It creates no consent, reservation, signature or grant.
Its digest identifies an inspection and cannot authorize a policy operation.

### Private API and CLI

`POST /v1/onboarding/access-inspection` accepts exactly
`{context:AdapterContext,network_id,person_public_key}`. Context is section 5's
exact attached-project binding; the network is an explicit canonical `net_` ID,
and the selected person is a canonical base64 32-byte public key. Ordinary DEC Ed25519 key validity applies. Reject unknown
or duplicate fields, nulls, wrong types, trailing JSON and inputs over 65,536
bytes. `peerspan onboarding access inspect --stdin` sends the same closed input
over the private Unix socket and prints the same public JSON. No positional
payload, signer override, implicit network, label resolution or invitation is
accepted. Missing daemon fails nonzero. CLI errors never echo input, including
parse errors when normal global flags occur between command words. Adapter
credentials and peer routes cannot invoke this owner administration API.
Public keys follow the ordinary DEC Ed25519 validity rules, not arbitrary
32-byte strings. An unknown valid key is unavailable authority; a malformed
encoding or invalid public key is malformed input. An unknown project flow
returns 404 `not_found`, preserving section 5; changed existing bindings remain
409 `review_changed`.

### Current verified terms

Hold one database read transaction. Sample the ordinary DEC local decision
clock once, load the exact network snapshot and build its ordinary projection.
Preserve migration fences, clock rollback, proof and fork refusals. Never save
the clock or repair evidence. Legacy networks are refused. Validate the latest
attached project and original agent terms at the observed time. Replaced,
detached or changed projects return 409 `review_changed`; malformed inputs
return 400 `invalid`; an absent network returns 404 `not_found`. Other unavailable
authority (including an unknown selected person), unsafe public values and
excessive output return 409
`access_inspection_unavailable`, without partial terms.

The local host must have a current verified person binding matching its stored
own identity. The selected person must have a current verified person lease.
Include all current machines of that person sorted by host public key; an empty
list is allowed and establishes no reachability. Self-selection is allowed.
Do not open or probe any signer/provider: a missing signer does not prevent a
valid read. Membership and labels never establish agent access.

With no retained local-person policy stream, return `policy:null`. Otherwise
require its unambiguous current active statement and complete verified ancestry.
An expired, revoked, ambiguous or incomplete retained stream is unavailable,
rather than an empty policy. Return the exact signed body separately from the
ordinary locally enforced content, including pending withdrawals. Preserve all
rules, principals, actions, byte bounds, trusted hosts and capability rules.
Do not add a second authorization evaluator or report policy presence/rule
matches as permission to deliver an operation.

### Public result

The closed outer object is exactly `{version:1,host_id,context,observed_at,
review_id,review,next_action:"review_agent_access"}`. The closed review contains:

- `version:1`, `kind:"inspect_project_agent_access"`, `host_id`, `context`,
  and the attached project's complete public `agent` terms;
- `network:{id,name,context_id}` and current `root_state_id`;
- `owner:{person_public_key,member,person_lease_id,host}`. `host` is the ordinary
  current-member response: host public key, member label, person public key,
  host/binding/device lease IDs and finite `not_after`;
- `participant:{person_public_key,member,person_lease_id,not_after,hosts}`;
- `policy:null`, or exactly `{statement_id,proof_id,body,enforced_content,
  valid_until}`. `body` preserves the complete verified JSON object inside the
  signed statement, including explicitly present optional/default fields such
  as `max_artifact_bytes:0`; it is not a normalized serialization of that body;
  `enforced_content` is exactly `{rules,capability_rules,trusted_hosts}`, the
  ordinary Content after pending local withdrawals (empty collections remain
  present);
  `valid_until` is its effective ancestry bound. `proof_id` is the first
  lexicographically sorted retained proof for the statement;
- `effects` with `inspect_current_membership:true`, `inspect_current_policy:true`,
  and `prepare_access`, `approve_access`, `sign_policy`, `publish_policy`,
  `grant_agent_access`, `share_files`, `share_conversation`, `capability_calls`
  all false.

`review_id` is `review_` plus lowercase SHA256 of
`peerspan-project-access-inspection-v1\n` followed by section 3 canonical JSON
of the complete review. The changing observation time stays outside the digest;
unchanged terms retain it. Real policy/member/project changes change or
invalidate it. Serialized output is at most 2 MiB and follows section 20's
public-value privacy checks. There are no signing requests, private journal
bytes, access/readiness booleans, model turns or native controls in this slice.

### Verification

A separate contract-only author supplies six compact black-box cases using
genuine ordinary operations and real attached projects:

1. Two people/two temporary hosts: exact project agent and selected person,
   verified P/H/B references, sorted machines, complete policy/enforced content,
   canonical digest and API/CLI parity; no inferred operation permission.
2. Exact parent/native/root/integration/review/agent binding; wrong, replaced,
   detached or changed context, unknown network/person and malformed keys fail
   closed without creating a project, identity or request.
3. Real absent policy returns null; message/task/capability/trusted-host terms
   remain complete, including explicitly signed zero/default field presence.
   A real pending withdrawal changes enforced content without
   rewriting the signed body. Reads retain the digest; a new policy changes it.
   Record source-only gaps where genuine absent/unsettled states cannot be
   reached through public operations; never fabricate authority/storage rows.
4. Genuine expiry/revocation/root or policy ambiguity and clock rollback cannot
   yield active-looking terms. Losing/clearing the signer still permits a valid
   read. Membership/policy never claim access, delivery or readiness.
5. Repeats, refusals and restart preserve aggregate DB rows, state/home files
   and both transport counters after genuine background work settles. No clock,
   reservation, intent, contact, queue, event or key write. Keep every original
   suite's assertions, actions, delays and timeouts.
6. Closed/duplicate/trailing/null/oversize inputs, stdin-only CLI privacy,
   unsupported methods, unavailable daemon, adapter/peer isolation, public
   secret-prefix refusal and output bounds; no secrets in diagnostics.

GU.impl30d diagnosis: corrected access source e928c4b / independent c658d84
passes6/6in35s in CI, while its first local full run passes5/6in75s.
The aggregate repeat/refusal purity assertion fails without identifying the
changed category; original before snapshots were not retained by that process.
Do not infer a product mutation or fixture cause. Independently add a failure-only
observer over the already captured expected/actual snapshot tuples at the
original purity assertions. Print only fixed phase, changed table names, row
counts and changed state/home entry counts; no rows, paths, bodies, keys or
private values. No new IO, mutation, wait, exclusion or altered assertion.
Removing the diagnostic helper/wrappers restores the exact prior source/AST.
Commit before one retained diagnostic full run; preserve all six cases and
all old suites. A passing diagnostic run leaves the earlier category unknown.

GU.impl30e fixture isolation: the diagnostic local run passed DB/state/home
comparison but failed the unchanged BOTH-bootstrap-carrier assertion (5/6in73s).
Its specific traffic source remains unidentified; the earlier aggregate category
remains unidentified too. Source/spec audit finds a concrete prerequisite error:
the shared fixture's1800s offset is before the ordinary3600s invitation/request
deadlines. A0.3s quiet sample does not retire their pollers. The preceding
revocation also introduces independent authorized delivery work.

Before the purity baseline, retain the actual genuine invitation and signed
request expiry bounds. Advance both debug clocks once beyond their maximum
plus one second, checking the target stays before the measured local person's,
host's and policy's verified effective bounds. Observe ordinary invitation
return-secret and request-frame/read-cap retirement and actual delivery/journal
settlement within the original five-second setup bound. Do not infer retirement
from a quiet interval. Ordinary unsigned request creation/cancellation may
trigger documented maintenance outside every measured baseline; verify actual
retirement afterward. Isolate the expiry/revocation stimuli in their own genuine
two-person fixture so they cannot enqueue work in the purity fixture. Retain
every existing case, assertion, refusal, restart, delay and timeout. All enabled
transport paths must be counted, preserving both original bootstrap counters;
genuine additional peer paths require additional counters, never an unmeasured
bypass. No manufactured storage, authority/queue edit, forced ACK, worker control,
sleep increase or clock/retry loop. An independent author commits the corrected
setup before one retained run against frozen production.

Selected: verified public terms, exact project binding and ordinary enforced
policy before separate explicit grant consent. Discarded: membership as access,
copied frontend policy as authority, label selection, a second policy evaluator,
opening keys during inspection, new inspection storage and this digest as consent.

## 31. Exact project agent-access consent (GU-01u / GU-02v / GU-04v)

This slice prepares and approves one exact ordinary policy action. Signing,
publication, application and native controls follow separately. Section30's
inspection digest is an input pin, never consent by itself.

### Fixed first grant profile

The explicit profile adds the selected person to the attached agent's ordinary
owner policy: actions exactly `message.append` and `task.submit`, message bound
65536, artifact bound0 and allow_disconnected false. There is no delegation,
capability call, trusted-host change, automatic file or conversation sharing.
The principal is `person:` plus the ordinary person ID derived from the exact
selected public key. Agent rules use the exact frozen agent NAME. Ordinary
owner policies apply to that name across the owner's machines; this is not a
host-exclusive or agent-ID permission. The review exposes
`policy_scope:"owner_agent_name"`, the exact agent ID and name, so native consent
can disclose this existing scope. No new authorization evaluator is introduced.

Preserve the complete verified signed baseline policy JSON, including explicit
optional/default presence and unrelated rules/capabilities/trust/edit entries.
For a same-key rule (ordinary agent/settings equality), append the principal
only if absent, preserving existing order/fields; otherwise append the exact
profile rule. Do not remove or broaden another rule.
For a newly appended profile rule, include the explicit raw
`max_artifact_bytes:0` field; a retained same-key rule preserves its original
optional/default field presence.
Existing broader authority remains visible in the complete baseline. An existing identical grant may yield
an ordinary new policy generation; no claim of newly absent permission follows.
A truly absent policy starts with format2 and empty arrays. Refuse retained
inactive/forked/incomplete policy or unsettled local edits; never auto-reapply.

Use the actual selected original or scope1 owned-device provider, with its fixed
ordinary signature format, no override/root fallback/provider change or external
signer probe. Pin exact current root, person/host/binding/device, policy head,
retained full-u64 maximum+1 and next local edit sequence. Proposed policy ends
at the minimum of now+24h, operation-required scope1 provider/parent ceiling and
selected-person effective lease bound. Refuse an unusable ceiling. Its complete
ordinary typed policy payload and unsigned template remain immutable.

### Private operations

- `POST /v1/onboarding/access-consent/lookup`: exactly
  `{context,network_id,person_public_key}`; returns latest matching local consent
  or null, without preparation, provider probe or repair.
- `POST /v1/onboarding/access-consent/prepare`: exactly those three fields plus
  `inspection_review_id`, and optional non-null `replace_access_id`. Require the
  exact current section30 review ID and attached project before fresh preparation.
  First preparation atomically stores one unsigned ordinary policy action intent
  and one nonsigning access-review receipt. No edit reservation, signature,
  selected-provider mutation, policy/admission/maximum/outbox/event or clock save.
- `POST /v1/onboarding/access-consent/approve`: exactly those three fields plus
  `access_id` and `access_review_id`. Approve only the exact retained latest
  receipt/action after current project/inspection/provider/ordinary policy-action
  guards at one decision time. Atomically approve both records with the same
  actual approved_at and save the ordinary clock guard. This never signs or
  publishes. Original/device key availability is not probed.

All requests are closed, duplicate/null/trailing/type checked and at most65536
bytes. Every successful operation returns200. `access_id` and replacement IDs are canonical `dint_` IDs. CLI commands
are `peerspan onboarding access {lookup,prepare,approve} --stdin`; exact same
input/output, private Unix socket only,5s request bound, no argv payload or
signer override, no input echoed even with interleaved global flags. Owner API
only; adapter credentials and peer routes cannot invoke it.

Prepare with no replacement reuses the latest exact matching inspection receipt,
including expired/approved/invalidated history, without refreshing its payload or time.
A different inspection requires explicit replacement. Replacement names the exact
latest receipt and is allowed only when its fresh work is expired/invalidated;
a still-live review or approved action refuses. Repeating that exact replacement
returns its retained successor, not another action. Keep old receipts/approval
history immutable. After replacement, the earlier receipt cannot authorize new
guided work. A preexisting ordinary action may not be adopted as fresh guided
consent; require a genuinely new action when first linking a receipt and return
409 access_review_unavailable on collision, without refreshing payload/time. Advanced
ordinary approval of a receipt's action without the exact guided receipt makes
that receipt invalidated, never guided-approved by inference. Refused live/nonlatest
replacement, superseded approval and an unapproved receipt whose action was
advanced-approved return409 review_changed; corrupt receipts return409
access_review_unavailable. Approved but stale/expired work may be explicitly
replaced under the same fresh-work liveness rule.

### Existing schema27 private record extension

No SQL/schema migration. Add kind `access_review` in existing `dec_intents`.
It is a typed NONSIGNING exact public-review receipt referencing its separate
ordinary `action` intent. Its normal Record has empty templates/signatures,
completed true (no signatures required), secret NULL, terminal `-`, result_base64
`-`, and original/device provider metadata copied from its exact ordinary action.
Its operation_id is `arev_` plus SHA256 of
`peerspan-project-access-key-v1\n` plus canonical JSON of exactly
`{context,network_id,person_public_key}`. Its review_base64 is the canonical
complete public review below, at most1MiB. Validate all duplicated IDs/provider/
root/person/host/device/scopes/time fields and the exact referenced action and
unsigned payload on every use. No access-review row can reach signing, action
publication or provider selection. Approval is the atomic exact human receipt;
only the referenced ordinary action can subsequently use its existing typed
signing path and authority guards.

At most256 access-review receipts and16MiB aggregate stored record bytes per
host, each complete public response at most1MiB; preserve ordinary total4096
intent/64 unsigned-action ceilings. Check capacity for both rows before writes.
Never evict retained history to fit. Latest selection is by insertion order among
this kind's exact operation_id/network key; it supplies local recovery only,
never network authority. Lookup also validates the original parent context/agent
terms. An approved receipt requires its action's matching approval timestamp;
an unapproved receipt cannot inherit an advanced action's approval. Both receipt
and ordinary intent must remain uncorrupted; a broken reference fails closed.

### Closed public view and history

Outer result is exactly `{version:1,host_id,context,observed_at,access}`.
`access` is null or exactly `{access_id,review_id,review,state,next_action}`.
Review is exactly:

`{version:1,kind:"approve_project_agent_access",access_id,host_id,context,
inspection_review_id,inspection,replaces_access_id,grant,action_id,intent_id,provider,statement,
created_at,expires_at,effects}`.

Inspection is the complete frozen section30 review.
The replacement link is the exact prior `dint_` or `"-"` for first preparation;
it is immutable local lineage, not revocation or new authority.
Grant is exactly
`{policy_scope:"owner_agent_name",agent_id,agent_name,principal,
actions:["message.append","task.submit"],max_message_bytes:65536,
max_artifact_bytes:0,allow_disconnected:false}`. Provider is the ordinary frozen
public PROVIDER_VIEW. Statement is exactly `{id,payload_sha256,payload}`;
payload is the complete exact unsigned ordinary policy payload with its
`body_base64` replaced by decoded `body` JSON, preserving every other field.
Payload_sha256 pins its original encoded payload bytes. No template, signature,
private key or base64 payload is returned. Created_at is the ordinary intent's
actual creation time. Expires_at is the minimum of its fixed issued_at+300s
expiry and the proposed policy bound; retries never refresh either timestamp.
Effects are exactly approve_policy_intent, authorize_policy_signature,
authorize_policy_publication, grant_agent_access_after_signatures true;
grant_membership, delegate_tasks, share_files, share_conversation,
capability_calls and allow_disconnected false.

Review_id is `review_` plus SHA256 of
`peerspan-project-access-consent-v1\n` plus canonical JSON of this entire review.
Observation time remains outside the digest. Public values follow section20's
privacy checks; unsafe/oversize reviews refuse atomically.

State is review, approved, expired or invalidated. Next_action respectively is
approve_policy_intent, follow_policy_action, inspect_agent_access,
inspect_agent_access. Approved history remains exact and pure after expiry,
policy/provider changes, detach/replacement/restart and absent original signer;
it claims recorded consent, not current permission or delivery. No raw time
before the original creation may yield misleading live history.
Raw decision time before a retained receipt's creation returns409
access_review_unavailable before live-work/approval classification, even when
the ordinary rollback guard clamps the projection time forward.
Unapproved state reflects current liveness without mutation. Already-approved exact replay
is pure and never updates approved_at/clock or invokes another signature.
Unknown network/project/access IDs are404; malformed input400invalid; wrong
context/digest or changed live terms409review_changed; elapsed review409
review_expired; other unavailable authority/capacity/corrupt state409
access_review_unavailable. Return no partial private state.

### Verification

Separate contract-only author supplies six compact real-binary cases:

1. Genuine two people/two hosts, attached project and exact current inspection:
   complete narrow profile and owner-wide name scope, raw signed baseline/default
   fields and unrelated policy terms preserved, exact immutable ordinary payload,
   next version/edit/provider/parents/expiry, digest and API/private-CLI parity.
   Preparation records both unsigned rows atomically without granting permission.
2. Context/native/project/agent/network/person/inspection exactness, lookup-null
   purity, repeated preparation/recovery and explicit replacement boundaries;
   never adopt an unrelated/advanced-approved ordinary action as guided consent.
   For the missing-original advanced-approval prerequisite, use the existing
   ordinary explicit external provider (the exact selected original public key,
   signature_format sshsig), which returns unsigned signing slots without a
   daemon key. Guided operations continue to use only their selected provider.
3. Late genuine SQLite INSERT/UPDATE fault rolls back both preparation or both
   approvals/clock. Real approval changes only exact receipt/action/guard, leaves
   all signatures/templates/policy/maximum/edit/outbox/provider/event evidence
   untouched; exact approval replay is pure. Missing external original still
   permits consent, broken selected device cannot fall back.
4. Genuine stale policy/provider/root/member/lease/expiry/clock and unsettled
   withdrawal refuse before approval/signature. Full-u64 max and local edit rules
   use ordinary guards, no reapply/renewal or hidden refreshed generation.
5. Approved/unapproved history after detach/replacement/restart/expiry and absent
   signers; whole DB/schema/state/home and BOTH original TCP plus every enabled
   UDP counter purity after genuinely observed setup retirement/startup work.
   Preserve every old case/assertion/delay/timeout and record any unexecuted
   complex fork/unsettled/multi-machine/limit prerequisite honestly.
   Failed strict purity checks report only already captured public category
   metadata: changed table names/counts, state/home file category counts and
   deltas for every original TCP and enabled UDP carrier. Preserve the same
   complete comparisons and fail; no reset, filtering, extra wait or retry.
6. Strict bounded/duplicate/null/trailing/private stdin corpus and argv redaction,
   unsupported methods, unavailable daemon, owner/adapter/peer isolation, unsafe
   public values/output/capacity/type corruption refusal. Existing schema27 and
   all old rows/intent kinds unchanged; new nonsigning kind never becomes a
   signing/provider route. No fabricated authority for a passing fixture.

Selected: exact nonsigning guided receipt plus atomic approval of the existing
ordinary policy action. Discarded: a new SQL table/schema for metadata, a second
signing mechanism, mutable payload refresh, automatic policy reapplication,
root/provider fallback, silently host-exclusive name claims, broader default
files/delegation/capability/offline access and combining consent with signing.

## 32. Bounded exact project policy signing (GU-01v / GU-02w / GU-04w)

After section31 approval, this slice records only the existing ordinary policy
intent's exact issuer signature. Policy publication/local application and native
controls follow separately. An access-review receipt remains NONSIGNING and
unchanged; the ordinary action remains the sole signing record and authority.
No new SQL/schema, intent kind, template, consent, policy generation or evaluator.

### Private input and public observation

- `POST /v1/onboarding/access-consent/signing`: exactly
  `{context,network_id,person_public_key,access_id,access_review_id}`. Read only,
  with no external signer discovery/probe, authority refresh or state repair.
  Preserve section31's read-only access-state projection for unapproved receipts;
  its existing retained local provider reads do not authorize signer IO.
- `POST /v1/onboarding/access-consent/sign`: exactly those five fields plus
  `decision:"sign_project_agent_access"`. One explicit bounded signing attempt,
  never approve, publish, apply or retry. Both section31 receipt AND its exact
  ordinary action must already have matching recorded approval timestamps.

IDs, context and input rules are section31's closed duplicate/null/type/trailing
checks and65536-byte bound. Unknown network/project/access is404; wrong exact
context/review or changed live terms409review_changed; elapsed fixed signing
window409review_expired; unapproved/advanced-only consent, corrupt state,
unavailable key or timeout409access_signing_unavailable; malformed400invalid.
No raw errors, private paths, input, signatures, templates or encoded payloads
are returned. Owner Unix API only, never scoped adapter or peer/bootstrap API.

CLI is `peerspan onboarding access {signing,sign} --stdin`, identical private
input/output, no argv payload/key/provider override or daemon initialization.
Read request bound5s; sign request95s and daemon attempt90s, monotonic. Any late
signer result must pass fresh live/clock/budget guards before persistence; a
timeout cannot retract already completed IO or a commit whose response was lost.
Recovery is explicit read-only `signing`, with no transparent retry.

Every successful operation returns200, exactly the section31 outer response
plus `signing`. `observed_at` is the captured ordinary canonical UTC timestamp
`YYYY-MM-DDTHH:MM:SSZ` (three time components, no fractional seconds). The original `access` object/review/digest remain unchanged.
`signing` is null until BOTH exact guided and ordinary approvals exist; advanced
ordinary approval alone cannot become guided consent. Otherwise it is exactly:

`{state:"unsigned"|"signed",action_id,intent_id,statement_id,
signature_count:0|1,required_signatures:1,policy_application:"not_verified",
peer_delivery:"not_verified",connection_readiness:"not_verified"}`.

The single policy slot is issuer, fixed format/key/message derived by the
ordinary typed template, never caller supplied. Validate the complete frozen
ordinary action and every retained signature; completed must exactly match its
typed pending-slot state. Counts/state describe retained cryptographically
verified signatures, not current authority, grant enforcement, publication,
delivery or readiness. A corrupt action/reference refuses instead of a marker.
The complete public response remains at most1MiB and public-safe; refuse unsafe
or oversize output before signing/persisting. Section31's old operations/shapes
and nonsigning receipt bytes remain unchanged.
Read-only `signing` returns200/null for unapproved or advanced-only consent and
200/unsigned for an approved unsigned action even after expiry, detach or
provider/head changes. It never implies fresh signing eligibility. Only `sign`
performs the fresh-work refusals. A missing requested access ID is404; a missing
or corrupt referenced action or retained signature is409access_signing_unavailable.

### Fresh signing, durable boundary and history

Fresh work requires exact latest receipt, approved immutable project/agent/
network/person/review/action/template/provider pins, attached current project,
unchanged section30 membership/policy inspection and ordinary scope1/retained
maximum/edit/root/parent/lease/quota guards. Use one captured raw/guarded clock
pair in each coherent transaction; raw before creation refuses unavailable.
New signatures must precede BOTH fixed review/action expiry and proposed policy
end. Never refresh/reapply, renew authority or choose a different provider.

For the selected owned device, rederive the exact available owned raw seed under
the held current-authority transaction and sign only its pinned issuer slot.
Missing/corrupt selected device cannot fall back to person/root/another device.
For a selected original, use the daemon's configured agent with that EXACT key,
then its configured private owner key file only if it matches. No sole-identity
discovery or caller path. A configured owner file must be regular, process-owned,
private (no group/other permission), unencrypted OpenSSH Ed25519, at most16KiB;
open without following a final symlink or blocking on a FIFO. Missing, malformed
or wrong-key file cannot produce another identity. The matching configured agent
is tried first under the ordinary daemon preference, not an inferred authority.

Check fresh consent/project/authority before external lookup, after lookup and
before the actual SSH signature, and again after IO before accepting it. Release
the SQLite connection/transaction during external key/agent IO. Verify returned
signature against the exact frozen slot. No extra possession signature or root
fallback. Overlapping explicit calls may request the same immutable message;
they must never create another payload/generation or conflicting stored slot.

Atomically save only that ordinary intent's single signature/completed flag and
the ordinary monotonic clock guard. Preserve both approvals/timestamps, every
template/review/provider and all unrelated rows, policy maxima/edits/outbox/
events/files. Late SQLite failure rolls back the entire signature/clock write.
A schema-only injected SQLite ABORT is checked as a controlled non2xx response
without private detail and exact rollback; no particular storage-error code is
required. Documented corrupt-retained-state refusals remain409access_signing_unavailable.
No ordinary signed-submission path that automatically applies the policy is
used. Existing terminal signed history may be observed without fresh work.

Already fully signed, exactly approved replay is pure even after review expiry,
policy/provider/root/membership changes, detach/project or consent replacement,
restart and missing/broken signer. It requires valid retained receipt/action/
signature bytes and raw time not before creation, but no current authority or
key probe. An unsigned superseded/changed/expired record cannot sign. Read-only
observation of an unapproved/unsigned record never makes it live or approved.

### Verification

A separate contract-only author supplies six compact real-binary cases, with
all26 original suite assertions/actions/delays/timeouts and shared harness/
helpers unchanged, except the independently contracted diagnostic-only additions
below. No fabricated authority/keys:

1. Genuine two people/two hosts and attached project: exact prepare/approve,
   null/unsigned read states, selected scope1 owned-device issuer signature
   verifies over the actual frozen policy message, one exact slot/completed
   write plus clock, no policy/edit/maximum/outbox/event/receipt changes and
   API/private-CLI parity. Membership still differs from agent access.
2. Genuine configured original file and real multi-identity ssh-agent: exact
   selected public key/SSHSIG message only, no extra probe signature; no daemon
   key import, root/provider fallback or wrong-key choice. Missing/broken/wrong
   signer fails with unchanged state. Use supported key/agent configuration,
   never edit device seeds or authority rows for a passing prerequisite.
3. Exact guided AND ordinary approval, latest/context/person/project/review/
   provider/policy pins, elapsed fixed signing window, raw rollback and genuine
   detach/provider/head changes refuse before signatures. Advanced-only approval
   never supplies guided consent. Slow/faulting agent permits genuine state
   change during external IO; no acceptance under changed terms.
4. Schema-only late signature UPDATE/clock fault rolls back both while preserving
   all prior bytes; signer returns wrong role/key/message/format/signature refuse.
   Existing true typed signing/application barriers remain unchanged. Mark any
   unconstructible complex fork/member/lease/quota/overflow prerequisite honestly.
5. Read-only and fully signed API/CLI retry/history after expiry/changes/detach/
   replacement/restart/absent signer: whole schemas/DB/state/home, all original
   TCP and every enabled UDP counter pure after genuinely observed request/
   invitation/transport retirement and startup work. No added wait/timeouts,
   counter filtering/reset or unchanged retries to obtain a pass. Failure-only
   diagnostics use already captured public categories, preserving comparisons.
6. Closed64KiB/duplicate/null/type/trailing/decision corpus, argv redaction with
   interleaved flags, missing daemon/method/router isolation, no public private
   material; genuine metadata/action/reference corruption refuses. Offline
   negative fault may alter only an already genuine local receipt/signature
   record and restore exact bytes; never invent valid authority/template/seed.

### Retained pre-existing CI purity failures and bounded diagnosis

Candidate325df66 passes new signing6/6in79s and every PR check with a clean
review, but existing section28 completion history observes issuer UDP receive
+2datagrams/+2400bytes, returns0, during detached API replay (5/6in84s).
Section24 finalization history observes only dec_contacts change,3rows before/
after, unchanged TCP (5/6in62s). Neither caller nor contact change is identified.
One unchanged local section28 diagnosis passes6/6in138s; that does not attribute
or erase the first CI failure. No unchanged retry to obtain a pass is permitted.

A separate contract-only author may make these diagnostic-only corrections
before one retained execution, preserving every original case/assertion/action/
sleep/timeout and original proof capture/comparison order and short-circuiting:

- Section24's failure-only contact schema gate must accept storage section9's
  documented paired network/context `-`/`-`, besides canonical net_/ctx_ pairs.
  No raw row/key/hash/body/path is printed, no extra SQL read or new verdict.
  Restoring that one predicate must reproduce the prior source bytes/AST.
- For section28's history failure only, enable the existing debug host timing
  observation (`PEERSPAN_TIMING=1`) ONLY during daemon launch, never CLI calls.
  A fixture start wrapper may delegate exactly once to the original real host
  start, restoring its environment afterward; restarts keep the same wrapper.
  No process/worker/transport control, changed arguments or artificial timing.
- After the original history snapshot/carrier baseline, retain each participant
  daemon-log byte offset using one metadata stat. On an actual carrier mismatch,
  read at most64KiB per host from that offset and project only fixed participant,
  timing request class (`background`/`served`/`unknown`), static peer route class
  (`directory`/`contact`/`catalog`/`repair`/`other`), completion-serving count and
  bounded numeric duration/counts. Keep unknown when absent or unrecognized.
  Directory classification follows the current launch contract:
  `/peer/v1/networks/{network_id}/agents`; the old unscoped launch proposal is
  not the current route contract. No request is sent by this classifier.
  No raw request number/path/ID/line/endpoint/body or provider diagnostic appears.
  These extra filesystem observations are diagnostic metadata, not SQL/state/
  home/carrier proof captures; the original actual tuples and assertions remain.
- Failure output must return the original actual value unchanged and cannot
  replace its verdict, request another operation or change any wait. Removing
  only timing wrapper/offset/diagnostic additions must restore prior source/AST.

Timing output lives only in the fixture's existing daemon log outside its
measured state/home. Logging can affect scheduling and is not a transport fence,
a full trace or proof of a missing caller. A completed background span alone
cannot retrospectively identify the two original CI datagrams. Keep initial
failures and classify any new data before choosing a genuine setup correction.
Discard guessed refresh/sync fences, disabling workers/paths, filtered counters,
longer waits, authority/queue edits, fabricated acknowledgments and unchanged
retry-to-green. No signing production change is justified by these observations.

Selected: signing and read-only recovery as the next small boundary, using the
existing immutable ordinary action and exact daemon-selected signer. Discarded:
combining signatures with policy application/delivery, an extra receipt/table,
signature material through public output/argv, new consent/provider fallback,
hidden payload refresh and claiming access/readiness from signature storage.

## 33. Exact signed project-policy local application

This slice continues section31's exact human approval and section32's stored
issuer signature. It publishes the signed policy into the local admitted proof
catalog and queues the ordinary bounded delivery work atomically. It neither
obtains another signature nor establishes peer delivery or current readiness.
The existing policy evaluator enforces the resulting ordinary policy; an
historical application marker is evidence of that committed operation only.

### Owner-local API and private CLI

Add owner-only POST `/v1/onboarding/access-consent/application` (pure) and
`/v1/onboarding/access-consent/apply` (explicit local publication). Both take
exactly section32's selection/context/access_id/access_review_id fields; apply
also requires `decision:"apply_project_agent_access"`. Reject extras, duplicates,
nulls, wrong types, invalid IDs, trailing input and more than64KiB as400.
Private `peerspan onboarding access application|apply --stdin` uses the same
closed payload, prints no input/private diagnostics, and redacts command values
from argv errors. No route on peer/bootstrap or scoped adapter routers.

Return exactly `{version:1,host_id,context,observed_at,access,application}` using
section31's unchanged access object. `application` is null when the human receipt
is unapproved. Otherwise it is exactly `{state,action_id,intent_id,statement_id,
proof_id,peer_delivery,connection_readiness}`. State is `unsigned`, `signed`, or
`locally_applied`; proof_id is `-` until signed, then the exact dp_ proof ID.
Both delivery and readiness always remain `not_verified`. Never expose signed
statement/catalog/template/signature bytes, private file paths or signer output.
Use canonical UTC YYYY-MM-DDTHH:MM:SSZ observation time. Output is at most1MiB.
Missing requested network/project/access is404; mismatched exact review/context
or superseded live work is409review_changed, elapsed original consent window
is409review_expired; other unavailable/corrupt/ineligible state is the closed
409access_application_unavailable. Unknown methods keep normal routing errors.

### Fresh application and recovery

Application observation validates the exact retained receipt, dual approvals,
approval timestamps, fixed policy payload/provider and its sole issuer slot.
It is pure for every state: no key/agent lookup, maintenance, clock save, signing,
publication, event, transport or policy write. An unsigned record never becomes
signed/applied through observation. An advanced-only ordinary approval or apply
cannot create or replace guided human consent. If its guided receipt remains
unapproved, pure observation preserves section31's access state (including
invalidated) and application:null; explicit apply refuses409review_changed.
Approved unsigned/signed observation remains historical after expiry, detach,
replacement or provider/head changes; only first apply requires fresh liveness.

For first apply, require BOTH exact approvals and the fully stored, verified
single signature. Require latest receipt, attached exact project/session/agent,
current selected provider, exact inspection/root/P/H/member/policy-head/edit
pins, ordinary scope1 policy authority, fixed creation/expiry, local raw time
not before receipt creation and ordinary guarded time within the original
five-minute consent deadline. Revalidate under the same final transaction that
applies; do not refresh/rewrite the payload, issuer, signature or consent. The
full signed statement must be admitted under fresh ordinary policy rules and
all ordinary catalog/edit/outbox bounds. Fresh eligibility does not pin the
ordinary private admission marker to basis.kind=current: storage section4's
current/retention/migration provenance describes the verified dependency closure,
which may include older ancestors/predecessors. Verify its closed format/kind/
proof/time/basis shape, sorted unique well-formed evidence IDs and exact admitted
statement/root/direct-parent evidence, alongside the exact signature/payload and
ordinary enforced current body. A provenance label alone is never authority. No network-root fallback or new signer
IO, membership/ownership change, file sharing, capability grant or delegation.

In one ordinary transaction, merge the exact signed policy proof and its
ordinary projection/admission/maxima/enforced policy, settle its existing local
edit, queue ordinary peer proof delivery, save action terminal=`applied` and its
normal result, save the monotonic clock and exactly one ordinary
network.action_applied event. Human receipt/approval/review and signature bytes
stay unchanged. Any late SQLite failure rolls back ALL of these writes. Return
only after commit. The guided handler sends no direct peer request; existing
workers may deliver the queued proof after commit under ordinary retry rules.
An overlapping call sees one durable application/event; never another action,
payload, signature or grant. No new schema/table/journal/protocol or retry loop.

Server explicit apply budget90s and private CLI95s; observation CLI5s. Check the
budget before accepting state changes and before commit. A client timeout or
lost response is unknown outcome; recover using pure application first. The
underlying blocking transaction may outlive an HTTP timeout but cannot accept a
new commit once its checked deadline has elapsed. No automatic CLI retry.

After committed application, both application and apply replay validate the
ordinary retained signed action result/catalog signature closure and exact
local proof/admission evidence. Return `locally_applied` purely, even after
review expiry, detach/replacement/provider/root/policy changes, restart or
missing signer. Do not require the historical grant to be current or recreate
missing evidence. Broken signature/result/proof/admission refuses closed; no
repair, key lookup or reapplication. Raw time before creation still refuses.
Later current enforcement and actual delivery/readiness are separate evidence.

### Verification

A separate contract-only author supplies six compact black-box cases using
real hosts and genuine signatures. All27 existing host suites and shared
harness/helpers/native remain unchanged, including original assertions,
actions, sleeps, timeouts, whole-state and every enabled TCP/UDP comparison.
Retain the prior PR79 failures as unclassified; no unchanged reruns to green,
guessed global fences, worker/path disabling, counter filtering or authority/
queue fabrication. Document unsupported prerequisites as limits honestly.

1. Two people/two hosts with an attached project: unapproved/unsigned/signed
   pure states, real section31 approval and section32 signature, exact apply
   admits the reviewed policy and exact proof, ordinary local enforcement and
   settled edit/outbox, exactly one event and unchanged receipt/signature;
   API/private CLI parity and no membership/readiness claim.
2. No guided approval, advanced-only ordinary approval, missing signature,
   changed digest/project/selection/selected provider/policy head or expired
   exact terms refuse before any application. Real state changes via supported
   public operations; no fabricated authority/provider/seed prerequisites.
3. Late schema-only SQLite ABORT on ordinary action terminal/result or event
   causes controlled non2xx, no private detail and exact all-state rollback.
   Existing authentic signatures remain. No mandatory internal-storage code.
4. Concurrent explicit application, lost response and pure recovery keep one
   action/proof/edit/event, no new signature or action. Use genuine ordinary
   transport retirement before any zero-IO comparison; record source/manual
   limits for full timeout/cancellation/overlap boundaries not constructed.
5. Pure observation and applied replay after elapsed deadline, genuine detach/
   replacement/restart and absent original sources preserve whole schemas/DB/
   state/home and all enabled TCP/UDP counters after observed ordinary startup
   work. Historical marker does not assert today's grant. Offline negative
   corruption may alter only an already genuine result/signature/proof/admission
   and restore exact bytes; missing evidence refuses without repair. In
   particular, removing an actual required statement/root/direct-parent ID from
   a genuine admission's still well-formed basis.evidence_ids must make BOTH
   observation and explicit replay refuse409access_application_unavailable
   purely. Restore the original entire admission record exactly afterward.
6. Closed input/error/argv privacy corpus,64KiB bound, duplicate/null/trailing/
   decision rejection, unknown/missing daemon/method/router isolation, no public
   signed bytes/key material/paths, actual retained-reference corruption fails
   closed. Keep any source/manual cryptographic/quota/fork/installed/physical/
   model/full-state-upgrade limits explicit.

### Historical transport prerequisites retained after first executions

The first provenance-corrected run passes application/enforcement, live guards,
full rollback and actual concurrent/lost-response recovery (4/6in92.23s), then
fails its post-expiry/restart directory prerequisite and subsequent5s retirement
wait. Retained evidence shows a return outbox containing the exact NEW policy
created in case5 (transport_unavailable,attempts2,next retry17s after that
history target). The last current-contact handoff preceded several clock jumps;
both retained remote contact bodies expire before the exact history target.
Current standalone person/host/binding/device grants remain valid. Neither
observation retrospectively attributes the first directory request or PR79's
unclassified failures; it identifies missing fixture prerequisites.

For this new suite only, before its history clock advance/restart, observe actual
retirement of the latest genuine policy generation AFTER the ordinary new-head
operation. Earlier quiescence cannot settle newly queued work. If current
mutual hints are already expired at this earlier stage, establish the same
ordinary signed counted handoffs/import/retained GET before observing that
policy generation's actual outbox/journal retirement. Its invitation secrets
may remain until the later shared cleanup; do not label that intermediate
stage whole-transport retirement or take a pure baseline there. Include every
such actual invitation deadline in the final cleanup target. After restart and
expiry, establish genuine mutually retained current counted contact hints using
ordinary short signed handoffs and authenticated peer import/retained GET. Retire
those actual short invitation windows with one bounded synchronized clock step
and genuine unapproved create/cancel maintenance (unique local maintenance keys,
no reused ssh-keygen destination). Prove all relevant contacts/authority remain
live at that cleanup target and all actual secrets/read-caps/frames/outboxes/
journals retire, then observe the original directory/startup result and use the
original strict history captures/assertions. A future recorded ordinary retry
may be made eligible with one bounded synchronized clock step only from its
actual next_attempt_at, within current contact/authority bounds; never invent
ACKs, alter queues or extend waits. No global transport fence is inferred.

Keep the first2/6 and corrected4/6 logs/dependencies, all prior evidence and
all27 old suites/helpers/native exact. The independent author adds only genuine
setup prerequisites to the new suite, preserving every existing new-suite
verdict, comparison, baseline order, sleep/timeout and original user operation.
No discarded path/counter, disabled worker, refreshed policy/approval/signature,
changed production code or unchanged retry-to-green follows from this evidence.

Selected: one explicit local application of the exact signed ordinary policy,
with pure independently verified recovery and ordinary delivery queueing.
Discard combining signer/application, a second consent/table/journal, hidden
payload refresh or auto-retry, and claiming delivery/readiness from a local
commit. Native controls and observed two-way exchange follow separately.

### Retained section25 historical-purity CI failure: bounded diagnosis

Candidate78df456 passes the new application6/6 and every PR check, with a clean
fresh review. Existing section25 owner_finalization_signing fails5/6in102s:
recorded F refusal changes only dec_contacts; no state/home path changes are
reported. This is a distinct retained observation; the runner discarded the
fixture and the changed row/caller remains unknown. All27 other suites pass.

Before choosing a setup or product correction, a separate contract-only author
may add one failure-only observer in section25 keyless_refusal immediately
before its existing whole-state assertion. Reuse only its already captured
before/after snapshots and the fixture's known public participant/network and
original request expiry. Do not perform new DB/file/transport reads or writes.
Preserve every original action, baseline order, assertion/verdict, short-circuit,
sleep and timeout. On an actual state mismatch, emit at most eight changed
contact categories, plus bounded before/after/added/removed/changed row counts.
For structurally canonical rows only, project fixed local/other/unknown host and
bound-network/unbound/unknown context roles, sequence changed/increased booleans,
record-field changed booleans and contact-list counts. Decode existing captured
contact bodies only to compare issued/expiry/payload changed booleans and
whether their times are after the already known original request expiry.
Do not emit IDs/keys/sequences/hashes/bodies/timestamps/locators/addresses/paths/
labels/private data or exception details; malformed data is fixed unknown.
Diagnostic errors cannot mask the original failure. Removing only this observer
and its call must restore prior source bytes/AST. Shared helpers, every other
host/native suite and frozen Rust4842404 remain exact. Commit before one retained
local diagnostic execution; a passing diagnosis does not identify or fix the CI
cause. Discard guessed waits/fences, counter filtering, worker/path disabling,
queue/authority edits, fabricated acknowledgments and unchanged retry-to-green.

### GU.impl33e: current own-contact history prerequisite

Diagnostic CIb937f96 repeats section25 failure5/6in102s and now identifies one
changed existing local-host bound-network contact, sequence increased, issued
and expiry times moved from before to after original request expiry, unchanged
payload, no added/removed rows. This establishes a local signed hint renewal;
it does not identify the earlier PR79/section24 callers or the exact async caller.
The history fixture adopts a real network, then advances beyond its old request
and contact windows without establishing a current own hint before measurement.

A separate contract-only author may add a genuine public contact prerequisite
immediately after that original history clock advance and before its existing
spare-request maintenance. Issue one short65s ordinary contact invitation from
the newly admitted host for a fresh real, unconsumed maintenance identity. Verify
its actual signed bound own contact and matching retained row using documented
wire/storage, with current unchanged transport payload and validity extending
at least60s beyond the cleanup target. Advance only the debug clock to the
actual new invitation expiry plus1s, within real authority/contact bounds.
The original spare create/cancel remains in place and must actually retire the
new expired invitation's secrets/read-cap/frames before original snapshots.
No recipient join/approval, original-F changes, policy grant or signer import.
Retain the normal current contact across the original restart and observe it is
still current, without refreshing or changing the original retry operation.

Only addition-only helper/setup checks/calls are permitted. Removing them must
restore the prior diagnostic source bytes/AST, with all original assertions,
actions, capture order, sleeps/timeouts and carrier comparisons intact. Never
edit contact/authority/queue records, disable workers/paths, claim a global fence
or increase waits. Contract and author commit precede one retained frozen-binary
run. Preserve the original CI failures and the147.75s passing diagnosis.

### GU.impl33f: relay-completion failure diagnosis

The same CIb937f96 delivery suite fails11/16in98s. Its first join wait times out
after60s: requester has linked/local application, inviter remains needs_commit
without activation/manifest/outcome, four later cases depend on that missing
linked fixture. The original commit reply's attention is not yet classified.
Neither the relay failure nor its transport/application caller is identified.

Before a fix, a separate contract-only author may add failure-only bounded
metadata in delivery.py, preserving the existing public diagnostic and original
wait/exception/verdict. Leave every other helper/suite unchanged. Enable existing
debug PEERSPAN_TIMING=1 only for each real daemon start, delegate once and restore
the caller environment afterward; never enable CLI timing or alter arguments.
Retain daemon log offsets before the original commit. Only after the original
join wait fails, read at most64KiB per host from those offsets, project fixed
participant role, served/background/unknown and completion/local-resume/other
route class, bounded HTTP status/duration/counts. No raw request numbers, paths,
IDs/keys/addresses, lines or private diagnostics. Unknown stays fixed unknown.

At that same failure only, one bounded read-only transaction per existing host
DB may observe this exact request's documented pending/outcome/frame/delivery/
contact state. Project only fixed roles/kinds/terminal/error enums, counts,
secret/read-cap presence, request/contact expiry booleans, outcome presence,
frame ACK counts by helper/participant role, outbox attempts/retry-due booleans,
and whether configured/retained helpers match the already known fixture helper.
Bound selected rows and decoded sizes; malformed fields/errors are unknown.
No raw record, body, locator/capability, primary key, timestamps, hashes, labels,
addresses, exception detail or signature appears. The already captured original
commit attention may project only fixed documented transport error categories.
Diagnostics cannot mask the existing failure or perform any peer request, retry,
repair, write, changed setup, larger wait or new verdict. Removing diagnostic
helper/call/timing wrapper/offset observations restores the exact prior source/
AST. Commit before one retained local run on frozen4842404. A pass leaves the
original CI cause unknown; no unchanged retry-to-green or guessed runtime fix.

### GU.impl33g: current-hint payload fixture clarification

The first GU.impl33e local run passes cases1–5, then stops in the new positive
hint prerequisite before cleanup/history (5/6in138.67s). Retained actual current
own contact has one matching bootstrap address, one QUIC address and no relays;
the added literal quic_addresses=[] was unsupported. Runtime contract section9
keeps the actual default integration/QUIC listener explicit; an enabled fresh
host may advertise its actual non-wildcard bound listener in private handoffs.

For this fixed loopback host profile, verify the exact closed signed payload as
bootstrap_addresses=[h.relay.address], quic_addresses=[h.peer_address], relays=[].
The independent author changes only that one added expectation from empty to
the already known actual fixture peer listener. All other newly added signature/
retention/validity/authority/cleanup checks and all old assertions/actions/order/
waits remain exact. Preserve the first failure, actual bounded payload category
artifact and duration; production stays frozen4842404. Commit before one run of
the corrected source. Do not treat this new fixture error as a runtime fix or
attribute old callers from its correction.

### GU.impl33h: pre-execution delivery diagnostic scope clarification

Static review before the delivery observer's first runtime identifies three
metadata gaps. A normal enabled host has its actual host.db plus the separate
dec-bootstrap.db; do not require exactly one *.db. For this standard fixture,
open only the existing host.state/host.db read-only, with the same single bounded
transaction. Never inspect or mutate the bootstrap store to find authority.

The original commit attention may be the documented transport_recovery_required
category: classify recovery_required explicitly, alongside quota_exceeded and
the other fixed documented transport codes, without printing arbitrary text.
Existing debug served timing has the form timing #N serve METHOD PATH STATUS
DURATIONms; recognize its trailing bare HTTP status as well as any supported
explicit status form. This remains fixed count/duration/route-class metadata,
not a trace or caller attribution. A contract-only author corrects only these
three newly added diagnostic parts before first execution, preserving every
old action/wait/exception/assertion and all caps. Record this as pre-execution
correction, not a runtime failure or product fix. Production stays4842404.

### GU.impl33i: classify a displayed transport category without its detail

Existing public transport attention may be displayed as transport_CODE followed
by a colon and explanatory text. For the33f observer's fixed recovery_required
and quota_exceeded categories, compare only that leading category before the
first colon, as well as the supported bare code. Never output or interpret the
explanatory suffix. An independent diagnostic-only correction preserves every
other projection and the complete old source on normalization. Keep the first
local delivery run attributed to its original65222cc2 source even if this narrow
metadata correction is authored while it runs; do not modify that running input
or retry unchanged. No product/runtime/verdict/wait change follows.

### GU.impl33j: isolate the standalone section31 input corpus after real startup

Final combinedcfbe31d passes27/28 suites including corrected section25 and
relay delivery, all PR checks and clean review. Existing section31 passes1–5,
then its2.5s input_refusal corpus changes dec_clock and dec_contacts on both
hosts (5/6in62s). State/home files stay unchanged. This is a newly retained
observation, not caller attribution. Section10's normal60s-plus-jitter sync can
overlap a long preceding ceremony; earlier directory completion/quiescence was
never a global fence. Do not erase or retrospectively attribute the failure.

The standalone malformed-input case may start from a genuine fully observed
fresh restart of BOTH existing hosts, preserving their durable authority,
receipts/actions, clocks, private keys, helpers, listeners and lifetime counters.
Keep every preceding history case and its original restart unchanged. Restart
normally with all workers/paths enabled and unchanged arguments/environment;
no timer override, signal pause, clock adjustment or stopped participant during
measurement. Ordinary first periodic anti-entropy is scheduled60s plus jitter
after daemon start; explicit approved work/outbox/startup behavior is unchanged.
Capture monotonic metadata immediately before the first real restart and require
the entire standalone input case to complete before that earliest60s boundary.
This is a bounded fresh-process fixture precondition, not an arbitrary wait or
claim that a directory refresh globally fences traffic.

Before its original stable/baseline calls, perform each host's real explicit
POST /v2/networks/{network}/sync with the existing30s server bound. Require the
exact known other host among attempted, no unavailable targets, actual current
usable membership and current bound own/other contacts. Require actual authority,
binding/member and contact expiry to exceed each host's current time plus the
remaining monotonic60s window; instant liveness alone is insufficient. This is
a read-only prerequisite guard, with no extra renewal/signing action. Observe
the original successful authenticated directory queries and actual whole transport retirement
(no private secret/read-cap/frame/outbox/journal), then run the old stable calls.
All genuine startup/explicit sync work precedes the original snapshots. The
first-start boundary must still cover the remaining input case; a setup that
exhausts it fails rather than pretending isolation. Check the final elapsed bound
after the existing strict assertions, retaining their verdict/short-circuit.

A separate contract-only author adds only one genuine setup helper/call and
bounded metadata checks in section31 verification6. Removing those additions
restores the entire prior source bytes/AST. Every original API/CLI/argv/router/
corruption case/action/assertion/baseline order/sleep/timeout/all-carrier comparison
stays exact, as do shared helpers and every other suite. No signer probe, new
consent, authority/queue edits, worker/path suppression, filtered counter, larger
wait or unchanged retry-to-green. Commit before one retained frozen4842404 run.
Keep the initial62s failure and source/manual duration limits. This setup change
establishes a valid standalone input fixture; it claims no runtime fix or proof
of the original caller.

## 34. Native project agent-access review and approval

This slice composes sections30/31 through human-only native controls. No Rust,
API, schema, signing/application, adapter/model/tool/prompt or protocol change.
Preserve all312 existing native tests and all28 host suites unchanged.
Signing and local application get separate controls in subsequent slices.

### Entry and explicit selection

An attached project's main pane offers **Review agent access**. Entry is inert
until pressed. Opening it clears other volatile setup panes, preserves any
already connected authorized runtime, and verifies terminal/root/conversation,
current host and the exact authoritative attached project before each stage.
Use configured executable plus literal --state,5s process bounds, no shell.
Read existing `onboarding` for explicit ID-sorted DEC network choices (ten/page),
retaining the known context ID to bind each later member response; legacy
history entries are not grant choices. Refuse a member response for another
context before presenting people. The quoted current project root is visible
inside this private human pane, while remaining absent from logs/model/outside
UI/argv; native session and internal flow/review/intent IDs stay undisplayed.
Read `network members NETWORK_ID` for the exact closed runtime section2 member
view. Group current bound members by exact person public key; ignore unbound
rows, never merge different keys by label, refuse duplicate hosts/malformed
fields. A member row's member is its HOST label, not necessarily the person
lease label: group by key and display the sorted unique quoted machine labels.
The later inspection supplies the independently verified person label; it need
not equal any machine label. Owner/participant host labels likewise need not
equal their person label. Show public keys alongside quoted labels and network
names; ten choices/page sorted by person key. Choice text includes the full public
ID/key and quoted label; paging labels need not have a particular wording.
The network ID is public argv;
no private context/payload/code enters argv. This slice lists only people with
at least one current bound host, including self. Hostless-person selection is
not added, and a label or list entry never establishes current access.

Selecting a person explicitly calls only `onboarding access inspect --stdin`
with section30's exact `{context,network_id,person_public_key}`. Validate its
closed wrapper/review/effects, typed IDs, canonical base64 public keys, canonical
UTC-second dates, exact project/host/agent/network/selected person, owner current
bound host, current root/P/H/B/D references and host-key sorted participant
machines. Check the domain-separated canonical section30 digest. Native current
and observed time must be finite, observation <=native+30s, and both before
owner/participant/current machine/policy effective bounds. The daemon performs
cryptographic/ancestry/evaluator checks; frontend does not fetch or evaluate
permissions. Display the complete signed baseline body and enforced content
separately, including all unrelated rules/capabilities/trust and explicit zeros.
Policy null means no retained policy, never denied/allowed delivery inference.
Show exact owner/participant public keys/labels, current public references and
lifetimes, project/agent ID/name, and inspect-only effects. No grant yet.

All public responses are bounded to the backend's2MiB inspection/1MiB consent
limits. Refuse unknown/null/extra/incorrect wrapper/review/known nested schema,
unsafe private-prefix/control strings (including object keys), nonfinite/unsafe
JS integers and malformed dates/IDs/keys. Preserve complete body JSON fields;
validate ordinary public policy structure and displayed grant/payload bindings,
without normalizing or dropping optional fields. Ordinary u64 values beyond
safe JS integers are an explicit unavailable native presentation, not rounded
terms. No template/signature/base64 payload/private record is displayable.
Crypto remains daemon-side: digest the public review, never reconstruct omitted
encoded payload bytes to pretend to verify payload_sha256 or statement signature.

### Separate preparation, recovery and approval

The inspected pane offers **Review proposed grant**, separately from inspection.
First perform section31 pure lookup for the exact selection. Recover an existing
review/history unchanged and never refresh or replace it automatically. Only an
explicit Review, null lookup and a fresh section30 inspection permit one prepare
with its exact inspection_review_id. Recheck authoritative host/parent/native
context and native time after asynchronous preflight, immediately before dispatch.
No implicit preparation on open, Check, Refresh/reload, page selection or approval.
No replacement/decline/revocation control in this slice; stale history directs
explicit advanced review rather than silently preparing another action.

Validate section31's full closed result/access/review, canonical consent digest
and embedded canonical inspection digest. Bind access IDs, all context/agent/
network/owner/participant/inspection references, fixed grant, provider, statement
and times. Review grant is exactly owner_agent_name scope, attached agent ID/name,
selected person's ordinary `person:person_SHA256(decoded_public_key)` principal,
message.append/task.submit only,65536 message bytes,0 artifacts, disconnected
false. Disclose that the name applies across the owner's machines and unrelated
broader policy remains. Provider is original_person or device, never network_root;
exact owner host/person/root/lease references, required scope1 among actual
available powers (original commonly7), and finite bounds. A member device lease
may be the ordinary ambiguous/absent marker '-'; it does not invalidate the
person choice. An explicitly selected device provider still names its concrete
lease and public key, independent of that display marker. Public
statement payload binds root, issuer person/provider kind, required issuer-person/
optional-device parents, predecessor baseline, sequence/body version, issued_at/
not_before and finite not_after/body valid_until; created_at equals issued_at,
review expiry=min(created_at+300s,not_after), end no later than24h/provider/
participant ceiling. The frozen inspection must also be live at proposal creation,
including baseline issued_at<=created_at; historical short-window fixtures must
use a baseline already issued before the historical proposal. Complete proposed body and provider/public references are
shown without signature material. Prepared first review names replacement '-';
existing history retains its typed immutable replacement lineage.

Only a current exact state=review offers **Approve agent access**. Synchronously
mark busy to invalidate old presses. Repeat authoritative parent/host/native
checks and pure lookup. Require exact displayed immutable review/digest/IDs.
An already matching approved result is read-only recovery, zero mutation.
Otherwise get fresh section30 inspection and require the captured digest and
complete review; recheck all context/host/parent and native/observed time after
preflight. No approval before creation or at/after review/proposed policy/owner/
participant/current-policy bounds. One5s command sends section31 exact private
stdin with access_id/access_review_id. It must return exact unchanged approved
review. Recheck authoritative display guards after IO; elapsed review time may
show durable historical approval, without current grant claims. Do not sign,
apply, call broad ordinary action APIs, choose a provider, access a key, retry,
poll or run any model action. The daemon remains the authority at dispatch.

Show **Agent-access consent: recorded** only for validated approved history.
State approval authorizes later policy signing/publication; signing/application/
peer delivery/connection readiness remain unverified here. It grants no membership,
delegation/files/conversation/capability/offline permission by itself. A timer
removes Approve at the earliest displayed live bound without IO or mutation;
approved history remains readable after its old review deadline.

**Check agent access** does fresh current inspection only in inspection mode,
and pure lookup only in consent/recovery mode (never prepare/approve/sign/apply).
Failed or malformed IO clears actionable terms and shows a fixed unavailable or
outcome-unknown notice with explicit Check; no raw output/errors/paths/codes in
UI/logs/model events. No automatic retry. Missing history does not prove no
prior signatures or publication; an ordinary worker may act after approval.

**Leave agent access** stays available during IO, clears only volatile pane/
callbacks/timer and returns to the attached project. It does not cancel/revoke
consent or retract dispatched work. Back/Close/Refresh/root/conversation/host/
parent/surface/session changes likewise invalidate pending reads/results/timers.
Late work cannot reopen a departed pane or disable a newer one. No new frontend
persistence, transport, credentials or changes to existing runtime delivery.

### Verification

A separate contract-only author adds one independent compact native suite from
this section and sections30/31/runtime member projections, never reading hooks/
Rust/importing product helpers or running real processes/transport. Keep original
312 cases/files/stimuli/assertions/delays/timeouts and all28 host suites exact.
Use pinned303 public native effects; barriers signal actual command dispatch
before navigation/time changes. Cover:

1. Inert entry/Refresh/reload; explicit network/person grouping/paging/keys/quoted
   labels, no ambiguous automatic selection, hostless/unbound limit. Exact5s
   configured commands, public network argv and private-stdin inspection.
2. Exact complete inspection/baseline/enforced terms and null policy, fixed
   digest/effects/parent/agent/owner/participant/context bindings; closed nested
   shapes/date/key/private-prefix/safe-number corpus refuses without mutation.
3. Explicit lookup-before-prepare only on null; existing live/approved/expired/
   invalidated history unchanged; Check never prepares/replaces/signs/applies.
4. Complete narrow proposed grant/name-wide scope/provider/unsigned body/digests/
   references/expiry; separate one-shot approval, double-press protection and
   matching already-approved preflight read-only recovery.
5. Changed preflight parent/host/native terms/digest/provider/inspection/state,
   expiry after async preflight and future/early time send zero mutation. Timer
   removes approval, old timers cannot alter new panes. Post-dispatch expiry
   permits exact historical approved result without current-access claims.
6. Nonzero/timeout/raw/malformed/changed approval yields unknown with no retry;
   pure Check/reentry recovery. Leave/Back/Close/Refresh/root/conversation/host/
   parent/surface/end during IO discard late results without revocation claims.

Run strict validation/full native suite once per committed source correction;
required Rust gates and all28 CI suites/PR checks/fresh bot+root review on one
final head. Reuse merged80 unchanged Rust and its required local gates; native
only changes do not require rebuilding/rerunning unchanged host binaries locally.
CI still runs every gate. Serialize root-owned native/runtime/build work; retain
every first failure/correction/duration/hash and source/manual limits. Current
kit's obsolete-callback and microscopic final-check/dispatch boundaries plus
installed/terminal/physical/model/schema23-to27/full-state/final readiness gates
remain manual/open; do not repeat unchanged quota-refused model probes.

Selected: compose existing verified inspection and exact nonsigning consent
through separate explicit native decisions with pure lookup-first recovery.
Discarded: pasted identity keys, labels as identity, a second evaluator, automatic
replacement/signing/application, one combined large control PR, new persistence,
provider fallback and approval as permission/delivery/readiness evidence.

### GU.impl34a: inherited action ordering and exact public body preservation

Fresh03c05f4 review identifies P2: section31 ordinary rule settings compare
actions as a sorted unique set, preserving the raw inherited rule's action
order and optional/default fields. Section34's fixed grant actions remain the
exact two-action public profile, but its matching proposed-body rule may retain
the reverse order or ordinary duplicate spellings. Compare matching rule actions
as sets only for that profile-presence check. Do not sort/rewrite frozen public
JSON, inspection/consent digest bytes, displayed terms, principals or any other
rule/field. Additional different actions still cannot match this profile.

A separate contract-only author independently corrects only the fixture's
ordinary same-key action comparison and adds a compact positive regression:
a genuine public baseline has task.submit before message.append in an otherwise
matching rule. Preparation adds the exact person principal to that retained rule,
preserves its reversed raw order and unrelated/default fields, exposes separate
approval and lookup recovery, and never signs/applies. Preserve all existing20
cases/assertions/actions/delays/timeouts and all312 old tests/28 host suites.
Commit before root verification; retain the initial review and previous runs.
No test is weakened or reordered to hide the refusal. Root runs once against
the corrected source, after observing the known external compiler completed;
record any subsequent overlap and default-timeout failures. Final exact-head
CI/review remains required.

Selected: semantic ordinary action-set equality with immutable presentation and
digests. Discarded: array-order equality, rewriting signed/raw policy JSON,
appending a duplicate replacement rule or broadening the fixed grant actions.

## 35. Native completion of exact approved agent access

This human-only native slice composes sections32/33 after section34's exact
nonsigning approval. No Rust/API/schema/protocol/provider/evaluator/storage,
original approval, model/tool/prompt or adapter/message/task/lease change.
Preserve all333 existing native cases/files and all28 host suites unchanged.
The UI uses the existing exact approved action, never another grant generation.

### Explicit completion and pure recovery

An exact approved consent pane offers **Finish agent access** while its fresh
work remains live, and **Check application** for retained history at any time.
Finish performs the remaining authorized signing and local application in one
bounded explicit action. There are no separate technical Sign/Apply decisions.
Before pressing, show that Finish signs the exact approved policy with its
already selected provider and applies it locally; ordinary proof delivery may
follow, but receipt/connection readiness must be observed separately.

Approval, Review proposed grant, Check agent access, normal entry/Refresh/reload
and lookup recovery retain section34 semantics: none implicitly signs/applies.
An already approved record found by a read does not automatically continue.
The existing Check agent access stays lookup-only in the consent pane.
This preserves its explicit nonsigning approval boundary and existing333 tests.

Both new actions synchronously enter a busy completion pane, invalidating old
presses while keeping **Leave agent access** available. Capture the exact
approved receipt, review/digest, parent, host, network/context and selected
person. Require current terminal/root/conversation and exact authoritative
attached parent/host before/after IO and after asynchronous public validation.

First perform pure section31 lookup; require the exact captured approved access
ID/review/digest/complete immutable terms. Then perform pure section33 application
observation with `{context,network_id,person_public_key,access_id,access_review_id}`.
Read commands use5s and private stdin. A retained locally_applied marker is
read-only recovery, zero signing/application calls, including after expiry.
Check application always stops after these reads, never inspection/preparation/
approval/sign/apply/progress/resume/retry/provider/key discovery or peer IO.
A missing/changed/unapproved receipt or malformed marker clears actionable terms.

Finish may continue only from a verified unsigned/signed approved snapshot while
still live. Recheck pure lookup for the same approval, current section30
inspection/digest/complete terms, authoritative parent/host/native context and
native time after all asynchronous preflight, immediately before each mutation.
Use the fixed receipt creation/review expiry/proposed policy end and all current
inspection bounds; no raw time before creation or future observation beyond30s.
Do not adopt changed provider/root/person/host/binding/device/policy/agent terms,
refresh timestamps, replace consent, choose a fallback or open keys in frontend.
The daemon still enforces all final ordinary authority/clock/budget guards.

If unsigned, dispatch one configured executable/literal --state command,
timeoutMs95000, exact private stdin:

```
onboarding access sign --stdin
{context,network_id,person_public_key,access_id,access_review_id,
 decision:"sign_project_agent_access"}
```

Accept only the complete section32 wrapper plus exact signed marker: same
approved receipt/digest/action/intent/statement, state signed, count1/required1,
application/delivery/readiness all not_verified. Recheck native/parent/host display
guards and future time after IO. Elapsed window after dispatch may retain valid
historical signing, but forbids any subsequent fresh application.

After a valid signing reply, repeat pure lookup/application for this exact
receipt. An already recorded application is read-only recovery. Otherwise
require signed, repeat all fresh preflight and dispatch one configured95s call:

```
onboarding access apply --stdin
{context,network_id,person_public_key,access_id,access_review_id,
 decision:"apply_project_agent_access"}
```

A verified already-signed first observation skips signing and proceeds only to
that fresh guarded apply. At most one sign and one apply dispatch per Finish;
no loop, retry, polling, broad ordinary action command or new consent. Each
existing daemon mutation has90s bound; two sequential operations have separate
95s client bounds, not one misleading shared95s total. Do not launch work in
parallel or extend the fixed five-minute consent deadline.

### Exact evidence, lifecycle and uncertainty

Validate full closed section32/33 outer wrappers and markers, <=1MiB raw output,
canonical dates/typed IDs/private-value/safe-number boundaries, unchanged section31
receipt/digest and exact marker action/intent/statement references. Null markers
are invalid for captured approved consent. Application marker must have exact
state unsigned/signed/locally_applied, proof '-' only when unsigned and canonical
dp_ otherwise; both delivery/readiness stay not_verified. Once a signed proof ID
is observed, later application/Check replies must retain it. Retained state must
not regress within a captured completion view (unsigned→signed→locally_applied
only), including Check after unknown outcomes. Retain the last verified public
state/proof as a volatile comparison guard when clearing actionable terms; reset
it only on leaving/navigation/new explicit selection. Signature-recorded prose
may be semantic; Local application: recorded remains the exact human literal. A successful Apply reply must specifically be locally_applied; a bare
consent/signature response never establishes local application. No frontend
cryptographic/evaluator substitute or omitted signature/payload reconstruction.

Show signature recorded only for a validated signed signing reply or a verified
signed/applied application marker. Show **Local application: recorded** only for
the exact locally_applied marker and its public proof/statement references.
These are global retained historical facts, without attributing which interface
performed work. State clearly that current permission, peer delivery, connection
and actual model receipt are not verified. Do not render the consent-only footer
as if signatures/application remain absent after verified completion. Complete
approved project/person/name-wide grant/provider/finite terms remain available
in the private human pane; internal consent/native IDs and raw private outputs
stay undisplayed. Preserve inherited policy JSON/order/defaults and all old terms.

A timer removes Finish at the earliest live bound without IO. Retained approved/
applied history remains readable after old bounds. Recheck clock after awaited
preflight before dispatch; a late already-sent result may show exact historical
evidence but cannot authorize another operation. A malformed/denied/nonzero/
timed-out/mismatched reply or guarded pipeline failure clears actionable terms,
shows fixed outcome unknown/unavailable and offers Check application only until
fresh terms are displayed. No automatic continuation after uncertainty, even
when the host may have signed/applied. Check is the first recovery step and may
show unsigned, signed or applied; a new Finish requires a new explicit press.
The existing underlying work cannot be retracted by UI leave or client timeout.

Leave/Back/Close/Refresh/root/conversation/host/parent/surface/session changes
clear volatile completion state, callbacks and timer. Late replies/old timers
cannot resurrect a departed pane or alter a newer selection. Never cancel/
revoke consent or disable an established authorized runtime merely by leaving.
No new persistence, credentials, model action or direct peer request is added.

### Verification

A separate contract-only native author supplies a compact independent suite
using section32/33 public projections and pinned303 effects, no product imports/
hooks/Rust reads, real process/transport/inference or self-authored unit tests.
Preserve original333 cases/actions/assertions/delays/timeouts and all28 host suites.
Actual delayed stimuli signal real dispatch plus virtual sleep registration.
Cover:

1. Inert section34 entry/approval/Check/reload, approved-only new controls,
   explicit Finish unsigned→sign→fresh reads/preflight→apply; literal configured
   argv, closed private stdin and5s/95s bounds; double press is single-flight.
2. Signed state skips signer; applied state recovers purely, including expired
   history. Check/reentry never resumes, signs/applies or creates another action.
   Full exact provider/grant/policy terms remain visible and no ready claim.
3. Closed signature/application wrappers/count/state/reference/proof/private/
   date/safe-number corpus; null/bare/changed replies cannot confirm. Preserve
   observed proof and monotone historical state on Check and apply success.
4. Changed immutable consent/inspection/provider/root/parent/host/person/agent/
   native context or deadline crossing during actual preflight sends no next
   mutation; timer removes Finish, old timers cannot disable another selection.
5. Sign failure/lost reply stops before apply; valid sign followed by failed
   apply becomes unknown with pure Check first, then explicit continuation of
   retained signed state. Expiry after signing dispatch prevents fresh apply;
   exact post-apply expiry permits historical success, without current authority.
6. Leave/navigation/context/end during preflight/sign/apply discards late work
   without consent revocation or interface attribution. Existing authorized
   lease/message/task behavior and all333 original cases remain intact.

Commit before root runs. Root serializes native/runtime/build work and checks
known external compiler activity before one retained first run; record any new
overlap and every failure/correction. Use strict native validation/full suite,
unchanged merged82 Rust local gates and final all28 CI/four PR checks/fresh bot+
root review on one final head. No unchanged retry-to-green, increased deadlines,
old-test edits or fabricated host evidence. Real terminal/reload/installed/
physical/model/schema23-to27/full-state/observed-readiness/full-feature acceptance
remain separate open gates. Do not repeat earlier quota-refused model probes.

Selected: one explicit Finish composes the approved signer/application backends,
with read-only Check and exact recovery. Discarded: two technical Sign/Apply UI
buttons, implicit work on reads/approval, new consent/provider/flow storage,
auto retry/repair, treating historical local application as current permission
or connection readiness, and widening existing333 tests' allowed effects.

## 36. Current project readiness evidence

This is the owner-local read foundation for observed connection readiness,
following merged85 (`8b20ab5`). It makes no overall-ready assertion and adds no
network operation, consent, schema, signature, grant, adapter connection or model
turn. Native presentation and explicit peer reachability checks follow separately.
Preserve all349 native cases and all28 existing host suites byte-for-byte.

### Private API and CLI

```
POST /v1/onboarding/readiness
peerspan [--state DIR] onboarding readiness --stdin
{context,network_id,person_public_key}
```

The input is exactly section30's closed64KiB input and exact AdapterContext.
Require its current attached project/agent/session, an explicitly named DEC
network and exact currently admitted person. No default choice, name resolution,
provider/key discovery, repair, synchronization, directory refresh or peer IO.
Serve only on the owner administration socket, not peer/bootstrap/scoped adapter
routers. Wrong methods fail. CLI uses literal configured state/admin socket,
private stdin, a5s local request bound, generic invalid/unavailable errors and no
raw private response diagnostics. Missing daemon must not create state/files.
Unknown network and changed/unavailable project/authority follow section30 errors.
New unavailable/unsafe aggregate evidence fails with409 readiness_unavailable;
never replace failure with a successful empty readiness view.

### One current read snapshot

Return exactly:

```
{version:1,host_id,context,observed_at,
 inspection:{review_id,review},
 readiness:{direction:"participant_hosts_to_project_agent",session_id,
   adapter_connections:[CONNECTION],
   peers:[{host_id,host_public_key,authorizations:[AUTHORIZATION]}],
   peer_reachability:"not_verified",model_receipt:"not_verified",
   connection_readiness:"not_verified"}}
```

Inspection is the complete current section30 public review and its unchanged
domain/digest. It describes membership and the exact raw signed baseline plus
ordinary separately enforced content; it is not historical access-consent or
application evidence. The digest covers that inspection review, not the mutable
readiness fields. Host/context/observed time match its exact original projection.
All fields are public local observations, never signed readiness attestations.

Use one SQLite read transaction for project, verified membership/policy,
authorizations and credentials/connections. Sample one DEC decision time and
reuse it for all DEC reads, without advancing any guard. Pinning read time must
preserve the ordinary receiver's strict errors: status-summary tolerance that
turns unavailable membership/policy into omitted counters is not appropriate
here. Do not convert a failed ordinary receiver projection into empty successful
authorizations. Adapter validity and lease checks still use their ordinary actual read-time checks. Do not copy
frontend state, reconstruct cryptography or add a second permission evaluator.

Peers are precisely the selected person's current bound remote machines from
the inspection, excluding this daemon's own host. Include machines with no
advertised authorization, as an empty array; do not infer that a missing local
policy grants access. Sort peers by host ID and derive each ID from its verified
public host key. For each, reuse the ordinary receiver directory's current
`GET /peer/v1/networks/{network_id}/agents` semantics from the launch contract,
under this same connection/snapshot, then select only this exact project's agent
ID/name. Preserve every authorization entry, its bounds and order: self access,
selected-network current signed/enforced policy (including named-vs-wildcard
precedence, groups and unsettled withdrawals), blocks, explicit grants and
`from_agent` restrictions. No union that hides requester-agent restrictions,
no historical approved-policy shortcut and no reinterpreted person label.
A machine may advertise an authorization through self access or an explicit
grant independently of the selected policy. These are what this receiver would
currently advertise to that caller in this network; they do not prove the
caller possesses the required origin, policy citation, credential or transport,
or that any particular future request/body/deadline will be accepted.

CONNECTION is the full existing public adapter connection object from section1.
Include every unrevoked, unexpired credential for this exact project's attached
session, ordered by adapter ID, even if its connection is merely registered.
Do not borrow another session's live/verified channel for the same agent. Zero
current credentials produces [], never a fabricated ready adapter. Expired or
revoked credentials disappear under ordinary checks; no cleanup/renewal occurs.
Keep registered, live unverified and live verified evidence distinct. Even a
verified host channel does not establish this native conversation's current
main-model acknowledgment, peer reachability or a completed peer request.

The output is <=2MiB and passes the existing recursive public/privacy gate.
No tokens, instances, invitation codes, private signer material, templates,
transport addresses, raw exception text or private protocol packets are exposed.
Context paths/native references stay on this exact private request/response
boundary, as in section30; routine human/model presentation is separate. No
new timestamps, tokens or rows are retained by this read. Background workers
remain independent and must be controlled/accounted for in purity evidence.

### Verification

A separate contract-only author adds a compact `readiness` slim suite, six
black-box cases, with real temporary hosts/ordinary public setup. Commit before
root executes. No product/Rust reads, self-authored implementation tests, direct
protocol/authority edits, fabricated readiness or new model/inference probe.
Use existing harness/pure read prerequisites; do not modify any existing host,
native helper/assertion/action/delay/timeout. Cover:

1. Exact API/CLI shape, input pins, same section30 inspection/digest, current
   remote host IDs/order and metadata-only project with no adapter. Establish
   two people/two hosts without a coordinator; empty authorizations are honest.
2. Ordinary current grant then withdrawal/block changes receiver-advertised
   entries; preserve exact message/task bounds and requester-agent restrictions.
   Compare with the ordinary authenticated receiver directory projection where
   feasible, using its documented array response (not a dict-only contacts
   helper). The fixture's ordinary policy uses explicit --valid-days1, keeping
   its signed end within genuine seven-day parents so an exact-effective-end
   assertion does not silently rely on the CLI's longer default lifetime.
   No historical consent/application receipt stands in for current
   permission; existing self/grant/policy semantics remain unchanged.
3. Registered/unverified/verified adapter states through ordinary public adapter
   handshakes, exact project session only, expiry/revocation exclusions, and
   another same-agent session never providing this session's readiness. Every
   peer/model/overall flag stays not_verified despite a verified local channel.
4. Repeated CLI/API reads in a bounded genuinely quiescent fixture preserve
   complete logical DB/clock/consent/authority plus private-file hashes and BOTH
   TCP+UDP carrier counters. Each unsigned retirement-maintenance pass uses a
   distinct scratch-key filename and fresh ordinary cancelled request; never
   overwrite an earlier fixture private key. Restart loses attachment by its existing rules;
   no read restores it or starts a daemon/worker/connection.
5. Changed project/root/native/review/agent, detached/replaced parent, unknown
   network/person and unavailable/expired current authority fail closed without
   rebound, fallback, key/provider use or successful empty substitute. Public
   privacy rejects unsafe metadata without echoing it. An ordinary accepted,
   syntactically valid short token_-prefixed adapter protocol revision is an
   aggregate privacy stimulus: readiness must return409 readiness_unavailable,
   without changing handshake semantics; a safe same-instance reconnect restores
   an otherwise current connection. Do not accept an unsafe successful view.
6. Closed malformed/unknown/null/duplicate/trailing/oversized input corpus,
   missing daemon/noncreating CLI failure and owner-only route isolation through
   ordinary peer/bootstrap/scoped adapter public interfaces.

Root serializes all builds/runtime/host runs, records first outcomes and exact
source/binary/test hashes, runs Rust fmt/test/Clippy/shipped binaries plus new
readiness and old access_onboarding locally, and unchanged native349/strict
validation. CI adds only this29th suite and runs all29/four PR checks on one
final head with fresh bot/root review. Retain failures and classify before
correction; no unchanged retry-to-green, deadline increase, old-test edit or
unbounded suite. Actual terminal/reload/installed/physical/model/schema23-to27/
full-state/peer-reachability/native-readiness/full-feature acceptance stay open.

Selected: compose current ordinary receiver authorization and exact-session
adapter evidence under one read snapshot. Discarded: an overall ready boolean,
frontend permission inference, historical applied-policy as current permission,
agent-wide channel as this session's proof, automatic network/model probes,
new durable flow/schema, and changing existing directory or adapter semantics.

## 37. Native current connection status

After merged86 (`3e759c9`), expose section36's owner-local evidence in the existing
human access pane. No Rust/API/schema/protocol/provider/evaluator or model/tool/
prompt/adapter/message/task change. Preserve all349 old native cases and all29
host suites/files unchanged. This slice is local observation, not a peer probe
or full ready-connection acceptance.

### Explicit read and navigation

A verified selected-person inspection, retained consent or verified completion
pane offers **Check connection status**. It requires the existing explicit
network and person choices; no default or identity is inferred. It is absent on
unverified/unknown access or completion outcomes until their ordinary explicit
Check restores terms. Normal entry, approval, Finish and their existing Check
commands never call readiness implicitly. Existing349 allowed effects stay exact.

Only the new explicit action starts a single-flight busy status pane with
**Leave connection status** available. Capture project parent/context, host,
network/context and person. Clear volatile completion comparison/dispatch state
on this navigation; durable approvals/signatures/application remain unchanged.
Use the configured executable/literal --state array with5s bound and private
stdin:

```
onboarding readiness --stdin
{context,network_id,person_public_key}
```

Recheck exact authoritative attached project/host/network and current native
root/conversation/terminal before and after IO, after asynchronous validation and
immediately before displaying. The only daemon operations are existing pure
project inspection/onboarding observations plus one readiness read. No agent
inventory/provider probe, access inspect/prepare/approve/sign/apply, directory
refresh/sync, credential retrieval, network or model action in a status check.

The status pane provides **Check connection status** again, **Show connection
details** / **Hide connection details**, **Review agent access** and Leave.
Details toggle is purely local. Review agent access explicitly returns to the
existing section30 inspection path for the captured network/person, issuing
one explicit access inspect without resetting selectors, never grant
preparation/approval. Leave
clears volatile terms/callbacks/timer and returns to the project. It does not
revoke consent, retract dispatched work or stop an existing authorized runtime.
Back/Close/Refresh/context/host/parent/surface/end similarly invalidate late
status replies and timers; existing runtime lifecycle rules remain unchanged.
No persistence or automatic polling/reconnect/retry is introduced.

### Closed projection and truthful presentation

Validate the entire <=2MiB section36 wrapper, exact parent/host/selected
network/context/person/session, canonical section30 inspection and digest plus
all complete nested terms. The inspection digest binds only its inspection;
never treat it as a readiness signature. Reuse existing public privacy and
safe-number checks on the whole DTO before presenting it. Unsafe JS integers,
private prefixes including decorated forms, controls, unknown/missing/null
fields or malformed references are unavailable, never rounded or echoed.

Peers must exactly match the current inspection's remote selected-person
machines, excluding this host: derive host IDs from validated public keys,
sort by host ID and require exactly that roster, no omissions/extras/duplicates.
Keep all receiver-advertised entries separate and in their original order. Do
not infer permissions from raw policy rules or historical consent/application,
union bounds/actions or erase from_agent restrictions. A policy's valid action
order/repetitions remain as returned, not normalized. Self entries have their
existing fixed three-action/65536/1GiB profile; policy entries and one-action
grants have the exact public directory keys. All actions are known, message
bounds1..65536 and artifact bounds0..1GiB. Grants retain typed IDs and their
original valid RFC3339 expiry, including supported offsets/fractional precision;
do not force a UTC-only grant representation. Policy/self/grant category order
and grant-ID order follow the receiver contract. No frontend authorization
or cryptographic substitute is added.

Connections are ordered by unique typed adapter ID and bound only to the exact
project session. Validate the full public connection object. Current credential
projection admits registered/ready/offline, not revoked/expired/detached. A ready
lease needs a future native lease end and valid last-seen time; verified channel
requires a valid channel verification time, while unverified requires null.
UTC connection times support fractional precision through9 digits and real
calendar validation, including past historical verification on offline records.
Do not borrow another session/agent channel. Protocol strings retain the public
bounded profile/privacy check. Host-observed verified channel is separate from
this module's current model acknowledgment, even with a saved verification time.

The primary view says **Connection status**, the observation timestamp,
project/agent/network/person, and the incoming direction from that person's
machines to this project's agent. Show each machine's public label/host ID,
separate authorization source/actions/bounds/requester-agent restriction and
explicit grant expiry. Empty authorization means none advertised to this machine
in this network; it is not a global denial or reachability result. No current
credential, registered, live unverified, live verified and offline historical
states remain distinct. IDs that only identify native/consent/adapter/session
plumbing, private paths outside the human pane and all raw private output stay
out of routine output/model/prompts/logs/argv.

Details make all current agent/owner/participant/finite terms, signed baseline
body, separately enforced content, public policy references, exact authorization
entries and connection state/lease/last-seen/channel/protocol inspectable, without
printing internal context/session/adapter IDs. Structured public details use
canonical JSON escaped once, including safe visible escapes for display controls;
do not wrap the JSON document in a second JSON string that obscures its labels.
Do not reuse the consent-only
footer or imply missing signatures/application from this independent read.
State **Peer reachability: not verified**, **Model receipt from this observation:
not verified**, and **Overall connection readiness: not verified**. Existing
separate live runtime checks remain visible with their own evidence. Suggest
reviewing agent access for changes and leaving to review the adapter/use its
separate incoming-delivery check. Do not turn a local snapshot into an overall
ready badge or automatically start that check's model turn.

### Freshness and failures

Use one bounded volatile observation, not an indefinitely current permission
claim. Inspection must be live at validation and final display; reject future
observations beyond30s or observations already30s old. Its display deadline is
the earliest of observed_at+30s, all current inspection membership/policy ends,
explicit grant expiries and ready lease ends. Recheck native time after all
awaits before displaying. A timer at that fixed earliest bound clears visible
status evidence/details and says **Connection status observation expired. Check
connection status again.** It performs no IO. Old timers cannot clear a newer
selection/read; reads never extend their captured timestamp. Every displayed
permission/channel fact is qualified as observed, not guaranteed for a future
request/body/origin/deadline. If a grant/lease is already expired at the native
final read time, fail unavailable rather than present it as current.

Malformed/denied/nonzero/timed-out/mismatched or elapsed replies clear old status
terms and show a fixed unavailable message with explicit Check/Review/Leave.
Never echo raw output/diagnostics or turn failure into empty successful evidence.
No automatic retry or mutation follows. Original consent/completion recovery,
lease/message/task behavior and349 previous cases remain unchanged.

### Verification

A separate contract-only native author supplies16 compact new public-runtime
cases on pinned303, no product/Rust/hook imports/reads, real host/process/network
execution or model inference. Derive public section36 fixtures from the specs
and existing independent fixtures. Commit before root executes. Preserve every
old349 native/29 host/helper case/action/assertion/delay/timeout byte-for-byte;
keep individual new corpora compact under the unchanged default5s limit.

Lifecycle fixtures count each actual session.start and require exactly one
ordinary delivery_acknowledge registration per start, in order, with no other
tools. Ending and explicitly starting another native session legitimately
registers that same tool again; status itself never registers a tool.

Cover:

1. Inert existing entry/review/approval/Finish/Check; explicit configured Check
   only, exact literal argv/private input/5s bounds, no hidden mutations/probes.
2. Empty authorization/no credential facts, incoming direction, bounded human
   labels and pure details toggles with complete raw/enforced/public terms.
3. Separate self/policy/grant entries, reversed/repeated valid policy actions,
   origin restrictions, bounds/order and RFC3339 offset/fraction grant dates.
4. Fresh current policy/enforced/withdrawn entries replace old observed terms
   without reusing historical consent/application or changing them.
5. Exact-session registered/unverified/verified/offline evidence, including
   historical channel verification; no overall/model/peer readiness inference.
6. Closed wrapper/inspection/flags/safe-number rejection without a fake empty
   success; preserve unknown/private-output refusal.
7. Closed authorization shapes/actions/bounds/origin/grant references.
8. Exact derived peer roster, no missing/extra/duplicate/mismatched machines.
9. Exact session/adapter order/identity/state/calendar/time/channel boundaries.
10. Aggregate short/decorated private values/control/oversized-output refusal,
    no routine/model/log/argv disclosure; public human project path is allowed.
11. Denied/nonzero/raw/missing response clears prior terms, never auto retries.
12. Earliest30s/membership/grant/lease timer clears evidence without IO; fresh
    explicit Check recovers, and old timers cannot clear newer selections.
13. Actual dispatched/delay-registered read single-flight, late elapsed reply
    cannot restore evidence, no increased deadlines or artificial stale handler.
14. Actual preflight/IO parent/root/native/host/context guard changes discard
    the captured read and never rebind a different project/person/network.
15. Leave/navigation/Refresh/end/surface during actual pending reads discards
    late replies, with no revocation or resurrection of newer views.
16. Existing authorized adapter lease/runtime survives Check/unavailable/
    details/Leave; no extra model tools/prompts/storage/direct transport.

Root serializes native/build/runtime execution, checks known compiler activity,
retains first outcomes and exact source/test/log hashes; run strict validation
and the full new+349 suite. Rust tree169da285 and merged86 local required gates
(fmt/test155+2ignored/Clippy/shipped bins, readiness6/6) are unchanged and reused;
final exact-head all29 CI/four PR checks/fresh bot/root review run again. No
unchanged local retry-to-green, larger timeouts or old-test edits. Prior local
native timeouts/host transport callers remain unclassified. Actual native
terminal/reload/installed/physical/model/schema23-to27/full-state/explicit-peer-
reachability/full-feature acceptance remain separate open gates; do not repeat
old quota-refused inference probes.

Selected: explicit local status with strict exact-session/roster projections,
short bounded observation and inspectable separate terms. Discarded: automatic
status reads after approval, a ready badge from a lease/applied policy, frontend
permission merging/evaluation, borrowed agent-wide channels, automatic peer/model
probes, new durable state and changes to the old349 tests' allowed effects.

## 38. Explicit selected-machine peer reachability

After merged87 (`c112cdd`), add an owner-local backend check, with native controls
in the following slice. Preserve all365 native cases and all29 old host suites
and helpers byte-for-byte. This is a bounded authenticated transport observation;
it is not incoming agent delivery, permission acceptance or model receipt.

### Exact private request and result

```
POST /v1/onboarding/reachability
peerspan [--state DIR] onboarding reachability --stdin
{context,network_id,person_public_key,peer_host_id}
```

The closed64KiB input extends section30's exact AdapterContext/network/person
with one typed `host_` plus64hex target. No default, address, URL, hostname,
public-key override, provider or target inference. Require the current attached
project and current section30 inspection, and that exact host derived from a
current selected-person remote machine key, excluding this host. Unknown network
uses existing404; unavailable membership/project/person uses existing fail-closed
errors. Wrong selected host returns409 reachability_unavailable before peer IO.
Malformed/duplicate/unknown/null/trailing/oversized input is400 without echo.
Owner administration socket only; no peer/bootstrap/scoped-adapter exposure.

A valid guarded observation returns HTTP200, including not_verified/null.
Return exactly:

```
{version:1,host_id,context,observed_at,
 inspection:{review_id,review},
 reachability:{direction:"project_host_to_participant_host",
   peer_host_id,peer_host_public_key,
   result:"authenticated_response"|"not_verified",http_status:NUMBER|null,
   incoming_delivery:"not_verified",model_receipt:"not_verified",
   connection_readiness:"not_verified"}}
```

Inspection is the complete current section30 review/digest; its digest does not
sign the mutable reachability result. The direction is deliberately opposite
the status pane's advertised incoming work. A complete bounded final HTTP
response (status200..599) over the exact pinned mutually authenticated ordinary
peer transport gives authenticated_response and that numeric status, including
403/404/500. It proves only that this host exchanged an authenticated response
with that machine. Even200 with an empty body/agent list grants no access and
proves no network agreement or incoming path. No remote body, metadata, header,
endpoint or diagnostic is returned, parsed as permissions or retained. Invalid,
partial/oversized response, timeout, absent route, refused authentication or
transport failure gives not_verified/null, never authenticated success. No
HTTP status alone bypasses the post-IO authority/project guards.

### One explicit bounded exchange

Capture the exact complete inspection and project/network/person/host public-key
pins in a short read transaction and release it before IO. Resolve only the
existing ordinary pinned dial target and require the same target ID/key.
An existing owner-configured manual peer address retains ordinary precedence;
configuring that transport hint remains a separate public owner operation,
never a request-field override or key fallback.
Issue one logical GET `/peer/v1/networks/{network_id}/agents` with no body and
an8s total exchange bound; the owner API is bounded12s and CLI15s. Reuse ordinary
QUIC identity/ALPN, current direct/optional replaceable helper routes, cached
connections and its one fresh-connection retry when a reused connection failed
before response bytes. No additional application retry, fanout, endpoint/key
fallback, contact-learning sync, directory refresh, catalog/repair, preparation,
signing/provider call, message/task/artifact/capability action or model turn.
An absent usable current route is an honest negative observation. Existing
ordinary callers retain their contact-learning and transport behavior unchanged.

Recheck the exact authoritative project and complete inspection in a fresh read
transaction after IO, including after failure. Changed or expired project,
membership/root/policy or selected host/key discards the result with409
reachability_unavailable (or the existing project error), never rebinds it to
new terms or falls back to a successful empty view. An expired overall request
returns a fixed unavailable error. DB reads run on blocking workers; no SQLite
transaction or thread-local DEC read guard survives an await. No DEC guard,
consent, authority, event, directory cache or durable observation write. Existing
normal transport connection/path caches, packet exchanges and certificate
construction are allowed; unrelated background workers retain their own effects.
No new state/schema/protocol/remote route or durable lifetime is introduced.

The whole <=2MiB public result passes the existing recursive privacy guard.
Private input paths/native references stay on the same owner-local boundary as
section30. CLI uses the configured state literally, never creates/starts a
missing daemon and emits fixed invalid/unavailable input/argument/response errors,
not raw remote output. This backend slice has no native status change and does
not overwrite section36/37's not_verified flags or invent a combined ready state.

### Verification

A separate contract-only author adds a compact six-case `peer_reachability`
slim suite, using genuine ordinary two-person/two-host coordinator-free setup
and public project/peer/grant/lifecycle operations. Commit before root executes;
no product/Rust reads or fabricated authority/protocol rows, no real-model probe.
Copy only independently authored public helpers; preserve all old files. Cover:

1. Exact owner API/CLI closed shape, section30 digest/binding and selected remote
   key, real pinned200 response without an adapter or advertised agent. Direction
   and all incoming/model/overall flags remain distinct and not_verified.
2. Real current receiver entries can change/withdraw without turning this check
   into permission/model proof. Failed route/wrong pinned endpoint returns
   not_verified/null without raw diagnostics, fallback key or automatic retry.
3. Exact project/network/person/remote host guards reject unknown/mismatched/self
   targets, detached/replaced project and expired authority before IO. No endpoint
   override or successful empty substitute; counted non-target carriers stay idle.
4. Delay an actual dispatched exchange using a counted transport barrier, change
   the authoritative project through ordinary lifecycle, then release the reply.
   Reject the old result, with no later rebind, mutation or duplicate exchange.
5. Repeated successful/failed checks in genuinely quiescent fixtures preserve
   complete logical DB/authority/consent and private-file hashes on both hosts.
   Account for BOTH TCP/UDP paths; expected peer traffic is explicit and only the
   selected pinned route is exercised. No directory-refresh/cache state change or
   hidden contact-learning sync when no route is currently usable. Genuine public
   maintenance/restart prerequisites precede captures, no worker suppression,
   excluded tables or relaxed counters. A genuine bootstrap-only fixture can
   retain normal proof outboxes that cannot drain without a peer route. Its
   no-route capture may use a naturally quiet retry-backoff window: all pending
   secrets/read caps/frames are retired, every actual outbox next_attempt_at is
   strictly beyond the complete short capture, and complete outbox rows remain
   in both state comparisons. Observe real time before/after; never move retry
   timestamps, suppress a worker or ignore an outbox/table/counter difference.
   Positive-route captures still finish actual outstanding transport first.
   The selected deterministic bootstrap prerequisite now temporarily enables
   counted peer listeners without manual peer rows, exchanges genuine signed
   current contacts and drains actual proof outboxes. These counted listeners
   may be available during the genuine initial admission/publication; the
   no-route purity capture itself still requires bootstrap-only operation.
   An enabled peer listener supplies an actual advertised default when the
   configured QUIC list is empty (the existing private-handoff default), so an
   empty advertise list alone does not withdraw a bound listener. Issue the
   genuine newer empty-QUIC handoffs while bootstrap-only, retain their actual
   signed contacts, temporarily enable counted listeners for authenticated
   imports, then restart bootstrap-only. Reissue own empty contact handoffs if
   a genuine intermediate own-contact refresh superseded them; require all
   actual retained local/remote contacts empty before capture. Retire every
   short handoff through real expiry/maintenance. No manual hint/helper or
   cached dial route survives. Preserve the failed empty-list expectation and
   its exact source/log; this corrects the fixture, not runtime advertising.
   Require actual empty outboxes/secrets/frames and the unchanged quiet gate;
   never delete/acknowledge rows directly. Earlier natural-window failures and
   diagnostics stay recorded; no sleep or deadline increase substitutes for
   finishing the genuine pending work.
   If the unchanged bootstrap quiet bound fails, a failure-only observer may
   retain the last eight existing samples: elapsed/stable milliseconds, retry
   margins against both actual clocks, secret/readcap/frame/journal counts,
   fixed changed-table/file categories and all carrier deltas. It adds no
   network/daemon operation, sleep, state mutation or extra sampling query,
   prints no raw identifiers/paths/records, and rethrows the original failure.
   A mismatched expected transport observation may similarly print only its
   expected/actual fixed result tags and numeric HTTP status, target process
   running/exit category, counted-proxy thread liveness and fixed carrier counts.
   For a later mismatch, retain at most four preceding ordinary observations:
   fixed expected/actual result and target-running category, elapsed monotonic
   milliseconds and existing carrier deltas. Count fixed-category existing
   proxy socket send/receive errors without changing their handling; expose
   those counts only on failure. No addresses, records or raw errors appear.
   Once a transport mismatch and its original state/carrier categories are
   captured, one failure-only independent ordinary peer-directory probe may
   use the same selected key/known counted endpoint, bounded15s. Emit only
   exit/status/body-type categories, elapsed time and before/after carrier
   deltas; no response body/raw errors. Retain the original failed verdict,
   never retry the observation endpoint or turn a diagnostic pass into success.
   A failure-only snapshot of each new proxy thread's current Python frame may
   emit a fixed selector/client-receive/upstream-receive/send/other category;
   inspect only this suite's own helper source, no raw frames/paths/lines. This
   distinguishes a live but blocked forwarding thread from a listening route.
   A read-only exact manual-hint match boolean may accompany it. This exception
   adds diagnostic IO only after the original failure, outside purity captures.
   The measured restart diagnostic finds the target proxy alive but blocked in
   upstream receive, while a fresh independent probe also cannot reach its
   counted ingress. Choose nonblocking sockets for this new suite's selector
   proxy: stale/spurious readiness or asynchronous UDP errors must not turn a
   subsequent receive into an unbounded block. Treat would-block as a transient
   no-datagram condition at receives/sends; retain real error counters, all
   datagram/byte accounting and barrier semantics. No production transport,
   shared old helper, assertion, action, sleep or deadline changes are implied.
   Temporary enabled listeners during setup explicitly advertise the counted
   endpoint; bootstrap-only issuance/final captures advertise no QUIC endpoint.
   This prevents an intermediate bound-address default bypassing accounting.
   Apart from that explicit post-failure probe/read exception, observers add no
   daemon/network/SQL operation or changed assertion/action/timing;
   the original failure remains a failure. These diagnostics establish no cause
   when they do not trigger.
   Document public-fixture coverage limits.
6. Closed malformed/duplicate/unknown/null/trailing/oversized/private stdin/argv,
   missing-daemon noncreation, wrong methods and owner-only isolation through
   ordinary peer/bootstrap/adapter interfaces. All fixed errors omit raw input.

Root serializes Rust fmt/test/Clippy/all shipped binaries and new slim suite plus
old readiness locally, retaining first outcomes and exact source/binary/test/log
hashes. Reuse merged87's unchanged native tree/strict validation/local history;
final exact-head all30 suites/four PR checks (native365)/fresh bot/root review run
again. No unchanged local retry-to-green, old-file edits or deadline increases.
Actual native controls, terminal/reload/installed/physical/model/other-computer/
schema23-to27/full-state/final combined/full-feature acceptance remain open;
prior local native timeouts/host transport callers remain unclassified.

Selected: explicit one-machine pinned outbound transport evidence using the
existing peer read, with exact before/after current-authority pins. Discarded:
unbounded all-machine fanout, ordinary directory refresh/contact-learning sync,
new public ping/admin route, mandatory hosted helper, remote body as permission
proof, interpreting reverse reachability as incoming delivery, messages/model
turns as an implicit probe and a combined overall-ready flag.

## 39. Native selected-machine outbound connection check

After merged89 (`9ca61f5`), expose section38 through the existing human native
connection-status pane. Rust/schema/protocol/provider/authority and authorized
adapter/message/task/model behavior remain unchanged. Preserve all365 existing
native cases and all30 host suites/helpers byte-for-byte. This adds an explicit
outbound transport observation, not incoming work or complete connection proof.

### Explicit machine choice and dispatch

A verified, live section37 status pane offers **Check a machine connection**.
Normal entry, status reads, approvals, Finish, recovery, details and reload
never dispatch reachability. The action opens **Choose a remote machine** from
that verified snapshot's selected-person remote roster. Entry/choice/pagination
use volatile public data plus existing native-context guards only; no additional
host command, status refresh, provider or network work. Exclude this host and
show every remote label quoted beside its derived host ID. Duplicate labels
remain distinct by key/ID. Ten choices per page use **Previous machines** and
**More machines**. An empty roster says no remote machines were observed and
offers Check connection status/Leave. Even a single machine needs an explicit
**Choose machine LABEL (HOST_ID)** press; never infer or default a target.

Selection opens **Outbound connection**, showing project/agent/network/person,
that exact selected public machine label, host ID and public host key. It says
no outbound check has been performed until **Check outbound connection** is
pressed. **Choose another machine** clears the result and returns to the same
bounded roster without IO. **Check connection status** explicitly returns through
section37's ordinary fresh local read; **Leave machine connection** returns to
the project. Neither navigation revokes consent or stops an authorized runtime.
No new command/model tool/storage or direct socket implementation is added.

Only Check outbound connection starts one single-flight request. Clear the old
outbound result/details immediately; while busy, show a bounded checking state
and Leave. Capture the exact attached parent, native context, host, network/
context/person and selected host ID/public key. Recheck current root/project/
conversation/terminal and the authoritative attached project/host/network before
dispatch and after IO, after asynchronous validation and at final display.
Use existing pure project inspect/onboarding guards, not access mutation,
directory refresh, membership sync, provider inventory or model inference.

Use configured executable/literal --state argv with private stdin and15s bound:

```
onboarding reachability --stdin
{context,network_id,person_public_key,peer_host_id}
```

No addresses/keys/provider options or shell interpolation enter argv; the
captured host key is a local validation pin, never a request override. One
explicit press sends at most one such command, with no automatic retry, fanout
or action after an uncertain reply. Backend cached-connection retry remains
section38's own transport behavior, without UI attribution. Leaving or timing
out cannot retract already dispatched peer IO; late results are discarded.

### Closed validation and truthful human evidence

Validate the entire <=2MiB section38 DTO with the existing recursive public
privacy/safe-number gate. Require its exact closed wrapper and reachability
fields, version/host/context, canonical time and complete section30 inspection/
digest for the captured parent/network/context/person. Require the selected
remote host key still occurs in the current inspected person, its derived ID
equals the captured selected ID, and returned ID/key equal those captured pins.
Never accept another key/target, this host, missing/unknown/null fields or a
private/unsafe aggregate, or substitute an empty success for unavailable data.
The backend may supply a newer current inspection with changed policy/membership
metadata while the same selected key remains current; show only the returned
observation's own terms. Do not merge its current policy with old status facts,
compare it as consent or turn it into a frontend permission evaluator.

Require direction project_host_to_participant_host, exactly
`authenticated_response` with a safe integer HTTP200..599, or exactly
`not_verified` with null status. The incoming_delivery/model_receipt/
connection_readiness flags must all remain not_verified. A negative observation
is a valid result, distinct from command/validation failure. Accept403/404/500
as authenticated transport responses and say their status does not establish
permission. HTTP200, an empty directory or any other response proves only the
outbound authenticated exchange; no remote body is supplied to the UI.

The result shows **Outbound authenticated response observed** and numeric HTTP
status, or **Outbound connection: not verified** for a valid negative, plus
observed time, exact selected ID/key and direction **from this project's host
to the selected person's machine**. Incoming agent delivery, model receipt from
this observation and overall connection readiness remain explicitly **not
verified**. The previous local permissions/adapter snapshot is cleared when
entering this separate pane; this check never overwrites its readiness flags
or borrows its model/adapter evidence. Existing live runtime checks remain
separate and are not started by this action.

**Show outbound connection details** / **Hide outbound connection details**
is local-only. Include the complete public current agent/network/root/owner/
participant membership, raw signed and separately enforced policy, proof refs,
selected machine, direction/status and display deadline. Use canonical JSON
escaped once. Hide internal native/project/consent/session plumbing IDs and
private context/diagnostics from routine output/model/prompts/logs/argv; the
quoted project path stays confined to the human pane. Do not use a consent
footer or imply missing signatures from this read. No addresses/raw remote
body/exception/return material are presented or retained.

### Bounded selection, evidence and recovery

The roster's fixed deadline is the earliest of its original observed_at+30s
and section30 owner/participant/machine/policy finite ends. Entry requires the
original section37 snapshot still live; after navigation only roster membership
is displayed, so old adapter-lease/grant facts are not extended or reused.
Selection/dispatch require the captured roster still live. Keep that same
fixed timer authoritative during preflight, request and async validation; its
expiry clears roster/selection/result/details and invalidates pending work.
A result never extends that captured roster window. Starting another explicit
check or choosing another machine clears the previous result and its separate
display-expiry authority; that old result's earlier deadline cannot clear the
new choice or in-flight observation. The original roster deadline stays fixed
and authoritative throughout. A result's own display deadline
is additionally bounded by returned observed_at+30s and every current section30
membership/policy end. Recheck time after every awaited preflight/validation
before dispatch/display. Reject future evidence beyond30s or already30s old.
No timer performs IO; old timers cannot clear another selection or new read.
On expiry say **Machine connection observation expired. Check connection status
again.** and offer fresh Check connection status/Leave only.

A malformed, denied, nonzero, timed-out, mismatched or elapsed reply removes
old outbound evidence and shows a fixed **Outbound connection unavailable**
message, never raw output or fabricated successful negative. A still-live
selection may be checked again only by another explicit press or changed by
Choose another machine. No action continues automatically. Back/Close/Refresh/
root/conversation/host/parent/surface/end invalidate callbacks, timers and late
results, without revoking prior consent, cancelling a peer request or changing
an existing authorized runtime beyond its existing lifecycle rules.

### Verification

A separate contract-only native author adds16 compact runtime cases from public
sections30/36/38/39 and pinned303 SDK/independent fixture source, with no product/
Rust/hook imports/reads or process/host/network/model execution. Commit before
root executes. All365 old native cases/all30 host suites/helpers remain exact;
new corpora fit the unchanged default5s individual limit. Actual pending stimuli
signal real dispatch and virtual-sleep registration. Cover:

1. Existing actions inert; explicit status entry, literal configured argv/private
   input and15s reachability bound, only ordinary pure parent/host guards.
2. Explicit no-default one/many/empty machine choices, derived IDs/keys,
   duplicate quoted labels, self exclusion, ten-item pagination; local choice.
3. Authenticated200 with no adapter/permission claim; precise outbound direction,
   exact selected key and distinct incoming/model/overall evidence.
4. Authenticated403/404/500 remain transport facts with numeric status, no
   permission or incoming-ready inference; valid negative is not command error.
5. Pure complete public details, original signed/enforced order and bounded
   human metadata; no new model tools/prompts/storage/direct networking.
6. Recheck clears old results; single-flight repeated press and actual delayed
   dispatch; no hidden retry or endpoint call from choice/details/navigation.
7. Closed wrapper/reachability/version/direction/flag/status/type/count corpus;
   malformed and unsafe JS integer data fail without empty-success substitution.
8. Exact selected machine/key/current membership, owner/network/person/agent/
   project pins, full inspection digest; changed labels/policy may be fresh
   current evidence for the same exact target, without blending old terms.
9. Aggregate private prefixes/decorated values/controls/oversized output and
   raw/nonzero/denied/missing replies clear old terms with fixed diagnostics.
10. Original roster deadline and returned earliest30s/membership/policy bounds;
    expiry removes all evidence/choices without IO and requires new local read.
11. Deadline crossing during actual preflight sends no reachability command;
    actual delayed response/async validation cannot resurrect elapsed selection.
12. Changing chosen machine clears previous facts; no ID/key/default rebind,
    and old result/timer cannot affect a fresh status/roster/target.
13. Root/conversation/host/network/parent changes during actual preflight or
    pending IO discard late evidence, without next mutation or automatic probe.
14. Leave/Back/Close/Refresh/end/surface changes while pending clear volatile
    state; reentry/reload starts without a selected target or saved result.
15. Unavailable/negative recovery needs explicit Check; Check connection status
    returns via the existing local read and never retries outbound work.
16. Existing authorized adapter lease/message/task lifecycle survives local
    choice/check/negative/unavailable/details/Leave, without extra model work.

Root serializes runtime/build/host work, checks known compiler activity,
records every first outcome and source/test/log hashes, runs strict pinned303
validation/full381 suite plus unchanged peer_reachability locally. Reuse merged89
Rust treeeac511ee/local required fmt/test155+2ignored/Clippy/shipped-bin gates and
old readiness6/6; final exact-head all30 suites/four PR checks/fresh bot/root
review run again, including all31 conformance jobs with pagination. No unchanged
retry-to-green, old-test edits or raised timeouts. Earlier unclassified native/
transport/history failures remain recorded. Actual terminal/reload/installed/
physical/model/other-computer/schema23-to27/full-state/final combined/full-feature
acceptance stay open; do not repeat quota-refused model probes.

Selected: explicit current remote-key choice and one bounded outbound check
with separate short-lived human evidence. Discarded: an implicit/default machine,
fanout, automatic probe on status/approval, conflating reverse transport with
incoming work, a combined ready badge, durable observations, frontend permission
inference, direct sockets and broader existing runtime scopes.

## 40. Native request to connect this computer to an existing person

GU.impl40 begins the new-computer side of GU-05 after merged90. Reuse existing
sections11/12/15 preview, durable public-key-only request consent, atomic ordinary
publication and pure progress. No new API/schema/journal, original-key inventory,
creation/import/copy/signature, provider, runtime scope or completed admission.

### Explicit private lane and exact pin

An attached project offers **Connect this computer** beside unchanged **Join a
network**. This explicitly selects a volatile machine-request lane. Recheck
exact attached project/native root/conversation/terminal/host, then section12
lookup before input. No implicit preview/prepare/inventory/key/model work. No
retained flow starts an empty **Private invitation for this computer** field.
Explain the original key stays on the existing computer, a separate device key
is requested only on publication approval, and the invitation must pin the
existing person. Input is visible private human terminal text, never agent chat;
Enter only updates a bounded volatile draft. No clipboard/file/plugin storage.

**Review this computer's identity** clears the drawn code synchronously, checks
psi2 syntax/32KiB bounds and sends one existing5s private-stdin preview. Validate
the complete section11 wrapper/review/digest, host/context/agent and canonical
times. An unpinned invitation refuses with controlled text requiring a pinned
invitation from the existing computer. No arbitrary pasted key, generated
substitute, inventory or first-key default repairs it. Show all verified public
invitation terms and **Existing person public key**. State the pin identifies
whom to ask, not ownership or inviter authority. No original identities are
read, enumerated or created even when available. No request is yet prepared.

Separate **Review machine request** rechecks native/parent/host/current deadline
and sends existing section12 prepare: exact context, captured private invitation,
its non-dash person pin and only an explicitly retained replacement reference.
Require a live review matching the complete preview/pin; a new proposal cannot
reuse the replaced flow ID. Keep all closed/public/privacy/digest checks.

### Publication and truthful recovery

Display the complete section12 review plus **Original person key stays on the
existing computer**. Approval creates/reuses one ordinary request with a separate
requester device key and publishes through ordinary transport. It grants no
membership, ownership, machine powers, agent/file/conversation/capability access.
No local-original source or possession claim. Actual host/device keys belong to
the resulting ordinary request; do not fabricate pre-publication key terms.
Later owner/requester reviews independently bind exact actual keys and powers.

**Approve machine request** and **Decline machine request** use existing decision
with literal executable/--state argv,5s and private stdin. Both freshly inspect
exact parent/host and retained flow/review. Approval requires captured code,
non-dash invitation pin equal to review person and exact preview terms, without
original inventory/provenance. After asynchronous preflight recheck time directly
before dispatch. Backend atomically rechecks immutable review/invitation before
ordinary device/request creation. Single-flight; uncertain outcomes drop code
and recover only by explicit reopening/lookup, never automatic retry.

Success is **Machine request: publication recorded**, never connected/linked.
Show immutable public outcome and publication versus approval/current-link/
permissions/transport/model limits. **Check machine request progress** uses
section15's pure exact-request snapshot and real next participant/action. No
polling/resume/proof fetch/selection/commit/signing. Do not expose sections17/19/
26/29 new-original owner controls in this lane. State **Approval on the existing
computer is still required** and guided existing-computer approval is subsequent
work. Automatic return is only as available as the invitation says, not proof
of delivery.

Lookup/Refresh/reopen recover public state with no inventory/code retrieval/
prepare/publication/key handling. Machine-lane recovery requires a non-dash
invitation pin equal to the retained person. Other flows refuse with controlled
text and retain their durable outcome, available through Join a network. The
lane is a fresh explicit choice after Close/reload, never persisted ownership.
Refresh preserves it only for that current attached native view.

A retained live review shows original terms but no Approve until exact private
code reentry via **Check invitation for this machine request**. Identical prepare
must return the same entire flow/review/non-dash pin; no inventory or second
preview. Decline needs no code. **Review another machine request**, only from a
non-review outcome, starts an empty draft retaining exact latest replacement ID.
Explain replacement does not cancel/revoke the earlier request; never silently
overwrite a review.

Keep fixed invitation/review expiry through choice/prepare/recovery/approval.
Expiry clears code/selection and removes approval; no timer does IO. Recheck
context/time after awaited guards before dispatch/final display; delayed work
cannot restore expired terms. Before/after every process effect require current
native/parent/host/terminal. Back/Close/Refresh/end/reload/context/pane changes
clear code and callback/timer authority; late results cannot populate a new view.
Preserve durable outcomes and existing authorized adapter/message/task behavior
under existing lifecycle rules. No new model tool/prompt/inference/direct socket/
credential scope/ready badge. Keep original identity lane's inventory/provenance/
creation requirements unchanged. Private prefixes, unsafe/closed aggregates and
raw diagnostics refuse. No code in argv/model/log/storage or post-submit drawing.

### Verification

Separate contract-only author adds12 compact native cases from public sections
11/12/15/40, pinned303 SDK and independent fixtures, no product/Rust/hook reads/
imports or runtime/process/network/model execution. Commit before root executes.
All381 prior native cases/all30 host suites/helpers stay byte-identical; retain
unchanged default5s individual limits. Actual pending stimuli signal dispatch.

1. Attached terminal-only explicit lookup-first entry; no implicit preview,
   inventory/mutation/key work; original Join a network stays separate.
2. Inert draft/Enter, literal configured argv/private stdin/5s preview, complete
   terms/pin; no original inventory even when identities happen to exist.
3. Unpinned/invalid/oversized/expired/future invitation refuses without prepare,
   substitute creation, default repair or private/raw output.
4. Separate Review machine request; exact complete preview/pin/replacement and
   prepare wrapper/digest/person binding, no possession or authority inference.
5. Exact one Approve with no local original, immutable publication outcome and
   truthful device/key/permission/readiness limits.
6. Decline without code/inventory; double presses; denied/nonzero/malformed/
   uncertain results recover lookup-only, no automatic retry.
7. Retained live review exact-code recovery then approval; unpinned/mismatched
   retained flow refuses in this lane without replacing its durable outcome.
8. Refresh/Close/reopen/reload public recovery without inventory/code/prepare;
   no original-owner signing/selection/commit controls in the machine lane.
9. Explicit pure progress/next participant without advancement; replacement
   keeps latest ID and explains that the older outcome is not cancelled.
10. Fixed invitation/review timers and real delayed preflight/IO: no late
    dispatch, expired evidence/code or old-timer resurrection.
11. Real pending root/conversation/parent/host/terminal/navigation/end changes
    discard callbacks; private/closed/digest/person substitution refuses.
12. Established adapter/message/task runtime survives the human lane without
    extra model tools/prompts, authority or wider runtime scope.

Root serializes runtime/build/host gates, samples known compilers, records every
first outcome/source/test/log hash. Run strict pinned303 validation/full393
native suite and unchanged join_onboarding with verified merged89 binaries.
Reuse unchanged Rust treeeac511ee's recorded local gates; final-head all30 host
suites/four PR checks/fresh bot/root review run again, including all31 jobs with
pagination. No unchanged local retry-to-green, old case/stimulus/deadline edits
or quota-refused model probes. Retain earlier unclassified native/transport/
history failures. Existing-computer guided approval and terminal/installed/
physical/model/schema23-to27/full-state/final combined/full-feature gates stay open.

First full393 native execution records390 pass: eleven new cases pass, one new
case requires the clearer explicit phrase pinned invitation, and two unchanged
old access-completion cases hit their original5s limits (cause unclassified).
Correct that guidance, preserve every case/deadline, and verify the affected
twelve in a byte-exact plugin artifact containing only the new test file: the
pinned CLI exposes no filename filter. Record its file manifest/source hashes;
do not retry the unchanged old cases locally. Required final CI still runs all
393 at one exact final head; that pass cannot classify the earlier timeouts.

Selected: explicit pinned existing-person requester lane over ordinary public-
key-only backend, original key stays on its machine. Discarded: copying/import,
substitute person creation, local inventory as a device prerequisite, arbitrary
unpinned input, pin as ownership/approval, new journal/schema and new-original
owner controls for this requester. No new owner choice is attributed.

### GU.impl40a: preserve first CI failures and identify purity prerequisites

First final-head CI8183a22 passes all four PR checks (native393/393in75.27s,
Rust155/2ignored/fmt/Clippy/build), while the full host matrix passes28/30
suites. Unchanged section24 owner_finalization case6 observes one existing
known-context contact row changing sequence/message hashes/contact bytes;
counts/conflict/files/relays remain unchanged, not the other participant key.
Its existing observer does not identify requester key or which of three
inspections failed. Unchanged section28 requester_completion case6, detached/API,
observes issuer UDP+2 datagrams/+2400 bytes with zero returns, after its entire
DB/state/home comparison passes. Existing timing metadata identifies no caller.
Both causes remain unclassified; do not infer them from earlier other suites.

Separate contract-only authors may add ONLY the following failure diagnostics,
before one retained serialized local run of each affected suite on unchanged
Rust binaries. No setup/action/clock/wait/deadline/worker/route/counter/record or
assertion changes, and no unchanged retry-to-green. Removing diagnostic additions
must restore every original source byte/AST, including all case bodies, original
captures and verdicts. Preserve the CI logs and exact source/test/binary hashes.

Section24: use captured before/after snapshots only, zero new IO/time reads.
Add fixed inspection phase before_F/after_F/after_expiry/unknown by explicitly
tagging the original three case6 calls. Classify each changed key as requester/
issuer/other/unknown against already known canonical participant keys. Add
sequence-increased and canonical singleton contact issued/expiry/payload-changed
booleans, and whether each before/after issued/expiry time lies after the known
original request deadline. Support canonical SQLite full-u64 sequence encoding;
invalid/duplicate/oversized/malformed input produces fixed unknown. No raw IDs,
keys, sequence values, hashes, bodies, payloads, timestamps, addresses, locators,
paths, labels, private material or diagnostic exception text. Never alter the
existing snapshot assertion or classify an unknown caller from this metadata.
An observed local renewal may later justify a separate contracted genuine
current-own-contact prerequisite like GU.impl33e; this is no approval to add it.

Section28: only after the original captured carrier mismatch, perform at most
one pure owner-local GET /v1/directory?network=EXACT_KNOWN_NETWORK with2s bound.
No directory refresh, peer/probe/resume request, retry or waiting. Print only
HTTP status (or unknown), network_matches boolean, known issuer row count,
whitelisted host state ok/error/unsupported/pending/unknown, known issuer host-
row refreshed_at-present and refreshed_at-at-or-before-current-time booleans.
The top-level directory timestamp is not a substitute. Unknown/unsafe/ambiguous
data stays unknown; no raw directory error/agent/key/ID/time/body or exception.
All diagnostic failures are swallowed, returning the original captured carrier
tuple so the original failing assertion/verdict is identical. A pending cache
row identifies incomplete observed directory state, never proves a traffic
caller or a global IO fence. Other results do not classify the earlier failure.

Selected: narrow failure-only public metadata, preserving every measurement
and verdict. Discard guessed contact/refresh fixes, artificial queue/authority
edits, disabling workers/paths, counter filtering, larger waits and blind reruns.

### GU.impl40b: access-signing startup prerequisite observation

Revised CI78668d1 passes four PR checks/native393 and29/30 host suites, including
both GU.impl40a diagnostic suites. Existing section32 access_signing cases5/6
fail the unchanged current genuine peer startup query has not completed setup
assertion. The log does not show the returned directory state; cause unknown.
Do not infer a timeout or relax the required successful current startup query.

One separate contract-only author may add a compact failure-only observer to
that existing directory helper. Use only its already-returned response/status
and known participant IDs; no new IO, clock read, refresh, retry, wait, bound or
setup change. When its original known-peer assertion would fail, print only:
local_role/remote_role a/b/unknown, HTTP status100..599/unknown, network_matches
boolean/unknown, known_row_count, whitelisted host state ok/error/unsupported/
pending/unknown, and refreshed_at-present boolean/unknown. No error strings,
raw rows, keys/IDs/addresses/timestamps/paths/labels/bodies or exceptions. Catch
diagnostic errors; execute the exact original assertion unchanged afterward.
No observer on success. Removing only helper/call additions restores original
source bytes/full AST. Keep all case actions/captures/assertions/delays/deadlines/
counted paths. Commit before one retained local diagnostic suite run against
the same frozen binaries. A pass does not classify prior CI or fix runtime.

Selected: identify the exact returned prerequisite state without guessing or
changing the test's success criterion. Discard blind rerun, state-ok relaxation,
counter filtering, new network attempts and increased existing waits.

## 41. Existing-computer machine-owner inspection

GU.impl41 adds the read-only backend prerequisite for approving the section40
machine request on an existing computer. It creates no consent. Later slices
add exact durable owner consent, bounded signing, native controls and requester
selection/completion. Existing advanced link operations remain available.

### Private operation and eligibility

Owner-local `POST /v1/onboarding/machine-owner-inspection` and advanced
`peerspan onboarding machine inspect --stdin` accept exactly
`{"context":AdapterContext,"request_id":LINK_ID}`. Context is section5's exact
five-field attached-project context. Decode at most65536 bytes, reject unknown,
duplicate, missing, null, wrong-type and malformed fields at every level before
work. CLI reads only stdin, never IDs/private payloads in argv, uses the configured
owner socket and a5s local request bound. Failures use fixed redacted text, even
Clap argument errors. No peer/bootstrap/adapter route or model tool is added.

Use one held read transaction. Missing request is404 `not_found`; malformed
input is400 `invalid`; stale/detached/replaced project is409 `review_changed`.
Other unavailable evidence is409 `machine_owner_inspection_unavailable`, without
raw diagnostics. Verify the retained ordinary request signature and exact pins.
Only a live incoming approver `new` nonmigration request on a different host,
with explicit non-dash network/context/person pins, qualifies. Request state must
be pending; no owner/selection/administrator/finalization/commit intent, packet,
manifest, activation, outcome, selection approval or commit approval may exist.
Check guarded decision time is at/after request creation and latest stage, and
strictly before both ordinary request and stage deadlines. Cancelled, expired,
blocked, later-stage, requester-local, unpinned and new-original requests refuse.
Unpinned here means a dash in the signed request's network/context/person pins;
an invitation's earlier pin is not an additional authority prerequisite for this
existing-computer inspection. Section40's requester UI still requires its pin.
No fetching/resume/import or automatic invitation redemption occurs.

Load the current admitted DEC network/context and project its actual verified
root, P/H/B/D membership, proof completeness, restrictions, maxima, bans,
conflicts and migration fence. Local host must currently belong to exactly the
requested person, and the network's remembered own person and selected public
provider must agree. No root-as-owner fallback or original-key substitute.
Use ONLY the persisted public selection: original or an owned local device.
Resolve current public authority without reading device/root seeds, original
key files or SSH agent, testing key availability or executing a signer. Thus
public authority may be reviewable even if its private signer is unavailable.
A device's selected lease/key must match its current active public path and must
not equal the requester's device key. Require all proposed owner bits7 to fit
within the provider's effective scopes; no silent powers downgrade. Reject an
already admitted requester host owned by a different person. This read grants
neither requester host admission nor new machine ownership.

The fixed first proposed profile is7: policy editing1, host binding2, eligible
own-device approval/renewal/revocation4. It excludes administrator8. Proposed
not_after is the earlier of signed request creation+7days and the provider's
current effective deadline; it must be strictly after observed time. This finite
cap is explicit in the review. An existing selected provider with effective8 may
fold host admission under later exact ordinary owner consent; otherwise a
separate administrator is required. This is potential, never consent or a
promise of successful signing/admission. No network_root fold is selected here.

### Closed public result and purity

Return exactly `{version:1,host_id,context,observed_at,request,review_id,review,
next_action:"review_machine_owner_consent"}`. `request` is the ordinary complete
public LINK_VIEW at this same observed time. `review` is exactly:

- `version:1`, `kind:"inspect_existing_person_machine"`, `host_id`, exact
  `context`, exact attached project `agent`;
- `network:{id,name,context_id,genesis_root_public_key}`, `root_state_id`;
- `request_id`, `request_packet_id`, `person_public_key`, actual requester
  `host_public_key`, actual requester `device_public_key`, current person `member`;
- `person_lease_id`; `local_host` is exactly the current member response
  `{host_public_key,member,person_public_key,host_lease_id,binding_lease_id,
  device_lease_id,not_after}`;
- `provider` is the ordinary public authority object exactly `{kind,
  person_public_key,host_public_key,device_public_key,lease_id,root_state_id,
  scopes,not_after}` (original_person or device); `provider_id` is the concrete
  original person key or selected device lease, `signature_format` is respectively
  sshsig or ed25519. These identify public authority, not signer availability;
- `scopes:7`, fixed `not_after`, `host_admission` is `owner_may_fold` iff current
  provider has effective8, otherwise `separate_administrator_required`;
- signed request `created_at`, ordinary request `expires_at`;
- `effects:{verify_request_signature:true,inspect_current_owner_authority:true,
  prepare_owner_intent:false,approve_owner_intent:false,sign_owner_offer:false,
  publish_owner_offer:false,grant_membership:false,grant_machine_powers:false,
  grant_agent_access:false,commit_request:false,share_files:false,
  share_conversation:false,capability_calls:false}`.

`review_id` is `review_` plus SHA256 of UTF8
`peerspan-machine-owner-inspection-v1\n` followed by recursively key-sorted,
compact canonical JSON of the entire review. Observation time is outside the
digest; unchanged reviewed facts retain the digest while the exact attached
parent remains valid. Restart detaches sessions under the existing contract:
old-context reads then refuse review_changed; explicit fresh attachment changes
project/digest even if authority/request terms stay equal. A new
root, selected provider, membership, cap or project produces changed terms or
refusal, never repairs the prior snapshot. It is not a consent token. No new
journal/schema/intent/clock save/event/key/queue/contact/cache refresh or network
IO. Existing unrelated workers may act independently; tests settle genuine
transport prerequisites before measuring the read. Public result must be <=2MiB,
reject unsafe control/private-prefixed label or aggregate rather than copying
private material into output. Never return invitations, request codes/secrets,
credentials, seeds, signatures, packet bodies, routes or signer diagnostics.
Readiness, incoming delivery and model receipt remain unverified.

### Verification

A separate contract-only author creates compact `machine_owner` slim conformance
from public sections5/9/11/12/40/41 and ordinary DEC specs, independent existing
harness/fixture source only. No implementation/Rust/hooks reads/imports or
runtime/process/host/network/model execution by author. Commit before root's
first execution. Six cases, under2minutes total, preserve all existing suites,
helpers, assertions and bounds. Use genuine public network creation/attached
project/pinned invitation/automatic incoming return; no authority/pending/clock/
queue row fabrication. Read-only SQL may snapshot/count rows.

1. Existing selected device owner and actual pending new computer: complete
   closed shape, actual signed pins, current authority/dependencies, exact digest,
   finite7/bit8 exclusion, public fold potential and no original key on requester.
2. Exact stdin CLI/API equivalence, stable digest across live reads, restart
   detachment refusal and fresh-project changed digest, no argv/
   private output; strict nested/duplicate/null/unknown/oversize/wrong-type inputs
   and redacted argument failures. Same socket and5s client bound.
3. Missing/local/new-original/unpinned/wrong-person/wrong-network-context and
   detached/replaced project refuse, without changing ordinary pending/authority.
4. Current selected original public authority is reviewable without private-key
   availability; selected device with insufficient bits refuses without fallback.
   Use public signer selection/authority operations, no seed deletion or DB edit.
5. Genuine cancelled/expired/later-stage and changed current authority refuse or
   show changed digest/current fixed cap. Include effective provider deadline cap
   and appropriate separate-admin potential through genuine public fixtures.
6. Settled whole-DB/private-files/traffic purity for repeat successful/failed
   API/CLI inspections; unchanged request/intent/key/consent counts. Peer mTLS,
   bootstrap and scoped adapter routes cannot invoke this owner administration.

Where no bounded genuine public fixture exists, record the exact source-only
limit rather than fabricate success or mark a requirement verified. Root owns
serialized Rust fmt/test/Clippy/build and local new-suite + unchanged join suites,
records first outcomes/head/test/binary/log hashes and known compiler samples.
No unchanged retries-to-green, old test/bound edits, guessed background fixes or
quota-refused model probes. Required final-head full matrix (31suites plus build),
four PR checks and fresh bot/root review follow. Native393 stays unchanged;
required final CI runs it. Full other-computer/native/terminal/reload/installed/
physical/model/schema23-to27/full-state/final combined acceptance stays open.

Pre-execution independent-test audit corrects semantic statement ds_ references
versus catalog dp_ proof IDs using the public exact-byte identity formulas, and
adds actual signed request dpk_ identity verification after both host/device
signatures. Initial author4c0615 and corrected7776522 sources are retained; no
new suite was executed before this correction. Six cases retain their bounds.
The bounded suite leaves insufficient-device/separate-administrator, complex
fork/restriction/ban/migration paths, foreign-person admitted requester, unavailable
owned seed, malformed proofs, incoming dash/context-inconsistent signed pins,
private-key/sign-call syscall attribution and an actual stalled-client5s cutoff
as source-only limits. Later packet-stage purity is combined with genuine
cancellation to retire approved work; it is not standalone live-packet purity.

The first corrected-format receipt write fails with errno28 in shared /dev/shm;
its child result is unretained. The following unchanged join_onboarding exits120
in2.01s with empty log (case progress unknown). Preserve these resource-failed
attempts. Relocate only this task's temporary data/logs to regular disk with
independently observed free capacity; keep exact binaries, sources and deadlines.
One affected-gate execution in this corrected environment is allowed, with no
product fix or old unrelated-failure classification inferred.

The corrected-environment local join_onboarding finishes14/14in75.64s, but root
erroneously starts ordinary join before it exits. Preserve that overlap limit
and interrupt the newer join (exit130/28.18s; three cases passed). No complete
local ordinary join claim. Correct the local runner with a task-owned exclusive
nonblocking gate lock. Do not rerun unchanged local suites for a cleaner receipt;
final exact-head CI independently runs both unchanged suites in isolated jobs.

### GU.impl41a: first CI and ordinary-setup observation

First draft CI at2c8a51e (run41230550919, machine_owner job124624035296)
records0/6in22s. Four cases fail exact current local P/H/B/D member comparison:
product inspection used a member-for-authority helper that deliberately leaves
its device-lease summary dash, while the ordinary members view includes the
actual single active device. Use the current members projection for that exact
local member, preserving all selected-provider and current authority checks.
This is a product correction, not a weaker test.

Case5 fails the ordinary unapproved owner-approval prerequisite; its status/code
were not retained, so cause is unknown. Case6 then expects the cancelled result
that case5 did not establish. A separate author may add ONLY failure-time
metadata for the already-returned case5 approval HTTP status and whitelisted
code (invalid/expired/forbidden/state_conflict/operation_conflict/proof_required/
clock_rollback/signer_unavailable/authority_expired/not_yet_valid/internal/unknown),
and boolean whether an owner_intent_id is retained. No new IO/time reads beyond
the original already required pending snapshot, no raw response/error/IDs/keys/
codes/labels/paths or exceptions, and no setup/action/assertion/wait/bound change.
Preserve the first log/hash. Do not guess a stale-code/contact fixture fix before
observing the response. Native/Rust checks pass in this first draft workflow;
full matrix outcomes are retained separately, including all32 jobs.

### GU.impl41b: distinguish compilation from an external test wrapper

The repeated local no-start fence eventually observes cargo test still alive
with an actual test-binary child but no rustc for several minutes. Its independent
mmfix target is separate from this task's target/binaries. Do not kill other
work or wait indefinitely by calling every cargo wrapper a compiler. Preserve
all no-start observations. The local runner still blocks actual rustc/native
plugin execution and any cargo command other than a test wrapper with no rustc.
Record those external noncompiling test PIDs and every before/during/after
compiler sample as a receipt limitation; don't call the machine wholly idle.
A task-owned exclusive gate lock continues to serialize this stream's runtime,
build and host gates. Test sources/assertions/bounds and resource counters stay
unchanged. Corrected product Rust requires fresh format/test/Clippy/build before
the first local diagnostic suite. Discard killing external tests, hiding their
activity, weaker deadlines and another unbounded compiler-name-only hold.

Selected: pure current existing-owner review, persisted public signer selection,
explicit finite profile7 capped by current authority, concrete public dependencies.
Discarded: seed/key/agent probes, root fallback, original-key copying, label/pin
as ownership, weakening bits, implicit approval, another schema/journal, protocol
progress while reading, and treating the new-original requester owner UI as an
existing-computer review. Choices are recommendations under GU-OWN1.

## 42. Exact existing-computer machine-owner consent

GU.impl42 adds durable consent after section41's public machine review. It uses
ordinary owner intent/transport and an unsigned local review receipt in existing
schema27 dec_intents; no new table, signature format or peer route. Native
controls and explicit bounded signer continuation follow in later sections.

### Private operations and exact input

Owner-local `POST /v1/onboarding/machine-owner-consent/{lookup,prepare,approve}`
and advanced `onboarding machine {lookup,prepare,approve} --stdin` accept:

- lookup: exactly `{context,request_id}`, optionally `consent_id` for a retained
  historical receipt;
- prepare: exactly `{context,request_id,inspection_review_id}`, optionally
  `replace_consent_id` naming the exact latest unapproved receipt;
- approve: exactly `{context,request_id,consent_id,consent_review_id}`.

Context is the existing exact five-field AdapterContext. IDs are canonical
link_64hex/review_64hex/dint_32hex. Reject duplicate/unknown/missing/null/wrong-type
and malformed fields recursively, at most65536 bytes, before work. No private
payload or ID positional argv; fixed redacted CLI parsing/transport errors,
configured owner socket,5s request bound, no daemon startup. API missing request
or specified receipt is404 not_found; malformed400 invalid; changed context/
inspection/replacement/review409 review_changed; elapsed consent409 review_expired;
other unsupported/corrupt evidence409 machine_owner_consent_unavailable. Every
successful lookup, prepare and approve returns HTTP200, including first prepare. Generic
fixed messages expose no private/raw diagnostics. All routes remain absent from
scoped adapter, mTLS peer and bootstrap routers.

### Public lookup and ordinary intent preparation

One held transaction returns exactly `{version:1,host_id,context,observed_at,
request,inspection,consent}`. Request is the complete ordinary public LINK_VIEW.
Inspection is null or exactly `{review_id,review}` with section41's complete
current review and digest, at this wrapper's observed time. Consent is null or
exactly `{consent_id,review_id,review,state,next_action}`. Public result <=2MiB
and no unsafe/private-prefixed label/aggregate. No codes, original key files,
credentials/seeds, raw templates/signatures/messages, routes or signer diagnostics.

Lookup is pure: no cleanup/clock save/intent/key creation, signing/availability
probe, fetch/resume, network IO or event. For a current attached parent it may
inspect a pending request with an existing UNAPPROVED unsigned owner intent;
this narrowly expanded inspection is used only here. Section41's standalone
inspection still refuses every owner intent. Check exactly the same signed
request pins, stage/request windows, current selected original/device/P/H/B/D,
root/restrictions/conflicts/migration and proposed7/deadline cap. An existing
owner intent must match these exact ordinary immutable owner terms, current
public provider and initial owner packet, with no root fallback, possession-only
exception, signature, other approvals or later packet. No original-file/agent
availability check; original public authority remains reviewable when private
signing is unavailable. Public inspection never becomes a new key prerequisite.

Before first preparation require the supplied inspection digest equal this
current review, then call the ordinary owner preparation with the concrete
selected provider, signature format, scopes7, fixed not_after and actual target
host/device/network/person pins. Reconstruct its private code only from retained
ordinary request frames/secret, without export or IO. Preparation may use the
ordinary owned-key resolver; it invokes no signer or external file/agent probe.
It atomically creates/reuses that exact UNAPPROVED owner intent and writes one
unsigned machine_owner_review receipt. No fresh requester key, signature,
publication, membership, access, event or protocol-stage advancement. Existing
ordinary unapproved intents may be reused only when every reviewed term matches;
never replace their templates, provider, creation time or proposed deadline.

### Immutable review and record

Review is exactly `{version:1,kind:"approve_existing_person_machine",consent_id,
host_id,context,agent,request_id,request_packet_id,inspection_review_id,inspection,
intent_id,proposed_owner_offer_id,replaces_consent_id,created_at,expires_at,
request_stage_deadline,effects}`.
Inspection is the complete frozen section41 review (not its wrapper); agent
exactly matches inspection.agent; context/host/request pins match throughout.
Proposed owner_offer ID derives from the actual ordinary first owner template,
not caller text. Intent ID is the actual owner intent. Replaces is dash or the
exact earlier receipt. Created_at is the actual first receipt preparation time.
Expires_at is the earliest of ordinary owner intent.created_at+300s, signed
request expiry, request_stage_deadline and proposed powers not_after. The
request_stage_deadline is a frozen canonical timestamp: stage_at at first
preparation, else signed request creation, plus600s. Retain this original
deadline through later ordinary stage changes. Expires_at must be strictly after created_at;
replays never refresh either timestamp or ordinary honest-signing window.

Effects are exactly:
`{approve_owner_intent:true,authorize_owner_offer_signature:true,
publish_owner_offer_after_signatures:true,authorize_owner_finalization:true,
authorize_binding_and_device_signatures:true,
authorize_host_admission_if_folded:BOOLEAN,grant_membership_now:false,
grant_machine_powers_now:false,grant_agent_access:false,
authorize_requester_selection:false,commit_request:false,share_files:false,
share_conversation:false,capability_calls:false}`. Fold boolean is true exactly
when frozen inspection.host_admission is owner_may_fold. The later ordinary
owner finalization is bounded by the same exact request/owner offer/provider,
scopes7, deadline and current verified authority. Administrator8 is not granted
to the new machine. Requester selection and final commit remain independent.

Review ID is review_+SHA256 of UTF8 `peerspan-machine-owner-consent-v1\n` plus
recursively sorted compact canonical JSON of the entire review. Metadata uses
existing strict Record with kind machine_owner_review, secret none, completed
true, templates/signatures empty, terminal/result dash and canonical review
in review_base64. Operation_id is mrev_+SHA256 of UTF8
`peerspan-machine-owner-review-key-v1\n` plus canonical JSON
`{host_id,request_id}`. Remaining immutable provider/root/person/target/scopes/
not_after fields copy the actual ordinary owner intent at preparation; root is
bound to the immutable first offer even if the ordinary finalization root later
advances. Actual folded slots must use the selected person/device, never root
fallback. Created/expires are the
receipt's reviewed times. This is nonsigning local attribution, never authority.
Validate exact closed review/bindings/record and first ordinary template on
load; corruption refuses without repair/fallback. Receipt quota256 and16MiB
aggregate serialized record bytes; total ordinary4096-intent quota also applies.
Schema/user_version remain27. Generic workers never sign metadata receipts.

### Approval, replacement and recovery

Before approval require exact latest receipt ID/digest and exact recorded
context. Recheck attached current parent/agent, complete frozen inspection,
current selected provider/ordinary owner terms, unsigned unapproved ordinary
intent and fixed windows in the same transaction. Set receipt and ordinary
approved flags/approved_at to the same guarded decision time and save the clock
atomically. An ABORT leaves both approvals, pending state and clock unchanged;
no signatures are produced inside this transaction. No extra host/peer/model IO.
Ordinary background work may sign/publish immediately after commit under this
explicit approval, including folded host admission and bounded B/D/F work after
requester selection. This API does not call resume/sign/publication. Never say
that approval guarantees delivery or that later authorized work cannot run.

Recorded approval state is approved only when BOTH exact receipt and ordinary
approval agree at the same approved_at. Another interface's ordinary approval
alone invalidates this unapproved receipt; never attribute it to this project.
Approved is immutable historical consent, not current powers, cancellation,
admission, access or readiness. Exact approved replay is a pure read even after
cancellation/expiry/provider change/project detachment; no clock/sign/revalidation
work is dispatched. It still requires exact recorded IDs/digest/context and
valid retained ordinary evidence, and never approves a different current review.

For unapproved receipts state precedence is cancelled when ordinary request or
intent is cancelled, expired at fixed expiry/request expiry, otherwise
invalidated for replacement, context/authority/terms changes or outside approval,
else review. Next action is approve_machine_owner_intent for review,
follow_machine_link for approved, inspect_machine_link otherwise. Missing receipt
is null, not approval. Inspection is null when current eligibility cannot be
verified; lookup never guesses or advances it. Historical exact consent may be
read with its old context after that parent is detached; a different context may
read latest old terms only when it is itself a current attached project. Its
wrapper must not imply the old review belongs to that new context.

Identical prepare (same recorded context/inspection digest) returns the exact
receipt without mutation, even after it is terminal. Explicit replacement must
name the latest unapproved receipt, and is allowed only after it became expired/
invalidated/cancelled AND the ordinary request/intent is still live, unsigned,
unapproved with the same immutable terms. A fresh attached parent can then
re-review using lookup's new current inspection. Replacement creates a new
receipt only, retaining the old one and ordinary intent; its fixed ordinary
signing window never restarts. Exact replacement retry with the same predecessor
and terms returns the same latest receipt. Stale IDs, live-review replacement,
approved receipt replacement, silent current-provider/terms switches, old review
approval and cancellation/revocation as a side effect all refuse. Ordinary
intent/request expiry still requires ordinary recovery/new explicit attempt.

### Verification

Separate contract-only author adds compact machine_owner_consent slim suite,
six real-host cases from sections5/12/41/42 and public ordinary DEC contracts,
using independent fixture source only. No product/Rust/hooks reads/imports or
author runtime/process/host/network/model execution. Commit cases before root
runs them. All prior31 suites/helpers/native393 remain byte-identical. Under2min
suite target; preserve original actions, counters and bounds. Genuine signed
requests/automatic return/current P/H/B/D, selected unavailable original and
owned device fixtures; no authority/pending/clock/queue row fabrication.
Only schema-only ABORT triggers may inject atomic-write failure, removed exactly.

1. Pure initial lookup and exact inspected prepare: closed wrapper/whole review,
   independent digest/proposed packet ID/current pins, fixed finite7/expiry;
   one ordinary owner intent plus one unsigned receipt, no signing/publication.
2. Lookup/exact prepare replay/unsuccessful mutations are whole DB/private-file/
   TCP+UDP pure after genuine transport settling. Fixed terms/times and no
   caller/frontend approval attribution; no original key on requester.
3. Exact approval flags/time/guard atomicity and schema-only ABORT rollback,
   with retry only after removal of the injected fault. Selected unavailable
   original remains reviewable/approvable without fallback; owned device may
   perform ordinary approved work, without implicit requester selection/commit.
4. Wrong inspection/context/person/provider/review/receipt/stale replacement,
   actual expiry/cancel/parent changes and explicit current-parent replacement;
   immutable original ordinary intent, exact replacement replay, old refusal.
5. Exact approved history and private stdin/API equivalence across restart,
   detachment, cancellation and expiry with settled real owner work; replacing
   approved or laundering outside ordinary approval into project consent refuses.
6. Strict recursive JSON/64KiB/argv redaction/missing socket/no startup and all
   three owner-router isolation boundaries. Retain source-only crypto/complex
   authority/5s-stalled-client limits where no bounded genuine fixture exists.

Root serializes actual runtime/build/host gates with task lock; distinguish an
external noncompiling cargo-test wrapper from actual compilers and record all
samples. Use regular-disk task TMPDIR/logs and hashed fresh binaries. Run Rust
fmt/test/Clippy/build, new suite and unchanged machine_owner locally; native393
is unchanged and runs in final CI. Preserve first outcomes/hashes, no unchanged
retry-to-green, weaker old assertions/bounds or quota-refused model probes.
Final exact-head32 host suites+build(33jobs), four PR checks and fresh bot/root
review required; all full-feature/native/installed/model/combined gates remain
open. Leave slice and tracking35 unmerged for owner review.

Selected: unsigned exact project attribution bound to ordinary owner intent,
explicit current-parent replacement preserving protocol terms/time, atomic dual
approval and truthful ordinary background authority. Discarded: reconstructing
consent from a mutable protocol review, attributing advanced approval to a
frontend, key copying, root fallback, template/time replacement, new schema,
implicit requester consent and overall readiness claims. Recommended under
GU-OWN1; no new choice is attributed to the owner.

### GU.impl42a: retain the first consent failures before diagnosis

First draft CI atfec1a09 (run41237964718, job124645992068) passes4/6 in27s.
Case1 observes pending evidence changed beyond roles/owner_intent_id but has not
classified the fields. Case4 observes an unexpected controlled refusal code but
has not retained the actual code/phase. Preserve the original log SHA256
3024b647301d32aa35ecf8395af47e7655a79db8960155e4742eb0a557cf0a09.
A separate contract-only author may add failure-only diagnostics from those
already captured values: case1 prints changed pending field names and the secret
unchanged boolean; the existing API wrapper prints operation, public HTTP/code
and expected public code when its code assertion fails. No raw values, paths,
keys, messages or IDs, no extra IO/actions/retries, no changed assertions/setup/
counters/deadlines/allowed fields. Run this diagnostic version once against the
same product tree before attributing either failure or changing behavior.

### GU.impl42b: classify independent maintenance without weakening purity

First root diagnostic run890bd74 passes2/6in21s on the unchanged b5567ac4
product tree. Case1 captures only catalog_base64, owner_intent_id and roles
changed; pairing secret is unchanged. Catalog retention is ordinary public
proof material, but this guided preparation must preserve the incoming pending
catalog through its unsigned phase. Use the same ordinary template preparation;
retain the current verified owner catalog during approved ordinary completion
of the first owner offer, before its proof/packet frames are queued. Never
omit the required proof publication, change advanced preparation behavior,
or refresh an ordinary template/provider/window. Shared approved owner workers
retain their currently revalidated public catalog at first offer completion. This is a product correction,
not a broader pending-field allowance in the test.

The same run case2 observes TCP counter changes on both counted paths with DB/
files unchanged. Case4's reuse fixture is then incomplete; its refusal cause is
unestablished. Case5 separately observes DB/files change during lookup CLI, with
all carrier counters unchanged. Causes of these maintenance/purity observations
are unclassified. Keep log SHA256
df90279b59f3f1b8f16c97c82eb29df1ff0bfba83423cd0e0d222ba5dc0ad3cb.
The separate author may extend ONLY failure metadata in strict() from already
captured snapshots/counters: closed table names or schema/version category per
side, state/home file-category booleans and changed counter component positions.
No raw DB values, paths/IDs, hashes of private values, new probes/actions/retries,
or altered pure/setup/assertion/bounds/allowed writes. A later genuine protocol
barrier, if needed, requires its own contract and evidence before fixture changes.

### GU.impl42c: classify the code mismatch and separate compile capacity

Diagnostic CI890bd74 (run41238437617, job124647347230) independently captures
catalog-only excess pending change and approve409 machine_owner_consent_unavailable
where review_changed is required after a provider change;4/6in29s, log SHA256
c72163deed2c4cefe2ec86eead3747045adea8fe2665d47f99b7129d489b426d.
Map a current ordinary/provider mismatch to changed review; corrupt retained
receipt evidence still refuses as unavailable. First root purity causes remain
unclassified; a successful CI read does not classify them.

Other-track actual compilers repeatedly occupy this shared host. Keep all our
gates serialized by the task lock. For Rust language checks/build ONLY, allow
explicitly recorded other-track cargo/rustc when its cwd/output target is
separate from this worktree and /dev/shm/peerspan-gu-target. Record before/during/
after PIDs and the overlap limitation; final isolated CI must independently
verify the resulting head. Host/conformance timing and purity gates still block
all actual compilers. Discard killing another track, target-cache sharing,
claiming global idle, weakening suite bounds or indefinitely serializing
unrelated compilation. This changes scheduling, not test assertions or gates.

### GU.impl42d: automatic owner work requires actual approval

Corrected CI89a7531 (run41238950061, job124648967716) passes5/6in31s: catalog
preservation and code mismatch pass. Case4 captures a new requester TCP
connection with no TLS bytes, UDP, DB/file/schema/version change during a pure
unapproved prepare replay. Preserve log SHA256
62e77ae8d3860ed925045066f22ec01dce6991128a9fb3ad912e940a148f26d6.
Source review identifies the ordinary background worker's approver condition
checks owner_intent_id presence without checking approval, despite its documented
approved-work boundary. Require a validated approved ordinary owner intent before
automatic owner-side poll/resume/publication. Requester-side polling under its
independent existing request publication remains unchanged. Neither an unsigned
receipt nor prepared owner intent authorizes owner transport work. This fixes a
product consent boundary; do not add a waiting/hold workaround or relax counters.
Earlier standalone DB/file purity and requester-completion UDP causes remain
unclassified; this source defect does not establish their causes.

### GU.impl42e: retain the remaining standalone history observation

First compiler-idle local owner-guard suite e9f7319 passes5/6in29s. The first
four cases now pass; case5 lookup CLI changes one unrecognized existing-side
logical table with no files/schema/version/database-set or carrier change.
Keep log SHA256 c580a002a68649f0a58adec0d3a782a7defa4cc20af317333d8c76ccae025e9a.
The first owner-guard CI independently passes6/6in33s; that does not classify the
local changed table. Before a further run, the separate author may expand ONLY
the captured observer's static table-name allowlist across the public host and
embedded-mailbox schemas. Safe literal additions: identity sqlite_sequence grants
received_messages outbound_messages deliveries received_replies outbound_replies
adapter_routes network_statements access_blocks received_tasks task_events
outbound_tasks outbound_task_events task_deliveries task_update_notifications
artifact_files task_artifacts task_children policy_deliveries adapter_outbound
directory_sends tool_servers tool_values capabilities source_access received_calls
outbound_calls adapter_calls call_update_notifications link_device_keys link_pending
link_frames link_operations link_objects link_features link_signers link_highwater
call_approvals approval_notices builtin_sources oauth_clients oauth_credentials
onboarding_project_flows onboarding_adapter_flows onboarding_invitation_flows
onboarding_join_flows helper_format mailboxes frames. Continue mapping any other
name to unknown; never print raw values/labels/paths/IDs. No assertion/setup/
operation/purity-counter/bound change. Run once to classify this remaining
observation; a passing sample leaves the prior cause unclassified.

## 43. Bounded existing-computer owner-offer signing

GU.impl43 follows merged94. Add an explicit bounded private signing continuation
for section42's exact dual-approved existing-person machine owner intent. Reuse
ordinary typed owner/host-lease slots, configured daemon signer and owned device
resolver; no new approval, schema, signature format or attribution journal. Native
controls and requester selection/completion remain later work.

### Private commands, input and safe public result

Owner-local POST `/v1/onboarding/machine-owner-consent/{signing,sign}` and
`onboarding machine {signing,sign} --stdin` accept exactly
`{context,request_id,consent_id,consent_review_id}`; sign additionally requires
`decision:"sign_machine_owner_offer"`. Section42 canonical IDs/context, recursive
JSON duplicate/null/unknown/type checks and65536-byte bound apply. No caller code,
provider/key/file/socket selector, scope/deadline, template/message or signature.
No startup/state/key creation; argv diagnostics are fixed/redacted. Signing
lookup HTTP/CLI timeout5s; sign has one90s total host budget and95s CLI transport
bound, no retry/poll loop. Success HTTP200. Missing request/specified receipt404;
invalid400 invalid; changed context/review/provider/ordinary terms409 review_changed;
elapsed fixed consent expiry409 review_expired; other unsupported/corrupt signer/
slot/evidence failures409 machine_owner_signing_unavailable. Fixed generic errors
never expose underlying diagnostics. Routes stay absent on adapter/peer/bootstrap.

Response is exactly section42's seven-field wrapper plus `signing`. Section42
lookup/prepare/approve and section41 inspection behavior/shapes stay unchanged.
Signing is null unless that exact receipt and ordinary owner are both approved
at the same time. Otherwise it is exactly:
`{state,intent_id,proposed_owner_offer_id,signature_count,required_signatures,
can_sign,next_action,owner_offer_publication:"not_verified",
host_admission:"not_verified",machine_powers:"not_verified",
requester_selection:"not_verified",request_commit:"not_verified",
agent_access:"not_verified",connection_readiness:"not_verified"}`.
State unsigned when count0, partial when0<count<required, signed when equal.
Count refers ONLY to actual valid signatures of the immutable initial owner
packet (host+authority) and its folded host-lease issuer when present: required2
or3. Later B/D/F signatures do not count. Require the complete first packet's
ordinary pending owner_packet/owner_offer references match its actual typed
assembled bytes/semantic ID whenever its two slots are full. Corruption refuses;
no marker based on an approval flag or packet ID alone. Metadata, templates,
review/hash, ordinary approval time and original deadlines stay exact.

Both routes require the exact recorded receipt context/digest/request/IDs. An
exact old context may read history after detachment; a different project's
context does not adopt this signing operation. can_sign is true only for an
incomplete dual-approved latest receipt with current public eligibility below.
It is NOT a key-availability probe. Next action is sign_machine_owner_offer when
can_sign, follow_machine_link when signed, inspect_machine_link otherwise. A
signed marker is retained historical signature evidence, not frontend attribution,
publication, admission, current powers/readiness or completion of the link.
Public result <=2MiB and section42 label/privacy rules; no raw templates,
messages/signatures, seeds, configured paths, agent identities/comments or codes.

### Pure observation, completed replay and fresh eligibility

Signing lookup holds one read snapshot, verifies retained receipt/ordinary
references and typed signatures, and computes public eligibility without clock
save, signer/availability probe, key resolution, cleanup, network, fetch/resume,
event, signature creation or persistence. Existing section42 inspection may be
null on approved records; retain that wrapper behavior. Exact sign replay of a
fully signed initial packet/fold is the same pure historical read, even after
provider/project changes, cancellation, later stages, request expiry or restart.
Do not dispatch live authority/key checks or later work for that complete replay.

Fresh work requires latest exact dual approval; pending approver/new/nonmigration
request, actual different target host, current attached exact parent and agent;
current signed request pins, selected original/device and complete original
inspection root/P/H/B/D/member/restrictions/conflicts/migration/finite7 terms.
Recompute the full section41 inspection in a narrow signing-only mode that may
accept this approved intent, partial initial signatures and the exact recorded
first owner packet. All selection/administrator/F/commit/result references and
requester selection/commit approvals remain absent. Never broaden section41 or
section42 eligibility. Compare complete current inspection digest to the frozen
receipt. Ordinary provider and first template/fold must match; root fallback,
foreign original/device, possession-only offers or silent provider switches refuse.

Fresh explicit signing is bounded by the ORIGINAL section42 expires_at and its
frozen request_stage_deadline, signed request deadline and powers not_after; no
refresh after approval. This conservative explicit action does not redefine
ordinary already-approved background work. Recheck guarded current time at every
phase and immediately before commit. A partial original packet may be complete
while its reviewed folded issuer remains missing: only that initial missing slot
may still be signed, before the same deadlines and before any later-stage packet.
No B/D/F, administrator, selection, commit or arbitrary signature in this action.

### Typed finite plan, exact configured key and atomic storage

Derive a stable finite plan from the actual immutable ordinary first template
and optional folded host_lease only. At most3 distinct typed roles: first packet
slot1 host Ed25519 with this host's key, slot1 authority with the reviewed
original SSHSIG or owned device Ed25519 key, plus the folded host-lease issuer
with that same reviewed original/device. Check all role/key/format/message/
object-ID/descriptor/network/context/request/person/target/scopes7/deadline and
fold parent pins using the ordinary typed validators. Verify every produced
signature locally with those types. No signer receives caller-selected bytes.
Never substitute another original, root or device, or use a requester device key.

Resolve only the exact reviewed owned device seed or the daemon's configured
original source. Reuse section32's configured original behavior: exact identity
from configured agent (even among multiple identities), else configured file;
no environment/global-agent discovery, generated-key discovery fallback,
key import/copy/generation or subprocess signer. File no-follow/nonblocking
leaf, owner-owned regular file, permissions&077==0, <=16384 bytes, bounded read
and existing OpenSSH parser, exact approved public key. Existing explicitly
configured ancestor semantics are unchanged. Missing/malformed/wrong/unsafe file
or absent exact agent identity refuses. No signer IO in a DB transaction.

Each phase holds its own coherent transaction/clock/authority snapshot. Drop it
before original identity lookup/key use and before producing any slot outside
SQLite. Revalidate exact receipt, current parent/authority, deadline and immutable
whole plan after identity lookup, immediately before key use and again before
storage. Other approved work may fill some planned roles in between: a fresh
plan signs only still-missing roles; before commit existing valid filled roles
may be retained, but no changed target/message/role/terms are accepted. No
automatic key-use retry. Whole action budget guards every dispatch/commit;
source timeouts/outer timeout cannot retract an already-dispatched key operation.
Do not claim key use, cancellation or an unknown HTTP response is transactional.

Atomically store the new verified initial signature batch in the existing
ordinary intent, and its complete owner_packet/owner_offer references when
complete; retain the current revalidated public owner catalog there before
later ordinary proof/offer frame publication. Save the guarded clock in the
same transaction. Metadata receipt and ordinary templates/created_at/approval/
not_after remain unchanged. No partial batch on SQL ABORT, no new table/journal,
event, frame/outbox/publication, peer/helper IO or explicit resume/F driver in
this API. Ordinary approved background work MAY publish the offer/fold and later
perform its authorized B/D/F work immediately after commit, independently. Keep
separate requester selection/commit and agent access. A returned signed marker
only proves the exact initial typed signature set is durably valid/recorded.

### Verification

A separate contract-only author adds six compact machine_owner_signing cases,
from public sections32/41/42/43 and independent fixture source only. No product/
Rust/hooks reads/imports or author runtime/process/host/network/model execution.
Copy independent fixture source without eager suite imports; no old suite/helper
changes. Commit cases before root runs them. Genuine signed automatic returns,
current P/H/B/D and schema27; only schema-only atomic ABORT fault permitted.
Target <2min, original comparisons/bounds/counters preserved. A genuine consumed
TLS ClientHello hold outside DB may isolate already-approved worker IO; confirm
its generation before/after the observed action, do not invent a worker-pause
flag, fabricate authority or attribute background work to this route. Establish
that hold before making the configured exact original file/agent available on
the existing computer when the automatic signer could otherwise win. No original
key is installed on the requester. Schema-only triggers on each affected
dec_intents/dec_pending/dec_clock table may ABORT only when all genuine intended
writes are visible, independent of write order; a genuine in-window fixture clock
advance may make the clock write observable before that fault is installed.

1. Null/unapproved signing and fresh sign refusal are DB/state/home +bothTCP/UDP
   pure, no key/agent contact or approval attribution; strict closed wrapper,
   inspection/consent domains and actual ordinary intent/template IDs.
2. Exact dual-approved original using a configured safe file: real typed first
   authority/host/fold signatures, unchanged immutable review/approvals/window,
   no key writes, no route network/events/frames and independent requester
   consent. Validate counts/types and actual SSHSIG/Ed25519 messages/signatures.
3. Exact configured SSH-agent identity among multiple identities; absent/wrong/
   unsafe file and agent/key failures refuse without fallback or secret output.
   Public parent/provider/review/deadline changes before/after delayed identity/
   key dispatch refuse new persistence. No raw private material in diagnostics.
4. Actual GUIDED receipt approval with owned device15 (not advanced approval),
   then explicit sign while an actual worker TLS request is held outside DB.
   Verify exact first+fold Ed25519 set and retained owner catalog. Release the
   hold and observe actual ordinary proof+owner frame retention/publication
   using the same intent/packet/provider. Before release, the explicit signing
   action changes no requester selection/commit; after ordinary requester work
   is released, unchanged spec8.4 may automatically select one valid offer, but
   never supplies commit consent. See the first-run clarification below.
   This closes section42's guided-only device proof-retention coverage gap.
5. Late schema-only ABORT after actual signature/pending/clock writes rolls back
   the whole new batch/pins/catalog/clock. Exact signed API/CLI replay is whole
   DB/files/carriers pure after cancellation/provider/parent changes, restart,
   actual expiry and later stages where a bounded genuine fixture permits;
   otherwise retain explicit source-only limits. Lost-response recovery may
   use an owner-local HTTP proxy over authentic responses, never invented grants.
6. Strict recursive JSON64KiB/decision/IDs/unknown/null/type/private argv/socket
   no-startup boundaries; owner-only method/router isolation. Controlled proxy
   faults over authentic captured ordinary/public views may test changed typed
   fields without altering stored authority. Retain bounded-case limits for
   complex authority, corrupt/quota, exact90s timeout, syscall attribution and
   narrow key-dispatch/commit races; do not infer them from snapshots.

### GU.impl43a: first-run fixture and attribution clarification

Keep first root source e435f16 (SHA256
e4e305001200a3c049a164ff548b5af3ade050925f2a23fcaf752d040afbccf2):4/6
in69s at bcc58b2, log SHA256
2370ca77419ae09c03d3ec90c951f79c4205015e5e2e871682c56dc81db4ec20.
The device action independently verified its complete3-slot set and owner
publication, and both hosts actually retained request/owner/proofs frames, but
the requester had not retained the parsed owner/catalog. Captured genuine
invitation member was `Existing person next computer`, while the signed owner
offered the current person's `Existing "é" owner`; the existing invitation pin
requires equality. Use that exact current verified person member in a genuine
positive invitation before request creation. Do not relax invitation/offer
validation or change any signed retained bytes. This is a fixture prerequisite,
not evidence that all remaining recipient validation succeeds.

Unchanged decentralized spec8.4/DEC-S5/DEC-Q5 permits the ordinary requester to
select its single valid matching offer automatically. Section43 forbids this
signing action from performing that work, not separately authorized requester
work after release. Preserve the strict before/after remote snapshot and no
selection/F/commit assertion while the real transport hold is active. After
release, verify actual same owner/proofs retention/publication; permit the
existing automatic selection, require no requester commit and make no readiness
claim. Discard changing ordinary selection policy or disguising automatic
selection as consent granted by this signing route.

The history case's pure-signing snapshot changed only embedded helper `frames`
and `mailboxes`, with no host DB/schema/files or TCP/UDP change. Captured later
state has expired mailboxes with zero ciphertext. This is consistent with
independent helper expiry collection, but the original crossing is not yet
causally classified. Before history assertions after a genuine fixture-clock
advance, establish bounded actual retirement of expired helper ciphertext from
read-only public-schema snapshots. No row edits, sleeps in place of evidence,
carrier disabling, table exclusions or relaxed whole-state comparisons. Tag
fresh-expiry versus retained-history phases distinctly and use captured-only
closed mailbox-state/frame-count summaries if another failure occurs. Preserve
the first observation even if the corrected prerequisite passes. No unchanged
retry-to-green. A separate author amends only the new suite from this contract;
all prior files remain exact.

Public test-observation schema reference for that prerequisite: embedded helper
format1 has `mailboxes` columns in order
`locator,request_id,read_cap_hash,created_at,expires_at,expires_unix,creator_key,
source_bucket,account_id,creation_identity_hash,state,ciphertext_bytes` and
`frames` columns `locator,frame_id,role,writer_key,body,ciphertext_bytes`.
`expires_unix` is whole UTC seconds, state is active/deleted/expired, and frames
reference their mailbox locator. Collection erases expired ciphertext and marks
the mailbox expired; deleted/expired tombstones may later disappear. A live
host's retirement prerequisite may read PRAGMA/table metadata and SELECT these
fixed fields in one read snapshot, waiting within a fixed bounded interval
until mailboxes with expires_unix<=that fixture's current clock are nonactive,
have zero ciphertext_bytes and no corresponding frames (or have been fully
collected). Do not require an already deleted mailbox to become expired. Do not
start a stopped requester merely for collection: its unchanged state remains
part of every whole-state comparison. Diagnostics use only captured state
categories/counts, not locators, capabilities, rows or ciphertext. This documents
observation of existing helper format1, not a schema/API change or a route action.

### GU.impl43b: preserve final-head requester refusal traffic evidence

First final3e026ab CI41246210795 passes32/33 suites+build (33/34 jobs),
including signing6/6in57s and unchanged consent6/6in33s. Four checks on
41246210747/native393in71.63s and fresh bot/root review pass. Unchanged
requester_completion case6 instead fails5/6in86s at its wrong-review pure
Complete refusal: issuer UDP receive+2 packets/+2400 bytes, zero returns, with
whole requester DB/state/home unchanged. Log SHA256
b6400c81ae96aa1996604621220893f45001f7d64733995b432a752ff049ac31.
The refusal's generic helper does not carry expired/detached/restarted phase
or the existing failure-only directory observation. Cause remains unclassified;
neither the pure refusal nor any background subsystem is identified as caller.

Permit one exception to the prior-file byte-preservation rule: a separate
contract-only author may add ONLY failure diagnostics to requester_completion.
Give Complete's generic pure helper an optional diagnostic phase defaulting to
unknown; tag the existing case6 wrong-review call with its existing loop phase.
Wrap the original captured carrier tuple at that helper's original equality
assertion, returning the same tuple. Preserve its assertion, original captures,
f-string evaluation, all calls/actions/clock/delays/bounds/counters and case
bodies otherwise. Only upon that original mismatch, report fixed operation
wrong_review/unknown, expired/detached/restarted/unknown phase, API/unknown mode,
known participant/carrier kind and nonnegative count/byte deltas. Reuse existing
GU.impl40a's one pure2s owner-local directory GET and its exact closed public
metadata limits when a known network is available. No refresh/resume/probe,
retry, extra wait or authority/queue/worker/path change; no identifiers, times,
addresses, paths, raw rows/packets/error text or private material. Diagnostic
failure cannot change the original captured verdict. No guessed transport fix.

Commit before one retained root serialized local diagnostic run on unchanged
105e8c54 Rust binaries. Removing the new helper/wrapper/optional parameter and
explicit phase keyword must restore every original requester source byte/AST.
All other84 prior conformance/native files and393 native cases remain exact;
the new signing source stays0cd90eeb. Preserve every earlier failure and any
over-target local duration. A silent passing diagnostic run would not classify
this CI failure. Final exact-head full34-job/four-check/fresh bot/root review
remains required; no unchanged CI retry or exclusion of an old failing suite.

The independent observer8ef1b77 / rootd3a50cb (source SHA256
894299c472b2374cc32c6afd237b56d5c3d230f6f3c8be8756284a924bb166a5)
passes its single local diagnostic6/6in143s (runner144.66s), log SHA256
569a037ebc8bd3b3ab48a1a88ebc60af092683ed238a7362a5da09e417a6e66f.
It emits no failure metadata, so the original CI phase/caller remains unknown;
this passing sample is no transport fix. Keep the over2min target duration and
the initial runner-label no-start (no suite launched). Root verified exact
restoration to cb852ae2fe033079c63fb31d7abcd68b71507de116f4ac76684f9bbb996e5524
and full AST SHA256dbae7adf1609a9c64b45f16cbc70702092b4d1a4f65a1e220a15c86820f3830f.
Rust105e8c54, signing source0cd90eeb, all other84 prior files and native393 stay
exact. The next final combined head still needs every CI/review gate.

Root serializes its language/runtime gates, logs/hashes fresh binaries and every
first result. Reuse section42's explicit separate-target compilation scheduling
for language gates only; host suites require compiler idle, regular-disk TMPDIR.
Run Rust fmt/test/Clippy/build, this suite and unchanged machine_owner_consent
locally; all33 host suites+build(34 jobs) and four checks/native393/fresh bot/root
review on one final head. Preserve all prior suites/helpers/native393 byteexact.
Keep first unknown history-table/requester UDP limits and no-starts; no unchanged
retry-to-green or quota-refused model probes. Native/installed/terminal/reload/
physical/model/schema-upgrade/full-state/final combined acceptance remain open.
Leave slice and tracking35 unmerged for owner review.

Selected: private server-side bounded initial owner/fold signing under the exact
existing project receipt, shared typed protocol/configured signer and atomic
ordinary storage, truthful historical marker and current public eligibility.
Discarded: client access to device seeds, new approval/journal, arbitrary signer
inputs, broader resume/F/commit automation, proofless completion, indefinite
polling, unbounded fallback or historical signature evidence as current readiness.
Recommended under GU-OWN1; no new choice attributed to the owner.

## 44. Native existing-computer machine-owner review and initial signing

GU.impl44 follows merged96. Compose sections41–43 in the existing terminal
`/peerspan` pane. No new host/API/schema, model setup tool, private code handling,
key inventory, signer selection or protocol driver. Existing new-computer
section40 and administrator/new-original lanes retain their separate meanings.

### Explicit choice, exact public evidence and consent

After a current project attachment, **Review machine requests** opens a fresh
owner-local `onboarding` inventory. Reuse the complete validated incoming new,
approver, nonmigration, network/context/person-pinned LINK_VIEW inventory and
immutable request pins of section23, sorted by request ID, ten choices per page.
Inventory claims are unverified; choosing a retained request performs only
`onboarding machine lookup --stdin`. No first candidate or provider is selected
by the frontend. Unsupported requests refuse without falling back to another
identity, root, new-original or administrator flow. Empty inventory says so.

All subprocesses use the trusted configured executable/state as literal argv;
IDs/context stay in private JSON stdin. Lookup/prepare/approve/signing have a5s
process bound. Sign has95s. No shell, startup, key/file/agent API, prompt, tool,
network, plugin storage or transcript write. Payloads are exactly section42/43:
lookup `{context,request_id}`, prepare additionally `inspection_review_id`,
approve additionally `consent_id,consent_review_id`, signing the latter exact
shape, sign additionally `decision:"sign_machine_owner_offer"`. Historical lookup
may add retained `consent_id`; no silent latest receipt substitution once one is
retained. No native replacement/cancellation/revocation in this slice; advanced
explicit replacement remains available, then leave/reopen for a fresh review.

Validate <=2MiB JSON, recursively safe public strings/keys, canonical IDs/keys/
whole-second timestamps, exact closed wrappers/reviews/effects, full context/
host/project agent/request pins, original/device provider/lease/format/root,
local P/H/B/D dependencies, finite scopes7/deadline cap/fold relationship, fixed
consent windows and both review domain hashes. Inspection in lookup may be null;
consent retains its own frozen full inspection and digest. A consent from another
recorded context is historical only even when the lookup's current context is
valid. Never relabel another project's approval or a changed review as ours.
Validate section43's exact closed signing fields,2/3 required counts, state/
can_sign/next-action consistency and all seven not_verified fields. Bind its
intent/offer IDs to the exact approved receipt. Signed is retained initial typed
signature evidence only; it need not have live eligibility or unexpired windows.

Choosing a request shows lookup's verified public terms. Display the complete
network/context/root, request/packet/person/target-host/device keys, member,
selected public provider kind/key/lease/scopes/deadline/signature format, local
P/H/B/D lease dependencies, proposed7 (1 policy,2 host binding,4 own-device work;
no administrator8), not_after and owner fold versus separate administrator.
Quote every public label. Explain this does not probe private key availability.
**Review machine consent** appears only after current inspection and null consent;
it prepares the exact inspection digest after a fresh matching lookup. Display
the immutable consent terms including ID/digest/intent/offer/predecessor and
original receipt/stage/request/powers deadlines, plus effects. Full context is
validated privately; never display native conversation IDs or parent project
flow/review/session plumbing. Public project/agent labels stay quoted in the pane
and never enter chat. Preparation grants
nothing. **Approve machine consent** requires the same complete displayed review
and a fresh pure lookup, exact project/host/request and all live windows. Approval
authorizes ordinary owner signing/publication and bounded B/D/F after requester
selection; it does not itself guarantee signatures/delivery/admission/powers.

### Explicit initial signatures and truthful recovery

For an approved receipt in this exact recorded project, obtain pure
`onboarding machine signing --stdin` evidence. **Sign machine owner offer** is
shown only for current can_sign with an incomplete initial2/3-slot signature set
and all original windows live. On press, re-read exact consent and signing,
compare the complete retained review/digest, recheck parent and time, then send
one explicit sign. No automatic signing, mutation retry, polling, progress/fetch/
resume/publication/F/selection/commit/access driver. Ordinary already-approved
background work can progress independently. A now-signed pure status replaces
the action without another sign. **Check machine consent** is explicit pure
lookup/status recovery after any result, error, uncertain timeout or reload.
Every response must match the retained request/receipt and cannot regress its
observation time. Never refresh the original windows from a new observation.

Single-flight guards and exact parent flow/review/full-review, root, conversation,
host and terminal surface checks surround every await/dispatch. A refreshed or
closed pane, parent/session/root/host/surface change, leave, deadline, or stale
callback invalidates in-flight work and actionable evidence. Keep the original
minimum consent/stage/request/powers deadline timer authoritative while busy;
check fresh time immediately before mutation dispatch. Refresh/leave/reopen do
only reads; no durable frontend state. Reads of retained historical approval or
signatures can be displayed after expiry without enabling mutation. Fail closed
on malformed/unsafe/changed evidence; discard stdout/stderr and fixed generic
messages only. A dispatched mutation failure says outcome unknown and offers
explicit pure Check, never retry. A late response cannot restore an invalidated
review. Shared pinned native test kit cannot retain obsolete rendered closures;
those callbacks and microscopic host changes after dispatch remain source/manual
limits, never claimed as runtime coverage.

Show separate facts: consent recorded; exact initial signature count recorded;
publication, host admission, machine powers, requester selection/commit, agent
access and connection readiness not verified. Link completion is later work.
No success/ready badge from approval or signed. No original key copying and no
change to ordinary single-offer requester selection under network spec8.4.

### Verification

An independent contract-only author adds one native `machine-owner.test.ts`
using public native runtime mocks and independently constructed sections41–43
fixtures, without implementation reads/imports or runtime/process execution.
Root alone runs pinned303 actual plugin validation and the complete native
suite, serially; preserve all393 existing cases/files and all existing host
suites/helpers byte-for-byte. Retain every first failure/no-start and fix from
the contract; no weakened assertion or unchanged retry. No backend source
changes: unchanged Rust/host behavior is verified by combined-head CI. New cases:

1. Explicit entry/empty inventory, ten-per-page retained choice, unverified
   inventory cannot itself enable Prepare/Approve/Sign; no eager mutation.
2. Valid original-person and device public inspections, exact quoted keys,
   finite7 and both fold/separate-administrator terms; private signer unavailable
   does not prevent a valid public inspection.
3. Exact prepare stdin/digest, no approval/sign and no private/model/storage work.
4. Complete same-review approval, exact argv/stdin; ordinary progression warning.
5. Pure approved signing/status, exact explicit initial sign,2/3 counts and all
   not_verified disclaimers, already-signed status does not dispatch sign.
6. Historical expired/cancelled/invalidated and other-project receipt stay
   view-only; signed history remains honest and never enables later work.
7. Changed request/context/agent/provider/root/digest/effects/lease/keys/cap/fold/
   consent or signature counts/IDs/unknown fields refuse without mutation.
8. Unsafe/private-prefixed/control/oversize output and subprocess diagnostics
   never appear in UI, chat, tools or writes; fixed generic refusal only.
9. Fixed deadline before action and while held; no late actionable resurrection,
   no restarted stage/powers/receipt windows.
10. Single flight, held responses and root/conversation/host/parent/surface change,
    Refresh/leave/Close/session end clear controls, no automatic mutation retry.
11. Lost prepare/approve/sign responses recover only by explicit pure Check;
    counts/status reflect actual retained host evidence without duplicate sign.
12. Original393 native cases and all old host suites remain unchanged; new suite
    covers only mocked native boundary. Actual terminal/reload, installed/two-
    machine/model receipt, requester completion and #35 combined acceptance
    remain open and cannot be inferred from passing fixtures.

## 45. New-computer verified machine requester commit inspection

GU.impl45 follows merged97. The new computer must review its actual received
existing-person owner finalization without having that person's original key or
a local new-original owner intent. This slice supplies the pure backend review;
exact requester consent, bounded completion and native controls follow. It does
not broaden sections16/24/27/28's new-original assumptions or spec8.4 selection.

### Private request and strict eligibility

Owner-local POST `/v1/onboarding/join-flows/{id}/machine-commit/inspect` accepts
exactly `{context,join_review_id}`. Context is section5's five-field attached
project context; flow IDs are flow_32hex, review IDs review_64hex. Advanced
`peerspan onboarding join machine-commit inspect --stdin` accepts exactly those
fields plus `flow_id`. Recursive duplicate/unknown/missing/null/type/canonical
ID/context checks,65536-byte input cap, configured owner socket and fixed redacted
CLI/argument failures. IDs/private payloads remain in stdin, never argv. Both API
and CLI have5s bounds. No daemon startup, scoped adapter/peer/bootstrap route or
model tool. Missing flow404 not_found; malformed400 invalid; changed exact
context/join review or detached/replaced current parent409 review_changed;
missing ordinary request409 request_unavailable; elapsed windows409 review_expired;
other unsupported/corrupt/missing authority409 machine_requester_inspection_unavailable.

One held read transaction binds the exact retained requested section12 join flow,
its immutable invitation/network/context/person outcome and attached project agent
to the actual ordinary request. Require the signed invitation's explicit person
pin equal to that person, requester/new/nonmigration role, all signed request
network/context/person pins exact, and this host's actual target key/device.
The network must not already exist locally. No local owner intent or original
possession offer qualifies. Require exact selected owner and signed requester
selection, selection_approved true, received owner finalization and actual
needs_commit state. Completed stages are request_created/owner_offered/
owner_selected/owner_finalized, with administrator_offered between selection and
finalization iff a separate administrator packet exists. Do not fabricate that
stage or require it when the owner legitimately folded host admission.

No commit approval/intent/template/signature/packet, manifest, activation or
outcome may exist, including an unreferenced ordinary requester_commit intent.
This first inspection does not adopt or repair advanced work. Current time must
be at/after signed request creation and current stage_at and strictly before
request expiry, stage_at+600s (creation+600s if absent) and proposed powers expiry.
Use the existing guarded clock read without saving it; recheck the exact current
attached parent at the verified effective observation time.

Read retained signed packets/catalog only. Reuse ordinary exact offer/selection/
optional administrator/finalization and Projection::prepare_finalization checks:
actual descriptor/genesis/context/root, signature/parent/object IDs, proof
completeness, P/H/B/D paths, restrictions/maxima/conflicts/migration and finite
bounds. Selected offer must name an admitted existing person with a non-dash
owner root/person lease, remote original_person or device provider, and a writer
host different from this requester. No possession-only/new-original, network_root,
first-candidate/default provider, local-original or private-signer fallback.
This is evidence retained locally, never a claim that unseen remote revocations
are known. Existing original/device authority remains valid only as the ordinary
verified projection permits.

Require signed owner scopes7, proposed binding scope2 and new device scope7 for
the exact person/host/device. Administrator8 is excluded for the new machine.
Powers not_after is the owner's actual signed finite deadline, no later than
signed request creation+7days or verified provider's effective deadline. Validate
the actual proposed binding/device IDs and parents against finalization; a
legitimate already existing binding may be reused only as ordinary verification
permits, with that distinction returned. Current F/root/person/host dependencies
are actual verified IDs, never caller strings or reconstructed authority.

### Closed public result and purity

Return exactly `{version:1,host_id,context,flow_id,join_review_id,observed_at,
request,review_id,review,next_action:"review_machine_requester_consent"}`.
Request is the complete ordinary public LINK_VIEW at that same effective time.
Review is exactly:

- `version:1,kind:"inspect_existing_person_requester_commit",host_id,context,
  agent,flow_id,join_review_id,request_id`;
- `network:{id,name,context_id,genesis_root_public_key}`, current person `member`,
  exact `person_public_key,host_public_key,device_public_key`;
- `request_packet_id,owner_offer_id,selection_id,administrator_offer_id,
  owner_finalization_id`; administrator ID dash iff folded;
- `owner_root_state_id` from the verified owner packet, `root_state_id` from
  actual verified finalization, `person_lease_id,host_lease_id,binding_lease_id,
  device_lease_id` from its verified P/H/B/D components;
- `owner_provider`, the ordinary complete closed public authority object
  `{kind,person_public_key,host_public_key,device_public_key,lease_id,
  root_state_id,scopes,not_after}`. This is the remote signer's verified public
  path, not the requester's device and not private signer availability;
- `host_admission:"folded_owner"|"separate_administrator"`, `reused_binding:bool`,
  `scopes:7,binding_scopes:2,not_after`, signed request `created_at,expires_at`,
  fixed current `request_stage_deadline`;
- `effects:{verify_existing_owner:true,verify_requester_selection:true,
  verify_host_admission:true,verify_owner_finalization:true,
  prepare_commit_intent:false,approve_commit_intent:false,
  sign_requester_commit:false,publish_requester_commit:false,
  apply_network:false,grant_membership:false,grant_machine_powers:false,
  grant_agent_access:false,share_files:false,share_conversation:false,
  capability_calls:false}`.

Review ID is review_+SHA256 of UTF8
`peerspan-machine-requester-inspection-v1\n` plus recursively sorted compact
canonical JSON of the entire review. Observation time stays outside it; unchanged
terms keep their digest. A root/provider/packet/project/deadline change refuses
or changes actual public terms; it never repairs an old review. This digest is
not consent, a readiness token or proof of current remote reachability.

At most2MiB safe closed public output. Reject unsafe control/private-prefixed
labels/aggregates; never expose invitations, request codes/secrets, credentials,
seeds, signatures/raw packets/templates/catalog, routes or signer diagnostics.
No original inventory/import/copy/generation, private original/device resolver,
file/SSH-agent availability probe or signer invocation. Ordinary retained-record
and loaded host-identity validation stays intact. No intent/approval/template/
key/clock save, journal/schema, queue/frame/contact/cache/event change, cleanup,
fetch/observe/resume/publication, adoption or network IO. Unrelated already
approved ordinary workers may progress independently; settle genuine carrier
prerequisites before whole-state assertions. Read-only does not disable them.

### Verification

A separate contract-only author adds six compact `machine_requester_inspection`
black-box cases using real distinct temporary hosts, signed pinned invitations,
requester public-key-only publication, guided existing-owner consent and genuine
ordinary owner/device/finalization evidence. Original person key stays only on
the existing computer; no authority/queue/clock row edits, fabricated grants,
worker disabling, eager suite imports or relaxed whole-state/carrier counters.
Source is committed before root executes. Preserve the baseline33 host suites, all helpers and415 native cases (all65 tracked test files) exactly;
this slice adds one suite, making34 suites+build. Cases:

1. Genuine guided device-owner15/folded admission reaches needs_commit. Exact
   API/CLI wrappers, independently computed digest, actual remote authority and
   target keys, P/H/B/D/F references, finite7/2, no fake administrator stage.
   Missing requester original identity/files/agent cannot prevent public review.
2. Genuine original-person remote owner and effective cap when bounded fixture
   permits; provider remains remote. A second identical read preserves digest.
   Whole logical DB/schema/state/home and counted bidirectional TCP+UDP carriers
   stay unchanged on repeated API/CLI inspection after settled ordinary work.
   Document separate-admin/device7/reused-binding gaps if no genuine bounded
   stimulus; do not fabricate evidence or claim unexecuted coverage.
3. Closed nested input corpus, IDs/types/nulls/duplicates/size and fixed CLI
   errors/argv privacy; unknown request/flow, stale context/review/agent and
   restart/detachment refuse without mutation or daemon creation.
4. Genuine wrong role/unpinned/renew/new-original/owner missing/selection missing/
   finalization missing, already existing network or commit work refuse as
   available through real public prerequisites. Do not overwrite protocol rows
   just to construct unavailable states. Source-only exclusions are explicit.
5. Real request/stage/powers expiry/cancellation and current verified authority
   change refuse, preserving whole DB/files and all carriers; no expiry cleanup
   or clock save. Retain the first actual crossing and limits if independent
   workers prevent attribution. No unchanged rerun-to-green.
6. Scoped adapter, peer and bootstrap absence; unsafe public labels/aggregate
   and genuine invalid evidence refuse without raw/private material or repair.
   Isolated malformed/corrupt-record storage stimulus may use the established
   independent corruption idiom only after genuine setup and an explicit snapshot;
   no trusted grant or positive authority is fabricated.

The existing computer may use its exact configured original source and one
explicit ordinary finalize after verified selection under its recorded owner
consent. The requester never receives/loads that key. An isolated stopped-
requester malformed retained catalog negative may restart and freshly attach
BEFORE its unchanged-state snapshot; assert refusal/no repair and never reuse
that corrupt fixture for positive authority. Restart detaches the exact join
parent; a resulting review_changed proves context refusal only, not malformed
catalog validation. The bounded suite may therefore retain corruption as a
source/fault-only limit instead of inventing a public parent restoration. These
are genuine setup/negative stimuli, not permission to fabricate grants or
disable workers.

A genuine existing computer may go fully offline AFTER publishing verified F
and BEFORE pure-read baselines. The requester stays live/held; count both hosts'
complete DB/files and both carrier directions. This proves retained-evidence
inspection with an offline owner, not both-live remote-worker attribution. No
requester/worker flag, queue, grant or clock edit and no mid-snapshot shutdown
is permitted to manufacture purity.

Root owns all execution, serializes compiler/runtime gates, verifies fresh debug
binary hashes and records every first compiler/no-start/local/CI outcome. Run
Rust fmt, existing155pass/2ignored, Clippy/build and this new six-case suite;
use unchanged prior native415 evidence and require final combined-head34-suite+
build/four checks/native415/fresh bot/root review. No unrelated local host/native
retries, old case/wait/default timeout edits or quota-refused model probes.
Requester exact consent/bounded completion/native flow and terminal/reload/
installed/physical/model/schema23→27/full-state/#35 acceptance remain separate.

## 46. Exact existing-person machine requester consent

GU.impl46 follows section45. Select one immutable project-bound unsigned
receipt alongside the ordinary requester_commit intent in dec_intents; no new
schema or journal. The original stays on the existing computer. Bounded
completion and native controls follow separately from this consent backend.

### Private actions and exact public review

Owner-local POST `/v1/onboarding/join-flows/{id}/machine-commit/lookup`,
`/prepare`, `/approve` accept respectively exactly `{context,join_review_id}`,
`{context,join_review_id,inspection_review_id}` and
`{context,join_review_id,consent_review_id}`. Private CLI
`onboarding join machine-commit lookup|prepare|approve --stdin` adds exactly
`flow_id`. Section45's recursive strict JSON, canonical IDs/context,64KiB input,
fixed private diagnostics, configured socket,5s single call and no startup apply.
Keep Inspect's diagnostics. No adapter/peer/bootstrap/native/model surface.
Invalid400 invalid; missing flow404 not_found; changed scope/digest409
review_changed; missing ordinary request409 request_unavailable; elapsed fresh
windows409 review_expired; other missing/incompatible/corrupt work409
machine_requester_consent_unavailable. Timeout/lost response needs explicit
Lookup; it does not prove rollback or authorize an automatic mutation retry.

Bind the exact requested section45 flow/outcome/person pin/host/device/agent.
First Prepare requires the attached exact parent and current inspection digest;
reverify all remote owner/selection/admission/F, finite7/2 and original windows.
Keep folded admission and actual binding reuse; no local original-owner receipt
or key availability. No existing network/terminal/commit artifact or unrelated
advanced requester_commit intent may be adopted by first preparation.

Create one ordinary unsigned unapproved requester_commit intent and one unsigned
`machine_requester_review` metadata record bound uniquely to this request.
Ordinary intent/templates/provider/reference/quota rules stay authoritative.
All successful actions return HTTP200. Metadata operation_id is request_id;
network/context and requester provider/person/host/device/root/scopes/not_after
copy the ordinary intent. Created_at copies its creation; expires_at is the
public consent expiry; review_base64 freezes the full canonical consent review.
Metadata has no templates/signatures/secret, completed=true, terminal dash and
no result; it is not a protocol signing job. Pending commit_intent_id stays dash
until approval. Freeze the complete verified section45 public review.

Return exactly `{version:1,host_id,context,flow_id,join_review_id,observed_at,
request,consent}`. Request is LINK_VIEW; consent null before preparation,
including missing F. Otherwise exactly
`{consent_id,review_id,review,state,next_action}`. Review is exactly:

```
{version:1,kind:"approve_existing_person_requester_commit",consent_id,
 host_id,context,agent,flow_id,join_review_id,request_id,intent_id,
 inspection_review_id,inspection,created_at,expires_at,effects}
```

Inspection is the frozen section45 review with its original false effects and
domain-separated digest. Consent ID is dint_32hex. Created_at is ordinary
intent.created_at; expires_at is the minimum of that+15min, signed request
deadline, frozen stage deadline and powers end. No replay restarts any window.
Review ID is review_+SHA256 of UTF8
`peerspan-machine-requester-consent-v1\n` + canonical(review). Effects exactly:

```
{approve_commit_intent:true,authorize_binding_host_signature:true,
 authorize_requester_commit_signatures:true,authorize_commit_publication:true,
 authorize_local_application:true,grant_agent_access:false,share_files:false,
 share_conversation:false,capability_calls:false}
```

### Atomic approval and read-only history

Lookup never prepares/repairs. Prepare replay with the same inspection digest
returns the existing receipt purely, including history. Changed digest refuses;
no replacement/rebind/refresh or advanced-work adoption. Flow attribution stays
immutable. Approve requires a retained exact consent_review_id, never implicitly
prepares. Revalidate current exact parent/agent, full received authority/frozen
inspection, ordinary intent/templates/selection, actual owned device, ordinary
publication budget and raw/guarded request/stage/powers/receipt windows before
fresh approval and again immediately before commit. Atomically save ordinary
intent approval, pending approval/reference, receipt approval at the same
effective time and ordinary guarded-clock anchor. All fresh prepare/approve
writes roll back on fault/refusal. Ordinary total4096/active64 quotas apply;
at most256 machine requester receipts and8MiB aggregate receipt records.

State is approved only if receipt and ordinary approval agree, including
approved_at; advanced approval alone is invalidated and cannot gain attribution.
Otherwise cancelled for cancellation, expired for request/stage/receipt/powers
expiry, invalidated for detached/changed/ineligible scope or conflicting work,
else review. Exact guided Approve after advanced-only approval refuses
review_changed; raw time before request/stage/intent creation refuses
machine_requester_consent_unavailable, including inside the300s clock clamp.
Next action: approved follow_machine_link, review
approve_machine_requester_commit, otherwise inspect_machine_link. Historical
approval is a past decision, not current powers/application/readiness. Ordinary
approved workers may sign/publish afterward; this route never invokes them.

Exact approved replay and recorded Lookup/Prepare return history before fresh
eligibility or owned-device/key resolution, including expiry/cancel/detach/
restart/progress/application. Wrong digest still refuses. Validate closed
receipt structure, immutable flow/request/ordinary intent references and frozen
public evidence. Pruned/corrupt records refuse without recreating anything;
unavailable live authority is not a historical prerequisite. Historical binding
and receipt recovery observe max(raw time, validated retained clock anchor)
without applying the fresh300s rollback limit or saving a clock. An actual
rollback greater than300s cannot hide retained Lookup/Prepare/approved replay;
fresh work still uses the ordinary guarded clock and raw-before-created checks. History saves no
clock/intent/queue/event/file/network work. Safe closed output at most2MiB;
no invitation/code/seed/private path/original inventory/templates/signatures/raw
packet/catalog/transport or signer diagnostics. No original/device signing,
original availability probe, implicit selection, commit publication/application,
access/capabilities/readiness/schema. Fresh owned-device validation is not signing.

### Verification

A separate contract-only author adds six `machine_requester_consent` black-box
cases from genuine distinct-host pinned invitations and remote machine/F
evidence, never reading product or running hosts/processes/models. Root runs
committed source with fresh hashed binaries. Keep all66 prior test/conformance
files and native415 tree exact, including every helper/counter/wait/timeout;
add one suite (35suites+build). No grant/queue/clock-row edits, worker disabling,
fabricated positive authority or unchanged retry-to-green.

1. Genuine remote device15 folded-F: independent exact API/CLI review/digests,
   finite7/2, exactly one ordinary unsigned intent and receipt, no requester
   original/network/commit/adoption; stable pure Prepare replay. Genuine remote
   original/capped deadline as bounded fixture permits.
2. Explicit approval: ordinary+pending+receipt matching atomic consent. Missing
   receipt/wrong digest/advanced approval cannot implicitly prepare or gain
   attribution. Do not assert postapproval workers cannot advance. A single
   coherent state-only lookup after external approval is acceptable there; it
   does not replace strict complete purity measurements for settled readers.
3. Temporary schema-only INSERT/UPDATE ABORT triggers over genuine ordinary or
   receipt writes prove full fresh Prepare/Approve rollback, including clock
   and references. Remove triggers before complete DB/files comparisons; never
   fabricate rows or edit authority/signatures to manufacture setup.
4. Real missing-prefix/context/digest/detachment/cancel and raw/stage/request/
   receipt expiry refusals/history. Preserve first crossings; record unavailable
   powers-expiry/changed-authority cases as source/fault limits. A cancelled
   ordinary request does not replace its immutable requested join flow; use a
   genuinely fresh attached parent/context for a new attempt. Before a later
   explicit advanced mutation, release the reader-only transport holds as real
   setup; preserve original mutation timeout and every read-purity category.
5. Lookup/null/history, identical Prepare and approved replay are pure after
   detach/restart/expiry and absent original sources. Count complete both-host
   DB/schema/state/home and bidirectional TCP/UDP. Existing computer may go
   offline after F before baselines; requester stays live. No both-live worker
   attribution or disabling authorized work. Record live postapproval limits.
   With genuine debug time more than300s behind the documented saved anchor,
   approved Lookup/Prepare/Approve still return exact pure history; unapproved
   fresh consent refuses. Advance/restore only public debug clocks outside
   baselines, never edit clock rows. A failure-only finalized-setup observer may
   emit only exitcode, fixed public error categories and status booleans, never
   IDs/paths/raw error/packets; retain the original failure and assertion.
6. Nested JSON/IDs/64KiB/private argv/no-startup/method/adapter/peer/bootstrap
   isolation and safe public projection. Pruned/corrupt/unsafe/complex separate-
   admin/reused-binding cases without real bounded stimulus stay source-only.

Root serializes Rust fmt/existing155+2ignored/Clippy/build and this new suite;
no unrelated local native/old host retries. Retain all first failures/corrections
and exact source/binary/test/log receipts. Final-head35suites+build/four checks/
native415 and fresh bot/root review required. Bounded completion/native controls
and full #35 terminal/reload/installed/physical/model/schema23→27/full-state/final
acceptance stay open.

### GU.impl46 finalization setup clarification

Second CI records an existing-computer finalization ID already present after
explicit Finalize returns exit1, while setup rejects its English diagnostic.
A positive retained-evidence fixture must establish actual signed F, not full
machine completion or one CLI wording. Use one unchanged bounded Finalize
command only, reject parse/crash/timeout outcomes (only exit0/1 eligible), then
require the original bounded requester-F observation and exact existing-host
read-only status. Both host views must agree on the same canonical F ID and
captured request/network/context/person/host/device/owner/selection/admin pins.
Use existing independent retained-envelope/reference/profile checks for setup.
Keep the first subject API/CLI inspection INSIDE its original complete purity
measurement and its full independent validation in place; do not pre-read that
API outside the baseline and hide a one-time mutation. All full-F/P/H/B/D and
ID/profile/digest checks remain required. Missing/mismatched/invalid F fails; no
repeated signing/resume, added mutation, original copying or larger wait.

The separate contract-only author may replace only the brittle Finalize
exit1-English guard in the NEW46 suite, adding the stronger exact two-host F
precondition. All66 prior test/conformance files, including section45's suite,
and full native415 tree stay byte-exact. The proposed old45 setup change was
rejected by automatic approval review under that preservation requirement and
is discarded for this pass. Original new46 case bodies, non-setup assertions,
private corpora, full state/carrier counters, waits and timeouts remain. Removing
the new setup verification and restoring that guard recovers exact prior new46
bytes/AST. No prior-suite exception is selected.
Retain both CI failures and unknown earlier timing causes; no claim that a
passing fixture diagnoses them or that arbitrary CLI errors imply success.

## 47. Bounded existing-person machine requester completion

GU.impl47 follows section46. Select the existing ordinary requester signing,
pinned publication and participant application pipeline, guarded by the exact
approved machine receipt. No schema, new consent, provider fallback, local
original-person key, capability/access grant or native control is added.

### Explicit private action and retained result

Owner-local POST `/v1/onboarding/join-flows/{id}/machine-commit/complete`
accepts exactly `{context,join_review_id,consent_review_id,decision}`; decision
is exactly `complete_machine_requester_commit`. Private CLI `onboarding join
machine-commit complete --stdin` adds exactly `flow_id`. Section46 recursive
strict JSON/typed IDs/context/private-prefix/64KiB/fixed diagnostics/no-startup
and router isolation apply. One daemon call, CLI95s/server90s monotonic bounds.
No supplied terms/provider/keys/mutation IDs in argv or automatic retry.

Bind the exact requested flow/outcome, pinned existing person, actual requester
host/device and immutable section46 receipt. Require matching approved
metadata/ordinary/pending IDs, approval flags and approved_at. Advanced ordinary
approval alone, a missing/unapproved receipt or a changed digest cannot authorize
completion. Never prepare/approve/replace/extend consent. Section46 Lookup is
the read-only recovery path after uncertainty.

HTTP200 requires an independently verified retained local application, never
only a signature, approval, carrier ACK or pending progress. Return section46's
exact closed wrapper with consent plus exactly `completion`:

```
{state:"locally_applied",review_id:consent_review_id,manifest_id,activation_id,
 outcome_id,participant_delivery:"not_verified",agent_access:"not_verified",
 connection_readiness:"not_verified"}
```

References equal the returned request and verified ordinary application.
Consent review/digest/approval remain immutable. Safe public output <=2MiB;
no keys/codes/private paths/templates/signatures/catalog/raw packet or signer,
transport, SQL diagnostics. Local application does not establish current
powers, remote application, agent access, messages, capabilities or readiness.

### Pure history and guarded fresh work

Exact already-applied replay verifies immutable operation/catalog/activation/
outcome at its saved application time and returns purely before fresh parent,
expiry, clock-rollback or key availability checks. Section46's validated
max(raw,retained) historical clock applies; wrong digest still refuses. No
signing/publication/repair/cleanup or clock write on replay, including after
detach/restart/expiry and >300s rollback. Pruned/corrupt application refuses.

Fresh work requires the same attached project/agent and approved machine
receipt, matching received remote owner/selection/admission/F, finite7 machine
powers/binding2, genuine inherited end, exact root/P/H/B/D and ordinary full
cryptographic projection. Folded admission has no separate administrator packet
or completed stage; actual binding reuse follows ordinary projection. A newly
linked host never resolves the person's original key. Partial/already signed
or sealed work reuses exact retained intent/templates/signatures/frames.

Raw time must be >= request/stage/ordinary-intent creation; raw and guarded
effective time must remain before signed request deadline and frozen powers
end. Unsigned work also obeys600s stage inactivity. The human review expiry
does not revoke an approval already recorded. Cancellation, incompatible local
network adoption, changed authority or conflicting work refuses. Guard parent,
exact receipt/digest, ordinary approval/projection and times in every signing
transaction before key work and before commit; at most four changing phases.
No broad resume, extra owner/admin signing, mailbox GET or automatic consent.

Reuse section28's bounded sequence: one exact-request publication pass <=30s
before guarded local application and one <=30s afterward, with no hidden retry
or new addresses/providers. Carrier failure alone does not prevent otherwise
valid local application. Recheck fresh guards before/after first IO and inside
application before outcome-key work and final commit. Only the same verified
operation applied in that transaction may pass its final installed-network
check. Application transaction rolls back all network/proof/outbox/operation/
event/device/outcome/secret-retirement changes on failure; earlier committed
signatures/frames/IO remain. After application, changed scope/time can suppress
second IO; retained application remains historical evidence.

No new phase starts after90s monotonic deadline. Timeout/cancellation cannot
retract dispatched IO/blocking work or independently authorized workers. Report
controlled uncertainty and use Lookup before another explicit action. No
persistent attempt/job. Microscopic final-check/key/commit races and global
worker attribution remain source limits.

Malformed400 invalid; unknown404; nonrequested409 state_conflict; wrong scope/
digest/changed fresh parent409 review_changed; missing request409
request_unavailable; fresh signed/fixed/unsigned-stage expiry409 review_expired;
missing/unapproved/unsupported/corrupt/incomplete/early raw/timeout409
machine_commit_completion_unavailable. Other methods405. CLI errors fixed,
nonzero, private and never echo supplied values/raw response.

### Verification

Separate contract-only author adds six `machine_requester_completion` cases
and the36th suite. Preserve all67 prior conformance/native files and complete
native415 tree byte-exact, with original helpers/counters/waits/timeouts. Author
reads contracts/test fixtures only and executes no host/runtime/model. Root
runs committed tests on fresh hashed binaries, serializing compiler/runtime
gates. No grant/approval/signature/queue/clock-row fabrication, key copying,
worker disabling, exclusions or unchanged retry-to-green.

1. Genuine two-host existing-person remote device15 folded-F and finite7/2
   approval reaches actual local application via exact API/CLI. Independently
   verify application packet/manifest/outcome references, unchanged consent,
   exact ordinary intent reuse, finite inherited end and no new schema/consent.
   Exercise original-person capped provider as bounded setup permits.
2. Missing/unapproved/advanced-only receipt, wrong digest/context, cancellation,
   fresh detachment and actual raw/signed/fixed/unsigned-stage expiry refuse
   without adopting consent. Strict full DB/schema/state/home and BOTH complete
   bidirectional TCP/UDP comparisons where pure settled stimuli are genuine;
   authorized worker progress has no route attribution or global absence claim.
3. Genuine existing public debug protocol barriers permit parent/time changes
   before application and final transaction checks. Prior competing application
   may return historical success; never fabricate an unapplied fixture. Partial
   signature barriers do not prove live transport holds. Unavailable narrow
   unsigned interval/key/commit races remain explicit source limits.
4. Temporary schema-only BEFORE INSERT ON dec_operations ABORT for the genuine
   request proves full application transaction rollback, including proof outbox
   and secret retirement. Earlier valid signatures/frames/transport may persist;
   retain exact immutable consent/approval. Remove trigger before comparisons.
5. Strict recursive JSON/typed IDs/64KiB/CLI/private prefixes/no-startup/method/
   scoped/peer/bootstrap isolation, closed public privacy and one bounded action.
   Corrupt/pruned/unsafe/key-syscall/exact deadlines/complex separate-admin or
   reused-binding variants without genuine stimulus remain source/fault limits.
6. Verified completed API/CLI replay is pure with stable consent/completion
   after detach/restart/expiry and genuine >300s rollback, no external original.
   Wrong digest still refuses. Whole both-host DB/schema/state/home and all
   bidirectional TCP/UDP categories remain. Genuine actual carrier settlement
   may precede baseline using existing documented section28 fixture rules;
   do not hide reader mutation with an unmeasured completion call. Installed,
   physical/model and fullfeature35 acceptance remain unexecuted.

Retain all first failures/no-starts, unknown causes and exact source/binary/
fixture/log provenance. Root fmt/existing Rust155+2ignored/Clippy/build and new
suite locally; no unrelated old/native retries. Final exact-head all36suites+
build (37jobs), all4 checks/native415 and fresh bot/root review required.
Owner merges this slice into #35; #35 main acceptance and native controls stay
open. Discard new completion receipts, a new journal, person-key copying,
broad resume and treating local application as connection readiness.

GU.impl47 bounded fixture clarification: an injected application SQL ABORT
returns409 machine_commit_completion_unavailable without raw SQL output.
A lost-response test may forward one real fresh Complete POST exactly once,
retain its real200 response privately for independent application verification,
and drop the client response. Use section46 Lookup before any later explicit
completed replay; no automatic retry or unmeasured warming Complete.

For terminal history only, existing section28 genuine delivery repair, signed
contact retention, peer registration/sync and one documented retry-eligibility
alignment <=61s may precede the baseline. Observe actual complete outbox/journal,
secret/frame/read-cap retirement. A genuinely fresh unsigned requester create
and immediate public cancel may drive documented capacity/expiry maintenance;
no row editing/deletion, forced ACK, omitted carrier or larger wait. Existing
counted QUIC paths must actually be authenticated/retained before relying on
delivery. The independent bounded suite uses two real ceremony pairs: device15
folded F and original-person capped F. Advanced-only without guided metadata is
already covered in46 and is an explicit source/fault-only completion boundary
here; discard a third ceremony that would duplicate it at runtime cost. Do not
claim that path was executed in47. Preserve genuine missing/unapproved/digest
refusals and all67 old files.

GU.impl47 pre-runtime independent static correction: ordinary cancellation
cannot succeed after commit persistence. Preserve draft44603a7 as unexecuted;
remove its unsupported postcommit cancel200 setup before the first run. Keep
actual original-cap time and parent barriers, exact detached refusal and all
whole-state/carrier assertions. Cancellation and original-provider positive
Complete remain explicit47 source/fault-only coverage; discard another fresh
ceremony solely to duplicate those boundaries. Establish quiet/live consumed
transport holds at actual time-barrier entry before its original full baseline,
with unchanged waits/timeouts. No executed failure is reclassified or hidden.

GU.impl47 first runtime:0/6in73s, with two setup failures and four dependent
prerequisite failures. After actual late SQL fault, device setup waits for an
unsigned requester ClientHello despite already signed/framed work. Retained
state has no requester network/operation/outcome, exact approved completed
intent, no outbox, and all four outbound frames ACKed by both actual carriers.
The fault trigger was removed. Original fresh-clock comparison changes only
requester helper mailboxes/frames, with no schema/files/carrier crossing;
retained helper is expired/zero ciphertext/frames while peer helper is active.
Exact earlier subcase timing is not captured. Preserve these facts and limits.

For signed/framed live fixtures only, before a pure baseline establish genuine
publication drain with original carriers reachable: every retained outbound
frame must have ACKs for every actual carrier endpoint address/public_key
(storage schema749–757), no outbox or journals. Use the existing5s prerequisite
bound, no protocol mutation retry, frame/ACK edit or new driver. Stop the old
host only after this genuine observation. Signed/drained work is not an
unsigned mailbox poller; do not fabricate a new ClientHello or claim a TLS hold
there. Validate that signed/ACK prerequisite and retain the complete both-host
DB/schema/state/home/all bidirectional TCP/UDP equality checks. Unsigned live
readers keep actual consumed live ClientHello generation guards. Actual signed
time/parent barriers use truthful drained prerequisites, not nonexistent
unsigned polling. No scope/category exclusion or ordinary worker disablement.

For raw/signed-expiry tests, apply genuine fixture clock stimulus and observe
actual helper expiry/ciphertext retirement before baseline, using the existing
bounded retirement helper. Preserve the exact API refusal and full purity
checks, restoring clocks only afterward. Do not measure independent expiry
collection as reader work, or remove it from snapshots. The corrected separate
author source must precede one new run on frozen Rust0047; no unchanged retry.

GU.impl47 corrected sourcec443848 passes5/6in95s on frozen Rust0047:
actual application/lost-response/SQL rollback/private corpus and genuine
original-cap raw/time/parent guards pass. Terminal history stops before baseline
when existing normal-peer contact setup probe returns nonzero. Both retained
participants have one applied operation/network; no probe error/category was
captured, so the cause remains unknown. Do not infer a product or proxy fix.

Authorize a separate new-suite failure-only observer around that same bounded
contact setup call: original probe numeric exit, parsed status if actual JSON,
fixed stderr categories (timeout/certificate/pin/TLS/connection/other), both
existing counted UDP thread-alive booleans and captured before/after counters.
No raw args/IDs/keys/paths/error text/contact/cert bytes or new network/API/probe
call. Return the exact original subprocess result and preserve/rethrow the
original helper failure/assertion. Print only on failure; success is not a
causal classification. Removing observer/wrappers restores exact prior source/
AST and every original case/action/wait/timeout/full purity category. Commit
before one diagnostic execution on unchanged binaries, no unchanged retry.

GU.impl47 diagnostic22703b5 passes4/6in101s. Parent-boundary comparison
crosses both TCP connection/byte/return counters only, with complete DB/files/
UDP unchanged; preserve without route attribution. Contact observer captures
exit1/unknown status/timeout category, both UDP threads alive and no counted
UDP change during that subprocess. No dead-proxy diagnosis follows. First CI
b056 additionally retains unchanged old28 expired-history issuer UDP crossing
(1datagram/1200bytes, DB/files unchanged, directory entry ok) and new47 malformed
issuer UDP crossing plus the same prebaseline contact failure. All four checks
and fresh bot review pass; failed conformance remains unready.

Extend only the new failure observer using its already supplied argv in memory:
fixed program category probe/other; fixed operation contactPOST/contactsGET/
catalogGET/other from exact known paths; booleans for address matching each
actual counted endpoint, each direct peer endpoint or other; before/after UDP
thread-alive booleans and existing counters. Never print the argv, endpoint,
IDs/path/error detail or add IO/calls/retries/timeouts. Preserve exact original
result/exception/assertion and all six case ASTs; inverse restores prior1ed578
source/AST. One committed diagnostic run follows on frozen0047. Do not add a
proxy fix or old-host-offline setup before this bounded diagnostic is captured.

GU.impl47 target diagnostic92c5393 passes3/6in90s, retaining the malformed
issuer UDP and parent TCP-only crossings. It identifies existing probe/contact
POST aimed at the counted existing-computer endpoint: timeout/nonzero, both
threads alive before/after, no counted UDP delta. This proves that attempted
counted path did not deliver traffic in that interval; it does not identify a
dead thread or root cause. Preserve all earlier unknown causes.

Select bounded phase-correct prerequisites before one corrected run:

- After genuine application on both participants, use section28's supported
  terminal transport config/restart and fresh counted QUIC endpoints, preserving
  exact identities/state. Keep both ORIGINAL counted UDP proxies/counters at
  their original traffic positions forever and append every new proxy/direction;
  never reset or omit old paths. Existing signed contact exchange, peer
  registrations and syncs must establish actual new normal-peer reachability.
  No retry at the failed old address, added probe loop or larger waits. This
  selects independently verified terminal resources, not a proxy defect claim.
- For original-cap unapplied time/parent barriers, after genuine barrier entry
  and observed no local operation, take the old computer genuinely offline
  before the stimulus/baseline. Its complete stopped DB/files and both original
  TCP/UDP remain included. Preserve exact parent/time refusal, no new local
  application and full before/after equality. No worker flag or mid-baseline
  shutdown. The command already completed its one pre-application IO phase.
- Run the whole malformed/private/refusal/method/scoped/peer/bootstrap/no-startup
  corpus against genuine signed/approved but UNAPPLIED work before the positive
  application case, avoiding an installed network's independent directory
  refresh during those parser checks. Preserve every corpus item, expected
  status/code, original timeout, full state/counter assertion and API/CLI call.
  Move the exact64KiB successful API replay and successful pure CLI completed
  replay to the genuine terminal-history phase after actual settlement. Do not
  remove them or make an unmeasured warming Complete. The primary fresh lost-
  response application remains explicitly measured and independently verified.

These are separate genuine prerequisites; no assertion/category weakening,
current-authority invention, worker disabling, schema/protocol edits, larger
waits, background-IO attribution or unchanged retry. Separate author commits
source and restoration audit before root execution on unchanged Rust0047.
All67 prior files/fullnative415 stay exact. The earlier CI old28 failure remains
unclassified; it is neither modified nor waived by this new-suite correction.

GU.impl47 first final-candidate CI41c5d66: old45 original-person setup fails
at its existing finalization CLI guard, before the subject inspection; two
later cases lose that fixture prerequisite. Retain the3/6in38s outcome/log.
No stderr, response category or narrow cause was captured. Do not infer signer,
key, race or transport failure from the English assertion alone.

Select a separate independent diagnostic launcher for unchanged old45. It may
wrap only the existing harness Host.cli call when the original args begin
`link finalize`, forwarding exact args/kwargs and returning the identical
Result or rethrowing the original exception. Emit fixed closed metadata only
when the existing finalization success/incomplete guard would fail: numeric
exit or fixed exception kind, known public error categories matched in the
already captured stderr, stdout parsed-object flag, and allowlisted public
request state plus owner/selection/finalization-presence booleans when present
in that same result. No raw stdout/stderr/argv/IDs/key/path/endpoint, additional
host/API/DB/files/network reads, mutations, retries, delay or timeout changes.
Use runpy with the original suite argv; restore the original method in finally,
including SystemExit. Existing assertions still decide the result. Launcher
failure cannot convert a failed suite to success or hide its exception.

All67 prior files and native415 remain byte-exact. CI invokes this launcher
only for machine_requester_inspection; other suites keep their exact command.
Independent author reads contracts/fixtures only and runs no hosts/runtime.
Root static inverse/delegation/privacy audit precedes one changed-source run
and final full CI; passing without diagnostic output leaves the earlier cause
unclassified. Discard an old45 fixture edit, arbitrary ignored errors, guessed
product fix, unchanged retry-to-green or waiver of a required suite.

GU.impl47 diagnostic candidate d13b3a9 again fails old45 original finalization
before inspection: exit1, no stdout JSON, no recognized public error code;
all optional request fields are unknown. Do not infer a signing/key/authority
failure. Select a finite English-diagnostic classifier on the SAME captured
stderr in the separate launcher. Match only documented fixed public patterns:
`link signing changed reviewed {field}` and `link signing changed the fixed
{field}`, where field is allowlisted network_id/context_id/person_public_key/
host_public_key/device_public_key/scopes/not_after/root_state_id/owner_offer_id/
selection_id/administrator_offer_id/person_lease_id/host_lease_id/binding_lease_id/
device_lease_id. Output only fixed class and that field enum. Also allow exact
fixed phrases for approved provider/root change, pending self-consent provider
change (field kind/person_public_key/host_public_key/device_public_key), linking
context change, original signing key/format change, too many/duplicate/mixed
signature slots/batches, typed slot/role/reference change, and known timeout or
missing/mismatched key classes. Never emit an unmatched line, dynamic suffix,
raw text/hash or inspect additional state. Pattern observation is not causal
proof; unknown remains unknown. No new assertion or success condition.

Independent author extends launcher only, with no-host fake private-canary and
exact forwarding/restoration checks. Old67/new47/native415 stay exact. Commit
before one meaningful diagnostic run and fresh full CI. Preserve d13b3a9 first
failure and earlier silent local pass; do not infer a fix from a passing sample.

The finite classifier literals are explicit (case-sensitive substring matching
on captured stderr, optional surrounding `Error: ` does not affect matching).
Only fixed labels/allowlisted field enums are output; never the matched text:

- provider_root_changed: `link signing changed the approved provider/root`.
- context_changed: `linking context changed`.
- original_key_format_changed: `original signing key/format changed`.
- key_mismatch: `keep the exact reviewed original/root key on its own machine`.
- local_timeout: `local host daemon request timed out`.
- missing_file: `No such file or directory`; denied_file: `Permission denied`.
- invalid_slot: `invalid signing intent/slot`, `invalid slot`.
- invalid_batch: `invalid signing batch`.
- too_many_slots: `too many ready signature slots`.
- duplicate_slots: `unordered/duplicate signature slots`.
- mixed_intents: `mixed signing intentions`.
- dependency_batches: `too many dependency signature batches; resume the exact retained request`.
- signing_response_changed: `signing response changes request`.
- typed_object_changed: `typed object ID changed`.
- typed_role_not_ready: `typed signature role is not ready`.
- typed_message_changed: `typed signature message/key/format differs`.
- packet_role_unreviewed: `unreviewed packet signing role`.
- grant_role_unreviewed: `unreviewed grant signing role`.
- packet_target_changed: `packet changes reviewed ceremony/key/role`.
- packet_issuer_changed: `root packet changes reviewed issuer`.
- packet_signer_changed: `packet changes original signer`.
- grant_terms_changed: `grant changes reviewed operation/finite terms`.
- grant_person_changed: `grant changes target person`.
- grant_host_changed: `grant changes target host`.
- grant_powers_changed: `grant changes reviewed device/powers`.
- typed_parents_invalid: `invalid typed grant parents`.
- signing_window_expired: `link signing window expired; retain and inspect this request`.

Field patterns: `pending self-consent changed provider {field}` outputs
pending_provider_changed plus kind/person_public_key/host_public_key/
device_public_key enum. `packet changes reviewed {field}` outputs
packet_field_changed plus the previous field allowlist extended only by
request_packet_id. `grant differs from the concrete reviewed {field}` and
`grant changes reviewed parent {field}` output grant_reference_changed and
grant_parent_changed plus only person_lease_id/host_lease_id/binding_lease_id/
device_lease_id. Exact finite replacement strings only, no captured suffix or
untrusted regular-expression fragment. Preserve prior public-code metadata.

GU.impl47 finite-classifier candidate c0e8d12 still captures old45 exit1/no
JSON/unknown code/English class before inspection. Preserve that failure and
separate old24 after-expiry contact-row sequence/message refresh failure.
The finite classifier is insufficient to diagnose the CLI message. Select one
bounded encrypted failure artifact, retaining all old67/new47/native415.

Only inside the EXISTING failed `link finalize` guard, and only when English
class remains unknown, the separate launcher may encrypt the final nonempty
line of the already captured/redacted stderr (UTF-8 max256bytes) using a fixed
4096-bit RSA diagnostic public PEM and OpenSSL pkeyutl OAEP/SHA256. The private
key exists only in root's temporary directory, never repo/CI/artifact/log/model
context. Public PEM is a new diagnostic fixture, unrelated to product identity
or authority. One subprocess max, timeout2s, no retry, network or daemon/API/DB
read. Plaintext only on subprocess stdin, never argv/file/output; suppress and
never log encryption stderr/stdout. On success write only <=512byte ciphertext
to fixed `diagnostic-artifacts/inspection-finalize-error.rsa` under repo cwd,
mode0600. Do not write plaintext; no timestamps/IDs/paths/keys in artifact name.
The single encryptor attempt is global per launcher run: first unknown failed
guard only, no overwrite or later attempt. OAEP and MGF1 both use SHA256.
On capture/encryption failure emit only fixed capture-unavailable and preserve
the same original Result/exception/verdict; no broadened test timeout or retry.

CI may upload this fixed ciphertext file only after failed old45, retention1day,
no-error on absence, no raw state/worktree/artifact upload. Root downloads and
decrypts privately to diagnose the actual error; no raw decrypted line is copied
to repository, PR or chat. Preserve provenance/hash/outcome and report only the
necessary fixed cause after inspection. Independent author writes launcher-only
capture against this contract with fake encryptor/private-canary/forwarding
checks, no actual suite/host/product/runtime access. Root verifies real RSA
round-trip with synthetic text locally, audits old67 exact and runs one changed
suite before full CI. Discard further blind phrase enumeration, public raw
stderr, any private-key commit and waiver of the original failure.

## 48. Remaining flow contract

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
