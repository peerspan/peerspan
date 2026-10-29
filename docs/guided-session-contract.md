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
the returned key with generated provenance, then show the ordinary chooser with
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

## 15. Remaining flow contract

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
