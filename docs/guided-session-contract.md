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
`review_changed`; malformed IDs/context return400 `invalid_request`. A new
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
changing its IDs, terms or expiry, including terminal outcomes. A new attempt
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
   appears only for explicit successful credential retrieval.
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

## 6. Remaining flow contract

Teammate/device admission, private handoff, native adapter connection and exact permission
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
