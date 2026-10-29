# Local host daemon contract

The Go and Rust implementations develop the same host service in parallel. This document specifies the first working milestone: a durable local identity, agent registry, separate session attachment records, and local activity. It does not finalize the future peer protocol.

The Rust host service lives in `rust/` in this repository ([DEC-OWN5](decision-log.md)); the Go host service is maintained separately at [peerspan/peerspan-go](https://github.com/peerspan/peerspan-go). The contract and conformance tests live alongside the Rust host in `docs/` and `conformance/`.

The product was called Capsule before 2026-10-15, and Peerspan does not carry anything over from it. Peerspan hosts and coordinators sign and verify only the `peerspan-*` domain strings and tokens. They do not read Capsule state, configuration, environment variables, or service locations. A Capsule network is therefore recreated and its hosts enrolled again. Records under `docs/results/` predate the rename and keep the old names.

## Local administration boundary

The accepted [machine-linking signing](machine-linking-contract.md) and
[transaction](machine-linking-transactions.md) contracts describe delegated
signing. The first [signed-object reader slice](linking-reader-checks.md) checks
bytes and signatures with independently supplied expected keys. The
[certificate-path evaluator](linking-path-checks.md) then checks exact parent
chains against independently verified current state. The bounded
[catalog/activation verifier](linking-activation-checks.md) derives that state
from signed genesis admissions and complete new/renew transcripts. The
[history verifier](linking-history-checks.md) adds legacy invite membership,
sticky removals and exact retained link records. The stateless
[feature activation checker](linking-feature-checks.md) enforces the first
proposal's deadline and exact signed roster, and distinguishes a previously
persisted feature from a proposal merely present in a catalog. The
[ordinary action authorization gate](linking-action-checks.md) checks current
signer scopes, role and expiry bounds, and refuses delegated changes that would
disable their own selected path. The [ordinary grant resolver](linking-record-checks.md)
materializes signed person/host admissions and host bindings, including exact
retained history and renewal references. The
[restriction resolver](linking-restriction-checks.md) adds ordinary unbinding,
person removal and host/invite revocation under the same history rules.
The [redemption resolver](linking-redemption-checks.md) adds completed invited
membership with exact invitation/redemption retention pairs. The
[access-state selector](linking-policy-checks.md) verifies legacy and ordinary
policies/groups, selects exact signed statements, and preserves caller-pinned
version high-water state through authority loss without falling back to older
access grants.
[root-chain verifier](linking-root-checks.md) resolves contiguous signed rotations,
current-epoch authority and attestations while preserving historical transcripts
and the exact activated feature.
The [fixed stored-catalog entry points](linking-stored-checks.md) accept complete
bounded public snapshots while preserving the original state-free API budgets.
[Historical descriptor verification](linking-coordinator-history-checks.md) keeps
complete old transcripts verifiable under their own coordinator pins, while new
operations remain pinned to the actual current connection.
These pure checks expose verified facts; the composed Go/Rust runtime applies
them under the [host runtime contract](linking-host-checks.md). Approved linking,
durable propagation and device providers are available, with the independent
[launch validation record](results/linking-launch-validation.json) documenting
the accepted implementation and its limits.

The [coordinator-free redesign](decentralized-network-contract.md) is a separate
DEC-01 draft with authority, bootstrap and migration contracts under review.
Those proposed protocol versions do not establish available runtime behavior.

The daemon listens on `admin.sock` within its private state directory. The directory has mode 0700; the socket, database, and process lock files have mode 0600. Administration trusts the local account that can access that socket. This is the local control interface for setup, integrations, and diagnostics. It is separate from the authenticated peer interface and from the daemon’s outbound connection to coordination; it does not define the everyday network-facing user workflow. The foundation starts with no TCP listener. An explicit peer listener, configured identities, and grants are specified in the [known-host messaging contract](peer-messaging-contract.md). Network membership and the coordination client are specified in the [coordination contract](coordination-contract.md).

Both binaries are named `peerspan-host`. They accept `--state DIR` before the command. Without it, state defaults to `$XDG_STATE_HOME/peerspan/host`, or `$HOME/.local/state/peerspan/host` when the former is unset. The `run` command starts the daemon in the foreground; `serve` remains a compatibility alias. An existing state directory must be private. The daemon creates a missing state directory and rejects an ordinary file at that path. Client commands do not create state or open the database. Run simultaneous implementations with separate directories.

## Identity and records

The current experimental identity uses a locally generated Ed25519 key. The private key stays in the local database. Public identity has `id`, `public_key`, and `created_at`: the public key is standard Base64, and the ID is `host_` followed by the hexadecimal SHA256 digest of the public key. This does not establish network membership or settle the future trust model.

Agents have `id`, `name`, `owner`, `capabilities`, and `created_at`. Names are unique within a host. Names and owner labels are trimmed, required, and at most 128 UTF-8 bytes. Capability names are trimmed, nonempty, and at most 256 UTF-8 bytes; duplicates are removed in input order. An owner is a local descriptive label. Capability metadata does not grant access or claim implemented functionality.

Sessions have `id`, `agent_id`, `integration`, `state`, `created_at`, and `updated_at`. An attachment requires an existing agent and a nonempty trimmed integration label of at most 128 UTF-8 bytes. State is `attached` or `detached`. Attachment records metadata only; it does not connect to or control an agent process. Host-managed sessions and actual integrations remain subsequent work.

Timestamps use UTC RFC3339. Agent IDs begin with `agent_`; session IDs begin with `session_`. Neither is derived from a runtime process ID. The current implementations append 16 random bytes encoded as hexadecimal.

## API and commands

Requests and responses use JSON. Creation endpoints return 201; reads and detachment return 200. Collections are arrays, including `[]` for empty collections. Mutation bodies are limited to 1 MiB and reject unknown fields, null field values, and trailing JSON. Field names use the exact lowercase spelling shown below. The table describes the required fields; creation bodies may omit capabilities to create an empty list.

| API | CLI | Behavior |
| --- | --- | --- |
| `GET /v1/host` | `info` | Return public local identity. |
| `POST /v1/agents` | `agent register --name NAME --owner OWNER [--label NAME]` | Register an agent with name, owner, and optional descriptive labels, stored in the `capabilities` field. `--capability` is accepted as an alias of `--label`. |
| `GET /v1/agents` | `agent list` | List agents by creation time, then ID. |
| `GET /v1/agents/{id}` | `agent inspect ID` | Return one agent. |
| `POST /v1/sessions` | `session attach --agent ID --integration NAME` | Attach metadata with agent_id and integration. |
| `GET /v1/sessions?agent_id=ID` | `session list [--agent ID]` | List sessions, optionally filtered by agent. |
| `GET /v1/sessions/{id}` | `session inspect ID` | Return one session. |
| `POST /v1/sessions/{id}/detach` | `session detach ID` | Detach idempotently. |
| `GET /v1/activity?after=N&limit=N` | `activity [--after N] [--limit N]` | Read local events after a sequence cursor. |

Invalid requests return 400 with code `invalid`, missing records return 404 with `not_found`, duplicate agent names return 409 with `conflict`, and storage failures return 500 with `internal`. Error bodies have `code` and `error`. Internal responses contain the generic message `internal error`; validation message wording is not fixed by the contract. CLI successes print JSON; failures exit nonzero. Root help (including no command) exits successfully without a daemon or state directory. Command help and parser diagnostics follow the implementation’s CLI library; their wording and exact nonzero exit codes are not a shared contract. Rust uses Clap with typed subcommands and arguments. The active Go host, coordinator, and peer-probe CLIs use Cobra for command dispatch, argument validation, and generated command help. Go long options use `--`; `--state` is inherited by host and coordinator subcommands and may appear before or after the command. Repeatable string flags keep each value verbatim, including commas. Options may follow positional IDs. `session start` passes harness arguments only after a `--` separator.

## Persistence and lifecycle

One service process owns a state directory at a time. Another process must fail without changing the running service's socket or identity. Ordinary files at the socket path are not overwritten. Database and lock-file symlinks are rejected.

Registration, attachment, and detachment each commit their state change and an activity event in the same transaction. Events contain `sequence`, `kind`, `subject_id`, and `created_at`. Reading activity defaults to 100 records; limits range from 1 to 1000 and cursors are nonnegative. Event kinds are `agent.registered`, `session.attached`, `session.detached`, and `session.disconnected`.

Detaching an already detached session leaves it unchanged and adds no event. At restart, identity, agents, historical sessions, and events survive. Previous attachments become detached with a `session.disconnected` event. This records lost attachment state; it does not imply that an external agent process was terminated. Orderly shutdown stops the local server and removes its socket. Crash recovery handles a stale socket after acquiring the state lock.

## Validation and next milestone

`conformance/host_service.py` runs identical checks against either or both built binaries using temporary state directories. It checks the API and CLI, crash recovery, process exclusivity, concurrent duplicate registration, and rollback when activity recording fails. Language-specific tests also check persistence and filesystem boundaries.

`conformance/build_timings.py` compares clean builds, unchanged warm builds, a comment-only edit followed by a build or test run, and first release builds. Dependencies are predownloaded and build caches are isolated. Results measure these implementations, dependency choices, and compiler profiles; they do not establish general language performance.

The [known-host messaging contract](peer-messaging-contract.md) extends this foundation with an opt-in TLS peer interface, host-scoped grants, durable message acceptance, and explicit recovery. The [coordination contract](coordination-contract.md) adds signed enrollment and a coordination client. Mixed Go/Rust hosts pass the same transport and enrollment tests. Live agent delivery, full conversations/tasks/capability calls, membership revocation, and isolated runtimes remain subsequent work.

## Session adapter extensions

The [adapter contract](agent-adapter-contract.md), [outbound extension](adapter-outbound-contract.md), and [recovery extension](adapter-recovery-contract.md) define the separate credential-scoped interface for existing sessions. Registry attachment alone is not readiness. A live adapter proves its bound instance and renews a connection lease; the same instance can recover its original attachment after daemon restart. Owner detach and authorization expiry/revocation stop access. Token rotation preserves the authorization ID, original expiry, routes, budgets, and collaboration records. Shared schema v6 adds these connection records atomically.

Owner creation of an authorization for a fresh session replaces a previously connected authorization whose lease is no longer valid. Its response includes `replaced_adapter_ids`, and revocation/detachment commit with the new credential. A live lease, an unbound setup, or the 15-second startup reconnect window still conflicts. The window protects previously bound, recoverable instances without restoring their leases; explicit owner detach or revoke bypasses it. Old collaboration records and routes retain their original authorization/session bindings.

## Owner integration setup and diagnostics

These endpoints exist only on `admin.sock`, with the same JSON validation and error conventions as other owner requests:

| API | Response | Behavior |
| --- | --- | --- |
| `POST /v1/adapters/setup` | 201: `{session, credential, routes}` | Atomically attach a session, issue its credential, and create its destinations. |
| `POST /v1/adapters/{id}/verify-credential` | 200: `{matches: boolean}` | Compare the supplied `{token}` with the stored digest without connecting an adapter. |
| `GET /v1/adapters/{id}/route-status` | 200: `[{route, messages_remaining}]` | Read all owner-configured routes, including withdrawn routes, ordered by name, with remaining lifetime budgets. |

Setup requires `agent_id`, a caller-chosen unused `session_id` (`session_` plus 32 hex characters), `integration`, and future RFC3339 `expires_at`. Optional `routes` is an array of at most 100 entries, each requiring `name`, `peer_host_id`, `target_agent_id`, `grant_id`, `expires_at`, `max_message_bytes`, and `max_messages`. Route validation and offline replacement use the existing adapter contracts. Session, credential, routes, activity, and any replacement commit together; a conflict, invalid route, or storage failure rolls everything back. Reusing a session ID conflicts; it does not mint or recover another credential. No schema migration is needed.

Credential verification reports digest equality separately from authorization validity; expiry, revocation, and connection state must still be inspected. Neither diagnostic endpoint changes leases, activity, message handoffs, or budgets. `messages_remaining` subtracts the number of durable requests bound to that route, including failed requests; retries of the same request do not consume more budget. Unknown authorizations return 404.

Both native CLIs provide `session setup --harness ID`, `session start`, and `session doctor` through the [harness integration contract](harness-integration-contract.md). The owner chooses an installed integration, agent, expiry, private directory, and optional destinations. Setup accepts either an explicit future RFC3339 `--expires-at` or a relative `--expires-in` expressed as whole minutes or hours from `1m` through `720h`; it resolves and returns one immutable RFC3339 expiry. Common profiles, credential issuance, scopes, recovery, and daemon diagnostics stay in Peerspan. Integrations handle harness configuration and prerequisite checks, plus an optional foreground launch plan. Recovery preserves the original session and scopes and refuses a bound instance. Doctor reads local readiness without connecting or renewing a lease; model availability and message consumption remain unverified. Shipped integrations include Claude Code channels and sidecars for existing Codex and OpenCode conversations. The Codex sidecar joins an explicitly selected, loaded thread over its local backend socket, installs scoped MCP tools with caller-thread checks, and queues input while retaining the original conversation and native permissions. It starts no Codex process or thread.

Task delegation between hosts, roadmap milestone 6, is specified in the [task delegation contract](task-contract.md).

The `peerspan` name, the reduced root help, network defaulting, expiry defaults with renewable session credentials, and `status` (`GET /v1/status`), roadmap milestone 7, are specified in the [launch contract](launch-contract.md), together with the service installer and coordinator limits, team onboarding, the directory and addressing, and two relay protocol versions: version 2's `changed` notifications (slice 5) and version 3's `presence` notifications (slice 6).

The guided `up` command composes installation, onboarding, and attachment as specified in the [guided setup contract](guided-setup-proposal.md), with installed-bundle recovery checks in `conformance/up_acceptance.py`.

The isolated guided-onboarding feature starts with a read-only
`GET /v1/onboarding` on the owner-local socket and the advanced `onboarding`
CLI command. The [guided session contract](guided-session-contract.md#1-observation-slice-gu-01a--gu-02a)
defines its coherent network/request snapshot, full public adapter connection
evidence, purity and verification. It grants no approval or setup authority;
the interactive flow remains subsequent work on that feature branch. The
[native Claude entry](guided-session-contract.md#2-native-claude-entry-and-delivery-check-gu-01b--gu-03a)
reads that observation and offers a local conversation check. Its model tool
only acknowledges a challenge; it acquires no owner administration authority.

The [exact local project review](guided-session-contract.md#3-exact-local-project-review-gu-01c--gu-02b)
adds owner-local prepare/inspect/decision routes and advanced stdin-only CLI
mutations. Schema24 adds private durable review rows. Approval records local
agent/session metadata atomically; it issues no adapter credential or access.

The [native project review controls](guided-session-contract.md#4-native-project-selection-and-human-review-gu-02c--gu-03b)
use a read-only private context lookup before agent selection. Its owner-local
POST and stdin CLI return current flow/agent choices in one snapshot. Native
callbacks inspect and submit the exact reviewed context; model tools retain
no owner-decision operation. Schema24 and the attachment effects are unchanged.

The [exact guided adapter review](guided-session-contract.md#5-exact-local-adapter-authorization-gu-01d--gu-02d)
adds a separate owner-local review for the existing project's scoped credential.
Approval issues one fixed-expiry authorization with no directory access,
outbound routes or capability calls. Private exact credential retrieval is
separate from public flow observations and decision responses, and supports
lost-response recovery without plaintext token storage. Schema25 adds one
private child-flow table; schema24 project rows and DEC authority are unchanged.
This host API does not establish a connection, channel verification or model
receipt.

The [native adapter review and lease](guided-session-contract.md#6-native-credential-review-and-scoped-lease-gu-02e--gu-03c)
adds exact human consent and explicit connection in the existing Claude pane.
Its private stdin `onboarding adapter transport` wrapper derives the original
instance and selects the sibling adapter socket after exact credential retrieval;
it adds no API, schema or write. Native renewal uses the existing scoped connect
route. A live lease remains separate from incoming delivery and peer receipt.

The [native incoming-message path](guided-session-contract.md#7-native-incoming-messages-and-exact-model-acknowledgment-gu-03d)
explicitly enables a current-conversation readiness challenge before using the
existing scoped ready/next/forwarded/seen/reply routes. It adds no API/schema or
access grant. A saved host channel is insufficient for the current native
attempt; submission, model acknowledgment and peer receipt remain distinct.

The [native assigned-task path](guided-session-contract.md#8-native-assigned-tasks-and-cancellation-gu-03e)
explicitly enables existing scoped task/cancellation claims and lifecycle
routes under the current native readiness proof. It changes no host API/schema
or grant. Submitted prompts, successful model lifecycle calls and peer result
retrieval remain separate. Task file transfer and outward delegation are not
provided by this frontend slice.

The [exact contact-invitation review](guided-session-contract.md#9-exact-contact-invitation-review-gu-01e--gu-02f--gu-04a)
adds owner-local prepare/lookup/inspect/decision and explicit private handoff
operations for an attached guided project. Schema26 adds only the durable
invitation-flow table. Approval atomically mints one ordinary coordinator-free
introduction and return-path state; ordinary views never return its private
code. Membership, machine approval, agent access and native human controls
remain separate. Existing advanced invitation semantics are preserved.

The [recipient invitation preview](guided-session-contract.md#11-recipient-invitation-inspection-gu-01f--gu-02g--gu-04c)
adds owner-local `POST /v1/onboarding/invitation-preview` and private stdin
`onboarding invitation preview`. It verifies the core signed introduction and
returns only exact public review terms for the attached project. It retains no
code, writes no state, creates no identity/request and performs no network I/O.
Schema26 and existing invitation/linking behavior remain unchanged. The native
private input is separate from chat; signature validity grants no authority.


The [recipient join-request review](guided-session-contract.md#12-exact-recipient-join-request-consent-backend)
adds owner-local prepare/lookup/inspect/decision routes and private stdin
`onboarding join` commands. Explicit consent binds one supplied person public
key and verified invitation; request/device/frame state and its public outcome
commit atomically. Schema27 adds public join-flow state only. Person-key
selection, creation/persistence and native controls remain subsequent work;
publication never establishes possession, membership, agent access or receipt.
