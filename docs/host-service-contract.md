# Local host daemon contract

The Go and Rust implementations develop the same host service in parallel. This document specifies the first working milestone: a durable local identity, agent registry, separate session attachment records, and local activity. It does not finalize the future peer protocol.

Both implementations live in the `capsule` repository: `go/` contains the Go host service and `rust/` contains the Rust host service. The shared contract and conformance tests live alongside them in `docs/` and `conformance/`. The choice of implementation to release as OSS remains open. Development history can be retained while that decision is pending; a later squash is a separate decision.

## Local administration boundary

The daemon listens on `admin.sock` within its private state directory. The directory has mode 0700; the socket, database, and process lock files have mode 0600. Administration trusts the local account that can access that socket. This is the local control interface for setup, integrations, and diagnostics. It is separate from the authenticated peer interface and from the daemon’s outbound connection to coordination; it does not define the everyday network-facing user workflow. The foundation starts with no TCP listener. An explicit peer listener, configured identities, and grants are specified in the [known-host messaging contract](peer-messaging-contract.md). Network membership and the coordination client are specified in the [coordination contract](coordination-contract.md).

Both binaries are named `capsule-host`. They accept `--state DIR` before the command. Without it, state defaults to `$XDG_STATE_HOME/capsule/host`, or `$HOME/.local/state/capsule/host` when the former is unset. The `run` command starts the daemon in the foreground; `serve` remains a compatibility alias. An existing state directory must be private. The daemon creates a missing state directory and rejects an ordinary file at that path. Client commands do not create state or open the database. Run simultaneous implementations with separate directories.

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
| `POST /v1/agents` | `agent register --name NAME --owner OWNER [--capability NAME]` | Register an agent with name, owner, and optional capabilities. |
| `GET /v1/agents` | `agent list` | List agents by creation time, then ID. |
| `GET /v1/agents/{id}` | `agent inspect ID` | Return one agent. |
| `POST /v1/sessions` | `session attach --agent ID --integration NAME` | Attach metadata with agent_id and integration. |
| `GET /v1/sessions?agent_id=ID` | `session list [--agent ID]` | List sessions, optionally filtered by agent. |
| `GET /v1/sessions/{id}` | `session inspect ID` | Return one session. |
| `POST /v1/sessions/{id}/detach` | `session detach ID` | Detach idempotently. |
| `GET /v1/activity?after=N&limit=N` | `activity [--after N] [--limit N]` | Read local events after a sequence cursor. |

Invalid requests return 400 with code `invalid`, missing records return 404 with `not_found`, duplicate agent names return 409 with `conflict`, and storage failures return 500 with `internal`. Error bodies have `code` and `error`. Internal responses contain the generic message `internal error`; validation message wording is not fixed by the contract. CLI successes print JSON; failures exit nonzero. Root help (including no command) exits successfully without a daemon or state directory. Command help and parser diagnostics follow the implementation’s CLI library; their wording and exact nonzero exit codes are not a shared contract. Rust uses Clap with typed subcommands and arguments.

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
