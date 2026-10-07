# Harness integrations

Both native CLIs own session profiles, credential issuance, destination scopes, recovery, and daemon diagnostics. A selected local integration handles harness configuration, prerequisite checks, message delivery, and an optional foreground launch plan. The generic CLI requires neither Node nor MCP. Claude Code, Codex, and OpenCode are shipped integrations; the Python/file fixture is a conformance fixture, not another product integration. The shared adapter library handles credentials, leases, tools, and handoff; each harness supplies its own delivery transport. Install the sibling `shared/` directory with the bundles.

## Owner commands

```sh
capsule-host --state STATE session setup --harness claude-code --directory DIR --agent AGENT_ID --expires-at FUTURE_TIME --integrations /absolute/capsule/integrations --runner /absolute/node --option executable=/absolute/claude --routes /absolute/destinations.json
capsule-host session start --directory DIR --workspace /absolute/project -- --name collaboration
capsule-host session doctor --directory DIR
```

`setup` requires a harness ID, registered agent, future RFC3339 expiry, and a new private directory. `--option KEY=VALUE` is repeatable and interpreted by that integration; duplicate keys are rejected. `--runner` overrides its helper executable. The integration directory comes from `--integrations`, `CAPSULE_INTEGRATIONS_DIR`, or `../share/capsule/integrations` relative to the host binary. Source checkouts use an explicit directory. Discovery reads bundle manifests; only the selected helper executes. Each bundle is an immediate subdirectory containing `integration.json`. Duplicate matching IDs are rejected; unrelated broken bundles do not block selection.

The profile records the resolved integration command, capabilities, options, and opaque state. `start` and `doctor` select it from the profile. Setup does not grant inbound access, admit network members, or launch a harness. Existing `session attach/list/inspect/detach` commands retain their metadata and administration roles.

An interrupted setup is resumed with `session setup --directory DIR`, using the recorded request without new scope or integration options. A launch-capable integration can also recover during `start`. Recovery preserves the exact session, expiry, destinations, and authorization; it refuses changed, withdrawn, expired, or already-bound attachments. A helper without launch support can still prepare and diagnose an external consumer; `start` refuses before recovery or authorization changes.

## Local helper protocol v1

An installed manifest declares a harness ID, executable/arguments, and operations:

```json
{
  "version": 1,
  "id": "example",
  "command": ["/absolute/helper", "./configuration.json"],
  "operations": ["prepare", "check", "launch"]
}
```

IDs use lowercase letters, digits, and hyphens (1–64 characters). `prepare` and `check` are required; `launch` is optional. Arguments starting with `./` or `../` resolve against the bundle directory; the executable resolves through PATH or an explicit path and is saved as an absolute path. Commands are executed directly, without a shell. Helpers are owner-selected local code running as that account; this interface provides no sandbox for an untrusted integration.

Each invocation reads one UTF-8 JSON object from stdin and writes one JSON object to stdout. The executable receives no credentials in argv. Requests and responses are limited to 1 MiB; invocations time out after 30 seconds. Stderr is not included in CLI diagnostics, and helper descendants are stopped when the invocation completes or fails.

```json
{
  "version": 1,
  "operation": "prepare",
  "context": {
    "directory": "/absolute/session",
    "state": "/absolute/host-state",
    "agent_id": "agent_…",
    "session_id": "session_…",
    "adapter_socket": "/absolute/host-state/adapter.sock",
    "credential_file": "/absolute/session/credential.json",
    "options": {},
    "provider_state": {},
    "workspace": "",
    "arguments": []
  }
}
```

The core passes the credential file's path, never its token, and keeps permission enforcement in the daemon. Helpers must not issue credentials, edit scopes, connect an adapter during checks, or launch a background agent during these operations. A separate harness/adapter process consumes the saved configuration and connects to the scoped adapter interface.

Every response has `version: 1` and a `checks` array. Checks have `name` (letters, digits, underscore or hyphen, at most 64 characters), `status` (`ok` or `error`), and `detail`. The CLI prefixes names with `harness/`. Details must not contain secrets; Capsule additionally redacts its token/instance formats. Unknown response fields and malformed responses are rejected.

| Operation | Additional response fields | Behavior |
| --- | --- | --- |
| `prepare` | `state`: opaque JSON; `files`: filename → UTF-8 content | Check prerequisites and describe configuration before the core creates an attachment. |
| `check` | None | Read-only prerequisite/configuration checks; do not connect or consume messages. |
| `launch` | `launch: {program, args}` | Validate owner-supplied arguments and describe the foreground command. `program` must be absolute; the core validates access and replaces itself with that process in the chosen workspace. |

Artifact names are single filenames of at most 128 letters/digits/dot/underscore/hyphen characters, starting with a letter or digit. `profile.json` and `credential.json` are reserved. The core writes artifacts into the private setup directory; path traversal is rejected. `state` and `files` default to empty objects when omitted from a successful `prepare`.

## Profiles and readiness

Profile v2 stores common identity and setup fields, the manifest, integration options/state, artifact descriptions, and the original owner request. Directories are 0700; profile, credential, and artifact files are 0600 and account-owned regular files. Private-file symlinks and FIFOs are rejected. Writes use temporary files, rename, and fsync. The preparing profile and artifact descriptions are saved before the daemon's atomic setup request. Known 4xx refusals remove the new directory; ambiguous outcomes retain it for recovery. Profiles are portable between Go and Rust CLIs on the same host.

`doctor` reports native identity, credential, authorization, adapter connection, and destination-budget checks alongside integration checks. It performs no recovery, lease renewal, message handoff, or permission mutation. `adapter_ready` requires valid native and integration checks plus a live adapter lease. `model_availability` remains `unknown`; `message_consumption` and remote acceptance remain `unverified`. This distinction applies to every harness.

The experimental top-level `claude` commands and profile v1 from PR #37 are replaced by this interface. Existing running consumers continue using their original credential/configuration files. For new generic CLI setups, withdraw unused old authorizations with the existing owner commands and use a fresh directory; v1 profiles are not automatically migrated or overwritten.

## Verification

`conformance/claude_setup.py` retains Claude prerequisite/launch and real MCP exchange coverage across all CLI/daemon pairings. `conformance/harness_setup.py` uses an explicit Python/file integration with Node absent from PATH; it covers cross-CLI profiles and recovery, optional launch, read-only inspection, literal arguments, malformed/oversized helper output, secret redaction, and artifact confinement. Live Claude runs use `conformance/live_cross_host_agents.py --setup-flow` separately.

The [Codex integration](../integrations/codex/README.md) attaches to an existing, loaded app-server thread with scoped MCP tools and durable queued input. The foreground integration process is a sidecar; it creates no Codex conversation and leaves the native client running. `conformance/codex_integration.py` checks this protocol against real daemons across all pairings; `conformance/live_codex_agents.py` separately verifies real model exchange. Acceptance into Codex’s queue does not establish model consumption. The live report is [codex-existing-sessions-live.json](results/codex-existing-sessions-live.json).

The [OpenCode integration](../integrations/opencode/README.md) uses a one-time native plugin and a sidecar for an existing HTTP server/session. Trusted OpenCode tool context selects a private per-session gateway binding. The sidecar changes no native permissions or configuration, preserves the recorded model/agent, and verifies the exact persisted input after asynchronous submission. `conformance/opencode_integration.py` covers all pairings; `conformance/opencode_runtime.py` uses actual OpenCode with an explicit fixture model. Real inference is separate.
