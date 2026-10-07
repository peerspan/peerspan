# Claude Code channel

One Node.js adapter connects an opted-in Claude Code session to either the Go or Rust host daemon. It uses the official MCP SDK over stdio and calls only the credential-scoped `adapter.sock` interface.

## Configure one session

Install Node.js 22 or later, then install the adapter dependencies:

```bash
cd integrations/claude-channel
npm ci --ignore-scripts
```

With your daemon running and your agent registered, prepare and start one explicitly opted-in session:

```bash
capsule-host --state STATE session setup --harness claude-code --directory /absolute/session-setup --agent AGENT_ID --expires-at FUTURE_TIME --integrations /absolute/capsule/integrations
capsule-host session start --directory /absolute/session-setup --workspace /absolute/project
capsule-host session doctor --directory /absolute/session-setup
```

`setup` creates the session, expiring credential, and optional destinations in one daemon transaction. It writes `profile.json`, `credential.json`, and `mcp.json` into a new private directory (0700; files 0600). Existing configuration is never overwritten. `--expires-at` is a future RFC3339 time. Use `--runner /absolute/node` and `--option executable=/absolute/claude` if the executables are outside PATH. Both native CLIs select the Claude integration through its `integration.json` manifest; its `provider.mjs` implements Claude checks and MCP/launch configuration. Install the complete integration directory. The [harness contract](../../docs/harness-integration-contract.md) defines the common lifecycle and local helper interface.

`start` launches Claude in the foreground using that private MCP configuration and opts in to `server:capsule`. It allows the four scoped Capsule tools; normal Claude project settings and permissions apply. Add Claude arguments after `--`, for example `-- --name collaboration`. Arguments cannot replace the prepared MCP configuration or channel selection. No global Claude configuration is edited.

Claude Code presents its development-channel confirmation. Channels are a [research preview](https://code.claude.com/docs/en/channels), subject to authentication and organization policy. Setup checks Node, installed dependencies, Claude launch flags, and `claude auth status`; organization policy is checked by Claude at launch. This flow starts an opted-in session; it cannot add a channel to an arbitrary already-running Claude process. Plain MCP registration does not enable incoming messages.

## Diagnose and recover

`doctor` prints JSON and exits zero when prerequisites, private configuration, credential, authorization, and the original adapter's lease pass inspection. Immediately after setup it exits nonzero with `registered`: configuration exists but no adapter has connected. It identifies unavailable daemons, changed host identity, missing or stale credentials, expired leases, detached sessions, and revoked or expired authorization. Destinations show remaining lifetime message budgets and expiry/revocation status. Remote reachability and grant acceptance remain unverified.

Inspection never connects an adapter, renews a lease, hands off a message, or changes permissions. `adapter_ready` refers to the adapter lease and local configuration. `model_availability: "unknown"` and `message_consumption: "unverified"` remain explicit even with a live lease. Check a live exchange separately to establish model consumption.

If setup loses the daemon response or fails while saving the credential, retain its private directory and run `session setup --directory DIR`. A `preparing` profile records the exact requested session and scopes before submission. Recovery reuses that session and original expiry/destinations, rotating its token if necessary. It refuses an attachment that has already connected or changed. Known setup refusals roll back all daemon changes and remove the new preparing directory; ambiguous failures retain it. `doctor` reports interrupted setup without completing it.

Once an adapter has connected, `start` will not adopt its authorization for another process. Keep the original Claude process during daemon recovery. For a closed session, choose a fresh setup directory; the existing offline replacement policy applies. Live leases, unbound setups, and the startup reconnect window still conflict. Explicit owner detach or revoke withdraws an unused setup. Authorization expiry requires a fresh owner-authorized setup; token rotation does not extend expiry. Keep credential files private and never commit them.

The existing `session attach`, `adapter create`, and `adapter route add` commands remain available for manual integrations. The generated `mcp.json` documents the required stdio channel arguments.

## Allow the agent to initiate messages

After configuring the peer or enrolling both hosts in a network, the receiving owner grants access to its target agent:

```bash
capsule-host --state RECEIVER_STATE grant create --peer SENDER_HOST_ID --agent TARGET_AGENT_ID --expires-at GRANT_EXPIRY --allow-disconnected
```

The sending owner can pass `--routes /absolute/destinations.json` to `session setup`. The file is a JSON array:

```json
[
  {
    "name": "bob",
    "peer_host_id": "RECEIVER_HOST_ID",
    "target_agent_id": "TARGET_AGENT_ID",
    "grant_id": "GRANT_ID",
    "expires_at": "ROUTE_EXPIRY",
    "max_message_bytes": 4096,
    "max_messages": 20
  }
]
```

Setup creates at most 100 destinations. Omitted limits default to 65536 bytes and 100 lifetime messages; omitted route expiry defaults to credential expiry. An invalid destination rolls back the whole setup. Setup grants no inbound access and creates no peer membership. For an already prepared attachment, add or inspect routes with the existing commands:

```bash
capsule-host --state SENDER_STATE adapter route add --adapter ADAPTER_ID --name bob --peer RECEIVER_HOST_ID --agent TARGET_AGENT_ID --grant GRANT_ID --expires-at ROUTE_EXPIRY --max-message-bytes 4096 --max-messages 20
capsule-host --state SENDER_STATE adapter route list --adapter ADAPTER_ID
```

Use `--allow-disconnected` for manually configured peers or when explicitly permitting work during a coordination outage. A recently synced enrolled peer can use a grant without it. Choose `ROUTE_EXPIRY` no later than the credential and grant expirations, and a byte bound within the receiver's grant. Configure each direction independently if both agents should initiate messages.

Ask the opted-in agent to list its Capsule destinations and send a message to `bob`. Its `list_destinations` and `send` tools expose only the owner's named routes. The daemon persists the request before sending; replies return to the same session automatically as `kind: "reply"` events carrying the original request ID. These response events have no delivery ID for the final-reply tool. A follow-up uses another authorized `send`.

For incoming `kind: "message"` events, the `reply` tool stores one final response addressed to the original sender. The owner CLI can also send a message and inspect its reply:

```bash
capsule-host --state SENDER_STATE message reply --peer RECEIVER_HOST_ID REQUEST_ID
capsule-host --state RECEIVER_STATE delivery list
```

`adapter revoke ADAPTER_ID`, owner session detachment, or credential expiry stop adapter access. Grants are checked again at handoff and reply. An uncertain handoff is retained for inspection and is never automatically sent again or moved to another session. `forwarded` confirms a notification write, not model execution. See the [adapter contract](../../docs/agent-adapter-contract.md).

`adapter route revoke ROUTE_ID` stops further sends through that route. Replies to earlier sends can still return while the original credential is valid. An uncertain send reports its request ID, and the daemon retries it automatically with that same ID until it is accepted, rejected, or past its deadline. The agent follows it with `send_status`. Only a send the host never recorded (`send_status` reports `not_recorded`) needs an explicit retry, with the same ID and identical destination/content. Each new persisted request uses one lifetime budget unit, including failed or rejected attempts; automatic and explicit retries of the same request use none. See the [outbound contract](../../docs/adapter-outbound-contract.md).

The adapter exposes `list_destinations`, `send`, `send_status`, and `reply`, plus the [task](../../docs/task-contract.md) tools `task_accept`, `task_reject`, `task_progress`, `task_complete`, `task_cancelled`, `delegate_task` (through a route added with `--action task.submit`), and `task_status`, and omits permission-relay capability. Tasks arrive as `kind: "task"` events, cancellation requests as `kind: "task_cancel_requested"`, and updates on delegated tasks as `kind: "task_update"`. Message access does not give a peer shell or filesystem access through Capsule; the existing agent still has whatever local permissions its owner granted it.

## Connection recovery and token rotation

The adapter binds a random process-instance secret kept in memory and renews a 15-second lease every five seconds. Inspect connectivity with `adapter connection ADAPTER_ID`: `registered` means no adapter has connected; `ready` means its lease is valid; `offline` means a bound adapter needs to reconnect. Detachment, revocation, and expiration are reported separately. These describe the adapter connection, not whether the model is busy or has executed a message.

Restarting the daemon invalidates leases. Previously bound, recoverable adapters get 15 seconds to reconnect before `adapter create` can replace them. This window does not grant a live lease. The same running adapter reconnects with its instance secret and recovers its original attachment, requests, and replies. Replacing the adapter subprocess requires an explicitly authorized fresh attachment; an existing credential file alone cannot take over its instance. Owner detachment also stops recovery when the daemon has already marked that session detached.

If the old adapter has exited, attach a fresh session and issue its credential using the setup commands above. Once the old lease has expired (at most 15 seconds after its last renewal) and any startup reconnect window has ended, `adapter create` retires the old authorization atomically and reports `replaced_adapter_ids`. It does not require a separate `session detach`. To replace it immediately during the window, explicitly detach its old session or revoke its credential first. The old adapter loses reconnect access; its pending work and outbound routes remain with its original session. Configure destinations for the new session explicitly. A still-valid lease or an authorization that has never connected remains protected; the conflict explains how to proceed.

Owners can rotate the token while keeping the original authorization ID, expiry, instance, routes, and budgets. Replace the private credential file atomically:

```bash
capsule_credential_next=$(mktemp /absolute/session-setup/.credential.XXXXXX)
capsule-host --state STATE adapter rotate ADAPTER_ID > "$capsule_credential_next" &&
  mv "$capsule_credential_next" /absolute/session-setup/credential.json
```

The running adapter reloads only the same authorization and session. The old token immediately loses access; the adapter allows up to 30 seconds for its replacement file. Rotation does not extend authorization lifetime. Inspect an agent-originated request with `message origin --peer HOST REQUEST_ID`, including an uncertain reply-notification handoff. See the [recovery contract](../../docs/adapter-recovery-contract.md).

## Verify

From the repository root:

```bash
npm --prefix integrations/claude-channel test
python3 conformance/agent_adapter.py --go GO_BINARY --rust RUST_BINARY --node NODE_BINARY --probe PROBE_BINARY
python3 conformance/adapter_outbound.py --go GO_BINARY --rust RUST_BINARY --node NODE_BINARY --coord COORD_BINARY
python3 conformance/adapter_recovery.py --go GO_BINARY --rust RUST_BINARY --node NODE_BINARY
python3 conformance/claude_setup.py --go GO_BINARY --rust RUST_BINARY --node NODE_BINARY
python3 conformance/harness_setup.py --go GO_BINARY --rust RUST_BINARY
```

The Python suites use deterministic MCP clients and temporary host state. `claude_setup.py` also uses an explicit Claude executable fixture for prerequisite and launch checks, across all CLI/daemon pairings; it makes no model calls. The separate `conformance/live_claude_channel.py` experiment uses authenticated Claude Code and real model calls; it tests an interactive session, a second message during model streaming, and revocation before queued handoff. Its PTY driver requires Linux:

```bash
python3 conformance/live_claude_channel.py --sender GO_BINARY --receiver RUST_BINARY --node NODE_BINARY --claude CLAUDE_BINARY --output /tmp/capsule-live.json
python3 conformance/live_agent_exchange.py --go GO_BINARY --rust RUST_BINARY --node NODE_BINARY --claude CLAUDE_BINARY --output /tmp/capsule-exchange-live.json
python3 conformance/live_agent_exchange.py --go GO_BINARY --rust RUST_BINARY --node NODE_BINARY --claude CLAUDE_BINARY --restart-pending --output /tmp/capsule-recovery-live.json
```

The second experiment uses two interactive Claude sessions to initiate messages in both directions and confirm automatic replies in their model output, without owner CLI send/fetch commands. Both experiments create temporary host and MCP configuration. Claude records each test workspace's trust/session information through its normal account state. Existing sessions and MCP configurations are not selected or reconfigured. Noninteractive stream-json mode connected to MCP but did not consume channel events in the tested installation; use the interactive path for this slice. Recorded results are in the [ingress report](../../docs/results/claude-channel-live.json) and [two-agent exchange report](../../docs/results/agent-exchange-live.json).

`--restart-pending` additionally restarts each originating daemon with the other implementation and rotates its token while waiting for a reply. The [recovery report](../../docs/results/agent-recovery-live.json) records the same two Claude processes completing those exchanges without duplicate sends or replacement sessions.

## Acceptance on two machines

[`live_cross_host_agents.py`](../../conformance/live_cross_host_agents.py) runs the experiment through two SSH accounts. Each machine needs this checkout, Python 3, the built host binaries, Node 22+, and the channel's installed npm dependencies. Alice also needs `capsule-coord`. For a model run, each account needs an authenticated Claude Code installation with channels available. The runner creates isolated test state and two opted-in sessions; it enables only Capsule tools. Existing daemons, workspaces, and grants are not used. Claude records these test sessions in its normal account history.

Configure SSH aliases with normal host-key verification. Each advertised peer port must be reachable over UDP for the coordinator-outage phases; Alice's coordinator port must be reachable over TCP. The daemons can use the coordinator's relay while it is running, but stopping that coordinator also stops its relay. SSH controls the workers; peer payloads use end-to-end QUIC. Build both hosts from the same protocol revision: the earlier TCP peer transport cannot communicate with QUIC peers. Save a configuration like this outside the repository, replacing the addresses and absolute paths:

```json
{
  "alice": {
    "ssh": "alice-dev",
    "repo": "/home/alice/capsule",
    "host_binary": "/tmp/capsule-host-go",
    "replacement_binary": "/home/alice/capsule/rust/target/debug/capsule-host",
    "node": "/usr/bin/node",
    "claude": "/home/alice/.local/bin/claude",
    "listen": "0.0.0.0:7443",
    "advertise": "10.0.0.10:7443",
    "coord_binary": "/tmp/capsule-coord",
    "coord_listen": "0.0.0.0:7444",
    "coord_advertise": "10.0.0.10:7444"
  },
  "bob": {
    "ssh": "bob-dev",
    "repo": "/home/bob/capsule",
    "host_binary": "/home/bob/capsule/rust/target/debug/capsule-host",
    "replacement_binary": "/tmp/capsule-host-go",
    "node": "/usr/bin/node",
    "claude": "/home/bob/.local/bin/claude",
    "listen": "0.0.0.0:7443",
    "advertise": "10.0.0.11:7443"
  }
}
```

`replacement_binary` is optional; omit it to restart the same implementation.

If this controller runs on Alice's machine, replace Alice's `"ssh"` entry with `"local": true`. Her paths then refer to this machine, while Bob still runs over SSH. The distinct-installation check remains enabled.

First run deterministic MCP consumers, which make no model calls:

```sh
python3 conformance/live_cross_host_agents.py --config /tmp/capsule-hosts.json --fixture --output /tmp/capsule-cross-host-fixture.json
```

Then omit `--fixture` for the real Claude experiment:

```sh
python3 conformance/live_cross_host_agents.py --config /tmp/capsule-hosts.json --output /tmp/capsule-cross-host-live.json
```

Add `--setup-flow` to prepare attachments and launch real Claude sessions through `session setup` and `session start`. With `--fixture`, setup still uses the public command, while the deterministic MCP consumer handles messages.

The earlier [setup-flow live report](../../docs/results/claude-setup-two-host-live.json) records two Claude Code 2.1.291 sessions on separate machines passing the full `--setup-flow --send-status` experiment with Go↔Rust: owner CLI preparation/launch, messages and model-observed replies, receiver downtime, coordinator outage, originating-daemon replacement, token rotation, and queued grant revocation. Both original sessions and their scoped budgets were preserved.

The runner verifies signed enrollment without manual peer pins, independently scoped grants, sends and automatic replies in both directions, collaboration after coordination stops, original-session recovery and token rotation during pending exchanges, and revocation before queued delivery. It pauses only its own receiving consumer to make the pending and queued cases deterministic. Arrival checks correlate request IDs. An uncertain send must recover through the daemon's automatic retries; the runner makes no further send calls. Invite and adapter secrets stay out of the report. Closing the workers stops their test processes and removes temporary state.

Add `--send-status` to stop each receiving daemon during the first two exchanges. The sending Claude session must call `send_status`, observe `unknown`, then observe `accepted` for the same request after the receiver returns, and receive its reply. The runner checks tool results and model text in its own session transcripts, with exactly one `send` call and one budget unit per message. `--send-status-only` runs just these two recovery exchanges:

```sh
python3 conformance/live_cross_host_agents.py --config /tmp/capsule-hosts.json --send-status-only --output /tmp/capsule-send-status-live.json
```

The [send-status live report](../../docs/results/send-status-two-host-live.json) records the full `--send-status` experiment passing with Claude Code 2.1.291, Go→Rust and Rust→Go, on separate machines. After the two receiver-outage exchanges, the original sessions also completed the coordinator-outage, originating-daemon replacement, token-rotation, and queued-revocation cases.

The report distinguishes MCP observations from model-observed replies and records each host's identity, machine fingerprint, session, versions, and grants. `--local` validates the runner on one machine; `--allow-same-machine` permits an SSH smoke test on one installation. Both report the shared machine accurately and provide no evidence of separate physical hosts. Different machine IDs identify installations, not developer identity or physical hardware.

The [two-host fixture report](../../docs/results/cross-host-runner-two-host-fixture.json) records all four Go/Rust pairings on separate installations, including coordinator outage, original-session recovery, token rotation, and queued revocation. A separate check forced Go↔Rust exchanges through the coordinator's relay by advertising closed UDP ports. These checks used deterministic MCP consumers and made no model calls.

The [two-host live report](../../docs/results/cross-host-runner-two-host-live.json) records two real Claude Code 2.1.291 sessions passing the full experiment on separate machines, with model-observed replies in both directions. Developer identities and the remaining task, conversation, and remote-tool capabilities were not tested.

The [harness-interface live report](../../docs/results/harness-interface-two-host-live.json) records the revised native `session setup --harness claude-code` and `session start` flow passing the full two-machine experiment with Claude Code 2.1.292, Go↔Rust, profile v2, and helper protocol v1. The original sessions completed messages/replies, receiver and coordinator downtime, originating-daemon replacement, token rotation, and queued grant revocation.

Installation must preserve the sibling `integrations/shared/` directory, which contains the harness-independent scoped adapter. The MCP transport and Claude launch configuration remain in this bundle.
