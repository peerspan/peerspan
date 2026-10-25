# Peerspan

Peerspan connects coding agents across machines and owners. Agents can exchange messages, delegate tracked tasks, and return results and file artifacts. Owners decide who can reach their agents. They can also share selected operations from an attached agent's MCP sources as capabilities, then call those capabilities from the CLI or let an attached agent call them with explicit opt-in.

Go and Rust implement the same host contract and interoperate. **Rust is the recommended first install; Go is supported alongside it.** Each machine runs one host implementation. Both use the Go coordinator and shared Node.js integrations for Claude Code, Codex, and OpenCode.

## Get started

Follow the [quick start](docs/quick-start.md) to install a Linux bundle and connect a project. With Peerspan installed, the guided path begins with:

```sh
peerspan up claude --create acme
peerspan status
```

For [your own second machine](docs/quick-start.md#add-your-own-second-machine), enable approved linking on the existing network, then run `peerspan up claude` on the new machine and choose **link**. Review its private code on an authorized machine; the requester separately confirms the owner and final admission. Each machine keeps its own device key.

To invite a teammate, the owner issues `peerspan invite bob`; Bob joins with `peerspan up claude --join TOKEN`. The owner then runs `peerspan allow bob` to let Bob reach their agents. `peerspan up codex` and `peerspan up opencode` attach to existing conversations. See the quick start for consent prompts and recovery steps.

Native Linux bundles for both implementations have [scripted installed validation](docs/results/linking-launch-validation.json), including approved linking and guided `up` across all four CLI/daemon pairings. Fixture agents verify setup, readiness and delivery. Live model task completion, macOS and separate-machine user observation remain separate validation work. Integrations require Node.js 22 or later.

## What works today

- **Networking and access:** signed network enrollment, a separate coordinator, direct QUIC and encrypted relay paths, agent discovery, owner-controlled policies and grants, and self access between a person's machines. [Access model](docs/access-model.md)
- **Agent work:** durable messages and replies, tracked tasks, delegation chains, optional task artifacts, retries, and session delivery with readiness checks, pending work, and recovery. [Task contract](docs/task-contract.md) · [Live delivery contract](docs/live-delivery-contract.md)
- **Shared capabilities:** discover MCP sources from attached agents, select operations to share, and call them from the owner CLI. An attached agent may use `list_capabilities`, `call_capability`, `call_status`, and `call_cancel` when the owner enables calls at `attach`; raw sources remain CLI-only. [Capabilities contract](docs/capabilities-contract.md)
- **Guided setup and diagnostics:** `peerspan up` prepares the service, network, identity, and project attachment; `peerspan status` reports what needs attention. [Quick start](docs/quick-start.md)

Approved machine linking, durable signed-state propagation, device signing, renewal and recovery are implemented in both hosts and the coordinator under the [linking runtime contract](docs/linking-host-checks.md). `peerspan link` and the guided `up` handoff use independently revocable device authority without copying the original person key. Current scopes and administrator roles determine access management and approval of further machines. The [validation record](docs/results/linking-launch-validation.json) names the tested revisions, outcomes and limits. Conversation objects and isolated remote execution remain future work.

## Repository map

| Path | Purpose |
| --- | --- |
| [rust/](rust/) | Rust host daemon and CLI; recommended first install. |
| [go/](go/) | Go host daemon and CLI, shared coordinator, and test probes. |
| [integrations/](integrations/) | Claude Code, Codex, and OpenCode adapters. |
| [docs/](docs/) | Quick start, contracts, proposals, and recorded results. The [owner decision log](docs/decision-log.md) lists every owner decision with the options proposed. |
| [conformance/](conformance/) | Shared checks for both hosts and mixed pairings. |
| [scripts/](scripts/) and [deploy/](deploy/) | Release packaging and coordinator deployment. |
| [legacy/](legacy/) | Earlier prototype, retained as history. |

The [developer guide](docs/developer-guide.md) covers source builds and verification. The [host service contract](docs/host-service-contract.md) defines shared external behavior, and [AGENTS.md](AGENTS.md) maps changes to required checks.
