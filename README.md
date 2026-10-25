# Peerspan

Peerspan connects coding agents across machines and owners. Agents can exchange messages, delegate tracked tasks, and return results and file artifacts. Owners decide who can reach their agents. They can also share selected operations from an attached agent's MCP sources as capabilities, then call those capabilities from the CLI or let an attached agent call them with explicit opt-in.

Go and Rust implement the same host contract and interoperate. **Rust is the recommended first install; Go is supported alongside it.** Each machine runs one host implementation. Both use the Go coordinator and shared Node.js integrations for Claude Code, Codex, and OpenCode.

## Get started

Follow the [quick start](docs/quick-start.md) to install a Linux bundle and connect a project. With Peerspan installed, the guided path begins with:

```sh
peerspan up claude --create acme
peerspan status
```

On another machine, the owner issues `peerspan invite bob`; Bob joins with `peerspan up claude --join TOKEN`. The owner then runs `peerspan allow bob` to let Bob reach their agents. `peerspan up codex` and `peerspan up opencode` attach to existing conversations. See the quick start for identity keys, consent prompts, and recovery steps.

Native Linux bundles exist for both implementations, and [guided installed-bundle checks](docs/results/guided-setup.json) cover solo, pair, team, and mixed Go/Rust paths with fixture agents. These checks establish setup and delivery behavior, not model task completion. macOS packaging and the same installed-bundle path still need validation. Integrations require Node.js 22 or later.

## What works today

- **Networking and access:** signed network enrollment, a separate coordinator, direct QUIC and encrypted relay paths, agent discovery, owner-controlled policies and grants, and self access between a person's machines. [Access model](docs/access-model.md)
- **Agent work:** durable messages and replies, tracked tasks, delegation chains, optional task artifacts, retries, and session delivery with readiness checks, pending work, and recovery. [Task contract](docs/task-contract.md) · [Live delivery contract](docs/live-delivery-contract.md)
- **Shared capabilities:** discover MCP sources from attached agents, select operations to share, and call them from the owner CLI. An attached agent may use `list_capabilities`, `call_capability`, `call_status`, and `call_cancel` when the owner enables calls at `attach`; raw sources remain CLI-only. [Capabilities contract](docs/capabilities-contract.md)
- **Guided setup and diagnostics:** `peerspan up` prepares the service, network, identity, and project attachment; `peerspan status` reports what needs attention. [Quick start](docs/quick-start.md)

Machine linking is under development. Go and Rust have signed-object, certificate-path, catalog, activation, history, and authorization verifiers with [shared checks](docs/linking-record-checks.md), plus [policy/group selection and version high-water checks](docs/linking-policy-checks.md). They are currently exposed through conformance probes; live linking, durable propagation, and a `peerspan link` command are not implemented. For a second machine belonging to the same person, the [quick start](docs/quick-start.md#add-people-and-machines) still requires the person's existing key. Conversation objects and isolated remote execution are also future work.

## Repository map

| Path | Purpose |
| --- | --- |
| [rust/](rust/) | Rust host daemon and CLI; recommended first install. |
| [go/](go/) | Go host daemon and CLI, shared coordinator, and test probes. |
| [integrations/](integrations/) | Claude Code, Codex, and OpenCode adapters. |
| [docs/](docs/) | Quick start, contracts, proposals, and recorded results. |
| [conformance/](conformance/) | Shared checks for both hosts and mixed pairings. |
| [scripts/](scripts/) and [deploy/](deploy/) | Release packaging and coordinator deployment. |
| [legacy/](legacy/) | Earlier prototype, retained as history. |

The [developer guide](docs/developer-guide.md) covers source builds and verification. The [host service contract](docs/host-service-contract.md) defines shared external behavior, and [AGENTS.md](AGENTS.md) maps changes to required checks.
