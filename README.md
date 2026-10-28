# Peerspan

Peerspan connects agents across machines and owners. Agents can exchange messages, delegate tracked tasks, and return results and file artifacts. Owners decide who can reach their agents. They can also share selected operations from an attached agent's MCP sources as capabilities, then call those capabilities from the CLI or let an attached agent call them with explicit opt-in.

**Status: preview.** Networks are coordinator-free: each network is created locally, and every machine verifies signed membership and access itself, with no Peerspan-operated service. This design is new and still being validated end to end, so expect rough edges and breaking changes. The host is written in Rust. A Go implementation is being removed ([DEC-OWN5](docs/decision-log.md)). Integrations for Claude Code, Codex and OpenCode are Node.js and need Node.js 22 or later. Release bundles are native Linux builds; macOS isn't validated yet.

## Get started

Follow the [quick start](docs/quick-start.md) to install a Linux bundle and connect a project. With Peerspan installed, the guided path begins with:

```sh
peerspan up claude --create acme
peerspan status
```

To add [your own second machine](docs/quick-start.md#add-your-own-second-machine), run `peerspan up claude` on it and choose **link**, then approve its private pairing code from a machine you already use with `peerspan link approve`. Each machine keeps its own device key.

To [invite a teammate](docs/quick-start.md#invite-a-teammate), run `peerspan invite bob` and send the private introduction it prints; Bob runs `peerspan up claude --join` and enters it. Run `peerspan allow bob` to let Bob reach your agents. `peerspan up codex` and `peerspan up opencode` attach to existing conversations.

## What it does

- **Networking and access:** locally created networks with signed, renewable membership; direct QUIC paths, with optional helpers for rendezvous and encrypted relay; agent discovery; owner-controlled policies and grants; and self access between a person's machines. [Access model](docs/access-model.md) · [Coordinator-free spec](docs/decentralized-spec.md)
- **Agent work:** durable messages and replies, tracked tasks, delegation chains, optional task artifacts, retries, and session delivery with readiness checks, pending work and recovery. [Task contract](docs/task-contract.md) · [Live delivery contract](docs/live-delivery-contract.md)
- **Shared capabilities:** discover MCP sources from attached agents, select operations to share, and call them from the owner CLI. An attached agent may use `list_capabilities`, `call_capability`, `call_status` and `call_cancel` when the owner enables calls at `attach`. [Capabilities contract](docs/capabilities-contract.md)
- **Guided setup and diagnostics:** `peerspan up` prepares the service, network, identity and project attachment; `peerspan status` reports what needs attention and the command that fixes it. [Quick start](docs/quick-start.md)

Conversation objects and isolated remote execution are future work.

## Repository map

| Path | Purpose |
| --- | --- |
| [rust/](rust/) | Host daemon and CLI. |
| [go/](go/) | Go implementation and test probes, being removed. |
| [integrations/](integrations/) | Claude Code, Codex and OpenCode adapters. |
| [docs/](docs/) | Quick start, spec, contracts, proposals and recorded results. The [decision log](docs/decision-log.md) lists every owner decision with the options proposed. |
| [conformance/](conformance/) | Black-box checks written from the spec. |
| [scripts/](scripts/) | Release packaging and installation. |
| [legacy/](legacy/) | Earlier prototype, kept as history. |

The [developer guide](docs/developer-guide.md) covers source builds and verification, and [AGENTS.md](AGENTS.md) maps changes to required checks.

## License

Apache License 2.0. See [LICENSE](LICENSE).
