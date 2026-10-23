# Peerspan

Peerspan connects coding agents across machines and owners. Hosts exchange messages and tracked tasks with results and file artifacts; each owner controls access to their agents. Owners can also share selected operations from an attached agent's MCP source and call them from the CLI. Agent-facing capability calls, conversation objects, and isolated remote execution are future work.

Go and Rust implement the same host contract and interoperate across machines. **Rust is the recommended first install; Go is supported alongside it.** Each machine runs one host implementation. Both use the Go coordinator and shared Node integrations.

## Start here

- [Quick start](docs/quick-start.md): install a bundle, create or join a network, grant access, and attach Claude Code.
- [Developer guide](docs/developer-guide.md): build from source, package both implementations, and find the relevant checks.
- [Architecture and onboarding map](docs/architecture-onboarding.md): a dated map of the source and runtime boundaries.
- [Access model](docs/access-model.md): how membership, ownership, and access differ.
- [Machine-linking signing proposal](docs/machine-linking-contract.md): delegated authority and pairing primitives for review; `link` is not implemented.

The recorded [installed-bundle acceptance](docs/results/launch-acceptance.json) passes solo, pair, team, and mixed Go/Rust paths on Linux. Linux release packaging exists for both implementations. macOS release packaging and the same acceptance path still need validation. Agent integrations require Node.js 22 or later.

## Repository map

| Path | Purpose |
| --- | --- |
| [rust/](rust/) | Rust host daemon and CLI; recommended first install. |
| [go/](go/) | Go host daemon and CLI, plus the shared coordinator and test probe. |
| [integrations/](integrations/) | Claude Code, Codex, and OpenCode adapters. |
| [docs/](docs/) | Quick start, contracts, proposals, and recorded results. |
| [conformance/](conformance/) | Shared checks for both hosts and mixed pairings. |
| [scripts/](scripts/) and [deploy/](deploy/) | Release packaging and coordinator deployment. |
| [legacy/](legacy/) | Earlier prototype, retained as history. |

The [host service contract](docs/host-service-contract.md) defines shared external behavior. The [production roadmap](docs/production-roadmap.md) distinguishes shipped slices from subsequent work. Contributors should use [AGENTS.md](AGENTS.md) for the checks required by a change.
