# Path to a coordinator-free preview

Status: the coordinator-free product is integrated; preview closeout and release qualification are in progress. This roadmap replaces the earlier coordinator deployment sequence. The current network contract is the [coordinator-free spec](decentralized-spec.md) and its [wire appendix](decentralized-wire-formats.md).

## Current implementation

| Area | Implemented behavior | Contract and checks |
| --- | --- | --- |
| Network lifecycle | Local creation, invitations with automatic request return, machine linking, automatic approved-stage progress and explicit final consent. | Spec sections 6 and 8; slim join suite. |
| Authority | Signed grants and restrictions, owner-controlled access, scope narrowing, automatic renewal and retention, root rotation and reinvitation after a root split. | Spec sections 4, 5, 7, 12–14; slim policy, renewal and root suites. |
| Transport | Direct QUIC, signed contacts, catalog sync and repair, optional rendezvous mailboxes and encrypted relay helpers. | Spec sections 9 and 10; slim delivery and sync suites. |
| Agent work | Durable messages and replies, tracked tasks, artifacts, bounded delegation chains, session readiness, pending work and recovery. | [Task](task-contract.md), [delegation](delegation-chain-contract.md) and [live delivery](live-delivery-contract.md) contracts; slim work and live suites. |
| Shared capabilities | Owner and opted-in agent calls, selected MCP operations, per-call approval, agent recipients, resource bounds, remote MCP/OAuth and the built-in gh source. | [Capabilities contract](capabilities-contract.md); slim capabilities suite. |
| Host and integrations | Rust daemon/CLI, guided setup and diagnostics, Claude Code, Codex and OpenCode adapters. | [Host contract](host-service-contract.md), [quick start](quick-start.md); slim basics and installed-bundle checks. |

Rust is the host implementation packaged here. The Go implementation is maintained separately at [peerspan/peerspan-go](https://github.com/peerspan/peerspan-go) (DEC-OWN5 and DEC-OWN8). Native Linux amd64 and arm64 bundles are the preview targets; macOS and Windows have not completed equivalent validation.

The coordinator product and in-place migration are retired (DEC-OWN2 and DEC-OWN3). Existing old networks remain read-only history; membership is moved by creating a new network and inviting its members again. Hosted-coordinator operations and Go/Rust pairing matrices are historical milestones, not remaining launch gates.

## Preview closeout

The remaining implementation paths are automatic renewal through delegated administrators without the root seed, original-key and external-root SSH-agent renewal, and combined owner/root approval when the local host holds the root seed. The normative behavior is in spec sections 7.1, 7.3 and 8.2. These paths require independent contract-derived conformance before being marked complete.

Each network still needs its root authority available often enough to renew administrator grants. Ordinary work uses locally verified grants until their deadlines or a known restriction stops it. Automatic renewal does not revive expired authority.

## Release qualification

Complete these checks at one recorded source revision before publishing the preview:

1. Run the Rust checks and all ten slim conformance suites. Record actual failures and fixes; suite success is evidence for the exercised cases.
2. Build native Linux amd64 and arm64 host/helper bundles with checksums and matching, clean-source RELEASE.json metadata. Run installed-bundle and packaging checks.
3. Install the candidate on clean Linux machines. Follow the quick start for one person linking a second machine and for two owners joining separately; record prompts, next steps and installation or recovery failures.
4. Run useful work in real agent sessions on separate machines: message/reply, a tracked task with input and result artifacts, progress/cancellation, a bounded shared capability, and withdrawal of access to new work. Check model-produced output separately from adapter readiness.
5. Exercise direct participant connectivity with helpers disabled and restrictive-network connectivity through an independently configured helper. Record topology, direct/relay observations, helper replacement, daemon restart, and offline catch-up within valid authority.
6. Publish the verified preview artifacts and installer, with their source revision, tested platforms, actual acceptance evidence and remaining limits.

The [release procedure](releasing.md) defines package review and publication. The [manual acceptance guide](manual-agent-testing.md) defines the real-session evidence to record. Older results under docs/results remain historical and do not qualify a new source revision.

## Following product work

- [Conversations](conversations-proposal.md) is accepted and awaits implementation: persistent conversation identity, explicit participants and bounded context for agents and people.
- [Isolated runtime tasks](https://github.com/peerspan/peerspan/pull/2) remain a separate proposed track. Existing task delegation uses agents already running on another host.
- Broader agent/platform support and onboarding improvements follow observed preview friction. Claims about new adapters or platforms require their own live validation.
