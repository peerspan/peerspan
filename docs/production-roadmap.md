# Path to a coordinator-free preview

Status: the coordinator-free product, guided onboarding, conversations, runtime tasks and the signed one-line install are implemented on `main`; the first release built from them is in qualification. This roadmap replaces the earlier coordinator deployment sequence. The current network contract is the [coordinator-free spec](decentralized-spec.md) and its [wire appendix](decentralized-wire-formats.md).

## Current implementation

| Area | Implemented behavior | Contract and checks |
| --- | --- | --- |
| Network lifecycle | Local creation, invitations with automatic request return, machine linking, automatic approved-stage progress and explicit final consent. | Spec sections 6 and 8; slim join suite. |
| Authority | Signed grants and restrictions, owner-controlled access, scope narrowing, automatic renewal and retention, root rotation and reinvitation after a root split. | Spec sections 4, 5, 7, 12–14; slim policy, renewal and root suites. |
| Transport | Direct QUIC, signed contacts, catalog sync and repair, optional rendezvous mailboxes and encrypted relay helpers. | Spec sections 9 and 10; slim delivery and sync suites. |
| Agent work | Durable messages and replies, tracked tasks, artifacts, bounded delegation chains, session readiness, pending work and recovery. | [Task](task-contract.md), [delegation](delegation-chain-contract.md) and [live delivery](live-delivery-contract.md) contracts; slim work and live suites. |
| Shared capabilities | Owner and opted-in agent calls, selected MCP operations, per-call approval, agent recipients, resource bounds, remote MCP/OAuth and the built-in gh source. | [Capabilities contract](capabilities-contract.md); slim capabilities suite. |
| Conversations | Persistent multi-party conversations among people and agents: membership, invitations, catch-up, bounded session context, per-author rates, and a must-route lead (C1 to C7). | [Conversations contract](conversations-contract.md); slim conversations suites. |
| Runtime tasks | Running a command in a microVM on a peer host's [runtime](https://github.com/peerspan/runtime), from an archive of the working tree or a named PeerFS workspace, authorized by the receiving owner's runtime rule ([#114](https://github.com/peerspan/peerspan/pull/114)). | [Runtime task contract](runtime-task-contract.md), RUN-1 to RUN-7; slim runtime suites against a fake runtime, in the second conformance tier ([#145](https://github.com/peerspan/peerspan/pull/145)). |
| Host and integrations | Rust daemon/CLI, guided setup and diagnostics, Claude Code, Codex and OpenCode adapters, and the native Claude Code onboarding frontend shipped in the bundles. | [Host contract](host-service-contract.md), [guided session contract](guided-session-contract.md), [quick start](quick-start.md); slim basics and guided suites, and installed acceptance ([DEC-OWN18](decision-log.md#dec-own18-installed-acceptance-runs-locally-2026-11-03)). |
| Install | `curl -fsSL https://peerspan.dev/install \| bash`: a manifest signed with the owner's offline Ed25519 key, checked before anything is installed; no `gh` or GitHub account. | [Install contract](install-contract.md), INST-1 to INST-8. |

Rust is the host implementation packaged here. The Go implementation is maintained separately at [peerspan/peerspan-go](https://github.com/peerspan/peerspan-go) (DEC-OWN5 and DEC-OWN8). Native Linux amd64 and arm64 bundles are the preview targets; macOS and Windows have not completed equivalent validation.

The coordinator product and in-place migration are retired (DEC-OWN2 and DEC-OWN3). Existing old networks remain read-only history; membership is moved by creating a new network and inviting its members again. Hosted-coordinator operations and Go/Rust pairing matrices are historical milestones, not remaining launch gates.

## Preview closeout

Automatic renewal through delegated administrators without the root seed, original-key and external-root SSH-agent renewal, and explicit combined owner/root approval are implemented in [PR #34](https://github.com/peerspan/peerspan/pull/34), with independent contract-derived renewal and join cases. The normative behavior is in spec sections 7.1, 7.3 and 8.2. The preview still needs the installed and live qualification below.

Each network still needs its root authority available often enough to renew administrator grants. Ordinary work uses locally verified grants until their deadlines or a known restriction stops it. Automatic renewal does not revive expired authority.

## Release qualification

Complete these checks at one recorded source revision before publishing the preview:

1. Run the Rust checks and both conformance tiers, per-push and full ([DEC-OWN15](decision-log.md#dec-own14-to-dec-own17-a-budget-for-the-conformance-suites-2026-11-03)). Record actual failures and fixes; suite success is evidence for the exercised cases.
2. Build native Linux amd64 and arm64 host/helper bundles with checksums and matching, clean-source RELEASE.json metadata. Run installed-bundle and packaging checks.
3. Install the candidate on clean Linux machines. Follow the quick start for one person linking a second machine and for two owners joining separately; record prompts, next steps and installation or recovery failures.
4. Run useful work in real agent sessions on separate machines: message/reply, a tracked task with input and result artifacts, progress/cancellation, a bounded shared capability, and withdrawal of access to new work. Check model-produced output separately from adapter readiness.
5. Exercise direct participant connectivity with helpers disabled and restrictive-network connectivity through an independently configured helper. Record topology, direct/relay observations, helper replacement, daemon restart, and offline catch-up within valid authority.
6. Sign the qualified draft and check the signed candidate before publication: the release key lists in the tagged `scripts/install.sh` and the draft's `install-release.sh` equal the latest key decision, `scripts/sign-release.sh` signs `release.json`, and `install-release.sh VERSION --from DIRECTORY` installs the signed candidate on clean Debian 12, Ubuntu 22.04 and Ubuntu 24.04 machines, amd64 and arm64, with no `gh` installed ([release procedure](releasing.md#before-publication)).
7. Publish the verified preview artifacts and installer as a full release, with their source revision, tested platforms, actual acceptance evidence and remaining limits.
8. After publication, check that `https://peerspan.dev/install` is byte-identical to the tagged `scripts/install.sh` with the decided keys, and run the real one-liner, as `latest` and with `--version`, on a clean machine per architecture with no `gh` installed. A failure marks the release as a prerelease straight away ([after publication](releasing.md#after-publication)).

The [release procedure](releasing.md) defines package review and publication. The [manual acceptance guide](manual-agent-testing.md) defines the real-session evidence to record. Older results under docs/results remain historical and do not qualify a new source revision.

## Following product work

- **PeerFS host integration** ([plan](peerfs-host-contract.md)): registering local PeerFS spaces and signing commits is in review ([#123](https://github.com/peerspan/peerspan/pull/123)); filesystem routes and sharing commands follow, each with its own contract and conformance.
- **Peerboxes** ([proposal](peerbox-proposal.md), [contract](peerbox-contract.md), PBX-1 to PBX-8): a repository one owner's host serves to known peers for fetching, contributing and running checks, with owner review. Specified; not implemented. Gates, an optional evaluator that promotes contributions by a measured result, are accepted ([proposal](peerbox-gate-proposal.md), PBX-9 to PBX-15) and await a contract amendment.
- **macOS** bundles and installer validation.
- **Bundled Node.js and Peerspan's own release verifier** for 0.2.1 ([#170](https://github.com/peerspan/peerspan/issues/170), [INST-9 to INST-11](decision-log.md#inst-9-to-inst-11-bundled-nodejs-and-our-own-release-verifier-2026-11-10)). 0.2.0 qualification showed Node.js 22 blocking the one-liner on clean machines, so the install path will no longer need Node.js ([install contract](install-contract.md#bundled-nodejs)).
- Broader agent/platform support and onboarding improvements follow observed preview friction. Claims about new adapters or platforms require their own live validation.
