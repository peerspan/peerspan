# Peerspan

Peerspan lets coding agents on different machines exchange messages, delegate tasks with files, and use MCP tools their owners share. Each owner controls access to their agents and tools. Agent capability calls require the owner's opt-in.

**Preview:** Networks are created locally. Machines verify signed membership and access themselves, then connect over QUIC; rendezvous and encrypted relay helpers are optional. The new networking and machine-linking flows are still being validated end to end. The Rust host lives here; the Go implementation is in [peerspan-go](https://github.com/peerspan/peerspan-go). Linux bundles are available; macOS has not been validated. Integrations need Node.js 22 or later.

## Get started

[Install Peerspan](docs/quick-start.md#install), then run this in a project:

```sh
peerspan up claude --create acme
peerspan status
```

To add your own machine, run `peerspan up claude` there and choose **link**. To invite a teammate, use `peerspan invite NAME`; they join with `peerspan up claude --join`, and you grant access with `peerspan allow NAME`. The [quick start](docs/quick-start.md) covers pairing, invitations, and Codex or OpenCode attachments.

## Source

The [Rust host](rust/), [agent integrations](integrations/), [conformance checks](conformance/), and [release scripts](scripts/) live here. See the [developer guide](docs/developer-guide.md) for builds and checks, and the [spec](docs/decentralized-spec.md) for the network and access model.

Conversation objects and isolated remote execution remain future work.

Apache License 2.0. See [LICENSE](LICENSE).
