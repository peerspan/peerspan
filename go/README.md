# Go agent host daemon

This directory contains the Go implementation of Capsule's host daemon. The Rust implementation is alongside it in [../rust](../rust/README.md). Both follow the [shared contract](../docs/host-service-contract.md) and repository-level conformance tests.

## Source structure

```text
go/
├── go.mod                     Module and dependency requirements
├── go.sum                     Dependency checksums
├── cmd/capsule-host/          Host executable and owner-local CLI
├── cmd/capsule-coord/         Coordination service executable
├── internal/host/             Identity, registry, peer transport, and network client
├── internal/coord/            Coordination service
├── internal/membership/       Signed invites, memberships, and tokens
└── internal/tlsid/            Host and coordinator certificates
```

The daemon owns local identity and registry state, known-host messaging on a separate authenticated interface, and a coordination client. `capsule-coord` is the coordination service both host implementations use. The shared [Claude channel adapter](../integrations/claude-channel/README.md) connects opted-in sessions, including scoped outbound sends and automatic replies. Membership revocation, the full collaboration operations, and runtime execution are subsequent work.

## Build and verify

From the repository root:

```bash
go -C go build -o /tmp/capsule-host-go ./cmd/capsule-host
go -C go build -o /tmp/capsule-coord ./cmd/capsule-coord
go -C go test -race ./internal/... ./cmd/...
go -C go vet ./internal/... ./cmd/...
python3 conformance/host_service.py --go /tmp/capsule-host-go
python3 conformance/peer_messaging.py --go /tmp/capsule-host-go
python3 conformance/coordination.py --go /tmp/capsule-host-go --coord /tmp/capsule-coord
```

Run `/tmp/capsule-host-go --state /tmp/capsule-go-state run` and use the CLI commands in the [repository guide](../README.md). The local Unix socket is an owner administration interface, not a peer API. Owner labels and capability metadata do not establish network access.
