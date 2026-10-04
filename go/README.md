# Go agent host service

This directory contains the Go implementation of Capsule's host service. The Rust implementation is alongside it in [../rust](../rust/README.md). Both follow the [shared contract](../docs/host-service-contract.md) and repository-level conformance tests.

## Source structure

```text
go/
├── go.mod                 Module and dependency requirements
├── go.sum                 Dependency checksums
├── cmd/capsule-host/      Executable and owner-local CLI
└── internal/host/         Identity, persistent registry, API, client, lifecycle
```

There are no empty packages for future transport or runtime features. The service currently manages local identity and registry metadata; actual agent integrations, peer operations, and runtime execution are subsequent work.

## Build and verify

From the repository root:

```bash
go -C go build -o /tmp/capsule-host-go ./cmd/capsule-host
go -C go test -race ./internal/host ./cmd/capsule-host
go -C go vet ./internal/host ./cmd/capsule-host
python3 conformance/host_service.py --go /tmp/capsule-host-go
```

Run `/tmp/capsule-host-go --state /tmp/capsule-go-state serve` and use the CLI commands in the [repository guide](../README.md). The local Unix socket is an owner administration interface, not a peer API. Owner labels and capability metadata do not establish network access.
