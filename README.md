# capsule

This repository contains the Go implementation of the agent host service. A Rust implementation is being developed alongside it in the provisional `capsule-rs` repository. Both follow the shared design and conformance suite in `mesh-new`; the implementation to release as OSS remains undecided.

## Host service foundation

The new host service owns a durable local identity, registered agents, session attachment records, and an activity log. It starts without coordination and exposes an owner-local HTTP API over a private Unix socket. It currently supports Unix platforms; validation has been run on Linux.

```bash
go build -o /tmp/capsule-host-go ./cmd/capsule-host
/tmp/capsule-host-go --state /tmp/capsule-go-state serve
```

From another terminal:

```bash
/tmp/capsule-host-go --state /tmp/capsule-go-state info
/tmp/capsule-host-go --state /tmp/capsule-go-state agent register --name bob --owner bob --capability conversation
/tmp/capsule-host-go --state /tmp/capsule-go-state agent list
/tmp/capsule-host-go --state /tmp/capsule-go-state session attach --agent AGENT_ID --integration test
/tmp/capsule-host-go --state /tmp/capsule-go-state session list
/tmp/capsule-host-go --state /tmp/capsule-go-state activity
```

Without `--state`, state lives in `$XDG_STATE_HOME/capsule/host` or `$HOME/.local/state/capsule/host`. Use separate explicit directories when running both implementations. An existing state directory must have private permissions (0700).

Agent identity survives service restarts. Session attachments become detached on restart and remain inspectable. An attachment is metadata only: this milestone does not connect a live Claude Code session or launch agent processes. Capability names and owner labels are metadata, not access grants or verified network identities. Peer networking, scoped sharing, the three collaboration operations, and runtime execution are subsequent milestones.

```text
cmd/capsule-host/    New host executable and owner-local CLI
internal/host/      Identity, persistent registry, API, client, daemon lifecycle
```

No empty packages are created for future features. Module boundaries can be separated as working functionality arrives.

### Verify the host service

```bash
go test -race ./internal/host ./cmd/capsule-host
go vet ./internal/host ./cmd/capsule-host
python3 ../mesh-new/conformance/host_service.py --go /tmp/capsule-host-go
```

The shared suite checks the running binary, including crash recovery, process exclusivity, concurrent duplicate registration, and atomic activity recording. Build both binaries to run it with both `--go` and `--rust`. `mesh-new/docs/host-service-contract.md` defines the initial common behavior.

## Earlier prototype

The following commands belong to the earlier prototype in `cmd/capsule` and the other `internal` packages. That code is retained during the rewrite and is separate from the new host service.

`capsule` is a CLI for creating and managing agent capsules. A capsule is an isolated workspace for an agent task, with a recorded runtime, network name, authority, and audit trail.

## Requirements

Go 1.26 or later.

## Usage

```bash
go run ./cmd/capsule serve
go run ./cmd/capsule secret set staging-token
go run ./cmd/capsule create --task "Fix issue 418" --repo https://github.com/example/app --capability github:pull_request:write --secret staging-token
go run ./cmd/capsule list
go run ./cmd/capsule inspect <capsule-id>
go run ./cmd/capsule exec <capsule-id> -- go test ./...
go run ./cmd/capsule destroy <capsule-id>
go run ./cmd/capsule session create --capsule <id> --task "staging failure" --allow logs/failure.txt
go run ./cmd/capsule session accept <session-id> --capsule <other-id>
go run ./cmd/capsule session message <session-id> --from <id> --text "here is the failure"
go run ./cmd/capsule session share <session-id> --from <id> --path logs/failure.txt
go run ./cmd/capsule session export <session-id>
```

`serve` hosts the control plane on `127.0.0.1:8077` and stores records in `.capsules/`. Other commands call that process. Set `CAPSULE_ADDR` to point at a different server. `create` requires `--task`. It starts a workcell in its own mount, process, and network namespaces. Inside the workcell the workspace is `/workspace`, and the host copy is `.capsules/<id>/workspace`. The workcell does not see the rest of the host filesystem or the host network. `create --runtime microvm` starts a Firecracker microVM instead. `serve --firecracker` and `serve --kernel` point at the VMM and the guest kernel; `CAPSULE_FIRECRACKER` and `CAPSULE_KERNEL` are the same paths when the flags are omitted. The guest workspace is `/workspace`, and the host copy is still `.capsules/<id>/workspace`. `--secret` is mounted read-only at `/run/secrets/<name>`. A session does not connect microVMs. `session accept` connects the two workcells so each can reach the other by its `<id>.capsule.local` name. That path is removed when the session is revoked or expires. When `--repo` is set, that directory is a git clone of the repository. When `--setup` is set, that shell command runs in the workspace before the process starts. `exec` runs a command there and records the exit code. `destroy` stops the process. Repeat `--capability` and `--secret` to attach more than one. `secret set` reads a value from stdin and stores it in `.capsules/secrets/` on the host. `--secret` mounts that file read-only at `/run/secrets/<name>` inside the workcell. The value is not written into the workspace, the capsule record, command logs, or the evidence bundle. A share whose file contains a secret value is refused. Capsule and session records are in `.capsules/capsule.db`. Process output is appended to `.capsules/<id>/process.log`. Each `exec` writes `.capsules/<id>/commands/NNNN.log`. When the workspace changes, it also writes `NNNN.diff` beside that log. The evidence bundle lists the paths that changed. The patch stays on the host. `session` opens a peering session between two running capsules. A share must be an allowlisted path, and the capsule must have the `share` capability. `share:approval-required` waits for `session approve` before the file is copied. `exec` requires the `exec` capability. During a session the command must also be listed with `--allow-exec`. `session export` prints the evidence bundle and writes it to `.capsules/sessions/<id>/evidence.json`. The bundle lists participants, their capabilities and allowlists, approvals, the transcript, artifact hashes, commands run in either capsule during the session, and the time the session expired or was revoked.

## Development

```bash
go test ./...
go run ./cmd/capsule --help
```

`go test ./demo` runs `demo/peering.sh` and checks the evidence bundle from that run. It needs root, the same as the workcell tests.
