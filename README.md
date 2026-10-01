# capsule

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

`serve` hosts the control plane on `127.0.0.1:8077` and stores records in `.capsules/`. Other commands call that process. Set `CAPSULE_ADDR` to point at a different server. `create` requires `--task`. It starts a workcell in its own mount, process, and network namespaces. Inside the workcell the workspace is `/workspace`, and the host copy is `.capsules/<id>/workspace`. The workcell does not see the rest of the host filesystem or the host network. `session accept` connects the two workcells so each can reach the other by its `<id>.capsule.local` name. That path is removed when the session is revoked or expires. When `--repo` is set, that directory is a git clone of the repository. When `--setup` is set, that shell command runs in the workspace before the process starts. `exec` runs a command there and records the exit code. `destroy` stops the process. Repeat `--capability` and `--secret` to attach more than one. `secret set` reads a value from stdin and stores it in `.capsules/secrets/` on the host. `--secret` mounts that file read-only at `/run/secrets/<name>` inside the workcell. The value is not written into the workspace, the capsule record, command logs, or the evidence bundle. A share whose file contains a secret value is refused. Capsule and session records are in `.capsules/capsule.db`. Process output is appended to `.capsules/<id>/process.log`. Each `exec` writes `.capsules/<id>/commands/NNNN.log`. `session` opens a peering session between two running capsules. A share must be an allowlisted path, and the capsule must have the `share` capability. `share:approval-required` waits for `session approve` before the file is copied. `exec` requires the `exec` capability. During a session the command must also be listed with `--allow-exec`. `session export` prints the evidence bundle and writes it to `.capsules/sessions/<id>/evidence.json`. The bundle lists participants, their capabilities and allowlists, approvals, the transcript, artifact hashes, commands run in either capsule during the session, and the time the session expired or was revoked.

## Development

```bash
go test ./...
go run ./cmd/capsule --help
```

`go test ./demo` runs `demo/peering.sh` and checks the evidence bundle from that run. It needs root, the same as the workcell tests.
