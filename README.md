# capsule

`capsule` is a CLI for creating and managing agent capsules. A capsule is an isolated workspace for an agent task, with a recorded runtime, network name, authority, and audit trail.

## Requirements

Go 1.25 or later.

## Usage

```bash
go run ./cmd/capsule serve
go run ./cmd/capsule create --task "Fix issue 418" --repo https://github.com/example/app --capability github:pull_request:write
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

`serve` hosts the control plane on `127.0.0.1:8077` and stores records in `.capsules/`. Other commands call that process. Set `CAPSULE_ADDR` to point at a different server. `create` requires `--task`. It starts a local process whose working directory is `.capsules/<id>/workspace` on the server. When `--repo` is set, that directory is a git clone of the repository. When `--setup` is set, that shell command runs in the workspace before the process starts. `exec` runs a command there and records the exit code. `destroy` stops the process. Repeat `--capability` and `--secret` to attach more than one. The capsule record is `.capsules/<id>/record.json`. Process output is appended to `.capsules/<id>/process.log`. Each `exec` writes `.capsules/<id>/commands/NNNN.log`. `session` opens a peering session between two running capsules. A share must be an allowlisted path, and the capsule must have the `share` capability. `share:approval-required` waits for `session approve` before the file is copied. `exec` requires the `exec` capability. During a session the command must also be listed with `--allow-exec`. `session export` prints the record.

## Development

```bash
go test ./...
go run ./cmd/capsule --help
```
