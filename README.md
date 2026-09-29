# capsule

`capsule` is a CLI for creating and managing agent capsules. A capsule is an isolated workspace for an agent task, with a recorded runtime, network name, authority, and audit trail.

## Requirements

Go 1.25 or later.

## Usage

```bash
go run ./cmd/capsule create --task "Fix issue 418" --repo https://github.com/example/app --capability github:pull_request:write
go run ./cmd/capsule list
go run ./cmd/capsule inspect <capsule-id>
go run ./cmd/capsule destroy <capsule-id>
```

`create` requires `--task`. Repeat `--capability` and `--secret` to attach more than one. Records are stored as JSON files in `.capsules/` in the current directory.

## Development

```bash
go test ./...
go run ./cmd/capsule --help
```
