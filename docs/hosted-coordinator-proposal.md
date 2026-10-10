# Hosted coordinator: operations and coordinator moves

Status: proposed; decisions settled with the owner on 2026-10-09 and 2026-10-10 (see [Decisions](#decisions)). This is roadmap milestone 8. Nothing here is implemented yet. It follows milestone 7, whose release bundles default to a hosted `capsule-coord` that does not yet exist.

## Problem

Release bundles name one hosted coordinator, and every network created with them depends on it:
- **Pinned for life.** A host stores its network's `coordinator_address` and `coordinator_public_key` at create or join, and nothing changes them afterwards. A new domain, a lost key, or a leaked key strands every network on the coordinator. The only remedy is to create the network again.
- **No way to move a network.** The coordinator verifies and stores every signed statement, but no command imports or exports a network.
- **Not operable.** `capsule-coord` logs one line at startup and has no health check, metrics, backup command, or restore procedure. Its private key lives inside `coord.db`, so losing the database also loses the key.

The coordinator is trusted for availability only ([coordination contract](coordination-contract.md)). It cannot admit hosts or change access. That keeps the stakes of operating it low, but its availability is now everyone's availability.

## Goals and non-goals

**Goals:**
- Run one hosted coordinator on one cloud VM, with continuous encrypted backups, a tested restore, health checks, metrics, and logs.
- Let the operator move every hosted network to a new address or key without action by each administrator.
- Let an administrator move one network to another coordinator, including from the hosted coordinator to a self-hosted one and back.
- Keep every existing network working across an upgrade, a restore, and a move.

**Non-goals:**
- High availability or multiple active coordinators. A restart or restore means a short outage. Hosts already keep working on their stored maps and retry syncs.
- Accounts, billing, or a web console.
- Moving a network's members, policies, or keys between networks. A move changes only where the network is coordinated.

## Operations

`capsule-coord` gains what one VM needs:
- **Ops listener.** `run --ops-listen 127.0.0.1:PORT` serves `GET /healthz` and Prometheus `GET /metrics` over plain HTTP, separate from the coordination port. The metrics cover networks, member hosts, connected relay hosts, syncs and their errors, relay bytes, limit refusals, and request latency. They carry no network or host IDs as labels.
- **Logs.** One JSON line per request and per relay connection on stderr: time, route, status, duration, and network and host IDs where known. No statement contents, keys, invite tokens, message or relay payloads. Source IP addresses are not logged; the registration cap keeps its own counts.
- **Backup.** `capsule-coord backup FILE` writes a consistent copy of the database while the coordinator runs (SQLite `VACUUM INTO`), mode 0600. The copy includes the private key. Restoring is stopping the service, replacing `coord.db`, and starting it.
- **Deployment files** in `deploy/coordinator/`: a hardened systemd unit, a Litestream configuration that replicates `coord.db` continuously to object storage, and a runbook. The runbook covers provisioning, the firewall (TCP and UDP on one port, ops port loopback only), upgrades, a restore drill, monitoring alerts, and the response to a leaked key.

**Key custody.** The key stays in `coord.db` on the VM's disk. Litestream replicas are encrypted and the bucket is private. The owner also keeps an offline encrypted copy of a `backup` file, refreshed after each key change.

## Coordinator moves

A network's pinned coordinator can change in two ways, both signed. Hosts verify the signature, switch only after the new coordinator answers a sync for the network, and keep the previous pin until then.

**Successor (operator).** The current coordinator key signs a successor naming a new address, a new key, or both, with a sequence number. It covers every network on that coordinator at once.
- The coordinator serves the chain of successors from the identity a host reached to the latest one, with every sync and join.
- A coordinator can listen on several addresses, each presenting one of its identities, so the old address and key keep serving until every host has moved. Metrics show how many hosts still use each.
- A successor grants nothing beyond availability. Whoever holds a leaked key could already deny service, and it gains no say over membership or access.

**Move (administrator).** The network root or a delegated administrator signs a move naming the network, a new address and key, and a sequence number. The signer's host:
1. imports the network into the new coordinator, sending the signed statements it holds (the chain, memberships, revocations, rotations, admins, groups, persons, bindings, and policies), each verified as on submission;
2. submits the move to the old coordinator, if it is reachable, which then serves it on sync;
3. pushes the move directly to every member host it can reach.

Hosts also answer a peer route with the move they hold, so a host whose coordinator is unreachable can learn it from any peer it reaches directly. A signed move always takes precedence: successors apply only on top of the coordinator the latest move names. Invites issued before a move name the old coordinator; while it still runs, joins with them succeed there and the new member follows the move like any other host.

**Repair.** Every statement is signed and verified, so any member host that finds a coordinator missing something it holds (after a restore, or after a move) re-submits it through the same import. Repair needs no administrator online.

## Slices

Each slice is implemented with shared conformance written from the contract by an independent author. Coordinator-only slices are Go, since `capsule-coord` is Go-only; host behavior is implemented in Go and Rust.
1. **Operations:** the ops listener, logs, `backup`, the deployment files and runbook, and a restore drill in conformance: back up while serving, restore, and every host keeps working.
2. **Successors:** coordinator identities and multiple listeners, the signed successor, and hosts following it, across Go and Rust hosts.
3. **Administrator moves and repair:** import, the signed move, peer distribution, precedence over successors, a move from a stopped coordinator, and members re-submitting what a coordinator lacks.
4. **Launch:** provision the hosted instance, build release bundles with its address and key, and run the [launch acceptance](launch-contract.md) and a live run against it.

## Decisions

Settled with the owner on 2026-10-09:
- **Hosting:** Cerebral Systems runs one `capsule-coord` on one cloud VM with a static address, as a systemd service.
- **Moves:** a coordinator move is part of this milestone.
- **Custody:** key on disk in the database, continuous encrypted backups, and an offline encrypted copy held by the owner, with a tested restore.
- **Visibility:** a loopback health and metrics endpoint, and structured logs without payloads or keys.

Settled with the owner on 2026-10-10:
- **Move authority:** both. The operator's coordinator-signed successor moves every hosted network; a move signed by the network root or a delegated administrator moves one network and always takes precedence.
- **Repair:** any member host re-submits signed statements a coordinator lacks, with no administrator needed.

## Open

- The cloud provider, region, object storage, and the hosted coordinator's DNS name (needed by slice 4).
- How long the old address keeps serving after a successor (proposed: until metrics show no hosts on it for 30 days).
