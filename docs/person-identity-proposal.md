# Person identity, multiple administrators, and owner-managed access

Status: accepted; decisions settled on 2026-10-06 (see [Decisions](#decisions)). This is roadmap milestone 2b, and nothing here is implemented yet. The roles it builds on are in the [access model](access-model.md): administrators control membership, and owners control access to their own agents. Where the original proposal and the decisions differ, the decisions apply. The sections below are updated to match.

## Problem

Today a network knows only hosts. That leaves three gaps:

- **One administrator key.** The network root key lives on one host. Nobody else can admit or remove members, and losing that host loses administration.
- **Per-host access toil.** A grant names one requester host ID. Bob with three laptops needs three grants from every owner who shares with him, and each new machine needs new grants everywhere.
- **No notion of an owner across machines.** "Bob's agents" means nothing to the system. Each host's owner label is unverified text.

The design must fix these without letting an administrator decide access to agents it does not own. It must also keep the property Tailscale is liked for: policy is managed in one place, not edited on every machine.

## Goals and non-goals

**Goals:**
- A verifiable identity for a person that spans their hosts.
- Several administrators.
- People who bind their own already-admitted machines to themselves, without an extra administrator step.
- Access policy written once by its owner, granting to people and groups, distributed by coordination, and enforced by each of the owner's hosts.

**Non-goals for 2b:**
- Per-agent requester identity and multi-hop delegation provenance. Requests stay authenticated as hosts, and a host acts for its owning person. This is roadmap milestone 6, sequenced with task delegation.
- Network-wide guardrails written by administrators.
- A dashboard. The CLI comes first; a dashboard is another client of the same signed statements.
- Hardware security keys (`sk-ssh-ed25519`). Person keys are software `ssh-ed25519` keys.

## Concepts

| Concept | Key | Holds authority over |
| --- | --- | --- |
| **Network authority** | the network root key (exists today) | Which persons are administrators; root rotation |
| **Administrator** | a person key the root has delegated to | Which hosts and persons are members; groups; revoking members |
| **Person** | a person key, separate from any host key | Their own hosts, and access to their own agents |
| **Host** | the existing host key | Enforcing its owner's policy for its local agents |

The resulting chain of authority:

```text
network root ──delegates──▶ administrator (person key)
administrator ──admits──▶ host (host key)          [as today]
administrator ──admits──▶ person (person key, member label)
person + host ──bind──▶ host belongs to person
person ──signs──▶ access policy ──enforced by──▶ that person's hosts
```

Administrators admit both hosts and persons. Admitting hosts stays as today: every machine is approved by an administrator. Persons are an optional layer on top. A person binds hosts that are already admitted, by signing the binding, and the host itself submits it. Binding needs no further administrator step, and a new laptop needs no new grants from anyone once it is bound. Removing a person unbinds all of their hosts, which return to being unowned members.

## Person keys

A person key is an existing OpenSSH `ssh-ed25519` key, separate from every host key.

- **Signing:** through `ssh-agent` (`SSH_AUTH_SOCK`), using OpenSSH's `SSHSIG` signature format, so the private key stays in the agent. `--person-key PATH` signs with an OpenSSH private-key file instead, for CI and servers without an agent, in the same `SSHSIG` format.
- **Key type:** only `ssh-ed25519`. Hardware security keys (`sk-ssh-ed25519@openssh.com`) are out of scope: they need a physical touch per signature, which conflicts with automatic policy re-signing.
- **Daemons never hold person keys.** The CLI signs and hands signed statements to the local daemon for submission.
- **Person ID:** `person_` followed by the lowercase hex SHA-256 of the 32-byte Ed25519 public key, by analogy with host IDs.
- **Joining:** a person is admitted either from their public key, sent to an administrator out of band, which returns a non-secret network descriptor; or by redeeming a one-time person invite token. Hosts gain the same two paths: today's one-time invite, or an administrator admitting a host's public key directly.

Losing a person key does not lose the person's hosts' identities. An administrator admits a replacement key under the same member label, and the person rebinds their hosts with it.

## Signed statements

All use the existing encoding rules: lines joined by `\n`, no trailing newline, canonical Base64 keys, RFC3339 times. Exact line formats and test vectors go in the contract once this proposal is accepted.

| Statement | Signed by | Says |
| --- | --- | --- |
| Admin delegation / revocation | current network root | Person key P is, or is no longer, an administrator |
| Person admission / removal | an administrator | Person key P is a member, labeled `alice`, or is removed |
| Group definition | an administrator | Group `backend` has members {P1, P2, …} (version N) |
| Host binding / unbinding | the person | Host key H belongs to person P, or no longer does |
| Access policy | the person | Policy version N for P's agents (rules below) |

Coordination distributes these with the network map, as it does membership chains today. It can withhold them but cannot forge them. The existing invite chain (root → invite → host) keeps working for hosts without a person: see Migration.

**Monotonicity.** Group definitions and access policies carry a version. Hosts persist the highest version they have verified and never accept a lower one, so a coordinator cannot roll a policy back. A coordinator can still **withhold** a newer version; Policy freshness below addresses that. Removals and unbindings are sticky, as revocations are in 2a.

## Access policy

An owner's policy is a list of rules, each answering "who may do what to which of my agents, within what bounds":

```json
{
  "person_id": "person_…",
  "version": 7,
  "issued_at": "2026-10-10T12:00:00Z",
  "valid_until": "2026-10-17T12:00:00Z",
  "rules": [
    { "agents": ["reviewer"], "principals": ["person:alice", "group:backend"],
      "actions": ["message.append"], "max_message_bytes": 65536, "allow_disconnected": false },
    { "agents": ["triage"], "principals": ["network:net_…"],
      "actions": ["message.append"], "max_message_bytes": 4096 }
  ]
}
```

- **Agents** are named by agent name on any of the owner's hosts. The same name on two hosts means either may serve. Session selection stays a host decision, as today.
- **Principals** are `person:LABEL` (resolved to the admitted person key), `group:NAME` (resolved through the administrator's group definition), or `network:ID` (every member).
- **Actions** are `message.append` today. Tasks and remote tools add actions later, under the same rule shape.
- **Bounds** match today's grant fields: message size, `allow_disconnected`, and the policy's own `valid_until`.

**Enforcement.** A receiving host authenticates the requesting **host**, as today. It resolves that host to its bound person, then evaluates the agent owner's current verified policy, alongside any manual grants. The existing per-request checks stay: revocation, freshness, and the connected state. Manual host-scoped grants remain for networks without persons and for exceptions.

**Requests address policy, not grant IDs.** A request today names a `grant_id`. A policy-authorized request instead names the policy owner and version it relies on, and the receiver checks against its own newest verified copy. The precise wire change is a contract decision.

## Policy freshness

Persisted versions prevent rollback but not withholding. A coordinator, or a network partition, could keep a host on an older policy that still grants access the owner has since withdrawn. Three layers bound this:

1. **Local revocation always works.** On any of their hosts, the owner can still revoke access immediately and without coordination. That host enforces it at once.
2. **Short policy validity.** A policy carries `valid_until`, chosen by its owner between 1 and 90 days, with a default of 7. After that its rules stop granting access. It is re-signed automatically before expiry while the owner's `ssh-agent` (via an agent socket the owner configures for their daemon) or key file is available. The daemon requests a signature and never stores the key. If no signature is available, access lapses, which fails closed.
3. **Direct propagation.** An owner's own hosts forward a newer policy to each other over the peer transport, so withholding requires partitioning those hosts too, not only the coordinator.

Layer 2 bounds disconnected operation: policy-derived access works without coordination only if its rule sets `allow_disconnected`, and only until `valid_until`. Manual host grants keep their own lifetimes, as today.

## Security analysis

| Compromised | Can | Cannot |
| --- | --- | --- |
| Coordinator | Withhold statements and policies, up to their validity; deny service | Admit people or hosts; forge or roll back policy; read traffic |
| One host | Act as its owning person toward peers, as any host can today | Sign policy or bind other hosts, unless the person key is on it |
| A person key | Change that person's access policy; bind already-admitted hosts that also consent, which in practice means hosts the attacker controls | Bind other people's hosts without their consent; affect other persons' agents; admit members |
| An administrator key | Admit or remove persons; define groups | Grant access to any agent it does not own; touch host state |
| Network root | Delegate or revoke administrators; rotate the root | Grant access to agents. Recovery is root rotation, as in 2a. |

The most important row is the administrator: under this design, even a malicious administrator gains no access to members' agents. It could add a fake person to a group that owners already grant to, so groups trade convenience for that indirect power. Owners who want to avoid it grant to persons instead of groups.

## Migration

- **Networks without persons** keep working unchanged: host invites, host-scoped manual grants, and the root as the single administrator.
- **Adopting persons:** the root delegates the first administrator, which is usually the root holder's own person key. Members' persons are admitted, and each person binds their already-admitted hosts.
- **Unbound hosts** remain full members. They match the `network:` principal and manual grants, but no `person:` or `group:` principal. Administrators keep admitting hosts as before.

## Delivery

1. **Person keys and host binding:**
   - CLI key management and the person admission and host-binding statements;
   - coordinator distribution;
   - hosts resolving requester host → person;
   - `network members` showing persons.
2. **Multiple administrators:** root delegation and revocation of administrators, administrator-signed admission and removal, and groups.
3. **Owner access policy:**
   - signing, versioning, validity, and distribution;
   - enforcement next to manual grants;
   - direct propagation among an owner's hosts;
   - the wire change from grant IDs.

Each slice ships in both host implementations with shared conformance. Like the earlier contracts, it includes adversarial checks: a withheld or rolled-back policy, a malicious administrator adding a fake member, and a stolen host without the person key.

## Decisions

Settled on 2026-10-06. These replace the original recommendations wherever they differ.

| # | Decision | Agreed |
| --- | --- | --- |
| 1 | Person keys | `ssh-ed25519` only, signed in OpenSSH `SSHSIG` format through `ssh-agent`. `--person-key PATH` falls back to an OpenSSH private-key file in the same format. Hardware security keys are out of scope. |
| 2 | What administrators admit | Hosts, as today. Persons are an optional layer that administrators also admit. |
| 3 | Join flows | For persons and hosts alike: a one-time invite token, or an administrator admitting a public key directly, plus a non-secret network descriptor. |
| 4 | Host binding | Valid with the person's signature and the host's own submission; no administrator step. |
| 5 | Rotation and removal | A root rotation re-signs person admissions; bound hosts need nothing. Person removal and host unbinding are signed, sticky, and permanent, like milestone 2a revocations. |
| 6 | Groups | Defined and versioned by administrators. Owners choose whether to grant to a group or to named persons. |
| 7 | Policy validity | Chosen by the owner per policy, 1–90 days, default 7. Re-signed automatically while the owner's agent or key file is available. |
| 8 | Disconnected use | A policy rule needs `allow_disconnected`, and ends at `valid_until`. Manual host grants are unchanged. |
| 9 | Request authorization | A request names the policy owner and version, and the receiver checks against its newest verified copy. |
| 10 | Root key after delegation | Kept offline, used only to delegate or revoke administrators and to rotate. |
