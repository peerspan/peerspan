# Person identity, multiple administrators, and owner-managed access

Status: proposal for review (roadmap milestone 2b). Nothing here is implemented. The roles it builds on are in the [access model](access-model.md): administrators control membership, and owners control access to their own agents. The decisions to settle are listed under [Decisions to settle](#decisions-to-settle).

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
- People who add and remove their own machines without administrator involvement.
- Access policy written once by its owner, granting to people and groups, distributed by coordination, and enforced by each of the owner's hosts.

**Non-goals for 2b:**
- Per-agent requester identity and multi-hop delegation provenance. Requests stay authenticated as hosts; a host acts for its owning person.
- Network-wide guardrails written by administrators.
- A dashboard. The CLI comes first; a dashboard is another client of the same signed statements.
- Hardware-backed keys. This proposal recommends leaving room for them.

## Concepts

| Concept | Key | Holds authority over |
| --- | --- | --- |
| **Network authority** | the network root key (exists today) | Which persons are administrators; root rotation |
| **Administrator** | a person key the root has delegated to | Which persons are members; groups; revoking members |
| **Person** | a person key, separate from any host key | Their own hosts, and access to their own agents |
| **Host** | the existing host key | Enforcing its owner's policy for its local agents |

The resulting chain of authority:

```text
network root ──delegates──▶ administrator (person key)
administrator ──admits──▶ person (person key, member label)
person ──binds──▶ host (host key)
person ──signs──▶ access policy ──enforced by──▶ that person's hosts
```

Administrators admit people, not machines. A person binds and unbinds their own hosts, so a new laptop needs no administrator and no new grants from anyone. Removing a person removes all of their hosts.

## Person keys

A person key is an Ed25519 key that is separate from every host key.

- **Recommended:** a person key file at `$XDG_CONFIG_HOME/capsule/person.key`, mode 0600, outside host state directories. It is used by the CLI, not held by a daemon. The CLI signs locally and hands signed statements to the local daemon for submission. A host compromise then does not automatically yield the person key, unless the attacker controls the same OS account and the file is present.
- **Recommended follow-up:** signing through `ssh-agent` with an existing Ed25519 SSH key (OpenSSH `SSHSIG`). Most developers already have one, and agent-held or hardware-backed keys then work without new tooling.
- **Person ID:** `person_` followed by the lowercase hex SHA-256 of the public key, by analogy with host IDs.

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
2. **Short policy validity.** A policy carries `valid_until`, recommended at 7 days. After that its rules stop granting access. The owner's CLI or daemon re-signs before expiry. If the person key is not available to re-sign, access lapses, which fails closed.
3. **Direct propagation.** An owner's own hosts forward a newer policy to each other over the peer transport, so withholding requires partitioning those hosts too, not only the coordinator.

Layer 2 interacts with disconnected operation. A grant that allows disconnected use is meant to outlive coordination outages; under policy, that outage tolerance is bounded by `valid_until`. This trade-off needs a decision (see below).

## Security analysis

| Compromised | Can | Cannot |
| --- | --- | --- |
| Coordinator | Withhold statements and policies, up to their validity; deny service | Admit people or hosts; forge or roll back policy; read traffic |
| One host | Act as its owning person toward peers, as any host can today | Sign policy or bind other hosts, unless the person key is on it |
| A person key | Bind hosts as that person; change that person's access policy | Affect other persons' agents; admit members |
| An administrator key | Admit or remove persons; define groups | Grant access to any agent it does not own; touch host state |
| Network root | Delegate or revoke administrators; rotate the root | Grant access to agents. Recovery is root rotation, as in 2a. |

The most important row is the administrator: under this design, even a malicious administrator gains no access to members' agents. It could add a fake person to a group that owners already grant to, so groups trade convenience for that indirect power. Owners who want to avoid it grant to persons instead of groups.

## Migration

- **Networks without persons** keep working unchanged: host invites, host-scoped manual grants, and the root as the single administrator.
- **Adopting persons:** the root delegates the first administrator, which is usually the root holder's own person key. Members create person keys and are admitted. Each existing host is bound by its person.
- **Unbound hosts:** a host with no person binding can still be granted to manually, but it matches no person, group, or network principal in owner policies. Host invites can be disabled per network once all members have persons.

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

## Decisions to settle

| Decision | Recommendation | Alternatives |
| --- | --- | --- |
| Where person keys live | CLI-held key file outside host state; `ssh-agent` signing as a follow-up | Held by one designated host daemon; hardware keys from the start |
| What administrators admit | Persons, who then bind their own hosts | Keep admitting hosts, with persons optional on top |
| Groups | Administrator-defined, versioned; owners choose whether to grant to groups | Owner-defined groups only (no administrator influence on access at all, more toil) |
| Policy validity | 7 days, re-signed automatically while the person key is available | Longer (more outage tolerance, slower withdrawal); no expiry (rely on local revocation only) |
| Disconnected use under policy | Bounded by `valid_until` | Allow manual host grants to keep longer disconnected validity, as today |
| Request authorization on the wire | Request names policy owner and version | Keep `grant_id`, with policies materialized into local grants on each host |
| Root key after delegation | Recommended to be kept offline, used only to delegate administrators and rotate | Stays on the creator's host, as today |
