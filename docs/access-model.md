# Who controls what: membership, access, and administration

Status: decisions agreed on 2026-10-06. Each item below is marked **implemented** or **planned**. The sequence is in the [roadmap](production-roadmap.md).

Capsule keeps three things separate:

| Concept | Question it answers | Who decides |
| --- | --- | --- |
| **Membership** | Which hosts belong to this network? | The network administrator |
| **Ownership** | Who controls this host and its agents? | Whoever runs the host |
| **Access** | Who may use this agent, and within what bounds? | The agent's owner |

Being a member grants no access. Administering a network grants no access to anyone's agents.

## Roles

| Role | Can | Cannot |
| --- | --- | --- |
| **Network administrator** (holds the network root key) | Invite hosts and revoke membership (**implemented** for invites; signed revocation **planned**, milestone 2a). Rotate the root key (**planned**, 2a). Share administration with other administrators (**planned**, 2b). | Grant anyone access to an agent it does not own. Read or change agents, grants, messages, or other state on member hosts. |
| **Owner** (runs a host and its agents) | Decide who may use each of their agents, and within what bounds, for each direction separately (**implemented** as per-host grants). Withdraw access at any time, enforced locally even with coordination down (**implemented**). Leave a network (**planned**, 2a). | Grant itself access to someone else's agents. |
| **Coordination operator** (runs `capsule-coord`) | Distribute signed membership, addresses, and candidates. Relay already-encrypted traffic. Refuse service. | Add a host to a network: hosts verify every membership chain themselves. Read relayed traffic, or impersonate a host: peer TLS is end to end. Forge an owner's or administrator's signed statement. |

The receiving host enforces every access decision. Agent prompts are not an enforcement mechanism, and permission to message an agent does not imply permission to run commands or read files.

## Why the administrator does not decide access

In Tailscale, the administrator writes one access policy for the whole network. That works because a tailnet usually has one owner. A Capsule network often joins several developers, and each developer's agents act with that developer's local permissions on their own machine. If the administrator could grant access, the administrator would in effect control every member's agents. Members would have to trust the administrator with their machines just to join a shared network. Keeping access with each owner means joining a network is safe on its own terms. The administrator decides who is in; owners decide what each member may use.

## Central management without central authority (planned)

Deciding access per owner must not mean configuring every host separately. Tailscale is easy to use because policy is managed in one place, and Capsule keeps that property by separating where policy is **managed** from who **authorizes** it.

- **Person identity:** a person uses an existing SSH Ed25519 key, through `ssh-agent`, separate from their host keys. Administrators admit persons as well as hosts. A person binds their already-admitted hosts with that key, and each host consents. "Bob" is then one identity across all of Bob's machines. Administrator keys use the same identity, so milestone 2b can add multiple administrators. Decisions are in the [proposal](person-identity-proposal.md#decisions).
- **Grants to people and groups:** grants name members or groups ("member `alice` may message `reviewer`", "anyone in network `team` may message `triage`"), not individual host IDs. New or re-enrolled machines are covered without new grants.
- **Owner-signed policy, distributed centrally:** an owner edits their access policy once, from any of their machines or a future dashboard. The coordinator delivers it to all of that owner's hosts. Each host enforces it only if it carries that owner's signature. The administrator cannot author or alter it, and a coordinator can withhold it but not forge it.

The result is configured once, applies everywhere, and is authorized only by the owner. The design is in the [person identity proposal](person-identity-proposal.md), under review. Network-wide guardrails, where an administrator publishes restrictions that can only narrow access, remain a separate future decision. Each host would enforce them on itself, so they are only as strong as membership revocation.

## Membership revocation (planned, milestone 2a)

- **Signed:** the root key, or after 2b any administrator, signs a revocation of a host or an unused invite. A member can sign its own departure.
- **Sticky:** hosts persist revocations and keep enforcing them, even if a coordinator later omits them or serves an older map. A compromised or stale coordinator therefore cannot restore a revoked host.
- **Effect:** a revoked host is no longer a known peer through that network. It fails authentication and loses its relay access, unless an owner has configured it manually as a peer. Grants that name it stop working, because it can no longer authenticate.

## Uncertain outcomes (planned, milestone 5)

A send whose outcome is unknown, such as a lost response, is retried automatically with the same request ID until it is accepted, rejected, or past its deadline. This applies to owner sends and agent-initiated sends alike. Receivers deduplicate by request ID, so a retry never creates a second message or consumes another unit of a send budget. The sender still sees the request ID and its final state.
