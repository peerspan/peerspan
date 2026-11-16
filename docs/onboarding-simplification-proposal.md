# Onboarding simplification: the pane takes the CLI's steps

Status: draft for the owner's decision (2026-11-16). Nothing here is implemented.

## Problem

An early user set Peerspan up with his AI, through the guided onboarding pane (`/peerspan` in an existing Claude conversation). He reported that the UX felt clunky, and that setup took almost half an hour.

The hosts are not the slow part. A scripted run of the same teammate join through the CLI takes about 3.5 seconds of machine time end to end. That covers invite, join, admission, commit, access and a first message, on a release build with two hosts over loopback. Linking a second machine takes about 4.3 seconds. The longest single waits are the two-second background workers.

The time goes to the pane. It turns each stage of the join protocol into its own review, with its own buttons. Nothing moves forward until someone presses a Check button. The AI in the conversation can explain the steps but cannot take any of them, because "no model setup tool is added".

## What the pane asks today

Counted from [the pane's guide](../integrations/claude-onboarding/README.md) for one teammate joining a network, on the happy path only:

| Stage | Joining person | Inviting person |
|---|---|---|
| Attach the conversation | Connect this project → Review new agent → Approve attachment | the same |
| Adapter | Review adapter connection → Approve adapter → Connect adapter | the same |
| Invitation | Join a network → paste → Review joining identities → (Create a new original identity → Create and save identity) → Review identity → Approve join request | Invite someone → Review invitation → Approve invitation → Reveal private invitation |
| Owner | Review owner powers → Approve owner powers → Sign original owner offer | |
| Administrator | | Review incoming connections → Review administrator consent → Approve administrator consent |
| Finalization | Review original finalization → Sign original finalization | |
| Commit | Review requester commit → Approve requester commit → Complete requester commit | |
| Delivery | Enable incoming messages, Enable incoming tasks | Enable incoming messages, Enable incoming tasks |
| Access | | Review agent access → Review proposed grant → Approve agent access |
| Waiting | Check join progress, Check owner consent, Check original finalization, Check requester consent, each pressed until the other side has acted | Check administrator consent, Check agent access |

That is about 22 presses for the joining person and 18 for the inviter, with a dense review on most screens, plus every Check. Linking one's own second machine takes a similar number (Request to connect this computer, Approve another computer, Complete this computer's machine link).

The CLI does the same protocol in far fewer steps:
- the joining person runs one `join`, with two prompts: **Approve this exact machine?** and **Commit this exact machine link?**;
- the inviter runs `invite`, one `link admit` and one `allow`;
- the daemons carry every stage in between.

## Goal: the experience already accepted

[GU-OWN1](guided-session-onboarding.md#gu-own1-experience) accepted four steps: connect this project, invite someone or connect my other computer, each participant reviews identity and permissions in their own flow, and **Peerspan completes the intermediate steps**. The requirements add "Continue deterministic protocol work after the relevant exact approval". The pane as shipped asks for each intermediate step instead.

This proposal brings the pane back to that experience. It keeps the authority protocol unchanged: GU-OWN1 explicitly discards replacing it to get fewer visible steps.

## Proposal

Each item names the pane steps it replaces. In every merged review, the participant sees all the terms the separate reviews show today, on one screen.

### P1. One join review and one commit for the joining person

- **Join** replaces Review joining identities, Review identity, Approve join request, Review owner powers, Approve owner powers, Sign original owner offer, Review original finalization and Sign original finalization.
  - One review shows the network, inviter, chosen identity, this machine's keys, the requested powers and the expiry.
  - Its one approval publishes the request, signs the owner offer and, when the administrator's admission arrives, signs the owner finalization. The CLI already treats the owner approval as covering finalization (spec 8.3).
  - Identity creation stays a separate, explicit choice when there is no identity to use.
- **Commit** replaces Review requester commit, Approve requester commit and Complete requester commit. It is the CLI's **Commit this exact machine link?**, with the final manifest on screen.

The joining person goes from about 15 presses to 3: Join a network, Approve, Commit.

### P2. One admission review for the inviter

**Admit NAME** replaces Review incoming connections, Review administrator consent and Approve administrator consent, as `link admit REQUEST_ID` does today. It appears when the joining person has approved, not before.

### P3. Progress that moves by itself

The pane shows "Waiting for bob to approve" or "Waiting for alice to admit you", and refreshes on its own every few seconds while it is open, as a read-only view. It offers the next review only when that review is due.

The daemons already advance approved work in the background, so this needs no new protocol action. The Check buttons go away. Explicit refresh stays available.

### P4. One "Connect this conversation" consent

This replaces the attachment review, the adapter review and its connect step, and Enable incoming messages and Enable incoming tasks. One review shows the project, agent name, expiry, and that messages and tasks from people with access will arrive in this conversation, with a checkbox for each. Both are on by default, and either can be turned off later.

### P5. Access granted with the invite

The invitation review gains "Let NAME reach my agents in this project", on by default. It records a pending grant that completes when that exact person is admitted. This is the pattern [peerbox invitations](peerbox-contract.md) already use for pending shares.

With a device signer the grant completes on its own. With an SSH person key it waits for the owner, as a peerbox share does today. This replaces Review agent access, Review proposed grant and Approve agent access for the common case. The separate access review stays for later changes.

### P6. The AI can open the next review

Add one model tool, `peerspan_next_step`. It returns which review is due for this participant, in plain words, and can open the pane at that review. It never carries an invitation or pairing code, never approves, and never sees private terms. The human still approves in the pane.

This lets "set it up with my AI" work: the AI walks the person through, and the person only reads and approves.

## Result

| | Joining person | Inviting person | Hand-offs |
|---|---|---|---|
| Today (pane) | ≈22 presses, repeated Checks | ≈18 presses, repeated Checks | invite code, plus watching for the other side twice |
| Proposed | Connect, Join a network, Approve, Commit (≈4) | Connect, Invite with access, Admit (≈3) | invite code; the pane says when the other side acted |
| CLI today, for comparison | `up --join` with 2 prompts | `invite`, `link admit`, `allow` | invite code |

The second-machine flow gets the same treatment: one approval on the existing computer and one commit on the new one.

## What stays the same

- **The protocol.** Membership is signed as today: requests, owner offers, administrator admission, finalization, requester commit and policy. Only the pane changes how many approvals it asks for, and when.
- **Separate authority.** The joining person's original key signs only on that person's machine. The administrator admits on theirs. The requester commits. A merged review never lets one role act for another.
- **Private material.** Invitation and pairing codes stay in the pane, out of model context, logs and plugin files.
- **Re-review on change.** Changed identity, powers, signer or expiry needs a new review, as the requirements say.
- **The detailed path.** Every existing backend route and CLI command keeps working. A "Show each step" setting can keep today's per-stage reviews for anyone who wants them.

## Decisions for the owner

1. **Merged approvals (P1, P2):** may one approval in the pane authorize several protocol consents, with all their terms on one screen? This is the central change. Recommended: yes. It is what "Peerspan completes the intermediate steps" asked for, and what the CLI already does.
2. **Automatic progress (P3):** may the open pane refresh a read-only progress view on its own? Recommended: yes.
3. **One connect consent (P4)**, with messages and tasks on by default. Recommended: yes, with both visible as checkboxes.
4. **Access with the invite (P5)**, on by default. Recommended: yes for the inviter's project agents only; wider grants keep their own review.
5. **A model tool that opens reviews (P6).** Recommended: yes, limited as described above. It changes the "no model setup tool" rule.
6. **Keep the per-stage pane** behind "Show each step"? Recommended: yes for one release, then decide from use.

## Cost and order

The pane composes backend routes that already exist. Most of the work is in the plugin (`integrations/claude-onboarding`) and its native tests:

1. P3 (automatic progress): pane only; no contract change beyond the pane's.
2. P1 and P2 (merged reviews): one pane review calls the existing consent routes in order. The guided session contract records that one human approval may cover them.
3. P4 (one connect consent): pane, plus the attachment and adapter sections of the contract.
4. P5 (access with the invite): host work (a pending grant on an invite) and contract work, reusing the peerbox pending-share code.
5. P6 (next-step tool): a small adapter tool, plus its privacy rules.

The guided slim suites (sections 16 to 33) test the backend routes and stay as they are. The pane's native tests change, written from the revised contract by a separate author, as AGENTS.md requires.

## Verification

- The two-host native flow completes a teammate join with the press counts above. A timing run records presses, reviews and hand-offs, as the setup timing run under Problem did for the CLI.
- A merged review shows every term its separate reviews showed. A change to any of them invalidates it.
- Declining at any merged review leaves the request as declining the first of its separate reviews does today.
- Codes never reach model context, including through P6.
- One early user repeats the setup through the AI path. Time is recorded from install to first message.

## Not in scope

- Changing who must approve what, or the protocol's stages.
- macOS, or other agent frontends (they follow once the pane's flow is settled).
- Install speed: the installer is a single command, and was not where the time went.
