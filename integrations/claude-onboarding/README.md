# Peerspan in an existing Claude conversation

Feature-branch preview for [tracking PR #35](https://github.com/peerspan/peerspan/pull/35).
Requires Claude Code 2.1.303 or newer in a terminal. This slice provides a
host view, an explicit local conversation check and a native human review for
local project attachment metadata. Adapter setup, invitations and sharing
permissions remain later slices.

## Try the entry

For development, load this directory as a Claude plugin:

```sh
claude --plugin-dir /absolute/peerspan/integrations/claude-onboarding
```

Then enter `/peerspan`. It opens a native pane in that conversation. Installed
plugin changes can be loaded in an existing conversation with
`/reload-plugins`; loading does not verify delivery. This preview does not yet
provide a marketplace or release-bundle installation path.

The pane reads `peerspan onboarding`, using the executable on PATH and normal
host-state discovery. Its optional trusted plugin settings are `executable`
(a program name or absolute path) and `state` (empty for the normal host).
Neither setting is an argument to `/peerspan`.

**Refresh** updates network names, local-agent counts, pending connections and
adapter evidence. It starts no daemon and changes no setup or permissions. A
missing or incompatible host is shown as unavailable. The command returns a
short read-only summary where no terminal pane is available.

## Connect this project

With the host running, press **Connect this project**. Peerspan looks up the
current native project and conversation. An existing review or outcome resumes
before a new choice is offered.

Choose **Review new agent**, with an editable name and descriptive owner label,
or explicitly choose an existing local agent. Review the full project, agent,
metadata, expiry and effects in the pane, then use **Approve attachment** or
**Decline attachment**. The buttons keep their exact host review references.
Changing the project/conversation or review terms requires another review.
Private flow payloads stay inside the native frontend and owner-local host.

A successful approval says **Project: attachment recorded** and **Adapter
connection is next**. This records a local agent/session association; adapter
connection, network admission and sharing each need subsequent steps. The
existing local model check below measures a separate delivery route.

Close or **Back to Peerspan** leaves the durable review intact. Reopen the pane
and Connect this project to look up its current outcome. Active-project Refresh
is read-only. Expired, declined or invalidated flows offer **Review a
replacement**, followed by a fresh explicit agent choice and review. Failed
owner decisions show an unknown outcome; Refresh checks what committed and
never repeats an approval automatically. Host restart invalidates metadata
attachments under the existing host contract. Managed Claude installations may
suppress the directory-change event for user-installed plugins: stale controls
are then invalidated on the next action, which always rechecks the native
project/conversation before sending a decision.

## Check this conversation

Press **Check this conversation** to submit one fixed, plugin-attributed local
challenge to the current model. This starts a model turn when the session can
accept it and uses the session's normal model allowance. Only a matching native
tool acknowledgment on this conversation's main loop marks it **verified**.
Queuing, refusal and a 60-second timeout are shown separately. Closing the pane
or changing/reloading the conversation clears the check.

The check grants no authority and reads no files. It sends no host observation,
pairing material or conversation history. The model tool only acknowledges the
local challenge; it cannot approve access, issue credentials or run owner
administration.

This proof concerns the native prompt/tool route in this conversation. It does
not establish a Peerspan adapter, remote reachability or peer message receipt.
The existing [Claude channel integration](../claude-channel/README.md) retains
its separate startup opt-in and readiness contract.

## Verify

```sh
claude plugin validate integrations/claude-onboarding --strict
claude plugin test integrations/claude-onboarding
```

The independent tests use Claude's actual mod runtime with public API effects
stubbed. They require no sign-in, network or inference. CI pins Claude 2.1.303.
These fixtures do not satisfy real-model acceptance. On 2.1.303, the actual
terminal pane, close, `/reload-plugins` and reopening `/peerspan` worked in the
same running process; a headless command also read a real temporary daemon.
A real terminal project review and approval also recorded exactly one local
agent/session attachment; close, native plugin reload and reconnect resumed the
same outcome without duplicate records. See the [smoke evidence](../../docs/results/guided-native-project-smoke.json)
for the exact source heads and scope. This run used no inference.
The live inference probe was refused by the account's weekly usage limit.
Real-model acknowledgment and the complete adapter/data path remain
outstanding acceptance work.

Contract, decisions and independent cases:
[guided-session-contract.md](../../docs/guided-session-contract.md#2-native-claude-entry-and-delivery-check-gu-01b--gu-03a).

Claude references: [mod reload](https://code.claude.com/docs/en/plugins/mods/overview),
[native controls](https://code.claude.com/docs/en/plugins/mods/interface) and
[background prompt submission](https://code.claude.com/docs/en/plugins/mods/api).
