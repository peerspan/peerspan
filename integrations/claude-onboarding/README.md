# Peerspan in an existing Claude conversation

Feature-branch preview for [tracking PR #35](https://github.com/peerspan/peerspan/pull/35).
Requires Claude Code 2.1.303 or newer in a terminal. This slice provides a
read-only host view and an explicit local conversation check. Project
attachment, invitations and permission reviews remain later slices.

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
These fixtures do not satisfy real-model acceptance. During development the
native command worked on 2.1.303, but the live inference probe was refused by
the account's weekly usage limit. Reload and real-model acknowledgment remain
outstanding acceptance work.

Contract, decisions and independent cases:
[guided-session-contract.md](../../docs/guided-session-contract.md#2-native-claude-entry-and-delivery-check-gu-01b--gu-03a).

Claude references: [mod reload](https://code.claude.com/docs/en/plugins/mods/overview),
[native controls](https://code.claude.com/docs/en/plugins/mods/interface) and
[background prompt submission](https://code.claude.com/docs/en/plugins/mods/api).
