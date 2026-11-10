# CLI output contract

How `peerspan` commands print what they did: a short readable summary by default, and the full object behind `--json`. The owner's decisions are [OUT-1 and OUT-2](decision-log.md#out-1-and-out-2-readable-output-by-default-2026-11-10); the review screens were deferred here by [ML-5](decision-log.md#ml-5-the-raw-json-review-screens). Issue [#158](https://github.com/peerspan/peerspan/issues/158).

## 1. The rule

- **Readable by default (OUT-1).** Every command prints a readable summary on stdout unless `--json` is given. This holds when stdout is not a terminal.
- **`--json` (OUT-2).** `--json` is accepted by every command, before or after the subcommand (`peerspan --json network list` and `peerspan network list --json` are the same). With it, a command prints exactly the object it printed before this contract: wherever another contract says a command "prints `{…}`" or describes its output object, that is now its `--json` output. Commands that already had `--json` (`status`, `agents`, `conversations`, `conversation show`, `shares`, `calls`, `approvals`, `session pending` and the others) keep its meaning. `call ADDRESS OPERATION` reads every argument after OPERATION as the operation's input, so there `--json` goes before OPERATION.
- **Objects on stderr.** An object a command printed on stderr follows the same rule: `up`'s setup report, `attach`'s launch report when it starts the integration, and the review screens (section 2.1) are summaries by default and the object with `--json`.
- **What does not change.** Exit statuses, the other stderr messages, and the `Next:` lines on stderr are the same with and without `--json`. Prompts and their default answers are the same. `--help` lists `--json` and is otherwise unchanged.
- **Already readable.** Commands whose default output was already readable (`status`, `agents`, `conversations`, the conversation views and the others) keep their layouts. A command whose `--json` was documented as "the default output", such as `runtime show`, now prints a readable summary by default.
- **`onboarding` is JSON only.** The `onboarding` commands are the onboarding plugin's machine interface ([guided session contract](guided-session-contract.md)), listed only in `help advanced`. They print their JSON with or without `--json`.
- **Errors.** A failing command prints `error: …` on stderr, as before, and nothing on stdout. A command that prints its record and then fails, such as a rejected send (MSG-1), prints the record readably, or as JSON with `--json`, before the error.

### 1.1 Readable layouts

The layouts are not shared, except for the facts each summary in section 2 must show. Scripts use `--json`.

- **Terminal safety.** Text that came from another host or person (labels, agent names, messages, error details) is printed with control characters (U+0000 to U+001F, U+007F, U+0080 to U+009F) written as `\u00XX`.
- **Codes are whole.** A private code or token that the user must pass on (an invitation, a reply code, an invite token, a credential) is printed in full, on a line of its own, never shortened.
- **IDs are whole.** Network, request, task, message and host IDs are printed in full, so they can be copied into the next command.
- **Times** are RFC 3339 UTC, as in the JSON.
- **Sizes** are bytes, shown as `N KB`, `N MB` or `N GB` (powers of 1024, as in `SIZE`) when exact, and otherwise `N bytes`.

### 1.2 Generic layout

A command without a summary in section 2 prints its object in this layout:

- an object as one `key: value` line per field, in the object's order, with a nested object or array of objects indented two spaces below its `key:` line;
- an array of scalars as its values joined by `, `, and an empty array as `none`;
- an array of objects as one `-` item per element, each laid out as an object;
- `null` as `none`, `true` as `yes` and `false` as `no`;
- a top-level array as one `-` item per element, or `none` when empty;
- numbers as in the JSON, including byte counts.

Every command without a row in section 2, other than `onboarding`, uses this layout.

## 2. Summaries

Each summary must show the facts listed for it. Wording and order are free unless quoted. Host and device keys are Ed25519, and a fingerprint is that of the `ssh-ed25519` key with the same bytes.

| Command | Must show |
|---|---|
| `install` | The service manager and unit; whether the service is running (`started`); the peer listen address when one is set; whether lingering is enabled when the manager reports it. |
| `uninstall` | The unit; whether it was removed, or that no unit was installed; that the state directory was kept. |
| `up` (its setup report on stderr) | Each stage with its state (`completed`, `reused`, `pending`, `failed`); each attention item's stage and detail; `next` when the setup is incomplete. |
| `network create` | The network's name and full ID, and this machine's member label. |
| `network list` | One line per network that starts with its full ID, followed by its name, this machine's member label, and its authority state when it is not `usable`. With no networks: a line saying there are none and that `peerspan network create` or `peerspan join` makes one. |
| `network members` | One line per member: its label and host ID. |
| `invite` | The member label, the expiry, and the `psi2-` introduction on a line of its own. The stderr note is unchanged. |
| `allow` | Who (the principal as given, `everyone` for `network`), which of your agents (`all your agents` for `*`, otherwise the agent name), what they can now send (messages; tasks; delegation), the file limit when tasks are on and it is not 0, and the new policy version and its `valid_until`. For example: "alice can now send all your agents messages and tasks, with files up to 100 MB. Policy version 2, valid until 2026-11-11T17:10:43Z." |
| `deny` | The principal and the number of rules it was removed from, and the new policy version. When `removed` is 0: the `note`, and that no new version was signed. |
| `block`, `unblock` | The person or host blocked or unblocked, by the label or ID given. |
| `send`, `message send`, `message retry` | The target (address, or peer and agent), the message ID, and the outcome: delivered (`accepted`), queued for retry (`unknown`, with `next_attempt_at` and the error when present), or refused (`rejected`, with its error, followed by the MSG-1 error on stderr). |
| `task submit` | The target, the task ID and the outcome as for `send` (from `submit_state`), and the command that follows the task, `peerspan task inspect …`. |
| `runtime show` | Whether runtime tasks are enabled, the runtime socket, and the runtime's report and this host's rule when present. |
| Linking views (`join`, `link` and each of its actions, such as `status`, `approve`, `admit`, `finalize`, `commit` and `resume`; `link status` without an ID is the list) | For each request: its full request ID, its network ID, its state, and the reply code on a line of its own when the command shows it. A list prints one block per request, or a line saying there are none. The `Next:` lines and the ML-3 messages on stderr are unchanged. |

### 2.1 Review screens

Before each "Approve this exact machine?" and "Commit this exact machine link?" prompt (spec 8.3, 8.4; ML-4), and in a preview without a terminal, the review is printed on stderr as a summary instead of JSON. It must show:

- the network name when this host knows it, and the network ID;
- the stage;
- the person, host and device keys, each as an OpenSSH `SHA256:` fingerprint;
- the scopes as names: 1 `edit policy`, 2 `bind hosts`, 4 `approve devices`, 8 `network admin`, or `none` for 0;
- `not_after`;
- the `authority_warning`, when present, on a line of its own.

With `--json`, the review object is printed on stderr as before.

## 3. Installer

`scripts/install-release.sh`:

- **No JSON.** It prints no JSON object. `peerspan install` output, when the installer runs it, is the readable summary, or nothing.
- **PATH hint.** It prints the "Add … to PATH" hint only when the launcher directory is on neither the current `PATH` nor the `PATH` a new login shell would have. It learns the latter by running the user's login shell (`$SHELL`, else `/bin/sh`) as a non-interactive login shell that prints `PATH`, with stdin closed and a limit of 5 seconds. When that fails or times out, it prints the hint. When only a new login shell has the directory, as with Ubuntu's default `~/.profile` and `~/.local/bin`, it says instead that `peerspan` is available in a new login shell.

INST-7 still applies: there is no conformance suite for the install scripts. The installed-bundle checks cover them.

## 4. Verification

The cases below go in the slim suites of the areas they touch: `basics` for sections 1 and 2's generic rules, `policy` for `allow`, `deny` and `block`, `work` for sends and tasks, `join_teammate` for linking views and the review screens.

- **`--json` everywhere:** for `network list`, `allow`, `deny`, `send` and `task submit`, `--json` before and after the subcommand gives the same object, with the fields other contracts list.
- **Readable by default, not JSON:** the same commands without `--json`, with stdout a pipe, print text that does not parse as JSON, with the same exit status as with `--json`.
- **`network list`:** each line starts with a network's full ID; the name and member label appear; with no networks, the line saying so.
- **`allow`:** the readable output names the principal as given, `all your agents` for `*` and the agent name with `--agent`, says messages, tasks and delegation as set, the file limit with `--files 100M` as `100 MB`, and the policy version that `--json` reports.
- **`deny`:** the removed count, and with 0 the note and no new version.
- **Sends:** an accepted send names the message ID and says it was delivered; a rejected send prints the readable record, then `error: rejected: …`, exit 1 (MSG-1); a task submit names the task ID and `peerspan task inspect`.
- **Linking:** `join` prints the request ID and the reply code, each in full; a list from `link status` names every request ID.
- **Review screens:** the summary before the joiner's approve prompt shows the network ID, the three key fingerprints, and scope names, and no JSON object; with `--json` the review object.
- **Generic layout:** a command without a summary (for example `info`) prints its fields as `key: value` lines, and an empty list (for example `peer list` with no peers) as `none`.
- **Terminal safety:** a peer agent's name or a message error containing an escape character is printed as `\u001b`.
- **Existing suites:** every existing case that reads a command's object passes `--json`; no case's expectations change otherwise.
