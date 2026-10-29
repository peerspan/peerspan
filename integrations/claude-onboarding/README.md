# Peerspan in an existing Claude conversation

Feature-branch preview for [tracking PR #35](https://github.com/peerspan/peerspan/pull/35).
Requires Claude Code 2.1.303 or newer in a terminal. This slice provides a
host view, an explicit local conversation check, native human reviews for
project attachment and scoped adapter credentials, and a local adapter lease.
Explicit incoming-message and assigned-task paths use scoped native tools.
Native invitation review and explicit private code reveal are available.
Private recipient invitation inspection is also available. Joining/admission,
sharing permissions and live model acceptance remain later work. The advanced owner-local invitation-review backend is
available for integration development; it adds no model invitation tool.

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

## Invite someone

After attaching the project, press **Invite someone**. No connected adapter or
model turn is needed. An existing invitation review/outcome resumes first.
Otherwise explicitly choose a network, enter an invitee label and optionally
pin the expected person's public key (`-` means unpinned). A listed network may
still lack current invitation authority; the host checks that when preparing.
An empty list requires creating a network through existing host administration.

Press **Review invitation**, check the full identity, connection hints, fixed
expiries and effects, then **Approve invitation** or **Decline invitation**.
Approval creates one contact-only introduction; it adds no membership, agent
access, machine approval, files, conversation sharing or capability permission.
It does not send the invitation or demonstrate connectivity.

On an issued invitation, **Reveal private invitation** privately retrieves the
original code and shows it in this terminal pane. Select/copy it through your
terminal and share privately with the intended person. **Do not paste it into
this or another agent conversation.** Peerspan does not put it in model context,
clipboard, files or plugin storage. **Hide private invitation**, Refresh, Back,
Close, context changes and expiry clear the displayed code. Terminal scrollback
or screenshots you make may retain what you displayed.

Refresh checks the retained result without replaying a decision or creating a
new invitation. After a lost decision response it resolves the unknown outcome.
Reveal again retrieves the same code with its original expiry. **Invite another
person** explicitly starts another choice and review; it does not revoke an
older exported invitation. Declined, expired or invalidated outcomes similarly
require an explicit replacement review. An introduction is not admission or
agent access: the recipient's guided join and each participant's permissions
are subsequent slices. There is no recipient import control in this preview.

## Review an invitation you received

After attaching the project, press **Review an invitation**. Paste the code
only into **Private invitation code** in this human pane, never into an agent
chat. The field is visible terminal text. Typing or Enter updates the private
draft; **Inspect invitation** clears that draft and asks the local host to
verify the signature, signed network identity, contacts and expiry. No model
turn, key creation, network adoption, request publication or permission change
occurs. There is no clipboard or file import.

A successful view says **Invitation: signature verified** and shows the exact
public terms. This identifies the introduction's signer; it does not establish
the signer's membership/authority, admission, agent access or reachability.
Old contact hints may remain useful inside a live invitation; their expiry is
shown independently. An old invitation without automatic return is identified.

Identity selection and joining follow in subsequent slices. This preview has
no Join/Approve control. **Inspect another invitation** starts an empty draft.
Refresh, Back, Close, context changes, reload and expiry discard the volatile
preview. Re-entry requires pasting privately again. No code is stored in plugin
files or sent to the model; your terminal or screenshots may retain displayed
input. The inviter's retained reviews and existing connected delivery runtimes
are separate from this private recipient view.

## Review and connect the adapter

After attachment, press **Review adapter connection**. Review the full project,
agent, fixed expiry and permissions, then **Approve adapter** or **Decline
adapter**. Approval issues one credential for the existing local session to
receive and reply to already authorized work, handle authorized tasks and their
artifacts. It adds no network membership, agent access, directory access,
outbound destination or capability-call power, and automatically shares no
project files or conversation. Local harness permissions still govern actions.
The credential expires 24 hours after review preparation and is not renewable.

Approval and connection are separate actions. Press **Connect adapter** to
retrieve private transport material and connect to the host's local adapter
socket. The frontend keeps secrets in memory, outside model context. It renews
the scoped lease while the native conversation and exact authorization remain
current. **Adapter: connected** is a lease observation: incoming delivery and
peer exchange remain **not verified**. This slice consumes no work and sends no
model prompt. The local conversation check below is a separate route.

Closing the pane or going Back keeps an established connection running; either
action cancels an initial connection that has not been confirmed. **Stop
adapter** halts renewal without revoking the credential; the last accepted
lease expires within 15 seconds, subject to an already sent request completing.
Ending the conversation, changing the project, losing the terminal surface,
expiry or a failed renewal stops the runtime. Plugin reload clears it and never
reconnects automatically. Reopen the project, review its retained outcome and
press Connect to reuse the original approved instance. Expired, declined or
invalidated reviews offer **Review a replacement adapter**.

The native Unix transport requires an absolute socket path of at most 103 UTF-8
bytes. An unsupported path or unavailable host produces a controlled failure.
No model approval or owner-administration tool is registered.

## Enable incoming messages

Once connected, press **Enable incoming messages**. This starts a model turn
using the conversation's normal allowance. The model must acknowledge a fresh
readiness challenge through `adapter_ready` before any message is claimed.
Queue acceptance or a saved host channel state does not satisfy that check.
After 60 seconds without acknowledgment, the attempt expires; **Retry incoming
messages** starts a fresh explicit check. Peerspan sends no automatic retry.

After acknowledgment and host confirmation, the pane reports **Incoming
delivery: verified (messages)**. It submits authorized messages to this same
conversation as external peer content. The model can acknowledge a held
delivery with `message_seen` or answer once with `message_reply`. The host
enforces the original sender, grant, session, expiry and reply bounds. These
tools add no local file/tool permission, owner operation, arbitrary destination
or capability-call access. Assigned tasks require the separate enable below;
outgoing delegation and its update notifications remain later work.

Submitted, seen and replied counts are separate. Submission is harness
acceptance; seen/reply requires a successful current-model tool call. **Peer
exchange** remains **not verified** because a saved reply does not prove its
sender retrieved it. The local conversation check below is separate.

Close/Back preserve an established enabled runtime. Stop, session end, reload,
context/scope change or lease expiry cancels its tool authority and polling.
A handoff/submission/forwarded failure stops the message attempt while lease
renewal continues. An uncertain message is never automatically resubmitted.
Retry performs a new readiness check; it does not recover uncertain held work.
Existing advanced host diagnostics remain available for that recovery.

## Enable incoming tasks

After the current native message readiness check succeeds, press **Enable
incoming tasks**. Tasks can start model turns under the normal allowance. This
adds no local tool or file permission, performs no new readiness prompt and
does not enable outgoing delegation or file transfer.

Assigned tasks arrive as external peer input. The model can use `task_accept`
or `task_reject`, then `task_progress` and `task_complete` with a text outcome.
An adopted running task resumes its observed progress and cancellation flag;
it is not accepted again as a queued task. Cancellation notices request a stop:
the model may call `task_cancelled` only if work actually stopped, or complete
its real outcome. The host checks held-task ownership, transitions and grant
rules. Accepted tasks can continue after their peer grant expires, while the
native credential and context must remain valid.

Attachments are metadata only in this frontend. It cannot download task inputs
or upload result files. No file is read or shared automatically, and onward
delegation remains unavailable even when a task's metadata permits it.

Task and cancellation submission counts mean native prompt acceptance. Tasks
observed and task changes confirmed require successful current-model lifecycle
calls; identical retries do not inflate them. A status record does not prove
the model performed the work or that its submitter retrieved the result.

**Stop incoming tasks** pauses delivery and reporting; it does not cancel an
accepted task, stop messages or revoke the credential. Task handoff failures
stop the task attempt; **Retry incoming tasks** starts another explicit attempt
without resubmitting uncertain held input. Close/Back preserve enabled tasks.
Losing the native ready proof, stopping the adapter, expiry, context change or
reload stops task authority and requires explicit setup again.

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

All148 independent native cases include20 invitation cases and preserve the
original128 project/adapter/message/task checks. The tests use Claude's actual mod runtime with public API effects
stubbed. They require no sign-in, network or inference. CI pins Claude 2.1.303.
These fixtures do not satisfy real-model acceptance. On 2.1.303, the actual
terminal pane, close, `/reload-plugins` and reopening `/peerspan` worked in the
same running process; a headless command also read a real temporary daemon.
A real terminal project review and approval also recorded exactly one local
agent/session attachment; close, native plugin reload and reconnect resumed the
same outcome without duplicate records. See the [smoke evidence](../../docs/results/guided-native-project-smoke.json)
for the exact source heads and scope. This run used no inference.
The [adapter smoke evidence](../../docs/results/guided-native-adapter-smoke.json)
records real native approval, connection, renewal with the pane closed, Stop
and explicit reconnect after plugin reload, with one retained authorization.
It used a temporary single host and no inference. The subsequent [message smoke](../../docs/results/guided-native-message-smoke.json)
submitted the actual readiness prompt, but the account's weekly usage limit
refused inference. The host remained unverified and claimed no messages.
Real-model acknowledgment, message/reply and installed two-machine acceptance
remain outstanding; deterministic runtime fixtures do not replace those checks.
Assigned-task receipt, lifecycle calls and cancellation also remain live-model
acceptance gates. The unchanged quota-refused probe is not repeated for this
slice, and no live task smoke is claimed. Independent native task fixtures and
the existing real-host work/live suites cover their respective boundaries.
The pinned test kit targets current drawings by key and does not retain old
callback closures. The stale displayed Enable control's readiness binding is
source-reviewed; its actual old-callback refusal remains a manual check.

The [invitation smoke](../../docs/results/guided-native-invitation-smoke.json)
records a real native network choice, exact review/approval, private handoff,
Refresh and reload/resume with one issued introduction, no adapter credential
and zero assistant messages. Private terminal output was withheld during reveal;
Hide-only behavior is covered by the independent runtime fixtures rather than
claimed as standalone manual evidence. This is the inviter side on one temporary
host, not installed two-person admission/access or model acceptance.

Contract, decisions and independent cases:
[guided-session-contract.md](../../docs/guided-session-contract.md#2-native-claude-entry-and-delivery-check-gu-01b--gu-03a).

Claude references: [mod reload](https://code.claude.com/docs/en/plugins/mods/overview),
[native controls](https://code.claude.com/docs/en/plugins/mods/interface) and
[background prompt submission](https://code.claude.com/docs/en/plugins/mods/api).
