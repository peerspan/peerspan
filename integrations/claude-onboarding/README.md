# Peerspan in an existing Claude conversation

Feature-branch preview for [tracking PR #35](https://github.com/peerspan/peerspan/pull/35).
Requires Claude Code 2.1.303 or newer in a terminal. This preview provides a
host view, an explicit local conversation check, native human reviews for
project attachment and scoped adapter credentials, and a local adapter lease.
Explicit incoming-message and assigned-task paths use scoped native tools.
Native invitation review and explicit private code reveal are available.
Private recipient invitation inspection and explicit join-request publication
with an existing or explicitly created local original identity are available.
A published request also offers exact new-original owner consent, original-offer
signing, original finalization and separate requester consent/completion.
The inviting computer has separate incoming administrator review/consent. Sharing permissions and
live message receipt are covered by the [final acceptance receipt](../../docs/results/guided-final-acceptance.json). Owner actions stay in the human pane;
no model setup tool is added.

## Install from a host archive

Requires Claude Code 2.1.303 or newer in a terminal. Verify and extract the
Peerspan Linux archive, then move it to the directory where you will keep it.
Set `PEERSPAN_PREFIX` to that absolute directory, including any spaces:

```sh
PEERSPAN_PREFIX='/absolute/path/to/peerspan-0.1.0-linux-amd64-rust'
claude plugin install peerspan --marketplace "$PEERSPAN_PREFIX/share/peerspan" \
  --scope user --config "executable=$PEERSPAN_PREFIX/bin/peerspan"
```

Claude installs from the archive's local marketplace and saves the exact host
executable in its user plugin configuration. Keep that directory in place after
installation. The optional `state` setting can stay empty for normal host-state
discovery, even if Claude lists it as unset. No hosted marketplace, repository
checkout or launch-time channel flags are needed.

In your existing Claude conversation, run `/reload-plugins` if Claude requests
it, then `/peerspan`. Installation does not start the host, attach a project or
verify delivery. Run the host through the ordinary Peerspan setup first. Mods
must be allowed by your Claude installation and organization policy. Native
installation is checked separately from actual reload, model receipt and
cross-machine acceptance. See the final receipt for the separate installed, terminal and authenticated model checks and their limitations.

The bundle's marketplace layout follows Claude's
[local marketplace interface](https://code.claude.com/docs/en/plugin-marketplaces)
and [plugin CLI](https://code.claude.com/docs/en/plugins/cli-reference).

## Development entry

For development, load this directory as a Claude plugin:

```sh
claude --plugin-dir /absolute/peerspan/integrations/claude-onboarding
```

Then enter `/peerspan`. It opens a native pane in that conversation. This
development flag loads the directory for that launch. Use the archive route
above to install into an existing conversation; loading does not verify delivery.

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
agent access. Use the separate recipient joining, participant approval and agent-access controls below.

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

This inspection pane is read-only; use the separate **Join a network** action
for explicit identity choice and request-publication consent.
Inspection itself creates no person key or request and proves no key
possession, membership or access.
This read-only inspection has no Join/Approve control. Use **Join a network** separately. **Inspect another invitation** starts an empty draft.
Refresh, Back, Close, context changes, reload and expiry discard the volatile
preview. Re-entry requires pasting privately again. No code is stored in plugin
files or sent to the model; your terminal or screenshots may retain displayed
input. The inviter's retained reviews and existing connected delivery runtimes
are separate from this private recipient view.

## Join a network

After attachment, press **Join a network**. Peerspan first reads any recorded
review/outcome. A new attempt starts an empty **Private invitation for joining**
field. Paste only in this human pane; the input is visible terminal text. Enter
only edits the draft. **Review joining identities** clears the drawn input,
verifies the exact incoming introduction, and reads available local identities.
The joining attempt retains the code only in volatile private memory until its
explicit decision, expiry or navigation; it never sends it to the model or
stores it in plugin files.

Choose explicitly among original Ed25519 identities from the normal local
Peerspan-generated person file or your SSH agent. No identity is selected by
default, copied, imported or used to sign ownership. A pinned
introduction only permits its matching key; all available keys and their sources
remain visible. A missing pinned key requires the original machine and its
device-linking ceremony; a random new identity cannot match that pin.

When there are no available local identities and the invitation is unpinned,
**Create a new original identity** opens a review without generating a key.
Review the effects, then explicitly **Create and save identity** or **Cancel
identity creation**. Saving creates a new person on this computer; it does not
link your existing person. The complete private key is saved at the normal
original identity location without replacing an existing key. No request is
prepared or published by this action.

**New original identity saved** returns to the chooser. Review that public key
explicitly; the separate request review and approval below still apply. The
saved key survives Close, navigation and later request decline. Back it up
privately through ordinary host administration. If creation times out or its
response is lost, a key may still have been saved: reopen and inspect local
identities with fresh private input. Peerspan does not automatically retry,
erase the saved original or generate a second key.

**Review identity KEY** prepares a public review, without publishing a request.
Read the full network, invitation, person-key, expiry and effect terms. Only
**Approve join request** publishes the ordinary request; **Decline join request**
records a refusal. Approval rechecks the parent, review, host and selected local
identity. A supplied/available public key is not proof of ownership. Publication
neither grants membership/access nor approves the remaining participant steps.

Success says **Join request: publication recorded**. This is a historical
publication outcome, not current link state, reachability, readiness or model
receipt. **Check join progress** explicitly reads a snapshot of that exact
ordinary request. It shows recorded stages, requester selection/final-commit
consent, and the next participant's task. **Local application recorded** is a
historical protocol result; current authority, agent access and readiness still
need separate checks. A pending-delivery observation does not prove arrival.
Use the separate original-owner, administrator and requester review controls below for the remaining approvals. Checking progress
never signs, resumes the protocol, polls a peer, retrieves a code or inventories
person keys. A failed check clears older progress and preserves publication;
Check again explicitly. Refresh/navigation discard the progress snapshot.

Reopen/Refresh reads the publication outcome without retrieving a code or making
another request. A live review after reload requires explicit code re-entry
through **Check invitation for this review** before Approve is available.
An uncertain result must be recovered through lookup; there is no automatic
resubmission. **Review another join request** explicitly replaces a non-review
attempt and does not cancel or revoke an earlier published request.

Back, Close/Escape, Refresh, reload, expiry or context loss clear the private
attempt. Ordinary pane navigation preserves an established adapter and delivery
runtime. No native owner/model tool is added. Sections13 and14 of the
[contract](https://github.com/peerspan/peerspan/blob/codex/guided-session-onboarding/docs/guided-session-contract.md#14-explicit-new-original-identity-creation)
define bindings, privacy, persistence, recovery and remaining acceptance gates.

The creation command uses `$XDG_CONFIG_HOME/peerspan/person_ed25519`, falling back
to `$HOME/.config/peerspan/person_ed25519`. It requires a private owner-controlled
`peerspan` directory and refuses symlink/traversing/insecure destinations; it
does not repair their permissions. The private file is0600 and the directory
is0700. No `.pub` sidecar is written. A crash can leave private reserved
`.person_ed25519.<random>.tmp` names in that directory. They are ignored by
identity discovery. After stopping any active creation command, the owner can
remove those temporary names; preserve `person_ed25519`. Never copy an original
private key to another computer to link that computer.

## Review owner powers

From a published join request, press **Review owner powers**. Peerspan reads the
retained consent first, preparing fixed public terms only when none exists.
Read the exact person, computer, network and finite powers: policy editing,
host binding, and approval/renewal/revocation of eligible own devices. Network
administration is excluded. The review also explains the later original signature,
bounded binding/device finalization and normal single-offer selection/publication.
None establishes membership, agent access, requester final commit or readiness.

**Approve owner powers** records the exact reviewed consent after fresh checks.
It neither uses the original key nor completes the original signature. The
separate **Sign original owner offer** action is available only for eligible
approved pending requests, after fresh project/host/review/request checks.
**Owner consent: recorded** reports a retained protocol record, which may have
been approved elsewhere; it does not identify the approving interface or prove
current powers. Review-window expiry does not erase historical approval.

**Leave owner review** closes local controls without declining, cancelling or
revoking protocol work. If a result is uncertain, **Check owner consent** only
reads the retained result; it never prepares, retries approval or signs. A null
result leaves preparation to another explicit **Review owner powers**. Ordinary
entry, progress, Refresh, reload and timers perform no owner preparation or
approval. Navigation/context loss clears confirmations and pending callbacks,
while an established adapter/message/task runtime stays active.

## Sign the original owner offer

Read the same exact identities, finite powers and effects before explicitly
pressing **Sign original owner offer**. Peerspan uses the approved original on
this computer: its safe normal generated key or exact SSH-agent identity. No key
is created, imported or copied. The command submits one exact original signature;
existing approved host work may publish the offer and select one matching offer.
Administrator admission, later original finalization, requester final commit and
agent access remain separate.

**Original signature: recorded** reports durable protocol evidence, which may
already have existed. It does not identify which interface signed it or prove
admission, current powers, access or connection readiness. **Owner offer recorded**
is shown only when the completed offer is present. A partial retained signature
can precede it. A public owner snapshot without a completed offer cannot confirm
whether that partial signature exists.

The approved review's old review window does not erase its consent. Request and
signature deadlines still bound new signing. A failed or timed-out action is
outcome unknown: **Check owner consent** reads public evidence without signing,
retrying or preparing anything. If the snapshot remains unconfirmed, any later
attempt requires another explicit Sign press; the CLI checks for existing proof
before using the key again. Leaving or navigation clears local confirmation and
cannot retract an already-dispatched signature. No signature state is persisted
by the plugin. Installed participant signing is covered by the final receipt; an actual multi-person terminal signing session is not claimed.

## Review incoming connections

On the inviting computer, attach the project and press **Review incoming
connections**. Choose a retained request by its full network, person and host
identity. The list is a snapshot of claims; it does not grant admission.

Selection first reads retained administrator consent. **Fetch incoming proofs**
explicitly fetches missing original-owner and requester-selection evidence from
already pinned carriers. A waiting result requires another participant; there
is no automatic poll or approval. Once the prefix is present, press **Review
administrator consent** to verify it and prepare the exact unapproved review.

Read the complete network/current-root, person/host/device, finite powers,
deadlines and effects before **Approve administrator consent**. Approval permits
ordinary background root/host signing and administrator-offer publication.
Original finalization on the joining computer, requester commit, agent access
and connection readiness remain separate.

**Check administrator consent** reads global protocol evidence only, including
approved history after expiry. It never fetches, prepares, approves or retries
an uncertain action. Leaving does not cancel or revoke consent and cannot
retract a dispatched action. Leave, Refresh, Close, context loss and reload
clear local selection and approval controls; reopen and choose the request to
recover its retained record. No original keys, raw codes or signing bytes enter
this flow, the model or plugin storage.

## Finalize the original machine binding

On the joining computer, **Check owner consent** reads the retained exact
original consent. Once its original offer, requester selection and administrator
offer are present, press **Review original finalization**. Review the original
person and machine, independently verified administrator/current-root/P/H
references, finite machine powers and expiry before **Sign original
finalization**. Existing approved host work fetches proofs; opening or checking
this review does not fetch, prepare consent, sign or resume the ceremony.

The separate explicit signing action uses the approved original's safe existing
generated key or exact SSH-agent identity. It creates, copies and imports no
key. It permits at most two ordered batches and three original signatures for
binding/device/finalization evidence. Requester final commit remains another
decision. Recorded finalization alone does not verify adopted powers, agent
access, reachability or model receipt.

**Original finalization: recorded** is global durable protocol evidence, without
attributing its creation or a historical review digest to this pane. A failed
or timed-out signing action is outcome unknown: partial signatures may remain.
**Check original finalization** reads retained consent and, while still eligible,
the pure finalization inspection. It never signs or automatically retries. A
later attempt needs a freshly displayed review and another explicit Sign press.

**Leave finalization review** returns to the published joining outcome and clears
both local owner/finalization controls. Leave is available during signing;
navigation, Refresh, context loss and reload discard pending callback authority.
They cannot retract an already dispatched signature or committed submission.
The native process has a95s bound, separate from the backend's90s asynchronous
deadline; timeout is not proof that no work committed. The final receipt distinguishes installed loopback host fixtures, terminal controls and actual-model receipt; separate physical machines were not exercised.

## Review and complete requester consent

On the joining computer, once **Original finalization: recorded** is visible,
press **Review requester commit**. It first recovers any existing consent. If
none exists and the request is eligible, this explicit action prepares the
review. Check the exact person, machine, network, original/administrator proofs,
finite powers, requester host/device and expiry before **Approve requester
commit**. This approval authorizes ordinary signing, publication and local
application; it does not grant agent access or prove a connection is ready.

**Complete requester commit** is a separate action over that approved consent.
It uses the owned host/device keys, without choosing or importing an original
key. **Local application: recorded** reports this computer's retained result.
Participant delivery, agent access, connection readiness and model receipt
remain unverified. Files, conversation sharing and capability calls remain
separate permissions. Historical consent or application is not current powers.

**Check requester consent** only reads public evidence. It never prepares,
approves, completes or retries. An uncertain or timed-out action may already
have recorded consent or partial work: use Check before deciding on another
explicit attempt. **Leave requester review**, available while work is pending,
clears the local owner/finalization/requester panes and returns to the published
outcome. Navigation and reload discard callback authority; they cannot retract
already dispatched work or revoke durable consent. Completion has a 95-second
native process bound and the backend's separate 90-second attempt bound.

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
expiry or a failed renewal stops the runtime. An actual mod runtime restart clears it and never reconnects automatically. On Claude2.1.303, `/reload-plugins --force` can retain an unchanged mod runtime and its lease. For an explicit fresh connection, press **Stop adapter**, reload, reopen the project, then **Review adapter connection**, **Connect adapter** and **Enable incoming messages**. This reuses the original approved instance and requires a fresh model readiness acknowledgment. Expired, declined or invalidated reviews offer **Review a replacement adapter**.

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

## Review agent access

From an attached project's main pane, choose **Review agent access**, a network,
and a person. Choices show each person's public key and their machine labels;
the review shows the verified person label separately. People without a current
bound machine are not listed yet. Membership alone grants no agent permission.

The first view only reads current membership, the signed policy and locally
enforced content. **Review proposed grant** recovers existing consent first; it
prepares new terms only when none exists. Review the exact agent name, recipient,
provider, full policy and expiry before pressing **Approve agent access**.

The proposed permission allows messages and task submission, with65,536 message
bytes, no task artifacts, delegation, capability calls or disconnected access.
It applies to this exact agent name across the owner's machines. Other existing
policy permissions remain visible and are preserved.

Approval records consent. **Finish agent access** uses the selected provider to
sign that exact policy and apply it locally, skipping work already recorded.
These are two separately bounded operations; signing can succeed even when
application is interrupted. Finish never prepares another permission review.

**Check agent access** reads inspection or consent. **Check application** only
reads retained signature/application evidence, including after expiry. A recorded
local application does not establish current permission, peer delivery, model
receipt or connection readiness. After an unknown outcome, Check application
comes first; another Finish requires a separate press while the work remains live.
**Leave agent access** clears the pane and does not revoke consent or retract
prior or dispatched work. Existing authorized delivery keeps its own lifecycle.

## Check connection status

After choosing a network and person under **Review agent access**, press
**Check connection status** from the verified inspection, consent or completion
pane. This reads current local evidence for that person's machines sending to
this project's agent. It does not change permissions or start a connection.

The pane shows each machine's separate advertised permissions and restrictions,
plus the local adapter's registered, connected or offline state for this exact
project session. **Show connection details** exposes current membership, signed
and separately enforced policy terms, permission entries and connection dates.
Evidence clears after at most 30 seconds, or sooner when a relevant membership,
grant or connection lease ends. Press Check again for a new observation.

Peer reachability, model receipt and overall connection readiness remain
**not verified** by this local read. **Review agent access** returns to inspection;
**Leave connection status** returns to the project without revoking access or
stopping an authorized adapter. Use the adapter's separate incoming-delivery
check to verify its model path.

## Check a machine connection

From **Check connection status**, press **Check a machine connection**, choose a
remote machine, then press **Check outbound connection**. Each choice shows the
machine's quoted label and host ID; the selected view also shows its public key.
Choosing a machine starts no connection check.

The result reports an authenticated outbound response with its HTTP status, or
an outbound connection that is not verified. A 403/404/500 response still proves
an authenticated exchange with that machine; permissions, incoming agent
delivery and model receipt have their own evidence. Overall readiness remains
not verified by this observation.

**Show outbound connection details** displays the current public membership and
signed/enforced policy from that observation. **Choose another machine** clears
the result. **Check connection status** returns through a fresh local status
read. **Leave machine connection** returns to the project while an authorized
adapter keeps its existing lifecycle.

The machine roster expires at most 30 seconds after its original observation,
or earlier when relevant membership/policy ends. Results also expire at their
own earliest bound, and a check cannot extend the original roster window.
Expired choices require a new Check connection status. Checks run only on an
explicit press; leaving clears the pane and discards late results.

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

## Request to connect this computer

After attaching the project, choose **Connect this computer** on the new
computer. Privately enter an invitation that pins your existing person's public
key. **Review this computer's identity** shows the signed invitation and that
exact person; **Review machine request** then prepares its publication terms.
**Approve machine request** creates/reuses and publishes one ordinary request
with a separate local device key. **Decline machine request** creates no request.

The original person key stays on the existing computer. This path does not
inventory, generate, import or copy an original key. An unpinned invitation is
unavailable in this lane; get a pinned invitation from the existing computer.
Typing or pressing Enter does not submit a review or grant anything.

**Machine request: publication recorded** is separate from machine approval,
membership, agent access and readiness. **Check machine request progress** reads
the actual recorded next participant without advancing it. Approval on the
existing computer is still required; use **Review machine requests** there.
The normal **Join a network** original-identity flow remains available separately.

Refresh/reopen recover public state without publishing again. A pending review
requires its exact invitation to be privately reentered through **Check
invitation for this machine request** before Approve returns. Unknown outcomes
require explicit reopening/lookup; no automatic retry. A replacement request
does not revoke the previous one. Close, expiry and navigation clear private
input; the invitation never enters agent chat or plugin storage.

## Approve another computer

On the existing computer, attach this project and choose **Review machine
requests**, then choose the retained request. Review the host-verified person,
actual target host/device keys, selected original/device authority, finite
powers7 and deadlines. This public inspection does not test signer availability.
**Review machine consent** prepares the exact unsigned review; **Approve machine
consent** explicitly authorizes ordinary owner work. Background work may sign
and publish after approval. It does not establish membership or readiness.

**Sign machine owner offer** explicitly records only the exact approved initial
2/3 signatures when currently eligible. **Check machine consent** reads the
retained receipt and signing evidence without retrying a mutation. Historical
consent/signatures stay separate from publication, admission, machine powers,
requester selection/commit, agent access and connection readiness. Other-project
receipts are view-only. No original key copying, native signer choice or native
review replacement. Leave/reopen after advanced explicit replacement.

Refresh, Leave and Close discard actionable native evidence. Unknown outcomes
require explicit Check; fixed original windows never restart. The requester-side
selection/completion controls are described below. The final receipt covers installed two-host fixtures and separate actual-model delivery.

## Verify

```sh
claude plugin validate integrations/claude-onboarding --strict
claude plugin test integrations/claude-onboarding
```

The independent native suite includes440 cases across22 files, covering project, adapter, message/task, invitation, participant, access, readiness and machine-link controls. The tests use Claude's actual mod runtime with public API effects
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
Those older receipts retain their original limitations. The final receipt separately records successful authenticated model acknowledgment/message/reply, same-conversation reload and installed two-host acceptance. Deterministic runtime fixtures do not replace those checks.
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

The [recipient smoke](../../docs/results/guided-native-recipient-smoke.json)
uses two distinct temporary hosts on one physical machine. The real pane
inspected a privately pasted signed introduction, displayed its public terms,
left all recipient database records unchanged, and returned to an empty input
after Close/reload. Its transcript has zero assistant messages and no code or
flow/review prefixes. Exact earlier source/build and a corrected manual fixture
attempt are recorded; no joining/admission/access or model receipt is claimed.

Contract, decisions and independent cases:
[guided-session-contract.md](https://github.com/peerspan/peerspan/blob/codex/guided-session-onboarding/docs/guided-session-contract.md#2-native-claude-entry-and-delivery-check-gu-01b--gu-03a).

Claude references: [mod reload](https://code.claude.com/docs/en/plugins/mods/overview),
[native controls](https://code.claude.com/docs/en/plugins/mods/interface) and
[background prompt submission](https://code.claude.com/docs/en/plugins/mods/api).


The [existing-identity joining smoke](../../docs/results/guided-native-join-smoke.json)
used the actual pinned terminal with two temporary hosts and a pre-existing,
independent recipient original key. Private paste, verified inventory, explicit
choice/review/approval produced one pending request with unchanged key bytes and
no participant/access approval. Close and parent re-entry succeeded; the final
native outcome lookup after re-entry remains a manual gate after automatic
approval review refused that terminal action. Source provenance, exact limits
and separate independent recovery coverage are recorded in the artifact.


## Complete this computer's machine link

After publishing through **Connect this computer**, press **Review machine link**.
Peerspan reads the existing computer's received approval, requester selection and
finalization. Missing evidence shows a waiting state; **Check machine requester
consent** reads again without contacting peers or driving the ceremony.

Review the exact person, remote provider, this host/device, finite powers and
fixed deadlines, then press **Review machine requester consent**. Preparation
records unsigned terms only. **Approve machine requester commit** records those
exact terms; **Complete machine requester commit** separately continues bounded
host/device signing, publication and local application. The original person key
stays on the existing computer. No original inventory, import or copy is needed.

**Local application: recorded** is retained global protocol evidence. Participant
delivery, current powers, agent access, connection readiness and model receipt
need separate checks. An uncertain action offers pure **Check machine requester
consent**, without automatically retrying. **Leave machine requester review**
closes controls and cannot retract dispatched work or revoke consent. Refresh,
Close, context changes and reload discard frontend evidence; reopen and read
the retained result. The final receipt records terminal/reload, installed two-host and actual-model acceptance separately; it makes no separate physical-machine claim.
