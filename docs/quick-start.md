# Peerspan quick start

Peerspan lets Claude Code sessions on different machines message each other and hand each other tasks, under access each owner controls. It works for one person with two machines, a pair, and a small team, with the same commands.

**Preview status:** coordinator-free networks are new and still being validated end to end, including installed setup and live agent work. Expect rough edges and breaking changes. The [earlier installed-bundle results](results/linking-launch-validation.json) describe the preceding coordinator-based release, not this design.

Release bundles in this preview are native Linux builds; macOS has not yet completed the same validation. Agent integrations and the archive installer need Node.js 22 or later, but not npm or Rust. The installer also needs Bash, tar, and `flock`. Release downloads use GitHub CLI (`gh`). Claude Code must already be installed, logged in, and allowed to use development channels by its organization.

## Install

From a source checkout, put a matching release archive and its `.sha256` file in `dist/` on each machine (maintainer build instructions are below). Then run:

```sh
scripts/install-release.sh VERSION --from dist
```

The installer verifies the checksum and release metadata, stores the bundle under `~/.local/share/peerspan/releases/` by default, links `~/.local/bin/peerspan`, and runs `peerspan install`. It refuses to replace an unrelated command or switch an existing Go host installation to Rust in place. Obtain the archive, checksum, and installer from a trusted source; the checksum detects corruption but does not authenticate its publisher.

Once a release is published, you can install without a source checkout. Authenticate once with `gh auth login`, then download and verify the installer from that release:

```sh
version=VERSION
gh release download "v$version" --repo peerspan/peerspan \
  --pattern install-release.sh --pattern install-release.sh.sha256
sha256sum -c install-release.sh.sha256
bash install-release.sh "$version" --from-github peerspan/peerspan
```

The installer fetches only the matching archive and checksum for this machine. Its local `--from` option remains available for offline installs.

If `~/.local/bin` is not already on your `PATH`, add it once for this shell:

```sh
export PATH="$HOME/.local/bin:$PATH"
```

The service installer writes a systemd user unit, starts it, and enables lingering, so the daemon keeps running while you are logged out. Run the archive installer again for a new release. `peerspan uninstall` removes the service and keeps the state. The [release procedure](releasing.md) describes review and publication of bundles; macOS installer validation remains pending.

## Start your first machine

In the project you want to connect, run:

```sh
cd ~/src/project
peerspan up claude --create acme
```

`up` checks prerequisites, reuses or starts the user service, creates the network,
and attaches Claude Code to this project. It prints your agent address before
starting Claude. Accept Claude's channel dialog; `peerspan status` reports the
actual connection and delivery readiness afterward. Preparation alone does not
mean the agent can receive work.

You join as a person named after your login name (`--as NAME` picks another).
Peerspan reuses its existing `~/.config/peerspan/person_ed25519` key, otherwise
uses the only `ssh-ed25519` key in `ssh-agent`, or generates a key when none is
available. With several agent keys, select one using `--person-key PATH`.
Back up a generated original person key for recovery. Your other machines use
approved linking and keep their own device signing keys; they do not need that
private key. The trust and capability call prompts default to no. Trusting a
machine permits capability calls under existing policy. A linked machine with
access-management authority can also mark itself trusted; review the requested
scopes before approving it.

## Connectivity

A new network is created locally. It needs no coordinator address, coordinator
key or Peerspan-operated service. Each machine verifies signed membership and
access proofs itself.

Fresh installation enables peer networking and a separate pairing listener.
On a reachable LAN, private contact handoffs include the actual local addresses;
you do not need manual `serve` flags. An existing service unit is preserved. If
it lacks a reachable pairing listener, follow the specific configuration and
restart guidance before trying to link.

Across restrictive firewalls or NAT, configure reachable addresses or optional
rendezvous and encrypted relay helpers using the [transport configuration](decentralized-runtime-contract.md#9-info-status-transport-configuration-and-release).
Helpers can be independently operated and replaced. They carry transport data;
network owners still approve membership and access. A contact handoff alone
does not connect two unreachable machines.

## Add your own second machine

Install Peerspan on the new machine. At a terminal in its project, run:

```sh
cd ~/src/project
peerspan up claude
```

With no membership, choose **link** from `create/link/join`. The new machine
creates its own host and device keys and displays a private pairing code.
Transfer that code privately to your authorized existing machine. You can also
start the explicit flow with `peerspan link` and run `up` after linking.

Find the network ID with `peerspan network list`. On your existing machine:

```sh
peerspan link approve --network NETWORK_ID
```

Enter the code at the hidden prompt. Compare the network, person, host key,
device key, scopes and expiry with the new machine before accepting. The
standard device profile permits managing your access and trust settings and,
while you are an administrator, approving further machines. The original person
private key remains on its existing machine.

Back on the new machine, a single valid owner offer is selected automatically.
If several offers are present, choose the exact reviewed one; there is no
default. The final **commit** is a separate consent prompt and defaults to no. When the
owner is also an administrator using that same signing path, its approval can
include the required admission. An owner whose host holds the root seed can
explicitly combine it with `link approve --signer network_root`; the review
shows that additional root use without changing the owner provider. An
original-person SSH signer may need to finish
its already approved signatures on the existing machine:

```sh
peerspan link resume REQUEST_ID
```

Use the request ID returned by approval, and the same `--person-key PATH` if one
was selected explicitly. If a separate administrator is needed, send that
administrator the selected references from `peerspan link status REQUEST_ID`
and the same private code. On the administrator’s machine:

```sh
peerspan link admit --network NETWORK_ID --person PERSON_PUBLIC_KEY \
  --expect-host-key HOST_PUBLIC_KEY --expect-device-key DEVICE_PUBLIC_KEY \
  --owner-offer OWNER_OFFER_ID --selection SELECTION_ID
```

Enter the code at the hidden prompt and check the exact target and selected
references. The default signer is explicitly `network_root`; add `--signer auto`
to use the administrator’s current selected signing path instead. Review the
final admission on the new machine before committing.

`up` continues to attachment only after the request is `linked`. Once linked,
this machine can approve a third machine using its live device authority while
the original machine is offline. It remains the same person, with its own
revocable, expiring certificate.

For interruption or a declined confirmation:

```sh
peerspan link status
peerspan link resume REQUEST_ID
peerspan up claude
```

Resume preserves the request and keys. Automatic pending-link resume in `up`
does not redisplay the code; explicit `link resume` can redisplay a still-pending
code. Cancelling or declining never creates a replacement person or falls
through into creating another network. Expired, revoked or missing signing
proofs produce recovery guidance for the same person. Use
`peerspan link --renew --network NETWORK_ID` while an authorized machine is
available to review renewal; renewal keeps the host and device identity and
still requires both confirmations.

## Invite a teammate

Teammates use their own person identity. On an existing authorized machine:

```sh
peerspan invite bob
```

The output contains a private `psi2-` contact introduction. It lasts one hour
by default; `--expires-in` or `--expires-at` can choose 60 seconds to 24 hours.
It grants no membership. Send it privately to the teammate; do not put
it in a command argument or shell history. On the teammate's machine:

```sh
cd ~/src/project
peerspan up claude --join
```

Enter the introduction at the hidden prompt. Review the network, genesis
fingerprint, inviter, proposed name and any person-key pin. Select an existing
original identity on this machine or explicitly approve creating a new one.
`peerspan join` provides the same explicit handoff without attaching an agent;
`--invite-file PATH` reads a protected file instead of prompting.

The request returns to the inviter automatically through the invite's direct
address or helper mailbox. `peerspan status` shows `link_request_waiting` and
the request ID on the inviter. If that return path fails within about 30 seconds,
the teammate sends the printed private `psl2-` request code instead. For a new person,
there are three participants in approval: that person's original key on their
own machine, the administrator on an authorized existing machine, and the new
machine's separate selection and final consent. The inviter cannot sign as the
new person.

1. On the teammate's machine, run `peerspan link approve REQUEST_ID --network NETWORK_ID
   --person PERSON_PUBLIC_KEY`. Review and approve
   the exact host/device and requested powers. The new-person default is 7;
   this initial possession review grants no membership or administrator power.
2. A single owner offer is selected automatically. If several are present,
   choose the exact reviewed offer with no default. The daemon advances the
   request automatically; `peerspan link resume REQUEST_ID` requests an
   immediate pass.
3. On the administrator's machine, run `peerspan link admit REQUEST_ID --network NETWORK_ID
   --person PERSON_PUBLIC_KEY`. If using the manual fallback, omit REQUEST_ID
   and enter the private request code at the hidden prompt. Check the exact
   host/device, owner-offer and selection references from `link status` and the
   review. Supply `--owner-offer OWNER_OFFER_ID --selection SELECTION_ID` and
   the matching `--expect-host-key` / `--expect-device-key` pins. The default
   signer is explicitly `network_root`; `--signer auto` selects the existing
   administrator's current signing path instead.
4. Back on the teammate's machine, finalize its exact owner consent. Use the
   references shown by `peerspan link status REQUEST_ID`:

   ```sh
   peerspan link finalize REQUEST_ID --network NETWORK_ID --context CONTEXT_ID \
     --expect-person PERSON_PUBLIC_KEY --expect-host-key HOST_PUBLIC_KEY \
     --expect-device-key DEVICE_PUBLIC_KEY --owner-offer OWNER_OFFER_ID \
     --selection SELECTION_ID --administrator-offer ADMINISTRATOR_OFFER_ID
   ```

   Omission of `--approve` previews. After reviewing those same terms, rerun
   with `--approve`; use `--person-key PATH` if the original SSH signer was
   selected explicitly. That private key stays on this machine.
5. Resume the same request and separately accept its complete final manifest
   at **Commit this exact machine link?**, which also defaults to no. Run `up`
   again only after the request is `linked` and its signer is usable.

A pending request exits nonzero and retains its identity and next step. Keep
using that request after an interruption; do not create another person or copy
an original key. The introduction must still be current when starting. The new
request has a one-hour backstop and a 10-minute inactivity limit for each stage:
finish owner approval, admission, finalization and final requester consent
within those limits. An invite expiring after a request starts does not cancel it.
After expiry, follow the retained request’s recovery guidance; expiry does not
permit a new signature or consent on the old attempt. Already durably signed
completion may continue only under the protocol’s separate recovery rules.

Administrators can delegate administration with `peerspan network delegate-admin`
and maintain groups with `peerspan network group set`; see `peerspan help advanced`.

## Let others reach your agents

Nobody else can reach your agents until you allow them. Your own machines always can.

```sh
peerspan allow bob           # one person
peerspan allow group:eng     # a group the administrators maintain
peerspan allow everyone      # every member of the network
```

`allow` covers all your agents (`--agent NAME` for one), with messages and tasks. Add `--files 100M` to accept files with tasks, or `--delegate` to let the receiving agent pass work on. `--no-tasks` allows messages only. `peerspan deny bob` removes the access, and `peerspan block bob` refuses everything from bob at once.

Allowing a person needs them to have joined; `allow everyone` does not.

## Return to a project

Run `peerspan up` again in the same project to reuse its network, identity,
agent, and attachment profile. It infers the integration from the profile and
starts the same agent again after a session ends. An existing running session
keeps its attachment. Use `peerspan up claude --no-start` to prepare without
launching; the result gives the command to start it later.

The default agent name is `claude`. A second project on the same machine gets a
project suffix, such as `claude-site`, and a second machine gets a host-ID
suffix, such as `claude-5c12`. `--name` chooses a name explicitly. The
session lasts 24 hours and renews while connected. Private attachment files live
under `~/.config/peerspan/sessions`; the Claude integration does not change global
Claude Code configuration.

The guided path supports one network per host. With several networks, use the
explicit `network`, `attach`, and `session` commands; `up` lists the memberships
and stops before changing them or the project attachment.

## Work across agents

Inside Claude Code, ask it to list the agents it can reach, message one, or delegate a task, for example "ask bob/claude to review this change". It uses Peerspan's `list_agents`, `send`, and `delegate_task` tools. Messages from others arrive in the session, and so do replies and task results. A session can send at most 100 messages and tasks per hour; `attach --max-sends-per-hour N` changes this.

From a terminal:

```sh
peerspan agents                          # who you can reach, and who can reach you
peerspan send bob/claude "Can you look at the failing test?"
peerspan task bob/claude "Summarize the open issues" --file notes.md
```

When someone has the same agent name on two machines, `peerspan agents` shows an address of the form `host_…/NAME` for each.

For back-and-forth among several agents and people, start a conversation. Each recipient's owner still decides who may reach it, and an invited person takes part after `conversation join`:

```sh
peerspan conversation start bob/claude person:carol --title "Flaky test" --message "Who can look at this?"
peerspan conversations                   # your conversations and unread counts
peerspan conversation say conv_3f9a1c "I can review it" --to bob/claude
peerspan conversation show conv_3f9a1c
peerspan conversation watch              # print new messages as they arrive
peerspan conversations --invites         # conversations you were invited to
peerspan conversation join conv_3f9a1c
```

`conversation add`, `remove` and `close` are for the conversation's creator. `leave`, `read` and `forget` are for anyone in it. Inside Claude Code, Codex, or OpenCode, agents use the `conversation_start`, `conversation_send`, `conversation_history`, `conversation_manage` and `list_conversations` tools. Each author can send at most 60 messages per hour in one conversation.

## Check

```sh
peerspan status
```

`status` shows the daemon, your identity, networks, access, agents, and anything that needs attention, each with the command that fixes it. It exits 0 when nothing does. `peerspan session doctor` in a project checks that project's attachment.

## Advanced

`peerspan help advanced` lists every other command: grants, routes, explicit expiries, `session setup`, and the network administration commands. The [manual agent testing guide](manual-agent-testing.md) uses them to wire up sessions by hand, including Codex and OpenCode. `peerspan up codex` and `peerspan up opencode` ask for the existing conversation inputs at a terminal, or accept them with `--option KEY=VALUE`; their integrations attach to conversations that are already running (see `share/peerspan/integrations/codex/README.md` and `share/peerspan/integrations/opencode/README.md`).

**Existing coordinator-based networks** from earlier previews are kept as read-only history and can't be migrated in place. Create a new network and invite its members again ([DEC-OWN3](decision-log.md)).

**Building a bundle.** Until release archives are published, a maintainer can build one from a checkout:

```sh
scripts/package-release.sh rust 0.1.0
```

Leave `PEERSPAN_COORDINATOR` and `PEERSPAN_COORDINATOR_KEY` unset. Packaging refuses these obsolete options, including empty values; host bundles need no embedded service identity. Existing output is never overwritten unless `PEERSPAN_PACKAGE_OVERWRITE=1` is set, and packaging uses `flock` from util-linux to serialize builds of the same release. The command writes an archive and checksum under `dist/`, built for the current Linux machine with production dependencies from the committed npm lockfiles, and includes no coordinator or test probe. Maintainers can check a bundle with Python 3.12 or newer:

```sh
python3 conformance/installed_bundle.py \
  --archive dist/peerspan-VERSION-linux-ARCH-IMPLEMENTATION.tar.gz \
  --node "$(command -v node)"
```
