# Guided setup: `peerspan up`

Status: first Linux implementation of `up`, following the proposal accepted in
PR #38. Approved machine linking (`link`) is a subsequent milestone. The owner chose to prioritize guided setup on 2026-10-23 and defer
release repository variables. Both host implementations ship; Rust is the
recommended installation and Go remains supported.

## Result to build

After installing Peerspan, a person runs `peerspan up` in a project. It checks the
prerequisites, starts the local service, creates or joins a network when needed,
and attaches the selected coding agent. Running it again continues the existing
setup. It explains a partial result instead of treating a successful host join as
proof that identity and agent delivery also work.

This implementation uses today's person keys and invites. Approved linking
of another machine is a subsequent milestone with a separate identity proposal.
The [current setup baseline](setup-baseline.md) records the work this flow should
remove and the measurements that still require a person on separate machines.

## First implementation scope

- Linux, from an installed bundle, for both Rust and Go. The existing installer
  verifies the bundle, links the command, and installs the user service. `up`
  detects and reuses that service. Installation into a shell's `PATH` remains an
  installer concern.
- One network per host in the guided path. An existing host with several networks
  gets their names and IDs and instructions for the explicit commands. This keeps
  the first flow consistent with `attach`, whose session can use all of the
  host's networks; a selection in `up` must not imply a new network boundary.
- The shipped Claude Code, Codex, and OpenCode integrations, following each
  integration's existing lifecycle and prerequisites. Claude Code can be
  launched for the project. Codex and OpenCode attach to an existing conversation
  selected by the owner; starting their sidecar does not create a conversation.
- Existing owner access rules. Setup shows the access that already exists. A
  person grants access to teammates explicitly with `allow`; capability sharing
  remains a separate action.

macOS bundle and service validation remains a launch task. The first milestone
can be developed with local bundles and a test coordinator while release
configuration is deferred.

## Command surface

```text
peerspan up [HARNESS] [--create NAME | --join TOKEN] [OPTIONS] [-- HARNESS_ARGS...]
```

`HARNESS` accepts the same integration IDs and aliases as `attach`. With an
existing project attachment, an omitted harness reuses that integration. At a
terminal, a new attachment asks the person to select an integration. An installed
executable alone does not select a particular existing conversation.

| Input | Meaning |
| --- | --- |
| `--create NAME` | Create a network, or resume the single existing network with that name under the checks below. |
| `--join TOKEN` | Join the network named by the invite, or resume it if this host already joined it. |
| Neither | Reuse the host's single network. With none, ask whether to create or join at a terminal; otherwise stop with the missing inputs. |
| `--as LABEL` | Person label when creating a network; same default as `network create`. A join uses the label in the invite. |
| `--person-key PATH` | Select the person key using the existing onboarding behavior. |
| `--coordinator HOST:PORT --coordinator-key KEY` | Explicit coordinator for creation. Otherwise use the daemon's built-in default; joining uses the invite. |
| `--trusted` / `--untrusted` | Existing machine-trust choice for direct capability calls. The review explains its reach. |
| `--directory DIR` | Existing project directory, default the current directory, with the same canonicalization as `attach`. |
| `--name NAME` | Explicit agent name, with the same reuse and collision checks as `attach`. |
| `--option KEY=VALUE`, `--runner PATH`, `--integrations DIR` | Existing integration selection and configuration options. Required conversation identifiers are collected before enrollment. |
| `--calls` / `--no-calls` and rate limits | Existing attachment choices and bounds. Reusing a profile preserves its choices unless explicitly changed. |
| `--no-start` | Prepare the attachment and print how to start it later. This does not claim that the agent is connected. |
| Global `--state DIR` | Use the same daemon state selection as the explicit commands; retain the installer's refusal to replace a service using unrelated state. |
| Arguments after `--` | Passed to the integration's launch, following `attach`. They conflict with `--no-start`. |

The implementation reuses onboarding, service, attachment, and provider
operations through structured results. The setup command tracks their outcomes
and keeps identity selection and authorization in the existing operations.

## Flow

### 1. Check the machine and project

Before enrollment or agent registration, validate arguments, the project
directory, the selected integration, Node and integration prerequisites, and
required integration options. Report every known missing prerequisite with a
concrete repair step. Reuse the integration providers' checks, including account
and version checks where supplied.

For Codex, the owner selects an existing backend socket and loaded conversation.
For OpenCode, the owner supplies the existing server, conversation, project and
plugin binding configuration. The flow should explain where to find those
values. It does not choose an arbitrary conversation from a list or claim that
plugin installation has happened merely because a configuration path exists.

Malformed inputs, missing prerequisite executables, and missing required
conversation options leave network membership and agent registrations unchanged.
A coordinator check requires a pinned identity; a TCP connection alone is not a
successful coordinator check.

### 2. Ensure the daemon is available

Reuse an installed, active service. Install or start it when needed using the
existing service operation. Preserve its state and implementation. If a
foreground daemon or another service configuration prevents this, show the
existing install diagnostic and stop.

Report whether the service was already running or was started. If later setup
is cancelled, keep the installed service and explain that it remains running.
The normal service installer continues to own port selection and lingering.

### 3. Select and establish membership

Read the daemon's current memberships before submitting an enrollment request.

- With no memberships, ask **Create a network** or **Join with an invite**, unless
  the flags already choose. Ask for the network name or invite, then show the
  proposed coordinator, person label, and key source. Never echo or persist the
  invite in a setup transcript or resume file.
- With one membership, reuse it by default and show its network name, bound
  person, and coordinator. Explicit create or join inputs must identify that
  same network to resume; conflicting inputs stop with instructions to use the
  explicit network commands.
- With several memberships, list them and stop the guided path before making
  network or attachment changes.

Use the existing person-key selection order. A generated key is never replaced
to make a setup retry work. New-key output includes the existing backup advice.
On a second machine, explain the current same-person prerequisite: the same key
must be available through the SSH agent or the documented key-file copy. The
first milestone does not present an approval code that has no protocol behind it.

Validate an invite's format and signature before using its network ID to
determine whether a join already happened. A consumed or expired invite is not
redeemed again just to recover an existing local membership and attachment. For
creation, resume only a single matching local network, also checking any
explicitly supplied coordinator and person identity; the name alone is not
evidence of identity. A missing original person key is a recovery case, not a
reason to generate another. Ambiguous local state requires an explicit recovery
command.

When reusing a membership, sync through its recorded pinned coordinator and
inspect the structured `last_sync_error` as well as the HTTP result. Recheck the
person binding after that sync. An unavailable coordinator produces incomplete
setup and leaves the existing membership and attachment available for recovery.

Inspect the onboarding result and refreshed status. Both person admission and
this host's binding must succeed before attachment proceeds. Today's create and
join can return exit 0 with `person.bound: false`; `up` must report that as
incomplete setup, preserve the membership, and show the relevant recovery action.
It must not create another network, generate a replacement key, or report the
person as connected on a retry.

Keep the existing trust choice visible: trusting this machine enables its use of
the owner's capabilities, including selected write operations, and direct source
tools on hosts that explicitly allow it. Same-person message and task access
already exists under the current self-access rule. A machine holding the person
private key can sign a policy that marks itself trusted; the prompt must retain
that limitation. A teammate's join does not grant teammate access to agents or
capabilities. At a terminal, keep the existing trust question with an untrusted
default. Without a terminal, a new enrollment is untrusted unless `--trusted` is
explicit. `--untrusted` records that choice without prompting.

When resuming, preserve the current trust setting unless a trust flag explicitly
changes it through the existing `trust` or `untrust` operation. If a requested
trust change fails, report incomplete setup with that operation's repair step;
do not label the requested setting as applied.

### 4. Prepare and start the selected agent

Reuse the attachment profile for this canonical project and integration. Existing
agent naming, collision handling, credentials, expiry, call budgets, and
recovery remain those of `attach`. Explicit incompatible agent or integration
inputs produce the existing refusal instead of replacing another attachment.

Before starting the integration, print the person and agent address, network,
what was reused, current access, and any remaining attention items. Distinguish
**prepared**, **starting**, and **connected**. A successful `prepare`, a launched
process, and a listed MCP server do not prove delivery readiness.

With `--no-start`, exit after preparation and give the command to start the
selected session. Otherwise hand the terminal to the integration as `attach`
does. Claude's channel confirmation and readiness handshake remain required.
Codex and OpenCode sidecars continue to preserve their selected native
conversation. `status` and `session doctor` report the actual connection and
readiness after launch. The setup summary does not print an unconditional
"ready" before that evidence exists.

## Repetition, interruption, and output

| Situation | Required result |
| --- | --- |
| Run again in the same project | Reuse membership, person, agent, and profile; recover credentials using existing attachment rules. |
| Service exists but is stopped | Start it, then continue from recorded host state. |
| Host joined but its person is unbound | Stop before attachment with the identity repair step; preserve the existing membership. |
| Enrollment succeeded but attachment failed | Rerun resumes membership and retries only attachment. |
| New create or join input conflicts with existing state | Explain the conflict; do not enroll in another network or replace identity. |
| Missing or stale conversation selection | Explain which existing conversation input to fix; do not launch a replacement conversation. |
| User cancels or input ends | Stop, list completed stages and the command to continue. Keep valid completed state. |
| Coordinator is unavailable | Report the stage and error. Preserve existing membership and attachment; do not create a replacement network. |
| Adapter has not completed readiness | Show prepared or starting and the relevant diagnostic, without claiming messages can be delivered. |

Prompts and progress go to stderr. Existing integration stdout belongs to the
launched integration. `--no-start` prints a structured result naming completed
stages, reused objects, incomplete stages, and the next command. Exit 0 means
preparation completed, not that a live model has handled a message. Incomplete
preparation and missing input exit nonzero. Once the integration takes over,
its exit behavior follows the current launch operation.

The result envelope has `setup.state` (`prepared` or `incomplete`),
`setup.stages` (ordered `{stage, state}` entries, where state is `reused`,
`completed`, `failed`, or `pending`), `service`, `network`, `attachment`,
`attention`, and `next`. `service` and `attachment` retain their existing
operations' result shapes; `network` identifies the coordinator, network, and
bound person. An incomplete result names the failed stage and diagnostic in
`attention`, with later stages pending. It contains no invite or credential
secrets. A normal launch prints this envelope on stderr before handing over the
terminal, with preparation state still distinct from live connection state.

Without a terminal, `up` never waits for a prompt. Inputs must select an
integration or reusable profile, create/join or a reusable single membership,
and required integration options. New attachments default to capability calls
disabled unless `--calls` is given; existing profiles retain their choice.
Missing inputs are listed before remote enrollment or registration; supplying
flags does not authorize unrelated sharing or configuration changes.

Illustrative first-machine invocation after installation:

```sh
cd ~/src/project
peerspan up claude --create personal --as alice
```

Illustrative teammate invocation after receiving an invite:

```sh
peerspan up claude --join "$invite"
```

The [quick start](quick-start.md) uses this flow. The previous explicit commands
remain available and are checked with `launch_acceptance.py --explicit`.

## Verification for the implementation milestone

The shared behavior is checked across Go and Rust CLIs and daemons. The
installed-bundle end-to-end checks are `conformance/launch_acceptance.py` and
`conformance/up_acceptance.py`. New conformance suites continue to require a
separate author under [AGENTS.md](../AGENTS.md).

1. Fresh create, teammate join, and same-person second machine with an already
   available key, including explicit coordinator flags and a bundled default.
2. Interactive choices and explicit noninteractive inputs. Missing inputs, EOF,
   cancellation, invalid options, absent prerequisites and invalid project paths
   do not cause unintended enrollment or registration. Prompts never expose the
   invite or private credentials in captured output.
3. Repetition after each completed stage, stopped service, a failed attachment,
   already consumed invite, and network/person conflicts. Assert stable network,
   person, agent, and profile identities rather than just exit codes.
4. Successful host join with failed person admission or binding is incomplete;
   no agent is attached and the repair action is shown. The next run preserves
   the joined network and key.
5. Several memberships are listed and refused by the guided path; no selection
   implies that an attachment gained a narrower authorization scope.
6. New trust and capability calls default off, opt-ins are explicit, existing
   profile choices are preserved, and no teammate access or capability share
   appears as a side effect.
7. Claude prepared versus channel-ready states; Codex and OpenCode attachment to
   pre-existing conversations; missing, unloaded, stale, or busy targets retain
   the existing integration's protection and useful diagnostics.
8. Installed-bundle solo, pair, and team checks, including mixed implementations,
   then a separate live-agent run with a completed task and checked result. Record
   scripted evidence separately from model behavior and user observations.

Run the existing CLI, service, onboarding, directory, integration-setup, and
launch-acceptance checks covering the reused behavior. The implementation PR
should name the precise checks run and any remaining platform or live-test gap.

### Recorded Linux checks

The [implementation results](results/guided-setup.json) record clean bundles from
`c0a00243c644779dd86ed50d97ac4ea28e0449dc`: all four CLI/daemon recovery pairings,
seven guided quick-start runs, and seven explicit-command regression runs passed.
Each simulated machine used a fresh Linux user, independent state, and a real
systemd user service. Cleanup left no temporary users, homes, linger entries, or
processes.

| Path | Before `up` | With `up` |
| --- | --- | --- |
| One person, two machines | 8 | 6 |
| Two people | 9 | 7 |
| Three people | 14 | 11 |

Counts include installers, CLI commands and the same-person key copy. Both
implementations and the mixed team have the same counts. Preparation, downloads,
prerequisite installation, shell configuration and human handoff time remain
outside the count, as in the [baseline](setup-baseline.md#counted-steps).

The fixture agent completes the real adapter handshake and readiness response;
the runs verify discovery, message acceptance, and task delivery. They do not
establish model task completion or fresh-machine user experience. Live agents,
separate machines and macOS remain validation tasks. Approved linking still
needs its own design and implementation before the same-person key copy can be
removed.

## Task queue

| Task | Deliverable | Depends on | State |
| --- | --- | --- | --- |
| UP-01 | Current setup baseline: scripted counts and timing, plus observed fresh-machine friction | Existing bundles and acceptance harness | Scripted baseline recorded; separate-machine user observation remains |
| UP-02 | Exact `up` behavior, scope, recovery, and verification cases | UP-01 | Accepted in PR #38 |
| UP-03 | Guided orchestration in Rust and Go, reusing existing operations | UP-02 | Implemented; scripted Linux checks passed |
| UP-04 | Prerequisite, partial-identity, repeat/resume, and readiness handling | UP-02; ships with UP-03 | Implemented; scripted Linux checks passed |
| UP-05 | Approved machine-link identity and recovery design | Current identity and trust model | Accepted in [docs PR #9](https://github.com/peerspan/docs-internal/pull/9) |
| UP-06a | [Delegated signing contract, pairing primitives and fixed vectors](machine-linking-contract.md) | UP-05; existing person/admin rules | Accepted in [PR #41](https://github.com/peerspan/peerspan-internal/pull/41); no runtime changes |
| UP-06b | [Complete transaction schemas, routes, persistence, activation/upgrade and recovery contract](machine-linking-transactions.md) | UP-06a review | Accepted in [PR #43](https://github.com/peerspan/peerspan-internal/pull/43) |
| UP-06c | Shared verification and signed-state propagation in Go, Rust and coordinator; separately authored conformance | UP-06b review | In progress; genesis verification, stateless feature eligibility, current action authorization and ordinary admission/binding facts implemented; other catalog kinds and propagation pending |
| UP-06c.1 | [Strict signed-object readers and independent byte/signature checks](linking-reader-checks.md) in Go and Rust | UP-06b | Accepted in [PR #44](https://github.com/peerspan/peerspan-internal/pull/44); cryptographic evidence only |
| UP-06c.2 | Catalog resolution, current chain/role/feature checks, activation and retained-history authority | UP-06c.1 | In progress; genesis membership, activations, ordinary admission/binding facts and their retained history verified; other catalog kinds, root rotation, high-water and freshness remain |
| UP-06c.2a | [Exact certificate-path evaluation](linking-path-checks.md), using a verified current-state snapshot | UP-06c.1 | Accepted in [PR #45](https://github.com/peerspan/peerspan-internal/pull/45) |
| UP-06c.2b | [Build verified state from signed catalogs and complete activation transcripts](linking-activation-checks.md) | UP-06c.2a | Accepted in [PR #46](https://github.com/peerspan/peerspan-internal/pull/46) |
| UP-06c.2c | General catalog evidence: invite membership/redemptions, removals, root rotation, checkpoints/retained history, feature activation and high-water/freshness rules | UP-06c.2b | [Genesis membership, removals and retained link history](linking-history-checks.md) accepted in [PR #47](https://github.com/peerspan/peerspan-internal/pull/47); [stateless feature activation checks](linking-feature-checks.md) accepted in [PR #48](https://github.com/peerspan/peerspan-internal/pull/48); rotation, remaining ordinary catalog kinds/delegated invites, policy/group high-water and durable feature/freshness rules remain before writers |
| UP-06c.2d | [Current authorization for new ordinary management actions](linking-action-checks.md), including exact signer, expiry bounds and self-invalidation refusal | UP-06c.2b and genesis history/feature checks | Accepted in [PR #49](https://github.com/peerspan/peerspan-internal/pull/49) as a stateless gate; operation-specific state checks and runtime writers remain pending |
| UP-06c.2e | [Ordinary person/host admissions and host bindings](linking-record-checks.md), dependency resolution, exact retained history and renewal proof references | UP-06c.2c and UP-06c.2d | Implemented in Go and Rust as verified catalog facts; restrictive ordinary records, policies/groups and delegated invites/redemptions remain pending |
| UP-06c.3 | Durable signed-state storage, v2 maps, coordinator/peer propagation and recovery conformance | UP-06c.2 | Pending |
| UP-06d | Linking ceremony, signer discovery/renewal and integration with `up` in both hosts | UP-06c | Pending |
| UP-07 | Installed-bundle and live checks; verified quick start and installer handoff | UP-03 and UP-04; repeat after UP-06d | Scripted Linux checks passed; live-agent and fresh-machine validation pending |
| UP-08 | Clean macOS bundle, service, and guided-setup validation | Linux guided flow | Pending |

UP-03 and UP-04 provide the first guided flow with the current invite path. UP-05 and UP-06a through UP-06d then remove the same-person private-key copy and invite
handoff. Private preview release configuration resumes after the setup flow is
ready for that validation.
