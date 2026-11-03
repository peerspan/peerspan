# Real-machine and NAT qualification

Status: recorded cloud cases passed; managed NAT preparation in progress,
2026-11-03. The owner prioritized this qualification before PeerFS integration. [Guided onboarding #35](https://github.com/peerspan/peerspan/pull/35)
is merged at `caea24b9eb41bb078749c5a1f739cd3d186d060e`. Its
[final receipt](https://github.com/peerspan/peerspan/pull/35#issuecomment-6581460238)
proves installed flows and an actual model reply using two fixtures on one
machine. It does not establish independent-machine or real-router behavior.

The owner identified an existing authorized DigitalOcean droplet. It and the
development server are separately deployed Linux machines with public IPv4
addresses. Dedicated private test roots are installed on both; existing services
and credentials remain in place. No home/office router or hotspot participant is
available in the current inventory. Direct protocol, normal routing, native reply, forced relay, helper replacement
and pending-message recovery now pass on the named cloud deployments.
Real-router NAT and changed-network attachment remain unverified.

On 2026-11-03 the owner selected managed-cloud NAT and created a test
Droplet in a new NYC1 VPC, peered with the existing public Droplet's NYC2 VPC.
The owner supplied the private endpoint and confirmed that its NAT Gateway
is not yet created. The jump host now has a narrowly scoped host route through
its existing VPC gateway, without a networking restart. Private SSH times out
before authentication; the first TCP preflight is retained and the owner is
checking peering/firewall state. No protocol test has started on this VM. The
[preparation receipt](results/real-network-nat-preparation.json) records only
these prerequisites and evidence hashes; no NAT result is claimed yet. Managed provider NAT is a valid real external
gateway for N1; home/office routers and mobile networks remain distinct,
unverified coverage. SSH may use the VPC peering through the existing jump
host. Tested Peerspan traffic must instead reach the workspace server and
explicitly configured helper outside those VPCs through the NAT gateway.

The rebuilt candidate is clean release source
`7da06b7a2fd5604b76029aa833bb7e35c63d133a`, archive
`7be42766f7fa8157512c92225fecb1a750a19ca1c931d1deaecf6ce5fc5afe8c`, executable
`1104cf850b55f2f6a751a0d718bd4fd9301ea6ed272c7c63eabafe829951c6f0`.
Both independent direct ceremonies now pass: existing-person machine linking
in24.506 seconds and distinct-person linking/access/withdrawal in31.877 seconds.
The [protocol receipt](results/real-network-direct-protocol.json) retains the
explicit transport-pin limitation. A fresh separate normal-CLI check then
passes in25.943 seconds: two directory refreshes and two addressed accepted
sends, one in each direction, with zero configured peers and helpers disabled.
Its [receipt](results/real-network-cli.json) records private control/capture hashes.

The final independent [immediate-preparation regression](results/real-network-machine-prepare.json)
passes2/2 in11.6 seconds against the same release. Its prearmed resource helper
stores one genuine original frame while every successful original-frame GET is
held; both alternative participant bootstrap paths are counted refusal proxies.
The owner retains the authentic request/capability but exactly one observation
finds no original frame. Exact inspection/preparation returns200 in0.041 seconds,
unsigned/unapproved, with every original TCP/UDP counter and the helper's full
encrypted counters unchanged. After unconditional requester resume and transport
release, the same ceremony completes with signed authority on both hosts.
The receipt binds the final independent sources, dependencies, closed observations
and private failure logs. Earlier local opaque-gate success, its four fixture
failures, the two CI precondition failures and resource-helper setup failures
remain retained below; none is relabeled or hidden. Assertions and5s/120s bounds
were not relaxed. Final-head CI is the remaining software gate.

The first manual normal-routing attempt requested forbidden contact publication
and correctly failed startup. Its corrected configuration then exposed that
the Unicode stress-fixture agent names are deliberately not addressable. The
successful normal check uses valid addressable project-agent names. These are
diagnosed driver corrections; neither initial attempt is claimed as acceptance.

The first forced-relay phase also passes on the rebuilt candidate: same-person
ceremony23.564s/work17.187s and distinct-person ceremony27.505s/work19.217s.
The latter verifies a narrow guided grant, one receiver append, and actual
receiver refusals before grant and after withdrawal. Direct peer UDP is dropped
at both test hosts; the primary helper carries payload traffic and the second
helper is stopped. [Replacement](results/real-network-relay-r2.json) passes on those same retained
identities and signed authority: same-person work34.102s and withdrawn teammate
refusal17.444s. Captures show replacement-helper payload traffic and zero
primary-helper payload traffic after the primary stopped. Membership, policy,
requester approval and original key custody remain unchanged. The
[first-phase receipt](results/real-network-relay-r1.json) and replacement receipt
bind private controls, packet captures and scoped firewall observations. These controlled firewall results do not
establish consumer-router NAT behavior.

A native attempt observed fresh model readiness and an exactly correlated
reply retrieved by the droplet in32.115s. Its controller then terminated the
native process before the reply tool call/result reached the first-party
transcript. This is incomplete model provenance, not a complete native/model
receipt. The retained transcript also shows old fixture-message redelivery;
therefore the controller's proposed two-prompt count is not established. A
corrected manual check will use a fresh explicitly reviewed local agent in the
same existing native conversation, and wait within the unchanged model budget
for the exact first-party reply call and successful result before cleanup.
Earlier private outputs and the failed receipt assertion remain retained.
The transcript follow-up first refused fixture startup in0.056s because its
controller reused the previous attempt's PID metadata filename. No Claude
process/model turn started. The corrected controller uses unique owned process
metadata; it does not remove or overwrite the retained prior record.

The corrected [native receipt](results/real-network-native.json) passes in33.323s:
exact first-party Haiku `adapter_ready` and nonce-bound `message_reply` calls,
two successful correlated tool results, and the droplet's independently retrieved
reply matching request, recipient agent, host and original native conversation.
The fresh local agent was explicitly reviewed in the existing conversation;
there was no new network membership/access approval, manual peer pin or helper.
Installed archive plugin entry, Stop/Connect and actual reload are observed;
marketplace installation was not repeated. Transparent daemon/adapter restart
recovery is not claimed: restarting required explicit stale fixture-adapter
revocation and fresh local attachment/adapter consent.

The next bounded manual recovery phase will stop both configured helpers while
direct test UDP remains blocked. Restart the retained same-person test daemons,
submit exactly one fresh durable request, require an unconfirmed outcome and no
receiver append, then restore the same replacement helper and observe automatic
recovery of that exact request once. Existing authority, original key custody
and receiver work history must stay intact. No resubmission, new membership,
access approval or native/model turn is part of this120-second phase.

The first outage controller stopped before host/message work in2.002s: its
second helper inspection reused an exclusive evidence filename. The root
operator restored the owned replacement helper. The corrected controller uses
unique sequence-numbered evidence files and a fresh work/process-metadata root;
all prior output, including the failed automatic restore record, is retained.

The corrected [outage/recovery receipt](results/real-network-recovery.json)
passes in27.311s. With both helpers stopped and direct test UDP blocked, one
fresh send returns `unknown` in4.356s and adds no receiver message. Restoring
the same replacement helper lets the daemon's automatic retry deliver that
same durable request exactly once in12.996s, with no resubmission, reapproval,
regrant or key transfer. Both retained daemons were restarted for this check.
The path inspection still reported `relay` while the helper was unavailable;
this reports a route, and is not evidence of current delivery readiness.
Owned helper processes/captures and scoped firewall rules were removed afterward.

The remaining useful-work check will submit one bounded same-person task on
the two cloud hosts, with a small generated non-secret input artifact. A
credential-scoped deterministic receiver will read it through the adapter API,
compute its SHA256/byte count and upload a result artifact. The submitter must
retrieve the result through its daemon and independently compare exact bytes,
manifest hashes and ordered final task events. SSH carries control/manifest
metadata only, never either tested artifact. This is a120-second protocol/task
check with zero model turns; it does not substitute for the native model receipt.

The first task attempt returned a valid durable `unknown` outcome in11.840s,
with `configured relay is unavailable`: this retained fixture still named its
relay helpers, both intentionally stopped after recovery qualification. Its
peer captures contain no packets. The manual controller incorrectly required
immediate acceptance without first establishing a usable transport. No receiver
worker/model started. Preserve that request; its deadline is not extended or
resubmitted. The next fresh bounded task uses the explicitly restored replacement
helper with direct test UDP blocked, and requires observed relay delivery plus
the same artifact/hash/event checks. This is a recorded topology correction,
not a reinterpretation of the first unconfirmed request as acceptance.

The fresh [task/artifact receipt](results/real-network-task-artifact.json)
passes in16.575s over the observed replacement relay with direct test UDP
blocked:290 input bytes arrive through the scoped receiver adapter, which
computes a122-byte result. The submitter retrieves and independently verifies
its exact bytes and both manifests' hashes; queued/accepted/succeeded events
are contiguous and ordered. The receiver's new fixture credential is revoked.
No model turn or artifact content crosses SSH. Helpers, captures and scoped
firewall rules are cleaned up again; both original unrelated UDP listeners
remain, and no owned live fixture PID remains on either host.

CI on37ed9bc and02e5bc2 passes52 existing checks but fails the new immediate-prepare
regression before its measured owner operation: an original-frame/held-stream
precondition is unavailable. Initial PID/socket provenance already passed.
The independent author added receive-only closed diagnostics for the exact
failed conjunction, without changing observations, assertions or deadlines.
Those diagnostics prove the original frame was already present, while the
owner-owned held fetch and every other barrier remained live. The corrected
fixture will use a prearmed independent resource-route helper to block every
original-frame GET while allowing genuine publication and invitation return;
section42 records the exact proof/counter obligations and discarded options.
The first CI failures remain retained; no unexplained rerun is counted as a fix.

The first prearmed-resource regression run fails setup in0.6s before any helper
connection: the public invitation contains listener-derived default bootstrap
and QUIC contacts despite empty configured advertise arrays. Public contracts
do not define those arrays as disabling listeners. The corrected fixture will
explicitly advertise counted TCP refusal proxies backed by owned non-listening
reservations, plus counted QUIC endpoints, and verify that only the already
refusing proxy and sole prearmed helper can carry the original frame. QUIC
completion cannot serve mailboxes. Original absence, all counters, successful
continuation and5s/120s bounds remain unchanged; no product advertising change
or implicit bypass is introduced.

The explicit-refusal resource fixture then fails before the measured owner
operation in15.7s. Receive-only diagnostics identify self-signed TLS verification
error18 and a stale300-second original mailbox lifetime check. Canonical wire
formats9.1/12 require3600 seconds. Section42 settles mandatory pinned-host-key
mTLS for the independent helper, with full certificate/key/socket validation,
test-only pinned PyOpenSSL and unchanged encrypted counters/5s/120s bounds.
These are fixture compatibility corrections; no new product failure is inferred.

The pinned-key resource helper then authenticates both hosts, stores the genuine
original frame and holds its GET with zero TLS/mailbox/provenance failures. Its
2.3s setup failure is a carrier-cardinality assumption: the retained array
includes the inviter's counted refusal proxy as well as the requester's and H.
The corrected exact union/sort still excludes every other address/key/kind and
both actual daemon bootstrap listeners; no absence/counter assertion is removed.

Final-head a09f925 workflow validation fails before conformance execution:
the new dependency-install command used an unquoted YAML scalar containing a
colon followed by a space. The corrected literal-block command parses, retains
all47 matrix suites and installs the exact requirements for this suite only.
The failed workflow run and parser diagnostic are retained; an incomplete
check list is not counted as a passing software gate.

The corrected workflow at `8f60e69` passes the new immediate-preparation
regression. Its existing completion-rate suite fails a concurrent framed-replay
fixture control: both real responses are 200/linked, but the initial caller has
finished before replay capture. A shared frame marker does not identify the
API caller. The independent contract author confirmed that the documented
approval barrier can establish that caller's unique false-to-true consent
transition while background work reaches the separate frame hold. The final
acceptance contract records this stronger two-barrier prerequisite, preserving
the same single 5 second entry budget, 120 second suite limit and every existing
held-caller, refusal, replay and signed-application assertion. No product
source change or release retest is inferred. The
[first failed CI job](https://github.com/peerspan/peerspan/actions/runs/41510929385/job/125504625696)
and private full log are retained; log SHA256 is
`a23a8a624942432f145bfacc52e3a19784c30b1a19db04b78b2164824fd7d3d2`.

The corrected independent replay fixture passes all 6 cases in 16 seconds
against the retained CI binaries, with no production change. Both actual
markers are required within the original 5 second entry budget. The uniquely
approving caller remains held when the one exact replay returns 200; altered
pins return 409, immutable consent/commit proofs stay intact, and both hosts
apply the same canonical operation after release. The
[local receipt](results/real-network-ci-replay.json) records source/binary and
first-failure hashes. Final-head CI remains required; no unexplained rerun or
deadline extension is counted as a fix.

## Retained first failures

Both endpoints verified the same installed archive and executable. The archive
is `de999b569d91f27984dda34abe92548199eafee0a1e9cbdec5c5eb57ffe64e08`;
the executable is
`a47d7b3718ad6a958ada736d10ecb6712daeb290cd99b8a9f78454da45b9ce3e`.
Its clean release source is `d819cf8eef38509ad14151af8501ae2c62a2f7f5`.
Production and packaging tree identities match the merged candidate; this
branch initially adds only documentation and an independently authored driver.

| Observation | Outcome and next action |
| --- | --- |
| Public network preflight | TCP and UDP exchanges succeeded in both directions in 3.157 seconds. SSH carried control only. This is reachability evidence, not Peerspan acceptance. |
| Existing-person machine ceremony | Failed in 7.202 seconds: exact public inspection succeeded; owner-consent preparation returned 409 `machine_owner_consent_unavailable`. Retained input matches the documented contract. A separate diagnostic build reproduced the refusal in 7.108 seconds and revealed underlying `state_conflict`. A second diagnostic identifies the absent reconstructed pairing code: automatic return exposes the authenticated request before its original mailbox frame is fetched. NET-02 removes that second-fetch prerequisite; the rebuilt candidate now passes both external ceremonies. Broader topology qualification remains incomplete. Diagnostic results do not qualify the release. |
| Distinct-person ceremony, original driver | Both hosts applied the completed ceremony. The driver then failed a proof assertion in 26.489 seconds: it incorrectly required network context on the initial request packet. The independent author corrected this to the wire contract's `-` context and retained signature and identity checks. |
| Distinct-person ceremony, corrected context assertion | Both host applications and signed proof checks passed. In 30.087 seconds the driver reached message enforcement, where its explicit-policy owner-local send returned 400 `invalid`. This establishes no receiver refusal. The owner-send/peer-wire distinction is under review; exact receiver checks will use an authenticated public peer probe. |

The corrected authenticated-probe teammate check subsequently passed in35.952
seconds: two actual host applications, one exact guided access grant, one
receiver append, two403/forbidden receiver denials (before access and after
withdrawal), independent signed proof verification and zero original-key
transfers. Public-interface captures on both machines contain direct bootstrap
TCP and peer UDP traffic, with helpers disabled. The
[partial protocol receipt](results/real-network-teammate-initial.json) records
source/control/capture hashes. It does not complete D1, establish normal CLI
routing, or qualify the pending product fix.

Original controls, daemon logs and packet captures remain private. No failed
attempt is relabeled as passing, and no unexplained attempt is rerun to obtain a
green result. The original control evidence indexes have SHA256 identities
`07cd542df4454d24012f3f4273026ba1719cff896eafd34a7ab88b9a552bc639`
(machine) and
`92a3aeed6c443e80d2012ca6450add96818d4618924b70d5c4adb6973b387ab7`
(teammate).

The protocol driver uses two explicit `/v1/peers` transport pins after membership
application. Those pins grant no authority, but they mean its eventual message
result cannot establish automatic directory routing. Normal CLI/directory sends,
native-terminal use, a model reply, forced relay, helper replacement and recovery
were subsequently observed separately on the rebuilt candidate, as recorded above. Helpers have been built and installed in
isolated prefixes; they were not running during these direct attempts.

## Candidate and deployment

- Freeze one clean source revision and checksummed Linux archive for the matrix.
  Record RELEASE.json, installed executable hashes, architecture, OS, Node and
  native-agent versions on every participant. Rebuild after a product change.
- Use separate machines and dedicated test users/projects. Privately record
  their deployment identities and actual network attachment. Different host
  keys, process IDs or container names alone do not establish separate machines.
  Report cloud instances as instances; do not infer bare-metal hardware identity.
- Obtain explicit test endpoints from the owner or an existing authorized test
  inventory. Do not repurpose an unrelated host discovered in SSH history.
- Keep personal services, networks and agent conversations separate. Scope any
  temporary network impairment to the test processes, ports or network namespace;
  retain the management connection and restore the original test configuration.
- Use existing SSH authentication without copying credentials. Generate each
  participant's test identity on that participant. Never copy the original
  person key to link another machine. Transfer private invitations through a
  private channel, outside arguments, routine logs and model context.
- Treat SSH as orchestration only. Peer messages, authority and files must cross
  the actual Peerspan transport, with no SSH tunnel carrying the tested data path.

## Topology matrix

Record the actual gateway/firewall configuration and the observed Peerspan path
for every case. A successful helper health check is not a relay-delivery result.
The NAT cases require a real external gateway; local namespaces remain useful
controlled fault checks, reported separately. Availability of the required
machines/gateways is a prerequisite, never an implicit pass.

| Case | Setup | Required observation |
| --- | --- | --- |
| D1: independent hosts | Two separately deployed, reachable Linux machines; every optional helper disabled. | Installed onboarding and authorized work complete over the actual direct peer path. |
| N1: one real NAT | One participant behind a real managed-provider NAT gateway, home/office router or hotspot, the other reachable; no new port forwarding. Record the actual gateway class. | Record actual onboarding behavior and direct versus relay use. Verify authorized delivery in both directions. A direct success requires observed direct traffic. |
| N2: two real NATs | Participants behind two independent external gateways, with an explicitly configured replaceable rendezvous/relay helper where needed. | Complete onboarding and work; record which paths were actually established. A relay success does not count as hole-punching success. |
| R1: forced relay | On independent hosts, disable only the test participants' direct peer path, retaining connectivity to the configured helper. | End-to-end encrypted work reaches the receiver through the observed relay. No helper grants membership or access. |
| R2: helper replacement | Prepare a second separately configured helper endpoint; withdraw the first while direct traffic remains unavailable. | Recover through the second helper with the same participant identities and existing authority; no new membership or access grant. If both helpers are unavailable, report unavailable rather than ready. |
| O1: interruption | Restart a test daemon, take a participant offline, then reconnect within valid authority. | Retained native conversation, recoverable pending outcomes, and a fresh authorized request after reconnection. Record interruption and recovery times. |
| O2: changed attachment | Where available, move a NAT participant between its ordinary network and a hotspot. | Record address/path change and whether the existing session recovers. Do not infer this result from a daemon restart or local NAT emulation. |

Do not require a direct path through a topology that cannot provide one. Require
successful encrypted relay delivery where the recorded supported configuration
provides it, and accurate unavailability when no permitted path exists. Record
unavailable topology prerequisites explicitly; they remain unverified.

## Product checks on the matrix

Follow [manual acceptance](manual-agent-testing.md) and the public guided flow,
recording each participant's actual terminal decisions and waiting states.

1. **One person, two machines.** Link a new device through the existing owner's
   explicit review. Verify separate host/device keys, finite device7/binding2
   authority and actual application on both machines, with no original-key copy.
2. **Two people.** Complete invitation, identity, owner/admin and requester
   reviews. Membership alone must not enable the other person's agent access.
   Use an exact explicit access grant, then observe receiver-enforced delivery.
3. **Useful work.** In the existing native conversation, obtain fresh adapter
   readiness and a correlated model reply. Separately run a bounded task with
   a non-secret input and independently checked result artifact. Keep model
   output, adapter readiness, peer observation and durable task state distinct.
4. **Withdrawal.** Withdraw the distinct person's access and verify that new
   work is refused by the receiver, including over the relay. No new request
   reaches the agent after the refusal. Historical completed work remains history.
5. **Recovery.** Exercise daemon restart, offline catch-up and helper replacement
   without repeating approval or silently replacing the conversation. A changed
   attachment or changed review requires its documented explicit consent.

Run the full same-person and two-person ceremonies on D1 and on the restricted
network configuration. For each additional topology, repeat the correlated
exchange, receiver refusal and applicable recovery check. Follow the existing
operation, UI and model time bounds; do not retry an unexplained failure to
produce a green result. Preserve first failures and record the diagnosed
correction or external topology change before a new attempt.

Existing conformance remains the protocol regression gate. If a failure requires
a product change, add any new protocol cases through a separate contract-only
author under [AGENTS.md](../AGENTS.md), rebuild the artifact, run affected suites
and applicable Rust/packaging gates, and repeat the affected real-network cases.
Actual installed/live drivers remain the separate end-to-end evidence layer.

## Evidence and completion

Retain private deployment and network evidence, packet/path observations, exact
request/session correlation, transcript locations, source/archive identities,
first failures and cleanup results. Commit only sanitized topology descriptions,
fixed outcomes, versions and evidence hashes. Exclude credentials, private codes,
message contents and participant addresses from the public receipt.

Complete this work only with a reviewed receipt naming the cases actually run,
their outcomes, remaining topology limits, and the final tested candidate. Keep
direct, real-NAT, controlled impairment, relay and model results separate.
Qualify the named matrix; do not claim universal success through arbitrary NAT.
An unavailable real-router case remains open even when local fault checks pass.

### Managed-cloud N1 execution contract

Use the owner's new private-only NYC1 Droplet and the independently deployed
public workspace server. Before a protocol run, root records both actual
deployment identities, the private VM's interface addresses and IPv4/IPv6
routes, its NAT egress address, the managed gateway/default-route configuration,
and the jump host's narrowly scoped management route. No public VM interface,
inbound port forwarding, SSH peer-data tunnel, private peering route between
the tested participants or local NAT emulation may substitute for this topology.
SSH peering is management only. Keep provider identifiers and addresses private;
publish only the topology class and sanitized evidence hashes.

Install the same verified archive and separately identified tools in isolated
prefixes. Run fresh same-person and distinct-person ceremonies with genuine
ordinary guided reviews. Independently verify both actual signed applications,
finite device7/binding2 authority, exact requester consent and local original
key custody. No manual peer pins, fabricated authority, database mutation,
clock extension or original-key transfer is permitted.

Configure one explicit pinned resource helper outside the peered VPCs, with
protected generated resource credentials stored locally and no network authority.
Its bootstrap and relay pins must be included in the actual invitation review.
The private VM advertises its actual non-wildcard local listener address as a
hint; no invented public IP or static external port mapping is allowed. Keep
normal peer traffic unblocked in this N1 phase. A valid direct or encrypted
relay path may carry work; do not require one path or infer successful direct
traversal from a diagnostic route label. Record each participant's actual path
diagnostic without converting a route observation into readiness. Root captures
the owned test ports at both actual participants and the helper, establishing
which path carried payload and the NAT source translation actually observed.

After each ceremony, retain the same participant state for a separately bounded
work phase. For the same person, ordinary directory lookup and addressed CLI
sends must deliver exact fresh requests in both directions, with matching real
receiver receipts/appends. For two people, membership alone must be denied by
the receiver; one narrow guided access grant permits exact delivery, and its
withdrawal refuses fresh work with no receiver-history append. A durable rejected
owner outcome with an actual attempt is not an exact peer HTTP403 claim. Do not
replace a receiver check with an address-resolution failure. Preserve existing
authority, reviewed policy, requester consent and original-key custody; check
that no manual peer/grant configuration was introduced.

Use the existing 120 second bound for each ceremony/work phase and unchanged
owner-operation bounds. An initially unknown send may observe only that exact
durable request's ordinary automatic retries within its existing deadline;
never submit another command or extend the deadline to obtain success. Retain
first failures and close owned processes on failure or completion. The driver
must validate its private fleet configuration and bounded output categories,
keep all codes/content/credentials/raw endpoint and path details private, and
emit only fixed outcomes/counts, source/archive/log hashes and coverage limits.
Private state retained between phases has public-proof checkpoints; it is not
an authority shortcut. Root alone provisions hosts/helper/routes/captures and
runs committed independent driver source. The independent author reads public
contracts and independent harnesses only, never product source or product runtime.

This observes one managed NAT against a reachable participant. It does not
qualify two independent NATs, home/mobile gateways, changed attachment, native
model behavior or transparent adapter restart. These require their own named
observations. Selected: provider NAT plus peering only for SSH, with explicit
replaceable helper and recorded actual data path. Discarded: blocking a public
VM's inbound traffic and calling it NAT, public IPv6 bypass, passing peer traffic
through the private peering/tunnel, requiring a fabricated direct result, or
assuming the NYC1/NYC2 placement from earlier reversed region descriptions.

## Next: PeerFS host integration

After this qualification, the next integration is PeerFS milestone3b, tracked
by [the existing daemon-bridge issue](https://github.com/peerspan/peerspan-internal/issues/137).
PeerFS already has local storage/workspaces, signing interfaces, and pull/push
between spaces; its [current implementation](https://github.com/peerspan/peerfs#status)
still lists host-managed signing, cross-host replication and durability receipts
as missing. Do not rebuild those local filesystem pieces in the host daemon.

The recommended first reviewable slice is:

1. Specify the local daemon/PeerFS contract: explicit space registration, socket
   ownership/lifetime, bounded errors, host-backed `Signer`/`HostKeys` behavior,
   and grant-checked object/branch operations. The daemon remains the network
   and authorization edge; the local PeerFS admin socket is never exported.
2. Specify signed `fs.read` authorization for an explicitly shared space/branch
   and its reachable objects. Hash knowledge alone grants no read access; an
   agent message grant grants no filesystem access. Define narrowing before
   claiming path-restricted sharing.
3. Wire an actual read-only pull through Peerspan into a local PeerFS workspace
   on the second machine. Verify content identities and author signatures,
   interrupted-transfer recovery, refusal of unshared objects and withdrawal.
4. Run that slice on the qualified direct and relay paths. Keep the host contract
   shared with the separately maintained Go implementation; Rust is the default
   implementation in this repository.

The first visible result is an agent on machine B reading an explicitly shared
branch from machine A in its own local workspace. Follow with authorized push
and home-host compare-and-swap, then signed closure/durability receipts and
offline catch-up. Remote execution and sandbox mounting remain later consumers.
This ordering is a recommendation for the next contract, not a claim that new
`fs.*` commands or routes are available today.
