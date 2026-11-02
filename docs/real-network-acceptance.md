# Real-machine and NAT qualification

Status: external tests in progress, 2026-11-02. The owner prioritized this qualification before
PeerFS integration. [Guided onboarding #35](https://github.com/peerspan/peerspan/pull/35)
is merged at `caea24b9eb41bb078749c5a1f739cd3d186d060e`. Its
[final receipt](https://github.com/peerspan/peerspan/pull/35#issuecomment-6581460238)
proves installed flows and an actual model reply using two fixtures on one
machine. It does not establish independent-machine or real-router behavior.

The owner identified an existing authorized DigitalOcean droplet. It and the
development server are separately deployed Linux machines with public IPv4
addresses. Dedicated private test roots are installed on both; existing services
and credentials remain in place. No home/office router or hotspot participant is
available in the current inventory. No completed D1 or real-NAT pass is claimed.

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
| Existing-person machine ceremony | Failed in 7.202 seconds: exact public inspection succeeded; owner-consent preparation returned 409 `machine_owner_consent_unavailable`. Retained input matches the documented contract. A separate diagnostic build reproduced the refusal in 7.108 seconds and revealed underlying `state_conflict`; the failing internal phase remains under investigation. Diagnostic results do not qualify the release. |
| Distinct-person ceremony, original driver | Both hosts applied the completed ceremony. The driver then failed a proof assertion in 26.489 seconds: it incorrectly required network context on the initial request packet. The independent author corrected this to the wire contract's `-` context and retained signature and identity checks. |
| Distinct-person ceremony, corrected context assertion | Both host applications and signed proof checks passed. In 30.087 seconds the driver reached message enforcement, where its explicit-policy owner-local send returned 400 `invalid`. This establishes no receiver refusal. The owner-send/peer-wire distinction is under review; exact receiver checks will use an authenticated public peer probe. |

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
remain separate required observations. Helpers have been built and installed in
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
| N1: one real NAT | One participant behind a home/office router or hotspot, the other reachable; no new port forwarding. | Record actual onboarding behavior and direct versus relay use. Verify authorized delivery in both directions. A direct success requires observed direct traffic. |
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
