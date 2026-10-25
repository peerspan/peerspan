# Guided machine-link handoff

At a terminal, `up HARNESS --no-start` on a host with no memberships or pending
request offers `create/link/join`. The choice question is
`Create a network, link this machine, or join with an invite (create/link/join)`;
literal `link` starts one new request using the explicitly supplied coordinator
address/key, or the daemon's independently configured default. It does not ask
for or generate an original-person key. Network and person may remain unknown
until an exact owner offer is reviewed. Missing coordinator configuration stops
without inventing a pin.

That explicit new-link choice may display its private pairing code once on the
interactive terminal, as `link` does. The code does not enter the structured
setup result, activity, service journal or attachment profile. The guide waits
for the existing-machine approval, then asks the separately pinned owner-offer
selection and final-commit consent questions, both defaulting to no. It may
continue setup only after independently observing the request state `linked`.

When `up` discovers an existing pending request, it resumes the same identity
and exact request. This automatic resume does not display the pairing code;
`peerspan link resume REQUEST_ID` remains the explicit code redisplay command.
Declining either consent stage exits nonzero, ends with the ordinary
`setup.state: "incomplete"` result and its exact resume command, and does not
fall through into create/join, person generation, agent registration or profile
attachment. No ordinary setup stage can treat a successfully printed partial
link view as completed machine linking.

An independent installed-bundle author checks all CLI/daemon pairings, the
fresh `link` choice with its actual pinned coordinator, and blank/default-no
exits at both pending consent stages. Preserve the request, host/device/person,
existing service unit/state and attachment identities. Prepared setup remains
separate from adapter readiness and live model task completion.
