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

## Reuse a live or reconnecting project attachment

`up` reuses an exact configured attachment for the same canonical project,
state, host, agent, session and integration when the original credential file
matches the daemon's existing token verification, the credential is unrevoked
and unexpired, and every requested setting is compatible with the saved profile.
The session and adapter IDs must match that profile. Omitted inputs inherit its
settings; explicit incompatible integration/name/options, expiry, calls or rate
budgets fail without replacing the attachment. This adds no credential, session,
lease extension, profile write or model readiness claim.

The additional reusable states are `ready` with session `attached`, or `offline`
with `recoverable: true` and session `attached` or `detached`. The public
connection result must match the exact adapter and session. A `registered`
credential keeps the existing preparation path; `revoked`, `expired`,
nonrecoverable `offline` and `detached` keep the existing recovery/refusal rules.
Explicit `attach` retains its existing live-session refusal and replacement
semantics.

Only this new `up` reuse result adds `attachment.connection`, the existing public
connection object, and `attachment.adapter_ready`, true only for the verified
`ready`/`attached` pair. With `--no-start`, setup returns `prepared` and
`attachment.reused: true` without changing that attachment. Normal `up` also
succeeds as prepared/reused for a ready attachment and explains that the existing
integration remains running; it never launches a duplicate. For a recoverable
offline attachment, normal `up` retains it and returns incomplete launch with
reconnect/session-doctor guidance, without launching a duplicate or claiming
connected state. No-argument repeat setup and credential renewal preserve the
same original attachment identities and private credential.

Check known explicit profile/settings conflicts during preflight, before service,
trust or enrollment changes. An omitted expiry inherits the saved attachment;
it is never compared with a newly generated default timestamp. After the normal
service and membership gates, independently revalidate the exact current token,
session, adapter and connection before reuse. This final check cannot replace
early rejection of a known incompatible request.

### Verification of existing attachment reuse

The independent installed renewal sequence checks the same canonical project
and original credential bytes before and after the new device certificate:

- With the original adapter `ready` and session `attached`, no-argument normal
  `up` succeeds as prepared/reused, reports that exact public connection and
  `adapter_ready: true`, and launches no duplicate integration. Host, person,
  agent, session, adapter, profile, service and private credential stay exact.
- After daemon restart, an `offline`, recoverable original attachment retains
  those identities and bytes. Normal `up` reports incomplete launch with its
  reconnect/doctor command, `adapter_ready: false`, and no duplicate process or
  replacement credential.
- In both states, `up --no-start` returns prepared/reused with the actual
  connection and truthful readiness. Explicit incompatible saved settings refuse
  before trust/enrollment changes, and explicit `attach` keeps its established
  behavior.
