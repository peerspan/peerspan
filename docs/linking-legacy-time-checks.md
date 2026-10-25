# Legacy timestamp compatibility at the linking boundary

Existing Go and Rust hosts emit UTC RFC3339 legacy statement times with
fractional seconds. A reader upgrade must verify these original signed records
without re-spelling any signed string or changing their proof IDs.

For legacy signed bodies only, accepted timestamps are `YYYY-MM-DDTHH:MM:SSZ`
or the same UTC form with `.` followed by 1 through 9 decimal digits before `Z`.
Calendar/time fields must be valid. Empty fractions, commas, offsets, more than
nine digits, whitespace and malformed dates remain invalid. Comparisons retain
the actual nanosecond precision.

This applies to existing rotations, attestations, administrator delegations and
format-1 removals, direct admissions/memberships/bindings/restrictions, direct
legacy policies/groups, coordinator moves/successors, and legacy invitations
embedded in a public redemption. It applies equally to historical verification
and fresh legacy writers; current authority and freshness still apply.

All new linking primitive timestamps remain exact whole UTC seconds: device
certificates, authorization envelopes and their typed payloads, revocations,
checkpoints, feature proposals, ceremony packets, redemption wrapper `joined_at`,
and root feature-import authorizations. A legacy invitation inside a new
redemption can retain its original fractional expiry; the new wrapper cannot
use fractional `joined_at`. New typed providers construct whole-second fields.

A separate author verifies valid independently signed legacy nanosecond facts
through feature preparation/activation and full stored network projection,
legacy policy/group time boundaries and invitation expiry, malformed legacy
forms, and unchanged strict rejection for new objects. Live Go/Rust setup also
uses actual emitted legacy data before enabling linking.
