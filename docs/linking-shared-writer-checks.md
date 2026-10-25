# Fresh host catalog additions

This mirrors the accepted coordinator mutation checks in
`linking-coordinator-checks.md`. Every previously unseen redemption or activation
in fresh statements or dependency additions must satisfy its direct first-use
time, current issuer/path/role and admission preconditions. Its own newly
supplied admission cannot establish these. Verify against candidate dependencies
with every newly supplied activation/redemption removed, then verify each exact
complete target. Earlier admission dependencies must be committed first or
explicitly repaired through historical recovery. Backdating cannot bypass an
expired invitation or operation deadline. Known exact durable objects and
explicit historical repair keep their existing semantics; failure writes none.

A new original-person legacy host binding may use new host/person admission or
membership targets from the same atomic request after each grant independently
passes first-use/current authority against pre-request authority. This supplies
consent targets only: newly supplied delegation/admission cannot authorize
another fresh grant. The final projection still applies all restrictions.

During a fresh root-rotation batch, the historical pre-action verifier may retain
new-current-root signed person-admission and administrator-delegation renewals
for persons/roles independently admitted/current in the complete pre-rotation
prior projection. Verify the prior projection at its own retained epoch and the
renewals against the independently verified new current root. This only preserves
existing authority while replaying old complete activations under the new epoch;
a newly admitted person or newly delegated administrator cannot authorize another
fresh mutation in that batch. All ordinary fresh action, version, restriction,
expiry and final complete-projection checks still apply.
