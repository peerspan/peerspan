package host

// These owner-local wire types are shared with the native client. Exporting
// their existing shape does not expose private signer state or add an API.
type DecCeremonyReview = decCeremonyReview
type DecApprovalResult = decApprovalResult
type DecConfirmationResult = decConfirmationResult
type DecActionReview = decActionReview
type DecActionResult = decActionResult
type DecPolicyContent = decPolicyContent
type DecPolicyReference = decPolicyReference
type DecPlanningStream = decPlanningStream
