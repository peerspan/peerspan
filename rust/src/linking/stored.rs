//! Fixed complete-snapshot budgets; normal verifier contracts remain unchanged.
use super::*;

pub const MAX_STORED_CATALOG: usize = 16 << 20;
pub const MAX_STORED_BODIES: usize = 8 << 20;
pub const MAX_STORED_PROBE: usize = 24 << 20;

pub(super) fn verification_budget(
    stored: bool,
    network: usize,
    catalog: usize,
    object: usize,
) -> bool {
    if stored {
        catalog <= MAX_STORED_CATALOG && network + object <= MAX_ACTIVATION
    } else {
        network + catalog + object <= MAX_ACTIVATION
    }
}
pub(super) fn catalog_probe_limit(stored: bool) -> usize {
    if stored {
        MAX_STORED_CATALOG
    } else {
        MAX_ACTIVATION
    }
}

/// Verify all stored public facts without truncating the catalog.
pub fn verify_stored_catalog_facts(
    ctx: CatalogFactContext<'_>,
    catalog: &[u8],
) -> Result<CatalogFacts> {
    records::verify_catalog_facts_budget(ctx, catalog, true)
}
/// Verify an activation against its complete stored dependency closure.
pub fn verify_stored_activation(
    ctx: ActivationContext<'_>,
    catalog: &[u8],
    activation: &[u8],
) -> Result<ActivationEvidence> {
    verify_activation_budget(ctx, catalog, activation, true)
}
/// Verify current action authority against the complete stored state.
pub fn verify_stored_action_authority(
    ctx: ActionContext<'_>,
    kind: &str,
    catalog: &[u8],
    action: &[u8],
) -> Result<ActionAuthority> {
    action::verify_action_authority_budget(ctx, kind, catalog, action, true)
}
/// Verify feature eligibility against the complete stored state.
pub fn verify_stored_feature(
    ctx: FeatureContext<'_>,
    catalog: &[u8],
    feature: &[u8],
) -> Result<FeatureEvidence> {
    feature::verify_feature_budget(ctx, catalog, feature, true)
}
/// Observe access maxima against the complete stored state.
pub fn verify_stored_access_state(ctx: AccessContext<'_>, catalog: &[u8]) -> Result<AccessState> {
    policy::verify_access_state_budget(ctx, catalog, true)
}
