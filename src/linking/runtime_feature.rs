//! Pre-upgrade proposal eligibility against the exact verified legacy roster.
use super::*;

pub struct FeaturePreparation {
    pub feature_id: String,
    pub epoch: u64,
    pub state: PathState,
}

pub fn verify_stored_feature_preparation(
    ctx: FeatureContext<'_>,
    catalog: &[u8],
    proposal: &[u8],
) -> Result<FeaturePreparation> {
    let run = || -> Result<FeaturePreparation> {
        check(
            proposal.len() <= MAX_OBJECT && ctx.known_feature_id == "-",
            "state_conflict",
        )?;
        check(
            ctx.network.len() <= MAX_ACTIVATION && catalog.len() <= MAX_STORED_CATALOG,
            "invalid",
        )?;
        let mut v = Verifier::new(ctx.network, ctx.epoch, "-", ctx.now)?;
        v.stored_snapshot = true;
        v.catalog(catalog)?;
        v.load_roots()?;
        let signed = read("feature_proposal", proposal, &v.root, "-")?;
        let p = obj(proposal)?;
        check(
            s(&p, "network_id") == v.net && num(&p, "epoch")? == ctx.epoch,
            "invalid",
        )?;
        let issued = stamp(text(&p, "issued_at")?)?;
        check(
            ctx.now >= issued && ctx.now < issued + chrono::Duration::hours(24),
            "expired",
        )?;
        for proof in v.proofs.values() {
            check(
                matches!(
                    proof.kind.as_str(),
                    "rotation"
                        | "coordinator_move"
                        | "coordinator_successor"
                        | "attestation"
                        | "admin_delegation"
                        | "admin_removal"
                        | "person_admission"
                        | "person_membership"
                        | "host_membership"
                        | "host_admission"
                        | "host_binding"
                        | "host_unbinding"
                        | "host_leave"
                        | "host_revocation"
                        | "invite_revocation"
                        | "person_removal"
                        | "group"
                        | "policy"
                ),
                "forbidden",
            )?;
        }
        v.feature_preparation = true;
        v.bootstrap(false)?;
        v.revocations()?;
        let hosts = string_list(&p, "host_public_keys")?;
        check(
            v.state.hosts.values().filter(|b| **b).count() == hosts.len()
                && hosts.iter().all(|h| v.state.hosts.get(*h) == Some(&true)),
            "state_conflict",
        )?;
        Ok(FeaturePreparation {
            feature_id: signed.id,
            epoch: ctx.epoch,
            state: v.state,
        })
    };
    run().map_err(|e| {
        if e.downcast_ref::<PathError>().is_some() {
            e
        } else {
            problem("invalid")
        }
    })
}
