//! Explicit current-root recovery binds one exact historical snapshot and target.
use super::*;
pub struct FeatureImportEvidence {
    pub feature_id: String,
    pub state: NetworkState,
}
pub fn verify_stored_feature_import(
    ctx: CatalogFactContext<'_>,
    catalog: &[u8],
    authorization: &[u8],
) -> Result<FeatureImportEvidence> {
    let run = || -> Result<FeatureImportEvidence> {
        check(
            authorization.len() <= MAX_OBJECT && catalog.len() <= 1 << 20,
            "invalid",
        )?;
        let mut v = Verifier::new(ctx.network, ctx.epoch, ctx.known_feature_id, ctx.now)?;
        v.stored_snapshot = true;
        v.catalog(catalog)?;
        v.load_roots()?;
        if authorization == b"\"-\"" {
            let state = verify_stored_network_state(
                CatalogFactContext {
                    network: ctx.network,
                    epoch: ctx.epoch,
                    known_feature_id: ctx.known_feature_id,
                    now: ctx.now,
                },
                catalog,
            )?;
            return Err(missing(&state.facts.feature_id));
        }
        let o = obj(authorization)?;
        fields(
            &o,
            "format network_id network_name epoch feature_id coordinator_address coordinator_public_key catalog_sha256 issued_at expires_at signature",
            &[],
        )?;
        version(&o, 1)?;
        for (field, descriptor) in [
            ("network_id", "network_id"),
            ("network_name", "name"),
            ("coordinator_address", "coordinator_address"),
            ("coordinator_public_key", "coordinator_public_key"),
        ] {
            check(text(&o, field)? == text(&v.network, descriptor)?, "invalid")?;
        }
        let epoch = num(&o, "epoch")?;
        check(epoch == v.epoch, "invalid")?;
        let feature = text(&o, "feature_id")?;
        check(ident(feature, "lf_"), "invalid")?;
        check(
            ctx.known_feature_id == "-" || ctx.known_feature_id == feature,
            "state_conflict",
        )?;
        check(text(&o, "catalog_sha256")? == hash(catalog), "invalid")?;
        let issued = stamp(text(&o, "issued_at")?)?;
        let expires = stamp(text(&o, "expires_at")?)?;
        check(
            expires == issued + chrono::Duration::seconds(300) && ctx.now >= issued,
            "invalid",
        )?;
        check(ctx.now < expires, "expired")?;
        let message = lines(&[
            "peerspan-link-feature-import-v1",
            text(&o, "network_id")?,
            text(&o, "network_name")?,
            &epoch.to_string(),
            feature,
            text(&o, "coordinator_address")?,
            text(&o, "coordinator_public_key")?,
            text(&o, "catalog_sha256")?,
            text(&o, "issued_at")?,
            text(&o, "expires_at")?,
        ]);
        root(&v.root, &message, text(&o, "signature")?).map_err(|_| problem("invalid"))?;
        let state = verify_stored_network_state(
            CatalogFactContext {
                network: ctx.network,
                epoch,
                known_feature_id: feature,
                now: ctx.now,
            },
            catalog,
        )?;
        Ok(FeatureImportEvidence {
            feature_id: feature.into(),
            state,
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
