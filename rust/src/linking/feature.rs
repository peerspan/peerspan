//! Stateless upgrade-gate eligibility over caller-pinned catalog state.
use super::*;

/// The known feature must come from previously verified durable local state.
pub struct FeatureContext<'a> {
    pub network: &'a [u8],
    pub epoch: u64,
    pub known_feature_id: &'a str,
    pub now: chrono::DateTime<chrono::Utc>,
}

/// Eligibility for a future atomic write, not persistence or remote readiness.
#[derive(Serialize)]
pub struct FeatureEvidence {
    pub network_id: String,
    pub feature_id: String,
    pub epoch: u64,
    pub disposition: &'static str,
}

pub fn verify_feature(
    ctx: FeatureContext<'_>,
    catalog: &[u8],
    feature: &[u8],
) -> Result<FeatureEvidence> {
    let run = || -> Result<FeatureEvidence> {
        check(
            ctx.network.len() + catalog.len() + feature.len() <= MAX_ACTIVATION,
            "invalid",
        )?;
        let mut v = Verifier::new(ctx.network, ctx.epoch, ctx.known_feature_id, ctx.now)?;
        let r = read("feature", feature, &v.root, "-")?;
        check(
            ctx.known_feature_id == "-" || ctx.known_feature_id == r.id,
            "state_conflict",
        )?;
        v.catalog(catalog)?;
        v.index("feature", feature)?;
        let first = ctx.known_feature_id == "-";
        if first {
            // The roster for the reader upgrade cannot depend on a linking
            // operation that needs that very upgrade to be enabled already.
            check(
                !v.proofs.values().any(|p| {
                    matches!(
                        p.kind.as_str(),
                        "activation"
                            | "certificate"
                            | "person_record"
                            | "root_record"
                            | "device_revocation"
                            | "checkpoint"
                            | "invite_redemption"
                    )
                }),
                "forbidden",
            )?;
        }
        v.bootstrap(!first)?;
        v.revocations()?;
        if first {
            let o = obj(feature)?;
            let p = object(o.get("proposal").ok_or_else(|| problem("invalid"))?)?;
            let issued = stamp(text(p, "issued_at")?)?;
            check(
                ctx.now >= issued && ctx.now < issued + chrono::Duration::hours(24),
                "expired",
            )?;
            let roster: BTreeSet<_> = string_list(p, "host_public_keys")?
                .into_iter()
                .map(str::to_owned)
                .collect();
            let current: BTreeSet<_> = v
                .state
                .hosts
                .iter()
                .filter(|(_, admitted)| **admitted)
                .map(|(host, _)| host.clone())
                .collect();
            check(roster == current, "state_conflict")?;
        }
        Ok(FeatureEvidence {
            network_id: v.net,
            feature_id: r.id,
            epoch: ctx.epoch,
            disposition: if first { "activate" } else { "already_enabled" },
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

pub(super) fn probe_feature(o: &Obj) -> Value {
    let run = || -> Result<Value> {
        fields(
            o,
            "kind network_base64 catalog_base64 feature_base64 epoch known_feature_id now",
            &[],
        )?;
        let network = decode(text(o, "network_base64")?, MAX_ACTIVATION)?;
        let catalog = decode(text(o, "catalog_base64")?, MAX_ACTIVATION)?;
        let feature = decode(text(o, "feature_base64")?, MAX_ACTIVATION)?;
        let r = verify_feature(
            FeatureContext {
                network: &network,
                epoch: num(o, "epoch")?,
                known_feature_id: text(o, "known_feature_id")?,
                now: stamp(text(o, "now")?)?,
            },
            &catalog,
            &feature,
        )?;
        let mut result = serde_json::to_value(r)?;
        result
            .as_object_mut()
            .expect("serialized evidence")
            .insert("ok".into(), Value::Bool(true));
        Ok(result)
    };
    run().unwrap_or_else(|e| {
        if let Some(e) = e.downcast_ref::<PathError>() {
            if e.code == "proof_required" {
                json!({"ok":false,"code":e.code,"required_ids":e.required_ids})
            } else {
                json!({"ok":false,"code":e.code})
            }
        } else {
            json!({"ok":false,"code":"invalid"})
        }
    })
}
