//! Current authorization for a separately supplied ordinary management action.
use super::*;

/// Pins from verified local state and exact signer selection, never discovery.
pub struct ActionContext<'a> {
    pub network: &'a [u8],
    pub epoch: u64,
    pub known_feature_id: &'a str,
    pub person_public_key: &'a str,
    pub certificate_id: &'a str,
    pub now: chrono::DateTime<chrono::Utc>,
}

/// Current signing authority, not an applied action or a transaction result.
#[derive(Serialize)]
pub struct ActionAuthority {
    pub action_kind: String,
    pub record_id: String,
    pub network_id: String,
    pub feature_id: String,
    pub person_public_key: String,
    pub certificate_id: String,
    pub required_scope: u64,
    pub not_after: String,
}

/// The complete selected path that would be disabled, oldest ancestor first.
#[derive(Debug)]
pub struct ActionInvalidation {
    pub certificate_ids: Vec<String>,
}
impl std::fmt::Display for ActionInvalidation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "linking action: authority_would_be_invalidated")
    }
}
impl std::error::Error for ActionInvalidation {}

fn action_scope(kind: &str) -> Result<u64> {
    Ok(match kind {
        "peerspan-policy-v1" | "peerspan-policy-v2" => 1,
        "peerspan-host-bind-v1" | "peerspan-host-unbind-v1" => 2,
        "peerspan-host-admit-v1"
        | "peerspan-person-admit-v1"
        | "peerspan-person-remove-v1"
        | "peerspan-revoke-host-v1"
        | "peerspan-revoke-invite-v1"
        | "peerspan-invite-v1"
        | "peerspan-person-invite-v1"
        | "peerspan-group-v1" => 8,
        _ => return Err(problem("invalid")),
    })
}

pub fn verify_action_authority(
    ctx: ActionContext<'_>,
    action_kind: &str,
    catalog: &[u8],
    action: &[u8],
) -> Result<ActionAuthority> {
    verify_action_authority_budget(ctx, action_kind, catalog, action, false)
}
pub(super) fn verify_action_authority_budget(
    ctx: ActionContext<'_>,
    action_kind: &str,
    catalog: &[u8],
    action: &[u8],
    stored: bool,
) -> Result<ActionAuthority> {
    let run = || -> Result<ActionAuthority> {
        check(
            verification_budget(stored, ctx.network.len(), catalog.len(), action.len())
                && key(ctx.person_public_key)
                && (ctx.certificate_id == "root" || ident(ctx.certificate_id, "dc_"))
                && matches!(action_kind, "person_record" | "device_revocation"),
            "invalid",
        )?;
        let mut v = Verifier::new(ctx.network, ctx.epoch, ctx.known_feature_id, ctx.now)?;
        v.stored_snapshot = stored;
        check(ctx.known_feature_id != "-", "upgrade_required")?;
        v.catalog(catalog)?;
        v.load_roots()?;
        let o = obj(action)?;
        check(
            s(&o, "network_id") == v.net && s(&o, "person_public_key") == ctx.person_public_key,
            "invalid",
        )?;
        let kind = s(&o, "kind");
        let required = if action_kind == "person_record" {
            check(
                s(&o, "certificate_id") == ctx.certificate_id
                    && s(&o, "operation_id") == "-"
                    && num(&o, "epoch")? == v.epoch,
                "invalid",
            )?;
            action_scope(kind)?
        } else {
            check(
                s(&o, "issuer_certificate_id") == ctx.certificate_id,
                "invalid",
            )?;
            4
        };
        v.bootstrap(true)?;
        v.revocations()?;
        let path = v.authority(ctx.person_public_key, ctx.certificate_id, required, 0)?;
        let r = read(action_kind, action, &path.signer_public_key, "-")?;
        validate_action_effects(&ctx, action_kind, kind, &o, r.payload.as_deref(), &v, &path)?;
        Ok(ActionAuthority {
            action_kind: action_kind.into(),
            record_id: r.id,
            network_id: v.net,
            feature_id: v.feature,
            person_public_key: ctx.person_public_key.into(),
            certificate_id: ctx.certificate_id.into(),
            required_scope: required,
            not_after: path.not_after,
        })
    };
    run().map_err(|e| {
        if e.downcast_ref::<PathError>().is_some()
            || e.downcast_ref::<ActionInvalidation>().is_some()
        {
            e
        } else {
            problem("invalid")
        }
    })
}

pub(super) fn probe_action(o: &Obj, stored: bool) -> Value {
    let verify = if stored {
        verify_stored_action_authority
    } else {
        verify_action_authority
    };
    let run = || -> Result<Value> {
        fields(
            o,
            "kind action_kind network_base64 catalog_base64 action_base64 epoch known_feature_id person_public_key certificate_id now",
            &[],
        )?;
        let network = decode(text(o, "network_base64")?, MAX_ACTIVATION)?;
        let catalog = decode(text(o, "catalog_base64")?, catalog_probe_limit(stored))?;
        let action = decode(text(o, "action_base64")?, MAX_ACTIVATION)?;
        let r = verify(
            ActionContext {
                network: &network,
                epoch: num(o, "epoch")?,
                known_feature_id: text(o, "known_feature_id")?,
                person_public_key: text(o, "person_public_key")?,
                certificate_id: text(o, "certificate_id")?,
                now: stamp(text(o, "now")?)?,
            },
            text(o, "action_kind")?,
            &catalog,
            &action,
        )?;
        let mut result = serde_json::to_value(r)?;
        result
            .as_object_mut()
            .expect("serialized authority")
            .insert("ok".into(), Value::Bool(true));
        Ok(result)
    };
    run().unwrap_or_else(|e| {
        if let Some(e) = e.downcast_ref::<ActionInvalidation>() {
            json!({"ok":false,"code":"authority_would_be_invalidated","certificate_ids":e.certificate_ids})
        } else if let Some(e) = e.downcast_ref::<PathError>() {
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

/// Strict ordinary unsigned payload parsing; this supplies no signing authority.
pub fn validate_action_payload(kind: &str, raw: &[u8]) -> Result<()> {
    let run = || -> Result<()> {
        action_scope(kind)?;
        let p = parse_limit(raw, MAX_PAYLOAD)?;
        record_payload(kind, object(&p)?)?;
        Ok(())
    };
    run().map_err(|_| problem("invalid"))
}

fn validate_action_effects(
    ctx: &ActionContext<'_>,
    action_kind: &str,
    kind: &str,
    o: &Obj,
    payload: Option<&[u8]>,
    v: &Verifier<'_>,
    path: &SigningPath,
) -> Result<()> {
    let invalidate = || -> anyhow::Error {
        ActionInvalidation {
            certificate_ids: path.certificate_ids.clone(),
        }
        .into()
    };
    if action_kind == "device_revocation" {
        let target = v.structural(text(o, "target_certificate_id")?, ctx.person_public_key)?;
        check(target.device == s(o, "target_device_public_key"), "invalid")?;
        for id in &path.certificate_ids {
            let c = Cert::candidate(id, v.state.certificates.get(id).expect("verified path"))?;
            if c.device == target.device {
                return Err(invalidate());
            }
        }
        check(
            ctx.certificate_id == "root" || v.ancestor(ctx.certificate_id, &target.id),
            "forbidden",
        )?;
    } else {
        let p = obj(payload.ok_or_else(|| problem("invalid"))?)?;
        let expiry = match kind {
            "peerspan-policy-v1" | "peerspan-policy-v2" => Some(stamp(text(&p, "valid_until")?)?),
            "peerspan-invite-v1" | "peerspan-person-invite-v1" => {
                let until = stamp(text(&p, "invite_expires_at")?)?;
                check(ctx.now < until, "expired")?;
                check(until <= ctx.now + chrono::Duration::days(30), "invalid")?;
                Some(until)
            }
            _ => None,
        };
        if let Some(until) = expiry
            && path.not_after != "-"
        {
            check(until <= stamp(&path.not_after)?, "forbidden")?;
        }
        if ctx.certificate_id != "root" {
            if kind == "peerspan-person-remove-v1"
                && s(&p, "person_public_key") == ctx.person_public_key
            {
                return Err(invalidate());
            }
            if matches!(kind, "peerspan-host-unbind-v1" | "peerspan-revoke-host-v1")
                && path
                    .host_public_keys
                    .iter()
                    .any(|h| h == s(&p, "host_public_key"))
            {
                return Err(invalidate());
            }
        }
    }
    Ok(())
}

/// Checks a typed current signing intention, before any private signature exists.
pub fn verify_stored_action_intent(
    ctx: ActionContext<'_>,
    action_kind: &str,
    catalog: &[u8],
    intent: &[u8],
) -> Result<ActionAuthority> {
    let run = || -> Result<ActionAuthority> {
        check(
            verification_budget(true, ctx.network.len(), catalog.len(), intent.len())
                && key(ctx.person_public_key)
                && (ctx.certificate_id == "root" || ident(ctx.certificate_id, "dc_"))
                && matches!(action_kind, "person_record" | "device_revocation"),
            "invalid",
        )?;
        check(ctx.known_feature_id != "-", "upgrade_required")?;
        let o = obj(intent)?;
        let (mut kind, mut required) = ("", 4);
        let mut raw_payload = None;
        if action_kind == "person_record" {
            fields(&o, "kind payload_base64", &[])?;
            kind = text(&o, "kind")?;
            let raw = decode(text(&o, "payload_base64")?, MAX_PAYLOAD)?;
            validate_action_payload(kind, &raw)?;
            required = action_scope(kind)?;
            raw_payload = Some(raw);
        } else {
            fields(
                &o,
                "format network_id person_public_key target_device_public_key target_certificate_id issuer_certificate_id revoked_at",
                &[],
            )?;
            version(&o, 1)?;
            public_fields(&o)?;
            check(
                s(&o, "person_public_key") == ctx.person_public_key
                    && s(&o, "issuer_certificate_id") == ctx.certificate_id
                    && key(s(&o, "target_device_public_key"))
                    && ident(s(&o, "target_certificate_id"), "dc_"),
                "invalid",
            )?;
        }
        let mut v = Verifier::new(ctx.network, ctx.epoch, ctx.known_feature_id, ctx.now)?;
        v.stored_snapshot = true;
        v.catalog(catalog)?;
        v.bootstrap(true)?;
        v.revocations()?;
        if action_kind == "device_revocation" {
            check(s(&o, "network_id") == v.net, "invalid")?;
        }
        if let Some(raw) = &raw_payload {
            let p = obj(raw)?;
            check(s(&p, "network_id") == v.net, "invalid")?;
            for field in ["epoch", "invite_epoch"] {
                if p.contains_key(field) {
                    check(num(&p, field)? == v.epoch, "invalid")?;
                }
            }
            if matches!(
                kind,
                "peerspan-policy-v1"
                    | "peerspan-policy-v2"
                    | "peerspan-host-bind-v1"
                    | "peerspan-host-unbind-v1"
            ) {
                check(
                    s(&p, "person_public_key") == ctx.person_public_key,
                    "invalid",
                )?;
            }
        }
        let path = v.authority(ctx.person_public_key, ctx.certificate_id, required, 0)?;
        validate_action_effects(
            &ctx,
            action_kind,
            kind,
            &o,
            raw_payload.as_deref(),
            &v,
            &path,
        )?;
        Ok(ActionAuthority {
            action_kind: action_kind.into(),
            record_id: "-".into(),
            network_id: v.net,
            feature_id: v.feature,
            person_public_key: ctx.person_public_key.into(),
            certificate_id: ctx.certificate_id.into(),
            required_scope: required,
            not_after: path.not_after,
        })
    };
    run().map_err(|e| {
        if e.downcast_ref::<PathError>().is_some()
            || e.downcast_ref::<ActionInvalidation>().is_some()
        {
            e
        } else {
            problem("invalid")
        }
    })
}
