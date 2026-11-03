//! Complete current projection from independently verified signed history.
use super::*;

#[derive(Clone, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberProof {
    pub host_public_key: String,
    pub member: String,
    pub person_public_key: String,
    pub membership_proof_id: String,
    pub binding_proof_id: String,
    pub join_proof_id: String,
}
pub struct NetworkState {
    pub facts: CatalogFacts,
    pub members: Vec<MemberProof>,
    pub epoch: u64,
    pub root_public_key: String,
    pub(crate) applicable_restrictions: BTreeSet<String>,
}

fn choose(map: &mut BTreeMap<String, String>, host: &str, id: &str) {
    if map.get(host).is_none_or(|old| id < old.as_str()) {
        map.insert(host.into(), id.into());
    }
}

pub fn verify_stored_network_state(
    ctx: CatalogFactContext<'_>,
    catalog: &[u8],
) -> Result<NetworkState> {
    verify_network_state(ctx, catalog, false)
}

/// Migration can inspect an actual pre-feature legacy source. This does not
/// create a feature, activate a device, or supply new-context authority.
pub(crate) fn verify_stored_migration_source(
    ctx: CatalogFactContext<'_>,
    catalog: &[u8],
) -> Result<NetworkState> {
    let pre_feature = ctx.known_feature_id == "-";
    verify_network_state(ctx, catalog, pre_feature)
}

fn verify_network_state(
    ctx: CatalogFactContext<'_>,
    catalog: &[u8],
    pre_feature: bool,
) -> Result<NetworkState> {
    let run = || -> Result<NetworkState> {
        check(
            verification_budget(true, ctx.network.len(), catalog.len(), 0),
            "invalid",
        )?;
        let mut v = Verifier::new(ctx.network, ctx.epoch, ctx.known_feature_id, ctx.now)?;
        v.stored_snapshot = true;
        v.catalog(catalog)?;
        if pre_feature {
            check(
                !v.proofs.values().any(|p| p.kind == "feature"),
                "state_conflict",
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
                            | "certificate"
                            | "device_revocation"
                            | "group"
                            | "policy"
                    ),
                    "forbidden",
                )?;
            }
            v.feature_preparation = true;
        }
        v.bootstrap(true)?;
        let requests: Vec<_> = v.activations.keys().cloned().collect();
        for request in requests {
            v.activate(&request, true, 0)?;
        }
        v.revocations()?;
        v.verify_stored_objects()?;
        v.restrict_state();
        let (mut memberships, mut bindings, mut joins) =
            (BTreeMap::new(), BTreeMap::new(), BTreeMap::new());
        let mut roster = BTreeSet::new();
        let proofs: Vec<_> = v
            .proofs
            .iter()
            .map(|(id, p)| (id.clone(), p.clone()))
            .collect();
        for (id, p) in &proofs {
            let o = &p.object;
            match p.kind.as_str() {
                "feature" => {
                    let proposal = object(o.get("proposal").ok_or_else(|| problem("invalid"))?)?;
                    roster.extend(
                        string_list(proposal, "host_public_keys")?
                            .into_iter()
                            .map(str::to_owned),
                    );
                }
                "join_ack" if s(o, "feature_id") == v.feature => {
                    choose(&mut joins, s(o, "host_public_key"), id)
                }
                "activation" => {
                    let request = object(o.get("request").ok_or_else(|| problem("invalid"))?)?;
                    if let Some(r) = v
                        .done
                        .get(s(request, "request_id"))
                        .filter(|r| r.feature_id == v.feature)
                    {
                        choose(&mut joins, &r.host_public_key, id);
                    }
                }
                "host_admission" => {
                    let host = s(o, "host_public_key");
                    let label = s(o, "member");
                    let message = lines(&[
                        "peerspan-host-admit-v1",
                        &v.net,
                        &num(o, "epoch")?.to_string(),
                        host,
                        label,
                        s(o, "admitted_at"),
                    ]);
                    let sig = text(o, "signature")?;
                    let valid = v.legacy_grant(o, "epoch", &message, sig)?;
                    if (valid
                        || v.attested.get(host).is_some_and(|l| l == label)
                            && v.any_root_signature(&message, sig))
                        && v.hosts.get(host).is_some_and(|l| l == label)
                    {
                        choose(&mut memberships, host, id);
                    }
                }
                "host_membership" => {
                    let host = s(o, "host_public_key");
                    if v.legacy_membership(p, false)?
                        && v.hosts.get(host).is_some_and(|l| l == s(o, "member"))
                    {
                        choose(&mut memberships, host, id);
                    }
                }
                "invite_redemption" if v.redemptions.contains(id) => {
                    let redemption = v.read_redemption(p)?;
                    for half in redemption.halves.iter().filter(|h| h.host) {
                        let host = s(o, "host_public_key");
                        if v.redemption_half(id, half)? && v.hosts.get(host) == Some(&half.label) {
                            choose(&mut memberships, host, id);
                        }
                    }
                }
                "host_binding" => {
                    let host = s(o, "host_public_key");
                    let person = s(o, "person_public_key");
                    if v.state.bindings.get(host).is_some_and(|p| p == person)
                        && !v.history.unbound.contains(&(person.into(), host.into()))
                    {
                        choose(&mut bindings, host, id);
                    }
                }
                "person_record" | "root_record" if v.active_records.contains(id) => {
                    let (_, payload) = p_obj(o)?;
                    let host = s(&payload, "host_public_key");
                    match s(o, "kind") {
                        "peerspan-host-admit-v1" => {
                            let label = s(&payload, "member");
                            if p.kind == "root_record"
                                && num(o, "epoch")? != v.epoch
                                && !v.attested.get(host).is_some_and(|l| l == label)
                            {
                                continue;
                            }
                            if v.hosts.get(host).is_some_and(|l| l == label) {
                                choose(&mut memberships, host, id);
                            }
                        }
                        "peerspan-host-bind-v1" => {
                            let person = s(&payload, "person_public_key");
                            if v.state.bindings.get(host).is_some_and(|p| p == person)
                                && !v.history.unbound.contains(&(person.into(), host.into()))
                            {
                                choose(&mut bindings, host, id);
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        // Current attestation is a membership fallback, never join capability.
        for (id, p) in &proofs {
            if p.kind != "attestation" {
                continue;
            }
            let host = s(&p.object, "host_public_key");
            if !memberships.contains_key(host)
                && num(&p.object, "epoch")? == v.epoch
                && v.hosts
                    .get(host)
                    .is_some_and(|l| l == s(&p.object, "member"))
            {
                memberships.insert(host.into(), id.clone());
            }
        }
        let mut members = Vec::new();
        for (host, admitted) in &v.state.hosts {
            if !admitted {
                continue;
            }
            let membership = memberships
                .get(host)
                .ok_or_else(|| problem("proof_required"))?;
            let join = if pre_feature || roster.contains(host) {
                "-"
            } else {
                joins.get(host).ok_or_else(|| problem("proof_required"))?
            };
            let person = v
                .state
                .bindings
                .get(host)
                .filter(|p| p.as_str() != "-")
                .map(String::as_str)
                .unwrap_or("-");
            let binding = if person == "-" {
                "-"
            } else {
                bindings
                    .get(host)
                    .ok_or_else(|| problem("proof_required"))?
            };
            members.push(MemberProof {
                host_public_key: host.clone(),
                member: v
                    .hosts
                    .get(host)
                    .ok_or_else(|| problem("proof_required"))?
                    .clone(),
                person_public_key: person.into(),
                membership_proof_id: membership.clone(),
                binding_proof_id: binding.into(),
                join_proof_id: join.into(),
            });
        }
        Ok(NetworkState {
            applicable_restrictions: v.history.restriction_proofs,
            members,
            epoch: v.epoch,
            root_public_key: v.root,
            facts: CatalogFacts {
                network_id: v.net,
                feature_id: v.feature,
                state: v.state,
                person_labels: v.persons,
                host_labels: v.hosts,
            },
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

impl Verifier<'_> {
    pub(super) fn verify_stored_objects(&self) -> Result<()> {
        for (id, p) in &self.proofs {
            let o = &p.object;
            match p.kind.as_str() {
                "certificate" => {
                    self.structural(&certificate_id(o)?, text(o, "person_public_key")?)?;
                }
                "checkpoint" => {
                    check(s(o, "network_id") == self.net, "invalid")?;
                    let person = text(o, "person_public_key")?;
                    let issuer = text(o, "issuer_certificate_id")?;
                    let signer = if issuer == "root" {
                        person.into()
                    } else {
                        self.structural(issuer, person)?.device
                    };
                    read("checkpoint", &p.body, &signer, "-")?;
                }
                "person_record" | "root_record" if s(o, "operation_id") != "-" => {
                    let (mut signer, _) = self.epoch_root(o, "epoch")?;
                    if p.kind == "person_record" {
                        let person = text(o, "person_public_key")?;
                        let cert = text(o, "certificate_id")?;
                        signer = if cert == "root" {
                            person.into()
                        } else {
                            self.structural(cert, person)?.device
                        };
                    }
                    read(&p.kind, &p.body, &signer, "-")?;
                    if !self.active_records.contains(id)
                        && !(self.project_history && self.inert_records.contains(id))
                    {
                        return Err(missing(text(o, "operation_id")?));
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}
