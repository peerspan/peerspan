//! Signed genesis membership, sticky restrictions and exact retained records.
use super::*;

#[derive(Clone)]
struct Withdrawal {
    revoke: bool,
    kept: BTreeSet<String>,
    object: Obj,
    v2: bool,
}
#[derive(Default)]
pub(super) struct HistoryFacts {
    pub(super) restriction_proofs: BTreeSet<String>,
    delegated: BTreeSet<String>,
    withdrawals: BTreeMap<String, Withdrawal>,
    pub(super) persons: BTreeSet<String>,
    pub(super) hosts: BTreeSet<String>,
    invites: BTreeSet<String>,
    pub(super) unbound: BTreeSet<(String, String)>,
}

impl Verifier<'_> {
    pub(super) fn access_admin_withdrawn(&self, person: &str) -> bool {
        self.history.withdrawals.contains_key(person)
    }
    pub(super) fn redemption_admin_kept(
        &self,
        person: &str,
        record: &str,
        id: &str,
    ) -> Result<(bool, bool)> {
        check(self.history.delegated.contains(person), "forbidden")?;
        Ok(match self.history.withdrawals.get(person) {
            Some(w) => (
                !w.revoke
                    && w.v2
                    && w.kept.contains(&format!("record:{record}"))
                    && w.kept.contains(&format!("redemption:{id}")),
                true,
            ),
            None => (true, false),
        })
    }

    pub(super) fn invite_revoked(&self, key: &str) -> bool {
        self.history.invites.contains(key)
    }

    // These facts restrict dependency resolution. Complete issuer activation,
    // retained authority and final history checks still precede publication.
    fn load_ordinary_restrictions(&mut self) -> Result<()> {
        let proofs: Vec<_> = self
            .proofs
            .values()
            .filter(|p| {
                p.kind == "person_record"
                    && s(&p.object, "operation_id") == "-"
                    && records::ordinary_restriction(s(&p.object, "kind"))
            })
            .cloned()
            .collect();
        for p in proofs {
            let g = self.read_ordinary(&p)?;
            if g.scope == 8 && !self.ordinary_admin_kept(&g.person, &g.record.id)? {
                continue;
            }
            let kind = s(&p.object, "kind");
            if g.cert != "root" {
                check(
                    !(kind == "peerspan-person-remove-v1"
                        && s(&g.payload, "person_public_key") == g.person),
                    "forbidden",
                )?;
                if matches!(kind, "peerspan-host-unbind-v1" | "peerspan-revoke-host-v1") {
                    let mut cert = g.cert.clone();
                    while cert != "root" {
                        // read_ordinary verified the bounded structural chain.
                        let c = self.structural(&cert, &g.person)?;
                        check(c.host != s(&g.payload, "host_public_key"), "forbidden")?;
                        cert = c.parent;
                    }
                }
            }
            self.apply_ordinary_restriction(&g, kind);
            self.history
                .restriction_proofs
                .insert(proof_id(&p.kind, &p.body));
        }
        Ok(())
    }

    pub(super) fn apply_ordinary_restriction(&mut self, g: &records::Grant, kind: &str) {
        match kind {
            "peerspan-host-unbind-v1" => {
                self.history
                    .unbound
                    .insert((g.person.clone(), s(&g.payload, "host_public_key").into()));
            }
            "peerspan-person-remove-v1" => {
                self.history
                    .persons
                    .insert(s(&g.payload, "person_public_key").into());
            }
            "peerspan-revoke-host-v1" => {
                self.history
                    .hosts
                    .insert(s(&g.payload, "host_public_key").into());
            }
            "peerspan-revoke-invite-v1" => {
                self.history
                    .invites
                    .insert(s(&g.payload, "invite_public_key").into());
            }
            _ => {}
        }
    }

    pub(super) fn ordinary_admin_kept(&self, person: &str, record: &str) -> Result<bool> {
        check(self.history.delegated.contains(person), "forbidden")?;
        Ok(self
            .history
            .withdrawals
            .get(person)
            .is_none_or(|r| !r.revoke && r.v2 && r.kept.contains(&format!("record:{record}"))))
    }

    fn load_withdrawals(&mut self) -> Result<()> {
        let mut seen = BTreeMap::new();
        let proofs: Vec<_> = self
            .proofs
            .values()
            .filter(|p| p.kind == "admin_removal")
            .cloned()
            .collect();
        for p in proofs {
            let o = &p.object;
            let v2 = o.contains_key("format");
            let names = if v2 {
                "format network_id person_public_key revoke_admitted removed_at kept signature"
            } else {
                "network_id person_public_key revoke_admitted removed_at kept signature"
            };
            fields(o, names, &[])?;
            check(
                s(o, "network_id") == self.net && key(s(o, "person_public_key")),
                "invalid",
            )?;
            let revoke = o
                .get("revoke_admitted")
                .and_then(Value::as_bool)
                .ok_or_else(|| problem("invalid"))?;
            let kept = string_list(o, "kept")?;
            check(sorted(&kept) && (!revoke || kept.is_empty()), "invalid")?;
            if v2 {
                stamp(text(o, "removed_at")?)?;
            } else {
                legacy_stamp(text(o, "removed_at")?)?;
            }
            if v2 {
                check(
                    self.roots
                        .iter()
                        .any(|key| read("admin_removal_v2", &p.body, key, "-").is_ok()),
                    "invalid",
                )?;
            } else {
                check(kept.iter().all(|s| ident(s, "")), "invalid")?;
                let mut parts = vec![
                    "peerspan-admin-remove-v1",
                    &self.net,
                    text(o, "person_public_key")?,
                    if revoke { "true" } else { "false" },
                    text(o, "removed_at")?,
                ];
                parts.extend(kept.iter().copied());
                check(
                    self.any_root_signature(&lines(&parts), text(o, "signature")?),
                    "invalid",
                )?;
            }
            let person = text(o, "person_public_key")?.to_owned();
            let version_key = (person.clone(), revoke);
            check(
                seen.get(&version_key).is_none_or(|old| old == o),
                "state_conflict",
            )?;
            seen.insert(version_key, o.clone());
            if let Some(old) = self.history.withdrawals.get(&person)
                && old.object != *o
            {
                check(old.revoke != revoke, "state_conflict")?;
                if old.revoke {
                    continue;
                }
            }
            self.history.withdrawals.insert(
                person.clone(),
                Withdrawal {
                    revoke,
                    kept: kept.into_iter().map(str::to_owned).collect(),
                    object: o.clone(),
                    v2,
                },
            );
            self.history
                .restriction_proofs
                .insert(proof_id(&p.kind, &p.body));
            self.admins.remove(&person);
        }
        Ok(())
    }
    pub(super) fn legacy_authority(&self, m: &[u8], sig: &str) -> Result<bool> {
        if self.any_root_signature(m, sig) {
            return Ok(root(&self.root, m, sig).is_ok());
        }
        let person = crate::persons::sshsig_signer(sig).ok_or_else(|| problem("invalid"))?;
        check(person != self.root, "invalid")?;
        check(self.history.delegated.contains(&person), "forbidden")?;
        ssh(&person, m, sig)?;
        if let Some(r) = self.history.withdrawals.get(&person) {
            let prefix = if r.v2 { "legacy:" } else { "" };
            return Ok(!r.revoke && r.kept.contains(&format!("{prefix}{}", hash(m))));
        }
        Ok(true)
    }
    fn load_restrictions(&mut self) -> Result<()> {
        let proofs: Vec<_> = self.proofs.values().cloned().collect();
        for p in proofs {
            let o = &p.object;
            let (domain, subject, at) = match p.kind.as_str() {
                "person_removal" => (
                    "peerspan-person-remove-v1",
                    "person_public_key",
                    "removed_at",
                ),
                "host_revocation" => ("peerspan-revoke-host-v1", "host_public_key", "revoked_at"),
                "invite_revocation" => (
                    "peerspan-revoke-invite-v1",
                    "invite_public_key",
                    "revoked_at",
                ),
                "host_leave" => ("peerspan-leave-v1", "host_public_key", "left_at"),
                "host_unbinding" => {
                    fields(
                        o,
                        "network_id person_public_key host_public_key unbound_at signature",
                        &[],
                    )?;
                    check(
                        s(o, "network_id") == self.net
                            && key(s(o, "person_public_key"))
                            && key(s(o, "host_public_key")),
                        "invalid",
                    )?;
                    legacy_stamp(text(o, "unbound_at")?)?;
                    ssh(
                        text(o, "person_public_key")?,
                        &lines(&[
                            "peerspan-host-unbind-v1",
                            &self.net,
                            text(o, "person_public_key")?,
                            text(o, "host_public_key")?,
                            text(o, "unbound_at")?,
                        ]),
                        text(o, "signature")?,
                    )?;
                    self.history.unbound.insert((
                        s(o, "person_public_key").into(),
                        s(o, "host_public_key").into(),
                    ));
                    self.history
                        .restriction_proofs
                        .insert(proof_id(&p.kind, &p.body));
                    continue;
                }
                _ => continue,
            };
            fields(o, &format!("network_id {subject} {at} signature"), &[])?;
            check(
                s(o, "network_id") == self.net && key(s(o, subject)),
                "invalid",
            )?;
            legacy_stamp(text(o, at)?)?;
            let m = lines(&[domain, &self.net, text(o, subject)?, text(o, at)?]);
            let valid = if p.kind == "host_leave" {
                raw(text(o, subject)?, &m, text(o, "signature")?)?;
                true
            } else {
                self.any_root_signature(&m, text(o, "signature")?)
                    || self.legacy_authority(&m, text(o, "signature")?)?
            };
            if !valid {
                continue;
            }
            self.history
                .restriction_proofs
                .insert(proof_id(&p.kind, &p.body));
            match p.kind.as_str() {
                "person_removal" => {
                    self.history.persons.insert(s(o, subject).into());
                }
                "invite_revocation" => {
                    self.history.invites.insert(s(o, subject).into());
                }
                _ => {
                    self.history.hosts.insert(s(o, subject).into());
                }
            }
        }
        Ok(())
    }
    pub(super) fn restrict_state(&mut self) {
        for person in &self.history.persons {
            let p = self.state.persons.entry(person.clone()).or_default();
            p.admitted = false;
            p.administrator = false;
        }
        for host in &self.history.hosts {
            self.state.hosts.insert(host.clone(), false);
        }
        for (host, person) in &mut self.state.bindings {
            if self.history.persons.contains(person)
                || self.history.hosts.contains(host)
                || self
                    .history
                    .unbound
                    .contains(&(person.clone(), host.clone()))
            {
                *person = "-".into();
            }
        }
    }
    pub(super) fn add_binding(&mut self, host: &str, person: &str) -> Result<()> {
        if self.history.persons.contains(person)
            || self.history.hosts.contains(host)
            || self.history.unbound.contains(&(person.into(), host.into()))
        {
            self.state
                .bindings
                .entry(host.into())
                .or_insert_with(|| "-".into());
            return Ok(());
        }
        check(
            self.state
                .bindings
                .get(host)
                .is_none_or(|old| old == "-" || old == person),
            "state_conflict",
        )?;
        self.state.bindings.insert(host.into(), person.into());
        Ok(())
    }
    pub(super) fn bootstrap(&mut self, check_host_features: bool) -> Result<()> {
        self.historical_persons.clear();
        self.load_roots()?;
        self.load_attestations()?;
        let proofs: Vec<_> = self.proofs.values().cloned().collect();
        for p in &proofs {
            if p.kind != "admin_delegation" {
                continue;
            }
            let o = &p.object;
            fields(
                o,
                "network_id epoch person_public_key delegated_at signature",
                &[],
            )?;
            check(
                s(o, "network_id") == self.net && key(s(o, "person_public_key")),
                "invalid",
            )?;
            let (epoch_root, epoch) = self.epoch_root(o, "epoch")?;
            legacy_stamp(text(o, "delegated_at")?)?;
            root(
                &epoch_root,
                &lines(&[
                    "peerspan-admin-delegate-v1",
                    &self.net,
                    &epoch.to_string(),
                    text(o, "person_public_key")?,
                    text(o, "delegated_at")?,
                ]),
                text(o, "signature")?,
            )?;
            if epoch == self.epoch {
                self.admins.insert(s(o, "person_public_key").into());
            }
            self.history
                .delegated
                .insert(s(o, "person_public_key").into());
        }
        self.load_withdrawals()?;
        self.coordinator_evidence()?;
        self.load_restrictions()?;
        self.load_ordinary_restrictions()?;
        for p in &proofs {
            let o = &p.object;
            match p.kind.as_str() {
                "person_admission" | "host_admission" | "person_membership" | "host_membership" => {
                    let person = p.kind.starts_with("person_");
                    let field = if person {
                        "person_public_key"
                    } else {
                        "host_public_key"
                    };
                    let k = text(o, field)?.to_owned();
                    let label = text(o, "member")?.to_owned();
                    check(key(&k) && s(o, "network_id") == self.net, "invalid")?;
                    crate::membership::label(&label)?;
                    let valid = if p.kind.ends_with("admission") {
                        fields(
                            o,
                            &format!("network_id epoch {field} member admitted_at signature"),
                            &[],
                        )?;
                        let epoch = num(o, "epoch")?;
                        legacy_stamp(text(o, "admitted_at")?)?;
                        let domain = if person {
                            "peerspan-person-admit-v1"
                        } else {
                            "peerspan-host-admit-v1"
                        };
                        self.legacy_grant(
                            o,
                            "epoch",
                            &lines(&[
                                domain,
                                &self.net,
                                &epoch.to_string(),
                                &k,
                                &label,
                                text(o, "admitted_at")?,
                            ]),
                            text(o, "signature")?,
                        )?
                    } else {
                        let valid = self.legacy_membership(p, person)?;
                        let half = format!("{field}:{}", text(o, "invite_public_key")?);
                        check(
                            self.invite_uses.get(&half).is_none_or(|old| old == &k),
                            "state_conflict",
                        )?;
                        self.invite_uses.insert(half, k.clone());
                        valid
                    };
                    if person {
                        if p.kind.ends_with("admission") {
                            let (key, epoch) = self.epoch_root(o, "epoch")?;
                            if valid
                                || root(
                                    &key,
                                    &lines(&[
                                        "peerspan-person-admit-v1",
                                        &self.net,
                                        &epoch.to_string(),
                                        &k,
                                        &label,
                                        text(o, "admitted_at")?,
                                    ]),
                                    text(o, "signature")?,
                                )
                                .is_ok()
                            {
                                self.historical_persons
                                    .insert((k.clone(), epoch, label.clone()));
                            }
                        } else {
                            let (key, epoch) = self.epoch_root(o, "invite_epoch")?;
                            if valid
                                || root(
                                    &key,
                                    &lines(&[
                                        "peerspan-person-invite-v1",
                                        &self.net,
                                        &epoch.to_string(),
                                        text(o, "invite_public_key")?,
                                        &label,
                                        text(o, "invite_expires_at")?,
                                    ]),
                                    text(o, "invite_signature")?,
                                )
                                .is_ok()
                            {
                                self.historical_persons
                                    .insert((k.clone(), epoch, label.clone()));
                            }
                        }
                        if valid {
                            check(
                                self.persons.get(&k).is_none_or(|old| old == &label),
                                "state_conflict",
                            )?;
                            self.persons.insert(k.clone(), label);
                        }
                        let old = self.state.persons.entry(k.clone()).or_default();
                        old.admitted |= valid;
                        old.administrator = self.admins.contains(&k);
                    } else {
                        if valid {
                            check(
                                self.hosts.get(&k).is_none_or(|old| old == &label),
                                "state_conflict",
                            )?;
                            self.hosts.insert(k.clone(), label);
                        }
                        *self.state.hosts.entry(k).or_default() |= valid;
                    }
                }
                "feature" => {
                    let proposal = object(o.get("proposal").ok_or_else(|| problem("invalid"))?)?;
                    let (epoch_root, _) = self.epoch_root(proposal, "epoch")?;
                    let r = read("feature", &p.body, &epoch_root, "-")?;
                    check(s(proposal, "network_id") == self.net, "invalid")?;
                    check(
                        self.feature.is_empty() || self.feature == r.id,
                        "state_conflict",
                    )?;
                    self.semantic(&r.id, o)?;
                    self.feature = r.id;
                }
                _ => {}
            }
        }
        for p in &proofs {
            if p.kind != "host_binding" {
                continue;
            }
            let o = &p.object;
            fields(
                o,
                "network_id person_public_key host_public_key bound_at signature host_signature",
                &[],
            )?;
            let (person, host, at) = (
                text(o, "person_public_key")?,
                text(o, "host_public_key")?,
                text(o, "bound_at")?,
            );
            check(
                s(o, "network_id") == self.net && key(person) && key(host),
                "invalid",
            )?;
            legacy_stamp(at)?;
            let m = lines(&["peerspan-host-bind-v1", &self.net, person, host, at]);
            ssh(person, &m, text(o, "signature")?)?;
            raw(host, &m, text(o, "host_signature")?)?;
            self.add_binding(host, person)?;
        }
        self.restrict_state();
        if self.feature.is_empty() && self.feature_preparation {
            self.validate_access_candidates()?;
            return Ok(());
        }
        check(!self.feature.is_empty(), "proof_required")?;
        check(
            self.ctx.known_feature_id == "-" || self.ctx.known_feature_id == self.feature,
            "state_conflict",
        )?;
        self.ordinary_records()?;
        self.redemption_records()?;
        self.validate_access_candidates()?;
        let mut roster = BTreeSet::new();
        for p in &proofs {
            if p.kind == "feature" {
                let proposal = object(p.object.get("proposal").ok_or_else(|| problem("invalid"))?)?;
                roster.extend(
                    string_list(proposal, "host_public_keys")?
                        .into_iter()
                        .map(str::to_owned),
                );
            }
        }
        for p in &proofs {
            if p.kind != "join_ack" {
                continue;
            }
            let host = text(&p.object, "host_public_key")?;
            read("feature_ack", &p.body, host, "-")?;
            check(s(&p.object, "feature_id") == self.feature, "invalid")?;
            roster.insert(host.into());
        }
        let hosts: Vec<_> = self
            .state
            .hosts
            .iter()
            .filter(|(_, admitted)| **admitted)
            .map(|(h, _)| h.clone())
            .collect();
        for host in hosts {
            if check_host_features && !roster.contains(&host) {
                self.host_activations(&host, 0)?;
                check(
                    self.done
                        .values()
                        .any(|r| r.host_public_key == host && r.feature_id == self.feature),
                    "proof_required",
                )?;
            }
        }
        Ok(())
    }
    pub(super) fn legacy_membership(&self, p: &Proof, person: bool) -> Result<bool> {
        let o = &p.object;
        let (field, sig_field, extra) = if person {
            ("person_public_key", "person_signature", " invite_epoch")
        } else {
            ("host_public_key", "host_signature", "")
        };
        fields(
            o,
            &format!(
                "network_id member invite_public_key invite_expires_at invite_signature {field} joined_at {sig_field}{extra}"
            ),
            &[],
        )?;
        let invite = text(o, "invite_public_key")?;
        check(key(invite), "invalid")?;
        let invite_epoch = if person {
            self.epoch_root(o, "invite_epoch")?.1.to_string()
        } else {
            String::new()
        };
        check(
            legacy_stamp(text(o, "joined_at")?)? <= legacy_stamp(text(o, "invite_expires_at")?)?,
            "invalid",
        )?;
        let parts = if person {
            vec![
                "peerspan-person-invite-v1",
                &self.net,
                &invite_epoch,
                invite,
                text(o, "member")?,
                text(o, "invite_expires_at")?,
            ]
        } else {
            vec![
                "peerspan-invite-v1",
                &self.net,
                invite,
                text(o, "member")?,
                text(o, "invite_expires_at")?,
            ]
        };
        let valid = if person {
            self.legacy_grant(
                o,
                "invite_epoch",
                &lines(&parts),
                text(o, "invite_signature")?,
            )?
        } else {
            self.legacy_authority(&lines(&parts), text(o, "invite_signature")?)?
                || self
                    .attested
                    .get(s(o, "host_public_key"))
                    .is_some_and(|label| label == s(o, "member"))
                    && self.any_root_signature(&lines(&parts), text(o, "invite_signature")?)
        };
        let domain = if person {
            "peerspan-person-member-v1"
        } else {
            "peerspan-member-v1"
        };
        raw(
            invite,
            &lines(&[
                domain,
                &self.net,
                invite,
                text(o, field)?,
                text(o, "joined_at")?,
            ]),
            text(o, sig_field)?,
        )?;
        Ok(valid && !self.history.invites.contains(invite))
    }

    pub(super) fn ancestor(&self, ancestor: &str, leaf: &str) -> bool {
        let mut next = leaf.to_owned();
        for _ in 0..8 {
            if next == "root" {
                break;
            }
            let Some(b) = self.state.certificates.get(&next) else {
                return false;
            };
            let Ok(c) = Cert::candidate(&next, b) else {
                return false;
            };
            next = c.parent;
            if next == ancestor {
                return true;
            }
        }
        false
    }
    pub(super) fn actor(
        &mut self,
        person: &str,
        cert: &str,
        scope: u64,
        historical: bool,
        depth: usize,
    ) -> Result<SigningPath> {
        if !historical {
            return self.authority(person, cert, scope, depth);
        }
        check(
            key(person) && (cert == "root" || ident(cert, "dc_")),
            "invalid",
        )?;
        self.ensure_person(person)?;
        let mut r = SigningPath {
            certificate_id: cert.into(),
            person_public_key: person.into(),
            signer_public_key: person.into(),
            scopes: 15,
            not_after: "-".into(),
            certificate_ids: Vec::new(),
            host_public_keys: Vec::new(),
        };
        if cert == "root" {
            return Ok(r);
        }
        let c = self.structural(cert, person)?;
        check(c.scopes & scope == scope, "forbidden")?;
        if !self.state.activated_certificates.contains(cert) {
            self.activate(&c.request, true, depth + 1)?;
        }
        check(
            self.state.activated_certificates.contains(cert)
                || self.project_history && self.inert_certificates.contains(cert),
            "invalid",
        )?;
        r.signer_public_key = c.device;
        r.scopes = c.scopes;
        r.not_after = c.until.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        Ok(r)
    }
    pub(super) fn record_path_live(&self, person: &str, cert: &str) -> bool {
        if cert == "root" {
            return true;
        }
        if !self.state.persons.get(person).is_some_and(|p| p.admitted) {
            return false;
        }
        let mut next = cert.to_owned();
        for _ in 0..8 {
            if next == "root" {
                break;
            }
            let Some(b) = self.state.certificates.get(&next) else {
                return false;
            };
            let Ok(c) = Cert::candidate(&next, b) else {
                return false;
            };
            if !self.state.activated_certificates.contains(&next)
                || self.ctx.now < c.issued
                || self.ctx.now >= c.until
                || self.state.revoked_devices.contains(&DeviceKey {
                    person_public_key: person.into(),
                    device_public_key: c.device,
                })
                || self.state.hosts.get(&c.host) != Some(&true)
                || !self
                    .state
                    .bindings
                    .get(&c.host)
                    .is_some_and(|p| p == person)
            {
                return false;
            }
            next = c.parent;
        }
        next == "root"
    }
    pub(super) fn historical_record(
        &mut self,
        r: &SignedObject,
        o: &Obj,
        scope: u64,
        depth: usize,
    ) -> Result<()> {
        let person = s(o, "person_public_key");
        let cert = s(o, "certificate_id");
        if person.is_empty() {
            return Ok(());
        }
        if scope == 8 {
            check(self.history.delegated.contains(person), "forbidden")?;
            if let Some(removed) = self.history.withdrawals.get(person) {
                check(
                    !removed.revoke
                        && removed.v2
                        && removed.kept.contains(&format!("record:{}", r.id)),
                    "forbidden",
                )?;
            } else {
                check(
                    self.state.persons.get(person).is_some_and(|p| p.admitted),
                    "forbidden",
                )?;
            }
        }
        if self.record_path_live(person, cert) {
            return Ok(());
        }
        self.retained(&r.id, person, cert, depth + 1)
    }
    pub(super) fn retention_subject(&self, id: &str) -> Result<(String, String, u64)> {
        if ident(id, "pf_") {
            let p = self.proofs.get(id).ok_or_else(|| missing(id))?;
            check(p.kind == "invite_redemption", "upgrade_required")?;
            let r = self.read_redemption(p)?;
            let h = &r.halves[0];
            check(key(&h.person), "forbidden")?;
            return Ok((h.person.clone(), h.cert.clone(), 8));
        }
        let p = self.evidence.get(id).ok_or_else(|| missing(id))?;
        let o = &p.object;
        let person = text(o, "person_public_key")?;
        let (cert, scope) = match p.kind.as_str() {
            "person_record" => {
                let mut scope = records::ordinary_scope(text(o, "kind")?);
                if scope == 0
                    && self.inline_invites.contains(id)
                    && redemptions::invite_kind(s(o, "kind"))
                {
                    scope = 8;
                }
                check(scope != 0, "upgrade_required")?;
                (text(o, "certificate_id")?, scope)
            }
            "device_revocation" => (text(o, "issuer_certificate_id")?, 4),
            _ => return Err(problem("invalid")),
        };
        check(
            s(o, "network_id") == self.net && key(person) && (cert == "root" || ident(cert, "dc_")),
            "invalid",
        )?;
        let signer = if cert == "root" {
            person.to_owned()
        } else {
            let c = self.structural(cert, person)?;
            check(c.scopes & scope == scope, "forbidden")?;
            c.device
        };
        let r = read(&p.kind, &p.body, &signer, "-")?;
        check(r.id == id, "invalid")?;
        if p.kind == "device_revocation" {
            let target = self.structural(text(o, "target_certificate_id")?, person)?;
            check(
                target.device == s(o, "target_device_public_key")
                    && (cert == "root" || self.ancestor(cert, &target.id)),
                "forbidden",
            )?;
        }
        Ok((person.into(), cert.into(), scope))
    }
    pub(super) fn checkpoint(
        &mut self,
        p: &Proof,
        id: &str,
        person: &str,
        depth: usize,
    ) -> Result<()> {
        self.checkpoint_with_signature(p, id, person, depth, true)
    }
    pub(super) fn checkpoint_with_signature(
        &mut self,
        p: &Proof,
        id: &str,
        person: &str,
        depth: usize,
        signed_body: bool,
    ) -> Result<()> {
        let o = &p.object;
        let issuer = text(o, "issuer_certificate_id")?;
        let signer = if issuer == "root" {
            person.to_owned()
        } else {
            self.structural(issuer, person)?.device
        };
        checkpoint_body(o, &signer, signed_body)?;
        let mut required = 0;
        for rid in string_list(o, "records")? {
            let (owner, target, scope) = self.retention_subject(rid)?;
            check(
                owner == person && (issuer == "root" || self.ancestor(issuer, &target)),
                "forbidden",
            )?;
            required |= scope;
        }
        if issuer != "root"
            && let Err(e) = self.authority(person, issuer, required, depth + 1)
        {
            if e.downcast_ref::<PathError>()
                .is_some_and(|p| matches!(p.code, "authority_expired" | "device_revoked"))
            {
                return Err(missing(id));
            }
            return Err(e);
        }
        Ok(())
    }
    fn retained(&mut self, id: &str, person: &str, _cert: &str, depth: usize) -> Result<()> {
        let busy = format!("retain:{id}");
        check(depth <= 24 && !self.busy.contains(&busy), "invalid")?;
        self.busy.insert(busy.clone());
        let candidates: Vec<_> = self
            .proofs
            .values()
            .filter(|p| {
                p.kind == "checkpoint"
                    && s(&p.object, "network_id") == self.net
                    && s(&p.object, "person_public_key") == person
                    && string_list(&p.object, "records").is_ok_and(|ids| ids.contains(&id))
            })
            .cloned()
            .collect();
        let mut failure = None;
        for root_only in [true, false] {
            for p in &candidates {
                if (s(&p.object, "issuer_certificate_id") == "root") != root_only {
                    continue;
                }
                match self.checkpoint(p, id, person, depth) {
                    Ok(()) => {
                        self.busy.remove(&busy);
                        return Ok(());
                    }
                    Err(e) => {
                        if failure.is_none() {
                            failure = Some(e);
                        }
                    }
                }
            }
        }
        self.busy.remove(&busy);
        Err(failure.unwrap_or_else(|| missing(id)))
    }
    pub(super) fn revocations(&mut self) -> Result<()> {
        let proofs: Vec<_> = self
            .proofs
            .values()
            .filter(|p| p.kind == "device_revocation")
            .cloned()
            .collect();
        for root_only in [true, false] {
            for p in &proofs {
                let o = &p.object;
                let person = text(o, "person_public_key")?;
                let issuer = text(o, "issuer_certificate_id")?;
                if (issuer == "root") != root_only {
                    continue;
                }
                let signer = if issuer == "root" {
                    person.to_owned()
                } else {
                    let c = self.structural(issuer, person)?;
                    check(c.scopes & 4 != 0, "forbidden")?;
                    c.device
                };
                let r = read("device_revocation", &p.body, &signer, "-")?;
                check(s(o, "network_id") == self.net, "invalid")?;
                let target = self.structural(text(o, "target_certificate_id")?, person)?;
                check(target.device == s(o, "target_device_public_key"), "invalid")?;
                if issuer != "root" {
                    check(self.ancestor(issuer, &target.id), "forbidden")?;
                    self.actor(person, issuer, 4, true, 0)?;
                    if !self.record_path_live(person, issuer) {
                        self.retained(&r.id, person, issuer, 0)?;
                    }
                }
                self.state.revoked_devices.insert(DeviceKey {
                    person_public_key: person.into(),
                    device_public_key: target.device,
                });
                self.history
                    .restriction_proofs
                    .insert(proof_id(&p.kind, &p.body));
            }
        }
        self.settle_history()
    }

    pub(super) fn withdrawn_activation_admission(&self, id: &str, o: &Obj) -> bool {
        let person = s(o, "person_public_key");
        self.project_history
            && self.history.delegated.contains(person)
            && self
                .history
                .withdrawals
                .get(person)
                .is_some_and(|withdrawal| {
                    withdrawal.revoke
                        || !withdrawal.v2
                        || !withdrawal.kept.contains(&format!("record:{id}"))
                })
    }

    // Dependencies may have been visited before a later issuer revocation.
    // Verify every derived historical fact against the final restrictive view.
    fn settle_history(&mut self) -> Result<()> {
        let ids: Vec<_> = self.redemptions.iter().cloned().collect();
        for id in ids {
            let r = self.read_redemption(self.proofs.get(&id).expect("indexed redemption"))?;
            for h in r.halves {
                self.redemption_half(&id, &h)?;
            }
        }
        let ordinary: Vec<_> = self
            .active_records
            .iter()
            .filter_map(|id| self.proofs.get(id))
            .filter(|p| p.kind == "person_record" && s(&p.object, "operation_id") == "-")
            .cloned()
            .collect();
        for p in ordinary {
            let g = self.read_ordinary(&p)?;
            self.historical_record(&g.record, &p.object, g.scope, 0)?;
        }
        let revoked: Vec<_> = self
            .evidence
            .iter()
            .filter(|(_, p)| {
                p.kind == "device_revocation" && s(&p.object, "issuer_certificate_id") != "root"
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in revoked {
            let (person, cert, _) = self.retention_subject(&id)?;
            if !self.record_path_live(&person, &cert) {
                self.retained(&id, &person, &cert, 0)?;
            }
        }
        let mut checked = BTreeSet::new();
        while checked.len() < self.done.len() {
            let ids: Vec<_> = self
                .done
                .keys()
                .filter(|id| !checked.contains(*id))
                .cloned()
                .collect();
            for id in ids {
                checked.insert(id.clone());
                if self.done.get(&id).expect("completed activation").mode != "new" {
                    continue;
                }
                let body = self.activations.get(&id).expect("indexed activation");
                let a = obj(body)?;
                let commit = object(a.get("commit").ok_or_else(|| problem("invalid"))?)?;
                let (com, _) = p_obj(commit)?;
                let admin = object(a.get("administrator").ok_or_else(|| problem("invalid"))?)?;
                let (adm, _) = p_obj(admin)?;
                for (raw, scope) in [
                    (raw_field(&adm, "admission_record")?, 8),
                    (raw_field(&com, "binding_record")?, 2),
                ] {
                    let o = obj(&raw)?;
                    let (typ, signer) = if o.contains_key("person_public_key") {
                        let person = text(&o, "person_public_key")?;
                        let cert = text(&o, "certificate_id")?;
                        (
                            "person_record",
                            if cert == "root" {
                                person.to_owned()
                            } else {
                                self.structural(cert, person)?.device
                            },
                        )
                    } else {
                        ("root_record", self.epoch_root(&o, "epoch")?.0)
                    };
                    let r = read(typ, &raw, &signer, "-")?;
                    if self.project_history
                        && (scope == 8 && self.withdrawn_activation_admission(&r.id, &o)
                            || self.inert_records.contains(&r.id))
                    {
                        continue;
                    }
                    self.historical_record(&r, &o, scope, 0)?;
                }
            }
        }
        Ok(())
    }
}

impl Verifier<'_> {
    pub(super) fn access_admin_known(&self, person: &str) -> bool {
        self.history.delegated.contains(person)
    }
}
