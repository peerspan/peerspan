//! Exact signed root lineage; persisted prefix comparison belongs to the caller.
use super::*;

impl Verifier<'_> {
    pub(super) fn load_roots(&mut self) -> Result<()> {
        let mut rotations = BTreeMap::new();
        for p in self.proofs.values().filter(|p| p.kind == "rotation") {
            let o = &p.object;
            fields(
                o,
                "network_id epoch previous_root_public_key root_public_key rotated_at signature",
                &[],
            )?;
            let epoch = num(o, "epoch")?;
            check(
                epoch > 0
                    && s(o, "network_id") == self.net
                    && key(s(o, "previous_root_public_key"))
                    && key(s(o, "root_public_key")),
                "invalid",
            )?;
            stamp(text(o, "rotated_at")?)?;
            check(
                rotations.get(&epoch).is_none_or(|old| old == o),
                "state_conflict",
            )?;
            rotations.insert(epoch, o.clone());
        }
        self.roots = vec![text(&self.network, "genesis_root_public_key")?.into()];
        for (epoch, o) in rotations {
            check(epoch == self.roots.len() as u64, "proof_required")?;
            let previous = self.roots.last().expect("genesis");
            check(s(&o, "previous_root_public_key") == previous, "invalid")?;
            root(
                previous,
                &lines(&[
                    "peerspan-root-rotate-v1",
                    &self.net,
                    &epoch.to_string(),
                    previous,
                    text(&o, "root_public_key")?,
                    text(&o, "rotated_at")?,
                ]),
                text(&o, "signature")?,
            )?;
            self.roots.push(text(&o, "root_public_key")?.into());
        }
        let tip = self.roots.len() as u64 - 1;
        check(self.epoch <= tip, "proof_required")?;
        check(self.epoch == tip, "state_conflict")?;
        self.root = self.roots.last().expect("genesis").clone();
        Ok(())
    }

    pub(super) fn epoch_root(&self, o: &Obj, field: &str) -> Result<(String, u64)> {
        let epoch = num(o, field)?;
        let key = self
            .roots
            .get(usize::try_from(epoch).map_err(|_| problem("proof_required"))?)
            .ok_or_else(|| problem("proof_required"))?;
        Ok((key.clone(), epoch))
    }

    pub(super) fn any_root_signature(&self, m: &[u8], sig: &str) -> bool {
        self.roots.iter().any(|key| root(key, m, sig).is_ok())
    }

    pub(super) fn legacy_grant(&self, o: &Obj, field: &str, m: &[u8], sig: &str) -> Result<bool> {
        let (key, epoch) = self.epoch_root(o, field)?;
        if root(&key, m, sig).is_ok() {
            return Ok(epoch == self.epoch);
        }
        check(!self.any_root_signature(m, sig), "invalid")?;
        self.legacy_authority(m, sig)
    }

    pub(super) fn load_attestations(&mut self) -> Result<()> {
        self.attested.clear();
        for p in self.proofs.values().filter(|p| p.kind == "attestation") {
            let o = &p.object;
            fields(
                o,
                "network_id epoch host_public_key member attested_at signature",
                &[],
            )?;
            check(
                s(o, "network_id") == self.net && key(s(o, "host_public_key")),
                "invalid",
            )?;
            crate::membership::label(text(o, "member")?)?;
            let (key, epoch) = self.epoch_root(o, "epoch")?;
            stamp(text(o, "attested_at")?)?;
            root(
                &key,
                &lines(&[
                    "peerspan-attest-v1",
                    &self.net,
                    &epoch.to_string(),
                    text(o, "host_public_key")?,
                    text(o, "member")?,
                    text(o, "attested_at")?,
                ]),
                text(o, "signature")?,
            )?;
            if epoch != self.epoch {
                continue;
            }
            let (host, label) = (
                text(o, "host_public_key")?.to_owned(),
                text(o, "member")?.to_owned(),
            );
            check(
                self.attested.get(&host).is_none_or(|old| old == &label),
                "state_conflict",
            )?;
            self.attested.insert(host.clone(), label.clone());
            self.hosts.insert(host.clone(), label);
            self.state.hosts.insert(host, true);
        }
        Ok(())
    }
    pub(super) fn historical_label(&self, person: &str, epoch: u64, label: &str) -> bool {
        if !self.historical_admission_known(person) {
            return false;
        }
        self.historical_persons
            .iter()
            .any(|(p, e, l)| p == person && *e <= epoch && l == label)
            || epoch == self.epoch && self.persons.get(person).is_some_and(|l| l == label)
    }
    pub(super) fn historical_admission_known(&self, person: &str) -> bool {
        self.persons.contains_key(person)
            || self.historical_persons.iter().any(|(p, _, _)| p == person)
    }
}
