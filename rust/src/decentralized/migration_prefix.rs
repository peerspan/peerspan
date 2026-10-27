//! Verified migration preparation facts. This reader never creates a prior,
//! projects authority, approves another host, or adopts the inert context.
use super::{
    catalog::{Catalog, raw_array_field},
    codec::*,
    migration::{self, SourceContext, SourceState},
    migration_local::Source,
    statement::{Descriptor, Statement},
    storage::MigrationRecord,
    transcript::Activation,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct Prefix {
    pub proposal: Statement,
    pub source: SourceState,
    pub catalog: Option<Catalog>,
    pub root: Option<Statement>,
    pub acknowledgments: BTreeMap<String, Statement>,
    pub commit: Option<Statement>,
}

fn root(d: &Descriptor, p: &Statement, raw: &[u8]) -> Result<Statement> {
    let s = Statement::read(d, raw)?;
    check(
        s.kind == "root_state"
            && text(&s.payload, "migration_proposal_id")? == p.id
            && num(&s.payload, "epoch")? == num(&p.payload, "legacy_epoch")?
            && text(&s.payload, "root_public_key")? == text(&p.payload, "legacy_root_public_key")?
            && text(&s.payload, "issued_at")? == text(&p.payload, "issued_at")?
            && ids(&s.payload, "predecessors", "ds_")?.is_empty()
            && ids(&s.payload, "resolves", "ds_")?.is_empty()
            && ids(&s.payload, "retained_statement_ids", "ds_")?.is_empty()
            && s.signer("issuer")?.public_key == text(&p.payload, "legacy_root_public_key")?,
    )?;
    Ok(s)
}

impl Prefix {
    pub(super) fn read(d: &Descriptor, r: &MigrationRecord) -> Result<Self> {
        let p = Statement::read(d, &b64(&r.proposal_base64, MAX_OBJECT)?)?;
        check(p.kind == "migration_proposal" && r.context_id == d.context_id())?;
        let source_bytes = b64(&r.source_catalog_base64, 512 << 10)?;
        let state_bytes = b64(&r.source_state_base64, MAX_PAYLOAD)?;
        check(
            hash(&source_bytes) == text(&p.payload, "source_catalog_sha256")?
                && hash(&state_bytes) == text(&p.payload, "source_state_sha256")?,
        )?;
        let (source, facts) = migration::source_snapshot(
            SourceContext {
                descriptor: d,
                legacy_descriptor: &b64(text(&p.payload, "legacy_descriptor_base64")?, MAX_OBJECT)?,
                epoch: num(&p.payload, "legacy_epoch")?,
                feature: text(&p.payload, "legacy_feature_id")?,
                root: text(&p.payload, "legacy_root_public_key")?,
                now: text(&p.payload, "issued_at")?,
            },
            &source_bytes,
            &state_bytes,
        )?;
        check(p.signer("issuer")?.public_key == facts.root_public_key)?;
        let rows = array(&p.payload, "roster")?;
        check(rows.len() == facts.members.len())?;
        for row in rows {
            let row = object(row)?;
            let host = text(row, "host_public_key")?;
            let member = facts
                .members
                .iter()
                .find(|m| m.host_public_key == host)
                .ok_or_else(|| Error::new("invalid"))?;
            check(
                text(row, "member")? == member.member
                    && text(row, "person_public_key")? == member.person_public_key,
            )?;
            // Existing device identity/profile is a source fact; a root's
            // proposal cannot silently replace it before its owner review.
            if member.person_public_key != "-" {
                let mut known = false;
                let mut matched = false;
                for (id, raw) in &facts.facts.state.certificates {
                    let value = parse(raw, MAX_OBJECT)?;
                    let certificate = object(&value)?;
                    if text(certificate, "host_public_key")? != host {
                        continue;
                    }
                    known = true;
                    if facts.facts.state.activated_certificates.contains(id)
                        && text(certificate, "device_public_key")?
                            == text(row, "device_public_key")?
                    {
                        require(
                            num(row, "scopes")? & !num(certificate, "scopes")? == 0,
                            "forbidden",
                        )?;
                        matched = true;
                    }
                }
                require(!known || matched, "forbidden")?;
            }
        }
        let mut initial = if r.initial_root_state_base64 == "-" {
            None
        } else {
            Some(root(
                d,
                &p,
                &b64(&r.initial_root_state_base64, MAX_OBJECT)?,
            )?)
        };
        let catalog = if r.prepared_catalog_base64 == "-" {
            None
        } else {
            let catalog = Catalog::read_prepared(d, &b64(&r.prepared_catalog_base64, MAX_OBJECT)?)?;
            for proof in catalog.proofs.values() {
                check(!matches!(
                    proof.kind.as_str(),
                    "migration" | "migration_ack" | "migration_commit"
                ))?;
                if proof.kind == "activation" {
                    let activation = Activation::read(d, &proof.body)?;
                    let request = &activation.packets["request"];
                    check(
                        text(&request.payload, "mode")? == "new"
                            && text(&request.payload, "migration_proposal_id")? == p.id,
                    )?;
                }
            }
            // Every exact alias is checked; a representative cannot conceal a
            // foreign root signature behind another correctly signed alias.
            for aliases in catalog.aliases.values() {
                for s in aliases {
                    if s.kind == "root_state" {
                        let candidate = root(d, &p, &s.body)?;
                        if let Some(old) = &initial {
                            check(old.id == candidate.id)?;
                        } else {
                            initial = Some(candidate);
                        }
                    } else if s.kind == "migration_proposal" {
                        check(
                            s.id == p.id
                                && s.payload_bytes == p.payload_bytes
                                && s.signer("issuer")?.public_key == facts.root_public_key,
                        )?;
                    }
                }
            }
            for aliases in catalog.aliases.values() {
                for s in aliases {
                    if matches!(s.kind.as_str(), "root_state" | "migration_proposal") {
                        continue;
                    }
                    let root_id = text(&s.payload, "root_state_id")?;
                    let initial = initial.as_ref().ok_or_else(|| Error::missing(root_id))?;
                    check(root_id == initial.id)?;
                    if text(s.issuer()?, "kind")? == "root" {
                        check(s.signer("issuer")?.public_key == facts.root_public_key)?;
                    }
                }
            }
            Some(catalog)
        };
        let mut acknowledgments = BTreeMap::new();
        let mut previous = String::new();
        require(r.acknowledgments_base64.len() <= 4096, "quota_exceeded")?;
        for encoded in &r.acknowledgments_base64 {
            let ack = Statement::read(d, &b64(encoded, MAX_OBJECT)?)?;
            let a = &ack.payload;
            let host = text(a, "host_public_key")?;
            check(ack.kind == "migration_ack" && host > previous.as_str())?;
            previous = host.to_owned();
            Self::check_ack(&p, initial.as_ref(), catalog.as_ref(), &ack)?;
            acknowledgments.insert(host.to_owned(), ack);
        }
        if r.local_acknowledgment_base64 != "-" {
            let ack = Statement::read(d, &b64(&r.local_acknowledgment_base64, MAX_OBJECT)?)?;
            Self::check_ack(&p, initial.as_ref(), catalog.as_ref(), &ack)?;
            let host = text(&ack.payload, "host_public_key")?.to_owned();
            require(
                acknowledgments
                    .get(&host)
                    .is_some_and(|old| old.body == ack.body),
                "state_conflict",
            )?;
        }
        if !acknowledgments.is_empty() {
            let prepared = catalog.as_ref().ok_or_else(|| Error::missing(&p.id))?;
            let root = initial.as_ref().ok_or_else(|| Error::missing(&p.id))?;
            let components = migration::prepared_components(
                &p,
                &source,
                &source_bytes,
                &facts,
                prepared,
                &root.id,
            )?;
            let mut times = BTreeSet::new();
            for (host, ack) in &acknowledgments {
                times.insert(text(&ack.payload, "acknowledged_at")?);
                if text(&ack.payload, "person_public_key")? == "-" {
                    continue;
                }
                let activation = components.get(host).ok_or_else(|| Error::missing(&p.id))?;
                check(activation.id == text(&ack.payload, "activation_id")?)?;
                for name in ["host_lease_id", "binding_lease_id", "device_lease_id"] {
                    check(text(&activation.manifest, name)? == text(&ack.payload, name)?)?;
                }
            }
            // Original ACKs attest the full prepared review at their own
            // signed decision time, never current authority at receipt time.
            // Identical times share one bounded scratch verification. None of
            // this state or its admissions is written as a local prior.
            for at in times {
                let projection = super::state::Projection::stage_migration(
                    d,
                    &prepared.bytes,
                    at,
                    &p.id,
                    &root.id,
                    &source.maxima,
                )?;
                for row in rows {
                    let row = object(row)?;
                    let host = text(row, "host_public_key")?;
                    let h = prepared
                        .statements
                        .values()
                        .find(|s| {
                            s.kind == "host_lease"
                                && s.subject().is_ok_and(|v| {
                                    text(v, "host_public_key").is_ok_and(|h| h == host)
                                })
                        })
                        .ok_or_else(|| Error::missing(&p.id))?;
                    projection.active(&h.id)?;
                    if let Some(activation) = components.get(host) {
                        for name in [
                            "person_lease_id",
                            "host_lease_id",
                            "binding_lease_id",
                            "device_lease_id",
                        ] {
                            projection.active(text(&activation.manifest, name)?)?;
                        }
                    }
                }
            }
        }
        let commit = if r.commit_base64 == "-" {
            require(r.migration_base64 == "-", "state_conflict")?;
            None
        } else {
            let body = Self::complete_body(r)?;
            let complete = migration::Migration::read(d, &body)?;
            if r.migration_base64 != "-" {
                let original = b64(&r.migration_base64, MAX_OBJECT)?;
                let m = migration::Migration::read(d, &original)?;
                require(
                    m.proposal.body == p.body
                        && m.commit.body == complete.commit.body
                        && m.prepared.bytes == complete.prepared.bytes
                        && raw_array_field(&original, "acknowledgments")?
                            == raw_array_field(&body, "acknowledgments")?,
                    "state_conflict",
                )?;
            }
            Some(complete.commit)
        };
        Ok(Self {
            proposal: p,
            source,
            catalog,
            root: initial,
            acknowledgments,
            commit,
        })
    }

    fn check_ack(
        p: &Statement,
        root: Option<&Statement>,
        catalog: Option<&Catalog>,
        ack: &Statement,
    ) -> Result<()> {
        let a = &ack.payload;
        check(ack.kind == "migration_ack")?;
        let host = text(a, "host_public_key")?;
        let row = array(&p.payload, "roster")?
            .iter()
            .find(|r| r.get("host_public_key").and_then(Value::as_str) == Some(host))
            .ok_or_else(|| Error::new("invalid"))?;
        let row = object(row)?;
        let root_id = text(a, "root_state_id")?;
        let root = root.ok_or_else(|| Error::missing(root_id))?;
        let catalog = catalog.ok_or_else(|| Error::missing(&p.id))?;
        check(
            text(a, "proposal_id")? == p.id
                && text(a, "root_state_id")? == root.id
                && text(a, "prepared_catalog_sha256")? == hash(&catalog.bytes)
                && text(a, "person_public_key")? == text(row, "person_public_key")?
                && text(a, "device_public_key")? == text(row, "device_public_key")?
                && ack.signer("host")?.public_key == host
                && text(a, "acknowledged_at")? >= text(&p.payload, "issued_at")?
                && text(a, "acknowledged_at")? < text(&p.payload, "expires_at")?,
        )?;
        if text(a, "device_public_key")? != "-" {
            check(ack.signer("device")?.public_key == text(a, "device_public_key")?)?;
        }
        let h = catalog.get(text(a, "host_lease_id")?)?;
        check(
            h.kind == "host_lease"
                && text(h.subject()?, "host_public_key")? == host
                && text(h.subject()?, "member")? == text(row, "member")?
                && text(&h.payload, "root_state_id")? == root.id,
        )?;
        if text(row, "person_public_key")? == "-" {
            check(
                text(a, "binding_lease_id")? == "-"
                    && text(a, "device_lease_id")? == "-"
                    && text(a, "activation_id")? == "-"
                    && text(&h.payload, "operation_id")? == p.id
                    && text(h.issuer()?, "kind")? == "root",
            )?;
        } else {
            let b = catalog.get(text(a, "binding_lease_id")?)?;
            let device = catalog.get(text(a, "device_lease_id")?)?;
            check(
                b.kind == "binding_lease"
                    && device.kind == "device_lease"
                    && text(b.subject()?, "host_public_key")? == host
                    && text(device.subject()?, "host_public_key")? == host
                    && text(b.subject()?, "person_public_key")? == text(row, "person_public_key")?
                    && text(device.subject()?, "person_public_key")?
                        == text(row, "person_public_key")?
                    && text(device.subject()?, "device_public_key")?
                        == text(row, "device_public_key")?
                    && num(device.subject()?, "scopes")? == num(row, "scopes")?,
            )?;
        }
        Ok(())
    }

    /// The frozen source is never rewritten. A union only checks that every
    /// independently known host/floor/restriction and the actual root survive.
    pub(super) fn known(&self, local: &Source, r: &MigrationRecord) -> Result<()> {
        let p = &self.proposal.payload;
        require(
            migration::legacy_descriptor(&local.legacy_descriptor)?
                == migration::legacy_descriptor(&b64(
                    text(p, "legacy_descriptor_base64")?,
                    MAX_OBJECT,
                )?)?
                && num(p, "legacy_epoch")? >= local.facts.epoch
                && (local.feature == "-" || local.feature == text(p, "legacy_feature_id")?),
            "state_conflict",
        )?;
        let proposed = b64(&r.source_catalog_base64, 512 << 10)?;
        let union = crate::link_runtime::catalog::merge(
            &local.descriptor.network_id,
            &[&local.catalog, &proposed],
        )
        .map_err(super::migration_local::legacy)?;
        let facts = crate::linking::verify_stored_migration_source(
            crate::linking::CatalogFactContext {
                network: &local.legacy_descriptor,
                epoch: num(p, "legacy_epoch")?,
                known_feature_id: &local.feature,
                now: stamp(&local.time)?,
            },
            &union,
        )
        .map_err(super::migration_local::legacy)?;
        require(
            facts.root_public_key == text(p, "legacy_root_public_key")?
                && facts.epoch == num(p, "legacy_epoch")?,
            "state_conflict",
        )?;
        require(
            facts
                .members
                .iter()
                .all(|m| self.source.hosts.contains(&m.host_public_key)),
            "forbidden",
        )?;
        let known = SourceState::read(&local.descriptor.network_id, &local.state_bytes)?;
        for (key, (version, hash)) in known.maxima {
            let (next, next_hash) = self
                .source
                .maxima
                .get(&key)
                .ok_or_else(|| Error::new("forbidden"))?;
            require(*next >= version, "forbidden")?;
            require(
                *next != version || hash == "-" || *next_hash == hash,
                "state_conflict",
            )?;
        }
        for (id, old) in known.restrictions {
            require(self.source.restrictions.get(&id) == Some(&old), "forbidden")?;
        }
        Ok(())
    }

    pub(super) fn complete_body(r: &MigrationRecord) -> Result<Vec<u8>> {
        // RawValue preserves the original signed envelopes. This is the
        // unchanged complete-M proof schema, never the public evidence carrier.
        let raw = |encoded: &str| -> Result<Box<serde_json::value::RawValue>> {
            if encoded == "-" {
                return serde_json::value::RawValue::from_string("\"-\"".into())
                    .map_err(|_| Error::new("internal"));
            }
            let bytes = b64(encoded, MAX_OBJECT)?;
            serde_json::value::RawValue::from_string(
                String::from_utf8(bytes).map_err(|_| Error::new("invalid"))?,
            )
            .map_err(|_| Error::new("invalid"))
        };
        #[derive(serde::Serialize)]
        struct Full<'a> {
            format: u64,
            proposal: Box<serde_json::value::RawValue>,
            source_catalog_base64: &'a str,
            source_state_base64: &'a str,
            prepared_catalog_base64: &'a str,
            acknowledgments: Vec<Box<serde_json::value::RawValue>>,
            commit: Box<serde_json::value::RawValue>,
        }
        let body = serde_json::to_vec(&Full {
            format: 1,
            proposal: raw(&r.proposal_base64)?,
            source_catalog_base64: &r.source_catalog_base64,
            source_state_base64: &r.source_state_base64,
            prepared_catalog_base64: &r.prepared_catalog_base64,
            acknowledgments: r
                .acknowledgments_base64
                .iter()
                .map(|a| raw(a))
                .collect::<Result<_>>()?,
            commit: raw(&r.commit_base64)?,
        })
        .map_err(|_| Error::new("internal"))?;
        require(body.len() <= MAX_OBJECT, "quota_exceeded")?;
        Ok(body)
    }

    pub(super) fn view(&self, d: &Descriptor, r: &MigrationRecord) -> Result<Value> {
        let p = &self.proposal.payload;
        require(
            !r.fenced || r.approved && r.local_acknowledgment_base64 != "-",
            "state_conflict",
        )?;
        require(
            !matches!(r.state.as_str(), "acknowledged" | "adopted") || r.fenced,
            "state_conflict",
        )?;
        let local = if r.local_acknowledgment_base64 == "-" {
            "-".to_owned()
        } else {
            Statement::read(d, &b64(&r.local_acknowledgment_base64, MAX_OBJECT)?)?.id
        };
        let missing = array(p, "roster")?
            .iter()
            .map(object)
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .filter_map(|row| match text(row, "host_public_key") {
                Ok(h) if !self.acknowledgments.contains_key(h) => Some(Ok(h.to_owned())),
                Ok(_) => None,
                Err(e) => Some(Err(e)),
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(
            json!({"network_id":d.network_id,"proposal_id":self.proposal.id,"context_id":d.context_id(),"state":r.state,"source_catalog_sha256":text(p,"source_catalog_sha256")?,"source_state_sha256":text(p,"source_state_sha256")?,"prepared_catalog_sha256":self.catalog.as_ref().map_or("-".to_owned(),|c|hash(&c.bytes)),"root_state_id":self.root.as_ref().map_or("-",|s|s.id.as_str()),"local_acknowledgment_id":local,"root_commit_id":self.commit.as_ref().map_or("-",|s|s.id.as_str()),"missing_host_keys":missing,"required_proof_ids":[],"approved":r.approved,"fenced":r.fenced,"expires_at":text(p,"expires_at")?}),
        )
    }
}
