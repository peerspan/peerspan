use super::{
    catalog::{Catalog, value_field},
    codec::*,
    statement::{Descriptor, Statement, lease, restriction},
    transcript::Activation,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
#[path = "stages.rs"]
mod stages;
pub(crate) use stages::{
    CeremonyPrefix, PreparedAdmissions, PreparedFinalization, folded_host,
    packet_agrees as check_requester_selection,
};

#[derive(Clone, Debug)]
pub struct Maximum {
    pub stream: Vec<String>,
    pub sequence: u64,
    pub statement_ids: BTreeSet<String>,
    pub head_ids: BTreeSet<String>,
}
#[derive(Clone, Debug)]
pub struct Prior {
    pub value: Value,
    pub catalog: Catalog,
    pub admitted: BTreeSet<String>,
    pub restrictions: BTreeSet<String>,
    pub activations: BTreeSet<String>,
    pub root_heads: BTreeSet<String>,
    pub maxima: BTreeMap<Vec<String>, Maximum>,
    pub migration_proposal_id: String,
    pub clock_guard: String,
}
impl Prior {
    pub fn read(d: &Descriptor, value: &Value) -> Result<Option<Self>> {
        Self::read_mode(d, value, false)
    }
    pub(crate) fn read_only(d: &Descriptor, value: &Value) -> Result<Option<Self>> {
        Self::read_mode(d, value, true)
    }
    fn read_mode(d: &Descriptor, value: &Value, read_only: bool) -> Result<Option<Self>> {
        if value.as_str() == Some("-") {
            return Ok(None);
        }
        let o = object(value)?;
        fields(
            o,
            "format context_id catalog_base64 admitted_statement_ids admitted_restriction_ids admitted_activation_ids root_head_ids maxima migration_proposal_id clock_guard",
        )?;
        version(o)?;
        check(text(o, "context_id")? == d.context_id())?;
        let catalog = Catalog::read(d, &b64(text(o, "catalog_base64")?, MAX_CATALOG)?)?;
        let admitted: BTreeSet<_> = ids(o, "admitted_statement_ids", "ds_")?
            .into_iter()
            .collect();
        let restrictions: BTreeSet<_> = ids(o, "admitted_restriction_ids", "ds_")?
            .into_iter()
            .collect();
        let activations = ids(o, "admitted_activation_ids", "da_")?
            .into_iter()
            .collect();
        let root_heads: BTreeSet<String> = ids(o, "root_head_ids", "ds_")?.into_iter().collect();
        let migration_proposal_id = text(o, "migration_proposal_id")?.to_owned();
        check(migration_proposal_id == "-" || ident(&migration_proposal_id, "ds_"))?;
        let clock_guard = text(o, "clock_guard")?.to_owned();
        if clock_guard != "-" {
            stamp(&clock_guard)?;
        }
        let mut maxima = BTreeMap::new();
        let mut previous: Option<Vec<String>> = None;
        for row in array(o, "maxima")? {
            let m = object(row)?;
            fields(m, "stream sequence statement_ids head_ids")?;
            let stream = strings(m, "stream")?;
            validate_stream(&stream)?;
            check(previous.as_ref().is_none_or(|p| p < &stream))?;
            previous = Some(stream.clone());
            let sequence = num(m, "sequence")?;
            check(sequence > 0 || stream == ["root"])?;
            let statement_ids = ids(m, "statement_ids", "ds_")?.into_iter().collect();
            let head_ids = ids(m, "head_ids", "ds_")?.into_iter().collect();
            maxima.insert(
                stream.clone(),
                Maximum {
                    stream,
                    sequence,
                    statement_ids,
                    head_ids,
                },
            );
        }
        if !admitted.is_empty() || !root_heads.is_empty() {
            check(maxima.contains_key(&vec!["root".into()]))?;
        }
        for id in &admitted {
            if let Some(s) = catalog.statements.get(id) {
                let stream = s.stream()?.ok_or_else(|| Error::new("invalid"))?;
                let maximum = maxima.get(&stream).ok_or_else(|| Error::new("invalid"))?;
                check(s.sequence()? <= maximum.sequence)?;
                if s.sequence()? == maximum.sequence {
                    check(maximum.statement_ids.contains(id))?;
                }
                check(
                    s.kind == "root_state"
                        || lease(&s.kind)
                        || matches!(s.kind.as_str(), "policy" | "group"),
                )?;
            } else {
                // Trusted head/maximum metadata preserves a remembered branch
                // even when its body is unavailable. It supplies no authority:
                // any verification that needs the body must resolve its exact ID.
                check(
                    read_only
                        || maxima
                            .values()
                            .any(|m| m.statement_ids.contains(id) || m.head_ids.contains(id)),
                )?;
            }
        }
        for m in maxima.values() {
            check(m.statement_ids.is_subset(&m.head_ids))?;
            if m.statement_ids.is_empty() {
                check(migration_proposal_id != "-" && m.head_ids.is_empty())?;
                let source = m.stream.get(1).and_then(|subject| {
                    catalog.migrations.values().find_map(|origin| {
                        (origin.proposal.id == migration_proposal_id)
                            .then(|| {
                                origin
                                    .source_state
                                    .maxima
                                    .get(&(m.stream[0].clone(), subject.clone()))
                            })
                            .flatten()
                    })
                });
                require(
                    source.is_some_and(|(version, _)| *version == m.sequence),
                    "proof_required",
                )?;
            }
            for id in &m.head_ids {
                check(admitted.contains(id))?;
                if let Some(body) = catalog.statements.get(id) {
                    check(
                        body.stream()?.as_ref() == Some(&m.stream)
                            && body.sequence()? <= m.sequence,
                    )?;
                }
            }
        }
        if let Some(root) = maxima.get(&vec!["root".into()]) {
            check(root.head_ids == root_heads)?;
        }
        for id in &restrictions {
            check(restriction(&catalog.get(id)?.kind))?;
        }
        for m in maxima.values() {
            for id in &m.statement_ids {
                if let Some(s) = catalog.statements.get(id) {
                    check(
                        s.stream()?.as_ref() == Some(&m.stream)
                            && s.sequence()? == m.sequence
                            && admitted.contains(id),
                    )?;
                }
            }
        }
        Ok(Some(Self {
            value: value.clone(),
            catalog,
            admitted,
            restrictions,
            activations,
            root_heads,
            maxima,
            migration_proposal_id,
            clock_guard,
        }))
    }
}
fn validate_stream(stream: &[String]) -> Result<()> {
    check(match stream {
        [root] => root == "root",
        [kind, key_] => {
            if kind == "group" {
                crate::admins::group_name(key_).is_ok()
            } else {
                matches!(
                    kind.as_str(),
                    "admin" | "person" | "host" | "binding" | "policy"
                ) && key(key_)
            }
        }
        [kind, person, device] => kind == "device" && key(person) && key(device),
        _ => false,
    })
}
#[derive(Clone, Debug)]
pub struct Stream {
    pub key: Vec<String>,
    pub heads: BTreeSet<String>,
    pub maximum: u64,
    pub at_maximum: BTreeSet<String>,
}
/// Projections recently built by `Projection::build`, by all of its inputs.
static BUILT: super::memo::Memo<Projection> = super::memo::Memo::new();
#[derive(Default)]
struct Preparation {
    migration: Option<(String, String)>,
    floors: BTreeMap<Vec<String>, u64>,
    genesis: Option<(String, String)>,
    owner_offer: Option<super::transcript::Packet>,
    administrator: Option<super::transcript::Packet>,
}
#[derive(Clone, Debug)]
pub struct Projection {
    pub descriptor: Descriptor,
    pub catalog: Catalog,
    pub decision_time: String,
    pub admitted: BTreeSet<String>,
    pub restrictions: BTreeSet<String>,
    pub(crate) activated: BTreeMap<String, Activation>,
    complete_operations: BTreeMap<String, Activation>,
    ceremony_statements: BTreeSet<String>,
    staged_origin: Option<(String, String)>,
    staged_floors: BTreeMap<Vec<String>, u64>,
    origin_conflicted: bool,
    local_genesis: Option<(String, String)>,
    pub streams: BTreeMap<Vec<String>, Stream>,
    pub inert: BTreeSet<String>,
    // Only read projections retain incomplete stored proof closures by DS.
    // These markers never supply a body or permit candidate admission.
    read_missing: BTreeMap<String, Error>,
    prior: Option<Prior>,
}
pub(crate) struct OwnerOfferPath {
    pub provider: Value,
    pub catalog: Catalog,
    pub decision_time: String,
}
#[derive(Clone, Debug)]
struct Power {
    deadline: Option<String>,
    scopes: u64,
    // Only successful finite authority contributions, never proof-only lineage.
    proven: BTreeSet<String>,
}
impl Power {
    fn unlimited() -> Self {
        Self {
            deadline: None,
            scopes: 15,
            proven: BTreeSet::new(),
        }
    }
    fn intersect(&mut self, other: &Self) {
        self.scopes &= other.scopes;
        self.proven.extend(other.proven.iter().cloned());
        if let Some(end) = &other.deadline
            && self.deadline.as_ref().is_none_or(|d| end < d)
        {
            self.deadline = Some(end.clone());
        }
    }
}
impl Projection {
    /// A bounded, private preparation result for one reviewed owner offer. The
    /// scratch admissions are deliberately not returned as transferable prior
    /// state and must never be persisted by selection or ordinary import.
    pub(crate) fn prepare_owner_offer(
        descriptor: &Descriptor,
        prior: &Value,
        catalog: &[u8],
        owner: &super::transcript::Packet,
        now: &str,
    ) -> Result<OwnerOfferPath> {
        check(text(&owner.object, "role")? == "owner")?;
        let person = text(&owner.object, "person_public_key")?;
        let host = text(&owner.object, "writer_host_public_key")?;
        let issuer = text(&owner.object, "issuer_id")?;
        check(key(person) && text(&owner.payload, "root_state_id")? != "-")?;
        let projection = Self::build_mode(
            descriptor,
            prior,
            Some(catalog),
            now,
            "repair",
            Preparation {
                owner_offer: Some(owner.clone()),
                ..Preparation::default()
            },
        )?;
        require(
            projection.root_state_id()? == text(&owner.payload, "root_state_id")?,
            "forbidden",
        )?;
        let member = projection.member_for(host, person)?;
        require(
            member.person_lease_id == text(&owner.payload, "person_lease_id")?,
            "forbidden",
        )?;
        let provider =
            projection.provider_potential(person, host, (issuer != "-").then_some(issuer))?;
        let mut references = vec![member.person_lease_id];
        if issuer != "-" {
            references.push(issuer.to_owned());
            require(
                text(
                    projection.catalog.get(issuer)?.subject()?,
                    "device_public_key",
                )? != text(&owner.payload, "device_public_key")?,
                "forbidden",
            )?;
            let renewed = text(&owner.payload, "renewed_device_lease_id")?;
            if renewed != "-" {
                require(projection.owner_ancestor(issuer, renewed)?, "forbidden")?;
            }
        }
        references.sort();
        check(references == ids(&owner.payload, "issuer_lease_ids", "ds_")?)?;
        let public = object(&provider)?;
        require(num(public, "scopes")? & 4 == 4, "forbidden")?;
        require(
            num(&owner.payload, "scopes")? & !num(public, "scopes")? == 0
                && text(&owner.payload, "not_after")? <= text(public, "not_after")?,
            "forbidden",
        )?;
        Ok(OwnerOfferPath {
            provider,
            catalog: projection.catalog,
            decision_time: projection.decision_time,
        })
    }
    fn scope_owner_preparation(&mut self, owner: &super::transcript::Packet) -> Result<()> {
        self.packet_provenance(owner)?;
        let person = text(&owner.object, "person_public_key")?;
        let host = text(&owner.object, "writer_host_public_key")?;
        let issuer = text(&owner.object, "issuer_id")?;
        let mut scope = BTreeSet::new();
        // Only the actual bound owner path and typed ancestors participate.
        // Signed retention/resolution lists remain proof requirements, never
        // a way to enroll unrelated grants into the preparation exception.
        for binding in self
            .catalog
            .statements
            .values()
            .filter(|s| s.kind == "binding_lease")
        {
            if text(binding.subject()?, "person_public_key")? == person
                && text(binding.subject()?, "host_public_key")? == host
            {
                scope.insert(binding.id.clone());
                self.ceremony_ancestry(&binding.id, &mut scope)?;
            }
        }
        if issuer != "-" {
            scope.insert(issuer.into());
            self.ceremony_ancestry(issuer, &mut scope)?;
        }
        self.ceremony_statements.extend(scope);
        Ok(())
    }
    pub fn build(
        d: &Descriptor,
        prior_value: &Value,
        candidate: Option<&[u8]>,
        now: &str,
        operation: &str,
    ) -> Result<Self> {
        // A projection is a pure function of these inputs. One command
        // rebuilds the same one many times (each read, each recheck of a
        // candidate inside its final transaction), so an identical set of
        // inputs reuses the projection built last time.
        let (descriptor, prior) = (
            serde_json::to_vec(d).map_err(|_| Error::new("internal"))?,
            serde_json::to_vec(prior_value).map_err(|_| Error::new("internal"))?,
        );
        let key = super::memo::key([
            descriptor.as_slice(),
            &prior,
            candidate.map_or(b"-".as_slice(), |_| b"+"),
            candidate.unwrap_or_default(),
            now.as_bytes(),
            operation.as_bytes(),
        ]);
        if let Some(hit) = BUILT.get(&key) {
            return Ok(hit);
        }
        let projection = Self::build_mode(
            d,
            prior_value,
            candidate,
            now,
            operation,
            Preparation::default(),
        )?;
        BUILT.put(key, &projection, projection.catalog.bytes.len());
        Ok(projection)
    }
    /// Verify additional exact proof bytes against an already trusted snapshot.
    /// Only the proof carrier changes: no admission, operation, restriction,
    /// head, maximum or clock marker is inferred from the supplied objects.
    pub(crate) fn read_with_proofs(
        d: &Descriptor,
        prior_value: &Value,
        proofs: &[u8],
        now: &str,
    ) -> Result<Self> {
        let prior =
            Prior::read_only(d, prior_value)?.ok_or_else(|| Error::new("proof_required"))?;
        let supplied = Catalog::read(d, proofs)?;
        let catalog = Catalog::union(d, &prior.catalog, &supplied)?;
        let mut frozen = prior.value;
        object(&frozen)?;
        frozen["catalog_base64"] = Value::from(encode(&catalog.bytes));
        Self::build(d, &frozen, None, now, "read")
    }
    pub(crate) fn stage_migration(
        d: &Descriptor,
        catalog: &[u8],
        now: &str,
        proposal: &str,
        root: &str,
        floors: &BTreeMap<(String, String), (u64, String)>,
    ) -> Result<Self> {
        Self::build_mode(
            d,
            &Value::from("-"),
            Some(catalog),
            now,
            "repair",
            Preparation {
                migration: Some((proposal.into(), root.into())),
                floors: floors
                    .iter()
                    .map(|((kind, subject), (version, _))| {
                        (vec![kind.clone(), subject.clone()], *version)
                    })
                    .collect(),
                genesis: None,
                owner_offer: None,
                administrator: None,
            },
        )
    }
    /// Extend only an already source-verified private migration scratch view
    /// with the exact original-self owner prefix. No ordinary prior is created.
    pub(crate) fn migration_owner_prefix(
        &self,
        catalog: &[u8],
        owner: &super::transcript::Packet,
        now: &str,
    ) -> Result<Self> {
        let (proposal, root) = self
            .staged_origin
            .as_ref()
            .ok_or_else(|| Error::new("forbidden"))?;
        check(text(&owner.payload, "root_state_id")? == root)?;
        Self::build_mode(
            &self.descriptor,
            &Value::from("-"),
            Some(catalog),
            now,
            "repair",
            Preparation {
                migration: Some((proposal.clone(), root.clone())),
                floors: self.staged_floors.clone(),
                owner_offer: Some(owner.clone()),
                ..Preparation::default()
            },
        )
    }
    pub(crate) fn genesis(
        d: &Descriptor,
        catalog: &[u8],
        now: &str,
        person: &str,
        host: &str,
    ) -> Result<Self> {
        check(key(person) && key(host))?;
        let source = Catalog::read(d, catalog)?;
        // A creation since DEC-Q21 also carries the creator device grant.
        let creator_device = source.statements.values().any(|s| s.kind == "device_lease");
        let mut expected = vec![
            "admin_lease",
            "binding_lease",
            "host_lease",
            "person_lease",
            "policy",
            "root_state",
        ];
        if creator_device {
            expected.push("device_lease");
        }
        check(source.proofs.len() == expected.len() && source.statements.len() == expected.len())?;
        let mut kinds = BTreeMap::new();
        for statement in source.statements.values() {
            check(
                expected.contains(&statement.kind.as_str())
                    && kinds.insert(statement.kind.as_str(), statement).is_none(),
            )?;
        }
        let root = kinds["root_state"];
        check(
            root.sequence()? == 0
                && root.signer("issuer")?.format == "ed25519"
                && text(&root.payload, "migration_proposal_id")? == "-"
                && ids(&root.payload, "predecessors", "ds_")?.is_empty(),
        )?;
        let admission = kinds["person_lease"];
        let membership = kinds["host_lease"];
        check(
            text(admission.subject()?, "person_public_key")? == person
                && text(membership.subject()?, "host_public_key")? == host
                && text(admission.subject()?, "member")? == text(membership.subject()?, "member")?,
        )?;
        check(text(kinds["admin_lease"].subject()?, "person_public_key")? == person)?;
        for kind in ["admin_lease", "person_lease", "host_lease"] {
            check(
                text(kinds[kind].issuer()?, "kind")? == "root"
                    && kinds[kind].signer("issuer")?.format == "ed25519",
            )?;
        }
        let binding = kinds["binding_lease"];
        check(
            text(binding.subject()?, "person_public_key")? == person
                && text(binding.subject()?, "host_public_key")? == host,
        )?;
        for kind in ["binding_lease", "policy"] {
            let s = kinds[kind];
            check(
                text(s.issuer()?, "kind")? == "person"
                    && text(s.issuer()?, "person_public_key")? == person
                    && s.parents()?.get("issuer_person") == Some(&admission.id),
            )?;
        }
        let parents = binding.parents()?;
        check(
            parents.get("subject_person") == Some(&admission.id)
                && parents.get("subject_host") == Some(&membership.id),
        )?;
        if creator_device {
            check(Self::creator_device_shape(
                kinds["device_lease"],
                &kinds,
                person,
                host,
            ))?;
        }
        for statement in source
            .statements
            .values()
            .filter(|s| s.kind != "root_state")
        {
            check(
                statement.sequence()? == 1
                    && text(&statement.payload, "root_state_id")? == root.id
                    && text(&statement.payload, "operation_id")? == "-"
                    && statement.issued_at()? == root.issued_at()?
                    && ids(&statement.payload, "predecessors", "ds_")?.is_empty()
                    && ids(&statement.payload, "resolves", "ds_")?.is_empty(),
            )?;
            if lease(&statement.kind) {
                check(ids(&statement.payload, "retained_statement_ids", "ds_")?.is_empty())?;
            }
        }
        let result = Self::build_mode(
            d,
            &Value::from("-"),
            Some(catalog),
            now,
            "fresh",
            Preparation {
                genesis: Some((person.into(), host.into())),
                ..Preparation::default()
            },
        )?;
        for id in source.statements.keys() {
            require(result.admitted.contains(id), "forbidden")?;
            result.active(id)?;
        }
        Ok(result)
    }
    /// The creator device grant (DEC-Q21): scopes 15, issued by the original
    /// key with the genesis person, host and binding grants as parents.
    fn creator_device_shape(
        device: &Statement,
        genesis: &BTreeMap<&str, &Statement>,
        person: &str,
        host: &str,
    ) -> bool {
        let Ok(parents) = device.parents() else {
            return false;
        };
        let Ok(subject) = device.subject() else {
            return false;
        };
        let admission = &genesis["person_lease"].id;
        text(subject, "person_public_key").is_ok_and(|k| k == person)
            && text(subject, "host_public_key").is_ok_and(|k| k == host)
            && num(subject, "scopes").is_ok_and(|s| s == 15)
            && device
                .issuer()
                .is_ok_and(|i| text(i, "kind").is_ok_and(|k| k == "person"))
            && parents.get("issuer_person") == Some(admission)
            && parents.get("subject_person") == Some(admission)
            && parents.get("subject_host") == Some(&genesis["host_lease"].id)
            && parents.get("subject_binding") == Some(&genesis["binding_lease"].id)
            && parents.len() == 4
    }
    fn build_mode(
        d: &Descriptor,
        prior_value: &Value,
        candidate: Option<&[u8]>,
        now: &str,
        operation: &str,
        preparation: Preparation,
    ) -> Result<Self> {
        let began = std::time::Instant::now();
        let out = Self::build_mode_inner(d, prior_value, candidate, now, operation, preparation);
        if crate::timing::enabled() {
            crate::timing::log("step", &format!("project {operation}"), began);
        }
        out
    }
    fn build_mode_inner(
        d: &Descriptor,
        prior_value: &Value,
        candidate: Option<&[u8]>,
        now: &str,
        operation: &str,
        preparation: Preparation,
    ) -> Result<Self> {
        let Preparation {
            migration: staged_origin,
            floors: staged_floors,
            genesis: local_genesis,
            owner_offer,
            administrator,
        } = preparation;
        check(matches!(operation, "read" | "fresh" | "repair"))?;
        check((operation == "read") == candidate.is_none())?;
        let prior = if operation == "read" {
            Prior::read_only(d, prior_value)?
        } else {
            Prior::read(d, prior_value)?
        };
        let decision_time = decision_clock(
            now,
            prior
                .as_ref()
                .map(|p| p.clock_guard.as_str())
                .unwrap_or("-"),
        )?;
        let candidate = candidate.map(|b| Catalog::read(d, b)).transpose()?;
        let catalog = match (&prior, &candidate) {
            (Some(p), Some(c)) => Catalog::union(d, &p.catalog, c)?,
            (Some(p), None) => p.catalog.clone(),
            (None, Some(c)) => c.clone(),
            (None, None) => return Err(Error::new("proof_required")),
        };
        let mut staged_floors = staged_floors;
        let mut origins = BTreeSet::new();
        for migration in catalog.migrations.values() {
            if stamp(migration.prepared.get(&migration.root_id)?.issued_at()?)?
                > stamp(&decision_time)?
            {
                continue;
            }
            origins.insert((
                migration.proposal.id.clone(),
                hash(&migration.prepared.bytes),
            ));
        }
        if catalog.statements.values().any(|s| {
            s.kind == "root_state"
                && s.issued_at()
                    .is_ok_and(|issued| issued <= decision_time.as_str())
                && s.payload
                    .get("migration_proposal_id")
                    .and_then(Value::as_str)
                    == Some("-")
                && s.payload
                    .get("predecessors")
                    .and_then(Value::as_array)
                    .is_some_and(|a| a.is_empty())
        }) && !origins.is_empty()
        {
            origins.insert(("-".into(), "-".into()));
        }
        if let Some(p) = &prior
            && p.migration_proposal_id != "-"
            && !origins.is_empty()
            && !origins
                .iter()
                .any(|(proposal, _)| proposal == &p.migration_proposal_id)
        {
            origins.insert((p.migration_proposal_id.clone(), "-".into()));
        }
        if origins.len() == 1 {
            for migration in catalog.migrations.values() {
                if stamp(migration.prepared.get(&migration.root_id)?.issued_at()?)?
                    > stamp(&decision_time)?
                {
                    continue;
                }
                for ((kind, subject), (maximum, _)) in &migration.source_state.maxima {
                    staged_floors
                        .entry(vec![kind.clone(), subject.clone()])
                        .and_modify(|old| *old = (*old).max(*maximum))
                        .or_insert(*maximum);
                }
            }
        }
        let mut result = Self {
            descriptor: d.clone(),
            catalog,
            decision_time,
            admitted: prior
                .as_ref()
                .map(|p| p.admitted.clone())
                .unwrap_or_default(),
            restrictions: prior
                .as_ref()
                .map(|p| p.restrictions.clone())
                .unwrap_or_default(),
            activated: BTreeMap::new(),
            complete_operations: BTreeMap::new(),
            ceremony_statements: BTreeSet::new(),
            staged_origin,
            staged_floors,
            origin_conflicted: origins.len() > 1,
            local_genesis,
            streams: BTreeMap::new(),
            inert: BTreeSet::new(),
            read_missing: BTreeMap::new(),
            prior,
        };
        // Every present proof is structurally verified before admission markers,
        // expiry or a domain conflict can influence a permission result.
        for (proof, _) in result.catalog.activation_proofs() {
            let activation = Activation::read(d, &proof.body)?;
            if let Some(old) = result.complete_operations.get(&activation.request_id) {
                require(old.id == activation.id, "operation_conflict")?;
            }
            result
                .complete_operations
                .insert(activation.request_id.clone(), activation);
        }
        result.read_missing = result.verify_provenance(operation == "read")?;
        if let Some(owner) = &owner_offer {
            result.scope_owner_preparation(owner)?;
        }
        if let Some(administrator) = &administrator {
            result.scope_owner_preparation(administrator)?;
        }
        result.verify_operations(operation != "read")?;
        if operation == "read" {
            // Inert stored proofs remain unadmitted during a read. Returning
            // unchanged next_prior is insufficient if views/actions evaluate
            // a different, newly admitted in-memory state.
            result.rebuild_streams()?;
            result.inert.extend(
                result
                    .catalog
                    .statements
                    .values()
                    .filter(|s| {
                        (s.kind == "root_state"
                            || lease(&s.kind)
                            || restriction(&s.kind)
                            || matches!(s.kind.as_str(), "policy" | "group"))
                            && !result.admitted.contains(&s.id)
                            && !result.restrictions.contains(&s.id)
                    })
                    .map(|s| s.id.clone()),
            );
            return Ok(result);
        }
        result.admit_roots()?;
        result.inert.extend(
            result
                .catalog
                .statements
                .values()
                .filter(|s| s.kind == "root_state" && !result.admitted.contains(&s.id))
                .map(|s| s.id.clone()),
        );
        result.rebuild_streams()?;
        let candidates: Vec<_> = result
            .catalog
            .statements
            .values()
            .filter(|s| lease(&s.kind) || matches!(s.kind.as_str(), "policy" | "group"))
            .map(|s| s.id.clone())
            .collect();
        let restricts: Vec<_> = result
            .catalog
            .statements
            .values()
            .filter(|s| restriction(&s.kind))
            .map(|s| s.id.clone())
            .collect();
        // Dependency-driven fixed point. A candidate's own target admission
        // never creates the current issuer power needed to admit itself.
        let mut pending: BTreeSet<_> = candidates.iter().chain(&restricts).cloned().collect();
        for _ in 0..=pending.len() {
            let mut progress = false;
            let ordered: Vec<_> = restricts
                .iter()
                .chain(&candidates)
                .filter(|id| pending.contains(*id))
                .cloned()
                .collect();
            for id in ordered {
                if result.admitted.contains(&id) || result.restrictions.contains(&id) {
                    pending.remove(&id);
                    continue;
                }
                let s = result.catalog.get(&id)?;
                if stamp(s.issued_at()?)? > stamp(&result.decision_time)? {
                    continue;
                }
                let eligible = result.admission(&id);
                match eligible {
                    Ok(()) => {
                        if restriction(&s.kind) {
                            result.restrictions.insert(id.clone());
                        } else {
                            result.admitted.insert(id.clone());
                        }
                        pending.remove(&id);
                        result.rebuild_streams()?;
                        progress = true;
                    }
                    Err(e) if e.code == "invalid" || e.code == "quota_exceeded" => return Err(e),
                    Err(_) => {}
                }
            }
            if !progress {
                break;
            }
        }
        for id in pending {
            if let Err(e) = result.admission(&id)
                && e.code == "proof_required"
                && !e.required_ids.is_empty()
            {
                // Exact still-incomplete ceremony components may be retained
                // for prefix review. No missing ancestor or other operation
                // is waived, and these statements remain wholly unadmitted.
                let pending_component = owner_offer.as_ref().is_some_and(|owner| {
                    let request = text(&owner.object, "request_id").unwrap_or("-");
                    e.required_ids.len() == 1
                        && e.required_ids.contains(request)
                        && result.catalog.get(&id).is_ok_and(|s| {
                            lease(&s.kind)
                                && text(&s.payload, "operation_id").is_ok_and(|op| op == request)
                        })
                });
                if !pending_component {
                    return Err(e);
                }
            }
            result.inert.insert(id);
        }
        // A cold context needs an actual complete origin, never a caller's
        // candidate-only claim that a root was previously admitted.
        require(
            result.streams.contains_key(&vec!["root".into()]),
            "proof_required",
        )?;
        Ok(result)
    }
    fn verify_provenance(&self, read_only: bool) -> Result<BTreeMap<String, Error>> {
        let mut device_counts = BTreeMap::<String, usize>::new();
        for s in self
            .catalog
            .statements
            .values()
            .filter(|s| s.kind == "device_lease")
        {
            let count = device_counts
                .entry(text(s.subject()?, "person_public_key")?.into())
                .or_default();
            *count += 1;
            require(*count <= 4096, "quota_exceeded")?;
        }
        let mut reverse = BTreeMap::<String, Vec<String>>::new();
        let mut remaining = BTreeMap::<String, usize>::new();
        let mut all_dependencies = BTreeMap::<String, BTreeSet<String>>::new();
        let mut missing = BTreeMap::<String, Error>::new();
        for s in self.catalog.statements.values() {
            let mut dependencies = BTreeSet::new();
            if s.payload.contains_key("root_state_id") {
                dependencies.insert(text(&s.payload, "root_state_id")?.to_owned());
            }
            if s.payload.contains_key("parents") {
                dependencies.extend(s.parents()?.into_values());
            }
            for name in [
                "predecessors",
                "resolves",
                "retained_statement_ids",
                "kept_statement_ids",
            ] {
                if s.payload.contains_key(name) {
                    let references = ids(&s.payload, name, "ds_")?;
                    if name == "retained_statement_ids" {
                        for id in &references {
                            if let Some(retained) = self.catalog.statements.get(id) {
                                check(retained.kind != "root_state")?;
                            }
                        }
                    }
                    dependencies.extend(references);
                }
            }
            if restriction(&s.kind) {
                let target = object(
                    s.payload
                        .get("target")
                        .ok_or_else(|| Error::new("invalid"))?,
                )?;
                for id in [text(target, "statement_id")?, text(&s.payload, "ratifies")?] {
                    if id != "-" {
                        dependencies.insert(id.into());
                    }
                }
            }
            let mut present = 0;
            for dependency in &dependencies {
                if !self.catalog.statements.contains_key(dependency) {
                    if !read_only {
                        return Err(Error::missing(dependency));
                    }
                    missing
                        .entry(s.id.clone())
                        .or_insert_with(|| Error::new("proof_required"))
                        .required_ids
                        .insert(dependency.clone());
                    continue;
                }
                reverse
                    .entry(dependency.clone())
                    .or_default()
                    .push(s.id.clone());
                present += 1;
            }
            remaining.insert(s.id.clone(), present);
            all_dependencies.insert(s.id.clone(), dependencies);
        }
        let mut ready: Vec<_> = remaining
            .iter()
            .filter(|(_, n)| **n == 0)
            .map(|(id, _)| id.clone())
            .collect();
        let mut verified = 0;
        while let Some(id) = ready.pop() {
            let aliases = self
                .catalog
                .aliases
                .get(&id)
                .ok_or_else(|| Error::new("invalid"))?;
            for alias in aliases {
                if let Err(error) =
                    self.provenance_statement(alias, &mut BTreeSet::new(), &mut Vec::new())
                {
                    if !read_only || error.code != "proof_required" {
                        return Err(error);
                    }
                    missing
                        .entry(id.clone())
                        .or_insert_with(|| Error::new("proof_required"))
                        .required_ids
                        .extend(error.required_ids);
                }
            }
            let inherited: BTreeSet<_> = all_dependencies[&id]
                .iter()
                .filter_map(|dependency| missing.get(dependency))
                .flat_map(|error| error.required_ids.iter().cloned())
                .collect();
            if !inherited.is_empty() {
                missing
                    .entry(id.clone())
                    .or_insert_with(|| Error::new("proof_required"))
                    .required_ids
                    .extend(inherited);
            }
            verified += 1;
            if let Some(children) = reverse.get(&id) {
                for child in children {
                    let count = remaining
                        .get_mut(child)
                        .ok_or_else(|| Error::new("invalid"))?;
                    *count -= 1;
                    if *count == 0 {
                        ready.push(child.clone());
                    }
                }
            }
        }
        check(verified == self.catalog.statements.len())?;
        Ok(missing)
    }
    pub(super) fn proof_complete(&self, id: &str) -> Result<()> {
        self.catalog.get(id)?;
        self.read_missing.get(id).map_or(Ok(()), |e| Err(e.clone()))
    }
    fn provenance(
        &self,
        id: &str,
        path: &mut BTreeSet<String>,
        devices: &mut Vec<String>,
    ) -> Result<()> {
        self.provenance_statement(self.catalog.get(id)?, path, devices)
    }
    fn provenance_statement(
        &self,
        s: &Statement,
        path: &mut BTreeSet<String>,
        devices: &mut Vec<String>,
    ) -> Result<()> {
        let id = &s.id;
        check(path.insert(id.clone()))?;
        let result = (|| {
            if s.kind == "root_state" {
                let migration_proposal = text(&s.payload, "migration_proposal_id")?;
                if migration_proposal != "-"
                    && !(self.staged_origin.as_ref().is_some_and(|(proposal, root)| {
                        proposal == migration_proposal && root == &s.id
                    }) || self
                        .catalog
                        .migrations
                        .values()
                        .any(|m| m.root_id == s.id && m.proposal.id == migration_proposal))
                {
                    return Err(Error::missing(migration_proposal));
                }
                let predecessors = ids(&s.payload, "predecessors", "ds_")?;
                let mut maximum = 0;
                for predecessor in &predecessors {
                    let old = self.catalog.get(predecessor)?;
                    check(old.kind == "root_state")?;

                    maximum = maximum.max(old.sequence()?);
                    let role = if predecessors.len() == 1 {
                        "issuer".into()
                    } else {
                        format!("root_branch:{predecessor}")
                    };
                    check(s.signer(&role)?.public_key == text(&old.payload, "root_public_key")?)?;
                }
                if !predecessors.is_empty() {
                    check(maximum.checked_add(1) == Some(s.sequence()?))?;
                }
                for a in &predecessors {
                    for b in &predecessors {
                        if a != b {
                            check(!self.descends(a, b, &mut BTreeSet::new())?)?;
                        }
                    }
                }
                return Ok(());
            }
            if s.kind.starts_with("migration_") {
                return Ok(());
            }
            let root = self.catalog.get(text(&s.payload, "root_state_id")?)?;
            check(root.kind == "root_state")?;

            let issuer = s.issuer()?;
            let ik = text(issuer, "kind")?;
            let person = text(issuer, "person_public_key")?;
            let parents = s.parents()?;
            let mut pushed = false;
            if s.kind == "device_lease" {
                let device = text(s.subject()?, "device_public_key")?;
                check(!devices.iter().any(|k| k == device))?;
                require(devices.len() < 8, "quota_exceeded")?;
                devices.push(device.into());
                let mut cursor = s;
                for _ in 0..8 {
                    let parents = cursor.parents()?;
                    let Some(parent) = parents.get("issuer_device") else {
                        break;
                    };
                    let p = self.catalog.get(parent)?;
                    let k = text(p.subject()?, "device_public_key")?;
                    check(!devices.iter().any(|existing| existing == k))?;
                    require(devices.len() < 8, "quota_exceeded")?;
                    devices.push(k.into());
                    cursor = p;
                }
                pushed = true;
            }
            for (role, parent) in &parents {
                let p = self.catalog.get(parent)?;
                check(
                    p.kind
                        == match role.as_str() {
                            "issuer_person" | "subject_person" => "person_lease",
                            "issuer_admin" => "admin_lease",
                            "issuer_device" => "device_lease",
                            "subject_host" => "host_lease",
                            "subject_binding" => "binding_lease",
                            _ => return Err(Error::new("invalid")),
                        },
                )?;

                if let Some(end) = s.payload.get("not_after").and_then(Value::as_str) {
                    check(end <= text(&p.payload, "not_after")?)?;
                }
                if role.starts_with("issuer_") {
                    check(text(p.subject()?, "person_public_key")? == person)?;
                }
                if role == "subject_person" {
                    check(
                        text(p.subject()?, "person_public_key")?
                            == text(s.subject()?, "person_public_key")?,
                    )?;
                }
                if role == "subject_host" {
                    check(
                        text(p.subject()?, "host_public_key")?
                            == text(s.subject()?, "host_public_key")?,
                    )?;
                }
                if role == "subject_binding" {
                    check(
                        text(p.subject()?, "host_public_key")?
                            == text(s.subject()?, "host_public_key")?
                            && text(p.subject()?, "person_public_key")?
                                == text(s.subject()?, "person_public_key")?,
                    )?;
                }
            }
            if ik == "root" {
                check(s.signer("issuer")?.public_key == text(&root.payload, "root_public_key")?)?;
            }
            if ik == "device" {
                let parent = self.catalog.get(
                    parents
                        .get("issuer_device")
                        .ok_or_else(|| Error::new("invalid"))?,
                )?;
                check(
                    s.signer("issuer")?.public_key == text(parent.subject()?, "device_public_key")?,
                )?;
                let required = required_scope(&s.kind);
                let _ = required;
            }
            if matches!(s.kind.as_str(), "binding_lease" | "device_lease") {
                let p = self.catalog.get(&parents["subject_person"])?;
                let h = self.catalog.get(&parents["subject_host"])?;
                check(text(p.subject()?, "member")? == text(h.subject()?, "member")?)?;
            }
            if restriction(&s.kind) {
                self.restriction_shape(s)?;
            }
            if let Some(stream) = s.stream()? {
                let predecessors = ids(&s.payload, "predecessors", "ds_")?;
                if predecessors.is_empty() {
                    if let Some(floor) = self.floor(&stream) {
                        // An authenticated inherited access floor also applies
                        // to sequence1 and survives ordinary root transitions.
                        require(s.sequence()? > floor, "state_conflict")?;
                    } else {
                        check(s.sequence()? == 1)?;
                    }
                }
                for predecessor in &predecessors {
                    let p = self.catalog.get(predecessor)?;
                    check(p.stream()?.as_ref() == Some(&stream) && s.sequence()? > p.sequence()?)?;
                }
                let resolves = ids(&s.payload, "resolves", "ds_")?;
                if predecessors.len() > 1 {
                    // A multi-head successor is an explicit resolver, even
                    // when imported rather than prepared by this host.
                    check(
                        predecessors
                            .iter()
                            .all(|id| resolves.binary_search(id).is_ok()),
                    )?;
                }
                for resolved in resolves {
                    if !predecessors.contains(&resolved) {
                        let r = self.catalog.get(&resolved)?;
                        check(matches!(
                            (s.kind.as_str(), r.kind.as_str()),
                            ("admin_lease", "admin_withdraw") | ("binding_lease", "host_unbind")
                        ))?;
                    }
                }
            }
            if pushed {
                devices.clear();
            }
            Ok(())
        })();
        path.remove(id);
        result
    }
    fn restriction_shape(&self, s: &Statement) -> Result<()> {
        let target = object(
            s.payload
                .get("target")
                .ok_or_else(|| Error::new("invalid"))?,
        )?;
        let referenced = text(target, "statement_id")?;
        if referenced != "-" {
            let old = self.catalog.get(referenced)?;
            check(
                old.kind
                    == if s.kind == "admin_withdraw" {
                        "admin_lease"
                    } else {
                        "binding_lease"
                    },
            )?;
            check(
                text(old.subject()?, "person_public_key")? == text(target, "person_public_key")?,
            )?;
            if s.kind == "host_unbind" {
                check(
                    text(old.subject()?, "host_public_key")? == text(target, "host_public_key")?,
                )?;
            }
        }
        for kept in ids(&s.payload, "kept_statement_ids", "ds_")? {
            let grant = self.catalog.get(&kept)?;
            check(
                matches!(grant.kind.as_str(), "person_lease" | "host_lease")
                    && grant.parents()?.get("issuer_admin").map(String::as_str) == Some(referenced),
            )?;
        }
        let ratifies = text(&s.payload, "ratifies")?;
        if ratifies != "-" {
            let original = self.catalog.get(ratifies)?;
            check(
                original.kind == s.kind
                    && original.payload.get("target") == s.payload.get("target")
                    && original.payload.get("kept_statement_ids")
                        == s.payload.get("kept_statement_ids"),
            )?;
        }
        Ok(())
    }
    fn floor(&self, key: &Vec<String>) -> Option<u64> {
        self.prior
            .as_ref()
            .filter(|p| p.migration_proposal_id != "-")
            .and_then(|p| p.maxima.get(key))
            .filter(|m| m.statement_ids.is_empty())
            .map(|m| m.sequence)
            .or_else(|| self.staged_floors.get(key).copied())
    }
    fn admit_roots(&mut self) -> Result<()> {
        let roots: Vec<_> = self
            .catalog
            .statements
            .values()
            .filter(|s| s.kind == "root_state")
            .collect();
        for _ in 0..=roots.len() {
            let mut progress = false;
            for s in &roots {
                if self.admitted.contains(&s.id) {
                    continue;
                }
                if stamp(s.issued_at()?)? <= stamp(&self.decision_time)?
                    && ids(&s.payload, "predecessors", "ds_")?
                        .iter()
                        .all(|id| self.admitted.contains(id))
                {
                    self.admitted.insert(s.id.clone());
                    progress = true;
                }
            }
            if !progress {
                break;
            }
        }
        Ok(())
    }
    fn rebuild_streams(&mut self) -> Result<()> {
        let mut streams = BTreeMap::<Vec<String>, Stream>::new();
        if let Some(p) = &self.prior {
            for m in p.maxima.values() {
                streams.insert(
                    m.stream.clone(),
                    Stream {
                        key: m.stream.clone(),
                        heads: m.head_ids.clone(),
                        maximum: m.sequence,
                        at_maximum: m.statement_ids.clone(),
                    },
                );
            }
        }
        for (key, maximum) in &self.staged_floors {
            streams.entry(key.clone()).or_insert(Stream {
                key: key.clone(),
                heads: BTreeSet::new(),
                maximum: *maximum,
                at_maximum: BTreeSet::new(),
            });
        }
        for id in &self.admitted {
            if let Some(s) = self.catalog.statements.get(id)
                && let Some(key) = s.stream()?
            {
                let seq = s.sequence()?;
                let stream = streams.entry(key.clone()).or_insert(Stream {
                    key,
                    heads: BTreeSet::new(),
                    maximum: seq,
                    at_maximum: BTreeSet::new(),
                });
                // Prior head metadata is independent durable knowledge. Its
                // non-head bodies cannot reappear as branches merely because
                // the remembered higher head currently lacks its exact bytes.
                if !self.prior.as_ref().is_some_and(|p| p.admitted.contains(id)) {
                    stream.heads.insert(id.clone());
                }
                if seq > stream.maximum {
                    stream.maximum = seq;
                    stream.at_maximum.clear();
                }
                if seq == stream.maximum {
                    stream.at_maximum.insert(id.clone());
                }
            }
        }
        for stream in streams.values_mut() {
            let mut pending = Vec::new();
            let mut visited = BTreeSet::new();
            for id in &stream.heads {
                if let Some(s) = self.catalog.statements.get(id) {
                    pending.extend(ids(&s.payload, "predecessors", "ds_")?);
                }
            }
            while let Some(id) = pending.pop() {
                if !visited.insert(id.clone()) {
                    continue;
                }
                stream.heads.remove(&id);
                if let Some(s) = self.catalog.statements.get(&id) {
                    pending.extend(ids(&s.payload, "predecessors", "ds_")?);
                }
            }
        }
        self.streams = streams;
        Ok(())
    }
    fn descends(&self, new: &str, old: &str, _path: &mut BTreeSet<String>) -> Result<bool> {
        let mut seen = BTreeSet::new();
        let mut pending = vec![new.to_owned()];
        while let Some(id) = pending.pop() {
            if id == old {
                return Ok(true);
            }
            if !seen.insert(id.clone()) {
                continue;
            }
            if let Some(s) = self.catalog.statements.get(&id)
                && s.payload.contains_key("predecessors")
            {
                pending.extend(ids(&s.payload, "predecessors", "ds_")?);
            }
        }
        Ok(false)
    }
    pub(crate) fn head(&self, key: &[String]) -> Result<&Statement> {
        require(key != ["root"] || !self.origin_conflicted, "state_conflict")?;
        let stream = self
            .streams
            .get(key)
            .ok_or_else(|| Error::new("proof_required"))?;
        require(stream.heads.len() <= 1, "state_conflict")?;
        let id = stream
            .heads
            .first()
            .ok_or_else(|| Error::new("proof_required"))?;
        self.proof_complete(id)?;
        self.catalog.get(id)
    }
    fn admission(&self, id: &str) -> Result<()> {
        let s = self.catalog.get(id)?;
        if self
            .prior
            .as_ref()
            .is_some_and(|p| p.admitted.contains(id) || p.restrictions.contains(id))
        {
            return Ok(());
        }
        // Durable admission preserves history. A first observation must itself
        // be live now; repair and complete consent cannot manufacture a past
        // admission or advance a head with an expired grant.
        self.time(s)?;
        if s.kind == "device_lease" && text(&s.payload, "operation_id")? == "-" {
            require(self.creator_device(s)?, "forbidden")?;
        }
        if lease(&s.kind) && text(&s.payload, "operation_id")? != "-" {
            let op = text(&s.payload, "operation_id")?;
            if s.kind == "host_lease"
                && (self
                    .staged_origin
                    .as_ref()
                    .is_some_and(|(proposal, _)| proposal == op)
                    || self
                        .catalog
                        .migrations
                        .values()
                        .any(|m| m.proposal.id == op && m.prepared.statements.contains_key(id)))
            {
                self.root_coverage(s)?;
                self.known_restrictions(s)?;
                return Ok(());
            }
            let activation = self.activated.get(op).ok_or_else(|| Error::missing(op))?;
            require(
                [
                    "person_lease_id",
                    "host_lease_id",
                    "binding_lease_id",
                    "device_lease_id",
                ]
                .iter()
                .any(|name| activation.manifest.get(*name).and_then(Value::as_str) == Some(id)),
                "forbidden",
            )?;
        }
        if matches!(s.kind.as_str(), "binding_lease" | "device_lease") {
            let operation = text(&s.payload, "operation_id")?;
            if let Some(activation) = self.activated.get(operation)
                && (s.kind != "device_lease" || !self.portable_issuance(s)?)
            {
                self.activation_stage_authority(activation, s)?;
            }
        }
        if restriction(&s.kind)
            && self
                .catalog
                .migrations
                .values()
                .any(|m| m.prepared.statements.contains_key(id))
        {
            // Exact carried stable-key restrictions are authenticated by the
            // complete source/root/all-host transition, not a current signer.
            return Ok(());
        }
        self.root_coverage(s)?;
        let issuer = s.issuer()?;
        if text(issuer, "kind")? != "root" {
            for (role, parent) in s.parents()? {
                if role.starts_with("issuer_") {
                    require(self.issuer_available(s, &parent)?, "forbidden")?;
                    self.use_parent(s, &role, &parent, &mut BTreeSet::new(), true)?;
                }
            }
        }
        if matches!(s.kind.as_str(), "binding_lease" | "device_lease") {
            for (role, parent) in s.parents()? {
                if role.starts_with("subject_") {
                    self.use_parent(s, &role, &parent, &mut BTreeSet::new(), true)?;
                }
            }
        }
        self.known_restrictions(s)?;
        if s.kind == "device_lease" && text(s.issuer()?, "kind")? == "device" {
            let parent_id = &s.parents()?["issuer_device"];
            let parent = self.catalog.get(parent_id)?;
            require(
                num(s.subject()?, "scopes")? & !num(parent.subject()?, "scopes")? == 0,
                "forbidden",
            )?;
            let issuer_power =
                self.use_parent(s, "issuer_device", parent_id, &mut BTreeSet::new(), true)?;
            require(
                num(s.subject()?, "scopes")? & !issuer_power.scopes == 0
                    || self.portable_issuance(s)?,
                "forbidden",
            )?;
        }
        if s.kind == "device_revoke" {
            self.strict_revoke(s)?;
        }
        Ok(())
    }
    /// A cold child may already have been issued before an independently
    /// authorized replacement explicitly retained it. Such evidence preserves
    /// the old nominal signature, while current use still intersects every
    /// retaining path. Merely appearing in a complete ceremony is insufficient.
    /// A device grant with `operation_id` `-` is valid only as the creator
    /// device grant (DEC-Q21): issued by the original key at genesis, with
    /// the genesis person, host and binding grants as its parents.
    fn creator_device(&self, s: &Statement) -> Result<bool> {
        let root = self.catalog.get(text(&s.payload, "root_state_id")?)?;
        if root.kind != "root_state"
            || root.sequence()? != 0
            || !ids(&root.payload, "predecessors", "ds_")?.is_empty()
        {
            return Ok(false);
        }
        let mut genesis = BTreeMap::new();
        for id in s.parents()?.into_values() {
            let parent = self.catalog.get(&id)?;
            if text(&parent.payload, "operation_id")? != "-"
                || parent.sequence()? != 1
                || text(&parent.payload, "root_state_id")? != root.id
                || parent.issued_at()? != root.issued_at()?
            {
                return Ok(false);
            }
            genesis.insert(parent.kind.as_str(), parent);
        }
        let (Some(person), Some(host), Some(binding)) = (
            genesis.get("person_lease"),
            genesis.get("host_lease"),
            genesis.get("binding_lease"),
        ) else {
            return Ok(false);
        };
        Ok(s.issued_at()? == root.issued_at()?
            && text(person.issuer()?, "kind")? == "root"
            && text(host.issuer()?, "kind")? == "root"
            && Self::creator_device_shape(
                s,
                &BTreeMap::from([
                    ("person_lease", *person),
                    ("host_lease", *host),
                    ("binding_lease", *binding),
                ]),
                text(s.subject()?, "person_public_key")?,
                text(s.subject()?, "host_public_key")?,
            ))
    }
    fn portable_issuance(&self, child: &Statement) -> Result<bool> {
        // A later root endorsement cannot retroactively supply a child missing
        // from an earlier narrowing ancestor's exact signed kept set.
        if self.current_carries_child(child).is_err() {
            return Ok(false);
        }
        for stream in self.streams.values() {
            if stream.heads.len() != 1 {
                continue;
            }
            let head = self
                .catalog
                .get(stream.heads.first().ok_or_else(|| Error::new("invalid"))?)?;
            if !self.admitted.contains(&head.id)
                || !head.payload.contains_key("retained_statement_ids")
            {
                continue;
            }
            if !ids(&head.payload, "retained_statement_ids", "ds_")?.contains(&child.id) {
                continue;
            }
            for predecessor in ids(&head.payload, "predecessors", "ds_")? {
                if self.related_contribution(child, &predecessor, &mut BTreeSet::new())?
                    && self
                        .cover(&head.id, &predecessor, &child.id, &mut BTreeSet::new())
                        .is_ok()
                    && self
                        .original_issuance_at(child, head.issued_at()?, &mut BTreeSet::new())
                        .is_ok()
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
    fn current_carries_child(&self, child: &Statement) -> Result<()> {
        let root = self.head(&["root".into()])?;
        self.cover(
            &root.id,
            text(&child.payload, "root_state_id")?,
            &child.id,
            &mut BTreeSet::new(),
        )?;
        let mut seen = BTreeSet::new();
        for parent in child.parents()?.into_values() {
            self.current_carries_parent(self.catalog.get(&parent)?, child, false, &mut seen)?;
        }
        Ok(())
    }
    fn current_carries_parent(
        &self,
        parent: &Statement,
        child: &Statement,
        kept_admin: bool,
        seen: &mut BTreeSet<String>,
    ) -> Result<()> {
        if !seen.insert(parent.id.clone()) {
            return Ok(());
        }
        let head = if kept_admin {
            parent
        } else {
            self.head(&parent.stream()?.ok_or_else(|| Error::new("invalid"))?)?
        };
        self.cover(&head.id, &parent.id, &child.id, &mut BTreeSet::new())?;
        let root = self.head(&["root".into()])?;
        self.cover(
            &root.id,
            text(&parent.payload, "root_state_id")?,
            &child.id,
            &mut BTreeSet::new(),
        )?;
        for (role, id) in parent.parents()? {
            self.current_carries_parent(
                self.catalog.get(&id)?,
                child,
                role == "issuer_admin" && self.kept_admission(parent)?,
                seen,
            )?;
        }
        Ok(())
    }
    /// Verify original finite issuance at the exact signed carrying transition.
    /// This follows typed parents and actual packet issuers, never retention
    /// references, and grants none of those old issuers current signing power.
    fn original_issuance_at(
        &self,
        statement: &Statement,
        at: &str,
        seen: &mut BTreeSet<String>,
    ) -> Result<()> {
        if !seen.insert(statement.id.clone()) {
            return Ok(());
        }
        let time = stamp(at)?;
        require(stamp(statement.issued_at()?)? <= time, "forbidden")?;
        if let Some(start) = statement.payload.get("not_before").and_then(Value::as_str) {
            require(stamp(start)? <= time, "forbidden")?;
        }
        if let Some(end) = statement.payload.get("not_after").and_then(Value::as_str) {
            require(time < stamp(end)?, "forbidden")?;
        }
        for (role, id) in statement.parents()? {
            let parent = self.catalog.get(&id)?;
            if role == "issuer_device" {
                require(
                    num(parent.subject()?, "scopes")? & required_scope(&statement.kind)
                        == required_scope(&statement.kind),
                    "forbidden",
                )?;
                if statement.kind == "device_lease" {
                    require(
                        num(statement.subject()?, "scopes")? & !num(parent.subject()?, "scopes")?
                            == 0,
                        "forbidden",
                    )?;
                }
            }
            self.original_issuance_at(parent, at, seen)?;
        }
        if statement.kind == "device_lease"
            && !(text(&statement.payload, "operation_id")? == "-"
                && self.creator_device(statement)?)
        {
            let operation = text(&statement.payload, "operation_id")?;
            let activation = self
                .complete_operations
                .get(operation)
                .ok_or_else(|| Error::missing(operation))?;
            require(
                text(&activation.manifest, "device_lease_id")? == statement.id,
                "forbidden",
            )?;
            for (role, required) in [("owner", 4), ("administrator", 8)] {
                let Some(packet) = activation.packets.get(role) else {
                    continue;
                };
                self.packet_provenance(packet)?;
                let issuer = text(&packet.object, "issuer_id")?;
                if issuer != "-" && text(&packet.object, "person_public_key")? != "-" {
                    let device = self.catalog.get(issuer)?;
                    require(
                        num(device.subject()?, "scopes")? & required == required,
                        "forbidden",
                    )?;
                }
                for id in ids(&packet.payload, "issuer_lease_ids", "ds_")? {
                    self.original_issuance_at(self.catalog.get(&id)?, at, seen)?;
                }
            }
        }
        Ok(())
    }
    fn issuer_available(&self, dependent: &Statement, parent: &str) -> Result<bool> {
        if let Some((person, host)) = &self.local_genesis
            && matches!(
                dependent.kind.as_str(),
                "binding_lease" | "policy" | "device_lease"
            )
            && text(dependent.issuer()?, "kind")? == "person"
            && text(dependent.issuer()?, "person_public_key")? == person
            && (dependent.kind != "binding_lease"
                || text(dependent.subject()?, "host_public_key")? == host)
            && self.catalog.get(parent)?.kind == "person_lease"
            && text(self.catalog.get(parent)?.subject()?, "person_public_key")? == person
        {
            return Ok(true);
        }
        if self
            .prior
            .as_ref()
            .is_some_and(|p| p.admitted.contains(parent))
        {
            return Ok(true);
        }
        if self.kept_admission(dependent)? {
            return Ok(true);
        }
        if (self.staged_origin.is_some()
            || self
                .catalog
                .migrations
                .values()
                .any(|m| m.prepared.statements.contains_key(&dependent.id)))
            && (dependent.kind == "policy" || restriction(&dependent.kind))
            && text(dependent.issuer()?, "kind")? == "person"
        {
            return Ok(true);
        }
        if self.ceremony_statements.contains(&dependent.id)
            && self.ceremony_statements.contains(parent)
        {
            return Ok(true);
        }
        // A portable retention signature supplies the explicit previous-state
        // endorsement; merely admitting another grant in this call does not.
        if !self.catalog.statements.contains_key(&dependent.id) {
            return Ok(false);
        }
        for id in &self.admitted {
            let Some(retainer) = self.catalog.statements.get(id) else {
                continue;
            };
            if !retainer.payload.contains_key("retained_statement_ids") {
                continue;
            }
            if ids(&retainer.payload, "retained_statement_ids", "ds_")?.contains(&dependent.id) {
                for predecessor in ids(&retainer.payload, "predecessors", "ds_")? {
                    if self.related_contribution(dependent, &predecessor, &mut BTreeSet::new())? {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }
    /// Authority follows actual typed ancestor contributions. The complete
    /// syntactic proof closure also contains unrelated signed retention lists,
    /// which must never establish an issuer's prior authority.
    fn related_contribution(
        &self,
        child: &Statement,
        predecessor: &str,
        seen: &mut BTreeSet<String>,
    ) -> Result<bool> {
        if !seen.insert(child.id.clone()) {
            return Ok(false);
        }
        let prior = self.catalog.get(predecessor)?;
        if child.stream()? == prior.stream()?
            && self.descends(&prior.id, &child.id, &mut BTreeSet::new())?
        {
            return Ok(true);
        }
        if prior.kind == "root_state"
            && let Some(root) = child.payload.get("root_state_id").and_then(Value::as_str)
            && self.descends(&prior.id, root, &mut BTreeSet::new())?
        {
            return Ok(true);
        }
        for parent in child.parents()?.into_values() {
            if self.related_contribution(self.catalog.get(&parent)?, predecessor, seen)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
    /// Evaluate only preservation of existing finite power under each maximal
    /// root branch. These scratch views never escape or authorize an action.
    fn retention_power(&self, id: &str, times: &[&str]) -> Result<Power> {
        require(!self.origin_conflicted, "state_conflict")?;
        let child = self.catalog.get(id)?;
        check(lease(&child.kind) || matches!(child.kind.as_str(), "policy" | "group"))?;
        let stream = child.stream()?.ok_or_else(|| Error::new("invalid"))?;
        require(self.head(&stream)?.id == id, "forbidden")?;
        let roots = self
            .streams
            .get(&vec!["root".into()])
            .ok_or_else(|| Error::new("proof_required"))?;
        require(!roots.heads.is_empty(), "proof_required")?;
        let mut common: Option<Power> = None;
        let mut administrators = Some(Power::unlimited());
        for time in times {
            for root_id in &roots.heads {
                let root = self.catalog.get(root_id)?;
                let mut branch = self.clone();
                branch.decision_time = (*time).into();
                // Ignore only the root-fork freeze, retaining every other stream,
                // restriction, origin and complete-consent fact unchanged.
                let root_stream = branch
                    .streams
                    .get_mut(&vec!["root".into()])
                    .ok_or_else(|| Error::new("proof_required"))?;
                root_stream.heads = BTreeSet::from([root_id.clone()]);
                root_stream.maximum = root.sequence()?;
                root_stream.at_maximum = root_stream.heads.clone();
                let power = branch.active_inner(id, &mut BTreeSet::new(), true)?;
                if child.kind == "device_lease" && power.scopes & 8 != 0 {
                    let admin_key = vec![
                        "admin".into(),
                        text(child.subject()?, "person_public_key")?.into(),
                    ];
                    let admin = match branch.streams.get(&admin_key) {
                        None => None,
                        Some(stream) if stream.heads.is_empty() => None,
                        Some(_) => match branch.head(&admin_key).and_then(|admin| {
                            branch.active_inner(&admin.id, &mut BTreeSet::new(), true)
                        }) {
                            Ok(admin) => Some(admin),
                            // Missing exact role bytes are unknown eligibility,
                            // unlike a known absent, withdrawn or conflicted role.
                            Err(error) if error.code == "proof_required" => return Err(error),
                            Err(error)
                                if matches!(
                                    error.code,
                                    "forbidden"
                                        | "state_conflict"
                                        | "authority_expired"
                                        | "expired"
                                        | "not_yet_valid"
                                        | "device_revoked"
                                ) =>
                            {
                                None
                            }
                            Err(error) => return Err(error),
                        },
                    };
                    if let Some(admin) = admin {
                        if let Some(needed) = &mut administrators {
                            needed.intersect(&admin);
                        }
                    } else {
                        administrators = None;
                    }
                }
                if let Some(common) = &mut common {
                    common.intersect(&power);
                } else {
                    common = Some(power);
                }
            }
        }
        let mut common = common.ok_or_else(|| Error::new("proof_required"))?;
        if child.kind == "device_lease" && common.scopes & 8 != 0 {
            if let Some(administrators) = administrators {
                // Add conditional role contributions only if the role survives
                // every branch and both fixed/current-time decisions.
                common.intersect(&administrators);
            } else {
                common.scopes &= !8;
            }
        }
        Ok(common)
    }
    fn root_action_retention(&self, intent: &Statement) -> Result<()> {
        let selected: BTreeSet<_> = ids(&intent.payload, "retained_statement_ids", "ds_")?
            .into_iter()
            .collect();
        let predecessors = ids(&intent.payload, "predecessors", "ds_")?;
        let transition = stamp(intent.issued_at()?)?;
        for id in &selected {
            let child = self.catalog.get(id)?;
            check(lease(&child.kind) || matches!(child.kind.as_str(), "policy" | "group"))?;
            require(
                stamp(child.issued_at()?)? <= transition
                    && stamp(text(&child.payload, "not_before")?)? <= transition
                    && transition < stamp(text(&child.payload, "not_after")?)?,
                "forbidden",
            )?;
        }
        let mut covered = BTreeSet::new();
        let mut denied = BTreeMap::new();
        for id in &selected {
            let result: Result<BTreeSet<String>> = (|| {
                let child = self.catalog.get(id)?;
                let mut related = false;
                for predecessor in &predecessors {
                    if self.related_contribution(child, predecessor, &mut BTreeSet::new())? {
                        related = true;
                        break;
                    }
                }
                require(related, "forbidden")?;
                let power = self
                    .retention_power(id, &[intent.issued_at()?, &self.decision_time])
                    .map_err(|error| {
                        if error.code == "not_yet_valid" {
                            Error::new("forbidden")
                        } else {
                            error
                        }
                    })?;
                require(power.proven.is_subset(&selected), "forbidden")?;
                Ok(power.proven)
            })();
            match result {
                Ok(required) => covered.extend(required),
                Err(error) => {
                    denied.insert(id.clone(), error);
                }
            }
        }
        // A withdrawn finite administrator may be needed by an eligible kept
        // P/H consumer without independently regaining administrator power.
        if let Some(id) = selected.difference(&covered).next() {
            return Err(denied.remove(id).unwrap_or_else(|| Error::new("forbidden")));
        }
        Ok(())
    }
    pub fn root_retention_preview(&self) -> Result<Value> {
        require(!self.origin_conflicted, "state_conflict")?;
        let roots = self
            .streams
            .get(&vec!["root".into()])
            .ok_or_else(|| Error::new("proof_required"))?;
        require(!roots.heads.is_empty(), "proof_required")?;
        // Root-head gaps prevent a trustworthy whole preview. Finite gaps are
        // reported individually and never silently classified as ineligible.
        for root in &roots.heads {
            self.dependency_closure(root, &mut BTreeSet::new(), &mut BTreeSet::new())?;
        }
        let heads: BTreeSet<_> = self
            .streams
            .values()
            .filter(|stream| stream.key.first().is_some_and(|kind| kind != "root"))
            .flat_map(|stream| stream.heads.iter().cloned())
            .collect();
        let mut candidates = Vec::new();
        let mut excluded = Vec::new();
        for id in heads {
            let result = self.retention_power(&id, &[&self.decision_time]);
            match result {
                Ok(power) => {
                    let child = self.catalog.get(&id)?;
                    let scopes = match child.kind.as_str() {
                        "device_lease" => power.scopes,
                        "admin_lease" => 8,
                        "binding_lease" => 2,
                        _ => 0,
                    };
                    candidates.push(json!({"statement_id":id,"kind":child.kind,
                        "required_retained_ids":power.proven,"effective_scopes":scopes,
                        "effective_not_after":power.deadline.ok_or_else(||Error::new("invalid"))?}));
                }
                Err(error) => excluded.push(json!({"statement_id":id,"code":error.code,
                    "required_ids":error.required_ids})),
            }
        }
        Ok(json!({"network_id":self.descriptor.network_id,
            "context_id":self.descriptor.context_id(),"decision_time":self.decision_time,
            "root_head_ids":roots.heads,"catalog":parse(&self.catalog.bytes,MAX_CATALOG)?,
            "candidates":candidates,"excluded":excluded}))
    }
    fn action_retention(&self, intent: &Statement) -> Result<()> {
        if intent.kind == "root_state" {
            return self.root_action_retention(intent);
        }
        if !intent.payload.contains_key("retained_statement_ids") {
            return Ok(());
        }
        let predecessors = ids(&intent.payload, "predecessors", "ds_")?;
        for id in ids(&intent.payload, "retained_statement_ids", "ds_")? {
            let child = self.catalog.get(&id)?;
            check(lease(&child.kind) || matches!(child.kind.as_str(), "policy" | "group"))?;
            require(self.admitted.contains(&id), "forbidden")?;
            let mut related = false;
            for predecessor in &predecessors {
                if self.related_contribution(child, predecessor, &mut BTreeSet::new())? {
                    related = true;
                    break;
                }
            }
            check(related)?;
            let transition = stamp(intent.issued_at()?)?;
            require(stamp(child.issued_at()?)? <= transition, "forbidden")?;
            require(
                stamp(text(&child.payload, "not_before")?)? <= transition
                    && transition < stamp(text(&child.payload, "not_after")?)?,
                "forbidden",
            )?;
            self.active(&id)?;
        }
        Ok(())
    }
    fn kept_admission(&self, grant: &Statement) -> Result<bool> {
        if !matches!(grant.kind.as_str(), "person_lease" | "host_lease") {
            return Ok(false);
        }
        let parents = grant.parents()?;
        let Some(admin) = parents.get("issuer_admin") else {
            return Ok(false);
        };
        for id in &self.restrictions {
            self.proof_complete(id)?;
            let restriction = self.catalog.get(id)?;
            if restriction.kind == "admin_withdraw"
                && text(
                    object(value_field(&restriction.payload, "target")?)?,
                    "statement_id",
                )? == admin
                && ids(&restriction.payload, "kept_statement_ids", "ds_")?.contains(&grant.id)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn root_coverage(&self, s: &Statement) -> Result<()> {
        let root = self.head(&["root".into()])?;
        let original = text(&s.payload, "root_state_id")?;
        self.cover(&root.id, original, &s.id, &mut BTreeSet::new())
            .map(|_| ())
    }
    fn cover(
        &self,
        current: &str,
        old: &str,
        dependent: &str,
        path: &mut BTreeSet<String>,
    ) -> Result<Power> {
        self.cover_branches(current, old, dependent, path, &mut BTreeMap::new())
    }
    fn cover_branches(
        &self,
        current: &str,
        old: &str,
        dependent: &str,
        path: &mut BTreeSet<String>,
        checked: &mut BTreeMap<String, Power>,
    ) -> Result<Power> {
        for id in [current, old, dependent] {
            self.proof_complete(id)?;
        }
        if current == old {
            return Ok(Power::unlimited());
        }
        let s = self.catalog.get(current)?;
        check(!path.contains(current))?;
        if let Some(power) = checked.get(current) {
            return Ok(power.clone());
        }
        let current_power = if lease(&s.kind) {
            Some(self.active_inner(current, path, true)?)
        } else {
            None
        };
        check(path.insert(current.into()))?;
        let retained = ids(&s.payload, "retained_statement_ids", "ds_")?;
        require(retained.iter().any(|id| id == dependent), "forbidden")?;
        if s.kind != "root_state" {
            require(retained.iter().any(|id| id == old), "forbidden")?;
        }
        let child = self.catalog.get(dependent)?;
        let retiring = self.catalog.get(old)?;
        for finite in
            std::iter::once(child).chain((retiring.kind != "root_state").then_some(retiring))
        {
            require(
                stamp(finite.issued_at()?)? <= stamp(s.issued_at()?)?,
                "forbidden",
            )?;
            if let Some(start) = finite.payload.get("not_before").and_then(Value::as_str) {
                require(stamp(start)? <= stamp(s.issued_at()?)?, "forbidden")?;
            }
            if let Some(end) = finite.payload.get("not_after").and_then(Value::as_str) {
                require(stamp(end)? > stamp(s.issued_at()?)?, "forbidden")?;
            }
        }
        let mut found: Option<Power> = None;
        for p in ids(&s.payload, "predecessors", "ds_")? {
            if self.descends(&p, old, &mut BTreeSet::new())? {
                // A resolver cannot revive a contribution dropped by any
                // relevant branch. Cache shared ancestors instead of expanding
                // every distinct path through the signed DAG.
                let power = self.cover_branches(&p, old, dependent, path, checked)?;
                if let Some(previous) = &mut found {
                    previous.intersect(&power);
                } else {
                    found = Some(power);
                }
            }
        }
        path.remove(current);
        let mut power = found.ok_or_else(|| Error::new("forbidden"))?;
        if let Some(current_power) = current_power {
            power.intersect(&current_power);
        }
        checked.insert(current.into(), power.clone());
        Ok(power)
    }
    fn time(&self, s: &Statement) -> Result<()> {
        if let Some(start) = s.payload.get("not_before").and_then(Value::as_str) {
            require(
                stamp(start)? <= stamp(&self.decision_time)?,
                "not_yet_valid",
            )?;
        }
        if let Some(end) = s.payload.get("not_after").and_then(Value::as_str) {
            require(
                stamp(&self.decision_time)? < stamp(end)?,
                if matches!(s.kind.as_str(), "policy" | "group") {
                    "expired"
                } else {
                    "authority_expired"
                },
            )?;
        }
        Ok(())
    }
    fn use_parent(
        &self,
        dependent: &Statement,
        role: &str,
        id: &str,
        path: &mut BTreeSet<String>,
        retained: bool,
    ) -> Result<Power> {
        let parent = self.catalog.get(id)?;
        let kept_admin = role == "issuer_admin" && self.kept_admission(dependent)?;
        if !self.admitted.contains(id) {
            // Complete known bytes can prove a denied current path even when
            // that denial kept the parent out of the admitted head set.
            self.time(parent)?;
            self.root_coverage(parent)?;
            self.known_restrictions_mode(parent, kept_admin)?;
        }
        let stream = parent.stream()?.ok_or_else(|| Error::new("invalid"))?;
        let head = if kept_admin && !self.streams.contains_key(&stream) {
            // An exact root kept-list can endorse this finite dependency on a
            // cold receiver without reviving the withdrawn administrator head.
            parent
        } else {
            self.head(&stream)?
        };
        let mut power = if head.id == id {
            Power::unlimited()
        } else if retained {
            self.cover(&head.id, id, &dependent.id, path)?
        } else {
            return Err(Error::new("forbidden"));
        };
        power.intersect(&self.active_inner_mode(id, path, true, kept_admin)?);
        if role == "issuer_device" {
            if dependent.kind == "device_lease"
                && (self.admitted.contains(&dependent.id) || self.portable_issuance(dependent)?)
            {
                // The original issuer needed delegation when this exact child
                // was admitted. A later explicit narrowing may keep its live
                // lower-scope work without granting fresh delegation power.
                // Current first-admission/activation gates still require4.
                require(num(parent.subject()?, "scopes")? & 4 == 4, "forbidden")?;
            } else {
                require(
                    power.scopes & required_scope(&dependent.kind)
                        == required_scope(&dependent.kind),
                    "forbidden",
                )?;
            }
        }
        Ok(power)
    }
    pub fn active(&self, id: &str) -> Result<()> {
        self.active_inner(id, &mut BTreeSet::new(), true)
            .map(|_| ())
    }
    pub(crate) fn current_statement(&self, stream: &[String]) -> Result<(&Statement, String)> {
        let statement = self.head(stream)?;
        let path = self.active_inner(&statement.id, &mut BTreeSet::new(), true)?;
        Ok((
            statement,
            path.deadline.ok_or_else(|| Error::new("invalid"))?,
        ))
    }
    fn active_inner(&self, id: &str, path: &mut BTreeSet<String>, retained: bool) -> Result<Power> {
        self.active_inner_mode(id, path, retained, false)
    }
    fn active_inner_mode(
        &self,
        id: &str,
        path: &mut BTreeSet<String>,
        retained: bool,
        kept_admin: bool,
    ) -> Result<Power> {
        check(path.insert(id.into()))?;
        let result = (|| {
            self.proof_complete(id)?;
            let s = self.catalog.get(id)?;
            require(
                self.admitted.contains(id)
                    || (kept_admin
                        && s.kind == "admin_lease"
                        && text(&s.payload, "operation_id")? == "-"),
                "forbidden",
            )?;
            if s.kind == "root_state" {
                let head = self.head(&["root".into()])?;
                require(head.id == id, "forbidden")?;
                return Ok(Power::unlimited());
            }
            self.time(s)?;
            self.root_coverage(s)?;
            self.known_restrictions_mode(s, kept_admin)?;
            let mut power = Power {
                deadline: Some(text(&s.payload, "not_after")?.into()),
                scopes: if s.kind == "device_lease" {
                    num(s.subject()?, "scopes")?
                } else {
                    15
                },
                proven: BTreeSet::from([id.into()]),
            };
            for (role, parent) in s.parents()? {
                power.intersect(&self.use_parent(s, &role, &parent, path, retained)?);
            }
            Ok(power)
        })();
        path.remove(id);
        result
    }
    fn known_restrictions(&self, s: &Statement) -> Result<()> {
        self.known_restrictions_mode(s, false)
    }
    fn resolves_barrier(&self, statement: &Statement, barrier: &str) -> Result<bool> {
        if ids(&statement.payload, "resolves", "ds_")?
            .iter()
            .any(|id| id == barrier)
        {
            return Ok(true);
        }
        let mut pending = ids(&statement.payload, "predecessors", "ds_")?;
        let mut seen = BTreeSet::new();
        while let Some(id) = pending.pop() {
            if !seen.insert(id.clone()) || !self.admitted.contains(&id) {
                continue;
            }
            let prior = self.catalog.get(&id)?;
            if ids(&prior.payload, "resolves", "ds_")?
                .iter()
                .any(|id| id == barrier)
            {
                return Ok(true);
            }
            pending.extend(ids(&prior.payload, "predecessors", "ds_")?);
        }
        Ok(false)
    }
    fn barrier_applies(&self, statement: &Statement, target: &str) -> Result<bool> {
        if statement.id == target {
            return Ok(true);
        }
        for predecessor in ids(&statement.payload, "predecessors", "ds_")? {
            if self.descends(&predecessor, target, &mut BTreeSet::new())? {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn known_restrictions_mode(&self, s: &Statement, kept_admin: bool) -> Result<()> {
        let parents = s.parents()?;
        for id in &self.restrictions {
            self.proof_complete(id)?;
            let r = self.catalog.get(id)?;
            let target = object(
                r.payload
                    .get("target")
                    .ok_or_else(|| Error::new("invalid"))?,
            )?;
            let subject = s.payload.get("subject").and_then(Value::as_object);
            let person = subject
                .and_then(|o| o.get("person_public_key"))
                .and_then(Value::as_str)
                .unwrap_or_else(|| {
                    s.payload
                        .get("issuer")
                        .and_then(Value::as_object)
                        .and_then(|o| o.get("person_public_key"))
                        .and_then(Value::as_str)
                        .unwrap_or("-")
                });
            let host = subject
                .and_then(|o| o.get("host_public_key"))
                .and_then(Value::as_str)
                .unwrap_or("-");
            let device = subject
                .and_then(|o| o.get("device_public_key"))
                .and_then(Value::as_str)
                .unwrap_or("-");
            match r.kind.as_str() {
                "person_remove" => {
                    require(person != text(target, "person_public_key")?, "forbidden")?
                }
                "host_revoke" => require(host != text(target, "host_public_key")?, "forbidden")?,
                "device_revoke" => require(
                    device != text(target, "device_public_key")?,
                    "device_revoked",
                )?,
                "admin_withdraw" => {
                    if !kept_admin
                        && s.kind == "admin_lease"
                        && self.barrier_applies(s, text(target, "statement_id")?)?
                        && !self.resolves_barrier(s, &r.id)?
                    {
                        return Err(Error::new("forbidden"));
                    }
                    if parents.get("issuer_admin").map(String::as_str)
                        == Some(text(target, "statement_id")?)
                    {
                        require(
                            ids(&r.payload, "kept_statement_ids", "ds_")?.contains(&s.id),
                            "forbidden",
                        )?;
                    }
                }
                "host_unbind"
                    if s.kind == "binding_lease"
                        && self.barrier_applies(s, text(target, "statement_id")?)?
                        && !self.resolves_barrier(s, &r.id)? =>
                {
                    return Err(Error::new("forbidden"));
                }
                _ => {}
            }
        }
        Ok(())
    }
    fn strict_revoke(&self, s: &Statement) -> Result<()> {
        let issuer = s.issuer()?;
        if text(issuer, "kind")? == "person" {
            return Ok(());
        }
        let p = s.parents()?;
        let current = self.catalog.get(&p["issuer_device"])?;
        let target = object(
            s.payload
                .get("target")
                .ok_or_else(|| Error::new("invalid"))?,
        )?;
        let key_ = text(target, "device_public_key")?;
        require(
            text(current.subject()?, "device_public_key")? != key_,
            "authority_would_be_invalidated",
        )?;
        let candidates: Vec<_> = self
            .catalog
            .statements
            .values()
            .filter(|d| {
                d.kind == "device_lease"
                    && d.subject().is_ok_and(|sub| {
                        sub.get("device_public_key").and_then(Value::as_str) == Some(key_)
                    })
            })
            .collect();
        require(!candidates.is_empty(), "proof_required")?;
        for target in candidates {
            let mut cursor = target;
            for _ in 0..8 {
                let parents = cursor.parents()?;
                let Some(parent) = parents.get("issuer_device") else {
                    break;
                };
                if parent == &current.id {
                    return Ok(());
                }
                cursor = self.catalog.get(parent)?;
            }
        }
        Err(Error::new("forbidden"))
    }
    fn stream_value(&self, stream: &Stream, root: bool) -> Result<Value> {
        let origin_conflicted = root && self.origin_conflicted;
        let selected = if stream.heads.len() == 1 && !origin_conflicted {
            stream.heads.first().cloned().unwrap_or_else(|| "-".into())
        } else {
            "-".into()
        };
        let result = if stream.heads.len() > 1 || origin_conflicted {
            Err(Error::new("state_conflict"))
        } else if selected == "-" {
            Err(Error::new("proof_required"))
        } else {
            self.active(&selected)
        };
        let (active, code, required) = match result {
            Ok(()) => (true, "-", BTreeSet::new()),
            Err(e) => (false, e.code, e.required_ids),
        };
        if root {
            Ok(
                json!({"head_ids":stream.heads,"maximum":stream.maximum,"selected_id":selected,"conflicted":stream.heads.len()>1 || origin_conflicted,"code":code,"required_ids":required}),
            )
        } else {
            Ok(
                json!({"stream":stream.key,"head_ids":stream.heads,"maximum":stream.maximum,"selected_id":selected,"active":active,"code":code,"required_ids":required}),
            )
        }
    }
    pub fn response(&self, operation: &str) -> Result<Value> {
        let root = self
            .streams
            .get(&vec!["root".into()])
            .ok_or_else(|| Error::new("proof_required"))?;
        let mut streams = Vec::new();
        for stream in self.streams.values().filter(|s| s.key != ["root"]) {
            streams.push(self.stream_value(stream, false)?);
        }
        let next = if operation == "read" {
            self.prior
                .as_ref()
                .map(|p| p.value.clone())
                .unwrap_or(Value::from("-"))
        } else {
            self.next_prior()
        };
        Ok(
            json!({"ok":true,"context_id":self.descriptor.context_id(),"decision_time":self.decision_time,"root":self.stream_value(root,true)?,"streams":streams,"restrictions":self.restrictions,"inert_statement_ids":self.inert,"next_prior":next}),
        )
    }
    pub fn next_prior(&self) -> Value {
        json!({"format":1,"context_id":self.descriptor.context_id(),"catalog_base64":encode(&self.catalog.bytes),"admitted_statement_ids":self.admitted,"admitted_restriction_ids":self.restrictions,"admitted_activation_ids":self.activated.values().map(|a|a.id.clone()).chain(self.prior.iter().flat_map(|p|p.activations.iter().cloned())).collect::<BTreeSet<_>>(),"root_head_ids":self.streams.get(&vec!["root".into()]).map(|s|s.heads.clone()).unwrap_or_default(),"maxima":self.streams.values().map(|s|json!({"stream":s.key,"sequence":s.maximum,"statement_ids":s.at_maximum,"head_ids":s.heads})).collect::<Vec<_>>(),"migration_proposal_id":self.prior.as_ref().map(|p|p.migration_proposal_id.as_str()).filter(|p|*p!="-").or_else(||self.catalog.migrations.values().find(|m|self.admitted.contains(&m.root_id)).filter(|_|!self.origin_conflicted).map(|m|m.proposal.id.as_str())).unwrap_or("-"),"clock_guard":self.decision_time})
    }
}
pub(crate) fn required_scope(kind: &str) -> u64 {
    match kind {
        "policy" => 1,
        "binding_lease" | "host_unbind" => 2,
        "device_lease" | "device_revoke" => 4,
        "person_lease" | "host_lease" | "group" | "person_remove" | "host_revoke" => 8,
        _ => 0,
    }
}

impl Projection {
    pub fn action(&self, actor: &Obj, kind: &str, payload_bytes: &[u8]) -> Result<Value> {
        fields(
            actor,
            "person_public_key host_public_key device_public_key issuer_id",
        )?;
        check(
            (lease(kind) && kind != "device_lease")
                || restriction(kind)
                || matches!(kind, "policy" | "group" | "root_state"),
        )?;
        let payload = object(&parse(payload_bytes, MAX_PAYLOAD)?)?.clone();
        super::statement::validate_payload(&self.descriptor, kind, &payload)?;
        let id = super::statement::statement_id(kind, &self.descriptor.context_id(), payload_bytes);
        let person = text(actor, "person_public_key")?;
        let device = text(actor, "device_public_key")?;
        let host = text(actor, "host_public_key")?;
        let issuer_id = text(actor, "issuer_id")?;
        check(
            (person == "-" || key(person))
                && (host == "-" || key(host))
                && (device == "-" || key(device)),
        )?;
        let actor_kind = if kind == "root_state" {
            "root"
        } else {
            text(
                object(payload.get("issuer").ok_or_else(|| Error::new("invalid"))?)?,
                "kind",
            )?
        };
        match actor_kind {
            "root" => {
                check(person == "-" && host == "-" && device == "-" && ident(issuer_id, "ds_"))?
            }
            "person" => check(key(person) && host == "-" && device == "-" && issuer_id == "-")?,
            "device" => check(key(person) && key(host) && key(device) && ident(issuer_id, "ds_"))?,
            _ => return Err(Error::new("invalid")),
        }
        let root = if kind == "root_state" {
            require(!self.origin_conflicted, "state_conflict")?;
            let roots = self
                .streams
                .get(&vec!["root".into()])
                .ok_or_else(|| Error::new("proof_required"))?;
            require(roots.heads.contains(issuer_id), "forbidden")?;
            self.proof_complete(issuer_id)?;
            self.catalog.get(issuer_id)?
        } else {
            self.head(&["root".into()])?
        };
        let (signer, format) = if kind == "root_state" {
            require(
                person == "-" && host == "-" && device == "-" && issuer_id == root.id,
                "forbidden",
            )?;
            (
                text(&root.payload, "root_public_key")?.to_owned(),
                "ed25519",
            )
        } else {
            let issuer = object(payload.get("issuer").ok_or_else(|| Error::new("invalid"))?)?;
            match text(issuer, "kind")? {
                "root" => {
                    require(
                        person == "-" && host == "-" && device == "-" && issuer_id == root.id,
                        "forbidden",
                    )?;
                    (
                        text(&root.payload, "root_public_key")?.to_owned(),
                        "ed25519",
                    )
                }
                "person" => {
                    require(
                        person == text(issuer, "person_public_key")?
                            && host == "-"
                            && device == "-"
                            && issuer_id == "-",
                        "forbidden",
                    )?;
                    (person.into(), "sshsig")
                }
                "device" => {
                    require(
                        person == text(issuer, "person_public_key")? && ident(issuer_id, "ds_"),
                        "forbidden",
                    )?;
                    let issuer = self.catalog.get(issuer_id)?;
                    require(
                        issuer.kind == "device_lease"
                            && text(issuer.subject()?, "device_public_key")? == device
                            && text(issuer.subject()?, "person_public_key")? == person
                            && text(issuer.subject()?, "host_public_key")? == host,
                        "forbidden",
                    )?;
                    self.active(issuer_id)?;
                    (device.into(), "ed25519")
                }
                _ => return Err(Error::new("invalid")),
            }
        };
        let mut signatures = BTreeMap::new();
        signatures.insert(
            "issuer".into(),
            super::statement::SignatureEntry {
                role: "issuer".into(),
                public_key: signer.clone(),
                format: format.into(),
                signature: "-".into(),
            },
        );
        let intent = Statement {
            kind: kind.into(),
            context_id: self.descriptor.context_id(),
            id,
            payload_bytes: payload_bytes.into(),
            payload,
            proof_id: "-".into(),
            body: Vec::new(),
            signatures,
        };
        // A new writer fixes issued_at to its guarded NOW. A fixed external
        // signing template can be rechecked seconds later without rewriting
        // that timestamp; its original honest-signing window stays finite.
        let age = stamp(&self.decision_time)? - stamp(intent.issued_at()?)?;
        check(age >= chrono::TimeDelta::zero())?;
        require(age <= chrono::TimeDelta::seconds(300), "expired")?;
        self.time(&intent)?;
        if kind == "root_state" {
            let old = self
                .streams
                .get(&vec!["root".into()])
                .ok_or_else(|| Error::new("proof_required"))?;
            let predecessors = ids(&intent.payload, "predecessors", "ds_")?;
            require(
                predecessors.iter().cloned().collect::<BTreeSet<_>>() == old.heads,
                "state_conflict",
            )?;
            for predecessor in &predecessors {
                self.proof_complete(predecessor)?;
            }
            check(old.maximum.checked_add(1) == Some(intent.sequence()?))?;
            if old.heads.len() > 1 {
                check(
                    ids(&intent.payload, "resolves", "ds_")?
                        .into_iter()
                        .collect::<BTreeSet<_>>()
                        == old.heads,
                )?;
            }
            self.action_retention(&intent)?;
            return Ok(
                json!({"ok":true,"context_id":self.descriptor.context_id(),"decision_time":self.decision_time,"issuer_id":issuer_id,"signer_public_key":signer,"required_parent_ids":predecessors,"effective_not_after":"-"}),
            );
        }
        require(
            text(&intent.payload, "root_state_id")? == root.id,
            "forbidden",
        )?;
        let mut structural = self.clone();
        structural
            .catalog
            .statements
            .insert(intent.id.clone(), intent.clone());
        structural.provenance(&intent.id, &mut BTreeSet::new(), &mut Vec::new())?;
        let mut power = Power::unlimited();
        for (role, parent) in intent.parents()? {
            let p = self.catalog.get(&parent)?;
            if !self.admitted.contains(&parent) {
                // Complete bytes may prove that this exact requested parent
                // is ineligible. Preserve that denial before a missing
                // admitted head can obscure it as proof_required[].
                self.time(p)?;
                self.root_coverage(p)?;
                self.known_restrictions(p)?;
            }
            let head = self.head(&p.stream()?.ok_or_else(|| Error::new("invalid"))?)?;
            require(head.id == parent, "forbidden")?;
            let parent_power = self.active_inner(&parent, &mut BTreeSet::new(), true)?;
            if role == "issuer_device" {
                require(
                    parent == issuer_id
                        && parent_power.scopes & required_scope(kind) == required_scope(kind),
                    "forbidden",
                )?;
            }
            if role.starts_with("issuer_") {
                require(self.issuer_available(&intent, &parent)?, "forbidden")?;
                check(text(p.subject()?, "person_public_key")? == person)?;
            }
            power.intersect(&parent_power);
        }
        if let Some(end) = intent.payload.get("not_after").and_then(Value::as_str) {
            if let Some(ceiling) = &power.deadline {
                require(end <= ceiling.as_str(), "forbidden")?;
            }
            power.deadline = Some(end.into());
        }
        self.local_generation(&intent)?;
        self.action_retention(&intent)?;
        if kind == "device_lease" {
            return Err(Error::new("forbidden"));
        }
        if restriction(kind) {
            self.restriction_shape(&intent)?;
            let target = object(
                intent
                    .payload
                    .get("target")
                    .ok_or_else(|| Error::new("invalid"))?,
            )?;
            let invalidates = match kind {
                "person_remove" => person != "-" && person == text(target, "person_public_key")?,
                "host_revoke" => host != "-" && host == text(target, "host_public_key")?,
                "host_unbind" => host != "-" && host == text(target, "host_public_key")?,
                "device_revoke" => device != "-" && device == text(target, "device_public_key")?,
                "admin_withdraw" => {
                    intent.parents()?.get("issuer_admin").map(String::as_str)
                        == Some(text(target, "statement_id")?)
                }
                _ => false,
            };
            require(!invalidates, "authority_would_be_invalidated")?;
            if kind == "device_revoke" {
                self.strict_revoke(&intent)?;
            }
        }
        self.known_restrictions(&intent)?;
        if person != "-" && host != "-" && kind != "binding_lease" {
            let binding = self.head(&["binding".into(), host.into()])?;
            require(
                text(binding.subject()?, "person_public_key")? == person,
                "forbidden",
            )?;
            self.active(&binding.id)?;
        }
        let mut required: BTreeSet<_> = intent.parents()?.into_values().collect();
        required.insert(root.id.clone());
        Ok(
            json!({"ok":true,"context_id":self.descriptor.context_id(),"decision_time":self.decision_time,"issuer_id":issuer_id,"signer_public_key":signer,"required_parent_ids":required,"effective_not_after":power.deadline.unwrap_or_else(||"-".into())}),
        )
    }
    fn local_generation(&self, s: &Statement) -> Result<()> {
        let Some(key) = s.stream()? else {
            return Ok(());
        };
        let predecessors = ids(&s.payload, "predecessors", "ds_")?;
        let actual = predecessors.iter().cloned().collect::<BTreeSet<_>>();
        if let Some(stream) = self.streams.get(&key) {
            require(actual == stream.heads, "state_conflict")?;
            for head in &stream.heads {
                self.proof_complete(head)?;
            }
            require(s.sequence()? > stream.maximum, "invalid")?;
            if stream.heads.len() > 1 {
                let resolves = ids(&s.payload, "resolves", "ds_")?
                    .into_iter()
                    .collect::<BTreeSet<_>>();
                require(stream.heads.is_subset(&resolves), "state_conflict")?;
            }
        } else {
            check(predecessors.is_empty() && s.sequence()? == 1)?;
        }
        Ok(())
    }
}

impl Projection {
    fn verify_operations(&mut self, admit_consent: bool) -> Result<()> {
        // Validate every original composite alias, not only its semantic map
        // representative. None of these checks confers grant admission.
        for (proof, _) in self.catalog.activation_proofs() {
            let activation = Activation::read(&self.descriptor, &proof.body)?;
            self.activation_provenance(&activation)?;
        }
        let mut dependencies = BTreeMap::<String, BTreeSet<String>>::new();
        let mut scopes = BTreeMap::<String, BTreeSet<String>>::new();
        for (request, activation) in &self.complete_operations {
            let mut scope = BTreeSet::new();
            for name in [
                "person_lease_id",
                "host_lease_id",
                "binding_lease_id",
                "device_lease_id",
            ] {
                let id = text(&activation.manifest, name)?;
                scope.insert(id.into());
                self.ceremony_ancestry(id, &mut scope)?;
            }
            let renewed = text(
                &activation.packets["request"].payload,
                "renewed_device_lease_id",
            )?;
            if renewed != "-" {
                scope.insert(renewed.into());
                self.ceremony_ancestry(renewed, &mut scope)?;
            }
            // Packet authority references are exact reviewed ancestors. They
            // cannot extend the exception to an unrelated ordinary grant.
            for packet in activation.packets.values() {
                for name in ["issuer_lease_ids"] {
                    if packet.payload.contains_key(name) {
                        for id in ids(&packet.payload, name, "ds_")? {
                            scope.insert(id.clone());
                            self.ceremony_ancestry(&id, &mut scope)?;
                        }
                    }
                }
                let issuer = text(&packet.object, "issuer_id")?;
                if issuer != "-" {
                    scope.insert(issuer.into());
                    self.ceremony_ancestry(issuer, &mut scope)?;
                }
            }
            let mut ancestors = BTreeSet::new();
            for id in &scope {
                let statement = self.catalog.get(id)?;
                if lease(&statement.kind) {
                    let operation = text(&statement.payload, "operation_id")?;
                    if ident(operation, "link_") {
                        let source = self
                            .complete_operations
                            .get(operation)
                            .ok_or_else(|| Error::missing(operation))?;
                        require(
                            [
                                "person_lease_id",
                                "host_lease_id",
                                "binding_lease_id",
                                "device_lease_id",
                            ]
                            .iter()
                            .any(|name| {
                                source.manifest.get(*name).and_then(Value::as_str) == Some(id)
                            }),
                            "invalid",
                        )?;
                        if operation != request {
                            ancestors.insert(operation.into());
                        }
                    }
                }
            }
            dependencies.insert(request.clone(), ancestors);
            scopes.insert(request.clone(), scope);
        }
        let mut pending: BTreeSet<_> = dependencies.keys().cloned().collect();
        let mut completed = BTreeSet::new();
        while !pending.is_empty() {
            let ready: Vec<_> = pending
                .iter()
                .filter(|id| dependencies[*id].iter().all(|p| completed.contains(p)))
                .cloned()
                .collect();
            check(!ready.is_empty())?;
            for id in ready {
                let activation = &self.complete_operations[&id];
                if admit_consent
                    || self
                        .prior
                        .as_ref()
                        .is_some_and(|p| p.activations.contains(&activation.id))
                {
                    self.ceremony_statements
                        .extend(scopes.remove(&id).ok_or_else(|| Error::new("invalid"))?);
                    self.activated.insert(id.clone(), activation.clone());
                }
                completed.insert(id.clone());
                pending.remove(&id);
            }
        }
        Ok(())
    }
    fn activation_provenance(&self, a: &Activation) -> Result<()> {
        let request = &a.packets["request"];
        let owner = &a.packets["owner"];
        let finalization = &a.packets["owner_finalization"];
        let commit = &a.packets["commit"];
        let person = text(&owner.object, "person_public_key")?;
        let host = text(&request.payload, "host_public_key")?;
        let device = text(&request.payload, "device_public_key")?;
        let manifest_proofs = ids(&a.manifest, "proof_ids", "dp_")?;
        for (proof, outer) in self.catalog.activation_proofs() {
            if let Ok(containing) = Activation::read(&self.descriptor, &proof.body)
                && containing.id == a.id
            {
                check(!manifest_proofs.contains(&proof.id))?;
                if let Some(outer) = outer {
                    check(!manifest_proofs.iter().any(|id| id == outer))?;
                }
            }
        }
        for id in &manifest_proofs {
            self.catalog.proof(id)?;
        }
        let person_id = text(&a.manifest, "person_lease_id")?;
        let host_id = text(&a.manifest, "host_lease_id")?;
        let binding_id = text(&a.manifest, "binding_lease_id")?;
        let device_id = text(&a.manifest, "device_lease_id")?;
        let p = self.catalog.get(person_id)?;
        let h = self.catalog.get(host_id)?;
        let b = self.catalog.get(binding_id)?;
        let d = self.catalog.get(device_id)?;
        check(
            p.kind == "person_lease"
                && h.kind == "host_lease"
                && b.kind == "binding_lease"
                && d.kind == "device_lease",
        )?;
        check(
            text(p.subject()?, "person_public_key")? == person
                && text(h.subject()?, "host_public_key")? == host
                && text(p.subject()?, "member")? == text(&owner.payload, "member")?
                && text(h.subject()?, "member")? == text(&owner.payload, "member")?,
        )?;
        check(
            text(b.subject()?, "person_public_key")? == person
                && text(b.subject()?, "host_public_key")? == host
                && text(d.subject()?, "person_public_key")? == person
                && text(d.subject()?, "host_public_key")? == host
                && text(d.subject()?, "device_public_key")? == device,
        )?;
        let binding_proof = text(&a.manifest, "binding_proof_id")?;
        let device_proof = text(&a.manifest, "device_proof_id")?;
        for (id, s) in [(binding_proof, b), (device_proof, d)] {
            let proof = self.catalog.proof(id)?;
            check(
                proof.kind == s.kind && super::statement::proof_id(&proof.kind, &proof.body) == id,
            )?;
            let parsed = Statement::read(&self.descriptor, &proof.body)?;
            check(parsed.id == s.id)?;
            check(manifest_proofs.iter().any(|p| p == id))?;
        }
        // Signature aliases share a semantic payload, but the manifest selects
        // one complete original envelope. Consent compares only that body.
        let pinned_binding =
            Statement::read(&self.descriptor, &self.catalog.proof(binding_proof)?.body)?;
        let b = &pinned_binding;
        let final_device = super::catalog::raw_field(&finalization.payload_bytes, "device_lease")?;
        check(self.catalog.proof(device_proof)?.body == final_device)?;
        if finalization.payload["binding_lease"].is_object() {
            let draft = Statement::read_draft(
                &self.descriptor,
                &super::catalog::raw_field(&finalization.payload_bytes, "binding_lease")?,
                true,
            )?;
            check(
                draft.payload_bytes == b.payload_bytes
                    && draft.signer("issuer")?.signature == b.signer("issuer")?.signature
                    && draft.signer("issuer")?.public_key == b.signer("issuer")?.public_key
                    && draft.signer("issuer")?.format == b.signer("issuer")?.format,
            )?;
            check(b.signer("host")?.signature == text(&commit.payload, "binding_host_signature")?)?;
        }
        let mut closure = BTreeSet::new();
        for selected in [person_id, host_id, binding_id, device_id] {
            self.dependency_closure(selected, &mut closure, &mut BTreeSet::new())?;
        }
        check(
            closure
                == ids(&a.manifest, "ancestor_statement_ids", "ds_")?
                    .into_iter()
                    .collect(),
        )?;
        for id in &closure {
            require(
                manifest_proofs
                    .iter()
                    .any(|proof| self.catalog.has_statement_source(id, proof)),
                "proof_required",
            )?;
        }
        if !a.packets.contains_key("administrator") {
            // Reuse independently authorized current P/H, including portable
            // earlier completed operations. Only a folded admin stage (spec
            // 8.2) mints the host grant, through the owner's admin path.
            check(text(&p.payload, "operation_id")? != a.request_id)?;
            if text(&h.payload, "operation_id")? == a.request_id {
                check(
                    text(&request.payload, "mode")? != "renew"
                        && text(&owner.payload, "person_lease_id")? != "-",
                )?;
                self.grant_packet_issuer(h, finalization)?;
                let issuers: BTreeMap<String, String> = h
                    .parents()?
                    .into_iter()
                    .filter(|(role, _)| role.starts_with("issuer_"))
                    .collect();
                let admin = issuers
                    .get("issuer_admin")
                    .ok_or_else(|| Error::new("invalid"))?;
                check(self.catalog.get(admin)?.kind == "admin_lease")?;
                let mut expected: BTreeSet<String> =
                    ids(&owner.payload, "issuer_lease_ids", "ds_")?
                        .into_iter()
                        .collect();
                expected.insert(admin.clone());
                check(issuers.into_values().collect::<BTreeSet<_>>() == expected)?;
            } else {
                check(text(&request.payload, "mode")? == "renew")?;
            }
        }
        let renewed = text(&request.payload, "renewed_device_lease_id")?;
        if text(&request.payload, "mode")? == "renew" {
            let old = self.catalog.get(renewed)?;
            check(
                old.kind == "device_lease"
                    && text(old.subject()?, "person_public_key")? == person
                    && text(old.subject()?, "host_public_key")? == host
                    && text(old.subject()?, "device_public_key")? == device,
            )?;
            require(
                num(d.subject()?, "scopes")? & !num(old.subject()?, "scopes")? == 0,
                "forbidden",
            )?;
        }
        for packet in [owner, finalization] {
            self.packet_provenance(packet)?;
        }
        if let Some(admin) = a.packets.get("administrator") {
            self.packet_provenance(admin)?;
            for grant in [p, h] {
                if text(&grant.payload, "operation_id")? == a.request_id {
                    self.grant_packet_issuer(grant, admin)?;
                    let issuer_parents: Vec<_> = grant
                        .parents()?
                        .into_iter()
                        .filter(|(role, _)| role.starts_with("issuer_"))
                        .map(|(_, id)| id)
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect();
                    check(issuer_parents == ids(&admin.payload, "issuer_lease_ids", "ds_")?)?;
                }
            }
        }
        let new_person = text(&owner.payload, "person_lease_id")? == "-";
        if new_person {
            let shared_migration_person = text(&p.payload, "operation_id")? == "-"
                && (self.staged_origin.as_ref().is_some_and(|(proposal, root)| {
                    text(&request.payload, "migration_proposal_id").is_ok_and(|id| id == proposal)
                        && text(&p.payload, "root_state_id").is_ok_and(|id| id == root)
                }) || self.catalog.migrations.values().any(|m| {
                    m.prepared.statements.contains_key(&p.id)
                        && text(&request.payload, "migration_proposal_id")
                            .is_ok_and(|id| id == m.proposal.id)
                }));
            check(
                text(&owner.object, "issuer_id")? == "-"
                    && text(&owner.object, "signer_public_key")? == person
                    && (text(&p.payload, "operation_id")? == a.request_id
                        || shared_migration_person),
            )?;
        }
        self.grant_packet_issuer(d, finalization)?;
        if finalization.payload["binding_lease"].is_object() {
            self.grant_packet_issuer(b, finalization)?;
            check(
                b.parents()?
                    .into_iter()
                    .filter(|(role, _)| role.starts_with("issuer_"))
                    .collect::<BTreeMap<_, _>>()
                    == d.parents()?
                        .into_iter()
                        .filter(|(role, _)| role.starts_with("issuer_"))
                        .collect::<BTreeMap<_, _>>(),
            )?;
        }
        let issuer = text(&owner.object, "issuer_id")?;
        if issuer != "-" {
            let source = self.catalog.get(issuer)?;
            require(
                text(source.subject()?, "device_public_key")? != device,
                "forbidden",
            )?;
            if renewed != "-" {
                require(self.owner_ancestor(issuer, renewed)?, "forbidden")?;
            }
        }
        if !new_person {
            let issuer_parents: Vec<_> = d
                .parents()?
                .into_iter()
                .filter(|(role, _)| role.starts_with("issuer_"))
                .map(|(_, id)| id)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            check(issuer_parents == ids(&owner.payload, "issuer_lease_ids", "ds_")?)?;
            check(
                d.parents()?.get("issuer_person").map(String::as_str)
                    == Some(text(&owner.payload, "person_lease_id")?),
            )?;
        }
        Ok(())
    }
    pub(crate) fn grant_packet_issuer(
        &self,
        grant: &Statement,
        packet: &super::transcript::Packet,
    ) -> Result<()> {
        let person = text(&packet.object, "person_public_key")?;
        let issuer_id = text(&packet.object, "issuer_id")?;
        check(
            grant.signer("issuer")?.public_key == text(&packet.object, "signer_public_key")?
                && text(grant.issuer()?, "person_public_key")? == person
                && text(grant.issuer()?, "kind")?
                    == if person == "-" {
                        "root"
                    } else if issuer_id == "-" {
                        "person"
                    } else {
                        "device"
                    },
        )?;
        if person == "-" {
            check(text(&grant.payload, "root_state_id")? == issuer_id)?;
        } else if issuer_id != "-" {
            check(grant.parents()?.get("issuer_device").map(String::as_str) == Some(issuer_id))?;
        }
        Ok(())
    }
    fn packet_provenance(&self, packet: &super::transcript::Packet) -> Result<()> {
        let person = text(&packet.object, "person_public_key")?;
        let issuer = text(&packet.object, "issuer_id")?;
        let signer = text(&packet.object, "signer_public_key")?;
        if person == "-" {
            let root = self.catalog.get(issuer)?;
            check(root.kind == "root_state" && text(&root.payload, "root_public_key")? == signer)?;
        } else if issuer != "-" {
            let device = self.catalog.get(issuer)?;
            check(
                device.kind == "device_lease"
                    && text(device.subject()?, "person_public_key")? == person
                    && text(device.subject()?, "device_public_key")? == signer
                    && text(device.subject()?, "host_public_key")?
                        == text(&packet.object, "writer_host_public_key")?,
            )?;
        }
        // Complete consent is provenance even when its selected D is expired.
        // Validate the typed issuer list before it can enter the ceremony's
        // narrow same-pass ancestry set; deferred current-stage checks cannot
        // turn arbitrary signed references into eligible issuer authority.
        if packet.payload.contains_key("issuer_lease_ids") {
            let references = ids(&packet.payload, "issuer_lease_ids", "ds_")?;
            let administrator = text(&packet.object, "role")? == "administrator";
            if person == "-" {
                check(
                    administrator
                        && references.is_empty()
                        && text(&packet.payload, "root_state_id")? == issuer,
                )?;
            } else if references.is_empty() {
                check(
                    !administrator
                        && issuer == "-"
                        && signer == person
                        && text(&packet.payload, "person_lease_id")? == "-",
                )?;
            } else {
                let mut roles = BTreeMap::new();
                for id in references {
                    let statement = self.catalog.get(&id)?;
                    let role = match statement.kind.as_str() {
                        "person_lease" => "person",
                        "admin_lease" if administrator => "admin",
                        "device_lease" if issuer != "-" => "device",
                        _ => return Err(Error::new("invalid")),
                    };
                    check(
                        text(statement.subject()?, "person_public_key")? == person
                            && roles.insert(role, id).is_none(),
                    )?;
                }
                let person_id = roles.get("person").ok_or_else(|| Error::new("invalid"))?;
                check(!administrator || roles.contains_key("admin"))?;
                if !administrator {
                    check(text(&packet.payload, "person_lease_id")? == person_id)?;
                }
                if issuer == "-" {
                    check(signer == person && !roles.contains_key("device"))?;
                } else {
                    check(roles.get("device").map(String::as_str) == Some(issuer))?;
                }
            }
        }
        Ok(())
    }
    fn activation_stage_authority(
        &self,
        activation: &Activation,
        dependent: &Statement,
    ) -> Result<()> {
        if dependent.kind == "binding_lease" {
            self.packet_authority(
                &activation.packets["owner_finalization"],
                2,
                false,
                dependent,
            )
        } else {
            self.packet_authority(&activation.packets["owner"], 4, false, dependent)?;
            if let Some(administrator) = activation.packets.get("administrator") {
                self.packet_authority(administrator, 8, true, dependent)?;
            } else {
                let host = self
                    .catalog
                    .get(text(&activation.manifest, "host_lease_id")?)?;
                if text(&host.payload, "operation_id")? == activation.request_id {
                    // A folded admin stage: the owner's path with its admin grant.
                    let issuers = host
                        .parents()?
                        .into_iter()
                        .filter(|(role, _)| role.starts_with("issuer_"))
                        .map(|(_, id)| id)
                        .collect();
                    self.packet_authority_with(
                        &activation.packets["owner_finalization"],
                        8,
                        true,
                        dependent,
                        issuers,
                    )?;
                }
            }
            Ok(())
        }
    }
    fn activation_state(&self, a: &Activation) -> Result<Self> {
        require(self.activated.contains_key(&a.request_id), "proof_required")?;
        let device = self.catalog.get(text(&a.manifest, "device_lease_id")?)?;
        self.time(device)?;
        self.activation_stage_authority(a, device)?;
        if a.packets["owner_finalization"].payload["binding_lease"].is_object() {
            self.activation_stage_authority(
                a,
                self.catalog.get(text(&a.manifest, "binding_lease_id")?)?,
            )?;
        }
        if !self.admitted.contains(&device.id) {
            self.admission(&device.id)?;
            return Err(Error::new("forbidden"));
        }
        let selected = self.head(&device.stream()?.ok_or_else(|| Error::new("invalid"))?)?;
        require(selected.id == device.id, "forbidden")?;
        self.active(&device.id)?;
        Ok(self.clone())
    }
    fn dependency_closure(
        &self,
        id: &str,
        out: &mut BTreeSet<String>,
        _path: &mut BTreeSet<String>,
    ) -> Result<()> {
        let mut pending = vec![id.to_owned()];
        let mut seen = BTreeSet::new();
        while let Some(current) = pending.pop() {
            if !seen.insert(current.clone()) {
                continue;
            }
            let s = self.catalog.get(&current)?;
            let mut refs = BTreeSet::new();
            if let Some(root) = s.payload.get("root_state_id").and_then(Value::as_str) {
                refs.insert(root.into());
            }
            if s.payload.contains_key("parents") {
                refs.extend(s.parents()?.into_values());
            }
            for name in [
                "predecessors",
                "resolves",
                "retained_statement_ids",
                "kept_statement_ids",
            ] {
                if s.payload.contains_key(name) {
                    refs.extend(ids(&s.payload, name, "ds_")?);
                }
            }
            if restriction(&s.kind) {
                let target = object(
                    s.payload
                        .get("target")
                        .ok_or_else(|| Error::new("invalid"))?,
                )?;
                for id in [text(target, "statement_id")?, text(&s.payload, "ratifies")?] {
                    if id != "-" {
                        refs.insert(id.into());
                    }
                }
            }
            for parent in refs {
                if out.insert(parent.clone()) {
                    pending.push(parent);
                }
            }
        }
        Ok(())
    }
    /// The scoped same-pass ceremony exception follows only the selected
    /// grants' actual typed ancestry and packet issuers. Signed retention,
    /// resolution and sticky-proof lists remain mandatory proof completeness,
    /// but cannot enroll unrelated ordinary grants into this authority scope.
    fn ceremony_ancestry(&self, start: &str, scope: &mut BTreeSet<String>) -> Result<()> {
        let mut pending = vec![start.to_owned()];
        let mut seen = BTreeSet::new();
        while let Some(id) = pending.pop() {
            if !seen.insert(id.clone()) {
                continue;
            }
            let statement = self.catalog.get(&id)?;
            let mut parents = BTreeSet::new();
            if let Some(root) = statement
                .payload
                .get("root_state_id")
                .and_then(Value::as_str)
            {
                parents.insert(root.to_owned());
            }
            if statement.payload.contains_key("parents") {
                parents.extend(statement.parents()?.into_values());
            }
            if statement.payload.contains_key("predecessors") {
                parents.extend(ids(&statement.payload, "predecessors", "ds_")?);
            }
            for parent in parents {
                scope.insert(parent.clone());
                pending.push(parent);
            }
        }
        Ok(())
    }
    fn owner_ancestor(&self, ancestor: &str, target: &str) -> Result<bool> {
        let mut cursor = self.catalog.get(target)?;
        for _ in 0..8 {
            let parents = cursor.parents()?;
            let Some(parent) = parents.get("issuer_device") else {
                return Ok(false);
            };
            if parent == ancestor {
                return Ok(true);
            }
            cursor = self.catalog.get(parent)?;
        }
        Ok(false)
    }
    fn packet_authority(
        &self,
        packet: &super::transcript::Packet,
        required: u64,
        administrator: bool,
        dependent: &Statement,
    ) -> Result<()> {
        self.packet_authority_with(packet, required, administrator, dependent, Vec::new())
    }
    /// EXPLICIT names the issuer grants to check instead of the packet's own
    /// list (a folded host grant adds the owner's admin grant to it).
    pub(crate) fn packet_authority_with(
        &self,
        packet: &super::transcript::Packet,
        required: u64,
        administrator: bool,
        dependent: &Statement,
        explicit: Vec<String>,
    ) -> Result<()> {
        let person = text(&packet.object, "person_public_key")?;
        let issuer = text(&packet.object, "issuer_id")?;
        let signer = text(&packet.object, "signer_public_key")?;
        let references = if !explicit.is_empty() {
            explicit
        } else if packet.payload.contains_key("issuer_lease_ids") {
            let references = ids(&packet.payload, "issuer_lease_ids", "ds_")?;
            if references.is_empty() && person != "-" {
                // The only empty original-person offer is the precise pending
                // self-person possession variant. Its final component names P.
                check(text(&packet.payload, "person_lease_id")? == "-" && issuer == "-")?;
                dependent
                    .parents()?
                    .into_iter()
                    .filter(|(role, _)| role.starts_with("issuer_"))
                    .map(|(_, id)| id)
                    .collect()
            } else {
                references
            }
        } else {
            dependent
                .parents()?
                .into_iter()
                .filter(|(role, _)| role.starts_with("issuer_"))
                .map(|(_, id)| id)
                .collect()
        };
        if person == "-" {
            require(administrator, "forbidden")?;
            check(references.is_empty())?;
            let root = self.head(&["root".into()])?;
            let original = self.catalog.get(issuer)?;
            check(
                original.kind == "root_state"
                    && text(&original.payload, "root_public_key")? == signer,
            )?;
            // A retained exact child carries the old role signature through
            // explicit transitions. This cannot authorize a different child
            // or restore unrestricted signing power to the retired root.
            self.cover(&root.id, issuer, &dependent.id, &mut BTreeSet::new())?;
            return Ok(());
        }
        let mut parents = BTreeMap::new();
        for id in references {
            let parent = self.catalog.get(&id)?;
            let role = match parent.kind.as_str() {
                "person_lease" => "person",
                "admin_lease" if administrator => "admin",
                "device_lease" if issuer != "-" => "device",
                _ => return Err(Error::new("invalid")),
            };
            check(
                text(parent.subject()?, "person_public_key")? == person
                    && parents.insert(role, id).is_none(),
            )?;
        }
        let person_parent = parents.get("person").ok_or_else(|| Error::new("invalid"))?;
        self.use_parent(
            dependent,
            "issuer_person",
            person_parent,
            &mut BTreeSet::new(),
            true,
        )?;
        if issuer != "-" {
            check(parents.get("device").map(String::as_str) == Some(issuer))?;
            let device = self.catalog.get(issuer)?;
            check(
                text(device.subject()?, "device_public_key")? == signer
                    && text(device.subject()?, "host_public_key")?
                        == text(&packet.object, "writer_host_public_key")?,
            )?;
            let power = self.use_parent(
                dependent,
                "packet_device",
                issuer,
                &mut BTreeSet::new(),
                true,
            )?;
            require(power.scopes & required == required, "forbidden")?;
        } else {
            check(signer == person)?;
        }
        if administrator {
            let role = parents.get("admin").ok_or_else(|| Error::new("invalid"))?;
            self.use_parent(dependent, "issuer_admin", role, &mut BTreeSet::new(), true)?;
        }
        Ok(())
    }
    pub fn activation_response(&self, request_id: &str, expected: &Value) -> Result<Value> {
        let a = self
            .complete_operations
            .get(request_id)
            .ok_or_else(|| Error::missing(request_id))?;
        let state = self.activation_state(a)?;
        let d = state.catalog.get(text(&a.manifest, "device_lease_id")?)?;
        let request = &a.packets["request"];
        let owner = &a.packets["owner"];
        if expected.as_str() != Some("-") {
            let expected = object(expected)?;
            fields(
                expected,
                "request_id context_id mode person_public_key host_public_key device_public_key renewed_device_lease_id owner_offer_id selection_id administrator_offer_id scopes not_after",
            )?;
            for (name, actual) in [
                ("request_id", a.request_id.as_str()),
                ("context_id", self.descriptor.context_id().as_str()),
                ("mode", text(&request.payload, "mode")?),
                (
                    "person_public_key",
                    text(&owner.object, "person_public_key")?,
                ),
                (
                    "host_public_key",
                    text(&request.payload, "host_public_key")?,
                ),
                (
                    "device_public_key",
                    text(&request.payload, "device_public_key")?,
                ),
                (
                    "renewed_device_lease_id",
                    text(&request.payload, "renewed_device_lease_id")?,
                ),
                ("owner_offer_id", a.packets["owner"].id.as_str()),
                ("selection_id", a.packets["selection"].id.as_str()),
                (
                    "administrator_offer_id",
                    text(&a.manifest, "administrator_offer_id")?,
                ),
                ("not_after", text(&owner.payload, "not_after")?),
            ] {
                check(text(expected, name)? == actual)?;
            }
            check(num(expected, "scopes")? == num(d.subject()?, "scopes")?)?;
        }
        let power = state.active_inner(&d.id, &mut BTreeSet::new(), true)?;
        let mut required: BTreeSet<_> = ids(&a.manifest, "ancestor_statement_ids", "ds_")?
            .into_iter()
            .collect();
        required.insert(d.id.clone());
        Ok(
            json!({"ok":true,"context_id":self.descriptor.context_id(),"request_id":a.request_id,"manifest_id":a.manifest_id,"activation_id":a.id,"person_public_key":text(d.subject()?,"person_public_key")?,"host_public_key":text(d.subject()?,"host_public_key")?,"device_public_key":text(d.subject()?,"device_public_key")?,"device_lease_id":d.id,"scopes":power.scopes,"effective_not_after":power.deadline.ok_or_else(||Error::new("invalid"))?,"required_statement_ids":required,"required_proof_ids":ids(&a.manifest,"proof_ids","dp_")?,"review_pins_matched":expected.as_str()!=Some("-")}),
        )
    }
}

/// Independently current public membership. A matching device is a display
/// fact, never a persistent provider selection or a private-key claim.
#[derive(Clone, Debug)]
pub struct CurrentMember {
    pub host_public_key: String,
    pub member: String,
    pub person_public_key: String,
    pub host_lease_id: String,
    pub person_lease_id: String,
    pub binding_lease_id: String,
    pub device_lease_id: String,
    pub activation_id: String,
    pub not_after: String,
}
impl CurrentMember {
    pub fn response(&self) -> Value {
        json!({"host_public_key":self.host_public_key,"member":self.member,"person_public_key":self.person_public_key,"host_lease_id":self.host_lease_id,"binding_lease_id":self.binding_lease_id,"device_lease_id":self.device_lease_id,"not_after":self.not_after})
    }
}
impl Projection {
    pub fn members(&self) -> Result<Vec<CurrentMember>> {
        let mut result = Vec::new();
        for stream in self.streams.values().filter(|s| s.key[0] == "host") {
            let Ok(host) = self.head(&stream.key) else {
                continue;
            };
            let Ok(mut power) = self.active_inner(&host.id, &mut BTreeSet::new(), true) else {
                continue;
            };
            let host_key = text(host.subject()?, "host_public_key")?;
            let mut member = CurrentMember {
                host_public_key: host_key.into(),
                member: text(host.subject()?, "member")?.into(),
                person_public_key: "-".into(),
                host_lease_id: host.id.clone(),
                person_lease_id: "-".into(),
                binding_lease_id: "-".into(),
                device_lease_id: "-".into(),
                activation_id: "-".into(),
                not_after: power
                    .deadline
                    .clone()
                    .ok_or_else(|| Error::new("invalid"))?,
            };
            if let Ok(binding) = self.head(&["binding".into(), host_key.into()])
                && let Ok(binding_power) =
                    self.active_inner(&binding.id, &mut BTreeSet::new(), true)
            {
                let person_key = text(binding.subject()?, "person_public_key")?;
                if let Ok(person) = self.head(&["person".into(), person_key.into()])
                    && let Ok(person_power) =
                        self.active_inner(&person.id, &mut BTreeSet::new(), true)
                {
                    power.intersect(&binding_power);
                    power.intersect(&person_power);
                    member.person_public_key = person_key.into();
                    member.person_lease_id = person.id.clone();
                    member.binding_lease_id = binding.id.clone();
                    member.not_after = power.deadline.ok_or_else(|| Error::new("invalid"))?;
                    let operation = text(&binding.payload, "operation_id")?;
                    if let Some(activation) = self.activated.get(operation) {
                        member.activation_id = activation.id.clone();
                    }
                    let mut devices = BTreeSet::new();
                    for device_stream in self
                        .streams
                        .values()
                        .filter(|s| s.key[0] == "device" && s.key[1] == person_key)
                    {
                        let Ok(device) = self.head(&device_stream.key) else {
                            continue;
                        };
                        if text(device.subject()?, "host_public_key")? == host_key
                            && self.active(&device.id).is_ok()
                        {
                            devices.insert(device.id.clone());
                        }
                    }
                    if devices.len() == 1 {
                        member.device_lease_id = devices
                            .into_iter()
                            .next()
                            .ok_or_else(|| Error::new("invalid"))?;
                    }
                }
            }
            result.push(member);
        }
        result.sort_by(|a, b| a.host_public_key.cmp(&b.host_public_key));
        Ok(result)
    }
    pub fn root_state_id(&self) -> Result<&str> {
        require(!self.origin_conflicted, "state_conflict")?;
        let stream = self
            .streams
            .get(&vec!["root".into()])
            .ok_or_else(|| Error::new("proof_required"))?;
        require(stream.heads.len() <= 1, "state_conflict")?;
        let id = stream
            .heads
            .first()
            .map(String::as_str)
            .ok_or_else(|| Error::new("proof_required"))?;
        self.proof_complete(id)?;
        Ok(id)
    }
    /// Conservative exact dependency evidence for a local admission marker.
    /// The containing DP remains separate from semantic nested DS identities.
    pub(crate) fn admission_basis(&self, id: &str) -> Result<(String, BTreeSet<String>)> {
        let statement = self.catalog.get(id)?;
        let mut evidence = BTreeSet::new();
        self.dependency_closure(id, &mut evidence, &mut BTreeSet::new())?;
        evidence.insert(id.into());
        let mut retained = false;
        let dependencies: Vec<_> = evidence.iter().cloned().collect();
        for dependency in dependencies {
            if let Some(s) = self.catalog.statements.get(&dependency)
                && let Some(stream) = s.stream()?
                && let Ok(head) = self.head(&stream)
                && head.id != s.id
            {
                retained = true;
                evidence.insert(head.id.clone());
                self.dependency_closure(&head.id, &mut evidence, &mut BTreeSet::new())?;
            }
        }
        for activation in self.activated.values() {
            if [
                "person_lease_id",
                "host_lease_id",
                "binding_lease_id",
                "device_lease_id",
            ]
            .iter()
            .any(|field| activation.manifest.get(*field).and_then(Value::as_str) == Some(id))
            {
                evidence.insert(activation.id.clone());
                evidence.insert(activation.manifest_id.clone());
                evidence.extend(activation.packets.values().map(|p| p.id.clone()));
            }
        }
        let migration = self
            .catalog
            .migrations
            .iter()
            .find(|(_, m)| m.prepared.statements.contains_key(id));
        let basis = if let Some((proof, m)) = migration {
            evidence.insert(proof.clone());
            evidence.insert(m.proposal.id.clone());
            evidence.insert(m.commit.id.clone());
            evidence.extend(m.acknowledgments.values().map(|a| a.id.clone()));
            "migration"
        } else if restriction(&statement.kind) {
            if text(&statement.payload, "ratifies")? != "-" {
                "ratification"
            } else {
                "current"
            }
        } else if retained && statement.kind != "root_state" {
            "retention"
        } else {
            "current"
        };
        let statements: Vec<_> = evidence
            .iter()
            .filter(|id| ident(id, "ds_"))
            .cloned()
            .collect();
        for id in statements {
            if let Some(source) = self
                .catalog
                .statement_proofs
                .get(&id)
                .and_then(|p| p.first())
            {
                evidence.insert(source.clone());
            }
        }
        Ok((basis.into(), evidence))
    }
}

impl Projection {
    pub(crate) fn member_for(&self, host: &str, person: &str) -> Result<CurrentMember> {
        let h = self.head(&["host".into(), host.into()])?;
        let mut power = self.active_inner(&h.id, &mut BTreeSet::new(), true)?;
        let mut member = CurrentMember {
            host_public_key: host.into(),
            member: text(h.subject()?, "member")?.into(),
            person_public_key: "-".into(),
            host_lease_id: h.id.clone(),
            person_lease_id: "-".into(),
            binding_lease_id: "-".into(),
            device_lease_id: "-".into(),
            activation_id: "-".into(),
            not_after: power
                .deadline
                .clone()
                .ok_or_else(|| Error::new("invalid"))?,
        };
        if person != "-" {
            let p = self.head(&["person".into(), person.into()])?;
            let b = self.head(&["binding".into(), host.into()])?;
            require(
                text(b.subject()?, "person_public_key")? == person
                    && text(b.subject()?, "host_public_key")? == host,
                "forbidden",
            )?;
            power.intersect(&self.active_inner(&p.id, &mut BTreeSet::new(), true)?);
            power.intersect(&self.active_inner(&b.id, &mut BTreeSet::new(), true)?);
            member.person_public_key = person.into();
            member.person_lease_id = p.id.clone();
            member.binding_lease_id = b.id.clone();
            member.not_after = power.deadline.ok_or_else(|| Error::new("invalid"))?;
            if let Some(a) = self.activated.get(text(&b.payload, "operation_id")?) {
                member.activation_id = a.id.clone();
            }
        }
        Ok(member)
    }
    pub(crate) fn provider_potential(
        &self,
        person: &str,
        host: &str,
        device: Option<&str>,
    ) -> Result<Value> {
        let member = self.member_for(host, person)?;
        let root = self.root_state_id()?;
        let (kind, device_key, lease, scopes, not_after) = if let Some(id) = device {
            let d = self.catalog.get(id)?;
            check(d.kind == "device_lease")?;
            require(
                text(d.subject()?, "person_public_key")? == person
                    && text(d.subject()?, "host_public_key")? == host,
                "forbidden",
            )?;
            require(
                self.head(&d.stream()?.ok_or_else(|| Error::new("invalid"))?)?
                    .id
                    == id,
                "forbidden",
            )?;
            let mut power = self.active_inner(id, &mut BTreeSet::new(), true)?;
            // Device bit8 remains conditional on this person's actual current
            // administrator role; losing that role does not erase owner bits.
            if power.scopes & 8 != 0 {
                match self
                    .head(&["admin".into(), person.into()])
                    .and_then(|admin| self.active_inner(&admin.id, &mut BTreeSet::new(), true))
                {
                    Ok(admin) => {
                        if let Some(end) = admin.deadline
                            && power.deadline.as_ref().is_none_or(|current| &end < current)
                        {
                            power.deadline = Some(end);
                        }
                    }
                    Err(_) => power.scopes &= !8,
                }
            }
            (
                "device",
                text(d.subject()?, "device_public_key")?.to_owned(),
                id.to_owned(),
                power.scopes,
                power.deadline.ok_or_else(|| Error::new("invalid"))?,
            )
        } else {
            let mut deadline = member.not_after.clone();
            let mut scopes = 7;
            if let Ok(a) = self.head(&["admin".into(), person.into()])
                && let Ok(power) = self.active_inner(&a.id, &mut BTreeSet::new(), true)
            {
                scopes |= 8;
                if let Some(end) = power.deadline
                    && end < deadline
                {
                    deadline = end;
                }
            }
            (
                "original_person",
                "-".into(),
                member.person_lease_id,
                scopes,
                deadline,
            )
        };
        Ok(
            json!({"kind":kind,"person_public_key":person,"host_public_key":host,"device_public_key":device_key,"lease_id":lease,"root_state_id":root,"scopes":scopes,"not_after":not_after}),
        )
    }
    pub(crate) fn binding_provider(&self, person: &str, host: &str) -> Result<Value> {
        let member = self.member_for(host, "-")?;
        // An old binding remains an exact generation/identity pin after its
        // expiry. Its own power is not an ancestor of a fresh original-owner
        // binding. A different owner needs the explicit rebind workflow.
        if let Some(stream) = self.streams.get(&vec!["binding".into(), host.into()]) {
            require(!stream.heads.is_empty(), "proof_required")?;
            let binding = self.head(&stream.key)?;
            require(
                text(binding.subject()?, "person_public_key")? == person,
                "forbidden",
            )?;
        }
        let person_lease = self.head(&["person".into(), person.into()])?;
        let power = self.active_inner(&person_lease.id, &mut BTreeSet::new(), true)?;
        let mut deadline = member.not_after;
        if let Some(end) = power.deadline {
            deadline = deadline.min(end);
        }
        let mut scopes = 7;
        if let Ok(admin) = self.head(&["admin".into(), person.into()])
            && let Ok(power) = self.active_inner(&admin.id, &mut BTreeSet::new(), true)
        {
            scopes |= 8;
            if let Some(end) = power.deadline {
                deadline = deadline.min(end);
            }
        }
        Ok(
            json!({"kind":"original_person","person_public_key":person,"host_public_key":host,"device_public_key":"-","lease_id":person_lease.id,"root_state_id":self.root_state_id()?,"scopes":scopes,"not_after":deadline}),
        )
    }
}
