//! Preparation of one exact incomplete ceremony prefix. These results contain
//! checked public components, never admitted state or a reusable signer grant.
use super::*;
use crate::decentralized::{catalog::raw_field, transcript::Packet};

#[derive(Clone, Copy)]
pub(crate) struct CeremonyPrefix<'a> {
    pub descriptor: &'a Descriptor,
    pub prior: &'a Value,
    pub catalog: &'a Catalog,
    pub request: &'a Packet,
    pub owner: &'a Packet,
    pub selection: &'a Packet,
    pub administrator: Option<&'a Packet>,
    pub now: &'a str,
    pub staging: Option<&'a Projection>,
}

pub(crate) struct PreparedAdmissions {
    pub person: Statement,
    pub host: Statement,
    pub root: String,
    pub catalog: Catalog,
    pub decision_time: String,
}
pub(crate) struct PreparedFinalization {
    pub admissions: PreparedAdmissions,
    pub binding: Statement,
    pub device: Statement,
    pub reused_binding: bool,
    pub ancestor_statement_ids: Vec<String>,
}
impl CeremonyPrefix<'_> {
    fn preparation(self) -> Result<Preparation> {
        let (migration, floors) = if let Some(stage) = self.staging {
            let (proposal, root) = stage
                .staged_origin
                .as_ref()
                .ok_or_else(|| Error::new("forbidden"))?;
            check(
                self.prior == "-"
                    && stage.descriptor.context_id() == self.descriptor.context_id()
                    && text(&self.request.payload, "migration_proposal_id")? == proposal
                    && stage.root_state_id()? == root
                    && text(&self.owner.payload, "root_state_id")? == root,
            )?;
            (
                Some((proposal.clone(), root.clone())),
                stage.staged_floors.clone(),
            )
        } else {
            check(text(&self.request.payload, "migration_proposal_id")? == "-")?;
            (None, BTreeMap::new())
        };
        Ok(Preparation {
            migration,
            floors,
            owner_offer: Some(self.owner.clone()),
            administrator: self.administrator.cloned(),
            genesis: None,
        })
    }
}
fn encode_value(value: &impl serde::Serialize) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| Error::new("internal"))
}
pub(crate) fn packet_agrees(
    request: &Packet,
    owner: &Packet,
    selection: &Packet,
    d: &Descriptor,
) -> Result<()> {
    let person = text(&owner.object, "person_public_key")?;
    let host = text(&request.payload, "host_public_key")?;
    let device = text(&request.payload, "device_public_key")?;
    for (name, expected) in [
        ("request_packet_id", request.id.as_str()),
        ("owner_offer_id", owner.id.as_str()),
        ("context_id", d.context_id().as_str()),
        ("person_public_key", person),
        ("host_public_key", host),
        ("device_public_key", device),
    ] {
        check(text(&selection.payload, name)? == expected)?;
    }
    check(
        text(&selection.object, "role")? == "selection"
            && text(&selection.object, "request_id")? == text(&request.object, "request_id")?
            && text(&selection.object, "context_id")? == d.context_id()
            && text(&selection.object, "person_public_key")? == person
            && text(&selection.object, "writer_host_public_key")? == host
            && text(&selection.object, "signer_public_key")? == device,
    )
}
fn pending_component(
    d: &Descriptor,
    admin: &Packet,
    field: &str,
    kind: &str,
    catalog: &Catalog,
    request: &str,
) -> Result<Statement> {
    match value_field(&admin.payload, field)? {
        Value::String(id) => {
            let s = catalog.get(id)?;
            check(s.kind == kind && text(&s.payload, "operation_id")? != request)?;
            Ok(s.clone())
        }
        Value::Object(_) => {
            let s = Statement::read(d, &raw_field(&admin.payload_bytes, field)?)?;
            check(s.kind == kind && text(&s.payload, "operation_id")? == request)?;
            Ok(s)
        }
        _ => Err(Error::new("invalid")),
    }
}
impl Projection {
    pub(crate) fn owner_preparation(prefix: CeremonyPrefix<'_>) -> Result<Self> {
        let admissions = Self::prepare_administrator(prefix)?;
        Self::build_mode(
            prefix.descriptor,
            prefix.prior,
            Some(&admissions.catalog.bytes),
            prefix.now,
            "repair",
            prefix.preparation()?,
        )
    }
    /// Owner-local signing preflight for exact typed administrator templates.
    /// Template signatures are still empty and these bodies are never indexed
    /// or returned as admitted authority. Complete packet verification remains
    /// mandatory after their real signatures have been retained.
    pub(crate) fn check_administrator_drafts(
        &self,
        request: &Packet,
        owner: &Packet,
        selection: &Packet,
        administrator: &Packet,
        drafts: &[Statement],
    ) -> Result<()> {
        packet_agrees(request, owner, selection, &self.descriptor)?;
        check(
            text(&administrator.object, "role")? == "administrator"
                && text(&administrator.object, "request_id")?
                    == text(&request.object, "request_id")?
                && text(&administrator.object, "context_id")? == self.descriptor.context_id()
                && text(&administrator.payload, "owner_offer_id")? == owner.id
                && text(&administrator.payload, "selection_id")? == selection.id
                && text(&administrator.payload, "root_state_id")? == self.root_state_id()?,
        )?;
        self.packet_provenance(administrator)?;
        let mut prepared = self.clone();
        for statement in drafts {
            if let Some(old) = prepared.catalog.statements.get(&statement.id) {
                check(old.kind == statement.kind && old.payload_bytes == statement.payload_bytes)?;
            }
            prepared
                .catalog
                .statements
                .insert(statement.id.clone(), statement.clone());
        }
        for statement in drafts {
            check(
                matches!(statement.kind.as_str(), "person_lease" | "host_lease")
                    && text(&statement.payload, "operation_id")?
                        == text(&request.object, "request_id")?
                    && text(&statement.payload, "not_after")? == text(&owner.payload, "not_after")?,
            )?;
            if statement.kind == "person_lease" {
                check(
                    text(statement.subject()?, "person_public_key")?
                        == text(&owner.object, "person_public_key")?,
                )?;
            } else {
                check(
                    text(statement.subject()?, "host_public_key")?
                        == text(&request.payload, "host_public_key")?,
                )?;
            }
            check(text(statement.subject()?, "member")? == text(&owner.payload, "member")?)?;
            prepared.grant_packet_issuer(statement, administrator)?;
            let issuer_ids = statement
                .parents()?
                .into_iter()
                .filter(|(role, _)| role.starts_with("issuer_"))
                .map(|(_, id)| id)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            check(issuer_ids == ids(&administrator.payload, "issuer_lease_ids", "ds_")?)?;
            prepared.check_prepared_grant(statement, &BTreeMap::new(), None)?;
            prepared.packet_authority(administrator, 8, true, statement)?;
        }
        // Reusing existing P/H is still a new administrator stage. Their
        // presence cannot hide an expired, revoked or wrong-scope signer.
        if drafts.is_empty() {
            let host = self
                .catalog
                .get(text(&administrator.payload, "host_lease")?)?;
            self.packet_authority(administrator, 8, true, host)?;
        }
        Ok(())
    }
    pub(crate) fn prepare_administrator(prefix: CeremonyPrefix<'_>) -> Result<PreparedAdmissions> {
        let preparation = prefix.preparation()?;
        let CeremonyPrefix {
            descriptor,
            prior,
            catalog,
            request,
            owner,
            selection,
            administrator,
            now,
            staging: _,
        } = prefix;
        packet_agrees(request, owner, selection, descriptor)?;
        let request_id = text(&request.object, "request_id")?;
        let mut pending = Vec::new();
        if let Some(admin) = administrator {
            check(
                text(&admin.object, "role")? == "administrator"
                    && text(&admin.object, "request_id")? == request_id
                    && text(&admin.object, "context_id")? == descriptor.context_id()
                    && text(&admin.payload, "owner_offer_id")? == owner.id
                    && text(&admin.payload, "selection_id")? == selection.id,
            )?;
            for (field, kind) in [
                ("person_lease", "person_lease"),
                ("host_lease", "host_lease"),
            ] {
                let statement =
                    pending_component(descriptor, admin, field, kind, catalog, request_id)?;
                if value_field(&admin.payload, field)?.is_object() {
                    pending.push(statement)
                }
            }
        } else {
            check(text(&request.payload, "mode")? == "renew")?
        }
        let candidate = if pending.is_empty() {
            catalog.clone()
        } else {
            // These are the exact original complete envelope slices from the
            // signed administrator packet. No signature or JSON is rebuilt.
            let objects: Vec<_> = pending
                .iter()
                .map(|s| {
                    (
                        s.proof_id.clone(),
                        json!({"id":s.proof_id,"kind":s.kind,"body_base64":encode(&s.body)}),
                    )
                })
                .collect::<BTreeMap<_, _>>()
                .into_values()
                .collect();
            let addition = Catalog::read(
                descriptor,
                &encode_value(
                    &json!({"format":1,"context_id":descriptor.context_id(),"objects":objects}),
                )?,
            )?;
            Catalog::union(descriptor, catalog, &addition)?
        };
        let projection = Self::build_mode(
            descriptor,
            prior,
            Some(&candidate.bytes),
            now,
            "repair",
            preparation,
        )?;
        let root = projection.root_state_id()?.to_owned();
        check(
            text(&owner.payload, "root_state_id")? == "-"
                || text(&owner.payload, "root_state_id")? == root,
        )?;
        if let Some(admin) = administrator {
            check(text(&admin.payload, "root_state_id")? == root)?
        }
        let person_key = text(&owner.object, "person_public_key")?;
        let host_key = text(&request.payload, "host_public_key")?;
        let (person, host) = if let Some(admin) = administrator {
            (
                pending_component(
                    descriptor,
                    admin,
                    "person_lease",
                    "person_lease",
                    &candidate,
                    request_id,
                )?,
                pending_component(
                    descriptor,
                    admin,
                    "host_lease",
                    "host_lease",
                    &candidate,
                    request_id,
                )?,
            )
        } else {
            (
                projection
                    .head(&["person".into(), person_key.into()])?
                    .clone(),
                projection.head(&["host".into(), host_key.into()])?.clone(),
            )
        };
        check(
            text(person.subject()?, "person_public_key")? == person_key
                && text(host.subject()?, "host_public_key")? == host_key
                && text(person.subject()?, "member")? == text(&owner.payload, "member")?
                && text(host.subject()?, "member")? == text(&owner.payload, "member")?,
        )?;
        for statement in [&person, &host] {
            if text(&statement.payload, "operation_id")? == request_id {
                let admin = administrator.ok_or_else(|| Error::new("invalid"))?;
                projection.grant_packet_issuer(statement, admin)?;
                let issuer_ids: Vec<_> = statement
                    .parents()?
                    .into_iter()
                    .filter(|(role, _)| role.starts_with("issuer_"))
                    .map(|(_, id)| id)
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                check(issuer_ids == ids(&admin.payload, "issuer_lease_ids", "ds_")?)?;
                projection.check_prepared_grant(statement, &BTreeMap::new(), None)?;
                projection.packet_authority(admin, 8, true, statement)?;
                require(
                    text(&statement.payload, "not_after")? <= text(&owner.payload, "not_after")?,
                    "forbidden",
                )?;
            } else {
                let selected =
                    projection.head(&statement.stream()?.ok_or_else(|| Error::new("invalid"))?)?;
                require(selected.id == statement.id, "forbidden")?;
                projection.active(&statement.id)?;
            }
        }
        // Even when both P/H are reused, a present administrator packet must
        // have its actual current role; old grants cannot mask a bad stage.
        if let Some(admin) = administrator {
            projection.packet_provenance(admin)?;
            projection.packet_authority(admin, 8, true, &host)?;
        }
        require(
            text(&person.payload, "not_after")? >= text(&owner.payload, "not_after")?
                && text(&host.payload, "not_after")? >= text(&owner.payload, "not_after")?,
            "forbidden",
        )?;
        Ok(PreparedAdmissions {
            person,
            host,
            root,
            catalog: projection.catalog,
            decision_time: projection.decision_time,
        })
    }
    pub(crate) fn prepare_finalization(
        prefix: CeremonyPrefix<'_>,
        finalization: &Packet,
    ) -> Result<PreparedFinalization> {
        Self::prepare_finalization_parts(prefix, finalization, None)
    }
    /// Check fixed, still unsigned owner templates against their exact selected
    /// prefix. No template or pending component becomes admitted authority.
    pub(crate) fn check_owner_drafts(
        prefix: CeremonyPrefix<'_>,
        finalization: &Packet,
        binding: &Statement,
        device: &Statement,
        reused_binding: bool,
    ) -> Result<PreparedFinalization> {
        Self::prepare_finalization_parts(
            prefix,
            finalization,
            Some((binding, device, reused_binding)),
        )
    }
    fn prepare_finalization_parts(
        prefix: CeremonyPrefix<'_>,
        finalization: &Packet,
        drafts: Option<(&Statement, &Statement, bool)>,
    ) -> Result<PreparedFinalization> {
        let admissions = Self::prepare_administrator(prefix)?;
        let preparation = prefix.preparation()?;
        let CeremonyPrefix {
            descriptor,
            prior,
            catalog: _,
            request,
            owner,
            selection,
            administrator,
            now,
            staging: _,
        } = prefix;
        let request_id = text(&request.object, "request_id")?;
        let person = text(&owner.object, "person_public_key")?;
        let host = text(&request.payload, "host_public_key")?;
        let device_key = text(&request.payload, "device_public_key")?;
        let f = &finalization.payload;
        check(
            text(&finalization.object, "role")? == "owner_finalization"
                && text(&finalization.object, "request_id")? == request_id
                && text(&finalization.object, "context_id")? == descriptor.context_id()
                && text(f, "selection_id")? == selection.id
                && text(f, "administrator_offer_id")?
                    == administrator.map(|a| a.id.as_str()).unwrap_or("-")
                && text(f, "root_state_id")? == admissions.root
                && text(f, "person_lease_id")? == admissions.person.id
                && text(f, "host_lease_id")? == admissions.host.id,
        )?;
        for field in [
            "person_public_key",
            "writer_host_public_key",
            "signer_public_key",
            "issuer_id",
            "authority_signature_format",
        ] {
            check(text(&finalization.object, field)? == text(&owner.object, field)?)?;
        }
        let projection = Self::build_mode(
            descriptor,
            prior,
            Some(&admissions.catalog.bytes),
            now,
            "repair",
            preparation,
        )?;
        let reused_binding = value_field(f, "binding_lease")?.is_string();
        if let Some((_, _, reused)) = drafts {
            check(reused == reused_binding)?;
        }
        let binding = if reused_binding {
            check(text(&request.payload, "mode")? == "renew")?;
            let b = projection.catalog.get(text(f, "binding_lease")?)?.clone();
            require(
                projection.head(&["binding".into(), host.into()])?.id == b.id,
                "forbidden",
            )?;
            projection.active(&b.id)?;
            b
        } else if let Some((binding, _, _)) = drafts {
            check(raw_field(&finalization.payload_bytes, "binding_lease")? == binding.body)?;
            binding.clone()
        } else {
            Statement::read_draft(
                descriptor,
                &raw_field(&finalization.payload_bytes, "binding_lease")?,
                true,
            )?
        };
        let device = if let Some((_, device, _)) = drafts {
            check(raw_field(&finalization.payload_bytes, "device_lease")? == device.body)?;
            device.clone()
        } else {
            Statement::read(
                descriptor,
                &raw_field(&finalization.payload_bytes, "device_lease")?,
            )?
        };
        check(
            binding.kind == "binding_lease"
                && device.kind == "device_lease"
                && text(binding.subject()?, "person_public_key")? == person
                && text(binding.subject()?, "host_public_key")? == host
                && text(device.subject()?, "person_public_key")? == person
                && text(device.subject()?, "host_public_key")? == host
                && text(device.subject()?, "device_public_key")? == device_key
                && text(&device.payload, "operation_id")? == request_id
                && num(device.subject()?, "scopes")? == num(&owner.payload, "scopes")?
                && text(&device.payload, "not_after")? == text(&owner.payload, "not_after")?,
        )?;
        let mut pending = BTreeMap::new();
        for s in [&admissions.person, &admissions.host] {
            if text(&s.payload, "operation_id")? == request_id {
                pending.insert(s.id.clone(), s.clone());
            }
        }
        let mut prepared = projection;
        for s in [&binding, &device] {
            prepared.catalog.statements.insert(s.id.clone(), s.clone());
        }
        let issuer = text(&owner.object, "issuer_id")?;
        let new_person = text(&owner.payload, "person_lease_id")? == "-";
        let mut owner_parents = vec![admissions.person.id.clone()];
        if !new_person {
            owner_parents = ids(&owner.payload, "issuer_lease_ids", "ds_")?
        }
        let owner_parent_set: BTreeSet<_> = owner_parents.into_iter().collect();
        for s in [&binding, &device] {
            if reused_binding && s.kind == "binding_lease" {
                continue;
            }
            check(text(&s.payload, "operation_id")? == request_id)?;
            prepared.grant_packet_issuer(s, finalization)?;
            check(
                s.parents()?.get("subject_person") == Some(&admissions.person.id)
                    && s.parents()?.get("subject_host") == Some(&admissions.host.id),
            )?;
            let issuer_parents: BTreeSet<_> = s
                .parents()?
                .into_iter()
                .filter(|(role, _)| role.starts_with("issuer_"))
                .map(|(_, id)| id)
                .collect();
            check(issuer_parents == owner_parent_set)?;
            prepared.check_prepared_grant(s, &pending, new_person.then_some(person))?;
            if s.kind == "binding_lease" {
                check(s.signer("host")?.signature == "-" && s.signer("host")?.public_key == host)?;
                pending.insert(s.id.clone(), s.clone());
            }
        }
        check(device.parents()?.get("subject_binding") == Some(&binding.id))?;
        if issuer != "-" {
            let power = prepared.active_inner(issuer, &mut BTreeSet::new(), true)?;
            require(
                power.scopes & 4 == 4 && num(device.subject()?, "scopes")? & !power.scopes == 0,
                "forbidden",
            )?;
            if !reused_binding {
                require(power.scopes & 2 == 2, "forbidden")?
            }
        }
        let mut ancestors = BTreeSet::new();
        for selected in [
            &admissions.person.id,
            &admissions.host.id,
            &binding.id,
            &device.id,
        ] {
            prepared.dependency_closure(selected, &mut ancestors, &mut BTreeSet::new())?;
        }
        Ok(PreparedFinalization {
            admissions,
            binding,
            device,
            reused_binding,
            ancestor_statement_ids: ancestors.into_iter().collect(),
        })
    }
    fn check_prepared_grant(
        &self,
        s: &Statement,
        pending: &BTreeMap<String, Statement>,
        self_person: Option<&str>,
    ) -> Result<()> {
        self.provenance_statement(s, &mut BTreeSet::new(), &mut Vec::new())?;
        self.time(s)?;
        check(stamp(s.issued_at()?)? <= stamp(&self.decision_time)?)?;
        require(
            text(&s.payload, "root_state_id")? == self.root_state_id()?,
            "forbidden",
        )?;
        self.local_generation(s)?;
        self.action_retention(s)?;
        self.known_restrictions(s)?;
        for (role, id) in s.parents()? {
            if let Some(parent) = pending.get(&id) {
                if !role.starts_with("subject_") {
                    check(
                        role == "issuer_person"
                            && self_person == Some(text(parent.subject()?, "person_public_key")?),
                    )?;
                }
                self.time(parent)?;
                require(
                    text(&s.payload, "not_after")? <= text(&parent.payload, "not_after")?,
                    "forbidden",
                )?;
                continue;
            }
            let parent = self.catalog.get(&id)?;
            if !self.admitted.contains(&id) {
                self.time(parent)?;
                self.root_coverage(parent)?;
                self.known_restrictions(parent)?;
                return Err(Error::new("forbidden"));
            }
            require(
                self.head(&parent.stream()?.ok_or_else(|| Error::new("invalid"))?)?
                    .id
                    == id,
                "forbidden",
            )?;
            let power = self.active_inner(&id, &mut BTreeSet::new(), true)?;
            require(
                power
                    .deadline
                    .as_deref()
                    .is_none_or(|end| text(&s.payload, "not_after").is_ok_and(|own| own <= end)),
                "forbidden",
            )?;
            if role == "issuer_device" {
                require(
                    power.scopes & required_scope(&s.kind) == required_scope(&s.kind),
                    "forbidden",
                )?;
                if s.kind == "device_lease" {
                    require(
                        num(s.subject()?, "scopes")? & !power.scopes == 0,
                        "forbidden",
                    )?
                }
            }
        }
        Ok(())
    }
}
