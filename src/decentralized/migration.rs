//! Exact legacy-source and all-participant cutover evidence. Inspecting this
//! proof does not adopt a context, clear a fence, or install a signing key.
use super::{
    catalog::{Catalog, raw_array_field, raw_field, value_field},
    codec::*,
    statement::{Descriptor, Statement},
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SourceState {
    pub root_highwater: u64,
    pub hosts: BTreeSet<String>,
    pub maxima: BTreeMap<(String, String), (u64, String)>,
    pub restrictions: BTreeMap<String, Obj>,
}
impl SourceState {
    pub(crate) fn read(network: &str, bytes: &[u8]) -> Result<Self> {
        let value = parse(bytes, MAX_PAYLOAD)?;
        let o = object(&value)?;
        fields(
            o,
            "format network_id legacy_root_highwater known_admitted_hosts access_maxima admitted_restrictions",
        )?;
        version(o)?;
        check(text(o, "network_id")? == network)?;
        let hosts = strings(o, "known_admitted_hosts", key)?;
        require(hosts.len() <= 4096, "quota_exceeded")?;
        require(array(o, "access_maxima")?.len() <= 4096, "quota_exceeded")?;
        require(
            array(o, "admitted_restrictions")?.len() <= 4096,
            "quota_exceeded",
        )?;
        let mut maxima = BTreeMap::new();
        let mut previous = None;
        for value in array(o, "access_maxima")? {
            let row = object(value)?;
            fields(row, "kind subject version message_hash")?;
            let kind = text(row, "kind")?;
            let subject = text(row, "subject")?;
            check(matches!(kind, "policy" | "group"))?;
            if kind == "policy" {
                check(key(subject))?;
            } else {
                crate::admins::group_name(subject).map_err(|_| Error::new("invalid"))?;
            }
            let version = num(row, "version")?;
            let hash = text(row, "message_hash")?;
            check(version > 0 && (hash == "-" || digest(hash)))?;
            let key = (kind.to_owned(), subject.to_owned());
            check(previous.as_ref().is_none_or(|old| old < &key))?;
            previous = Some(key.clone());
            maxima.insert(key, (version, hash.into()));
        }
        let mut restrictions = BTreeMap::new();
        let mut previous = "";
        for value in array(o, "admitted_restrictions")? {
            let row = object(value)?;
            fields(
                row,
                "proof_id kind person_public_key host_public_key device_public_key",
            )?;
            let id = text(row, "proof_id")?;
            check(ident(id, "pf_") && id > previous)?;
            previous = id;
            check(matches!(
                text(row, "kind")?,
                "admin_removal"
                    | "person_removal"
                    | "host_revocation"
                    | "invite_revocation"
                    | "host_leave"
                    | "host_unbinding"
                    | "device_revocation"
                    | "person_record"
                    | "root_record"
            ))?;
            for field in ["person_public_key", "host_public_key", "device_public_key"] {
                let value = text(row, field)?;
                check(value == "-" || key(value))?;
            }
            restrictions.insert(id.into(), row.clone());
        }
        Ok(Self {
            root_highwater: num(o, "legacy_root_highwater")?,
            hosts,
            maxima,
            restrictions,
        })
    }
    fn retains(&self, old: &Self) -> Result<()> {
        require(self.root_highwater >= old.root_highwater, "state_conflict")?;
        require(old.hosts.is_subset(&self.hosts), "state_conflict")?;
        for (key, (version, hash)) in &old.maxima {
            let (next, next_hash) = self
                .maxima
                .get(key)
                .ok_or_else(|| Error::new("state_conflict"))?;
            require(
                next >= version && (next != version || hash == "-" || next_hash == hash),
                "state_conflict",
            )?;
        }
        for (id, row) in &old.restrictions {
            require(self.restrictions.get(id) == Some(row), "state_conflict")?;
        }
        Ok(())
    }
}
fn strings(o: &Obj, name: &str, valid: impl Fn(&str) -> bool) -> Result<BTreeSet<String>> {
    let mut result = BTreeSet::new();
    let mut previous = "";
    for value in array(o, name)? {
        let value = value.as_str().ok_or_else(|| Error::new("invalid"))?;
        check(valid(value) && value > previous)?;
        previous = value;
        result.insert(value.into());
    }
    Ok(result)
}
fn legacy_error(error: anyhow::Error) -> Error {
    if let Some(path) = error.downcast_ref::<crate::linking::PathError>() {
        Error {
            code: path.code,
            required_ids: path.required_ids.iter().cloned().collect(),
            stage: None,
            retry_after: None,
            detail: None,
        }
    } else {
        Error::new("invalid")
    }
}
fn legacy_source(
    descriptor: &[u8],
    catalog: &[u8],
    epoch: u64,
    feature: &str,
    now: &str,
) -> Result<crate::linking::NetworkState> {
    crate::linking::verify_stored_migration_source(
        crate::linking::CatalogFactContext {
            network: descriptor,
            epoch,
            known_feature_id: feature,
            now: stamp(now)?,
        },
        catalog,
    )
    .map_err(legacy_error)
}
pub(super) fn legacy_objects(
    network: &str,
    bytes: &[u8],
) -> Result<BTreeMap<String, (String, Vec<u8>)>> {
    let value = parse(bytes, 512 << 10)?;
    let o = object(&value)?;
    fields(o, "format network_id objects")?;
    version(o)?;
    check(text(o, "network_id")? == network)?;
    let mut proofs = BTreeMap::new();
    require(array(o, "objects")?.len() <= 4096, "quota_exceeded")?;
    let mut previous = "";
    for value in array(o, "objects")? {
        let row = object(value)?;
        fields(row, "id kind body_base64")?;
        let id = text(row, "id")?;
        let kind = text(row, "kind")?;
        check(ident(id, "pf_") && id > previous)?;
        previous = id;
        let body = b64(text(row, "body_base64")?, MAX_OBJECT)?;
        check(
            id == format!(
                "pf_{}",
                hash(&lines(&["peerspan-link-proof-v1", kind, &hash(&body)]))
            ),
        )?;
        proofs.insert(id.into(), (kind.into(), body));
    }
    Ok(proofs)
}
/// Strict local-context compatibility only. The independently verified source
/// still retains its original descriptor bytes and declared hashes.
pub(super) fn legacy_descriptor(bytes: &[u8]) -> Result<Obj> {
    let value = parse(bytes, MAX_OBJECT)?;
    let o = object(&value)?;
    fields(
        o,
        "network_id name genesis_root_public_key coordinator_address coordinator_public_key",
    )?;
    for field in [
        "network_id",
        "name",
        "genesis_root_public_key",
        "coordinator_address",
        "coordinator_public_key",
    ] {
        text(o, field)?;
    }
    Ok(o.clone())
}
/// Target decoding follows independently verified exact legacy catalog bytes.
/// Presence alone is not a local admission marker or a current restriction.
pub(super) fn source_restriction(id: &str, kind: &str, bytes: &[u8]) -> Result<Option<Obj>> {
    check(id == crate::link_runtime::catalog::proof_id(kind, bytes))?;
    let value = parse(bytes, MAX_OBJECT)?;
    let outer = object(&value)?;
    let mut target = outer.clone();
    let restrictive = if matches!(kind, "person_record" | "root_record") {
        let domain = text(outer, "kind")?;
        if !matches!(
            domain,
            "peerspan-person-remove-v1"
                | "peerspan-revoke-host-v1"
                | "peerspan-revoke-invite-v1"
                | "peerspan-host-unbind-v1"
                | "peerspan-admin-remove-v2"
        ) {
            return Ok(None);
        }
        target = object(&parse(
            &b64(text(outer, "payload_base64")?, MAX_PAYLOAD)?,
            MAX_PAYLOAD,
        )?)?
        .clone();
        true
    } else {
        matches!(
            kind,
            "admin_removal"
                | "person_removal"
                | "host_revocation"
                | "invite_revocation"
                | "host_leave"
                | "host_unbinding"
                | "device_revocation"
        )
    };
    if !restrictive {
        return Ok(None);
    }
    let mut row = object(&json!({"proof_id":id,"kind":kind,"person_public_key":"-","host_public_key":"-","device_public_key":"-"}))?.clone();
    for field in ["person_public_key", "host_public_key", "device_public_key"] {
        let name = if kind == "device_revocation" && field == "device_public_key" {
            "target_device_public_key"
        } else {
            field
        };
        let actual = target.get(name).and_then(Value::as_str).unwrap_or("-");
        check(actual == "-" || key(actual))?;
        row.insert(field.into(), Value::from(actual));
    }
    Ok(Some(row))
}
fn source_restrictions(
    source: &SourceState,
    proofs: &BTreeMap<String, (String, Vec<u8>)>,
) -> Result<()> {
    for (id, row) in &source.restrictions {
        let (kind, raw) = proofs.get(id).ok_or_else(|| Error::missing(id))?;
        check(source_restriction(id, kind, raw)?.as_ref() == Some(row))?;
    }
    Ok(())
}
/// An endorsed sticky source restriction narrows this migration's OLD source
/// roster only. It creates no DEC prior/admission, signer or normal permission.
pub(super) struct SourceContext<'a> {
    pub descriptor: &'a Descriptor,
    pub legacy_descriptor: &'a [u8],
    pub epoch: u64,
    pub feature: &'a str,
    pub root: &'a str,
    pub now: &'a str,
}
pub(super) fn source_snapshot(
    ctx: SourceContext<'_>,
    catalog: &[u8],
    state_bytes: &[u8],
) -> Result<(SourceState, crate::linking::NetworkState)> {
    let SourceContext {
        descriptor,
        legacy_descriptor,
        epoch,
        feature,
        root,
        now,
    } = ctx;
    let old_value = parse(legacy_descriptor, MAX_OBJECT)?;
    let old = object(&old_value)?;
    fields(
        old,
        "network_id name genesis_root_public_key coordinator_address coordinator_public_key",
    )?;
    check(
        text(old, "network_id")? == descriptor.network_id
            && text(old, "name")? == descriptor.name
            && text(old, "genesis_root_public_key")? == descriptor.genesis_root_public_key,
    )?;
    let source = SourceState::read(&descriptor.network_id, state_bytes)?;
    let mut facts = legacy_source(legacy_descriptor, catalog, epoch, feature, now)?;
    require(
        facts.epoch == epoch && facts.root_public_key == root && source.root_highwater == epoch,
        "state_conflict",
    )?;
    let proofs = legacy_objects(&descriptor.network_id, catalog)?;
    source_restrictions(&source, &proofs)?;
    for id in &facts.applicable_restrictions {
        let (kind, raw) = proofs.get(id).ok_or_else(|| Error::missing(id))?;
        if source_restriction(id, kind, raw)?.is_some() {
            require(source.restrictions.contains_key(id), "forbidden")?;
        }
    }
    for (id, row) in &source.restrictions {
        let (kind, raw) = &proofs[id];
        let body = parse(raw, MAX_OBJECT)?;
        let domain = if matches!(kind.as_str(), "person_record" | "root_record") {
            text(object(&body)?, "kind")?
        } else {
            kind.as_str()
        };
        let person = text(row, "person_public_key")?;
        let host = text(row, "host_public_key")?;
        match domain {
            "person_removal" | "peerspan-person-remove-v1" => {
                let p = facts.facts.state.persons.entry(person.into()).or_default();
                p.admitted = false;
                p.administrator = false;
                for owner in facts.facts.state.bindings.values_mut() {
                    if owner == person {
                        *owner = "-".into();
                    }
                }
            }
            "host_revocation" | "host_leave" | "peerspan-revoke-host-v1" => {
                facts.facts.state.hosts.insert(host.into(), false);
                facts.facts.state.bindings.insert(host.into(), "-".into());
            }
            "host_unbinding" | "peerspan-host-unbind-v1" => {
                if facts
                    .facts
                    .state
                    .bindings
                    .get(host)
                    .is_some_and(|p| p == person)
                {
                    facts.facts.state.bindings.insert(host.into(), "-".into());
                }
            }
            "admin_removal" | "peerspan-admin-remove-v2" => {
                facts
                    .facts
                    .state
                    .persons
                    .entry(person.into())
                    .or_default()
                    .administrator = false;
            }
            "device_revocation" => {
                facts
                    .facts
                    .state
                    .revoked_devices
                    .insert(crate::linking::DeviceKey {
                        person_public_key: person.into(),
                        device_public_key: text(row, "device_public_key")?.into(),
                    });
            }
            _ => {}
        }
    }
    facts
        .members
        .retain(|member| facts.facts.state.hosts.get(&member.host_public_key) == Some(&true));
    for member in &mut facts.members {
        let person = facts
            .facts
            .state
            .bindings
            .get(&member.host_public_key)
            .filter(|p| p.as_str() != "-")
            .cloned()
            .unwrap_or("-".into());
        if person == "-" {
            member.binding_proof_id = "-".into();
        }
        member.person_public_key = person;
    }
    let hosts: BTreeSet<_> = facts
        .members
        .iter()
        .map(|m| m.host_public_key.clone())
        .collect();
    require(source.hosts == hosts, "state_conflict")?;
    Ok((source, facts))
}

fn proposal_roster(p: &Obj, legacy: &crate::linking::NetworkState) -> Result<()> {
    let roster = array(p, "roster")?;
    check(roster.len() == legacy.members.len())?;
    for row in roster {
        let row = object(row)?;
        let host = text(row, "host_public_key")?;
        let member = legacy
            .members
            .iter()
            .find(|m| m.host_public_key == host)
            .ok_or_else(|| Error::new("invalid"))?;
        check(
            member.member == text(row, "member")?
                && member.person_public_key == text(row, "person_public_key")?,
        )?;
        if text(row, "person_public_key")? != "-" {
            let device = text(row, "device_public_key")?;
            let mut matched = false;
            for id in &legacy.facts.state.activated_certificates {
                let raw = legacy
                    .facts
                    .state
                    .certificates
                    .get(id)
                    .ok_or_else(|| Error::missing(id))?;
                let value = parse(raw, MAX_OBJECT)?;
                let c = object(&value)?;
                if text(c, "host_public_key")? == host && text(c, "device_public_key")? == device {
                    require(num(row, "scopes")? & !num(c, "scopes")? == 0, "forbidden")?;
                    matched = true;
                }
            }
            // A host without an old device may explicitly generate one;
            // an existing selected tuple may not be silently replaced.
            let known = legacy.facts.state.certificates.values().any(|raw| {
                parse(raw, MAX_OBJECT)
                    .ok()
                    .and_then(|v| {
                        v.get("host_public_key")
                            .and_then(Value::as_str)
                            .map(|h| h == host)
                    })
                    .unwrap_or(false)
            });
            require(!known || matched, "forbidden")?;
        }
    }
    Ok(())
}

/// Verify only the endorsed source portion of an exact six-field evidence
/// carrier. Later prepared/ACK/commit bytes are bounded, but are not evidence
/// for these source facts and are not authorized by this reader.
fn evidence_source(
    descriptor: &Descriptor,
    evidence: &Value,
) -> Result<(SourceState, crate::linking::NetworkState, Vec<u8>)> {
    let o = object(evidence)?;
    fields(
        o,
        "proposal_base64 source_catalog_base64 source_state_base64 prepared_catalog_base64 acknowledgments_base64 commit_base64",
    )?;
    let mut size = 0usize;
    for name in [
        "proposal_base64",
        "source_catalog_base64",
        "source_state_base64",
        "prepared_catalog_base64",
        "commit_base64",
    ] {
        size += text(o, name)?.len();
    }
    let acknowledgments = array(o, "acknowledgments_base64")?;
    require(acknowledgments.len() <= MAX_ITEMS, "quota_exceeded")?;
    for ack in acknowledgments {
        size = size
            .checked_add(ack.as_str().ok_or_else(|| Error::new("invalid"))?.len())
            .ok_or_else(|| Error::new("quota_exceeded"))?;
    }
    require(size <= 20 << 20, "quota_exceeded")?;
    for name in ["prepared_catalog_base64", "commit_base64"] {
        if text(o, name)? != "-" {
            b64(text(o, name)?, MAX_OBJECT)?;
        }
    }
    for ack in acknowledgments {
        b64(
            ack.as_str().ok_or_else(|| Error::new("invalid"))?,
            MAX_OBJECT,
        )?;
    }
    let proposal = Statement::read(descriptor, &b64(text(o, "proposal_base64")?, MAX_OBJECT)?)?;
    check(proposal.kind == "migration_proposal")?;
    let p = &proposal.payload;
    let catalog = b64(text(o, "source_catalog_base64")?, 512 << 10)?;
    let state = b64(text(o, "source_state_base64")?, MAX_PAYLOAD)?;
    check(
        hash(&catalog) == text(p, "source_catalog_sha256")?
            && hash(&state) == text(p, "source_state_sha256")?,
    )?;
    let (source, legacy) = source_snapshot(
        SourceContext {
            descriptor,
            legacy_descriptor: &b64(text(p, "legacy_descriptor_base64")?, MAX_OBJECT)?,
            epoch: num(p, "legacy_epoch")?,
            feature: text(p, "legacy_feature_id")?,
            root: text(p, "legacy_root_public_key")?,
            now: text(p, "issued_at")?,
        },
        &catalog,
        &state,
    )?;
    proposal_roster(p, &legacy)?;
    Ok((source, legacy, catalog))
}

/// Return source-admitted person labels authenticated by the exact signed
/// proposal and frozen legacy source. This performs no local-time, provider,
/// approval, admission or adoption decision.
pub fn migration_person_labels(
    descriptor: &Descriptor,
    evidence: &Value,
) -> Result<BTreeMap<String, String>> {
    let (_, legacy, _) = evidence_source(descriptor, evidence)?;
    legacy
        .facts
        .state
        .persons
        .iter()
        .filter(|(_, p)| p.admitted)
        .map(|(person, _)| {
            let member = legacy
                .facts
                .person_labels
                .get(person)
                .ok_or_else(|| Error::new("state_conflict"))?;
            Ok((person.clone(), member.clone()))
        })
        .collect()
}

/// Derive inherited irreversible ban targets and ALL exact endorsed source
/// proof IDs for each target. These are preparation facts, never authority or
/// permission to sign; current local signing checks remain separate.
pub fn migration_inherited_bans(descriptor: &Descriptor, evidence: &Value) -> Result<Vec<Value>> {
    let (source, legacy, catalog) = evidence_source(descriptor, evidence)?;
    Ok(inherited_bans(&source, &catalog, &legacy)?
        .into_iter()
        .map(|((kind, person, host, device), proofs)| {
            json!({"kind":kind,"person_public_key":person,"host_public_key":host,
                "device_public_key":device,"source_proof_ids":proofs})
        })
        .collect())
}

pub(super) type BanTarget = (String, String, String, String);

pub(super) fn inherited_bans(
    source_state: &SourceState,
    source_catalog: &[u8],
    legacy: &crate::linking::NetworkState,
) -> Result<BTreeMap<BanTarget, BTreeSet<String>>> {
    let mut required_bans = BTreeMap::<BanTarget, BTreeSet<String>>::new();
    let source_proofs = legacy_objects(&legacy.facts.network_id, source_catalog)?;
    for (id, row) in &source_state.restrictions {
        let (kind, raw) = &source_proofs[id];
        let value = parse(raw, MAX_OBJECT)?;
        let outer = object(&value)?;
        let domain = if matches!(kind.as_str(), "person_record" | "root_record") {
            text(outer, "kind")?
        } else {
            kind
        };
        let modern = match domain {
            "person_removal" | "peerspan-person-remove-v1" => "person_remove",
            "host_revocation" | "peerspan-revoke-host-v1" => "host_revoke",
            "device_revocation" => "device_revoke",
            _ => continue,
        };
        required_bans
            .entry((
                modern.to_owned(),
                text(row, "person_public_key")?.to_owned(),
                text(row, "host_public_key")?.to_owned(),
                text(row, "device_public_key")?.to_owned(),
            ))
            .or_default()
            .insert(id.clone());
    }
    // The complete verified old device-ban set cannot disappear from the
    // signed source-state snapshot even if a source writer omitted its row.
    for revoked in &legacy.facts.state.revoked_devices {
        check(required_bans.keys().any(|(kind, person, _, device)| {
            kind == "device_revoke"
                && person == &revoked.person_public_key
                && device == &revoked.device_public_key
        }))?;
    }
    let removed_people: BTreeSet<_> = required_bans
        .keys()
        .filter(|(kind, _, _, _)| kind == "person_remove")
        .map(|(_, person, _, _)| person.clone())
        .collect();
    required_bans.retain(|(kind, person, _, _), _| {
        kind != "device_revoke" || !removed_people.contains(person)
    });
    Ok(required_bans)
}

pub(super) fn prepared_components(
    proposal: &Statement,
    source_state: &SourceState,
    source_catalog: &[u8],
    legacy: &crate::linking::NetworkState,
    prepared: &Catalog,
    root_id: &str,
) -> Result<BTreeMap<String, super::transcript::Activation>> {
    let p = &proposal.payload;
    let proposal = &proposal.id;
    let mut people = BTreeMap::new();
    let mut operations = BTreeMap::new();
    let mut host_leases = BTreeSet::new();
    let required_bans: BTreeSet<_> = inherited_bans(source_state, source_catalog, legacy)?
        .into_keys()
        .collect();
    let mut present_bans = BTreeSet::new();
    for proof in prepared.proofs.values().filter(|p| p.kind == "activation") {
        let activation = super::transcript::Activation::read(
            &Descriptor::from_value(value_field(p, "new_descriptor")?)?,
            &proof.body,
        )?;
        let request = &activation.packets["request"];
        check(
            text(&request.payload, "migration_proposal_id")? == proposal
                && text(&request.payload, "mode")? == "new"
                && text(&activation.manifest, "root_state_id")? == root_id
                && text(&activation.packets["owner"].object, "issuer_id")? == "-"
                && text(
                    &activation.packets["owner_finalization"].object,
                    "issuer_id",
                )? == "-",
        )?;
        let host = text(&request.payload, "host_public_key")?;
        if let Some(old) = operations.insert(host.to_owned(), activation.clone()) {
            check(old.id == activation.id)?;
        }
    }
    for statement in prepared.statements.values() {
        if matches!(statement.kind.as_str(), "root_state" | "migration_proposal") {
            continue;
        }
        check(text(&statement.payload, "root_state_id")? == root_id)?;
        let issued = stamp(statement.issued_at()?)?;
        check(issued >= stamp(text(p, "issued_at")?)? && issued < stamp(text(p, "expires_at")?)?)?;
        match statement.kind.as_str() {
            "person_lease" => {
                let person = text(statement.subject()?, "person_public_key")?;
                check(
                    people
                        .insert(person.to_owned(), statement.id.clone())
                        .is_none()
                        && statement.sequence()? == 1
                        && text(statement.issuer()?, "kind")? == "root"
                        && text(&statement.payload, "operation_id")? == "-",
                )?;
                require(
                    legacy
                        .facts
                        .state
                        .persons
                        .get(person)
                        .is_some_and(|p| p.admitted),
                    "forbidden",
                )?;
                let member = legacy
                    .facts
                    .person_labels
                    .get(person)
                    .ok_or_else(|| Error::new("state_conflict"))?;
                check(text(statement.subject()?, "member")? == member)?;
            }
            "admin_lease" | "group" => {
                check(text(statement.issuer()?, "kind")? == "root")?;
            }
            "host_lease" => {
                let host = text(statement.subject()?, "host_public_key")?;
                check(
                    host_leases.insert(host.to_owned())
                        && text(statement.issuer()?, "kind")? == "root",
                )?;
                let row = array(p, "roster")?
                    .iter()
                    .find(|r| r.get("host_public_key").and_then(Value::as_str) == Some(host))
                    .ok_or_else(|| Error::new("invalid"))?;
                let row = object(row)?;
                let operation = text(&statement.payload, "operation_id")?;
                check(
                    text(statement.subject()?, "member")? == text(row, "member")?
                        && if text(row, "person_public_key")? == "-" {
                            operation == proposal
                        } else {
                            ident(operation, "link_")
                        },
                )?;
            }
            "binding_lease" | "device_lease" => {
                let subject = statement.subject()?;
                let host = text(subject, "host_public_key")?;
                let row = array(p, "roster")?
                    .iter()
                    .find(|r| r.get("host_public_key").and_then(Value::as_str) == Some(host))
                    .ok_or_else(|| Error::new("invalid"))?;
                let row = object(row)?;
                let person = text(row, "person_public_key")?;
                check(
                    person != "-"
                        && text(subject, "person_public_key")? == person
                        && text(subject, "member")? == "-"
                        && text(statement.issuer()?, "kind")? == "person"
                        && text(statement.issuer()?, "person_public_key")? == person
                        && ident(text(&statement.payload, "operation_id")?, "link_"),
                )?;
                if statement.kind == "device_lease" {
                    check(
                        text(subject, "device_public_key")? == text(row, "device_public_key")?
                            && num(subject, "scopes")? == num(row, "scopes")?,
                    )?;
                }
            }
            "policy" => {
                check(text(statement.issuer()?, "kind")? == "person")?;
            }
            "person_remove" | "host_revoke" | "device_revoke" => {
                check(
                    text(statement.issuer()?, "kind")?
                        == if statement.kind == "device_revoke" {
                            "person"
                        } else {
                            "root"
                        },
                )?;
                let target = object(value_field(&statement.payload, "target")?)?;
                let entry = (
                    statement.kind.clone(),
                    text(target, "person_public_key")?.to_owned(),
                    text(target, "host_public_key")?.to_owned(),
                    text(target, "device_public_key")?.to_owned(),
                );
                check(required_bans.contains(&entry))?;
                present_bans.insert(entry);
            }
            _ => return Err(Error::new("invalid")),
        }
        if super::statement::lease(&statement.kind) {
            check(
                statement.sequence()? == 1
                    && ids(&statement.payload, "predecessors", "ds_")?.is_empty()
                    && ids(&statement.payload, "resolves", "ds_")?.is_empty()
                    && ids(&statement.payload, "retained_statement_ids", "ds_")?.is_empty(),
            )?;
        }
        if matches!(statement.kind.as_str(), "policy" | "group") {
            let body = super::statement::access_body(&statement.payload)?;
            let subject = if statement.kind == "policy" {
                text(&body, "person_public_key")?
            } else {
                text(&body, "name")?
            };
            if let Some((floor, _)) = source_state
                .maxima
                .get(&(statement.kind.clone(), subject.into()))
            {
                require(statement.sequence()? > *floor, "state_conflict")?;
            }
        }
    }
    let expected_people: BTreeSet<_> = legacy
        .facts
        .state
        .persons
        .iter()
        .filter(|(_, p)| p.admitted)
        .map(|(key, _)| key.clone())
        .collect();
    require(
        people.keys().cloned().collect::<BTreeSet<_>>() == expected_people,
        "proof_required",
    )
    .map_err(|_| Error::missing(proposal))?;
    for statement in prepared
        .statements
        .values()
        .filter(|s| matches!(s.kind.as_str(), "binding_lease" | "device_lease"))
    {
        let person = text(statement.subject()?, "person_public_key")?;
        let shared = people.get(person).ok_or_else(|| Error::missing(proposal))?;
        let parents = statement.parents()?;
        check(
            parents.get("subject_person") == Some(shared)
                && parents.get("issuer_person") == Some(shared),
        )?;
    }
    let mut owned = 0usize;
    for row in array(p, "roster")? {
        let row = object(row)?;
        let host = text(row, "host_public_key")?;
        require(host_leases.contains(host), "proof_required")
            .map_err(|_| Error::missing(proposal))?;
        if text(row, "person_public_key")? == "-" {
            check(!operations.contains_key(host))?;
            let h = prepared
                .statements
                .values()
                .find(|s| {
                    s.kind == "host_lease"
                        && s.subject()
                            .is_ok_and(|sub| text(sub, "host_public_key").is_ok_and(|h| h == host))
                })
                .ok_or_else(|| Error::missing(proposal))?;
            check(text(&h.payload, "operation_id")? == proposal)?;
            continue;
        }
        owned += 1;
        let activation = operations
            .get(host)
            .ok_or_else(|| Error::missing(proposal))?;
        let device = prepared.get(text(&activation.manifest, "device_lease_id")?)?;
        check(
            text(&activation.packets["owner"].object, "person_public_key")?
                == text(row, "person_public_key")?
                && text(&activation.packets["request"].payload, "device_public_key")?
                    == text(row, "device_public_key")?
                && num(device.subject()?, "scopes")? == num(row, "scopes")?,
        )?;
    }
    check(operations.len() == owned && host_leases.len() == array(p, "roster")?.len())?;
    require(present_bans == required_bans, "forbidden")?;
    Ok(operations)
}

fn validate_prepared(migration: &Migration) -> Result<()> {
    let mut operations = prepared_components(
        &migration.proposal,
        &migration.source_state,
        &migration.source_catalog,
        &migration.legacy,
        &migration.prepared,
        &migration.root_id,
    )?;
    let p = &migration.proposal.payload;
    for row in array(p, "roster")? {
        let row = object(row)?;
        if text(row, "person_public_key")? == "-" {
            continue;
        }
        let host = text(row, "host_public_key")?;
        let activation = operations
            .remove(host)
            .ok_or_else(|| Error::missing(&migration.proposal.id))?;
        let ack = migration
            .acknowledgments
            .get(host)
            .ok_or_else(|| Error::missing(&migration.proposal.id))?;
        for name in ["host_lease_id", "binding_lease_id", "device_lease_id"] {
            check(text(&activation.manifest, name)? == text(&ack.payload, name)?)?;
        }
        check(activation.id == text(&ack.payload, "activation_id")?)?;
    }
    check(operations.is_empty())
}

pub(crate) struct Migration {
    pub proposal: Statement,
    pub commit: Statement,
    pub source_state: SourceState,
    pub prepared: Catalog,
    pub root_id: String,
    pub acknowledgments: BTreeMap<String, Statement>,
    pub source_catalog: Vec<u8>,
    pub legacy_descriptor: Vec<u8>,
    pub legacy: crate::linking::NetworkState,
}
impl std::fmt::Debug for Migration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Migration")
            .field("proposal_id", &self.proposal.id)
            .field("root_id", &self.root_id)
            .finish_non_exhaustive()
    }
}
impl Migration {
    pub(crate) fn read(descriptor: &Descriptor, bytes: &[u8]) -> Result<Self> {
        let value = parse(bytes, MAX_OBJECT)?;
        let o = object(&value)?;
        fields(
            o,
            "format proposal source_catalog_base64 source_state_base64 prepared_catalog_base64 acknowledgments commit",
        )?;
        version(o)?;
        let proposal = Statement::read(descriptor, &raw_field(bytes, "proposal")?)?;
        check(proposal.kind == "migration_proposal")?;
        let p = &proposal.payload;
        let legacy_descriptor = b64(text(p, "legacy_descriptor_base64")?, MAX_OBJECT)?;
        let old_value = parse(&legacy_descriptor, MAX_OBJECT)?;
        let old = object(&old_value)?;
        fields(
            old,
            "network_id name genesis_root_public_key coordinator_address coordinator_public_key",
        )?;
        check(
            text(old, "network_id")? == descriptor.network_id
                && text(old, "name")? == descriptor.name
                && text(old, "genesis_root_public_key")? == descriptor.genesis_root_public_key,
        )?;
        let source_catalog = b64(text(o, "source_catalog_base64")?, 512 << 10)?;
        let state_bytes = b64(text(o, "source_state_base64")?, 512 << 10)?;
        check(
            hash(&source_catalog) == text(p, "source_catalog_sha256")?
                && hash(&state_bytes) == text(p, "source_state_sha256")?,
        )?;
        let epoch = num(p, "legacy_epoch")?;
        let (source_state, legacy) = source_snapshot(
            SourceContext {
                descriptor,
                legacy_descriptor: &legacy_descriptor,
                epoch,
                feature: text(p, "legacy_feature_id")?,
                root: text(p, "legacy_root_public_key")?,
                now: text(p, "issued_at")?,
            },
            &source_catalog,
            &state_bytes,
        )?;
        proposal_roster(p, &legacy)?;
        let roster = array(p, "roster")?;
        let prepared_bytes = b64(text(o, "prepared_catalog_base64")?, MAX_OBJECT)?;
        let prepared = Catalog::read_prepared(descriptor, &prepared_bytes)?;
        check(!prepared.proofs.values().any(|p| {
            matches!(
                p.kind.as_str(),
                "migration" | "migration_ack" | "migration_commit"
            )
        }))?;
        let roots: Vec<_> = prepared
            .statements
            .values()
            .filter(|s| s.kind == "root_state")
            .collect();
        check(roots.len() == 1)?;
        let root = roots[0];
        check(
            num(&root.payload, "epoch")? == epoch
                && text(&root.payload, "root_public_key")? == legacy.root_public_key
                && text(&root.payload, "migration_proposal_id")? == proposal.id
                && text(&root.payload, "issued_at")? == text(p, "issued_at")?
                && ids(&root.payload, "predecessors", "ds_")?.is_empty()
                && ids(&root.payload, "retained_statement_ids", "ds_")?.is_empty(),
        )?;
        let root_id = root.id.clone();
        check(prepared.get(&proposal.id)?.payload_bytes == proposal.payload_bytes)?;
        let mut acknowledgments = BTreeMap::new();
        let mut previous = String::new();
        for raw in raw_array_field(bytes, "acknowledgments")? {
            let ack = Statement::read(descriptor, &raw)?;
            check(ack.kind == "migration_ack")?;
            let a = &ack.payload;
            let host = text(a, "host_public_key")?.to_owned();
            check(host > previous)?;
            previous = host.clone();
            check(
                text(a, "proposal_id")? == proposal.id
                    && text(a, "root_state_id")? == root_id
                    && text(a, "prepared_catalog_sha256")? == hash(&prepared_bytes),
            )?;
            let at = stamp(text(a, "acknowledged_at")?)?;
            check(at >= stamp(text(p, "issued_at")?)? && at < stamp(text(p, "expires_at")?)?)?;
            let row = roster
                .iter()
                .map(object)
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .find(|r| text(r, "host_public_key").is_ok_and(|h| h == host))
                .ok_or_else(|| Error::new("invalid"))?;
            check(
                text(a, "person_public_key")? == text(row, "person_public_key")?
                    && text(a, "device_public_key")? == text(row, "device_public_key")?,
            )?;
            let h = prepared.get(text(a, "host_lease_id")?)?;
            check(
                h.kind == "host_lease"
                    && text(h.subject()?, "host_public_key")? == host
                    && text(h.subject()?, "member")? == text(row, "member")?,
            )?;
            if text(row, "person_public_key")? == "-" {
                check(
                    text(&h.payload, "operation_id")? == proposal.id
                        && text(h.issuer()?, "kind")? == "root"
                        && text(&h.payload, "root_state_id")? == root_id
                        && h.signer("issuer")?.public_key == legacy.root_public_key,
                )?;
            } else {
                let b = prepared.get(text(a, "binding_lease_id")?)?;
                let d = prepared.get(text(a, "device_lease_id")?)?;
                check(
                    b.kind == "binding_lease"
                        && d.kind == "device_lease"
                        && text(b.subject()?, "host_public_key")? == host
                        && text(d.subject()?, "host_public_key")? == host
                        && text(b.subject()?, "person_public_key")?
                            == text(row, "person_public_key")?
                        && text(d.subject()?, "person_public_key")?
                            == text(row, "person_public_key")?
                        && text(d.subject()?, "device_public_key")?
                            == text(row, "device_public_key")?
                        && num(d.subject()?, "scopes")? == num(row, "scopes")?,
                )?;
            }
            acknowledgments.insert(host, ack);
        }
        let commit = Statement::read(descriptor, &raw_field(bytes, "commit")?)?;
        check(
            commit.kind == "migration_commit"
                && commit.signer("issuer")?.public_key == legacy.root_public_key,
        )?;
        let c = &commit.payload;
        check(
            text(c, "proposal_id")? == proposal.id
                && text(c, "root_state_id")? == root_id
                && text(c, "prepared_catalog_sha256")? == hash(&prepared_bytes),
        )?;
        let at = stamp(text(c, "committed_at")?)?;
        check(at >= stamp(text(p, "issued_at")?)? && at < stamp(text(p, "expires_at")?)?)?;
        let present: BTreeSet<_> = acknowledgments.values().map(|a| a.id.clone()).collect();
        let required: BTreeSet<_> = ids(c, "acknowledgment_ids", "ds_")?.into_iter().collect();
        if let Some(missing) = required.difference(&present).next() {
            return Err(Error::missing(missing));
        }
        check(required == present && acknowledgments.len() == roster.len())?;
        let result = Self {
            proposal,
            commit,
            source_state,
            prepared,
            root_id,
            acknowledgments,
            source_catalog,
            legacy_descriptor,
            legacy,
        };
        validate_prepared(&result)?;
        super::state::Projection::stage_migration(
            descriptor,
            &result.prepared.bytes,
            text(&result.proposal.payload, "issued_at")?,
            &result.proposal.id,
            &result.root_id,
            &result.source_state.maxima,
        )?;
        Ok(result)
    }
}

pub(crate) fn verify(
    descriptor: &Descriptor,
    legacy_prior: &Value,
    prior: &Value,
    bytes: &[u8],
    now: &str,
    purpose: &str,
    local_host: &str,
) -> Result<Value> {
    check(matches!(purpose, "evidence" | "adoption") && (local_host == "-" || key(local_host)))?;
    let migration = Migration::read(descriptor, bytes)?;
    let p = &migration.proposal.payload;
    let mut decision = decision_clock(now, "-")?;
    if let Some(prior) = prior.as_object() {
        require(
            text(prior, "context_id")? == descriptor.context_id(),
            "state_conflict",
        )?;
        let proposal = text(prior, "migration_proposal_id")?;
        require(
            proposal == "-" || proposal == migration.proposal.id,
            "state_conflict",
        )?;
        decision = decision_clock(&decision, text(prior, "clock_guard")?)?;
        if let Some(known) = super::state::Prior::read(descriptor, &Value::Object(prior.clone()))? {
            for origin in known.catalog.migrations.values() {
                require(
                    origin.proposal.id == migration.proposal.id
                        && hash(&origin.prepared.bytes) == hash(&migration.prepared.bytes),
                    "state_conflict",
                )?;
            }
        }
    } else {
        check(prior.as_str() == Some("-"))?;
    }
    let mut matched = false;
    if let Some(old) = legacy_prior.as_object() {
        fields(
            old,
            "format legacy_descriptor_base64 legacy_catalog_base64 legacy_feature_id legacy_epoch legacy_root_public_key source_state_base64 clock_guard pending_operation_ids acknowledged_proposal_id acknowledged_prepared_sha256 acknowledgment_base64 adopted_context_id adopted_proposal_id",
        )?;
        version(old)?;
        decision = decision_clock(&decision, text(old, "clock_guard")?)?;
        let known_descriptor = b64(text(old, "legacy_descriptor_base64")?, MAX_OBJECT)?;
        let known_catalog = b64(text(old, "legacy_catalog_base64")?, 512 << 10)?;
        let epoch = num(old, "legacy_epoch")?;
        let known = legacy_source(
            &known_descriptor,
            &known_catalog,
            epoch,
            text(old, "legacy_feature_id")?,
            text(p, "issued_at")?,
        )?;
        require(
            legacy_descriptor(&known_descriptor)?
                == legacy_descriptor(&migration.legacy_descriptor)?,
            "state_conflict",
        )?;
        require(
            known.root_public_key == text(old, "legacy_root_public_key")?
                && epoch == migration.legacy.epoch
                && known.root_public_key == migration.legacy.root_public_key
                && text(old, "legacy_feature_id")? == text(p, "legacy_feature_id")?,
            "state_conflict",
        )?;
        let old_state = SourceState::read(
            &descriptor.network_id,
            &b64(text(old, "source_state_base64")?, MAX_PAYLOAD)?,
        )?;
        migration.source_state.retains(&old_state)?;
        require(
            array(old, "pending_operation_ids")?.is_empty(),
            "recovery_required",
        )?;
        let origin = text(old, "adopted_context_id")?;
        let proposal = text(old, "adopted_proposal_id")?;
        require(
            (origin == "-" || origin == descriptor.context_id())
                && (proposal == "-" || proposal == migration.proposal.id),
            "state_conflict",
        )?;
        let proposal = text(old, "acknowledged_proposal_id")?;
        let prepared = text(old, "acknowledged_prepared_sha256")?;
        require(
            (proposal == "-" || proposal == migration.proposal.id)
                && (prepared == "-" || prepared == hash(&migration.prepared.bytes)),
            "state_conflict",
        )?;
        if text(old, "acknowledgment_base64")? != "-" {
            let ack = Statement::read(
                descriptor,
                &b64(text(old, "acknowledgment_base64")?, MAX_OBJECT)?,
            )?;
            matched = migration
                .acknowledgments
                .get(local_host)
                .is_some_and(|a| a.body == ack.body)
                && proposal == migration.proposal.id
                && prepared == hash(&migration.prepared.bytes);
        }
        // The proposed source must contain every exact locally retained proof.
        let old_proofs = legacy_objects(&descriptor.network_id, &known_catalog)?;
        let proposed = legacy_objects(&descriptor.network_id, &migration.source_catalog)?;
        for (id, proof) in old_proofs {
            require(proposed.get(&id) == Some(&proof), "state_conflict")?;
        }
    } else {
        check(legacy_prior.as_str() == Some("-"))?;
    }
    require(purpose != "adoption" || matched, "forbidden")?;
    // Origin evidence authenticates the frozen preparation; current usability
    // must also preserve ALL independently retained restrictions/heads/floors.
    // A complete migration is a catalog object, so use the same union and
    // current graph gate as ordinary repair instead of replaying the prepared
    // snapshot in isolation from the caller's trusted current prior.
    let carrier = serde_json::to_vec(&json!({"format":1,"context_id":descriptor.context_id(),"objects":[{"id":super::statement::proof_id("migration",bytes),"kind":"migration","body_base64":encode(bytes)}]})).map_err(|_| Error::new("internal"))?;
    let projected =
        super::state::Projection::build(descriptor, prior, Some(&carrier), &decision, "repair")?;
    let mut usable = BTreeSet::new();
    let mut inactive = BTreeSet::new();
    for ack in migration.acknowledgments.values() {
        let device = text(&ack.payload, "device_lease_id")?;
        if device != "-" {
            if projected.active(device).is_ok() && projected.admitted.contains(device) {
                usable.insert(device);
            } else {
                inactive.insert(device);
            }
        }
    }
    Ok(
        json!({"ok":true,"context_id":descriptor.context_id(),"proposal_id":migration.proposal.id,"root_state_id":migration.root_id,"prepared_catalog_sha256":hash(&migration.prepared.bytes),"roster_host_public_keys":migration.acknowledgments.keys().collect::<Vec<_>>(),"local_approval_matched":matched,"context_origin_valid":true,"usable_device_lease_ids":usable,"inactive_device_lease_ids":inactive}),
    )
}
