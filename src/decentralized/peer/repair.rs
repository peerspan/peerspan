//! A deliberately non-actionable view of durable identity provenance. Missing
//! authority bodies may be fetched, never inferred from contacts or metadata.
use super::*;
use std::collections::BTreeSet;
fn db(error: rusqlite::Error) -> Error {
    match error {
        rusqlite::Error::QueryReturnedNoRows => Error::new("not_found"),
        rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..) => Error::new("state_conflict"),
        _ => Error::new("internal"),
    }
}

pub(super) struct View {
    pub network: super::super::storage::NetworkRecord,
    pub descriptor: super::super::Descriptor,
    pub catalog: super::super::Catalog,
    pub guard: String,
    pub hosts: BTreeSet<String>,
    banned: BTreeSet<String>,
    required: BTreeSet<String>,
}
impl View {
    pub fn load(c: &Connection, network: &str, own: &str) -> Result<Self> {
        Self::load_inner(c, network, own).map_err(|mut error| {
            if error.code == "invalid" {
                error.code = "state_conflict";
            }
            error
        })
    }
    fn load_inner(c: &Connection, network: &str, own: &str) -> Result<Self> {
        check(ident(network, "net_") && key(own))?;
        let raw: String = c
            .query_row("SELECT record FROM networks WHERE id=?1", [network], |r| {
                r.get(0)
            })
            .map_err(db)?;
        let value = parse(raw.as_bytes(), 32 << 20)?;
        let o = object(&value)?;
        require(
            o.get("mode").and_then(Value::as_str) == Some("decentralized"),
            "upgrade_required",
        )?;
        fields(
            o,
            "format mode descriptor_base64 context_id root_state_id own_identity created_at",
        )?;
        check(num(o, "format")? == 2)?;
        let record: super::super::storage::NetworkRecord =
            serde_json::from_value(value).map_err(|_| Error::new("state_conflict"))?;
        let descriptor =
            super::super::Descriptor::read(&b64(&record.descriptor_base64, MAX_OBJECT)?)?;
        check(
            descriptor.network_id == network
                && descriptor.context_id() == record.context_id
                && record.own_identity.host_public_key == own,
        )?;
        check(record.root_state_id == "-" || ident(&record.root_state_id, "ds_"))?;
        check(
            record.own_identity.person_public_key == "-"
                || key(&record.own_identity.person_public_key),
        )?;
        if record.own_identity.member != "-" {
            label(&record.own_identity.member)?;
        }
        stamp(&record.created_at)?;
        let raw: String = c
            .query_row(
                "SELECT record FROM dec_contexts WHERE network_id=?1 AND context_id=?2",
                params![network, record.context_id],
                |r| r.get(0),
            )
            .map_err(db)?;
        let value = parse(raw.as_bytes(), 32 << 20)?;
        fields(
            object(&value)?,
            "format descriptor_base64 origin initial_root_state_id origin_proof_id migration_proposal_id adopted_at",
        )?;
        version(object(&value)?)?;
        let context: super::super::storage::ContextRecord =
            serde_json::from_value(value).map_err(|_| Error::new("state_conflict"))?;
        check(
            context.descriptor_base64 == record.descriptor_base64
                && ident(&context.initial_root_state_id, "ds_")
                && ident(&context.origin_proof_id, "dp_"),
        )?;
        check(match context.origin.as_str() {
            "genesis" => context.migration_proposal_id == "-",
            "migration" => ident(&context.migration_proposal_id, "ds_"),
            _ => false,
        })?;
        stamp(&context.adopted_at)?;
        let mut objects = Vec::new();
        let mut query=c.prepare("SELECT proof_id,kind,body FROM dec_objects WHERE network_id=?1 AND context_id=?2 ORDER BY proof_id").map_err(db)?;
        let rows = query
            .query_map(params![network, record.context_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(db)?;
        for row in rows {
            let (id, kind, body) = row.map_err(db)?;
            objects.push(json!({"id":id,"kind":kind,"body_base64":encode(&body)}));
        }
        let catalog = super::super::Catalog::read(
            &descriptor,
            &encode_json(&json!({"format":1,"context_id":record.context_id,"objects":objects}))?,
        )?;
        let raw: String = c
            .query_row(
                "SELECT record FROM dec_clock WHERE network_id=?1",
                [network],
                |r| r.get(0),
            )
            .map_err(db)?;
        let value = parse(raw.as_bytes(), 32 << 20)?;
        let o = object(&value)?;
        fields(o, "format largest_local_time")?;
        version(o)?;
        let guard = text(o, "largest_local_time")?.to_owned();
        stamp(&guard)?;
        check(guard >= record.created_at && guard >= context.adopted_at)?;
        let mut required = BTreeSet::from([context.origin_proof_id]);
        let mut hosts = BTreeSet::new();
        let mut banned = BTreeSet::new();
        for (table, id_column, restriction) in [
            ("dec_admissions", "statement_id", false),
            ("dec_restrictions", "restriction_id", true),
        ] {
            let mut query=c.prepare(&format!("SELECT {id_column},record FROM {table} WHERE network_id=?1 AND context_id=?2 ORDER BY {id_column}")).map_err(db)?;
            let rows = query
                .query_map(params![network, record.context_id], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })
                .map_err(db)?;
            for row in rows {
                let (id, raw) = row.map_err(db)?;
                check(ident(&id, "ds_"))?;
                let marker = super::super::storage::marker(&raw, restriction)?;
                let proof = text(&marker, "proof_id")?;
                check(text(&marker, "admitted_at")? <= guard.as_str())?;
                let kind = text(&marker, "kind")?;
                check(super::super::statement::restriction(kind) == restriction)?;
                if !restriction {
                    check(matches!(
                        kind,
                        "root_state"
                            | "admin_lease"
                            | "person_lease"
                            | "host_lease"
                            | "binding_lease"
                            | "device_lease"
                            | "policy"
                            | "group"
                    ))?;
                }
                if restriction
                    || !matches!(kind, "root_state" | "policy" | "group")
                    || catalog.statements.contains_key(&id)
                {
                    required.insert(proof.to_owned());
                }
                if kind != "host_lease" && !restriction {
                    continue;
                }
                // An exact retained H body plus its independently durable H-ID
                // admission is identity memory, even when its original public
                // container needs repair. No fresh admission follows from it.
                let Some(statement) = catalog.statements.get(&id) else {
                    if restriction {
                        return Err(Error::missing(proof));
                    }
                    continue;
                };
                check(statement.kind == kind)?;
                if catalog.proofs.contains_key(proof) {
                    check(
                        catalog
                            .statement_proofs
                            .get(&id)
                            .is_some_and(|ids| ids.iter().any(|p| p == proof)),
                    )?;
                }
                if kind == "host_lease" {
                    hosts.insert(text(statement.subject()?, "host_public_key")?.to_owned());
                }
                if kind == "host_revoke" {
                    let target = object(
                        statement
                            .payload
                            .get("target")
                            .ok_or_else(|| Error::new("state_conflict"))?,
                    )?;
                    banned.insert(text(target, "host_public_key")?.to_owned());
                }
            }
        }
        Ok(Self {
            network: record,
            descriptor,
            catalog,
            guard,
            hosts,
            banned,
            required,
        })
    }
    pub fn remembered(&self, host: &str) -> Result<()> {
        require(
            self.hosts.contains(host) && !self.banned.contains(host),
            "forbidden",
        )
    }
    /// Restore only exact proof bodies referenced by PREEXISTING local markers.
    /// The surrounding writer transaction rolls these bytes back unless the
    /// ordinary strict snapshot and full candidate verification both succeed.
    pub fn restore(&self, c: &Connection, candidate: &[u8]) -> Result<()> {
        let incoming = super::super::Catalog::read(&self.descriptor, candidate)?;
        let union = super::super::Catalog::union(&self.descriptor, &self.catalog, &incoming)?;
        let missing: BTreeSet<_> = self
            .required
            .iter()
            .filter(|id| !self.catalog.proofs.contains_key(*id) && union.proof(id).is_err())
            .cloned()
            .collect();
        if !missing.is_empty() {
            let mut error = Error::new("proof_required");
            error.required_ids = missing;
            return Err(error);
        }
        for id in &self.required {
            if self.catalog.proofs.contains_key(id) {
                continue;
            }
            let proof = union.proof(id)?;
            c.execute("INSERT INTO dec_objects(network_id,context_id,proof_id,kind,body) VALUES(?1,?2,?3,?4,?5)",params![self.descriptor.network_id,self.network.context_id,id,proof.kind,proof.body]).map_err(db)?;
        }
        Ok(())
    }
}
