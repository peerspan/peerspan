use super::{
    codec::*,
    statement::{Descriptor, Statement, proof_id},
};
use serde_json::Value;
use std::{collections::BTreeMap, sync::Arc};

#[derive(Clone, Debug)]
pub struct Proof {
    pub id: String,
    pub kind: String,
    pub body: Vec<u8>,
}
#[derive(Clone, Debug)]
pub struct Catalog {
    pub context_id: String,
    pub bytes: Vec<u8>,
    pub proofs: BTreeMap<String, Proof>,
    pub statements: BTreeMap<String, Statement>,
    pub aliases: BTreeMap<String, Vec<Statement>>,
    pub statement_proofs: BTreeMap<String, Vec<String>>,
    pub(crate) migrations: BTreeMap<String, Arc<super::migration::Migration>>,
}
impl Catalog {
    pub fn read(descriptor: &Descriptor, bytes: &[u8]) -> Result<Self> {
        Self::read_inner(descriptor, bytes, true)
    }
    pub(crate) fn read_prepared(descriptor: &Descriptor, bytes: &[u8]) -> Result<Self> {
        Self::read_inner(descriptor, bytes, false)
    }
    fn read_inner(descriptor: &Descriptor, bytes: &[u8], allow_migration: bool) -> Result<Self> {
        let value = parse(bytes, MAX_CATALOG)?;
        let o = object(&value)?;
        fields(o, "format context_id objects")?;
        version(o)?;
        let context = text(o, "context_id")?;
        check(context == descriptor.context_id())?;
        let mut result = Self {
            context_id: context.into(),
            bytes: bytes.into(),
            proofs: BTreeMap::new(),
            statements: BTreeMap::new(),
            aliases: BTreeMap::new(),
            statement_proofs: BTreeMap::new(),
            migrations: BTreeMap::new(),
        };
        let mut previous = "";
        let mut decoded = 0usize;
        for entry in array(o, "objects")? {
            let row = object(entry)?;
            fields(row, "id kind body_base64")?;
            let id = text(row, "id")?;
            let kind = text(row, "kind")?;
            check(allow_migration || kind != "migration")?;
            check(ident(id, "dp_") && id > previous)?;
            previous = id;
            let body = b64(text(row, "body_base64")?, MAX_OBJECT)?;
            decoded = decoded
                .checked_add(body.len())
                .ok_or_else(|| Error::new("quota_exceeded"))?;
            require(decoded <= MAX_DECODED, "quota_exceeded")?;
            check(id == proof_id(kind, &body))?;
            let proof = Proof {
                id: id.into(),
                kind: kind.into(),
                body,
            };
            result.index(descriptor, &proof)?;
            result.proofs.insert(id.into(), proof);
        }
        Ok(result)
    }
    fn index(&mut self, descriptor: &Descriptor, proof: &Proof) -> Result<()> {
        match proof.kind.as_str() {
            "activation" => {
                let activation = super::transcript::Activation::read(descriptor, &proof.body)?;
                for statement in activation.statements {
                    self.insert(statement, &proof.id)?;
                }
            }
            "migration" => {
                let migration = super::migration::Migration::read(descriptor, &proof.body)?;
                for aliases in migration.prepared.aliases.values() {
                    for statement in aliases {
                        self.insert(statement.clone(), &proof.id)?;
                    }
                }
                self.insert(migration.proposal.clone(), &proof.id)?;
                for statement in migration.acknowledgments.values() {
                    self.insert(statement.clone(), &proof.id)?;
                }
                self.insert(migration.commit.clone(), &proof.id)?;
                self.migrations
                    .insert(proof.id.clone(), Arc::new(migration));
            }
            kind => {
                let statement = Statement::read(descriptor, &proof.body)?;
                check(statement.kind == kind)?;
                self.insert(statement, &proof.id)?;
            }
        }
        Ok(())
    }
    fn insert(&mut self, statement: Statement, proof_id: &str) -> Result<()> {
        if let Some(old) = self.statements.get(&statement.id) {
            check(old.kind == statement.kind && old.payload_bytes == statement.payload_bytes)?;
        }
        self.statement_proofs
            .entry(statement.id.clone())
            .or_default()
            .push(proof_id.into());
        self.aliases
            .entry(statement.id.clone())
            .or_default()
            .push(statement.clone());
        self.statements
            .entry(statement.id.clone())
            .or_insert(statement);
        Ok(())
    }
    /// Resolve original proof bytes inside a retained composite without
    /// fabricating a standalone dec_objects row or changing its source DP.
    pub(crate) fn proof(&self, id: &str) -> Result<&Proof> {
        self.proofs
            .get(id)
            .or_else(|| {
                self.migrations
                    .values()
                    .find_map(|m| m.prepared.proofs.get(id))
            })
            .ok_or_else(|| Error::missing(id))
    }
    pub(crate) fn has_statement_source(&self, statement: &str, proof: &str) -> bool {
        self.statement_proofs
            .get(statement)
            .is_some_and(|sources| sources.iter().any(|source| source == proof))
            || self.migrations.values().any(|m| {
                m.prepared
                    .statement_proofs
                    .get(statement)
                    .is_some_and(|sources| sources.iter().any(|source| source == proof))
            })
    }
    pub(crate) fn activation_proofs(&self) -> Vec<(&Proof, Option<&str>)> {
        self.proofs
            .values()
            .filter(|p| p.kind == "activation")
            .map(|p| (p, None))
            .chain(self.migrations.iter().flat_map(|(outer, m)| {
                m.prepared
                    .proofs
                    .values()
                    .filter(|p| p.kind == "activation")
                    .map(move |p| (p, Some(outer.as_str())))
            }))
            .collect()
    }
    pub fn get(&self, id: &str) -> Result<&Statement> {
        self.statements.get(id).ok_or_else(|| Error::missing(id))
    }
    pub fn union(descriptor: &Descriptor, prior: &Self, candidate: &Self) -> Result<Self> {
        check(prior.context_id == candidate.context_id)?;
        let mut proofs = prior.proofs.clone();
        for (id, p) in &candidate.proofs {
            if let Some(old) = proofs.get(id) {
                check(old.body == p.body && old.kind == p.kind)?;
            }
            proofs.insert(id.clone(), p.clone());
        }
        let bytes=serde_json::to_vec(&serde_json::json!({"format":1,"context_id":prior.context_id,"objects":proofs.values().map(|p|serde_json::json!({"id":p.id,"kind":p.kind,"body_base64":encode(&p.body)})).collect::<Vec<_>>()})).map_err(|_|Error::new("invalid"))?;
        Self::read(descriptor, &bytes)
    }
}
pub(crate) fn raw_field(body: &[u8], field: &str) -> Result<Vec<u8>> {
    let fields: BTreeMap<&str, &serde_json::value::RawValue> =
        serde_json::from_slice(body).map_err(|_| Error::new("invalid"))?;
    fields
        .get(field)
        .map(|v| v.get().as_bytes().to_vec())
        .ok_or_else(|| Error::new("invalid"))
}
pub(crate) fn raw_array_field(body: &[u8], field: &str) -> Result<Vec<Vec<u8>>> {
    let raw = raw_field(body, field)?;
    let entries: Vec<&serde_json::value::RawValue> =
        serde_json::from_slice(&raw).map_err(|_| Error::new("invalid"))?;
    Ok(entries
        .iter()
        .map(|v| v.get().as_bytes().to_vec())
        .collect())
}
pub(crate) fn value_field<'a>(o: &'a Obj, name: &str) -> Result<&'a Value> {
    o.get(name).ok_or_else(|| Error::new("invalid"))
}
