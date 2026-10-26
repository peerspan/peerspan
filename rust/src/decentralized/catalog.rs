use super::{
    codec::*,
    statement::{Descriptor, Statement, proof_id},
};
use serde_json::Value;
use std::collections::BTreeMap;

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
}
impl Catalog {
    pub fn read(descriptor: &Descriptor, bytes: &[u8]) -> Result<Self> {
        Self::read_inner(descriptor, bytes, true)
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
                let value = parse(&proof.body, MAX_OBJECT)?;
                let o = object(&value)?;
                fields(
                    o,
                    "format proposal source_catalog_base64 source_state_base64 prepared_catalog_base64 acknowledgments commit",
                )?;
                version(o)?;
                // Nested originals are read from RawValue, never synthesized.
                let proposal = Statement::read(descriptor, &raw_field(&proof.body, "proposal")?)?;
                check(proposal.kind == "migration_proposal")?;
                let source = b64(text(o, "source_catalog_base64")?, 512 << 10)?;
                let source_state = b64(text(o, "source_state_base64")?, 256 << 10)?;
                check(
                    hash(&source) == text(&proposal.payload, "source_catalog_sha256")?
                        && hash(&source_state) == text(&proposal.payload, "source_state_sha256")?,
                )?;
                parse(&source_state, 256 << 10)?;
                let prepared = b64(text(o, "prepared_catalog_base64")?, MAX_OBJECT)?;
                let prepared_catalog = Self::read_inner(descriptor, &prepared, false)?;
                for aliases in prepared_catalog.aliases.into_values() {
                    for statement in aliases {
                        self.insert(statement, &proof.id)?;
                    }
                }
                self.insert(proposal, &proof.id)?;
                let acks = raw_array_field(&proof.body, "acknowledgments")?;
                for ack in acks {
                    let statement = Statement::read(descriptor, &ack)?;
                    check(statement.kind == "migration_ack")?;
                    self.insert(statement, &proof.id)?;
                }
                let commit = Statement::read(descriptor, &raw_field(&proof.body, "commit")?)?;
                check(commit.kind == "migration_commit")?;
                self.insert(commit, &proof.id)?;
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
