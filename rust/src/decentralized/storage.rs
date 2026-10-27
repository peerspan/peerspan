//! Additive schema23: exact public evidence and private local admission are
//! separate. Opening the schema never creates or adopts a DEC network.

pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS dec_contexts (
 network_id TEXT NOT NULL, context_id TEXT NOT NULL, record TEXT NOT NULL,
 PRIMARY KEY(network_id, context_id)
);
CREATE TABLE IF NOT EXISTS dec_objects (
 network_id TEXT NOT NULL, context_id TEXT NOT NULL, proof_id TEXT NOT NULL,
 kind TEXT NOT NULL, body BLOB NOT NULL,
 PRIMARY KEY(network_id, context_id, proof_id)
);
CREATE TABLE IF NOT EXISTS dec_admissions (
 network_id TEXT NOT NULL, context_id TEXT NOT NULL, statement_id TEXT NOT NULL,
 record TEXT NOT NULL,
 PRIMARY KEY(network_id, context_id, statement_id)
);
CREATE TABLE IF NOT EXISTS dec_restrictions (
 network_id TEXT NOT NULL, context_id TEXT NOT NULL, restriction_id TEXT NOT NULL,
 record TEXT NOT NULL,
 PRIMARY KEY(network_id, context_id, restriction_id)
);
CREATE TABLE IF NOT EXISTS dec_activations (
 network_id TEXT NOT NULL, context_id TEXT NOT NULL, activation_id TEXT NOT NULL,
 request_id TEXT NOT NULL, record TEXT NOT NULL,
 PRIMARY KEY(network_id, context_id, activation_id)
);
CREATE TABLE IF NOT EXISTS dec_heads (
 network_id TEXT NOT NULL, context_id TEXT NOT NULL, stream_kind TEXT NOT NULL,
 subject TEXT NOT NULL, subject2 TEXT NOT NULL, record TEXT NOT NULL,
 PRIMARY KEY(network_id, context_id, stream_kind, subject, subject2)
);
CREATE TABLE IF NOT EXISTS dec_highwater (
 network_id TEXT NOT NULL, context_id TEXT NOT NULL, stream_kind TEXT NOT NULL,
 subject TEXT NOT NULL, subject2 TEXT NOT NULL, version INTEGER NOT NULL,
 record TEXT NOT NULL,
 PRIMARY KEY(network_id, context_id, stream_kind, subject, subject2)
);
CREATE TABLE IF NOT EXISTS dec_signers (
 network_id TEXT NOT NULL, context_id TEXT NOT NULL, provider_kind TEXT NOT NULL,
 person_key TEXT NOT NULL, device_key TEXT NOT NULL, lease_id TEXT NOT NULL,
 PRIMARY KEY(network_id, context_id)
);
CREATE TABLE IF NOT EXISTS dec_clock (
 network_id TEXT PRIMARY KEY, record TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dec_intents (
 intent_id TEXT PRIMARY KEY, network_id TEXT NOT NULL, context_id TEXT NOT NULL,
 kind TEXT NOT NULL, record TEXT NOT NULL, secret BLOB
);
CREATE TABLE IF NOT EXISTS dec_pending (
 request_id TEXT PRIMARY KEY, deadline TEXT NOT NULL, record TEXT NOT NULL,
 secret BLOB, terminal_read_cap BLOB
);
CREATE TABLE IF NOT EXISTS dec_frames (
 request_id TEXT NOT NULL, role TEXT NOT NULL, writer_key TEXT NOT NULL,
 frame_id TEXT NOT NULL, record TEXT NOT NULL,
 PRIMARY KEY(request_id, role, writer_key, frame_id)
);
CREATE TABLE IF NOT EXISTS dec_operations (
 network_id TEXT NOT NULL, context_id TEXT NOT NULL, request_id TEXT NOT NULL,
 activation_id TEXT NOT NULL, manifest_id TEXT NOT NULL, record TEXT NOT NULL,
 locally_applied INTEGER NOT NULL CHECK(locally_applied = 1),
 PRIMARY KEY(network_id, context_id, request_id)
);
CREATE TABLE IF NOT EXISTS dec_outbox (
 delivery_id TEXT PRIMARY KEY, network_id TEXT NOT NULL, context_id TEXT NOT NULL,
 target_key TEXT NOT NULL, record TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dec_migrations (
 network_id TEXT NOT NULL, proposal_id TEXT NOT NULL, record TEXT NOT NULL,
 PRIMARY KEY(network_id, proposal_id)
);
CREATE TABLE IF NOT EXISTS dec_contacts (
 network_id TEXT NOT NULL, context_id TEXT NOT NULL, host_key TEXT NOT NULL,
 sequence INTEGER NOT NULL, record TEXT NOT NULL,
 PRIMARY KEY(network_id, context_id, host_key)
);
CREATE TABLE IF NOT EXISTS dec_helpers (
 kind TEXT NOT NULL, address TEXT NOT NULL, public_key TEXT NOT NULL,
 record TEXT NOT NULL, credential BLOB,
 PRIMARY KEY(kind, address, public_key)
);
PRAGMA user_version = 23;
"#;

const TABLES: [&str; 17] = [
    "dec_contexts",
    "dec_objects",
    "dec_admissions",
    "dec_restrictions",
    "dec_activations",
    "dec_heads",
    "dec_highwater",
    "dec_signers",
    "dec_clock",
    "dec_intents",
    "dec_pending",
    "dec_frames",
    "dec_operations",
    "dec_outbox",
    "dec_migrations",
    "dec_contacts",
    "dec_helpers",
];
/// A genuine pre-DEC database has no objects in this reserved namespace.
/// Refuse before any migration DDL; never repair a table/view collision.
pub(crate) fn check_migration_namespace(connection: &rusqlite::Connection) -> anyhow::Result<()> {
    for name in TABLES {
        let present: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name=?1)",
            [name],
            |r| r.get(0),
        )?;
        anyhow::ensure!(
            !present,
            "corrupt decentralized schema: reserved object {name} exists before schema23"
        );
    }
    Ok(())
}
/// Compare normative table kinds, ordered columns/affinities/nullability/defaults
/// and primary-key positions. Extra indexes are allowed; opening never repairs.
pub(crate) fn check_schema(connection: &rusqlite::Connection) -> anyhow::Result<()> {
    let expected = rusqlite::Connection::open_in_memory()?;
    expected.execute_batch(SCHEMA)?;
    for name in TABLES {
        let kind: Option<String> = connection
            .query_row(
                "SELECT type FROM sqlite_schema WHERE name=?1",
                [name],
                |r| r.get(0),
            )
            .optional()?;
        anyhow::ensure!(
            kind.as_deref() == Some("table"),
            "corrupt decentralized schema: {name} is not a table"
        );
        anyhow::ensure!(
            columns(connection, name)? == columns(&expected, name)?,
            "corrupt decentralized schema: {name} has unexpected columns"
        );
    }
    let operations: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE name='dec_operations'",
        [],
        |r| r.get(0),
    )?;
    let normalized: String = operations
        .chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect();
    anyhow::ensure!(
        normalized.contains("check(locally_applied=1)"),
        "corrupt decentralized schema: missing applied-outcome constraint"
    );
    Ok(())
}
type Column = (i64, String, String, bool, Option<String>, i64, i64);
fn columns(connection: &rusqlite::Connection, table: &str) -> rusqlite::Result<Vec<Column>> {
    let mut query = connection.prepare(&format!("PRAGMA table_xinfo({table})"))?;
    query
        .query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get::<_, String>(2)?.to_ascii_uppercase(),
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
            ))
        })?
        .collect()
}

use super::{
    catalog::Catalog,
    codec::*,
    state::{Prior, Projection},
    statement::Descriptor,
    transcript::Activation,
};
use rusqlite::{Connection, OptionalExtension, types::Value as SqlValue};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

const MAX_PRIVATE: usize = 32 << 20;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnIdentity {
    pub member: String,
    pub person_public_key: String,
    pub host_public_key: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkRecord {
    pub format: u64,
    pub mode: String,
    pub descriptor_base64: String,
    pub context_id: String,
    pub root_state_id: String,
    pub own_identity: OwnIdentity,
    pub created_at: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextRecord {
    pub format: u64,
    pub descriptor_base64: String,
    pub origin: String,
    pub initial_root_state_id: String,
    pub origin_proof_id: String,
    pub migration_proposal_id: String,
    pub adopted_at: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderSelection {
    pub kind: String,
    pub person_key: String,
    pub device_key: String,
    pub lease_id: String,
}
/// A coherent collection of exact public proof bytes and private local markers.
/// This is not a transferable network map or a provider availability claim.
pub struct Snapshot {
    pub network: NetworkRecord,
    pub context: ContextRecord,
    pub descriptor: Descriptor,
    pub selection: Option<ProviderSelection>,
    pub prior: Prior,
    pub revision: String,
    /// Exact durable migration/fence records, never candidate-supplied state.
    pub migrations: Vec<MigrationRecord>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationRecord {
    pub format: u64,
    pub context_id: String,
    pub state: String,
    pub proposal_base64: String,
    pub source_catalog_base64: String,
    pub source_state_base64: String,
    pub prepared_catalog_base64: String,
    pub initial_root_state_base64: String,
    pub acknowledgments_base64: Vec<String>,
    pub commit_base64: String,
    pub migration_base64: String,
    pub local_acknowledgment_base64: String,
    pub root_intent_ids: Vec<String>,
    pub local_ack_intent_id: String,
    pub approved: bool,
    pub fenced: bool,
    pub publication_started: bool,
}
fn db(error: rusqlite::Error) -> Error {
    match error {
        rusqlite::Error::QueryReturnedNoRows => Error::new("not_found"),
        rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..) => Error::new("state_conflict"),
        _ => Error::new("internal"),
    }
}
fn private(bytes: &[u8]) -> Result<Obj> {
    Ok(object(&parse(bytes, MAX_PRIVATE)?)?.clone())
}
pub fn encode_u64(value: u64, positive: bool) -> Result<SqlValue> {
    check(!positive || value != 0)?;
    Ok(if value <= i64::MAX as u64 {
        SqlValue::Integer(value as i64)
    } else {
        SqlValue::Blob(value.to_be_bytes().into())
    })
}
pub fn decode_u64(value: &SqlValue, positive: bool) -> Result<u64> {
    let number = match value {
        SqlValue::Integer(value) if *value >= 0 => *value as u64,
        SqlValue::Blob(bytes) if bytes.len() == 8 && bytes[0] & 0x80 != 0 => u64::from_be_bytes(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| Error::new("invalid"))?,
        ),
        _ => return Err(Error::new("invalid")),
    };
    check(!positive || number != 0)?;
    Ok(number)
}
fn stream(kind: &str, subject: &str, subject2: &str) -> Result<Vec<String>> {
    Ok(match kind {
        "root" => {
            check(subject == "-" && subject2 == "-")?;
            vec![kind.into()]
        }
        "device" => {
            check(key(subject) && key(subject2))?;
            vec![kind.into(), subject.into(), subject2.into()]
        }
        "admin" | "person" | "host" | "binding" | "policy" => {
            check(key(subject) && subject2 == "-")?;
            vec![kind.into(), subject.into()]
        }
        "group" => {
            crate::admins::group_name(subject).map_err(|_| Error::new("invalid"))?;
            check(subject2 == "-")?;
            vec![kind.into(), subject.into()]
        }
        _ => return Err(Error::new("invalid")),
    })
}
pub(super) fn marker(bytes: &str, restriction: bool) -> Result<Obj> {
    let row = private(bytes.as_bytes())?;
    fields(&row, "format kind proof_id admitted_at basis")?;
    version(&row)?;
    check(ident(text(&row, "proof_id")?, "dp_"))?;
    stamp(text(&row, "admitted_at")?)?;
    let basis = object(row.get("basis").ok_or_else(|| Error::new("invalid"))?)?;
    fields(basis, "kind evidence_ids")?;
    check(if restriction {
        matches!(
            text(basis, "kind")?,
            "current" | "ratification" | "migration"
        )
    } else {
        matches!(text(basis, "kind")?, "current" | "retention" | "migration")
    })?;
    evidence_ids(basis)?;
    Ok(row)
}
fn evidence_ids(basis: &Obj) -> Result<()> {
    let mut previous = "";
    for id in array(basis, "evidence_ids")? {
        let id = id.as_str().ok_or_else(|| Error::new("invalid"))?;
        check(
            [
                "ds_", "dp_", "da_", "dpk_", "dm_", "pf_", "ar_", "dc_", "lf_",
            ]
            .iter()
            .any(|prefix| ident(id, prefix))
                && id > previous,
        )?;
        previous = id;
    }
    Ok(())
}
impl Snapshot {
    /// Caller holds one connection guard/read transaction while copying every
    /// coupled table. No nested Store lock or network/SSH operation occurs.
    pub fn load(connection: &Connection, network_id: &str, own_host_key: &str) -> Result<Self> {
        Self::load_inner(connection, network_id, own_host_key).map_err(|mut e| {
            if e.code == "invalid" {
                e.code = "state_conflict";
            }
            e
        })
    }
    fn load_inner(connection: &Connection, network_id: &str, own_host_key: &str) -> Result<Self> {
        check(ident(network_id, "net_") && key(own_host_key))?;
        let raw: String = connection
            .query_row(
                "SELECT record FROM networks WHERE id=?1",
                [network_id],
                |r| r.get(0),
            )
            .map_err(db)?;
        let network_value = parse(raw.as_bytes(), MAX_PRIVATE)?;
        let n = object(&network_value)?;
        if n.get("mode").and_then(Value::as_str) != Some("decentralized") {
            return Err(Error::new("upgrade_required"));
        }
        fields(
            n,
            "format mode descriptor_base64 context_id root_state_id own_identity created_at",
        )?;
        check(num(n, "format")? == 2)?;
        let network: NetworkRecord =
            serde_json::from_value(network_value).map_err(|_| Error::new("invalid"))?;
        let descriptor = Descriptor::read(&b64(&network.descriptor_base64, MAX_OBJECT)?)?;
        check(
            descriptor.network_id == network_id
                && descriptor.context_id() == network.context_id
                && (network.root_state_id == "-" || ident(&network.root_state_id, "ds_"))
                && network.own_identity.host_public_key == own_host_key
                && (network.own_identity.person_public_key == "-"
                    || key(&network.own_identity.person_public_key)),
        )?;
        if network.own_identity.member != "-" {
            label(&network.own_identity.member)?;
        }
        stamp(&network.created_at)?;
        let context_raw: String = connection
            .query_row(
                "SELECT record FROM dec_contexts WHERE network_id=?1 AND context_id=?2",
                [network_id, &network.context_id],
                |r| r.get(0),
            )
            .map_err(db)?;
        let context_value = parse(context_raw.as_bytes(), MAX_PRIVATE)?;
        let c = object(&context_value)?;
        fields(
            c,
            "format descriptor_base64 origin initial_root_state_id origin_proof_id migration_proposal_id adopted_at",
        )?;
        version(c)?;
        let context: ContextRecord =
            serde_json::from_value(context_value).map_err(|_| Error::new("invalid"))?;
        check(
            context.descriptor_base64 == network.descriptor_base64
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
        let mut revision = vec![Value::from(raw), Value::from(context_raw)];
        let mut query=connection.prepare("SELECT proof_id,kind,body FROM dec_objects WHERE network_id=?1 AND context_id=?2 ORDER BY proof_id").map_err(db)?;
        let rows = query
            .query_map([network_id, &network.context_id], |r| {
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
        let catalog_bytes = serde_json::to_vec(
            &json!({"format":1,"context_id":network.context_id,"objects":objects}),
        )
        .map_err(|_| Error::new("internal"))?;
        let catalog = Catalog::read(&descriptor, &catalog_bytes)?;
        revision.push(Value::from(hash(&catalog_bytes)));
        let mut admission_times = Vec::new();
        let origin = catalog
            .proofs
            .get(&context.origin_proof_id)
            .ok_or_else(|| Error::missing(&context.origin_proof_id))?;
        if context.origin == "genesis" {
            check(origin.kind == "root_state")?;
            let root = super::statement::Statement::read(&descriptor, &origin.body)?;
            check(
                root.id == context.initial_root_state_id
                    && root.kind == "root_state"
                    && root.sequence()? == 0
                    && text(&root.payload, "migration_proposal_id")? == "-",
            )?;
        } else {
            check(origin.kind == "migration")?;
            let migration = catalog
                .migrations
                .get(&context.origin_proof_id)
                .ok_or_else(|| Error::new("invalid"))?;
            check(
                migration.proposal.id == context.migration_proposal_id
                    && migration.root_id == context.initial_root_state_id,
            )?;
        }
        let mut admitted = BTreeSet::new();
        let mut restrictions = BTreeSet::new();
        for (table, id_column, restrictive) in [
            ("dec_admissions", "statement_id", false),
            ("dec_restrictions", "restriction_id", true),
        ] {
            let sql = format!(
                "SELECT {id_column},record FROM {table} WHERE network_id=?1 AND context_id=?2 ORDER BY {id_column}"
            );
            let mut query = connection.prepare(&sql).map_err(db)?;
            let rows = query
                .query_map([network_id, &network.context_id], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })
                .map_err(db)?;
            for row in rows {
                let (id, raw) = row.map_err(db)?;
                check(ident(&id, "ds_"))?;
                let record = marker(&raw, restrictive)?;
                admission_times.push(text(&record, "admitted_at")?.to_owned());
                if let Some(statement) = catalog.statements.get(&id) {
                    check(
                        statement.kind == text(&record, "kind")?
                            && catalog.statement_proofs.get(&id).is_some_and(|p| {
                                p.iter()
                                    .any(|p| p == text(&record, "proof_id").unwrap_or(""))
                            }),
                    )?;
                    check(super::statement::restriction(&statement.kind) == restrictive)?;
                } else {
                    check(
                        !restrictive
                            && matches!(text(&record, "kind")?, "root_state" | "policy" | "group"),
                    )?;
                }
                if restrictive {
                    restrictions.insert(id.clone());
                } else {
                    admitted.insert(id.clone());
                }
                revision.push(json!([table, id, raw]));
            }
        }
        let mut activations = BTreeSet::new();
        let mut query=connection.prepare("SELECT activation_id,request_id,record FROM dec_activations WHERE network_id=?1 AND context_id=?2 ORDER BY activation_id").map_err(db)?;
        let rows = query
            .query_map([network_id, &network.context_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })
            .map_err(db)?;
        for row in rows {
            let (id, request, raw) = row.map_err(db)?;
            check(ident(&id, "da_") && ident(&request, "link_"))?;
            let record = private(raw.as_bytes())?;
            fields(&record, "format proof_id manifest_id admitted_at basis")?;
            version(&record)?;
            stamp(text(&record, "admitted_at")?)?;
            admission_times.push(text(&record, "admitted_at")?.to_owned());
            let basis = object(record.get("basis").ok_or_else(|| Error::new("invalid"))?)?;
            fields(basis, "kind evidence_ids")?;
            check(matches!(
                text(basis, "kind")?,
                "current" | "retention" | "migration"
            ))?;
            evidence_ids(basis)?;
            let proof = catalog
                .proofs
                .get(text(&record, "proof_id")?)
                .ok_or_else(|| Error::missing(text(&record, "proof_id").unwrap_or("")))?;
            if proof.kind == "activation" {
                let activation = Activation::read(&descriptor, &proof.body)?;
                check(
                    activation.id == id
                        && activation.request_id == request
                        && activation.manifest_id == text(&record, "manifest_id")?,
                )?;
            } else {
                check(proof.kind == "migration")?;
                let migration = super::migration::Migration::read(&descriptor, &proof.body)?;
                let mut found = false;
                for nested in migration
                    .prepared
                    .proofs
                    .values()
                    .filter(|p| p.kind == "activation")
                {
                    let activation = Activation::read(&descriptor, &nested.body)?;
                    if activation.id == id {
                        check(
                            activation.request_id == request
                                && activation.manifest_id == text(&record, "manifest_id")?,
                        )?;
                        found = true;
                    }
                }
                check(found)?;
            }
            activations.insert(id.clone());
            revision.push(json!([id, request, raw]));
        }
        let mut heads = BTreeMap::new();
        let mut query=connection.prepare("SELECT stream_kind,subject,subject2,record FROM dec_heads WHERE network_id=?1 AND context_id=?2 ORDER BY stream_kind,subject,subject2").map_err(db)?;
        let rows = query
            .query_map([network_id, &network.context_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })
            .map_err(db)?;
        for row in rows {
            let (kind, subject, subject2, raw) = row.map_err(db)?;
            let key = stream(&kind, &subject, &subject2)?;
            let record = private(raw.as_bytes())?;
            fields(&record, "format head_ids")?;
            version(&record)?;
            heads.insert(key.clone(), ids(&record, "head_ids", "ds_")?);
            revision.push(json!([key, raw]));
        }
        let mut maxima = BTreeMap::new();
        let mut query=connection.prepare("SELECT stream_kind,subject,subject2,version,record FROM dec_highwater WHERE network_id=?1 AND context_id=?2 ORDER BY stream_kind,subject,subject2").map_err(db)?;
        let rows = query
            .query_map([network_id, &network.context_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, SqlValue>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })
            .map_err(db)?;
        for row in rows {
            let (kind, subject, subject2, version, raw) = row.map_err(db)?;
            let key = stream(&kind, &subject, &subject2)?;
            let version = decode_u64(&version, kind != "root")?;
            let record = private(raw.as_bytes())?;
            fields(&record, "format statement_ids floor_proof_ids")?;
            version_field(&record)?;
            let statements = ids(&record, "statement_ids", "ds_")?;
            let floors = ids(&record, "floor_proof_ids", "dp_")?;
            if !floors.is_empty() {
                check(
                    context.origin == "migration"
                        && floors.iter().all(|id| id == &context.origin_proof_id),
                )?;
            }
            if statements.is_empty() {
                check(!floors.is_empty())?;
            }
            let stream_heads = heads.get(&key).ok_or_else(|| Error::new("invalid"))?;
            maxima.insert(key.clone(),json!({"stream":key,"sequence":version,"statement_ids":statements,"head_ids":stream_heads}));
            revision.push(json!([key, version, raw]));
        }
        check(heads.len() == maxima.len())?;
        let roots = heads
            .get(&vec!["root".to_owned()])
            .ok_or_else(|| Error::new("invalid"))?;
        check(!roots.is_empty())?;
        let origins: BTreeSet<_> = catalog
            .migrations
            .values()
            .filter(|m| admitted.contains(&m.root_id))
            .map(|m| (m.proposal.id.clone(), hash(&m.prepared.bytes)))
            .collect();
        let genesis = admitted
            .iter()
            .filter_map(|id| catalog.statements.get(id))
            .any(|s| {
                s.kind == "root_state"
                    && s.payload
                        .get("migration_proposal_id")
                        .and_then(Value::as_str)
                        == Some("-")
                    && s.payload
                        .get("predecessors")
                        .and_then(Value::as_array)
                        .is_some_and(|p| p.is_empty())
            });
        let disputed = origins.len() > 1 || (!origins.is_empty() && genesis);
        check(
            network.root_state_id
                == if roots.len() == 1 && !disputed {
                    roots[0].as_str()
                } else {
                    "-"
                },
        )?;
        let clock_raw: Option<String> = connection
            .query_row(
                "SELECT record FROM dec_clock WHERE network_id=?1",
                [network_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(db)?;
        let clock_raw = clock_raw.ok_or_else(|| Error::new("invalid"))?;
        let clock = private(clock_raw.as_bytes())?;
        fields(&clock, "format largest_local_time")?;
        version(&clock)?;
        let guard = text(&clock, "largest_local_time")?;
        stamp(guard)?;
        check(network.created_at.as_str() <= guard && context.adopted_at.as_str() <= guard)?;
        check(admission_times.iter().all(|at| at.as_str() <= guard))?;
        revision.push(Value::from(clock_raw.clone()));
        let prior_value = json!({"format":1,"context_id":network.context_id,"catalog_base64":encode(&catalog_bytes),"admitted_statement_ids":admitted,"admitted_restriction_ids":restrictions,"admitted_activation_ids":activations,"root_head_ids":roots,"maxima":maxima.into_values().collect::<Vec<_>>(),"migration_proposal_id":context.migration_proposal_id,"clock_guard":guard});
        // Loading retained markers grants no authority. Read projections may
        // diagnose a missing historical access body within its own closure;
        // every fresh/repair application still reparses the strict prior.
        let prior =
            Prior::read_only(&descriptor, &prior_value)?.ok_or_else(|| Error::new("invalid"))?;
        let selection:Option<(String,String,String,String)>=connection.query_row("SELECT provider_kind,person_key,device_key,lease_id FROM dec_signers WHERE network_id=?1 AND context_id=?2",[network_id,&network.context_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().map_err(db)?;
        let selection =
            selection.map(
                |(kind, person_key, device_key, lease_id)| ProviderSelection {
                    kind,
                    person_key,
                    device_key,
                    lease_id,
                },
            );
        if let Some(selected) = &selection {
            check(
                key(&selected.person_key)
                    && selected.person_key == network.own_identity.person_public_key,
            )?;
            check(match selected.kind.as_str() {
                "original" => selected.device_key == "-" && selected.lease_id == "-",
                "device" => key(&selected.device_key) && ident(&selected.lease_id, "ds_"),
                _ => false,
            })?;
            revision.push(json!([
                selected.kind,
                selected.person_key,
                selected.device_key,
                selected.lease_id
            ]));
        }
        let mut migrations = Vec::new();
        let mut query = connection.prepare("SELECT proposal_id,record FROM dec_migrations WHERE network_id=?1 ORDER BY proposal_id").map_err(db)?;
        let rows = query
            .query_map([network_id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })
            .map_err(db)?;
        for row in rows {
            let (proposal_id, raw) = row.map_err(db)?;
            check(ident(&proposal_id, "ds_"))?;
            let value = parse(raw.as_bytes(), MAX_PRIVATE)?;
            let record: MigrationRecord =
                serde_json::from_value(value).map_err(|_| Error::new("invalid"))?;
            check(
                record.format == 1
                    && ident(&record.context_id, "ctx_")
                    && matches!(
                        record.state.as_str(),
                        "needs_approvals" | "prepared" | "acknowledged" | "adopted" | "conflict"
                    ),
            )?;
            for encoded in [
                &record.proposal_base64,
                &record.source_catalog_base64,
                &record.source_state_base64,
                &record.prepared_catalog_base64,
                &record.initial_root_state_base64,
                &record.commit_base64,
                &record.migration_base64,
                &record.local_acknowledgment_base64,
            ] {
                if encoded != "-" {
                    b64(encoded, MAX_CATALOG)?;
                }
            }
            let mut previous_host = String::new();
            for encoded in &record.acknowledgments_base64 {
                let ack =
                    super::statement::Statement::read(&descriptor, &b64(encoded, MAX_OBJECT)?)?;
                let host = text(&ack.payload, "host_public_key")?;
                check(
                    ack.kind == "migration_ack"
                        && text(&ack.payload, "proposal_id")? == proposal_id
                        && host > previous_host.as_str(),
                )?;
                previous_host = host.into();
            }
            let mut seen = BTreeSet::new();
            for id in &record.root_intent_ids {
                check(local_intent(id) && seen.insert(id))?;
            }
            check(record.local_ack_intent_id == "-" || local_intent(&record.local_ack_intent_id))?;
            require(!record.fenced || record.approved, "state_conflict")?;
            if record.proposal_base64 != "-" {
                let proposal = super::statement::Statement::read(
                    &descriptor,
                    &b64(&record.proposal_base64, MAX_OBJECT)?,
                )?;
                check(
                    proposal.kind == "migration_proposal"
                        && proposal.id == proposal_id
                        && record.context_id == descriptor.context_id(),
                )?;
            }
            revision.push(json!([proposal_id, raw]));
            migrations.push(record);
        }
        let revision = hash(&serde_json::to_vec(&revision).map_err(|_| Error::new("internal"))?);
        Ok(Self {
            network,
            context,
            descriptor,
            selection,
            prior,
            revision,
            migrations,
        })
    }
    pub fn project(&self, now: &str) -> Result<Projection> {
        Projection::build(&self.descriptor, &self.prior.value, None, now, "read")
    }
}
fn version_field(o: &Obj) -> Result<()> {
    version(o)
}

fn local_intent(id: &str) -> bool {
    id.len() == 37
        && id.starts_with("dint_")
        && id[5..]
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

#[derive(Serialize)]
struct MemberRecord<'a> {
    format: u64,
    mode: &'a str,
    host_public_key: &'a str,
    member: &'a str,
    person_public_key: &'a str,
    host_lease_id: &'a str,
    person_lease_id: &'a str,
    binding_lease_id: &'a str,
    activation_id: &'a str,
}
impl Snapshot {
    /// Recheck the actual current snapshot under the caller's final transaction.
    /// This merges evidence only into an already adopted exact context. It
    /// never adopts a context, changes consent/provider, or signs/publishes.
    pub fn apply_catalog(
        &self,
        transaction: &mut rusqlite::Transaction<'_>,
        candidate: &[u8],
        now: &str,
        purpose: &str,
    ) -> Result<Projection> {
        check(matches!(purpose, "fresh" | "repair"))?;
        let savepoint = transaction.savepoint().map_err(db)?;
        let latest = Self::load(
            &savepoint,
            &self.descriptor.network_id,
            &self.network.own_identity.host_public_key,
        )?;
        require(latest.revision == self.revision, "state_conflict")?;
        let projection = Projection::build(
            &latest.descriptor,
            &latest.prior.value,
            Some(candidate),
            now,
            purpose,
        )?;
        latest.persist(&savepoint, &projection)?;
        super::renewal::reconcile(&savepoint, &latest, &projection)?;
        savepoint.commit().map_err(db)?;
        Ok(projection)
    }
    fn persist(&self, connection: &Connection, projection: &Projection) -> Result<()> {
        let network = &self.descriptor.network_id;
        let context = &self.network.context_id;
        check(projection.descriptor.context_id() == *context)?;
        // A corrupted/obsolete owned root is never silently used with a new
        // public root. Root-fork recovery material remains private and unused.
        let seed: Option<Vec<u8>> = connection
            .query_row(
                "SELECT root_seed FROM networks WHERE id=?1",
                [network],
                |r| r.get(0),
            )
            .map_err(db)?;
        if let Some(seed) = seed {
            let seed: &[u8; 32] = seed
                .as_slice()
                .try_into()
                .map_err(|_| Error::new("state_conflict"))?;
            if let Ok(root) = projection
                .root_state_id()
                .and_then(|id| projection.catalog.get(id))
                && projection.active(&root.id).is_ok()
                && encode(
                    ed25519_dalek::SigningKey::from_bytes(seed)
                        .verifying_key()
                        .as_bytes(),
                ) != text(&root.payload, "root_public_key")?
            {
                connection
                    .execute("UPDATE networks SET root_seed=NULL WHERE id=?1", [network])
                    .map_err(db)?;
            }
        }
        for proof in projection.catalog.proofs.values() {
            connection.execute("INSERT OR IGNORE INTO dec_objects(network_id,context_id,proof_id,kind,body) VALUES(?1,?2,?3,?4,?5)",rusqlite::params![network,context,proof.id,proof.kind,proof.body]).map_err(db)?;
        }
        for (table, column, ids, old) in [
            (
                "dec_admissions",
                "statement_id",
                &projection.admitted,
                &self.prior.admitted,
            ),
            (
                "dec_restrictions",
                "restriction_id",
                &projection.restrictions,
                &self.prior.restrictions,
            ),
        ] {
            for id in ids.difference(old) {
                let statement = projection.catalog.get(id)?;
                let proof = projection
                    .catalog
                    .statement_proofs
                    .get(id)
                    .and_then(|p| p.first())
                    .ok_or_else(|| Error::missing(id))?;
                let (basis, evidence) = projection.admission_basis(id)?;
                let record = json!({"format":1,"kind":statement.kind,"proof_id":proof,"admitted_at":projection.decision_time,"basis":{"kind":basis,"evidence_ids":evidence}});
                let sql = format!(
                    "INSERT INTO {table}(network_id,context_id,{column},record) VALUES(?1,?2,?3,?4)"
                );
                connection
                    .execute(
                        &sql,
                        rusqlite::params![network, context, id, record.to_string()],
                    )
                    .map_err(db)?;
            }
        }
        for activation in projection.activated.values() {
            if self.prior.activations.contains(&activation.id) {
                continue;
            }
            let source = projection
                .catalog
                .activation_proofs()
                .into_iter()
                .find_map(|(p, outer)| {
                    Activation::read(&projection.descriptor, &p.body)
                        .ok()
                        .filter(|a| a.id == activation.id)
                        .map(|_| outer.unwrap_or(&p.id).to_owned())
                })
                .ok_or_else(|| Error::missing(&activation.id))?;
            let basis = if projection
                .catalog
                .proofs
                .get(&source)
                .is_some_and(|p| p.kind == "migration")
            {
                "migration"
            } else {
                "current"
            };
            let evidence: BTreeSet<_> = activation
                .packets
                .values()
                .map(|p| p.id.clone())
                .chain([activation.manifest_id.clone(), source.clone()])
                .collect();
            let record = json!({"format":1,"proof_id":source,"manifest_id":activation.manifest_id,"admitted_at":projection.decision_time,"basis":{"kind":basis,"evidence_ids":evidence}});
            connection.execute("INSERT INTO dec_activations(network_id,context_id,activation_id,request_id,record) VALUES(?1,?2,?3,?4,?5)",rusqlite::params![network,context,activation.id,activation.request_id,record.to_string()]).map_err(db)?;
        }
        for stream in projection.streams.values() {
            let (kind, subject, subject2) = stream_tuple(&stream.key)?;
            let head = json!({"format":1,"head_ids":stream.heads});
            let mut floors = BTreeSet::new();
            for (proof, migration) in &projection.catalog.migrations {
                if proof == &self.context.origin_proof_id
                    && migration
                        .source_state
                        .maxima
                        .get(&(kind.into(), subject.into()))
                        .is_some_and(|(version, _)| *version <= stream.maximum)
                {
                    floors.insert(proof);
                }
            }
            let highwater =
                json!({"format":1,"statement_ids":stream.at_maximum,"floor_proof_ids":floors});
            connection.execute("INSERT INTO dec_heads(network_id,context_id,stream_kind,subject,subject2,record) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(network_id,context_id,stream_kind,subject,subject2) DO UPDATE SET record=excluded.record",rusqlite::params![network,context,kind,subject,subject2,head.to_string()]).map_err(db)?;
            connection.execute("INSERT INTO dec_highwater(network_id,context_id,stream_kind,subject,subject2,version,record) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(network_id,context_id,stream_kind,subject,subject2) DO UPDATE SET version=excluded.version,record=excluded.record",rusqlite::params![network,context,kind,subject,subject2,encode_u64(stream.maximum,kind!="root")?,highwater.to_string()]).map_err(db)?;
        }
        let members = projection.members()?;
        let mut native = self.network.clone();
        native.root_state_id = projection.root_state_id().unwrap_or("-").into();
        if let Some(own) = members.iter().find(|m| {
            m.host_public_key == native.own_identity.host_public_key
                && m.person_public_key == native.own_identity.person_public_key
        }) {
            native.own_identity.member = own.member.clone();
        }
        connection
            .execute(
                "UPDATE networks SET record=?2 WHERE id=?1",
                rusqlite::params![
                    network,
                    serde_json::to_string(&native).map_err(|_| Error::new("internal"))?
                ],
            )
            .map_err(db)?;
        connection
            .execute("DELETE FROM network_members WHERE network_id=?1", [network])
            .map_err(db)?;
        for member in &members {
            let record = MemberRecord {
                format: 2,
                mode: "decentralized",
                host_public_key: &member.host_public_key,
                member: &member.member,
                person_public_key: &member.person_public_key,
                host_lease_id: &member.host_lease_id,
                person_lease_id: &member.person_lease_id,
                binding_lease_id: &member.binding_lease_id,
                activation_id: &member.activation_id,
            };
            let host = format!("host_{}", hash(&b64(&member.host_public_key, 32)?));
            connection
                .execute(
                    "INSERT INTO network_members(network_id,host_id,record) VALUES(?1,?2,?3)",
                    rusqlite::params![
                        network,
                        host,
                        serde_json::to_string(&record).map_err(|_| Error::new("internal"))?
                    ],
                )
                .map_err(db)?;
        }
        let clock = json!({"format":1,"largest_local_time":projection.decision_time});
        connection
            .execute(
                "UPDATE dec_clock SET record=?2 WHERE network_id=?1",
                rusqlite::params![network, clock.to_string()],
            )
            .map_err(db)?;
        let mut new_proofs: BTreeSet<_> = projection
            .catalog
            .proofs
            .keys()
            .filter(|p| !self.prior.catalog.proofs.contains_key(*p))
            .cloned()
            .collect();
        for id in projection
            .admitted
            .difference(&self.prior.admitted)
            .chain(projection.restrictions.difference(&self.prior.restrictions))
        {
            if let Some(proof) = projection
                .catalog
                .statement_proofs
                .get(id)
                .and_then(|proofs| proofs.first())
            {
                new_proofs.insert(proof.clone());
            }
        }
        let mut deliveries = Vec::new();
        if !new_proofs.is_empty() {
            let mut targets: BTreeSet<_> =
                members.iter().map(|m| m.host_public_key.clone()).collect();
            if let Ok(prior) = self.project(&projection.decision_time) {
                targets.extend(prior.members()?.into_iter().map(|m| m.host_public_key));
            }
            targets.remove(&self.network.own_identity.host_public_key);
            let body = json!({"catalog":parse(&projection.catalog.bytes,MAX_CATALOG)?});
            let encoded = encode(&serde_json::to_vec(&body).map_err(|_| Error::new("internal"))?);
            for target in targets {
                let delivery = crate::store::new_id("ddel").map_err(|_| Error::new("internal"))?;
                let record = json!({"format":1,"kind":"proofs","body_base64":encoded,"proof_ids":new_proofs,"created_at":projection.decision_time,"attempts":0,"next_attempt_at":projection.decision_time,"last_error_code":"-","last_error_detail":"-"});
                deliveries.push((delivery, target, record));
            }
        }
        check_outbox_capacity(
            connection,
            &deliveries.iter().map(|(_, _, r)| r).collect::<Vec<_>>(),
        )?;
        for (delivery, target, record) in deliveries {
            connection.execute("INSERT INTO dec_outbox(delivery_id,network_id,context_id,target_key,record) VALUES(?1,?2,?3,?4,?5)",rusqlite::params![delivery,network,context,target,record.to_string()]).map_err(db)?;
        }
        Ok(())
    }
}
fn stream_tuple(key: &[String]) -> Result<(&str, &str, &str)> {
    Ok(match key {
        [kind] if kind == "root" => ("root", "-", "-"),
        [kind, subject] => (kind, subject, "-"),
        [kind, subject, subject2] => (kind, subject, subject2),
        _ => return Err(Error::new("invalid")),
    })
}

impl Snapshot {
    /// Install only a complete, locally acknowledged all-host migration. The
    /// caller validates the current legacy source and consent in this same TX;
    /// an ordinary catalog reader never calls this mode switch.
    pub(crate) fn install_migration(
        transaction: &mut rusqlite::Transaction<'_>,
        descriptor_bytes: &[u8],
        migration_bytes: &[u8],
        now: &str,
        identity: &OwnIdentity,
    ) -> Result<Self> {
        let descriptor = Descriptor::read(descriptor_bytes)?;
        let migration = super::migration::Migration::read(&descriptor, migration_bytes)?;
        let savepoint = transaction.savepoint().map_err(db)?;
        let actual: Vec<u8> = savepoint
            .query_row(
                "SELECT private_key FROM identity WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .map_err(db)?;
        let key = ed25519_dalek::SigningKey::from_keypair_bytes(
            actual
                .as_slice()
                .try_into()
                .map_err(|_| Error::new("state_conflict"))?,
        )
        .map_err(|_| Error::new("state_conflict"))?;
        require(
            encode(key.verifying_key().as_bytes()) == identity.host_public_key,
            "forbidden",
        )?;
        let ack = migration
            .acknowledgments
            .get(&identity.host_public_key)
            .ok_or_else(|| Error::new("forbidden"))?;
        require(
            text(&ack.payload, "person_public_key")? == identity.person_public_key,
            "forbidden",
        )?;
        let roster = array(&migration.proposal.payload, "roster")?;
        let own = object(
            roster
                .iter()
                .find(|r| {
                    r.get("host_public_key").and_then(Value::as_str)
                        == Some(&identity.host_public_key)
                })
                .ok_or_else(|| Error::new("forbidden"))?,
        )?;
        require(text(own, "member")? == identity.member, "forbidden")?;
        let old: String = savepoint
            .query_row(
                "SELECT record FROM networks WHERE id=?1",
                [&descriptor.network_id],
                |r| r.get(0),
            )
            .map_err(db)?;
        require(old.len() <= MAX_PRIVATE, "quota_exceeded")?;
        let old: Value = serde_json::from_str(&old).map_err(|_| Error::new("state_conflict"))?;
        require(
            old.get("mode").and_then(Value::as_str) != Some("decentralized"),
            "state_conflict",
        )?;
        let known: bool = savepoint
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM dec_contexts WHERE network_id=?1)",
                [&descriptor.network_id],
                |r| r.get(0),
            )
            .map_err(db)?;
        require(!known, "state_conflict")?;
        let decision = super::controls::guarded_decision(&savepoint, &descriptor.network_id, now)?;
        let proof = super::statement::proof_id("migration", migration_bytes);
        let catalog = serde_json::to_vec(&json!({"format":1,"context_id":descriptor.context_id(),
            "objects":[{"id":proof,"kind":"migration","body_base64":encode(migration_bytes)}]}))
        .map_err(|_| Error::new("internal"))?;
        let projection = Projection::build(
            &descriptor,
            &Value::from("-"),
            Some(&catalog),
            &decision,
            "repair",
        )?;
        require(
            projection.root_state_id()? == migration.root_id,
            "state_conflict",
        )?;
        let network = NetworkRecord {
            format: 2,
            mode: "decentralized".into(),
            descriptor_base64: encode(descriptor_bytes),
            context_id: descriptor.context_id(),
            root_state_id: migration.root_id.clone(),
            own_identity: identity.clone(),
            created_at: decision.clone(),
        };
        let context = ContextRecord {
            format: 1,
            descriptor_base64: network.descriptor_base64.clone(),
            origin: "migration".into(),
            initial_root_state_id: migration.root_id.clone(),
            origin_proof_id: proof,
            migration_proposal_id: migration.proposal.id.clone(),
            adopted_at: decision.clone(),
        };
        let empty = serde_json::to_vec(
            &json!({"format":1,"context_id":descriptor.context_id(),"objects":[]}),
        )
        .map_err(|_| Error::new("internal"))?;
        let prior=Prior::read(&descriptor,&json!({"format":1,"context_id":descriptor.context_id(),
            "catalog_base64":encode(&empty),"admitted_statement_ids":[],"admitted_restriction_ids":[],
            "admitted_activation_ids":[],"root_head_ids":[],"maxima":[],"migration_proposal_id":"-","clock_guard":decision}))?
            .ok_or_else(||Error::new("invalid"))?;
        savepoint
            .execute(
                "UPDATE networks SET record=?2 WHERE id=?1",
                rusqlite::params![
                    descriptor.network_id,
                    serde_json::to_string(&network).map_err(|_| Error::new("internal"))?
                ],
            )
            .map_err(db)?;
        savepoint
            .execute(
                "INSERT INTO dec_contexts(network_id,context_id,record) VALUES(?1,?2,?3)",
                rusqlite::params![
                    descriptor.network_id,
                    descriptor.context_id(),
                    serde_json::to_string(&context).map_err(|_| Error::new("internal"))?
                ],
            )
            .map_err(db)?;
        super::controls::remember_decision(&savepoint, &descriptor.network_id, &decision)?;
        let initial = Self {
            network,
            context,
            descriptor,
            selection: None,
            prior,
            revision: String::new(),
            migrations: Vec::new(),
        };
        initial.persist(&savepoint, &projection)?;
        if identity.person_public_key != "-" {
            let device = text(&ack.payload, "device_public_key")?;
            let seed: Option<Vec<u8>> = savepoint
                .query_row(
                    "SELECT seed FROM link_device_keys WHERE public_key=?1",
                    [device],
                    |r| r.get(0),
                )
                .optional()
                .map_err(db)?;
            let seed: [u8; 32] = seed
                .ok_or_else(|| Error::new("signer_unavailable"))?
                .try_into()
                .map_err(|_| Error::new("state_conflict"))?;
            require(
                encode(
                    ed25519_dalek::SigningKey::from_bytes(&seed)
                        .verifying_key()
                        .as_bytes(),
                ) == device,
                "signer_unavailable",
            )?;
            savepoint.execute("INSERT INTO dec_signers(network_id,context_id,provider_kind,person_key,device_key,lease_id) VALUES(?1,?2,'device',?3,?4,?5)",
                rusqlite::params![initial.descriptor.network_id,initial.network.context_id,identity.person_public_key,device,text(&ack.payload,"device_lease_id")?]).map_err(db)?;
        }
        let result = Self::load(
            &savepoint,
            &initial.descriptor.network_id,
            &identity.host_public_key,
        )?;
        savepoint.commit().map_err(db)?;
        Ok(result)
    }
    /// Adopt one exact locally approved requester activation. The caller owns
    /// consent/outcome atomicity; this helper never signs or imports a key.
    pub(crate) fn install_activation(
        transaction: &mut rusqlite::Transaction<'_>,
        descriptor_bytes: &[u8],
        catalog: &[u8],
        now: &str,
        identity: &OwnIdentity,
        request_id: &str,
    ) -> Result<Self> {
        let descriptor = Descriptor::read(descriptor_bytes)?;
        let savepoint = transaction.savepoint().map_err(db)?;
        let actual: Vec<u8> = savepoint
            .query_row(
                "SELECT private_key FROM identity WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .map_err(db)?;
        let host = ed25519_dalek::SigningKey::from_keypair_bytes(
            actual
                .as_slice()
                .try_into()
                .map_err(|_| Error::new("state_conflict"))?,
        )
        .map_err(|_| Error::new("state_conflict"))?;
        require(
            encode(host.verifying_key().as_bytes()) == identity.host_public_key,
            "state_conflict",
        )?;
        let mut q = savepoint
            .prepare("SELECT id,record FROM networks ORDER BY id")
            .map_err(db)?;
        for row in q
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(db)?
        {
            let (id, raw) = row.map_err(db)?;
            require(
                id != descriptor.network_id && network_name(&raw)? != descriptor.name,
                "state_conflict",
            )?;
        }
        drop(q);
        let known: bool = savepoint
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM dec_contexts WHERE network_id=?1)",
                [&descriptor.network_id],
                |r| r.get(0),
            )
            .map_err(db)?;
        require(!known, "state_conflict")?;
        let guard: Option<String> = savepoint
            .query_row(
                "SELECT record FROM dec_clock WHERE network_id=?1",
                [&descriptor.network_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(db)?;
        let guard = guard
            .map(|raw| -> Result<String> {
                let record = private(raw.as_bytes())?;
                fields(&record, "format largest_local_time")?;
                version(&record)?;
                stamp(text(&record, "largest_local_time")?)?;
                Ok(text(&record, "largest_local_time")?.into())
            })
            .transpose()?;
        let decision = decision_clock(now, guard.as_deref().unwrap_or("-"))?;
        let projection = Projection::build(
            &descriptor,
            &Value::from("-"),
            Some(catalog),
            &decision,
            "repair",
        )?;
        projection.activation_response(request_id, &Value::from("-"))?;
        let activation = projection
            .activated
            .get(request_id)
            .ok_or_else(|| Error::missing(request_id))?;
        require(
            text(&activation.packets["request"].payload, "host_public_key")?
                == identity.host_public_key
                && text(&activation.packets["owner"].object, "person_public_key")?
                    == identity.person_public_key,
            "forbidden",
        )?;
        let member =
            projection.member_for(&identity.host_public_key, &identity.person_public_key)?;
        check(member.member == identity.member)?;
        let device = projection
            .catalog
            .get(text(&activation.manifest, "device_lease_id")?)?;
        let device_key = text(device.subject()?, "device_public_key")?;
        let seed: Option<Vec<u8>> = savepoint
            .query_row(
                "SELECT seed FROM link_device_keys WHERE public_key=?1",
                [device_key],
                |r| r.get(0),
            )
            .optional()
            .map_err(db)?;
        let seed: [u8; 32] = seed
            .ok_or_else(|| Error::new("signer_unavailable"))?
            .try_into()
            .map_err(|_| Error::new("signer_unavailable"))?;
        require(
            encode(
                ed25519_dalek::SigningKey::from_bytes(&seed)
                    .verifying_key()
                    .as_bytes(),
            ) == device_key,
            "signer_unavailable",
        )?;
        projection.provider_potential(
            &identity.person_public_key,
            &identity.host_public_key,
            Some(&device.id),
        )?;
        let root = projection.root_state_id()?.to_owned();
        let (origin, initial, proof, proposal) = if let Some((proof, migration)) = projection
            .catalog
            .migrations
            .iter()
            .find(|(_, m)| projection.admitted.contains(&m.root_id))
        {
            (
                "migration",
                migration.root_id.clone(),
                proof.clone(),
                migration.proposal.id.clone(),
            )
        } else {
            let initial = projection
                .catalog
                .statements
                .values()
                .find(|s| {
                    s.kind == "root_state"
                        && s.payload
                            .get("predecessors")
                            .and_then(Value::as_array)
                            .is_some_and(|p| p.is_empty())
                        && s.payload
                            .get("migration_proposal_id")
                            .and_then(Value::as_str)
                            == Some("-")
                })
                .ok_or_else(|| Error::new("proof_required"))?;
            let proof = projection
                .catalog
                .statement_proofs
                .get(&initial.id)
                .and_then(|sources| {
                    sources.iter().find(|id| {
                        projection
                            .catalog
                            .proofs
                            .get(*id)
                            .is_some_and(|p| p.kind == "root_state")
                    })
                })
                .ok_or_else(|| Error::missing(&initial.id))?;
            ("genesis", initial.id.clone(), proof.clone(), "-".into())
        };
        let network = NetworkRecord {
            format: 2,
            mode: "decentralized".into(),
            descriptor_base64: encode(descriptor_bytes),
            context_id: descriptor.context_id(),
            root_state_id: root,
            own_identity: identity.clone(),
            created_at: decision.clone(),
        };
        let context = ContextRecord {
            format: 1,
            descriptor_base64: network.descriptor_base64.clone(),
            origin: origin.into(),
            initial_root_state_id: initial,
            origin_proof_id: proof,
            migration_proposal_id: proposal,
            adopted_at: decision.clone(),
        };
        let empty = serde_json::to_vec(
            &json!({"format":1,"context_id":descriptor.context_id(),"objects":[]}),
        )
        .map_err(|_| Error::new("internal"))?;
        let prior=Prior::read(&descriptor,&json!({"format":1,"context_id":descriptor.context_id(),"catalog_base64":encode(&empty),"admitted_statement_ids":[],"admitted_restriction_ids":[],"admitted_activation_ids":[],"root_head_ids":[],"maxima":[],"migration_proposal_id":"-","clock_guard":decision}))?.ok_or_else(||Error::new("invalid"))?;
        savepoint
            .execute(
                "INSERT INTO networks(id,record,root_seed) VALUES(?1,?2,NULL)",
                rusqlite::params![
                    descriptor.network_id,
                    serde_json::to_string(&network).map_err(|_| Error::new("internal"))?
                ],
            )
            .map_err(db)?;
        savepoint
            .execute(
                "INSERT INTO dec_contexts(network_id,context_id,record) VALUES(?1,?2,?3)",
                rusqlite::params![
                    descriptor.network_id,
                    descriptor.context_id(),
                    serde_json::to_string(&context).map_err(|_| Error::new("internal"))?
                ],
            )
            .map_err(db)?;
        savepoint.execute("INSERT INTO dec_clock(network_id,record) VALUES(?1,?2) ON CONFLICT(network_id) DO UPDATE SET record=excluded.record",rusqlite::params![descriptor.network_id,json!({"format":1,"largest_local_time":decision}).to_string()]).map_err(db)?;
        let initial = Self {
            network,
            context,
            descriptor,
            selection: None,
            prior,
            revision: String::new(),
            migrations: Vec::new(),
        };
        initial.persist(&savepoint, &projection)?;
        savepoint.execute("INSERT INTO dec_signers(network_id,context_id,provider_kind,person_key,device_key,lease_id) VALUES(?1,?2,'device',?3,?4,?5)",rusqlite::params![initial.descriptor.network_id,initial.network.context_id,identity.person_public_key,device_key,device.id]).map_err(db)?;
        let result = Self::load(
            &savepoint,
            &initial.descriptor.network_id,
            &identity.host_public_key,
        )?;
        savepoint.commit().map_err(db)?;
        Ok(result)
    }
    /// Called only after the fixed owner-local creation intent has all explicit
    /// approval/signature slots. Ordinary ingestion never calls this gate.
    /// Genesis initializes an ORIGINAL provider and issues no device lease.
    pub fn install_genesis(
        transaction: &mut rusqlite::Transaction<'_>,
        descriptor_bytes: &[u8],
        catalog: &[u8],
        now: &str,
        identity: &OwnIdentity,
        root_seed: &[u8; 32],
    ) -> Result<Self> {
        let descriptor = Descriptor::read(descriptor_bytes)?;
        require(
            encode(
                ed25519_dalek::SigningKey::from_bytes(root_seed)
                    .verifying_key()
                    .as_bytes(),
            ) == descriptor.genesis_root_public_key,
            "state_conflict",
        )?;
        let savepoint = transaction.savepoint().map_err(db)?;
        let actual: Vec<u8> = savepoint
            .query_row(
                "SELECT private_key FROM identity WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .map_err(db)?;
        let keypair: &[u8; 64] = actual
            .as_slice()
            .try_into()
            .map_err(|_| Error::new("state_conflict"))?;
        let host = ed25519_dalek::SigningKey::from_keypair_bytes(keypair)
            .map_err(|_| Error::new("state_conflict"))?;
        require(
            encode(host.verifying_key().as_bytes()) == identity.host_public_key,
            "state_conflict",
        )?;
        let mut query = savepoint
            .prepare("SELECT record FROM networks ORDER BY id")
            .map_err(db)?;
        let rows = query.query_map([], |r| r.get::<_, String>(0)).map_err(db)?;
        for row in rows {
            let raw = row.map_err(db)?;
            let name = network_name(&raw)?;
            require(name != descriptor.name, "state_conflict")?;
        }
        drop(query);
        let known: bool = savepoint
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM dec_contexts WHERE network_id=?1)",
                [&descriptor.network_id],
                |r| r.get(0),
            )
            .map_err(db)?;
        require(!known, "state_conflict")?;
        let clock: Option<String> = savepoint
            .query_row(
                "SELECT record FROM dec_clock WHERE network_id=?1",
                [&descriptor.network_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(db)?;
        let clock = clock
            .map(|raw| -> Result<String> {
                let record = private(raw.as_bytes())?;
                fields(&record, "format largest_local_time")?;
                version(&record)?;
                let at = text(&record, "largest_local_time")?;
                stamp(at)?;
                Ok(at.into())
            })
            .transpose()?;
        let decision = decision_clock(now, clock.as_deref().unwrap_or("-"))?;
        let projection = Projection::genesis(
            &descriptor,
            catalog,
            &decision,
            &identity.person_public_key,
            &identity.host_public_key,
        )?;
        let member = projection
            .members()?
            .into_iter()
            .find(|m| {
                m.host_public_key == identity.host_public_key
                    && m.person_public_key == identity.person_public_key
                    && m.member == identity.member
            })
            .ok_or_else(|| Error::new("forbidden"))?;
        let root = projection.catalog.get(projection.root_state_id()?)?;
        let network = NetworkRecord {
            format: 2,
            mode: "decentralized".into(),
            descriptor_base64: encode(descriptor_bytes),
            context_id: descriptor.context_id(),
            root_state_id: root.id.clone(),
            own_identity: identity.clone(),
            created_at: decision.clone(),
        };
        let context = ContextRecord {
            format: 1,
            descriptor_base64: network.descriptor_base64.clone(),
            origin: "genesis".into(),
            initial_root_state_id: root.id.clone(),
            origin_proof_id: root.proof_id.clone(),
            migration_proposal_id: "-".into(),
            adopted_at: decision.clone(),
        };
        let empty = serde_json::to_vec(
            &json!({"format":1,"context_id":descriptor.context_id(),"objects":[]}),
        )
        .map_err(|_| Error::new("internal"))?;
        let prior=Prior::read(&descriptor,&json!({"format":1,"context_id":descriptor.context_id(),"catalog_base64":encode(&empty),"admitted_statement_ids":[],"admitted_restriction_ids":[],"admitted_activation_ids":[],"root_head_ids":[],"maxima":[],"migration_proposal_id":"-","clock_guard":decision}))?.ok_or_else(||Error::new("invalid"))?;
        savepoint
            .execute(
                "INSERT INTO networks(id,record,root_seed) VALUES(?1,?2,?3)",
                rusqlite::params![
                    descriptor.network_id,
                    serde_json::to_string(&network).map_err(|_| Error::new("internal"))?,
                    root_seed.as_slice()
                ],
            )
            .map_err(db)?;
        savepoint
            .execute(
                "INSERT INTO dec_contexts(network_id,context_id,record) VALUES(?1,?2,?3)",
                rusqlite::params![
                    descriptor.network_id,
                    descriptor.context_id(),
                    serde_json::to_string(&context).map_err(|_| Error::new("internal"))?
                ],
            )
            .map_err(db)?;
        let clock = json!({"format":1,"largest_local_time":decision});
        savepoint.execute("INSERT INTO dec_clock(network_id,record) VALUES(?1,?2) ON CONFLICT(network_id) DO UPDATE SET record=excluded.record",rusqlite::params![descriptor.network_id,clock.to_string()]).map_err(db)?;
        let initial = Self {
            network,
            context,
            descriptor,
            selection: None,
            prior,
            revision: String::new(),
            migrations: Vec::new(),
        };
        initial.persist(&savepoint, &projection)?;
        savepoint.execute("INSERT INTO dec_signers(network_id,context_id,provider_kind,person_key,device_key,lease_id) VALUES(?1,?2,'original',?3,'-','-')",rusqlite::params![initial.descriptor.network_id,initial.network.context_id,member.person_public_key]).map_err(db)?;
        savepoint
            .execute(
                "INSERT INTO events(kind,subject_id,created_at) VALUES('network.created',?1,?2)",
                rusqlite::params![initial.descriptor.network_id, decision],
            )
            .map_err(db)?;
        let result = Self::load(
            &savepoint,
            &initial.descriptor.network_id,
            &identity.host_public_key,
        )?;
        savepoint.commit().map_err(db)?;
        Ok(result)
    }
}

/// Name collision checks preserve the unchanged legacy record encoding, whose
/// nullable observation fields are not DEC signed/private JSON. This extracts
/// a label only; it never projects that record as decentralized authority.
pub(crate) fn network_name(raw: &str) -> Result<String> {
    let value: Value = serde_json::from_str(raw).map_err(|_| Error::new("state_conflict"))?;
    if value.get("mode").and_then(Value::as_str) == Some("decentralized") {
        let strict = parse(raw.as_bytes(), MAX_PRIVATE)?;
        let record = object(&strict)?;
        Ok(Descriptor::read(&b64(text(record, "descriptor_base64")?, MAX_OBJECT)?)?.name)
    } else {
        let legacy: crate::network::Network =
            serde_json::from_value(value).map_err(|_| Error::new("state_conflict"))?;
        label(&legacy.name)?;
        Ok(legacy.name)
    }
}

/// Inclusive process-local limits across every DEC network. Call before an
/// owned signature and again in its final transaction with exact fanout rows.
/// Existing unknown-failure deliveries are never evicted to manufacture room.
pub fn check_outbox_capacity(connection: &Connection, additions: &[&Value]) -> Result<()> {
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM dec_outbox", [], |r| r.get(0))
        .map_err(db)?;
    require(
        u64::try_from(count)
            .ok()
            .and_then(|count| count.checked_add(additions.len() as u64))
            .is_some_and(|n| n <= 4096),
        "quota_exceeded",
    )?;
    let mut decoded = 0usize;
    let mut stored = 0usize;
    let mut row = |raw: &[u8], corrupt: bool| -> Result<()> {
        stored = stored
            .checked_add(raw.len())
            .ok_or_else(|| Error::new("quota_exceeded"))?;
        require(stored <= 1 << 30, "quota_exceeded")?;
        let value = parse(raw, MAX_PRIVATE).map_err(|e| {
            if corrupt {
                Error::new("state_conflict")
            } else {
                e
            }
        })?;
        let record = object(&value)?;
        fields(
            record,
            "format kind body_base64 proof_ids created_at attempts next_attempt_at last_error_code last_error_detail",
        )?;
        version(record)?;
        check(matches!(
            text(record, "kind")?,
            "proofs" | "activation" | "migration"
        ))?;
        ids(record, "proof_ids", "dp_")?;
        stamp(text(record, "created_at")?)?;
        stamp(text(record, "next_attempt_at")?)?;
        num(record, "attempts")?;
        check(
            text(record, "last_error_code")?.len() <= 1024
                && text(record, "last_error_detail")?.len() <= 1024,
        )?;
        let body = b64(text(record, "body_base64")?, 20 << 20)?;
        decoded = decoded
            .checked_add(body.len())
            .ok_or_else(|| Error::new("quota_exceeded"))?;
        require(decoded <= 512 << 20, "quota_exceeded")?;
        Ok(())
    };
    let mut query = connection
        .prepare("SELECT record FROM dec_outbox ORDER BY delivery_id")
        .map_err(db)?;
    for raw in query.query_map([], |r| r.get::<_, String>(0)).map_err(db)? {
        row(raw.map_err(db)?.as_bytes(), true)?;
    }
    for value in additions {
        row(
            &serde_json::to_vec(value).map_err(|_| Error::new("internal"))?,
            false,
        )?;
    }
    Ok(())
}
