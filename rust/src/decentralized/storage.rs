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

use rusqlite::OptionalExtension;

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
