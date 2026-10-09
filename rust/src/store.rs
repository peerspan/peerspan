use crate::model::{Agent, AttachSession, Error, Event, Identity, RegisterAgent, Session};
use anyhow::{Context, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{SecondsFormat, Utc};
use ed25519_dalek::SigningKey;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, DirBuilder, File, OpenOptions},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard, RwLock,
        atomic::{AtomicI64, AtomicU64},
    },
    time::{Duration, Instant},
};

const SCHEMA: &str = "
CREATE TABLE identity (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), private_key BLOB NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE agents (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, owner TEXT NOT NULL, capabilities TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE sessions (id TEXT PRIMARY KEY, agent_id TEXT NOT NULL REFERENCES agents(id), integration TEXT NOT NULL, state TEXT NOT NULL CHECK (state IN ('attached', 'detached')), created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE INDEX sessions_agent ON sessions(agent_id);
CREATE TABLE events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, subject_id TEXT NOT NULL, created_at TEXT NOT NULL);
PRAGMA user_version = 1;
";

/// Local persistence and installation ownership. Network coordination is not
/// required. The process lock lives for as long as the connection does.
pub struct Store {
    connection: Mutex<Connection>,
    _lock: File,
    directory: PathBuf,
    identity: Identity,
    pub(crate) signing_key: SigningKey,
    pub(crate) peer_pins: RwLock<BTreeMap<String, Vec<u8>>>,
    /// Keys of verified network members other than this host.
    pub(crate) member_pins: RwLock<BTreeMap<String, Vec<u8>>>,
    pub(crate) coordination_interval: AtomicU64,
    pub(crate) advertise: RwLock<String>,
    /// Immutable startup deadlines for previously bound, recoverable instances.
    pub(crate) adapter_recovery_until: BTreeMap<String, Instant>,
    /// The daemon's single QUIC peer endpoint, created on listen or first dial.
    pub(crate) peer_transport: Mutex<Option<Arc<crate::quic::Transport>>>,
    /// Wakes the relay manager when this host creates or joins a network, so
    /// it becomes reachable through the new coordinator without waiting for
    /// the next refresh.
    pub(crate) relay_wake: tokio::sync::Notify,
    /// The peer socket's bound address while listening. Candidates are
    /// published only then.
    pub(crate) peer_bound: RwLock<Option<std::net::SocketAddr>>,
    /// The candidates most recently published to a coordinator.
    pub(crate) candidates: RwLock<Vec<std::net::SocketAddr>>,
    /// The owner's `ssh-agent` socket for policy renewal signatures. The
    /// daemon asks the agent to sign and never holds the key.
    pub(crate) person_agent: RwLock<Option<PathBuf>>,
    /// The CLI-generated person key file (`run --person-key-file`), read
    /// when a renewal needs it, which renews policies when the agent lacks
    /// the key.
    pub(crate) person_key_file: RwLock<Option<PathBuf>>,
    /// Bytes of artifact storage this host allows (`run --artifact-quota`).
    pub(crate) artifact_quota: AtomicI64,
    /// Wakes the policy propagation worker when deliveries are queued.
    pub(crate) policy_wake: tokio::sync::Notify,
    /// Seconds between periodic policy syncs with siblings.
    pub(crate) policy_sync_interval: AtomicU64,
    /// Policy deliveries and sibling syncs in progress, so each runs once.
    pub(crate) policy_inflight: Mutex<std::collections::BTreeSet<String>>,
    /// Coordinator limits each network has reached, by network ID: from the
    /// usage fetched after a sync and from the latest 429. Kept in memory.
    pub(crate) coordinator_limits: Mutex<BTreeMap<String, crate::network::CoordinatorLimits>>,
    /// The agent directory of every network, kept in memory.
    pub(crate) agent_directory: Mutex<crate::directory::Cache>,
}

impl Store {
    pub fn open(directory: &Path) -> anyhow::Result<Self> {
        if directory.as_os_str().is_empty() {
            bail!("state directory is empty");
        }
        let directory = std::path::absolute(directory)?;
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&directory)?;
        let metadata = fs::symlink_metadata(&directory)?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            bail!("state directory must be a private directory (mode 0700)");
        }
        let lock = private_file(&directory.join("host.lock"))?;
        fs2::FileExt::try_lock_exclusive(&lock).context("host state is already in use")?;
        let database_path = directory.join("host.db");
        drop(private_file(&database_path)?);
        let mut connection = Connection::open(database_path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA foreign_keys = ON; PRAGMA synchronous = FULL;")?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if !(0..=13).contains(&version) {
            bail!("unsupported host database version: {version}");
        }
        let tx = connection.transaction()?;
        if version == 0 {
            tx.execute_batch(SCHEMA)?;
        }
        if version < 2 {
            tx.execute_batch(crate::peer_store::SCHEMA)?;
        }
        if version < 3 {
            tx.execute_batch(crate::network::SCHEMA)?;
        }
        if version < 4 {
            tx.execute_batch(crate::adapter::SCHEMA)?;
        }
        if version < 5 {
            tx.execute_batch(crate::adapter_outbound::SCHEMA)?;
        }
        if version < 6 {
            tx.execute_batch(crate::adapter_connection::SCHEMA)?;
        }
        if version < 7 {
            tx.execute_batch(crate::network::STATEMENT_SCHEMA)?;
        }
        if version < 8 {
            tx.execute_batch(crate::policy::SCHEMA)?;
        }
        if version < 9 {
            tx.execute_batch(crate::task::SCHEMA)?;
        }
        if version < 10 {
            tx.execute_batch(crate::artifact::SCHEMA)?;
        }
        if version < 11 {
            tx.execute_batch(crate::chain::SCHEMA)?;
        }
        if version < 12 {
            tx.execute_batch(crate::policy_sync::SCHEMA)?;
        }
        if version < 13 {
            tx.execute_batch(crate::directory::SCHEMA)?;
        }
        let stored: Option<(Vec<u8>, String)> = tx
            .query_row(
                "SELECT private_key, created_at FROM identity WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (private_key, created_at) = match stored {
            Some(stored) => stored,
            None => {
                let mut seed = [0u8; 32];
                getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("random source: {e}"))?;
                let key = SigningKey::from_bytes(&seed).to_keypair_bytes().to_vec();
                let created = now();
                tx.execute(
                    "INSERT INTO identity VALUES (1, ?1, ?2)",
                    params![key, created],
                )?;
                (key, created)
            }
        };
        let key_bytes: [u8; 64] = private_key
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid persisted host identity"))?;
        let signing = SigningKey::from_keypair_bytes(&key_bytes)
            .context("invalid persisted host identity")?;
        chrono::DateTime::parse_from_rfc3339(&created_at)
            .context("invalid identity creation time")?;
        let public = signing.verifying_key().to_bytes();
        let identity = Identity {
            id: format!("host_{}", hex::encode(Sha256::digest(public))),
            public_key: STANDARD.encode(public),
            created_at,
        };
        let stale = {
            let mut statement = tx.prepare("SELECT id FROM sessions WHERE state = 'attached'")?;
            statement
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        let at = now();
        tx.execute(
            "UPDATE sessions SET state = 'detached', updated_at = ?1 WHERE state = 'attached'",
            [&at],
        )?;
        tx.execute("UPDATE adapter_connections SET lease_until_ms = 0", [])?;
        for id in stale {
            append_event(&tx, "session.disconnected", &id, &at)?;
        }
        let recovering = {
            let mut statement = tx.prepare("SELECT adapter_id FROM adapter_connections WHERE instance_hash IS NOT NULL AND recoverable = 1")?;
            statement
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        tx.commit()?;
        let peer_pins = crate::peer_store::load_pins(&connection)?;
        let member_pins = crate::network::load_member_pins(&connection, &identity.id)?;
        let deadline =
            Instant::now() + Duration::from_secs(crate::adapter_connection::LEASE_SECONDS);
        let adapter_recovery_until = recovering.into_iter().map(|id| (id, deadline)).collect();
        let store = Self {
            connection: Mutex::new(connection),
            _lock: lock,
            directory,
            identity,
            signing_key: signing,
            peer_pins: RwLock::new(peer_pins),
            member_pins: RwLock::new(member_pins),
            coordination_interval: AtomicU64::new(30),
            advertise: RwLock::new(String::new()),
            adapter_recovery_until,
            peer_transport: Mutex::new(None),
            relay_wake: tokio::sync::Notify::new(),
            peer_bound: RwLock::new(None),
            candidates: RwLock::new(Vec::new()),
            person_agent: RwLock::new(None),
            person_key_file: RwLock::new(None),
            artifact_quota: AtomicI64::new(crate::artifact::DEFAULT_QUOTA),
            policy_wake: tokio::sync::Notify::new(),
            policy_sync_interval: AtomicU64::new(crate::policy_sync::SYNC_INTERVAL_SECONDS),
            policy_inflight: Mutex::new(Default::default()),
            coordinator_limits: Mutex::new(BTreeMap::new()),
            agent_directory: Mutex::new(Default::default()),
        };
        store.prepare_artifacts(&*store.connection().map_err(|e| anyhow::anyhow!("{e}"))?)?;
        Ok(store)
    }

    /// The private state directory.
    pub(crate) fn state_directory(&self) -> &Path {
        &self.directory
    }

    pub fn identity(&self) -> Identity {
        self.identity.clone()
    }
    pub fn socket_path(&self) -> PathBuf {
        self.directory.join("admin.sock")
    }

    pub(crate) fn connection(&self) -> Result<MutexGuard<'_, Connection>, Error> {
        self.connection
            .lock()
            .map_err(|_| Error::Internal(anyhow::anyhow!("host store lock poisoned")))
    }

    pub fn register_agent(&self, request: RegisterAgent) -> Result<Agent, Error> {
        let name = request.name.trim().to_owned();
        let owner = request.owner.trim().to_owned();
        if name.is_empty() || owner.is_empty() {
            return Err(Error::Invalid("name and owner are required".into()));
        }
        if name.len() > 128 || owner.len() > 128 {
            return Err(Error::Invalid(
                "name and owner must be at most 128 bytes".into(),
            ));
        }
        if name == crate::policy::ALL_AGENTS {
            return Err(Error::Invalid(format!(
                "the agent name {name:?} is reserved: policy rules use it for every agent"
            )));
        }
        let mut capabilities = Vec::new();
        for capability in request.capabilities {
            let capability = capability.trim().to_owned();
            if capability.is_empty() || capability.len() > 256 {
                return Err(Error::Invalid("invalid capability name".into()));
            }
            if !capabilities.contains(&capability) {
                capabilities.push(capability);
            }
        }
        let agent = Agent {
            id: new_id("agent")?,
            name,
            owner,
            capabilities,
            created_at: now(),
        };
        let encoded = serde_json::to_string(&agent.capabilities)?;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let exists: i64 = tx.query_row(
            "SELECT COUNT(*) FROM agents WHERE name = ?1",
            [&agent.name],
            |r| r.get(0),
        )?;
        if exists != 0 {
            return Err(Error::Conflict("agent name already exists".into()));
        }
        tx.execute(
            "INSERT INTO agents VALUES (?1, ?2, ?3, ?4, ?5)",
            params![agent.id, agent.name, agent.owner, encoded, agent.created_at],
        )?;
        append_event(&tx, "agent.registered", &agent.id, &agent.created_at)?;
        tx.commit()?;
        Ok(agent)
    }

    pub fn agent(&self, id: &str) -> Result<Agent, Error> {
        Ok(self.connection()?.query_row(
            "SELECT id, name, owner, capabilities, created_at FROM agents WHERE id = ?1",
            [id],
            read_agent,
        )?)
    }

    pub fn agents(&self) -> Result<Vec<Agent>, Error> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id, name, owner, capabilities, created_at FROM agents ORDER BY created_at, id",
        )?;
        Ok(statement
            .query_map([], read_agent)?
            .collect::<Result<Vec<_>, _>>()?)
    }

    pub fn attach_session(&self, request: AttachSession) -> Result<Session, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let session = Self::attach_session_in(&tx, request, None)?;
        tx.commit()?;
        Ok(session)
    }
    pub(crate) fn attach_session_in(
        tx: &rusqlite::Transaction<'_>,
        request: AttachSession,
        id: Option<String>,
    ) -> Result<Session, Error> {
        let integration = request.integration.trim().to_owned();
        if request.agent_id.is_empty() || integration.is_empty() || integration.len() > 128 {
            return Err(Error::Invalid(
                "agent_id and integration are required; integration must be at most 128 bytes"
                    .into(),
            ));
        }
        let at = now();
        let session = Session {
            id: match id {
                Some(id) if crate::peer_store::valid_id(&id, "session", 16) => id,
                Some(_) => return Err(Error::Invalid("invalid session ID".into())),
                None => new_id("session")?,
            },
            agent_id: request.agent_id,
            integration,
            state: "attached".into(),
            created_at: at.clone(),
            updated_at: at,
        };
        let exists: i64 = tx.query_row(
            "SELECT COUNT(*) FROM sessions WHERE id = ?1",
            [&session.id],
            |r| r.get(0),
        )?;
        if exists != 0 {
            return Err(Error::Conflict("session already exists".into()));
        }
        tx.query_row(
            "SELECT id FROM agents WHERE id = ?1",
            [&session.agent_id],
            |r| r.get::<_, String>(0),
        )?;
        tx.execute(
            "INSERT INTO sessions VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                session.id,
                session.agent_id,
                session.integration,
                session.state,
                session.created_at,
                session.updated_at
            ],
        )?;
        append_event(tx, "session.attached", &session.id, &session.created_at)?;
        Ok(session)
    }

    pub fn session(&self, id: &str) -> Result<Session, Error> {
        Ok(self.connection()?.query_row("SELECT id, agent_id, integration, state, created_at, updated_at FROM sessions WHERE id = ?1", [id], read_session)?)
    }

    pub fn sessions(&self, agent_id: &str) -> Result<Vec<Session>, Error> {
        let connection = self.connection()?;
        if !agent_id.is_empty() {
            connection.query_row("SELECT id FROM agents WHERE id = ?1", [agent_id], |r| {
                r.get::<_, String>(0)
            })?;
        }
        let mut statement = connection.prepare("SELECT id, agent_id, integration, state, created_at, updated_at FROM sessions WHERE (?1 = '' OR agent_id = ?1) ORDER BY created_at, id")?;
        Ok(statement
            .query_map([agent_id], read_session)?
            .collect::<Result<Vec<_>, _>>()?)
    }

    pub fn detach_session(&self, id: &str) -> Result<Session, Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let mut session = tx.query_row("SELECT id, agent_id, integration, state, created_at, updated_at FROM sessions WHERE id = ?1", [id], read_session)?;
        let changed=tx.execute("UPDATE adapter_connections SET recoverable = 0,lease_until_ms = 0 WHERE adapter_id IN (SELECT id FROM adapter_credentials WHERE session_id = ?1) AND recoverable = 1",[id])?;
        if session.state == "detached" && changed == 0 {
            return Ok(session);
        }
        session.state = "detached".into();
        session.updated_at = now();
        tx.execute(
            "UPDATE sessions SET state = ?1, updated_at = ?2 WHERE id = ?3",
            params![session.state, session.updated_at, id],
        )?;
        append_event(&tx, "session.detached", id, &session.updated_at)?;
        tx.commit()?;
        Ok(session)
    }

    pub fn events(&self, after: i64, limit: i64) -> Result<Vec<Event>, Error> {
        if after < 0 || !(1..=1000).contains(&limit) {
            return Err(Error::Invalid(
                "after must be nonnegative and limit must be between 1 and 1000".into(),
            ));
        }
        let connection = self.connection()?;
        let mut statement = connection.prepare("SELECT sequence, kind, subject_id, created_at FROM events WHERE sequence > ?1 ORDER BY sequence LIMIT ?2")?;
        Ok(statement
            .query_map(params![after, limit], |r| {
                Ok(Event {
                    sequence: r.get(0)?,
                    kind: r.get(1)?,
                    subject_id: r.get(2)?,
                    created_at: r.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?)
    }
}

fn private_file(path: &Path) -> anyhow::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        bail!("host state file must be private and regular");
    }
    Ok(file)
}

/// Matches Go's RFC3339Nano spelling (trailing fractional zeros removed), so a
/// stored timestamp reads back identically through either implementation.
pub(crate) fn now() -> String {
    rfc3339(Utc::now())
}

pub(crate) fn rfc3339(time: chrono::DateTime<Utc>) -> String {
    let full = time.to_rfc3339_opts(SecondsFormat::Nanos, true);
    let (fraction_start, fraction_end) = (full.len() - 11, full.len() - 1);
    let trimmed = full[fraction_start..fraction_end].trim_end_matches('0');
    let fraction = if trimmed == "." { "" } else { trimmed };
    format!("{}{fraction}Z", &full[..fraction_start])
}

pub(crate) fn new_id(prefix: &str) -> Result<String, Error> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|e| Error::Internal(anyhow::anyhow!("random source: {e}")))?;
    Ok(format!("{prefix}_{}", hex::encode(bytes)))
}

pub(crate) fn append_event(
    tx: &Transaction<'_>,
    kind: &str,
    subject: &str,
    at: &str,
) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO events (kind, subject_id, created_at) VALUES (?1, ?2, ?3)",
        params![kind, subject, at],
    )?;
    Ok(())
}

fn read_agent(row: &rusqlite::Row<'_>) -> rusqlite::Result<Agent> {
    let encoded: String = row.get(3)?;
    let capabilities = serde_json::from_str(&encoded).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(e))
    })?;
    Ok(Agent {
        id: row.get(0)?,
        name: row.get(1)?,
        owner: row.get(2)?,
        capabilities,
        created_at: row.get(4)?,
    })
}

fn read_session(row: &rusqlite::Row<'_>) -> rusqlite::Result<Session> {
    Ok(Session {
        id: row.get(0)?,
        agent_id: row.get(1)?,
        integration: row.get(2)?,
        state: row.get(3)?,
        created_at: row.get(4)?,
        updated_at: row.get(5)?,
    })
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    #[test]
    fn timestamps_use_go_rfc3339_nano_spelling() {
        let at = |nanos| super::rfc3339(Utc.timestamp_opt(1_790_000_000, nanos).unwrap());
        assert_eq!(at(758_529_830), "2026-09-21T14:13:20.75852983Z");
        assert_eq!(at(241_260_800), "2026-09-21T14:13:20.2412608Z");
        assert_eq!(at(416_958_318), "2026-09-21T14:13:20.416958318Z");
        assert_eq!(at(0), "2026-09-21T14:13:20Z");
    }
}
