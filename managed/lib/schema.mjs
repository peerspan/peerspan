// Store schema and migrations. Runs on the storage worker thread only.
//
// Version 1 (contract section 13) was one `records(kind, id, body)` table with
// `PRAGMA user_version` 0. Version 2 is relational, so that the two exclusion
// rules of contract section 4 are constraints of the store itself and history
// is read through indexes instead of whole-table scans.
import { DatabaseSync } from 'node:sqlite';
import { chmodSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';

export const SCHEMA_VERSION = 2;
export const BACKUP_NAME = 'managed.v1-backup.sqlite';

// States in which a task still reserves its target and its run its workflow.
export const OPEN_STATES = ['submitting', 'queued', 'running'];

const DDL = `
CREATE TABLE connections (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  mode TEXT NOT NULL CHECK (mode IN ('file', 'agent')),
  worker_state TEXT,
  host_dir TEXT,
  host_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  sender_state TEXT,
  ready INTEGER,
  ready_since TEXT,
  created_at TEXT NOT NULL,
  removed_at TEXT
);

CREATE TABLE observations (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  directory TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE workflows (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  instructions TEXT NOT NULL,
  interval_minutes INTEGER NOT NULL,
  max_runs_per_day INTEGER NOT NULL,
  acceptance_minutes INTEGER NOT NULL,
  enabled INTEGER NOT NULL,
  paused_by TEXT CHECK (paused_by IN ('operator', 'failures')),
  paused_at TEXT,
  next_run_at TEXT NOT NULL,
  failure_streak INTEGER NOT NULL DEFAULT 0,
  blocked_reason TEXT,
  -- Terminal runs since the operator last acted on this workflow.
  unattended_runs INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  archived_at TEXT
);

-- One durable Peerspan submission. Its identity and payload are written
-- before any external effect and never change afterwards.
CREATE TABLE tasks (
  task_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'work',
  connection_id TEXT,
  target TEXT NOT NULL,
  peer TEXT NOT NULL,
  agent TEXT NOT NULL,
  sender_state TEXT,
  input TEXT NOT NULL,
  deadline TEXT NOT NULL,
  state TEXT NOT NULL,
  open INTEGER NOT NULL,
  output TEXT,
  output_truncated INTEGER NOT NULL DEFAULT 0,
  error TEXT,
  problem_since TEXT,
  reason TEXT,
  progress TEXT,
  retry_at TEXT,
  cancel_requested_at TEXT,
  cancel_sent_at TEXT,
  last_event INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT
);
-- One unresolved task per worker agent, host and agent (contract section 4).
CREATE UNIQUE INDEX tasks_open_target ON tasks(target) WHERE open = 1;
CREATE INDEX tasks_finished ON tasks(finished_at);

CREATE TABLE runs (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT NOT NULL UNIQUE,
  workflow_id TEXT NOT NULL,
  task_id TEXT NOT NULL UNIQUE,
  open INTEGER NOT NULL,
  created_at TEXT NOT NULL
);
-- One unresolved run per workflow (contract section 4).
CREATE UNIQUE INDEX runs_open_workflow ON runs(workflow_id) WHERE open = 1;
CREATE INDEX runs_workflow ON runs(workflow_id, seq);
CREATE INDEX runs_workflow_created ON runs(workflow_id, created_at);
CREATE INDEX runs_created ON runs(created_at);

CREATE TABLE task_events (
  task_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  kind TEXT NOT NULL,
  state TEXT,
  message TEXT,
  at TEXT,
  PRIMARY KEY (task_id, sequence)
) WITHOUT ROWID;

CREATE TABLE activity (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  actor TEXT NOT NULL CHECK (actor IN ('operator', 'system')),
  kind TEXT NOT NULL,
  workflow_id TEXT,
  run_id TEXT,
  connection_id TEXT,
  data TEXT
);
CREATE INDEX activity_workflow ON activity(workflow_id, seq);
`;

function tableExists(db, name) {
  return Boolean(db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(name));
}

function userVersion(db) {
  return db.prepare('PRAGMA user_version').get().user_version;
}

function parseBody(row) {
  const body = JSON.parse(row.body);
  if (!body || typeof body !== 'object' || body.id !== row.id) throw new Error('Version 1 state has an invalid record');
  return body;
}

// Version 1 to version 2, inside the caller's transaction.
function migrateFromV1(db, now) {
  db.exec(DDL);
  const rows = kind => db.prepare('SELECT id, body FROM records WHERE kind = ? ORDER BY rowid').all(kind).map(parseBody);

  const addConnection = db.prepare(`INSERT INTO connections
    (id, name, mode, worker_state, host_dir, host_id, agent_id, sender_state, created_at)
    VALUES (?, ?, 'file', ?, ?, ?, ?, ?, ?)`);
  for (const c of rows('connection')) {
    addConnection.run(c.id, c.name, c.workerState, c.hostDir, c.hostId, c.agentId, c.senderState ?? null, now);
  }

  const addObservation = db.prepare('INSERT INTO observations (id, name, directory, created_at) VALUES (?, ?, ?, ?)');
  for (const o of rows('observation')) addObservation.run(o.id, o.name, o.directory, now);

  const addWorkflow = db.prepare(`INSERT INTO workflows
    (id, name, connection_id, instructions, interval_minutes, max_runs_per_day, acceptance_minutes,
     enabled, paused_by, paused_at, next_run_at, failure_streak, blocked_reason, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
  for (const w of rows('workflow')) {
    const enabled = w.enabled ? 1 : 0;
    const pausedBy = enabled ? null : w.failureStreak >= 3 ? 'failures' : 'operator';
    const created = w.createdAt || now;
    addWorkflow.run(w.id, w.name, w.connectionId, w.instructions, w.intervalMinutes, w.maxRunsPerDay,
      w.acceptanceMinutes, enabled, pausedBy, enabled ? null : now, w.nextRunAt || now,
      w.failureStreak || 0, w.blockedReason ?? null, created, created);
  }

  const addTask = db.prepare(`INSERT INTO tasks
    (task_id, run_id, role, connection_id, target, peer, agent, sender_state, input, deadline, state, open,
     output, error, problem_since, retry_at, created_at, updated_at, finished_at)
    VALUES (?, ?, 'work', (SELECT connection_id FROM workflows WHERE id = ?), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
      ?, ?, ?)`);
  const addRun = db.prepare('INSERT INTO runs (id, workflow_id, task_id, open, created_at) VALUES (?, ?, ?, ?, ?)');
  for (const r of rows('run')) {
    const open = OPEN_STATES.includes(r.state) ? 1 : 0;
    const s = r.submission;
    if (!s) throw new Error('Version 1 state has a run without its submission');
    // The target is derived from the submission itself, the same way new reservations derive it.
    const target = JSON.stringify([s.peer, s.agent]);
    addTask.run(r.taskId, r.id, r.workflowId, target, s.peer, s.agent, s.senderState ?? null, s.input,
      s.deadline, r.state, open, r.output ?? null, open ? r.error ?? null : null,
      open && r.error ? r.updatedAt : null, open ? r.retryAt ?? null : null, r.createdAt,
      r.updatedAt || r.createdAt, open ? null : r.finishedAt || r.updatedAt || r.createdAt);
    addRun.run(r.id, r.workflowId, r.taskId, open, r.createdAt);
  }
  // Version 1 recorded no operator actions, so every finished run counts as unattended.
  db.exec(`UPDATE workflows SET unattended_runs =
    (SELECT COUNT(*) FROM runs WHERE runs.workflow_id = workflows.id AND runs.open = 0)`);
  db.exec('DROP TABLE records');
}

/**
 * Opens the state database, creating or migrating it as needed.
 * Throws without changing anything when the file was written by a newer schema.
 */
export function openDatabase(file) {
  const existed = existsSync(file);
  const db = new DatabaseSync(file);
  try {
    // Read the version before any pragma that would write to the file.
    const version = userVersion(db);
    if (version > SCHEMA_VERSION) {
      throw new Error(`State was written by a newer Peerspan Managed (schema ${version}); this version reads schema ${SCHEMA_VERSION}`);
    }
    db.exec('PRAGMA busy_timeout = 5000');
    const isV1 = version === 0 && tableExists(db, 'records');
    if (isV1) {
      const backup = join(dirname(file), BACKUP_NAME);
      if (!existsSync(backup)) {
        db.exec(`VACUUM INTO '${backup.replaceAll("'", "''")}'`);
        chmodSync(backup, 0o600);
      }
    }
    db.exec('PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON');
    if (version < SCHEMA_VERSION) {
      db.exec('BEGIN IMMEDIATE');
      try {
        // Another process may have migrated while this one waited for the lock.
        if (userVersion(db) < SCHEMA_VERSION) {
          if (tableExists(db, 'records')) migrateFromV1(db, new Date().toISOString());
          else db.exec(DDL);
          db.exec(`PRAGMA user_version = ${SCHEMA_VERSION}`);
        }
        db.exec('COMMIT');
      } catch (error) {
        db.exec('ROLLBACK');
        throw error;
      }
    }
    if (!existed) chmodSync(file, 0o600);
    return db;
  } catch (error) {
    db.close();
    throw error;
  }
}
