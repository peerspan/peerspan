// The controller's state transitions. Runs on the storage worker thread, where
// node:sqlite is synchronous: the worker wraps each call below in one
// transaction, so every operation is atomic and no two interleave. Nothing here
// performs I/O other than SQLite, and every external effect elsewhere is
// preceded by one of these writes (contract section 4).
import { randomBytes, randomUUID } from 'node:crypto';

const MINUTE = 60_000;
const WINDOW_DAYS = 7;
const ACTIVITY_LIMIT = 5000;
const EVENT_LIMIT = 500;
const PREVIEW_CHARS = 2000;

export const FAILURE_LIMIT = 3;
export const OUTPUT_LIMIT = 262_144;

const TERMINAL = new Set(['succeeded', 'failed', 'rejected', 'expired', 'cancelled', 'abandoned']);

const PAUSED_BY_OPERATOR = 'Paused by operator';
const PAUSED_BY_FAILURES = 'Paused after three consecutive failures';

/** A request the current state does not permit; `status` is the HTTP status. */
export class Refusal extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const iso = ms => new Date(ms).toISOString();

// A worker agent takes one assignment at a time, whichever sender submits it (MGD-6).
export const targetOf = connection => JSON.stringify([connection.host_id, connection.agent_id]);

// An operator's own decision is not a worker failure (contract section 4).
const isOperatorResult = task =>
  task.state === 'abandoned' || (task.state === 'cancelled' && task.cancel_requested_at !== null);

function connectionRecord(row) {
  return {
    id: row.id,
    name: row.name,
    mode: row.mode,
    workerState: row.worker_state,
    hostDir: row.host_dir,
    hostId: row.host_id,
    agentId: row.agent_id,
    senderState: row.sender_state
  };
}

function taskRecord(row) {
  return {
    taskId: row.task_id,
    runId: row.run_id,
    state: row.state,
    peer: row.peer,
    agent: row.agent,
    senderState: row.sender_state,
    input: row.input,
    deadline: row.deadline,
    retryAt: row.retry_at,
    cancelRequestedAt: row.cancel_requested_at,
    cancelSentAt: row.cancel_sent_at,
    lastEvent: row.last_event,
    startedAt: row.started_at
  };
}

function workflowView(row) {
  return {
    id: row.id,
    name: row.name,
    connectionId: row.connection_id,
    instructions: row.instructions,
    intervalMinutes: row.interval_minutes,
    maxRunsPerDay: row.max_runs_per_day,
    acceptanceMinutes: row.acceptance_minutes,
    enabled: row.enabled === 1,
    nextRunAt: row.next_run_at,
    failureStreak: row.failure_streak,
    blockedReason: row.blocked_reason,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    pausedBy: row.enabled === 1 ? null : row.paused_by || 'operator'
  };
}

const RUN_COLUMNS = `r.seq, r.id, r.workflow_id, w.name AS workflow_name, t.task_id, t.state,
  t.output_truncated, t.error, t.problem_since, t.reason, t.progress, t.cancel_requested_at,
  r.created_at, t.updated_at, t.started_at, t.finished_at`;
const RUN_SOURCE = `runs r JOIN tasks t ON t.task_id = r.task_id LEFT JOIN workflows w ON w.id = r.workflow_id`;
const RUN_PREVIEW = `SELECT ${RUN_COLUMNS}, substr(t.output, 1, ${PREVIEW_CHARS}) AS output,
  length(t.output) > ${PREVIEW_CHARS} AS output_longer FROM ${RUN_SOURCE}`;
const RUN_FULL = `SELECT ${RUN_COLUMNS}, t.output, t.input, 0 AS output_longer FROM ${RUN_SOURCE}`;

function runView(row) {
  return {
    id: row.id,
    workflowId: row.workflow_id,
    workflowName: row.workflow_name ?? 'Workflow',
    taskId: row.task_id,
    state: row.state,
    output: row.output,
    outputTruncated: row.output_truncated === 1 || row.output_longer === 1,
    error: row.error,
    reason: row.reason,
    progress: row.progress,
    cancelRequestedAt: row.cancel_requested_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    startedAt: row.started_at,
    finishedAt: row.finished_at
  };
}

function activityView(row) {
  return {
    seq: row.seq,
    at: row.at,
    actor: row.actor,
    kind: row.kind,
    workflowId: row.workflow_id,
    runId: row.run_id,
    connectionId: row.connection_id,
    data: row.data === null ? null : JSON.parse(row.data)
  };
}

export class Model {
  constructor(db) {
    this.db = db;
    this.prepared = new Map();
  }

  statement(text) {
    let statement = this.prepared.get(text);
    if (!statement) {
      statement = this.db.prepare(text);
      this.prepared.set(text, statement);
    }
    return statement;
  }

  one(text, ...values) {
    return this.statement(text).get(...values);
  }

  all(text, ...values) {
    return this.statement(text).all(...values);
  }

  run(text, ...values) {
    return this.statement(text).run(...values);
  }

  // ----- activity -------------------------------------------------------------

  log(now, actor, kind, { workflowId = null, runId = null, connectionId = null, data = null } = {}) {
    const { lastInsertRowid } = this.run(
      'INSERT INTO activity (at, actor, kind, workflow_id, run_id, connection_id, data) VALUES (?, ?, ?, ?, ?, ?, ?)',
      now, actor, kind, workflowId, runId, connectionId, data === null ? null : JSON.stringify(data));
    const seq = Number(lastInsertRowid);
    if (seq % 100 === 0) this.run('DELETE FROM activity WHERE seq <= ?', seq - ACTIVITY_LIMIT);
    // Every operator action on a workflow after its creation is an intervention.
    if (actor === 'operator' && workflowId && kind !== 'workflow.created') {
      this.run('UPDATE workflows SET unattended_runs = 0 WHERE id = ?', workflowId);
    }
  }

  listActivity({ before = null, limit = 50 } = {}) {
    const rows = before === null
      ? this.all('SELECT * FROM activity ORDER BY seq DESC LIMIT ?', limit + 1)
      : this.all('SELECT * FROM activity WHERE seq < ? ORDER BY seq DESC LIMIT ?', before, limit + 1);
    const page = rows.slice(0, limit);
    return {
      activity: page.map(activityView),
      nextBefore: rows.length > limit ? page.at(-1).seq : null
    };
  }

  // ----- connections and observations (local commands) -------------------------

  addConnection(connection, now) {
    this.run(`INSERT INTO connections
      (id, name, mode, worker_state, host_dir, host_id, agent_id, sender_state, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    connection.id, connection.name, connection.mode, connection.workerState, connection.hostDir,
    connection.hostId, connection.agentId, connection.senderState, now);
    this.log(now, 'operator', 'connection.added', { connectionId: connection.id });
    return {
      id: connection.id,
      name: connection.name,
      hostId: connection.hostId,
      agentId: connection.agentId,
      mode: connection.mode
    };
  }

  removeConnection(id, now) {
    if (!this.one('SELECT 1 FROM connections WHERE id = ? AND removed_at IS NULL', id)) {
      throw new Refusal(404, 'Unknown connection');
    }
    if (this.one('SELECT 1 FROM workflows WHERE connection_id = ? AND archived_at IS NULL LIMIT 1', id)) {
      throw new Refusal(409, 'A workflow still uses this connection; archive the workflow or move it to another worker first');
    }
    if (this.one('SELECT 1 FROM tasks WHERE connection_id = ? AND open = 1 LIMIT 1', id)) {
      throw new Refusal(409, 'A run on this connection is unresolved');
    }
    this.run('UPDATE connections SET removed_at = ? WHERE id = ?', now, id);
    this.log(now, 'operator', 'connection.removed', { connectionId: id });
    return { id, removed: true };
  }

  listConnections() {
    return this.all('SELECT * FROM connections WHERE removed_at IS NULL ORDER BY rowid').map(connectionRecord);
  }

  addObservation(observation, now) {
    this.run('INSERT INTO observations (id, name, directory, created_at) VALUES (?, ?, ?, ?)',
      observation.id, observation.name, observation.directory, now);
    this.log(now, 'operator', 'observation.added');
    return { id: observation.id, name: observation.name };
  }

  removeObservation(id, now) {
    const { changes } = this.run('DELETE FROM observations WHERE id = ?', id);
    if (!changes) throw new Refusal(404, 'Unknown observation');
    this.log(now, 'operator', 'observation.removed');
    return { id, removed: true };
  }

  listObservations() {
    return this.all('SELECT id, name, directory FROM observations ORDER BY rowid');
  }

  /** Records a readiness result; returns when `ready` last changed. */
  recordReadiness(id, ready, code, now) {
    const row = this.one('SELECT ready, ready_since FROM connections WHERE id = ? AND removed_at IS NULL', id);
    if (!row) return null;
    const value = ready ? 1 : 0;
    if (row.ready === value) return row.ready_since;
    this.run('UPDATE connections SET ready = ?, ready_since = ? WHERE id = ?', value, now, id);
    this.log(now, 'system', ready ? 'worker.ready' : 'worker.unready', { connectionId: id, data: { code } });
    return now;
  }

  // ----- workflows ---------------------------------------------------------------

  workflowRow(id) {
    const row = this.one('SELECT * FROM workflows WHERE id = ?', id);
    if (!row) throw new Refusal(404, 'Workflow not found');
    return row;
  }

  activeWorkflowRow(id) {
    const row = this.workflowRow(id);
    if (row.archived_at !== null) throw new Refusal(409, 'Workflow is archived; restore it first');
    return row;
  }

  hasConnection(id) {
    return Boolean(this.one('SELECT 1 FROM connections WHERE id = ? AND removed_at IS NULL', id));
  }

  workflowDetail(id, now) {
    const row = this.workflowRow(id);
    const since = iso(Date.parse(now) - WINDOW_DAYS * 24 * 60 * MINUTE);
    return this.decorate(row, this.statistics(since));
  }

  createWorkflow(fields, now) {
    if (!this.hasConnection(fields.connectionId)) throw new Refusal(400, 'Unknown worker connection');
    const id = randomUUID();
    const enabled = fields.enabled ? 1 : 0;
    this.run(`INSERT INTO workflows
      (id, name, connection_id, instructions, interval_minutes, max_runs_per_day, acceptance_minutes,
       enabled, paused_by, paused_at, next_run_at, failure_streak, blocked_reason, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)`,
    id, fields.name, fields.connectionId, fields.instructions, fields.intervalMinutes,
    fields.maxRunsPerDay, fields.acceptanceMinutes, enabled, enabled ? null : 'operator',
    enabled ? null : now, now, enabled ? null : PAUSED_BY_OPERATOR, now, now);
    this.log(now, 'operator', 'workflow.created', { workflowId: id });
    return this.workflowDetail(id, now);
  }

  editWorkflow(id, patch, now) {
    const row = this.activeWorkflowRow(id);
    if (patch.connectionId !== undefined && !this.hasConnection(patch.connectionId)) {
      throw new Refusal(400, 'Unknown worker connection');
    }
    const columns = {
      name: 'name',
      connectionId: 'connection_id',
      instructions: 'instructions',
      intervalMinutes: 'interval_minutes',
      maxRunsPerDay: 'max_runs_per_day',
      acceptanceMinutes: 'acceptance_minutes'
    };
    const changed = Object.keys(patch).filter(key => patch[key] !== row[columns[key]]).sort();
    if (!changed.length) return this.workflowDetail(id, now);
    for (const key of changed) this.run(`UPDATE workflows SET ${columns[key]} = ? WHERE id = ?`, patch[key], id);
    if (changed.includes('intervalMinutes')) {
      const latest = this.one(`SELECT t.finished_at FROM runs r JOIN tasks t ON t.task_id = r.task_id
        WHERE r.workflow_id = ? AND t.open = 0 ORDER BY r.seq DESC LIMIT 1`, id);
      if (latest?.finished_at) {
        this.run('UPDATE workflows SET next_run_at = ? WHERE id = ?',
          iso(Date.parse(latest.finished_at) + patch.intervalMinutes * MINUTE), id);
      }
    }
    this.run('UPDATE workflows SET updated_at = ? WHERE id = ?', now, id);
    this.log(now, 'operator', 'workflow.edited', { workflowId: id, data: { fields: changed } });
    return this.workflowDetail(id, now);
  }

  workflowAction(id, action, now) {
    if (action === 'restore') {
      const row = this.workflowRow(id);
      if (row.archived_at === null) throw new Refusal(409, 'Workflow is not archived');
      this.run(`UPDATE workflows SET archived_at = NULL, enabled = 0, paused_by = 'operator', paused_at = ?,
        failure_streak = 0, blocked_reason = ?, updated_at = ? WHERE id = ?`, now, PAUSED_BY_OPERATOR, now, id);
      this.log(now, 'operator', 'workflow.restored', { workflowId: id });
      return this.workflowDetail(id, now);
    }
    const row = this.activeWorkflowRow(id);
    if (action === 'pause') {
      // Pausing a workflow the failure circuit already paused keeps that cause visible.
      if (row.enabled === 1) {
        this.run(`UPDATE workflows SET enabled = 0, paused_by = 'operator', paused_at = ?, blocked_reason = ?,
          updated_at = ? WHERE id = ?`, now, PAUSED_BY_OPERATOR, now, id);
      }
      this.log(now, 'operator', 'workflow.paused', { workflowId: id });
    } else if (action === 'resume') {
      this.run(`UPDATE workflows SET enabled = 1, paused_by = NULL, paused_at = NULL, failure_streak = 0,
        blocked_reason = NULL, updated_at = ? WHERE id = ?`, now, id);
      this.log(now, 'operator', 'workflow.resumed', { workflowId: id });
    } else if (action === 'run') {
      this.run('UPDATE workflows SET next_run_at = ?, updated_at = ? WHERE id = ?', now, now, id);
      this.log(now, 'operator', 'workflow.run_requested', { workflowId: id });
    } else if (action === 'archive') {
      if (this.one('SELECT 1 FROM runs WHERE workflow_id = ? AND open = 1', id)) {
        throw new Refusal(409, 'Workflow has an unresolved run; wait for it, cancel it or release it first');
      }
      this.run(`UPDATE workflows SET archived_at = ?, enabled = 0, paused_by = 'operator', paused_at = ?,
        blocked_reason = ?, updated_at = ? WHERE id = ?`, now, now, PAUSED_BY_OPERATOR, now, id);
      this.log(now, 'operator', 'workflow.archived', { workflowId: id });
    } else {
      throw new Refusal(404, 'Unknown action');
    }
    return this.workflowDetail(id, now);
  }

  // ----- dispatch ------------------------------------------------------------------

  /**
   * Decides, for every workflow, whether it may dispatch now, and reserves a run
   * for each one that may. `readiness` maps connection IDs to `{ready, reason}`.
   * Returns the reserved tasks; nothing has been sent for them yet.
   */
  planDispatch(now, readiness) {
    const dayStart = now.slice(0, 10) + 'T00:00:00.000Z';
    const reserved = [];
    const workflows = this.all('SELECT * FROM workflows WHERE archived_at IS NULL ORDER BY next_run_at, rowid');
    for (const workflow of workflows) {
      const connection = this.one('SELECT * FROM connections WHERE id = ? AND removed_at IS NULL', workflow.connection_id);
      const reason = this.blockedReason(workflow, connection, readiness, now, dayStart);
      if (reason === null) {
        reserved.push(this.reserve(workflow, connection, now));
      } else if (reason !== workflow.blocked_reason) {
        this.run('UPDATE workflows SET blocked_reason = ? WHERE id = ?', reason, workflow.id);
      }
    }
    return reserved;
  }

  blockedReason(workflow, connection, readiness, now, dayStart) {
    if (workflow.enabled !== 1) return workflow.paused_by === 'failures' ? PAUSED_BY_FAILURES : PAUSED_BY_OPERATOR;
    if (this.one('SELECT 1 FROM runs WHERE workflow_id = ? AND open = 1', workflow.id)) return 'Assignment in progress';
    if (this.dispatchedSince(workflow.id, dayStart) >= workflow.max_runs_per_day) return 'Daily dispatch limit reached';
    const state = connection && readiness[connection.id];
    if (!state?.ready) return state?.reason || 'Worker unavailable';
    if (this.one('SELECT 1 FROM tasks WHERE peer = ? AND agent = ? AND open = 1', connection.host_id, connection.agent_id)) {
      return 'Worker is assigned to another managed workflow';
    }
    if (workflow.next_run_at > now) return 'Waiting for next scheduled run';
    return null;
  }

  dispatchedSince(workflowId, dayStart) {
    return this.one('SELECT COUNT(*) AS count FROM runs WHERE workflow_id = ? AND created_at >= ?', workflowId, dayStart).count;
  }

  reserve(workflow, connection, now) {
    const runId = randomUUID();
    const taskId = 'task_' + randomBytes(16).toString('hex');
    const deadline = iso(Date.parse(now) + workflow.acceptance_minutes * MINUTE);
    // Persist before every external effect. A crash can replay only these bytes.
    this.run(`INSERT INTO tasks
      (task_id, run_id, role, connection_id, target, peer, agent, sender_state, input, deadline, state, open,
       created_at, updated_at)
      VALUES (?, ?, 'work', ?, ?, ?, ?, ?, ?, ?, 'submitting', 1, ?, ?)`,
    taskId, runId, connection.id, targetOf(connection), connection.host_id, connection.agent_id,
    connection.sender_state, workflow.instructions, deadline, now, now);
    this.run('INSERT INTO runs (id, workflow_id, task_id, open, created_at) VALUES (?, ?, ?, 1, ?)',
      runId, workflow.id, taskId, now);
    this.run("UPDATE workflows SET blocked_reason = 'Assignment in progress' WHERE id = ?", workflow.id);
    this.log(now, 'system', 'run.dispatched', { workflowId: workflow.id, runId });
    return taskRecord(this.one('SELECT * FROM tasks WHERE task_id = ?', taskId));
  }

  // ----- reconciliation --------------------------------------------------------------

  openTasks() {
    return this.all('SELECT * FROM tasks WHERE open = 1 ORDER BY created_at, task_id').map(taskRecord);
  }

  /** Whether a not-yet-accepted task may (still) be sent: not released, not cancel-requested. */
  maySubmit(taskId) {
    return Boolean(this.one(
      "SELECT 1 FROM tasks WHERE task_id = ? AND open = 1 AND state = 'submitting' AND cancel_requested_at IS NULL", taskId));
  }

  /** Whether the controller may still act on a task at all. */
  isOpen(taskId) {
    return Boolean(this.one('SELECT 1 FROM tasks WHERE task_id = ? AND open = 1', taskId));
  }

  markCancelSent(taskId, now) {
    this.run('UPDATE tasks SET cancel_sent_at = ? WHERE task_id = ? AND open = 1 AND cancel_sent_at IS NULL', now, taskId);
  }

  /**
   * Applies what a reconciliation pass learned about an open task.
   * `update` is `{state, events?, output?, outputTruncated?, reason?, startedAt?, finishedAt?}`.
   * A task that is no longer open is left untouched: its result is already final.
   */
  applyTask(taskId, update, now) {
    const task = this.one('SELECT * FROM tasks WHERE task_id = ?', taskId);
    if (!task || task.open !== 1) return false;
    let lastEvent = task.last_event;
    let progress = task.progress;
    for (const event of update.events ?? []) {
      this.run('INSERT OR IGNORE INTO task_events (task_id, sequence, kind, state, message, at) VALUES (?, ?, ?, ?, ?, ?)',
        taskId, event.sequence, event.kind, event.state, event.message, event.at);
      lastEvent = Math.max(lastEvent, event.sequence);
      if (event.kind === 'progress' && event.message) progress = event.message.slice(0, 300);
    }
    if (update.events?.length) {
      this.run(`DELETE FROM task_events WHERE task_id = ? AND sequence <=
        (SELECT sequence FROM task_events WHERE task_id = ? ORDER BY sequence DESC LIMIT 1 OFFSET ?)`,
      taskId, taskId, EVENT_LIMIT);
    }
    const terminal = TERMINAL.has(update.state);
    let startedAt = task.started_at;
    if (startedAt === null) {
      // The accepted event carries the other host's clock; keep it inside this run's own times.
      const observed = update.startedAt ?? (update.state === 'running' ? now : null);
      if (observed !== null) startedAt = observed < task.created_at ? task.created_at : observed > now ? now : observed;
    }
    const finishedAt = terminal ? now : null;
    this.run(`UPDATE tasks SET state = ?, open = ?, output = ?, output_truncated = ?, error = NULL,
      problem_since = NULL, reason = ?, progress = ?, retry_at = NULL, last_event = ?, updated_at = ?,
      started_at = ?, finished_at = ? WHERE task_id = ?`,
    update.state, terminal ? 0 : 1, update.output ?? null, update.outputTruncated ? 1 : 0,
    update.reason ?? task.reason, progress, lastEvent, now, startedAt, finishedAt, taskId);
    const run = this.one('SELECT id, workflow_id FROM runs WHERE task_id = ?', taskId);
    if (terminal) {
      this.close({ ...task, state: update.state }, run, now);
    } else if (task.error !== null) {
      this.log(now, 'system', 'run.recovered', { workflowId: run.workflow_id, runId: run.id });
    }
    return true;
  }

  /**
   * Releases a finished task's reservations and updates its workflow. A run the
   * operator released ends at the moment of that intervention, not after it, so
   * it does not count as unattended.
   */
  close(task, run, now, { released = false } = {}) {
    this.run('UPDATE runs SET open = 0 WHERE id = ?', run.id);
    this.log(now, 'system', 'run.finished', { workflowId: run.workflow_id, runId: run.id, data: { state: task.state } });
    const workflow = this.one('SELECT * FROM workflows WHERE id = ?', run.workflow_id);
    if (!workflow) return;
    const succeeded = task.state === 'succeeded';
    const streak = succeeded ? 0 : isOperatorResult(task) ? workflow.failure_streak : workflow.failure_streak + 1;
    const delay = Math.max(workflow.interval_minutes * MINUTE, succeeded ? 0 : MINUTE);
    this.run(`UPDATE workflows SET failure_streak = ?, next_run_at = ?, unattended_runs = unattended_runs + ?
      WHERE id = ?`, streak, iso(Date.parse(now) + delay), released ? 0 : 1, workflow.id);
    if (streak >= FAILURE_LIMIT && workflow.enabled === 1) {
      this.run(`UPDATE workflows SET enabled = 0, paused_by = 'failures', paused_at = ?, blocked_reason = ?
        WHERE id = ?`, now, PAUSED_BY_FAILURES, workflow.id);
      this.log(now, 'system', 'workflow.auto_paused', { workflowId: workflow.id, data: { failureStreak: streak } });
    }
  }

  /** Records that a task could not be resolved this pass; its identity is retained. */
  taskProblem(taskId, message, retryAt, now) {
    const task = this.one('SELECT error FROM tasks WHERE task_id = ? AND open = 1', taskId);
    if (!task) return false;
    if (task.error === null) {
      const run = this.one('SELECT id, workflow_id FROM runs WHERE task_id = ?', taskId);
      this.run('UPDATE tasks SET error = ?, problem_since = ?, retry_at = ?, updated_at = ? WHERE task_id = ?',
        message, now, retryAt, now, taskId);
      this.log(now, 'system', 'run.problem', { workflowId: run.workflow_id, runId: run.id });
    } else {
      this.run('UPDATE tasks SET error = ?, retry_at = ? WHERE task_id = ?', message, retryAt, taskId);
    }
    return true;
  }

  // ----- operator actions on runs -------------------------------------------------------

  openRun(runId) {
    const row = this.one(`SELECT r.id, r.workflow_id, t.* FROM runs r JOIN tasks t ON t.task_id = r.task_id
      WHERE r.id = ?`, runId);
    if (!row) throw new Refusal(404, 'Run not found');
    if (row.open !== 1) throw new Refusal(409, 'Run is already finished');
    return row;
  }

  requestCancel(runId, now) {
    const row = this.openRun(runId);
    if (row.cancel_requested_at === null) {
      this.run('UPDATE tasks SET cancel_requested_at = ?, retry_at = NULL, updated_at = ? WHERE task_id = ?',
        now, now, row.task_id);
      this.log(now, 'operator', 'run.cancel_requested', { workflowId: row.workflow_id, runId });
    }
    return this.runPreview(runId);
  }

  abandonRun(runId, confirm, now) {
    const row = this.openRun(runId);
    if (confirm !== row.task_id) throw new Refusal(400, 'Confirm with the exact task ID of this run');
    this.run(`UPDATE tasks SET state = 'abandoned', open = 0, error = NULL, problem_since = NULL, retry_at = NULL,
      updated_at = ?, finished_at = ? WHERE task_id = ?`, now, now, row.task_id);
    this.log(now, 'operator', 'run.abandoned', { workflowId: row.workflow_id, runId });
    this.close({ ...row, state: 'abandoned' }, { id: runId, workflow_id: row.workflow_id }, now, { released: true });
    return this.runPreview(runId);
  }

  // ----- views ---------------------------------------------------------------------------

  runPreview(runId) {
    return runView(this.one(`${RUN_PREVIEW} WHERE r.id = ?`, runId));
  }

  runDetail(runId) {
    const row = this.one(`${RUN_FULL} WHERE r.id = ?`, runId);
    if (!row) throw new Refusal(404, 'Run not found');
    const events = this.all(
      'SELECT sequence, kind, state, message, at FROM task_events WHERE task_id = ? ORDER BY sequence', row.task_id);
    return { run: { ...runView(row), instructions: row.input }, events };
  }

  listRuns({ workflowId = null, before = null, limit = 50 } = {}) {
    const where = [];
    const values = [];
    if (workflowId !== null) {
      where.push('r.workflow_id = ?');
      values.push(workflowId);
    }
    if (before !== null) {
      where.push('r.seq < ?');
      values.push(before);
    }
    const rows = this.all(
      `${RUN_PREVIEW} ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY r.seq DESC LIMIT ?`,
      ...values, limit + 1);
    const page = rows.slice(0, limit);
    return { runs: page.map(runView), nextBefore: rows.length > limit ? String(page.at(-1).seq) : null };
  }

  /** Seven-day statistics for every workflow, keyed by workflow ID. */
  statistics(since) {
    const stats = new Map();
    const entry = id => {
      if (!stats.has(id)) stats.set(id, { runs: 0, succeeded: 0, failed: 0, averageSeconds: null, interventions: 0 });
      return stats.get(id);
    };
    for (const row of this.all(
      'SELECT workflow_id, COUNT(*) AS runs FROM runs WHERE created_at >= ? GROUP BY workflow_id', since)) {
      entry(row.workflow_id).runs = row.runs;
    }
    for (const row of this.all(`SELECT r.workflow_id,
        SUM(t.state = 'succeeded') AS succeeded,
        SUM(t.state <> 'succeeded' AND t.state <> 'abandoned'
          AND NOT (t.state = 'cancelled' AND t.cancel_requested_at IS NOT NULL)) AS failed,
        AVG(CASE WHEN t.state = 'succeeded'
          THEN (julianday(t.finished_at) - julianday(r.created_at)) * 86400.0 END) AS average_seconds
      FROM tasks t JOIN runs r ON r.task_id = t.task_id
      WHERE t.open = 0 AND t.finished_at >= ? GROUP BY r.workflow_id`, since)) {
      const item = entry(row.workflow_id);
      item.succeeded = row.succeeded;
      item.failed = row.failed;
      item.averageSeconds = row.average_seconds === null ? null : Math.max(0, Math.round(row.average_seconds));
    }
    for (const row of this.all(`SELECT workflow_id, COUNT(*) AS interventions FROM activity
      WHERE at >= ? AND actor = 'operator' AND kind <> 'workflow.created' AND workflow_id IS NOT NULL
      GROUP BY workflow_id`, since)) {
      entry(row.workflow_id).interventions = row.interventions;
    }
    return stats;
  }

  decorate(row, statistics) {
    const stats = statistics.get(row.id) ?? { runs: 0, succeeded: 0, failed: 0, averageSeconds: null, interventions: 0 };
    const judged = stats.succeeded + stats.failed;
    const recent = this.all(`SELECT r.id, t.state, r.created_at, t.finished_at FROM runs r
      JOIN tasks t ON t.task_id = r.task_id WHERE r.workflow_id = ? ORDER BY r.seq DESC LIMIT 20`, row.id);
    return {
      ...workflowView(row),
      recent: recent.map(r => ({ id: r.id, state: r.state, createdAt: r.created_at, finishedAt: r.finished_at })),
      stats: {
        windowDays: WINDOW_DAYS,
        runs: stats.runs,
        succeeded: stats.succeeded,
        failed: stats.failed,
        successRate: judged ? stats.succeeded / judged : null,
        averageSeconds: stats.averageSeconds,
        interventions: stats.interventions,
        unattendedRuns: row.unattended_runs
      }
    };
  }

  /** Everything the snapshot needs from the store, read in one transaction. */
  snapshot(now) {
    const since = iso(Date.parse(now) - WINDOW_DAYS * 24 * 60 * MINUTE);
    const dayStart = now.slice(0, 10) + 'T00:00:00.000Z';
    const statistics = this.statistics(since);
    const workflows = this.all('SELECT * FROM workflows WHERE archived_at IS NULL ORDER BY rowid').map(row => ({
      ...this.decorate(row, statistics),
      // Internal to snapshot assembly; removed before the response is built.
      dailyLimitReached: row.enabled === 1
        && !this.one('SELECT 1 FROM runs WHERE workflow_id = ? AND open = 1', row.id)
        && this.dispatchedSince(row.id, dayStart) >= row.max_runs_per_day,
      pausedAt: row.paused_at,
      latestRunAt: this.one('SELECT created_at FROM runs WHERE workflow_id = ? ORDER BY seq DESC LIMIT 1', row.id)?.created_at ?? null
    }));
    const connections = this.all('SELECT * FROM connections WHERE removed_at IS NULL ORDER BY rowid').map(row => ({
      id: row.id,
      name: row.name,
      hostId: row.host_id,
      agentId: row.agent_id,
      mode: row.mode,
      ready: row.ready === null ? null : row.ready === 1,
      readySince: row.ready_since
    }));
    const problems = this.all(`SELECT r.id, w.name AS workflow_name, t.error, t.problem_since FROM tasks t
      JOIN runs r ON r.task_id = t.task_id LEFT JOIN workflows w ON w.id = r.workflow_id
      WHERE t.open = 1 AND t.error IS NOT NULL ORDER BY t.problem_since`);
    return {
      connections,
      workflows,
      runs: this.all(`${RUN_PREVIEW} ORDER BY r.seq DESC LIMIT 100`).map(runView),
      problems: problems.map(row => ({
        id: row.id,
        name: row.workflow_name ?? 'Workflow',
        message: row.error,
        since: row.problem_since
      })),
      archived: this.all('SELECT id, name, archived_at FROM workflows WHERE archived_at IS NOT NULL ORDER BY archived_at DESC, rowid DESC')
        .map(row => ({ id: row.id, name: row.name, archivedAt: row.archived_at })),
      activity: this.all('SELECT * FROM activity ORDER BY seq DESC LIMIT 30').map(activityView)
    };
  }

  /** The newest time recorded anywhere, for the controller's clock to continue from. */
  latestTime() {
    return this.one(`SELECT MAX(time) AS latest FROM (
      SELECT MAX(at) AS time FROM activity UNION ALL
      SELECT MAX(created_at) FROM runs UNION ALL
      SELECT MAX(updated_at) FROM tasks)`).latest;
  }

  dataVersion() {
    return this.one('PRAGMA data_version').data_version;
  }
}
