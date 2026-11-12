// The controller's state transitions. Runs on the storage worker thread, where
// node:sqlite is synchronous: the worker wraps each call below in one
// transaction, so every operation is atomic and no two interleave. Nothing here
// performs I/O other than SQLite, and every external effect elsewhere is
// preceded by one of these writes (contract section 4).
import { randomBytes, randomUUID } from 'node:crypto';
import { nextSlot } from './schedule.mjs';
import { branchOf, readVerdict, reviewInput, reworkInput } from './review.mjs';

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

const scheduleOf = row => (row.schedule === null ? null : JSON.parse(row.schedule));

/** When a workflow next runs after one of its runs finished at `finishedAt` (contract sections 4 and 14). */
function nextAfterFinish(workflow, finishedAt, succeeded) {
  const finished = Date.parse(finishedAt);
  const schedule = scheduleOf(workflow);
  if (schedule) return iso(nextSlot(schedule, finished + MINUTE, { inclusive: true }));
  return iso(finished + Math.max(workflow.interval_minutes * MINUTE, succeeded ? 0 : MINUTE));
}

// Reviewing results is the expected work of a reviewed workflow, not an intervention (contract section 8).
const isIntervention = (actor, kind) => actor === 'operator' && kind !== 'workflow.created' && kind !== 'run.reviewed';

// A worker agent takes one assignment at a time, whichever sender submits it (MGD-6),
// and a review task is such an assignment too (contract section 4).
export const targetOf = connection => JSON.stringify([connection.host_id, connection.agent_id]);

const newTaskId = () => 'task_' + randomBytes(16).toString('hex');

// A review task's problem is told apart in the activity log (contract section 11).
const problemData = task => (task.role === 'review' ? { task: 'review' } : null);

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
    senderState: row.sender_state,
    networkId: row.network_id
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
    schedule: scheduleOf(row),
    review: row.review,
    reviewerId: row.reviewer_id,
    reviewCriteria: row.review_criteria,
    reworkLimit: row.rework_limit,
    reworkPending: row.rework_pending,
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
  r.created_at, t.updated_at, t.started_at, t.finished_at, r.review, r.reviewed_at, r.review_note,
  r.reviewed_by, r.reviewer_id, r.review_fallback, r.attempt, r.rework_of, t.branch,
  v.task_id AS review_task_id, v.state AS review_state, v.error AS review_error, v.reason AS review_reason,
  v.cancel_requested_at AS review_cancel_requested_at, v.created_at AS review_created_at,
  v.finished_at AS review_finished_at`;
const RUN_SOURCE = `runs r JOIN tasks t ON t.task_id = r.task_id LEFT JOIN workflows w ON w.id = r.workflow_id
  LEFT JOIN tasks v ON v.task_id = r.review_task_id`;
const RUN_PREVIEW = `SELECT ${RUN_COLUMNS}, substr(t.output, 1, ${PREVIEW_CHARS}) AS output,
  length(t.output) > ${PREVIEW_CHARS} AS output_longer FROM ${RUN_SOURCE}`;
const RUN_FULL = `SELECT ${RUN_COLUMNS}, t.output, t.input, r.assignment, v.input AS review_input,
  v.output AS review_output, v.output_truncated AS review_output_truncated, 0 AS output_longer FROM ${RUN_SOURCE}`;

/** The run's agent review, or null when it needs none or has not ended `succeeded` (section 15.1). */
function reviewTaskView(row) {
  if (row.reviewer_id === null || row.state !== 'succeeded') return null;
  return {
    connectionId: row.reviewer_id,
    taskId: row.review_task_id ?? null,
    state: row.review_state ?? null,
    error: row.review_error ?? null,
    reason: row.review_reason ?? null,
    cancelRequestedAt: row.review_cancel_requested_at ?? null,
    createdAt: row.review_created_at ?? null,
    finishedAt: row.review_finished_at ?? null
  };
}

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
    finishedAt: row.finished_at,
    review: row.review,
    reviewedAt: row.reviewed_at,
    reviewNote: row.review_note,
    reviewedBy: row.reviewed_by,
    reviewTask: reviewTaskView(row),
    reviewFallback: row.review_fallback,
    attempt: row.attempt,
    reworkOf: row.rework_of,
    branch: row.branch === null ? null : JSON.parse(row.branch)
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
    // Every operator action on a workflow after its creation, other than a review verdict, is an intervention.
    if (workflowId && isIntervention(actor, kind)) {
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
      (id, name, mode, worker_state, host_dir, host_id, agent_id, sender_state, network_id, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    connection.id, connection.name, connection.mode, connection.workerState, connection.hostDir,
    connection.hostId, connection.agentId, connection.senderState, connection.networkId ?? null, now);
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
    if (this.one('SELECT 1 FROM workflows WHERE reviewer_id = ? AND archived_at IS NULL LIMIT 1', id)) {
      throw new Refusal(409, 'A workflow uses this connection as its reviewer; archive the workflow or choose another reviewer first');
    }
    if (this.one('SELECT 1 FROM tasks WHERE connection_id = ? AND open = 1 LIMIT 1', id)) {
      throw new Refusal(409, 'A run or review task on this connection is unresolved');
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

  /** A reviewer is a connection whose worker agent is not the workflow's own (contract section 15.1). */
  checkReviewer(connectionId, reviewerId) {
    const reviewer = this.one('SELECT host_id, agent_id FROM connections WHERE id = ? AND removed_at IS NULL', reviewerId);
    if (!reviewer) throw new Refusal(400, 'Unknown reviewer connection');
    const worker = this.one('SELECT host_id, agent_id FROM connections WHERE id = ? AND removed_at IS NULL', connectionId);
    if (worker && worker.host_id === reviewer.host_id && worker.agent_id === reviewer.agent_id) {
      throw new Refusal(400, 'The reviewer must be another agent than the worker');
    }
  }

  createWorkflow(fields, now) {
    if (!this.hasConnection(fields.connectionId)) throw new Refusal(400, 'Unknown worker connection');
    if (fields.review === 'agent') this.checkReviewer(fields.connectionId, fields.reviewerId);
    const id = randomUUID();
    const enabled = fields.enabled ? 1 : 0;
    const schedule = fields.schedule ?? null;
    // An interval workflow is due at once; a scheduled one at its first slot (contract section 14).
    const nextRunAt = schedule ? iso(nextSlot(schedule, Date.parse(now))) : now;
    this.run(`INSERT INTO workflows
      (id, name, connection_id, instructions, interval_minutes, schedule, review, reviewer_id, review_criteria,
       rework_limit, max_runs_per_day, acceptance_minutes, enabled, paused_by, paused_at, next_run_at,
       failure_streak, blocked_reason, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)`,
    id, fields.name, fields.connectionId, fields.instructions, fields.intervalMinutes ?? null,
    schedule ? JSON.stringify(schedule) : null, fields.review, fields.reviewerId, fields.reviewCriteria,
    fields.reworkLimit, fields.maxRunsPerDay, fields.acceptanceMinutes, enabled, enabled ? null : 'operator',
    enabled ? null : now, nextRunAt, enabled ? null : PAUSED_BY_OPERATOR, now, now);
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
      schedule: 'schedule',
      review: 'review',
      reviewerId: 'reviewer_id',
      reviewCriteria: 'review_criteria',
      reworkLimit: 'rework_limit',
      maxRunsPerDay: 'max_runs_per_day',
      acceptanceMinutes: 'acceptance_minutes'
    };
    const current = Object.fromEntries(Object.entries(columns).map(([key, column]) => [key, row[column]]));
    const next = { ...current };
    for (const [key, value] of Object.entries(patch)) next[key] = key === 'schedule' ? JSON.stringify(value) : value;
    // A workflow has an interval or a schedule: setting one clears the other.
    if (patch.schedule !== undefined) next.intervalMinutes = null;
    if (patch.intervalMinutes !== undefined) next.schedule = null;
    // Only an agent review has a reviewer, so switching to another review clears it (contract section 15.1).
    if (patch.review !== undefined && patch.review !== 'agent' && (patch.reviewerId ?? null) === null) {
      next.reviewerId = null;
    }
    if (next.review === 'agent' && next.reviewerId === null) throw new Refusal(400, 'Choose the reviewer agent');
    if (next.review !== 'agent' && next.reviewerId !== null) {
      throw new Refusal(400, 'Only a workflow reviewed by an agent has a reviewer');
    }
    if (next.review === 'agent' && (patch.review !== undefined || patch.reviewerId !== undefined
      || patch.connectionId !== undefined)) {
      this.checkReviewer(next.connectionId, next.reviewerId);
    }
    const changed = Object.keys(next).filter(key => next[key] !== current[key]).sort();
    if (!changed.length) return this.workflowDetail(id, now);
    // One statement, so that the store never sees both or neither of interval and schedule.
    this.run(`UPDATE workflows SET ${changed.map(key => columns[key] + ' = ?').join(', ')}, updated_at = ? WHERE id = ?`,
      ...changed.map(key => next[key]), now, id);
    if (changed.includes('schedule') && next.schedule !== null) {
      this.run('UPDATE workflows SET next_run_at = ? WHERE id = ?', iso(nextSlot(patch.schedule, Date.parse(now))), id);
    } else if (changed.includes('intervalMinutes') && next.intervalMinutes !== null) {
      const latest = this.one(`SELECT t.finished_at FROM runs r JOIN tasks t ON t.task_id = r.task_id
        WHERE r.workflow_id = ? AND t.open = 0 ORDER BY r.seq DESC LIMIT 1`, id);
      if (latest?.finished_at) {
        this.run('UPDATE workflows SET next_run_at = ? WHERE id = ?',
          iso(Date.parse(latest.finished_at) + next.intervalMinutes * MINUTE), id);
      }
    }
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
      // An archived workflow gets no rework; reviews of its runs go on (contract section 9).
      this.run(`UPDATE workflows SET archived_at = ?, enabled = 0, paused_by = 'operator', paused_at = ?,
        blocked_reason = ?, rework_pending = NULL, updated_at = ? WHERE id = ?`, now, now, PAUSED_BY_OPERATOR, now, id);
      this.log(now, 'operator', 'workflow.archived', { workflowId: id });
    } else {
      throw new Refusal(404, 'Unknown action');
    }
    return this.workflowDetail(id, now);
  }

  // ----- dispatch ------------------------------------------------------------------

  /**
   * Decides, for every workflow, whether it may dispatch now, and reserves a run
   * for each one that may. `readiness` maps connection IDs to `{ready, reason, capacity}`.
   * Returns the reserved tasks; nothing has been sent for them yet.
   */
  planDispatch(now, readiness) {
    const dayStart = now.slice(0, 10) + 'T00:00:00.000Z';
    const capacities = this.capacities(readiness);
    // Results already produced are checked before new work starts (contract section 4).
    const reserved = this.planReviews(now, readiness, capacities);
    const workflows = this.all('SELECT * FROM workflows WHERE archived_at IS NULL ORDER BY next_run_at, rowid');
    for (const workflow of workflows) {
      const connection = this.one('SELECT * FROM connections WHERE id = ? AND removed_at IS NULL', workflow.connection_id);
      const reason = this.blockedReason(workflow, connection, readiness, now, dayStart, capacities);
      if (reason === null) {
        reserved.push(this.reserve(workflow, connection, now, this.freeTarget(connection, capacities)));
      } else if (reason !== workflow.blocked_reason) {
        this.run('UPDATE workflows SET blocked_reason = ? WHERE id = ?', reason, workflow.id);
      }
    }
    return reserved;
  }

  blockedReason(workflow, connection, readiness, now, dayStart, capacities) {
    if (workflow.enabled !== 1) return workflow.paused_by === 'failures' ? PAUSED_BY_FAILURES : PAUSED_BY_OPERATOR;
    if (this.one('SELECT 1 FROM runs WHERE workflow_id = ? AND open = 1', workflow.id)) return 'Assignment in progress';
    if (this.dispatchedSince(workflow.id, dayStart) >= workflow.max_runs_per_day) return 'Daily dispatch limit reached';
    const state = connection && readiness[connection.id];
    if (!state?.ready) return state?.reason || 'Worker unavailable';
    if (!this.freeTarget(connection, capacities)) {
      const capacity = capacities.get(targetOf(connection)) ?? 1;
      return capacity > 1 ? `Worker is at its capacity of ${capacity} tasks` : 'Worker is busy with another managed task';
    }
    // A due rework does not wait for the interval or schedule (contract section 15.2).
    if (workflow.next_run_at > now && workflow.rework_pending === null) return 'Waiting for next scheduled run';
    return null;
  }

  /**
   * Each worker agent's capacity, by target: the largest that any of its
   * connections' readiness gives, 1 unless a runtime agent is ready (MGD-14).
   */
  capacities(readiness) {
    const byTarget = new Map();
    for (const connection of this.all('SELECT id, host_id, agent_id FROM connections WHERE removed_at IS NULL')) {
      const target = targetOf(connection);
      byTarget.set(target, Math.max(byTarget.get(target) ?? 1, readiness[connection.id]?.capacity ?? 1));
    }
    return byTarget;
  }

  /**
   * A target with room for one more task of the connection's worker agent, or
   * null when it holds its capacity. Each concurrent task takes a slot of its own,
   * so the store's unique index still enforces the limit (contract section 4).
   */
  freeTarget(connection, capacities) {
    const capacity = capacities.get(targetOf(connection)) ?? 1;
    const held = new Set(this.all('SELECT target FROM tasks WHERE peer = ? AND agent = ? AND open = 1',
      connection.host_id, connection.agent_id).map(row => row.target));
    if (held.size >= capacity) return null;
    for (let slot = 0; slot < capacity; slot += 1) {
      const target = slot === 0 ? targetOf(connection) : JSON.stringify([connection.host_id, connection.agent_id, slot]);
      if (!held.has(target)) return target;
    }
    return null;
  }

  /**
   * Reserves the review task of each run that waits for its reviewer agent,
   * oldest result first, while that reviewer is ready and free (section 15.1).
   */
  planReviews(now, readiness, capacities) {
    const reserved = [];
    const waiting = this.all(`SELECT r.id, r.workflow_id, r.reviewer_id FROM runs r JOIN tasks t ON t.task_id = r.task_id
      WHERE r.review = 'pending' AND r.reviewer_id IS NOT NULL AND r.review_task_id IS NULL
        AND r.review_fallback IS NULL
      ORDER BY t.finished_at, r.seq`);
    for (const run of waiting) {
      const reviewer = this.one('SELECT * FROM connections WHERE id = ? AND removed_at IS NULL', run.reviewer_id);
      if (!reviewer) {
        this.fallBack(run, 'reviewer_removed', now);
        continue;
      }
      if (!readiness[reviewer.id]?.ready) continue;
      const target = this.freeTarget(reviewer, capacities);
      if (target) reserved.push(this.reserveReview(run, reviewer, now, target));
    }
    return reserved;
  }

  reserveReview(run, reviewer, now, target) {
    const details = this.one(`SELECT r.assignment, t.output, w.review_criteria, w.acceptance_minutes
      FROM runs r JOIN tasks t ON t.task_id = r.task_id JOIN workflows w ON w.id = r.workflow_id WHERE r.id = ?`, run.id);
    const taskId = newTaskId();
    const input = reviewInput({ assignment: details.assignment, criteria: details.review_criteria, output: details.output });
    const deadline = iso(Date.parse(now) + details.acceptance_minutes * MINUTE);
    // Persisted before anything is sent, exactly as a run's task is.
    this.run(`INSERT INTO tasks
      (task_id, run_id, role, connection_id, target, peer, agent, sender_state, input, deadline, state, open,
       created_at, updated_at)
      VALUES (?, ?, 'review', ?, ?, ?, ?, ?, ?, ?, 'submitting', 1, ?, ?)`,
    taskId, run.id, reviewer.id, target, reviewer.host_id, reviewer.agent_id, reviewer.sender_state,
    input, deadline, now, now);
    this.run('UPDATE runs SET review_task_id = ? WHERE id = ?', taskId, run.id);
    this.log(now, 'system', 'review.dispatched', { workflowId: run.workflow_id, runId: run.id });
    return taskRecord(this.one('SELECT * FROM tasks WHERE task_id = ?', taskId));
  }

  dispatchedSince(workflowId, dayStart) {
    return this.one('SELECT COUNT(*) AS count FROM runs WHERE workflow_id = ? AND created_at >= ?', workflowId, dayStart).count;
  }

  reserve(workflow, connection, now, target) {
    const runId = randomUUID();
    const taskId = newTaskId();
    const deadline = iso(Date.parse(now) + workflow.acceptance_minutes * MINUTE);
    // A due rework sends the review and the rejected result back with the instructions (section 15.2).
    let input = workflow.instructions;
    let attempt = 1;
    let reworkOf = null;
    if (workflow.rework_pending !== null) {
      const rejected = this.one(`SELECT r.id, r.attempt, r.review_note, t.output FROM runs r
        JOIN tasks t ON t.task_id = r.task_id WHERE r.id = ?`, workflow.rework_pending);
      if (rejected) {
        input = reworkInput({ instructions: workflow.instructions, note: rejected.review_note, output: rejected.output });
        attempt = rejected.attempt + 1;
        reworkOf = rejected.id;
      }
    }
    // Persist before every external effect. A crash can replay only these bytes.
    this.run(`INSERT INTO tasks
      (task_id, run_id, role, connection_id, target, peer, agent, sender_state, input, deadline, state, open,
       created_at, updated_at)
      VALUES (?, ?, 'work', ?, ?, ?, ?, ?, ?, ?, 'submitting', 1, ?, ?)`,
    taskId, runId, connection.id, target, connection.host_id, connection.agent_id,
    connection.sender_state, input, deadline, now, now);
    // The run keeps the review requirement and reviewer its workflow has now (contract sections 15, 15.1).
    this.run(`INSERT INTO runs (id, workflow_id, task_id, open, created_at, review_required, reviewer_id, attempt,
      rework_of, assignment) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?)`,
    runId, workflow.id, taskId, now, workflow.review === 'none' ? 0 : 1,
    workflow.review === 'agent' ? workflow.reviewer_id : null, attempt, reworkOf, workflow.instructions);
    this.run(`UPDATE workflows SET blocked_reason = 'Assignment in progress', rework_pending = NULL WHERE id = ?`,
      workflow.id);
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
    const output = update.output ?? null;
    const branch = terminal ? branchOf(update.state, output, Boolean(update.outputTruncated)) : null;
    this.run(`UPDATE tasks SET state = ?, open = ?, output = ?, output_truncated = ?, error = NULL,
      problem_since = NULL, reason = ?, progress = ?, retry_at = NULL, last_event = ?, updated_at = ?,
      started_at = ?, finished_at = ?, branch = ? WHERE task_id = ?`,
    update.state, terminal ? 0 : 1, output, update.outputTruncated ? 1 : 0,
    update.reason ?? task.reason, progress, lastEvent, now, startedAt, finishedAt,
    branch === null ? null : JSON.stringify(branch), taskId);
    const run = this.one('SELECT id, workflow_id FROM runs WHERE id = ?', task.run_id);
    if (terminal) {
      if (task.role === 'review') this.closeReview({ ...task, state: update.state, output }, run, now);
      else this.close({ ...task, state: update.state }, run, now);
    } else if (task.error !== null) {
      this.log(now, 'system', 'run.recovered', { workflowId: run.workflow_id, runId: run.id, data: problemData(task) });
    }
    return true;
  }

  /**
   * A review task ended. Unless the operator decided first, its output gives the
   * verdict, or the run falls back to the operator (contract section 15.1).
   */
  closeReview(task, run, now) {
    this.log(now, 'system', 'review.finished', { workflowId: run.workflow_id, runId: run.id, data: { state: task.state } });
    const current = this.one('SELECT review, review_task_id FROM runs WHERE id = ?', run.id);
    if (current.review !== 'pending' || current.review_task_id !== task.task_id) return;
    if (task.state !== 'succeeded') {
      this.fallBack(run, task.state, now);
      return;
    }
    const verdict = readVerdict(task.output ?? '');
    if (verdict) this.decide(run, verdict.verdict, verdict.note, 'agent', now);
    else this.fallBack(run, 'no_verdict', now);
  }

  /** The agent gave no verdict: the result now waits for the operator's. */
  fallBack(run, cause, now) {
    const { changes } = this.run(`UPDATE runs SET review_fallback = ?
      WHERE id = ? AND review = 'pending' AND review_fallback IS NULL`, cause, run.id);
    if (changes) this.log(now, 'system', 'review.fallback', { workflowId: run.workflow_id, runId: run.id, data: { cause } });
  }

  /** Records a final verdict and, after a rejection, makes a rework due when the workflow asks for one. */
  decide(run, verdict, note, by, now) {
    this.run('UPDATE runs SET review = ?, reviewed_at = ?, review_note = ?, reviewed_by = ? WHERE id = ?',
      verdict, now, note, by, run.id);
    this.log(now, by === 'agent' ? 'system' : 'operator', 'run.reviewed',
      { workflowId: run.workflow_id, runId: run.id, data: { verdict } });
    if (verdict === 'rejected') this.dueRework(run, now);
  }

  /**
   * A rejected result is sent back when it is its workflow's latest run, the
   * workflow is not archived and the run's attempt is within the limit (section 15.2).
   */
  dueRework(run, now) {
    const rejected = this.one('SELECT seq, attempt FROM runs WHERE id = ?', run.id);
    const workflow = this.one('SELECT rework_limit, archived_at FROM workflows WHERE id = ?', run.workflow_id);
    if (!workflow || workflow.archived_at !== null || rejected.attempt > workflow.rework_limit) return;
    if (this.one('SELECT 1 FROM runs WHERE workflow_id = ? AND seq > ? LIMIT 1', run.workflow_id, rejected.seq)) return;
    this.run('UPDATE workflows SET rework_pending = ? WHERE id = ?', run.id, run.workflow_id);
    this.log(now, 'system', 'workflow.rework_due',
      { workflowId: run.workflow_id, runId: run.id, data: { attempt: rejected.attempt + 1 } });
  }

  /**
   * Releases a finished task's reservations and updates its workflow. A run the
   * operator released ends at the moment of that intervention, not after it, so
   * it does not count as unattended.
   */
  close(task, run, now, { released = false } = {}) {
    const succeeded = task.state === 'succeeded';
    this.run('UPDATE runs SET open = 0 WHERE id = ?', run.id);
    // A success of a reviewed workflow waits for the operator's verdict before it counts.
    if (succeeded) this.run("UPDATE runs SET review = 'pending' WHERE id = ? AND review_required = 1", run.id);
    this.log(now, 'system', 'run.finished', { workflowId: run.workflow_id, runId: run.id, data: { state: task.state } });
    const workflow = this.one('SELECT * FROM workflows WHERE id = ?', run.workflow_id);
    if (!workflow) return;
    const streak = succeeded ? 0 : isOperatorResult(task) ? workflow.failure_streak : workflow.failure_streak + 1;
    this.run(`UPDATE workflows SET failure_streak = ?, next_run_at = ?, unattended_runs = unattended_runs + ?
      WHERE id = ?`, streak, nextAfterFinish(workflow, now, succeeded), released ? 0 : 1, workflow.id);
    if (streak >= FAILURE_LIMIT && workflow.enabled === 1) {
      this.run(`UPDATE workflows SET enabled = 0, paused_by = 'failures', paused_at = ?, blocked_reason = ?
        WHERE id = ?`, now, PAUSED_BY_FAILURES, workflow.id);
      this.log(now, 'system', 'workflow.auto_paused', { workflowId: workflow.id, data: { failureStreak: streak } });
    }
  }

  /** Records that a task could not be resolved this pass; its identity is retained. */
  taskProblem(taskId, message, retryAt, now) {
    const task = this.one('SELECT error, run_id, role FROM tasks WHERE task_id = ? AND open = 1', taskId);
    if (!task) return false;
    if (task.error === null) {
      const run = this.one('SELECT id, workflow_id FROM runs WHERE id = ?', task.run_id);
      this.run('UPDATE tasks SET error = ?, problem_since = ?, retry_at = ?, updated_at = ? WHERE task_id = ?',
        message, now, retryAt, now, taskId);
      this.log(now, 'system', 'run.problem', { workflowId: run.workflow_id, runId: run.id, data: problemData(task) });
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

  /**
   * The operator's final verdict on a result that waits for review (contract
   * section 15), whether it waits for the operator or for a reviewer agent.
   */
  reviewRun(runId, verdict, note, now) {
    const row = this.one('SELECT id, workflow_id, review FROM runs WHERE id = ?', runId);
    if (!row) throw new Refusal(404, 'Run not found');
    if (row.review !== 'pending') {
      throw new Refusal(409, row.review === null ? 'This run has no result waiting for review' : 'This result was already reviewed');
    }
    this.decide(row, verdict, note, 'operator', now);
    return this.runPreview(runId);
  }

  /** A run and its unresolved review task, for the operator's actions on that task (section 15.1). */
  openReview(runId) {
    const run = this.one('SELECT id, workflow_id, review_task_id FROM runs WHERE id = ?', runId);
    if (!run) throw new Refusal(404, 'Run not found');
    const task = run.review_task_id === null ? null
      : this.one('SELECT * FROM tasks WHERE task_id = ? AND open = 1', run.review_task_id);
    if (!task) throw new Refusal(409, 'This run has no unresolved review task');
    return { run, task };
  }

  requestReviewCancel(runId, now) {
    const { run, task } = this.openReview(runId);
    if (task.cancel_requested_at === null) {
      this.run('UPDATE tasks SET cancel_requested_at = ?, retry_at = NULL, updated_at = ? WHERE task_id = ?',
        now, now, task.task_id);
      this.log(now, 'operator', 'review.cancel_requested', { workflowId: run.workflow_id, runId });
    }
    return this.runPreview(runId);
  }

  abandonReview(runId, confirm, now) {
    const { run, task } = this.openReview(runId);
    if (confirm !== task.task_id) throw new Refusal(400, 'Confirm with the exact task ID of this review task');
    this.run(`UPDATE tasks SET state = 'abandoned', open = 0, error = NULL, problem_since = NULL, retry_at = NULL,
      updated_at = ?, finished_at = ? WHERE task_id = ?`, now, now, task.task_id);
    this.log(now, 'operator', 'review.abandoned', { workflowId: run.workflow_id, runId });
    this.closeReview({ ...task, state: 'abandoned' }, run, now);
    return this.runPreview(runId);
  }

  // ----- views ---------------------------------------------------------------------------

  runPreview(runId) {
    return runView(this.one(`${RUN_PREVIEW} WHERE r.id = ?`, runId));
  }

  runDetail(runId) {
    const row = this.one(`${RUN_FULL} WHERE r.id = ?`, runId);
    if (!row) throw new Refusal(404, 'Run not found');
    const timeline = taskId => (taskId === null ? [] : this.all(
      'SELECT sequence, kind, state, message, at FROM task_events WHERE task_id = ? ORDER BY sequence', taskId));
    const run = { ...runView(row), instructions: row.input, assignment: row.assignment };
    if (run.reviewTask) {
      run.reviewTask = {
        ...run.reviewTask,
        input: row.review_input ?? null,
        output: row.review_output ?? null,
        outputTruncated: row.review_output_truncated === 1
      };
    }
    return { run, events: timeline(row.task_id), reviewEvents: timeline(row.review_task_id ?? null) };
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
      if (!stats.has(id)) {
        stats.set(id, { runs: 0, succeeded: 0, failed: 0, averageSeconds: null, interventions: 0, awaitingReview: 0 });
      }
      return stats.get(id);
    };
    for (const row of this.all(
      'SELECT workflow_id, COUNT(*) AS runs FROM runs WHERE created_at >= ? GROUP BY workflow_id', since)) {
      entry(row.workflow_id).runs = row.runs;
    }
    // A success counts once it needs no review or was accepted; a rejected one counts as a failure.
    // `IS` rather than `=` for the nullable review, so that no term is NULL and every sum is a count.
    const counted = "t.state = 'succeeded' AND (r.review IS NULL OR r.review IS 'accepted')";
    for (const row of this.all(`SELECT r.workflow_id,
        TOTAL(${counted}) AS succeeded,
        TOTAL((t.state <> 'succeeded' AND t.state <> 'abandoned'
          AND NOT (t.state = 'cancelled' AND t.cancel_requested_at IS NOT NULL))
          OR (t.state = 'succeeded' AND r.review IS 'rejected')) AS failed,
        AVG(CASE WHEN ${counted}
          THEN (julianday(t.finished_at) - julianday(r.created_at)) * 86400.0 END) AS average_seconds
      FROM tasks t JOIN runs r ON r.task_id = t.task_id
      WHERE t.open = 0 AND t.finished_at >= ? GROUP BY r.workflow_id`, since)) {
      const item = entry(row.workflow_id);
      item.succeeded = row.succeeded;
      item.failed = row.failed;
      item.averageSeconds = row.average_seconds === null ? null : Math.max(0, Math.round(row.average_seconds));
    }
    for (const row of this.all(`SELECT workflow_id, COUNT(*) AS interventions FROM activity
      WHERE at >= ? AND actor = 'operator' AND kind NOT IN ('workflow.created', 'run.reviewed')
        AND workflow_id IS NOT NULL
      GROUP BY workflow_id`, since)) {
      entry(row.workflow_id).interventions = row.interventions;
    }
    for (const row of this.all(
      "SELECT workflow_id, COUNT(*) AS waiting FROM runs WHERE review = 'pending' GROUP BY workflow_id")) {
      entry(row.workflow_id).awaitingReview = row.waiting;
    }
    return stats;
  }

  decorate(row, statistics) {
    const stats = statistics.get(row.id)
      ?? { runs: 0, succeeded: 0, failed: 0, averageSeconds: null, interventions: 0, awaitingReview: 0 };
    const judged = stats.succeeded + stats.failed;
    const recent = this.all(`SELECT r.id, t.state, r.created_at, t.finished_at, r.review FROM runs r
      JOIN tasks t ON t.task_id = r.task_id WHERE r.workflow_id = ? ORDER BY r.seq DESC LIMIT 20`, row.id);
    return {
      ...workflowView(row),
      recent: recent.map(r => ({
        id: r.id,
        state: r.state,
        createdAt: r.created_at,
        finishedAt: r.finished_at,
        review: r.review
      })),
      stats: {
        windowDays: WINDOW_DAYS,
        runs: stats.runs,
        succeeded: stats.succeeded,
        failed: stats.failed,
        successRate: judged ? stats.succeeded / judged : null,
        averageSeconds: stats.averageSeconds,
        interventions: stats.interventions,
        unattendedRuns: row.unattended_runs,
        awaitingReview: stats.awaitingReview
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
      readySince: row.ready_since,
      activeTasks: this.one('SELECT COUNT(*) AS count FROM tasks WHERE peer = ? AND agent = ? AND open = 1',
        row.host_id, row.agent_id).count
    }));
    // A run's own task and its review task are never unresolved together; its own task wins if they were.
    const problems = new Map();
    for (const row of this.all(`SELECT r.id, w.name AS workflow_name, t.error, t.problem_since, t.role FROM tasks t
      JOIN runs r ON r.id = t.run_id LEFT JOIN workflows w ON w.id = r.workflow_id
      WHERE t.open = 1 AND t.error IS NOT NULL ORDER BY t.role = 'review', t.problem_since`)) {
      if (!problems.has(row.id)) problems.set(row.id, row);
    }
    // Results waiting for the operator's verdict, per workflow, archived ones included.
    const reviews = this.all(`SELECT r.workflow_id, w.name AS workflow_name, COUNT(*) AS waiting,
        MIN(t.finished_at) AS since
      FROM runs r JOIN tasks t ON t.task_id = r.task_id LEFT JOIN workflows w ON w.id = r.workflow_id
      WHERE r.review = 'pending' AND (r.reviewer_id IS NULL OR r.review_fallback IS NOT NULL)
      GROUP BY r.workflow_id ORDER BY since`);
    // Reviewer connections that a result waits for before its review task can be reserved.
    const awaitedReviewers = this.all(`SELECT DISTINCT reviewer_id FROM runs
      WHERE review = 'pending' AND reviewer_id IS NOT NULL AND review_task_id IS NULL AND review_fallback IS NULL`)
      .map(row => row.reviewer_id);
    return {
      connections,
      workflows,
      runs: this.all(`${RUN_PREVIEW} ORDER BY r.seq DESC LIMIT 100`).map(runView),
      problems: [...problems.values()].sort((a, b) => (a.problem_since < b.problem_since ? -1 : 1)).map(row => ({
        id: row.id,
        name: row.workflow_name ?? 'Workflow',
        message: row.role === 'review' ? 'Review task: ' + row.error : row.error,
        since: row.problem_since
      })),
      awaitedReviewers,
      reviews: reviews.map(row => ({
        id: row.workflow_id,
        name: row.workflow_name ?? 'Workflow',
        waiting: row.waiting,
        since: row.since
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
