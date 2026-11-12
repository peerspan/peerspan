// Assembles the console's view of the controller (contract section 8). This is
// the privacy boundary of the HTTP API: everything returned here is built from
// public fields; no path, credential or upstream detail text is passed through.
import { stamp } from './clock.mjs';
import { readObservations } from './observations.mjs';
import { capacityOf } from './readiness.mjs';
import { SCHEMA_VERSION } from './schema.mjs';

const SEVERITIES = ['action', 'warning', 'info'];

function orderAttention(items) {
  const rank = item => SEVERITIES.indexOf(item.severity);
  return items.sort((a, b) => {
    if (rank(a) !== rank(b)) return rank(a) - rank(b);
    if (a.since === b.since) return 0;
    if (a.since === null) return 1;
    if (b.since === null) return -1;
    return a.since < b.since ? -1 : 1;
  });
}

function attentionFor({ engine, workflows, connections, problems, reviews, awaitedReviewers, observed, alerts }) {
  const items = [];
  const add = (kind, severity, type, subject, message, since) =>
    items.push({ kind, severity, subject: { type, id: subject.id, name: subject.name }, message, since: since ?? null });

  if (engine.error) {
    add('controller_error', 'action', 'controller', { id: 'controller', name: 'controller' }, engine.error, engine.errorSince);
  }
  for (const workflow of workflows) {
    if (workflow.pausedBy === 'failures') {
      add('workflow_auto_paused', 'action', 'workflow', workflow,
        'Paused after three consecutive failed runs; review the results, then resume', workflow.pausedAt);
    }
    // (rev 11) A run that waits for the operator's approval (section 14.2).
    if (workflow.approvalPending) {
      add('approval_pending', 'action', 'workflow', workflow, 'Its next run waits for your approval', workflow.approvalPending);
    }
  }
  for (const review of reviews) {
    add('review_pending', 'action', 'workflow', review, review.waiting === 1
      ? '1 result waits for your review' : `${review.waiting} results wait for your review`, review.since);
  }
  for (const connection of connections) {
    const { readiness } = connection;
    if (readiness.ready || readiness.code === 'checking') continue;
    // In use as an enabled workflow's worker or reviewer, or awaited by a result's review (contract section 8).
    const inUse = workflows.some(workflow => workflow.enabled
      && (workflow.connectionId === connection.id || workflow.reviewerId === connection.id))
      || awaitedReviewers.includes(connection.id);
    add('worker_unready', inUse ? 'action' : 'warning', 'connection', connection, readiness.reason, readiness.since);
  }
  for (const problem of problems) add('run_problem', 'warning', 'run', problem, problem.message, problem.since);
  for (const source of observed) {
    if (!source.available) add('observed_unavailable', 'warning', 'observation', source, source.error, null);
    else if (source.error) add('observed_problem', 'warning', 'observation', source, source.error, source.lastTickAt);
  }
  // (rev 10) Alerts that cannot be delivered show here, never through another alert (section 8.1).
  if (alerts.failingSince) {
    add('alerts_failing', 'warning', 'alerts', { id: 'alerts', name: 'Alerts' }, alerts.failure, alerts.failingSince);
  }
  for (const workflow of workflows) {
    if (workflow.dailyLimitReached) {
      add('daily_limit_reached', 'info', 'workflow', workflow,
        'Daily dispatch limit reached; dispatch continues after 00:00 UTC', workflow.latestRunAt);
    }
  }
  return orderAttention(items);
}

export async function buildSnapshot({ store, engine, version }) {
  const [data, sources] = await Promise.all([store.snapshot(stamp()), store.listObservations()]);
  const observed = await readObservations(sources);
  const connections = data.connections.map(connection => {
    const readiness = engine.readinessOf(connection);
    return {
      id: connection.id,
      name: connection.name,
      hostId: connection.hostId,
      agentId: connection.agentId,
      mode: connection.mode,
      readiness,
      // How many tasks its worker agent may hold, and holds, across workflows (contract sections 4 and 8).
      capacity: capacityOf(readiness),
      activeTasks: connection.activeTasks
    };
  });
  const attention = attentionFor({
    engine,
    workflows: data.workflows,
    connections,
    problems: data.problems,
    reviews: data.reviews,
    awaitedReviewers: data.awaitedReviewers,
    observed,
    alerts: data.alerts
  });
  return {
    connections,
    workflows: data.workflows.map(({ dailyLimitReached, pausedAt, latestRunAt, ...workflow }) => workflow),
    runs: data.runs,
    observed,
    attention,
    activity: data.activity,
    archived: data.archived,
    meta: {
      name: 'Peerspan Managed',
      version,
      mode: 'Local operator preview',
      revision: engine.revision,
      schemaVersion: SCHEMA_VERSION,
      lastTickAt: engine.lastTickAt,
      tickSeconds: engine.tickMs / 1000,
      error: engine.error,
      modelCostAvailable: false,
      modelCost: 'Unavailable; model usage is billed by your provider',
      cloudProvisioning: false,
      // (rev 10) Never the webhook URL: only whether alerts are set, its host, and whether they fail.
      alerts: { configured: data.alerts.configured, host: data.alerts.host, failing: data.alerts.failingSince !== null }
    }
  };
}
