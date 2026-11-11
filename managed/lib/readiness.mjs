// Worker readiness (contract section 3): positive evidence that the pinned
// agent has an attached session whose live channel is verified, with a stable
// code for why not.
import { readFile } from 'node:fs/promises';
import { isAbsolute, resolve } from 'node:path';

const MAX_WORKER_STATE_BYTES = 65_536;
const MAX_CANDIDATES = 4;
const MAX_HINTS = 10;

const REASONS = {
  ready: 'Verified channel',
  ready_service_inactive: 'Verified channel; user service is inactive',
  worker_state_invalid: 'Worker state file is missing or invalid',
  identity_changed: 'Worker identity changed; reconnect explicitly',
  peerspan_unavailable: 'Peerspan executable is unavailable',
  peerspan_incompatible: 'Peerspan executable is too old: it does not accept the global --json flag',
  daemon_not_running: 'Worker host daemon is not running',
  status_invalid: 'Worker host status could not be read',
  sender_unavailable: 'Sender host daemon is not answering',
  sender_is_worker: 'Sender and worker are the same Peerspan host; a host cannot send tasks to itself',
  agent_missing: 'Agent is no longer registered on the worker host',
  session_not_ready: 'Waiting for an attached, ready agent session',
  channel_unverified: 'Waiting for a verified worker channel'
};

export const isIdentifier = (kind, value) =>
  typeof value === 'string' && new RegExp(`^${kind}_[a-f0-9]{${kind === 'host' ? 64 : 32}}$`).test(value);

/** Reads and validates a file-mode worker state file. */
export async function readWorkerState(file) {
  const text = await readFile(file, 'utf8');
  if (text.length > MAX_WORKER_STATE_BYTES) throw new Error('Worker state is too large');
  const state = JSON.parse(text);
  if (!state || typeof state !== 'object') throw new Error('Invalid worker state');
  for (const kind of ['host', 'agent', 'adapter', 'session']) {
    if (!isIdentifier(kind, state[kind + '_id'])) throw new Error('Invalid worker identity');
  }
  if (typeof state.host_dir !== 'string' || !isAbsolute(state.host_dir)) {
    throw new Error('Worker host directory must be absolute');
  }
  return state;
}

/**
 * Upstream attention items as advice. Only the kind and a plainly safe command
 * are kept: upstream detail and subject texts never leave this process.
 */
export function hintsFrom(attention) {
  const hints = [];
  for (const item of attention) {
    if (hints.length === MAX_HINTS) break;
    if (!item || typeof item.kind !== 'string' || !/^[a-z_]{1,64}$/.test(item.kind)) continue;
    const command = typeof item.command === 'string' && /^peerspan [\x20-\x7e]{0,191}$/.test(item.command)
      && !/[/\\]/.test(item.command) ? item.command : null;
    hints.push({ kind: item.kind, command });
  }
  return hints;
}

const verdict = (code, hints = []) => ({
  ready: code === 'ready' || code === 'ready_service_inactive',
  code,
  reason: REASONS[code],
  hints
});

/** The adapter's own report of its live channel, or null when it cannot be read. */
async function adapterReport(peerspan, hostDir, adapterId) {
  try {
    return await peerspan.adapterConnection(hostDir, adapterId);
  } catch (error) {
    if (error.aborted) throw error;
    return null;
  }
}

const isVerified = (report, session) =>
  Boolean(report) && report.adapter_id === session.adapter_id && report.session_id === session.id
  && report.state === 'ready' && report.channel === 'verified'
  && typeof report.channel_verified_at === 'string' && report.channel_verified_at.length > 0;

/** Evaluates one connection. Resolves `{ready, code, reason, hints}`. */
export async function checkReadiness(connection, peerspan) {
  let hostDir = connection.hostDir;
  let named = null;
  let namedReport = null;
  if (connection.mode === 'file') {
    let state;
    try {
      state = await readWorkerState(connection.workerState);
    } catch {
      return verdict('worker_state_invalid');
    }
    if (state.host_id !== connection.hostId || state.agent_id !== connection.agentId
      || resolve(state.host_dir) !== connection.hostDir) {
      return verdict('identity_changed');
    }
    hostDir = state.host_dir;
    named = { id: state.session_id, adapter_id: state.adapter_id };
    // The file names the adapter, so both reads describe the same moment.
    namedReport = adapterReport(peerspan, hostDir, named.adapter_id);
  }

  const [status, report, sender] = await Promise.all([
    peerspan.status(hostDir),
    namedReport,
    peerspan.status(connection.senderState)
  ]);
  if (status.kind !== 'ok') return verdict(status.kind);
  const { value } = status;
  const hints = hintsFrom(value.attention);
  if (value.host_id !== connection.hostId) return verdict('identity_changed', hints);
  // Tasks are submitted through the sender host, which must answer and be another host.
  if (sender.kind !== 'ok') return verdict('sender_unavailable', hints);
  if (sender.value.host_id === connection.hostId) return verdict('sender_is_worker', hints);
  const agent = value.agents.find(item => item?.id === connection.agentId);
  if (!agent) return verdict('agent_missing', hints);

  const sessions = (Array.isArray(agent.sessions) ? agent.sessions : [])
    .filter(session => session && typeof session.id === 'string' && typeof session.adapter_id === 'string')
    .filter(session => !named || (session.id === named.id && session.adapter_id === named.adapter_id))
    .filter(session => session.connection === 'ready')
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
    .slice(0, MAX_CANDIDATES);
  if (!sessions.length) return verdict('session_not_ready', hints);

  const ready = verdict(value.service.active ? 'ready' : 'ready_service_inactive', hints);
  if (named) return isVerified(report, named) ? ready : verdict('channel_unverified', hints);
  for (const session of sessions) {
    if (isVerified(await adapterReport(peerspan, hostDir, session.adapter_id), session)) return ready;
  }
  return verdict('channel_unverified', hints);
}

/** Refuses a registration whose sender host is the worker host itself. */
export async function checkSender(peerspan, senderState, workerHostId) {
  const sender = await peerspan.status(senderState);
  if (sender.kind === 'ok' && sender.value.host_id === workerHostId) {
    throw new Error('Sender and worker are the same Peerspan host, and a host cannot send tasks to itself; '
      + 'pass --sender-state for another local host that may send this agent tasks');
  }
}

/**
 * Resolves an agent for `connect --agent`: one status read, an exact match on
 * agent ID or name, and nothing registered unless exactly one agent matches.
 */
export async function resolveAgent(peerspan, hostDir, wanted) {
  const status = await peerspan.status(hostDir);
  if (status.kind !== 'ok') throw new Error(`Cannot read the worker host status: ${REASONS[status.kind]}`);
  if (!isIdentifier('host', status.value.host_id)) throw new Error('Worker host reported an invalid host ID');
  const agents = status.value.agents.filter(agent => agent && isIdentifier('agent', agent.id));
  const matches = agents.filter(agent => agent.id === wanted || agent.name === wanted);
  if (!matches.length) {
    throw new Error(`No agent with that name or ID on the worker host; pass the agent ID from peerspan agent list`);
  }
  if (matches.length > 1) {
    throw new Error('More than one agent has that name on the worker host; pass the agent ID instead');
  }
  return { hostId: status.value.host_id, agentId: matches[0].id };
}
