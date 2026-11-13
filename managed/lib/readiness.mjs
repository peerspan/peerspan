// Worker readiness (contract section 3): positive evidence that the pinned
// agent has an attached session whose live channel is verified, or (section
// 3.1) that its host's runtime would start its tasks, with a stable code for
// why not.
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
  channel_unverified: 'Waiting for a verified worker channel',
  // Runtime agents (contract section 3.1).
  runtime_disabled: "The worker host's runtime is switched off, so it would reject this runtime agent's tasks",
  runtime_unavailable: "The worker host's runtime is not answering",
  runtime_credential_missing: 'This runtime agent has no model credential on its host',
  ready_runtime: "Runtime agent: each task runs in the worker host's runtime, on its own fork"
};

const READY_CODES = new Set(['ready', 'ready_service_inactive', 'ready_runtime']);
const MAX_CAPACITY = 64;

/**
 * How many unresolved tasks a readiness lets its worker agent hold (contract
 * section 4, MGD-14): a ready runtime agent's `maxRuns`, and 1 for anything else.
 */
export function capacityOf(readiness) {
  const runs = readiness?.runtime?.maxRuns;
  return readiness?.code === 'ready_runtime' && Number.isInteger(runs) && runs >= 1 && runs <= MAX_CAPACITY ? runs : 1;
}
const PROFILES_UNREADABLE = "The worker host's launch profiles could not be read";
const STATUS_CHANGING = 'Worker host status changed while it was being checked; checking again';

// Remote mode reads only the sender's directory (contract section 7.1).
const REMOTE_REASONS = {
  ...REASONS,
  directory_unavailable: "The sender host's directory of agents could not be read",
  agent_missing: "The agent is not in the sender host's directory",
  host_unreachable: 'The sender could not reach the worker host when it last tried',
  not_authorized: "The worker's owner does not allow this sender to submit tasks to the agent"
};

const asOf = at => (at ? ` as of ${at.slice(0, 19).replace('T', ' ')} UTC` : '');

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

const verdict = (code, hints = [], { reason = REASONS[code], directoryAt = null, runtime = null } = {}) => ({
  ready: READY_CODES.has(code),
  code,
  reason,
  hints,
  directoryAt,
  runtime
});

/** What the console may show of a launch profile: never a path (contract section 3.1). */
function runtimeSummary(profile) {
  const value = key => (typeof profile[key] === 'string' || Number.isInteger(profile[key]) ? profile[key] : null);
  return {
    fromBranch: value('from_branch'),
    network: value('network'),
    cpus: value('cpus'),
    memoryMib: value('memory_mib'),
    timeoutSeconds: value('timeout_seconds'),
    maxRuns: value('max_runs'),
    // Revision 7: which agent program runs, and on which image (null: the runtime's own).
    harness: value('harness'),
    image: value('image')
  };
}

const isRuntimeReport = report => Boolean(report) && typeof report === 'object' && !Array.isArray(report)
  && !Object.hasOwn(report, 'error');

/**
 * A runtime agent is ready when its host would start its tasks: the runtime
 * switch on, a runtime that answers, and a credential (contract section 3.1).
 */
async function checkRuntime(peerspan, hostDir, profile, serviceActive, hints) {
  const runtime = runtimeSummary(profile);
  const runtimeVerdict = (code, reason) => verdict(code, hints, { runtime, reason });
  const shown = await peerspan.runtimeSwitch(hostDir);
  if (shown?.enabled === false) return runtimeVerdict('runtime_disabled');
  if (shown?.enabled !== true || !isRuntimeReport(shown.runtime)) return runtimeVerdict('runtime_unavailable');
  if (profile.credential !== true) return runtimeVerdict('runtime_credential_missing');
  return runtimeVerdict('ready_runtime',
    REASONS.ready_runtime + (serviceActive ? '' : '; the user service is inactive'));
}

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

// Upstream text never passes through: a time is re-written in UTC, and anything else is no time.
function time(value) {
  const ms = typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d/.test(value) ? Date.parse(value) : NaN;
  return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
}

/** Directory entries for one host and agent: a `reachable` entry first, then a `mine` entry. */
function directoryEntry(directory, hostId, agentId) {
  const matches = entry => entry && entry.host_id === hostId && entry.agent_id === agentId;
  const reachable = directory.reachable.find(matches);
  if (reachable) return { entry: reachable, mine: false };
  const mine = directory.mine.find(matches);
  return mine ? { entry: mine, mine: true } : null;
}

/**
 * A remote connection: the sender's status and its directory, read together
 * (contract section 7.1). The worker host itself is never read.
 */
async function checkRemote(connection, peerspan, refresh) {
  const [sender, directory] = await Promise.all([
    peerspan.status(connection.senderState),
    peerspan.agents(connection.senderState, { network: connection.networkId, refresh })
  ]);
  // Only a directory of the pinned network is evidence; its time goes with every verdict of this check.
  const listing = directory.kind === 'ok' && directory.value.network_id === connection.networkId ? directory.value : null;
  const host = listing?.hosts.find(item => item?.host_id === connection.hostId);
  const directoryAt = time(host?.refreshed_at);
  const remote = (code, hints = []) => verdict(code, hints, { reason: REMOTE_REASONS[code], directoryAt });
  for (const code of ['peerspan_unavailable', 'peerspan_incompatible']) {
    if (sender.kind === code || directory.kind === code) return remote(code);
  }
  if (sender.kind !== 'ok') return remote('sender_unavailable');
  // The worker host's attention is not visible here, so the sender's is the advice the operator can act on.
  const hints = hintsFrom(sender.value.attention);
  if (sender.value.host_id === connection.hostId) return remote('sender_is_worker', hints);
  if (!listing) return remote('directory_unavailable', hints);
  const found = directoryEntry(listing, connection.hostId, connection.agentId);
  if (!found) return remote('agent_missing', hints);
  if (host?.state !== 'ok') return remote('host_unreachable', hints);
  if (!found.mine && !(Array.isArray(found.entry.actions) && found.entry.actions.includes('task.submit'))) {
    return remote('not_authorized', hints);
  }
  if (found.entry.connected !== true) {
    return verdict('session_not_ready', hints, {
      reason: "The sender's directory shows no connected, verified session for this agent" + asOf(directoryAt),
      directoryAt
    });
  }
  return verdict('ready', hints, {
    reason: 'Connected with a verified channel, according to the sender\'s directory' + asOf(directoryAt),
    directoryAt
  });
}

const profileOf = (profiles, agentId) => (profiles.kind === 'ok'
  ? profiles.value.find(item => item && typeof item === 'object' && item.agent_id === agentId)
  : undefined);

/**
 * The facts of a ready verdict that were read before its last read (MGD-16): the
 * worker state file's identity, the status host and agent, the verified session,
 * the sender host, and in agent mode the agent's launch profile or its absence.
 */
function factsOf(connection, { state, status, sender, profiles, session }) {
  const value = status.value;
  const agent = value.agents.find(item => item?.id === connection.agentId);
  const held = session && (Array.isArray(agent?.sessions) ? agent.sessions : []).some(item => item
    && item.id === session.id && item.adapter_id === session.adapter_id && item.connection === 'ready');
  const profile = profiles && (profiles.kind === 'invalid' ? 'invalid' : profileOf(profiles, connection.agentId) ?? null);
  return JSON.stringify([state && [state.host_id, state.agent_id, state.host_dir, state.session_id, state.adapter_id],
    value.host_id, Boolean(agent), session ? Boolean(held) : null,
    sender.kind === 'ok' ? sender.value.host_id : sender.kind, profile ?? null]);
}

/** Whether the facts a ready verdict rests on read the same again, after its last read. */
async function stillHolds(connection, peerspan, basis) {
  const [state, status, sender, profiles] = await Promise.all([
    connection.mode === 'file' ? readWorkerState(connection.workerState).catch(() => null) : null,
    peerspan.status(basis.hostDir),
    peerspan.status(connection.senderState),
    connection.mode === 'agent' ? peerspan.launchProfiles(basis.hostDir) : null
  ]);
  if ((connection.mode === 'file' && !state) || status.kind !== 'ok') return false;
  return factsOf(connection, { state, status, sender, profiles, session: basis.session }) === basis.facts;
}

/**
 * Evaluates one connection. Resolves `{ready, code, reason, hints, directoryAt}`.
 * `refresh` asks a remote connection's sender to refresh its directory first.
 */
export async function checkReadiness(connection, peerspan, { refresh = false } = {}) {
  if (connection.mode === 'remote') return checkRemote(connection, peerspan, refresh);
  // A ready verdict rests on reads made one after another. It stands only when the facts read
  // before its last read are read unchanged after it, so that all of them held at one moment of
  // that last read; otherwise the check is made again, once (contract section 3, MGD-16).
  for (let attempt = 1; ; attempt += 1) {
    const { result, basis } = await checkLocal(connection, peerspan);
    if (!result.ready || await stillHolds(connection, peerspan, basis)) return result;
    if (attempt === 2) return verdict('status_invalid', result.hints, { reason: STATUS_CHANGING });
  }
}

/** One check of a file-mode or agent-mode connection: `{result, basis}`, `basis` for a ready result. */
async function checkLocal(connection, peerspan) {
  const done = result => ({ result, basis: null });
  let hostDir = connection.hostDir;
  let state = null;
  let named = null;
  if (connection.mode === 'file') {
    try {
      state = await readWorkerState(connection.workerState);
    } catch {
      return done(verdict('worker_state_invalid'));
    }
    if (state.host_id !== connection.hostId || state.agent_id !== connection.agentId
      || resolve(state.host_dir) !== connection.hostDir) {
      return done(verdict('identity_changed'));
    }
    hostDir = state.host_dir;
    named = { id: state.session_id, adapter_id: state.adapter_id };
  }

  const [status, sender] = await Promise.all([
    peerspan.status(hostDir),
    peerspan.status(connection.senderState)
  ]);
  if (status.kind !== 'ok') return done(verdict(status.kind));
  const { value } = status;
  const hints = hintsFrom(value.attention);
  if (value.host_id !== connection.hostId) return done(verdict('identity_changed', hints));
  // Tasks are submitted through the sender host, which must answer and be another host.
  if (sender.kind !== 'ok') return done(verdict('sender_unavailable', hints));
  if (sender.value.host_id === connection.hostId) return done(verdict('sender_is_worker', hints));
  const agent = value.agents.find(item => item?.id === connection.agentId);
  if (!agent) return done(verdict('agent_missing', hints));

  // An agent with a launch profile runs its tasks in the host's runtime, never in a session.
  let profiles = null;
  if (connection.mode === 'agent') {
    profiles = await peerspan.launchProfiles(hostDir);
    if (profiles.kind === 'invalid') return done(verdict('status_invalid', hints, { reason: PROFILES_UNREADABLE }));
    const profile = profileOf(profiles, connection.agentId);
    if (profile) {
      const result = await checkRuntime(peerspan, hostDir, profile, value.service.active, hints);
      return { result, basis: { hostDir, session: null, facts: factsOf(connection, { state, status, sender, profiles }) } };
    }
  }

  const sessions = (Array.isArray(agent.sessions) ? agent.sessions : [])
    .filter(session => session && typeof session.id === 'string' && typeof session.adapter_id === 'string')
    .filter(session => !named || (session.id === named.id && session.adapter_id === named.adapter_id))
    .filter(session => session.connection === 'ready')
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
    .slice(0, MAX_CANDIDATES);
  if (!sessions.length) return done(verdict('session_not_ready', hints));

  // The adapter's report is read after the status that made its session a candidate (MGD-16).
  const ready = verdict(value.service.active ? 'ready' : 'ready_service_inactive', hints);
  for (const session of sessions) {
    if (isVerified(await adapterReport(peerspan, hostDir, session.adapter_id), session)) {
      const ids = { id: session.id, adapter_id: session.adapter_id };
      return { result: ready, basis: { hostDir, session: ids, facts: factsOf(connection, { state, status, sender, profiles, session: ids }) } };
    }
  }
  return done(verdict('channel_unverified', hints));
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

/**
 * Resolves an agent for `connect --remote` from the sender's refreshed
 * directory (contract section 7.1): an exact match on address or agent ID, in
 * `reachable` or `mine`, on another host than the sender itself.
 */
export async function resolveRemote(peerspan, senderState, wanted, network) {
  const [sender, directory] = await Promise.all([
    peerspan.status(senderState),
    peerspan.agents(senderState, { network, refresh: true })
  ]);
  if (sender.kind !== 'ok') throw new Error(`Cannot read the sender host status: ${REASONS[sender.kind]}`);
  if (directory.kind === 'peerspan_unavailable' || directory.kind === 'peerspan_incompatible') {
    throw new Error(REASONS[directory.kind]);
  }
  if (directory.kind !== 'ok') {
    // The upstream error names the problem, such as a host in several networks without --network.
    const detail = (directory.stderr ?? '').trim().split('\n')[0].replace(/^error:\s*/, '').slice(0, 200);
    throw new Error("Cannot read the sender host's directory of agents" + (detail ? `: ${detail}` : ''));
  }
  const { value } = directory;
  if (!/^[\x21-\x7e]{1,128}$/.test(value.network_id)) throw new Error('The sender reported an invalid network ID');
  const candidates = new Map();
  for (const entry of [...value.reachable, ...value.mine]) {
    if (!entry || !isIdentifier('host', entry.host_id) || !isIdentifier('agent', entry.agent_id)) continue;
    if (entry.address !== wanted && entry.agent_id !== wanted) continue;
    // One agent may be listed in both lists; it is still one match.
    candidates.set(entry.host_id + '/' + entry.agent_id, entry);
  }
  const matches = [...candidates.values()];
  if (!matches.length) {
    throw new Error("No agent with that address or ID in the sender's directory, which lists only agents its "
      + 'owner lets this sender reach and whose names are addressable (lowercase); '
      + 'run peerspan agents for the sender host and pass an address or agent ID it lists');
  }
  if (matches.length > 1) throw new Error('More than one agent matches; pass the agent ID instead');
  if (matches[0].host_id === sender.value.host_id) {
    throw new Error('Sender and worker are the same Peerspan host, and a host cannot send tasks to itself; '
      + 'register this agent with --agent and pass --sender-state for another local host');
  }
  return { hostId: matches[0].host_id, agentId: matches[0].agent_id, networkId: value.network_id };
}
