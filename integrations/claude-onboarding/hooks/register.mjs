import { observation, privateValue } from './observation.mjs';
import { flow as parseProjectFlow, lookup as parseProjectLookup, validContext, same, defaultName, choiceLabel, reviewLines } from './project.mjs';
import { context as adapterContext, flow as parseAdapterFlow, lookup as parseAdapterLookup,
  transport as parseTransport, connection as parseConnection, reviewLines as adapterReviewLines } from './adapter.mjs';

let options;
let hostId = null;
let project = { stage: 'inactive', busy: false };
let projectExpiry = null;
let session = null;
let generation = 0;
let read = 0;
let lines = ['Host: unavailable'];
let check = { state: 'unverified' };
let expiration = null;
let adapter = { stage: 'inactive', busy: false };
let adapterExpiry = null;
let runtime = null;
let runtimeNotice = null;

function clearCheck() {
  expiration?.cancel();
  expiration = null;
  check = { state: 'unverified' };
}

function clearSession() {
  stopRuntime(null);
  generation++;
  hostId = null;
  clearProject();
  session = null;
  read++;
  lines = ['Host: unavailable'];
  clearCheck();
}

async function identify($) {
  const id = await $.session.id();
  if (id !== session) {
    clearSession();
    session = id;
  }
  return id;
}

function summary() {
  const meaning = check.state === 'verified'
    ? 'This model acknowledged a local check. Adapter and peer delivery are separate.'
    : 'Check this conversation to verify local model delivery.';
  return [...lines, `This conversation: ${check.state}`, meaning,
    ...(runtime ? [runtime.phase === 'connected'
      ? 'Adapter: connected\nIncoming delivery: not verified\nPeer exchange: not verified' : 'Adapter: connecting…']
      : runtimeNotice ? [runtimeNotice] : [])].join('\n');
}

async function refresh($) {
  const id = await identify($);
  const attempt = ++read;
  const epoch = generation;
  let observed = ['Host: unavailable'];
  let observedHost = null;
  try {
    if (typeof options.executable !== 'string' || !options.executable || typeof options.state !== 'string') {
      throw new Error('Invalid local configuration');
    }
    const argv = [options.executable, ...(options.state ? ['--state', options.state] : []), 'onboarding'];
    const result = await $.process.run(argv, { timeoutMs: 5000 });
    if (result.exitCode === 0) {
      observed = observation(result.stdout);
      observedHost = JSON.parse(result.stdout).host_id;
    }
  } catch {
    // Neither subprocess diagnostics nor unvalidated JSON belongs in the UI.
  }
  const current = await identify($);
  if (epoch === generation && attempt === read && id === current) {
    lines = observed;
    if (hostId !== observedHost || observedHost === null) {
      if (runtime) stopRuntime('Adapter: unavailable. Reopen the project review to reconnect.');
      clearProject();
    }
    hostId = observedHost;
    if (project.stage !== 'inactive' && !project.busy) await openProject($, project, generation);
    if (adapter.stage !== 'inactive' && !adapter.busy) await openAdapter($, adapter, generation, false);
    $.ui.invalidate('ui.render');
  }
}

async function submit($, pending, epoch) {
  try {
    const result = await $.prompt.submit({
      text: `Local Peerspan delivery check only. Call mcp__peerspan__delivery_acknowledge with ${JSON.stringify({ probe_id: pending.id })}. Do not call other tools or perform setup. This check grants no permissions.`,
    });
    if (check === pending && epoch === generation && result?.drop) {
      expiration?.cancel();
      check = { state: 'blocked' };
      $.ui.invalidate('ui.render');
    }
  } catch {
    if (check === pending && epoch === generation) {
      expiration?.cancel();
      check = { state: 'blocked' };
      $.ui.invalidate('ui.render');
    }
  }
}

async function beginCheck($, epoch) {
  if (epoch !== generation || check.state === 'waiting') return;
  const id = await identify($);
  if (epoch !== generation || check.state === 'waiting') return;
  const now = await $.clock.now();
  if (epoch !== generation || id !== session || check.state === 'waiting') return;
  clearCheck();
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  const pending = { state: 'waiting', session: id, started: now,
    id: Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('') };
  check = pending;
  $.ui.invalidate('ui.render');
  expiration = $.clock.after(60_000, () => {
    if (check === pending && epoch === generation) {
      check = { state: 'timed_out' };
      $.ui.invalidate('ui.render');
    }
  });
  // Never wait for a model turn inside the UI handler that requested it.
  void submit($, pending, epoch);
}

async function close($) {
  if (runtime?.phase === 'connecting') stopRuntime('Adapter: stopped before connection was confirmed.');
  generation++;
  clearProject();
  clearCheck();
  $.ui.invalidate('ui.render');
  await $.ui.close({ id: 'peerspan' });
}

// All native effects stay in this module; imported project helpers are pure.
function clearProject() {
  clearAdapter();
  projectExpiry?.cancel();
  projectExpiry = null;
  project = { stage: 'inactive', busy: false };
}
function projectStart($, previous, epoch) {
  if (project !== previous || previous.busy || epoch !== generation) return null;
  project = { ...previous, busy: true };
  $.ui.invalidate('ui.render');
  return project;
}
async function projectContext($) {
  const native_session_id = await $.session.id();
  const project_root = await $.session.root();
  const value = { project_root, native_session_id, integration: 'claude-code' };
  if (!validContext(value) || privateValue(project_root) || privateValue(native_session_id)) throw new Error('Unavailable native project context');
  return value;
}
async function projectCurrent($, running, epoch, context) {
  if (project !== running || epoch !== generation) return false;
  const current = await projectContext($);
  if (project !== running || epoch !== generation) return false;
  if (!same(current, context) || current.native_session_id !== session || running.host !== hostId) {
    if (runtime) stopRuntime('Adapter: stopped after project or conversation change.');
    clearProject();
    project = { stage: 'unavailable', message: 'Project or conversation changed. Reopen Peerspan.', busy: false };
    $.ui.invalidate('ui.render');
    return false;
  }
  return true;
}
async function projectRun($, command, payload) {
  if (typeof options.executable !== 'string' || !options.executable || typeof options.state !== 'string') {
    throw new Error('Unavailable local host configuration');
  }
  const argv = [options.executable, ...(options.state ? ['--state', options.state] : []), 'onboarding', 'project', ...command];
  const result = await $.process.run(argv, { timeoutMs: 5000, ...(payload ? { stdin: JSON.stringify(payload) } : {}) });
  if (result.exitCode !== 0) throw new Error('Unavailable project flow');
  return result.stdout;
}
function projectFailure($, running, epoch, decision = false) {
  if (project !== running || epoch !== generation) return;
  projectExpiry?.cancel();
  projectExpiry = null;
  project = { stage: 'unavailable', busy: false,
    context: running.context, host: running.host,
    message: decision ? 'Decision outcome unknown. Refresh to check the host.' : 'Project review unavailable. Refresh to check the host.' };
  $.ui.invalidate('ui.render');
}
async function projectView($, running, epoch, context, agents, flow) {
  const now = await $.clock.now();
  if (!await projectCurrent($, running, epoch, context)) return;
  projectExpiry?.cancel();
  projectExpiry = null;
  const stage = flow === null ? 'choose' : flow.state === 'review' && Date.parse(flow.review.expires_at) <= now ? 'expired' : flow.state;
  if (adapter.stage !== 'inactive' && (stage !== 'attached' || adapter.parent?.flow_id !== flow.flow_id ||
      adapter.parent?.review_id !== flow.review_id || !same(adapter.parent?.review, flow.review))) clearAdapter();
  const view = { stage, context, host: hostId, agents, flow, busy: false, page: 0,
    name: running.name ?? defaultName(context.project_root), owner: running.owner ?? 'local owner' };
  project = view;
  if (stage === 'review') {
    const captured = flow;
    projectExpiry = $.clock.after(Math.max(0, Date.parse(flow.review.expires_at) - now), () => {
      if (epoch === generation && project.flow?.flow_id === captured.flow_id &&
          project.flow?.review_id === captured.review_id && project.stage === 'review') {
        project = { ...project, stage: 'expired', busy: false };
        $.ui.invalidate('ui.render');
      }
    });
  }
  $.ui.invalidate('ui.render');
}
async function openProject($, previous, epoch) {
  const running = projectStart($, previous, epoch);
  if (!running) return;
  try {
    const context = await projectContext($);
    if (project !== running || epoch !== generation) return;
    if (previous.context && !same(previous.context, context)) {
      if (runtime) stopRuntime('Adapter: stopped after project change.');
      clearProject();
      project = { stage: 'unavailable', message: 'Project changed. Refresh to review the current project.', busy: false };
      $.ui.invalidate('ui.render');
      return;
    }
    running.context = context;
    running.host = hostId;
    if (!await projectCurrent($, running, epoch, context)) return;
    const raw = await projectRun($, ['lookup', '--stdin'], context);
    if (!await projectCurrent($, running, epoch, context)) return;
    const result = parseProjectLookup(raw, context, hostId);
    await projectView($, running, epoch, context, result.agents, result.flow);
  } catch { projectFailure($, running, epoch); }
}
function projectDraft($, previous, epoch, key, value) {
  if (project !== previous || previous.busy || epoch !== generation || previous.stage !== 'choose') return;
  project = { ...previous, [key]: value };
  $.ui.invalidate('ui.render');
}
function projectPage($, previous, epoch, page) {
  if (project !== previous || previous.busy || epoch !== generation || previous.stage !== 'choose') return;
  project = { ...previous, page };
  $.ui.invalidate('ui.render');
}
function replaceProject($, previous, epoch) {
  if (project !== previous || previous.busy || epoch !== generation || !['declined', 'expired', 'invalidated'].includes(previous.stage)) return;
  projectExpiry?.cancel();
  projectExpiry = null;
  project = { ...previous, stage: 'choose', replace: previous.flow.flow_id,
    name: defaultName(previous.context.project_root), owner: 'local owner', page: 0 };
  $.ui.invalidate('ui.render');
}
async function prepareProject($, previous, epoch, agent) {
  const running = projectStart($, previous, epoch);
  if (!running) return;
  try {
    if (!await projectCurrent($, running, epoch, previous.context)) return;
    const request = { ...previous.context, agent, ...(previous.replace ? { replace_flow_id: previous.replace } : {}) };
    const raw = await projectRun($, ['prepare', '--stdin'], request);
    if (!await projectCurrent($, running, epoch, previous.context)) return;
    const flow = parseProjectFlow(JSON.parse(raw), previous.context, hostId);
    if (flow.state !== 'review' || (previous.replace && flow.flow_id === previous.replace) ||
        (agent.kind === 'existing' && (flow.review.create_agent || flow.review.agent.id !== agent.id)) ||
        (agent.kind === 'new' && (!flow.review.create_agent || flow.review.agent.name !== agent.name.trim() || flow.review.agent.owner !== agent.owner.trim()))) {
      throw new Error('Unavailable selected project review');
    }
    await projectView($, running, epoch, previous.context, previous.agents, flow);
  } catch { projectFailure($, running, epoch); }
}
async function decideProject($, previous, epoch, decision) {
  if (previous.stage !== 'review' || !previous.flow) return;
  const running = projectStart($, previous, epoch);
  if (!running) return;
  let sent = false;
  try {
    if (!await projectCurrent($, running, epoch, previous.context)) return;
    const captured = previous.flow;
    const raw = await projectRun($, ['inspect', captured.flow_id]);
    if (!await projectCurrent($, running, epoch, previous.context)) return;
    const current = parseProjectFlow(JSON.parse(raw), previous.context, hostId);
    const now = await $.clock.now();
    if (current.flow_id !== captured.flow_id || current.review_id !== captured.review_id ||
        !same(current.review, captured.review) || current.state !== 'review' || Date.parse(captured.review.expires_at) <= now) {
      throw new Error('Project review changed or expired');
    }
    if (!await projectCurrent($, running, epoch, previous.context)) return;
    sent = true;
    const result = await projectRun($, ['decide', '--stdin'], { flow_id: captured.flow_id, review_id: captured.review_id,
      ...previous.context, decision });
    if (!await projectCurrent($, running, epoch, previous.context)) return;
    const outcome = parseProjectFlow(JSON.parse(result), previous.context, hostId);
    if (outcome.flow_id !== captured.flow_id || outcome.review_id !== captured.review_id || !same(outcome.review, captured.review) ||
        outcome.state !== (decision === 'approve' ? 'attached' : 'declined')) throw new Error('Unknown project decision result');
    await projectView($, running, epoch, previous.context, previous.agents, outcome);
  } catch { projectFailure($, running, epoch, sent); }
}

function clearAdapter() {
  if (runtime?.phase === 'connecting') stopRuntime('Adapter: stopped before connection was confirmed.');
  adapterExpiry?.cancel();
  adapterExpiry = null;
  adapter = { stage: 'inactive', busy: false };
}
function stopRuntime(message) {
  runtime?.renewal?.cancel();
  runtime?.expiry?.cancel();
  runtime = null;
  runtimeNotice = message;
}
function adapterStart($, previous, epoch) {
  if (adapter !== previous || previous.busy || epoch !== generation || project.stage !== 'attached' || project.busy) return null;
  adapter = { ...previous, busy: true, parent: project.flow, context: project.context, host: hostId };
  $.ui.invalidate('ui.render');
  return adapter;
}
async function adapterCurrent($, running, epoch) {
  if (adapter !== running || epoch !== generation || project.stage !== 'attached' ||
      project.flow.flow_id !== running.parent.flow_id || project.flow.review_id !== running.parent.review_id ||
      !same(project.flow.review, running.parent.review)) return false;
  const current = await projectContext($);
  if (adapter !== running || epoch !== generation) return false;
  if (!same(current, running.context) || current.native_session_id !== session || running.host !== hostId) {
    clearProject();
    if (runtime) stopRuntime('Adapter: stopped after project or conversation change.');
    $.ui.invalidate('ui.render');
    return false;
  }
  return true;
}
async function adapterRun($, command, payload) {
  if (typeof options.executable !== 'string' || !options.executable || typeof options.state !== 'string') throw new Error('Unavailable local host');
  const result = await $.process.run([options.executable, ...(options.state ? ['--state', options.state] : []),
    'onboarding', 'adapter', ...command], { timeoutMs: 5000, ...(payload ? { stdin: JSON.stringify(payload) } : {}) });
  if (result.exitCode !== 0) throw new Error('Unavailable adapter flow');
  return result.stdout;
}
async function inspectAdapterParent($, running, epoch) {
  if (!await adapterCurrent($, running, epoch)) return false;
  const raw = await projectRun($, ['inspect', running.parent.flow_id]);
  if (!await adapterCurrent($, running, epoch)) return false;
  const current = parseProjectFlow(JSON.parse(raw), running.context, running.host);
  if (current.state !== 'attached' || current.flow_id !== running.parent.flow_id ||
      current.review_id !== running.parent.review_id || !same(current.review, running.parent.review)) throw new Error('Changed project review');
  return true;
}
function adapterFailure($, running, epoch, decision = false) {
  if (adapter !== running || epoch !== generation) return;
  adapterExpiry?.cancel();
  adapterExpiry = null;
  adapter = { ...running, stage: 'unavailable', busy: false,
    message: decision ? 'Adapter decision outcome unknown. Refresh to check the host.' : 'Adapter review unavailable. Refresh to check the host.' };
  $.ui.invalidate('ui.render');
}
async function adapterView($, running, epoch, flow) {
  const now = await $.clock.now();
  if (!await adapterCurrent($, running, epoch)) return;
  adapterExpiry?.cancel();
  adapterExpiry = null;
  const deadline = flow?.state === 'review' ? flow.review.expires_at : flow?.state === 'authorized' ? flow.review.credential_expires_at : null;
  const stage = flow === null ? 'empty' : deadline && Date.parse(deadline) <= now ? 'expired' : flow.state;
  adapter = { ...running, stage, flow, busy: false, message: null };
  if (deadline && stage !== 'expired') {
    const captured = flow;
    adapterExpiry = $.clock.after(Math.max(0, Date.parse(deadline) - now), () => {
      if (epoch === generation && adapter.flow === captured) {
        adapter = { ...adapter, stage: 'expired', busy: false };
        $.ui.invalidate('ui.render');
      }
    });
  }
  $.ui.invalidate('ui.render');
}
async function openAdapter($, previous, epoch, prepareMissing) {
  const running = adapterStart($, previous, epoch);
  if (!running) return;
  try {
    if (!await inspectAdapterParent($, running, epoch)) return;
    const raw = await adapterRun($, ['lookup', '--stdin'], adapterContext(running.parent));
    if (!await adapterCurrent($, running, epoch)) return;
    let flow = parseAdapterLookup(raw, running.parent, running.host).flow;
    if (flow === null && prepareMissing) {
      const prepared = await adapterRun($, ['prepare', '--stdin'], { context: adapterContext(running.parent) });
      if (!await adapterCurrent($, running, epoch)) return;
      flow = parseAdapterFlow(JSON.parse(prepared), running.parent, running.host);
      if (flow.state !== 'review') throw new Error('Unavailable prepared adapter review');
    }
    await adapterView($, running, epoch, flow);
  } catch { adapterFailure($, running, epoch); }
}
async function replaceAdapter($, previous, epoch) {
  if (!['declined', 'expired', 'invalidated'].includes(previous.stage) || !previous.flow) return;
  const running = adapterStart($, previous, epoch);
  if (!running) return;
  try {
    if (!await inspectAdapterParent($, running, epoch)) return;
    const raw = await adapterRun($, ['prepare', '--stdin'], { context: adapterContext(running.parent), replace_flow_id: previous.flow.flow_id });
    if (!await adapterCurrent($, running, epoch)) return;
    const flow = parseAdapterFlow(JSON.parse(raw), running.parent, running.host);
    if (flow.state !== 'review' || flow.flow_id === previous.flow.flow_id) throw new Error('Unavailable adapter replacement');
    await adapterView($, running, epoch, flow);
  } catch { adapterFailure($, running, epoch); }
}
async function decideAdapter($, previous, epoch, decision) {
  if (previous.stage !== 'review' || !previous.flow) return;
  const running = adapterStart($, previous, epoch);
  if (!running) return;
  let sent = false;
  try {
    if (!await inspectAdapterParent($, running, epoch)) return;
    const captured = previous.flow;
    const raw = await adapterRun($, ['inspect', captured.flow_id]);
    if (!await adapterCurrent($, running, epoch)) return;
    const current = parseAdapterFlow(JSON.parse(raw), running.parent, running.host);
    const now = await $.clock.now();
    if (current.flow_id !== captured.flow_id || current.review_id !== captured.review_id || !same(current.review, captured.review) ||
        current.state !== 'review' || Date.parse(captured.review.expires_at) <= now) throw new Error('Changed adapter review');
    if (!await adapterCurrent($, running, epoch)) return;
    sent = true;
    const result = await adapterRun($, ['decide', '--stdin'], { flow_id: captured.flow_id, context: adapterContext(running.parent),
      review_id: captured.review_id, decision });
    if (!await adapterCurrent($, running, epoch)) return;
    const outcome = parseAdapterFlow(JSON.parse(result), running.parent, running.host);
    if (outcome.flow_id !== captured.flow_id || outcome.review_id !== captured.review_id || !same(outcome.review, captured.review) ||
        outcome.state !== (decision === 'approve' ? 'authorized' : 'declined')) throw new Error('Unknown adapter outcome');
    await adapterView($, running, epoch, outcome);
  } catch { adapterFailure($, running, epoch, sent); }
}
async function runtimeCurrent($, active) {
  if (runtime !== active) return false;
  const current = await projectContext($);
  const surfaces = await $.session.surfaces();
  if (runtime !== active) return false;
  if (!same(current, active.context) || current.native_session_id !== session || active.host !== hostId || !surfaces.includes('terminal')) {
    stopRuntime('Adapter: stopped after project, conversation or surface change.');
    clearProject();
    $.ui.invalidate('ui.render');
    return false;
  }
  return true;
}
async function runtimeInspect($, active) {
  if (!await runtimeCurrent($, active)) return false;
  const rawParent = await projectRun($, ['inspect', active.parent.flow_id]);
  if (!await runtimeCurrent($, active)) return false;
  const parent = parseProjectFlow(JSON.parse(rawParent), active.context, active.host);
  if (parent.state !== 'attached' || parent.flow_id !== active.parent.flow_id || parent.review_id !== active.parent.review_id ||
      !same(parent.review, active.parent.review)) throw new Error('Changed adapter project');
  const raw = await adapterRun($, ['inspect', active.flow.flow_id]);
  if (!await runtimeCurrent($, active)) return false;
  const flow = parseAdapterFlow(JSON.parse(raw), active.parent, active.host);
  const now = await $.clock.now();
  if (flow.state !== 'authorized' || flow.flow_id !== active.flow.flow_id || flow.review_id !== active.flow.review_id ||
      !same(flow.review, active.flow.review) || Date.parse(flow.review.credential_expires_at) <= now) throw new Error('Changed adapter authorization');
  return runtimeCurrent($, active);
}
async function scopedConnect($, active) {
  let deadline;
  try {
    const timeout = new Promise((_, reject) => {
      deadline = $.clock.after(5000, () => reject(new Error('Adapter request outcome unknown')));
    });
    const response = await Promise.race([$.http.fetch('http://peerspan/adapter/v1/connect', {
      method: 'POST', socketPath: active.transport.adapter_socket,
      headers: { Authorization: `Bearer ${active.transport.token}`, 'X-Peerspan-Instance': active.transport.instance_id, 'Content-Type': 'application/json' },
      body: JSON.stringify({ adapter_id: active.transport.adapter_id, session_id: active.transport.session_id,
        instance_id: active.transport.instance_id, protocol_version: 'claude-mod-v1' }),
    }), timeout]);
    if (response.status !== 200 || !response.ok) throw new Error('Unavailable scoped connection');
    return parseConnection(JSON.parse(response.text), active.flow);
  } finally { deadline?.cancel(); }
}
async function renewRuntime($, active) {
  if (runtime !== active || active.busy) return;
  active.busy = true;
  try {
    if (!await runtimeInspect($, active)) return;
    const connection = await scopedConnect($, active);
    if (!await runtimeCurrent($, active)) return;
    const now = await $.clock.now();
    if (runtime !== active) return;
    const until = Date.parse(connection.lease_expires_at);
    if (connection.state !== 'ready' || !Number.isFinite(until) || until <= now ||
        until > Date.parse(active.flow.review.credential_expires_at)) throw new Error('Unavailable live lease');
    active.phase = 'connected';
    active.connection = connection;
    active.expiry?.cancel();
    active.expiry = $.clock.after(until - now, () => {
      if (runtime === active && active.connection === connection) {
        stopRuntime('Adapter: lease expired. Reopen the project review to reconnect.');
        $.ui.invalidate('ui.render');
      }
    });
    active.renewal = $.clock.after(5000, () => renewRuntime($, active));
    $.ui.invalidate('ui.render');
  } catch {
    if (runtime === active) {
      stopRuntime('Adapter: connection outcome unknown. Reopen the project review to reconnect.');
      $.ui.invalidate('ui.render');
    }
  } finally { active.busy = false; }
}
async function connectAdapter($, previous, epoch) {
  if (runtime || previous.stage !== 'authorized' || !previous.flow) return;
  const running = adapterStart($, previous, epoch);
  if (!running) return;
  const active = { parent: running.parent, context: running.context, host: running.host, flow: previous.flow, phase: 'connecting', busy: false };
  runtime = active;
  runtimeNotice = null;
  try {
    if (!await inspectAdapterParent($, running, epoch) || !await runtimeInspect($, active)) return;
    const raw = await adapterRun($, ['transport', '--stdin'], { flow_id: active.flow.flow_id,
      context: adapterContext(active.parent), review_id: active.flow.review_id });
    if (!await adapterCurrent($, running, epoch) || !await runtimeCurrent($, active)) return;
    active.transport = parseTransport(raw, active.flow);
    await renewRuntime($, active);
  } catch {
    if (runtime === active) stopRuntime('Adapter: unavailable. Refresh and review before reconnecting.');
  } finally {
    // A stopped/closed view cannot regain callback authority from a late result.
    if (adapter === running && epoch === generation) adapter = { ...running, busy: false };
    if (runtime === active && active.phase !== 'connected') stopRuntime('Adapter: unavailable. Reopen the project review to reconnect.');
    $.ui.invalidate('ui.render');
  }
}
function adapterControls($, { Text, Button }, epoch) {
  if (project.stage !== 'attached' || project.busy) return [];
  const previous = adapter;
  const button = (key, label, onPress) => Button({ key, label, onPress });
  if (previous.busy) return [Text({ children: ['Adapter: working…'] })];
  if (previous.stage === 'inactive') return [button('adapter-review', 'Review adapter connection', () => openAdapter($, previous, epoch, true))];
  const back = button('adapter-back', 'Back to project', () => {
    if (adapter === previous && epoch === generation) { clearAdapter(); $.ui.invalidate('ui.render'); }
  });
  if (previous.stage === 'unavailable') return [Text({ children: [previous.message] }), back];
  if (previous.stage === 'empty') return [button('adapter-prepare', 'Review adapter permissions', () => openAdapter($, previous, epoch, true)), back];
  const status = previous.stage === 'authorized' ? 'Adapter: authorized; connection requires Connect adapter.'
    : previous.stage === 'review' ? 'Adapter: review permissions' : `Adapter: ${previous.stage}`;
  return [Text({ children: [status, '\n', adapterReviewLines(previous.flow)] }),
    ...(previous.stage === 'review' ? [
      button('adapter-approve', 'Approve adapter', () => decideAdapter($, previous, epoch, 'approve')),
      button('adapter-decline', 'Decline adapter', () => decideAdapter($, previous, epoch, 'decline')),
    ] : previous.stage === 'authorized' ? runtime ? [] : [
      button('adapter-connect', 'Connect adapter', () => connectAdapter($, previous, epoch)),
    ] : [button('adapter-replace', 'Review a replacement adapter', () => replaceAdapter($, previous, epoch))]), back];
}
function projectControls($, { Text, Button, Input }, epoch) {
  const previous = project;
  const button = (key, label, onPress) => Button({ key, label, onPress });
  if (previous.busy) return [Text({ children: ['Project: working…'] })];
  if (previous.stage === 'inactive') return hostId ? [button('project-connect', 'Connect this project', () => openProject($, previous, epoch))] : [];
  const back = button('project-back', 'Back to Peerspan', () => {
    if (project === previous && epoch === generation) { clearProject(); $.ui.invalidate('ui.render'); }
  });
  if (previous.stage === 'unavailable') return [Text({ children: [previous.message] }), back];
  if (previous.stage === 'choose') {
    const page = previous.page ?? 0;
    return [Text({ children: ['Project: choose an agent'] }),
      Input({ key: 'project-new-name', label: 'New agent name', value: previous.name,
        onInput: value => projectDraft($, previous, epoch, 'name', value),
        onSubmit: value => projectDraft($, previous, epoch, 'name', value) }),
      Input({ key: 'project-owner', label: 'Owner label', value: previous.owner,
        onInput: value => projectDraft($, previous, epoch, 'owner', value),
        onSubmit: value => projectDraft($, previous, epoch, 'owner', value) }),
      button('project-new-review', 'Review new agent', () => prepareProject($, previous, epoch,
        { kind: 'new', name: previous.name, owner: previous.owner })),
      ...previous.agents.slice(page * 10, page * 10 + 10).map(a => button(`project-agent-${a.id}`, choiceLabel(a),
        () => prepareProject($, previous, epoch, { kind: 'existing', id: a.id }))),
      ...(page > 0 ? [button('project-prev', 'Previous agents', () => projectPage($, previous, epoch, page - 1))] : []),
      ...(previous.agents.length > page * 10 + 10 ? [button('project-next', 'More agents', () => projectPage($, previous, epoch, page + 1))] : []), back];
  }
  const status = previous.stage === 'attached' ? 'Project: attachment recorded\nAdapter connection is next.'
    : previous.stage === 'review' ? 'Project: review attachment'
    : previous.stage === 'expired' ? 'Project: review deadline reached. Refresh to check the host.'
    : `Project: ${previous.stage}`;
  return [Text({ children: [status, '\n', reviewLines(previous.flow)] }),
    ...(previous.stage === 'review' ? [
      button('project-approve', 'Approve attachment', () => decideProject($, previous, epoch, 'approve')),
      button('project-decline', 'Decline attachment', () => decideProject($, previous, epoch, 'decline')),
    ] : previous.stage !== 'attached' ? [button('project-replace', 'Review a replacement', () => replaceProject($, previous, epoch))] : []), back];
}

export function register(on, configured = {}) {
  options = { executable: 'peerspan', state: '', ...configured };
  on('session.start', async ($, e, next) => {
    clearSession();
    await $.tool.register({
      name: 'delivery_acknowledge',
      description: 'Acknowledge the exact local Peerspan delivery check. It grants no authority and performs no setup.',
      inputSchema: { type: 'object', properties: { probe_id: { type: 'string' } },
        required: ['probe_id'], additionalProperties: false },
    });
    await $.command.register({ name: 'peerspan', description: 'Connect this project and inspect Peerspan', immediate: true });
    return next(e);
  });
  on('command.run', { command: 'peerspan' }, async ($, e) => {
    if (e.args.trim()) return { text: 'Usage: /peerspan' };
    await refresh($);
    const surfaces = await $.session.surfaces();
    if (!surfaces.includes('terminal')) return { text: summary() };
    await $.ui.open({ id: 'peerspan', title: 'Peerspan', focus: true, closeOnEscape: true });
    return {};
  });
  on('ui.render', { component: 'Pane' }, async ($, e, next) => {
    if (e.requestId !== 'peerspan' || e.surface !== 'terminal') return next(e);
    const epoch = generation;
    const displayedRuntime = runtime;
    const { Box, Text, Button, Input } = $.ui.resolve(e);
    return Box({ flexDirection: 'column', children: [
      Text({ children: [summary()] }),
      Button({ key: 'refresh', label: 'Refresh', onPress: () => refresh($) }),
      check.state === 'waiting' ? Text({ children: ['Waiting for this model to acknowledge…'] })
        : Button({ key: 'check', label: 'Check this conversation', onPress: () => beginCheck($, epoch) }),
      ...projectControls($, { Text, Button, Input }, epoch),
      ...adapterControls($, { Text, Button }, epoch),
      ...(runtime ? [Button({ key: 'adapter-stop', label: 'Stop adapter', onPress: () => {
        if (runtime !== displayedRuntime || epoch !== generation) return;
        stopRuntime('Adapter: stopped. The last accepted lease will expire; the credential is not revoked.');
        if (adapter.busy) adapter = { ...adapter, busy: false };
        $.ui.invalidate('ui.render');
      } })] : []),
      Button({ key: 'close', label: 'Close', onPress: () => close($) }),
    ] });
  });
  on('tool.call', { tool: 'mcp__peerspan__delivery_acknowledge' }, async ($, e, next) => {
    const pending = check;
    const id = await identify($);
    const now = await $.clock.now();
    if (check !== pending || pending.state !== 'waiting' || typeof e.probe_id !== 'string' ||
        e.probe_id !== pending.id || id !== pending.session || e.agentId !== undefined ||
        next.origin.plugin !== 'engine' || next.origin.tier !== 'core' || now < pending.started ||
        now - pending.started >= 60_000) {
      return { deny: 'No matching current conversation check.' };
    }
    expiration?.cancel();
    check = { state: 'verified' };
    $.ui.invalidate('ui.render');
    return { result: { state: 'verified' } };
  }).catch(() => ({ deny: 'Conversation check unavailable.' }));
  on('ui.close', { id: 'peerspan' }, async ($, e, next) => {
    if (runtime?.phase === 'connecting') stopRuntime('Adapter: stopped before connection was confirmed.');
    generation++;
    clearProject();
    clearCheck();
    return next(e);
  });
  on('classic.CwdChanged', async ($, e, next) => {
    if (runtime) stopRuntime('Adapter: stopped after project change.');
    clearProject();
    $.ui.invalidate('ui.render');
    return next(e);
  });
  on('session.end', async ($, e, next) => {
    clearSession();
    return next(e);
  });
}
