import { observation, privateValue } from './observation.mjs';
import { flow as parseProjectFlow, lookup as parseProjectLookup, validContext, same, bytes, quoted, defaultName, choiceLabel, reviewLines } from './project.mjs';
import { context as adapterContext, flow as parseAdapterFlow, lookup as parseAdapterLookup,
  transport as parseTransport, connection as parseConnection, reviewLines as adapterReviewLines } from './adapter.mjs';
import { tools as messageTools, argumentsOf, typedId, content as messageContent, hello as messageHello,
  prompt as messagePrompt, handoff as parseHandoff, delivery as parseDelivery, seen as parseSeen, reply as parseReply } from './messages.mjs';
import { tools as taskTools, handoff as parseTask, cancellation as parseCancellation, prompt as taskPrompt,
  cancelPrompt, argumentsFor as taskArguments, result as taskResult, url as taskUrl } from './tasks.mjs';

import { flow as parseInvitationFlow, lookup as parseInvitationLookup, networks as invitationNetworks,
  proposal as invitationProposal, handoff as parseInvitationHandoff, reviewLines as invitationReviewLines } from './invitation.mjs';

import { validCode as validInvitationCode, preview as parseRecipientPreview, reviewLines as recipientReviewLines, terms as recipientPublicTerms } from './recipient.mjs';
import { identities as parseJoinIdentities, createdIdentity as parseCreatedIdentity, flow as parseJoinFlow, lookup as parseJoinLookup,
  reviewLines as joinReviewLines, provenance as joinProvenance } from './join.mjs';
import { progress as parseJoinProgress, progressLines as joinProgressLines } from './join-progress.mjs';
import { owner as parseOwner, reviewLines as ownerReviewLines, signature as parseOriginalSignature,
  sameOriginal, signable, signatureDeadline as ownerSignatureDeadline } from './owner.mjs';

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
let invitation = { stage: 'inactive', busy: false };
let invitationExpiry = null;
let recipient = { stage: 'inactive', busy: false };
let recipientExpiry = null;
let joining = { stage: 'inactive', busy: false };
let joiningExpiry = null;
let runtime = null;
let runtimeNotice = null;
let registeredMessageTools = new Set();
let registeredTaskTools = new Map();

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
  registeredMessageTools = new Set();
  registeredTaskTools = new Map();
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
      ? `Adapter: connected\n${messageSummary(runtime)}${taskSummary(runtime)}\nPeer exchange: not verified` : 'Adapter: connecting…']
      : runtimeNotice ? [runtimeNotice] : [])].join('\n');
}

async function refresh($) {
  const previousJoining = joining;
  clearJoining();
  const clearedJoining = joining;
  clearRecipient();
  // Invalidate pending invitation effects and drop a revealed code before any await.
  if (invitation.stage !== 'inactive') invitation = { ...invitation, code: null, busy: false };
  $.ui.invalidate('ui.render');
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
    if (invitation.stage !== 'inactive' && !invitation.busy) await openInvitation($, invitation, generation);
    if (previousJoining.stage !== 'inactive' && joining === clearedJoining && epoch === generation && attempt === read &&
        previousJoining.host === hostId && project.stage === 'attached' && same(previousJoining.context, project.context) &&
        previousJoining.parent.flow_id === project.flow.flow_id && previousJoining.parent.review_id === project.flow.review_id &&
        same(previousJoining.parent.review, project.flow.review)) await openJoining($, joining, epoch);
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
  clearJoining();
  clearRecipient();
  clearInvitation();
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
  if (invitation.stage !== 'inactive' && (stage !== 'attached' || invitation.parent?.flow_id !== flow.flow_id ||
      invitation.parent?.review_id !== flow.review_id || !same(invitation.parent?.review, flow.review))) clearInvitation();
  if (recipient.stage !== 'inactive' && (stage !== 'attached' || recipient.parent?.flow_id !== flow.flow_id ||
      recipient.parent?.review_id !== flow.review_id || !same(recipient.parent?.review, flow.review))) clearRecipient();
  if (joining.stage !== 'inactive' && (stage !== 'attached' || joining.parent?.flow_id !== flow.flow_id ||
      joining.parent?.review_id !== flow.review_id || !same(joining.parent?.review, flow.review))) clearJoining();
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
  stopTasks(runtime);
  runtime?.messages?.deadline?.cancel();
  runtime?.messages?.poll?.cancel();
  runtime?.renewal?.cancel();
  runtime?.expiry?.cancel();
  runtime = null;
  runtimeNotice = message;
}
function messageSummary(active) {
  const attempt = active.messages;
  if (!attempt) return 'Incoming delivery: not verified';
  const status = attempt.state === 'ready' ? 'verified (messages)' : ['starting', 'waiting'].includes(attempt.state)
    ? 'waiting for model' : `not verified (${attempt.state})`;
  const counts = active.messageCounts;
  return `Incoming delivery: ${status}\nMessages submitted: ${counts.submitted.size}\nMessages seen: ${counts.seen.size}\nMessages replied: ${counts.replied.size}`;
}
function messageFailure($, active, attempt, state = 'blocked') {
  if (runtime !== active || active.messages !== attempt) return;
  attempt.deadline?.cancel();
  attempt.poll?.cancel();
  attempt.state = state;
  stopTasks(active, 'blocked');
  $.ui.invalidate('ui.render');
}
async function messageCurrent($, active, attempt, ready = false) {
  if (runtime !== active || active.messages !== attempt || active.phase !== 'connected' ||
      !['starting', 'waiting', 'ready'].includes(attempt.state) || (ready && attempt.state !== 'ready')) return false;
  if (!await runtimeCurrent($, active)) return false;
  const now = await $.clock.now();
  if (runtime !== active || active.messages !== attempt || !['starting', 'waiting', 'ready'].includes(attempt.state)) return false;
  if (Date.parse(active.connection.lease_expires_at) <= now || Date.parse(active.flow.review.credential_expires_at) <= now) {
    stopRuntime('Adapter: lease expired. Reopen the project review to reconnect.');
    $.ui.invalidate('ui.render');
    return false;
  }
  if (attempt.state !== 'ready' && attempt.until !== undefined && attempt.until <= now) {
    messageFailure($, active, attempt, 'expired');
    return false;
  }
  return true;
}
async function messageRequest($, active, attempt, operation, body, id, guard = () => true) {
  if (!await messageCurrent($, active, attempt) || !guard() || !await inspectMessageAuthorization($, active, attempt, guard) ||
      !await messageCurrent($, active, attempt) || !guard()) throw new Error('Unavailable message context');
  let url;
  if (operation === 'ready') url = 'http://peerspan/adapter/v1/ready';
  else if (operation === 'next') url = 'http://peerspan/adapter/v1/next';
  else if (operation === 'seen') url = 'http://peerspan/adapter/v1/seen';
  else if (typedId(id, 'delivery') && operation === 'forwarded') url = `http://peerspan/adapter/v1/deliveries/${id}/forwarded`;
  else if (typedId(id, 'delivery') && operation === 'reply') url = `http://peerspan/adapter/v1/deliveries/${id}/reply`;
  else if (operation.startsWith('task_')) url = taskUrl(operation, id);
  else throw new Error('Unavailable scoped message route');
  let deadline;
  try {
    const timeout = new Promise((_, reject) => {
      deadline = $.clock.after(5000, () => reject(new Error('Unknown message outcome')));
    });
    const response = await Promise.race([$.http.fetch(url, { method: 'POST', socketPath: active.transport.adapter_socket,
      headers: { Authorization: `Bearer ${active.transport.token}`, 'X-Peerspan-Instance': active.transport.instance_id, 'Content-Type': 'application/json' },
      body: JSON.stringify(body) }), timeout]);
    if (!await messageCurrent($, active, attempt) || !guard() || response.status !== 200 || !response.ok) throw new Error('Unavailable scoped message');
    return JSON.parse(response.text);
  } finally { deadline?.cancel(); }
}
async function inspectMessageAuthorization($, active, attempt, guard = () => true) {
  try { return await runtimeInspect($, active); }
  catch {
    if (runtime === active && active.messages === attempt && guard()) {
      stopRuntime('Adapter: authorization unavailable. Reopen the project review to reconnect.');
      $.ui.invalidate('ui.render');
    }
    throw new Error('Unavailable message authorization');
  }
}
async function enableMessages($, active, epoch) {
  if (runtime !== active || epoch !== generation || active.phase !== 'connected' ||
      ['starting', 'waiting', 'ready'].includes(active.messages?.state)) return;
  const attempt = { state: 'starting' };
  active.messages = attempt;
  active.messageCounts ??= { submitted: new Set(), seen: new Set(), replied: new Set() };
  active.messageClaims ??= new Set();
  $.ui.invalidate('ui.render');
  try {
    if (!await inspectMessageAuthorization($, active, attempt) || !await messageCurrent($, active, attempt)) return;
    for (const spec of messageTools) {
      if (!registeredMessageTools.has(spec.name)) {
        await $.tool.register(spec);
        if (!await messageCurrent($, active, attempt)) return;
        registeredMessageTools.add(spec.name);
      }
    }
    const now = await $.clock.now();
    if (!await messageCurrent($, active, attempt)) return;
    attempt.nonce = Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, '0')).join('');
    attempt.until = now + 60_000;
    attempt.state = 'waiting';
    attempt.deadline = $.clock.after(60_000, () => {
      if (active.messages === attempt && attempt.state !== 'ready') messageFailure($, active, attempt, 'expired');
    });
    $.ui.invalidate('ui.render');
    void submitMessageHello($, active, attempt);
  } catch { messageFailure($, active, attempt); }
}
async function submitMessageHello($, active, attempt) {
  try {
    if (!await messageCurrent($, active, attempt)) return;
    const result = await $.prompt.submit({ text: messageHello(attempt.nonce) });
    if (active.messages === attempt && attempt.state !== 'ready' && result?.drop) messageFailure($, active, attempt);
  } catch { if (attempt.state !== 'ready') messageFailure($, active, attempt); }
}
const modelOrigin = (event, next) => event.agentId === undefined && next.origin.plugin === 'engine' && next.origin.tier === 'core';
async function readyMessages($, event, next) {
  const active = runtime, attempt = active?.messages;
  if (!active || !attempt || !modelOrigin(event, next) || attempt.readyBusy) return { deny: 'No current message delivery check.' };
  attempt.readyBusy = true;
  let checking = false;
  try {
    const args = argumentsOf(event, 'nonce');
    if (typeof args.nonce !== 'string' || !/^[0-9a-f]{32}$/.test(args.nonce) || args.nonce !== attempt.nonce ||
        !await messageCurrent($, active, attempt)) return { deny: 'No current message delivery check.' };
    if (attempt.state === 'ready') {
      if (!await inspectMessageAuthorization($, active, attempt) || !await messageCurrent($, active, attempt, true)) throw new Error('Changed message context');
      return { result: { ready: true } };
    }
    if (attempt.state !== 'waiting') return { deny: 'No current message delivery check.' };
    checking = true;
    const value = parseConnection(await messageRequest($, active, attempt, 'ready', { nonce: args.nonce }), active.flow);
    const now = await $.clock.now();
    if (!await messageCurrent($, active, attempt) || value.state !== 'ready' || value.channel !== 'verified' ||
        Date.parse(value.lease_expires_at) <= now || Date.parse(value.lease_expires_at) > Date.parse(active.flow.review.credential_expires_at)) throw new Error('Unavailable message readiness');
    attempt.deadline?.cancel();
    attempt.state = 'ready';
    $.ui.invalidate('ui.render');
    void pollMessages($, active, attempt);
    return { result: { ready: true } };
  } catch {
    if (checking) messageFailure($, active, attempt);
    return { deny: 'Message delivery check unavailable. Retry incoming messages in Peerspan.' };
  } finally { attempt.readyBusy = false; }
}
async function pollMessages($, active, attempt) {
  if (attempt.pollBusy || runtime !== active || active.messages !== attempt) return;
  attempt.pollBusy = true;
  try {
    if (!await messageCurrent($, active, attempt, true)) return;
    const raw = await messageRequest($, active, attempt, 'next', {});
    const now = await $.clock.now();
    if (!await messageCurrent($, active, attempt, true)) return;
    const value = parseHandoff(raw, active, now);
    if (value !== null) {
      if (active.messageClaims.has(value.delivery.id)) throw new Error('Duplicate message handoff');
      active.messageClaims.add(value.delivery.id);
      let deadline;
      let accepted;
      try {
        const timeout = new Promise((_, reject) => {
          deadline = $.clock.after(5000, () => reject(new Error('Unknown prompt outcome')));
        });
        accepted = await Promise.race([$.prompt.submit({ text: messagePrompt(value) }), timeout]);
      } finally { deadline?.cancel(); }
      if (!await messageCurrent($, active, attempt, true)) return;
      if (accepted?.drop || typeof accepted?.text !== 'string') throw new Error('Unavailable message submission');
      const forwarded = parseDelivery(await messageRequest($, active, attempt, 'forwarded', {}, value.delivery.id), active);
      if (forwarded.id !== value.delivery.id || forwarded.request_id !== value.delivery.request_id ||
          forwarded.sender_host_id !== value.delivery.sender_host_id || !['forwarded', 'replied'].includes(forwarded.state)) throw new Error('Unavailable forwarded receipt');
      if (!await messageCurrent($, active, attempt, true)) return;
      active.messageCounts.submitted.add(value.delivery.id);
      $.ui.invalidate('ui.render');
    }
    if (await messageCurrent($, active, attempt, true)) attempt.poll = $.clock.after(1000, () => pollMessages($, active, attempt));
  } catch { messageFailure($, active, attempt); }
  finally { attempt.pollBusy = false; }
}
async function messageWrite($, event, next, operation) {
  const active = runtime, attempt = active?.messages;
  if (!active || !attempt || !modelOrigin(event, next) || attempt.state !== 'ready' || attempt.writeBusy) return { deny: 'No available native message connection.' };
  attempt.writeBusy = true;
  try {
    const args = argumentsOf(event, operation === 'reply' ? 'delivery_id content' : 'delivery_id');
    if (!typedId(args.delivery_id, 'delivery') || (operation === 'reply' && !messageContent(args.content)) ||
        !await messageCurrent($, active, attempt, true)) return { deny: 'Invalid or unavailable message operation.' };
    const value = await messageRequest($, active, attempt, operation,
      operation === 'reply' ? { content: args.content } : { ids: [args.delivery_id] }, args.delivery_id);
    const result = operation === 'reply' ? parseReply(value, active, args.delivery_id, args.content) : parseSeen(value, args.delivery_id);
    if (!await messageCurrent($, active, attempt, true)) throw new Error('Changed message context');
    active.messageCounts.seen.add(args.delivery_id);
    if (operation === 'reply') active.messageCounts.replied.add(args.delivery_id);
    $.ui.invalidate('ui.render');
    return { result };
  } catch { return { deny: 'Message operation unavailable or outcome unknown. No automatic retry was made.' }; }
  finally { attempt.writeBusy = false; }
}
function stopTasks(active, state = 'stopped') {
  if (!active?.tasks) return;
  active.tasks.poll?.cancel();
  active.tasks.state = state;
}
function taskSummary(active) {
  const c = active.taskCounts;
  return `\nIncoming tasks: ${active.tasks?.state ?? 'not enabled'}\nTasks submitted: ${c?.submitted.size ?? 0}\nTasks observed: ${c?.observed.size ?? 0}\nTask changes confirmed: ${c?.changes.size ?? 0}\nCancellations submitted: ${c?.cancellations.size ?? 0}`;
}
const taskGuard = (active, attempt) => runtime === active && active.tasks === attempt &&
  ['starting', 'enabled'].includes(attempt.state) && active.messages === attempt.ready && attempt.ready.state === 'ready';
async function taskCurrent($, active, attempt) {
  if (!taskGuard(active, attempt)) return false;
  return await messageCurrent($, active, attempt.ready, true) && taskGuard(active, attempt);
}
async function enableTasks($, active, ready, epoch) {
  if (runtime !== active || epoch !== generation || active.phase !== 'connected' || active.messages !== ready || ready?.state !== 'ready' ||
      ['starting', 'enabled'].includes(active.tasks?.state)) return;
  const attempt = { state: 'starting', ready };
  active.tasks = attempt;
  active.taskCounts ??= { submitted: new Set(), observed: new Set(), changes: new Set(), cancellations: new Set() };
  active.taskClaims ??= new Set();
  active.cancelClaims ??= new Set();
  $.ui.invalidate('ui.render');
  try {
    if (!await taskCurrent($, active, attempt) || !await inspectMessageAuthorization($, active, attempt.ready, () => taskGuard(active, attempt)) ||
        !await taskCurrent($, active, attempt)) return;
    const registry = registeredTaskTools;
    for (const spec of taskTools) {
      let registration = registry.get(spec.name);
      if (!registration) {
        registration = $.tool.register(spec);
        registry.set(spec.name, registration);
      }
      try { await registration; }
      catch (error) {
        if (registry.get(spec.name) === registration) registry.delete(spec.name);
        throw error;
      }
      if (!await taskCurrent($, active, attempt)) return;
    }
    if (!await taskCurrent($, active, attempt)) return;
    attempt.state = 'enabled';
    $.ui.invalidate('ui.render');
    void pollTasks($, active, attempt);
  } catch { taskFailure($, active, attempt); }
}
function taskFailure($, active, attempt) {
  if (!taskGuard(active, attempt)) return;
  stopTasks(active, 'blocked');
  $.ui.invalidate('ui.render');
}
async function taskRequest($, active, attempt, operation, body, id) {
  if (attempt.state !== 'enabled' || !await taskCurrent($, active, attempt)) throw new Error('Unavailable native task context');
  return messageRequest($, active, attempt.ready, operation, body, id, () => taskGuard(active, attempt) && attempt.state === 'enabled');
}
async function submitTask($, active, attempt, text) {
  if (!await taskCurrent($, active, attempt)) return false;
  let deadline;
  try {
    const timeout = new Promise((_, reject) => {
      deadline = $.clock.after(5000, () => reject(new Error('Unknown task submission outcome')));
    });
    const accepted = await Promise.race([$.prompt.submit({ text }), timeout]);
    if (!await taskCurrent($, active, attempt)) return false;
    if (accepted?.drop || typeof accepted?.text !== 'string') throw new Error('Unavailable task submission');
    return true;
  } finally { deadline?.cancel(); }
}
async function pollTasks($, active, attempt) {
  if (attempt.busy || !taskGuard(active, attempt) || attempt.state !== 'enabled') return;
  attempt.busy = true;
  try {
    const cancel = parseCancellation(await taskRequest($, active, attempt, 'task_cancel_next', {}), active);
    if (!await taskCurrent($, active, attempt)) return;
    if (cancel !== null) {
      if (active.cancelClaims.has(cancel.delivery.id)) throw new Error('Duplicate cancellation handoff');
      active.cancelClaims.add(cancel.delivery.id);
      if (!await submitTask($, active, attempt, cancelPrompt(cancel))) return;
      active.taskCounts.cancellations.add(cancel.delivery.id);
      $.ui.invalidate('ui.render');
    }
    const raw = await taskRequest($, active, attempt, 'task_next', {});
    const now = await $.clock.now();
    if (!await taskCurrent($, active, attempt)) return;
    const task = parseTask(raw, active, now);
    if (task !== null) {
      if (active.taskClaims.has(task.delivery.id)) throw new Error('Duplicate task handoff');
      active.taskClaims.add(task.delivery.id);
      if (!await submitTask($, active, attempt, taskPrompt(task))) return;
      active.taskCounts.submitted.add(task.delivery.id);
      $.ui.invalidate('ui.render');
    }
    if (await taskCurrent($, active, attempt)) attempt.poll = $.clock.after(1000, () => pollTasks($, active, attempt));
  } catch { taskFailure($, active, attempt); }
  finally { attempt.busy = false; }
}
async function taskWrite($, event, next, operation) {
  const active = runtime, attempt = active?.tasks;
  if (!active || !attempt || !modelOrigin(event, next) || attempt.state !== 'enabled' || attempt.writeBusy || !taskGuard(active, attempt)) {
    return { deny: 'No available native task connection.' };
  }
  attempt.writeBusy = true;
  try {
    const { id, body } = taskArguments(event, operation, argumentsOf);
    const value = await taskRequest($, active, attempt, `task_${operation}`, body, id);
    const result = taskResult(value, active, id, operation, body);
    if (!await taskCurrent($, active, attempt)) throw new Error('Changed task context');
    const key = `${value.sender_host_id}/${id}`;
    active.taskCounts.observed.add(key);
    active.taskCounts.changes.add(`${key}/${value.last_event}`);
    $.ui.invalidate('ui.render');
    return { result };
  } catch { return { deny: 'Task operation unavailable or outcome unknown. No automatic retry was made.' }; }
  finally { attempt.writeBusy = false; }
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
function clearJoining() {
  joiningExpiry?.cancel();
  joiningExpiry = null;
  joining = { stage: 'inactive', busy: false };
}
function joinStart($, previous, epoch, extra = {}) {
  if (joining !== previous || previous.busy || epoch !== generation || project.stage !== 'attached' || project.busy) return null;
  joiningExpiry?.cancel();
  joiningExpiry = null;
  joining = { ...previous, code: '', busy: true, expiryAuthority: null, progress: null, progressError: false,
    owner: null, ownerError: null, ownerExpired: false, ownerOperation: false,
    ownerCanSign: false, ownerSignExpired: false, originalSignature: false,
    parent: project.flow, context: project.context, host: hostId, ...extra };
  $.ui.invalidate('ui.render');
  return joining;
}
async function joinCurrent($, running, epoch) {
  if (joining !== running || epoch !== generation || project.stage !== 'attached' ||
      project.flow.flow_id !== running.parent.flow_id || project.flow.review_id !== running.parent.review_id ||
      !same(project.flow.review, running.parent.review)) return false;
  const current = await projectContext($), surfaces = await $.session.surfaces();
  if (joining !== running || epoch !== generation) return false;
  if (!same(current, running.context) || current.native_session_id !== session || running.host !== hostId || !surfaces.includes('terminal')) {
    if (runtime) stopRuntime('Adapter: stopped after project, conversation or surface change.');
    clearProject();
    $.ui.invalidate('ui.render');
    return false;
  }
  return true;
}
async function joinHost($, running, epoch) {
  if (!await joinCurrent($, running, epoch)) return false;
  const result = await $.process.run([options.executable, ...(options.state ? ['--state', options.state] : []), 'onboarding'], { timeoutMs: 5000 });
  if (!await joinCurrent($, running, epoch)) return false;
  if (result.exitCode !== 0) throw new Error('Unavailable joining host');
  observation(result.stdout);
  if (JSON.parse(result.stdout).host_id !== running.host) throw new Error('Changed joining host');
  return true;
}
async function joinParent($, running, epoch) {
  if (!await joinCurrent($, running, epoch)) return false;
  const raw = await projectRun($, ['inspect', running.parent.flow_id]);
  if (!await joinCurrent($, running, epoch)) return false;
  const parent = parseProjectFlow(JSON.parse(raw), running.context, running.host);
  if (parent.state !== 'attached' || parent.flow_id !== running.parent.flow_id || parent.review_id !== running.parent.review_id ||
      !same(parent.review, running.parent.review)) throw new Error('Changed joining project');
  return joinHost($, running, epoch);
}
async function joinRun($, command, payload) {
  const result = await $.process.run([options.executable, ...(options.state ? ['--state', options.state] : []),
    'onboarding', 'join', ...command], { timeoutMs: ['identities', 'create-identity'].includes(command[0]) ? 15000 : 5000,
    ...(payload ? { stdin: JSON.stringify(payload) } : {}) });
  if (result.exitCode !== 0) throw new Error('Unavailable join flow');
  return result.stdout;
}
async function joinIdentities($, running, epoch) {
  const raw = await joinRun($, ['identities', '--stdin'], { context: adapterContext(running.parent) });
  if (!await joinCurrent($, running, epoch)) return null;
  return parseJoinIdentities(raw, running.parent, running.host);
}
function joinFailure($, running, epoch, uncertain = false) {
  if (joining !== running || epoch !== generation) return;
  joiningExpiry?.cancel();
  joiningExpiry = null;
  joining = { ...running, stage: 'unavailable', code: '', secret: null, preview: null, busy: false,
    message: uncertain ? 'Join outcome unavailable. Reopen joining to inspect the recorded result; no automatic retry.'
      : 'Joining unavailable. Reopen to inspect the host before another private attempt.' };
  $.ui.invalidate('ui.render');
}
async function joinView($, running, epoch, flow, extra = {}) {
  if (!await joinCurrent($, running, epoch)) return;
  const now = await $.clock.now();
  if (!await joinCurrent($, running, epoch)) return;
  joiningExpiry?.cancel();
  joiningExpiry = null;
  let stage = flow ? flow.state : extra.stage ?? 'draft';
  const deadline = flow?.state === 'review' ? flow.review.expires_at : ['choose', 'create_review'].includes(stage) ? extra.preview.review.invitation.expires_at : null;
  if (deadline && Date.parse(deadline) <= now) stage = 'expired';
  if (flow?.state === 'review' && Date.parse(deadline) - now > 900000) throw new Error('Changed join deadline');
  const ownerDeadline = flow?.state === 'requested' && extra.owner?.owner?.state === 'review' ? extra.owner.owner.review.expires_at : null;
  const ownerExpired = ownerDeadline !== null && Date.parse(ownerDeadline) <= now;
  if (ownerDeadline && Date.parse(ownerDeadline) - now > 900000) throw new Error('Changed owner deadline');
  const signingDeadline = flow?.state === 'requested' && extra.owner?.owner?.state === 'approved' &&
    extra.owner.request.owner_offer_id === '-' && !extra.originalSignature ? ownerSignatureDeadline(extra.owner) : null;
  const ownerSignExpired = signingDeadline !== null &&
    Math.max(now, Date.parse(extra.owner.observed_at)) >= signingDeadline;
  const ownerCanSign = !extra.originalSignature && signable(extra.owner, now);
  const secret = ['choose', 'create_review', 'review'].includes(stage) ? extra.secret ?? null : null;
  const expiryAuthority = {};
  joining = { ...running, ...extra, flow, stage, secret, code: '', busy: false, message: null, expiryAuthority,
    ownerExpired, ownerCanSign, ownerSignExpired };
  const activeDeadline = deadline && stage !== 'expired' ? deadline : ownerDeadline && !ownerExpired ? ownerDeadline
    : signingDeadline && !ownerSignExpired ? signingDeadline : null;
  if (activeDeadline) {
    joiningExpiry = $.clock.after(Date.parse(activeDeadline) - now, () => {
      if (joining.expiryAuthority === expiryAuthority && epoch === generation) {
        joining = ownerDeadline || signingDeadline
          ? { ...joining, ownerExpired: !!ownerDeadline, ownerCanSign: false, ownerSignExpired: !!signingDeadline, busy: false }
          : { ...joining, stage: 'expired', secret: null, code: '', preview: null, busy: false };
        $.ui.invalidate('ui.render');
      }
    });
  }
  $.ui.invalidate('ui.render');
}
async function openJoining($, previous, epoch) {
  const running = joinStart($, previous, epoch);
  if (!running) return;
  clearInvitation(); clearRecipient();
  try {
    if (!await joinParent($, running, epoch)) return;
    const raw = await joinRun($, ['lookup', '--stdin'], { context: adapterContext(running.parent) });
    if (!await joinCurrent($, running, epoch)) return;
    const value = await parseJoinLookup(raw, running.parent, running.host);
    if (!await joinCurrent($, running, epoch)) return;
    await joinView($, running, epoch, value.flow, { preview: null, selected: null, identities: [], replace: null, saved: null });
  } catch { joinFailure($, running, epoch); }
}
function joinDraft($, previous, epoch, value) {
  if (joining !== previous || previous.busy || epoch !== generation ||
      !(previous.stage === 'draft' || previous.stage === 'review' && !previous.secret)) return;
  joining = { ...previous, code: typeof value === 'string' && bytes(value) <= 32768 ? value : '' };
  $.ui.invalidate('ui.render');
}
async function joiningChoices($, previous, epoch) {
  if (previous.stage !== 'draft') return;
  const code = previous.code;
  const running = joinStart($, previous, epoch);
  if (!running) return;
  try {
    if (!validInvitationCode(code)) throw new Error('Invalid private joining invitation');
    if (!await joinParent($, running, epoch)) return;
    const raw = await invitationRun($, ['preview', '--stdin'], { context: adapterContext(running.parent), invitation: code });
    if (!await joinCurrent($, running, epoch)) return;
    const preview = await parseRecipientPreview(raw, running.parent, running.host);
    if (!await joinCurrent($, running, epoch)) return;
    const now = await $.clock.now();
    if (!await joinCurrent($, running, epoch)) return;
    if (Date.parse(preview.review.invitation.expires_at) <= now || Date.parse(preview.review.invitation.issued_at) > now + 30000) throw new Error('Expired joining invitation');
    const identities = await joinIdentities($, running, epoch);
    if (identities === null) return;
    await joinView($, running, epoch, null, { stage: 'choose', preview, identities, page: 0, selected: null, secret: code, saved: null });
  } catch { joinFailure($, running, epoch); }
}
async function chooseJoinIdentity($, previous, epoch, selected) {
  if (previous.stage !== 'choose' || !previous.identities.includes(selected) || !previous.secret ||
      previous.preview.review.invitation.expected_person_public_key !== '-' &&
      previous.preview.review.invitation.expected_person_public_key !== selected.public_key) return;
  const running = joinStart($, previous, epoch);
  if (!running) return;
  try {
    if (!await joinParent($, running, epoch)) return;
    const identities = await joinIdentities($, running, epoch);
    if (identities === null) return;
    if (!identities.some(i => same(i, selected))) throw new Error('Changed local original identity');
    if (!await joinHost($, running, epoch)) return;
    const raw = await joinRun($, ['prepare', '--stdin'], { context: adapterContext(running.parent), invitation: previous.secret,
      person_public_key: selected.public_key, ...(previous.replace ? { replace_flow_id: previous.replace } : {}) });
    if (!await joinCurrent($, running, epoch)) return;
    const flow = await parseJoinFlow(raw, running.parent, running.host);
    if (!await joinCurrent($, running, epoch)) return;
    if (flow.state !== 'review' || flow.review.person_public_key !== selected.public_key ||
        flow.review.invitation_review_id !== previous.preview.review_id || !same(flow.review.invitation, previous.preview.review) ||
        flow.flow_id === previous.replace) throw new Error('Changed join proposal');
    await joinView($, running, epoch, flow, { selected, identities, preview: previous.preview, secret: previous.secret });
  } catch { joinFailure($, running, epoch); }
}
function canCreateIdentity(previous) {
  return previous.stage === 'choose' && previous.identities.length === 0 && previous.secret &&
    previous.preview.review.invitation.expected_person_public_key === '-';
}
async function reviewIdentityCreation($, previous, epoch) {
  if (!canCreateIdentity(previous)) return;
  const running = joinStart($, previous, epoch);
  if (!running) return;
  try {
    if (!await joinParent($, running, epoch)) return;
    await joinView($, running, epoch, null, { stage: 'create_review', preview: previous.preview, secret: previous.secret });
  } catch { joinFailure($, running, epoch); }
}
async function createJoinIdentity($, previous, epoch) {
  if (previous.stage !== 'create_review' || !previous.secret || previous.identities.length !== 0 ||
      previous.preview.review.invitation.expected_person_public_key !== '-') return;
  const running = joinStart($, previous, epoch);
  if (!running) return;
  let sent = false;
  try {
    if (!await joinParent($, running, epoch)) return;
    const before = await joinIdentities($, running, epoch);
    if (before === null) return;
    if (before.length) throw new Error('Local identity now exists');
    if (!await joinHost($, running, epoch)) return;
    const now = await $.clock.now();
    if (!await joinCurrent($, running, epoch)) return;
    if (Date.parse(previous.preview.review.invitation.expires_at) <= now ||
        Date.parse(previous.preview.review.invitation.issued_at) > now + 30000) throw new Error('Expired identity creation review');
    sent = true;
    const raw = await joinRun($, ['create-identity', '--stdin'], {
      context: adapterContext(running.parent), decision: 'create_new_identity' });
    if (!await joinCurrent($, running, epoch)) return;
    const saved = parseCreatedIdentity(raw, running.parent, running.host);
    const identities = await joinIdentities($, running, epoch);
    if (identities === null) return;
    if (!identities.some(i => i.public_key === saved.public_key && i.sources.includes('generated'))) throw new Error('Saved identity unavailable');
    await joinView($, running, epoch, null, { stage: 'choose', preview: previous.preview, secret: previous.secret,
      identities, page: 0, selected: null, saved: saved.public_key });
  } catch {
    const current = joining === running && epoch === generation;
    joinFailure($, running, epoch);
    if (sent && current) {
      joining = { ...joining, message: 'Identity creation outcome unavailable. A new original may have been saved. Reopen joining and inspect local identities before another attempt; no automatic retry.' };
      $.ui.invalidate('ui.render');
    }
  }
}
async function recoverJoinCode($, previous, epoch) {
  if (previous.stage !== 'review' || previous.secret) return;
  const code = previous.code, captured = previous.flow;
  const running = joinStart($, previous, epoch);
  if (!running) return;
  try {
    if (!validInvitationCode(code)) throw new Error('Invalid private joining invitation');
    if (!await joinParent($, running, epoch)) return;
    const raw = await joinRun($, ['prepare', '--stdin'], { context: adapterContext(running.parent), invitation: code,
      person_public_key: captured.review.person_public_key });
    if (!await joinCurrent($, running, epoch)) return;
    const flow = await parseJoinFlow(raw, running.parent, running.host);
    if (!await joinCurrent($, running, epoch)) return;
    if (!same(flow, captured) || flow.state !== 'review') throw new Error('Changed retained join review');
    const identities = await joinIdentities($, running, epoch);
    if (identities === null) return;
    const selected = identities.find(i => i.public_key === captured.review.person_public_key);
    if (!selected) throw new Error('Selected local original identity unavailable');
    await joinView($, running, epoch, flow, { selected, identities, secret: code });
  } catch { joinFailure($, running, epoch); }
}
async function decideJoining($, previous, epoch, decision) {
  if (previous.stage !== 'review' || decision === 'approve' && (!previous.secret || !previous.selected)) return;
  const captured = previous.flow;
  const running = joinStart($, previous, epoch);
  if (!running) return;
  let sent = false;
  try {
    if (!await joinParent($, running, epoch)) return;
    const raw = await joinRun($, ['inspect', captured.flow_id]);
    if (!await joinCurrent($, running, epoch)) return;
    const flow = await parseJoinFlow(raw, running.parent, running.host);
    if (!await joinCurrent($, running, epoch)) return;
    if (!same(flow, captured) || flow.state !== 'review') throw new Error('Changed join review');
    if (decision === 'approve') {
      const identities = await joinIdentities($, running, epoch);
      if (identities === null) return;
      if (!identities.some(i => same(i, previous.selected))) throw new Error('Changed local original identity');
    }
    if (!await joinHost($, running, epoch)) return;
    const now = await $.clock.now();
    if (!await joinCurrent($, running, epoch)) return;
    if (Date.parse(captured.review.expires_at) <= now) throw new Error('Expired join review');
    sent = true;
    const result = await joinRun($, ['decide', '--stdin'], { context: adapterContext(running.parent), flow_id: captured.flow_id,
      review_id: captured.review_id, decision, ...(decision === 'approve' ? { invitation: previous.secret } : {}) });
    if (!await joinCurrent($, running, epoch)) return;
    const outcome = await parseJoinFlow(result, running.parent, running.host);
    if (!await joinCurrent($, running, epoch)) return;
    if (outcome.flow_id !== captured.flow_id || outcome.review_id !== captured.review_id || !same(outcome.review, captured.review) ||
        outcome.state !== (decision === 'approve' ? 'requested' : 'declined')) throw new Error('Unknown join outcome');
    await joinView($, running, epoch, outcome, { preview: null, selected: null, identities: [] });
  } catch { joinFailure($, running, epoch, sent); }
}
async function anotherJoining($, previous, epoch) {
  if (!previous.flow || previous.stage === 'review') return;
  const running = joinStart($, previous, epoch);
  if (!running) return;
  try {
    if (!await joinParent($, running, epoch)) return;
    await joinView($, running, epoch, null, { stage: 'draft', replace: previous.flow.flow_id, preview: null,
      selected: null, identities: [], secret: null });
  } catch { joinFailure($, running, epoch); }
}
async function checkJoinProgress($, previous, epoch) {
  if (previous.stage !== 'requested' || previous.flow?.state !== 'requested') return;
  const captured = previous.flow, running = joinStart($, previous, epoch);
  if (!running) return;
  try {
    if (!await joinParent($, running, epoch)) return;
    const raw = await joinRun($, ['inspect', captured.flow_id]);
    if (!await joinCurrent($, running, epoch)) return;
    const flow = await parseJoinFlow(raw, running.parent, running.host);
    if (!await joinCurrent($, running, epoch)) return;
    if (!same(flow, captured) || flow.state !== 'requested') throw new Error('Changed published join flow');
    if (!await joinHost($, running, epoch)) return;
    const result = await joinRun($, ['progress', '--stdin'], { flow_id: captured.flow_id,
      context: adapterContext(running.parent), review_id: captured.review_id });
    if (!await joinCurrent($, running, epoch)) return;
    const value = await parseJoinProgress(result, captured, running.parent, running.host);
    if (!await joinCurrent($, running, epoch)) return;
    await joinView($, running, epoch, captured, { progress: value, progressError: false, secret: null });
  } catch {
    if (joining === running && epoch === generation) {
      joining = { ...running, busy: false, code: '', secret: null, progress: null, progressError: true };
      $.ui.invalidate('ui.render');
    }
  }
}
function ownerPayload(running, flow, captured = null) {
  return { flow_id: flow.flow_id, context: adapterContext(running.parent), join_review_id: flow.review_id,
    ...(captured ? { owner_review_id: captured.owner.review_id } : {}) };
}
async function inspectOwnerJoin($, running, epoch, captured) {
  if (!await joinParent($, running, epoch)) return false;
  const raw = await joinRun($, ['inspect', captured.flow_id]);
  if (!await joinCurrent($, running, epoch)) return false;
  const flow = await parseJoinFlow(raw, running.parent, running.host);
  if (!await joinCurrent($, running, epoch)) return false;
  if (flow.state !== 'requested' || !same(flow, captured)) throw new Error('Changed owner join flow');
  return joinHost($, running, epoch);
}
function ownerFailure($, running, epoch, uncertain = false, signing = false) {
  if (joining !== running || epoch !== generation) return;
  joiningExpiry?.cancel(); joiningExpiry = null;
  joining = { ...running, busy: false, code: '', secret: null, owner: null, ownerExpired: false,
    ownerOperation: false, ownerCanSign: false, ownerSignExpired: false, originalSignature: false,
    ownerError: signing
      ? uncertain ? 'Original signature outcome unknown. Check owner consent to read public evidence; no automatic retry. Leaving cannot retract a dispatched signature.'
        : 'Original signing unavailable. Check owner consent to inspect public evidence; no automatic retry.'
      : uncertain ? 'Owner consent outcome unknown. Check owner consent to read the recorded result; no automatic retry.'
        : 'Owner review unavailable. Check owner consent to inspect the host; no automatic retry.' };
  $.ui.invalidate('ui.render');
}
async function readOwner($, previous, epoch, prepare) {
  if (previous.stage !== 'requested' || previous.flow?.state !== 'requested') return;
  const captured = previous.flow, running = joinStart($, previous, epoch, { ownerOperation: true });
  if (!running) return;
  try {
    if (!await inspectOwnerJoin($, running, epoch, captured)) return;
    let raw = await joinRun($, ['owner', 'lookup', '--stdin'], ownerPayload(running, captured));
    if (!await joinCurrent($, running, epoch)) return;
    let value = await parseOwner(raw, captured, running.parent, running.host);
    if (!await joinCurrent($, running, epoch)) return;
    if (prepare && value.owner === null) {
      if (!await joinHost($, running, epoch)) return;
      raw = await joinRun($, ['owner', 'prepare', '--stdin'], ownerPayload(running, captured));
      if (!await joinCurrent($, running, epoch)) return;
      value = await parseOwner(raw, captured, running.parent, running.host);
      if (!await joinCurrent($, running, epoch)) return;
      if (value.owner === null) throw new Error('Missing prepared owner review');
    }
    await joinView($, running, epoch, captured, { owner: value, ownerError: null, ownerOperation: false, secret: null });
  } catch { ownerFailure($, running, epoch); }
}
async function approveOwner($, previous, epoch) {
  if (previous.stage !== 'requested' || previous.owner?.owner?.state !== 'review' || previous.ownerExpired) return;
  const captured = previous.owner, flow = previous.flow;
  const running = joinStart($, previous, epoch, { ownerOperation: true });
  if (!running) return;
  let sent = false;
  try {
    if (!await inspectOwnerJoin($, running, epoch, flow)) return;
    const raw = await joinRun($, ['owner', 'lookup', '--stdin'], ownerPayload(running, flow));
    if (!await joinCurrent($, running, epoch)) return;
    const current = await parseOwner(raw, flow, running.parent, running.host);
    if (!await joinCurrent($, running, epoch)) return;
    if (current.owner?.state !== 'review' || current.owner.review_id !== captured.owner.review_id ||
        !same(current.owner.review, captured.owner.review)) throw new Error('Changed displayed owner review');
    if (!await joinHost($, running, epoch)) return;
    const now = await $.clock.now();
    if (!await joinCurrent($, running, epoch)) return;
    const remaining = Date.parse(captured.owner.review.expires_at) - now;
    if (remaining <= 0 || remaining > 900000 || Date.parse(current.observed_at) > now + 30000) throw new Error('Elapsed owner review');
    sent = true;
    const result = await joinRun($, ['owner', 'approve', '--stdin'], ownerPayload(running, flow, captured));
    if (!await joinCurrent($, running, epoch)) return;
    const approved = await parseOwner(result, flow, running.parent, running.host);
    if (!await joinCurrent($, running, epoch)) return;
    if (approved.owner?.state !== 'approved' || approved.owner.review_id !== captured.owner.review_id ||
        !same(approved.owner.review, captured.owner.review)) throw new Error('Unknown owner consent outcome');
    await joinView($, running, epoch, flow, { owner: approved, ownerError: null, ownerOperation: false, secret: null });
  } catch { ownerFailure($, running, epoch, sent); }
}
async function signOriginalOwner($, previous, epoch) {
  if (previous.stage !== 'requested' || !previous.ownerCanSign || previous.originalSignature) return;
  const captured = previous.owner, flow = previous.flow;
  const running = joinStart($, previous, epoch, { ownerOperation: true });
  if (!running) return;
  let sent = false;
  try {
    if (!await inspectOwnerJoin($, running, epoch, flow)) return;
    const raw = await joinRun($, ['owner', 'lookup', '--stdin'], ownerPayload(running, flow));
    if (!await joinCurrent($, running, epoch)) return;
    const current = await parseOwner(raw, flow, running.parent, running.host);
    if (!await joinCurrent($, running, epoch)) return;
    if (current.owner?.state !== 'approved' || !sameOriginal(captured, current)) throw new Error('Changed displayed original consent');
    if (!await inspectOwnerJoin($, running, epoch, flow)) return;
    if (current.request.owner_offer_id !== '-') {
      await joinView($, running, epoch, flow, { owner: current, ownerError: null, ownerOperation: false, secret: null });
      return;
    }
    const now = await $.clock.now();
    if (!await joinCurrent($, running, epoch)) return;
    if (!signable(current, now)) throw new Error('Original signing bounds changed');
    sent = true;
    const result = await $.process.run([options.executable, ...(options.state ? ['--state', options.state] : []),
      'onboarding', 'join', 'owner', 'sign', '--stdin'], { timeoutMs: 45000,
      stdin: JSON.stringify({ ...ownerPayload(running, flow, captured), decision: 'sign_original_owner_offer' }) });
    if (!await joinCurrent($, running, epoch)) return;
    if (result.exitCode !== 0) throw new Error('Original signature outcome unknown');
    const recorded = await parseOriginalSignature(result.stdout, flow, running.parent, running.host, captured);
    if (!await joinCurrent($, running, epoch)) return;
    if (!await inspectOwnerJoin($, running, epoch, flow)) return;
    await joinView($, running, epoch, flow, { owner: recorded, ownerError: null, ownerOperation: false,
      originalSignature: true, secret: null });
  } catch { ownerFailure($, running, epoch, sent, true); }
}
function leaveOwner($, previous, epoch) {
  if (joining !== previous || epoch !== generation) return;
  joiningExpiry?.cancel(); joiningExpiry = null;
  joining = { ...previous, owner: null, ownerError: null, ownerExpired: false, ownerOperation: false,
    ownerCanSign: false, ownerSignExpired: false, originalSignature: false, busy: false, expiryAuthority: null };
  $.ui.invalidate('ui.render');
}
function ownerControls($, { Text, Button }, previous, epoch) {
  const button = (key, label, onPress) => Button({ key, label, onPress });
  if (!previous.owner && !previous.ownerError) return [button('owner-review', 'Review owner powers', () => readOwner($, previous, epoch, true))];
  return [
    ...(previous.owner ? [Text({ children: [ownerReviewLines(previous.owner, previous.parent, previous.ownerExpired, previous.originalSignature)] })] : []),
    ...(previous.ownerError ? [Text({ children: [previous.ownerError] })] : []),
    ...(previous.owner?.owner?.state === 'review' && !previous.ownerExpired ? [
      button('owner-approve', 'Approve owner powers', () => approveOwner($, previous, epoch)),
    ] : []),
    ...(previous.ownerCanSign && !previous.originalSignature ? [
      button('owner-sign', 'Sign original owner offer', () => signOriginalOwner($, previous, epoch)),
    ] : []),
    ...(previous.ownerSignExpired ? [Text({ children: ['Original signing deadline elapsed. Check owner consent for public evidence; no automatic retry.'] })] : []),
    ...(previous.owner?.owner === null ? [button('owner-review', 'Review owner powers', () => readOwner($, previous, epoch, true))] : []),
    button('owner-check', 'Check owner consent', () => readOwner($, previous, epoch, false)),
    button('owner-leave', 'Leave owner review', () => leaveOwner($, previous, epoch)),
  ];
}
function joinPage($, previous, epoch, page) {
  if (joining !== previous || previous.busy || epoch !== generation || previous.stage !== 'choose' ||
      page < 0 || page * 10 >= previous.identities.length) return;
  joining = { ...previous, page };
  $.ui.invalidate('ui.render');
}
function joiningControls($, { Text, Button, Input }, epoch) {
  if (project.stage !== 'attached' || project.busy) return [];
  const previous = joining, button = (key, label, onPress) => Button({ key, label, onPress });
  if (previous.stage === 'inactive') return invitation.stage === 'inactive' && recipient.stage === 'inactive'
    ? [button('join-open', 'Join a network', () => openJoining($, previous, epoch))] : [];
  const back = button('join-back', 'Back from joining', () => {
    if (joining === previous && epoch === generation) { clearJoining(); $.ui.invalidate('ui.render'); }
  });
  const cancelCreation = button('join-create-cancel', 'Cancel identity creation', () => {
    if (joining === previous && epoch === generation) { clearJoining(); $.ui.invalidate('ui.render'); }
  });
  if (previous.busy) return [Text({ children: [previous.stage === 'requested'
    ? 'Join request: publication recorded\n' + joinReviewLines(previous.flow, null) + '\nJoining: working…' : 'Joining: working…'] }),
    ...(previous.ownerOperation ? [button('owner-leave', 'Leave owner review', () => leaveOwner($, previous, epoch))] : []),
    ...(previous.stage === 'create_review' ? [cancelCreation] : []), back];
  if (previous.stage === 'draft') return [
    Text({ children: ['Paste only in this private human pane, not in agent chat. The code is visible terminal text. Reviewing identities creates no key; creating a new original requires separate consent.',
      previous.replace ? '\nAnother publication does not cancel or revoke the earlier request.' : ''] }),
    Input({ key: 'join-code', label: 'Private invitation for joining', value: previous.code,
      onInput: v => joinDraft($, previous, epoch, v), onSubmit: v => joinDraft($, previous, epoch, v) }),
    button('join-identities', 'Review joining identities', () => joiningChoices($, previous, epoch)), back];
  if (previous.stage === 'choose') {
    const page = previous.page ?? 0, pin = previous.preview.review.invitation.expected_person_public_key;
    return [Text({ children: ['Joining: choose an original identity', '\n', recipientReviewLines(previous.preview),
      '\nChoosing a public key is not proof of ownership and does not publish a request.',
      previous.saved ? `\nNew original identity saved: ${quoted(previous.saved)}. Review its public key before publishing a join request.` : '',
      !previous.identities.length ? '\nNo local original identity is available. Creating a new person and linking your existing person are separate workflows.'
        : pin !== '-' && !previous.identities.some(i => i.public_key === pin) ? '\nNo local identity matches the invitation pin. Use the original identity on its existing machine; device linking is separate.' : ''] }),
      ...previous.identities.slice(page * 10, page * 10 + 10).flatMap(i => [Text({ children: [`Original public key: ${quoted(i.public_key)}\nIdentity source: ${joinProvenance(i)}`] }),
        ...(pin === '-' || pin === i.public_key ? [button(`join-identity-${i.public_key}`, `Review identity ${i.public_key}`,
          () => chooseJoinIdentity($, previous, epoch, i))] : [Text({ children: ['This identity does not match the invitation pin.'] })])]),
      ...(page > 0 ? [button('join-prev', 'Previous identities', () => joinPage($, previous, epoch, page - 1))] : []),
      ...(previous.identities.length > (page + 1) * 10 ? [button('join-next', 'More identities', () => joinPage($, previous, epoch, page + 1))] : []),
      ...(canCreateIdentity(previous) ? [button('join-create-review', 'Create a new original identity', () => reviewIdentityCreation($, previous, epoch))] : []), back];
  }
  if (previous.stage === 'create_review') return [Text({ children: ['New original identity: review creation\n', recipientReviewLines(previous.preview),
    '\nGenerate and save one new original person identity on this computer, in its normal original identity location.',
    '\nThis creates a new person. It does not copy, import or link your existing person from another computer.',
    '\nThe private key is saved locally and needs a private backup through ordinary host administration.',
    '\nThe saved original survives Back, Close, cancellation of a later request, or navigation after approval is dispatched.',
    '\nNo join request is prepared or published. No participant approval, membership, agent permission, files, conversation or capability access is granted.',
    '\nConnection readiness and model receipt: not verified. After saving, separately review the public key and approve any join request.'] }),
    button('join-create-save', 'Create and save identity', () => createJoinIdentity($, previous, epoch)),
    cancelCreation, back];
  if (previous.stage === 'unavailable') return [Text({ children: [previous.message] }), back];
  const flow = previous.flow;
  const status = previous.stage === 'requested' ? 'Join request: publication recorded'
    : previous.stage === 'review' ? 'Join request: review publication' : `Join request: ${previous.stage}`;
  return [Text({ children: [status, flow && ['review', 'requested', 'declined'].includes(previous.stage) ? '\n' + joinReviewLines(flow, previous.selected) : '',
      previous.stage === 'requested' ? '\nThis records publication only. Participant approvals and current link state, access, reachability and model receipt are not verified.' : ''] }),
    ...(previous.stage === 'requested' ? [
      ...(previous.progress ? [Text({ children: [joinProgressLines(previous.progress)] })] : []),
      ...(previous.progressError ? [Text({ children: ['Join progress unavailable. Publication remains recorded. Check again explicitly; no automatic retry.'] })] : []),
      button('join-progress', 'Check join progress', () => checkJoinProgress($, previous, epoch)),
      ...ownerControls($, { Text, Button }, previous, epoch),
    ] : []),
    ...(previous.stage === 'review' ? [
      ...(previous.secret && previous.selected ? [button('join-approve', 'Approve join request', () => decideJoining($, previous, epoch, 'approve'))] : [
        Input({ key: 'join-recover-code', label: 'Private invitation for joining', value: previous.code,
          onInput: v => joinDraft($, previous, epoch, v), onSubmit: v => joinDraft($, previous, epoch, v) }),
        button('join-recover', 'Check invitation for this review', () => recoverJoinCode($, previous, epoch)),
      ]),
      button('join-decline', 'Decline join request', () => decideJoining($, previous, epoch, 'decline')),
    ] : flow ? [button('join-another', 'Review another join request', () => anotherJoining($, previous, epoch))] : []), back];
}

function clearRecipient() {
  recipientExpiry?.cancel();
  recipientExpiry = null;
  recipient = { stage: 'inactive', busy: false };
}
function recipientStart($, previous, epoch) {
  if (recipient !== previous || previous.busy || epoch !== generation || project.stage !== 'attached' || project.busy) return null;
  recipientExpiry?.cancel();
  recipientExpiry = null;
  recipient = { ...previous, code: '', preview: null, busy: true, parent: project.flow, context: project.context, host: hostId };
  $.ui.invalidate('ui.render');
  return recipient;
}
async function recipientCurrent($, running, epoch) {
  if (recipient !== running || epoch !== generation || project.stage !== 'attached' ||
      project.flow.flow_id !== running.parent.flow_id || project.flow.review_id !== running.parent.review_id ||
      !same(project.flow.review, running.parent.review)) return false;
  const current = await projectContext($), surfaces = await $.session.surfaces();
  if (recipient !== running || epoch !== generation) return false;
  if (!same(current, running.context) || current.native_session_id !== session || running.host !== hostId || !surfaces.includes('terminal')) {
    if (runtime) stopRuntime('Adapter: stopped after project, conversation or surface change.');
    clearProject();
    $.ui.invalidate('ui.render');
    return false;
  }
  return true;
}
async function inspectRecipientParent($, running, epoch) {
  if (!await recipientCurrent($, running, epoch)) return false;
  const raw = await projectRun($, ['inspect', running.parent.flow_id]);
  if (!await recipientCurrent($, running, epoch)) return false;
  const parent = parseProjectFlow(JSON.parse(raw), running.context, running.host);
  if (parent.state !== 'attached' || parent.flow_id !== running.parent.flow_id || parent.review_id !== running.parent.review_id ||
      !same(parent.review, running.parent.review)) throw new Error('Changed recipient project');
  // Observe daemon identity after the parent read, before sending private input.
  const observed = await $.process.run([options.executable, ...(options.state ? ['--state', options.state] : []), 'onboarding'], { timeoutMs: 5000 });
  if (!await recipientCurrent($, running, epoch)) return false;
  if (observed.exitCode !== 0) throw new Error('Unavailable recipient host');
  observation(observed.stdout);
  if (JSON.parse(observed.stdout).host_id !== running.host) throw new Error('Changed recipient host');
  return true;
}

function recipientFailure($, running, epoch) {
  if (recipient !== running || epoch !== generation) return;
  recipientExpiry?.cancel();
  recipientExpiry = null;
  recipient = { ...running, stage: 'unavailable', code: '', preview: null, busy: false };
  $.ui.invalidate('ui.render');
}
async function openRecipient($, previous, epoch) {
  const running = recipientStart($, previous, epoch);
  if (!running) return;
  clearJoining();
  clearInvitation();
  try {
    if (!await inspectRecipientParent($, running, epoch)) return;
    recipientExpiry?.cancel();
    recipientExpiry = null;
    recipient = { ...running, stage: 'draft', code: '', preview: null, busy: false };
    $.ui.invalidate('ui.render');
  } catch { recipientFailure($, running, epoch); }
}
function recipientDraft($, previous, epoch, value) {
  if (recipient !== previous || previous.busy || previous.stage !== 'draft' || epoch !== generation) return;
  recipient = { ...previous, code: typeof value === 'string' && bytes(value) <= 32768 ? value : '', message: null };
  $.ui.invalidate('ui.render');
}
async function inspectRecipient($, previous, epoch) {
  if (previous.stage !== 'draft') return;
  const code = previous.code;
  // Drop raw input before any asynchronous context/host reads or process call.
  const running = recipientStart($, previous, epoch);
  if (!running) return;
  try {
    if (!validInvitationCode(code)) throw new Error('Invalid private invitation');
    if (!await inspectRecipientParent($, running, epoch)) return;
    const raw = await invitationRun($, ['preview', '--stdin'], { context: adapterContext(running.parent), invitation: code });
    if (!await recipientCurrent($, running, epoch)) return;
    const value = await parseRecipientPreview(raw, running.parent, running.host);
    if (!await recipientCurrent($, running, epoch)) return;
    const now = await $.clock.now();
    if (recipient !== running || epoch !== generation || Date.parse(value.review.invitation.expires_at) <= now ||
        Date.parse(value.review.invitation.issued_at) > now + 30_000) throw new Error('Expired invitation preview');
    recipient = { ...running, stage: 'verified', preview: value, code: '', busy: false };
    recipientExpiry = $.clock.after(Date.parse(value.review.invitation.expires_at) - now, () => {
      if (epoch === generation && recipient.preview === value) {
        recipient = { ...recipient, stage: 'expired', preview: null, code: '', busy: false };
        $.ui.invalidate('ui.render');
      }
    });
    $.ui.invalidate('ui.render');
  } catch { recipientFailure($, running, epoch); }
}
function recipientControls($, { Text, Button, Input }, epoch) {
  if (project.stage !== 'attached' || project.busy) return [];
  const previous = recipient;
  const button = (key, label, onPress) => Button({ key, label, onPress });
  if (previous.stage === 'inactive') return invitation.stage === 'inactive' && joining.stage === 'inactive'
    ? [button('recipient-open', 'Review an invitation', () => openRecipient($, previous, epoch))] : [];
  if (previous.busy) return [Text({ children: ['Invitation inspection: working…'] })];
  const back = button('recipient-back', 'Back from invitation review', () => {
    if (recipient === previous && epoch === generation) { clearRecipient(); $.ui.invalidate('ui.render'); }
  });
  if (previous.stage === 'draft') return [
    Text({ children: ['Paste only in this private human pane, not in agent chat. The code is visible terminal text. Inspection creates no identity or join request.'] }),
    Input({ key: 'recipient-code', label: 'Private invitation code', value: previous.code,
      onInput: v => recipientDraft($, previous, epoch, v), onSubmit: v => recipientDraft($, previous, epoch, v) }),
    button('recipient-inspect', 'Inspect invitation', () => inspectRecipient($, previous, epoch)), back];
  return [Text({ children: previous.stage === 'verified'
    ? ['Invitation: signature verified', '\n', recipientReviewLines(previous.preview)]
    : [previous.stage === 'expired' ? 'Invitation preview expired.' : 'Invitation preview unavailable. Re-enter privately to inspect again.'] }),
    button('recipient-another', 'Inspect another invitation', () => openRecipient($, previous, epoch)), back];
}

function clearInvitation() {
  invitationExpiry?.cancel();
  invitationExpiry = null;
  invitation = { stage: 'inactive', busy: false };
}
function invitationStart($, previous, epoch) {
  if (invitation !== previous || previous.busy || epoch !== generation || project.stage !== 'attached' || project.busy) return null;
  invitation = { ...previous, code: null, busy: true, parent: project.flow, context: project.context, host: hostId };
  $.ui.invalidate('ui.render');
  return invitation;
}
async function invitationCurrent($, running, epoch) {
  if (invitation !== running || epoch !== generation || project.stage !== 'attached' ||
      project.flow.flow_id !== running.parent.flow_id || project.flow.review_id !== running.parent.review_id ||
      !same(project.flow.review, running.parent.review)) return false;
  const current = await projectContext($);
  const surfaces = await $.session.surfaces();
  if (invitation !== running || epoch !== generation) return false;
  if (!same(current, running.context) || current.native_session_id !== session || running.host !== hostId || !surfaces.includes('terminal')) {
    if (runtime && (!same(current, running.context) || !surfaces.includes('terminal'))) stopRuntime('Adapter: stopped after project, conversation or surface change.');
    clearProject();
    $.ui.invalidate('ui.render');
    return false;
  }
  return true;
}
async function invitationRun($, command, payload) {
  if (typeof options.executable !== 'string' || !options.executable || typeof options.state !== 'string') throw new Error('Unavailable local host');
  const result = await $.process.run([options.executable, ...(options.state ? ['--state', options.state] : []),
    'onboarding', 'invitation', ...command], { timeoutMs: 5000, ...(payload ? { stdin: JSON.stringify(payload) } : {}) });
  if (result.exitCode !== 0) throw new Error('Unavailable invitation flow');
  return result.stdout;
}
async function inspectInvitationParent($, running, epoch) {
  if (!await invitationCurrent($, running, epoch)) return false;
  const raw = await projectRun($, ['inspect', running.parent.flow_id]);
  if (!await invitationCurrent($, running, epoch)) return false;
  const parent = parseProjectFlow(JSON.parse(raw), running.context, running.host);
  if (parent.state !== 'attached' || parent.flow_id !== running.parent.flow_id || parent.review_id !== running.parent.review_id ||
      !same(parent.review, running.parent.review)) throw new Error('Changed invitation project');
  return true;
}
function invitationFailure($, running, epoch, decision = false) {
  if (invitation !== running || epoch !== generation) return;
  invitationExpiry?.cancel();
  invitationExpiry = null;
  invitation = { ...running, code: null, stage: 'unavailable', busy: false,
    message: decision ? 'Invitation decision outcome unknown. Refresh to check the host.' : 'Invitation unavailable. Refresh to check the host.' };
  $.ui.invalidate('ui.render');
}
async function invitationView($, running, epoch, flow, extra = {}) {
  const now = await $.clock.now();
  if (!await invitationCurrent($, running, epoch)) return;
  invitationExpiry?.cancel();
  invitationExpiry = null;
  const deadline = flow?.state === 'review' ? flow.review.expires_at : flow?.state === 'issued' ? flow.review.invitation_expires_at : null;
  const stage = flow === null ? 'choose' : deadline && Date.parse(deadline) <= now ? 'expired' : flow.state;
  invitation = { ...running, ...extra, code: null, stage, flow, busy: false, message: null };
  if (deadline && stage !== 'expired') {
    invitationExpiry = $.clock.after(Math.max(0, Date.parse(deadline) - now), () => {
      if (epoch === generation && invitation.flow === flow && ['review', 'issued'].includes(invitation.stage)) {
        invitation = { ...invitation, stage: 'expired', busy: false, code: null };
        $.ui.invalidate('ui.render');
      }
    });
  }
  $.ui.invalidate('ui.render');
}
async function invitationChoices($, running, epoch, replace) {
  if (!await inspectInvitationParent($, running, epoch)) return;
  const result = await $.process.run([options.executable, ...(options.state ? ['--state', options.state] : []), 'onboarding'], { timeoutMs: 5000 });
  if (!await invitationCurrent($, running, epoch)) return;
  if (result.exitCode !== 0) throw new Error('Unavailable invitation networks');
  const networks = invitationNetworks(result.stdout, running.host);
  await invitationView($, running, epoch, null, { networks, page: 0, selected: null, member: '', pin: '-', replace });
}
async function openInvitation($, previous, epoch) {
  const running = invitationStart($, previous, epoch);
  if (!running) return;
  clearJoining();
  clearRecipient();
  try {
    if (!await inspectInvitationParent($, running, epoch)) return;
    const raw = await invitationRun($, ['lookup', '--stdin'], { context: adapterContext(running.parent) });
    if (!await invitationCurrent($, running, epoch)) return;
    const flow = (await parseInvitationLookup(raw, running.parent, running.host)).flow;
    if (flow === null) await invitationChoices($, running, epoch);
    else await invitationView($, running, epoch, flow);
  } catch { invitationFailure($, running, epoch); }
}
function invitationDraft($, previous, epoch, key, value) {
  if (invitation !== previous || previous.busy || epoch !== generation || !['choose', 'draft'].includes(previous.stage)) return;
  invitation = { ...previous, [key]: value, message: null };
  $.ui.invalidate('ui.render');
}
function selectInvitationNetwork($, previous, epoch, network) {
  if (invitation !== previous || previous.busy || epoch !== generation || previous.stage !== 'choose' || !previous.networks.includes(network)) return;
  invitation = { ...previous, stage: 'draft', selected: network, member: '', pin: '-', message: null };
  $.ui.invalidate('ui.render');
}
async function prepareInvitation($, previous, epoch) {
  if (previous.stage !== 'draft') return;
  const running = invitationStart($, previous, epoch);
  if (!running) return;
  try {
    let terms;
    try { terms = invitationProposal(previous.member, previous.pin); }
    catch {
      if (invitation === running) {
        invitation = { ...running, busy: false, message: 'Enter a nonempty invitee label (up to 128 UTF-8 bytes) and a valid public key or -.' };
        $.ui.invalidate('ui.render');
      }
      return;
    }
    if (!await inspectInvitationParent($, running, epoch)) return;
    const request = { context: adapterContext(running.parent), network_id: previous.selected.id, ...terms,
      ...(previous.replace ? { replace_flow_id: previous.replace } : {}) };
    const raw = await invitationRun($, ['prepare', '--stdin'], request);
    if (!await invitationCurrent($, running, epoch)) return;
    const flow = await parseInvitationFlow(JSON.parse(raw), running.parent, running.host);
    if (flow.state !== 'review' || flow.review.network.id !== request.network_id || flow.review.member !== terms.member ||
        flow.review.expected_person_public_key !== terms.expected_person_public_key || flow.flow_id === previous.replace) throw new Error('Changed invitation proposal');
    await invitationView($, running, epoch, flow);
  } catch { invitationFailure($, running, epoch); }
}
async function inspectInvitation($, running, epoch, state) {
  if (!await inspectInvitationParent($, running, epoch)) return false;
  // A newly replaced daemon must be observed even if a retained UI still has
  // the original project references. This read creates no setup or authority.
  const observed = await $.process.run([options.executable, ...(options.state ? ['--state', options.state] : []), 'onboarding'], { timeoutMs: 5000 });
  if (!await invitationCurrent($, running, epoch)) return false;
  if (observed.exitCode !== 0) throw new Error('Unavailable invitation host');
  observation(observed.stdout);
  if (JSON.parse(observed.stdout).host_id !== running.host) throw new Error('Changed invitation host');
  const captured = running.flow;
  const raw = await invitationRun($, ['inspect', captured.flow_id]);
  if (!await invitationCurrent($, running, epoch)) return false;
  const current = await parseInvitationFlow(JSON.parse(raw), running.parent, running.host);
  const now = await $.clock.now();
  if (!await invitationCurrent($, running, epoch)) return false;
  if (current.flow_id !== captured.flow_id || current.review_id !== captured.review_id || !same(current.review, captured.review) ||
      !same(current.invitation, captured.invitation) || current.state !== state ||
      Date.parse(state === 'review' ? captured.review.expires_at : captured.review.invitation_expires_at) <= now) throw new Error('Changed invitation review');
  return true;
}
async function decideInvitation($, previous, epoch, decision) {
  if (previous.stage !== 'review' || !previous.flow) return;
  const running = invitationStart($, previous, epoch);
  if (!running) return;
  let sent = false;
  try {
    if (!await inspectInvitation($, running, epoch, 'review')) return;
    const captured = previous.flow;
    sent = true;
    const raw = await invitationRun($, ['decide', '--stdin'], { context: adapterContext(running.parent),
      flow_id: captured.flow_id, review_id: captured.review_id, decision });
    if (!await invitationCurrent($, running, epoch)) return;
    const flow = await parseInvitationFlow(JSON.parse(raw), running.parent, running.host);
    if (flow.flow_id !== captured.flow_id || flow.review_id !== captured.review_id || !same(flow.review, captured.review) ||
        flow.state !== (decision === 'approve' ? 'issued' : 'declined')) throw new Error('Unknown invitation outcome');
    await invitationView($, running, epoch, flow);
  } catch { invitationFailure($, running, epoch, sent); }
}
async function revealInvitation($, previous, epoch) {
  if (previous.stage !== 'issued' || previous.code || !previous.flow) return;
  const running = invitationStart($, previous, epoch);
  if (!running) return;
  try {
    if (!await inspectInvitation($, running, epoch, 'issued')) return;
    const raw = await invitationRun($, ['handoff', '--stdin'], { context: adapterContext(running.parent),
      flow_id: previous.flow.flow_id, review_id: previous.flow.review_id });
    if (!await invitationCurrent($, running, epoch)) return;
    const code = parseInvitationHandoff(raw, previous.flow);
    const now = await $.clock.now();
    if (!await invitationCurrent($, running, epoch)) return;
    if (Date.parse(previous.flow.review.invitation_expires_at) <= now) throw new Error('Expired private invitation');
    invitation = { ...running, code, busy: false };
    $.ui.invalidate('ui.render');
  } catch { invitationFailure($, running, epoch); }
}
async function replaceInvitation($, previous, epoch) {
  if (!['issued', 'declined', 'expired', 'invalidated'].includes(previous.stage) || !previous.flow) return;
  const running = invitationStart($, previous, epoch);
  if (!running) return;
  try {
    invitationExpiry?.cancel();
    invitationExpiry = null;
    await invitationChoices($, running, epoch, previous.flow.flow_id);
  } catch { invitationFailure($, running, epoch); }
}
function invitationControls($, { Text, Button, Input }, epoch) {
  if (project.stage !== 'attached' || project.busy) return [];
  const previous = invitation;
  const button = (key, label, onPress) => Button({ key, label, onPress });
  if (previous.busy) return [Text({ children: ['Invitation: working…'] })];
  if (previous.stage === 'inactive') return recipient.stage === 'inactive' && joining.stage === 'inactive' ? [button('invitation-open', 'Invite someone', () => openInvitation($, previous, epoch))] : [];
  const back = button('invitation-back', 'Back from invitation', () => {
    if (invitation === previous && epoch === generation) { clearInvitation(); $.ui.invalidate('ui.render'); }
  });
  if (previous.stage === 'unavailable') return [Text({ children: [previous.message] }), back];
  if (previous.stage === 'choose') {
    const page = previous.page;
    return [Text({ children: ['Invitation: choose a network', '\nA listed network is not proof of invitation authority.',
      previous.replace ? '\nAnother invitation does not revoke an older exported code.' : '',
      previous.networks.length ? '' : '\nNo networks. Create a network through existing host administration first.'] }),
      ...previous.networks.slice(page * 10, page * 10 + 10).map(n => button(`invitation-network-${n.id}`,
        `Choose network ${quoted(n.name)} (${n.id})`, () => selectInvitationNetwork($, previous, epoch, n))),
      ...(page > 0 ? [button('invitation-prev', 'Previous networks', () => invitationDraft($, previous, epoch, 'page', page - 1))] : []),
      ...(previous.networks.length > page * 10 + 10 ? [button('invitation-next', 'More networks', () => invitationDraft($, previous, epoch, 'page', page + 1))] : []), back];
  }
  if (previous.stage === 'draft') return [Text({ children: [`Invitation network: ${quoted(previous.selected.name)} (${previous.selected.id})`,
    '\nUse - for an unpinned identity. A public-key pin grants no membership or access.', previous.message ? '\n' + previous.message : ''] }),
    Input({ key: 'invitation-member', label: 'Invitee label', value: previous.member,
      onInput: v => invitationDraft($, previous, epoch, 'member', v), onSubmit: v => invitationDraft($, previous, epoch, 'member', v) }),
    Input({ key: 'invitation-pin', label: 'Expected person public key', value: previous.pin,
      onInput: v => invitationDraft($, previous, epoch, 'pin', v), onSubmit: v => invitationDraft($, previous, epoch, 'pin', v) }),
    button('invitation-prepare', 'Review invitation', () => prepareInvitation($, previous, epoch)), back];
  const status = previous.stage === 'expired' && previous.flow.state === 'review'
    ? 'Invitation: review expired locally. Refresh to check the host.' : `Invitation: ${previous.stage}`;
  return [Text({ children: [status, '\n', invitationReviewLines(previous.flow)] }),
    ...(previous.stage === 'review' ? [
      button('invitation-approve', 'Approve invitation', () => decideInvitation($, previous, epoch, 'approve')),
      button('invitation-decline', 'Decline invitation', () => decideInvitation($, previous, epoch, 'decline')),
    ] : previous.stage === 'issued' ? [
      Text({ children: ['Share privately with the intended person. Do not paste into this or another agent conversation. Possession grants no membership or agent access.'] }),
      ...(previous.code ? [Text({ children: ['Private invitation:\n', previous.code] }),
        button('invitation-hide', 'Hide private invitation', () => {
          if (invitation === previous && epoch === generation) { invitation = { ...previous, code: null }; $.ui.invalidate('ui.render'); }
        }),
      ] : [button('invitation-reveal', 'Reveal private invitation', () => revealInvitation($, previous, epoch))]),
      button('invitation-replace', 'Invite another person', () => replaceInvitation($, previous, epoch)),
    ] : [button('invitation-replace', 'Review a replacement invitation', () => replaceInvitation($, previous, epoch))]), back];
}

function adapterControls($, { Text, Button }, epoch) {
  if (project.stage !== 'attached' || project.busy || invitation.stage !== 'inactive' || recipient.stage !== 'inactive' || joining.stage !== 'inactive') return [];
  const previous = adapter;
  const button = (key, label, onPress) => Button({ key, label, onPress });
  if (previous.busy) return [Text({ children: ['Adapter: working…'] })];
  if (previous.stage === 'inactive') return [button('adapter-review', 'Review adapter connection', () => openAdapter($, previous, epoch, true))];
  const back = button('adapter-back', 'Back to project', () => {
    if (adapter === previous && epoch === generation) { clearAdapter(); $.ui.invalidate('ui.render'); }
  });
  if (previous.stage === 'unavailable') return [Text({ children: [previous.message] }), back];
  if (previous.stage === 'empty') return [button('adapter-prepare', 'Review adapter permissions', () => openAdapter($, previous, epoch, true)), back];
  const status = previous.stage === 'authorized' ? 'Adapter: authorized'
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
  if (previous.stage === 'attached' && (joining.stage !== 'inactive' || recipient.stage !== 'inactive' || invitation.stage !== 'inactive' || adapter.stage !== 'inactive' || runtime?.parent.flow_id === previous.flow.flow_id)) {
    return [Text({ children: ['Project: attachment recorded'] }), back];
  }
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
    if (e.requestId !== 'peerspan') return next(e);
    if (e.surface !== 'terminal') { clearJoining(); clearRecipient(); clearInvitation(); return next(e); }
    const epoch = generation;
    if (invitation.stage !== 'inactive') {
      const captured = invitation;
      try { if (!await invitationCurrent($, captured, epoch) && invitation === captured) clearInvitation(); }
      catch { if (invitation === captured) clearInvitation(); }
    }
    if (recipient.stage !== 'inactive') {
      const captured = recipient;
      try { if (!await recipientCurrent($, captured, epoch) && recipient === captured) clearRecipient(); }
      catch { if (recipient === captured) clearRecipient(); }
    }
    if (joining.stage !== 'inactive') {
      const captured = joining;
      try { if (!await joinCurrent($, captured, epoch) && joining === captured) clearJoining(); }
      catch { if (joining === captured) clearJoining(); }
    }
    const displayedRuntime = runtime;
    const displayedReady = runtime?.messages;
    const displayedTasks = runtime?.tasks;
    const { Box, Text, Button, Input } = $.ui.resolve(e);
    return Box({ flexDirection: 'column', children: [
      Text({ children: [summary()] }),
      Button({ key: 'refresh', label: 'Refresh', onPress: () => refresh($) }),
      check.state === 'waiting' ? Text({ children: ['Waiting for this model to acknowledge…'] })
        : Button({ key: 'check', label: 'Check this conversation', onPress: () => beginCheck($, epoch) }),
      ...projectControls($, { Text, Button, Input }, epoch),
      ...adapterControls($, { Text, Button }, epoch),
      ...invitationControls($, { Text, Button, Input }, epoch),
      ...recipientControls($, { Text, Button, Input }, epoch),
      ...joiningControls($, { Text, Button, Input }, epoch),
      ...(runtime?.phase === 'connected' && !['starting', 'waiting', 'ready'].includes(runtime.messages?.state) ? [
        Text({ children: ['Enable incoming messages starts a model turn using this conversation’s normal model allowance.'] }),
        Button({ key: 'message-enable', label: runtime.messages ? 'Retry incoming messages' : 'Enable incoming messages',
          onPress: () => enableMessages($, displayedRuntime, epoch) }),
      ] : []),
      ...(runtime?.phase === 'connected' && runtime.messages?.state === 'ready' ?
        ['starting', 'enabled'].includes(runtime.tasks?.state) ? [
          Text({ children: ['Stopping incoming tasks pauses delivery and reporting; running tasks are not cancelled.'] }),
          Button({ key: 'task-stop', label: 'Stop incoming tasks', onPress: () => {
            if (runtime !== displayedRuntime || runtime.tasks !== displayedTasks || epoch !== generation) return;
            stopTasks(runtime);
            $.ui.invalidate('ui.render');
          } }),
        ] : [
          Text({ children: ['Incoming tasks can start model turns using the normal allowance. They grant no new local tool or file permission.'] }),
          Button({ key: 'task-enable', label: runtime.tasks?.state === 'blocked' && runtime.tasks.ready === runtime.messages
            ? 'Retry incoming tasks' : 'Enable incoming tasks',
            onPress: () => enableTasks($, displayedRuntime, displayedReady, epoch) }),
        ] : []),
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
  on('tool.call', { tool: 'mcp__peerspan__adapter_ready' }, ($, e, next) => readyMessages($, e, next))
    .catch(() => ({ deny: 'Message delivery check unavailable.' }));
  on('tool.call', { tool: 'mcp__peerspan__message_seen' }, ($, e, next) => messageWrite($, e, next, 'seen'))
    .catch(() => ({ deny: 'Message acknowledgment unavailable.' }));
  on('tool.call', { tool: 'mcp__peerspan__message_reply' }, ($, e, next) => messageWrite($, e, next, 'reply'))
    .catch(() => ({ deny: 'Message reply unavailable.' }));
  on('tool.call', { tool: 'mcp__peerspan__task_accept' }, ($, e, next) => taskWrite($, e, next, 'accept'))
    .catch(() => ({ deny: 'Task acceptance unavailable.' }));
  on('tool.call', { tool: 'mcp__peerspan__task_reject' }, ($, e, next) => taskWrite($, e, next, 'reject'))
    .catch(() => ({ deny: 'Task rejection unavailable.' }));
  on('tool.call', { tool: 'mcp__peerspan__task_progress' }, ($, e, next) => taskWrite($, e, next, 'progress'))
    .catch(() => ({ deny: 'Task progress unavailable.' }));
  on('tool.call', { tool: 'mcp__peerspan__task_complete' }, ($, e, next) => taskWrite($, e, next, 'complete'))
    .catch(() => ({ deny: 'Task completion unavailable.' }));
  on('tool.call', { tool: 'mcp__peerspan__task_cancelled' }, ($, e, next) => taskWrite($, e, next, 'cancelled'))
    .catch(() => ({ deny: 'Task cancellation unavailable.' }));
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
    $.ui.invalidate('ui.render');
    return next(e);
  });
}
