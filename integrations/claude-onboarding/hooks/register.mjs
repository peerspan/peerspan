import { observation } from './observation.mjs';

let options;
let session = null;
let generation = 0;
let read = 0;
let lines = ['Host: unavailable'];
let check = { state: 'unverified' };
let expiration = null;
let submission = null;

function clearCheck() {
  expiration?.cancel();
  submission?.cancel();
  expiration = submission = null;
  check = { state: 'unverified' };
}

function clearSession() {
  generation++;
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
  return [...lines, `This conversation: ${check.state}`, meaning].join('\n');
}

async function refresh($) {
  const id = await identify($);
  const attempt = ++read;
  const epoch = generation;
  let observed = ['Host: unavailable'];
  try {
    if (typeof options.executable !== 'string' || !options.executable || typeof options.state !== 'string') {
      throw new Error('Invalid local configuration');
    }
    const argv = [options.executable, ...(options.state ? ['--state', options.state] : []), 'onboarding'];
    const result = await $.process.run(argv, { timeoutMs: 5000 });
    if (result.exitCode === 0) observed = observation(result.stdout);
  } catch {
    // Neither subprocess diagnostics nor unvalidated JSON belongs in the UI.
  }
  const current = await identify($);
  if (epoch === generation && attempt === read && id === current) {
    lines = observed;
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
      submission?.cancel();
      $.ui.invalidate('ui.render');
    }
  });
  // Submit outside the UI event; awaiting a new turn inside its handler can stall it.
  submission = $.clock.after(0, () => submit($, pending, epoch));
}

async function close($) {
  generation++;
  clearCheck();
  $.ui.invalidate('ui.render');
  await $.ui.close({ id: 'peerspan' });
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
    await $.command.register({ name: 'peerspan', description: 'Inspect Peerspan in this conversation', immediate: true });
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
    const epoch = generation;
    const { Box, Text, Button } = $.ui.resolve(e);
    return Box({ flexDirection: 'column', children: [
      Text({ children: [summary()] }),
      Button({ key: 'refresh', label: 'Refresh', onPress: () => { void refresh($); } }),
      check.state === 'waiting' ? Text({ children: ['Waiting for this model to acknowledge…'] })
        : Button({ key: 'check', label: 'Check this conversation', onPress: () => { void beginCheck($, epoch); } }),
      Button({ key: 'close', label: 'Close', onPress: () => { void close($); } }),
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
    generation++;
    clearCheck();
    return next(e);
  });
  on('session.end', async ($, e, next) => {
    clearSession();
    return next(e);
  });
}
