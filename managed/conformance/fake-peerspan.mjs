#!/usr/bin/env node
// Explicitly fake contract fixture. Never use this executable for customer work.
// It is configured by config.json in FAKE_PEERSPAN_FIXTURE; README.md lists the keys.
import fs from 'node:fs';
import path from 'node:path';

const dir = process.env.FAKE_PEERSPAN_FIXTURE;
if (!dir) throw new Error('FAKE_PEERSPAN_FIXTURE is required: this is not Peerspan');
const args = process.argv.slice(2);
const config = JSON.parse(fs.readFileSync(path.join(dir, 'config.json'), 'utf8'));
const flag = name => args[args.indexOf(name) + 1];
const emit = (value, code = 0) => {
  process.stdout.write(JSON.stringify(value) + '\n');
  process.exitCode = code;
};
const fail = (message, code = 1) => {
  process.stderr.write(message + '\n');
  process.exitCode = code;
};
const append = (name, value) => fs.appendFileSync(path.join(dir, name), JSON.stringify(value) + '\n', {mode: 0o600});
// Revision 3: `mono` is the system-wide monotonic clock in milliseconds (process.hrtime), so a suite can
// measure the time between calls even while the wall clock of a virtual machine steps back.
append('calls.jsonl', {at: new Date().toISOString(), mono: Number(process.hrtime.bigint() / 1000000n), argv: args});
// Revision 2: every invocation that exits also logs its exit status, so a suite can tell a
// failed call from a successful one without reading anything but this fixture directory.
process.on('exit', code => {
  try { append('outcomes.jsonl', {at: new Date().toISOString(), argv: args, code}); } catch { /* fixture removed */ }
});
const taskIndex = args.indexOf('task');
const command = args[taskIndex + 1];
const invoked = args.includes('status') ? 'status'
  : args.includes('agents') ? 'agents'
  : args.includes('adapter') && args.includes('connection') ? 'adapter'
  : taskIndex >= 0 ? command : null;
// Revision 3: "default" in senderStates makes a call without --state a call to a sender host.
const stateArgument = args.includes('--state') ? flag('--state') : 'default';
const senderState = (config.senderStates ?? [path.join(dir, 'PRIVATE-sender')]).includes(stateArgument);
// rejectJson is true (every command) or, in revision 3, a list of command names.
const rejectsJson = config.rejectJson === true || (Array.isArray(config.rejectJson) && config.rejectJson.includes(invoked));
const taskPath = id => path.join(dir, 'remote', id + '.json');
const taskArgument = () => args.find(arg => /^task_[a-f0-9]{32}$/.test(arg));
const publicRecord = remote => {
  const {events, ...record} = remote;
  return record;
};
// Revision 2 "a Peerspan call is hanging": log the hang, then do nothing until the configuration
// stops listing this command, the fixture directory is removed, or hangSeconds (default 60) pass.
const hangUntilReleased = () => {
  append('hanging.jsonl', {at: new Date().toISOString(), pid: process.pid, argv: args});
  const end = Date.now() + 1000 * (config.hangSeconds ?? 60);
  const timer = setInterval(() => {
    let current = null;
    try { current = JSON.parse(fs.readFileSync(path.join(dir, 'config.json'), 'utf8')); } catch { /* fixture removed */ }
    if (Date.now() < end && Array.isArray(current?.hang) && current.hang.includes(invoked)) return;
    clearInterval(timer);
    fail('FAKE hang ended without contacting anything', 2);
  }, 200);
};

if (rejectsJson && args.includes('--json')) {
  // An executable older than the global flag (contract section 6): nothing on stdout.
  fail("error: unexpected argument '--json' found\n\nUsage: FAKE-peerspan <COMMAND>\n\nFor more information, try '--help'.", 2);
} else if (!args.includes('--json')) {
  fail('FAKE fixture requires the global --json flag for every Peerspan command', 2);
} else if (Array.isArray(config.hang) && config.hang.includes(invoked)) {
  hangUntilReleased();
} else if (invoked === 'agents') {
  // Revision 3 (contract section 6): `agents [--network ID] [--refresh]` prints the sender host's directory
  // of the named network, or of its only network. `networks` maps a network ID to that directory's fields;
  // a `network_id` inside one overrides the reported ID. The fixture's directories are static: --refresh
  // is only logged.
  const networks = config.networks ?? {};
  const known = Object.keys(networks);
  const named = args.includes('--network') ? flag('--network') : null;
  if (config.agentsExit) fail('error: FAKE directory failure', config.agentsExit);
  else if (named !== null && !Object.hasOwn(networks, named)) fail(`error: FAKE network not found: ${named}`, 1);
  else if (named === null && known.length !== 1) {
    fail(known.length ? `error: FAKE host is in several networks (${known.join(', ')}); pass --network`
      : 'error: FAKE host is in no network', 1);
  } else if (config.agentsMalformed) process.stdout.write('FAKE directory that is not JSON\n');
  else {
    const id = named ?? known[0];
    const directory = {network_id: id, refreshed_at: null, reachable: [], mine: [], inbound: [], hosts: [],
      ...networks[id]};
    for (const key of config.agentsOmit ?? []) delete directory[key];
    emit(directory);
  }
} else if (args.includes('status') && senderState) {
  // Revision 2 (contract section 6): a sender state directory is another host than the worker's, with
  // no agents. senderStatusExit 2 makes it unreachable; senderHostId can be set to the worker's host.
  const exit = config.senderStatusExit ?? 0;
  if (exit === 2) {
    emit({daemon: 'not running', state: args.includes('--state') ? flag('--state') : 'FAKE-default-state',
      service: {active: false}}, 2);
  }
  else emit({host_id: config.senderHostId ?? 'host_' + 'd'.repeat(64), service: {active: true},
    attention: config.senderAttention ?? [], agents: []}, exit);
} else if (args.includes('status')) {
  if (config.statusMalformed) process.stdout.write('FAKE invalid JSON\n');
  else if (config.statusMode === 'daemon-not-running') {
    // A status that cannot reach its daemon (contract section 6).
    emit({daemon: 'not running', state: args.includes('--state') ? flag('--state') : 'FAKE-default-state',
      service: {active: false}}, 2);
  } else {
    const status = {host_id: config.hostId, service: {active: config.active},
      attention: config.attention ?? (config.statusExit === 1 ? [{message: 'FAKE historical attention'}] : []),
      agents: config.agents ?? [{id: config.agentId, name: 'FAKE-CONFORMANCE worker',
        sessions: [{id: config.sessionId, adapter_id: config.adapterId,
          connection: config.ready ? 'ready' : 'disconnected'}]}]};
    for (const key of config.statusOmit ?? []) delete status[key];
    emit(status, config.statusExit);
  }
} else if (args.includes('adapter') && args.includes('connection')) {
  const adapter = args.find(arg => /^adapter_[a-f0-9]{32}$/.test(arg));
  const entry = config.adapters?.[adapter];
  if (config.adapters && !entry) fail('error: host daemon: not found');
  else if (entry?.exit) fail('FAKE adapter connection failure', entry.exit);
  else if (entry) emit({adapter_id: adapter, ...entry});
  else emit({adapter_id: config.adapterId, session_id: config.sessionId,
    state: config.ready ? 'ready' : 'disconnected',
    channel: config.verified ? 'verified' : 'unverified',
    channel_verified_at: config.verifiedAt});
} else if (taskIndex >= 0 && command === 'submit') {
  const id = flag('--task');
  const inputs = args.filter(arg => arg.startsWith('--input='));
  if (args.includes('--input')) {
    // Contract section 4: the input is the single argument --input=TEXT. Upstream reads a separate
    // value that begins with a hyphen as an option and exits 2; this fixture refuses every separate
    // value the same way, so a return to the revision 1 form cannot pass unnoticed.
    fail(`error: unexpected argument '${flag('--input') ?? ''}' found\n\nFAKE fixture: pass the input as one --input=TEXT argument`, 2);
  } else if (inputs.length !== 1) {
    fail('error: FAKE fixture requires exactly one --input=TEXT argument', 2);
  } else if (!/^task_[a-f0-9]{32}$/.test(id)) {
    fail('FAKE fixture refuses invalid task ID');
  } else if (config.submitMode === 'lost-missing') {
    fail('FAKE transport failed before remote acceptance', 2);
  } else {
    const rejected = config.submitMode === 'rejected';
    const revision2 = config.recordShape === 'rev2';
    const remote = {peer_host_id: flag('--peer'), request: {
      task_id: id, target_agent_id: flag('--agent'), input: inputs[0].slice('--input='.length),
      deadline: flag('--deadline')},
    submit_state: rejected ? 'rejected' : 'accepted',
    status: rejected ? null
      : {state: config.remoteState, ...(revision2 ? {cancel_requested: false} : {}), last_event: 1},
    ...(revision2 ? {cancel_state: null} : {}),
    error: rejected ? 'FAKE upstream rejection' : null,
    events: [{sequence: 1, kind: 'queued', state: config.remoteState, message: null,
      output: null, created_at: new Date().toISOString()}]};
    if (!fs.existsSync(taskPath(id))) {
      fs.writeFileSync(taskPath(id), JSON.stringify(remote), {mode: 0o600});
    }
    if (config.submitMode === 'lost-accepted') fail('FAKE response lost after remote acceptance', 2);
    else emit(publicRecord(JSON.parse(fs.readFileSync(taskPath(id), 'utf8'))));
  }
} else if (taskIndex >= 0 && command === 'inspect') {
  const id = taskArgument();
  const priorSubmission = fs.readFileSync(path.join(dir, 'calls.jsonl'), 'utf8')
    .split('\n').filter(Boolean).map(line => JSON.parse(line)).some(call => call.argv.includes('submit'));
  if (config.inspectMode === 'error' || (config.inspectMode === 'error-after-submit' && priorSubmission)) {
    fail('FAKE temporary inspection transport failure', 2);
  }
  else if (!id || !fs.existsSync(taskPath(id))) fail('error: host daemon: not found');
  else emit(publicRecord(JSON.parse(fs.readFileSync(taskPath(id), 'utf8'))));
} else if (taskIndex >= 0 && command === 'events') {
  const id = taskArgument();
  if (config.eventsMode === 'error') fail('FAKE temporary task-event transport failure', 2);
  else if (config.eventsMode === 'missing') emit([]);
  else if (!id || !fs.existsSync(taskPath(id))) fail('error: host daemon: not found');
  else {
    const after = args.includes('--after') ? Number(flag('--after')) : 0;
    emit(JSON.parse(fs.readFileSync(taskPath(id), 'utf8')).events.filter(event => event.sequence > after));
  }
} else if (taskIndex >= 0 && command === 'cancel') {
  // Revision 2 (contract section 6): a cancellation is a request. It sets cancel_requested and
  // cancel_state "sent" and records a cancel_requested event; it never changes the task state.
  // A repeat, a rejected submission or a final task returns the record unchanged.
  const id = taskArgument();
  if (config.cancelMode === 'error') fail('FAKE temporary cancel transport failure', 2);
  else if (!id || !fs.existsSync(taskPath(id))) fail('error: host daemon: not found');
  else {
    const remote = JSON.parse(fs.readFileSync(taskPath(id), 'utf8'));
    const final = ['succeeded', 'failed', 'cancelled', 'rejected', 'expired'].includes(remote.status?.state);
    if (remote.submit_state === 'accepted' && remote.status && !final && !remote.status.cancel_requested) {
      const sequence = remote.status.last_event + 1;
      remote.status = {...remote.status, cancel_requested: true, last_event: sequence};
      remote.cancel_state = 'sent';
      remote.events.push({sequence, kind: 'cancel_requested', state: remote.status.state, message: null,
        output: null, created_at: new Date().toISOString()});
      fs.writeFileSync(taskPath(id) + '.cancel', JSON.stringify(remote), {mode: 0o600});
      fs.renameSync(taskPath(id) + '.cancel', taskPath(id));
    }
    emit(publicRecord({...remote, cancel_state: remote.cancel_state ?? null,
      status: remote.status && {...remote.status, cancel_requested: Boolean(remote.status.cancel_requested)}}));
  }
} else {
  fail('FAKE unexpected command: ' + JSON.stringify(args), 2);
}
