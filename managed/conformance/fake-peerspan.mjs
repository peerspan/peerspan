#!/usr/bin/env node
// Explicitly fake contract fixture. Never use this executable for customer work.
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
const event = {at: new Date().toISOString(), argv: args};
fs.appendFileSync(path.join(dir, 'calls.jsonl'), JSON.stringify(event) + '\n', {mode: 0o600});
const taskIndex = args.indexOf('task');
const command = args[taskIndex + 1];
const taskPath = id => path.join(dir, 'remote', id + '.json');
const publicRecord = remote => {
  const {events, ...record} = remote;
  return record;
};
if (!args.includes('--json')) {
  fail('FAKE fixture requires the global --json flag for every Peerspan command', 2);
} else if (args.includes('status')) {
  if (config.statusMalformed) process.stdout.write('FAKE invalid JSON\n');
  else emit({host_id: config.hostId, service: {active: config.active},
    attention: config.statusExit === 1 ? [{message: 'FAKE historical attention'}] : [],
    agents: [{id: config.agentId, name: 'FAKE-CONFORMANCE worker',
      sessions: [{id: config.sessionId, adapter_id: config.adapterId,
        connection: config.ready ? 'ready' : 'disconnected'}]}]}, config.statusExit);
} else if (args.includes('adapter') && args.includes('connection')) {
  emit({adapter_id: config.adapterId, session_id: config.sessionId,
    state: config.ready ? 'ready' : 'disconnected',
    channel: config.verified ? 'verified' : 'unverified',
    channel_verified_at: config.verifiedAt});
} else if (taskIndex >= 0 && command === 'submit') {
  const id = flag('--task');
  if (!/^task_[a-f0-9]{32}$/.test(id)) {
    fail('FAKE fixture refuses invalid task ID');
  } else if (config.submitMode === 'lost-missing') {
    fail('FAKE transport failed before remote acceptance', 2);
  } else {
    const remote = {peer_host_id: flag('--peer'), request: {
      task_id: id, target_agent_id: flag('--agent'), input: flag('--input'),
      deadline: flag('--deadline')},
    submit_state: config.submitMode === 'rejected' ? 'rejected' : 'accepted',
    status: config.submitMode === 'rejected' ? null : {state: config.remoteState, last_event: 1},
    error: config.submitMode === 'rejected' ? 'FAKE upstream rejection' : null,
    events: [{sequence: 1, kind: 'queued', state: config.remoteState, message: null,
      output: null, created_at: new Date().toISOString()}]};
    if (!fs.existsSync(taskPath(id))) {
      fs.writeFileSync(taskPath(id), JSON.stringify(remote), {mode: 0o600});
    }
    if (config.submitMode === 'lost-accepted') fail('FAKE response lost after remote acceptance', 2);
    else emit(publicRecord(JSON.parse(fs.readFileSync(taskPath(id), 'utf8'))));
  }
} else if (taskIndex >= 0 && command === 'inspect') {
  const id = args.find(arg => /^task_[a-f0-9]{32}$/.test(arg));
  const priorSubmission = fs.readFileSync(path.join(dir, 'calls.jsonl'), 'utf8')
    .split('\n').filter(Boolean).map(line => JSON.parse(line)).some(call => call.argv.includes('submit'));
  if (config.inspectMode === 'error' || (config.inspectMode === 'error-after-submit' && priorSubmission)) {
    fail('FAKE temporary inspection transport failure', 2);
  }
  else if (!id || !fs.existsSync(taskPath(id))) fail('error: host daemon: not found');
  else emit(publicRecord(JSON.parse(fs.readFileSync(taskPath(id), 'utf8'))));
} else if (taskIndex >= 0 && command === 'events') {
  const id = args.find(arg => /^task_[a-f0-9]{32}$/.test(arg));
  if (config.eventsMode === 'error') fail('FAKE temporary task-event transport failure', 2);
  else if (config.eventsMode === 'missing') emit([]);
  else if (!id || !fs.existsSync(taskPath(id))) fail('error: host daemon: not found');
  else {
    const after = args.includes('--after') ? Number(flag('--after')) : 0;
    emit(JSON.parse(fs.readFileSync(taskPath(id), 'utf8')).events.filter(event => event.sequence > after));
  }
} else {
  fail('FAKE unexpected command: ' + JSON.stringify(args), 2);
}
