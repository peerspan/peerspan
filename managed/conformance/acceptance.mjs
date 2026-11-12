#!/usr/bin/env node
// Contract-only black-box acceptance. No imports or reads of managed implementation/state DB.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import http from 'node:http';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {setTimeout as delay} from 'node:timers/promises';

assert.equal(Number(process.versions.node.split('.')[0]), 24, 'Run this suite with Node 24');
assert.equal(process.platform, 'linux', 'Throwaway state and permissions must be tested on Linux');
const here = path.dirname(fileURLToPath(import.meta.url));
const cli = path.resolve(here, '../cli.mjs');
const started = Date.now();
const fixtures = [];
const ids = {hostId: 'host_' + '1'.repeat(64), agentId: 'agent_' + '2'.repeat(32),
  adapterId: 'adapter_' + '3'.repeat(32), sessionId: 'session_' + '4'.repeat(32)};
const defaults = {...ids, active: true, ready: true, verified: true,
  verifiedAt: '2026-01-01T00:00:00Z', statusExit: 0, statusMalformed: false,
  submitMode: 'normal', inspectMode: 'normal', eventsMode: 'normal', remoteState: 'queued'};

async function until(description, check, timeout = 10000) {
  const end = Date.now() + timeout;
  let last;
  while (Date.now() < end) {
    try { const value = await check(); if (value) return value; }
    catch (error) { last = error; }
    await delay(80);
  }
  throw new Error('Timed out: ' + description, {cause: last});
}

async function command(args, env, timeout = 8000) {
  const child = spawn(process.execPath, [cli, ...args], {env, stdio: ['ignore', 'pipe', 'pipe']});
  let stdout = '', stderr = '';
  child.stdout.on('data', data => stdout += data);
  child.stderr.on('data', data => stderr += data);
  const timer = setTimeout(() => child.kill('SIGKILL'), timeout);
  const code = await new Promise((resolve, reject) => {
    child.on('error', reject);
    child.on('exit', resolve);
  });
  clearTimeout(timer);
  return {code, stdout, stderr};
}

async function freePort() {
  const server = net.createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

async function writeJson(file, value) {
  const temp = file + '.new';
  await fs.writeFile(temp, JSON.stringify(value), {mode: 0o600});
  await fs.rename(temp, file);
}

async function fixture(label, {connect = true, config = {}} = {}) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'FAKE-managed-conformance-' + label + '-'));
  await fs.chmod(dir, 0o700);
  const state = path.join(dir, 'private-managed-state');
  const fake = path.join(dir, 'explicitly-fake-peerspan');
  await fs.copyFile(path.join(here, 'fake-peerspan.mjs'), fake);
  await fs.chmod(fake, 0o700);
  await fs.mkdir(path.join(dir, 'remote'), {mode: 0o700});
  await fs.writeFile(path.join(dir, 'calls.jsonl'), '', {mode: 0o600});
  const workerFile = path.join(dir, 'PRIVATE-worker.json');
  const workerDir = path.join(dir, 'PRIVATE-worker-host');
  const senderDir = path.join(dir, 'PRIVATE-sender');
  const worker = {host_dir: workerDir, host_id: ids.hostId, agent_id: ids.agentId,
    adapter_id: ids.adapterId, session_id: ids.sessionId};
  await writeJson(workerFile, worker);
  const env = {...process.env, PEERSPAN_BIN: fake, FAKE_PEERSPAN_FIXTURE: dir, MANAGED_TICK_MS: '100'};
  const f = {dir, state, fake, workerFile, workerDir, senderDir, worker, env,
    config: {...defaults, ...config}, child: null, extraChildren: [], logs: '', token: '', connectionId: null,
    port: await freePort()};
  fixtures.push(f);
  f.configure = async patch => {
    Object.assign(f.config, patch);
    await writeJson(path.join(dir, 'config.json'), f.config);
  };
  await f.configure({});
  f.cli = async (...args) => command([...args, '--state', state], env);
  f.checkedCli = async (...args) => {
    const result = await f.cli(...args);
    assert.equal(result.code, 0, JSON.stringify({args, ...result}));
    return result.stdout.trim();
  };
  if (connect) {
    const result = JSON.parse(await f.checkedCli('connect', '--name', 'FAKE-CONFORMANCE ' + label,
      '--worker-state', workerFile, '--sender-state', senderDir));
    assert.ok(result.id, 'connect returns registered id');
    f.connectionId = result.id;
  }
  f.origin = 'http://127.0.0.1:' + f.port;
  f.request = async (method, route, body, options = {}) => {
    const headers = {Host: '127.0.0.1:' + f.port,
      ...(options.auth === false ? {} : {Authorization: 'Bearer ' + f.token}),
      ...options.headers};
    let payload;
    if (body !== undefined) {
      payload = options.raw ? body : JSON.stringify(body);
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(payload);
    }
    return new Promise((resolve, reject) => {
      const req = http.request({hostname: '127.0.0.1', port: f.port, method, path: route, headers}, res => {
        let text = '';
        res.setEncoding('utf8');
        res.on('data', chunk => text += chunk);
        res.on('end', () => {
          let data; try { data = JSON.parse(text); } catch { data = null; }
          resolve({status: res.statusCode, headers: res.headers, text, data});
        });
      });
      req.on('error', reject);
      req.setTimeout(6000, () => req.destroy(new Error('HTTP request timed out')));
      req.end(payload);
    });
  };
  f.start = async () => {
    assert.equal(f.child, null);
    f.child = spawn(process.execPath, [cli, 'serve', '--state', state, '--port', String(f.port)],
      {env, stdio: ['ignore', 'pipe', 'pipe']});
    f.child.stdout.on('data', data => f.logs += data);
    f.child.stderr.on('data', data => f.logs += data);
    await until(label + ' serve health; logs=' + f.logs, async () => {
      if (f.child.exitCode !== null) throw new Error('serve exited: ' + f.logs);
      return (await f.request('GET', '/health', undefined, {auth: false})).status === 200;
    });
    f.token = await f.checkedCli('token');
    assert.ok(f.token.length >= 24, 'private token must be nonempty and unguessable');
  };
  f.stop = async (signal = 'SIGTERM') => {
    const children = [f.child, ...f.extraChildren].filter(Boolean);
    f.child = null;
    f.extraChildren = [];
    for (const child of children) {
      if (child.exitCode !== null || child.signalCode !== null) continue;
      const exited = new Promise(resolve => child.once('exit', resolve));
      child.kill(signal);
      const killer = setTimeout(() => child.kill('SIGKILL'), 2000);
      await exited;
      clearTimeout(killer);
    }
  };
  f.snapshot = async () => {
    const response = await f.request('GET', '/api/snapshot');
    assert.equal(response.status, 200, response.text);
    const text = response.text;
    for (const secret of [f.dir, f.workerFile, f.workerDir, f.senderDir, f.token]) {
      assert.ok(!text.includes(secret), 'snapshot leaks private local state: ' + secret);
    }
    return response.data;
  };
  f.create = async (patch = {}) => {
    const response = await f.request('POST', '/api/workflows', {
      name: 'FAKE-CONFORMANCE ' + label, connectionId: f.connectionId,
      instructions: 'FAKE fixture only: $(touch NEVER_EXECUTE); `not-a-shell`\nUnicode: λ',
      intervalMinutes: 1, maxRunsPerDay: 20, acceptanceMinutes: 5, ...patch});
    assert.equal(response.status, 201, response.text);
    return response.data;
  };
  f.action = async (id, action, body = {}) => {
    const response = await f.request('POST', '/api/workflows/' + id + '/' + action, body);
    assert.equal(response.status, 200, response.text);
    return response.data;
  };
  f.calls = async () => (await fs.readFile(path.join(dir, 'calls.jsonl'), 'utf8'))
    .split('\n').filter(Boolean).map(line => JSON.parse(line));
  f.submissions = async () => (await f.calls()).filter(call => {
    const index = call.argv.indexOf('task'); return index >= 0 && call.argv[index + 1] === 'submit';
  });
  f.remote = async (taskId, stateValue, output = null) => {
    const file = path.join(dir, 'remote', taskId + '.json');
    // The record exists once the fake sender has received the submission, which can follow the logged call.
    const remote = await until('fake sender received ' + taskId, async () => JSON.parse(await fs.readFile(file, 'utf8')), 15000);
    const sequence = (remote.status?.last_event ?? 0) + 1;
    if (output === null && ['succeeded', 'failed'].includes(stateValue)) output = 'FAKE ' + stateValue + ' output';
    remote.status = {state: stateValue, last_event: sequence};
    remote.events.push({sequence, kind: stateValue, state: stateValue, message: null,
      output, created_at: new Date().toISOString()});
    await writeJson(file, remote);
  };
  f.run = async (workflowId, stateValue) => until(label + ' run ' + stateValue, async () => {
    const runs = (await f.snapshot()).runs.filter(run => run.workflowId === workflowId);
    return runs.find(run => !stateValue || run.state === stateValue);
  });
  f.workflow = async id => (await f.snapshot()).workflows.find(item => item.id === id);
  f.ready = async expected => until(label + ' readiness=' + expected, async () => {
    const connection = (await f.snapshot()).connections.find(item => item.id === f.connectionId);
    return connection?.readiness?.ready === expected && connection;
  });
  return f;
}

function protectedResponse(response) {
  assert.match(response.headers['cache-control'] ?? '', /no-store/i);
  assert.match(response.headers['x-robots-tag'] ?? '', /noindex/i);
  assert.equal(response.headers['access-control-allow-origin'], undefined);
}

async function authenticationAndValidation() {
  const f = await fixture('authentication', {connect: false});
  await f.start();
  const health = await f.request('GET', '/health', undefined, {auth: false});
  assert.deepEqual(health.data, {ok: true});
  protectedResponse(health);
  const empty = await f.snapshot();
  for (const key of ['connections', 'workflows', 'runs', 'observed']) assert.deepEqual(empty[key], []);
  assert.match(JSON.stringify(empty.meta), /cost/i);
  assert.match(JSON.stringify(empty.meta), /unavailable/i);
  const unauth = await f.request('GET', '/api/snapshot', undefined, {auth: false});
  assert.equal(unauth.status, 401); assert.ok(unauth.data); protectedResponse(unauth);
  const signin = await f.request('GET', '/', undefined, {auth: false});
  assert.equal(signin.status, 200); assert.match(signin.text, /sign.?in|access token/i);
  assert.ok(!signin.text.includes(f.token)); protectedResponse(signin);
  const consolePage = await f.request('GET', '/');
  assert.equal(consolePage.status, 200); protectedResponse(consolePage);
  assert.ok(!consolePage.text.includes(f.token));
  const wrongHost = await f.request('GET', '/health', undefined, {headers: {Host: 'evil.example'}});
  assert.equal(wrongHost.status, 403); protectedResponse(wrongHost);
  const wrongPort = await f.request('GET', '/health', undefined, {headers: {Host: '127.0.0.1:1'}});
  assert.equal(wrongPort.status, 403);
  assert.equal((await f.request('GET', '/health', undefined,
    {headers: {Host: 'localhost:' + f.port}})).status, 200);
  assert.equal((await f.request('POST', '/api/login', {token: 'FAKE-invalid'},
    {auth: false, headers: {Origin: f.origin}})).status, 401);
  assert.equal((await f.request('POST', '/api/login', {token: f.token, extra: true},
    {auth: false, headers: {Origin: f.origin}})).status, 400);
  assert.equal((await f.request('POST', '/api/login', {token: f.token},
    {auth: false, headers: {Origin: 'https://evil.example'}})).status, 403);
  const login = await f.request('POST', '/api/login', {token: f.token},
    {auth: false, headers: {Origin: f.origin}});
  assert.equal(login.status, 200, login.text); protectedResponse(login);
  const setCookie = login.headers['set-cookie']?.join(';') ?? '';
  assert.match(setCookie, /HttpOnly/i); assert.match(setCookie, /SameSite=Strict/i);
  const cookie = setCookie.split(';')[0];
  assert.equal((await f.request('GET', '/api/snapshot', undefined,
    {auth: false, headers: {Cookie: cookie}})).status, 200);
  assert.equal((await f.request('POST', '/api/logout', {},
    {auth: false, headers: {Cookie: cookie, Origin: 'https://evil.example'}})).status, 403);
  const logout = await f.request('POST', '/api/logout', {},
    {auth: false, headers: {Cookie: cookie, Origin: f.origin}});
  assert.equal(logout.status, 200);
  assert.match(logout.headers['set-cookie']?.join(';') ?? '', /Max-Age=0|Expires=/i);
  const oversized = await f.request('POST', '/api/workflows', ' '.repeat(65537), {raw: true});
  assert.ok([400, 413].includes(oversized.status)); protectedResponse(oversized);
  assert.equal((await f.request('POST', '/api/workflows', '{', {raw: true})).status, 400);
  await f.stop();
  f.connectionId = JSON.parse(await f.checkedCli('connect', '--name', 'FAKE validation',
    '--worker-state', f.workerFile, '--sender-state', f.senderDir)).id;
  await f.start();
  const valid = {name: 'FAKE schema', connectionId: f.connectionId, instructions: 'FAKE only',
    intervalMinutes: 1, maxRunsPerDay: 1, acceptanceMinutes: 1};
  const invalid = [null, [], {...valid, extra: 1}, {...valid, name: ''}, {...valid, name: 'x'.repeat(101)},
    {...valid, instructions: ''}, {...valid, instructions: 'x'.repeat(12001)},
    {...valid, intervalMinutes: 0}, {...valid, intervalMinutes: 10081}, {...valid, intervalMinutes: '1'},
    {...valid, maxRunsPerDay: 0}, {...valid, maxRunsPerDay: 1001}, {...valid, maxRunsPerDay: 1.5},
    {...valid, acceptanceMinutes: 0}, {...valid, acceptanceMinutes: 1441}, {...valid, enabled: 'true'},
    {...valid, connectionId: 'FAKE-missing'}];
  for (const body of invalid) {
    const response = await f.request('POST', '/api/workflows', body);
    assert.equal(response.status, 400, 'invalid body accepted: ' + JSON.stringify(body).slice(0, 180));
    assert.ok(response.data); protectedResponse(response);
  }
  const boundary = await f.create({name: 'x'.repeat(100), instructions: 'x'.repeat(12000),
    intervalMinutes: 10080, maxRunsPerDay: 1000, acceptanceMinutes: 1440});
  assert.equal(boundary.enabled, false);
  const keys = ['id', 'name', 'connectionId', 'instructions', 'intervalMinutes', 'maxRunsPerDay',
    'acceptanceMinutes', 'enabled', 'nextRunAt', 'failureStreak', 'blockedReason'];
  for (const key of keys) assert.ok(Object.hasOwn(boundary, key), 'missing workflow field ' + key);
  for (const action of ['pause', 'resume', 'run']) {
    assert.equal((await f.request('POST', '/api/workflows/FAKE-absent/' + action, {})).status, 404);
    assert.equal((await f.request('POST', '/api/workflows/' + boundary.id + '/' + action,
      {unknown: true})).status, 400);
  }
  assert.equal((await f.request('DELETE', '/api/workflows/' + boundary.id)).status, 404);
  assert.ok(!f.logs.includes(f.token), 'token leaked in server output');
  await f.stop();
}

async function readinessAndTargetExclusion() {
  const f = await fixture('readiness', {config: {verified: false}});
  await f.start();
  const paused = await f.create();
  assert.equal(paused.enabled, false);
  await f.action(paused.id, 'run');
  await delay(350);
  assert.equal((await f.submissions()).length, 0, 'manual run bypassed paused state');
  const enabled = await f.create({enabled: true});
  const blocked = await f.ready(false);
  assert.ok(blocked.readiness.reason);
  await delay(250);
  assert.equal((await f.submissions()).length, 0, 'unverified adapter dispatched');
  await f.configure({verified: true, verifiedAt: ''});
  await delay(350);
  assert.equal((await f.submissions()).length, 0, 'missing verification time dispatched');
  await f.configure({verifiedAt: defaults.verifiedAt, hostId: 'host_' + '9'.repeat(64)});
  await delay(350);
  assert.equal((await f.submissions()).length, 0, 'changed status host dispatched');
  await f.configure({hostId: ids.hostId, agentId: 'agent_' + '9'.repeat(32)});
  await delay(350);
  assert.equal((await f.submissions()).length, 0, 'changed status agent dispatched');
  await f.configure({agentId: ids.agentId, statusMalformed: true});
  await delay(350);
  assert.equal((await f.submissions()).length, 0, 'malformed status dispatched');
  await f.configure({statusMalformed: false, statusExit: 2});
  await delay(350);
  assert.equal((await f.submissions()).length, 0, 'status exit 2 dispatched');
  await f.action(enabled.id, 'pause');
  await f.configure({active: false, statusExit: 1});
  const standalone = await f.ready(true);
  assert.match(standalone.readiness.reason, /service/i);
  assert.match(standalone.readiness.reason, /inactive|not active/i);
  await f.action(enabled.id, 'run');
  await delay(250);
  assert.equal((await f.submissions()).length, 0, 'standalone readiness bypassed paused state');
  await f.configure({active: true});
  await f.action(enabled.id, 'resume');
  await f.ready(true);
  const first = await f.run(enabled.id, 'queued');
  assert.match(first.taskId, /^task_[0-9a-f]{32}$/);
  await f.action(enabled.id, 'pause');
  assert.equal((await f.workflow(enabled.id)).enabled, false);
  await f.action(paused.id, 'resume');
  await f.action(paused.id, 'run');
  await delay(500);
  assert.equal((await f.submissions()).length, 1, 'same target ran unresolved work concurrently');
  await f.remote(first.taskId, 'running');
  await f.run(enabled.id, 'running');
  await f.remote(first.taskId, 'succeeded', 'FAKE completed despite pause');
  await f.run(enabled.id, 'succeeded');
  const second = await f.run(paused.id, 'queued');
  assert.notEqual(second.taskId, first.taskId);
  assert.equal((await f.submissions()).length, 2);
  await f.action(paused.id, 'pause');
  await f.remote(second.taskId, 'succeeded', 'FAKE target released');
  await f.run(paused.id, 'succeeded');
  await writeJson(f.workerFile, {...f.worker, host_id: 'host_' + '8'.repeat(64)});
  await f.action(paused.id, 'resume');
  await f.action(paused.id, 'run');
  await f.ready(false);
  await delay(400);
  assert.equal((await f.submissions()).length, 2, 'changed pinned worker file identity dispatched');
  await writeJson(f.workerFile, {...f.worker, adapter_id: 'adapter_' + '5'.repeat(32),
    session_id: 'session_' + '6'.repeat(32)});
  await f.configure({adapterId: 'adapter_' + '5'.repeat(32), sessionId: 'session_' + '6'.repeat(32)});
  await f.ready(true);
  await until('same-identity session rotation dispatch', async () => (await f.submissions()).length === 3);
  await f.stop();
}

async function durableRecovery() {
  const f = await fixture('recovery', {config: {submitMode: 'lost-accepted', inspectMode: 'error-after-submit'}});
  await f.start();
  const workflow = await f.create({enabled: true});
  await until('lost submit captured', async () => (await f.submissions()).length === 1);
  const originalSubmit = (await f.submissions())[0];
  const original = await f.run(workflow.id);
  await f.stop('SIGKILL');
  await f.configure({ready: false, inspectMode: 'normal'});
  await f.start();
  await f.ready(false);
  const recovered = await f.run(workflow.id, 'queued');
  assert.equal(recovered.taskId, original.taskId);
  assert.equal(recovered.id, original.id);
  assert.equal((await f.submissions()).length, 1, 'accepted task was submitted twice after restart');
  await f.configure({inspectMode: 'error'});
  await until('inspection error visible', async () => Boolean((await f.run(workflow.id)).error));
  await f.action(workflow.id, 'run');
  await delay(400);
  assert.equal((await f.snapshot()).runs.length, 1);
  assert.equal((await f.submissions()).length, 1);
  await f.remote(original.taskId, 'FAKE_UNKNOWN_STATE');
  await f.configure({inspectMode: 'normal', ready: true});
  await delay(500);
  await f.action(workflow.id, 'run');
  await delay(400);
  assert.equal((await f.snapshot()).runs.length, 1, 'unknown state manufactured replacement work');
  assert.equal((await f.submissions()).length, 1);
  await f.configure({eventsMode: 'error'});
  await f.remote(original.taskId, 'succeeded', 'FAKE durable final output');
  await until('final output event requested', async () => (await f.calls()).some(call => call.argv.includes('events')));
  await f.action(workflow.id, 'run');
  await delay(400);
  assert.ok(['submitting', 'queued', 'running'].includes((await f.run(workflow.id)).state),
    'finalized before output event retrieval');
  assert.equal((await f.workflow(workflow.id)).failureStreak, 0);
  assert.equal((await f.submissions()).length, 1, 'event failure released target reservation');
  await f.stop('SIGKILL');
  await f.configure({eventsMode: 'missing', ready: false});
  await f.start();
  await delay(500);
  const awaitingOutput = await f.run(workflow.id);
  assert.equal(awaitingOutput.id, original.id);
  assert.ok(['submitting', 'queued', 'running'].includes(awaitingOutput.state),
    'missing final event became terminal after restart');
  assert.equal((await f.snapshot()).runs.length, 1);
  assert.equal((await f.submissions()).length, 1);
  await f.configure({eventsMode: 'normal'});
  const completed = await f.run(workflow.id, 'succeeded');
  assert.equal(completed.output, 'FAKE durable final output');
  await f.action(workflow.id, 'pause');
  await f.stop('SIGKILL');
  await f.start();
  const retained = await f.run(workflow.id, 'succeeded');
  assert.equal(retained.output, completed.output);
  assert.equal(retained.taskId, original.taskId);
  assert.deepEqual((await f.submissions())[0].argv, originalSubmit.argv);
  await f.stop();

  const missing = await fixture('not-found-replay', {config: {submitMode: 'lost-missing', inspectMode: 'error-after-submit'}});
  await missing.start();
  const work = await missing.create({enabled: true});
  await until('uncertain submission reserved', async () => (await missing.submissions()).length === 1);
  const before = (await missing.submissions())[0];
  const reserved = await missing.run(work.id);
  await missing.stop('SIGKILL');
  await missing.configure({submitMode: 'normal', inspectMode: 'normal', ready: false});
  await missing.start();
  const replayed = await missing.run(work.id, 'queued');
  assert.equal(replayed.id, reserved.id);
  assert.equal(replayed.taskId, reserved.taskId);
  const submits = await missing.submissions();
  assert.equal(submits.length, 2);
  assert.deepEqual(submits[1].argv, before.argv, 'replay payload changed');
  const all = await missing.calls();
  const replayIndex = all.findLastIndex(call => call.argv.includes('submit'));
  assert.ok(all.slice(1, replayIndex).some(call => call.argv.includes('inspect') &&
    call.argv.includes(reserved.taskId)), 'replay was not preceded by same-ID inspection');
  const argv = before.argv;
  assert.equal(argv[argv.indexOf('--state') + 1], missing.senderDir);
  assert.ok(argv.includes('--input=' + work.instructions) && !argv.includes('--input'),
    'section 4: the input travels as the single argument --input=TEXT');
  assert.equal(argv[argv.indexOf('--peer') + 1], ids.hostId);
  assert.equal(argv[argv.indexOf('--agent') + 1], ids.agentId);
  assert.ok(Number.isFinite(Date.parse(argv[argv.indexOf('--deadline') + 1])));
  await missing.stop();
}

async function recurrenceAndCap() {
  const f = await fixture('recurrence');
  await f.start();
  const workflow = await f.create({enabled: true, maxRunsPerDay: 2});
  const first = await f.run(workflow.id, 'queued');
  await f.remote(first.taskId, 'succeeded', 'FAKE recurring output one');
  const completed = await f.run(workflow.id, 'succeeded');
  const updated = await f.workflow(workflow.id);
  assert.ok(Date.parse(updated.nextRunAt) >= Date.parse(completed.updatedAt) + 59000,
    'completion did not schedule the one-minute interval');
  await delay(800);
  assert.equal((await f.submissions()).length, 1, 'recurrence dispatched too soon');
  await until('automatic one-minute recurrence', async () => (await f.submissions()).length === 2, 70000);
  const runs = (await f.snapshot()).runs;
  assert.equal(runs.length, 2);
  assert.ok(Date.parse(runs[0].createdAt) >= Date.parse(runs[1].createdAt), 'runs must be newest first');
  const second = runs.find(run => run.taskId !== first.taskId);
  await f.remote(second.taskId, 'succeeded', 'FAKE recurring output two');
  await until('second completion', async () => (await f.snapshot()).runs.every(run => run.state === 'succeeded'));
  await f.stop('SIGKILL');
  await f.start();
  assert.equal((await f.snapshot()).runs.length, 2);
  await f.action(workflow.id, 'run');
  await delay(600);
  assert.equal((await f.submissions()).length, 2, 'daily cap was bypassed after restart/manual run');
  assert.ok((await f.workflow(workflow.id)).blockedReason, 'cap block must be visible');
  await f.stop();
}

async function failureCircuit() {
  const f = await fixture('failure-circuit');
  await f.start();
  const workflow = await f.create({enabled: true});
  let count = 0;
  async function finish(stateValue, expectedStreak) {
    const run = await until('new failure-circuit run', async () => {
      const runs = (await f.snapshot()).runs;
      return runs.length === count + 1 && runs.find(item => item.state === 'queued');
    });
    count++;
    await f.remote(run.taskId, stateValue, stateValue === 'succeeded' ? 'FAKE reset' : null);
    await until('terminal ' + stateValue, async () =>
      (await f.snapshot()).runs.find(item => item.id === run.id)?.state === stateValue);
    const current = await f.workflow(workflow.id);
    assert.equal(current.failureStreak, expectedStreak);
    assert.ok(Date.parse(current.nextRunAt) >= Date.now() + 58000, 'terminal delay below one minute');
    return current;
  }
  await finish('failed', 1);
  await f.action(workflow.id, 'run');
  await finish('succeeded', 0);
  for (const [index, stateValue] of ['failed', 'cancelled', 'expired'].entries()) {
    await f.action(workflow.id, 'run');
    const current = await finish(stateValue, index + 1);
    assert.equal(current.enabled, index < 2, 'failure circuit threshold incorrect');
    if (index === 2) assert.ok(current.blockedReason);
  }
  await f.action(workflow.id, 'run');
  await delay(500);
  assert.equal((await f.submissions()).length, count, 'manual run bypassed failure circuit pause');
  const resumed = await f.action(workflow.id, 'resume');
  assert.equal(resumed.enabled, true);
  assert.equal(resumed.failureStreak, 0);
  await f.action(workflow.id, 'run');
  await finish('rejected', 1);
  await f.action(workflow.id, 'pause');
  await f.configure({submitMode: 'rejected'});
  const capped = await f.create({enabled: true, maxRunsPerDay: 1});
  await f.run(capped.id, 'rejected');
  assert.equal((await f.workflow(capped.id)).failureStreak, 1);
  const submissionsBefore = (await f.submissions()).length;
  await f.action(capped.id, 'run');
  await delay(500);
  assert.equal((await f.submissions()).length, submissionsBefore, 'rejected submission did not consume cap');
  await f.stop();
}

async function observationAndLock() {
  const f = await fixture('observation', {connect: false});
  const external = path.join(f.dir, 'PRIVATE-external-controller');
  await fs.mkdir(external, {mode: 0o700});
  const source = {
    'config.json': JSON.stringify({enabled: true, token: 'PRIVATE-OBSERVATION-TOKEN',
      directory: external, customerSecret: 'PRIVATE-CUSTOMER-SECRET'}),
    'state.json': JSON.stringify({cycle: 7, phase: 'FAKE watching', lastTickAt: '2026-01-01T00:00:00Z',
      error: null, task: {id: 'FAKE-external-task', key: 'FAKE-key', state: 'running', lane: 'fake',
        reportPath: external, token: 'PRIVATE-NESTED-TOKEN'},
      lastBatch: {key: 'FAKE-batch', status: 'done', articlesAdded: 3, dossiersAdded: 2, reportPath: external},
      reportPath: external, secret: 'PRIVATE-STATE-SECRET'}),
    'events.jsonl': '{"secret":"PRIVATE-EVENT-SECRET"}\n'};
  for (const [name, content] of Object.entries(source)) await fs.writeFile(path.join(external, name), content);
  const observed = JSON.parse(await f.checkedCli('observe', '--name', 'FAKE external read-only', '--directory', external));
  assert.ok(observed.id);
  await f.start();
  const snapshot = await f.snapshot();
  assert.equal(snapshot.workflows.length, 0);
  assert.equal(snapshot.runs.length, 0);
  const item = snapshot.observed.find(row => row.id === observed.id);
  assert.ok(item); assert.equal(item.available, true); assert.equal(item.enabled, true);
  assert.equal(item.cycle, 7); assert.equal(item.phase, 'FAKE watching');
  assert.deepEqual(item.task, {id: 'FAKE-external-task', key: 'FAKE-key', state: 'running', lane: 'fake'});
  assert.deepEqual(item.lastBatch, {key: 'FAKE-batch', status: 'done', articlesAdded: 3, dossiersAdded: 2});
  assert.ok(!JSON.stringify(snapshot).includes('PRIVATE-'));
  for (const action of ['run', 'pause', 'resume', 'delete']) {
    assert.equal((await f.request('POST', '/api/observed/' + observed.id + '/' + action, {})).status, 404);
    assert.equal((await f.request('POST', '/api/workflows/' + observed.id + '/' + action, {})).status, 404);
  }
  for (const [name, content] of Object.entries(source)) {
    assert.equal(await fs.readFile(path.join(external, name), 'utf8'), content, 'observation changed source ' + name);
  }
  await fs.writeFile(path.join(external, 'state.json'), 'FAKE malformed JSON');
  const unavailable = (await f.snapshot()).observed.find(row => row.id === observed.id);
  assert.equal(unavailable.available, false);
  assert.equal(unavailable.phase, 'unavailable'); assert.ok(unavailable.error);
  assert.ok(!unavailable.error.includes(external));
  await fs.unlink(path.join(external, 'config.json'));
  assert.equal((await f.snapshot()).observed[0].available, false);
  assert.equal(await fs.readFile(path.join(external, 'state.json'), 'utf8'), 'FAKE malformed JSON');
  assert.equal(await fs.readFile(path.join(external, 'events.jsonl'), 'utf8'), source['events.jsonl']);
  const otherPort = await freePort();
  const second = await f.cli('serve', '--port', String(otherPort));
  assert.notEqual(second.code, 0, 'second writer succeeded');
  assert.notEqual(second.code, null, 'second writer hung instead of refusing');
  assert.equal((await f.request('GET', '/health')).status, 200, 'second writer disturbed original');
  assert.equal((await fs.stat(f.state)).mode & 0o777, 0o700);
  async function privateEntries(dir) {
    for (const entry of await fs.readdir(dir, {withFileTypes: true})) {
      const file = path.join(dir, entry.name);
      const info = await fs.stat(file);
      assert.equal(info.mode & 0o777, entry.isDirectory() ? 0o700 : 0o600,
        'private state permission differs from contract: ' + entry.name);
      if (entry.isDirectory()) await privateEntries(file);
    }
  }
  await privateEntries(f.state);
  assert.equal((await f.submissions()).length, 0, 'observation dispatched external work');
  const status = await f.checkedCli('status');
  assert.ok(status.length > 0, 'status command unavailable');
  await f.stop('SIGKILL');
  const ports = [await freePort(), await freePort()];
  const contenders = ports.map(port => {
    const child = spawn(process.execPath, [cli, 'serve', '--state', f.state, '--port', String(port)],
      {env: f.env, stdio: ['ignore', 'pipe', 'pipe']});
    child.stdout.on('data', data => f.logs += data);
    child.stderr.on('data', data => f.logs += data);
    f.extraChildren.push(child);
    return child;
  });
  await until('exactly one restart writer refuses', () =>
    contenders.filter(child => child.exitCode !== null).length === 1);
  const loser = contenders.find(child => child.exitCode !== null);
  assert.notEqual(loser.exitCode, 0, 'losing simultaneous writer did not refuse');
  const winnerIndex = contenders.findIndex(child => child.exitCode === null);
  f.port = ports[winnerIndex];
  await until('winning restart serves', async () => (await f.request('GET', '/health')).status === 200);
  await delay(200);
  assert.equal(contenders[winnerIndex].exitCode, null, 'winning restart unexpectedly exited');
  await f.stop();
}

const cases = [authenticationAndValidation, readinessAndTargetExclusion, durableRecovery,
  recurrenceAndCap, failureCircuit, observationAndLock];
const watchdog = setTimeout(() => {
  console.error('FAIL: bounded suite exceeded 115 seconds');
  failures++;
  for (const f of fixtures) for (const child of [f.child, ...f.extraChildren]) child?.kill('SIGKILL');
}, 115000);
let failures = 0;
try {
  await Promise.all(cases.map(async runCase => {
    const start = Date.now();
    try {
      await runCase();
      console.log('PASS ' + runCase.name + ' (' + ((Date.now() - start) / 1000).toFixed(1) + 's)');
    } catch (error) {
      failures++;
      console.error('FAIL ' + runCase.name + ':', error.stack);
      if (error.cause) console.error('  cause:', error.cause.stack ?? error.cause);
    }
  }));
} finally {
  clearTimeout(watchdog);
  for (const f of fixtures) {
    await f.stop();
    if (process.env.KEEP_FAKE_MANAGED_FIXTURES === '1') console.log('FAKE fixture retained: ' + f.dir);
    else await fs.rm(f.dir, {recursive: true, force: true});
  }
}
console.log(`${cases.length - failures}/${cases.length} cases passed in ${((Date.now() - started) / 1000).toFixed(1)}s; fake adapter only, no model or transport validation.`);
process.exitCode = failures ? 1 : 0;
