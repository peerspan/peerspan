import assert from 'node:assert/strict';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { adapterTransfer, createAdapter } from './adapter.mjs';
const adapterId = 'adapter_' + 'a'.repeat(32),
  sessionId = 'session_' + 'b'.repeat(32);
const entry = (name, digit) => ({ name, size: 1, sha256: digit.repeat(64), media_type: 'application/octet-stream' });
const handoff = {
  delivery: { id: 'delivery_' + 'c'.repeat(32), session_id: sessionId },
  request: { content: 'hello' }
};
test('renew the original lease while a harness submission blocks; claim only one delivery', async () => {
  let connects = 0,
    claims = 0,
    forwarded = 0,
    release,
    submitted;
  const waiting = new Promise((resolve) => {
    release = resolve;
  });
  const started = new Promise((resolve) => {
    submitted = resolve;
  });
  const adapter = createAdapter({
    adapterId,
    sessionId,
    leaseRenewMs: 20,
    pollMs: 10,
    call: async (_method, path) => {
      if (path === '/adapter/v1/connect') {
        connects++;
        return { adapter_id: adapterId, session_id: sessionId, state: 'ready' };
      }
      if (path === '/adapter/v1/next') {
        claims++;
        return claims === 1 ? handoff : null;
      }
      if (path.endsWith('/forwarded')) forwarded++;
      return null;
    },
    notify: async () => {
      submitted();
      await waiting;
    },
    log: () => {}
  });
  adapter.start();
  try {
    await started;
    await delay(120);
    assert(connects >= 3);
    assert.equal(claims, 1);
    assert.equal(forwarded, 0);
    release();
    await delay(20);
    assert.equal(forwarded, 1);
  } finally {
    release();
    await adapter.stop();
  }
});
test('ambiguous harness submission stops without acknowledgement or automatic replay', async () => {
  let claims = 0,
    forwarded = 0,
    failed;
  const failure = new Promise((resolve) => {
    failed = resolve;
  });
  const adapter = createAdapter({
    adapterId,
    sessionId,
    pollMs: 10,
    call: async (_method, path) => {
      if (path === '/adapter/v1/connect')
        return { adapter_id: adapterId, session_id: sessionId, state: 'ready' };
      if (path === '/adapter/v1/next') {
        claims++;
        return handoff;
      }
      if (path.endsWith('/forwarded')) forwarded++;
      return null;
    },
    notify: async () => {
      throw Object.assign(new Error('acceptance unknown'), { fatal: true });
    },
    onFatal: failed,
    log: () => {}
  });
  adapter.start();
  try {
    await failure;
    await delay(30);
    assert.equal(claims, 1);
    assert.equal(forwarded, 0);
  } finally {
    await adapter.stop();
  }
});
test('a stopped adapter cannot reconnect or execute a late tool request', async () => {
  let calls = 0;
  const adapter = createAdapter({
    adapterId,
    sessionId,
    notify: async () => {},
    call: async () => {
      calls++;
    }
  });
  await adapter.stop();
  const result = await adapter.callTool('list_destinations', {});
  assert.equal(result.isError, true);
  assert.equal(calls, 0);
});

test('message and reply events carry agent origin and the sender person', async () => {
  const origin = { agent_id: 'agent_' + 'd'.repeat(32), session_id: 'session_' + 'e'.repeat(32) };
  const message = {
    delivery: { id: 'delivery_' + 'f'.repeat(32), session_id: sessionId, request_id: 'request_1', sender_host_id: 'host_x' },
    request: { content: 'hello', origin },
    sender_person_id: 'person_' + '1'.repeat(64),
    sender_person: 'bob'
  };
  const reply = {
    delivery: { id: 'delivery_' + '2'.repeat(32), session_id: sessionId, request_id: 'request_2', peer_host_id: 'host_y' },
    reply: { content: 'done', origin: { agent_id: 'agent_' + '3'.repeat(32), session_id: 'session_' + '4'.repeat(32) } }
  };
  let messages = 0, replies = 0;
  const events = [];
  const adapter = createAdapter({
    adapterId,
    sessionId,
    leaseRenewMs: 1000,
    pollMs: 5,
    call: async (_method, path) => {
      if (path === '/adapter/v1/connect') return { adapter_id: adapterId, session_id: sessionId, state: 'ready' };
      if (path === '/adapter/v1/next') return messages++ === 0 ? message : null;
      if (path === '/adapter/v1/replies/next') return replies++ === 0 ? reply : null;
      return null;
    },
    notify: async (event) => {
      events.push(event.meta);
    },
    log: () => {}
  });
  adapter.start();
  try {
    for (let i = 0; i < 100 && events.length < 2; i++) await delay(10);
    const m = events.find((e) => e.kind === 'message');
    const r = events.find((e) => e.kind === 'reply');
    assert.equal(m.origin_agent_id, origin.agent_id);
    assert.equal(m.origin_session_id, origin.session_id);
    assert.equal(m.sender_person_id, message.sender_person_id);
    assert.equal(m.sender_person, 'bob');
    assert.equal(r.origin_agent_id, reply.reply.origin.agent_id);
    assert.equal(r.origin_session_id, reply.reply.origin.session_id);
  } finally {
    await adapter.stop();
  }
});

test('events without origin or person report null', async () => {
  const events = [];
  let messages = 0;
  const adapter = createAdapter({
    adapterId,
    sessionId,
    leaseRenewMs: 1000,
    pollMs: 5,
    call: async (_method, path) => {
      if (path === '/adapter/v1/connect') return { adapter_id: adapterId, session_id: sessionId, state: 'ready' };
      if (path === '/adapter/v1/next') return messages++ === 0 ? handoff : null;
      return null;
    },
    notify: async (event) => {
      events.push(event.meta);
    },
    log: () => {}
  });
  adapter.start();
  try {
    for (let i = 0; i < 100 && events.length < 1; i++) await delay(10);
    assert.equal(events[0].origin_agent_id, null);
    assert.equal(events[0].origin_session_id, null);
    assert.equal(events[0].sender_person_id, null);
    assert.equal(events[0].sender_person, null);
  } finally {
    await adapter.stop();
  }
});

test('task, cancellation, and task update events; only updates are acknowledged', async () => {
  const taskId = 'task_' + '5'.repeat(32);
  const origin = { agent_id: 'agent_' + '6'.repeat(32), session_id: 'session_' + '7'.repeat(32) };
  const delivery = { id: 'delivery_' + '8'.repeat(32), session_id: sessionId, task_id: taskId, sender_host_id: 'host_z' };
  const claimed = {
    delivery,
    task: { task_id: taskId, input: 'review it', deadline: '2099-01-01T00:00:00Z', origin, artifacts: [entry('in.txt', '1')] },
    status: { state: 'queued', cancel_requested: false },
    sender_person_id: null,
    sender_person: null
  };
  const update = {
    delivery: { id: 'notification_' + '9'.repeat(32), session_id: sessionId, task_id: taskId, peer_host_id: 'host_w', sequence: 3 },
    event: { sequence: 3, kind: 'succeeded', state: 'succeeded', message: null, output: 'all good', artifacts: [entry('out.txt', '2')] }
  };
  const counts = {};
  const acknowledged = [];
  const events = [];
  const once = (path, value) => ((counts[path] = (counts[path] ?? 0) + 1) === 1 ? value : null);
  const adapter = createAdapter({
    adapterId,
    sessionId,
    leaseRenewMs: 1000,
    pollMs: 5,
    call: async (_method, path) => {
      if (path === '/adapter/v1/connect') return { adapter_id: adapterId, session_id: sessionId, state: 'ready' };
      if (path === '/adapter/v1/tasks/next') return once(path, claimed);
      if (path === '/adapter/v1/tasks/cancels/next') return once(path, { delivery, status: { state: 'running' } });
      if (path === '/adapter/v1/task-updates/next') return once(path, update);
      if (path.endsWith('/forwarded')) acknowledged.push(path);
      return null;
    },
    notify: async (event) => {
      events.push(event);
    },
    log: () => {}
  });
  adapter.start();
  try {
    for (let i = 0; i < 100 && (events.length < 3 || !acknowledged.length); i++) await delay(10);
    const task = events.find((e) => e.meta.kind === 'task');
    assert.equal(task.content, 'review it');
    assert.equal(task.meta.task_id, taskId);
    assert.equal(task.meta.delivery_id, delivery.id);
    assert.equal(task.meta.origin_agent_id, origin.agent_id);
    assert.equal(task.meta.origin_session_id, origin.session_id);
    assert.equal(task.meta.cancel_requested, false);
    assert.equal(task.meta.sender_person, null);
    assert.deepEqual(task.meta.artifacts, claimed.task.artifacts);
    const cancel = events.find((e) => e.meta.kind === 'task_cancel_requested');
    assert.equal(cancel.meta.task_id, taskId);
    const result = events.find((e) => e.meta.kind === 'task_update');
    assert.equal(result.content, 'all good');
    assert.equal(result.meta.state, 'succeeded');
    assert.equal(result.meta.event_kind, 'succeeded');
    assert.equal(result.meta.notification_id, update.delivery.id);
    assert.deepEqual(result.meta.artifacts, update.event.artifacts);
    assert.deepEqual(acknowledged, [`/adapter/v1/task-updates/${update.delivery.id}/forwarded`]);
    assert.equal(counts['/adapter/v1/tasks/next'] >= 2, true);
  } finally {
    await adapter.stop();
  }
});

test('task tools call the scoped routes and validate their arguments', async () => {
  const taskId = 'task_' + 'a'.repeat(32);
  const calls = [];
  const adapter = createAdapter({
    adapterId,
    sessionId,
    notify: async () => {},
    call: async (method, path, body) => {
      if (path === '/adapter/v1/connect') return { adapter_id: adapterId, session_id: sessionId, state: 'ready' };
      calls.push([method, path, body]);
      if (path === '/adapter/v1/delegations')
        return { peer_host_id: 'host_p', submit_state: 'accepted', status: { state: 'queued' }, attempts: 1, next_attempt_at: null, error: null };
      if (path.startsWith('/adapter/v1/delegations/')) throw Object.assign(new Error('not found'), { status: 404 });
      if (path.endsWith('/cancelled')) throw Object.assign(new Error('conflict'), { status: 409 });
      return { task_id: taskId, state: 'running' };
    },
    log: () => {}
  });
  try {
    assert(!(await adapter.callTool('task_accept', { task_id: taskId })).isError);
    assert(!(await adapter.callTool('task_reject', { task_id: taskId })).isError);
    assert(!(await adapter.callTool('task_progress', { task_id: taskId, message: 'half' })).isError);
    assert(!(await adapter.callTool('task_complete', { task_id: taskId, status: 'failed', output: 'no' })).isError);
    const refused = await adapter.callTool('task_cancelled', { task_id: taskId });
    assert(refused.isError && refused.content[0].text.includes('state'));
    assert.deepEqual(
      calls.map(([method, path, body]) => [method, path.replace(taskId, 'ID'), body]),
      [
        ['POST', '/adapter/v1/tasks/ID/accept', {}],
        ['POST', '/adapter/v1/tasks/ID/reject', { reason: '' }],
        ['POST', '/adapter/v1/tasks/ID/progress', { message: 'half' }],
        ['POST', '/adapter/v1/tasks/ID/complete', { status: 'failed', output: 'no' }],
        ['POST', '/adapter/v1/tasks/ID/cancelled', {}]
      ]
    );
    calls.length = 0;
    const delegated = JSON.parse((await adapter.callTool('delegate_task', { destination: 'review', input: 'please' })).content[0].text);
    assert.match(delegated.task_id, /^task_[0-9a-f]{32}$/);
    assert.equal(delegated.submit_state, 'accepted');
    assert.equal(delegated.state, 'queued');
    assert.deepEqual(calls[0][2], { destination: 'review', task_id: delegated.task_id, input: 'please' });
    const status = JSON.parse((await adapter.callTool('task_status', { task_id: taskId })).content[0].text);
    assert.equal(status.submit_state, 'not_recorded');
    calls.length = 0;
    for (const [name, args] of [
      ['task_accept', {}],
      ['task_accept', { task_id: 'task_bad' }],
      ['task_progress', { task_id: taskId }],
      ['task_progress', { task_id: taskId, message: '' }],
      ['task_complete', { task_id: taskId, status: 'done', output: 'x' }],
      ['task_reject', { task_id: taskId, extra: 1 }],
      ['delegate_task', { destination: 'Bad', input: 'x' }],
      ['delegate_task', { destination: 'review', input: 'x', task_id: 'request_' + 'a'.repeat(32) }],
      ['task_status', { task_id: 5 }]
    ]) {
      assert((await adapter.callTool(name, args)).isError, name);
    }
    assert.equal(calls.length, 0);
  } finally {
    await adapter.stop();
  }
});

test('artifact paths are uploaded before delegate_task and task_complete; artifact_save tries both scopes', async () => {
  const taskId = 'task_' + 'c'.repeat(32);
  const calls = [];
  const transfers = [];
  const adapter = createAdapter({
    adapterId,
    sessionId,
    notify: async () => {},
    call: async (method, path, body) => {
      if (path === '/adapter/v1/connect') return { adapter_id: adapterId, session_id: sessionId, state: 'ready' };
      calls.push([method, path, body]);
      if (path === '/adapter/v1/delegations')
        return { peer_host_id: 'host_p', submit_state: 'accepted', status: { state: 'queued' }, artifacts: [], attempts: 1 };
      return { task_id: taskId, state: 'succeeded' };
    },
    transfer: {
      upload: async (path, file) => {
        transfers.push(['upload', path, file]);
        if (file.endsWith('huge')) throw Object.assign(new Error('too large'), { status: 413 });
        return entry(file.split('/').pop(), String(transfers.length));
      },
      download: async (path, file) => {
        transfers.push(['download', path, file]);
        if (path.includes('/delegations/')) throw Object.assign(new Error('not found'), { status: 404 });
        if (file.endsWith('pending')) throw Object.assign(new Error('conflict'), { status: 409 });
        return { size: 3, sha256: 'd'.repeat(64) };
      }
    },
    log: () => {}
  });
  try {
    const delegated = JSON.parse(
      (await adapter.callTool('delegate_task', { destination: 'review', input: 'x', artifacts: ['/w/a.txt', '/w/b.bin'] })).content[0].text
    );
    assert.equal(delegated.submit_state, 'accepted');
    assert.deepEqual(calls[0][2].artifacts, [entry('a.txt', '1'), entry('b.bin', '2')]);
    assert.deepEqual(transfers.map((t) => t[1]), ['/adapter/v1/artifacts', '/adapter/v1/artifacts']);
    const done = await adapter.callTool('task_complete', { task_id: taskId, status: 'succeeded', output: 'ok', artifacts: ['/w/r.md'] });
    assert(!done.isError);
    assert.deepEqual(calls[1], ['POST', `/adapter/v1/tasks/${taskId}/complete`, { status: 'succeeded', output: 'ok', artifacts: [entry('r.md', '3')] }]);
    // Without artifacts, the body is unchanged.
    await adapter.callTool('task_complete', { task_id: taskId, status: 'failed', output: 'no', artifacts: [] });
    assert.deepEqual(calls[2][2], { status: 'failed', output: 'no' });
    // A failed upload submits nothing.
    calls.length = 0;
    const refused = await adapter.callTool('delegate_task', { destination: 'review', input: 'x', artifacts: ['/w/huge'] });
    assert(refused.isError && refused.content[0].text.includes('100 MiB'));
    assert.equal(calls.length, 0);
    transfers.length = 0;
    const saved = JSON.parse((await adapter.callTool('artifact_save', { task_id: taskId, sha256: 'd'.repeat(64), path: '/w/out' })).content[0].text);
    assert.deepEqual(saved, { task_id: taskId, sha256: 'd'.repeat(64), size: 3, path: '/w/out' });
    assert.deepEqual(transfers.map((t) => t[1]), [
      `/adapter/v1/delegations/${taskId}/artifacts/${'d'.repeat(64)}`,
      `/adapter/v1/tasks/${taskId}/artifacts/${'d'.repeat(64)}`
    ]);
    const pending = await adapter.callTool('artifact_save', { task_id: taskId, sha256: 'd'.repeat(64), path: '/w/pending' });
    assert(pending.isError && pending.content[0].text.includes('not been fetched'));
    for (const [name, args] of [
      ['delegate_task', { destination: 'review', input: 'x', artifacts: 'a.txt' }],
      ['delegate_task', { destination: 'review', input: 'x', artifacts: [''] }],
      ['delegate_task', { destination: 'review', input: 'x', artifacts: Array(65).fill('a') }],
      ['task_complete', { task_id: taskId, status: 'succeeded', output: 'x', artifacts: [5] }],
      ['artifact_save', { task_id: taskId, sha256: 'D'.repeat(64), path: '/w/x' }],
      ['artifact_save', { task_id: taskId, sha256: 'd'.repeat(64) }]
    ])
      assert((await adapter.callTool(name, args)).isError, JSON.stringify(args));
  } finally {
    await adapter.stop();
  }
});

test('adapterTransfer streams files over the socket and never overwrites', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'capsule-transfer-'));
  const socket = join(directory, 'adapter.sock');
  const seen = [];
  const server = http.createServer((request, response) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => {
      seen.push([request.method, request.url, request.headers.authorization, Buffer.concat(chunks).toString()]);
      if (request.method === 'POST') {
        response.writeHead(200, { 'Content-Type': 'application/json' });
        response.end(JSON.stringify(entry('in.txt', 'e')));
      } else if (request.url.endsWith('/missing')) {
        response.writeHead(409, { 'Content-Type': 'application/json' });
        response.end(JSON.stringify({ code: 'conflict', error: 'pending' }));
      } else {
        response.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': 3 });
        response.end('abc');
      }
    });
  });
  await new Promise((resolve) => server.listen(socket, resolve));
  try {
    const transfer = adapterTransfer(socket, 'token_x', 'instance_y');
    await writeFile(join(directory, 'in.txt'), 'hello');
    assert.deepEqual(await transfer.upload('/adapter/v1/artifacts', join(directory, 'in.txt')), entry('in.txt', 'e'));
    assert.deepEqual(seen[0], ['POST', '/adapter/v1/artifacts?name=in.txt', 'Bearer token_x', 'hello']);
    const out = join(directory, 'out.bin');
    const saved = await transfer.download('/adapter/v1/tasks/t/artifacts/d', out);
    assert.equal(saved.size, 3);
    assert.equal(await readFile(out, 'utf8'), 'abc');
    await assert.rejects(transfer.download('/adapter/v1/tasks/t/artifacts/d', out), { code: 'EEXIST' });
    const missing = join(directory, 'missing.bin');
    await assert.rejects(transfer.download('/adapter/v1/tasks/t/missing', missing), { status: 409 });
    await assert.rejects(readFile(missing), { code: 'ENOENT' });
    await assert.rejects(transfer.upload('/adapter/v1/artifacts', directory), /regular file/);
  } finally {
    server.close();
    await rm(directory, { recursive: true, force: true });
  }
});
