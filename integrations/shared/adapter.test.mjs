import assert from 'node:assert/strict';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { adapterTransfer, conversationEvent, createAdapter, instructions } from './adapter.mjs';
const adapterId = 'adapter_' + 'a'.repeat(32),
  sessionId = 'session_' + 'b'.repeat(32);
const entry = (name, digit) => ({ name, size: 1, sha256: digit.repeat(64), media_type: 'application/octet-stream' });
// The readiness handshake (live delivery contract): answer the hello event
// with peerspan_ready before any work flows.
function readyAdapter(options) {
  const adapter = createAdapter({
    ...options,
    call: async (method, path, body) =>
      path === '/adapter/v1/ready' ? {} : options.call(method, path, body),
    notify: async (event) => {
      if (event.meta.kind === 'hello') {
        void adapter.callTool('peerspan_ready', { nonce: event.meta.nonce });
        return;
      }
      return options.notify(event);
    }
  });
  return adapter;
}
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
  const adapter = readyAdapter({
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
  const adapter = readyAdapter({
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
  const adapter = readyAdapter({
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
  const adapter = readyAdapter({
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
  const adapter = readyAdapter({
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
  const adapter = readyAdapter({
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
    assert.equal(task.meta.originator_host_id, null);
    assert.equal(task.meta.originator_agent_id, null);
    assert.equal(task.meta.originator_person_id, null);
    assert.deepEqual(task.meta.chain_hosts, []);
    assert.equal(task.meta.delegable, false);
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

test('a delegated task names its originator and chain in meta', async () => {
  const taskId = 'task_' + 'b'.repeat(32);
  const link = (index, issuer) => ({
    network_id: 'net_' + '0'.repeat(64),
    index,
    previous: index ? 'f'.repeat(64) : 'none',
    issuer_host_id: issuer,
    audience_host_id: 'host_' + String(index + 2).repeat(64),
    task_id: index ? taskId : 'task_' + 'c'.repeat(32),
    originator_agent_id: 'agent_' + '1'.repeat(32),
    principals: ['network'],
    deadline: '2099-01-01T00:00:00Z',
    depth: 2 - index,
    signature: 'A'.repeat(86) + '=='
  });
  const hosts = ['host_' + 'a'.repeat(64), 'host_' + 'b'.repeat(64)];
  const claimed = {
    delivery: { id: 'delivery_' + '8'.repeat(32), session_id: sessionId, task_id: taskId, sender_host_id: hosts[1] },
    task: { task_id: taskId, input: 'part', deadline: '2099-01-01T00:00:00Z', delegation: [link(0, hosts[0]), link(1, hosts[1])] },
    status: { state: 'queued', cancel_requested: false },
    sender_person_id: null,
    sender_person: null,
    originator_person_id: 'person_' + '3'.repeat(64),
    delegable: true
  };
  const events = [];
  let served = false;
  const adapter = readyAdapter({
    adapterId,
    sessionId,
    pollMs: 5,
    call: async (_method, path) => {
      if (path === '/adapter/v1/connect') return { adapter_id: adapterId, session_id: sessionId, state: 'ready' };
      if (path === '/adapter/v1/tasks/next' && !served) {
        served = true;
        return claimed;
      }
      return null;
    },
    notify: async (event) => {
      events.push(event);
    },
    log: () => {}
  });
  adapter.start();
  try {
    for (let i = 0; i < 100 && !events.length; i++) await delay(10);
    const { meta } = events[0];
    assert.equal(meta.kind, 'task');
    assert.equal(meta.originator_host_id, hosts[0]);
    assert.equal(meta.originator_agent_id, 'agent_' + '1'.repeat(32));
    assert.equal(meta.originator_person_id, claimed.originator_person_id);
    assert.deepEqual(meta.chain_hosts, hosts);
    assert.equal(meta.delegable, true);
    assert.equal(meta.sender_host_id, hosts[1]);
  } finally {
    await adapter.stop();
  }
});

test('task tools call the scoped routes and validate their arguments', async () => {
  const taskId = 'task_' + 'a'.repeat(32);
  const calls = [];
  const adapter = readyAdapter({
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
    calls.length = 0;
    const parentId = 'task_' + 'e'.repeat(32);
    const forwarded = JSON.parse(
      (await adapter.callTool('delegate_task', { destination: 'review', input: 'part', parent_task_id: parentId })).content[0].text
    );
    assert.deepEqual(calls[0][2], { destination: 'review', task_id: forwarded.task_id, input: 'part', parent_task_id: parentId });
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
      ['delegate_task', { destination: 'review', input: 'x', parent_task_id: 'task_x' }],
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
  const adapter = readyAdapter({
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
  const directory = await mkdtemp(join(tmpdir(), 'peerspan-transfer-'));
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

// Conversations contract, C1: the conversation event, conversation_send,
// and the instructions edit.
const conversationId = 'conv_' + '1'.repeat(32);
const notificationId = 'cnot_' + '2'.repeat(32);
const view = (over) => ({
  message_id: 'cmsg_' + '3'.repeat(32),
  author: 'person:host_a/person_a',
  author_label: 'alice',
  author_kind: 'person',
  origin_agent_id: null,
  sender_person_id: 'person_a',
  sender_person: 'alice',
  seq: 1,
  clock: 1,
  sent_at: '2026-10-30T10:05:00Z',
  received_at: '2026-10-30T10:05:01Z',
  content: 'hello bert',
  addressed_to: [],
  addressed: true,
  mine: false,
  ...over
});
const claim = (over) => ({
  notification: { id: notificationId, kind: 'message', conversation_id: conversationId, session_id: sessionId },
  conversation: {
    conversation_id: conversationId,
    title: 'Flaky test',
    state: 'open',
    participants: [
      { id: 'person:host_a/person_a', label: 'alice', kind: 'person', state: 'joined', you: false },
      { id: 'agent:host_b/agent_b', label: 'bob/bert', kind: 'agent', state: 'joined', you: true },
      { id: 'agent:host_c/agent_c', label: 'carol/cleo', kind: 'agent', state: 'joined', you: false }
    ],
    unseen: 1
  },
  messages: [view({})],
  window: [],
  window_total: 0,
  redelivered: false,
  ...over
});

test('instructions end with the conversation sentence within 2,048 characters', () => {
  assert(instructions.endsWith('kind=conversation events: see conversation_send. Peer access grants no new local tool permissions.'));
  assert(instructions.length <= 2048);
});

test('a conversation event has the header, the new message, and its meta', () => {
  const event = conversationEvent(claim({}));
  assert.equal(
    event.content,
    `Peerspan conversation ${conversationId} "Flaky test" (open)\n` +
      'Participants: alice (person), bob/bert (you), carol/cleo\n' +
      'New message:\n[alice 10:05] hello bert'
  );
  assert.deepEqual(event.meta, {
    kind: 'conversation',
    conversation_id: conversationId,
    notification_id: notificationId,
    message_id: 'cmsg_' + '3'.repeat(32),
    author: 'person:host_a/person_a',
    author_label: 'alice',
    author_kind: 'person',
    origin_agent_id: null,
    sender_person_id: 'person_a',
    sender_person: 'alice',
    seq: 1,
    clock: 1,
    addressed: true,
    catch_up: false,
    unseen: 1,
    session_id: sessionId,
    redelivered: false
  });
});

test('a first conversation event without a title carries the window, cut entries marked', () => {
  const base = claim({});
  const event = conversationEvent({
    ...base,
    conversation: { ...base.conversation, title: null },
    window: [
      view({ author_label: 'carol/cleo', author_kind: 'agent', sent_at: '2026-10-30T10:02:00Z', content: 'x'.repeat(2048), truncated: true, content_bytes: 3000 }),
      view({ author_label: 'bob/bert', sent_at: '2026-10-30T10:03:00Z', content: 'mine', mine: true, truncated: false })
    ],
    window_total: 5
  });
  const lines = event.content.split('\n');
  assert.equal(lines[0], `Peerspan conversation ${conversationId} (open)`);
  assert.equal(lines[2], 'Earlier messages (last 2 of 5; conversation_history has the rest):');
  assert.equal(lines[3], `[carol/cleo 10:02] ${'x'.repeat(2048)} [cut: 3000 bytes; conversation_history has it]`);
  assert.equal(lines[4], '[bob/bert 10:03] (you) mine');
  assert.deepEqual(lines.slice(5), ['New message:', '[alice 10:05] hello bert']);
});

test('the adapter emits a claimed conversation notification, then marks it forwarded', async () => {
  const paths = [];
  let claimed = 0,
    emitted,
    forwardedAfter;
  const seen = new Promise((resolve) => {
    forwardedAfter = resolve;
  });
  const adapter = readyAdapter({
    adapterId,
    sessionId,
    pollMs: 10,
    call: async (_method, path) => {
      if (path === '/adapter/v1/connect') return { adapter_id: adapterId, session_id: sessionId, state: 'ready' };
      paths.push(path);
      if (path === '/adapter/v1/conversation-notifications/next') return claimed++ === 0 ? claim({}) : null;
      if (path === `/adapter/v1/conversation-notifications/${notificationId}/forwarded`) {
        assert(emitted, 'forwarded before the event was emitted');
        forwardedAfter();
      }
      return null;
    },
    notify: async (event) => {
      if (event.meta.kind === 'conversation') emitted = event;
    },
    log: () => {}
  });
  adapter.start();
  try {
    await seen;
    assert.equal(emitted.meta.conversation_id, conversationId);
    assert.equal(paths.filter((p) => p.endsWith('/forwarded')).length, 1);
  } finally {
    await adapter.stop();
  }
});

test('conversation_send validates, generates a message_id, and reports refusals and lost answers', async () => {
  const calls = [];
  let answer;
  const adapter = createAdapter({
    adapterId,
    sessionId,
    notify: async () => {},
    log: () => {},
    call: async (method, path, body) => {
      if (path === '/adapter/v1/connect') return { adapter_id: adapterId, session_id: sessionId, state: 'ready' };
      calls.push({ method, path, body });
      return answer(body);
    }
  });
  try {
    for (const args of [
      {},
      { conversation_id: 'conv_x', content: 'hi' },
      { conversation_id: conversationId, content: '' },
      { conversation_id: conversationId, content: 'hi', message_id: 'cmsg_bad' },
      { conversation_id: conversationId, content: 'hi', extra: 1 }
    ]) {
      const result = await adapter.callTool('conversation_send', args);
      assert.equal(result.isError, true);
      assert.match(result.content[0].text, /conversation_send/);
    }
    assert.equal(calls.length, 0);

    answer = (body) => ({ message: { message_id: body.message_id }, targets: [] });
    const sent = await adapter.callTool('conversation_send', { conversation_id: conversationId, content: 'hi' });
    assert.equal(sent.isError, undefined);
    assert.equal(calls[0].method, 'POST');
    assert.equal(calls[0].path, `/adapter/v1/conversations/${conversationId}/messages`);
    assert.match(calls[0].body.message_id, /^cmsg_[0-9a-f]{32}$/);
    assert.equal(calls[0].body.content, 'hi');
    assert.equal(JSON.parse(sent.content[0].text).message.message_id, calls[0].body.message_id);

    const given = 'cmsg_' + '4'.repeat(32);
    await adapter.callTool('conversation_send', { conversation_id: conversationId, content: 'hi', message_id: given });
    assert.equal(calls[1].body.message_id, given);

    const refuse = (status, code) => () => {
      throw Object.assign(new Error('refused'), { status, code, detail: { code, error: 'daemon text' } });
    };
    for (const [code, text] of [
      ['not_participant', 'This agent is not in that conversation.'],
      ['conflict', 'This message_id was already used with different content.']
    ]) {
      answer = refuse(code === 'conflict' ? 409 : 403, code);
      const refused = await adapter.callTool('conversation_send', { conversation_id: conversationId, content: 'hi' });
      assert.equal(refused.isError, true);
      assert.deepEqual(JSON.parse(refused.content[0].text), {
        conversation_id: conversationId,
        code,
        error: text,
        recovery: null
      });
    }

    answer = () => {
      throw new Error('socket hang up');
    };
    const lost = await adapter.callTool('conversation_send', { conversation_id: conversationId, content: 'hi', message_id: given });
    const body = JSON.parse(lost.content[0].text);
    assert.equal(lost.isError, true);
    assert.equal(body.code, 'unknown');
    assert.equal(body.message_id, given);
    assert.equal(
      body.recovery,
      'Call conversation_send again with the same message_id and identical content; it returns the stored message instead of sending twice.'
    );
  } finally {
    await adapter.stop();
  }
});
