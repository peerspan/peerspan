import assert from 'node:assert/strict';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { createAdapter } from './adapter.mjs';
const adapterId = 'adapter_' + 'a'.repeat(32),
  sessionId = 'session_' + 'b'.repeat(32);
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
    task: { task_id: taskId, input: 'review it', deadline: '2099-01-01T00:00:00Z', origin },
    status: { state: 'queued', cancel_requested: false },
    sender_person_id: null,
    sender_person: null
  };
  const update = {
    delivery: { id: 'notification_' + '9'.repeat(32), session_id: sessionId, task_id: taskId, peer_host_id: 'host_w', sequence: 3 },
    event: { sequence: 3, kind: 'succeeded', state: 'succeeded', message: null, output: 'all good' }
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
    const cancel = events.find((e) => e.meta.kind === 'task_cancel_requested');
    assert.equal(cancel.meta.task_id, taskId);
    const result = events.find((e) => e.meta.kind === 'task_update');
    assert.equal(result.content, 'all good');
    assert.equal(result.meta.state, 'succeeded');
    assert.equal(result.meta.event_kind, 'succeeded');
    assert.equal(result.meta.notification_id, update.delivery.id);
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
