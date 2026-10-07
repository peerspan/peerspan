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
