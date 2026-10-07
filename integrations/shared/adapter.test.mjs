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
