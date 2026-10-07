import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import test from 'node:test';
import { ExistingThread } from './thread.mjs';
import { RPCError } from './connection.mjs';
class Fake extends EventEmitter {
  calls = [];
  async request(method, params) {
    this.calls.push({ method, params });
    return this.reply(method, params);
  }
  reply = async (method) =>
    method === 'thread/read' || method === 'thread/resume'
      ? {
          thread: { id: 'original', status: { type: 'idle' } },
          approvalPolicy: 'on-request',
          sandbox: { type: 'workspaceWrite' }
        }
      : method === 'thread/queue/add'
        ? { queuedSubmission: { id: 'queued' } }
        : method === 'thread/queue/list'
          ? { data: [{ id: 'queued' }] }
          : { turn: { id: 'turn' } };
  complete() {
    this.emit('notification', {
      method: 'turn/completed',
      params: { threadId: 'original', turn: { id: 'turn', status: 'completed' } }
    });
  }
}
test('attachment rejoins only the running conversation, with no permissions, history, or model overrides', async () => {
  const rpc = new Fake(),
    thread = new ExistingThread(rpc, 'original');
  await thread.attach();
  assert.deepEqual(rpc.calls, [
    { method: 'thread/read', params: { threadId: 'original', includeTurns: false } },
    { method: 'thread/resume', params: { threadId: 'original', excludeTurns: true } }
  ]);
});
test('unloaded history is refused instead of starting/resuming another agent', async () => {
  const rpc = new Fake();
  rpc.reply = async () => ({ thread: { id: 'original', status: { type: 'notLoaded' } } });
  await assert.rejects(new ExistingThread(rpc, 'original').attach(), /already-running/);
  assert.equal(rpc.calls.length, 1);
});
test('busy agents accept durable input without replacing their active turn', async () => {
  const rpc = new Fake(),
    thread = new ExistingThread(rpc, 'original');
  await thread.attach();
  thread.busy = true;
  await thread.submit('external input');
  await thread.pump();
  assert.equal(rpc.calls.at(-1).method, 'thread/queue/add');
  thread.busy = false;
  await thread.pump();
  assert.equal(rpc.calls.at(-1).method, 'thread/queue/start');
});
test('completion preceding start acknowledgement never resurrects a busy turn', async () => {
  const rpc = new Fake(),
    thread = new ExistingThread(rpc, 'original');
  await thread.attach();
  await thread.submit('one');
  rpc.reply = async (method) => {
    if (method === 'thread/queue/list') return { data: [{ id: 'queued' }] };
    rpc.complete();
    return { turn: { id: 'turn' } };
  };
  await thread.pump();
  assert.equal(thread.busy, false);
});
test('a native frontend consuming queued input does not cause duplicate submission', async () => {
  const rpc = new Fake(),
    thread = new ExistingThread(rpc, 'original');
  await thread.attach();
  await thread.submit('one');
  rpc.reply = async (method) => {
    if (method === 'thread/queue/start') throw new RPCError(-32600);
    return { data: [], nextCursor: null };
  };
  await thread.pump();
  assert.equal(thread.pending.length, 0);
  assert.equal(rpc.calls.filter((c) => c.method === 'thread/queue/add').length, 1);
});
test('ambiguous queue acknowledgement is never retried', async () => {
  const rpc = new Fake(),
    thread = new ExistingThread(rpc, 'original');
  await thread.attach();
  rpc.reply = async () => {
    throw new Error('response lost');
  };
  await assert.rejects(thread.submit('one'), /response lost/);
  assert.equal(thread.pending.length, 0);
});
test('Capsule input cannot jump ahead of an owner message in the native queue', async () => {
  const rpc = new Fake(),
    thread = new ExistingThread(rpc, 'original');
  await thread.attach();
  await thread.submit('external');
  rpc.reply = async () => ({ data: [{ id: 'owner-first' }, { id: 'queued' }], nextCursor: null });
  await thread.pump();
  assert.equal(thread.pending.length, 1);
  assert(!rpc.calls.some((call) => call.method === 'thread/queue/start'));
});
