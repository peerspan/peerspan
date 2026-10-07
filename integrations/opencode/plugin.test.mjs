import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, mkdir, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Capsule } from './plugin.mjs';
import { publishBinding } from './binding.mjs';
import { toolGateway } from '../shared/tools.mjs';
import { submit } from './bridge.mjs';
import { HTTPError } from './client.mjs';
const selected = 'ses_' + 'a'.repeat(26),
  other = 'ses_' + 'b'.repeat(26);
test('trusted session context fences calls; scopes and native permission decisions remain enforced', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'capsule-opencode-')),
    bindings = join(directory, 'bindings'),
    socket = join(directory, 'tools.sock');
  let calls = 0,
    asked = 0;
  const gateway = await toolGateway(socket, selected, {
    callTool: async (name, args) => {
      calls++;
      return { content: [{ type: 'text', text: JSON.stringify({ name, args }) }] };
    }
  });
  let unpublish;
  try {
    unpublish = await publishBinding(bindings, selected, {
      version: 1,
      session_id: selected,
      socket,
      profile: '/private/credential.json'
    });
    const hooks = await Capsule({}, { bindings });
    const fn = hooks.tool.capsule_send.execute;
    const args = { destination: 'remote', content: 'hello' },
      context = {
        sessionID: selected,
        ask: async (request) => {
          asked++;
          assert.equal(request.permission, 'capsule_send');
        }
      };
    const result = JSON.parse(await fn(args, context));
    assert.equal(result.args.destination, 'remote');
    assert.match(result.args.request_id, /^request_[a-f0-9]{32}$/);
    await assert.rejects(fn(args, { ...context, sessionID: other }));
    assert.equal(calls, 1);
    await assert.rejects(
      fn(args, {
        ...context,
        ask: async () => {
          throw new Error('permission denied');
        }
      }),
      /permission denied/
    );
    assert.equal(calls, 1);
    assert.equal(asked, 1);
    await unpublish();
    unpublish = undefined;
    await assert.rejects(fn(args, context));
    assert.equal(calls, 1);
  } finally {
    await unpublish?.();
    await gateway.close();
    await rm(directory, { recursive: true, force: true });
  }
});
test('bindings cannot silently replace another attachment', async () => {
  const root = await mkdtemp(join(tmpdir(), 'capsule-binding-'));
  const dir = join(root, 'bindings');
  try {
    const clear = await publishBinding(dir, selected, {
      version: 1,
      session_id: selected,
      socket: '/socket',
      profile: '/first'
    });
    await assert.rejects(
      publishBinding(dir, selected, {
        version: 1,
        session_id: selected,
        socket: '/other',
        profile: '/second'
      }),
      { code: 'EEXIST' }
    );
    await clear();
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
test('HTTP acceptance is confirmed by the exact persisted input; preserve the current model and agent', async () => {
  const calls = [];
  let body;
  const client = {
    async request(method, path, value) {
      calls.push({ method, path });
      if (path.includes('?limit='))
        return [{ info: { agent: 'plan', model: { providerID: 'original', modelID: 'model' } } }];
      if (method === 'POST') {
        body = value;
        return null;
      }
      return { info: { id: body.messageID, sessionID: selected }, parts: body.parts };
    }
  };
  const id = await submit(
    client,
    { session_id: selected },
    { content: 'external', meta: { kind: 'message' } }
  );
  assert.match(id, /^msg_[a-f0-9]{32}$/);
  assert.equal(body.agent, 'plan');
  assert.deepEqual(body.model, { providerID: 'original', modelID: 'model' });
  assert.equal(calls.filter((call) => call.method === 'POST').length, 1);
});
test('a lost asynchronous submission response is never retried', async () => {
  let posts = 0;
  const client = {
    async request(method) {
      if (method === 'GET') return [];
      posts++;
      throw new Error('response lost');
    }
  };
  await assert.rejects(
    submit(client, { session_id: selected }, { content: 'external', meta: { kind: 'message' } }),
    /response lost/
  );
  assert.equal(posts, 1);
});
