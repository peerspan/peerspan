import assert from 'node:assert/strict';
import { mkdtemp, writeFile, chmod, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { readCredential, createChannel, AdapterError, channelParams } from './channel.mjs';

test('channel meta holds only strings, as Claude Code requires', () => {
  const params = channelParams({
    content: 'work',
    meta: {
      kind: 'task',
      sequence: 4,
      delegable: false,
      chain_hosts: ['host_a', 'host_b'],
      artifacts: [{ name: 'r.txt', size: 3 }],
      originator_person_id: null,
      origin_session_id: undefined
    }
  });
  assert.equal(params.content, 'work');
  assert.deepEqual(params.meta, {
    kind: 'task',
    sequence: '4',
    delegable: 'false',
    chain_hosts: '["host_a","host_b"]',
    artifacts: '[{"name":"r.txt","size":3}]'
  });
});

test('credentials must be private regular files; symlinks are refused', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'peerspan-channel-'));
  try {
    const path = join(directory, 'credential.json');
    const credential = { token: `token_${'a'.repeat(64)}`, adapter: { id: `adapter_${'c'.repeat(32)}`, session_id: `session_${'b'.repeat(32)}` } };
    await writeFile(path, JSON.stringify(credential), { mode: 0o600 });
    assert.deepEqual(await readCredential(path), credential);
    await chmod(path, 0o644);
    await assert.rejects(readCredential(path));
    await chmod(path, 0o600);
    await symlink(path, join(directory, 'link'));
    await assert.rejects(readCredential(join(directory, 'link')));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('a lost claim reconnects without forwarding uncertain content again', async () => {
  let claims = 0;
  const messages = [];
  const notifications = [];
  const sessionId = `session_${'b'.repeat(32)}`;
  const channel = createChannel({ sessionId, adapterId: `adapter_${'c'.repeat(32)}`,  pollMs: 10, log: message => messages.push(message), call: async (method, path) => {
    if (path === '/adapter/v1/connect') return { adapter_id: `adapter_${'c'.repeat(32)}`, session_id: sessionId, state: 'ready' };
    if (path === '/adapter/v1/ready') return {};
    if (path === '/adapter/v1/next') {
      claims++;
      if (claims === 1) throw new Error('claim committed but response lost');
      if (claims === 2) return { delivery: { id: `delivery_${'a'.repeat(32)}`, session_id: sessionId }, request: { content: 'another unclaimed message' } };
    }
    return null;
  } });
  // Answer the readiness hello with peerspan_ready, as the model would.
  const callTool = channel.server._requestHandlers.get('tools/call');
  channel.server.notification = async event => {
    notifications.push(event);
    if (event.params.meta.kind === 'hello')
      void callTool({ method: 'tools/call', params: { name: 'peerspan_ready', arguments: { nonce: event.params.meta.nonce } } }, {});
  };
  try {
    channel.server.oninitialized();
    channel.server.oninitialized();
    await delay(350);
    assert(claims >= 2);
    assert.equal(notifications.filter(event => event.params.meta.kind === 'hello').length, 1);
    assert.deepEqual(notifications.filter(event => event.params.meta.kind !== 'hello').map(event => event.params.content), ['another unclaimed message']);
    assert(messages.some(message => message.includes('Reconnecting the original instance')));
  } finally { await channel.stop(); }
});

test('an uncertain send returns its ID; only an explicit identical retry reuses it', async () => {
  const sessionId = `session_${'b'.repeat(32)}`;
  const sends = [];
  const channel = createChannel({ sessionId, adapterId: `adapter_${'c'.repeat(32)}`,  pollMs: 10, call: async (method, path, body) => {
    if (path === '/adapter/v1/connect') return { adapter_id: `adapter_${'c'.repeat(32)}`, session_id: sessionId, state: 'ready' };
    if (path === '/adapter/v1/send') {
      sends.push(body);
      if (sends.length === 1) throw new Error('response lost');
      return { state: 'accepted', peer_host_id: 'test-host' };
    }
    return null;
  } });
  const client = new Client({ name: 'conformance', version: '1' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  try {
    await channel.server.connect(serverTransport);
    await client.connect(clientTransport);
    const first = await client.callTool({ name: 'send', arguments: { destination: 'bob', content: 'hello' } });
    assert.equal(first.isError, true);
    const outcome = JSON.parse(first.content[0].text);
    assert.match(outcome.request_id, /^request_[0-9a-f]{32}$/);
    await delay(30);
    assert.equal(sends.length, 1);
    const retry = await client.callTool({ name: 'send', arguments: {
      destination: 'bob', content: 'hello', request_id: outcome.request_id,
    } });
    assert.equal(JSON.parse(retry.content[0].text).state, 'accepted');
    assert.deepEqual(sends[0], sends[1]);
    const invalid = await client.callTool({ name: 'send', arguments: {
      destination: 'bob', content: 'hello', peer_host_id: 'arbitrary',
    } });
    assert.equal(invalid.isError, true);
    assert.equal(sends.length, 2);
  } finally {
    await client.close();
    await channel.stop();
  }
});

test('send_status follows a send the host retries automatically', async () => {
  const sessionId = `session_${'b'.repeat(32)}`;
  const known = `request_${'1'.repeat(32)}`;
  const missing = `request_${'2'.repeat(32)}`;
  const paths = [];
  const channel = createChannel({ sessionId, adapterId: `adapter_${'c'.repeat(32)}`, pollMs: 10, call: async (method, path) => {
    if (path === '/adapter/v1/connect') return { adapter_id: `adapter_${'c'.repeat(32)}`, session_id: sessionId, state: 'ready' };
    if (path.startsWith('/adapter/v1/sends/')) {
      paths.push(`${method} ${path}`);
      if (path.endsWith(known)) return { request_id: known, destination: 'bob', state: 'unknown', attempts: 2, next_attempt_at: '2026-10-07T00:00:02Z', error: 'peer returned HTTP 503' };
      throw new AdapterError('not found', 404);
    }
    return null;
  } });
  const client = new Client({ name: 'conformance', version: '1' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  try {
    await channel.server.connect(serverTransport);
    await client.connect(clientTransport);
    const tools = (await client.listTools()).tools.map(tool => tool.name);
    assert(tools.includes('send_status'));
    const status = await client.callTool({ name: 'send_status', arguments: { request_id: known } });
    assert.equal(status.isError, undefined);
    assert.deepEqual(JSON.parse(status.content[0].text).attempts, 2);
    const absent = await client.callTool({ name: 'send_status', arguments: { request_id: missing } });
    assert.equal(JSON.parse(absent.content[0].text).state, 'not_recorded');
    for (const args of [{}, { request_id: 'request_x' }, { request_id: known, extra: 1 }]) {
      const invalid = await client.callTool({ name: 'send_status', arguments: args });
      assert.equal(invalid.isError, true);
    }
    assert.deepEqual(paths, [`GET /adapter/v1/sends/${known}`, `GET /adapter/v1/sends/${missing}`]);
  } finally {
    await client.close();
    await channel.stop();
  }
});
