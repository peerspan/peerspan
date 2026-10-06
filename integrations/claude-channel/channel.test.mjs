import assert from 'node:assert/strict';
import { mkdtemp, writeFile, chmod, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { readCredential, createChannel } from './channel.mjs';

test('credentials must be private regular files; symlinks are refused', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'capsule-channel-'));
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
    if (path === '/adapter/v1/next') {
      claims++;
      if (claims === 1) throw new Error('claim committed but response lost');
      if (claims === 2) return { delivery: { id: `delivery_${'a'.repeat(32)}`, session_id: sessionId }, request: { content: 'another unclaimed message' } };
    }
    return null;
  } });
  channel.server.notification = async event => notifications.push(event);
  try {
    channel.server.oninitialized();
    channel.server.oninitialized();
    await delay(350);
    assert(claims >= 2);
    assert.deepEqual(notifications.map(event => event.params.content), ['another unclaimed message']);
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
