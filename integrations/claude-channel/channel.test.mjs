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
    const credential = { token: `token_${'a'.repeat(64)}`, adapter: { session_id: `session_${'b'.repeat(32)}` } };
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

test('an uncertain claim stops polling without a second mutating request', async () => {
  let claims = 0;
  const messages = [];
  const sessionId = `session_${'b'.repeat(32)}`;
  const channel = createChannel({ sessionId, pollMs: 10, log: message => messages.push(message), call: async (method, path) => {
    if (path === '/adapter/v1/session') return { id: sessionId, state: 'attached' };
    claims++;
    throw new Error('could not confirm adapter request');
  } });
  channel.server.oninitialized();
  channel.server.oninitialized();
  await delay(30);
  assert.equal(claims, 1);
  assert(messages.some(message => message.includes('polling stopped')));
  await channel.stop();
});

test('an uncertain send returns its ID; only an explicit identical retry reuses it', async () => {
  const sessionId = `session_${'b'.repeat(32)}`;
  const sends = [];
  const channel = createChannel({ sessionId, pollMs: 10, call: async (method, path, body) => {
    if (path === '/adapter/v1/session') return { id: sessionId, state: 'attached' };
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
