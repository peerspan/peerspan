import assert from 'node:assert/strict';
import { mkdtemp, writeFile, chmod, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';
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
