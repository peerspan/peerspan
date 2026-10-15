import assert from 'node:assert/strict';
import test from 'node:test';
import http from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { proxyTool } from './tools.mjs';
test('a lost gateway response preserves the caller send ID for status and identical retry', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'peerspan-proxy-'));
  const socket = join(directory, 'tools.sock'),
    requests = [];
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    requests.push(JSON.parse(Buffer.concat(chunks)));
    if (requests.length === 1) {
      req.socket.destroy();
      return;
    }
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ content: [{ type: 'text', text: 'accepted' }] }));
  });
  await new Promise((resolve) => server.listen(socket, resolve));
  try {
    const first = await proxyTool(socket, 'original', 'send', {
      destination: 'remote',
      content: 'hello'
    });
    assert.equal(first.isError, true);
    const outcome = JSON.parse(first.content[0].text);
    assert.match(outcome.request_id, /^request_[0-9a-f]{32}$/);
    assert.equal(requests[0].arguments.request_id, outcome.request_id);
    await proxyTool(socket, 'original', 'send', {
      destination: 'remote',
      content: 'hello',
      request_id: outcome.request_id
    });
    assert.deepEqual(requests[0], requests[1]);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(directory, { recursive: true, force: true });
  }
});
