import assert from 'node:assert/strict';
import test from 'node:test';
import { installEntry, removeEntry } from './configuration.mjs';
const expected = {
  command: '/node',
  args: ['/mcp', '--thread', 'existing'],
  default_tools_approval_mode: 'approve'
};
function fake(entry) {
  const calls = [];
  return {
    calls,
    async request(method, params) {
      calls.push({ method, params });
      return {
        config: { mcp_servers: entry ? { peerspan: entry } : {} },
        layers: [{ name: { type: 'user', profile: null }, version: 'version' }]
      };
    }
  };
}
test('installation changes only its unique MCP entry, with a native config version check', async () => {
  const rpc = fake();
  await installEntry(rpc, 'peerspan', expected);
  assert.deepEqual(rpc.calls[1], {
    method: 'config/value/write',
    params: {
      keyPath: 'mcp_servers.peerspan',
      value: expected,
      mergeStrategy: 'replace',
      expectedVersion: 'version'
    }
  });
});
test('a conflicting registration and an owner edit are preserved', async () => {
  for (const op of [installEntry, removeEntry]) {
    const rpc = fake({ ...expected, args: ['/other'] });
    await assert.rejects(op(rpc, 'peerspan', expected));
    assert.equal(rpc.calls.length, 1);
  }
});
test('removal touches only the matching entry and reloads without changing thread settings', async () => {
  const rpc = fake(expected);
  await removeEntry(rpc, 'peerspan', expected);
  assert.equal(rpc.calls[1].params.value, null);
  assert.equal(rpc.calls[1].params.expectedVersion, 'version');
  assert.equal(rpc.calls[2].method, 'config/mcpServer/reload');
});
test('Codex materialized defaults do not prevent removal of the original entry', async () => {
  const rpc = fake({ ...expected, enabled: true, environment_id: 'local', tool_timeout_sec: null });
  await removeEntry(rpc, 'peerspan', expected);
  assert.equal(rpc.calls[1].params.value, null);
  const edited = fake({ ...expected, tool_timeout_sec: 90 });
  await assert.rejects(removeEntry(edited, 'peerspan', expected));
  assert.equal(edited.calls.length, 1);
});
