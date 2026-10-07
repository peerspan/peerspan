import { isDeepStrictEqual } from 'node:util';
function owned(entry, expected) {
  if (!entry) return false;
  const actual = { ...entry };
  if (actual.enabled === true) delete actual.enabled;
  // config/read materializes these 0.160.0 defaults even when they were absent
  // from the value written to config.toml. Preserve every nondefault owner edit.
  if (actual.environment_id === 'local') delete actual.environment_id;
  if (actual.tool_timeout_sec === null) delete actual.tool_timeout_sec;
  return isDeepStrictEqual(actual, expected);
}
async function read(rpc) {
  const result = await rpc.request('config/read', { includeLayers: true });
  const user = result.layers?.find((layer) => layer.name?.type === 'user' && !layer.name.profile);
  if (typeof user?.version !== 'string')
    throw new Error('Codex did not identify its writable user configuration.');
  return { entries: result.config?.mcp_servers ?? {}, version: user.version };
}
export async function installEntry(rpc, name, entry) {
  const current = await read(rpc);
  if (current.entries[name] && !owned(current.entries[name], entry))
    throw new Error('The selected Capsule MCP name is already configured differently.');
  await rpc.request('config/value/write', {
    keyPath: 'mcp_servers.' + name,
    value: entry,
    mergeStrategy: 'replace',
    expectedVersion: current.version
  });
}
export async function removeEntry(rpc, name, entry) {
  const current = await read(rpc);
  if (!current.entries[name]) return;
  if (!owned(current.entries[name], entry))
    throw new Error('The Capsule MCP entry was edited; it was retained.');
  await rpc.request('config/value/write', {
    keyPath: 'mcp_servers.' + name,
    value: null,
    mergeStrategy: 'replace',
    expectedVersion: current.version
  });
  await rpc.request('config/mcpServer/reload', {});
}
