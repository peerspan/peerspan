import { pathToFileURL } from 'node:url';
import { tools } from '../shared/adapter.mjs';
import { toolName } from './binding.mjs';
export async function inspect(client, config) {
  const health = await client.request('GET', '/global/health');
  const match = /^(\d+)\.(\d+)\.(\d+)/.exec(health.version ?? '');
  if (
    !health.healthy ||
    !match ||
    (Number(match[1]) === 1 &&
      (Number(match[2]) < 18 || (Number(match[2]) === 18 && Number(match[3]) < 31))) ||
    Number(match[1]) < 1
  )
    throw new Error('OpenCode server 1.18.31 or newer is required.');
  const session = await client.request('GET', '/session/' + encodeURIComponent(config.session_id));
  if (
    session.id !== config.session_id ||
    session.directory !== config.directory ||
    session.time?.archived !== undefined
  )
    throw new Error('Select an existing nonarchived OpenCode conversation in this workspace.');
  const effective = await client.request('GET', '/config');
  const expected = pathToFileURL(config.plugin).href;
  const loaded = (effective.plugin ?? []).some(
    (entry) =>
      Array.isArray(entry) && entry[0] === expected && entry[1]?.bindings === config.bindings
  );
  if (!loaded)
    throw new Error(
      'Install the Capsule OpenCode plugin once with this bindings directory, then reload OpenCode while idle.'
    );
  const ids = await client.request('GET', '/experimental/tool/ids');
  if (
    !Array.isArray(ids) ||
    !tools.every((tool) => ids.includes(toolName(tool.name)))
  )
    throw new Error('The configured Capsule plugin tools are not loaded.');
  return session;
}
