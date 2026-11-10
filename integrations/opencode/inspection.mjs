import { realpath } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { tools } from '../shared/adapter.mjs';
import { toolName } from './binding.mjs';
const PLUGIN = /^(.*)\/releases\/[^/]+\/(share\/peerspan\/integrations\/opencode\/plugin\.mjs)$/;
const real = (path) => realpath(path).catch(() => null);
function entryPath(entry) {
  try {
    return Array.isArray(entry) && typeof entry[0] === 'string' && entry[0].startsWith('file:')
      ? fileURLToPath(entry[0])
      : null;
  } catch {
    return null;
  }
}
/** The path the plugin entry should name: the installer's stable `current`
 * link when it leads to this release's plugin, else this plugin itself. */
export async function pluginPath(plugin) {
  const own = await real(plugin);
  const match = own && PLUGIN.exec(own);
  if (match) {
    const stable = match[1] + '/current/' + match[2];
    if ((await real(stable)) === own) return stable;
  }
  return plugin;
}
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
  const own = await real(config.plugin);
  const wanted = pathToFileURL(await pluginPath(config.plugin)).href;
  let loaded = false,
    stale = null;
  for (const entry of effective.plugin ?? []) {
    const path = entryPath(entry);
    if (!path || !path.endsWith('/integrations/opencode/plugin.mjs')) continue;
    // An entry may name this plugin directly or through the stable link.
    if (own && (await real(path)) === own) {
      if (entry[1]?.bindings === config.bindings) loaded = true;
    } else stale ??= entry[0];
  }
  if (!loaded && stale)
    throw new Error(
      `OpenCode loads a Peerspan plugin from another release (${stale}). Point its plugin entry at ${wanted}, then reload OpenCode while idle.`
    );
  if (!loaded)
    throw new Error(
      `Install the Peerspan OpenCode plugin once at ${wanted} with this bindings directory, then reload OpenCode while idle.`
    );
  const ids = await client.request('GET', '/experimental/tool/ids');
  if (
    !Array.isArray(ids) ||
    !tools.every((tool) => ids.includes(toolName(tool.name)))
  )
    throw new Error('The configured Peerspan plugin tools are not loaded.');
  // OpenCode reaches the tools through its plugin API, not MCP. The server
  // version is reported whole when it fits the daemon's protocol_version
  // pattern, and otherwise as its X.Y.Z prefix.
  const version = /^[0-9A-Za-z._-]{1,48}$/.test(health.version) ? health.version : match[0];
  return { session, protocolVersion: 'opencode-plugin-' + version };
}
