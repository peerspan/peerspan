import { dirname, join, resolve } from 'node:path';
import { readFile, realpath } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { provider, configCheck } from '../shared/provider.mjs';
import { Client, serverURL } from './client.mjs';
import { inspect } from './inspection.mjs';
import { readBinding } from './binding.mjs';
import { toolSocketPath } from '../shared/tools.mjs';
const directory = dirname(fileURLToPath(import.meta.url)),
  bridge = join(directory, 'bridge.mjs'),
  plugin = join(directory, 'plugin.mjs');
function configuration(context) {
  return {
    version: 1,
    server: serverURL(context.options.server),
    directory: resolve(context.options.directory),
    session_id: context.options.session,
    bindings: resolve(context.options.bindings),
    plugin,
    ...(context.options['auth-file'] && { auth_file: resolve(context.options['auth-file']) }),
    socket: context.adapter_socket,
    credential: context.credential_file,
    tool_socket: toolSocketPath(join(context.directory, 'tools.sock'))
  };
}
async function prerequisites(config, checks) {
  const add = (name, ok, detail) => checks.push({ name, status: ok ? 'ok' : 'error', detail });
  add(
    'node',
    Number(process.versions.node.split('.')[0]) >= 22,
    'The OpenCode sidecar requires Node 22 or newer.'
  );
  let dependencies = false;
  try {
    const installed = JSON.parse(
      await readFile(join(directory, 'node_modules/@opencode-ai/plugin/package.json'), 'utf8')
    );
    dependencies = installed.version === '1.18.31';
  } catch {}
  add('dependencies', dependencies, 'Run npm ci in the opencode integration directory.');
  const client = new Client(config);
  try {
    await inspect(client, config);
    add(
      'existing_session',
      true,
      'The existing OpenCode conversation and Peerspan plugin are available. Model availability is unverified.'
    );
  } catch (error) {
    add('existing_session', false, error.message);
  } finally {
    client.close();
  }
}
await provider(async ({ operation, context }) => {
  const checks = [],
    response = { version: 1, checks };
  if (
    Object.keys(context.options).some(
      (key) => !['server', 'session', 'directory', 'bindings', 'auth-file'].includes(key)
    ) ||
    !/^ses_[a-zA-Z0-9]{20,64}$/.test(context.options.session) ||
    !context.options.directory?.startsWith('/') ||
    !context.options.bindings?.startsWith('/')
  )
    throw new Error(
      'Select server, existing session, absolute directory and bindings; optional auth-file.'
    );
  const config = configuration(context);
  parseArgs({ args: context.arguments, options: { json: { type: 'boolean' } }, strict: true });
  if (operation === 'prepare') {
    await prerequisites(config, checks);
    try {
      const existing = await readBinding(config.bindings, config.session_id);
      if (existing.profile !== config.credential)
        throw new Error(
          'This OpenCode conversation already has a Peerspan binding. Inspect its sidecar before replacing it.'
        );
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    response.state = { node: await realpath(process.execPath), bridge };
    response.files = { 'harness.json': JSON.stringify(config, null, 2) + '\n' };
    return response;
  }
  const state = context.provider_state;
  if (!state || state.bridge !== bridge || state.node !== (await realpath(process.execPath)))
    throw new Error('OpenCode integration state differs from this installation.');
  if (operation === 'check') {
    await prerequisites(config, checks);
    let matches = false,
      missing = false;
    try {
      const binding = await readBinding(config.bindings, config.session_id);
      matches = binding.profile === config.credential && binding.socket === config.tool_socket;
    } catch (error) {
      missing = error.code === 'ENOENT';
    }
    checks.push({
      name: 'binding',
      status: matches || missing ? 'ok' : 'error',
      detail: matches
        ? 'This conversation selects the prepared private gateway.'
        : missing
          ? 'The sidecar publishes its binding at start; the native lease determines adapter readiness.'
          : 'The existing binding differs from this attachment.'
    });
  }
  await configCheck(context, config, checks);
  if (operation === 'launch') {
    response.launch = {
      program: state.node,
      args: [bridge, '--config', join(context.directory, 'harness.json'), ...context.arguments]
    };
  }
  return response;
});
