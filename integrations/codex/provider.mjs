import { dirname, join, resolve } from 'node:path';
import { realpath, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { command, executable, configCheck, provider } from '../shared/provider.mjs';
import { toolSocketPath } from '../shared/tools.mjs';
import { inspectExisting } from './connection.mjs';
const directory = dirname(fileURLToPath(import.meta.url)),
  bridge = join(directory, 'bridge.mjs'),
  mcp = join(directory, 'mcp.mjs');
function configuration(context, state) {
  const toolSocket = toolSocketPath(join(context.directory, 'tools.sock'));
  return {
    version: 1,
    thread_id: context.options.thread,
    codex_socket: resolve(context.options.socket),
    socket: context.adapter_socket,
    credential: context.credential_file,
    tool_socket: toolSocket,
    server_name: 'capsule_' + context.session_id.slice(8),
    mcp_entry: {
      command: state.node,
      args: [mcp, '--socket', toolSocket, '--thread', context.options.thread],
      default_tools_approval_mode: 'approve'
    }
  };
}
async function prerequisites(context, state, checks) {
  const add = (name, ok, detail) => checks.push({ name, status: ok ? 'ok' : 'error', detail });
  add(
    'node',
    Number(process.versions.node.split('.')[0]) >= 22,
    'The Codex integration requires Node 22 or newer.'
  );
  const version = command(state.executable, ['--version']);
  const match = /^codex-cli (\d+)\.(\d+)\.(\d+)/m.exec(version.output);
  add(
    'executable',
    version.ok && !!match && (Number(match[1]) > 0 || Number(match[2]) >= 160),
    'Codex CLI/backend 0.160.0 or newer is required.'
  );
  let dependencies = false;
  try {
    const installed = JSON.parse(
      await readFile(join(directory, 'node_modules/@modelcontextprotocol/sdk/package.json'), 'utf8')
    );
    dependencies = installed.version === '1.32.1';
  } catch {}
  add('dependencies', dependencies, 'Run npm ci in the codex integration directory.');
  try {
    await inspectExisting(context.options.socket, context.options.thread);
    add(
      'existing_session',
      true,
      'The selected thread is already running in the existing Codex backend.'
    );
  } catch (error) {
    add('existing_session', false, error.message);
  }
}
await provider(async ({ operation, context }) => {
  const checks = [],
    response = { version: 1, checks };
  if (
    Object.keys(context.options).some((key) => !['executable', 'thread', 'socket'].includes(key)) ||
    !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(context.options.thread) ||
    !context.options.socket?.startsWith('/') ||
    context.options.socket.includes(':')
  )
    throw new Error(
      'Select --option thread=EXISTING_UUID and --option socket=/absolute/Codex.sock; optional executable.'
    );
  let state = context.provider_state;
  if (operation === 'prepare') {
    state = {
      executable: await executable(context.options.executable ?? 'codex'),
      node: await realpath(process.execPath),
      bridge
    };
    await prerequisites(context, state, checks);
    response.state = state;
    response.files = {
      'harness.json': JSON.stringify(configuration(context, state), null, 2) + '\n'
    };
    return response;
  }
  if (
    !state ||
    state.bridge !== bridge ||
    state.node !== (await realpath(process.execPath)) ||
    typeof state.executable !== 'string'
  )
    throw new Error('Codex integration state differs from this installation.');
  if (operation === 'check') await prerequisites(context, state, checks);
  await configCheck(context, configuration(context, state), checks);
  if (operation === 'launch') {
    parseArgs({ args: context.arguments, options: { json: { type: 'boolean' } }, strict: true });
    response.launch = {
      program: state.node,
      args: [bridge, '--config', join(context.directory, 'harness.json'), ...context.arguments]
    };
  }
  return response;
});
