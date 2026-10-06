// Claude-specific configuration, checks, and launch plans. Capsule owns the
// profile, credential, destination scopes, and all daemon lifecycle requests.
import {constants} from 'node:fs';
import {access, open, readFile, realpath} from 'node:fs/promises';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {isDeepStrictEqual} from 'node:util';

const directory = dirname(fileURLToPath(import.meta.url));
const channel = join(directory, 'channel.mjs');
const command = (program, args) => {
  const result = spawnSync(program, args, {encoding: 'utf8', timeout: 10000, maxBuffer: 1048576, stdio: ['ignore', 'pipe', 'pipe']});
  return {ok: !result.error && result.status === 0, output: result.stdout ?? ''};
};
async function executable(program) {
  const paths = program.includes('/') ? [resolve(program)] : (process.env.PATH ?? '').split(':').map(path => join(path || '.', program));
  for (const path of paths) {
    try { await access(path, constants.X_OK); return await realpath(path); } catch {}
  }
  throw new Error('Claude Code is missing. Install it or set --option executable=PROGRAM.');
}
async function prerequisites(state, checks) {
  const check = (name, ok, detail) => checks.push({name, status: ok ? 'ok' : 'error', detail});
  check('node', Number(process.versions.node.split('.')[0]) >= 22, 'The Claude integration requires Node 22 or newer.');
  let dependencies = false;
  try {
    const installed = JSON.parse(await readFile(join(directory, 'node_modules/@modelcontextprotocol/sdk/package.json'), 'utf8'));
    const declared = JSON.parse(await readFile(join(directory, 'package.json'), 'utf8'));
    dependencies = installed.name === '@modelcontextprotocol/sdk' && installed.version === declared.dependencies?.['@modelcontextprotocol/sdk'];
  } catch {}
  check('dependencies', dependencies, dependencies ? 'Claude channel dependencies are installed.' : 'Run npm ci in the claude-channel integration directory.');
  check('channel_script', command(process.execPath, ['--check', state.channel]).ok, 'The installed channel script must be compatible with this Node version.');
  let claude;
  try { claude = await executable(state.executable); }
  catch (error) { check('executable', false, error.message); return; }
  const version = command(claude, ['--version']);
  const compatible = command(claude, ['--mcp-config', '{}', '--dangerously-load-development-channels', 'server:capsule', '--version']);
  check('executable', version.ok && compatible.ok, compatible.ok ? 'Claude Code accepts the channel launch flags.' : 'This Claude installation does not accept the required channel launch flags.');
  let authenticated = false, supported = false;
  try {
    const auth = command(claude, ['auth', 'status']);
    const value = JSON.parse(auth.output);
    authenticated = auth.ok && value.loggedIn === true;
    supported = ['claude.ai', 'oauth_token', 'api_key', 'api_key_helper'].includes(value.authMethod);
  } catch {}
  check('authentication', authenticated && supported, !authenticated ? 'Sign in with claude auth login.' : !supported ? 'Channels require an Anthropic authentication method.' : 'Claude is authenticated. Organization channel policy is checked at launch.');
}
function configuration(context, state) {
  return {mcpServers: {capsule: {command: state.node, args: [state.channel, '--socket', context.adapter_socket, '--credential-file', context.credential_file]}}};
}
async function configurationCheck(context, state, checks) {
  let file;
  let valid = false;
  try {
    file = await open(join(context.directory, 'mcp.json'), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const stat = await file.stat();
    if (stat.isFile() && stat.uid === process.getuid() && (stat.mode & 0o077) === 0 && stat.size <= 1048576) {
      valid = isDeepStrictEqual(JSON.parse(await file.readFile('utf8')), configuration(context, state));
    }
  } catch {} finally { await file?.close(); }
  checks.push({name: 'mcp_config', status: valid ? 'ok' : 'error', detail: 'MCP configuration must match this private attachment.'});
}
async function main(request) {
  const checks = [];
  const context = request.context;
  const response = {version: 1, checks};
  if (request.version !== 1 || !['prepare', 'check', 'launch'].includes(request.operation) || !context) throw new Error('Invalid integration request.');
  if (Object.keys(context.options ?? {}).some(key => key !== 'executable')) throw new Error('Claude integration supports only --option executable=PROGRAM.');
  if (request.operation === 'prepare') {
    const state = {channel, node: await realpath(process.execPath), executable: await executable(context.options?.executable ?? 'claude')};
    await prerequisites(state, checks);
    response.state = state;
    response.files = {'mcp.json': JSON.stringify(configuration(context, state), null, 2) + '\n'};
    return response;
  }
  const state = context.provider_state;
  if (!state || state.channel !== channel || state.node !== await realpath(process.execPath) || typeof state.executable !== 'string') throw new Error('Claude integration state differs from this installation.');
  if (request.operation === 'check') {
    await prerequisites(state, checks);
    await configurationCheck(context, state, checks);
    return response;
  }
  const extra = context.arguments;
  if (!Array.isArray(extra) || extra.some(arg => typeof arg !== 'string' || arg.includes('\0')) || extra.some(arg => /^--(?:mcp-config|channels|dangerously-load-development-channels)(?:=|$)/.test(arg))) {
    throw new Error('Claude arguments cannot override the prepared MCP configuration or channel selection.');
  }
  await configurationCheck(context, state, checks);
  response.launch = {
    program: state.executable,
    args: ['--mcp-config', join(context.directory, 'mcp.json'), '--dangerously-load-development-channels', 'server:capsule',
      '--allowedTools', 'mcp__capsule__list_destinations,mcp__capsule__send,mcp__capsule__send_status,mcp__capsule__reply', ...extra],
  };
  return response;
}
try {
  const chunks = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > 1048576) throw new Error('Integration request exceeds 1 MiB.');
    chunks.push(chunk);
  }
  console.log(JSON.stringify(await main(JSON.parse(Buffer.concat(chunks).toString('utf8')))));
} catch (error) {
  const detail = String(error.message).replace(/(?:token|instance)_[0-9a-f]{64}/g, '[redacted]').slice(0, 600);
  console.log(JSON.stringify({version: 1, checks: [{name: 'configuration', status: 'error', detail}]}));
}
