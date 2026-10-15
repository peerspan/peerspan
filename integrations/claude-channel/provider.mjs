// Claude-specific configuration, checks, and launch plans. Peerspan owns the
// profile, credential, destination scopes, and all daemon lifecycle requests.
import {constants} from 'node:fs';
import {access, open, readFile, readlink, realpath, rename, unlink} from 'node:fs/promises';
import {randomBytes} from 'node:crypto';
import {basename, dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {isDeepStrictEqual} from 'node:util';
import {tools} from '../shared/adapter.mjs';

const directory = dirname(fileURLToPath(import.meta.url));
const channel = join(directory, 'channel.mjs');
// Channels need at least this Claude Code version.
const minimumVersion = [2, 1, 187];
// Claude Code negotiates the MCP protocol revision that delivers channel events.
const launchEnvironment = ['MCP_PROTOCOL_NEGOTIATION=legacy'];
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
  const compatible = command(claude, ['--mcp-config', '{}', '--dangerously-load-development-channels', 'server:peerspan', '--version']);
  check('executable', version.ok && compatible.ok, compatible.ok ? 'Claude Code accepts the channel launch flags.' : 'This Claude installation does not accept the required channel launch flags.');
  const minimum = minimumVersion.join('.');
  const parsed = version.ok ? /^(\d+)\.(\d+)\.(\d+)(?=\s|$)/.exec(version.output.trim()) : null;
  const found = parsed?.slice(1, 4).map(Number);
  const recent = found !== undefined && (found[0] - minimumVersion[0] || found[1] - minimumVersion[1] || found[2] - minimumVersion[2]) >= 0;
  check('claude_version', recent, !found ? `Could not read the Claude Code version; channels need Claude Code ${minimum} or newer.` : recent ? `Claude Code ${found.join('.')} meets the minimum ${minimum}.` : `Claude Code ${found.join('.')} is older than the minimum ${minimum}; update Claude Code.`);
  let authenticated = false, supported = false, account;
  try {
    const auth = command(claude, ['auth', 'status']);
    const value = JSON.parse(auth.output);
    authenticated = auth.ok && value.loggedIn === true;
    supported = ['claude.ai', 'oauth_token', 'api_key', 'api_key_helper'].includes(value.authMethod);
    if (value && typeof value === 'object') account = value;
  } catch {}
  check('authentication', authenticated && supported, !authenticated ? 'Sign in with claude auth login.' : !supported ? 'Channels require an Anthropic authentication method.' : 'Claude is authenticated. Organization channel policy is checked at launch.');
  // Account warnings never fail a check. The helper interface has only ok
  // and error, so a warning is an ok check whose detail starts "Warning:".
  const warnings = [];
  if (account && account.apiProvider !== undefined && account.apiProvider !== 'firstParty') warnings.push('channels are not available on this provider');
  if (account && ['team', 'enterprise'].includes(account.subscriptionType)) warnings.push('an organization Owner must enable channels');
  checks.push({name: 'claude_account', status: 'ok', detail: !account ? 'Claude account details are unavailable.' : warnings.length ? `Warning: ${warnings.join('; ')}.` : 'The Claude account can use channels.'});
}
// launchProgram runs Claude Code through env so that its environment gains
// launchEnvironment; the helper's launch plan has no environment field.
async function launchProgram(claude) {
  if (claude.includes('=')) throw new Error('The Claude executable path cannot contain "=".');
  let env;
  for (const candidate of ['env', '/usr/bin/env', '/bin/env']) {
    try { env = await executable(candidate); break; } catch {}
  }
  if (!env) throw new Error('env is missing; it sets the Claude Code launch environment.');
  // A multi-call binary (busybox, uutils) selects its applet by name.
  return {program: env, args: [...(basename(env) === 'env' ? [] : ['env']), ...launchEnvironment, claude]};
}
// peerspanExecutable names the peerspan executable running this launch: the
// CLI's own path when it passes one, otherwise this helper's parent process,
// which the CLI runs directly.
async function peerspanExecutable(context) {
  const given = context.peerspan_executable;
  if (given !== undefined) {
    if (typeof given !== 'string' || !given.startsWith('/') || given.includes('\0')) throw new Error('Invalid peerspan executable path.');
    return given;
  }
  try { return await readlink(`/proc/${process.ppid}/exe`); }
  catch { throw new Error('Could not find the peerspan executable that started this launch; update the peerspan CLI so it passes peerspan_executable.'); }
}
const shellQuote = value => `'${value.replaceAll("'", `'\\''`)}'`;
// sessionSettings adds a SessionStart hook that lists owed Peerspan work after
// /clear, compaction, or resume; it changes no global or project settings.
function sessionSettings(peerspan) {
  return {hooks: {SessionStart: [{matcher: 'clear|compact|resume',
    hooks: [{type: 'command', command: `${shellQuote(peerspan)} session pending --hook`}]}]}};
}
// writePrivate atomically replaces a 0600 file in the private profile directory.
async function writePrivate(path, content) {
  const temporary = join(dirname(path), `.${basename(path)}.${randomBytes(8).toString('hex')}`);
  const file = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    await file.writeFile(content);
    await file.sync();
  } catch (error) {
    await file.close();
    await unlink(temporary).catch(() => {});
    throw error;
  }
  await file.close();
  try { await rename(temporary, path); }
  catch (error) { await unlink(temporary).catch(() => {}); throw error; }
}
function configuration(context, state) {
  return {mcpServers: {peerspan: {command: state.node, args: [state.channel, '--socket', context.adapter_socket, '--credential-file', context.credential_file]}}};
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
  if (!Array.isArray(extra) || extra.some(arg => typeof arg !== 'string' || arg.includes('\0')) || extra.some(arg => /^--(?:mcp-config|settings|channels|dangerously-load-development-channels)(?:=|$)/.test(arg))) {
    throw new Error('Claude arguments cannot override the prepared MCP configuration, session settings, or channel selection.');
  }
  await configurationCheck(context, state, checks);
  const launcher = await launchProgram(state.executable);
  const settings = join(context.directory, 'claude-settings.json');
  await writePrivate(settings, JSON.stringify(sessionSettings(await peerspanExecutable(context))) + '\n');
  response.launch = {
    program: launcher.program,
    args: [...launcher.args, '--mcp-config', join(context.directory, 'mcp.json'), '--settings', settings, '--dangerously-load-development-channels', 'server:peerspan',
      '--allowedTools', tools.map(tool => 'mcp__peerspan__' + tool.name).join(','), ...extra],
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
