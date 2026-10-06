// Owner-invoked setup and diagnostics shared by the Go and Rust CLIs.
// This program never connects an adapter or uses a peer administration API.
import { constants } from 'node:fs';
import { access, lstat, mkdir, open, readFile, realpath, rename, rmdir, unlink } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import http from 'node:http';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

class SetupError extends Error {
  constructor(code, message, status) { super(message); this.code = code; this.status = status; }
}
const fail = (code, message) => { throw new SetupError(code, message); };
const id = (value, kind) => typeof value === 'string' && new RegExp(`^${kind}_[0-9a-f]{32}$`).test(value);
const scrub = value => String(value).replace(/(?:token|instance)_[0-9a-f]{64}/g, '[redacted]').slice(0, 600);
const json = text => { try { return JSON.parse(text); } catch { fail('invalid_json', 'A configuration file contains invalid JSON.'); } };

async function privateJson(path, limit = 1048576) {
  let file;
  try {
    file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const stat = await file.stat();
    if (!stat.isFile() || (stat.mode & 0o077) !== 0 || stat.uid !== process.getuid() || stat.size > limit) {
      fail('private_file', 'Setup files must be private regular files owned by this account.');
    }
    return json(await file.readFile('utf8'));
  } catch (error) {
    if (error instanceof SetupError) throw error;
    fail('private_file', 'A private setup file is missing, unreadable, or a symbolic link.');
  } finally { await file?.close(); }
}
async function privateDirectory(path) {
  let stat;
  try { stat = await lstat(path); } catch { fail('setup_missing', 'Setup directory is missing. Run claude setup first.'); }
  if (!stat.isDirectory() || (stat.mode & 0o077) !== 0 || stat.uid !== process.getuid()) {
    fail('private_directory', 'Setup directory must be private and owned by this account.');
  }
}
async function writePrivate(path, value) {
  const temporary = `${path}.${randomBytes(8).toString('hex')}.tmp`;
  let file;
  try {
    file = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    await file.writeFile(JSON.stringify(value, null, 2) + '\n');
    await file.sync();
    await file.close(); file = undefined;
    await rename(temporary, path);
    const directory = await open(dirname(path), constants.O_RDONLY | constants.O_DIRECTORY);
    try { await directory.sync(); } finally { await directory.close(); }
  } catch {
    fail('write_failed', 'Could not save private setup files. The preparing profile is retained for recovery.');
  } finally { await file?.close(); await unlink(temporary).catch(() => {}); }
}
function call(state, method, path, body) {
  return new Promise((resolveResult, reject) => {
    const encoded = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    const request = http.request({socketPath: join(state, 'admin.sock'), method, path, agent: false,
      signal: AbortSignal.timeout(10000), headers: encoded ? {'Content-Type': 'application/json', 'Content-Length': encoded.length} : {}}, response => {
      const chunks = []; let length = 0;
      response.on('data', chunk => {
        length += chunk.length;
        if (length > 1048576) response.destroy(); else chunks.push(chunk);
      });
      response.on('error', () => reject(new SetupError('daemon_unavailable', 'Could not confirm the daemon response. Start or check the host daemon.')));
      response.on('end', () => {
        let value;
        try { value = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(Buffer.concat(chunks))); }
        catch { reject(new SetupError('daemon_response', 'The daemon returned an invalid response.')); return; }
        if (response.statusCode >= 400) {
          reject(new SetupError(value.code ?? 'daemon_error', scrub(value.error ?? 'Host request failed.'), response.statusCode));
        } else resolveResult(value);
      });
    });
    request.on('error', () => reject(new SetupError('daemon_unavailable', 'Host daemon is not reachable. Start it with capsule-host --state DIR run.')));
    request.end(encoded);
  });
}
async function executable(program) {
  const candidates = program.includes('/') ? [resolve(program)] : (process.env.PATH ?? '').split(':').map(path => join(path || '.', program));
  for (const path of candidates) {
    try { await access(path, constants.X_OK); if ((await lstat(await realpath(path))).isFile()) return await realpath(path); } catch {}
  }
  fail('claude_missing', 'Claude Code was not found. Install it or specify --claude PROGRAM.');
}
function command(program, args) {
  const result = spawnSync(program, args, {encoding: 'utf8', timeout: 10000, maxBuffer: 1048576, stdio: ['ignore', 'pipe', 'pipe']});
  return {ok: !result.error && result.status === 0, output: result.stdout ?? ''};
}
async function prerequisites(profile, checks) {
  const check = (name, ok, detail) => checks.push({name, status: ok ? 'ok' : 'error', detail});
  const nodeVersion = command(profile.node || process.execPath, ['--version']);
  const nodeMajor = Number(nodeVersion.output.trim().match(/^v(\d+)\./)?.[1]);
  check('node', nodeVersion.ok && nodeMajor >= 22, 'The configured channel executable must be Node 22 or newer.');
  let packageReady = false;
  try {
    const dependency = json(await readFile(join(dirname(profile.channel), 'node_modules/@modelcontextprotocol/sdk/package.json'), 'utf8'));
    const declared = json(await readFile(join(dirname(profile.channel), 'package.json'), 'utf8'));
    packageReady = dependency.name === '@modelcontextprotocol/sdk' && dependency.version === declared.dependencies?.['@modelcontextprotocol/sdk'];
  } catch {}
  check('channel_dependencies', packageReady, packageReady ? 'Capsule channel dependencies are installed.' : 'Run npm ci in the installed claude-channel integration directory.');
  const syntax = command(process.execPath, ['--check', profile.channel]);
  check('channel_script', syntax.ok, syntax.ok ? 'Channel script can be parsed.' : 'Channel script is missing or incompatible with this Node version.');
  let claude;
  try { claude = await executable(profile.claude || 'claude'); }
  catch { check('claude', false, 'Claude Code is missing. Install it or specify --claude PROGRAM.'); return; }
  const version = command(claude, ['--version']);
  const compatible = command(claude, ['--mcp-config', '{}', '--dangerously-load-development-channels', 'server:capsule', '--version']);
  check('claude', version.ok && compatible.ok, compatible.ok ? `Claude Code ${version.output.trim().match(/^\d+\.\d+\.\d+/)?.[0] ?? 'version unknown'} accepts the channel launch flags.` : 'This Claude Code installation does not accept the required channel launch flags.');
  const auth = command(claude, ['auth', 'status']);
  let authenticated = false, supported = false;
  try {
    const value = JSON.parse(auth.output);
    authenticated = value.loggedIn === true;
    supported = ['claude.ai', 'oauth_token', 'api_key', 'api_key_helper'].includes(value.authMethod);
  } catch {}
  check('claude_auth', authenticated && supported, !authenticated ? 'Sign in with claude auth login.' : !supported ? 'Channels require an Anthropic authentication method; third-party providers are unsupported.' : 'Claude is authenticated with an Anthropic method. Organization channel policy is verified by Claude at launch.');
  return claude;
}
function configured(profile) {
  return {state: 'configured', adapter_ready: false, directory: profile.directory, agent_id: profile.agent_id,
    session_id: profile.session_id, adapter_id: profile.adapter_id, expires_at: profile.request.expires_at,
    destinations: profile.request.routes.map(route => route.name),
    next: ['capsule-host', 'claude', 'start', '--directory', profile.directory]};
}
async function profileFrom(options) {
  const directory = resolve(options.directory);
  await privateDirectory(directory);
  const profile = await privateJson(join(directory, 'profile.json'));
  if (profile.version !== 1 || !['preparing', 'configured'].includes(profile.phase) || profile.directory !== directory ||
      !id(profile.agent_id, 'agent') || !id(profile.session_id, 'session') || profile.request?.agent_id !== profile.agent_id ||
      profile.request?.session_id !== profile.session_id || profile.request?.integration !== 'claude-code' ||
      !Array.isArray(profile.request.routes) || !['state', 'channel', 'node', 'claude'].every(key => typeof profile[key] === 'string' && isAbsolute(profile[key]))) {
    fail('profile_invalid', 'Setup profile is invalid or does not match this directory.');
  }
  if (options.state && resolve(options.state) !== profile.state) fail('state_mismatch', 'This setup belongs to another state directory. Use its recorded daemon or prepare a fresh setup.');
  if (profile.phase === 'configured' && !id(profile.adapter_id, 'adapter')) fail('profile_invalid', 'Setup profile has no valid adapter ID.');
  return profile;
}
async function host(profile) {
  const identity = await call(profile.state, 'GET', '/v1/host');
  if (identity.id !== profile.host_id) fail('host_changed', 'The daemon identity differs from the setup. Prepare a fresh setup for this host.');
  return identity;
}
async function credential(profile) {
  const value = await privateJson(join(profile.directory, 'credential.json'), 4096);
  if (!/^token_[0-9a-f]{64}$/.test(value.token) || value.adapter?.id !== profile.adapter_id || value.adapter?.session_id !== profile.session_id) {
    fail('credential_mismatch', 'Credential file does not belong to this attachment. Restore its matching private credential file.');
  }
  return value;
}
async function finish(profile, result) {
  if (result.session?.id !== profile.session_id || result.session?.agent_id !== profile.agent_id || result.credential?.adapter?.session_id !== profile.session_id || !id(result.credential?.adapter?.id, 'adapter') || !/^token_[0-9a-f]{64}$/.test(result.credential?.token)) {
    fail('daemon_response', 'The daemon response does not match the prepared attachment.');
  }
  profile.adapter_id = result.credential.adapter.id;
  await writePrivate(join(profile.directory, 'credential.json'), result.credential);
  profile.phase = 'configured';
  await writePrivate(join(profile.directory, 'profile.json'), profile);
  return profile;
}
async function recover(profile) {
  await host(profile);
  let session;
  try { session = await call(profile.state, 'GET', `/v1/sessions/${profile.session_id}`); }
  catch (error) {
    if (error.status !== 404) throw error;
    return finish(profile, await call(profile.state, 'POST', '/v1/adapters/setup', profile.request));
  }
  if (session.agent_id !== profile.agent_id || session.integration !== 'claude-code' || session.state !== 'attached') {
    fail('recovery_refused', 'The original preparing session changed or was detached. Prepare a fresh setup.');
  }
  const adapters = (await call(profile.state, 'GET', '/v1/adapters')).filter(value => value.session_id === profile.session_id);
  if (adapters.length !== 1 || adapters[0].revoked_at !== null || adapters[0].expires_at !== profile.request.expires_at || Date.parse(adapters[0].expires_at) <= Date.now()) {
    fail('recovery_refused', 'The preparing authorization is missing, changed, revoked, or expired. Inspect it before creating another setup.');
  }
  profile.adapter_id = adapters[0].id;
  const connection = await call(profile.state, 'GET', `/v1/adapters/${profile.adapter_id}/connection`);
  if (connection.state !== 'registered') fail('recovery_refused', 'The preparing attachment has already connected. It cannot be substituted or adopted by this launcher.');
  const routes = await call(profile.state, 'GET', `/v1/adapters/${profile.adapter_id}/routes`);
  const shape = route => Object.fromEntries(['name', 'peer_host_id', 'target_agent_id', 'grant_id', 'expires_at', 'max_message_bytes', 'max_messages'].map(key => [key, route[key]]));
  const ordered = values => values.map(shape).sort((a, b) => a.name.localeCompare(b.name));
  if (routes.some(route => route.revoked_at !== null) || JSON.stringify(ordered(routes)) !== JSON.stringify(ordered(profile.request.routes))) {
    fail('recovery_refused', 'The preparing destinations differ from the owner request. Inspect them before continuing.');
  }
  let secret;
  try {
    secret = await credential(profile);
    if (!(await call(profile.state, 'POST', `/v1/adapters/${profile.adapter_id}/verify-credential`, {token: secret.token})).matches) secret = undefined;
  } catch (error) { if (!['private_file', 'credential_mismatch'].includes(error.code)) throw error; }
  secret ??= await call(profile.state, 'POST', `/v1/adapters/${profile.adapter_id}/rotate`);
  return finish(profile, {session, credential: secret});
}
async function prepare(options) {
  const directory = resolve(options.directory);
  try {
    await lstat(directory);
    const existing = await profileFrom(options);
    if (existing.phase !== 'preparing') fail('setup_exists', 'This directory already has a setup. Use claude start or claude doctor, or choose a fresh directory.');
    if (existing.agent_id !== options.agent || existing.request.expires_at !== options.expires_at || JSON.stringify(await readRoutes(options)) !== JSON.stringify(existing.request.routes)) fail('setup_changed', 'Recovery must use the original agent, expiry, and destinations. Use claude start --directory DIR to resume the saved request.');
    return recover(existing);
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (!id(options.agent, 'agent') || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)$/.test(options.expires_at) || !(Date.parse(options.expires_at) > Date.now())) fail('setup_arguments', 'Use a registered agent ID and a future RFC3339 expiry.');
  const channel = await realpath(resolve(options.channel)).catch(() => fail('channel_missing', 'Installed channel.mjs is missing.'));
  const state = resolve(options.state || (process.env.XDG_STATE_HOME ? join(process.env.XDG_STATE_HOME, 'capsule/host') : join(process.env.HOME || fail('state_missing', 'Specify --state DIR.'), '.local/state/capsule/host')));
  const claude = await executable(options.claude || 'claude');
  const checks = []; await prerequisites({channel, claude}, checks);
  if (checks.some(check => check.status === 'error')) fail('prerequisites', checks.filter(check => check.status === 'error').map(check => check.detail).join(' '));
  const routes = await readRoutes(options);
  const identity = await call(state, 'GET', '/v1/host');
  await call(state, 'GET', `/v1/agents/${options.agent}`);
  const sessionId = `session_${randomBytes(16).toString('hex')}`;
  const profile = {version: 1, phase: 'preparing', directory, state, host_id: identity.id, agent_id: options.agent,
    session_id: sessionId, channel, node: process.execPath, claude,
    request: {agent_id: options.agent, session_id: sessionId, integration: 'claude-code', expires_at: options.expires_at, routes}};
  try {
    await mkdir(dirname(directory), {recursive: true, mode: 0o700});
    await mkdir(directory, {mode: 0o700});
  } catch { fail('setup_directory', 'Choose a new setup directory with a writable parent. Existing files are never overwritten.'); }
  await writePrivate(join(directory, 'profile.json'), profile);
  await writePrivate(join(directory, 'mcp.json'), {mcpServers: {capsule: {command: process.execPath, args: [channel, '--socket', join(state, 'adapter.sock'), '--credential-file', join(directory, 'credential.json')]}}});
  try { return await finish(profile, await call(state, 'POST', '/v1/adapters/setup', profile.request)); }
  catch (error) {
    if (error.status >= 400 && error.status < 500) {
      for (const file of ['profile.json', 'mcp.json']) await unlink(join(directory, file)).catch(() => {});
      await rmdir(directory).catch(() => {});
    }
    throw error;
  }
}
async function readRoutes(options) {
  let routes = [];
  if (options.routes) {
    let file;
    try {
      file = await open(resolve(options.routes), constants.O_RDONLY | constants.O_NONBLOCK);
      const stat = await file.stat();
      if (!stat.isFile() || stat.size > 1048576) fail('routes_file', 'Destination file must be a regular JSON file of at most 1 MiB.');
      routes = json(await file.readFile('utf8'));
    }
    catch (error) { if (error instanceof SetupError) throw error; fail('routes_file', 'Destination file is missing or unreadable.'); }
    finally { await file?.close(); }
    if (!Array.isArray(routes) || routes.length > 100) fail('routes_file', 'Destination file must contain an array of at most 100 routes.');
    routes = routes.map(route => {
      const keys = ['name', 'peer_host_id', 'target_agent_id', 'grant_id', 'expires_at', 'max_message_bytes', 'max_messages'];
      if (!route || Object.keys(route).some(key => !keys.includes(key) || route[key] === null)) fail('routes_file', 'A destination has unknown or null fields.');
      return {...route, expires_at: route.expires_at ?? options.expires_at, max_message_bytes: route.max_message_bytes ?? 65536, max_messages: route.max_messages ?? 100};
    });
  }
  return routes;
}
async function doctor(profile, options) {
  const checks = []; const routes = []; let connection;
  const check = (name, ok, detail) => checks.push({name, status: ok ? 'ok' : 'error', detail});
  await prerequisites({...profile, claude: options.claude || profile.claude}, checks);
  check('setup', profile.phase === 'configured', profile.phase === 'configured' ? 'Private configuration is prepared.' : 'Setup was interrupted. Resume it with claude start --directory DIR.');
  try {
    const config = await privateJson(join(profile.directory, 'mcp.json'));
    const expected = {command: profile.node, args: [profile.channel, '--socket', join(profile.state, 'adapter.sock'), '--credential-file', join(profile.directory, 'credential.json')]};
    check('mcp_config', Object.keys(config.mcpServers ?? {}).length === 1 && JSON.stringify(config.mcpServers?.capsule) === JSON.stringify(expected), 'MCP configuration must match the prepared private attachment.');
    await host(profile); check('daemon', true, 'The original host daemon is reachable.');
    if (profile.phase === 'configured') {
      const secret = await credential(profile);
      const matches = (await call(profile.state, 'POST', `/v1/adapters/${profile.adapter_id}/verify-credential`, {token: secret.token})).matches;
      check('credential', matches, matches ? 'Credential file matches the daemon.' : 'Credential file is stale. Save the result of adapter rotate atomically.');
      const adapter = await call(profile.state, 'GET', `/v1/adapters/${profile.adapter_id}`);
      const session = await call(profile.state, 'GET', `/v1/sessions/${profile.session_id}`);
      check('authorization', adapter.revoked_at === null && Date.parse(adapter.expires_at) > Date.now() && adapter.session_id === profile.session_id && session.agent_id === profile.agent_id,
        adapter.revoked_at ? 'Authorization was revoked. Prepare a fresh owner-authorized setup.' : Date.parse(adapter.expires_at) <= Date.now() ? 'Authorization expired. Token rotation does not extend its lifetime; prepare a fresh setup.' : 'Authorization belongs to the original session and has not expired.');
      connection = await call(profile.state, 'GET', `/v1/adapters/${profile.adapter_id}/connection`);
      check('adapter_connection', connection.state === 'ready', {
        registered: 'Configuration exists but no adapter has connected. Start the prepared Claude session and accept its channel notice.',
        offline: 'Adapter lease expired. Check the original Claude session, daemon availability, and matching rotated credential file.',
        detached: 'Owner detached this session. Prepare a fresh setup; this launcher will not reattach it.',
        revoked: 'Owner revoked this authorization. Prepare a fresh setup.',
        expired: 'Authorization expired. Prepare a fresh setup.',
        ready: 'The original adapter has a valid lease. This does not establish model availability or channel consumption.',
      }[connection.state] ?? 'Adapter state is unknown.');
      const all = await call(profile.state, 'GET', `/v1/adapters/${profile.adapter_id}/route-status`);
      for (const {route, messages_remaining: remaining} of all) {
        const status = route.revoked_at ? 'revoked' : Date.parse(route.expires_at) <= Date.now() ? 'expired' : remaining <= 0 ? 'budget_exhausted' : 'configured';
        routes.push({name: route.name, status, expires_at: route.expires_at, messages_remaining: remaining, remote_acceptance: 'unverified'});
      }
    }
  } catch (error) { check(error.code ?? 'inspection', false, error instanceof SetupError ? scrub(error.message) : 'Could not inspect this attachment.'); }
  const adapterReady = connection?.state === 'ready' && checks.every(check => check.status === 'ok');
  return {checked_at: new Date().toISOString(), directory: profile.directory, agent_id: profile.agent_id,
    session_id: profile.session_id, adapter_id: profile.adapter_id ?? null,
    adapter_ready: adapterReady, model_availability: 'unknown', channel_consumption: 'unverified',
    connection: connection ?? null, checks, destinations: routes};
}
export async function main(options) {
  if (!['setup', 'start', 'doctor'].includes(options.action) || typeof options.directory !== 'string') fail('arguments', 'Use claude setup, start, or doctor with --directory DIR.');
  const extra = options.claude_args ?? [];
  if (!Array.isArray(extra) || extra.some(arg => typeof arg !== 'string' || arg.includes('\0')) || extra.some(arg => /^--(?:mcp-config|channels|dangerously-load-development-channels)(?:=|$)/.test(arg))) {
    fail('arguments', 'Claude arguments may not override the Capsule MCP configuration or channel selection.');
  }
  const workspace = resolve(options.workspace || process.cwd());
  if (options.action === 'start' && !(await lstat(workspace).catch(() => undefined))?.isDirectory()) fail('workspace', 'Claude workspace must be an existing directory.');
  let profile = options.agent ? await prepare(options) : await profileFrom(options);
  if (options.action === 'setup') { console.log(JSON.stringify(configured(profile), null, 2)); return; }
  if (options.action === 'doctor') {
    const report = await doctor(profile, options); console.log(JSON.stringify(report, null, 2));
    if (!report.adapter_ready) process.exitCode = 1;
    return;
  }
  if (profile.phase === 'preparing') profile = await recover(profile);
  const report = await doctor(profile, options);
  const blocked = report.checks.filter(check => check.status === 'error' && check.name !== 'adapter_connection');
  if (blocked.length) fail('launch_blocked', blocked.map(check => check.detail).join(' '));
  if (report.connection?.state !== 'registered') fail('already_bound', 'This attachment has already connected or was withdrawn. Keep its original process, or prepare a fresh owner-authorized setup.');
  const config = await privateJson(join(profile.directory, 'mcp.json'));
  const server = config.mcpServers?.capsule;
  if (Object.keys(config.mcpServers ?? {}).length !== 1 || server?.command !== profile.node || JSON.stringify(server?.args) !== JSON.stringify([profile.channel, '--socket', join(profile.state, 'adapter.sock'), '--credential-file', join(profile.directory, 'credential.json')])) fail('config_changed', 'MCP configuration differs from the prepared attachment. Restore the original private configuration.');
  const claude = await executable(options.claude || profile.claude);
  const args = ['--mcp-config', join(profile.directory, 'mcp.json'), '--dangerously-load-development-channels', 'server:capsule',
    '--allowedTools', 'mcp__capsule__list_destinations,mcp__capsule__send,mcp__capsule__send_status,mcp__capsule__reply', ...extra];
  console.error(`Capsule setup: ${profile.directory}`);
  process.chdir(workspace);
  if (process.execve) { process.execve(claude, [claude, ...args], process.env); return; }
  const child = spawn(claude, args, {stdio: 'inherit'});
  process.on('SIGINT', () => {}); // The foreground child receives terminal SIGINT.
  process.on('SIGTERM', () => child.kill('SIGTERM'));
  await new Promise((resolveExit, reject) => { child.on('error', reject); child.on('exit', (code, signal) => { process.exitCode = code ?? (signal ? 1 : 0); resolveExit(); }); });
}
if (import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try { await main(JSON.parse(process.argv[2])); }
  catch (error) {
    console.error(JSON.stringify({code: error.code ?? 'setup_failed', error: error instanceof SetupError ? scrub(error.message) : 'Setup failed; inspect the private setup directory and host daemon.'}));
    process.exitCode = 1;
  }
}
