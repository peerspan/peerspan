#!/usr/bin/env node
// Peerspan Managed: local commands (contract sections 1 and 7).
import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { Alerter, alertHost, checkAlertUrl } from './lib/alerts.mjs';
import { seedClock, stamp } from './lib/clock.mjs';
import { runDoctor } from './lib/doctor.mjs';
import { Engine } from './lib/engine.mjs';
import { Peerspan } from './lib/peerspan.mjs';
import { checkSender, readWorkerState, resolveAgent, resolveRemote } from './lib/readiness.mjs';
import { startServer } from './lib/server.mjs';
import { buildSnapshot } from './lib/snapshot.mjs';
import { acquireLock, defaultState, prepareState } from './lib/state.mjs';
import { openStore } from './lib/store.mjs';

process.umask(0o077);

const HELP = `Peerspan Managed — persistent agent operations

node managed/cli.mjs serve [--state DIR] [--port 4310]
node managed/cli.mjs token [--state DIR]
node managed/cli.mjs status [--state DIR]
node managed/cli.mjs connect --name NAME --agent AGENT [--host-state DIR] [--sender-state DIR] [--state DIR]
node managed/cli.mjs connect --name NAME --worker-state FILE [--sender-state DIR] [--state DIR]
node managed/cli.mjs connect --name NAME --remote AGENT [--network ID] [--sender-state DIR] [--state DIR]
node managed/cli.mjs disconnect --id ID [--state DIR]
node managed/cli.mjs observe --name NAME --directory DIR [--state DIR]
node managed/cli.mjs unobserve --id ID [--state DIR]
node managed/cli.mjs alerts [--url URL | --off] [--state DIR]
node managed/cli.mjs doctor [--state DIR]

Connect existing Peerspan workers. This preview does not launch model sessions.
Read managed/README.md for setup, limits, and the supervised service recipe.`;

const OPTIONS = {
  serve: ['state', 'port'],
  token: ['state'],
  status: ['state'],
  connect: ['state', 'name', 'agent', 'host-state', 'worker-state', 'sender-state', 'remote', 'network'],
  disconnect: ['state', 'id'],
  observe: ['state', 'name', 'directory'],
  unobserve: ['state', 'id'],
  alerts: ['state', 'url', 'off'],
  doctor: ['state']
};
// Options that take no value.
const FLAGS = new Set(['off']);

const SHUTDOWN_GRACE_MS = 4000;

function parseCommand(argv) {
  const [command, ...rest] = argv;
  const allowed = OPTIONS[command];
  if (!allowed) throw new Error('Unknown command; use --help');
  try {
    const { values } = parseArgs({
      args: rest,
      options: Object.fromEntries(allowed.map(name => [name, { type: FLAGS.has(name) ? 'boolean' : 'string' }])),
      strict: true,
      allowPositionals: false
    });
    return { command, options: values };
  } catch {
    throw new Error('Invalid command option; use --help');
  }
}

function requireName(options) {
  const name = options.name?.trim();
  if (!name || name.length > 100) throw new Error('--name is required, 1 to 100 characters');
  return name;
}

async function version() {
  return JSON.parse(await readFile(new URL('./package.json', import.meta.url), 'utf8')).version;
}

async function connect(store, options) {
  const name = requireName(options);
  const senderState = options['sender-state'] ? resolve(options['sender-state']) : null;
  const forms = ['agent', 'worker-state', 'remote'].filter(form => options[form]);
  if (forms.length !== 1) throw new Error('Pass exactly one of --agent, --worker-state and --remote');
  if (options.network !== undefined && !options.remote) throw new Error('--network is valid only with --remote');
  let connection;
  if (options.remote) {
    if (options['host-state']) throw new Error('--host-state is valid only with --agent');
    // Only the sender's view of the worker is used: its host is on another machine (contract section 7.1).
    const remote = await resolveRemote(new Peerspan(), senderState, options.remote, options.network ?? null);
    const added = await store.addConnection({
      id: randomUUID(), name, senderState, mode: 'remote', workerState: null, hostDir: null, ...remote
    }, stamp());
    return added;
  }
  if (options.agent) {
    const hostDir = options['host-state'] ? resolve(options['host-state']) : null;
    const { hostId, agentId } = await resolveAgent(new Peerspan(), hostDir, options.agent);
    connection = { mode: 'agent', workerState: null, hostDir, hostId, agentId };
  } else {
    if (options['host-state']) throw new Error('--host-state is valid only with --agent');
    const file = resolve(options['worker-state']);
    const worker = await readWorkerState(file);
    connection = {
      mode: 'file',
      workerState: file,
      hostDir: resolve(worker.host_dir),
      hostId: worker.host_id,
      agentId: worker.agent_id
    };
  }
  await checkSender(new Peerspan(), senderState, connection.hostId);
  return store.addConnection({ id: randomUUID(), name, senderState, ...connection }, stamp());
}

async function serve(store, { token, options }) {
  const port = Number(options.port || 4310);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('Port must be an integer from 1024 to 65535');
  let tickMs = Number(process.env.MANAGED_TICK_MS || 10_000);
  if (!Number.isFinite(tickMs) || tickMs < 100) throw new Error('Invalid polling interval');
  // With the conformance clock, a moved clock must reach a scheduler pass within one second (contract section 1).
  if (process.env.MANAGED_CLOCK_FILE) tickMs = Math.min(tickMs, 1000);

  const abort = new AbortController();
  const engine = new Engine(store, new Peerspan({ signal: abort.signal }), { tickMs });
  store.onChange(() => engine.touch());
  // Without its store the controller can do nothing correctly; a supervisor restarts it.
  store.onFatal(() => {
    console.error('Storage worker stopped; exiting so that the service manager can restart the controller');
    process.exit(1);
  });
  const server = await startServer({ engine, store, token, port, version: await version() });
  engine.start();
  // Attention items announced to the operator's webhook, when one is set (contract section 8.1).
  const alerter = new Alerter({ store, engine, version: await version() });
  alerter.start();
  console.log(`Peerspan Managed ready at http://localhost:${port}\n`
    + 'Use the token command to sign in. No model sessions are started automatically.');

  await new Promise(done => {
    process.once('SIGTERM', done);
    process.once('SIGINT', done);
  });
  // Interrupted work is reconciled after the next start under the same task identities.
  const forced = setTimeout(() => process.exit(0), SHUTDOWN_GRACE_MS);
  abort.abort();
  await Promise.all([engine.stop(), server.close(), alerter.stop()]);
  clearTimeout(forced);
}

/**
 * The webhook URL an `alerts` command sets, validated before anything is opened, or undefined. With
 * `--url -` it is read from standard input, which keeps the secret out of the process list and the
 * shell's history (contract section 8.1).
 */
async function alertUrlOption(options) {
  if (options.url !== undefined && options.off) throw new Error('Pass --url or --off, not both');
  if (options.url === undefined) return undefined;
  let text = options.url;
  if (text === '-') {
    if (process.stdin.isTTY) console.error('Paste the webhook URL, then press Ctrl-D');
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    text = Buffer.concat(chunks).toString('utf8').trim();
  }
  return checkAlertUrl(text);
}

/** `alerts`: set, remove or show the webhook; nothing of its URL but the host is ever printed. */
async function alerts(store, options, url) {
  if (url !== undefined) return store.configureAlerts(url, stamp());
  if (options.off) return store.removeAlerts(stamp());
  const setting = await store.alertsSetting();
  return { configured: setting.url !== null, host: alertHost(setting.url) };
}

async function main() {
  const argv = process.argv.slice(2);
  if (!argv.length || argv[0] === '--help' || argv[0] === '-h') {
    console.log(HELP);
    return;
  }
  const { command, options } = parseCommand(argv);
  const stateDirectory = options.state || defaultState();

  if (command === 'doctor') {
    const checks = await runDoctor({ stateDirectory, peerspan: new Peerspan() });
    for (const check of checks) console.log(`${check.ok ? 'ok' : 'problem'} ${check.text}`);
    if (checks.some(check => !check.ok)) process.exitCode = 1;
    return;
  }

  // A refused alert URL changes nothing, not even the state directory (contract section 8.1).
  const alertUrl = command === 'alerts' ? await alertUrlOption(options) : undefined;
  const { path, token } = await prepareState(stateDirectory);
  if (command === 'token') {
    console.log(token);
    return;
  }
  if (command === 'serve') await acquireLock(path);

  const store = await openStore(path);
  try {
    seedClock(await store.latestTime());
    if (command === 'serve') {
      await serve(store, { token, options });
    } else if (command === 'status') {
      const engine = new Engine(store, new Peerspan());
      console.log(JSON.stringify(await buildSnapshot({ store, engine, version: await version() }), null, 2));
    } else if (command === 'connect') {
      console.log(JSON.stringify(await connect(store, options)));
    } else if (command === 'disconnect' || command === 'unobserve') {
      if (!options.id) throw new Error('--id is required');
      const remove = command === 'disconnect' ? store.removeConnection : store.removeObservation;
      console.log(JSON.stringify(await remove(options.id, stamp())));
    } else if (command === 'alerts') {
      console.log(JSON.stringify(await alerts(store, options, alertUrl)));
    } else if (command === 'observe') {
      if (!options.directory) throw new Error('--directory is required');
      const observation = { id: randomUUID(), name: requireName(options), directory: resolve(options.directory) };
      console.log(JSON.stringify(await store.addObservation(observation, stamp())));
    }
  } finally {
    await store.close();
  }
}

main().catch(error => {
  console.error(String(error.message).split('\n')[0]);
  process.exitCode = 1;
});
