#!/usr/bin/env node
// Peerspan Managed: local commands (contract sections 1 and 7).
import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { seedClock, stamp } from './lib/clock.mjs';
import { runDoctor } from './lib/doctor.mjs';
import { Engine } from './lib/engine.mjs';
import { Peerspan } from './lib/peerspan.mjs';
import { checkSender, readWorkerState, resolveAgent } from './lib/readiness.mjs';
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
node managed/cli.mjs disconnect --id ID [--state DIR]
node managed/cli.mjs observe --name NAME --directory DIR [--state DIR]
node managed/cli.mjs unobserve --id ID [--state DIR]
node managed/cli.mjs doctor [--state DIR]

Connect existing Peerspan workers. This preview does not launch model sessions.
Read managed/README.md for setup, limits, and the supervised service recipe.`;

const OPTIONS = {
  serve: ['state', 'port'],
  token: ['state'],
  status: ['state'],
  connect: ['state', 'name', 'agent', 'host-state', 'worker-state', 'sender-state'],
  disconnect: ['state', 'id'],
  observe: ['state', 'name', 'directory'],
  unobserve: ['state', 'id'],
  doctor: ['state']
};

const SHUTDOWN_GRACE_MS = 4000;

function parseCommand(argv) {
  const [command, ...rest] = argv;
  const allowed = OPTIONS[command];
  if (!allowed) throw new Error('Unknown command; use --help');
  try {
    const { values } = parseArgs({
      args: rest,
      options: Object.fromEntries(allowed.map(name => [name, { type: 'string' }])),
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
  if (Boolean(options.agent) === Boolean(options['worker-state'])) {
    throw new Error('Pass exactly one of --agent and --worker-state');
  }
  let connection;
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
  const tickMs = Number(process.env.MANAGED_TICK_MS || 10_000);
  if (!Number.isFinite(tickMs) || tickMs < 100) throw new Error('Invalid polling interval');

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
  console.log(`Peerspan Managed ready at http://localhost:${port}\n`
    + 'Use the token command to sign in. No model sessions are started automatically.');

  await new Promise(done => {
    process.once('SIGTERM', done);
    process.once('SIGINT', done);
  });
  // Interrupted work is reconciled after the next start under the same task identities.
  const forced = setTimeout(() => process.exit(0), SHUTDOWN_GRACE_MS);
  abort.abort();
  await Promise.all([engine.stop(), server.close()]);
  clearTimeout(forced);
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
