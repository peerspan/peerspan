// The launch plan's `terminal` (launch contract: A launch that needs a terminal), through the helper protocol of the
// harness integration contract: integration.json's command, one JSON object in and one out. The executable is a fixture,
// so no Claude Code runs and no model is called.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const bundle = dirname(fileURLToPath(import.meta.url));

const FIXTURE = `#!/bin/sh
if [ "$1" = "--version" ]; then echo "2.1.291 (fixture)"; exit 0; fi
if [ "$1" = "auth" ]; then echo '{"loggedIn":true,"authMethod":"claude.ai"}'; exit 0; fi
echo "{}"
`;

async function helper(request) {
  const manifest = JSON.parse(await readFile(join(bundle, 'integration.json'), 'utf8'));
  const [program, ...args] = manifest.command.map(part => (/^\.\.?\//.test(part) ? resolve(bundle, part) : part));
  const child = spawn(program === 'node' ? process.execPath : program, args, { stdio: ['pipe', 'pipe', 'pipe'] });
  let out = '', err = '';
  child.stdout.on('data', chunk => { out += chunk; });
  child.stderr.on('data', chunk => { err += chunk; });
  const closed = new Promise((done, failed) => { child.on('close', done); child.on('error', failed); });
  child.stdin.end(JSON.stringify(request));
  const code = await closed;
  assert.equal(code, 0, `helper exit ${code}: ${err}`);
  return JSON.parse(out);
}

async function plan(root, name, argumentsAfterDashes) {
  const directory = join(root, name);
  const workspace = join(root, 'workspace');
  await mkdir(directory, { recursive: true, mode: 0o700 }); // the core's modes for a profile, as the contract says
  await mkdir(workspace, { recursive: true });
  const claude = join(root, 'claude-fixture');
  await writeFile(claude, FIXTURE);
  await chmod(claude, 0o700);
  const context = {
    directory,
    state: join(root, 'state'),
    agent_id: `agent_${'a'.repeat(32)}`,
    session_id: `session_${'b'.repeat(32)}`,
    adapter_socket: join(root, 'state', 'adapter.sock'),
    credential_file: join(directory, 'credential.json'),
    options: { executable: claude },
    provider_state: {},
    workspace,
    arguments: argumentsAfterDashes
  };
  const prepared = await helper({ version: 1, operation: 'prepare', context });
  assert.deepEqual(prepared.checks.filter(check => check.status !== 'ok'), []);
  for (const [file, content] of Object.entries(prepared.files ?? {})) await writeFile(join(directory, file), content, { mode: 0o600 });
  const launched = await helper({
    version: 1, operation: 'launch', context: { ...context, provider_state: prepared.state ?? {} }
  });
  assert.deepEqual(launched.checks.filter(check => check.status !== 'ok'), []);
  assert.ok(isAbsolute(launched.launch.program), `program: ${launched.launch.program}`);
  return launched.launch;
}

const needing = [[], ['--name', 'x']];
const notNeeding = [['-p'], ['--print'], ['-h'], ['--help'], ['-v'], ['--version']];

test('the launch plan needs a terminal without arguments and with --name x', async () => {
  const root = await mkdtemp(join(tmpdir(), 'peerspan-plan-'));
  try {
    for (const [index, args] of needing.entries()) {
      const launch = await plan(root, `needs${index}`, args);
      assert.equal(launch.terminal, true, `arguments ${JSON.stringify(args)}: ${JSON.stringify(launch)}`);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('the launch plan leaves terminal out with -p, --print, -h, --help, -v and --version', async () => {
  const root = await mkdtemp(join(tmpdir(), 'peerspan-plan-'));
  try {
    for (const [index, args] of notNeeding.entries()) {
      const launch = await plan(root, `free${index}`, args);
      assert.ok(!('terminal' in launch), `arguments ${JSON.stringify(args)}: ${JSON.stringify(launch)}`);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
