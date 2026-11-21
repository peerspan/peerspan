// The private state directory: location, access token and the single-writer lock.
import { access, chmod, constants, mkdir, readFile, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { delimiter, join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';

export const LOCK_CONFLICT_EXIT = 73;
const LOCK_MARKER = 'PEERSPAN_MANAGED_LOCKED';

export const defaultState = () => join(homedir(), '.local/state/peerspan-managed');

/** Creates the state directory and its access token when absent; both stay private. */
export async function prepareState(directory) {
  const path = resolve(directory);
  await mkdir(path, { recursive: true, mode: 0o700 });
  await chmod(path, 0o700);
  const tokenFile = join(path, 'access-token');
  try {
    await writeFile(tokenFile, randomBytes(32).toString('hex') + '\n', { flag: 'wx', mode: 0o600 });
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
  }
  const token = (await readFile(tokenFile, 'utf8')).trim();
  if (!/^[a-f0-9]{64}$/.test(token)) throw new Error('Invalid private access token');
  await chmod(tokenFile, 0o600);
  return { path, token };
}

export async function findFlock() {
  const directories = [...(process.env.PATH || '').split(delimiter).filter(Boolean), '/usr/bin', '/bin'];
  for (const directory of directories) {
    const candidate = join(directory, 'flock');
    try {
      await access(candidate, constants.X_OK);
      return candidate;
    } catch {
      // Keep looking.
    }
  }
  return null;
}

/**
 * Takes the state directory's writer lock for the life of this process, or
 * exits with LOCK_CONFLICT_EXIT when another controller holds it.
 *
 * The process replaces itself with `flock --no-fork`, which takes the lock and
 * then runs this same command again: the PID is kept, no wrapper is left
 * behind, and the kernel releases the lock however the process dies. A PID
 * file could not offer that when two controllers restart at the same moment.
 */
export async function acquireLock(path) {
  if (process.platform !== 'linux' || typeof process.execve !== 'function') {
    throw new Error('Run the controller in Linux or WSL with Node 24');
  }
  const marker = path + ':' + process.pid;
  if (process.env[LOCK_MARKER] === marker) {
    delete process.env[LOCK_MARKER];
    return;
  }
  const flock = await findFlock();
  if (!flock) throw new Error('The flock utility (util-linux) is required');
  process.execve(flock,
    ['flock', '--nonblock', '--conflict-exit-code', String(LOCK_CONFLICT_EXIT), '--no-fork',
      join(path, 'runner.lock'), process.execPath, ...process.argv.slice(1)],
    { ...process.env, [LOCK_MARKER]: marker });
}
