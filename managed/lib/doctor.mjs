// `doctor`: read-only checks of what the controller needs (contract section 7).
// It creates no state, starts no daemon and never prints the access token.
import { readdir, stat } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { findFlock } from './state.mjs';

async function privateState(directory) {
  let info;
  try {
    info = await stat(directory);
  } catch (error) {
    if (error.code === 'ENOENT') return { ok: true, text: 'state directory does not exist yet; serve creates it private' };
    return { ok: false, text: 'state directory cannot be read' };
  }
  if (!info.isDirectory()) return { ok: false, text: 'state path is not a directory' };
  if ((info.mode & 0o777) !== 0o700) return { ok: false, text: 'state directory is not private (expected mode 0700)' };
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const mode = (await stat(join(directory, entry.name))).mode & 0o777;
    if (mode !== (entry.isDirectory() ? 0o700 : 0o600)) {
      return { ok: false, text: `state file ${entry.name} is not private (expected mode 0600)` };
    }
  }
  return { ok: true, text: 'state directory and files are private' };
}

/** Runs every check; resolves `[{ok, text}]` in the documented order. */
export async function runDoctor({ stateDirectory, peerspan }) {
  const checks = [];
  const major = Number(process.versions.node.split('.')[0]);
  checks.push({ ok: major >= 24, text: `Node ${process.versions.node}${major >= 24 ? '' : ' (24 or later is required)'}` });
  checks.push({ ok: process.platform === 'linux', text: process.platform === 'linux' ? 'Linux' : 'Linux or WSL is required' });
  checks.push((await findFlock()) ? { ok: true, text: 'flock utility found' }
    : { ok: false, text: 'flock utility (util-linux) not found' });
  checks.push(await privateState(resolve(stateDirectory)));

  // `status` is read-only and starts nothing; any exit status proves the executable runs.
  let probe = null;
  try {
    probe = await peerspan.exec(null, ['status']);
    checks.push({ ok: true, text: 'Peerspan executable starts' });
  } catch (error) {
    checks.push({ ok: false, text: error.unavailable
      ? 'Peerspan executable not found; install Peerspan or set PEERSPAN_BIN'
      : 'Peerspan executable did not run to completion' });
  }
  if (!probe) {
    checks.push({ ok: false, text: 'Peerspan --json support could not be checked' });
  } else if (probe.code === 2 && probe.stderr.includes("unexpected argument '--json'")) {
    checks.push({ ok: false, text: 'Peerspan executable is too old: it does not accept the global --json flag; update Peerspan' });
  } else {
    checks.push({ ok: true, text: 'Peerspan accepts the global --json flag' });
  }
  return checks;
}
