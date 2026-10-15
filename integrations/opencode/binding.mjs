import { constants } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { mkdir, lstat, open, rename, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { privateJSON } from '../shared/provider.mjs';
// OpenCode tool names carry a peerspan_ prefix, once.
export const toolName = (name) => (name.startsWith('peerspan_') ? name : 'peerspan_' + name);
export function bindingPath(directory, session) {
  if (!/^ses_[a-zA-Z0-9]{20,64}$/.test(session))
    throw new Error('Invalid OpenCode session identity.');
  return join(directory, session + '.json');
}
export async function readBinding(directory, session) {
  const stat = await lstat(directory);
  if (!stat.isDirectory() || stat.uid !== process.getuid() || stat.mode & 0o077)
    throw new Error('Peerspan bindings must be in a private owned directory.');
  const result = await privateJSON(bindingPath(directory, session), 4096);
  if (
    result.version !== 1 ||
    result.session_id !== session ||
    typeof result.socket !== 'string' ||
    !result.socket.startsWith('/') ||
    typeof result.profile !== 'string' ||
    !result.profile.startsWith('/')
  )
    throw new Error('Invalid Peerspan session binding.');
  return result;
}
export async function publishBinding(directory, session, binding, { gateway } = {}) {
  await mkdir(directory, { mode: 0o700, recursive: false }).catch((error) => {
    if (error.code !== 'EEXIST') throw error;
  });
  const stat = await lstat(directory);
  if (!stat.isDirectory() || stat.uid !== process.getuid() || stat.mode & 0o077)
    throw new Error('Peerspan bindings must be in a private owned directory.');
  const path = bindingPath(directory, session);
  const flags = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW;
  let file, previous, temp, owned;
  try {
    file = await open(path, flags, 0o600);
  } catch (error) {
    if (error.code !== 'EEXIST' || gateway?.socket !== binding.socket || !(await gateway.ownsSocket()))
      throw error;
    previous = await lstat(path);
    const existing = await readBinding(directory, session);
    if (existing.profile !== binding.profile || existing.socket !== binding.socket)
      throw error;
    // The new gateway owns this socket: its predecessor could only have
    // been reclaimed after proving no listener remained. Replace the matching
    // stale binding atomically so plugin readers never see partial JSON.
    temp = path + '.tmp-' + randomBytes(16).toString('hex');
    file = await open(temp, flags, 0o600);
  }
  try {
    await file.writeFile(JSON.stringify(binding) + '\n');
    await file.sync();
    owned = await file.stat();
    if (temp) {
      const current = await lstat(path);
      if (current.dev !== previous.dev || current.ino !== previous.ino || !(await gateway.ownsSocket()))
        throw new Error('Peerspan binding changed during recovery; it was retained.');
      await rename(temp, path);
    }
  } catch (error) {
    if (!temp) await unlink(path);
    throw error;
  } finally {
    await file.close();
    if (temp) await unlink(temp).catch((error) => { if (error.code !== 'ENOENT') throw error; });
  }
  return async () => {
    const current = await readBinding(directory, session);
    const stat = await lstat(path);
    if (stat.dev !== owned.dev || stat.ino !== owned.ino ||
        current.profile !== binding.profile || current.socket !== binding.socket)
      throw new Error('Peerspan binding changed; it was retained.');
    await unlink(path);
  };
}
