import { constants } from 'node:fs';
import { mkdir, lstat, open, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { privateJSON } from '../shared/provider.mjs';
export function bindingPath(directory, session) {
  if (!/^ses_[a-zA-Z0-9]{20,64}$/.test(session))
    throw new Error('Invalid OpenCode session identity.');
  return join(directory, session + '.json');
}
export async function readBinding(directory, session) {
  const stat = await lstat(directory);
  if (!stat.isDirectory() || stat.uid !== process.getuid() || stat.mode & 0o077)
    throw new Error('Capsule bindings must be in a private owned directory.');
  const result = await privateJSON(bindingPath(directory, session), 4096);
  if (
    result.version !== 1 ||
    result.session_id !== session ||
    typeof result.socket !== 'string' ||
    !result.socket.startsWith('/')
  )
    throw new Error('Invalid Capsule session binding.');
  return result;
}
export async function publishBinding(directory, session, binding) {
  await mkdir(directory, { mode: 0o700, recursive: false }).catch((error) => {
    if (error.code !== 'EEXIST') throw error;
  });
  const stat = await lstat(directory);
  if (!stat.isDirectory() || stat.uid !== process.getuid() || stat.mode & 0o077)
    throw new Error('Capsule bindings must be in a private owned directory.');
  const path = bindingPath(directory, session);
  const file = await open(
    path,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    0o600
  );
  try {
    await file.writeFile(JSON.stringify(binding) + '\n');
    await file.sync();
  } finally {
    await file.close();
  }
  return async () => {
    const current = await readBinding(directory, session);
    if (current.profile !== binding.profile || current.socket !== binding.socket)
      throw new Error('Capsule binding changed; it was retained.');
    await unlink(path);
  };
}
