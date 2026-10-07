import { constants } from 'node:fs';
import { access, open, realpath } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { isDeepStrictEqual } from 'node:util';
export function command(program, args) {
  const result = spawnSync(program, args, {
    encoding: 'utf8',
    timeout: 10000,
    maxBuffer: 1048576,
    stdio: ['ignore', 'pipe', 'pipe']
  });
  return { ok: !result.error && result.status === 0, output: result.stdout ?? '' };
}
export async function executable(program) {
  const paths = program.includes('/')
    ? [resolve(program)]
    : (process.env.PATH ?? '').split(':').map((path) => join(path || '.', program));
  for (const path of paths) {
    try {
      await access(path, constants.X_OK);
      return await realpath(path);
    } catch {}
  }
  throw new Error('Harness executable is missing; set --option executable=PROGRAM.');
}
export async function privateJSON(path, limit = 1048576) {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.uid !== process.getuid() || stat.mode & 0o077 || stat.size > limit)
      throw new Error('Configuration must be a private regular file owned by this account.');
    try {
      return JSON.parse(await file.readFile('utf8'));
    } catch {
      throw new Error('Invalid private JSON configuration.');
    }
  } finally {
    await file.close();
  }
}
export async function configCheck(context, expected, checks) {
  let valid = false;
  try {
    valid = isDeepStrictEqual(await privateJSON(join(context.directory, 'harness.json')), expected);
  } catch {}
  checks.push({
    name: 'configuration',
    status: valid ? 'ok' : 'error',
    detail: 'Harness configuration must match this private attachment.'
  });
}
export async function provider(main) {
  try {
    const chunks = [];
    let size = 0;
    for await (const chunk of process.stdin) {
      size += chunk.length;
      if (size > 1048576) throw new Error('Integration request exceeds 1 MiB.');
      chunks.push(chunk);
    }
    const request = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (
      request.version !== 1 ||
      !['prepare', 'check', 'launch'].includes(request.operation) ||
      !request.context
    )
      throw new Error('Invalid integration request.');
    console.log(JSON.stringify(await main(request)));
  } catch (error) {
    const detail = String(error.message)
      .replace(/(?:token|instance)_[0-9a-f]{64}/g, '[redacted]')
      .slice(0, 600);
    console.log(
      JSON.stringify({ version: 1, checks: [{ name: 'configuration', status: 'error', detail }] })
    );
  }
}
