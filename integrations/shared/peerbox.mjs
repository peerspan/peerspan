// The local Git work of the peerbox tools (peerbox contract, Agents), done
// under this session's own permissions. Nothing is written outside the
// agent's repository: temporary files live in its Git directory (or, for a
// repository the fetch creates, in a directory inside it) and are removed
// afterwards. No command changes the checked-out branch, the index or the
// worktree, and every Git command runs without hooks or system and global
// configuration, as the host's own peerbox Git commands do.
import { execFile } from 'node:child_process';
import { lstat, mkdir, mkdtemp, open, realpath, rm, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';

export const BUNDLE_TYPE = 'application/x-git-bundle';

// A failure with the code a tool answers in {error, message}.
export class PeerboxFailure extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

const commitPattern = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;

// The branch names a peerbox accepts (peerbox contract, Requests); Git's
// own check-ref-format runs as well.
export function validBranch(branch) {
  return (
    typeof branch === 'string' &&
    /^[A-Za-z0-9._-]{1,64}$/.test(branch) &&
    !/^[-.]/.test(branch) &&
    !branch.endsWith('.lock') &&
    !branch.includes('..')
  );
}

function environment() {
  const env = {
    LANG: 'C',
    LC_ALL: 'C',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_TERMINAL_PROMPT: '0',
    GIT_NO_REPLACE_OBJECTS: '1'
  };
  for (const name of ['PATH', 'HOME', 'TMPDIR']) if (process.env[name] !== undefined) env[name] = process.env[name];
  return env;
}

// git ARGS in DIR: its trimmed stdout, or a PeerboxFailure with CODE and
// Git's message. /dev/null as the hooks path holds no hook.
function git(dir, args, code = 'invalid') {
  return new Promise((resolveResult, reject) => {
    execFile(
      'git',
      ['-C', dir, '-c', 'core.hooksPath=/dev/null', ...args],
      { env: environment(), maxBuffer: 16 * 1024 * 1024, encoding: 'utf8' },
      (error, stdout, stderr) => {
        if (error?.code === 'ENOENT')
          return reject(new PeerboxFailure('git_missing', 'git 2.34 or later is needed on PATH'));
        if (error) {
          const text = (stderr || '').trim().slice(0, 1000) || `git exited with ${error.code}`;
          return reject(new PeerboxFailure(code, text));
        }
        resolveResult(stdout.trim());
      }
    );
  });
}

async function exists(path) {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw error;
  }
}

// The Git directory of the repository at exactly DIR (its top level, or a
// bare repository's own directory), or a PeerboxFailure.
async function repository(dir) {
  const given = await realpath(dir).catch(() => undefined);
  if (given !== undefined) {
    for (const query of ['--show-toplevel', '--absolute-git-dir']) {
      const found = await git(dir, ['rev-parse', query]).catch(() => undefined);
      if (found !== undefined && (await realpath(found).catch(() => undefined)) === given)
        return git(dir, ['rev-parse', '--absolute-git-dir']);
    }
  }
  throw new PeerboxFailure('invalid', `${dir} is not the top level of a Git repository`);
}

// The object IDs of DIR's refs under refs/peerbox/PEERBOX/, distinct, at
// most 32, with their names.
async function peerboxRefs(dir, peerbox) {
  const listed = await git(dir, ['for-each-ref', '--format=%(objectname) %(refname)', `refs/peerbox/${peerbox}/`]);
  return listed
    .split('\n')
    .filter(Boolean)
    .map((line) => {
      const [id, ref] = line.split(' ');
      return { id, ref };
    })
    .filter(({ ref }) => ref.split('/').length === 4);
}

// The object format a bundle's header names: sha1 for version 2, the
// object-format capability (default sha1) for version 3.
async function bundleFormat(file) {
  const handle = await open(file, 'r');
  try {
    const buffer = Buffer.alloc(65536);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    const lines = buffer.subarray(0, bytesRead).toString('latin1').split('\n');
    if (lines[0] === '# v2 git bundle') return 'sha1';
    if (lines[0] !== '# v3 git bundle') throw new PeerboxFailure('bundle_invalid', "the bundle's header is not a Git bundle's");
    let format = 'sha1';
    for (const line of lines.slice(1)) {
      if (!line.startsWith('@')) break;
      const value = line.startsWith('@object-format=') ? line.slice('@object-format='.length) : undefined;
      if (value === undefined) continue;
      if (value !== 'sha1' && value !== 'sha256')
        throw new PeerboxFailure('bundle_invalid', "the bundle's header is not a Git bundle's");
      format = value;
    }
    return format;
  } finally {
    await handle.close();
  }
}

// The single head of a bundle: {head, branch}, when it is exactly one
// refs/heads/BRANCH.
async function bundleHead(dir, file, code) {
  const heads = (await git(dir, ['bundle', 'list-heads', file], code)).split('\n').filter(Boolean);
  const [id, name, ...rest] = heads.length === 1 ? heads[0].split(' ') : [];
  const branch = name?.startsWith('refs/heads/') ? name.slice('refs/heads/'.length) : undefined;
  if (!commitPattern.test(id ?? '') || rest.length || !validBranch(branch)) return undefined;
  return { head: id, branch };
}

// peerbox_fetch: `have` from the repository's refs for the peerbox, the
// fetch task, then the bundle verified by digest, by `git bundle verify`,
// and fetched into a quarantine repository with transfer.fsckObjects before
// refs/peerbox/PEERBOX/BRANCH is set (peerbox contract, Fetch). operation
// submits the op and returns {value, event, taskId}; download saves a
// result artifact to a new file and returns {size, sha256}.
export async function fetchInto({ peerbox, repositoryPath, operation, download }) {
  const dir = resolve(repositoryPath);
  const present = await exists(dir);
  let gitDir = present ? await repository(dir) : undefined;
  const known = present ? await peerboxRefs(dir, peerbox) : [];
  const have = [...new Set(known.map(({ id }) => id))].slice(0, 32);
  const { value, event, taskId } = await operation({
    op: 'fetch',
    peerbox_id: peerbox,
    ...(have.length && { have })
  });
  if (!value || typeof value.head !== 'string' || !commitPattern.test(value.head))
    throw new PeerboxFailure('bundle_invalid', 'the fetch result names no head');
  if (value.bundle_sha256 === null) {
    // The repository has the head: nothing is new and no ref changes.
    const held = known.find(({ id }) => id === value.head);
    return { head: value.head, ref: held?.ref ?? null };
  }
  const listed = Array.isArray(event.artifacts) ? event.artifacts : [];
  if (
    !listed.some(
      (a) =>
        a.name === 'peerbox.bundle' &&
        a.media_type === BUNDLE_TYPE &&
        a.sha256 === value.bundle_sha256 &&
        a.size === value.size
    )
  )
    throw new PeerboxFailure('bundle_invalid', 'the fetch result names no peerbox.bundle artifact');
  if (!present) await mkdir(dir, { recursive: true });
  const scratch = await mkdtemp(join(gitDir ?? dir, present ? 'peerspan-peerbox-' : '.peerspan-peerbox-'));
  try {
    const file = join(scratch, 'peerbox.bundle');
    const saved = await download(taskId, value.bundle_sha256, file);
    if (saved.sha256 !== value.bundle_sha256 || saved.size !== value.size)
      throw new PeerboxFailure('bundle_invalid', 'the bundle does not match its digest');
    const found = await bundleHead(scratch, file, 'bundle_invalid');
    if (!found || found.head !== value.head)
      throw new PeerboxFailure('bundle_invalid', "the bundle's single ref is not refs/heads/BRANCH at the head");
    const format = await bundleFormat(file);
    if (present) {
      const own = await git(dir, ['rev-parse', '--show-object-format']);
      if (own !== format)
        throw new PeerboxFailure(
          'invalid',
          `${dir} uses the ${own} object format and the peerbox uses ${format}; fetch it into another directory`
        );
    } else {
      await git(scratch, ['init', '-q', `--object-format=${format}`, dir]);
      gitDir = await repository(dir);
    }
    await git(dir, ['bundle', 'verify', '-q', file], 'bundle_invalid');
    // The quarantine borrows the repository's objects for the bundle's
    // prerequisites.
    const quarantine = join(scratch, 'quarantine');
    await git(scratch, ['init', '-q', '--bare', `--object-format=${format}`, quarantine]);
    const objects = resolve(dir, await git(dir, ['rev-parse', '--git-path', 'objects']));
    await writeFile(join(quarantine, 'objects/info/alternates'), `${objects}\n`);
    await git(
      quarantine,
      ['-c', 'transfer.fsckObjects=true', 'fetch', '-q', '--no-write-fetch-head', file, `+refs/heads/${found.branch}:refs/quarantine/head`],
      'bundle_invalid'
    );
    const ref = `refs/peerbox/${peerbox}/${found.branch}`;
    await git(
      dir,
      [
        '-c', 'transfer.fsckObjects=true',
        '-c', 'gc.auto=0',
        '-c', 'maintenance.auto=false',
        'fetch', '-q', '--no-write-fetch-head', quarantine, `+refs/quarantine/head:${ref}`
      ],
      'bundle_invalid'
    );
    return { head: value.head, ref };
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}

// peerbox_submit's local part: the bundle of refs/heads/BRANCH without the
// history reachable from base (given, or the merge base with the one
// fetched ref of the peerbox), made in a scratch directory of the
// repository's Git directory. upload sends the file and returns its
// manifest entry. Returns {base, branch, sha256}; the file is removed.
export async function bundleBranch({ peerbox, repositoryPath, branch, base, upload }) {
  if (!validBranch(branch)) throw new PeerboxFailure('invalid', `${branch} is not a branch name a peerbox accepts`);
  const dir = resolve(repositoryPath);
  const gitDir = await repository(dir);
  await git(dir, ['check-ref-format', '--branch', branch]).catch(() => {
    throw new PeerboxFailure('invalid', `${branch} is not a branch name a peerbox accepts`);
  });
  const tip = await git(dir, ['rev-parse', '--verify', '-q', '--end-of-options', `refs/heads/${branch}^{commit}`]).catch(
    () => {
      throw new PeerboxFailure('invalid', `${dir} has no branch ${branch}`);
    }
  );
  let from;
  if (base !== undefined) {
    from = await git(dir, ['rev-parse', '--verify', '-q', '--end-of-options', `${base}^{commit}`]).catch(() => {
      throw new PeerboxFailure('invalid', `base ${base} names no commit in ${dir}`);
    });
  } else {
    const fetched = await peerboxRefs(dir, peerbox);
    if (fetched.length !== 1)
      throw new PeerboxFailure('invalid', `fetch the peerbox into ${dir} first with peerbox_fetch, or give base`);
    from = await git(dir, ['merge-base', tip, fetched[0].ref]).catch(() => {
      throw new PeerboxFailure('invalid', `${branch} has no merge base with ${fetched[0].ref}; give base`);
    });
  }
  const scratch = await mkdtemp(join(gitDir, 'peerspan-peerbox-'));
  try {
    const file = join(scratch, 'contribution.bundle');
    await git(dir, ['-c', 'pack.threads=1', 'bundle', 'create', '-q', file, `refs/heads/${branch}`, `^${from}`], 'unavailable');
    const found = await bundleHead(dir, file, 'unavailable');
    if (!found || found.branch !== branch) throw new PeerboxFailure('unavailable', 'the bundle names another ref');
    const entry = await upload(file);
    return { base: from, branch, sha256: entry.sha256 };
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}
