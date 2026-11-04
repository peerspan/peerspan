#!/usr/bin/env bash
# Release signing for the one-line install (docs/install-contract.md).
#
#   scripts/sign-release.sh --generate KEYFILE
#   scripts/sign-release.sh DIRECTORY KEYFILE
#
# --generate creates a passphrase-encrypted Ed25519 release key. Generating a
# key gives it no trust: only the keys listed in PEERSPAN_RELEASE_KEYS in
# scripts/install.sh and scripts/install-release.sh are accepted, and changing
# that list is an owner decision (INST-6).
#
# Signing checks DIRECTORY/release.json and every asset it lists, and only then
# asks for the passphrase and writes DIRECTORY/release.json.sig. The passphrase
# is read from the terminal, or as one line of standard input when there is none
# (two matching lines for --generate). It is never passed on a command line.
set -euo pipefail

usage() {
  echo "usage: $0 --generate KEYFILE | $0 DIRECTORY KEYFILE" >&2
  exit 2
}

# read_passphrase PROMPT: sets passphrase from the terminal (without echo), or
# from one line of standard input when standard input is not a terminal.
read_passphrase() {
  passphrase=
  if [[ -t 0 ]]; then
    IFS= read -rs -p "$1" passphrase || { echo >&2; echo "no passphrase given" >&2; exit 1; }
    echo >&2
  else
    IFS= read -r passphrase || [[ -n $passphrase ]] || { echo "no passphrase on standard input" >&2; exit 1; }
  fi
  if [[ -z $passphrase ]]; then
    echo "refusing an empty passphrase" >&2
    exit 1
  fi
}

command -v node >/dev/null || { echo "Node.js 22 or later is required" >&2; exit 1; }
node_major=$(node -p "process.versions.node.split('.')[0]")
[[ $node_major -ge 22 ]] || { echo "Node.js 22 or later is required" >&2; exit 1; }

if [[ $# -eq 2 && $1 == --generate ]]; then
  keyfile=$2
  if [[ -e $keyfile || -L $keyfile ]]; then
    echo "$keyfile already exists; refusing to overwrite it" >&2
    exit 1
  fi
  read_passphrase 'New release key passphrase: '
  first=$passphrase
  read_passphrase 'Repeat the passphrase: '
  if [[ $first != "$passphrase" ]]; then
    echo "the passphrases differ" >&2
    exit 1
  fi
  # The passphrase reaches node on file descriptor 3, not in its arguments.
  node - "$keyfile" 3< <(printf '%s' "$passphrase") <<'JS'
const fs = require('node:fs');
const crypto = require('node:crypto');
const [keyfile] = process.argv.slice(2);
const passphrase = fs.readFileSync(3, 'utf8');
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const pem = privateKey.export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase });
let fd;
try {
  fd = fs.openSync(keyfile, 'wx', 0o600);
} catch (error) {
  process.stderr.write(`cannot create ${keyfile}: ${error.message}\n`);
  process.exit(1);
}
fs.fchmodSync(fd, 0o600);
fs.writeFileSync(fd, pem);
fs.fsyncSync(fd);
fs.closeSync(fd);
process.stdout.write(`${publicKey.export({ format: 'jwk' }).x}\n`);
JS
  exit 0
fi

[[ $# -eq 2 && $1 != -* ]] || usage
directory=$1
keyfile=$2
[[ -d $directory ]] || { echo "$directory is not a directory" >&2; exit 1; }
[[ -f $keyfile && -r $keyfile ]] || { echo "cannot read key file $keyfile" >&2; exit 1; }
if [[ -e $directory/release.json.sig || -L $directory/release.json.sig ]]; then
  echo "$directory/release.json.sig already exists; refusing to replace it" >&2
  exit 1
fi

# Every check before the passphrase. Prints the SHA-256 of the checked
# release.json, so the signing step signs exactly the bytes that were checked.
checked=$(node - "$directory" <<'JS'
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const [directory] = process.argv.slice(2);
const fail = (reason) => {
  process.stderr.write(`${reason}\n`);
  process.exit(1);
};

let data;
try {
  data = fs.readFileSync(path.join(directory, 'release.json'));
} catch {
  fail('release.json: missing or unreadable');
}
if (data.length > 65536) fail('release.json: invalid manifest (larger than 64 KiB)');
let manifest;
try {
  manifest = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(data));
} catch {
  fail('release.json: invalid manifest (not UTF-8 JSON)');
}
const isObject = (value) => typeof value === 'object' && value !== null && !Array.isArray(value);
if (!isObject(manifest)) fail('release.json: invalid manifest (not a JSON object)');
for (const member of ['format', 'name', 'version', 'source_revision', 'assets']) {
  if (!Object.hasOwn(manifest, member)) fail(`release.json: invalid manifest (no ${member})`);
}
if (manifest.format !== 1) fail('release.json: invalid manifest (format is not 1)');
if (manifest.name !== 'peerspan') fail('release.json: invalid manifest (name is not "peerspan")');
const { version, source_revision: revision, assets } = manifest;
if (typeof version !== 'string' || !/^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$/.test(version)) {
  fail('release.json: invalid manifest (malformed version)');
}
if (typeof revision !== 'string' || !/^[0-9a-f]{40}$/.test(revision)) {
  fail('release.json: invalid manifest (malformed source_revision)');
}
if (!isObject(assets)) fail('release.json: invalid manifest (assets is not an object)');
for (const [name, digest] of Object.entries(assets)) {
  if (!/^[A-Za-z0-9._+-]+$/.test(name) || name === '.' || name === '..') {
    fail('release.json: invalid manifest (malformed asset name)');
  }
  if (typeof digest !== 'string' || !/^[0-9a-f]{64}$/.test(digest)) {
    fail(`release.json: invalid manifest (malformed digest for ${name})`);
  }
}

// A release lists exactly its two host archives, two helper archives and
// install-release.sh.
const expected = [];
for (const arch of ['amd64', 'arm64']) {
  expected.push(`peerspan-${version}-linux-${arch}-rust.tar.gz`);
  expected.push(`peerspan-helper-${version}-linux-${arch}.tar.gz`);
}
expected.push('install-release.sh');
const listed = Object.keys(assets);
if (listed.length !== expected.length || !expected.every((name) => Object.hasOwn(assets, name))) {
  fail(`release.json: assets must be exactly ${expected.join(', ')}`);
}

for (const name of expected) {
  const file = path.join(directory, name);
  let bytes;
  try {
    if (!fs.lstatSync(file).isFile()) fail(`${name}: not a regular file`);
    bytes = fs.readFileSync(file);
  } catch {
    fail(`${name}: missing from ${directory}`);
  }
  const actual = crypto.createHash('sha256').update(bytes).digest('hex');
  if (actual !== assets[name]) fail(`${name}: digest mismatch (listed ${assets[name]}, got ${actual})`);
  if (name === 'install-release.sh') continue;

  const host = name.match(/^peerspan-(.+)-linux-(amd64|arm64)-rust\.tar\.gz$/);
  const arch = host ? host[2] : name.match(/-linux-(amd64|arm64)\.tar\.gz$/)[1];
  const root = name.slice(0, -'.tar.gz'.length);
  const read = spawnSync('tar', ['-xOzf', file, `${root}/RELEASE.json`], { maxBuffer: 1 << 20 });
  let release;
  try {
    if (read.status !== 0) throw new Error();
    release = JSON.parse(read.stdout.toString('utf8'));
  } catch {
    fail(`${name}: cannot read ${root}/RELEASE.json`);
  }
  const problems = [];
  if (!isObject(release)) problems.push('not a JSON object');
  else {
    if (release.version !== version) problems.push(`version ${JSON.stringify(release.version)}`);
    if (release.source_revision !== revision) problems.push(`source_revision ${JSON.stringify(release.source_revision)}`);
    if (release.source_dirty !== false) problems.push(`source_dirty ${JSON.stringify(release.source_dirty)}`);
    if (release.architecture !== arch) problems.push(`architecture ${JSON.stringify(release.architecture)}`);
    if (host && release.implementation !== 'rust') problems.push(`implementation ${JSON.stringify(release.implementation)}`);
  }
  if (problems.length > 0) fail(`${name}: RELEASE.json disagrees with release.json: ${problems.join(', ')}`);
}
process.stdout.write(crypto.createHash('sha256').update(data).digest('hex'));
JS
) || exit 1

read_passphrase 'Release key passphrase: '
node - "$directory" "$keyfile" "$checked" 3< <(printf '%s' "$passphrase") <<'JS'
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const [directory, keyfile, checked] = process.argv.slice(2);
const passphrase = fs.readFileSync(3, 'utf8');
const fail = (reason) => {
  process.stderr.write(`${reason}\n`);
  process.exit(1);
};
const data = fs.readFileSync(path.join(directory, 'release.json'));
if (crypto.createHash('sha256').update(data).digest('hex') !== checked) {
  fail('release.json changed while signing; nothing written');
}
let privateKey;
try {
  privateKey = crypto.createPrivateKey({ key: fs.readFileSync(keyfile), format: 'pem', passphrase });
} catch {
  fail(`cannot open ${keyfile}: wrong passphrase or not a release key`);
}
if (privateKey.asymmetricKeyType !== 'ed25519') fail(`${keyfile} is not an Ed25519 key`);
const publicKey = crypto.createPublicKey(privateKey);
const signature = crypto.sign(null, data, privateKey);
if (!crypto.verify(null, data, publicKey, signature)) fail('the new signature does not verify');
const target = path.join(directory, 'release.json.sig');
const temporary = path.join(directory, `.release.json.sig.${process.pid}`);
try {
  fs.writeFileSync(temporary, `${signature.toString('base64')}\n`, { flag: 'wx', mode: 0o644 });
  fs.linkSync(temporary, target);
} catch (error) {
  fail(`cannot write ${target}: ${error.message}`);
} finally {
  fs.rmSync(temporary, { force: true });
}
process.stderr.write(`Wrote ${target}, signed with release key:\n`);
process.stdout.write(`${publicKey.export({ format: 'jwk' }).x}\n`);
JS
