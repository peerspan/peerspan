#!/usr/bin/env bash
set -euo pipefail

# Accepted release public keys: base64url Ed25519 keys, separated by spaces.
# This list must equal the one in scripts/install.sh. Adding or removing a key
# is an owner decision with its own decision-log entry, in a pull request that
# changes nothing else (INST-6).
# PLACEHOLDER: the key below is not a real release key. It is not a point on the
# Ed25519 curve, so no signature verifies under it and no one holds its private
# key. The owner replaces it with the real release key by an owner decision.
PEERSPAN_RELEASE_KEYS="AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

usage() {
  echo "usage: $0 VERSION [--implementation rust] [--from DIRECTORY | --from-github OWNER/REPO] [--no-service]" >&2
  exit 2
}

[[ $# -ge 1 ]] || usage
version=$1
shift
[[ $version =~ ^[A-Za-z0-9._-]+$ ]] || usage

implementation=rust
source_dir=.
source_repo=
source_given=false
source_kind=local
install_service=true
while [[ $# -gt 0 ]]; do
  case $1 in
    --implementation)
      [[ $# -ge 2 ]] || usage
      implementation=$2
      shift 2
      ;;
    --from)
      [[ $# -ge 2 ]] || usage
      $source_given && usage
      source_dir=$2
      source_given=true
      shift 2
      ;;
    --from-github)
      [[ $# -ge 2 ]] || usage
      $source_given && usage
      source_repo=$2
      source_kind=github
      source_given=true
      shift 2
      ;;
    --no-service)
      install_service=false
      shift
      ;;
    *) usage ;;
  esac
done
if [[ $implementation == go ]]; then
  echo "the Go host moved to https://github.com/peerspan/peerspan-go; this installer installs the Rust host only" >&2
  exit 2
fi
[[ $implementation == rust ]] || usage

if [[ $(uname -s) != Linux ]]; then
  echo "release archives are currently validated for Linux only" >&2
  exit 1
fi
case $(uname -m) in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

command -v node >/dev/null || { echo "Node.js 22 or later is required" >&2; exit 1; }
node_major=$(node -p "process.versions.node.split('.')[0]")
[[ $node_major -ge 22 ]] || { echo "Node.js 22 or later is required" >&2; exit 1; }
command -v tar >/dev/null || { echo "tar is required" >&2; exit 1; }
command -v flock >/dev/null || { echo "flock is required" >&2; exit 1; }

download_dir=
stage=
temporary_link=
cleanup() {
  if [[ -n $stage ]]; then rm -rf -- "$stage"; fi
  if [[ -n $download_dir ]]; then rm -rf -- "$download_dir"; fi
  if [[ -n $temporary_link ]]; then rm -f -- "$temporary_link"; fi
}
trap cleanup EXIT

if [[ $source_kind == github ]]; then
  [[ $source_repo =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || {
    echo "--from-github requires OWNER/REPO" >&2
    exit 2
  }
  if command -v curl >/dev/null; then
    downloader=curl
  elif command -v wget >/dev/null; then
    downloader=wget
  else
    echo "curl or wget is required for --from-github" >&2
    exit 1
  fi
  download_dir=$(mktemp -d "${TMPDIR:-/tmp}/peerspan-download.XXXXXX")
  source_dir=$download_dir
else
  source_dir=$(CDPATH= cd -- "$source_dir" && pwd)
fi
name="peerspan-${version}-linux-${arch}-${implementation}"
archive="$source_dir/$name.tar.gz"
checksum="$archive.sha256"
# A signed manifest pair (release.json and release.json.sig) is verified
# against PEERSPAN_RELEASE_KEYS: the signature, the manifest's form, its version
# and this archive's signed digest. It is required for --from-github; with
# --from it is verified when both files are present and refused when only one is.
signed_digest=
verify_manifest() {
  local signed
  signed=$(node - '' "$PEERSPAN_RELEASE_KEYS" "$source_dir/release.json" "$source_dir/release.json.sig" "$version" "$arch" archive <<'JS'
const fs = require('node:fs');
const crypto = require('node:crypto');
const [prefix, keyList, manifestPath, signaturePath, wantVersion, arch, mode] = process.argv.slice(2);
const fail = (file, reason) => {
  process.stderr.write(`${prefix}${file}: ${reason}\n`);
  process.exit(1);
};

const keys = keyList.split(/\s+/).filter(Boolean);
if (keys.length < 1 || keys.length > 4) fail('PEERSPAN_RELEASE_KEYS', 'must list 1 to 4 keys');
const publicKeys = keys.map((x) => {
  if (!/^[A-Za-z0-9_-]{43}$/.test(x) || Buffer.from(x, 'base64url').toString('base64url') !== x) {
    fail('PEERSPAN_RELEASE_KEYS', `malformed key ${x}`);
  }
  try {
    return crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x }, format: 'jwk' });
  } catch {
    return fail('PEERSPAN_RELEASE_KEYS', `unusable key ${x}`);
  }
});

let data, signatureText;
try {
  data = fs.readFileSync(manifestPath);
} catch {
  fail('release.json', 'missing or unreadable');
}
try {
  signatureText = fs.readFileSync(signaturePath);
} catch {
  fail('release.json.sig', 'missing or unreadable');
}
if (data.length > 65536) fail('release.json', 'invalid manifest (larger than 64 KiB)');
if (signatureText.length > 1024) fail('release.json.sig', 'bad signature (larger than 1 KiB)');

// One line: standard base64 with padding of 64 bytes, then a newline.
const text = signatureText.toString('latin1');
if (!/^[A-Za-z0-9+/]{86}==\n$/.test(text)) fail('release.json.sig', 'bad signature (not one base64 line of 64 bytes)');
const signature = Buffer.from(text.slice(0, 88), 'base64');
if (signature.length !== 64 || signature.toString('base64') !== text.slice(0, 88)) {
  fail('release.json.sig', 'bad signature (not one base64 line of 64 bytes)');
}
const verified = publicKeys.some((key) => {
  try {
    return crypto.verify(null, data, key, signature);
  } catch {
    return false;
  }
});
if (!verified) fail('release.json.sig', 'bad signature (not made by a listed release key)');

let manifest;
try {
  manifest = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(data));
} catch {
  fail('release.json', 'invalid manifest (not UTF-8 JSON)');
}
const isObject = (value) => typeof value === 'object' && value !== null && !Array.isArray(value);
if (!isObject(manifest)) fail('release.json', 'invalid manifest (not a JSON object)');
for (const member of ['format', 'name', 'version', 'source_revision', 'assets']) {
  if (!Object.hasOwn(manifest, member)) fail('release.json', `invalid manifest (no ${member})`);
}
if (manifest.format !== 1) fail('release.json', 'invalid manifest (format is not 1)');
if (manifest.name !== 'peerspan') fail('release.json', 'invalid manifest (name is not "peerspan")');
if (typeof manifest.version !== 'string' ||
    !/^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$/.test(manifest.version)) {
  fail('release.json', 'invalid manifest (malformed version)');
}
if (typeof manifest.source_revision !== 'string' || !/^[0-9a-f]{40}$/.test(manifest.source_revision)) {
  fail('release.json', 'invalid manifest (malformed source_revision)');
}
if (!isObject(manifest.assets)) fail('release.json', 'invalid manifest (assets is not an object)');
for (const [name, digest] of Object.entries(manifest.assets)) {
  if (!/^[A-Za-z0-9._+-]+$/.test(name) || name === '.' || name === '..') {
    fail('release.json', 'invalid manifest (malformed asset name)');
  }
  if (typeof digest !== 'string' || !/^[0-9a-f]{64}$/.test(digest)) {
    fail('release.json', `invalid manifest (malformed digest for ${name})`);
  }
}

if (wantVersion !== '' && manifest.version !== wantVersion) {
  fail('release.json', `version mismatch (manifest names ${manifest.version}, wanted ${wantVersion})`);
}
const archive = `peerspan-${manifest.version}-linux-${arch}-rust.tar.gz`;
if (!Object.hasOwn(manifest.assets, archive)) fail('release.json', `missing architecture (does not list ${archive})`);
const lines = [manifest.version, manifest.assets[archive]];
if (mode === 'installer') {
  if (!Object.hasOwn(manifest.assets, 'install-release.sh')) {
    fail('release.json', 'invalid manifest (does not list install-release.sh)');
  }
  lines.push(manifest.assets['install-release.sh']);
}
process.stdout.write(lines.join('\n') + '\n');
JS
  ) || exit 1
  signed_digest=${signed#*$'\n'}
}

if [[ $source_kind == github ]]; then
  release_url="https://github.com/$source_repo/releases/download/v$version"
  # fetch NAME LIMIT: download release_url/NAME into the download directory,
  # refusing more than LIMIT bytes (0 for no limit).
  fetch() {
    local size
    if [[ $downloader == curl ]]; then
      curl --proto '=https' --tlsv1.2 -fsSL -o "$download_dir/$1" "$release_url/$1" || {
        echo "$1: download failed" >&2
        exit 1
      }
    else
      wget --https-only -q -O "$download_dir/$1" "$release_url/$1" || {
        echo "$1: download failed" >&2
        exit 1
      }
    fi
    if [[ $2 -gt 0 ]]; then
      size=$(wc -c < "$download_dir/$1")
      if [[ $size -gt $2 ]]; then
        echo "$1: refused, larger than $2 bytes" >&2
        exit 1
      fi
    fi
  }
  fetch release.json 65536
  fetch release.json.sig 1024
  verify_manifest
  fetch "$name.tar.gz" 0
  fetch "$name.tar.gz.sha256" 0
elif [[ -e $source_dir/release.json || -L $source_dir/release.json ]]; then
  if [[ -e $source_dir/release.json.sig || -L $source_dir/release.json.sig ]]; then
    verify_manifest
  else
    echo "$source_dir has release.json but no release.json.sig; refusing to install" >&2
    exit 1
  fi
elif [[ -e $source_dir/release.json.sig || -L $source_dir/release.json.sig ]]; then
  echo "$source_dir has release.json.sig but no release.json; refusing to install" >&2
  exit 1
fi
[[ -f $archive && -f $checksum ]] || {
  echo "missing $archive or its .sha256 file" >&2
  exit 1
}

# The checksum detects a mismatched or damaged archive. Obtain both files from
# the trusted release repository; a checksum beside an untrusted archive does
# not establish who published it.
digest=$(node - "$archive" "$checksum" "$(basename "$archive")" <<'JS'
const fs = require('node:fs');
const crypto = require('node:crypto');
const [archive, checksum, name] = process.argv.slice(2);
const match = fs.readFileSync(checksum, 'utf8').match(/^([0-9a-f]{64})  ([^\n]+)\n$/);
if (!match || match[2] !== name) {
  process.stderr.write('invalid release checksum file\n');
  process.exit(1);
}
const actual = crypto.createHash('sha256').update(fs.readFileSync(archive)).digest('hex');
if (actual !== match[1]) {
  process.stderr.write('release checksum mismatch\n');
  process.exit(1);
}
process.stdout.write(actual);
JS
)
if [[ -n $signed_digest && $digest != "$signed_digest" ]]; then
  echo "$(basename "$archive"): digest mismatch with release.json (signed $signed_digest, got $digest)" >&2
  exit 1
fi

data_home=${PEERSPAN_INSTALL_DATA_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}}
[[ $data_home == /* ]] || { echo "install data directory must be an absolute path" >&2; exit 1; }
release_base="$data_home/peerspan/releases"
bin_dir=${PEERSPAN_INSTALL_BIN_DIR:-$HOME/.local/bin}
[[ $bin_dir == /* ]] || {
  echo "PEERSPAN_INSTALL_BIN_DIR must be an absolute path" >&2
  exit 1
}
launcher="$bin_dir/peerspan"
release="$release_base/$name-${digest:0:16}"
mkdir -p -- "$release_base" "$bin_dir"
exec 9>"$data_home/peerspan/.install.lock"
flock -n 9 || { echo "another Peerspan install is running" >&2; exit 1; }

if [[ -e $launcher && ! -L $launcher ]]; then
  echo "$launcher already exists and is not a Peerspan installer link" >&2
  exit 1
fi
if [[ -L $launcher ]]; then
  current=$(readlink -- "$launcher")
  [[ $current == "$release_base"/*/bin/peerspan ]] || {
    echo "$launcher points outside Peerspan releases; refusing to replace it" >&2
    exit 1
  }
  current_release=${current%/bin/peerspan}
  node - "$current_release/RELEASE.json" "$implementation" <<'JS'
const fs = require('node:fs');
const [metadata, implementation] = process.argv.slice(2);
let installed;
try {
  installed = JSON.parse(fs.readFileSync(metadata, 'utf8')).implementation;
} catch {
  process.stderr.write('cannot read the installed release metadata\n');
  process.exit(1);
}
if (installed !== implementation) {
  process.stderr.write('switching the installed host implementation needs a state migration review\n');
  process.exit(1);
}
JS
fi

stage=$(mktemp -d "$release_base/.install.XXXXXX")
temporary_link="$bin_dir/.peerspan-link.$$"

# The packager emits one named root. Reject unexpected paths before extraction.
tar -tzf "$archive" > "$stage/members"
while IFS= read -r member; do
  case $member in
    "$name"|"$name/"|"$name/"*) ;;
    *) echo "unexpected archive path: $member" >&2; exit 1 ;;
  esac
  case /$member/ in
    */../*|*/./*) echo "unsafe archive path: $member" >&2; exit 1 ;;
  esac
done < "$stage/members"

if [[ ! -e $release && ! -L $release ]]; then
  tar -xzf "$archive" -C "$stage" --no-same-owner --no-same-permissions
  bundle="$stage/$name"
else
  [[ -d $release && ! -L $release ]] || {
    echo "release path is not a directory: $release" >&2
    exit 1
  }
  bundle=$release
fi

node - "$bundle" "$version" "$arch" "$implementation" <<'JS'
const fs = require('node:fs');
const path = require('node:path');
const [bundle, version, arch, implementation] = process.argv.slice(2);
const release = JSON.parse(fs.readFileSync(path.join(bundle, 'RELEASE.json'), 'utf8'));
if (release.version !== version || release.os !== 'linux' ||
    release.architecture !== arch || release.implementation !== implementation) {
  process.stderr.write('release metadata does not match the selected archive\n');
  process.exit(1);
}
const binary = path.join(bundle, 'bin/peerspan-host');
const short = path.join(bundle, 'bin/peerspan');
if (!fs.statSync(binary).isFile() || (fs.statSync(binary).mode & 0o111) === 0 ||
    !fs.lstatSync(short).isSymbolicLink() || fs.readlinkSync(short) !== 'peerspan-host') {
  process.stderr.write('release binary layout is incomplete\n');
  process.exit(1);
}
JS

if [[ $bundle != "$release" ]]; then
  mv -T -- "$bundle" "$release"
fi

if $install_service; then
  if ! "$release/bin/peerspan" install; then
    if [[ -n ${current:-} && -x $current ]]; then
      echo "new service install failed; restoring the previous release" >&2
      "$current" install || echo "previous service also failed to start" >&2
    fi
    exit 1
  fi
fi

ln -s -- "$release/bin/peerspan" "$temporary_link"
mv -Tf -- "$temporary_link" "$launcher"

echo "Installed Peerspan $version ($implementation) at $release"
echo "Command: $launcher"
if [[ :$PATH: != *":$bin_dir:"* ]]; then
  echo "Add $bin_dir to PATH to use 'peerspan' from a new shell."
fi
