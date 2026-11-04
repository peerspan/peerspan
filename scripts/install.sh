#!/usr/bin/env bash
# Peerspan one-line install (docs/install-contract.md).
#
#   curl -fsSL https://peerspan.dev/install | bash
#   curl -fsSL https://peerspan.dev/install | bash -s -- --version VERSION
#
# Installs the latest (or the given) Peerspan release for this machine into
# the user's home directory. It downloads the release's signed manifest,
# checks its Ed25519 signature against the keys below, checks the host archive
# and install-release.sh against the signed digests, and hands off to that
# install-release.sh. It never runs gh or sudo and never edits shell profiles.

PEERSPAN_RELEASES_URL="https://github.com/peerspan/peerspan/releases"
# Accepted release public keys: base64url Ed25519 keys, separated by spaces.
# This list must equal the one in scripts/install-release.sh. Adding or removing
# a key is an owner decision with its own decision-log entry, in a pull request
# that changes nothing else (INST-6).
# PLACEHOLDER: the key below is not a real release key. It is not a point on the
# Ed25519 curve, so no signature verifies under it and no one holds its private
# key. The owner replaces it with the real release key by an owner decision.
PEERSPAN_RELEASE_KEYS="AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

# The rest of the file is one function, called on the last line, so a copy cut
# off at any byte executes nothing.
peerspan_bootstrap() {
  set -euo pipefail

  local usage='usage: install.sh [--version VERSION] [--no-service]'
  local version_pattern='^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$'
  local want_version='' version_given=false no_service=false
  while [[ $# -gt 0 ]]; do
    case $1 in
      --version)
        if $version_given || [[ $# -lt 2 || ! $2 =~ $version_pattern ]]; then
          echo "$usage" >&2
          exit 2
        fi
        want_version=$2
        version_given=true
        shift 2
        ;;
      --no-service)
        if $no_service; then
          echo "$usage" >&2
          exit 2
        fi
        no_service=true
        shift
        ;;
      *)
        echo "$usage" >&2
        exit 2
        ;;
    esac
  done

  # Preflight, in the contract's order. Nothing is downloaded or written first.
  local system machine arch node_version downloader
  system=$(uname -s)
  if [[ $system != Linux ]]; then
    echo "peerspan install: unsupported operating system: $system (Linux is required)" >&2
    exit 1
  fi
  machine=$(uname -m)
  case $machine in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *)
      echo "peerspan install: unsupported architecture: $machine (amd64 or arm64 is required)" >&2
      exit 1
      ;;
  esac
  if ! command -v tar >/dev/null 2>&1; then
    echo "peerspan install: tar is required but was not found" >&2
    exit 1
  fi
  if ! command -v flock >/dev/null 2>&1; then
    echo "peerspan install: flock is required but was not found" >&2
    exit 1
  fi
  local node_help='get Node.js 22 from https://nodejs.org/en/download'
  if ! command -v node >/dev/null 2>&1; then
    echo "peerspan install: Node.js 22 or later is required but node was not found; $node_help" >&2
    exit 1
  fi
  node_version=$(node --version 2>/dev/null || true)
  if [[ ! $node_version =~ ^v?([0-9]+)\. ]] || ((10#${BASH_REMATCH[1]} < 22)); then
    echo "peerspan install: Node.js 22 or later is required, found ${node_version:-an unknown version}; $node_help" >&2
    exit 1
  fi
  if command -v curl >/dev/null 2>&1; then
    downloader=curl
  elif command -v wget >/dev/null 2>&1; then
    downloader=wget
  else
    echo "peerspan install: curl or wget is required but neither was found" >&2
    exit 1
  fi
  local base=$PEERSPAN_RELEASES_URL
  if [[ $base != https://* ]]; then
    echo "peerspan install: release URL is not HTTPS: $base" >&2
    exit 1
  fi

  echo "Installing Peerspan ${want_version:-latest} for linux-$arch into your home directory"

  # Every exit from here on, including signals, removes the temporary directory.
  peerspan_bootstrap_dir=
  trap 'if [[ -n $peerspan_bootstrap_dir ]]; then rm -rf -- "$peerspan_bootstrap_dir"; fi' EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  peerspan_bootstrap_dir=$(mktemp -d "${TMPDIR:-/tmp}/peerspan-install.XXXXXX")
  local dir=$peerspan_bootstrap_dir
  chmod 0700 -- "$dir"

  # fetch NAME URL LIMIT: download URL to DIR/NAME, refusing more than LIMIT
  # bytes (0 for no limit).
  fetch() {
    local name=$1 url=$2 limit=$3 detail size
    if [[ $downloader == curl ]]; then
      curl --proto '=https' --tlsv1.2 -fsSL -o "$dir/$name" "$url" 2>"$dir/.download-error" || {
        detail=$(tail -n 1 -- "$dir/.download-error" 2>/dev/null || true)
        echo "peerspan install: $name: download failed${detail:+ ($detail)}" >&2
        exit 1
      }
    else
      wget --https-only -q -O "$dir/$name" "$url" 2>"$dir/.download-error" || {
        echo "peerspan install: $name: download failed (wget exit status $?)" >&2
        exit 1
      }
    fi
    if [[ $limit -gt 0 ]]; then
      size=$(wc -c < "$dir/$name")
      if [[ $size -gt $limit ]]; then
        echo "peerspan install: $name: refused, larger than $limit bytes" >&2
        exit 1
      fi
    fi
  }

  local manifest_url
  if $version_given; then
    manifest_url="$base/download/v$want_version"
  else
    manifest_url="$base/latest/download"
  fi
  fetch release.json "$manifest_url/release.json" 65536
  fetch release.json.sig "$manifest_url/release.json.sig" 1024

  # Prints the manifest version, the host archive digest and the
  # install-release.sh digest, one per line, or names the failure and exits 1.
  local signed
  signed=$(node - 'peerspan install: ' "$PEERSPAN_RELEASE_KEYS" "$dir/release.json" "$dir/release.json.sig" "$want_version" "$arch" installer <<'JS'
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

  local version archive_digest installer_digest
  { read -r version; read -r archive_digest; read -r installer_digest; } <<< "$signed"
  local archive="peerspan-$version-linux-$arch-rust.tar.gz"
  local release_url="$base/download/v$version"

  # check NAME DIGEST: DIR/NAME must have the signed SHA-256 digest.
  check() {
    local actual
    actual=$(node -e "process.stdout.write(require('node:crypto').createHash('sha256').update(require('node:fs').readFileSync(process.argv[1])).digest('hex'))" "$dir/$1") || {
      echo "peerspan install: $1: cannot be read" >&2
      exit 1
    }
    if [[ $actual != "$2" ]]; then
      echo "peerspan install: $1: digest mismatch (signed $2, got $actual)" >&2
      exit 1
    fi
  }

  fetch "$archive" "$release_url/$archive" 0
  check "$archive" "$archive_digest"
  fetch install-release.sh "$release_url/install-release.sh" 1048576
  check install-release.sh "$installer_digest"
  printf '%s  %s\n' "$archive_digest" "$archive" > "$dir/$archive.sha256"
  rm -f -- "$dir/.download-error"

  local status=0
  if $no_service; then
    bash "$dir/install-release.sh" "$version" --from "$dir" --no-service || status=$?
  else
    bash "$dir/install-release.sh" "$version" --from "$dir" || status=$?
  fi
  exit "$status"
}

{ peerspan_bootstrap "$@"; }
