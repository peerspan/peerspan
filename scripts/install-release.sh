#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 VERSION [--implementation rust|go] [--from DIRECTORY] [--no-service]" >&2
  exit 2
}

[[ $# -ge 1 ]] || usage
version=$1
shift
[[ $version =~ ^[A-Za-z0-9._-]+$ ]] || usage

implementation=rust
source_dir=.
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
      source_dir=$2
      shift 2
      ;;
    --no-service)
      install_service=false
      shift
      ;;
    *) usage ;;
  esac
done
[[ $implementation == rust || $implementation == go ]] || usage

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

source_dir=$(CDPATH= cd -- "$source_dir" && pwd)
name="peerspan-${version}-linux-${arch}-${implementation}"
archive="$source_dir/$name.tar.gz"
checksum="$archive.sha256"
[[ -f $archive && -f $checksum ]] || {
  echo "missing $archive or its .sha256 file" >&2
  exit 1
}

# The checksum detects a mismatched or damaged archive. Obtain both files from
# the release's trusted download location; a checksum beside an untrusted
# archive does not establish who published it.
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
  [[ ${current_release##*/} == *"-$implementation-"* ]] || {
    echo "switching the installed host implementation needs a state migration review" >&2
    exit 1
  }
fi

stage=$(mktemp -d "$release_base/.install.XXXXXX")
temporary_link="$bin_dir/.peerspan-link.$$"
trap 'rm -rf -- "$stage"; rm -f -- "$temporary_link"' EXIT

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
