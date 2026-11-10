#!/usr/bin/env bash
set -euo pipefail

# Accepted release public keys: base64url Ed25519 keys, separated by spaces.
# This list must equal the one in scripts/install.sh. Adding or removing a key
# is an owner decision with its own decision-log entry, in a pull request that
# changes nothing else (INST-6).
# The owner's release key, decided in INST-8 (docs/decision-log.md).
PEERSPAN_RELEASE_KEYS="KEVbydgOxsDcbjKkau07nJT5lKQUChqJYGhGqNg0pRc"
# Peerspan's release verifier (docs/install-contract.md#release-verifier,
# INST-10). Both must equal the ones in scripts/install.sh.
PEERSPAN_VERIFIER_RELEASE="verifier-v1"
PEERSPAN_VERIFIER_SHA256="amd64:bd875a35dc2a66253126701a94b40dacf83acfdee4ec9e8c1789d9443df7c8e0 arm64:91c486c383d58d8fd9b0c15cd18ce540aab6e4b6cb65aad245a873a70b8bfba6"

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

# No Node.js is needed: the checks before extraction use the release verifier
# and sha256sum, and later checks use the bundle's own Node.js.
command -v sha256sum >/dev/null || { echo "sha256sum is required" >&2; exit 1; }
command -v tar >/dev/null || { echo "tar is required" >&2; exit 1; }
command -v flock >/dev/null || { echo "flock is required" >&2; exit 1; }

download_dir=
stage=
temporary_link=
verifier_dir=
cleanup() {
  if [[ -n $stage ]]; then rm -rf -- "$stage"; fi
  if [[ -n $download_dir ]]; then rm -rf -- "$download_dir"; fi
  if [[ -n $verifier_dir ]]; then rm -rf -- "$verifier_dir"; fi
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
verifier_name="peerspan-verify-linux-$arch"
pinned_verifier_digest=
for entry in $PEERSPAN_VERIFIER_SHA256; do
  [[ $entry == "$arch:"* ]] && pinned_verifier_digest=${entry#"$arch:"}
done
verifier=
# use_verifier FILE: accept FILE as the release verifier only with the pinned
# digest, and run it from a private copy.
use_verifier() {
  local actual
  [[ -f $1 && ! -L $1 ]] || {
    echo "$verifier_name: missing; download it from the $PEERSPAN_VERIFIER_RELEASE release of peerspan/peerspan" >&2
    exit 1
  }
  actual=$(sha256sum -- "$1" | cut -d ' ' -f 1)
  if [[ -z $pinned_verifier_digest || $actual != "$pinned_verifier_digest" ]]; then
    echo "$verifier_name: verifier digest mismatch (pinned ${pinned_verifier_digest:-none for $arch}, got $actual)" >&2
    exit 1
  fi
  verifier_dir=$(mktemp -d "${TMPDIR:-/tmp}/peerspan-verify.XXXXXX")
  cp -- "$1" "$verifier_dir/$verifier_name"
  chmod 0700 -- "$verifier_dir/$verifier_name"
  verifier="$verifier_dir/$verifier_name"
}
# verify_manifest ARGS...: the verifier checks release.json and its signature
# against PEERSPAN_RELEASE_KEYS, the manifest's form and version, and ARGS
# (--file NAME[=PATH]).
verify_manifest() {
  "$verifier" --keys "$PEERSPAN_RELEASE_KEYS" --manifest "$source_dir/release.json" \
    --signature "$source_dir/release.json.sig" --version "$version" "$@" >/dev/null || exit 1
}

if [[ $source_kind == github ]]; then
  release_url="https://github.com/$source_repo/releases/download/v$version"
  # fetch NAME LIMIT: download release_url/NAME into the download directory,
  # refusing more than LIMIT bytes (0 for no limit).
  fetch() {
    local status=0 detail size
    local -a limit_flag=()
    if [[ $downloader == curl ]]; then
      [[ $2 -gt 0 ]] && limit_flag=(--max-filesize "$2")
      curl --proto '=https' --proto-redir '=https' --tlsv1.2 --max-redirs 5 \
        ${limit_flag[@]+"${limit_flag[@]}"} -fsSL -o "$download_dir/$1" "$release_url/$1" \
        2>"$download_dir/.download-error" || status=$?
      detail=$(tr '\n' ' ' < "$download_dir/.download-error" 2>/dev/null || true)
    else
      wget --https-only --max-redirect=5 --tries=1 --timeout=60 -q \
        -O "$download_dir/$1" "$release_url/$1" 2>"$download_dir/.download-error" || status=$?
      case $status in
        4) detail="wget: network failure or connection closed early (exit 4)" ;;
        5) detail="wget: TLS verification failure (exit 5)" ;;
        8) detail="wget: the server returned an error status (exit 8)" ;;
        *) detail="wget: exit $status" ;;
      esac
    fi
    if [[ $status -ne 0 ]]; then
      detail=${detail%"${detail##*[! ]}"}
      echo "$1: download failed${detail:+ ($detail)}" >&2
      exit 1
    fi
    if [[ $2 -gt 0 ]]; then
      size=$(wc -c < "$download_dir/$1")
      if [[ $size -gt $2 ]]; then
        echo "$1: refused, larger than $2 bytes" >&2
        exit 1
      fi
    fi
  }
  fetch_from() {
    local saved=$release_url
    release_url=$1
    fetch "$2" "$3"
    release_url=$saved
  }
  fetch_from "https://github.com/$source_repo/releases/download/$PEERSPAN_VERIFIER_RELEASE" "$verifier_name" 16777216
  use_verifier "$download_dir/$verifier_name"
  fetch release.json 65536
  fetch release.json.sig 1024
  verify_manifest --file "$name.tar.gz"
  fetch "$name.tar.gz" 0
  fetch "$name.tar.gz.sha256" 1024
  verify_manifest --file "$name.tar.gz=$archive"
  rm -f -- "$download_dir/.download-error"
elif [[ -e $source_dir/release.json || -L $source_dir/release.json ]]; then
  if [[ -e $source_dir/release.json.sig || -L $source_dir/release.json.sig ]]; then
    # Offline: the verifier must be in the directory; it is never downloaded here.
    use_verifier "$source_dir/$verifier_name"
    [[ -f $archive ]] || { echo "missing $archive" >&2; exit 1; }
    verify_manifest --file "$name.tar.gz=$archive"
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
checksum_line=$(head -c 1025 -- "$checksum")
checksum_pattern='^([0-9a-f]{64})  ([^/]+)$'
if [[ $(wc -c < "$checksum") -gt 1024 || $(wc -l < "$checksum") -ne 1 ||
      ! $checksum_line =~ $checksum_pattern || ${BASH_REMATCH[2]} != "$(basename "$archive")" ]]; then
  echo "invalid release checksum file" >&2
  exit 1
fi
expected=${BASH_REMATCH[1]}
digest=$(sha256sum -- "$archive" | cut -d ' ' -f 1)
if [[ $digest != "$expected" ]]; then
  echo "release checksum mismatch" >&2
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
  # RELEASE.json is written by the packaging script, one member per line.
  installed=$(sed -n 's/^  "implementation": "\([a-z]*\)",\{0,1\}$/\1/p' "$current_release/RELEASE.json" 2>/dev/null || true)
  if [[ -z $installed ]]; then
    echo "cannot read the installed release metadata" >&2
    exit 1
  fi
  if [[ $installed != "$implementation" ]]; then
    echo "switching the installed host implementation needs a state migration review" >&2
    exit 1
  fi
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

# The bundle is verified by now; its own Node.js checks the rest.
bundled_node="$bundle/share/peerspan/node/bin/node"
if [[ ! -x $bundled_node ]] || ! "$bundled_node" --version >/dev/null 2>&1; then
  echo "the bundled Node.js does not run on this machine (it needs glibc 2.28 or later)" >&2
  exit 1
fi
"$bundled_node" - "$bundle" "$version" "$arch" "$implementation" <<'JS'
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
  # The PATH a new login shell would have: Ubuntu's default ~/.profile, for
  # example, adds ~/.local/bin once it exists (cli-output-contract section 3).
  login_path=$(timeout 5 env -u PATH -u BASH_ENV -u ENV "${SHELL:-/bin/sh}" -lc 'printf %s "$PATH"' </dev/null 2>/dev/null) || login_path=
  if [[ :$login_path: == *":$bin_dir:"* ]]; then
    echo "'peerspan' is available in a new login shell."
  else
    echo "Add $bin_dir to PATH to use 'peerspan' from a new shell."
  fi
fi
