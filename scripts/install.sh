#!/usr/bin/env bash
# Peerspan one-line install (docs/install-contract.md).
#
#   curl -fsSL https://peerspan.dev/install | bash
#   curl -fsSL https://peerspan.dev/install | bash -s -- --version VERSION
#
# Installs the latest (or the given) Peerspan release for this machine into
# the user's home directory. It downloads Peerspan's release verifier and
# accepts it only with the digest pinned below; the verifier checks the
# release's signed manifest against the keys below, and the host archive and
# install-release.sh against the signed digests. It then hands off to that
# install-release.sh, with the verifier that installer pins. It needs no
# Node.js, never runs gh or sudo and never edits shell profiles.

PEERSPAN_RELEASES_URL="https://github.com/peerspan/peerspan/releases"
# Accepted release public keys: base64url Ed25519 keys, separated by spaces.
# This list must equal the one in scripts/install-release.sh. Adding or removing
# a key is an owner decision with its own decision-log entry, in a pull request
# that changes nothing else (INST-6).
# The owner's release key, decided in INST-8 (docs/decision-log.md).
PEERSPAN_RELEASE_KEYS="KEVbydgOxsDcbjKkau07nJT5lKQUChqJYGhGqNg0pRc"
# Peerspan's release verifier (docs/install-contract.md#release-verifier,
# INST-10): the verifier-vN release to download it from, and the SHA-256 of
# its binary per architecture. Both must equal the ones in
# scripts/install-release.sh, and change only in a pull request that changes
# nothing else. The all-zero digests below are placeholders: no verifier
# matches them, so nothing installs until verifier-v1 is published and pinned.
PEERSPAN_VERIFIER_RELEASE="verifier-v1"
PEERSPAN_VERIFIER_SHA256="amd64:0000000000000000000000000000000000000000000000000000000000000000 arm64:0000000000000000000000000000000000000000000000000000000000000000"

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
  local system machine arch downloader
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
  if ! command -v sha256sum >/dev/null 2>&1; then
    echo "peerspan install: sha256sum is required but was not found" >&2
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
  # bytes (0 for no limit). The tool's own error is folded into one line.
  fetch() {
    local name=$1 url=$2 limit=$3 status=0 detail size
    local -a limit_flag=()
    if [[ $downloader == curl ]]; then
      [[ $limit -gt 0 ]] && limit_flag=(--max-filesize "$limit")
      curl --proto '=https' --proto-redir '=https' --tlsv1.2 --max-redirs 5 \
        ${limit_flag[@]+"${limit_flag[@]}"} -fsSL -o "$dir/$name" "$url" 2>"$dir/.download-error" || status=$?
      detail=$(tr '\n' ' ' < "$dir/.download-error" 2>/dev/null || true)
    else
      wget --https-only --max-redirect=5 --tries=1 --timeout=60 -q \
        -O "$dir/$name" "$url" 2>"$dir/.download-error" || status=$?
      case $status in
        4) detail="wget: network failure or connection closed early (exit 4)" ;;
        5) detail="wget: TLS verification failure (exit 5)" ;;
        8) detail="wget: the server returned an error status (exit 8)" ;;
        *) detail="wget: exit $status" ;;
      esac
    fi
    if [[ $status -ne 0 ]]; then
      detail=${detail%"${detail##*[! ]}"}
      echo "peerspan install: $name: download failed${detail:+ ($detail)}" >&2
      exit 1
    fi
    if [[ $limit -gt 0 ]]; then
      size=$(wc -c < "$dir/$name")
      if [[ $size -gt $limit ]]; then
        echo "peerspan install: $name: refused, larger than $limit bytes" >&2
        exit 1
      fi
    fi
  }

  # pinned_digest PINS: the digest PINS (amd64:HEX arm64:HEX) lists for this
  # architecture.
  pinned_digest() {
    local entry
    for entry in $1; do
      if [[ $entry == "$arch:"* ]]; then
        echo "${entry#"$arch:"}"
        return
      fi
    done
  }
  # fetch_verifier RELEASE DIGEST: download the verifier binary of RELEASE into
  # DIR/verifier and accept it only with DIGEST.
  local verifier_name="peerspan-verify-linux-$arch"
  fetch_verifier() {
    local actual
    fetch "$verifier_name" "$base/download/$1/$verifier_name" 16777216
    actual=$(sha256sum -- "$dir/$verifier_name" | cut -d ' ' -f 1)
    if [[ -z $2 || $actual != "$2" ]]; then
      echo "peerspan install: $verifier_name: verifier digest mismatch (pinned ${2:-none for $arch}, got $actual)" >&2
      exit 1
    fi
    chmod 0755 -- "$dir/$verifier_name"
  }
  # verify ARGS...: run the verifier on the release files in DIR; its own
  # failure line is reported as the bootstrap's.
  verify() {
    local out
    if ! out=$("$dir/$verifier_name" --keys "$PEERSPAN_RELEASE_KEYS" \
      --manifest "$dir/release.json" --signature "$dir/release.json.sig" "$@" 2>&1); then
      echo "peerspan install: ${out#peerspan-verify: }" >&2
      exit 1
    fi
    echo "$out"
  }

  fetch_verifier "$PEERSPAN_VERIFIER_RELEASE" "$(pinned_digest "$PEERSPAN_VERIFIER_SHA256")"

  local manifest_url
  if $version_given; then
    manifest_url="$base/download/v$want_version"
  else
    manifest_url="$base/latest/download"
  fi
  fetch release.json "$manifest_url/release.json" 65536
  fetch release.json.sig "$manifest_url/release.json.sig" 1024

  local version
  if $version_given; then
    version=$(verify --version "$want_version")
  else
    version=$(verify)
  fi
  local archive="peerspan-$version-linux-$arch-rust.tar.gz"
  local release_url="$base/download/v$version"
  if ! "$dir/$verifier_name" --keys "$PEERSPAN_RELEASE_KEYS" --manifest "$dir/release.json" \
    --signature "$dir/release.json.sig" --file "$archive" >/dev/null 2>&1; then
    echo "peerspan install: release.json: missing architecture (does not list $archive)" >&2
    exit 1
  fi
  verify --file install-release.sh >/dev/null

  fetch "$archive" "$release_url/$archive" 0
  fetch install-release.sh "$release_url/install-release.sh" 1048576
  verify --file "$archive=$dir/$archive" --file "install-release.sh=$dir/install-release.sh" >/dev/null
  printf '%s  %s\n' "$(sha256sum -- "$dir/$archive" | cut -d ' ' -f 1)" "$archive" > "$dir/$archive.sha256"

  # The verified installer may pin another verifier than this bootstrap (an
  # older bootstrap, or --version of an older release). Read its pins as exact
  # single assignments, never by running it, and hand it the verifier it pins.
  local installer_release installer_pins
  installer_release=$(sed -n 's/^PEERSPAN_VERIFIER_RELEASE="\([^"]*\)"$/\1/p' "$dir/install-release.sh")
  installer_pins=$(sed -n 's/^PEERSPAN_VERIFIER_SHA256="\([^"]*\)"$/\1/p' "$dir/install-release.sh")
  if [[ $(grep -c '^PEERSPAN_VERIFIER_RELEASE=' "$dir/install-release.sh") -ne 1 ||
        $(grep -c '^PEERSPAN_VERIFIER_SHA256=' "$dir/install-release.sh") -ne 1 ||
        ! $installer_release =~ ^verifier-v[1-9][0-9]*$ ||
        ! $installer_pins =~ ^amd64:[0-9a-f]{64}\ arm64:[0-9a-f]{64}$ ]]; then
    echo "peerspan install: install-release.sh: invalid installer pins" >&2
    exit 1
  fi
  if [[ $installer_release != "$PEERSPAN_VERIFIER_RELEASE" ||
        $(pinned_digest "$installer_pins") != "$(pinned_digest "$PEERSPAN_VERIFIER_SHA256")" ]]; then
    rm -f -- "$dir/$verifier_name"
    fetch_verifier "$installer_release" "$(pinned_digest "$installer_pins")"
  fi
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
