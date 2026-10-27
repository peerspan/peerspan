#!/bin/sh
set -eu

usage() {
  echo "usage: $0 VERSION [OUTPUT_DIR]" >&2
  exit 2
}

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage
version=$1
output=${2:-dist}

case "$version" in
  ''|*[!A-Za-z0-9._-]*)
    echo "VERSION may contain only letters, numbers, dots, underscores, and hyphens" >&2
    exit 2
    ;;
esac

if [ "${PEERSPAN_COORDINATOR+x}" = x ] || [ "${PEERSPAN_COORDINATOR_KEY+x}" = x ]; then
  echo "unset PEERSPAN_COORDINATOR and PEERSPAN_COORDINATOR_KEY; the optional helper has no network or coordinator authority" >&2
  exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(dirname "$script_dir")
if git -C "$repo" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  source_revision=$(git -C "$repo" rev-parse HEAD)
  if [ -n "$(git -C "$repo" status --porcelain)" ]; then
    source_dirty=true
  else
    source_dirty=false
  fi
else
  source_revision=unknown
  source_dirty=null
fi

for command in go tar file cut flock; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "missing required command: $command" >&2
    exit 1
  fi
done
if command -v sha256sum >/dev/null 2>&1; then
  checksum_command=sha256sum
elif command -v shasum >/dev/null 2>&1; then
  checksum_command="shasum -a 256"
else
  echo "neither sha256sum nor shasum is available" >&2
  exit 1
fi

if [ "$(uname -s)" != Linux ]; then
  echo "helper packaging currently supports validated native Linux builds only" >&2
  exit 1
fi
os=linux
case "$(uname -m)" in
  x86_64|amd64)
    arch=amd64
    file_arch='x86-64'
    ;;
  arm64|aarch64)
    arch=arm64
    file_arch='ARM aarch64'
    ;;
  *)
    echo "unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

mkdir -p "$output"
output=$(CDPATH= cd -- "$output" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/peerspan-helper-package.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
name="peerspan-helper-${version}-${os}-${arch}"
bundle="$work/$name"
mkdir -p "$bundle/bin"
archive="$output/$name.tar.gz"
checksum="$archive.sha256"

# Retaining the lock inode prevents concurrent builders from locking different
# files after a prior builder exits. The kernel releases our lock on exit.
exec 9>"$output/.${name}.lock"
if ! flock -n 9; then
  echo "another packaging process is building this release: $name" >&2
  exit 1
fi
if { [ -e "$archive" ] || [ -L "$archive" ] || [ -e "$checksum" ] || [ -L "$checksum" ]; } && [ "${PEERSPAN_PACKAGE_OVERWRITE:-}" != 1 ]; then
  echo "package output already exists; remove it or set PEERSPAN_PACKAGE_OVERWRITE=1" >&2
  exit 1
fi

GOOS=linux GOARCH="$arch" CGO_ENABLED=0 \
  go -C "$repo/go" build -trimpath -o "$bundle/bin/peerspan-helper" ./cmd/peerspan-helper
case "$(file -b "$bundle/bin/peerspan-helper")" in
  *ELF*"$file_arch"*) ;;
  *)
    echo "built peerspan-helper does not match linux/$arch" >&2
    exit 1
    ;;
esac
cp "$repo/docs/decentralized-helper-contract.md" "$bundle/README.md"
cat > "$bundle/RELEASE.json" <<EOF
{
  "version": "$version",
  "source_revision": "$source_revision",
  "source_dirty": $source_dirty,
  "os": "$os",
  "architecture": "$arch"
}
EOF

archive_tmp=$(mktemp "$output/.${name}.archive.XXXXXX")
checksum_tmp=$(mktemp "$output/.${name}.checksum.XXXXXX")
trap 'rm -rf "$work"; rm -f "$archive_tmp" "$checksum_tmp"' EXIT HUP INT TERM
tar -C "$work" -czf "$archive_tmp" "$name"
digest=$($checksum_command "$archive_tmp" | cut -d ' ' -f 1)
printf '%s  %s\n' "$digest" "$(basename "$archive")" > "$checksum_tmp"
if [ "${PEERSPAN_PACKAGE_OVERWRITE:-}" = 1 ]; then
  mv -T -- "$archive_tmp" "$archive"
  mv -T -- "$checksum_tmp" "$checksum"
else
  if ! ln -T -- "$archive_tmp" "$archive"; then
    echo "package output appeared during the build; refusing to overwrite it" >&2
    exit 1
  fi
  if ! ln -T -- "$checksum_tmp" "$checksum"; then
    if [ "$archive_tmp" -ef "$archive" ]; then
      rm -f -- "$archive"
    fi
    echo "checksum output appeared during the build; refusing to overwrite it" >&2
    exit 1
  fi
  rm -f -- "$archive_tmp" "$checksum_tmp"
fi
echo "$archive"
echo "$checksum"
