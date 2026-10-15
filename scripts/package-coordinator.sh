#!/bin/sh
# Builds the hosted coordinator release archive: peerspan-coord for this Linux
# machine with the deployment files and install.sh. See the hosted coordinator
# contract, slice 4.
set -eu

usage() {
  echo "usage: $0 VERSION [OUTPUT_DIR]" >&2
  exit 2
}

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  usage
fi

version=$1
output=${2:-dist}

case "$version" in
  ''|*[!A-Za-z0-9._-]*)
    echo "VERSION may contain only letters, numbers, dots, underscores, and hyphens" >&2
    exit 2
    ;;
esac

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo=$(dirname "$script_dir")

if git -C "$repo" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  source_revision=$(git -C "$repo" rev-parse HEAD)
else
  source_revision=unknown
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
  echo "coordinator packaging supports native Linux builds only" >&2
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
output=$(CDPATH='' cd -- "$output" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/peerspan-coord-package.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM

name="peerspan-coord-${version}-${os}-${arch}"
bundle="$work/$name"
deploy="$bundle/share/peerspan-coord/deploy"
mkdir -p "$bundle/bin" "$deploy"

archive="$output/$name.tar.gz"
checksum="$archive.sha256"
# Keep the lock file in place: removing it would let concurrent builders lock
# different inodes. The kernel releases the lock when the processes exit.
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
  go -C "$repo/go" build -trimpath \
  -ldflags "-X github.com/Cerebral-Systems/capsule/go/internal/coord.Version=$version" \
  -o "$bundle/bin/peerspan-coord" ./cmd/peerspan-coord

case "$(file -b "$bundle/bin/peerspan-coord")" in
  *ELF*"$file_arch"*) ;;
  *)
    echo "built peerspan-coord does not match linux/$arch" >&2
    exit 1
    ;;
esac

# Every regular file in deploy/coordinator/, keeping install.sh executable.
found=false
for source in "$repo"/deploy/coordinator/*; do
  if [ -L "$source" ] || [ ! -f "$source" ]; then
    echo "missing or linked deployment file: $source" >&2
    exit 1
  fi
  cp -p "$source" "$deploy/"
  found=true
done
if [ "$found" != true ] || [ ! -x "$deploy/install.sh" ]; then
  echo "incomplete deployment files in deploy/coordinator/" >&2
  exit 1
fi

cat > "$bundle/release.json" <<EOF
{
  "version": "$version",
  "os": "$os",
  "architecture": "$arch",
  "source_revision": "$source_revision"
}
EOF

archive_tmp=$(mktemp "$output/.${name}.archive.XXXXXX")
checksum_tmp=$(mktemp "$output/.${name}.checksum.XXXXXX")
trap 'rm -rf "$work"; rm -f "$archive_tmp" "$checksum_tmp"' EXIT HUP INT TERM
tar -C "$work" --owner=0 --group=0 --numeric-owner -czf "$archive_tmp" "$name"
chmod 0644 "$archive_tmp" "$checksum_tmp"
digest=$($checksum_command "$archive_tmp" | cut -d ' ' -f 1)
printf '%s  %s\n' "$digest" "$(basename "$archive")" > "$checksum_tmp"
if [ "${PEERSPAN_PACKAGE_OVERWRITE:-}" = 1 ]; then
  mv -T -- "$archive_tmp" "$archive"
  mv -T -- "$checksum_tmp" "$checksum"
else
  # Hard links publish each complete file atomically without replacing an
  # output that appeared during the build, including dangling symlinks.
  if ! ln -T -- "$archive_tmp" "$archive"; then
    echo "package output appeared during the build; refusing to overwrite it" >&2
    exit 1
  fi
  if ! ln -T -- "$checksum_tmp" "$checksum"; then
    # Roll back only our archive if checksum publication loses a race.
    # shellcheck disable=SC3013 # dash and bash both support -ef
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
