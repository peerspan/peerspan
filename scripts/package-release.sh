#!/bin/sh
set -eu

usage() {
  echo "usage: $0 go|rust VERSION [OUTPUT_DIR]" >&2
  exit 2
}

[ "$#" -ge 2 ] && [ "$#" -le 3 ] || usage

implementation=$1
version=$2
output=${3:-dist}

case "$implementation" in
  go|rust) ;;
  *) usage ;;
esac

case "$version" in
  ''|*[!A-Za-z0-9._-]*)
    echo "VERSION may contain only letters, numbers, dots, underscores, and hyphens" >&2
    exit 2
    ;;
esac

# Coordinator-free hosts do not embed a required transport service identity.
# Refuse stale release configuration instead of silently carrying it forward.
if [ "${PEERSPAN_COORDINATOR+x}" = x ] || [ "${PEERSPAN_COORDINATOR_KEY+x}" = x ]; then
  echo "unset PEERSPAN_COORDINATOR and PEERSPAN_COORDINATOR_KEY for coordinator-free releases; configure optional helpers on participating hosts" >&2
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

for command in node npm tar file cut flock; do
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

node_major=$(node -p "process.versions.node.split('.')[0]")
if [ "$node_major" -lt 22 ]; then
  echo "Node.js 22 or later is required; found $(node --version)" >&2
  exit 1
fi

if [ "$(uname -s)" != Linux ]; then
  echo "release packaging currently supports validated native Linux builds only" >&2
  exit 1
fi
os=linux

case "$(uname -m)" in
  x86_64|amd64)
    arch=amd64
    go_arch=amd64
    rust_target=x86_64-unknown-linux-gnu
    file_arch='x86-64'
    ;;
  arm64|aarch64)
    arch=arm64
    go_arch=arm64
    rust_target=aarch64-unknown-linux-gnu
    file_arch='ARM aarch64'
    ;;
  *)
    echo "unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

mkdir -p "$output"
output=$(CDPATH= cd -- "$output" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/peerspan-package.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM

name="peerspan-${version}-${os}-${arch}-${implementation}"
bundle="$work/$name"
mkdir -p "$bundle/bin" "$bundle/share/peerspan"

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

case "$implementation" in
  go)
    command -v go >/dev/null 2>&1 || {
      echo "missing required command: go" >&2
      exit 1
    }
    go_host=github.com/peerspan/peerspan/go/internal/host
    GOOS=linux GOARCH="$go_arch" CGO_ENABLED=0 \
      go -C "$repo/go" build -trimpath \
      -ldflags "-X $go_host.Version=$version" \
      -o "$bundle/bin/peerspan-host" ./cmd/peerspan-host
    ;;
  rust)
    command -v cargo >/dev/null 2>&1 || {
      echo "missing required command: cargo" >&2
      exit 1
    }
    cargo_target="$repo/rust/target/peerspan-package-$rust_target"
    CARGO_TARGET_DIR="$cargo_target" cargo build --release --locked \
      --target "$rust_target" --manifest-path "$repo/rust/Cargo.toml"
    cp "$cargo_target/$rust_target/release/peerspan-host" "$bundle/bin/peerspan-host"
    ;;
esac

case "$(file -b "$bundle/bin/peerspan-host")" in
  *ELF*"$file_arch"*) ;;
  *)
    echo "built peerspan-host does not match linux/$arch" >&2
    exit 1
    ;;
esac

# peerspan is the same binary under its short name; a relative link keeps the
# bundle relocatable.
ln -s peerspan-host "$bundle/bin/peerspan"

integrations="$bundle/share/peerspan/integrations"
copy_integration() {
  integration=$1
  shift
  mkdir -p "$integrations/$integration"
  for source in "$@"; do
    if [ -L "$repo/integrations/$integration/$source" ] || [ ! -f "$repo/integrations/$integration/$source" ]; then
      echo "missing or linked integration source: $integration/$source" >&2
      exit 1
    fi
    cp "$repo/integrations/$integration/$source" "$integrations/$integration/$source"
  done
}

copy_integration shared adapter.mjs presentation.mjs provider.mjs tools.mjs
copy_integration claude-channel integration.json package.json package-lock.json README.md \
  channel.mjs provider.mjs
copy_integration codex integration.json package.json package-lock.json README.md \
  bridge.mjs configuration.mjs connection.mjs mcp.mjs provider.mjs thread.mjs
copy_integration opencode integration.json package.json package-lock.json README.md \
  binding.mjs bridge.mjs client.mjs inspection.mjs plugin.mjs provider.mjs

for integration in claude-channel codex opencode; do
  npm ci --omit=dev --ignore-scripts \
    --prefix "$bundle/share/peerspan/integrations/$integration"
done

cp "$repo/docs/quick-start.md" "$bundle/README.md"

cat > "$bundle/RELEASE.json" <<EOF
{
  "version": "$version",
  "implementation": "$implementation",
  "source_revision": "$source_revision",
  "source_dirty": $source_dirty,
  "os": "$os",
  "architecture": "$arch",
  "node_requirement": ">=22",
  "rust_libc": "glibc (builder baseline; rust bundles only)"
}
EOF

for required in \
  "$bundle/bin/peerspan-host" \
  "$bundle/bin/peerspan" \
  "$bundle/RELEASE.json" \
  "$bundle/share/peerspan/integrations/shared/adapter.mjs" \
  "$bundle/share/peerspan/integrations/claude-channel/integration.json" \
  "$bundle/share/peerspan/integrations/codex/integration.json" \
  "$bundle/share/peerspan/integrations/opencode/integration.json" \
  "$bundle/share/peerspan/integrations/claude-channel/node_modules/@modelcontextprotocol/sdk/package.json" \
  "$bundle/share/peerspan/integrations/codex/node_modules/ws/package.json" \
  "$bundle/share/peerspan/integrations/opencode/node_modules/@opencode-ai/plugin/package.json"
do
  if [ ! -e "$required" ]; then
    echo "incomplete bundle; missing $required" >&2
    exit 1
  fi
done

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
  # Hard links publish each complete file atomically without replacing an
  # output that appeared during the build, including dangling symlinks.
  if ! ln -T -- "$archive_tmp" "$archive"; then
    echo "package output appeared during the build; refusing to overwrite it" >&2
    exit 1
  fi
  if ! ln -T -- "$checksum_tmp" "$checksum"; then
    # Roll back only our archive if checksum publication loses a race.
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
