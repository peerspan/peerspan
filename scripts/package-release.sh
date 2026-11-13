#!/bin/sh
set -eu

usage() {
  echo "usage: $0 rust VERSION [OUTPUT_DIR]" >&2
  exit 2
}

[ "$#" -ge 2 ] && [ "$#" -le 3 ] || usage

implementation=$1
version=$2
output=${3:-dist}

case "$implementation" in
  rust) ;;
  go)
    echo "the Go host moved to https://github.com/peerspan/peerspan-go; this repository packages the Rust host only" >&2
    exit 2
    ;;
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

# The Node.js runtime each bundle carries (docs/install-contract.md#bundled-nodejs,
# INST-9 and INST-11). A patch update within line 24 is an ordinary pull
# request; copy both digests from https://nodejs.org/dist/vVERSION/SHASUMS256.txt.
# Another major line is an owner decision.
bundled_node_version=24.22.2
bundled_node_sha256_amd64=48cc0e21e048790e54c0cf5749c2725005313d652651c40b7a21feb9697aaf75
bundled_node_sha256_arm64=eb187837a2230d4047161ac0be008584e16b46f726e9c9490ee35dc6b17d9ba8

for command in node npm tar xz file cut flock; do
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
    rust_target=x86_64-unknown-linux-gnu
    file_arch='x86-64'
    node_platform=linux-x64
    bundled_node_sha256=$bundled_node_sha256_amd64
    ;;
  arm64|aarch64)
    arch=arm64
    rust_target=aarch64-unknown-linux-gnu
    file_arch='ARM aarch64'
    node_platform=linux-arm64
    bundled_node_sha256=$bundled_node_sha256_arm64
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

command -v cargo >/dev/null 2>&1 || {
  echo "missing required command: cargo" >&2
  exit 1
}
cargo_target="$repo/target/peerspan-package-$rust_target"
# The binary reports VERSION in --version and status (peerspan_host::VERSION).
PEERSPAN_RELEASE_VERSION="$version" CARGO_TARGET_DIR="$cargo_target" cargo build --release --locked \
  --target "$rust_target" --manifest-path "$repo/Cargo.toml" --bin peerspan-host
cp "$cargo_target/$rust_target/release/peerspan-host" "$bundle/bin/peerspan-host"

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
    mkdir -p "$integrations/$integration/$(dirname -- "$source")"
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

# Keep the native frontend self-contained. Copy only shipped runtime sources,
# never a developer's tests, credentials or other files in the plugin directory.
for directory in \
  "$repo/integrations/claude-onboarding" \
  "$repo/integrations/claude-onboarding/.claude-plugin" \
  "$repo/integrations/claude-onboarding/hooks"
do
  if [ -L "$directory" ] || [ ! -d "$directory" ]; then
    echo "missing or linked native plugin directory" >&2
    exit 1
  fi
done
copy_integration claude-onboarding .claude-plugin/plugin.json README.md hooks/hooks.json \
  hooks/access-completion.mjs hooks/access.mjs hooks/adapter.mjs hooks/admission.mjs \
  hooks/finalization.mjs hooks/invitation.mjs hooks/join-progress.mjs hooks/join.mjs \
  hooks/machine-owner.mjs hooks/machine-request.mjs hooks/machine-requester.mjs \
  hooks/messages.mjs hooks/observation.mjs hooks/owner.mjs hooks/project.mjs \
  hooks/reachability.mjs hooks/readiness.mjs hooks/recipient.mjs hooks/register.mjs \
  hooks/requester-commit.mjs hooks/tasks.mjs

# Claude caches installed plugins by version. Stamp only the packaged manifest;
# the source plugin and every runtime module retain their original bytes.
node - "$integrations/claude-onboarding/.claude-plugin/plugin.json" "$version" <<'NODE'
const fs = require('node:fs');
const [path, version] = process.argv.slice(2);
const manifest = JSON.parse(fs.readFileSync(path, 'utf8'));
manifest.version = version;
fs.writeFileSync(path, JSON.stringify(manifest, null, 2) + '\n');
NODE

marketplace="$repo/integrations/claude-onboarding-marketplace.json"
if [ -L "$marketplace" ] || [ ! -f "$marketplace" ]; then
  echo "missing or linked native plugin marketplace" >&2
  exit 1
fi
mkdir -p "$bundle/share/peerspan/.claude-plugin"
cp "$marketplace" "$bundle/share/peerspan/.claude-plugin/marketplace.json"

for integration in claude-channel codex opencode; do
  npm ci --omit=dev --ignore-scripts \
    --prefix "$bundle/share/peerspan/integrations/$integration"
done

# The bundled Node.js: the official tarball for this architecture, accepted only
# with its pinned digest, of which the archive keeps bin/node, LICENSE and
# README.md. PEERSPAN_NODE_TARBALL names an already downloaded copy (still
# checked against the digest); otherwise it is downloaded from nodejs.org.
node_tarball_name="node-v${bundled_node_version}-${node_platform}.tar.xz"
node_tarball=${PEERSPAN_NODE_TARBALL:-}
if [ -z "$node_tarball" ]; then
  command -v curl >/dev/null 2>&1 || {
    echo "missing required command: curl (or set PEERSPAN_NODE_TARBALL)" >&2
    exit 1
  }
  node_tarball="$work/$node_tarball_name"
  curl --proto '=https' --tlsv1.2 -fsSL -o "$node_tarball" \
    "https://nodejs.org/dist/v${bundled_node_version}/${node_tarball_name}"
fi
node_digest=$($checksum_command "$node_tarball" | cut -d ' ' -f 1)
if [ "$node_digest" != "$bundled_node_sha256" ]; then
  echo "$node_tarball_name: digest mismatch (pinned $bundled_node_sha256, got $node_digest)" >&2
  exit 1
fi
node_root="node-v${bundled_node_version}-${node_platform}"
mkdir -p "$work/node"
tar -xJf "$node_tarball" -C "$work/node" --no-same-owner --no-same-permissions \
  "$node_root/bin/node" "$node_root/LICENSE" "$node_root/README.md"
mkdir -p "$bundle/share/peerspan/node/bin"
cp "$work/node/$node_root/bin/node" "$bundle/share/peerspan/node/bin/node"
cp "$work/node/$node_root/LICENSE" "$work/node/$node_root/README.md" "$bundle/share/peerspan/node/"
chmod 0755 "$bundle/share/peerspan/node/bin/node"
case "$(file -b "$bundle/share/peerspan/node/bin/node")" in
  *ELF*"$file_arch"*) ;;
  *)
    echo "bundled node does not match linux/$arch" >&2
    exit 1
    ;;
esac
if [ "$("$bundle/share/peerspan/node/bin/node" --version)" != "v$bundled_node_version" ]; then
  echo "bundled node does not report v$bundled_node_version" >&2
  exit 1
fi

cp "$repo/docs/quick-start.md" "$bundle/README.md"

cat > "$bundle/RELEASE.json" <<EOF
{
  "version": "$version",
  "implementation": "$implementation",
  "source_revision": "$source_revision",
  "source_dirty": $source_dirty,
  "os": "$os",
  "architecture": "$arch",
  "node": "$bundled_node_version",
  "rust_libc": "glibc (builder baseline; rust bundles only)"
}
EOF

for required in \
  "$bundle/bin/peerspan-host" \
  "$bundle/bin/peerspan" \
  "$bundle/RELEASE.json" \
  "$bundle/share/peerspan/node/bin/node" \
  "$bundle/share/peerspan/node/LICENSE" \
  "$bundle/share/peerspan/integrations/shared/adapter.mjs" \
  "$bundle/share/peerspan/integrations/claude-channel/integration.json" \
  "$bundle/share/peerspan/integrations/codex/integration.json" \
  "$bundle/share/peerspan/integrations/opencode/integration.json" \
  "$bundle/share/peerspan/.claude-plugin/marketplace.json" \
  "$bundle/share/peerspan/integrations/claude-onboarding/.claude-plugin/plugin.json" \
  "$bundle/share/peerspan/integrations/claude-onboarding/hooks/hooks.json" \
  "$bundle/share/peerspan/integrations/claude-onboarding/hooks/register.mjs" \
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
