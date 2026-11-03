#!/usr/bin/env bash
# Installed acceptance, run on a developer machine instead of CI (DEC-OWN18):
# package a bundle from this checkout, then run the installed bundle,
# onboarding, terminal, upgrade and participant checks against it. It writes
# sanitized receipts to WORK_DIR/receipts and exits non-zero if any check fails.
set -euo pipefail

usage() {
  echo "usage: $0 [WORK_DIR]" >&2
  exit 2
}

[ "$#" -le 1 ] || usage
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(dirname "$script_dir")
cd "$repo"

# The versions CI used: Linux, Node.js 22, Python 3.12 and the pinned native CLI.
claude_version=2.1.303
case "$(uname -m)" in
  x86_64 | amd64) architecture=amd64 ;;
  aarch64 | arm64) architecture=arm64 ;;
  *) echo "unsupported architecture $(uname -m)" >&2; exit 2 ;;
esac
[ "$(uname -s)" = Linux ] || { echo "installed acceptance needs Linux" >&2; exit 2; }
python3 -c 'import sys; sys.exit(sys.version_info < (3, 12))' || { echo "needs Python 3.12 or later" >&2; exit 2; }
for command in cargo node npm sha256sum git; do
  command -v "$command" >/dev/null || { echo "missing $command" >&2; exit 2; }
done

work=${1:-$(mktemp -d "${TMPDIR:-/tmp}/peerspan-acceptance.XXXXXX")}
mkdir -p "$work"
work=$(CDPATH= cd -- "$work" && pwd)
# The checks put daemon sockets several directories below WORK_DIR, and a Unix
# socket path must fit in 108 bytes.
[ "${#work}" -le 40 ] || { echo "$work is too long for the daemons' socket paths; use a WORK_DIR of at most 40 characters" >&2; exit 2; }
[ -z "$(ls -A "$work")" ] || { echo "$work is not empty" >&2; exit 2; }
echo "work directory: $work"

export DISABLE_UPDATES=1 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
dist="$work/dist"
old_target="$work/old-target"

npm install --prefix "$work/claude" --no-audit --no-fund --save-exact "@anthropic-ai/claude-code@$claude_version"
claude="$work/claude/node_modules/.bin/claude"
python3 -m venv "$work/venv"
"$work/venv/bin/pip" install --quiet --disable-pip-version-check -r conformance/requirements-terminal.txt
python="$work/venv/bin/python"

python3 conformance/test_package_release.py
python3 conformance/test_onboarding_package.py

bundle_version="$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["package"]["version"])')-local"
scripts/package-release.sh rust "$bundle_version" "$dist"
archive="$dist/peerspan-${bundle_version}-linux-${architecture}-rust.tar.gz"
(cd "$dist" && sha256sum -c "$(basename "$archive").sha256")
python3 conformance/installed_bundle.py --archive "$archive" --node "$(command -v node)"
python3 conformance/onboarding_bundle.py --archive "$archive" --claude "$claude"

# The remaining checks each record an outcome and the receipts are written
# whatever they are, as the CI job did.
terminal=failure upgrade=failure participants=failure

if "$python" conformance/installed_terminal.py --archive "$archive" --claude "$claude" \
    --work "$work/terminal"; then
  terminal=success
fi

# Genuine old hosts for the upgrade check, built from exported sources of the
# commits that introduced schemas 23, 24 and 27.
upgrade_check() {
  local history commit
  mkdir -p "$work/old-binaries"
  for history in old23:2719d9978ddb86fba003675217fd04922de77a9f \
      main24:7d675b6f80304c82e1ad3162b94e5ba305ecdffb \
      feature27:a214ec687d820689269be95c5e31fb6001a443a3; do
    commit=${history#*:}
    history=${history%%:*}
    mkdir -p "$work/sources/$history"
    git archive "$commit" | tar -x -C "$work/sources/$history"
    # The histories share a package identity. Clear only this package so
    # mtime-based reuse cannot substitute another history.
    CARGO_TARGET_DIR="$old_target" cargo clean --manifest-path "$work/sources/$history/rust/Cargo.toml" -p peerspan-host
    CARGO_TARGET_DIR="$old_target" CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
      cargo build --locked --manifest-path "$work/sources/$history/rust/Cargo.toml" --bin peerspan-host
    cp "$old_target/debug/peerspan-host" "$work/old-binaries/$history"
  done
  python3 conformance/installed_upgrade.py --archive "$archive" \
    --old23 "$work/old-binaries/old23" --main24 "$work/old-binaries/main24" \
    --feature27 "$work/old-binaries/feature27" --work "$work/upgrade"
}
if (upgrade_check); then
  upgrade=success
fi

participant_check() {
  CARGO_TARGET_DIR="$old_target" cargo clean -p peerspan-host
  CARGO_TARGET_DIR="$old_target" CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
    cargo build --locked --bin peerspan-peer-probe
  python3 conformance/installed_participants.py --archive "$archive" \
    --sha256 "$(sha256sum "$archive" | cut -d ' ' -f 1)" \
    --probe "$old_target/debug/peerspan-peer-probe" --suite all --work-dir "$work/participants"
}
if (participant_check); then
  participants=success
fi

python3 conformance/acceptance_receipts.py --terminal-work "$work/terminal" \
  --upgrade-work "$work/upgrade" --participants-work "$work/participants" \
  --archive-dir "$dist" --output "$work/receipts"
printf '{"candidate_sha": "%s", "PARTICIPANT_OUTCOME": "%s", "TERMINAL_OUTCOME": "%s", "UPGRADE_OUTCOME": "%s"}\n' \
  "$(git rev-parse HEAD)" "$participants" "$terminal" "$upgrade" > "$work/receipts/gate-outcomes.json"

echo "terminal: $terminal, upgrade: $upgrade, participants: $participants"
echo "receipts: $work/receipts"
[ "$terminal$upgrade$participants" = successsuccesssuccess ]
