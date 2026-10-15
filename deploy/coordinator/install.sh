#!/bin/bash
# Installs or upgrades the Peerspan coordinator on Debian 12 or Ubuntu 24.04,
# from an extracted peerspan-coord release archive
# (scripts/package-coordinator.sh). Run as root:
#
#   share/peerspan-coord/deploy/install.sh --listen 0.0.0.0:443 [--no-firewall]
#   share/peerspan-coord/deploy/install.sh --upgrade
#
# It prints {"id", "public_key", "listen", "litestream", "firewall"} as JSON on
# stdout.
# It never generates or reads the private key (peerspan-coord creates it on its
# first start), and contacts nothing except the pinned Litestream download.
# See README.md in this directory.
set -euo pipefail
umask 022

LITESTREAM_VERSION=0.5.17
# From checksums.txt of the Litestream v0.5.17 release.
litestream_sha256() {
  case "$1" in
    x86_64) echo cfb371176d164437ae869f8351cfde49bd1804ae71c61923f75c9cba9c9c006d ;;
    arm64) echo f8ca4a050095c1efbda2c4365172e61bf9d955ea0d9ac42f448b52e51819baa5 ;;
    *) return 1 ;;
  esac
}

USER_NAME=peerspan-coord
STATE_DIR=/var/lib/peerspan-coord
CONFIG_DIR=/etc/peerspan-coord
ENV_FILE=$CONFIG_DIR/peerspan-coord.env
LITESTREAM_ENV=$CONFIG_DIR/litestream.env
SSE_KEY=$CONFIG_DIR/litestream-sse.key
FIREWALL_FILE=$CONFIG_DIR/nftables.nft
BINARY=/usr/local/bin/peerspan-coord
LITESTREAM_BINARY=/usr/local/bin/litestream
UNIT_DIR=/etc/systemd/system
HEALTH_PORT=9464
HEALTH_SECONDS=10

fail() {
  echo "install.sh: $*" >&2
  exit 1
}

usage() {
  echo "usage: $0 --listen HOST:PORT [--litestream-archive FILE] [--no-firewall]" >&2
  echo "       $0 --upgrade" >&2
  exit 2
}

# Debian 12 and Ubuntu 24.04 only; checked before anything else.
os_release=/etc/os-release
[ -e "$os_release" ] || os_release=/usr/lib/os-release
distribution=$(
  # shellcheck disable=SC1090
  . "$os_release" 2>/dev/null && echo "${ID:-}:${VERSION_ID:-}"
) || distribution=unknown
case "$distribution" in
  debian:12|ubuntu:24.04) ;;
  *) fail "this script supports Debian 12 and Ubuntu 24.04 only (found ${distribution})" ;;
esac

listen=
upgrade=false
litestream_archive=
no_firewall=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --listen) [ "$#" -ge 2 ] || usage; listen=$2; shift 2 ;;
    --listen=*) listen=${1#--listen=}; shift ;;
    --upgrade) upgrade=true; shift ;;
    --litestream-archive) [ "$#" -ge 2 ] || usage; litestream_archive=$2; shift 2 ;;
    --litestream-archive=*) litestream_archive=${1#--litestream-archive=}; shift ;;
    --no-firewall) no_firewall=true; shift ;;
    *) usage ;;
  esac
done
if [ "$upgrade" = true ]; then
  if [ -n "$listen" ] || [ -n "$litestream_archive" ] || [ "$no_firewall" = true ]; then usage; fi
else
  [ -n "$listen" ] || usage
fi

[ "$(id -u)" = 0 ] || fail "run as root"
[ -d /run/systemd/system ] || fail "systemd is not running as init"

for command in systemctl useradd runuser sha256sum tar cmp timeout flock; do
  command -v "$command" >/dev/null 2>&1 || fail "missing required command: $command"
done

# The firewall: none with --no-firewall; ufw when it is active, since it then
# manages this machine's firewall; otherwise a table of our own.
ufw_active() {
  command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | head -n 1 | grep -qx 'Status: active'
}
if [ "$no_firewall" = true ]; then
  firewall=none
elif ufw_active; then
  firewall=ufw
else
  firewall=nftables
fi
if [ "$upgrade" = false ] && [ "$firewall" = nftables ]; then
  command -v nft >/dev/null 2>&1 || fail "missing required command: nft (or use --no-firewall)"
fi

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
archive_root=$(CDPATH='' cd -- "$script_dir/../../.." && pwd)
new_binary=$archive_root/bin/peerspan-coord
if [ ! -f "$new_binary" ] || [ ! -x "$new_binary" ]; then
  fail "not run from an extracted release archive: $new_binary is missing"
fi
for file in peerspan-coord.service peerspan-coord.env.example litestream.service litestream.yml; do
  [ -f "$script_dir/$file" ] || fail "missing $script_dir/$file"
done

exec 9>/run/peerspan-coord-install.lock
flock -n 9 || fail "another install.sh is running"

work=$(mktemp -d /tmp/peerspan-coord-install.XXXXXX)
trap 'rm -rf "$work"' EXIT

# put SOURCE DEST MODE OWNER: installs SOURCE as DEST only when the content,
# mode, or owner differ, through a temporary file and rename. Sets changed=1
# when it writes anything.
changed=0
put() {
  local source=$1 dest=$2 mode=$3 owner=$4
  if [ -f "$dest" ] && [ ! -L "$dest" ] && cmp -s -- "$source" "$dest"; then
    if [ "$(stat -c '%a %U:%G' -- "$dest")" != "${mode#0} $owner" ]; then
      chown -- "$owner" "$dest"
      chmod -- "$mode" "$dest"
      changed=1
    fi
    return 0
  fi
  install -m "$mode" -o "${owner%%:*}" -g "${owner##*:}" -- "$source" "$dest.install-new"
  mv -f -- "$dest.install-new" "$dest"
  changed=1
}

# HTTP GET of the loopback /healthz; prints the body when it is 200 and ok.
health() {
  local response
  response=$(timeout 2 bash -c "exec 3<>/dev/tcp/127.0.0.1/$HEALTH_PORT && printf 'GET /healthz HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n' >&3 && cat <&3" 2>/dev/null) || return 1
  case "$response" in
    "HTTP/1."?" 200 "*) ;;
    *) return 1 ;;
  esac
  printf '%s\n' "$response" | grep -q '"status": *"ok"' || return 1
  printf '%s\n' "$response" | sed -n 's/.*"id": *"\([^"]*\)".*/\1/p' | head -n 1
}

# Waits up to HEALTH_SECONDS for /healthz; prints the reported id.
wait_health() {
  local deadline=$((SECONDS + HEALTH_SECONDS)) id
  while :; do
    if id=$(health) && [ -n "$id" ]; then
      echo "$id"
      return 0
    fi
    [ "$SECONDS" -lt "$deadline" ] || return 1
    sleep 0.5
  done
}

# The env file's PEERSPAN_COORD_LISTEN, as systemd reads it (last assignment).
env_listen() {
  sed -n 's/^[[:space:]]*PEERSPAN_COORD_LISTEN=//p' "$ENV_FILE" | tail -n 1 | sed 's/^["'\'']\(.*\)["'\'']$/\1/; s/[[:space:]]*$//'
}

validate_listen() {
  [[ "$1" =~ ^([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\]):([0-9]{1,5})$ ]] || fail "--listen must be HOST:PORT: $1"
  port=$((10#${BASH_REMATCH[2]}))
  if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then fail "--listen port out of range: $1"; fi
}

litestream_configured() {
  [ -f "$LITESTREAM_ENV" ] && [ -f "$SSE_KEY" ]
}

# Reads the latest identity with peerspan-coord info, as the service user so
# no file in the state directory ends up owned by root.
read_identity() {
  local info
  info=$(runuser -u "$USER_NAME" -- "$BINARY" --state "$STATE_DIR" info) || return 1
  identity_id=$(printf '%s\n' "$info" | sed -n 's/^[[:space:]]*"id": "\([^"]*\)".*/\1/p' | head -n 1)
  identity_key=$(printf '%s\n' "$info" | sed -n 's/^[[:space:]]*"public_key": "\([^"]*\)".*/\1/p' | head -n 1)
  [ -n "$identity_id" ] && [ -n "$identity_key" ]
}

print_identity() {
  local status
  read_identity || fail "could not read the coordinator identity with peerspan-coord info"
  status="not configured"
  if litestream_configured && systemctl -q is-enabled litestream.service 2>/dev/null; then
    status=enabled
  fi
  printf '{"id": "%s", "public_key": "%s", "listen": "%s", "litestream": "%s", "firewall": "%s"}\n' "$identity_id" "$identity_key" "$1" "$status" "$2"
}

# --upgrade: replace the binary, restart, and roll back if health fails.
if [ "$upgrade" = true ]; then
  if [ ! -f "$BINARY" ] || [ ! -f "$UNIT_DIR/peerspan-coord.service" ] || [ ! -f "$ENV_FILE" ]; then
    fail "peerspan-coord is not installed; run install.sh --listen HOST:PORT first"
  fi
  listen=$(env_listen)
  read_identity || fail "could not read the coordinator identity with peerspan-coord info"
  previous_id=$identity_id
  if ! cmp -s -- "$new_binary" "$BINARY"; then
    backup=$BINARY.previous
    cp -p -- "$BINARY" "$backup"
    put "$new_binary" "$BINARY" 0755 root:root
    systemctl restart peerspan-coord.service || true
    if ! id=$(wait_health) || [ "$id" != "$previous_id" ]; then
      mv -f -- "$backup" "$BINARY"
      systemctl restart peerspan-coord.service || true
      if wait_health >/dev/null; then
        echo "install.sh: the new peerspan-coord failed /healthz; restored the previous binary" >&2
      else
        echo "install.sh: the new peerspan-coord failed /healthz; restored the previous binary, which is not healthy either" >&2
      fi
      exit 1
    fi
    rm -f -- "$backup"
  fi
  print_identity "$listen" unchanged
  exit 0
fi

# --listen: install, or verify an existing installation.
validate_listen "$listen"
if [ -f "$ENV_FILE" ]; then
  existing=$(env_listen)
  [ "$existing" = "$listen" ] ||
    fail "$ENV_FILE sets PEERSPAN_COORD_LISTEN=$existing; edit it or run with --listen $existing"
fi
if [ -f "$BINARY" ] && ! cmp -s -- "$new_binary" "$BINARY"; then
  fail "a different $BINARY is installed; use install.sh --upgrade to replace it"
fi

# Litestream: fetched and checked before anything changes.
case "$(uname -m)" in
  x86_64|amd64) litestream_arch=x86_64 ;;
  aarch64|arm64) litestream_arch=arm64 ;;
  *) fail "unsupported architecture: $(uname -m)" ;;
esac
litestream_new=
installed_version=
if [ -x "$LITESTREAM_BINARY" ]; then
  installed_version=$("$LITESTREAM_BINARY" version 2>/dev/null || true)
fi
if [ "${installed_version#v}" != "$LITESTREAM_VERSION" ] || [ -n "$litestream_archive" ]; then
  tarball_name=litestream-$LITESTREAM_VERSION-linux-$litestream_arch.tar.gz
  tarball=$work/$tarball_name
  if [ -n "$litestream_archive" ]; then
    cp -- "$litestream_archive" "$tarball" || fail "cannot read $litestream_archive"
  else
    url=https://github.com/benbjohnson/litestream/releases/download/v$LITESTREAM_VERSION/$tarball_name
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL --proto '=https' --retry 3 -o "$tarball" "$url" || fail "cannot download $url"
    elif command -v wget >/dev/null 2>&1; then
      wget -q --https-only -O "$tarball" "$url" || fail "cannot download $url"
    else
      fail "curl or wget is needed to download Litestream"
    fi
  fi
  expected=$(litestream_sha256 "$litestream_arch")
  actual=$(sha256sum -- "$tarball" | cut -d ' ' -f 1)
  [ "$actual" = "$expected" ] || fail "Litestream $tarball_name has SHA-256 $actual, expected $expected"
  tar -xzf "$tarball" -C "$work" litestream || fail "cannot extract litestream from $tarball_name"
  litestream_new=$work/litestream
fi

# The user, directories, and files.
if ! getent passwd "$USER_NAME" >/dev/null; then
  useradd --system --user-group --home-dir "$STATE_DIR" --no-create-home --shell /usr/sbin/nologin "$USER_NAME"
fi
install -d -m 0755 -o root -g root "$CONFIG_DIR"
if [ ! -d "$STATE_DIR" ]; then
  install -d -m 0700 -o "$USER_NAME" -g "$USER_NAME" "$STATE_DIR"
fi

service_changed=0
changed=0
put "$new_binary" "$BINARY" 0755 root:root
service_changed=$((service_changed | changed))

if [ ! -f "$ENV_FILE" ]; then
  sed "s|^PEERSPAN_COORD_LISTEN=.*|PEERSPAN_COORD_LISTEN=$listen|" "$script_dir/peerspan-coord.env.example" > "$work/peerspan-coord.env"
  changed=0
  put "$work/peerspan-coord.env" "$ENV_FILE" 0644 root:root
  service_changed=$((service_changed | changed))
fi

# The unit, with CAP_NET_BIND_SERVICE as its only capability below port 1024.
cp -- "$script_dir/peerspan-coord.service" "$work/peerspan-coord.service"
if [ "$port" -lt 1024 ]; then
  sed -i 's/^CapabilityBoundingSet=$/CapabilityBoundingSet=CAP_NET_BIND_SERVICE/; s/^AmbientCapabilities=$/AmbientCapabilities=CAP_NET_BIND_SERVICE/' "$work/peerspan-coord.service"
  [ "$(grep -c -x -e 'CapabilityBoundingSet=CAP_NET_BIND_SERVICE' -e 'AmbientCapabilities=CAP_NET_BIND_SERVICE' "$work/peerspan-coord.service")" = 2 ] ||
    fail "peerspan-coord.service does not have the expected capability lines"
fi
units_changed=0
changed=0
put "$work/peerspan-coord.service" "$UNIT_DIR/peerspan-coord.service" 0644 root:root
units_changed=$((units_changed | changed))
service_changed=$((service_changed | changed))

litestream_changed=0
changed=0
put "$script_dir/litestream.yml" "$CONFIG_DIR/litestream.yml" 0644 root:root
litestream_changed=$((litestream_changed | changed))
changed=0
put "$script_dir/litestream.service" "$UNIT_DIR/litestream.service" 0644 root:root
units_changed=$((units_changed | changed))
litestream_changed=$((litestream_changed | changed))
if [ -n "$litestream_new" ]; then
  changed=0
  put "$litestream_new" "$LITESTREAM_BINARY" 0755 root:root
  litestream_changed=$((litestream_changed | changed))
fi

# Firewall: with ufw, allow the coordination port over TCP and UDP and leave
# the rest of its rules alone. With our own table: SSH, the coordination port
# over TCP and UDP, and established traffic; everything else inbound is
# dropped. Loopback stays open for the ops listener, and IPv6 neighbor
# discovery for IPv6 to work at all. --no-firewall changes neither.
case "$firewall" in
  ufw)
    ufw allow "$port/tcp" comment peerspan-coord >/dev/null || fail "cannot add the ufw rule for $port/tcp"
    ufw allow "$port/udp" comment peerspan-coord >/dev/null || fail "cannot add the ufw rule for $port/udp"
    ;;
  nftables)
    cat > "$work/nftables.nft" <<EOF
#!/usr/sbin/nft -f
# Written by peerspan-coord install.sh; included from /etc/nftables.conf.
table inet peerspan_coord
delete table inet peerspan_coord
table inet peerspan_coord {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		iif "lo" accept
		icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } ip6 hoplimit 255 accept
		tcp dport 22 accept
		tcp dport $port accept
		udp dport $port accept
	}
}
EOF
    changed=0
    put "$work/nftables.nft" "$FIREWALL_FILE" 0644 root:root
    if [ "$changed" = 1 ] || ! nft list table inet peerspan_coord >/dev/null 2>&1; then
      nft -f "$FIREWALL_FILE" || fail "cannot apply $FIREWALL_FILE"
    fi
    include="include \"$FIREWALL_FILE\""
    if [ ! -f /etc/nftables.conf ]; then
      printf '#!/usr/sbin/nft -f\n%s\n' "$include" > /etc/nftables.conf
    elif ! grep -qxF "$include" /etc/nftables.conf; then
      printf '%s\n' "$include" >> /etc/nftables.conf
    fi
    if ! systemctl -q is-enabled nftables.service 2>/dev/null; then
      systemctl enable nftables.service
    fi
    ;;
esac

# Services.
if [ "$units_changed" = 1 ]; then
  systemctl daemon-reload
fi
if ! systemctl -q is-enabled peerspan-coord.service 2>/dev/null; then
  systemctl enable peerspan-coord.service
fi
if systemctl -q is-active peerspan-coord.service && [ "$service_changed" = 1 ]; then
  systemctl restart peerspan-coord.service
elif ! systemctl -q is-active peerspan-coord.service; then
  systemctl start peerspan-coord.service
fi
wait_health >/dev/null || fail "peerspan-coord did not report healthy within ${HEALTH_SECONDS}s; check journalctl -u peerspan-coord"

if litestream_configured; then
  # Litestream runs as peerspan-coord and must read the key; systemd reads the
  # environment file as root.
  if [ "$(stat -c '%a %U:%G' -- "$SSE_KEY")" != "600 $USER_NAME:$USER_NAME" ]; then
    chown "$USER_NAME:$USER_NAME" "$SSE_KEY"
    chmod 0600 "$SSE_KEY"
  fi
  if [ "$(stat -c '%a %U:%G' -- "$LITESTREAM_ENV")" != "600 root:root" ]; then
    chown root:root "$LITESTREAM_ENV"
    chmod 0600 "$LITESTREAM_ENV"
  fi
  if ! systemctl -q is-enabled litestream.service 2>/dev/null; then
    systemctl enable litestream.service
  fi
  if systemctl -q is-active litestream.service && [ "$litestream_changed" = 1 ]; then
    systemctl restart litestream.service
  elif ! systemctl -q is-active litestream.service; then
    systemctl start litestream.service
  fi
else
  if systemctl -q is-enabled litestream.service 2>/dev/null || systemctl -q is-active litestream.service; then
    systemctl disable --now litestream.service
  fi
  echo "install.sh: Litestream is not configured: $LITESTREAM_ENV and $SSE_KEY are both needed; litestream.service stays disabled (README.md, Litestream)" >&2
fi

print_identity "$listen" "$firewall"
