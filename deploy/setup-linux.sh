#!/bin/sh
# Installs tear-mesh on one Linux machine: the binary, a `tearmesh` system user for the daemon,
# one OS user per boundary (tm-<boundary>, private home), the config and the service (systemd or
# OpenRC). The user who ran sudo becomes an admin, so `tearmesh setup`, `mesh invite` and
# `status` work without sudo.
# `sudo tearmesh install` runs a copy of this script built into the binary; running it from a
# clone works too. Running it again upgrades the binary, adds new boundary users and restarts.
# Usage: sudo deploy/setup-linux.sh <machine-name> <boundary>...
#        TEARMESH_BIN=/path/to/tearmesh sudo -E deploy/setup-linux.sh ...   (a prebuilt binary)
#        sudo deploy/setup-linux.sh --uninstall [<boundary>...]   (also deletes those users)
set -eu
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
here=$(cd "$(dirname "$0")" && pwd)

if [ "${1:-}" = --uninstall ]; then
  shift
  if [ -d /run/systemd/system ]; then
    systemctl disable --now tearmesh 'tearmesh-steward@*' >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/tearmesh.service /etc/systemd/system/tearmesh-steward@.service
    systemctl daemon-reload
  elif command -v rc-service >/dev/null; then
    rc-service tearmesh stop >/dev/null 2>&1 || true
    rc-update del tearmesh default >/dev/null 2>&1 || true
    rm -f /etc/init.d/tearmesh
  fi
  pkill -u tearmesh >/dev/null 2>&1 || true
  for b in "$@"; do
    u="tm-$b"
    id "$u" >/dev/null 2>&1 || continue
    pkill -u "$u" >/dev/null 2>&1 || true
    if command -v userdel >/dev/null; then userdel -r "$u" 2>/dev/null || userdel "$u"; else deluser --remove-home "$u"; fi
  done
  if id tearmesh >/dev/null 2>&1; then
    if command -v userdel >/dev/null; then userdel tearmesh; else deluser tearmesh; fi
  fi
  rm -rf /usr/local/bin/tearmesh /usr/local/share/tearmesh /etc/tearmesh /var/lib/tearmesh /var/log/tearmesh.log
  echo "tear-mesh removed${1:+, with users $(printf 'tm-%s ' "$@")}"
  exit 0
fi

[ $# -ge 2 ] || { echo "usage: $0 <machine-name> <boundary>..." >&2; exit 1; }
machine=$1; shift
bin=${TEARMESH_BIN:-}
if [ -z "$bin" ]; then
  for b in "$here/../target/release/tearmesh" "$here/../target/x86_64-unknown-linux-musl/release/tearmesh"; do
    [ -x "$b" ] && bin=$b && break
  done
fi
[ -n "$bin" ] && [ -x "$bin" ] || { echo "no tearmesh binary: build it or set TEARMESH_BIN" >&2; exit 1; }
nologin=$(command -v nologin || echo /sbin/nologin)
shell=$(command -v bash || echo /bin/sh)

# useradd where it exists; BusyBox adduser otherwise (Alpine without the shadow package).
add_system_user() {
  if command -v useradd >/dev/null; then useradd --system --home-dir /var/lib/tearmesh --shell "$nologin" "$1"
  else adduser -S -D -H -h /var/lib/tearmesh -s "$nologin" "$1"; fi
}
add_user() {
  if command -v useradd >/dev/null; then useradd --create-home --shell "$shell" "$1"
  else adduser -D -s "$shell" "$1"; fi
}

# Copied beside it and renamed over it, so this works while the old one runs (or is $bin).
cp "$bin" /usr/local/bin/.tearmesh.new && chmod 0755 /usr/local/bin/.tearmesh.new
mv -f /usr/local/bin/.tearmesh.new /usr/local/bin/tearmesh
id tearmesh >/dev/null 2>&1 || add_system_user tearmesh

users=""
for b in "$@"; do
  u="tm-$b"
  id "$u" >/dev/null 2>&1 || add_user "$u"
  # Boundaries can't read each other's files, transcripts or agent logins.
  chmod 0700 "$(getent passwd "$u" | cut -d: -f6)"
  users="$users$u = \"$b\"
"
done

admins=""
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then admins="admins = [\"$SUDO_USER\"]
"; fi
mkdir -p /etc/tearmesh
if [ ! -e /etc/tearmesh/config.toml ]; then
  printf 'machine = "%s"\n%s\n[users]\n%s' "$machine" "$admins" "$users" > /etc/tearmesh/config.toml
  chmod 0644 /etc/tearmesh/config.toml
else
  echo "/etc/tearmesh/config.toml exists; left as is" >&2
fi

# Create the node key before the service starts, so both see the same key.
install -d -o tearmesh -m 0700 /var/lib/tearmesh
id=$(su -s /bin/sh tearmesh -c "/usr/local/bin/tearmesh id --config /etc/tearmesh/config.toml")

if [ -d /run/systemd/system ]; then
  install -m 0644 "$here/tearmesh.service" /etc/systemd/system/tearmesh.service
  install -m 0644 "$here/tearmesh-steward@.service" /etc/systemd/system/tearmesh-steward@.service
  systemctl daemon-reload
  systemctl enable tearmesh >/dev/null 2>&1
  # A restart picks up a new binary or config on a re-run.
  systemctl restart tearmesh
  started="systemd: tearmesh.service (stewards: systemctl enable --now tearmesh-steward@tm-<boundary>)"
elif command -v rc-service >/dev/null; then
  install -m 0755 "$here/openrc/tearmesh" /etc/init.d/tearmesh
  rc-update add tearmesh default >/dev/null
  rc-service tearmesh restart
  started="OpenRC: /etc/init.d/tearmesh (run a steward per boundary user yourself: tearmesh steward)"
else
  started="no systemd or OpenRC found: start it yourself as the tearmesh user: tearmesh daemon --config /etc/tearmesh/config.toml"
fi
echo "machine $machine, node id: $id"
echo "$started"
