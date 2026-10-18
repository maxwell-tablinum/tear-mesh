#!/bin/sh
# Installs tear-mesh on one Linux machine: the binary, a `tearmesh` system user for the daemon,
# one OS user per boundary (tm-<boundary>, private home), the config and the service (systemd or
# OpenRC). The user who ran sudo becomes an admin, so `tearmesh setup`, `mesh invite` and
# `status` work without sudo.
# Usage: sudo deploy/setup-linux.sh <machine-name> <boundary>...
#        TEARMESH_BIN=/path/to/tearmesh sudo -E deploy/setup-linux.sh ...   (a prebuilt binary)
set -eu
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
[ $# -ge 2 ] || { echo "usage: $0 <machine-name> <boundary>..." >&2; exit 1; }
here=$(cd "$(dirname "$0")" && pwd)
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

install -m 0755 "$bin" /usr/local/bin/tearmesh
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
  systemctl enable --now tearmesh
  started="systemd: tearmesh.service (stewards: systemctl enable --now tearmesh-steward@tm-<boundary>)"
elif command -v rc-service >/dev/null; then
  install -m 0755 "$here/openrc/tearmesh" /etc/init.d/tearmesh
  rc-update add tearmesh default >/dev/null
  rc-service tearmesh start
  started="OpenRC: /etc/init.d/tearmesh (run a steward per boundary user yourself: tearmesh steward)"
else
  started="no systemd or OpenRC found: start it yourself as the tearmesh user: tearmesh daemon --config /etc/tearmesh/config.toml"
fi
echo "machine $machine, node id: $id"
echo "$started"
