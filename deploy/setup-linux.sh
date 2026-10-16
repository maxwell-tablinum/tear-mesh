#!/bin/sh
# Installs tear-mesh on one Linux machine: the binary, a `tearmesh` system user for the daemon,
# one OS user per boundary (tm-<boundary>, private home), the config and the systemd units.
# Usage: sudo deploy/setup-linux.sh <machine-name> <boundary>...
set -eu
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
[ $# -ge 2 ] || { echo "usage: $0 <machine-name> <boundary>..." >&2; exit 1; }
here=$(cd "$(dirname "$0")" && pwd)
machine=$1; shift
bin=${TEARMESH_BIN:-$here/../target/release/tearmesh}

install -m 0755 "$bin" /usr/local/bin/tearmesh
id tearmesh >/dev/null 2>&1 || useradd --system --home-dir /var/lib/tearmesh --shell /usr/sbin/nologin tearmesh

users=""
for b in "$@"; do
  u="tm-$b"
  id "$u" >/dev/null 2>&1 || useradd --create-home --shell /bin/bash "$u"
  # Boundaries can't read each other's files, transcripts or agent logins.
  chmod 0700 "$(getent passwd "$u" | cut -d: -f6)"
  users="$users$u = \"$b\"
"
done

mkdir -p /etc/tearmesh
if [ ! -e /etc/tearmesh/config.toml ]; then
  printf 'machine = "%s"\n\n[users]\n%s' "$machine" "$users" > /etc/tearmesh/config.toml
  chmod 0644 /etc/tearmesh/config.toml
else
  echo "/etc/tearmesh/config.toml exists; left as is" >&2
fi

# Create the node key before the service starts, so both see the same key.
install -d -o tearmesh -g tearmesh -m 0700 /var/lib/tearmesh
id=$(sudo -u tearmesh /usr/local/bin/tearmesh id --config /etc/tearmesh/config.toml)

install -m 0644 "$here/tearmesh.service" /etc/systemd/system/tearmesh.service
install -m 0644 "$here/tearmesh-waker@.service" /etc/systemd/system/tearmesh-waker@.service
systemctl daemon-reload
systemctl enable --now tearmesh
echo "machine $machine, node id: $id"
