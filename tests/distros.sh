#!/bin/bash
# Runs tests/e2e-linux.sh and `tearmesh install` (re-run, then uninstall) inside containers of
# several Linux distributions, with the static (musl) binary, so one build is checked everywhere.
# Needs podman (set PODMAN="sudo podman" for rootful, or PODMAN=docker) and network access for
# the packages.
# Usage: cargo build --release --target x86_64-unknown-linux-musl && tests/distros.sh [image...]
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=$ROOT/target/x86_64-unknown-linux-musl/release/tearmesh
[ -x "$BIN" ] || { echo "build first: cargo build --release --target x86_64-unknown-linux-musl" >&2; exit 2; }
IMAGES=("$@")
[ ${#IMAGES[@]} -gt 0 ] || IMAGES=(
  docker.io/library/debian:13
  docker.io/library/ubuntu:24.04
  registry.fedoraproject.org/fedora:42
  docker.io/library/archlinux:latest
  registry.opensuse.org/opensuse/tumbleweed:latest
  docker.io/library/alpine:3.22
)
LOGS=$(mktemp -d /tmp/tm-distros.XXXX)

# Installs what the tests use, with whichever package manager the image has.
DEPS='set -e
if command -v apt-get >/dev/null; then apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sudo openssh-client python3 curl tmux procps passwd >/dev/null
elif command -v dnf >/dev/null; then dnf install -y -q sudo openssh-clients python3 curl tmux procps-ng shadow-utils >/dev/null
elif command -v pacman >/dev/null; then pacman -Sy --noconfirm --needed sudo openssh python curl tmux procps-ng >/dev/null
elif command -v zypper >/dev/null; then zypper -n -q in sudo openssh-clients python3 curl tmux procps shadow >/dev/null
elif command -v apk >/dev/null; then apk add -q sudo openssh-keygen python3 curl tmux bash shadow procps grep coreutils
fi'

run_one() {
  local img=$1 log=$LOGS/$(echo "$1" | tr '/:' '__').log
  ${PODMAN:-podman} run --rm -v "$ROOT:/src:ro" -v "$BIN:/usr/local/bin/tearmesh-test:ro" \
    -e TEARMESH_BIN=/usr/local/bin/tearmesh-test "$img" sh -c "$DEPS
      echo '== e2e'; bash /src/tests/e2e-linux.sh || true
      echo '== install'
      tearmesh-test install box 2>&1 | tail -3 | tee /tmp/bare | sed 's/^/  /'
      grep -q 'No boundaries yet' /tmp/bare && grep -q '^machine = \"box\"' /etc/tearmesh/config.toml && echo 'BARE OK' || echo 'BARE FAILED'
      tearmesh-test install box work vault 2>&1 | tail -3
      # tm-pre existed before install, so uninstall keeps it.
      { useradd -m tm-pre 2>/dev/null || adduser -D tm-pre; } >/dev/null
      tearmesh install box work vault extra pre 2>&1 | tail -3
      id tm-work >/dev/null && id tm-vault >/dev/null && id tm-extra >/dev/null \
        && test \"\$(grep -c '^tm-work = ' /etc/tearmesh/config.toml)\" = 1 && grep -q '^tm-extra = \"extra\"' /etc/tearmesh/config.toml \
        && test \"\$(stat -c %a /home/tm-vault)\" = 700 && test \"\$(stat -c %U /var/lib/tearmesh/node.key)\" = tearmesh \
        && su -s /bin/sh tm-work -c 'cat /usr/local/share/tearmesh/.claude-plugin/marketplace.json' >/dev/null \
        && tearmesh install >/dev/null 2>&1 && grep -q '^machine = \"box\"' /etc/tearmesh/config.toml \
        && ! tearmesh install other work 2>/dev/null && echo 'SETUP OK' || echo 'SETUP FAILED'
      # With no names, uninstall deletes the tm-* users install made.
      tearmesh uninstall --yes 2>&1 | tail -4 | tee /tmp/un
      grep -q 'kept (not created by install): tm-pre' /tmp/un && id tm-pre >/dev/null \
        && ! getent passwd | grep -v '^tm-pre:' | grep -q '^tm-' && ! id tearmesh 2>/dev/null && test ! -e /etc/tearmesh \
        && test ! -e /etc/init.d/tearmesh && test ! -e /etc/systemd/system/tearmesh.service && test ! -e /etc/systemd/system/tearmesh-update.timer && test ! -e /usr/local/bin/tearmesh \
        && echo 'UNINSTALL OK' || echo 'UNINSTALL FAILED'" >"$log" 2>&1
  local e2e setup
  e2e=$(grep -E '^(ALL PASSED|FAIL )' "$log" | head -3 | tr '\n' ' ')
  setup=$(grep -E '^(BARE|SETUP|UNINSTALL)' "$log" | tr '\n' ' ')
  printf '%-52s %s | %s\n' "$img" "${e2e:-no result (see $log)}" "${setup:-no setup result}"
}

for img in "${IMAGES[@]}"; do run_one "$img" & done
wait
echo "logs: $LOGS"
