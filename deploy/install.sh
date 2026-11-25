#!/bin/sh
# Downloads this release's tear-mesh binary, checks it against the SHA-256 pinned below, and runs
# `tearmesh install` with the arguments given. The release workflow fills in the placeholders.
#   curl -fsSL <release>/install.sh | sudo sh -s -- [<machine> [<boundary>...]]
#   curl -fsSL <release>/install.sh | sudo sh -s -- --join <ticket>
#   curl -fsSL <release>/install.sh | sudo sh -s -- --uninstall [--keep-users]
# The pinned SHA protects against a replaced binary, not against a replaced copy of this script.
# TEARMESH_RELEASE_URL replaces the download folder (for tests).
set -eu

# Everything is in main, so a download cut short runs nothing (stdin is this script under `| sh`).
main() {
  [ "$(uname -s)" = Linux ] || { echo "install.sh is for Linux (this is $(uname -s)); on Windows use install.ps1" >&2; exit 1; }
  VERSION=@VERSION@
  RELEASES=https://github.com/maxwell-tablinum/tear-mesh/releases/download
  [ "$(id -u)" = 0 ] || { echo "run as root: ... | sudo sh -s -- $*" >&2; exit 1; }
  if [ "${1:-}" = --uninstall ]; then
    shift
    [ -x /usr/local/bin/tearmesh ] || { echo "tear-mesh isn't installed (no /usr/local/bin/tearmesh)" >&2; exit 1; }
    # The confirmation reads the terminal: stdin is this script. With no terminal (CI), it reads
    # nothing, so only --yes goes ahead.
    if (: </dev/tty) 2>/dev/null; then exec /usr/local/bin/tearmesh uninstall "$@" </dev/tty; fi
    exec /usr/local/bin/tearmesh uninstall "$@" </dev/null
  fi
  case $(uname -m) in
    x86_64 | amd64) asset=tearmesh-x86_64-linux sha=@SHA_X86_64_LINUX@ ;;
    aarch64 | arm64) asset=tearmesh-aarch64-linux sha=@SHA_AARCH64_LINUX@ ;;
    *) echo "no tear-mesh build for $(uname -m)" >&2; exit 1 ;;
  esac
  base=${TEARMESH_RELEASE_URL:-$RELEASES/v$VERSION}
  dir=$(mktemp -d)
  trap 'rm -rf "$dir"' EXIT
  f=$dir/tearmesh
  if command -v curl >/dev/null; then
    curl -fsSL -o "$f" "$base/$asset"
  elif command -v wget >/dev/null; then
    wget -q -O "$f" "$base/$asset"
  else
    echo "needs curl or wget" >&2; exit 1
  fi
  echo "$sha  $f" | sha256sum -c - >/dev/null 2>&1 || { echo "checksum mismatch: not installing" >&2; exit 1; }
  chmod 755 "$f"
  "$f" install "$@" </dev/null
}

main "$@"
