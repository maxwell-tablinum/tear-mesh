#!/bin/sh
# Builds the Claude Desktop extension: pack.sh OUT.mcpb. Fails if the manifest's version differs from Cargo.toml's.
set -eu
out=${1:?usage: pack.sh OUT.mcpb}
here=$(cd "$(dirname "$0")" && pwd)
crate=$(sed -n 's/^version = "\(.*\)"/\1/p' "$here/../../Cargo.toml" | head -1)
man=$(node -p 'require(process.argv[1]).version' "$here/manifest.json")
test "$crate" = "$man" || { echo "manifest version $man differs from Cargo.toml $crate" >&2; exit 1; }
case $out in /*) ;; *) out=$PWD/$out ;; esac
mkdir -p "$(dirname "$out")"
# Only the extension's own files go in: no README or script.
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
cp -r "$here/manifest.json" "$here/server" "$stage/"
npx --yes @anthropic-ai/mcpb@2.1.2 validate "$stage/manifest.json"
npx --yes @anthropic-ai/mcpb@2.1.2 pack "$stage" "$out"
