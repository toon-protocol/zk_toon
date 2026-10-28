#!/usr/bin/env bash
# Regenerate zk-prover's `land` fixtures (cs003_*, w003_cs003.json, inputs.json) from o1js 3.1.0.
# Usage: ./regenerate.sh <output-dir>
set -euo pipefail
cd "$(dirname "$0")"
out=$(mkdir -p "${1:?output dir}" && cd "$1" && pwd)
npm ci
bindings=node_modules/o1js/dist/node/bindings/compiled/node_bindings/o1js_node.bc.cjs
if ! grep -q SPIKE_DUMP "$bindings"; then
  patch -p0 < patches/o1js_node.bc.cjs.patch
  patch -p0 < patches/exists.js.patch
fi
SPIKE_DUMP="$out" node prove-local.mjs
