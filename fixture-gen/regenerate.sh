#!/usr/bin/env bash
# Regenerate zk-prover's fixtures from o1js 3.1.0 for both `land` and `setup`.
#   ./regenerate.sh --write   rewrite ../zk-prover/fixtures/ (gzipped) and print the VK hashes to pin
#   ./regenerate.sh <dir>     only dump o1js's raw output to <dir>
set -euo pipefail
cd "$(dirname "$0")"
# `npm ci` runs patch-package, which applies patches/o1js+3.1.0.patch (the SPIKE_DUMP dump).
npm ci
if [ "${1:?--write or an output dir}" = "--write" ]; then
  out=$(mktemp -d)
else
  out=$(mkdir -p "$1" && cd "$1" && pwd)
fi
SPIKE_DUMP="$out" node prove-local.mjs
[ "$1" = "--write" ] || exit 0
fixtures=../zk-prover/fixtures
# cs003 is land's step circuit, cs004 setup's, cs005 the wrap circuit. w001/w003 are the step
# witnesses of setup/land, w002/w004 the wrap witnesses; stepproof001/002 are setup's and land's step proofs.
for f in cs00{3,4,5}_gates.json cs00{3,4,5}_internal_vars.bin cs00{3,4,5}_rows_rev.bin inputs.json \
  w001_cs004.json w002_cs005.json w003_cs003.json w004_cs005.json \
  stepproof001.b64 stepproof002.b64 land_proof.json setup_proof.json; do
  gzip -9nc "$out/$f" > "$fixtures/$f.gz"
done
cargo run --quiet -p zk-prover --example vk_hashes
