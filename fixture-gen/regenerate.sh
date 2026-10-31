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
node step-map.mjs "$out"
fixtures=../zk-prover/fixtures
# cs003 is land's step circuit, cs004 setup's, cs005 the wrap circuit. w001/w003 are the step
# witnesses of setup/land, w002/w004 the wrap witnesses; stepproof001/002 are setup's and land's step proofs.
# land-step-map.txt is step-map.mjs's call-site map of w003.
for f in cs00{3,4,5}_gates.json cs00{3,4,5}_internal_vars.bin cs00{3,4,5}_rows_rev.bin inputs.json \
  w001_cs004.json w002_cs005.json w003_cs003.json w004_cs005.json \
  stepproof001.b64 stepproof002.b64 land_proof.json setup_proof.json land-step-map.txt; do
  gzip -9nc "$out/$f" > "$fixtures/$f.gz"
done
# A step proof's public input (the hash of its messages_for_next_step_proof) is not in its dump, but o1js's
# wrap witness carries it as field 12: stepproof001 pairs with w002, stepproof002 with w004.
for pair in 001:w002_cs005 002:w004_cs005; do
  node -e 'const w=JSON.parse(require("fs").readFileSync(process.argv[1]));console.log(JSON.stringify([w.external[12]]))' \
    "$out/${pair#*:}.json" | gzip -9nc > "$fixtures/stepproof${pair%%:*}_public.json.gz"
done
# The Rust wrap proofs of both step proofs, in the form o1js's `verify` reads (o1js/src/rust-wrap.test.ts).
rust=$(mktemp -d)
cargo run --quiet --release -p zk-prover --example rust_wrap_proofs -- "$rust"
for m in land setup; do
  gzip -9nc "$rust/rust_${m}_proof.json" > "$fixtures/rust_${m}_proof.json.gz"
done
cargo run --quiet -p zk-prover --example vk_hashes
