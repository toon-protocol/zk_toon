#!/usr/bin/env bash
# Regenerate zk-prover's fixtures from o1js 3.1.0 for both `land` and `setup`.
#   ./regenerate.sh --write        rewrite ../zk-prover/fixtures/ (gzipped) and print the VK hashes to pin
#   ./regenerate.sh <dir>          only dump o1js's raw output to <dir> (the toy's to <dir>/toy)
#   ./regenerate.sh --toy-only     rewrite only the toy fixtures (`toy_*`), which `toy.mjs` makes
set -euo pipefail
cd "$(dirname "$0")"
# `npm ci` runs patch-package, which applies patches/o1js+3.1.0.patch (the SPIKE_DUMP dump).
npm ci
if [ "${1:?--write or an output dir}" = "--write" ]; then
  out=$(mktemp -d)
elif [ "$1" = "--toy-only" ]; then
  out=$(mktemp -d)
else
  out=$(mkdir -p "$1" && cd "$1" && pwd)
fi
fixtures=../zk-prover/fixtures
if [ "$1" != "--toy-only" ]; then
SPIKE_DUMP="$out" node prove-local.mjs
fi
# The toy that exercises recursion (`toy.mjs`): its own dump, since o1js numbers circuits and witnesses
# from 1 on each run.
toy="$out/toy"
mkdir -p "$toy"
SPIKE_DUMP="$toy" node prove-toy.mjs
if [ "$1" = "--write" ] || [ "$1" = "--toy-only" ]; then
  # The numbers are fixed by the order `prove-toy.mjs` compiles and proves in: cs006 and cs007 are the step
  # circuits of `plain` and `recurse`, cs008 the wrap circuit both share; stepproof002/003 and w003/w005
  # are their step proofs and step witnesses, w004/w006 the wrap witnesses.
  node check-toy.mjs "$toy"
  for pair in plain:cs006 recurse:cs007 wrap:cs008; do
    for ext in gates.json internal_vars.bin rows_rev.bin; do
      gzip -9nc "$toy/${pair#*:}_$ext" > "$fixtures/toy_${pair%%:*}_$ext.gz"
    done
  done
  # Only the values the Rust tests read: o1js's wrap witnesses carry the circuit's columns too.
  for pair in plain:w004_cs008 recurse:w006_cs008; do
    node -e 'const w=JSON.parse(require("fs").readFileSync(process.argv[1]));console.log(JSON.stringify({public_input_size:w.public_input_size,external:w.external}))' \
      "$toy/${pair#*:}.json" | gzip -9nc > "$fixtures/toy_${pair%%:*}_wrap_witness.json.gz"
  done
  # o1js's step witnesses, with the call site of each variable (`toy_<method>_step_map.txt`, from `step-map.mjs`).
  for pair in plain:w003_cs006 recurse:w005_cs007; do
    node -e 'const w=JSON.parse(require("fs").readFileSync(process.argv[1]));console.log(JSON.stringify({public_input_size:w.public_input_size,external:w.external}))' \
      "$toy/${pair#*:}.json" | gzip -9nc > "$fixtures/toy_${pair%%:*}_step_witness.json.gz"
    node step-map.mjs "$toy" "${pair#*:}" "toy_${pair%%:*}_step_map"
    gzip -9nc "$toy/toy_${pair%%:*}_step_map.txt" > "$fixtures/toy_${pair%%:*}_step_map.txt.gz"
  done
  gzip -9nc "$toy/stepproof002.b64" > "$fixtures/toy_plain_stepproof.b64.gz"
  gzip -9nc "$toy/stepproof003.b64" > "$fixtures/toy_recurse_stepproof.b64.gz"
  # A step proof's public input is not in its dump, but o1js's step witness starts with it.
  for pair in plain:w003_cs006 recurse:w005_cs007; do
    node -e 'const w=JSON.parse(require("fs").readFileSync(process.argv[1]));console.log(JSON.stringify(w.external.slice(0,w.public_input_size)))' \
      "$toy/${pair#*:}.json" | gzip -9nc > "$fixtures/toy_${pair%%:*}_stepproof_public.json.gz"
  done
  for f in inputs.json inner_proof.json plain_proof.json recurse_proof.json; do
    gzip -9nc "$toy/$f" > "$fixtures/toy_$f.gz"
  done
fi
# The Rust wrap proofs, in the form o1js's `verify` reads (o1js/src/rust-wrap.test.ts).
rust_proofs() {
  rust=$(mktemp -d)
  cargo run --quiet --release -p zk-prover --example rust_wrap_proofs -- "$rust"
  for m in "$@"; do
    gzip -9nc "$rust/rust_${m}_proof.json" > "$fixtures/rust_${m}_proof.json.gz"
  done
}
if [ "$1" = "--toy-only" ]; then
  rust_proofs toy_plain toy_recurse witness_toy_plain witness_toy_recurse
  cargo run --quiet -p zk-prover --example vk_hashes
  exit 0
fi
[ "$1" = "--write" ] || exit 0
node step-map.mjs "$out"
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
rust_proofs land setup witness_land toy_plain toy_recurse witness_toy_plain witness_toy_recurse
cargo run --quiet -p zk-prover --example vk_hashes
