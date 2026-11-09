# fixture-gen

The code that produced `zk-prover/fixtures/`: a tiny zkApp with two methods, `setup` and `land` (`land.mjs`),
a script that proves both on a `LocalBlockchain` (`prove-local.mjs`) and a patch to o1js 3.1.0
(`patches/o1js+3.1.0.patch`, applied by `patch-package` on `npm ci`) that dumps the step and wrap circuits
(`cs00N_*`) and witnesses (`w00N_*`) and the step proofs (`stepproof00N.b64`) when `SPIKE_DUMP=<dir>` is set.
o1js is pinned to 3.1.0 in `package.json` and `package-lock.json`. This package is separate from the `o1js/`
vector package.

Regenerate every committed fixture, from a clean checkout:

```sh
./regenerate.sh --write
```

It rewrites `zk-prover/fixtures/` (gzipped) and prints the VK hashes; `zk-prover/src/pins.rs` says what to
do with them (bump, run this, update the pins, commit). The gate does not run it: o1js proofs are
randomised, so `stepproof*`, the wrap witnesses (`w002`, `w004`) and `*_proof.json` change on every run and
only match each other within one run. To dump o1js's raw output elsewhere and compare it with the committed
circuits:

```sh
./regenerate.sh /tmp/land-dump
zcat ../zk-prover/fixtures/w003_cs003.json.gz | cmp - /tmp/land-dump/w003_cs003.json
```

What each fixture is: `cs003` is `land`'s step circuit, `cs004` `setup`'s and `cs005` the wrap circuit both
share. `w003` and `w001` are o1js's witnesses for the `land` and `setup` step circuits, `w004` and `w002` its
wrap witnesses for the step proofs `stepproof002` and `stepproof001`. `inputs.json` holds the program's
verification key data and hash, `land_proof.json` and `setup_proof.json` o1js's final proofs.
`rust_land_proof.json` and `rust_setup_proof.json` are the Rust wrap proofs of those step proofs
(`zk-prover`'s `rust_wrap_proofs` example), in `land_proof.json`'s shape, for `o1js/src/rust-wrap.test.ts`.
`rust_witness_land_proof.json` is the same for `land` proved wholly in Rust, from the Rust step witness.
`land-step-map.txt` (from `step-map.mjs`, run by `--write`) names the o1js call site of each of `w003`'s
variables, for `zk-prover`'s witness tests.
The circuits (`cs00N_*`), the step witnesses (`w001`, `w003`), `inputs.json` and `land-step-map.txt` are
byte-identical on a rerun.
Two things are pinned so a rerun is byte-identical: the fee payer (o1js picks a random one) and
the blinding of each account update's `callData` (`Fp.random`).

The private keys in `prove-local.mjs` and `prove-toy.mjs` are toy scalars. Never use them for anything else.

## The toy zkApp that verifies a proof

`land` and `setup` verify no proof. `toy.mjs` is a second toy, kept apart from the vault, for the wrap of a step proof that
verified a previous one: a ZkProgram `toy-inner` with one method (`base`, proving that 49 is a square) and a zkApp `Outer`
with two methods, `plain`, which verifies no proof, and `recurse`, which verifies a proof of `toy-inner`. The zkApp's
`maxProofsVerified` is 1. `prove-toy.mjs` proves both methods on a `LocalBlockchain`, dumping with the same patch; `check-toy.mjs`
checks the numbered dump is laid out as `regenerate.sh` assumes. `./regenerate.sh --write` writes these fixtures too, and
`./regenerate.sh --toy-only` writes only them (and `rust_toy_*`), leaving the `land` and `setup` fixtures as they are.

- `toy_plain_*` and `toy_recurse_*` (`gates.json`, `internal_vars.bin`, `rows_rev.bin`) are the step circuits, `toy_wrap_*` the
  wrap circuit both share.
- `toy_<method>_stepproof.b64` is o1js's step proof and `toy_<method>_stepproof_public.json` its public input: 34 fields, the
  unfinalized proof (32, a dummy for `plain`), the `messages_for_next_step_proof` hash and the `messages_for_next_wrap_proof`
  hash. `toy_<method>_wrap_witness.json` is o1js's wrap witness for that step proof, reduced to its `external` values.
- `toy_inner_proof.json` is the proof of `toy-inner` that `recurse` verified, `toy_inputs.json` holds the zkApp's verification key
  and hash and `toy-inner`'s, and `toy_<method>_proof.json` o1js's final proofs. `rust_toy_<method>_proof.json` are the Rust wrap
  proofs, at `maxProofsVerified` 1, for `o1js/src/rust-wrap.test.ts`, and `rust_witness_toy_<method>_proof.json` the same for the
  methods proved wholly in Rust, from the Rust step witness (`zk-prover`'s `ToyProgram`).
- `toy_<method>_step_witness.json` is o1js's step witness for the method (its public input, then the auxiliary values), and
  `toy_<method>_step_map.txt` names the o1js call site of each variable, as `land-step-map.txt` does, for `zk-prover`'s
  `tests/toy_witness.rs`. `step-map.mjs <dir> <witness> <map>` writes them: o1js's trace counts external values, the public
  input first, and also holds the calls that built the transaction, which it drops.

The circuits, `inputs`-style files (`toy_inputs.json`) and the VK hashes in `zk-prover/src/pins.rs` are byte-identical on a rerun;
the step proofs, the wrap witnesses and `*_proof.json` are not (o1js's proofs are randomised), and neither is the step witness of
`recurse`, which holds the inner proof, so the step witnesses of `recurse` and the `toy_inner_proof.json` it holds come from one run.

`trace-land.mjs` is a development tool for `zk-prover/src/witness`: it proves `land` as `prove-local.mjs`
does and logs the calls into o1js's OCaml side (Poseidon, `scaleFastUnpack`, `truncateToBits16`) and the
input of the account update hash, to `$SPIKE_DUMP/snarky-log.json`. The Rust witness mirrors were checked
against that; the template of the account update's hash input (`src/witness/account_update.rs`) was
dumped with it.
