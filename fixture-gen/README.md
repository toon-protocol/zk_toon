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
verification key data and hash, `land_proof.json` and `setup_proof.json` o1js's final proofs. (`land-step-map.txt` comes from `trace-land.mjs`, below.)
The circuits (`cs00N_*`), the step witnesses (`w001`, `w003`) and `inputs.json` are byte-identical on a rerun.
Two things are pinned so a rerun is byte-identical: the fee payer (o1js picks a random one) and
the blinding of each account update's `callData` (`Fp.random`).

The private keys in `prove-local.mjs` are toy scalars. Never use them for anything else.

`trace-land.mjs` is a development tool for `zk-prover/src/witness`: it proves `land` as `prove-local.mjs`
does and logs the calls into o1js's OCaml side (Poseidon, `scaleFastUnpack`, `truncateToBits16`) and the
input of the account update hash, to `$SPIKE_DUMP/snarky-log.json`. The Rust witness mirrors were checked
against that; the template of the account update's hash input (`src/witness/account_update.rs`) was
dumped with it.
