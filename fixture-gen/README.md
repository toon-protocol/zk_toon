# fixture-gen

The code that produced `zk-prover/fixtures/`: a tiny zkApp (`land.mjs`), a script that proves it on a
`LocalBlockchain` (`prove-local.mjs`) and a patch to o1js 3.1.0 (`patches/o1js+3.1.0.patch`, applied by
`patch-package` on `npm ci`) that dumps the step and wrap circuits (`cs00N_*`) and witnesses (`w00N_*`)
when `SPIKE_DUMP=<dir>` is set. o1js is pinned to 3.1.0 in `package.json` and `package-lock.json`.
This package is separate from the `o1js/` vector package.

```sh
./regenerate.sh /tmp/land-dump
zcat ../zk-prover/fixtures/w003_cs003.json.gz | cmp - /tmp/land-dump/w003_cs003.json
```

`cs003` is `land`'s step circuit and `w003` o1js's witness for it. The same check works for
`cs003_gates.json`, `cs003_internal_vars.bin`, `cs003_rows_rev.bin` and `inputs.json`.
Two things are pinned so a rerun is byte-identical: the fee payer (o1js picks a random one) and
the blinding of each account update's `callData` (`Fp.random`).

The private keys in `prove-local.mjs` are toy scalars. Never use them for anything else.

`trace-land.mjs` is a development tool for `zk-prover/src/witness`: it proves `land` as `prove-local.mjs`
does and logs the calls into o1js's OCaml side (Poseidon, `scaleFastUnpack`, `truncateToBits16`) and the
input of the account update hash, to `$SPIKE_DUMP/snarky-log.json`. The Rust witness mirrors were checked
against that; the template of the account update's hash input (`src/witness/account_update.rs`) was
dumped with it.
