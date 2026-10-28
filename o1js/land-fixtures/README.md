# land fixtures

The code that produced `zk-prover/fixtures/`: a tiny zkApp (`land.mjs`), a script that proves it on a
`LocalBlockchain` (`prove-local.mjs`) and the two o1js 3.1.0 patches (`patches/`) that dump the step and
wrap circuits (`cs00N_*`) and witnesses (`w00N_*`) when `SPIKE_DUMP=<dir>` is set. o1js is pinned to 3.1.0
in `package.json` and `package-lock.json`.

```sh
./regenerate.sh /tmp/land-dump
zcat ../../zk-prover/fixtures/w003_cs003.json.gz | cmp - /tmp/land-dump/w003_cs003.json
```

`cs003` is `land`'s step circuit and `w003` o1js's witness for it. The same check works for
`cs003_gates.json`, `cs003_internal_vars.bin`, `cs003_rows_rev.bin` and `inputs.json`.
Two things are pinned so a rerun is byte-identical: the fee payer (o1js picks a random one) and
the blinding of each account update's `callData` (`Fp.random`).

The private keys in `prove-local.mjs` are toy scalars. Never use them for anything else.
