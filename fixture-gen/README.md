# fixture-gen

The code that produced `zk-prover/fixtures/`: a tiny zkApp with two methods, `setup` and `land` (`land.mjs`),
a script that proves both on a `LocalBlockchain` (`prove-local.mjs`) and a patch to o1js 3.1.0
(`patches/o1js+3.1.0.patch`, applied by `patch-package` on `npm ci`) that dumps the step and wrap circuits
(`cs00N_*`) and witnesses (`w00N_*`) and the step proofs (`stepproof00N.b64`) when `SPIKE_DUMP=<dir>` is set.
o1js is pinned to 3.1.0 in `package.json` and `package-lock.json`. This package is separate from the `o1js/`
vector package.

Regenerate every committed fixture except the real vault's (`vault_*`, `chunk_*`, see below), from a clean checkout:

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

## The real vault and the action-stack program

`./regenerate.sh --vault` (about half an hour; leave the other fixtures as they are) proves every method of the real `Vault`
(`../o1js/src/vault.ts`) on a `LocalBlockchain`, with the dump patch on in its light mode (`SPIKE_DUMP_LIGHT=1`, which leaves
out the witness columns; `SPIKE_DUMP_TRACE=1` keeps the call-site trace, which the step maps are made from), and writes the fixtures for `zk-prover`'s wrap of them. The vault is
deployed under its own key, not through the registry, whose circuit no fixture needs. o1js's wasm prover hangs on `reduce`
(about 56k rows, 2^16) when every prover key is held in memory, so the run is three processes, all `vault-fixtures.ts`,
which `../o1js`'s `tsx` runs with `vault-register.mjs` pointing the vault sources' `import 'o1js'` at this package's patched copy:

- `compile` compiles with an empty cache directory: every circuit is dumped, and the keys are written to the cache.
- `main` compiles from that cache (the keys load lazily) and proves `setup`, `deposit`, `reduce`, `mutualClose`, `escape`,
  `defeat`, `raise`, `finalize` and `sweepExpired`.
- `recursive` does the same and proves the real action-stack chunks (`proveChunk`) for more pending action lists than
  one `reduce` takes, then `reduce` again from them. `provableBatches` (`../o1js/src/vault-view.ts`) builds them: the last
  chunk from a dummy proof of the program's domain, 2^15 (o1js 3.1.0's own dummy has the wrong domain, see #71), the one before
  from that chunk.

Each process numbers circuits and witnesses from 1; `vault-collect.mjs` reads each case's files from the process that
made it, checks that every circuit is among `compile`'s and that no two vault methods share a step circuit, and writes:

- `vault_<method>_*` and `chunk_*` (`gates.json`, `internal_vars.bin`, `rows_rev.bin`), the step circuits; `vault_wrap_*` and
  `chunk_wrap_*`, the wrap circuit of the vault and of the action-stack program.
- For each case, `<case>_stepproof.b64` (o1js's step proof), `<case>_stepproof_public.json` (its public input),
  `<case>_wrap_witness.json` (o1js's wrap witness, reduced to its `external` values). The cases are the nine methods
  (`vault_<method>`), `vault_reduce_recursive` (`reduce` from the real chunk, the same circuit as `vault_reduce`),
  `chunk_dummy` and `chunk_chained` (`proveChunk` from the dummy and from the real previous chunk, one circuit, `chunk`).
- For `chunk_dummy` and `chunk_chained`, `<case>_previous.json` (the proof `proveChunk` verified: the 2^15 dummy, then the
  first chunk, under the `vaultReducer` key) and `<case>_proof.json` (the proof it made, whose public input and output
  `o1js/src/rust-wrap.test.ts` verifies the Rust wrap under).
- For each vault case, `<case>_zkapp_public.json` (the zkApp public input o1js proved the call under, which the wrap
  proof is verified against), and, for a method that verifies a proof (`reduce`, `mutualClose`, `escape`, `defeat`,
  `raise`), `<case>_previous.json`: that proof, with the `key` of its program in `vault_keys.json`. The first `reduce`
  verifies a dummy action-stack proof.
- For each case, what a Rust builder of its step witness starts from, as the toy's `toy_<method>_step_witness.json`,
  `toy_<method>_step_map.txt` and `toy_inputs.json` are:
  - `<case>_step_witness.json`: o1js's step witness (`public_input_size` and `external`, the public input then the auxiliary
    values), which `zk-prover`'s `StepWitness::from_o1js_json` reads; its auxiliary values are the `AUX_LEN` of the case's
    step shape in `zk-prover/src/lib.rs`. A method that verifies a proof holds it, so a witness, the `_previous.json`, the step
    proof and the wrap witness of a case are of one run. `zk-prover/tests/step_vault.rs` proves each case's step circuit
    from it.
  - `<case>_step_map.txt`: the o1js call site of each variable (`step-map.mjs`, the toy's format). The vault's frames are
    TypeScript, so the sites are `.ts` lines of the o1js sources and of `../o1js/src`.
  - `<case>_inputs.json`: what the circuit witnesses and does not compute, recorded when the method is called:
    `method`, the vault's `vault` address, the `slot` of the call, the `sender` (the account that pays and signs), the
    `tokenId` (MINA's, 1), the `args` as the method takes them (field elements and integers as decimal strings, keys as
    base58; a proof as its public input and output, the proof itself being `<case>_previous.json`; an `IndexedMerkleMap` as
    its `root`, `length` and `sortedLeaves`, in key order; an `Unconstrained` as its contents, e.g. the `NoteWitness`es of
    `reduce`, the `SweptNote`s of `sweepExpired`), the vault account's `state` as the method reads it (its 32 `appState`
    fields, `actionState`, `provedState`, `balance`, `nonce`, `verificationKeyHash`), and the `blinding` of the call's
    `callData`. o1js draws that blinding with `Fp.random`, twice for a call (building the transaction, proving it), and the
    second is the one in the step witness; `vault-fixtures.ts` replaces `Fp.random` by a counter, as `prove-local.mjs` does,
    so a rerun draws the same values. Nothing else in a method is random. The `chunk_*` files hold the arguments of
    `proveChunk`: the input, the previous proof's public input and output, `isRecursive` and the `witnesses` (null for an
    empty slot).
  - A step witness over 50 MB gzipped is committed as `<case>_step_witness_blocks.json` instead: the sha256 of each block of 1024
    values (each value's decimal string followed by a newline). None is, so far (the largest, `reduce`'s, is 21 MB);
    `STEP_WITNESS_DIR=<dir> ./regenerate.sh --vault` also writes every full step witness to `<dir>`.
- `rust_vault_<case>_proof.json`, `rust_chunk_dummy_proof.json`, `rust_chunk_chained_proof.json`: the Rust wrap proof of
  each vault case and of the two chunks (`zk-prover`'s `rust_wrap_proofs` example, which `--vault` runs after collecting),
  which `o1js/src/rust-wrap.test.ts` verifies under the vault's key (the chunks' under the reducer's).
- `vault_keys.json`: the verification keys (`data` and `hash`) of the vault, its reducer (`vaultReducer`) and the programs
  the vault verifies (`request`, `withdrawal`). `zk-prover/src/pins.rs` pins the vault's and the reducer's hashes.

The circuits and keys are byte-identical on a rerun; the step proofs and wrap witnesses are not, and the step witness of
a method that verifies a proof holds that proof, so each case's step witness, step proof, `_previous.json` and wrap witness
come from one run.

The new fixtures are 73 gzipped files, 56.5 MB committed: each wrap witness is about 4 MB (118,000 field elements, which
`xz` shrinks by only about 14%), 11 of them make 43 MB, and the circuits are the rest. The step witnesses, step maps
and inputs add 36 files, 81.4 MB: the two `reduce` witnesses (685,329 values) are 21 and 23 MB each, the two chunks' 4 and
8 MB, the methods that verify a proof 5 MB each, the rest 1 to 3 MB. A full `--vault` run took 40 minutes (`compile` 6, `main` 8,
`recursive` 20, the rest the Rust wrap proofs).

`trace-land.mjs` is a development tool for `zk-prover/src/witness`: it proves `land` as `prove-local.mjs`
does and logs the calls into o1js's OCaml side (Poseidon, `scaleFastUnpack`, `truncateToBits16`) and the
input of the account update hash, to `$SPIKE_DUMP/snarky-log.json`. The Rust witness mirrors were checked
against that; the template of the account update's hash input (`src/witness/account_update.rs`) was
dumped with it.
