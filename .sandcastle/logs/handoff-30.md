# Handoff for #30

#30 is narrowed (triage 2026-10-30): the generalised wrap prover only. Done:

- `zk-prover/src/wrap/`: `wrap::<C>(WrapParams, &WrapCircuit)` returns the wrap proof and
  `WrapWitness`; `wrap_witness` returns the witness alone. N (`max_proofs_verified`), the step
  circuits (one key per method) and the feature flags are parameters. Only N=0 is supported;
  N>0 returns an error naming #32.
- `tests/wrap.rs`: the witness equals `w004_cs005` at every index (the failure reports the first
  differing index), satisfies cs005's constraints, and the proof verifies against cs005's kimchi
  verifier index.
- Not in #30 any more: `fixture-gen` for `land` + `setup`, the `setup` fixtures, the VK-hash pins
  test (#55); verifying the wrap proof under the program VK in Rust and o1js, tamper refusal, the
  `setup` witness check (#56).

Things #55 / #56 need to know:

- The OCaml reference is Mina `228c409a` (the commit o1js v3.1.0 bundles; Pickles lives at
  `src/lib/crypto/pickles` there), not `aa93c444`. The difference that matters: each round of the
  endo gate has an extra `inv` witness, which mina-rust's `endo` lacks (`wrap/endo.rs`).
- The wrap circuit's prover index has 2 previous challenges (`WrapLandSetup`); the spike's
  `WrapLand` says 0.
- `WrapOutput.proof` is the fork's `WrapProof` (proof, statement, prev_evals), what a Pickles proof
  is built from.
- `stepproof002_public.json.gz` is the public input o1js proved `stepproof002` under; `fixture-gen`
  should write it with the step proof (it is `w004_cs005`'s field 12).
- The fork keeps `Witness`'s vectors private, so `WrapWitness::of_witness` reads them from the
  `Debug` output. A fork PR making `Witness::aux()`/`primary` public would remove that.
- The `setup` branch of `exists_messages` (the lookup messages absent, `Maybe(false, dummy)`) is
  ported but untested until #55 captures `setup`'s step proof.
