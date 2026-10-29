# Handoff for #30

Done (commit "zk-prover: verifier + wrap fixtures"):
- `zk-prover/src/verify.rs`: `load_vk`, `WrapProof::from_o1js_base64`, `fields`, `verify` (ported from toon-1512). Test `tests/verify.rs` verifies o1js's real `land` proof (`fixtures/land_proof.json.gz`) and refuses a tampered input. Note: a trailing zero public field is implicit, so dropping it still verifies.
- Fixtures copied gzipped from zk-note-vectors@spike-1561-rust-prover: cs004 (setup step), cs005 (wrap circuit), w004_cs005, stepproof002.b64.

Not done (all of the wrap prover):
1. Wrap prover in `zk-prover`: generalised copy of the fork's private `wrap_main`/`deferred_values`/`make_public_input`/`choose_key`
   (`crates/ledger/src/proofs/wrap.rs` in ~/.cargo/git/checkouts/mina-rust-*/*/; 2987 lines) with N, step-key list and feature flags (lookup / `Opt`) as parameters, from Mina aa93c444 `wrap_main.ml` + `wrap_verifier.ml`. Apache-2.0 headers, LICENSE-APACHE, NOTICE, `license` in Cargo.toml. Test: witness == w004_cs005 at every index (report first mismatch).
2. Verify the Rust wrap proof under o1js's program VK (hash 98709477…69766) — needs the program VK data; regenerate via fixture-gen.
3. Extend `fixture-gen` (o1js 3.1.0 + patch) to write land+setup circuits, step proofs, wrap witnesses, VK hashes; capture setup's step proof + wrap witness; README command. Spike patches: `rust/` and `spike-1561/o1js/patches` in the spike branch.
4. o1js test in `o1js/` loading the Rust wrap proof and `verify`ing against the compiled VK.
5. Pins test: compute VK hashes from committed circuits; extend `pins.rs` with Mina commit aa93c444, setup/land step VK hashes, program VK hash, regeneration steps.
6. setup test: same as land.
First `cargo test` takes ~6 min cold (mina-tree build).
