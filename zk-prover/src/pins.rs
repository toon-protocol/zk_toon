//! What this crate's proofs are pinned to. Changing any of these changes the circuits or the
//! fixtures.

/// The mina-rust fork `ledger` comes from (`toon-protocol/mina-rust`, branch `toon/v0.19.0`).
pub const MINA_RUST_FORK: &str = "https://github.com/toon-protocol/mina-rust";

/// The fork commit, the same `rev` as in `Cargo.toml`.
pub const MINA_RUST_REV: &str = "6feeb3797fff6dba49fd848cb2d6decd63fee1b4";

/// The o1-labs/proof-systems commit the fork, and so the whole workspace, builds on.
pub const PROOF_SYSTEMS_REV: &str = "ab84160fa2c22290a8506a7742ac1378879fc386";

/// The o1js version the fixtures were dumped from.
pub const O1JS_VERSION: &str = "3.1.0";

/// The Mina commit o1js 3.1.0 builds on (its `src/mina` submodule). The witness mirrors in
/// `witness` follow that commit's `src/lib/crypto/pickles` and snarky sources; they differ from
/// the fork's older copies, e.g. in `Scalar_challenge.endo`'s `inv` (see `witness::pickles`).
pub const MINA_REV_OF_O1JS: &str = "228c409a1696669d963425162f12e88d41231c6d";

/// The Mina commit the wrap prover ports `wrap_main.ml` and `wrap_verifier.ml` from.
pub const MINA_COMMIT: &str = "aa93c444";

/// The hash of `land`'s step verification key, from `fixtures/cs003_*`
/// ([`crate::StepCircuit::vk_hash`]).
pub const LAND_STEP_VK_HASH: &str =
    "17017478399840948585953943687802012566600948659124502148738425754785660902622";

/// The hash of `setup`'s step verification key, from `fixtures/cs004_*`.
pub const SETUP_STEP_VK_HASH: &str =
    "5816393794908604648999406800500419851440280522735853070404335141274887767380";

/// The hash of the program's verification key (the wrap key `Land.compile()` returns), from
/// `fixtures/inputs.json`. It covers both methods.
pub const PROGRAM_VK_HASH: &str =
    "9870947700175903446193934776973478446598173288641875524808838875088037769766";

// To regenerate the fixtures (after bumping the fork rev, proof-systems or o1js):
//
// 1. Change the pin: `Cargo.toml`'s `rev`s, `fixture-gen/package.json`'s o1js version (and its
//    patch) and the constants above.
// 2. Run `fixture-gen/regenerate.sh --write`. It rewrites `fixtures/` from o1js and prints the VK hashes.
// 3. Put the printed hashes in the three `*_VK_HASH` constants. `tests/pins.rs` fails until they
//    match the committed circuits and `inputs.json`.
// 4. Run `cargo test --workspace` and commit the fixtures with the pins.
//
// o1js proofs are randomised, so a regenerated `stepproof*`, `w002`/`w004` and `*_proof.json` never
// match byte for byte, and the gate never runs the generator. The circuits (`cs00N_*`), the step
// witnesses and `inputs.json` do match.
