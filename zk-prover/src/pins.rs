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
