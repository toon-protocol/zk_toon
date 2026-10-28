# vendor/mina-rust

A copy of the parts of [mina-rust](https://github.com/o1-labs/mina-rust) that `zk-prover` builds on.
The code is Apache-2.0; `LICENSE` is mina-rust's, unchanged, and every copied crate inherits
`license = "Apache-2.0"` from this directory's `Cargo.toml`.

- Upstream: `https://github.com/o1-labs/mina-rust`, tag **v0.19.0**.
- Copied: the `ledger` crate (package `mina-tree`) and the crates it depends on by path: `core`,
  `macros`, `p2p-messages`, `fuzzer` (an optional dependency of `core`, which Cargo still needs on
  disk), `poseidon`, `libs/redux` and `libs/alloc-test` (a dev-dependency of `p2p-messages`).
  Not copied: the node, the CLI, the P2P stack, the tools, and the `tests/` and `shapes/`
  directories of `p2p-messages` (180 MB of fixtures the build does not use).
- Patches applied, in this order, both from
  [`toon-protocol/zk-note-vectors@spike-1561-rust-prover`](https://github.com/toon-protocol/zk-note-vectors/tree/spike-1561-rust-prover):
  1. `rust/patches/mina-rust-v0.19.0-mesa-proof-systems-ab84160.patch`: moves mina-rust to
     o1-labs/proof-systems commit `ab84160fa2c22290a8506a7742ac1378879fc386`.
  2. `spike-1561/rust/patches/mina-rust-v0.19.0-mesa-plus-toon-1561.patch`: exports the prover
     entry points and adds `crates/ledger/src/proofs/toon1561.rs`.
  No other change was made to mina-rust's source.
- Edited around the copy, not in mina-rust's code: `Cargo.toml` lists only the copied crates as
  workspace members and drops `vendor/salsa-simple`; the `tools/toon-*` members the patches added
  are gone; `rust-toolchain.toml` and mina-rust's `Cargo.lock` are not kept. The repository root
  `Cargo.toml` carries mina-rust's `[patch.crates-io]` for `num-bigint` and `num-rational`, because
  a `[patch]` only counts at the root of a build, and the root `Cargo.lock` was seeded from mina-rust's.
