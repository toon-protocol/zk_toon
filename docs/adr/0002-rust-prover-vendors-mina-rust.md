---
status: accepted
---

# The Rust prover copies mina-rust into this repository

The connector proves its Mina zkApp transactions in Rust (toon-protocol/connector#1551), and the
prover lives here. It needs mina-rust's Pickles and kimchi code (the `ledger` crate and the crates it
depends on locally), patched for Mesa and for o1js zkApp circuits. We copy those crates into
`vendor/mina-rust/` with the patches already applied, and build the prover as one crate, `zk-prover`,
in this Cargo workspace beside `zk-note`. The whole workspace uses one proof-systems commit,
`ab84160`, the one mina-rust's Mesa patch was tested against.

## Considered Options

- **A `toon-protocol/mina-rust` fork as a git dependency:** rejected. The wrap prover (#30) changes
  mina-rust's own `wrap_main` in about 85 places, and with a fork every such change would be a pull
  request to a second repository, which the factory's agents can't open from here. mina-rust's
  development is paused, so a copy costs us no upstream merges.
- **A separate Cargo workspace for the prover:** rejected. The connector depends on both `zk-prover`
  and `zk-note`, and one lockfile keeps them on the same proof-systems types. `cargo test -p zk-note`
  doesn't build the prover's dependency tree.
- **Moving the patched mina-rust up to proof-systems `0.7.0`, where `zk-note` was:** rejected.
  `ab84160` is only 2 commits behind `0.7.0`, while moving mina-rust would mean redoing a 32 KB patch.
  `zk-note` moves to `ab84160` instead, and its vectors confirm nothing changed.

## Consequences

- `vendor/mina-rust/` keeps mina-rust's Apache-2.0 licence. Its README records the upstream tag
  (v0.19.0) and lists each patch applied, which is the change notice Apache-2.0 §4 asks for. The
  repository's own licence (#28) doesn't cover `vendor/`.
- The prover's fixtures are gzipped in the crate, not in `vectors/`: only the Rust prover reads them.
  The o1js code that regenerates them, with the o1js version it is pinned to, is committed beside the
  o1js package.
- Revisit this if mina-rust's development resumes, or when o1js moves to a new Pickles version: either
  one changes the code we copied.
