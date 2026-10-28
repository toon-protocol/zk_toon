---
status: accepted
---

# Mina's prover comes from a pinned fork, and the zkApp wrap is our own copy

The connector proves its Mina zkApp transactions in Rust, with a prover kept in this repository
(toon-protocol/connector#1551). That prover is one crate, `zk-prover`, in this Cargo workspace, shared
by the wrap (#30), the step witness (#31) and recursive methods (#32). It is built on mina-rust's Pickles and kimchi code. We take
that code from **`toon-protocol/mina-rust`, branch `toon/v0.19.0`**: mina-rust `v0.19.0` plus the
Mesa proof-systems patch (connector#1512) and the small changes the prover spike needed
(connector#1561). This repository depends on that fork as a Cargo git dependency **pinned by `rev`**.
mina-rust is paused upstream, so nothing should move under us unless we move it.

mina-rust's `wrap()` covers only Mina's own circuits: two previous proofs, one step key, no optional
gates. An o1js zkApp program needs a wrap with any number of previous proofs, several step keys and
lookup features. We write that wrap as a **generalised copy** in this repository's `zk-prover`
crate. We don't edit `wrap.rs` in the fork. The fork changes only to make items `pub`. The copied
code keeps mina-rust's Apache-2.0 licence.

## Considered Options

- **Copying the mina-rust crates into this repository:** rejected. That's tens of MB of someone else's
  code in our history, and each Pickles upgrade would be a huge diff.
- **A git submodule:** rejected. It adds a checkout step everywhere and gives nothing a pinned `rev`
  doesn't.
- **Generalising `wrap.rs` inside the fork:** rejected. Mina's own N=2 path would change. The work
  would also be reviewed in a repository that has no gate and no agent factory.

## Consequences

- **Upgrading Pickles or o1js is a deliberate act.** We cut a new fork branch (for a new Mina
  version), port the wrap again, regenerate the fixtures with o1js, and update the pins. A test pins
  the Mina commit, the fork `rev`, the o1js version and the verification-key hashes. It fails until all of
  them agree.
- **The gate builds mina-rust**, which makes CI and agent runs slower.
