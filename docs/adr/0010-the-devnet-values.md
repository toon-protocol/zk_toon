---
status: accepted
---

# The devnet vault keeps its sizes, tiers and ring; the mainnet values are decided at the mainnet gates

Spec #2 left four values open: the fixed deposit sizes, the tiers, the length of the recent-roots
ring, and whether the vault has an owner pause. The spec ends at a vault working on the local chain
and on Mina devnet, and every test and the devnet smoke test (#17) ran with the values below. Until
now `zk-note/src/policy.rs` and `o1js/src/policy.ts` called them "provisional", with no record of
whether anyone had chosen them.

## Decision

For the local chain and devnet:

| value | devnet | where |
|---|---|---|
| deposit sizes | 10, 100 and 1000 MINA | `DEPOSIT_SIZES`; the vault's `depositSizes` state, set at deploy |
| tiers `b` | 0.01, 0.1 and 1 MINA; the smallest is the only subsidised one | `TIERS` |
| recent-roots ring | 8 roots | `ROOT_RING_LENGTH` in `o1js/src/vault.ts` |
| owner pause | none | the vault has no pause method (`vault-escape.test.ts`, ADR 0006) |

- **The sizes** are a factor of ten apart, so a payer picks one near what it means to spend, and three
  sizes split a small crowd only three ways.
- **The tiers** make the largest allowance a tenth of the smallest deposit. An escape gives up at most
  one tier, so a payer's worst case is known before it deposits.
- **The ring** grows by a root only when a reduce changes the note tree, so a proof made from a root
  stays good for at least eight such reduces. At devnet's volume that is far more time than proving
  and sending take.
- **No pause** keeps the escape guarantee unconditional. zkAPI bounds its pause at 45 days. Here a
  payer can always leave without the zk edge's help.

The **mainnet values are decided at the mainnet gates** (`docs/design/zkapi-payments.md`, phase 4),
once the crowd's real size is known. Each size splits the crowd, so a small early crowd argues for
fewer sizes. Either change makes a new vault, not an upgrade, since the vault's key can't be
replaced before a hard fork (ADR 0006):
- the smallest tier is a constant of the request circuit, so changing the tiers changes the
  verification keys and the code hash;
- the sizes are the vault's initial state, so changing them changes what the vault check requires
  (`depositSizes` equals policy, ADR 0008).

## Two departures from the spec, recorded here

- **No verification-key identifiers in the vault's state.** The spec put them in on-chain state. The
  vault instead takes request and withdrawal proofs as the compiled `RequestProof` and
  `WithdrawalProof` classes, so their keys are fixed into the vault's own verification key. A changed
  circuit changes the vault's key, which the published keys and the vault check (ADR 0008) pin. No state field is
  spent on them.
- **`zk-note` is pinned to a proof-systems commit, not a tag, and uses arkworks directly.** It moved
  from tag `0.7.0` to `rev = ab84160…`, the proof-systems commit that `zk-prover` and the mina-rust
  fork build on (#39, ADR 0003). One build then carries one proof-systems. A `rev` pins as firmly as
  a tag. `ark-ec` and `ark-ff` are the curve and field crates proof-systems itself is built on. zk-note
  uses them for curve and field arithmetic, and they add no I/O and no clock.

## Considered Options

- **Choose mainnet values now:** rejected. There's no crowd yet to size them against, and nothing in
  #2's scope depends on them.
- **Make the tiers vault state, like the sizes:** rejected. The circuits check the smallest tier as a
  constant, so the tiers would cost state fields and circuit rows to change something that, on
  mainnet, makes a new vault anyway.

## Consequences

- The policy files point to this ADR instead of calling the values provisional.
- The design doc's open question on sizes and tiers is answered for devnet and left open for mainnet.
