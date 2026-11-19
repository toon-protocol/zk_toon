---
status: accepted
---

# A payout opens its destination's account

ADR 0002 required a withdrawal's destination to exist, because a payout to a missing account would fail
the batched reduce and stall every action behind it. That forced a payer withdrawing to a fresh address
to fund it first, which links the two addresses. This ADR supersedes that consequence of ADR 0002 and
amends the raise of ADR 0004.

## Decision

- `mutualClose` and `escape` no longer require the destination's account to exist. `setup` still
  requires the treasury's.
- Every payout the reduce makes sets `implicitAccountCreationFee`. Only when the destination is new,
  the chain takes the account creation fee (1 MINA, `ACCOUNT_CREATION_FEE` in the policy) out of the
  payout; a payout of exactly the fee opens the account at zero. An existing destination gets the
  full amount.
- A payout below the fee is refused by the chain, and refuses the whole transaction. Dispatch can't
  tell a new destination from an existing one (an update that moves nothing on a new account is
  refused), so every withdrawal must pay at least the fee: a mutual close needs `amount ≥ fee`, an
  escape `amount − conceded ≥ fee`. A payer with less left can't withdraw it; the note expires and is
  swept as any other.
- A raise's concession is `min(claimed, tier, amount)` as in ADR 0004, except that when it would leave
  `amount − conceded` above zero and below the fee, the concession is the whole `amount`. So a
  pending escape's payout is zero or at least the fee, and the reduce's payouts never fail for want of
  the fee. A raise must still increase the concession. The vault mirror and the Rust challenger
  compute the same rounding, or a challenger would name a record whose hash differs from the reduce's.

## Considered Options

- **A reduce fallback for a payout below the fee:** rejected. The reduce can't tell a new destination
  from an existing one either, and a fallback that paid the treasury for a new destination couldn't
  be checked on chain, so the reducer could keep up to the fee from an honest payer.
