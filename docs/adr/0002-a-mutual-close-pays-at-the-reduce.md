---
status: accepted
---

# A mutual close pays at the reduce, through the one action stream

A mutual close is a public transaction, so anyone can copy its withdrawal proof and clearance and
submit them again. Consumed nullifiers enter the nullifier set only when a reduce folds them in,
because shared roots change only through actions (#2). If the close paid out itself, every copy
submitted before the next reduce would pay again. So a mutual close only dispatches an action. The
reduce inserts the nullifier, pays the balance to the destination and the rest of the deposit to the
treasury, and skips, without paying and without failing, any action whose nullifier is already in
the set or appeared earlier in the same batch. A mutual close still has no challenge window: it is
paid at the next reduce.

The vault has one action stream. Deposits, closes, and later escapes, raises and defeats are one
fixed-width action with a `kind`, and one reduce handles them all.

## Considered Options

- **Pay at close, insert at reduce:** rejected. It pays every resubmission made before the next reduce.
- **Pay at close and update the nullifier root directly:** rejected. Two closes in one block then
  conflict on the root's precondition, which breaks the rule that payers acting in the same block
  never conflict.
- **A failing reduce on a duplicate nullifier:** rejected. One duplicate action would stall every
  action queued behind it.

## Consequences

- The close also checks, against the stored nullifier root, that its nullifier is absent, so an
  obvious second close is refused with a reason. A close proven before a reduce lands goes stale and
  has to be resubmitted with a fresh witness.
- A reduce pays up to two account updates per close, so its batch size is bounded by Mina's limit on
  account updates per transaction, not only by proving cost.
- Someone has to call the reduce before a close is paid. The zk edge operator is the natural caller.
- A payout to an account that does not exist fails the reduce, and a failing reduce stalls every action
  queued behind it. So setup requires the treasury's account to exist, and a close (and an escape,
  whose finalize pays the same way) requires its destination's account to exist, all as account
  preconditions.
