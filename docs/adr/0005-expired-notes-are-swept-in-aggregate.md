---
status: accepted
---

# Expired notes are swept in aggregate, never claimed one by one

After a note expires, what it left in the vault goes to the treasury (#2). A claim per note can't be
built without linking. A close or an escape reveals a nullifier, never the note's index, so the vault
can't tell which notes were withdrawn. Marking a note withdrawn would link the withdrawal to its
deposit.

So the vault sweeps in aggregate. Every close and every finalized escape pays out exactly its note's
size: the balance to the destination and the rest to the treasury. A permissionless `sweepExpired`
walks the note tree in index order from a cursor, and adds the sizes of the expired notes it passes to
`expiredTotal`. Then it dispatches a sweep carrying that total. The reduce keeps `claimedTotal`, the
sizes of the notes it has paid out or holds for a pending escape. A close or a recorded escape adds
its note's size and a defeat takes it back. A finalize doesn't change it, because its escape already
counted. When the reduce reaches the sweep, it pays the treasury

    expired − claimed − swept    (or nothing, if that isn't positive)

and adds the payment to `sweptTotal`. The walk sees sizes and deposit times, which are public at
deposit. The totals reveal nothing about any one note.

The walk counts a note only from `expiry + CLOSE_WINDOW_MS`. A mutual close proven just before expiry
may land until then. An escape lands before expiry (`validUntil < expiry`). So every withdrawal of a
counted note was dispatched before the sweep, and the reduce applies it first: the sweep's total
reaches the reduce through the action stream, not through state. The sweep never pays out money that
is still owed:
- **Live notes:** a note isn't counted until no withdrawal of it can land.
- **Pending escapes:** the escape's size stays in `claimed` until it finalizes, and is then paid.
- **Unreduced deposits:** the walk only reaches reduced notes.

What the vault holds after a sweep is at least the unreduced deposits, plus the sizes of unexpired
reduced notes, plus the pending escapes.

The sweep underpays while withdrawn notes are unexpired. Their sizes are in `claimed` but not yet in
`expired`, so the expired notes they offset are swept only once those withdrawn notes also expire. We
accept this. Deposit times can run up to a slot out of index order, because a deposit names a time up
to a slot old. A note that expires later than the next one holds that one back by at most a slot.

## Considered Options

- **A claim per note** (the first version of #11): rejected. It needs the note's index, which links a
  withdrawal to its deposit.
- **Sweep the vault's balance less a reserve:** this is the same formula, since the balance is every
  deposit less what was paid out. The vault can't know the unreduced deposits without making every
  deposit write state, and concurrent deposits would then conflict. Counting with totals needs no such
  write. MINA sent to the vault outside a deposit is never swept.
- **Pay the sweep directly, outside the reduce:** rejected. A direct sweep would have to wait until no
  action is pending, or it could pay before a close or escape queued ahead of it.

## Consequences

- The vault adds four state fields (`sweepCursor`, `expiredTotal`, `claimedTotal`, `sweptTotal`, 29 of
  32) and action kind 7. The reduce grows to about 55.4k rows of 65,536 at a batch of 5. The sweep is
  its own method, of about 6.7k rows for a walk of 16 notes.
- The formula relies on every close and finalize paying out exactly its note's size. A change to what
  they pay has to change what they add to `claimedTotal`.
