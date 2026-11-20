# Hard fork checklist

What the operator, the share holders and the zk edge do around a Mina hard fork. ADR 0015 decides what a fork does
to each vault value, ADR 0006 the fork notice, and `docs/upgrade-key-holders.md` the holders' steps.

The **stop slot** is the fork's `slot_tx_end`: from it no transaction lands until the new chain starts. Every deadline
here counts back from it. The slot keeps counting through the halt (ADR 0015).

Parts of this need code that isn't built yet: the generation table, `resume` and the fee rule (#136, #137, #138).

## When the fork is announced

1. **Read the fork's values:** its stop slot, `slot_chain_end` and genesis delta, its slot length, its account creation
   fee, whether it raises the transaction version, and whether a proof made before it verifies after it. If the
   version doesn't rise, the vaults' keys stay valid: nothing is re-keyed, and only a changed fee or slot length needs
   a decision. If earlier proofs won't verify, no challenge from earlier evidence lands after the fork (ADR 0015):
   follow the warning steps marked **(breaks proofs)** below.
2. **Run the pre-fork check** (`docs/upgrade-key-holders.md`): within 7 days of the announcement and at least 42 days
   before the stop slot.
3. **List the vaults to re-key:** every vault from an earlier generation that still holds a balance. An empty one is
   never re-keyed, and its generation leaves the table.
4. **Update the generation table:** add the new generation, with the fork's slot length, the slot counts it gives and
   the fork's fee as the minimum withdrawal. Set each live earlier generation's minimum withdrawal to the fork's fee and
   leave its slot counts alone.
5. **Build the keys:** the gate publishes the re-key of every live earlier generation, the new generation's vault and
   the new registry, all reproducible from one commit. Tag that commit.

## At least 14 days before the stop slot

6. **Publish each re-keyed vault's fork notice** at its zkApp URI: the re-key, the source tag and how to rebuild it, the
   vault's durations in post-fork time (note lifetime, challenge window, close window), any change of fee, and that
   payers should leave before the stop slot. If the fee rises, warn payers whose payout would fall below it.
   **(breaks proofs)** The zk edge stops serving the vault now, not at the stop slot, and asks every payer to mutual
   close before the stop slot. Its unsettled charges in the vault are at risk after the fork.
7. **Publish the new registry's key and the new vault code hash,** so wallets can update their pins before the fork
   (ADR 0011).

## At the stop slot

8. **The zk edge stops serving every vault from before the fork.** It offers their payers only a mutual close.

## After the new chain starts

9. **The share holders install each re-key** (`docs/upgrade-key-holders.md`, "Signing a transaction"). Each holder
   rebuilds the key from the notice's source tag first.
10. **Call `resume` on each re-keyed vault,** straight after its install. Anyone may; the operator does. No escape
    finalizes until a challenge window after it.
11. **Deploy the new registry** with its key discarded, and write its deployment record (ADR 0011).
12. **Run the key ceremony for the new vault and deploy it through the new registry** (ADR 0013).
13. **Point the zk edge and the challengers at the new generation:** its keys, its values, the new registry and vault.
14. **Keep keeping the old vaults:** reduce and sweep them until they are empty.
