---
status: accepted
---

# A client checks a vault before trusting it

The vault code hash names only the code. `init` and `deploy` aren't `@method`s: they run under the vault account's
signature and aren't compiled into the circuit, so the hash says nothing about the state and permissions they
write (#75). Each zk edge names its own vault (connector ADR 0080, the greeting's `payTo`), and any operator can
deploy one, so the deployer is a party the payer needs protecting from.

On o1js's local chain with proofs off, a modified deploy stored a challenge window of 1 and `send: signature` under
the published code hash. A prefilled note root let a phantom note take a victim's 10 MINA. On devnet, `short-1` holds
a window of 2 slots under the published hash.

## Decision

`checkVault` in `o1js/src/vault-check.ts` asks one question of a vault address and answers with a pass, or a refusal
naming each thing that failed. A wallet calls it with the published vault code hash and a `VaultReader`. Nothing is
changed in the vault, so its key is unchanged. `judgeVault` is the same check as a pure function of a snapshot, and
`test-vectors/vault-check.json` holds snapshots with their answers.

A pass means:

0. The pinned vault registry lists the vault, and the registry's own key, permissions and entries check out. This rule
   was added by ADR 0011, which supersedes the limit below: the rest of this ADR stands.
1. The account's verification key hash is the published code hash.
2. Every permission equals ADR 0006's table, and the account has no vesting schedule, which could lock deposits.
3. `depositSizes`, `noteLifetime` and `challengeWindow` equal policy.
4. `setup` has run and the treasury's account exists. A reduce paying a treasury with no account would fail, and
   stall every action behind it.
5. The whole action stream, replayed from the empty tree as the reduce applies it, gives every value on the account
   that depends on it: `noteRoot`, `nextLeafIndex`, `nullifierRoot`, `pendingEscapesRoot`, `sweepCursor`, and the
   expired, claimed and swept totals. Every root in `rootRing` was once the note root, and the newest is the current
   one. `actionState` is a point in the stream, and `actionStack` holds actions from the stream.
6. At no point in the stream has a size paid out more often than it was deposited, no escape precedes every deposit
   of its size, and no finalize, defeat or raise names an escape that was dispatched and no reduce has recorded yet.
   At the end of the stream, no size is claimed more often than it was deposited. Each sweep's total ends at a note,
   with every note it walks past its expiry and the close window after it.
7. The balance covers all deposits, pending ones included, less what reduced actions paid.
8. A reduce can process every action. Each account update holds one action, each action has only the fields its kind
   sets, its amounts are in order, and everyone an action names as a payee has an account.
   The reduce's circuit is the same for every kind, so a forged action that breaks one of these fails the reduce
   whatever it claims to be, and every action behind it is stuck, including a victim's deposit. `vault-check.test.ts`
   sees such reduces fail, except over-long updates: o1js's `prepareBatches` ran out of memory on one, so that test
   only asserts the refusal. No nullifier is 0 either, since it's a hash; that one didn't fail a reduce. A passing check reads the node once per payee in the stream.

Claims are judged only at the end because a stale escape can legitimately push them over: it spends other nullifiers
than a close of the same note. So a vault refuses while a stale escape stands and passes again once it's defeated.
A holder of old signed states can cause that refusal for a challenge window, and it's a fair one: undefeated, that
escape takes someone's money.

An unreachable node or archive, a missing account and a malformed answer all refuse.

**The archive isn't trusted.** The account's action state is a hash chain from the empty state over every action
ever dispatched, so an archive's answer counts only if it hashes up to the account's latest state. An archive that
lags by a block refuses until it catches up. Events aren't committed on chain, so they only supply the deadlines of
recorded escapes, which the reduce picks and the actions don't hold: a wrong one fails `pendingEscapesRoot`.

**More is checked than the first design listed.** The first list was the note root, leaf index and balance. Each
of these does harm if prefilled and is now checked too:

- A phantom root in `rootRing` lets a close prove against a tree the note root never was.
- A forged `actionStack` lets a reduce pop actions that were never dispatched, skipping the stream altogether.
- A prefilled pending escape, or a high `expiredTotal`, pays out of the vault.
- A prefilled nullifier blocks a note.
- An action a reduce can't process stalls the vault, and costs the forger nothing if it needs no backing.

## What a pass doesn't show

**This section is the problem ADR 0011 closes** for any vault the check now passes: the check refuses a vault the pinned
registry doesn't list, and a registered vault never had an unlocked phase. What follows is the limit that ADR answers,
and it still describes a vault deployed under its own key.

**A forged close can hide a note, and the check passes that vault.** The deployer, under loose permissions,
dispatches a fake deposit and a fake close of it with an invented nullifier, writes the state a reduce would leave,
and locks the account. Replay matches, and the books balance: one deposit, one payout, nothing held. No money ever
moved. The phantom's leaf is in the tree and its real nullifier is unspent, so once a victim deposits, the deployer
closes it for real and takes the deposit. `vault-check.test.ts` runs this end to end, with proofs off.

A deployer who really deposits can do the same with a forged escape or close left pending, for the price of that
deposit until it's paid back. The replay can't catch any of these, because a close doesn't name its note (ADR 0005: naming it would link the withdrawal
to its deposit), and nothing on the account records whether a payout really happened or a withdrawal had a proof.

So:

- **A pass on a vault with no history was sound**, and a wallet could extend that trust by remembering the action state
  it saw. ADR 0011 removes that path: the registry is the rule, so a wallet has nothing to remember.
- **A pass on an unregistered vault with history says its books are consistent, not that they're real.** The check now
  refuses it (ADR 0011).

One lead, not tried: the account's `receiptChainHash` is said to commit to every authorised update of the account,
so replaying it could show there was no signed phase. That would need the full history of transactions from an
archive, and it isn't verified that the hash covers enough.

**`creationTime` can't be judged** beyond not being in the future. The subsidy period counts from it, so a wrong one
shifts when subsidised allowances renew, but it moves no money.

**`stateKey` and `treasury` are the operator's choice.** The check says they're set, not that they're good.

**The check is only as good as the moment it ran.** It says nothing about a later hard fork, which ADR 0006 covers
with the fork notice. A pass at a slot also doesn't stop the vault changing through its own methods afterwards.

## Rejected

- **An `@method` initialiser.** It changes the key and the deploy flow, and doesn't close the hole above. A signed
  deploy leaves `provedState` false, and a proved write of all 32 fields sets it true, but swapping the verification
  key under a signature leaves it true (tried on the local chain with proofs off, 2026-11-02). So a deployer can
  write any state under a rogue key that sets the flag, and then install the published key. Only a signed write
  clears it.
- **Comparing against policy inside the methods.** It changes the key, and covers the constants only. They can be
  checked from outside for free.
- **Trusting one known deployment address.** Each zk edge has its own vault.
- **Replaying the note root and the balance alone.** See "More is checked than the first design listed".

The published hash isn't in the repo: it's a build output (`npm run keys`), so the caller passes it in. The check
reads the policy constants and ADR 0006's table from this build, and the vectors name o1js's transaction version, so
they change when o1js's does.
