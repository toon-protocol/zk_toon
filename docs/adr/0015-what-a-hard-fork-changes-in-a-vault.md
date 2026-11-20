---
status: accepted
---

# What a hard fork changes in a vault

A hard fork can change three things the vault depends on (#108): the slot's length (Mesa took it from 180 s to
90 s), the account creation fee, and so what a slot count means in days. Every fork that raises the transaction
version also makes the vault's verification key stale, and the share holders install a new one (ADR 0006). This ADR
decides what a fork does with each value, for the vaults deployed before it and for the one deployed after it. The
steps are in `docs/hard-fork.md`.

## How the chain counts slots across a fork

Read from Mina's source and published fork configs (MinaProtocol/mina: `runtime_config.ml`, `proof_of_stake.ml`,
`genesis_ledgers/*.json`):

- Transactions stop at `slot_tx_end`, the **stop slot**. Block production stops 100 slots later (`slot_chain_end`),
  and the new chain starts `hard_fork_genesis_slot_delta` slots after that.
- The slot keeps counting through the halt, at the old length: the new genesis gets the slot its time would have
  had on the old chain. Mesa's devnet genesis is slot 859,560 = 445,860 + 413,640 + 60. From there it counts slots of
  the new length. Nothing is renumbered.
- A zkApp's state and action state carry over unchanged, so every slot the vault stored keeps its number and stays
  comparable with the chain's.
- The halts so far took 8 to 15 hours (Mesa 8, Berkeley mainnet 15).

## The values

| Value | Where it lives | A vault from before the fork | The vault after it |
|---|---|---|---|
| Slot length | `SLOT_SECONDS`, in `o1js/src/policy.ts` and `zk-note/src/policy.rs` | its own | the fork's |
| Note lifetime, 172,800 slots | the policy: the request and withdrawal circuits and the sweep recompute each leaf's expiry from it; `noteLifetime` state | kept | 180 days of new slots |
| Challenge window, 1,920 slots | `challengeWindow` state, written by `init`; each pending escape's deadline | kept | 2 days of new slots |
| Subsidy period and minimum subsidy age, 6,720 slots each | the request circuit; periods count from `creationTime` | kept | 7 days |
| Request max age, which is also the close window, 7 slots | the vault's close check and the sweep; the zk edge's freshness check | kept | 10 minutes, rounded up |
| Request max lead, 1 slot | the zk edge's freshness check | not used: the zk edge no longer serves the vault | 1 minute, rounded up |
| Account creation fee, 1 MINA | the chain; once #106 lands, the minimum withdrawal in the circuits | the fork's | the fork's |

## Decision

**A vault from before a fork keeps its slot counts.** It is re-keyed with the same counts, compiled for the new proof
system. After the fork it is refused for new deposits (ADR 0011) and only pays out, so every note in it is from before
the fork. Keeping the counts keeps every leaf, deadline, state field and subsidy period consistent, with no new circuit
logic. Its times in days change with the slot: if a fork halves the slot, a note with 100 days left has 50, and the
challenge window is a day. Each fork notice states the vault's durations in post-fork time.

So notes made before a fork keep their meaning in slots, not in days. Reading a leaf's stored expiry instead of
recomputing it wouldn't keep days either: the stored expiry is a slot too.

**The vault after a fork keeps the days.** The vault deployed through the new registry is built with the fork's slot
length, so its durations keep their length in days and their slot counts change. ADR 0007 already derives them from
`SLOT_SECONDS`, rounded up.

**One tree builds every live vault generation.** A vault generation is the vaults built with one set of values. The
policy holds a table of generations, mirrored in TypeScript and Rust, each with its slot length, slot counts and
minimum withdrawal. `npm run keys` publishes the keys of every live generation from one commit, so a fork notice's
source tag rebuilds an old vault's re-key and the new vault's key together. The keeper, the challenger and the
transaction builder take a vault's values from its generation, found by its code hash. The vault check needs only the
current generation: it refuses a vault from before a fork, which the new registry doesn't list (ADR 0011).

**A vault is re-keyed only while it holds a balance.** At each later fork, a vault from an earlier generation that still
holds funds is re-keyed again, with its own slot counts and that fork's fee. An empty one is never re-keyed, and its
generation leaves the table. A vault that only pays out is empty once its last notes expire and are swept, a note
lifetime and a close window after its last deposit.

**The fee follows the network.** A re-key takes the fork's account creation fee, since a payout below the real fee to a
new account fails and stalls the reduce. If the fee rises, a payout already dispatched between the old and the new
fee is paid to the treasury instead: the reduce can't tell whether its destination is new, and leaving it pending would
freeze it for good. That is #106's rule that a payout is zero or at least the fee. A new dispatch needs the new
minimum. Until #106 lands, every destination must already exist and the fee doesn't reach the vault.

**Escapes pending at a fork get a full challenge window after the vault resumes.** From the stop slot until the new key
is installed, no vault method runs: nothing lands during the halt, and every method after it needs a proof under the
new key. The slot keeps counting, so an escape whose deadline falls in that time could be finalized as soon as the key
is installed, with no time left to defeat it. So every re-key has a `resume` method. Anyone may call it, once, and it
records the slot it lands at. `finalize` then requires the vault to have resumed and the current slot to be at least
the resume slot plus the challenge window. An escape recorded after the resume meets that anyway, and calling `resume`
and `finalize` in one block gains nothing. `init` counts as a resume, so a new vault needs none. An escape dispatched
before the stop slot but not yet reduced isn't affected: its deadline is set when its reduce lands.

**The window helps only while the evidence still verifies.** A defeat and a raise carry a request proof the payer made
and the zk edge kept as evidence, and the vault verifies it. A challenger can't make it again: it needs the payer's
secret. If a fork changes the proof system so that proofs made before it don't verify under the re-key, no challenge
from earlier evidence lands after the fork, whatever the window. A payer could then escape from any stale state of
their note, proving the new withdrawal themselves, and be paid balance they had already spent. The loss is bounded by
each note's size and falls on the zk edge's unsettled charges, not on other payers' deposits. Challenging across such
a fork is a design of its own (#135). Until it lands, when a fork breaks earlier proofs the zk edge stops
serving the vault at the fork notice and asks every payer to close before the stop slot. That is a warning, not a
block: the vault is still re-keyed, since leaving it frozen would hold honest payers' deposits too. Whether a fork
breaks earlier proofs is read when it is announced (`docs/hard-fork.md`).

**The zk edge stops serving a vault from before a fork at the stop slot.** From then on it offers that vault's payers
only a mutual close, which pays back the unspent balance. So after a fork the zk edge never needs an earlier
generation's request circuit or freshness values. A payer who wants to keep paying deposits into the new vault.

## Considered Options

- **Convert slots at the fork** (`F + (t − F)·k` for a slot t past the fork's slot F): rejected. It keeps days, but it
  touches every time comparison, every leaf, the pending deadlines, the subsidy periods and state, and LocalBlockchain
  can't fork to test it.
- **Re-key an old vault with the new counts:** rejected. Every circuit recomputes a leaf's expiry from the lifetime, so
  no leaf from before the fork would prove, and every note in the vault would freeze.
- **A release branch per generation:** rejected. Two trees to build and gate, and every fix backported.
- **Give back only the lost time** (`deadline + resume slot − stop slot`): rejected. It puts a constant of each fork into
  each build, and the install has to land before the arithmetic means anything. The full window costs an honest payer
  whose escape straddles a fork up to 2 days.
- **Leave a payout below a raised fee pending:** rejected. Nothing could ever pay it.
- **The zk edge serves old vaults until their notes expire:** rejected. It would keep a request key and freshness values
  for every live generation.
- **Hold the re-key until challenges across a fork that breaks proofs are built:** rejected. The vault would stay frozen
  for everyone, honest payers included, to protect the zk edge's bounded loss.

## Consequences

- A payer who stays in a vault across a fork may get fewer days than they deposited for, if the slot gets shorter. The
  fork notice says so, and tells them to leave.
- A payer who moves to the new vault starts a new anonymity set and waits the minimum subsidy age again.
- Across a fork that breaks earlier proofs, the zk edge's unsettled charges in an old vault are at risk until
  #135 lands.
- The code is in separate issues: the generation table (#136), `resume` (#137), the fee rule
  (#138, after #106), and the zk edge's handling of old vaults (toon-protocol/connector#1683).
- Behaviour across a fork still isn't tested here, since LocalBlockchain can't raise the transaction version. #109's
  rehearsal runs `docs/hard-fork.md` on a forked local network.
