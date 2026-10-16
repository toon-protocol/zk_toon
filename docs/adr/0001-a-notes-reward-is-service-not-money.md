---
status: accepted
---

# A note's reward is service, not money

The vault's privacy depends on many independent zk notes staying unspent for a long time, so we reward
note age. We reward it with a **subsidised allowance**: once per subsidy period, a note at least 7 days
old may open one smallest-tier allowance whose charge the zk edge's subsidy budget pays. We don't add
MINA to the note's balance.

We chose service because a money reward would:
- loosen the circuit's rule that a balance never exceeds its deposit (`B ≤ D`), which stops a leaked
  state key from minting money;
- need the vault topped up to stay solvent, with no end date;
- look like yield on a privacy pool;
- pay farmers, who then need personhood checks that agents can't pass.

A free allowance is worth something only to someone who uses TOON. Each zk edge funds its own subsidy
budget and may set it to zero.

## Considered Options

- **MINA added to the note's balance** (Tornado-style anonymity mining, Namada-style shielded rewards):
  rejected for the reasons above.
- **A tradeable TOON token as the reward:** rejected. Mina's liquidity is too thin, swaps would link
  claimers, and a project token tied to a privacy pool carries the most regulatory risk
  (`docs/research/token-distribution-and-the-vault.md`).
- **A personhood-gated reward:** deferred. The guards at launch are one claim per note per subsidy
  period, a fixed budget per period, and a minimum age.

## Consequences

- **A subsidised proof can never raise an escape's concession.** The request proof states publicly
  that it is subsidised, and the vault caps a raise from such a proof at zero. Otherwise a zk edge
  could withhold the successor, raise from the subsidised proof, and charge the note for the
  allowance the subsidy was supposed to pay. A subsidised proof can still defeat a stale escape.
- **The zk edge can tell which allowances are subsidised**, so it learns that the payer's note is at
  least 7 days old. We accept this leak.
- **The vault stores each note's deposit time**, and note age is measured from it. Notes live 180 days.
  Subsidy periods are whole weeks counted from the vault's creation, so every note and every zk edge
  agrees which period it is.
- **The work is split.** This repository owns the age statement in the circuit, the policy and the
  per-period nullifier's derivation. The connector (toon-protocol/connector#1511) owns only three
  things: which party pays an allowance's charge (the note or the subsidy budget), checking the
  per-period nullifier, and stopping subsidised allowances once the budget is spent.
