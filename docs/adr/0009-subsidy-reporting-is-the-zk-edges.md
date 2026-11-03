---
status: accepted
---

# The zk edge reports subsidised claims, not the vault

Spec #2's story 38 asks for "aggregate reporting of subsidised claims per finished period available
from what the vault records". But the vault records no subsidised claim. A subsidised request proof
opens an allowance at the zk edge, and the zk edge checks the per-period nullifier, one claim per note
per period (`docs/design/zkapi-payments.md`). No claim is a vault transaction. The vault sees only
deposits, withdrawals and challenges. A subsidised proof reaches the vault only as a defeat's
evidence, and a defeat can use any proof.

## Decision

The zk edge reports: its self-description publishes how many subsidised allowances it granted in each
**finished** period, never the current one, as the design's subsidy table says. That is connector
#1511's to build. This repository gives it what it needs: the period arithmetic and the per-period
nullifier in `zk-note`, which count claims the same way at every zk edge. The vault gains no
per-period state.

## Considered Options

- **A per-period counter on the vault:** rejected. Every subsidised claim would become a vault
  transaction, with a fee and a write to shared state, and the time it lands would tie the allowance
  to a chain event. That is the linking a subsidised claim exists to avoid. The vault also has only
  three of its 32 state fields left (ADR 0005).
- **Publish the per-period nullifiers somewhere public:** rejected for the same reason. A count is
  all the crowd's growth needs.

## Consequences

- Story 38 is met by the zk edge, and the count is only as honest as the zk edge. A zk edge that
  overstates its count gains nothing it can spend, since the reward is service, not money (ADR 0001).
- A count over every zk edge is the sum of their self-descriptions. There is one vault and one zk edge
  per note (#2, out of scope), so a note's claims are counted at one place.
