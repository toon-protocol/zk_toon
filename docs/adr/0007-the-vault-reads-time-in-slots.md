---
status: accepted
---

# The vault reads time in slots

The vault reads chain time only through `this.network.timestamp.requireBetween` (`o1js/src/vault.ts`),
and on devnet that fails (#54). This records the fix: the vault reads time in slots.

## Context

o1js turns each timestamp bound into a `globalSlotSinceGenesis` range, using `genesisTimestamp` and
`slotTime` from `Mina.getNetworkConstants()`. In a proved method those constants are fixed into the
circuit when it is compiled. `npm run keys` compiles with o1js's defaults (`genesisTimestamp = 0`,
`slotTime = 180000`), so the published vault asks for slots around `t / 180000`, about 9,960,000 today.

Devnet checks slot preconditions against the global slot counted from the network's **original**
genesis (about 927,641 on 2026-10-29). Its slots have been 90 s since the Mesa fork and were 180 s
before. Two signed no-op transactions from the dev funder, probed on 2026-10-29, show it:

| Required `globalSlotSinceGenesis` range | Result |
|---|---|
| around 68,083, what `daemonStatus.consensusTimeNow.globalSlot` reports (counted from the Mesa fork's genesis, 2026-08-19) | **failed**, `Protocol_state_precondition_unsatisfied`, fee charged: `5JuARUuBmxdywB5JP9myr1NKxPGn9WHZg7m66B2uXcjVMZ3vznWF` |
| around 927,641, `bestChain…consensusState.slotSinceGenesis` (counted from the original 2024 genesis) | **applied**: `5JvENEV6BACmhWYBywYYRULqr31DzKzTc9btg7qNBL3cWxMqkSFw` |

So every time-bound vault method fails on devnet as published. Compiling under devnet's constants
doesn't help: no (`genesisTimestamp`, `slotTime`) pair maps today's timestamps to slot 927,641,
because the slots before the fork were 180 s and the ones after are 90 s. Mainnet went through the
same fork, so the same holds there (inference, not probed).

The channel zkApp reached the same conclusion: see "Time" in
`docs/design/scheme_batch_settlement_mina.md`.

## Decision

**Slots are the only unit of time.** Every time the vault stores, every time in a note leaf, action,
pending escape or proof public input, and every policy duration is a slot count. The slot is the
global slot counted from the network's original genesis (GLOSSARY: Slot).

The vault reads chain time only through `this.currentSlot.requireBetween(lo, hi)`. It has no
`network.*` time precondition, and no check requires an exact slot: every time check is a range.

Durations come from `SLOT_SECONDS = 90`, defined once per language, and `SLOTS_PER_DAY = 960`:

| Duration | Slots | Time |
|---|---|---|
| Note lifetime | 172,800 | 180 days |
| Challenge window | 1,920 | 2 days |
| Subsidy period | 6,720 | 7 days |
| Minimum subsidy age | 6,720 | 7 days |
| Request max age (the close window still equals it) | 7 | 10 minutes, rounded up |
| Request max lead | 1 | 1 minute, rounded up |

Durations of a minute or so round **up** to whole slots. These constants are part of the verification
key, so a fork that changes slot length changes them with the key.

The zk edge's freshness check takes slots. How the edge gets its current slot is connector#1511.

## Considered Options

- **Keep milliseconds and compile under a made-up genesis** (`slotTime = 90000`): rejected. It needs a
  hand-worked fork anchor built into the key, and it keeps a `network.*` precondition, which "Time" in
  `docs/design/scheme_batch_settlement_mina.md` says is checked against the parent block rather than
  the including one.
- **Keep the edge's `requestTime` in milliseconds:** rejected. The vault compares it with chain time,
  and the request circuit compares it with `depositTime`, so both sides would need a conversion.

## Consequences

- The vault and `zk-note` change in a follow-up slice (#54): the code and its mirror in
  `zk-note/src/policy.rs` move to slots, and the verification keys are regenerated.
- A test can now fail if a vault method's time check depends on `Mina.getNetworkConstants()`.
