// Policy arithmetic shared with zk-note/src/policy.rs. Times are slots (ADR 0007, GLOSSARY: Slot);
// amounts are nanomina.
//
// The deposit sizes and tiers are the devnet values (ADR 0010); mainnet's are decided at the mainnet gates.
import { Field } from 'o1js';

/**
 * A vault generation (ADR 0015): the vaults built with one set of values. A slot length and the slot counts it gives,
 * each rounded up as ADR 0007 does. A vault from before a fork keeps its generation's counts, and a vault deployed after it
 * takes the fork's slot length, so the table holds a row for every generation with a balance still in it.
 */
export type Generation = {
  id: string;
  /** How long a slot lasts. Durations below are whole slots of it. */
  slotSeconds: bigint;
  slotsPerDay: bigint;
  noteLifetimeSlots: bigint;
  minSubsidyAgeSlots: bigint;
  subsidyPeriodSlots: bigint;
  /** How long a challenger has to answer a close or an escape. */
  challengeWindowSlots: bigint;
  /** How far a request's `requestTime` may be behind the zk edge's current slot: 10 minutes, rounded up. Fixed by the connector. */
  requestMaxAgeSlots: bigint;
  /** How far a request's `requestTime` may be ahead of the zk edge's current slot: a minute, rounded up. Fixed by the connector. */
  requestMaxLeadSlots: bigint;
  /**
   * The least a close or an escape may pay, and the least a payout may be unless it is zero: the account creation fee when the
   * generation was built, or the fork's after a re-key. It follows the network's fee, separately from the slot counts (ADR 0015).
   */
  minWithdrawal: bigint;
};

const MINA = 1_000_000_000n;
/** What the chain takes from a payout that opens its destination's account (1 MINA). Every withdrawal must pay at least it (ADR 0013). */
export const ACCOUNT_CREATION_FEE = MINA;

/**
 * The generation whose slots last `slotSeconds`: every slot count follows from it (ADR 0007). Its minimum withdrawal is the
 * fork's account creation fee, `minWithdrawal`, the fee today's chain takes unless given.
 */
export function generationOf(id: string, slotSeconds: bigint, minWithdrawal: bigint = ACCOUNT_CREATION_FEE): Generation {
  const slotsCeil = (seconds: bigint) => (seconds + slotSeconds - 1n) / slotSeconds;
  const slotsPerDay = 86_400n / slotSeconds;
  return {
    id,
    slotSeconds,
    slotsPerDay,
    noteLifetimeSlots: 180n * slotsPerDay,
    minSubsidyAgeSlots: 7n * slotsPerDay,
    subsidyPeriodSlots: 7n * slotsPerDay,
    challengeWindowSlots: 2n * slotsPerDay,
    requestMaxAgeSlots: slotsCeil(600n),
    requestMaxLeadSlots: slotsCeil(60n),
    minWithdrawal,
  };
}

/** The live vault generations, oldest first. Today's slot length (Mesa's) is the only one. A fork adds a row (`docs/hard-fork.md`). */
export const GENERATIONS: readonly Generation[] = [generationOf('mesa', 90n)];
/** The id of the generation new vaults are deployed with and the registry fixes. */
export const CURRENT_GENERATION_ID = 'mesa';

/** The generation with `id` in `table`; throws if there is none. */
export function generationById(id: string, table: readonly Generation[] = GENERATIONS): Generation {
  const found = table.find((g) => g.id === id);
  if (!found) throw Error(`no vault generation '${id}'`);
  return found;
}
export const CURRENT_GENERATION: Generation = generationById(CURRENT_GENERATION_ID);

/** A key for building each generation once: its id, which names its programs, and every value it compiles in. */
export const generationKey = (g: Generation) => Object.values(g).join(':');

/**
 * The generation of the vault whose code hash is `codeHash`, given each generation's published code hash (`vault.codeHash` in
 * `Keys`). Throws, naming the hash, if it is in none: the keeper, the challenger and the transaction builder refuse such a vault.
 */
export function generationOfCodeHash(
  codeHash: string, published: Readonly<Record<string, { vault: { codeHash: string } }>>, table: readonly Generation[] = GENERATIONS,
): Generation {
  const id = Object.keys(published).find((k) => published[k].vault.codeHash === codeHash);
  const found = id === undefined ? undefined : table.find((g) => g.id === id);
  if (!found) throw Error(`vault code hash ${codeHash} is in no vault generation`);
  return found;
}

const CURRENT = CURRENT_GENERATION;
/** How long a slot lasts since the Mesa fork. Durations below are whole slots of it. */
export const SLOT_SECONDS = CURRENT.slotSeconds;
export const SLOTS_PER_DAY = CURRENT.slotsPerDay;
export const NOTE_LIFETIME_SLOTS = CURRENT.noteLifetimeSlots;
export const MIN_SUBSIDY_AGE_SLOTS = CURRENT.minSubsidyAgeSlots;
export const SUBSIDY_PERIOD_SLOTS = CURRENT.subsidyPeriodSlots;
/** How long a challenger has to answer a close or an escape. */
export const CHALLENGE_WINDOW_SLOTS = CURRENT.challengeWindowSlots;
/** How far a request's `requestTime` may be behind the zk edge's current slot: 10 minutes, rounded up. Fixed by the connector. */
export const REQUEST_MAX_AGE_SLOTS = CURRENT.requestMaxAgeSlots;
/** How far a request's `requestTime` may be ahead of the zk edge's current slot: a minute, rounded up. Fixed by the connector. */
export const REQUEST_MAX_LEAD_SLOTS = CURRENT.requestMaxLeadSlots;

/** Request tiers `b`, ascending. The first is the smallest, the only one a subsidised allowance may use. */
export const TIERS: readonly bigint[] = [MINA / 100n, MINA / 10n, MINA];
/** Accepted deposit sizes, ascending. */
export const DEPOSIT_SIZES: readonly bigint[] = [10n * MINA, 100n * MINA, 1000n * MINA];

export const isTier = (b: bigint) => TIERS.includes(b);
export const isDepositSize = (size: bigint) => DEPOSIT_SIZES.includes(size);
export const isSmallestTier = (b: bigint) => b === TIERS[0];

export const expiryOf = (depositTime: bigint, g: Generation = CURRENT) => depositTime + g.noteLifetimeSlots;
/** `expiryOf` in a circuit. */
export const expiryOfField = (depositTime: Field, g: Generation = CURRENT) => depositTime.add(Field(g.noteLifetimeSlots));

/** Whole subsidy periods (weeks) of slots since the vault's creation slot; undefined before it. */
export function subsidyPeriod(vaultCreation: bigint, now: bigint, g: Generation = CURRENT): bigint | undefined {
  if (now < vaultCreation) return undefined;
  return (now - vaultCreation) / g.subsidyPeriodSlots;
}

/** A note may claim a subsidised allowance once it is at least 7 days (6,720 slots) old. */
export const isOldEnoughForSubsidy = (depositTime: bigint, now: bigint, g: Generation = CURRENT) =>
  now >= depositTime && now - depositTime >= g.minSubsidyAgeSlots;

/** A zk edge accepts a `requestTime` (a slot) at most `REQUEST_MAX_AGE_SLOTS` behind and at most `REQUEST_MAX_LEAD_SLOTS` ahead of `currentSlot`, its current slot. */
export const isRequestTimeFresh = (requestTime: bigint, currentSlot: bigint, g: Generation = CURRENT) =>
  requestTime + g.requestMaxAgeSlots >= currentSlot && requestTime <= currentSlot + g.requestMaxLeadSlots;
