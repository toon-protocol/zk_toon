// Policy arithmetic shared with zk-note/src/policy.rs. Times are slots (ADR 0007, GLOSSARY: Slot);
// amounts are nanomina.
//
// The deposit sizes and tiers are open values in the spec (#2); these are provisional.
import { Field } from 'o1js';

/** How long a slot lasts since the Mesa fork. Durations below are whole slots of it. */
export const SLOT_SECONDS = 90n;
export const SLOTS_PER_DAY = 86_400n / SLOT_SECONDS;
/** Rounds up: a duration of a minute or so is whole slots. */
const slotsCeil = (seconds: bigint) => (seconds + SLOT_SECONDS - 1n) / SLOT_SECONDS;
export const NOTE_LIFETIME_SLOTS = 180n * SLOTS_PER_DAY;
export const MIN_SUBSIDY_AGE_SLOTS = 7n * SLOTS_PER_DAY;
export const SUBSIDY_PERIOD_SLOTS = 7n * SLOTS_PER_DAY;
/** How long a challenger has to answer a close or an escape. */
export const CHALLENGE_WINDOW_SLOTS = 2n * SLOTS_PER_DAY;
/** How far a request's `requestTime` may be behind the zk edge's current slot: 10 minutes, rounded up. Fixed by the connector. */
export const REQUEST_MAX_AGE_SLOTS = slotsCeil(600n);
/** How far a request's `requestTime` may be ahead of the zk edge's current slot: a minute, rounded up. Fixed by the connector. */
export const REQUEST_MAX_LEAD_SLOTS = slotsCeil(60n);

const MINA = 1_000_000_000n;
/** Request tiers `b`, ascending. The first is the smallest, the only one a subsidised allowance may use. */
export const TIERS: readonly bigint[] = [MINA / 100n, MINA / 10n, MINA];
/** Accepted deposit sizes, ascending. */
export const DEPOSIT_SIZES: readonly bigint[] = [10n * MINA, 100n * MINA, 1000n * MINA];

export const isTier = (b: bigint) => TIERS.includes(b);
export const isDepositSize = (size: bigint) => DEPOSIT_SIZES.includes(size);
export const isSmallestTier = (b: bigint) => b === TIERS[0];

export const expiryOf = (depositTime: bigint) => depositTime + NOTE_LIFETIME_SLOTS;
/** `expiryOf` in a circuit. */
export const expiryOfField = (depositTime: Field) => depositTime.add(Field(NOTE_LIFETIME_SLOTS));

/** Whole subsidy periods (weeks) of slots since the vault's creation slot; undefined before it. */
export function subsidyPeriod(vaultCreation: bigint, now: bigint): bigint | undefined {
  if (now < vaultCreation) return undefined;
  return (now - vaultCreation) / SUBSIDY_PERIOD_SLOTS;
}

/** A note may claim a subsidised allowance once it is at least 7 days (6,720 slots) old. */
export const isOldEnoughForSubsidy = (depositTime: bigint, now: bigint) =>
  now >= depositTime && now - depositTime >= MIN_SUBSIDY_AGE_SLOTS;

/** A zk edge accepts a `requestTime` (a slot) at most `REQUEST_MAX_AGE_SLOTS` behind and at most `REQUEST_MAX_LEAD_SLOTS` ahead of `currentSlot`, its current slot. */
export const isRequestTimeFresh = (requestTime: bigint, currentSlot: bigint) =>
  requestTime + REQUEST_MAX_AGE_SLOTS >= currentSlot && requestTime <= currentSlot + REQUEST_MAX_LEAD_SLOTS;
