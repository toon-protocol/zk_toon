// Policy arithmetic shared with crates/zk-note/src/policy.rs. Times are milliseconds
// (Mina block timestamps); amounts are nanomina.
//
// The deposit sizes and tiers are open values in the spec (#2); these are provisional.

export const MS_PER_DAY = 86_400_000n;
export const NOTE_LIFETIME_MS = 180n * MS_PER_DAY;
export const MIN_SUBSIDY_AGE_MS = 7n * MS_PER_DAY;
export const SUBSIDY_PERIOD_MS = 7n * MS_PER_DAY;

const MINA = 1_000_000_000n;
/** Request tiers `b`, ascending. The first is the smallest, the only one a subsidised allowance may use. */
export const TIERS: readonly bigint[] = [MINA / 100n, MINA / 10n, MINA];
/** Accepted deposit sizes, ascending. */
export const DEPOSIT_SIZES: readonly bigint[] = [10n * MINA, 100n * MINA, 1000n * MINA];

export const isTier = (b: bigint) => TIERS.includes(b);
export const isDepositSize = (a: bigint) => DEPOSIT_SIZES.includes(a);
export const isSmallestTier = (b: bigint) => b === TIERS[0];

export const expiryOf = (depositTime: bigint) => depositTime + NOTE_LIFETIME_MS;

/** Whole weeks since the vault's creation; undefined before it. */
export function subsidyPeriod(vaultCreation: bigint, now: bigint): bigint | undefined {
  if (now < vaultCreation) return undefined;
  return (now - vaultCreation) / SUBSIDY_PERIOD_MS;
}

/** A note may claim a subsidised allowance once it is at least 7 days old. */
export const isOldEnoughForSubsidy = (depositTime: bigint, now: bigint) =>
  now >= depositTime && now - depositTime >= MIN_SUBSIDY_AGE_MS;
