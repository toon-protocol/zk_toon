//! Policy arithmetic shared with `o1js/src/policy.ts`. Times are milliseconds (Mina block
//! timestamps); amounts are nanomina.
//!
//! The deposit sizes and tiers are open values in the spec (#2); these are provisional.

pub const MS_PER_DAY: u64 = 86_400_000;
pub const NOTE_LIFETIME_MS: u64 = 180 * MS_PER_DAY;
pub const MIN_SUBSIDY_AGE_MS: u64 = 7 * MS_PER_DAY;
pub const SUBSIDY_PERIOD_MS: u64 = 7 * MS_PER_DAY;

const MINA: u64 = 1_000_000_000;
/// Request tiers `b`, ascending. The first is the smallest, the only one a subsidised allowance may use.
pub const TIERS: [u64; 3] = [MINA / 100, MINA / 10, MINA];
/// Accepted deposit sizes, ascending.
pub const DEPOSIT_SIZES: [u64; 3] = [10 * MINA, 100 * MINA, 1000 * MINA];

pub fn is_tier(b: u64) -> bool {
    TIERS.contains(&b)
}

pub fn is_deposit_size(a: u64) -> bool {
    DEPOSIT_SIZES.contains(&a)
}

pub fn is_smallest_tier(b: u64) -> bool {
    b == TIERS[0]
}

/// A note expires 180 days after its deposit time.
pub fn expiry_of(deposit_time: u64) -> u64 {
    deposit_time + NOTE_LIFETIME_MS
}

/// Whole weeks since the vault's creation; `None` before it.
pub fn subsidy_period(vault_creation: u64, now: u64) -> Option<u64> {
    now.checked_sub(vault_creation).map(|d| d / SUBSIDY_PERIOD_MS)
}

/// A note may claim a subsidised allowance once it is at least 7 days old.
pub fn is_old_enough_for_subsidy(deposit_time: u64, now: u64) -> bool {
    now.checked_sub(deposit_time).is_some_and(|age| age >= MIN_SUBSIDY_AGE_MS)
}
