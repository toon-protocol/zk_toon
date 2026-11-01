//! Policy arithmetic shared with `o1js/src/policy.ts`. Times are slots (ADR 0007, GLOSSARY: Slot);
//! amounts are nanomina.
//!
//! The deposit sizes and tiers are open values in the spec (#2); these are provisional.

/// How long a slot lasts since the Mesa fork. Durations below are whole slots of it.
pub const SLOT_SECONDS: u64 = 90;
pub const SLOTS_PER_DAY: u64 = 86_400 / SLOT_SECONDS;
pub const NOTE_LIFETIME_SLOTS: u64 = 180 * SLOTS_PER_DAY;
pub const MIN_SUBSIDY_AGE_SLOTS: u64 = 7 * SLOTS_PER_DAY;
pub const SUBSIDY_PERIOD_SLOTS: u64 = 7 * SLOTS_PER_DAY;
/// How long a challenger has to answer a close or an escape.
pub const CHALLENGE_WINDOW_SLOTS: u64 = 2 * SLOTS_PER_DAY;
/// How far a request's `requestTime` may be behind the zk edge's current slot: 10 minutes, rounded up.
/// Fixed by the connector.
pub const REQUEST_MAX_AGE_SLOTS: u64 = 600_u64.div_ceil(SLOT_SECONDS);
/// How far a request's `requestTime` may be ahead of the zk edge's current slot: a minute, rounded up.
/// Fixed by the connector.
pub const REQUEST_MAX_LEAD_SLOTS: u64 = 60_u64.div_ceil(SLOT_SECONDS);

const MINA: u64 = 1_000_000_000;
/// Request tiers `b`, ascending. The first is the smallest, the only one a subsidised allowance may use.
pub const TIERS: [u64; 3] = [MINA / 100, MINA / 10, MINA];
/// Accepted deposit sizes, ascending.
pub const DEPOSIT_SIZES: [u64; 3] = [10 * MINA, 100 * MINA, 1000 * MINA];

pub fn is_tier(b: u64) -> bool {
    TIERS.contains(&b)
}

pub fn is_deposit_size(size: u64) -> bool {
    DEPOSIT_SIZES.contains(&size)
}

pub fn is_smallest_tier(b: u64) -> bool {
    b == TIERS[0]
}

/// A note expires 180 days after its deposit slot.
pub fn expiry_of(deposit_time: u64) -> u64 {
    deposit_time + NOTE_LIFETIME_SLOTS
}

/// Whole subsidy periods (weeks) of slots since the vault's creation slot; `None` before it.
pub fn subsidy_period(vault_creation: u64, now: u64) -> Option<u64> {
    now.checked_sub(vault_creation).map(|d| d / SUBSIDY_PERIOD_SLOTS)
}

/// A note may claim a subsidised allowance once it is at least 7 days old.
pub fn is_old_enough_for_subsidy(deposit_time: u64, now: u64) -> bool {
    now.checked_sub(deposit_time).is_some_and(|age| age >= MIN_SUBSIDY_AGE_SLOTS)
}

/// A zk edge accepts a `requestTime` (a slot) at most [`REQUEST_MAX_AGE_SLOTS`] behind and at most
/// [`REQUEST_MAX_LEAD_SLOTS`] ahead of `current_slot`, the edge's current slot.
pub fn is_request_time_fresh(request_time: u64, current_slot: u64) -> bool {
    request_time.saturating_add(REQUEST_MAX_AGE_SLOTS) >= current_slot
        && request_time <= current_slot.saturating_add(REQUEST_MAX_LEAD_SLOTS)
}
