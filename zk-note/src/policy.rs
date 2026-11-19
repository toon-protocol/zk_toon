//! Policy arithmetic shared with `o1js/src/policy.ts`. Times are slots (ADR 0007, GLOSSARY: Slot);
//! amounts are nanomina.
//!
//! The deposit sizes and tiers are the devnet values (ADR 0010); mainnet's are decided at the mainnet gates.

/// A vault generation (ADR 0015): the vaults built with one set of values. A slot length and the slot counts it gives,
/// each rounded up as ADR 0007 does. Mirrors `Generation` in `o1js/src/policy.ts`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Generation {
    pub id: &'static str,
    /// How long a slot lasts. Durations below are whole slots of it.
    pub slot_seconds: u64,
    pub slots_per_day: u64,
    pub note_lifetime_slots: u64,
    pub min_subsidy_age_slots: u64,
    pub subsidy_period_slots: u64,
    /// How long a challenger has to answer a close or an escape.
    pub challenge_window_slots: u64,
    /// How far a request's `requestTime` may be behind the zk edge's current slot: 10 minutes, rounded up.
    /// Fixed by the connector.
    pub request_max_age_slots: u64,
    /// How far a request's `requestTime` may be ahead of the zk edge's current slot: a minute, rounded up.
    /// Fixed by the connector.
    pub request_max_lead_slots: u64,
}

/// The generation whose slots last `slot_seconds`: every slot count follows from it (ADR 0007).
pub const fn generation_of(id: &'static str, slot_seconds: u64) -> Generation {
    let slots_per_day = 86_400 / slot_seconds;
    Generation {
        id,
        slot_seconds,
        slots_per_day,
        note_lifetime_slots: 180 * slots_per_day,
        min_subsidy_age_slots: 7 * slots_per_day,
        subsidy_period_slots: 7 * slots_per_day,
        challenge_window_slots: 2 * slots_per_day,
        request_max_age_slots: 600_u64.div_ceil(slot_seconds),
        request_max_lead_slots: 60_u64.div_ceil(slot_seconds),
    }
}

/// The live vault generations, oldest first. Today's slot length (Mesa's) is the only one. A fork adds a row
/// (`docs/hard-fork.md`).
pub const GENERATIONS: [Generation; 1] = [generation_of("mesa", 90)];
/// The id of the generation new vaults are deployed with and the registry fixes.
pub const CURRENT_GENERATION_ID: &str = "mesa";
/// The current generation: the row named by [`CURRENT_GENERATION_ID`]. The build fails if there is none.
pub const CURRENT_GENERATION: Generation = {
    let mut i = 0;
    loop {
        assert!(i < GENERATIONS.len(), "CURRENT_GENERATION_ID names no generation");
        let (id, want) = (GENERATIONS[i].id.as_bytes(), CURRENT_GENERATION_ID.as_bytes());
        let mut same = id.len() == want.len();
        let mut j = 0;
        while same && j < id.len() {
            same = id[j] == want[j];
            j += 1;
        }
        if same {
            break GENERATIONS[i];
        }
        i += 1;
    }
};

/// The generation with `id`, if the table has one.
pub fn generation(id: &str) -> Option<&'static Generation> {
    GENERATIONS.iter().find(|g| g.id == id)
}

/// A vault code hash that is in no generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownCodeHash(pub String);

impl std::fmt::Display for UnknownCodeHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "vault code hash {} is in no vault generation", self.0)
    }
}

impl std::error::Error for UnknownCodeHash {}

/// The generation of the vault whose code hash is `code_hash`, given each generation's published code hash as
/// `(id, vault.codeHash)` pairs (the published keys' `generations`). A code hash in no generation is refused,
/// naming it.
pub fn generation_of_code_hash(
    code_hash: &str,
    published: &[(&str, &str)],
) -> Result<&'static Generation, UnknownCodeHash> {
    published
        .iter()
        .find(|(_, hash)| *hash == code_hash)
        .and_then(|(id, _)| generation(id))
        .ok_or_else(|| UnknownCodeHash(code_hash.to_string()))
}

/// How long a slot lasts since the Mesa fork. Durations below are whole slots of it.
pub const SLOT_SECONDS: u64 = CURRENT_GENERATION.slot_seconds;
pub const SLOTS_PER_DAY: u64 = CURRENT_GENERATION.slots_per_day;
pub const NOTE_LIFETIME_SLOTS: u64 = CURRENT_GENERATION.note_lifetime_slots;
pub const MIN_SUBSIDY_AGE_SLOTS: u64 = CURRENT_GENERATION.min_subsidy_age_slots;
pub const SUBSIDY_PERIOD_SLOTS: u64 = CURRENT_GENERATION.subsidy_period_slots;
/// How long a challenger has to answer a close or an escape.
pub const CHALLENGE_WINDOW_SLOTS: u64 = CURRENT_GENERATION.challenge_window_slots;
/// How far a request's `requestTime` may be behind the zk edge's current slot: 10 minutes, rounded up.
/// Fixed by the connector.
pub const REQUEST_MAX_AGE_SLOTS: u64 = CURRENT_GENERATION.request_max_age_slots;
/// How far a request's `requestTime` may be ahead of the zk edge's current slot: a minute, rounded up.
/// Fixed by the connector.
pub const REQUEST_MAX_LEAD_SLOTS: u64 = CURRENT_GENERATION.request_max_lead_slots;

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
