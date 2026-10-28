//! The withdrawal proof's public inputs. The connector reads this layout, mirrored by
//! `WithdrawalPublic` in `o1js/src/withdrawal.ts`.
//!
//! # Layout
//!
//! ```text
//! kind, vault (the state key), root, nullifier, nextNullifier, amount, size, destination, validUntil, requestTime
//! ```
//!
//! `vault` and `destination` are Mina public keys, each two field elements `(x, isOdd)`. The proof's
//! kinds: 1 mutual close, 2 escape (reserved), 3 ownership; 0 is invalid. A mutual close and an
//! ownership proof have zero `nextNullifier` and `validUntil`. Note expiry is not a public input.
use crate::Field;

pub const KIND_MUTUAL_CLOSE: u64 = 1;
pub const KIND_ESCAPE: u64 = 2;
pub const KIND_OWNERSHIP: u64 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WithdrawalPublic {
    pub kind: u64,
    pub vault_x: Field,
    pub vault_is_odd: bool,
    pub root: Field,
    pub nullifier: Field,
    pub next_nullifier: Field,
    pub amount: u64,
    pub size: u64,
    pub destination_x: Field,
    pub destination_is_odd: bool,
    pub valid_until: u64,
    pub request_time: u64,
}

impl WithdrawalPublic {
    /// The public input as field elements, in the layout above (twelve: each key is two).
    pub fn to_fields(&self) -> Vec<Field> {
        vec![
            self.kind.into(),
            self.vault_x,
            Field::from(self.vault_is_odd as u64),
            self.root,
            self.nullifier,
            self.next_nullifier,
            self.amount.into(),
            self.size.into(),
            self.destination_x,
            Field::from(self.destination_is_odd as u64),
            self.valid_until.into(),
            self.request_time.into(),
        ]
    }

    /// Whether this kind carries no next nullifier and no `valid_until`, as the circuit enforces.
    pub fn shape_is_valid(&self) -> bool {
        let zero_tail = self.next_nullifier == Field::from(0u64) && self.valid_until == 0;
        match self.kind {
            KIND_MUTUAL_CLOSE | KIND_OWNERSHIP => zero_tail && self.amount <= self.size,
            _ => false,
        }
    }
}
