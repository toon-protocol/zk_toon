//! The withdrawal proof's public inputs. The connector reads this layout, mirrored by
//! `WithdrawalPublic` in `o1js/src/withdrawal.ts`.
//!
//! # Layout
//!
//! ```text
//! kind, vault (the state key), root, nullifier, nextNullifier, amount, size, destination, validUntil, requestTime, conceded
//! ```
//!
//! `vault` and `destination` are Mina public keys, each two field elements `(x, isOdd)`. The proof's
//! kinds: 1 mutual close, 2 escape, 3 ownership; 0 is invalid. A mutual close and an ownership proof
//! have zero `nextNullifier`, `validUntil` and `conceded`. An escape publishes the next state's
//! nullifier ([`WithdrawalPublic::escape_next_nullifier`]), `validUntil`, the last slot it may
//! land at (`requestTime ≤ validUntil < expiry`), and `conceded`, what it gives up of its balance
//! (`conceded ≤ amount`). `conceded` was appended by the escape (#9), so every other input keeps its
//! position. Note expiry is not a public input.
use crate::{field_to_bool, field_to_u64, next_anchor, nullifier, Field};

pub const KIND_MUTUAL_CLOSE: u64 = 1;
pub const KIND_ESCAPE: u64 = 2;
pub const KIND_OWNERSHIP: u64 = 3;

/// How many fields the withdrawal proof's public input flattens into.
pub const WITHDRAWAL_PUBLIC_FIELDS: usize = 13;

/// Why [`WithdrawalPublic::from_fields`] refused an array.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WithdrawalPublicError {
    /// The array does not have [`WITHDRAWAL_PUBLIC_FIELDS`] elements.
    Length(usize),
    /// A field that must be 0 or 1 (a flag) is neither.
    NotBool(&'static str),
    /// A field that must fit 64 bits does not.
    NotU64(&'static str),
    /// Not one of the three kinds.
    Kind(u64),
    /// The inputs break the shape the circuit enforces for their kind ([`WithdrawalPublic::shape_is_valid`]).
    Shape,
}

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
    /// What an escape gives up of its balance; zero for the other kinds.
    pub conceded: u64,
}

impl WithdrawalPublic {
    /// The public input as field elements, in the layout above (thirteen: each key is two).
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
            self.conceded.into(),
        ]
    }

    /// Decodes the thirteen fields of the layout above, as a proof's `publicInput` holds them. Refuses
    /// an unknown kind, and inputs whose shape their kind does not allow ([`Self::shape_is_valid`]).
    pub fn from_fields(f: &[Field]) -> Result<Self, WithdrawalPublicError> {
        use WithdrawalPublicError::{NotBool, NotU64};
        let [kind, vault_x, vault_odd, root, nullifier, next_nullifier, amount, size, destination_x, destination_odd, valid_until, request_time, conceded] =
            *f
        else {
            return Err(WithdrawalPublicError::Length(f.len()));
        };
        let u = |v: Field, name| field_to_u64(v).ok_or(NotU64(name));
        let b = |v: Field, name| field_to_bool(v).ok_or(NotBool(name));
        let kind = u(kind, "kind")?;
        if ![KIND_MUTUAL_CLOSE, KIND_ESCAPE, KIND_OWNERSHIP].contains(&kind) {
            return Err(WithdrawalPublicError::Kind(kind));
        }
        let public = WithdrawalPublic {
            kind,
            vault_x,
            vault_is_odd: b(vault_odd, "vault.isOdd")?,
            root,
            nullifier,
            next_nullifier,
            amount: u(amount, "amount")?,
            size: u(size, "size")?,
            destination_x,
            destination_is_odd: b(destination_odd, "destination.isOdd")?,
            valid_until: u(valid_until, "validUntil")?,
            request_time: u(request_time, "requestTime")?,
            conceded: u(conceded, "conceded")?,
        };
        if !public.shape_is_valid() {
            return Err(WithdrawalPublicError::Shape);
        }
        Ok(public)
    }

    /// Whether the inputs have the shape the circuit enforces for their kind: `amount ≤ size`, and a
    /// zero `nextNullifier`, `validUntil` and `conceded` for a mutual close or an ownership proof; for an
    /// escape, a next nullifier, `conceded ≤ amount` and `requestTime ≤ validUntil`. It cannot check what
    /// needs the note's secret or expiry.
    pub fn shape_is_valid(&self) -> bool {
        let zero = Field::from(0u64);
        let bounded = self.amount <= self.size;
        match self.kind {
            KIND_MUTUAL_CLOSE | KIND_OWNERSHIP => {
                bounded && self.next_nullifier == zero && self.valid_until == 0 && self.conceded == 0
            }
            KIND_ESCAPE => {
                bounded
                    && self.next_nullifier != zero
                    && self.conceded <= self.amount
                    && self.request_time <= self.valid_until
            }
            _ => false,
        }
    }

    /// The nullifier an escape names as `nextNullifier`: that of the state the zk edge would sign
    /// next, whose anchor derives from this state's nullifier.
    pub fn escape_next_nullifier(&self, secret: Field) -> Field {
        nullifier(secret, next_anchor(self.nullifier))
    }
}
