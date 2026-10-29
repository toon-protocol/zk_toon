//! The request proof's public inputs, decoded from the flat field array o1js puts in a proof's
//! `publicInput`. Mirrors `RequestPublic` in `o1js/src/request.ts`; the field order is pinned by the
//! `publicInput` entries of `test-vectors/zk-note.json`.
//!
//! # The subsidy period
//!
//! A subsidised proof's `period` is checked by the circuit only against a creation time the payer
//! chooses, because the circuit cannot read the vault. A payer who forges the creation time proves
//! another period, and with it another per-period nullifier, so it could claim twice in one week. The
//! zk edge must therefore call [`RequestPublic::check_subsidy_period`] with the vault's `creationTime`
//! on every request proof it accepts, before it trusts the per-period nullifier.

use crate::{field_to_bool, field_to_u64, policy, Field};

/// How many fields o1js flattens `RequestPublic` into.
pub const REQUEST_PUBLIC_FIELDS: usize = 12;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestPublicError {
    /// The array does not have [`REQUEST_PUBLIC_FIELDS`] elements.
    Length(usize),
    /// A field that must be 0 or 1 (a flag) is neither.
    NotBool(&'static str),
    /// A field that must fit 64 bits does not.
    NotU64(&'static str),
}

/// Why [`RequestPublic::check_subsidy_period`] refused a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubsidyPeriodError {
    /// An unsubsidised request with a nonzero `period` or `periodNullifier`.
    Unsubsidised,
    /// A subsidised request whose `requestTime` is before the vault's creation, so in no period.
    BeforeCreation,
    /// A subsidised request whose `period` is not the week of its `requestTime` counted from the
    /// vault's creation: it was proven with another creation time.
    WrongPeriod { claimed: u64, expected: u64 },
}

/// The point on the curve a commitment is: affine coordinates, not checked here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point {
    pub x: Field,
    pub y: Field,
}

/// The request proof's public inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestPublic {
    /// The vault's public key (the state key): x coordinate and whether y is odd.
    pub vault_x: Field,
    pub vault_is_odd: bool,
    pub root: Field,
    pub request_time: u64,
    pub tier: u64,
    pub nullifier: Field,
    pub tag: Field,
    /// The state's balance commitment, re-randomised.
    pub commitment: Point,
    pub subsidised: bool,
    /// Whole weeks since a creation time. The circuit bounds it to 64 bits when subsidised and makes
    /// it zero otherwise; [`RequestPublic::check_subsidy_period`] binds it to the vault.
    pub period: u64,
    pub period_nullifier: Field,
}

fn flag(f: Field, name: &'static str) -> Result<bool, RequestPublicError> {
    field_to_bool(f).ok_or(RequestPublicError::NotBool(name))
}

fn as_u64(f: Field, name: &'static str) -> Result<u64, RequestPublicError> {
    field_to_u64(f).ok_or(RequestPublicError::NotU64(name))
}

impl RequestPublic {
    /// Decode the flat array, in o1js `RequestPublic`'s field order: vault (x, isOdd), root,
    /// requestTime, tier, nullifier, tag, commitment (x, y), subsidised, period, periodNullifier.
    pub fn from_fields(fields: &[Field]) -> Result<Self, RequestPublicError> {
        let [vault_x, vault_odd, root, request_time, tier, nullifier, tag, cx, cy, subsidised, period, period_nullifier] =
            *fields
        else {
            return Err(RequestPublicError::Length(fields.len()));
        };
        Ok(Self {
            vault_x,
            vault_is_odd: flag(vault_odd, "vault.isOdd")?,
            root,
            request_time: as_u64(request_time, "requestTime")?,
            tier: as_u64(tier, "tier")?,
            nullifier,
            tag,
            commitment: Point { x: cx, y: cy },
            subsidised: flag(subsidised, "subsidised")?,
            period: as_u64(period, "period")?,
            period_nullifier,
        })
    }

    /// Binds a verified request proof's period to the vault (spec #2: "the period number is whole
    /// weeks since the vault's creation"), which the circuit cannot do: it takes the creation time as
    /// a private input. A subsidised request passes when its `period` is
    /// [`policy::subsidy_period`]`(vault_creation, request_time)`; an unsubsidised one when its `period`
    /// and `period_nullifier` are zero.
    ///
    /// The zk edge must call this, with the vault's `creationTime`, on every request proof it accepts,
    /// before it trusts a subsidised proof's per-period nullifier. Mirrors `subsidyPeriodHolds` in
    /// `o1js/src/request.ts`.
    pub fn check_subsidy_period(&self, vault_creation: u64) -> Result<(), SubsidyPeriodError> {
        if !self.subsidised {
            return if self.period == 0 && self.period_nullifier == Field::from(0u64) {
                Ok(())
            } else {
                Err(SubsidyPeriodError::Unsubsidised)
            };
        }
        let expected =
            policy::subsidy_period(vault_creation, self.request_time).ok_or(SubsidyPeriodError::BeforeCreation)?;
        if self.period == expected {
            Ok(())
        } else {
            Err(SubsidyPeriodError::WrongPeriod { claimed: self.period, expected })
        }
    }
}
