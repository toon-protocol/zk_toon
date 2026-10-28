//! The request proof's public inputs, decoded from the flat field array o1js puts in a proof's
//! `publicInput`. Mirrors `RequestPublic` in `o1js/src/request.ts`; the field order is pinned by the
//! `publicInput` entries of `test-vectors/zk-note.json`.

use ark_ff::{PrimeField, Zero};

use crate::Field;

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

/// The point on the curve a commitment is: affine coordinates, not checked here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point {
    pub x: Field,
    pub y: Field,
}

/// The request proof's public inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestPublic {
    /// The vault's public key: x coordinate and whether y is odd.
    pub vault_x: Field,
    pub vault_is_odd: bool,
    pub root: Field,
    pub request_time: u64,
    pub tier: u64,
    pub nullifier: Field,
    pub tag: Field,
    pub commitment: Point,
    pub subsidised: bool,
    pub period: Field,
    pub period_nullifier: Field,
}

fn flag(f: Field, name: &'static str) -> Result<bool, RequestPublicError> {
    if f.is_zero() {
        Ok(false)
    } else if f == Field::from(1u64) {
        Ok(true)
    } else {
        Err(RequestPublicError::NotBool(name))
    }
}

fn amount(f: Field, name: &'static str) -> Result<u64, RequestPublicError> {
    let limbs = f.into_bigint().0;
    if limbs[1..].iter().any(|l| *l != 0) {
        return Err(RequestPublicError::NotU64(name));
    }
    Ok(limbs[0])
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
            request_time: amount(request_time, "requestTime")?,
            tier: amount(tier, "tier")?,
            nullifier,
            tag,
            commitment: Point { x: cx, y: cy },
            subsidised: flag(subsidised, "subsidised")?,
            period,
            period_nullifier,
        })
    }
}
