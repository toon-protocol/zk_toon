//! Mirrors o1js `lib/mina/state.js` and the `setKind` of `lib/mina/account-update.js`: what a
//! `SmartContract` method's state reads, state writes and proof authorization put in the witness.
//!
//! `State.set(x)` creates no variables: `x` becomes the account update's `update.appState[i]`,
//! which is where [`crate::witness::account_update::Body`] takes it from.

use mina_curves::pasta::Fp;

use super::range_check::range_check_n_64;
use super::signature::{witness_public_key, PublicKey};
use crate::witness::{Cs, Field};

/// `State<PublicKey>.getAndRequireEquals()`: the state witnessed as a `PublicKey`. The
/// precondition it sets creates no variables.
pub fn get_and_require_equals_public_key(cs: &mut Cs, x: Fp, is_odd: bool) -> PublicKey {
    witness_public_key(cs, x, is_odd)
}

/// `State<UInt64>.getAndRequireEquals()`: the state witnessed as a `UInt64`, so range checked.
pub fn get_and_require_equals_uint64(cs: &mut Cs, value: u64) -> Field {
    let x = cs.exists_one(Fp::from(value));
    range_check_n_64(cs, &x);
    x
}

/// `AccountUpdate.setKind` for a proof authorization: the verification key hash, witnessed.
pub fn set_kind(cs: &mut Cs, verification_key_hash: Fp) -> Field {
    cs.exists_one(verification_key_hash)
}
