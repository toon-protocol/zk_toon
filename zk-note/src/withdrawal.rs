//! The withdrawal proof's public inputs. Mirrors `WithdrawalPublic` in `o1js/src/withdrawal.ts`.
//!
//! The withdrawal proof is its own o1js `ZkProgram`, so its verification key is not the request
//! proof's. It has a mutual-close method and an ownership method; escape (#9) adds a third.
//!
//! # Field layout
//!
//! Twelve Pallas base field elements, in this order:
//!
//! ```text
//! [kind, vault.x, vault.isOdd, root, nullifier, nextNullifier, amount, size,
//!  destination.x, destination.isOdd, validUntil, requestTime]
//! ```
//!
//! `vault` is the state key. `nextNullifier` and `validUntil` are zero for a mutual close and an
//! ownership proof, and the circuit enforces it. `amount` is the state's balance and `size` the
//! note's deposit size, with `amount ≤ size`. The note's expiry is not public: deposit times are,
//! so publishing it would link a withdrawal to its deposit.
use mina_signer::CompressedPubKey;

use crate::Field;

/// The `kind` public input. 0 is invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum WithdrawalKind {
    MutualClose = 1,
    /// Reserved for escape (#9).
    Escape = 2,
    /// Shown only to the zk edge; the vault refuses it.
    Ownership = 3,
}

impl TryFrom<u64> for WithdrawalKind {
    type Error = u64;

    fn try_from(kind: u64) -> Result<Self, u64> {
        match kind {
            1 => Ok(Self::MutualClose),
            2 => Ok(Self::Escape),
            3 => Ok(Self::Ownership),
            other => Err(other),
        }
    }
}

/// The withdrawal proof's public inputs, in the circuit's order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WithdrawalPublic {
    pub kind: WithdrawalKind,
    /// The state key.
    pub vault: CompressedPubKey,
    pub root: Field,
    pub nullifier: Field,
    pub next_nullifier: Field,
    pub amount: u64,
    pub size: u64,
    /// The Mina public key the balance goes to. An ownership proof binds the destination its holder
    /// wants cleared.
    pub destination: CompressedPubKey,
    pub valid_until: u64,
    pub request_time: u64,
}

impl WithdrawalPublic {
    /// The public inputs as the proof carries them.
    pub fn to_fields(&self) -> Vec<Field> {
        vec![
            Field::from(self.kind as u64),
            self.vault.x,
            Field::from(self.vault.is_odd as u64),
            self.root,
            self.nullifier,
            self.next_nullifier,
            self.amount.into(),
            self.size.into(),
            self.destination.x,
            Field::from(self.destination.is_odd as u64),
            self.valid_until.into(),
            self.request_time.into(),
        ]
    }
}
