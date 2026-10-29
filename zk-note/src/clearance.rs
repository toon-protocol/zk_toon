//! The clearance the zk edge signs under the state key: one state's nullifier may close to one destination.
//!
//! # Message layout
//!
//! Six Pallas base field elements, in this order:
//!
//! ```text
//! [clearanceTag, stateKey.x, stateKey.isOdd, nullifier, destination.x, destination.isOdd]
//! ```
//!
//! `clearanceTag` is the field of [`crate::tags::CLEARANCE`], so a clearance never passes as a state
//! message. Keys are Mina public keys `(x, isOdd)`, `isOdd` hashed as 0 or 1. The clearance does not
//! carry the amount. It is signed like the state message: Mina Schnorr under the **devnet** network
//! ID with the o1js-compatible chunked nonce.
use mina_signer::{CompressedPubKey, Keypair, NetworkId, NonceMode, PubKey, Signature, Signer};

use crate::state::Fields;
use crate::{tag_to_field, tags, Field};

#[derive(Clone, Copy, Debug)]
pub struct ClearanceMessage {
    pub state_key_x: Field,
    pub state_key_is_odd: bool,
    pub nullifier: Field,
    pub destination_x: Field,
    pub destination_is_odd: bool,
}

impl ClearanceMessage {
    pub fn new(state_key: &CompressedPubKey, nullifier: Field, destination: &CompressedPubKey) -> Self {
        Self {
            state_key_x: state_key.x,
            state_key_is_odd: state_key.is_odd,
            nullifier,
            destination_x: destination.x,
            destination_is_odd: destination.is_odd,
        }
    }

    /// The six field elements that are signed.
    pub fn to_fields(&self) -> Vec<Field> {
        vec![
            tag_to_field(tags::CLEARANCE),
            self.state_key_x,
            Field::from(self.state_key_is_odd as u64),
            self.nullifier,
            self.destination_x,
            Field::from(self.destination_is_odd as u64),
        ]
    }
}

/// Sign a clearance under the devnet network ID.
pub fn sign_clearance(keypair: &Keypair, msg: &ClearanceMessage) -> Signature {
    mina_signer::create_kimchi::<Fields>(NetworkId::TESTNET).sign(
        keypair,
        &Fields(msg.to_fields()),
        NonceMode::Chunked,
    )
}

/// Verify a clearance under the devnet network ID. `state_key` must be the key the message names.
pub fn verify_clearance(sig: &Signature, state_key: &PubKey, msg: &ClearanceMessage) -> bool {
    let named = state_key.into_compressed();
    if (named.x, named.is_odd) != (msg.state_key_x, msg.state_key_is_odd) {
        return false;
    }
    mina_signer::create_kimchi::<Fields>(NetworkId::TESTNET).verify(sig, state_key, &Fields(msg.to_fields()))
}
