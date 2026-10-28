//! The clearance: the zk edge's signature, under the state key, agreeing that one state's nullifier
//! may close to one destination. Mirrors `o1js/src/clearance.ts`.
//!
//! # Message layout
//!
//! Six Pallas base field elements, in this order:
//!
//! ```text
//! [clearanceTag, stateKey.x, stateKey.isOdd, nullifier, destination.x, destination.isOdd]
//! ```
//!
//! `clearanceTag` is [`tags::CLEARANCE`] read as a field element ([`tag_to_field`]), so a clearance
//! never passes as a state message. Keys are Mina public keys `(x, isOdd)`, `isOdd` 1 or 0. The
//! clearance does not carry the amount: the withdrawal proof binds it.
//!
//! # Signing
//!
//! The state message's rule ([`crate::state`]): Mina Schnorr under the **devnet** network ID with
//! the chunked nonce, which o1js 3.1.0 and the vault circuit use.
use mina_signer::{CompressedPubKey, Keypair, NetworkId, NonceMode, PubKey, Signature, Signer};

use crate::state::Fields;
use crate::{tag_to_field, tags, Field};

/// What the zk edge signs under the state key to clear a mutual close.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClearanceMessage {
    pub state_key: CompressedPubKey,
    pub nullifier: Field,
    pub destination: CompressedPubKey,
}

impl ClearanceMessage {
    pub fn new(state_key: &CompressedPubKey, nullifier: Field, destination: &CompressedPubKey) -> Self {
        Self { state_key: state_key.clone(), nullifier, destination: destination.clone() }
    }

    /// The six field elements that are signed.
    pub fn to_fields(&self) -> Vec<Field> {
        vec![
            tag_to_field(tags::CLEARANCE),
            self.state_key.x,
            Field::from(self.state_key.is_odd as u64),
            self.nullifier,
            self.destination.x,
            Field::from(self.destination.is_odd as u64),
        ]
    }
}

/// Sign a clearance under the devnet network ID.
pub fn sign_clearance(keypair: &Keypair, msg: &ClearanceMessage) -> Signature {
    mina_signer::create_kimchi::<Fields>(NetworkId::TESTNET).sign(keypair, &Fields(msg.to_fields()), NonceMode::Chunked)
}

/// Verify a clearance under the devnet network ID. `state_key` must be the key the message names.
pub fn verify_clearance(sig: &Signature, state_key: &PubKey, msg: &ClearanceMessage) -> bool {
    verify_clearance_on(NetworkId::TESTNET, sig, state_key, msg)
}

/// Verify under an explicit network ID. Only tests and diagnostics need this: clearances are always
/// devnet-signed.
pub fn verify_clearance_on(network: NetworkId, sig: &Signature, state_key: &PubKey, msg: &ClearanceMessage) -> bool {
    if state_key.into_compressed() != msg.state_key {
        return false;
    }
    mina_signer::create_kimchi::<Fields>(network).verify(sig, state_key, &Fields(msg.to_fields()))
}
