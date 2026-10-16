//! The state message the zk edge signs under the vault key, and its signature.
//!
//! # Message layout
//!
//! Five Pallas base field elements, in this order:
//!
//! ```text
//! [vault.x, vault.isOdd, commitment.x, commitment.y, anchor]
//! ```
//!
//! The vault key is a Mina public key `(x, isOdd)`; `isOdd` is 1 when its y coordinate is odd and 0
//! otherwise, the same convention as the session key in [`crate::RequestContext`].
//!
//! # Signing
//!
//! Mina Schnorr under the **devnet** network ID (domain `CodaSignature`) with the o1js-compatible
//! chunked nonce, for every vault including a mainnet one. o1js 3.1.0 `Signature.create` and
//! `Signature.verify` hard-code that ID, and the vault circuit verifies in-circuit with them, so a
//! state signed under the mainnet ID is refused there.
use ark_ec::AffineRepr;
use mina_hasher::{Hashable, ROInput};
use mina_signer::{CompressedPubKey, Keypair, NetworkId, NonceMode, PubKey, Signature, Signer};

use crate::balance::Commitment;
use crate::Field;

/// What the zk edge signs under the vault key: the note's balance commitment and the anchor of its current state.
#[derive(Clone, Copy, Debug)]
pub struct StateMessage {
    pub vault_x: Field,
    pub vault_is_odd: bool,
    pub commitment: Commitment,
    pub anchor: Field,
}

impl StateMessage {
    pub fn new(vault: &CompressedPubKey, commitment: Commitment, anchor: Field) -> Self {
        Self { vault_x: vault.x, vault_is_odd: vault.is_odd, commitment, anchor }
    }

    /// The five field elements that are signed.
    pub fn to_fields(&self) -> Vec<Field> {
        let (cx, cy) = self.commitment.xy().expect("a commitment is never the point at infinity");
        vec![self.vault_x, Field::from(self.vault_is_odd as u64), cx, cy, self.anchor]
    }
}

#[derive(Clone)]
struct Fields(Vec<Field>);

impl Hashable for Fields {
    type D = NetworkId;

    fn to_roinput(&self) -> ROInput {
        self.0.iter().fold(ROInput::new(), |roi, f| roi.append_field(*f))
    }

    fn domain_string(network_id: NetworkId) -> Option<String> {
        Some(network_id.into_domain_string())
    }
}

/// Sign a state under the devnet network ID.
pub fn sign_state(keypair: &Keypair, msg: &StateMessage) -> Signature {
    mina_signer::create_kimchi::<Fields>(NetworkId::TESTNET).sign(
        keypair,
        &Fields(msg.to_fields()),
        NonceMode::Chunked,
    )
}

/// Verify a state signature under the devnet network ID. `vault` must be the key the message names.
pub fn verify_state(sig: &Signature, vault: &PubKey, msg: &StateMessage) -> bool {
    verify_state_on(NetworkId::TESTNET, sig, vault, msg)
}

/// Verify under an explicit network ID. Only tests and diagnostics need this: a vault's states
/// are always devnet-signed.
pub fn verify_state_on(network: NetworkId, sig: &Signature, vault: &PubKey, msg: &StateMessage) -> bool {
    let named = vault.into_compressed();
    if (named.x, named.is_odd) != (msg.vault_x, msg.vault_is_odd) {
        return false;
    }
    mina_signer::create_kimchi::<Fields>(network).verify(sig, vault, &Fields(msg.to_fields()))
}
