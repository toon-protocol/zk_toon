//! Pure zk-note primitives. No I/O, no clock.

use mina_curves::pasta::Fp;
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    pasta::{fp_kimchi, FULL_ROUNDS},
    poseidon::{ArithmeticSponge, Sponge},
};

/// The field Poseidon works over: the Pallas base field.
pub type Field = Fp;

/// Kimchi Poseidon over the Pallas base field, the same function as o1js `Poseidon.hash`.
pub fn poseidon_hash(input: &[Field]) -> Field {
    let mut sponge = ArithmeticSponge::<Field, PlonkSpongeConstantsKimchi, FULL_ROUNDS>::new(
        fp_kimchi::static_params(),
    );
    sponge.absorb(input);
    sponge.squeeze()
}
