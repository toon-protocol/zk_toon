//! The balance commitment: a Pedersen commitment `B·G + r·H` over Pallas, and the two ways a
//! holder moves it without opening it.
//!
//! # Generators
//!
//! `G` and `H` are derived, not chosen, so nobody knows a discrete-log relation between them or
//! to the curve generator. The derivation is try-and-increment over Poseidon, computed outside
//! the circuit (o1js carries the results as constants):
//!
//! ```text
//! for counter = 0, 1, 2, ...
//!     x = Poseidon([tag_field(GENERATOR_SEED), index, counter])
//!     if x³ + 5 is a square in Fp:
//!         y = the square root with even y (the root whose canonical integer is even)
//!         return (x, y)
//! ```
//!
//! `index` is 0 for `G` and 1 for `H`. The seed tag is [`GENERATOR_SEED`], read as a little-endian
//! field element like every other domain tag. Pallas has cofactor 1, so every curve point is in the
//! prime-order group. The shared vector file pins the resulting points and counters.
use std::sync::OnceLock;

use ark_ec::CurveGroup;
use ark_ff::{BigInteger, Field as _, PrimeField};
use mina_curves::pasta::{Fq, Pallas};

use crate::{hash_with_tag, Field};

/// Domain tag seeding the generator derivation. It is not one of [`crate::tags`]: those tag
/// hashes of note values, and adding it there would change the domain-separation vectors.
pub const GENERATOR_SEED: &str = "toon.zk.generator.v1";

/// A balance commitment: a Pallas affine point.
pub type Commitment = Pallas;

/// A scalar, used for balances, deltas and blinding factors.
pub type Scalar = Fq;

/// Derive the generator with this index, and the counter at which the search stopped.
pub fn derive_generator(index: u64) -> (Pallas, u64) {
    let mut counter = 0u64;
    loop {
        let x = hash_with_tag(GENERATOR_SEED, &[Field::from(index), Field::from(counter)]);
        let rhs = x.square() * x + Field::from(5u64);
        if let Some(y) = rhs.sqrt() {
            let y = if y.into_bigint().is_even() { y } else { -y };
            let point = Pallas::new_unchecked(x, y);
            assert!(point.is_on_curve());
            return (point, counter);
        }
        counter += 1;
    }
}

/// The generator for balances.
pub fn generator_g() -> Pallas {
    static G: OnceLock<Pallas> = OnceLock::new();
    *G.get_or_init(|| derive_generator(0).0)
}

/// The generator for blinding factors.
pub fn generator_h() -> Pallas {
    static H: OnceLock<Pallas> = OnceLock::new();
    *H.get_or_init(|| derive_generator(1).0)
}

/// `commit(B, r) = B·G + r·H`.
pub fn commit(balance: Scalar, blinding: Scalar) -> Commitment {
    (generator_g() * balance + generator_h() * blinding).into_affine()
}

/// `rerandomise(C, r') = C + r'·H`: the same balance, blinding `r + r'`.
pub fn rerandomise(c: Commitment, blinding: Scalar) -> Commitment {
    (c + generator_h() * blinding).into_affine()
}

/// `charge(C, Δ) = C − Δ·G`: `commit(B − Δ, r)`, without opening `C`.
pub fn charge(c: Commitment, delta: Scalar) -> Commitment {
    (c - generator_g() * delta).into_affine()
}
