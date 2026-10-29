//! The fixed encoding of a nullifier at the challenger's ports: the Pallas field element as 32 bytes,
//! little-endian and canonical (below the modulus). It is the encoding of `zk-evidence`'s
//! `field_to_bytes`, so the evidence port and the chain port name a state the same way.
use ark_ff::{BigInteger, PrimeField};
use zk_note::Field;
use zk_toon_challenger::Nullifier;

/// A field element as a nullifier.
pub fn nullifier_of_field(f: Field) -> Nullifier {
    let mut out = [0u8; 32];
    out.copy_from_slice(&f.into_bigint().to_bytes_le());
    out
}

/// The field element a nullifier encodes, or `None` if the bytes are at or above the modulus.
pub fn field_of_nullifier(n: &Nullifier) -> Option<Field> {
    let f = Field::from_le_bytes_mod_order(n);
    (nullifier_of_field(f) == *n).then_some(f)
}
