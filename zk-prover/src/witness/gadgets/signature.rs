//! Mirrors o1js `lib/provable/crypto/signature.js`: `PublicKey.toGroup` and `Signature.verify`.

use mina_curves::pasta::Fp;

use super::comparison::is_odd_and_high;
use super::native_curve::{group_add, scale_field, scale_shifted, Point, ShiftedScalar};
use super::poseidon;
use crate::witness::{Bool, Cs, Field};

/// A public key: the x coordinate and the parity of y.
#[derive(Clone, Debug)]
pub struct PublicKey {
    pub x: Field,
    pub is_odd: Bool,
}

/// A Schnorr signature `(r, s)`, with `s` in the shifted representation.
#[derive(Clone, Debug)]
pub struct Signature {
    pub r: Field,
    pub s: ShiftedScalar,
}

/// `PublicKey.toGroup`: the curve point, with y recovered from the curve equation.
pub fn public_key_to_group(cs: &mut Cs, pk: &PublicKey) -> Point {
    // compute y from the elliptic curve equation y^2 = x^3 + 5
    let x = &pk.x;
    let x2 = x.square(cs);
    let x3 = x2.mul(cs, x);
    let y = x3.add_const(Fp::from(5u64)).sqrt(cs);
    // negate y if its parity is different from the public key's
    let (y_is_odd, _) = is_odd_and_high(cs, &y);
    let same_parity = y_is_odd.equals(cs, &pk.is_odd).to_field();
    // (2*sameParity - 1) == 1 if same parity, -1 if different parity
    let sign = same_parity.mul_const(Fp::from(2u64)).sub_const(Fp::from(1u64));
    let y = y.mul(cs, &sign);
    Point { x: x.clone(), y }
}

/// `Signature.verify`, with the Poseidon state after the signature's prefix.
pub fn verify(
    cs: &mut Cs,
    sig: &Signature,
    public_key: &PublicKey,
    msg: &[Field],
    prefix_state: [Fp; 3],
    generator: &Point,
) -> Bool {
    let point = public_key_to_group(cs, public_key);
    // we chose an arbitrary prefix for the signature
    let mut input: Vec<Field> = msg.to_vec();
    input.extend([point.x.clone(), point.y.clone(), sig.r.clone()]);
    let state = prefix_state.map(Field::constant);
    let h = poseidon::update(cs, state, &input)[0].clone();
    let scaled = scale_field(cs, &point, &h).neg();
    let g_s = scale_shifted(cs, generator, &sig.s, 254);
    let r = group_add(cs, &scaled, &g_s);
    let x_equals = r.x.equals(cs, &sig.r);
    let (y_is_odd, _) = is_odd_and_high(cs, &r.y);
    x_equals.and(cs, &y_is_odd.not())
}
