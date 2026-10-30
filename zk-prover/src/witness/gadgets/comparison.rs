//! Mirrors o1js `lib/provable/gadgets/comparison.js`.

use ark_ff::{Field as _, One, Zero};
use mina_curves::pasta::Fp;
use num_bigint::BigInt;

use super::foreign_field::{big_to_fp, field3_constant, fp_to_big, negate, split, Field3, L};
use super::range_check::{multi_range_check, range_check_n_64};
use crate::witness::{bit_slice, Bool, Cs, Field};

/// The modulus of Pallas's base field, as a bigint.
pub fn fp_modulus() -> BigInt {
    fp_to_big(&-Fp::one()) + 1
}

/// `fieldToField3`: split a field element into three range-checked limbs.
pub fn field_to_field3(cs: &mut Cs, x: &Field) -> Field3 {
    if x.is_constant() {
        return field3_constant(&fp_to_big(&x.value()));
    }
    let [a, b, c] = split(&fp_to_big(&x.value())).map(|l| big_to_fp(&l));
    let x_big = cs.exists([a, b, c]);
    multi_range_check(cs, &x_big);
    // prove that x == x0 + x1*2^l + x2*2^2l
    let x_ = x_big[0]
        .add(&x_big[1].mul_const(big_to_fp(&(BigInt::from(1) << L))))
        .add(&x_big[2].mul_const(big_to_fp(&(BigInt::from(1) << (2 * L)))));
    x_.assert_equals(cs, x);
    x_big
}

/// `assertLessThanFull(x, y)` for a constant `y`: `x < y`, for any `x` in `[0, p)`.
pub fn assert_less_than_full(cs: &mut Cs, x: &Field, y: &Field) {
    assert!(y.is_constant(), "assertLessThanFull is mirrored for a constant y only");
    let x_big = field_to_field3(cs, x);
    // x < y as bigints: `(y - 1) - x`, range checked
    let y_big = fp_to_big(&y.value());
    assert!(y_big.sign() == num_bigint::Sign::Plus, "assertLessThan: y <= 0");
    negate(cs, &x_big, &(y_big - 1));
    // y < p holds for a constant y
}

/// `Field.assertLessThan` for a constant bound.
pub fn field_assert_less_than(cs: &mut Cs, x: &Field, y: Fp) {
    if x.is_constant() {
        assert!(x.value() < y, "Field.assertLessThan()");
        return;
    }
    assert_less_than_full(cs, x, &Field::constant(y));
}

/// `isOddAndHigh`: split `x` into a low bit and a 254-bit high part.
pub fn is_odd_and_high(cs: &mut Cs, x: &Field) -> (Bool, Field) {
    if x.is_constant() {
        let x0 = x.value();
        let odd = bit_slice(&x0, 0, 1).is_one();
        let high = fp_to_big(&x0) >> 1u32;
        return (Bool::constant(odd), Field::constant(big_to_fp(&high)));
    }
    // witness a bit b such that x = b + 2z for some z <= (p-1)/2
    let x0 = x.value();
    let [b, z] = cs.exists([bit_slice(&x0, 0, 1), big_to_fp(&(fp_to_big(&x0) >> 1u32))]);
    let is_odd = b.assert_bool(cs);
    // z < (p + 1) / 2
    let half = big_to_fp(&((fp_modulus() + 1) >> 1u32));
    field_assert_less_than(cs, &z, half);
    // x == b + 2z
    b.add(&z.mul_const(Fp::from(2u64))).assert_equals(cs, x);
    // prevent overflow case when x = 0: we witness x' such that b == x * x'
    let x_ = if b.value().is_zero() { Fp::zero() } else { x0.inverse().unwrap_or_else(Fp::zero) };
    let x_ = cs.exists_one(x_);
    x.mul(cs, &x_).assert_equals(cs, &b);
    (is_odd, z)
}

/// `assertLessThanGeneric(x, y, rangeCheck)` with the 64-bit range check `UInt64` passes:
/// `x < y` for `x, y` in `[0, 2^64)`.
pub fn assert_less_than_generic_u64(cs: &mut Cs, x: &Field, y: &Field) {
    let diff = y.sub_const(Fp::one()).sub(x).seal(cs);
    range_check_n_64(cs, &diff);
}
