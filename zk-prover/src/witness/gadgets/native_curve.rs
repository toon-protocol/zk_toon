//! Mirrors o1js `lib/provable/gadgets/native-curve.js` and the parts of `group.js` and
//! `provable.js` (`Provable.if`, `Provable.switch`) that `land`'s signature check uses.

use ark_ff::{Field as _, PrimeField, Zero};
use ledger::proofs::{field::FieldWitness, public_input::plonk_checks::ShiftingValue};
use mina_curves::pasta::{Fp, Fq};
use num_bigint::BigInt;

use super::comparison::is_odd_and_high;
use super::foreign_field::{big_to_fp, fp_to_big};
use crate::witness::{pickles::from_fork, Bool, Cs, Field};

/// A curve point: `Group` in o1js, `{ x, y }` in the native-curve gadgets.
#[derive(Clone, Debug)]
pub struct Point {
    pub x: Field,
    pub y: Field,
}

impl Point {
    pub fn constant(x: Fp, y: Fp) -> Self {
        Self { x: Field::constant(x), y: Field::constant(y) }
    }

    /// `Group.zero`.
    pub fn zero() -> Self {
        Self::constant(Fp::zero(), Fp::zero())
    }

    /// `Group.neg`.
    pub fn neg(&self) -> Point {
        Point { x: self.x.clone(), y: self.y.neg() }
    }

    fn fields(&self) -> [Field; 2] {
        [self.x.clone(), self.y.clone()]
    }
}

/// A scalar in the shifted representation: a low bit and a 254-bit high part.
#[derive(Clone, Debug)]
pub struct ShiftedScalar {
    pub low_bit: Bool,
    pub high254: Field,
}

/// `ifField`: `b ? x : y` as `b*(x - y) + y`, sealed.
pub fn if_field(cs: &mut Cs, b: &Field, x: &Field, y: &Field) -> Field {
    b.mul(cs, &x.sub(y)).add(y).seal(cs)
}

/// `Provable.if(condition, Point, x, y)`.
pub fn if_point(cs: &mut Cs, condition: &Bool, x: &Point, y: &Point) -> Point {
    let b = condition.to_field();
    if b.is_constant() {
        return if condition.value() { x.clone() } else { y.clone() };
    }
    let [xx, xy] = x.fields();
    let [yx, yy] = y.fields();
    Point { x: if_field(cs, &b, &xx, &yx), y: if_field(cs, &b, &xy, &yy) }
}

/// `Provable.switch(mask, Group, values)` with `allowNonExclusive`.
pub fn switch_point(cs: &mut Cs, mask: &[Bool], values: &[Point]) -> Point {
    let mut fields = [Field::zero(), Field::zero()];
    for (value, mask) in values.iter().zip(mask) {
        let mask = mask.to_field();
        for (j, f) in value.fields().iter().enumerate() {
            let maybe = f.mul(cs, &mask);
            fields[j] = fields[j].add(&maybe);
        }
    }
    let [x, y] = fields;
    Point { x, y }
}

/// `add` of `native-curve.js`: complete addition with the `EC_add` gate. Returns the sum and
/// whether it is the point at infinity.
pub fn add(cs: &mut Cs, g: &Point, h: &Point) -> (Point, Bool) {
    let (x1, y1, x2, y2) = (g.x.value(), g.y.value(), h.x.value(), h.y.value());
    let same_x = x1 == x2;
    let inf = same_x && y1 != y2;
    let inf_z = if same_x { (y2 - y1).inverse().unwrap_or_else(Fp::zero) } else { Fp::zero() };
    let x21_inv = (x2 - x1).inverse().unwrap_or_else(Fp::zero);
    let slope_double =
        (Fp::from(3u64) * x1.square()) * (Fp::from(2u64) * y1).inverse().unwrap_or_else(Fp::zero);
    let slope_add = (y2 - y1) * x21_inv;
    let s = if same_x { slope_double } else { slope_add };
    let x3 = s.square() - x1 - x2;
    let y3 = s * (x1 - x3) - y1;
    let [_same_x, inf, _inf_z, _x21_inv, _s, x3, y3] = cs.exists([
        Fp::from(same_x as u64),
        Fp::from(inf as u64),
        inf_z,
        x21_inv,
        s,
        x3,
        y3,
    ]);
    // the gate's arguments are sealed, in order
    g.x.seal(cs);
    g.y.seal(cs);
    h.x.seal(cs);
    h.y.seal(cs);
    (Point { x: x3, y: y3 }, Bool(inf))
}

/// `addNonZero`: addition that asserts the result is non-zero.
pub fn add_non_zero(cs: &mut Cs, g: &Point, h: &Point) -> Point {
    let (result, is_infinity) = add(cs, g, h);
    is_infinity.assert_false(cs);
    result
}

/// `Snarky.group.scaleFastUnpack(P, [0, s], 255)`: `(2 * (s >> 1) + 1 + 2^255) * P`, and the bits
/// of `s`. The variables are those of Pickles' `scale_fast_unpack`, which the fork mirrors; `bits`
/// holds the bit variables, least significant first.
fn scale_fast_unpack_255(cs: &mut Cs, p: &Point, s: &Field) -> (Point, Vec<Field>) {
    use ledger::proofs::transaction::{make_group, plonk_curve_ops};
    let start = cs.next_var();
    let base = make_group::<Fp>(p.x.value(), p.y.value());
    let (_, aux) = from_fork(|w| {
        plonk_curve_ops::scale_fast_unpack::<Fp, Fp, 255>(
            base,
            <Fp as FieldWitness>::Shifting::of_raw(s.value()),
            w,
        )
    });
    let n = aux.len();
    cs.extend(aux);
    // the 255 bits come first, most significant first; the result is the last two variables
    let bits = (0..255).map(|i| cs.var(start + 254 - i)).collect();
    let r = Point { x: cs.var(start + n - 2), y: cs.var(start + n - 1) };
    (r, bits)
}

/// `scaleField`: scale a point by a native field element `s`.
pub fn scale_field(cs: &mut Cs, p: &Point, s: &Field) -> Point {
    // compute t = s + (-2^255 mod q) in (1, 254) arithmetic
    let (s_lo, s_hi) = is_odd_and_high(cs, s);
    let shift = fq_neg_2_pow_255();
    let shift_hi = big_to_fp(&(shift >> 1u32));
    let t_lo = s_lo.clone();
    let t_hi = s_hi.add_const(shift_hi).seal(cs);
    // the values for s not supported by `scaleFastUnpack` are 0 and 1, iff sHi = 0
    let is_edge_case = s_hi.equals(cs, &Field::zero());
    let t_hi_safe = if_field(cs, &is_edge_case.to_field(), &Field::zero(), &t_hi);
    // R = (2*(t >> 1) + 1 + 2^255)P, and a 255-bit representation of tHi
    let (r, bits) = scale_fast_unpack_255(cs, p, &t_hi_safe);
    // prove that tHi has only 254 bits set
    bits[254].assert_equals(cs, &Field::zero());
    // R = tLo ? R : R - P = (t + 2^255)P = sP
    let r_minus_p = add_non_zero(cs, &r, &p.neg());
    let r = if_point(cs, &t_lo, &r, &r_minus_p);
    // now handle the two edge cases s=0 and s=1
    let zero_point = Point::zero();
    let edge_case_result = if_point(cs, &s_lo, p, &zero_point);
    if_point(cs, &is_edge_case, &edge_case_result, &r)
}

/// `scaleShifted`: `(t + 2^255) * P` for the shifted scalar `t = tLo + 2 * tHi`.
pub fn scale_shifted(cs: &mut Cs, p: &Point, t: &ShiftedScalar, num_high_bits: usize) -> Point {
    let zero = Field::zero();
    let q = fq_modulus();
    let minus_shift = big_to_fp(&(&q - (BigInt::from(1) << 254u32)));
    let minus_shift_minus_1 = big_to_fp(&(&q - (BigInt::from(1) << 254u32) - 1));
    let equals_minus_shift = t.high254.equals(cs, &Field::constant(minus_shift));
    let equals_minus_shift_minus_1 = t.high254.equals(cs, &Field::constant(minus_shift_minus_1));
    let is_edge_case = equals_minus_shift.or(cs, &equals_minus_shift_minus_1);
    let t_hi_safe = if_field(cs, &is_edge_case.to_field(), &zero, &t.high254);
    let (r, bits) = scale_fast_unpack_255(cs, p, &t_hi_safe);
    // prove that tHi has only `numHighBits` bits set
    for bit in bits.iter().skip(num_high_bits) {
        bit.assert_equals(cs, &zero);
    }
    // handle edge cases: 2*(-2^254) + 1 + 2^255 = 1 and 2*(-2^254 - 1) + 1 + 2^255 = -1, so the
    // result is (x, +-y)
    let sign = equals_minus_shift.to_field().mul_const(Fp::from(2u64)).sub_const(Fp::from(1u64));
    let edge_case_y = p.y.mul(cs, &sign);
    let edge_case_result = Point { x: p.x.clone(), y: edge_case_y };
    let r = if_point(cs, &is_edge_case, &edge_case_result, &r);
    // R = tLo ? R : R - P = (t + 2^255)P, handling a zero R-P result
    let (r_minus_p, is_infinity) = add(cs, &r, &p.neg());
    let r_minus_p = if_point(cs, &is_infinity, &Point::zero(), &r_minus_p);
    if_point(cs, &t.low_bit, &r, &r_minus_p)
}

/// The scalar field's modulus `q`, the order of the Pallas group.
pub(crate) fn fq_modulus() -> BigInt {
    fp_to_big_fq(&-Fq::from(1u64)) + 1
}

fn fp_to_big_fq(x: &Fq) -> BigInt {
    use ark_ff::BigInteger;
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &x.into_bigint().to_bytes_le())
}

/// `Fq.mod(-(1n << 255n))`.
fn fq_neg_2_pow_255() -> BigInt {
    let q = fq_modulus();
    let two255 = BigInt::from(1) << 255u32;
    (&q - (two255 % &q)) % &q
}

#[allow(dead_code)]
fn unused(_: &Fp) -> BigInt {
    fp_to_big(&Fp::zero())
}

/// `Group.isZero`: only the zero element has `x = 0`.
pub fn group_is_zero(cs: &mut Cs, g: &Point) -> Bool {
    g.x.equals(cs, &Field::zero())
}

/// `Group.add` for non-constant operands: `add`, with the cases of a zero operand and of a
/// negation handled by `Provable.switch`.
pub fn group_add(cs: &mut Cs, this: &Point, g: &Point) -> Point {
    let (result, is_infinity) = add(cs, this, g);
    // we check if either operand is zero, because adding zero to g just results in g
    let g_is_zero = group_is_zero(cs, g);
    let this_is_zero = group_is_zero(cs, this);
    let only_this_is_zero = this_is_zero.and(cs, &g_is_zero.not());
    let is_negation = is_infinity;
    let any = g_is_zero.or(cs, &only_this_is_zero).or(cs, &is_negation);
    let is_normal_addition = any.not();
    switch_point(
        cs,
        &[g_is_zero, only_this_is_zero, is_negation, is_normal_addition],
        &[this.clone(), g.clone(), Point::zero(), result],
    )
}
