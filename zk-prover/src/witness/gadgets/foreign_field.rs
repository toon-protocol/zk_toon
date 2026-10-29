//! Mirrors the parts of o1js `lib/provable/gadgets/foreign-field.js` that `land` uses: the chain
//! of one foreign-field addition, with its range check.

use ark_ff::{BigInteger, PrimeField, Zero};
use mina_curves::pasta::Fp;
use num_bigint::{BigInt, Sign};

use crate::witness::{gadgets::range_check::multi_range_check, Cs, Field};

/// A foreign field element: three 88-bit limbs.
pub type Field3 = [Field; 3];

/// Bits per limb.
pub const L: usize = 88;

pub(crate) fn fp_to_big(x: &Fp) -> BigInt {
    BigInt::from_bytes_le(Sign::Plus, &x.into_bigint().to_bytes_le())
}

/// A bigint (possibly negative) as a field element, reduced mod p.
pub(crate) fn big_to_fp(x: &BigInt) -> Fp {
    let (sign, bytes) = x.to_bytes_le();
    let v = Fp::from_le_bytes_mod_order(&bytes);
    if sign == Sign::Minus {
        -v
    } else {
        v
    }
}

fn l_mask() -> BigInt {
    (BigInt::from(1) << L) - 1
}

/// `split`: three 88-bit limbs.
pub fn split(x: &BigInt) -> [BigInt; 3] {
    let m = l_mask();
    [x & &m, (x >> L) & &m, (x >> (2 * L)) & &m]
}

/// `combine`.
pub fn combine([x0, x1, x2]: &[BigInt; 3]) -> BigInt {
    x0 + (x1 << L) + (x2 << (2 * L))
}

/// `Field3.from(bigint)`.
pub fn field3_constant(x: &BigInt) -> Field3 {
    split(x).map(|l| Field::constant(big_to_fp(&l)))
}

fn to_bigint3(x: &Field3) -> [BigInt; 3] {
    [fp_to_big(&x[0].value()), fp_to_big(&x[1].value()), fp_to_big(&x[2].value())]
}

/// `singleAdd`: `x + sign * y` modulo `f`, as a `foreignFieldAdd` row. Returns the result limbs
/// (the row after holds them), which must be chained with a second row.
fn single_add(cs: &mut Cs, x: &Field3, y: &Field3, sign: i32, f: &BigInt) -> Field3 {
    let f_ = split(f);
    let x_ = to_bigint3(x);
    let y_ = to_bigint3(y);
    let sign = BigInt::from(sign);
    // figure out if there's overflow
    let r = combine(&x_) + &sign * combine(&y_);
    let mut overflow = BigInt::from(0);
    if sign == BigInt::from(1) && &r >= f {
        overflow = BigInt::from(1);
    }
    if sign == BigInt::from(-1) && r < BigInt::from(0) {
        overflow = BigInt::from(-1);
    }
    if f.is_zero_big() {
        overflow = BigInt::from(0);
    }
    // do the add with carry; this "just works" with negative r01
    let combine2 = |[a, b, _]: &[BigInt; 3]| a + (b << L);
    let r01 = combine2(&x_) + &sign * combine2(&y_) - &overflow * combine2(&f_);
    let carry = &r01 >> (2 * L);
    let r01 = r01 & ((BigInt::from(1) << (2 * L)) - 1);
    let m = l_mask();
    let r0 = &r01 & &m;
    let r1 = (&r01 >> L) & &m;
    let r2 = &x_[2] + &sign * &y_[2] - &overflow * &f_[2] + &carry;
    let [r0, r1, r2, _overflow, _carry] =
        cs.exists([r0, r1, r2, overflow, carry].map(|v| big_to_fp(&v)));
    [r0, r1, r2]
}

trait IsZeroBig {
    fn is_zero_big(&self) -> bool;
}

impl IsZeroBig for BigInt {
    fn is_zero_big(&self) -> bool {
        self.sign() == Sign::NoSign
    }
}

/// `sum([x, y], [sign], f)`: `x + sign * y` modulo `f`, with a range check on the result.
pub fn sum(cs: &mut Cs, x: &Field3, y: &Field3, sign: i32, f: &BigInt) -> Field3 {
    assert!(
        !(x.iter().all(Field::is_constant) && y.iter().all(Field::is_constant)),
        "foreign-field sum of constants is not mirrored"
    );
    let x = [x[0].to_var(cs), x[1].to_var(cs), x[2].to_var(cs)];
    let y = [y[0].to_var(cs), y[1].to_var(cs), y[2].to_var(cs)];
    let result = single_add(cs, &x, &y, sign, f);
    // final zero row to hold the result: `Gates.zero` pads its three cells to 15 with variables
    for _ in 0..12 {
        cs.empty_cell();
    }
    indirect_multi_range_check(cs, &result);
    result
}

/// `ForeignField.negate(x, f)`: `0 - x` modulo `f`.
pub fn negate(cs: &mut Cs, x: &Field3, f: &BigInt) -> Field3 {
    let zero = field3_constant(&BigInt::from(0));
    sum(cs, &zero, x, -1, f)
}

/// `indirectMultiRangeChange`: range check a truncated copy of `x`, then assert it equals `x`.
fn indirect_multi_range_check(cs: &mut Cs, x: &Field3) {
    let m = l_mask();
    let [t0, t1, t2] = to_bigint3(x).map(|v| big_to_fp(&(v & &m)));
    let x_trunc = cs.exists([t0, t1, t2]);
    multi_range_check(cs, &x_trunc);
    for i in 0..3 {
        x[i].assert_equals(cs, &x_trunc[i]);
    }
}
