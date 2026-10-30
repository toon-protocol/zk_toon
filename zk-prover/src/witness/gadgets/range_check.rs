//! Mirrors o1js `lib/provable/gadgets/range-check.js`.

use ark_ff::Zero;
use mina_curves::pasta::Fp;

use crate::witness::{bit_slice, pickles::from_fork, Cs, Field};

/// `rangeCheck0Helper`: the 2-bit crumbs and 12-bit limbs of `x`. Returns the two highest limbs,
/// `[x64, x76]`, which the `rangeCheck1` gate that follows constrains.
pub fn range_check0_helper(cs: &mut Cs, x: &Field) -> (Field, Field) {
    let v = x.value();
    let slice = |start| bit_slice(&v, start, 2);
    cs.exists([slice(0), slice(2), slice(4), slice(6), slice(8), slice(10), slice(12), slice(14)]);
    let limb = |start| bit_slice(&v, start, 12);
    let [_x16, _x28, _x40, _x52, x64, x76] =
        cs.exists([limb(16), limb(28), limb(40), limb(52), limb(64), limb(76)]);
    (x64, x76)
}

/// `rangeCheck1Helper`: the limbs of `z` for the current and the next row. (The gate also takes
/// the highest limbs `rangeCheck0Helper` returned, which are existing variables.)
pub fn range_check1_helper(cs: &mut Cs, z: &Field) {
    let zz = z.value();
    let s = |start, len| bit_slice(&zz, start, len);
    cs.exists([
        s(22, 2),
        s(24, 2),
        s(26, 2),
        s(28, 2),
        s(30, 2),
        s(32, 2),
        s(34, 2),
        s(36, 2),
        s(38, 12),
        s(50, 12),
        s(62, 12),
        s(74, 12),
        s(86, 2),
    ]);
    cs.exists([
        s(0, 2),
        s(2, 2),
        s(4, 2),
        s(6, 2),
        s(8, 2),
        s(10, 2),
        s(12, 2),
        s(14, 2),
        s(16, 2),
        s(18, 2),
        s(20, 2),
    ]);
}

/// `multiRangeCheck`: `x, y, z` are all in `[0, 2^88)`.
pub fn multi_range_check(cs: &mut Cs, [x, y, z]: &[Field; 3]) {
    if x.is_constant() && y.is_constant() && z.is_constant() {
        return;
    }
    // ensure we are using pure variables
    let x = x.to_var(cs);
    let y = y.to_var(cs);
    let z = z.to_var(cs);
    let _zero = Field::constant(Fp::zero()).to_var(cs);
    range_check0_helper(cs, &x);
    range_check0_helper(cs, &y);
    range_check1_helper(cs, &z);
}

/// `rangeCheckN(64, x)`, which `UInt64.check` is: `x` fits in 64 bits.
///
/// o1js truncates `x` to 64 bits with Pickles' `to_field_checked'` (`Snarky.field.truncateToBits16`),
/// which the fork mirrors, and asserts the truncation equals `x`.
pub fn range_check_n_64(cs: &mut Cs, x: &Field) {
    if x.is_constant() {
        assert!(x.value() < Fp::from(1u128 << 64), "rangeCheckN: expected field to fit in 64 bits");
        return;
    }
    let actual = truncate_to_bits16(cs, 4, x);
    actual.assert_equals(cs, x);
}

/// `Snarky.field.truncateToBits16(length_div_16, x)`: `x` truncated to its lowest
/// `16 * length_div_16` bits, with the variables of Pickles' `to_field_checked'`
/// (`[...rows, n, a, b]`, the truncation being `n`).
pub fn truncate_to_bits16(cs: &mut Cs, length_div_16: usize, x: &Field) -> Field {
    let start = cs.next_var();
    let ((_a, _b, n), aux) = from_fork(|w| match length_div_16 {
        1 => w.to_field_checked_prime::<16>(x.value()),
        2 => w.to_field_checked_prime::<32>(x.value()),
        3 => w.to_field_checked_prime::<48>(x.value()),
        4 => w.to_field_checked_prime::<64>(x.value()),
        _ => unimplemented!("truncateToBits16 for {length_div_16} limbs"),
    });
    // the truncation `n` is the value created just before `a` and `b`
    let n_index = start + aux.len() - 3;
    cs.extend(aux);
    debug_assert_eq!(cs.var(n_index).value(), n);
    cs.var(n_index)
}
