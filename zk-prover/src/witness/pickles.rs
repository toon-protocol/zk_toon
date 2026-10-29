//! The Pickles step circuit around a zkApp method: what `step_main` and `Pickles.compile` add
//! before and after the method's own variables.
//!
//! The pieces that mina-rust's fork already mirrors (`dummy_constraints`, the verification key
//! `exists`, the scalar-challenge and `scale_fast` gadgets) are called from the fork. Those write to
//! the fork's `Witness`, whose values we read back through its `Debug` output: `Witness::aux` is
//! private, and the fork changes only in visibility.

use ark_ff::{AdditiveGroup as _, Field as _, One};
use ledger::proofs::{
    field::{FieldWitness, GroupAffine},
    public_input::plonk_checks::ShiftingValue,
    transaction::{endos, field_to_bits, make_group, plonk_curve_ops, InnerCurve},
    witness::Witness,
};
use mina_curves::pasta::Fp;

use super::Cs;

/// Run `f` on a fresh fork `Witness` and return the values it created.
pub(crate) fn from_fork<R>(f: impl FnOnce(&mut Witness<Fp>) -> R) -> (R, Vec<Fp>) {
    let mut w = Witness::<Fp>::empty();
    let r = f(&mut w);
    (r, aux_of(&w))
}

fn aux_of(w: &Witness<Fp>) -> Vec<Fp> {
    use std::str::FromStr;
    let s = format!("{w:?}");
    let a = s.find("aux: [").expect("Witness's Debug output has an aux field") + "aux: [".len();
    let b = a + s[a..].find(']').expect("aux list ends");
    s[a..b]
        .split(", ")
        .filter(|x| !x.is_empty())
        .map(|x| Fp::from_str(x).expect("decimal field element"))
        .collect()
}

/// The variables a step proof starts with: the app state (`ZkappPublicInput`, the account update
/// hash and the calls hash), then Pickles' `dummy_constraints`.
///
/// o1js's Mina has one `scale_fast` in `dummy_constraints` where the fork has two; the gates in
/// the committed circuit (`cs003`) show one, so the prelude is built from the fork's parts.
pub fn prelude(cs: &mut Cs, account_update_hash: Fp, calls: Fp) {
    cs.exists_one(account_update_hash);
    cs.exists_one(calls);
    let ((), aux) = from_fork(|w| {
        let x: Fp = w.exists(Fp::from(3u64));
        let g: InnerCurve<Fp> = w.exists(InnerCurve::<Fp>::one());
        let _ = w.to_field_checked_prime::<16>(x);
        let _ = plonk_curve_ops::scale_fast::<Fp, Fp, 5>(
            g.to_affine(),
            <Fp as FieldWitness>::Shifting::of_raw(x),
            w,
        );
        endo_4(w, g.to_affine(), x);
    });
    cs.extend(aux);
}

/// `Scalar_challenge.endo ~num_bits:4` of Mina's `pickles/scalar_challenge.ml` at the commit o1js
/// 3.1.0 builds on (`228c409a`). The fork's `endo` is the version before that commit added `inv`,
/// the inverse of `(xp - xr) * (xr - xs)`, to each round.
fn endo_4(w: &mut Witness<Fp>, t: GroupAffine<Fp>, scalar: Fp) {
    const NBITS: usize = 4;
    let mut bits_msb = field_to_bits::<Fp, NBITS>(scalar);
    bits_msb.reverse();
    let GroupAffine::<Fp> { x: xt, y: yt, .. } = t;
    let (endo_base, _) = endos::<Fp>();
    // `seal (Field.scale xt Endo.base)`, then `t + (that, yt)` and `p + p`
    let tmp = w.exists(xt * endo_base);
    let p = w.add_fast(t, make_group::<Fp>(tmp, yt));
    let mut acc = w.add_fast(p, p);
    let mut n_acc = Fp::from(0u64);
    for i in 0..NBITS / 4 {
        let n_acc_prev = n_acc;
        let b = |j: usize| Fp::from(bits_msb[i * 4 + j]);
        let (b1, b2, b3, b4) = (b(0), b(1), b(2), b(3));
        let (b1, b2, b3, b4) = (w.exists(b1), w.exists(b2), w.exists(b3), w.exists(b4));
        let GroupAffine::<Fp> { x: xp, y: yp, .. } = acc;
        let xq1 = w.exists((Fp::one() + ((endo_base - Fp::one()) * b1)) * xt);
        let yq1 = w.exists((b2.double() - Fp::one()) * yt);
        let s1 = w.exists((yq1 - yp) / (xq1 - xp));
        let s1_squared = w.exists(s1.square());
        let s2 = w.exists((yp.double() / (xp.double() + xq1 - s1_squared)) - s1);
        let xr = w.exists(xq1 + s2.square() - s1_squared);
        let yr = w.exists(((xp - xr) * s2) - yp);
        let xq2 = w.exists((Fp::one() + ((endo_base - Fp::one()) * b3)) * xt);
        let yq2 = w.exists((b4.double() - Fp::one()) * yt);
        let s3 = w.exists((yq2 - yr) / (xq2 - xr));
        let s3_squared = w.exists(s3.square());
        let s4 = w.exists((yr.double() / (xr.double() + xq2 - s3_squared)) - s3);
        let xs = w.exists(xq2 + s4.square() - s3_squared);
        let ys = w.exists(((xr - xs) * s4) - yr);
        w.exists(((xp - xr) * (xr - xs)).inverse().expect("endo: inv"));
        acc = make_group::<Fp>(xs, ys);
        n_acc = w.exists((((n_acc_prev.double() + b1).double() + b2).double() + b3).double() + b4);
    }
}
