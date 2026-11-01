//! Endomorphism scalar multiplication in the wrap circuit, and the IPA `bullet_reduce` built on it.
//!
//! Derived from `scalar_challenge::{endo, endo_cvar, endo_inv}` in
//! `crates/ledger/src/proofs/transaction.rs` and `wrap_verifier::bullet_reduce` in `wrap.rs` of
//! `toon-protocol/mina-rust` at rev `6feeb3797fff6dba49fd848cb2d6decd63fee1b4` (itself from
//! `o1-labs/mina-rust` v0.19.0, Apache-2.0). Each round of the endo gate also creates the witness
//! `inv`, as in Mina `228c409a` (the commit o1js v3.1.0 bundles),
//! `src/lib/crypto/pickles/scalar_challenge.ml`; mina-rust predates it. Licensed under Apache-2.0;
//! see `LICENSE-APACHE` and `NOTICE`.

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::BigInteger256;
use ledger::proofs::{
    field::{CircuitVar, FieldWitness, GroupAffine},
    public_input::scalar_challenge::ScalarChallenge,
    transaction::{endos, field_to_bits, make_group, poseidon::Sponge, InnerCurve},
    witness::Witness,
};

use ledger::proofs::wrap::wrap_verifier::lowest_128_bits;

fn bits_msb<F: FieldWitness, const NBITS: usize>(field: F) -> [bool; NBITS] {
    let mut bits = field_to_bits::<F, NBITS>(field);
    bits.reverse();
    bits
}

/// `Scalar_challenge.endo` on a point held in variables.
pub fn endo<F: FieldWitness, F2: FieldWitness, const NBITS: usize>(
    t: GroupAffine<F>,
    scalar: F2,
    w: &mut Witness<F>,
) -> GroupAffine<F> {
    endo_cvar::<F, F2, NBITS>(CircuitVar::Var(t), scalar, w)
}

pub fn endo_cvar<F: FieldWitness, F2: FieldWitness, const NBITS: usize>(
    t: CircuitVar<GroupAffine<F>>,
    scalar: F2,
    w: &mut Witness<F>,
) -> GroupAffine<F> {
    let bits: [bool; NBITS] = bits_msb::<F2, NBITS>(scalar);

    let bits_per_row = 4;
    let rows = NBITS / bits_per_row;

    let GroupAffine::<F> { x: xt, y: yt, .. } = *t.value();
    let (endo_base, _) = endos::<F>();

    let mut acc = {
        // The `exists` call is made by the `seal` call in OCaml
        // Note: it's actually `Cvar.scale`
        let tmp = match t {
            CircuitVar::Var(_) => w.exists(xt * endo_base),
            CircuitVar::Constant(_) => xt * endo_base,
        };
        let p = w.add_fast(*t.value(), make_group::<F>(tmp, yt));
        w.add_fast(p, p)
    };

    let mut n_acc = F::zero();
    for i in 0..rows {
        let n_acc_prev = n_acc;
        let b1 = w.exists(F::from(bits[i * bits_per_row]));
        let b2 = w.exists(F::from(bits[(i * bits_per_row) + 1]));
        let b3 = w.exists(F::from(bits[(i * bits_per_row) + 2]));
        let b4 = w.exists(F::from(bits[(i * bits_per_row) + 3]));

        let GroupAffine::<F> { x: xp, y: yp, .. } = acc;
        let xq1 = w.exists((F::one() + ((endo_base - F::one()) * b1)) * xt);
        let yq1 = w.exists((b2.double() - F::one()) * yt);
        let s1 = w.exists((yq1 - yp) / (xq1 - xp));
        let s1_squared = w.exists(s1.square());
        let s2 = w.exists((yp.double() / (xp.double() + xq1 - s1_squared)) - s1);
        let xr = w.exists(xq1 + s2.square() - s1_squared);
        let yr = w.exists(((xp - xr) * s2) - yp);
        let xq2 = w.exists((F::one() + ((endo_base - F::one()) * b3)) * xt);
        let yq2 = w.exists((b4.double() - F::one()) * yt);
        let s3 = w.exists((yq2 - yr) / (xq2 - xr));
        let s3_squared = w.exists(s3.square());
        let s4 = w.exists((yr.double() / (xr.double() + xq2 - s3_squared)) - s3);
        let xs = w.exists(xq2 + s4.square() - s3_squared);
        let ys = w.exists(((xr - xs) * s4) - yr);
        // The inverse the gate uses to check the round is not degenerate.
        let _inv = w.exists(((xp - xr) * (xr - xs)).inverse().unwrap_or_default());

        acc = make_group::<F>(xs, ys);
        n_acc = w.exists((((n_acc_prev.double() + b1).double() + b2).double() + b3).double() + b4);
    }

    acc
}

/// `Scalar_challenge.endo_inv`
pub fn endo_inv<F: FieldWitness, F2: FieldWitness, const NBITS: usize>(
    t: GroupAffine<F>,
    chal: F2,
    w: &mut Witness<F>,
) -> GroupAffine<F> {
    let (_, e) = endos::<F>();

    let res = w.exists({
        let chal = ScalarChallenge::from(chal).to_field(&e);
        let scalar: <F as FieldWitness>::Scalar = <F as FieldWitness>::Scalar::from(1u64) / chal;
        let scalar: BigInteger256 = scalar.into();
        InnerCurve::<F>::of_affine(GroupAffine::<F>::from(t.mul_bigint(scalar).into_affine()))
    });
    let res = res.to_affine();
    let _ = endo::<F, F2, NBITS>(res, chal, w);
    res
}

/// `Wrap_verifier.bullet_reduce`
pub fn bullet_reduce<F: FieldWitness>(
    sponge: &mut Sponge<F>,
    gammas: &[(GroupAffine<F>, GroupAffine<F>)],
    w: &mut Witness<F>,
) -> (GroupAffine<F>, Vec<F>) {
    let absorb_curve = |c: &GroupAffine<F>, sponge: &mut Sponge<F>, w: &mut Witness<F>| {
        let GroupAffine::<F> { x, y, .. } = c;
        sponge.absorb(&[*x, *y], w);
    };

    let prechallenges = gammas
        .iter()
        .map(|gamma_i| {
            absorb_curve(&gamma_i.0, sponge, w);
            absorb_curve(&gamma_i.1, sponge, w);
            lowest_128_bits(sponge.squeeze(w), false, w)
        })
        .collect::<Vec<_>>();

    let mut term_and_challenge = |(l, r): &(GroupAffine<F>, GroupAffine<F>), pre: F| {
        let left_term = endo_inv::<F, F, 128>(*l, pre, w);
        let right_term = endo::<F, F, 128>(*r, pre, w);
        (w.add_fast(left_term, right_term), pre)
    };

    let (terms, challenges): (Vec<_>, Vec<_>) = gammas
        .iter()
        .zip(prechallenges)
        .map(|(c, pre)| term_and_challenge(c, pre))
        .unzip();

    (
        terms
            .into_iter()
            .reduce(|acc, v| w.add_fast(acc, v))
            .unwrap(),
        challenges,
    )
}
