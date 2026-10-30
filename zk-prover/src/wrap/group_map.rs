//! The Brier-Wohlwend-style group map (`Group_map.Bw19`) the wrap circuit hashes to the curve with.
//!
//! Derived from `crates/ledger/src/proofs/group_map.rs` in `toon-protocol/mina-rust` at rev
//! `6feeb3797fff6dba49fd848cb2d6decd63fee1b4` (itself from `o1-labs/mina-rust` v0.19.0,
//! Apache-2.0), whose `is_square` tests the Legendre symbol with the modulus of `Fp` whatever the
//! field is, so it fails for the wrap circuit's `Fq`. Licensed under Apache-2.0; see
//! `LICENSE-APACHE` and `NOTICE`.

use std::ops::Neg;

use ark_ff::{Field, PrimeField, Zero};
use ledger::proofs::{
    field::{field, Boolean, FieldWitness, GroupAffine, ToBoolean},
    transaction::make_group,
    witness::Witness,
};

#[derive(Clone, Copy)]
struct Params<F: FieldWitness> {
    u: F,
    fu: F,
    sqrt_neg_three_u_squared_minus_u_over_2: F,
    sqrt_neg_three_u_squared: F,
    inv_three_u_squared: F,
}

impl<F: FieldWitness> Params<F> {
    fn create() -> Self {
        let b = F::PARAMS.b;

        fn first_map<F: FieldWitness, T>(f: impl Fn(F) -> Option<T>) -> T {
            let mut v = F::zero();
            let one = F::one();
            loop {
                match f(v) {
                    Some(x) => return x,
                    None => v += one,
                }
            }
        }

        let curve_eqn = |u: F| (u * u * u) + b;

        let (u, fu) = first_map(|u| {
            let fu = curve_eqn(u);
            if u.is_zero() || fu.is_zero() {
                None
            } else {
                Some((u, fu))
            }
        });

        let three_u_squared = u * u * F::from(3);
        let sqrt_neg_three_u_squared = three_u_squared.neg().sqrt().unwrap();

        Self {
            u,
            fu,
            sqrt_neg_three_u_squared_minus_u_over_2: (sqrt_neg_three_u_squared - u) / F::from(2),
            sqrt_neg_three_u_squared,
            inv_three_u_squared: F::one() / three_u_squared,
        }
    }
}

fn potential_xs<F: FieldWitness>(t: F, params: &Params<F>, w: &mut Witness<F>) -> (F, F, F) {
    let square = |x: F, w: &mut Witness<F>| field::mul(x, x, w);

    let t2 = field::mul(t, t, w);
    let alpha = {
        let alpha_inv = field::mul(t2 + params.fu, t2, w);
        field::div(F::one(), alpha_inv, w)
    };
    let x1 = {
        let t2_squared = square(t2, w);
        let temp = field::mul(t2_squared, alpha, w) * params.sqrt_neg_three_u_squared;
        params.sqrt_neg_three_u_squared_minus_u_over_2 - temp
    };
    let x2 = params.u.neg() - x1;
    let x3 = {
        let t2_plus_fu = t2 + params.fu;
        let t2_inv = field::mul(alpha, t2_plus_fu, w);
        let temp = {
            let t2_plus_fu_squared = square(t2_plus_fu, w);
            field::mul(t2_plus_fu_squared, t2_inv, w) * params.inv_three_u_squared
        };
        params.u - temp
    };
    (x1, x2, x3)
}

fn sqrt_exn<F: FieldWitness>(x: F, w: &mut Witness<F>) -> F {
    w.exists(x.sqrt().unwrap())
}

fn is_square<F: FieldWitness>(x: F) -> bool {
    let s = x.pow(F::MODULUS_MINUS_ONE_DIV_TWO);
    s.is_zero() || s.is_one()
}

fn sqrt_flagged<F: FieldWitness>(x: F, w: &mut Witness<F>) -> (F, Boolean) {
    let is_square = w.exists(is_square(x).to_boolean());
    let m = non_residue::<F>();
    let v = w.exists_no_check(match is_square {
        Boolean::True => x,
        Boolean::False => x * m,
    });
    (sqrt_exn(v, w), is_square)
}

fn non_residue<F: FieldWitness>() -> F {
    let mut i = F::from(2);
    let one = F::one();
    loop {
        if !is_square(i) {
            break i;
        } else {
            i += one;
        }
    }
}

/// `Wrap_verifier.group_map`
pub fn group_map<F: FieldWitness>(x: F, w: &mut Witness<F>) -> GroupAffine<F> {
    let params = Params::<F>::create();
    let potential_xs = potential_xs(x, &params, w);
    wrap(potential_xs, w)
}

fn wrap<F: FieldWitness>(potential_xs: (F, F, F), w: &mut Witness<F>) -> GroupAffine<F> {
    let y_squared =
        |x: F, w: &mut Witness<F>| field::muls(&[x, x, x], w) + (F::PARAMS.a * x) + F::PARAMS.b;

    let (x1, x2, x3) = potential_xs;

    let (y1, b1) = sqrt_flagged(y_squared(x1, w), w);
    let (y2, b2) = sqrt_flagged(y_squared(x2, w), w);
    let (y3, b3) = sqrt_flagged(y_squared(x3, w), w);

    Boolean::assert_any(&[b1, b2, b3], w);

    let x1_is_first = b1.to_field::<F>();
    let x2_is_first = (b1.neg().and(&b2, w)).to_field::<F>();
    let x3_is_first = (b1.neg().and(&b2.neg(), w).and(&b3, w)).to_field::<F>();

    // We decompose this way because of OCaml evaluation order
    let x3_is_first_y3 = field::mul(x3_is_first, y3, w);
    let x2_is_first_y2 = field::mul(x2_is_first, y2, w);
    let x1_is_first_y1 = field::mul(x1_is_first, y1, w);
    let x3_is_first_x3 = field::mul(x3_is_first, x3, w);
    let x2_is_first_x2 = field::mul(x2_is_first, x2, w);
    let x1_is_first_x1 = field::mul(x1_is_first, x1, w);

    let (x, y) = (
        (x1_is_first_x1 + x2_is_first_x2 + x3_is_first_x3),
        (x1_is_first_y1 + x2_is_first_y2 + x3_is_first_y3),
    );
    make_group(x, y)
}
