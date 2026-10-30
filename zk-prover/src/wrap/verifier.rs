//! The in-circuit Pickles verifier of the wrap circuit, generalised to optional gates and lookups.
//!
//! Derived from `wrap_verifier` in `crates/ledger/src/proofs/wrap.rs` of `toon-protocol/mina-rust`
//! at rev `6feeb3797fff6dba49fd848cb2d6decd63fee1b4` (itself from `o1-labs/mina-rust` v0.19.0,
//! Apache-2.0), which handles neither optional commitments nor lookups. The generalisation
//! follows Mina `aa93c444`, `src/lib/pickles/wrap_verifier.ml`
//! (`incrementally_verify_proof`, `index_to_field_elements`, `Split_commitments`,
//! `simulate_optional_sponge_with_alignment`) and `src/lib/crypto/plonkish_prelude/pcs_batch.ml`.
//! Licensed under Apache-2.0; see `LICENSE-APACHE` and `NOTICE`.

use std::sync::Arc;

use ark_ec::short_weierstrass::{Affine, Projective};
use std::ops::Neg;

use ark_ff::{BigInteger256, One, Zero};
use itertools::Itertools;
use kimchi::circuits::wires::COLUMNS;
use ledger::proofs::{
    field::{field, Boolean, CircuitVar, FieldWitness, GroupAffine, ToBoolean},
    public_input::{
        plonk_checks::{ShiftedValue, ShiftingValue},
        prepared_statement::Plonk,
    },
    step::OptFlag,
    transaction::{
        plonk_curve_ops::scale_fast, poseidon::Sponge, scalar_challenge, InnerCurve, make_group,
        Check,
    },
    util::two_u64_to_field,
    witness::Witness,
    wrap::{
        wrap_verifier::{
            chunks_needed, equal_g, lagrange_commitment, lowest_128_bits, Advice,
            OPS_BITS_PER_CHUNK,
        },
        Domain, Domains, Packed,
    },
};
use mina_curves::pasta::{Fp, Fq, Vesta};
use poly_commitment::{ipa::{OpeningProof, SRS}, PolyComm, SRS as _};

use super::{
    group_map::group_map,
    endo::{bullet_reduce, endo, endo_cvar},
    key::{ChosenKey, Comm, Opt},
    opt_sponge::{OptSponge, SpongeState},
};
pub(super) fn lagrange(domain: (&[Boolean], &[Domains]), srs: &mut SRS<Vesta>, i: usize) -> (Fq, Fq) {
    let (which_branch, domains) = domain;
    assert_eq!(which_branch.len(), domains.len());

    domains
        .iter()
        .zip(which_branch)
        .filter(|(_, b)| b.as_bool())
        .map(|(d, _)| {
            let d = 2u64.pow(d.h.log2_size() as u32);
            match lagrange_commitment::<Fq>(srs, d, i).chunks.as_slice() {
                &[GroupAffine::<Fq> { x, y, .. }] => (x, y),
                _ => unreachable!(),
            }
        })
        .reduce(|mut acc, v| {
            acc.0 += v.0;
            acc.1 += v.1;
            acc
        })
        .unwrap()
}

fn lagrange_with_correction(
    input_length: usize,
    domain: (&[Boolean], &[Domains]),
    srs: &mut SRS<Vesta>,
    i: usize,
    w: &mut Witness<Fq>,
) -> (CircuitVar<InnerCurve<Fq>>, InnerCurve<Fq>) {
    let (which_branch, domains) = domain;
    assert_eq!(which_branch.len(), domains.len());

    let actual_shift = { OPS_BITS_PER_CHUNK * chunks_needed(input_length) };
    let pow2pow = |x: InnerCurve<Fq>, n: usize| (0..n).fold(x, |acc, _| acc.clone() + acc);

    let base_and_correction = |h: Domain| {
        let d = 2u64.pow(h.log2_size() as u32);
        match lagrange_commitment::<Fq>(srs, d, i).chunks.as_slice() {
            &[g] => {
                let g = InnerCurve::of_affine(g);
                let b = pow2pow(g.clone(), actual_shift).neg();
                (g, b)
            }
            _ => unreachable!(),
        }
    };

    let [d, ds @ ..] = domains else {
        panic!("invalid state");
    };

    let (a, b) = if ds.iter().all(|d2| d.h == d2.h) {
        base_and_correction(d.h)
    } else {
        let (x, y) = domains
            .iter()
            .map(|ds| base_and_correction(ds.h))
            .zip(which_branch)
            .map(|((x, y), b)| {
                let b = b.to_field::<Fq>();
                let x = {
                    let GroupAffine::<Fq> { x, y, .. } = x.to_affine();
                    make_group(b * x, b * y)
                };
                let y = {
                    let GroupAffine::<Fq> { x, y, .. } = y.to_affine();
                    make_group(b * x, b * y)
                };
                (x, y)
            })
            .fold(
                (Projective::default(), Projective::default()),
                |mut acc, v| {
                    acc.0 += v.0;
                    acc.1 += v.1;
                    acc
                },
            );

        w.exists([y.y, y.x]);
        w.exists([x.y, x.x]);

        (
            InnerCurve::of_affine(Affine::from(x)),
            InnerCurve::of_affine(Affine::from(y)),
        )
    };

    // TODO: Hack until we have proper cvar :(
    // `base_and_correction` returns `Constant`
    if domains.len() == 1 {
        (CircuitVar::Constant(a), b)
    } else {
        (CircuitVar::Var(a), b)
    }
}

// TODO: We might have to use F::Scalar here
fn scale_fast2<F: FieldWitness>(
    g: CircuitVar<GroupAffine<F>>,
    (s_div_2, s_odd): (F, Boolean),
    num_bits: usize,
    w: &mut Witness<F>,
) -> GroupAffine<F> {
    use ledger::proofs::transaction::plonk_curve_ops::scale_fast_unpack;

    let s_div_2_bits = num_bits - 1;
    let chunks_needed = chunks_needed(s_div_2_bits);
    let actual_bits_used = chunks_needed * OPS_BITS_PER_CHUNK;

    let shifted = F::Shifting::of_raw(s_div_2);
    let g2 = *g.value();
    let h = match actual_bits_used {
        255 => scale_fast_unpack::<F, F, 255>(g2, shifted, w).0,
        130 => scale_fast_unpack::<F, F, 130>(g2, shifted, w).0,
        n => todo!("{:?}", n),
    };

    let on_false = {
        let g_neg = g2.neg();
        if let CircuitVar::Var(_) = g {
            w.exists(g_neg.y);
        };
        w.add_fast(h, g_neg)
    };

    w.exists_no_check(match s_odd {
        Boolean::True => h,
        Boolean::False => on_false,
    })
}

// TODO: We might have to use F::Scalar here
fn scale_fast2_prime<F: FieldWitness>(
    g: CircuitVar<InnerCurve<F>>,
    s: F,
    num_bits: usize,
    w: &mut Witness<F>,
) -> GroupAffine<F> {
    let s_parts = w.exists({
        // TODO: Here `s` is a `F` but needs to be read as a `F::Scalar`
        let bigint: BigInteger256 = s.into();
        let bigint: [u64; 4] = bigint.0;
        let s_odd = bigint[0] & 1 != 0;
        let v = if s_odd { s - F::one() } else { s };
        (v / F::from(2u64), s_odd.to_boolean())
    });

    scale_fast2(g.map(|g| g.to_affine()), s_parts, num_bits, w)
}


struct CheckBulletProofParams<'a> {
    sponge: Sponge<Fq>,
    xi: [u64; 2],
    advice: &'a Advice<Fq>,
    openings_proof: &'a OpeningProof<Vesta, { ledger::proofs::FULL_ROUNDS }>,
    srs: &'a SRS<GroupAffine<Fq>>,
    polynomials: Vec<Opt<Comm>>,
}

fn check_bulletproof(
    params: CheckBulletProofParams,
    w: &mut Witness<Fq>,
) -> (Boolean, Vec<Fq>) {
    let scale = scale_fast::<Fq, Fp, { OTHER_FIELD_PACKED_CONSTANT_SIZE_IN_BITS }>;

    let CheckBulletProofParams {
        mut sponge,
        xi,
        advice,
        openings_proof,
        srs,
        polynomials,
    } = params;

    let OpeningProof {
        lr,
        delta,
        z1,
        z2,
        sg,
    } = openings_proof;

    let combined_inner_product: Fq = {
        let bigint: BigInteger256 = advice.combined_inner_product.shifted.into();
        bigint.into() // Never fail, `Fq` is larger than `Fp`
    };
    sponge.absorb(&[combined_inner_product], w);
    super::trace("bulletproof: absorbed cip", w);

    let u = {
        let t = sponge.squeeze(w);
        super::trace("bulletproof: squeezed t", w);
        group_map(t, w)
    };
    super::trace("bulletproof: group_map", w);

    let combined_polynomial = split_commitments::combine(xi, &polynomials, w);

    let (lr_prod, challenges) = bullet_reduce(&mut sponge, lr, w);

    let p_prime = {
        let _ = w.exists_no_check(u); // Made by `plonk_curve_ops.seal` in `scale_fast`
        let uc = scale(u, advice.combined_inner_product.clone(), w);
        w.add_fast(combined_polynomial, uc)
    };

    let absorb_curve = |c: &GroupAffine<Fq>, sponge: &mut Sponge<Fq>, w: &mut Witness<Fq>| {
        let GroupAffine::<Fq> { x, y, .. } = c;
        sponge.absorb(&[*x, *y], w);
    };

    let q = w.add_fast(p_prime, lr_prod);

    absorb_curve(delta, &mut sponge, w);
    let c = lowest_128_bits(sponge.squeeze(w), false, w);

    let lhs = {
        let cq = endo::<Fq, Fq, 128>(q, c, w);
        w.add_fast(cq, *delta)
    };

    let rhs = {
        let b_u = {
            let _ = w.exists_no_check(u); // Made by `plonk_curve_ops.seal` in `scale_fast`
            scale(u, advice.b.clone(), w)
        };
        let z_1_g_plus_b_u = scale(w.add_fast(*sg, b_u), ShiftedValue::of_field(*z1), w);
        let z2_h = scale(srs.h, ShiftedValue::of_field(*z2), w);
        w.add_fast(z_1_g_plus_b_u, z2_h)
    };

    (equal_g(lhs, rhs, w), challenges)
}

/// `Other_field.Packed.Constant.size_in_bits`
const OTHER_FIELD_PACKED_CONSTANT_SIZE_IN_BITS: usize = 255;

/// `Permuts_minus_1.add Nat.N1.n`
const PERMUTS_MINUS_1_ADD_N1: usize = 6;

/// `Common.ft_comm`
fn ft_comm<Scale>(
    plonk: &Plonk<Fp>,
    t_comm: &PolyComm<GroupAffine<Fq>>,
    base: &ledger::proofs::transaction::PlonkVerificationKeyEvals<Fq>,
    scale: Scale,
    w: &mut Witness<Fq>,
) -> GroupAffine<Fq>
where
    Scale: Fn(
        GroupAffine<Fq>,
        <Fp as FieldWitness>::Shifting,
        &mut Witness<Fq>,
    ) -> GroupAffine<Fq>,
{
    let [sigma_comm_last] = &base.sigma[PERMUTS_MINUS_1_ADD_N1..] else {
        panic!()
    };

    // We decompose this way because of OCaml evaluation order (reversed)
    let f_comm = [scale(sigma_comm_last.to_affine(), plonk.perm.clone(), w)]
        .into_iter()
        .rev()
        .reduce(|acc, v| w.add_fast(acc, v))
        .unwrap();

    let chunked_t_comm = t_comm
        .chunks
        .iter()
        .rev()
        .copied()
        .reduce(|acc, v| {
            let scaled = scale(acc, plonk.zeta_to_srs_length.clone(), w);
            w.add_fast(v, scaled)
        })
        .unwrap();

    // We decompose this way because of OCaml evaluation order
    let scaled = scale(chunked_t_comm, plonk.zeta_to_domain_size.clone(), w).neg();
    let v = w.add_fast(f_comm, chunked_t_comm);

    // Because of `neg()` above
    w.exists_no_check(scaled.y);

    w.add_fast(v, scaled)
}

/// `Wrap_verifier.Split_commitments`
pub mod split_commitments {
    use super::*;

    struct CurveOpt {
        point: GroupAffine<Fq>,
        non_zero: CircuitVar<Boolean>,
    }

    /// `Point.add` on a finite point
    fn reduce_point(p: &Comm) -> GroupAffine<Fq> {
        assert_eq!(p.len(), 1, "commitments with several chunks are not ported");
        p[0]
    }

    pub fn combine(xi: [u64; 2], without_bound: &[Opt<Comm>], w: &mut Witness<Fq>) -> GroupAffine<Fq> {
        let xi_field: Fq = two_u64_to_field(&xi);
        let init = |p: &Opt<Comm>| -> Option<CurveOpt> {
            match p {
                Opt::Nothing => None,
                Opt::Maybe(keep, p) => Some(CurveOpt {
                    // `keep &&& true_`
                    non_zero: *keep,
                    point: reduce_point(p),
                }),
                Opt::Just(p) => Some(CurveOpt {
                    non_zero: CircuitVar::Constant(Boolean::True),
                    point: reduce_point(p),
                }),
            }
        };
        let scale_and_add = |acc: CurveOpt, p: &Opt<Comm>, w: &mut Witness<Fq>| -> CurveOpt {
            let point = |keep: CircuitVar<Boolean>, p: &Comm, w: &mut Witness<Fq>| {
                let p = reduce_point(p);
                // Both branches of the `if_` are computed.
                let on_acc_non_zero = {
                    let scaled = endo_cvar::<Fq, Fq, 128>(
                        CircuitVar::Var(acc.point),
                        xi_field,
                        w,
                    );
                    w.add_fast(p, scaled)
                };
                let base_point = match acc.non_zero.as_boolean() {
                    Boolean::True => on_acc_non_zero,
                    Boolean::False => p,
                };
                if let CircuitVar::Var(_) = acc.non_zero {
                    w.exists_no_check(base_point);
                }
                let point = match keep.as_boolean() {
                    Boolean::True => base_point,
                    Boolean::False => acc.point,
                };
                if let CircuitVar::Var(_) = keep {
                    w.exists_no_check(point);
                }
                // `keep &&& true_ ||| acc.non_zero`
                let non_zero = keep.or(&acc.non_zero, w);
                CurveOpt { point, non_zero }
            };
            match p {
                Opt::Nothing => acc,
                Opt::Maybe(keep, p) => point(*keep, p, w),
                Opt::Just(p) => point(CircuitVar::Constant(Boolean::True), p, w),
            }
        };

        let mut rev = without_bound.iter().rev();
        let mut acc = None;
        for p in rev.by_ref() {
            if let Some(i) = init(p) {
                acc = Some(i);
                break;
            }
        }
        let mut acc = acc.expect("combine_split_commitments: empty");
        for p in rev {
            acc = scale_and_add(acc, p, w);
        }
        // `Boolean.Assert.is_true non_zero`
        assert!(acc.non_zero.as_boolean().as_bool());
        acc.point
    }
}

/// An absorption `(keep, point)` of a point into the optional sponge: `x`, then `y`.
fn absorb_points(
    sponge: &mut OptSponge<Fq>,
    keep: CircuitVar<Boolean>,
    points: &[GroupAffine<Fq>],
) {
    for GroupAffine::<Fq> { x, y, .. } in points {
        sponge.absorb((keep, *x));
        sponge.absorb((keep, *y));
    }
}

fn fields_of(comm: &Comm) -> Vec<Fq> {
    comm.iter().flat_map(|g| [g.x, g.y]).collect()
}

/// `index_to_field_elements`: the key in the order its digest absorbs it.
fn index_to_field_elements(key: &ChosenKey) -> Vec<Opt<Vec<Fq>>> {
    let just = |c: &InnerCurve<Fq>| {
        let GroupAffine::<Fq> { x, y, .. } = c.to_affine();
        Opt::Just(vec![x, y])
    };
    let opt = |c: &Opt<Comm>| c.map(fields_of);
    let base = &key.base;
    let mut items: Vec<Opt<Vec<Fq>>> = Vec::new();
    items.extend(base.sigma.iter().map(just));
    items.extend(base.coefficients.iter().map(just));
    items.extend(
        [
            &base.generic,
            &base.psm,
            &base.complete_add,
            &base.mul,
            &base.emul,
            &base.endomul_scalar,
        ]
        .into_iter()
        .map(just),
    );
    items.extend([
        opt(&key.range_check0),
        opt(&key.range_check1),
        opt(&key.foreign_field_mul),
        opt(&key.foreign_field_add),
        opt(&key.xor),
        opt(&key.rot),
    ]);
    items.extend(key.lookup_table.iter().map(opt));
    items.extend([
        opt(&key.lookup_table_ids),
        opt(&key.runtime_tables_selector),
        opt(&key.lookup_selector_xor),
        opt(&key.lookup_selector_lookup),
        opt(&key.lookup_selector_range_check),
        opt(&key.lookup_selector_ffmul),
    ]);
    items
}

/// `if_ b ~then_ ~else_` on a field element held in a variable
fn if_field(b: Boolean, then_: Fq, else_: Fq, w: &mut Witness<Fq>) -> Fq {
    w.exists_no_check(match b {
        Boolean::True => then_,
        Boolean::False => else_,
    })
}

/// `if_ b ~then_ ~else_` on a point held in variables
fn if_curve(
    b: Boolean,
    then_: GroupAffine<Fq>,
    else_: GroupAffine<Fq>,
    w: &mut Witness<Fq>,
) -> GroupAffine<Fq> {
    w.exists_no_check(match b {
        Boolean::True => then_,
        Boolean::False => else_,
    })
}

/// The index digest, with `simulate_optional_sponge_with_alignment` for the maybe-present parts.
fn index_digest(key: &ChosenKey, w: &mut Witness<Fq>) -> Fq {
    let mut sponge = Sponge::<Fq>::new();
    for item in index_to_field_elements(key) {
        match item {
            Opt::Nothing => {}
            Opt::Just(fields) => sponge.absorb2(&fields, w),
            Opt::Maybe(b, fields) => {
                let state_before = sponge.state;
                let sponge_state_before = sponge.sponge_state.clone();
                sponge.absorb2(&fields, w);
                assert_eq!(
                    format!("{:?}", sponge_state_before),
                    format!("{:?}", sponge.sponge_state),
                    "the sponge ends in a different state"
                );
                let after = sponge.state;
                for i in 0..3 {
                    sponge.state[i] = if_field(b.as_boolean(), after[i], state_before[i], w);
                }
            }
        }
    }
    sponge.squeeze(w)
}

/// One lookup message set, as `Messages.Lookup.In_circuit`.
#[derive(Clone, Debug)]
pub struct LookupMessages {
    pub sorted: Vec<Comm>,
    pub sorted_5th_column: Opt<Comm>,
    pub aggreg: Comm,
    pub runtime: Opt<Comm>,
}

/// `Messages.In_circuit`
#[derive(Clone, Debug)]
pub struct Messages {
    pub w_comm: [Comm; COLUMNS],
    pub z_comm: Comm,
    pub t_comm: Comm,
    pub lookup: Opt<LookupMessages>,
}

pub struct IncrementallyVerifyProofParams<'a> {
    pub actual_proofs_verified_mask: Vec<Boolean>,
    pub step_domains: &'a [Domains],
    pub verification_key: &'a ChosenKey,
    pub srs: Arc<SRS<Vesta>>,
    pub xi: &'a [u64; 2],
    pub sponge: OptSponge<Fq>,
    pub public_input: Vec<Packed<Boolean>>,
    pub sg_old: Vec<InnerCurve<Fq>>,
    pub advice: Advice<Fq>,
    pub messages: &'a Messages,
    pub which_branch: Vec<Boolean>,
    pub openings_proof: &'a OpeningProof<Vesta, { ledger::proofs::FULL_ROUNDS }>,
    pub plonk: &'a Plonk<Fp>,
}

pub fn incrementally_verify_proof(
    params: IncrementallyVerifyProofParams,
    w: &mut Witness<Fq>,
) -> (Fq, (Boolean, Vec<Fq>)) {
    let IncrementallyVerifyProofParams {
        actual_proofs_verified_mask,
        step_domains,
        verification_key: m,
        srs,
        xi,
        mut sponge,
        public_input,
        sg_old,
        advice,
        messages,
        which_branch,
        openings_proof,
        plonk,
    } = params;

    let challenge =
        |s: &mut OptSponge<Fq>, w: &mut Witness<Fq>| lowest_128_bits(s.squeeze(w), true, w);
    let scalar_challenge =
        |s: &mut OptSponge<Fq>, w: &mut Witness<Fq>| lowest_128_bits(s.squeeze(w), false, w);

    let t = CircuitVar::Constant(Boolean::True);

    let mut srs = (*srs).clone();
    let sg_old = actual_proofs_verified_mask
        .iter()
        .map(|b| CircuitVar::Var(*b))
        .zip(&sg_old)
        .collect::<Vec<_>>();

    let sample = challenge;
    let sample_scalar = scalar_challenge;

    super::trace("before index digest", w);
    let index_digest = index_digest(m, w);
    super::trace("index digest", w);

    sponge.absorb((t, index_digest));

    for (b, v) in &sg_old {
        absorb_points(&mut sponge, *b, &[v.to_affine()]);
    }

    let x_hat = {
        let domain = (which_branch.as_slice(), step_domains);

        let public_input = public_input.iter().flat_map(|v| {
            // TODO: Do not use `vec!` here
            match v {
                Packed::Field((x, b)) => vec![
                    Packed::Field((*x, 255)),
                    Packed::Field((CircuitVar::Var(b.to_field::<Fq>()), 1)),
                ],
                Packed::PackedBits(x, n) => vec![Packed::Field((*x, *n))],
            }
        });

        let (constant_part, non_constant_part): (Vec<_>, Vec<_>) =
            public_input.enumerate().partition_map(|(i, t)| {
                use itertools::Either::{Left, Right};
                match t {
                    Packed::Field((CircuitVar::Constant(c), _)) => Left(if c.is_zero() {
                        None
                    } else if c.is_one() {
                        Some(lagrange(domain, &mut srs, i))
                    } else {
                        todo!()
                    }),
                    Packed::Field(x) => Right((i, x)),
                    _ => unreachable!(),
                }
            });

        #[derive(Debug)]
        enum CondOrAdd {
            CondAdd(Boolean, (Fq, Fq)),
            AddWithCorrection(
                (CircuitVar<Fq>, usize),
                (CircuitVar<InnerCurve<Fq>>, InnerCurve<Fq>),
            ),
        }

        let terms = non_constant_part
            .into_iter()
            .map(|(i, x)| match x {
                (b, 1) => CondOrAdd::CondAdd(
                    Boolean::of_field(b.as_field()),
                    lagrange(domain, &mut srs, i),
                ),
                (x, n) => CondOrAdd::AddWithCorrection(
                    (x, n),
                    lagrange_with_correction(n, domain, &mut srs, i, w),
                ),
            })
            .collect::<Vec<_>>();

        let correction = terms
            .iter()
            .filter_map(|term| match term {
                CondOrAdd::CondAdd(_, _) => None,
                CondOrAdd::AddWithCorrection(_, (_, corr)) => Some(corr.to_affine()),
            })
            .reduce(|acc, v| w.add_fast(acc, v))
            .unwrap();

        let init = constant_part
            .into_iter()
            .flatten()
            .fold(correction, |acc, (x, y)| w.add_fast(acc, make_group(x, y)));

        terms
            .into_iter()
            .enumerate()
            .fold(init, |acc, (_i, term)| match term {
                CondOrAdd::CondAdd(b, (x, y)) => {
                    let g = w.exists_no_check(make_group(x, y));
                    let on_true = w.add_fast(g, acc);

                    w.exists_no_check(match b {
                        Boolean::True => on_true,
                        Boolean::False => acc,
                    })
                }
                CondOrAdd::AddWithCorrection((x, num_bits), (g, _)) => {
                    let v = scale_fast2_prime(g, x.as_field(), num_bits, w);
                    w.add_fast(acc, v)
                }
            })
            .neg()
    };

    let x_hat = {
        w.exists(x_hat.y); // Because of `.neg()` above
        w.add_fast(x_hat, srs.h)
    };

    super::trace("x_hat", w);
    absorb_points(&mut sponge, t, &[x_hat]);

    for w_comm in &messages.w_comm {
        absorb_points(&mut sponge, t, w_comm);
    }

    // `runtime_comm`
    let runtime_comm: Opt<&Comm> = match &messages.lookup {
        Opt::Nothing => Opt::Nothing,
        Opt::Maybe(_, l) | Opt::Just(l) if matches!(l.runtime, Opt::Nothing) => Opt::Nothing,
        Opt::Maybe(b_lookup, l) => match &l.runtime {
            Opt::Maybe(b_runtime, runtime) => {
                let b = b_lookup.and(b_runtime, w);
                Opt::Maybe(b, runtime)
            }
            Opt::Just(runtime) => Opt::Maybe(*b_lookup, runtime),
            Opt::Nothing => unreachable!(),
        },
        Opt::Just(l) => match &l.runtime {
            Opt::Maybe(b, runtime) => Opt::Maybe(*b, runtime),
            Opt::Just(runtime) => Opt::Just(runtime),
            Opt::Nothing => unreachable!(),
        },
    };
    match &runtime_comm {
        Opt::Nothing => {}
        Opt::Maybe(b, runtime) => absorb_points(&mut sponge, *b, runtime),
        Opt::Just(runtime) => absorb_points(&mut sponge, t, runtime),
    }

    super::trace("before joint combiner", w);
    // `joint_combiner`
    let joint_combiner: Opt<Fq> = {
        let compute_joint_combiner =
            |l: &LookupMessages, sponge: &mut OptSponge<Fq>, w: &mut Witness<Fq>| -> Fq {
                let absorb_sorted_1 = |sponge: &mut OptSponge<Fq>| {
                    absorb_points(sponge, t, &l.sorted[0]);
                };
                let absorb_sorted_2_to_4 = |sponge: &mut OptSponge<Fq>| {
                    for z in &l.sorted[1..] {
                        absorb_points(sponge, t, z);
                    }
                };
                let absorb_sorted_5 = |sponge: &mut OptSponge<Fq>| match &l.sorted_5th_column {
                    Opt::Nothing => {}
                    Opt::Maybe(b, z) => absorb_points(sponge, *b, z),
                    Opt::Just(z) => absorb_points(sponge, t, z),
                };
                let table_second_just = matches!(m.lookup_table[1], Opt::Just(_));
                let table_second_nothing = matches!(m.lookup_table[1], Opt::Nothing);
                let runtime_just = matches!(m.runtime_tables_selector, Opt::Just(_));
                let runtime_nothing = matches!(m.runtime_tables_selector, Opt::Nothing);
                if table_second_just || runtime_just {
                    let joint_combiner = sample_scalar_opt(sponge, w);
                    absorb_sorted_1(sponge);
                    absorb_sorted_2_to_4(sponge);
                    absorb_sorted_5(sponge);
                    joint_combiner
                } else if table_second_nothing && runtime_nothing {
                    absorb_sorted_1(sponge);
                    absorb_sorted_2_to_4(sponge);
                    absorb_sorted_5(sponge);
                    Fq::from(0u64)
                } else {
                    unimplemented!("a joint lookup whose second column or runtime tables may be absent")
                }
            };
        match &messages.lookup {
            Opt::Nothing => Opt::Nothing,
            Opt::Maybe(b, l) => {
                sponge.consume_all_pending(w);
                let sponge2 = sponge.copy();
                let jc = compute_joint_combiner(l, &mut sponge, w);
                sponge.consume_all_pending(w);
                sponge.recombine(&sponge2, b.as_boolean(), w);
                // We explicitly set this, because when we squeeze for `beta`, there will be no
                // pending values *but* we don't want to add a dedicated permutation.
                sponge.needs_final_permute_if_empty = false;
                Opt::Maybe(*b, jc)
            }
            Opt::Just(l) => {
                sponge.consume_all_pending(w);
                Opt::Just(compute_joint_combiner(l, &mut sponge, w))
            }
        }
    };
    super::trace("joint combiner", w);
    // `lookup_table_comm`
    let lookup_table_comm: Opt<Comm> = {
        let add = |a: &Comm, b: &Comm, w: &mut Witness<Fq>| -> Comm {
            a.iter().zip(b).map(|(a, b)| w.add_fast(*a, *b)).collect()
        };
        let if_comm = |b: Boolean, then_: &Comm, else_: &Comm, w: &mut Witness<Fq>| -> Comm {
            then_
                .iter()
                .zip(else_)
                .map(|(t, e)| if_curve(b, *t, *e, w))
                .collect()
        };
        let endo = |acc: &Comm, jc: Fq, w: &mut Witness<Fq>| -> Comm {
            acc.iter()
                .map(|acc| endo::<Fq, Fq, 128>(*acc, jc, w))
                .collect()
        };
        let compute = |l: &LookupMessages, jc: Fq, w: &mut Witness<Fq>| -> Opt<Comm> {
            let [first_column, second_column, rest @ ..] = &m.lookup_table else {
                unreachable!()
            };
            let second_column_with_runtime: Opt<Comm> = match (second_column, &l.runtime) {
                (Opt::Nothing, comm) => comm.clone(),
                (comm, Opt::Nothing) => comm.clone(),
                (Opt::Maybe(has_second_column, second), Opt::Maybe(has_runtime, runtime)) => {
                    let second_with_runtime = {
                        let sum = add(second, runtime, w);
                        second
                            .iter()
                            .zip(&sum)
                            .map(|(sc, sum)| if_curve(has_runtime.as_boolean(), *sum, *sc, w))
                            .collect::<Comm>()
                    };
                    let res = second_with_runtime
                        .iter()
                        .zip(runtime)
                        .map(|(swr, rt)| if_curve(has_second_column.as_boolean(), *swr, *rt, w))
                        .collect::<Comm>();
                    let b = has_second_column.or(has_runtime, w);
                    Opt::Maybe(b, res)
                }
                (Opt::Maybe(has_second_column, second), Opt::Just(runtime)) => {
                    let sum = add(second, runtime, w);
                    let res = runtime
                        .iter()
                        .zip(&sum)
                        .map(|(rt, sum)| if_curve(has_second_column.as_boolean(), *sum, *rt, w))
                        .collect::<Comm>();
                    Opt::Just(res)
                }
                (Opt::Just(second), Opt::Maybe(has_runtime, runtime)) => {
                    let sum = add(second, runtime, w);
                    let res = second
                        .iter()
                        .zip(&sum)
                        .map(|(sc, sum)| if_curve(has_runtime.as_boolean(), *sum, *sc, w))
                        .collect::<Comm>();
                    Opt::Just(res)
                }
                (Opt::Just(second), Opt::Just(runtime)) => Opt::Just(add(second, runtime, w)),
            };
            let mut rest_rev: Vec<&Opt<Comm>> = vec![first_column, &second_column_with_runtime];
            rest_rev.extend(rest.iter());
            rest_rev.reverse();
            rest_rev
                .into_iter()
                .fold(m.lookup_table_ids.clone(), |acc, comm| match (acc, comm) {
                    (Opt::Nothing, comm) => comm.clone(),
                    (Opt::Maybe(has_acc, acc), Opt::Nothing) => Opt::Maybe(has_acc, acc),
                    (Opt::Maybe(has_acc, acc), Opt::Maybe(has_comm, comm)) => {
                        let scaled_acc = endo(&acc, jc, w);
                        let sum = add(&scaled_acc, comm, w);
                        let acc_with_comm = sum
                            .iter()
                            .zip(comm)
                            .map(|(sum, comm)| if_curve(has_acc.as_boolean(), *sum, *comm, w))
                            .collect::<Comm>();
                        let res = acc
                            .iter()
                            .zip(&acc_with_comm)
                            .map(|(acc, awc)| if_curve(has_comm.as_boolean(), *awc, *acc, w))
                            .collect::<Comm>();
                        let b = has_acc.or(has_comm, w);
                        Opt::Maybe(b, res)
                    }
                    (Opt::Maybe(has_acc, acc), Opt::Just(comm)) => {
                        let scaled_acc = endo(&acc, jc, w);
                        let sum = add(&scaled_acc, comm, w);
                        let res = sum
                            .iter()
                            .zip(comm)
                            .map(|(sum, comm)| if_curve(has_acc.as_boolean(), *sum, *comm, w))
                            .collect::<Comm>();
                        Opt::Just(res)
                    }
                    (Opt::Just(acc), Opt::Nothing) => Opt::Just(acc),
                    (Opt::Just(acc), Opt::Maybe(has_comm, comm)) => {
                        let scaled_acc = endo(&acc, jc, w);
                        let sum = add(&scaled_acc, comm, w);
                        let res = sum
                            .iter()
                            .zip(&acc)
                            .map(|(sum, acc)| if_curve(has_comm.as_boolean(), *sum, *acc, w))
                            .collect::<Comm>();
                        Opt::Just(res)
                    }
                    (Opt::Just(acc), Opt::Just(comm)) => {
                        let scaled_acc = endo(&acc, jc, w);
                        Opt::Just(add(&scaled_acc, comm, w))
                    }
                })
        };
        match (&messages.lookup, &joint_combiner) {
            (Opt::Nothing, Opt::Nothing) => Opt::Nothing,
            (Opt::Maybe(b_l, l), Opt::Maybe(_b_joint_combiner, jc)) => {
                // NB: b_l = _b_joint_combiner by construction
                match compute(l, *jc, w) {
                    Opt::Nothing => Opt::Nothing,
                    Opt::Maybe(b_lookup_table_comm, comm) => {
                        let b = b_l.and(&b_lookup_table_comm, w);
                        Opt::Maybe(b, comm)
                    }
                    Opt::Just(comm) => Opt::Maybe(*b_l, comm),
                }
            }
            (Opt::Just(l), Opt::Just(jc)) => compute(l, *jc, w),
            _ => unreachable!(),
        }
    };

    super::trace("lookup_table_comm", w);
    // `lookup_sorted`
    let lookup_sorted: Vec<Opt<Comm>> = (0..5)
        .map(|i| match &messages.lookup {
            Opt::Nothing => Opt::Nothing,
            Opt::Maybe(b, l) => {
                if i == 4 {
                    l.sorted_5th_column.clone()
                } else {
                    Opt::Maybe(*b, l.sorted[i].clone())
                }
            }
            Opt::Just(l) => {
                if i == 4 {
                    l.sorted_5th_column.clone()
                } else {
                    Opt::Just(l.sorted[i].clone())
                }
            }
        })
        .collect();

    let _beta = sample(&mut sponge, w);
    let _gamma = sample(&mut sponge, w);

    match &messages.lookup {
        Opt::Nothing => {}
        Opt::Maybe(b, l) => absorb_points(&mut sponge, *b, &l.aggreg),
        Opt::Just(l) => absorb_points(&mut sponge, t, &l.aggreg),
    }

    absorb_points(&mut sponge, t, &messages.z_comm);

    let _alpha = sample_scalar(&mut sponge, w);

    absorb_points(&mut sponge, t, &messages.t_comm);

    let _zeta = sample_scalar(&mut sponge, w);

    let mut sponge = {
        let SpongeState::Squeezed(n_squeezed) = sponge.sponge_state else {
            // We just called `sample_scalar`
            panic!("OCaml panics too")
        };
        let mut sponge = Sponge::<Fq>::new_with_state(sponge.state);
        sponge.sponge_state = ::poseidon::SpongeState::Squeezed(n_squeezed);
        sponge
    };

    let sponge_before_evaluations = sponge.clone();
    let sponge_digest_before_evaluations = sponge.squeeze(w);

    super::trace("digest before evaluations", w);
    let scale = scale_fast::<Fq, Fp, { OTHER_FIELD_PACKED_CONSTANT_SIZE_IN_BITS }>;
    let t_comm = PolyComm {
        chunks: messages.t_comm.clone(),
    };
    let ft_comm = ft_comm(plonk, &t_comm, &m.base, scale, w);

    let bulletproof_challenges = {
        let curve = |c: &InnerCurve<Fq>| vec![c.to_affine()];
        let mut without_degree_bound: Vec<Opt<Comm>> = Vec::new();
        without_degree_bound.extend(sg_old.iter().map(|(b, p)| Opt::Maybe(*b, vec![p.to_affine()])));
        without_degree_bound.push(Opt::Just(vec![x_hat]));
        without_degree_bound.push(Opt::Just(vec![ft_comm]));
        without_degree_bound.push(Opt::Just(messages.z_comm.clone()));
        without_degree_bound.extend(
            [
                &m.base.generic,
                &m.base.psm,
                &m.base.complete_add,
                &m.base.mul,
                &m.base.emul,
                &m.base.endomul_scalar,
            ]
            .into_iter()
            .map(|c| Opt::Just(curve(c))),
        );
        without_degree_bound.extend(messages.w_comm.iter().map(|c| Opt::Just(c.clone())));
        without_degree_bound.extend(m.base.coefficients.iter().map(|c| Opt::Just(curve(c))));
        without_degree_bound.extend(
            m.base.sigma[..PERMUTS_MINUS_1_ADD_N1]
                .iter()
                .map(|c| Opt::Just(curve(c))),
        );
        without_degree_bound.extend([
            m.range_check0.clone(),
            m.range_check1.clone(),
            m.foreign_field_add.clone(),
            m.foreign_field_mul.clone(),
            m.xor.clone(),
            m.rot.clone(),
        ]);
        without_degree_bound.extend(lookup_sorted);
        without_degree_bound.extend([
            match &messages.lookup {
                Opt::Nothing => Opt::Nothing,
                Opt::Maybe(b, l) => Opt::Maybe(*b, l.aggreg.clone()),
                Opt::Just(l) => Opt::Just(l.aggreg.clone()),
            },
            lookup_table_comm,
            match &runtime_comm {
                Opt::Nothing => Opt::Nothing,
                Opt::Maybe(b, c) => Opt::Maybe(*b, (*c).clone()),
                Opt::Just(c) => Opt::Just((*c).clone()),
            },
            m.runtime_tables_selector.clone(),
            m.lookup_selector_xor.clone(),
            m.lookup_selector_lookup.clone(),
            m.lookup_selector_range_check.clone(),
            m.lookup_selector_ffmul.clone(),
        ]);

        super::trace("ft_comm", w);
        let srs = &srs;
        let advice = &advice;
        check_bulletproof(
            CheckBulletProofParams {
                sponge: sponge_before_evaluations,
                xi: *xi,
                advice,
                openings_proof,
                srs,
                polynomials: without_degree_bound,
            },
            w,
        )
    };

    (sponge_digest_before_evaluations, bulletproof_challenges)
}

fn sample_scalar_opt(sponge: &mut OptSponge<Fq>, w: &mut Witness<Fq>) -> Fq {
    lowest_128_bits(sponge.squeeze(w), false, w)
}
