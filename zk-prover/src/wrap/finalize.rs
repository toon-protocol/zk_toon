//! `finalize_other_proof`: what the wrap circuit checks of a previous proof's deferred values (the
//! ones the step circuit left, which are in the wrap field).
//!
//! Derived from `wrap_verifier::finalize_other_proof` in `crates/ledger/src/proofs/wrap.rs` of
//! `toon-protocol/mina-rust` at rev `6feeb3797fff6dba49fd848cb2d6decd63fee1b4` (itself from
//! `o1-labs/mina-rust` v0.19.0, Apache-2.0), where it is private to the crate. Mina `228c409a` (the
//! commit o1js v3.1.0 bundles), `src/lib/crypto/pickles/wrap_verifier.ml`, is the reference. Licensed
//! under Apache-2.0; see `LICENSE-APACHE` and `NOTICE`.

use std::rc::Rc;

use ark_ff::BigInteger256;
use kimchi::{
    curve::KimchiCurve,
    proof::{PointEvaluations, ProofEvaluations},
};
use ledger::proofs::{
    field::{field, Boolean, FieldWitness},
    public_input::{
        plonk_checks::{checked, PlonkMinimal, ScalarsEnv, ShiftingValue},
        prepared_statement::Plonk,
    },
    step::{FeatureFlags, Opt, OptFlag},
    transaction::{endos, poseidon::Sponge, scalar_challenge::to_field_checked},
    unfinalized::{self, AllEvals},
    util::{
        challenge_polynomial_checked, proof_evaluation_to_list, to_absorption_sequence_opt,
        two_u64_to_field,
    },
    witness::Witness,
    wrap::{
        make_scalars_env_checked,
        pseudo::PseudoDomain,
        wrap_verifier::{lowest_128_bits, PlonkWithField},
        MakeScalarsEnvParams, COMMON_MAX_DEGREE_WRAP_LOG2,
    },
};
use mina_curves::pasta::{Fp, Fq};

use super::constant_term::constant_term;

fn map_plonk_to_field(plonk: &Plonk<Fq>, w: &mut Witness<Fq>) -> PlonkWithField<Fq> {
    let Plonk {
        alpha,
        beta,
        gamma,
        zeta,
        zeta_to_srs_length,
        zeta_to_domain_size,
        perm,
        lookup: _,
        feature_flags: _,
    } = plonk;

    let (_, endo) = endos::<Fp>();

    let mut scalar = |v: &[u64; 2]| to_field_checked::<Fq, 128>(two_u64_to_field(v), endo, w);

    let zeta = scalar(zeta);
    let gamma: Fq = two_u64_to_field(gamma);
    let beta: Fq = two_u64_to_field(beta);
    let alpha = scalar(alpha);

    PlonkWithField {
        alpha,
        beta,
        gamma,
        zeta,
        zeta_to_srs_length: zeta_to_srs_length.clone(),
        zeta_to_domain_size: zeta_to_domain_size.clone(),
        perm: perm.clone(),
        lookup: (),
    }
}

/// `Plonk_checks.actual_evaluation` for a single chunk.
/// `challenge_polynomial` evaluated at `pt`: with constant challenges the products with the point's powers are
/// linear, and add no witness.
fn challenge_polynomial(chals: &[Fq], constant: bool, pt: Fq, w: &mut Witness<Fq>) -> Fq {
    if !constant {
        return challenge_polynomial_checked(chals)(pt, w);
    }
    let k = chals.len();
    let pow_two_pows = {
        let mut res = vec![pt; k];
        for i in 1..k {
            res[i] = field::square(res[i - 1], w);
        }
        res
    };
    let term = |i: usize| Fq::from(1u64) + chals[i] * pow_two_pows[k - 1 - i];
    let mut r = term(0);
    for i in 1..k {
        r = field::mul(term(i), r, w);
    }
    r
}

fn actual_evaluation(e: &[Fq]) -> Fq {
    match e {
        [one] => *one,
        _ => unimplemented!("a wrap proof's evaluations have one chunk"),
    }
}

/// `Plonk_checks.ft_eval0`, the evaluation of the linearization at zeta that the proof of the circuit leaves out, for a
/// wrap proof (no features, no lookups).
///
/// Derived from `ft_eval0_checked` in `crates/ledger/src/proofs/public_input/plonk_checks.rs` of
/// `toon-protocol/mina-rust` at the rev above, with the constant term of Mina `228c409a` ([`constant_term`]).
fn ft_eval0(
    env: &ScalarsEnv<Fq>,
    evals: &ProofEvaluations<PointEvaluations<Fq>>,
    minimal: &PlonkMinimal<Fq, 4>,
    p_eval0: &[Fq],
    w: &mut Witness<Fq>,
) -> Fq {
    const PERMUTS_MINUS_1: usize = 6;
    // `Plonk_checks.perm_alpha0`
    const PERM_ALPHA0: usize = 21;

    let e0_s: Vec<_> = evals.s.iter().map(|s| s.zeta).collect();
    let zkp = env.zk_polynomial;
    let alpha_pows = {
        let mut pows = vec![Fq::from(1u64); 71];
        for i in 1..pows.len() {
            pows[i] = pows[i - 1] * minimal.alpha;
        }
        pows
    };
    let alpha_pow = |i: usize| alpha_pows[i];

    let zeta1m1 = env.zeta_to_n_minus_1;
    let p_eval0 = p_eval0
        .iter()
        .copied()
        .rfold(None, |acc, p_eval0| match acc {
            None => Some(p_eval0),
            Some(acc) => {
                let zeta1 = *env.zeta_to_srs_length.get(w);
                Some(p_eval0 + field::mul(zeta1, acc, w))
            }
        })
        .expect("a public input evaluation");
    let w0: Vec<_> = evals.w.iter().map(|w| w.zeta).collect();

    let ft_eval0 = {
        let a0 = alpha_pow(PERM_ALPHA0);
        let w_n = w0[PERMUTS_MINUS_1];
        let init = field::muls(&[(w_n + minimal.gamma), evals.z.zeta_omega, a0, zkp], w);
        e0_s.iter().enumerate().fold(init, |acc, (i, s)| {
            // We decompose this way because of OCaml evaluation order
            let beta_s = field::mul(minimal.beta, *s, w);
            field::mul(beta_s + w0[i] + minimal.gamma, acc, w)
        })
    };

    let shifts = env.domain.shifts();
    let ft_eval0 = ft_eval0 - p_eval0;

    let ft_eval0 = ft_eval0
        - shifts.iter().enumerate().fold(
            field::muls(&[alpha_pow(PERM_ALPHA0), zkp, evals.z.zeta], w),
            |acc, (i, s)| {
                let beta_zeta = field::mul(minimal.beta, minimal.zeta, w);
                field::mul(acc, minimal.gamma + (beta_zeta * s) + w0[i], w)
            },
        );

    // We decompose this way because of OCaml evaluation order
    let a = field::muls(
        &[
            zeta1m1,
            alpha_pow(PERM_ALPHA0 + 2),
            (minimal.zeta - Fq::from(1u64)),
        ],
        w,
    );
    let b = field::muls(
        &[
            zeta1m1,
            alpha_pow(PERM_ALPHA0 + 1),
            (minimal.zeta - env.omega_to_minus_zk_rows),
        ],
        w,
    );
    let nominator = field::mul(a + b, Fq::from(1u64) - evals.z.zeta, w);

    let denominator = field::mul(
        minimal.zeta - env.omega_to_minus_zk_rows,
        minimal.zeta - Fq::from(1u64),
        w,
    );
    let ft_eval0 = ft_eval0 + field::div_by_inv(nominator, denominator, w);

    let (endo, _) = endos::<Fq>();
    let mds = &<<Fq as FieldWitness>::OtherCurve as KimchiCurve<{ ledger::proofs::FULL_ROUNDS }>>::sponge_params().mds;
    ft_eval0 - constant_term(evals, &alpha_pows, mds, endo, w)
}

pub struct FinalizeOtherProofParams<'a> {
    pub domain: &'a PseudoDomain<Fq>,
    pub sponge: Sponge<Fq>,
    /// The previous proof's old challenges, padded to 2 (`Wrap_hack.Checked.pad_challenges`).
    pub old_bulletproof_challenges: &'a [[Fq; 15]],
    /// How many of them, from the front, are the constant dummies of the padding rather than values the
    /// circuit witnessed: operations on a constant add no witness.
    pub constant_challenges: usize,
    pub deferred_values: &'a unfinalized::DeferredValues,
    pub evals: &'a AllEvals<Fq>,
}

/// Whether the previous proof's deferred values are right, and its bulletproof challenges.
pub fn finalize_other_proof(
    params: FinalizeOtherProofParams,
    w: &mut Witness<Fq>,
) -> (Boolean, Vec<Fq>) {
    let FinalizeOtherProofParams {
        domain,
        mut sponge,
        old_bulletproof_challenges,
        constant_challenges,
        deferred_values,
        evals,
    } = params;

    let unfinalized::DeferredValues {
        plonk,
        combined_inner_product,
        b,
        xi,
        bulletproof_challenges,
    } = deferred_values;

    let AllEvals { ft_eval1, evals } = evals;

    let plonk = map_plonk_to_field(plonk, w);
    let zetaw = field::mul(domain.domain.group_gen, plonk.zeta, w);

    let (sg_evals1, sg_evals2) = {
        let mut sg_evals = |pt: Fq| {
            let mut e = old_bulletproof_challenges
                .iter()
                .enumerate()
                .rev()
                .map(|(i, chals)| challenge_polynomial(chals, i < constant_challenges, pt, w))
                .collect::<Vec<_>>();
            e.reverse();
            e
        };

        // We decompose this way because of OCaml evaluation order
        let sg_evals2 = sg_evals(zetaw);
        let sg_evals1 = sg_evals(plonk.zeta);
        (sg_evals1, sg_evals2)
    };

    // sponge state
    {
        // The constant padding goes through the sponge like any other challenge: the circuit still
        // constrains the permutations.
        let challenge_digest = {
            let mut sponge = Sponge::<Fq>::new();
            old_bulletproof_challenges.iter().for_each(|v| {
                sponge.absorb2(v, w);
            });
            sponge.squeeze(w)
        };

        sponge.absorb2(&[challenge_digest], w);
        sponge.absorb(&[*ft_eval1], w);
        sponge.absorb(&evals.public_input.0, w);
        sponge.absorb(&evals.public_input.1, w);

        for eval in &to_absorption_sequence_opt(&evals.evals, OptFlag::No) {
            match eval {
                Opt::No => {}
                Opt::Some(PointEvaluations { zeta, zeta_omega }) => {
                    sponge.absorb(zeta, w);
                    sponge.absorb(zeta_omega, w);
                }
                Opt::Maybe(_b, _pt) => unimplemented!("a wrap proof has no optional evaluations"),
            }
        }
    };

    let xi_actual = lowest_128_bits(sponge.squeeze(w), false, w);
    let r_actual = lowest_128_bits(sponge.squeeze(w), true, w);

    let xi_correct = field::equal(xi_actual, two_u64_to_field(xi), w);

    let (_, endo) = endos::<Fp>();

    let xi = to_field_checked::<Fq, 128>(two_u64_to_field(xi), endo, w);
    let r = to_field_checked::<Fq, 128>(r_actual, endo, w);

    let to_bytes = |f: Fq| {
        let bigint: BigInteger256 = f.into();
        let [a, b, c, d] = bigint.0;
        [a, b, c, d]
    };

    let plonk_mininal = PlonkMinimal::<Fq, 4> {
        alpha: plonk.alpha,
        beta: plonk.beta,
        gamma: plonk.gamma,
        zeta: plonk.zeta,
        joint_combiner: None,
        alpha_bytes: to_bytes(plonk.alpha),
        beta_bytes: to_bytes(plonk.beta),
        gamma_bytes: to_bytes(plonk.gamma),
        zeta_bytes: to_bytes(plonk.zeta),
        joint_combiner_bytes: None,
        feature_flags: FeatureFlags::empty_bool(),
    };

    let combined_evals = {
        // The evaluations are of one chunk, so the powers of the points are not used, but the OCaml computes
        // them (`pow2pow`) and their squares are witnesses.
        let mut pow2pow =
            |f: Fq| (0..COMMON_MAX_DEGREE_WRAP_LOG2).fold(f, |acc, _| field::square(acc, w));
        pow2pow(plonk.zeta);
        pow2pow(zetaw);

        evals
            .evals
            .map_ref(&|PointEvaluations { zeta, zeta_omega }| PointEvaluations {
                zeta: actual_evaluation(zeta),
                zeta_omega: actual_evaluation(zeta_omega),
            })
    };

    let srs_length_log2 = COMMON_MAX_DEGREE_WRAP_LOG2 as u64;
    let env = make_scalars_env_checked(
        MakeScalarsEnvParams {
            minimal: &plonk_mininal,
            domain: Rc::new(domain.clone()),
            srs_length_log2,
            hack_feature_flags: OptFlag::No,
            zk_rows: 3,
        },
        w,
    );

    let combined_inner_product_correct = {
        let p_eval0 = &evals.public_input.0;
        let ft_eval0 = ft_eval0(&env, &combined_evals, &plonk_mininal, p_eval0, w);
        let a = proof_evaluation_to_list(&evals.evals);

        let actual_combined_inner_product = {
            enum WhichEval {
                First,
                Second,
            }

            let combine = |which_eval: WhichEval,
                           sg_evals: &[Fq],
                           ft_eval: Fq,
                           x_hat: &[Fq],
                           w: &mut Witness<Fq>| {
                let f = |PointEvaluations { zeta, zeta_omega }: &PointEvaluations<Vec<Fq>>| {
                    match which_eval {
                        WhichEval::First => zeta.clone(),
                        WhichEval::Second => zeta_omega.clone(),
                    }
                };
                sg_evals
                    .iter()
                    .copied()
                    .chain(x_hat.iter().copied())
                    .chain([ft_eval])
                    .chain(a.iter().flat_map(|a| f(a)))
                    .rev()
                    .reduce(|acc, fx| fx + field::mul(xi, acc, w))
                    // OCaml panics too
                    .expect("combine_split_evaluations: empty")
            };

            // We decompose this way because of OCaml evaluation order
            let b = combine(
                WhichEval::Second,
                &sg_evals2,
                *ft_eval1,
                &evals.public_input.1,
                w,
            );
            let b = field::mul(b, r, w);
            let a = combine(
                WhichEval::First,
                &sg_evals1,
                ft_eval0,
                &evals.public_input.0,
                w,
            );
            a + b
        };

        let combined_inner_product = ShiftingValue::<Fq>::shifted_to_field(combined_inner_product);
        field::equal(combined_inner_product, actual_combined_inner_product, w)
    };

    let mut bulletproof_challenges = bulletproof_challenges
        .iter()
        .rev()
        .map(|bytes| to_field_checked::<Fq, 128>(two_u64_to_field(bytes), endo, w))
        .collect::<Vec<_>>();
    bulletproof_challenges.reverse();

    let b_correct = {
        let challenge_poly = challenge_polynomial_checked(&bulletproof_challenges);

        // We decompose this way because of OCaml evaluation order
        let r_zetaw = field::mul(r, challenge_poly(zetaw, w), w);
        let b_actual = challenge_poly(plonk.zeta, w) + r_zetaw;

        field::equal(b.shifted_to_field(), b_actual, w)
    };

    let plonk_checks_passed = checked(&env, &combined_evals, &plonk, w);
    let finalized = Boolean::all(
        &[
            xi_correct,
            b_correct,
            combined_inner_product_correct,
            plonk_checks_passed,
        ],
        w,
    );

    (finalized, bulletproof_challenges)
}
