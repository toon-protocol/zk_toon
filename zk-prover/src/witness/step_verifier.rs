//! The step side of verifying one previous proof: Pickles' `Step_main.verify_one` and the
//! `Step_verifier` it calls (`finalize_other_proof`, `hash_messages_for_next_step_proof_opt`,
//! `incrementally_verify_proof`, `check_bulletproof`, ...), as the witness they create.
//!
//! Derived from `crates/ledger/src/proofs/step.rs` of `toon-protocol/mina-rust` at rev
//! `6feeb3797fff6dba49fd848cb2d6decd63fee1b4` (itself from `o1-labs/mina-rust` v0.19.0, Apache-2.0),
//! where these are private to the crate. Mina `228c409a` (the commit o1js v3.1.0 bundles),
//! `src/lib/crypto/pickles/{step_main,step_verifier}.ml`, is the reference. Licensed under Apache-2.0;
//! see `LICENSE-APACHE` and `NOTICE`.
//!
//! What differs from the fork, for a previous proof of an o1js program: the linearization's constant
//! term is Mina's generated code ([`super::constant_term`]), as the fork's evaluation orders the
//! witnesses differently; each round of the endo gate also creates its `inv` (the wrap code's
//! [`crate::wrap::endo`]); the previous proof's accumulators are as many as its program's
//! `maxProofsVerified`, padded to two with the dummy where Pickles pads them (`Wrap_hack`); and
//! side-loaded verification keys are not supported, only a known one (the key is a constant).

use ark_ff::{BigInteger256, One, Zero};
use kimchi::{
    curve::KimchiCurve,
    proof::{PointEvaluations, ProofEvaluations},
};
use ledger::proofs::{
    field::{Boolean, CircuitVar, FieldWitness, GroupAffine},
    public_input::{
        plonk_checks::{InCircuit, PlonkMinimal, ScalarsEnv, ShiftingValue},
        prepared_statement::{DeferredValues, Plonk, PreparedStatement, ProofState},
    },
    step::{FeatureFlags, ForStep, ForStepKind, Opt, OptFlag, Packed, PerProofWitness},
    to_field_elements::ToFieldElements,
    transaction::{
        endos, scalar_challenge::to_field_checked, CircuitPlonkVerificationKeyEvals, InnerCurve,
        PlonkVerificationKeyEvals, ReducedMessagesForNextStepProof,
    },
    unfinalized::{AllEvals, Unfinalized},
    util::{four_u64_to_field, two_u64_to_field},
    witness::Witness,
    wrap::{wrap_verifier, Domain, Domains, COMMON_MAX_DEGREE_STEP_LOG2},
    ProverProof,
};
use mina_curves::pasta::{Fp, Fq, Pallas};
use mina_p2p_messages::v2;
use poly_commitment::ipa::OpeningProof;
use std::rc::Rc;

use super::constant_term::constant_term;
use crate::wrap::endo::{bullet_reduce, endo, endo_cvar};

/// `Plonk_checks.ft_eval0`, the evaluation of the linearization at zeta that the proof leaves out, for a
/// step proof that uses none of the optional gates and no lookups.
///
/// Derived from `ft_eval0_checked` in `crates/ledger/src/proofs/public_input/plonk_checks.rs` of
/// `toon-protocol/mina-rust` at the rev above, with the constant term of Mina `228c409a`
/// ([`constant_term`]), which the fork evaluates in another order.
fn ft_eval0(
    env: &ScalarsEnv<Fp>,
    evals: &ProofEvaluations<PointEvaluations<Fp>>,
    minimal: &PlonkMinimal<Fp, 4>,
    p_eval0: &[Fp],
    w: &mut Witness<Fp>,
) -> Fp {
    use ledger::proofs::field::field;
    const PERMUTS_MINUS_1: usize = 6;
    // `Plonk_checks.perm_alpha0`
    const PERM_ALPHA0: usize = 21;

    let e0_s: Vec<_> = evals.s.iter().map(|s| s.zeta).collect();
    let zkp = env.zk_polynomial;
    let alpha_pows = {
        let mut pows = vec![Fp::one(); 71];
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
    let a = field::muls(&[zeta1m1, alpha_pow(PERM_ALPHA0 + 2), (minimal.zeta - Fp::one())], w);
    let b = field::muls(
        &[zeta1m1, alpha_pow(PERM_ALPHA0 + 1), (minimal.zeta - env.omega_to_minus_zk_rows)],
        w,
    );
    let nominator = field::mul(a + b, Fp::one() - evals.z.zeta, w);

    let denominator =
        field::mul(minimal.zeta - env.omega_to_minus_zk_rows, minimal.zeta - Fp::one(), w);
    let ft_eval0 = ft_eval0 + field::div_by_inv(nominator, denominator, w);

    let (endo, _) = endos::<Fp>();
    let mds = &<<Fp as FieldWitness>::OtherCurve as KimchiCurve<{ ledger::proofs::FULL_ROUNDS }>>::sponge_params().mds;
    ft_eval0 - constant_term(evals, &alpha_pows, mds, endo, w)
}

pub mod step_verifier {
    use std::ops::Neg;

    use super::*;
    use ledger::proofs::step::step_verifier::PlonkDomain;
    use ledger::proofs::{
        self,
        field::{field, ToBoolean},
        opt_sponge::OptSponge,
        public_input::plonk_checks::{self},
        transaction::poseidon::Sponge,
        unfinalized,
        util::{
            challenge_polynomial_checked, proof_evaluation_to_list_opt, to_absorption_sequence_opt,
        },
        wrap::{
            make_scalars_env_checked,
            pcs_batch::PcsBatch,
            pseudo::{self, PseudoDomain},
            wrap_verifier::{
                actual_evaluation, lowest_128_bits, split_commitments::Point,
                Advice,
            },
            MakeScalarsEnvParams, PERMUTS_MINUS_1_ADD_N1,
        },
    };
    use itertools::Itertools;
    
    use poly_commitment::{ipa::SRS, PolyComm};

    fn squeeze_challenge(s: &mut Sponge<Fp>, w: &mut Witness<Fp>) -> Fp {
        lowest_128_bits(s.squeeze(w), true, w)
    }

    fn squeeze_scalar(s: &mut Sponge<Fp>, w: &mut Witness<Fp>) -> Fp {
        lowest_128_bits(s.squeeze(w), false, w)
    }

    fn absorb_curve(c: &Pallas, sponge: &mut Sponge<Fp>, w: &mut Witness<Fp>) {
        let GroupAffine::<Fp> { x, y, .. } = c;
        sponge.absorb2(&[*x, *y], w);
    }

    fn domain_for_compiled(
        domains: &[Domains],
        branch_data: &v2::CompositionTypesBranchDataStableV1,
        w: &mut Witness<Fp>,
    ) -> PseudoDomain<Fp> {
        let unique_domains = domains
            .iter()
            .map(|d| d.h)
            .sorted()
            .dedup()
            .collect::<Vec<_>>();
        let mut which_log2 = unique_domains
            .iter()
            .rev()
            .map(|Domain::Pow2RootsOfUnity(d)| {
                let d = Fp::from(*d);
                let domain_log2 = Fp::from(branch_data.domain_log2.as_u8() as u64);
                field::equal(d, domain_log2, w)
            })
            .collect::<Vec<_>>();

        which_log2.reverse();

        pseudo::to_domain::<Fp>(&which_log2, &unique_domains)
    }

    pub fn proof_verified_to_prefix(
        p: &v2::PicklesBaseProofsVerifiedStableV1,
    ) -> [Boolean; 2] {
        use v2::PicklesBaseProofsVerifiedStableV1::*;

        match p {
            N0 => [Boolean::False, Boolean::False],
            N1 => [Boolean::False, Boolean::True],
            N2 => [Boolean::True, Boolean::True],
        }
    }

    // TODO: This assumes that feature flags are never enabled (we make this assumption everywhere else too)
    fn validate_feature_flags(hack_feature_flags: OptFlag, w: &mut Witness<Fp>) {
        let no = CircuitVar::Var(Boolean::False);

        let range_check0 = no;
        let range_check1 = no;
        let rot = no;
        let xor = no;
        let foreign_field_mul = no;
        let lookup = no;

        if let OptFlag::Maybe = hack_feature_flags {
            let range_check_lookup = {
                let first = range_check0.or(&range_check1, w);
                first.or(&rot, w)
            };
            let lookups_per_row_4 = {
                let first = xor.or(&range_check_lookup, w);
                first.or(&foreign_field_mul, w)
            };
            let _lookups_per_row_3 = lookups_per_row_4.or(&lookup, w);
        };
    }

    pub struct FinalizeOtherProofParams<'a> {
        pub max_proof_verified: usize,
        pub feature_flags: &'a FeatureFlags<OptFlag>,
        pub step_domains: &'a ForStepKind<Box<[Domains]>>,
        pub sponge: Sponge<Fp>,
        pub prev_challenges: &'a [[Fp; Fp::NROUNDS]],
        pub deferred_values: &'a DeferredValues<Fp>,
        pub evals: &'a AllEvals<Fp>,
        pub hack_feature_flags: OptFlag,
        pub zk_rows: u64,
    }

    pub fn finalize_other_proof(
        params: FinalizeOtherProofParams,
        w: &mut Witness<Fp>,
    ) -> anyhow::Result<(Boolean, Vec<Fp>)> {
        let FinalizeOtherProofParams {
            max_proof_verified,
            feature_flags: _,
            step_domains,
            mut sponge,
            prev_challenges,
            deferred_values,
            evals,
            hack_feature_flags,
            zk_rows,
        } = params;

        let DeferredValues {
            plonk,
            combined_inner_product,
            b,
            xi,
            bulletproof_challenges,
            branch_data,
        } = deferred_values;

        validate_feature_flags(hack_feature_flags, w);

        let AllEvals { ft_eval1, evals } = evals;

        let actual_width_mask = &branch_data.proofs_verified;
        let actual_width_mask = proof_verified_to_prefix(actual_width_mask);

        let (_, endo) = endos::<Fq>();
        let scalar = |b: &[u64; 2], w: &mut Witness<Fp>| -> Fp {
            let scalar = two_u64_to_field(b);
            to_field_checked::<Fp, 128>(scalar, endo, w)
        };

        let plonk = {
            let Plonk {
                alpha,
                beta,
                gamma,
                zeta,
                zeta_to_srs_length,
                zeta_to_domain_size,
                perm,
                feature_flags,
                lookup: _,
            } = plonk;

            // We decompose this way because of OCaml evaluation order
            // let lookup = lookup.as_ref().map(|lookup| scalar(lookup, w));
            let lookup = match hack_feature_flags {
                OptFlag::No => None,
                OptFlag::Maybe => {
                    // TODO: Hack
                    // This assumes that `plonk.lookup` (just above) is [0, 0]
                    // <https://github.com/MinaProtocol/mina/blob/a51f09d09e6ae83362ea74eaca072c8e40d08b52/src/lib/pickles/composition_types/composition_types.ml#L131>
                    Some(scalar(&[0, 0], w))
                }
                OptFlag::Yes => todo!(),
            };
            let zeta = scalar(zeta, w);
            let alpha = scalar(alpha, w);

            InCircuit {
                alpha,
                beta: two_u64_to_field(beta),
                gamma: two_u64_to_field(gamma),
                zeta,
                zeta_to_domain_size: zeta_to_domain_size.clone(),
                zeta_to_srs_length: zeta_to_srs_length.clone(),
                perm: perm.clone(),
                lookup,
                feature_flags: feature_flags.clone(),
            }
        };

        let domain: Rc<dyn PlonkDomain<Fp>> = match step_domains {
            ForStepKind::Known(ds) => Rc::new(domain_for_compiled(ds, branch_data, w)),
            ForStepKind::SideLoaded(()) => unimplemented!("side-loaded verification keys"),
        };

        let zetaw = field::mul(domain.generator(), plonk.zeta, w);

        let sg_olds = prev_challenges
            .iter()
            .map(|chals| challenge_polynomial_checked(chals))
            .collect::<Vec<_>>();

        let (sg_evals1, sg_evals2) = {
            let sg_evals = |pt: Fp, w: &mut Witness<Fp>| {
                let ntrim_front = 2 - max_proof_verified;

                let mut sg = sg_olds
                    .iter()
                    .zip(&actual_width_mask[ntrim_front..])
                    .rev()
                    .map(|(f, keep)| (*keep, f(pt, w)))
                    .collect::<Vec<_>>();
                sg.reverse();
                sg
            };

            // We decompose this way because of OCaml evaluation order
            let sg_evals2 = sg_evals(zetaw, w);
            let sg_evals1 = sg_evals(plonk.zeta, w);
            (sg_evals1, sg_evals2)
        };

        // sponge state
        {
            let challenge_digest = {
                let ntrim_front = 2 - max_proof_verified;

                let mut sponge = OptSponge::create();
                prev_challenges
                    .iter()
                    .zip(&actual_width_mask[ntrim_front..])
                    .for_each(|(chals, keep)| {
                        let keep = CircuitVar::Var(*keep);
                        for chal in chals {
                            sponge.absorb((keep, *chal));
                        }
                    });
                sponge.squeeze(w)
            };

            sponge.absorb2(&[challenge_digest], w);
            sponge.absorb(&[*ft_eval1], w);
            sponge.absorb(&evals.public_input.0, w);
            sponge.absorb(&evals.public_input.1, w);

            for eval in &to_absorption_sequence_opt(&evals.evals, hack_feature_flags) {
                match eval {
                    Opt::No => {}
                    Opt::Some(PointEvaluations { zeta, zeta_omega }) => {
                        sponge.absorb(zeta, w);
                        sponge.absorb(zeta_omega, w);
                    }
                    Opt::Maybe(b, PointEvaluations { zeta, zeta_omega }) => {
                        let sponge_state_before = sponge.sponge_state.clone();
                        let state_before = sponge.state;

                        sponge.absorb(zeta, w);
                        sponge.absorb(zeta_omega, w);

                        // TODO: Does it panic in OCaml ?
                        use ::poseidon::SpongeState::{Absorbed, Squeezed};
                        match (sponge_state_before, &sponge.sponge_state) {
                            (Absorbed(x), Absorbed(y)) => assert_eq!(x, *y),
                            (Squeezed(x), Squeezed(y)) => assert_eq!(x, *y),
                            (Absorbed(_), Squeezed(_)) => panic!(),
                            (Squeezed(_), Absorbed(_)) => panic!(),
                        }

                        sponge
                            .state
                            .iter_mut()
                            .zip(state_before)
                            .for_each(|(then, else_)| {
                                *then = w.exists_no_check(match b {
                                    Boolean::True => *then,
                                    Boolean::False => else_,
                                })
                            });
                    }
                }
            }
        };

        let xi_actual = lowest_128_bits(sponge.squeeze(w), true, w);
        let r_actual = lowest_128_bits(sponge.squeeze(w), true, w);

        let xi_correct = field::equal(xi_actual, two_u64_to_field(xi), w);

        let xi = scalar(xi, w);
        let r = to_field_checked::<Fp, 128>(r_actual, endo, w);

        let to_bytes = |f: Fp| {
            let bigint: BigInteger256 = f.into();
            bigint.0
        };

        let plonk_mininal = PlonkMinimal::<Fp, 4> {
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
            feature_flags: FeatureFlags::empty_bool(), // TODO
        };

        let combined_evals = {
            let mut pow2pow =
                |f: Fp| (0..COMMON_MAX_DEGREE_STEP_LOG2).fold(f, |acc, _| field::square(acc, w));

            let zeta_n = pow2pow(plonk.zeta);
            let zetaw_n = pow2pow(zetaw);

            evals
                .evals
                .map_ref(&|PointEvaluations { zeta, zeta_omega }| {
                    let zeta = actual_evaluation(zeta, zeta_n);
                    let zeta_omega = actual_evaluation(zeta_omega, zetaw_n);
                    PointEvaluations { zeta, zeta_omega }
                })
        };

        let srs_length_log2 = COMMON_MAX_DEGREE_STEP_LOG2;
        let env = make_scalars_env_checked(
            MakeScalarsEnvParams {
                minimal: &plonk_mininal,
                domain,
                srs_length_log2,
                hack_feature_flags,
                zk_rows,
            },
            w,
        );
        let combined_inner_product_correct = {
            let p_eval0 = &evals.public_input.0;

            let ft_eval0 = ft_eval0(&env, &combined_evals, &plonk_mininal, p_eval0, w);
            let a = proof_evaluation_to_list_opt(&evals.evals, hack_feature_flags)
                .into_iter()
                .filter_map(|v| match v {
                    Opt::No => None,
                    Opt::Some(PointEvaluations { zeta, zeta_omega }) => Some([
                        zeta.into_iter().map(Opt::Some).collect::<Vec<_>>(),
                        zeta_omega.into_iter().map(Opt::Some).collect::<Vec<_>>(),
                    ]),
                    Opt::Maybe(boolean, PointEvaluations { zeta, zeta_omega }) => Some([
                        zeta.into_iter()
                            .map(|a| Opt::Maybe(boolean, a))
                            .collect::<Vec<_>>(),
                        zeta_omega
                            .into_iter()
                            .map(|a| Opt::Maybe(boolean, a))
                            .collect::<Vec<_>>(),
                    ]),
                })
                .collect::<Vec<_>>();

            let actual_combined_inner_product = {
                enum WhichEval {
                    First,
                    Second,
                }

                let combine = |which_eval: WhichEval,
                               sg_evals: &[(Boolean, Fp)],
                               ft_eval: Fp,
                               x_hat: &[Fp],
                               w: &mut Witness<Fp>| {
                    let f = |[a, b]: &[Vec<Opt<Fp>>; 2]| match which_eval {
                        WhichEval::First => a.clone(),
                        WhichEval::Second => b.clone(),
                    };
                    let v = sg_evals
                        .iter()
                        .copied()
                        .map(|(b, v)| Opt::Maybe(b, v))
                        .chain(x_hat.iter().copied().map(Opt::Some).collect::<Vec<_>>())
                        .chain([Opt::Some(ft_eval)])
                        .chain(a.iter().flat_map(f))
                        .rev()
                        .collect::<Vec<_>>();
                    let (init, rest) = v.split_at(1);

                    let init = match init[0] {
                        Opt::Some(x) => x,
                        Opt::No => Fp::zero(),
                        Opt::Maybe(b, x) => field::mul(b.to_field(), x, w),
                    };
                    rest.iter().fold(init, |acc: Fp, fx: &Opt<Fp>| match fx {
                        Opt::No => acc,
                        Opt::Some(fx) => *fx + field::mul(xi, acc, w),
                        Opt::Maybe(b, fx) => {
                            let on_true = *fx + field::mul(xi, acc, w);
                            w.exists_no_check(match b {
                                Boolean::True => on_true,
                                Boolean::False => acc,
                            })
                        }
                    })
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

            let combined_inner_product =
                ShiftingValue::<Fp>::shifted_to_field(combined_inner_product);
            field::equal(combined_inner_product, actual_combined_inner_product, w)
        };

        let mut bulletproof_challenges = bulletproof_challenges
            .iter()
            .rev()
            .map(|f| to_field_checked::<Fp, 128>(*f, endo, w))
            .collect::<Vec<_>>();
        bulletproof_challenges.reverse();

        let b_correct = {
            let challenge_poly = challenge_polynomial_checked(&bulletproof_challenges);

            // We decompose this way because of OCaml evaluation order
            let r_zetaw = field::mul(r, challenge_poly(zetaw, w), w);
            let b_actual = challenge_poly(plonk.zeta, w) + r_zetaw;

            field::equal(b.shifted_to_field(), b_actual, w)
        };

        let plonk = wrap_verifier::PlonkWithField {
            alpha: plonk.alpha,
            beta: plonk.beta,
            gamma: plonk.gamma,
            zeta: plonk.zeta,
            zeta_to_srs_length: plonk.zeta_to_srs_length,
            zeta_to_domain_size: plonk.zeta_to_domain_size,
            perm: plonk.perm,
            lookup: (),
        };
        let plonk_checks_passed = plonk_checks::checked(&env, &combined_evals, &plonk, w);

        let finalized = Boolean::all(
            &[
                xi_correct,
                b_correct,
                combined_inner_product_correct,
                plonk_checks_passed,
            ],
            w,
        );

        Ok((finalized, bulletproof_challenges))
    }

    pub fn sponge_after_index(
        index: &PlonkVerificationKeyEvals<Fp>,
        w: &mut Witness<Fp>,
    ) -> Sponge<Fp> {
        let mut sponge = Sponge::<Fp>::new();
        let fields = index.to_field_elements_owned();
        sponge.absorb2(&fields, w);
        sponge
    }

    pub fn hash_messages_for_next_step_proof_opt(
        msg: ReducedMessagesForNextStepProof,
        sponge: Sponge<Fp>,
        _widths: &ForStepKind<Vec<Fp>>,
        _max_width: usize,
        proofs_verified_mask: &[Boolean],
        w: &mut Witness<Fp>,
    ) -> Fp {
        enum MaybeOpt<T, T2> {
            Opt(Boolean, T),
            NotOpt(T2),
        }

        let ReducedMessagesForNextStepProof {
            app_state,
            challenge_polynomial_commitments,
            old_bulletproof_challenges,
        } = msg;

        let old_bulletproof_challenges = proofs_verified_mask
            .iter()
            .zip(old_bulletproof_challenges)
            .map(|(b, v)| {
                let b = *b;
                v.map(|v| MaybeOpt::Opt(b, v))
            });

        let challenge_polynomial_commitments = proofs_verified_mask
            .iter()
            .zip(challenge_polynomial_commitments)
            .map(|(b, v)| {
                let b = *b;
                let GroupAffine::<Fp> { x, y, .. } = v.to_affine();
                [MaybeOpt::Opt(b, x), MaybeOpt::Opt(b, y)]
            });

        let app_state = app_state
            .to_field_elements_owned()
            .into_iter()
            .map(MaybeOpt::NotOpt);

        let both = challenge_polynomial_commitments
            .zip(old_bulletproof_challenges)
            .flat_map(|(c, o)| c.into_iter().chain(o));

        let sponge = Box::new(sponge);
        let res = app_state
            .chain(both)
            .fold(MaybeOpt::NotOpt(sponge), |acc, v| match (acc, v) {
                (MaybeOpt::NotOpt(mut sponge), MaybeOpt::NotOpt(v)) => {
                    sponge.absorb(&[v], w);
                    MaybeOpt::NotOpt(sponge)
                }
                (MaybeOpt::NotOpt(sponge), MaybeOpt::Opt(b, v)) => {
                    let mut sponge = Box::new(OptSponge::of_sponge(*sponge, w));
                    sponge.absorb((CircuitVar::Var(b), v));
                    MaybeOpt::Opt(Boolean::True, sponge)
                }
                (MaybeOpt::Opt(_, mut sponge), MaybeOpt::Opt(b, v)) => {
                    sponge.absorb((CircuitVar::Var(b), v));
                    MaybeOpt::Opt(Boolean::True, sponge)
                }
                (MaybeOpt::Opt(_, _), MaybeOpt::NotOpt(_)) => panic!(),
            });

        match res {
            MaybeOpt::NotOpt(mut sponge) => sponge.squeeze(w),
            MaybeOpt::Opt(_, mut sponge) => sponge.squeeze(w),
        }
    }

    // TODO: Dedup with the one in `wrap_verifier`
    fn scale_fast2<F: FieldWitness>(
        g: CircuitVar<GroupAffine<F>>,
        (s_div_2, s_odd): (F, Boolean),
        num_bits: usize,
        w: &mut Witness<F>,
    ) -> GroupAffine<F> {
        use ledger::proofs::transaction::plonk_curve_ops::scale_fast_unpack;
        use wrap_verifier::*;

        let s_div_2_bits = num_bits - 1;
        let chunks_needed = chunks_needed(s_div_2_bits);
        let actual_bits_used = chunks_needed * OPS_BITS_PER_CHUNK;

        let g_value = *g.value();
        let shifted = F::Shifting::of_raw(s_div_2);
        let h = match actual_bits_used {
            255 => scale_fast_unpack::<F, F, 255>(g_value, shifted, w).0,
            130 => scale_fast_unpack::<F, F, 130>(g_value, shifted, w).0,
            10 => scale_fast_unpack::<F, F, 10>(g_value, shifted, w).0,
            // a one-bit value (the low bit of a split one): its high part is constrained to 0
            0 => scale_fast_unpack::<F, F, 0>(g_value, shifted, w).0,
            n => todo!("{:?} param_num_bits={:?}", n, num_bits),
        };

        let on_false = {
            let g_neg = g.value().neg();
            if let CircuitVar::Var(_) = g {
                w.exists(g_neg.y);
            } else {
                // eprintln!("ignoring {:?}", g_neg.y);
            }
            w.add_fast(h, g_neg)
        };

        w.exists_no_check(match s_odd {
            Boolean::True => h,
            Boolean::False => on_false,
        })
    }

    // TODO: Dedup with the one above and in `wrap_verifier`
    fn scale_fast22<F: FieldWitness>(
        g: CircuitVar<GroupAffine<F>>,
        (s_div_2, s_odd): (F, Boolean),
        num_bits: usize,
        w: &mut Witness<F>,
    ) -> GroupAffine<F> {
        use ledger::proofs::transaction::plonk_curve_ops::scale_fast_unpack;
        use wrap_verifier::*;

        let s_div_2_bits = num_bits - 1;
        let chunks_needed = chunks_needed(s_div_2_bits);
        let actual_bits_used = chunks_needed * OPS_BITS_PER_CHUNK;

        let g_value = *g.value();
        let shifted = F::Shifting::of_raw(s_div_2);
        let h = match actual_bits_used {
            255 => scale_fast_unpack::<F, F, 255>(g_value, shifted, w).0,
            130 => scale_fast_unpack::<F, F, 130>(g_value, shifted, w).0,
            10 => scale_fast_unpack::<F, F, 10>(g_value, shifted, w).0,
            // a one-bit value (the low bit of a split one): its high part is constrained to 0
            0 => scale_fast_unpack::<F, F, 0>(g_value, shifted, w).0,
            n => todo!("{:?} param_num_bits={:?}", n, num_bits),
        };

        let on_false = {
            let g_neg = w.exists_no_check(g.value().neg());
            w.add_fast(h, g_neg)
        };

        w.exists_no_check(match s_odd {
            Boolean::True => h,
            Boolean::False => on_false,
        })
    }

    // TODO: Dedup with the one in `wrap_verifier`
    pub fn scale_fast2_prime<F: FieldWitness, F2: FieldWitness>(
        g: CircuitVar<GroupAffine<F>>,
        s: F2,
        num_bits: usize,
        w: &mut Witness<F>,
    ) -> GroupAffine<F> {
        let s_parts = w.exists({
            // TODO: Here `s` is a `F` but needs to be read as a `F::Scalar`
            let bigint: BigInteger256 = s.into();
            let bigint = bigint.0;
            let s_odd = bigint[0] & 1 != 0;
            let v = if s_odd { s - F2::one() } else { s };
            // TODO: Remove this ugly hack
            let v: BigInteger256 = (v / F2::from(2u64)).into();
            (F::from(v), s_odd.to_boolean()) // `unwrap` never fail
        });

        scale_fast2(g, s_parts, num_bits, w)
    }

    // TODO: Dedup with the one in `wrap_verifier`
    pub fn ft_comm<F: FieldWitness, Scale>(
        plonk: &Plonk<<F as proofs::field::FieldWitness>::Scalar>,
        t_comm: &PolyComm<GroupAffine<F>>,
        verification_key: &CircuitPlonkVerificationKeyEvals<F>,
        scale: Scale,
        w: &mut Witness<F>,
    ) -> GroupAffine<F>
    where
        Scale: Fn(
            CircuitVar<GroupAffine<F>>,
            <<F as proofs::field::FieldWitness>::Scalar as FieldWitness>::Shifting,
            &mut Witness<F>,
        ) -> GroupAffine<F>,
    {
        let m = verification_key;
        let [sigma_comm_last] = &m.sigma[PERMUTS_MINUS_1_ADD_N1..] else {
            panic!()
        };

        // We decompose this way because of OCaml evaluation order (reversed)
        let f_comm = [scale(*sigma_comm_last, plonk.perm.clone(), w)]
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
                let scaled = scale(CircuitVar::Var(acc), plonk.zeta_to_srs_length.clone(), w);
                w.add_fast(v, scaled)
            })
            .unwrap();

        // We decompose this way because of OCaml evaluation order
        let scaled = scale(
            CircuitVar::Var(chunked_t_comm),
            plonk.zeta_to_domain_size.clone(),
            w,
        )
        .neg();
        let v = w.add_fast(f_comm, chunked_t_comm);

        // Because of `neg()` above
        w.exists_no_check(scaled.y);

        w.add_fast(v, scaled)
    }

    fn multiscale_known(ts: &[(&Packed, InnerCurve<Fp>)], w: &mut Witness<Fp>) -> GroupAffine<Fp> {
        let pow2pow = |x: InnerCurve<Fp>, n: usize| (0..n).fold(x, |acc, _| acc.clone() + acc);

        let (constant_part, non_constant_part): (Vec<_>, Vec<_>) =
            ts.iter().partition_map(|(t, g)| {
                use itertools::Either::{Left, Right};
                use CircuitVar::Constant;
                use Packed::{Field, PackedBits};

                match t {
                    Field(Constant(c)) | PackedBits(Constant(c), _) => Left(if c.is_zero() {
                        None
                    } else if c.is_one() {
                        Some(g)
                    } else {
                        todo!()
                    }),
                    Field(x) => Right((Field(*x), g)),
                    PackedBits(x, n) => Right((PackedBits(*x, *n), g)),
                }
            });

        let add_opt = |xo: Option<InnerCurve<Fp>>, y: &InnerCurve<Fp>| match xo {
            Some(x) => x + y.clone(),
            None => y.clone(),
        };

        let constant_part = constant_part
            .iter()
            .filter_map(|c| c.as_ref())
            .fold(None, |acc, x| Some(add_opt(acc, x)));

        let (correction, acc) = {
            non_constant_part
                .iter()
                .map(|(s, x)| {
                    let (rr, n) = match s {
                        Packed::PackedBits(s, n) => {
                            let x = CircuitVar::Constant(x.to_affine());
                            let c = scale_fast2_prime(x, s.as_field(), *n, w);
                            (c, *n)
                        }
                        Packed::Field(s) => {
                            let x = CircuitVar::Constant(x.to_affine());
                            let c = scale_fast2_prime(x, s.as_field(), 255, w);
                            (c, 255)
                        }
                    };

                    let n = wrap_verifier::OPS_BITS_PER_CHUNK * wrap_verifier::chunks_needed(n - 1);
                    let cc = pow2pow((*x).clone(), n);
                    (cc, rr)
                })
                .collect::<Vec<_>>() // We need to collect because `w` is borrowed :(
                .into_iter()
                .reduce(|(a1, b1), (a2, b2)| ((a1 + a2), w.add_fast(b1, b2)))
                .unwrap()
        };

        let correction = InnerCurve::of_affine(correction.to_affine().neg());
        w.add_fast(acc, add_opt(constant_part, &correction).to_affine())
    }

    fn lagrange_commitment<F: FieldWitness>(
        srs: &mut SRS<GroupAffine<F>>,
        domain: &Domain,
        i: usize,
    ) -> InnerCurve<F> {
        let d = domain.size();
        let elems = wrap_verifier::lagrange_commitment::<F>(srs, d, i).chunks;

        assert_eq!(elems.len(), 1);
        InnerCurve::of_affine(elems[0])
    }

    fn to_high_low(f: Fq) -> (Fp, Boolean) {
        fn of_bits<F: FieldWitness>(bs: &[bool; 254]) -> F {
            bs.iter().rev().fold(F::zero(), |acc, b| {
                let acc = acc + acc;
                if *b {
                    acc + F::one()
                } else {
                    acc
                }
            })
        }
        let to_high_low = |fq: Fq| {
            let [low, high @ ..] = ledger::proofs::transaction::field_to_bits::<Fq, 255>(fq);
            (of_bits::<Fp>(&high), low.to_boolean())
        };
        to_high_low(f)
    }

    fn scale_for_ft_comm(
        g: CircuitVar<GroupAffine<Fp>>,
        f: <Fq as FieldWitness>::Shifting,
        w: &mut Witness<Fp>,
    ) -> GroupAffine<Fp> {
        let scalar = to_high_low(f.shifted_raw());
        scale_fast2(g, scalar, 255, w)
    }

    struct CheckBulletProofParams<'a> {
        sponge: Sponge<Fp>,
        xi: [u64; 2],
        advice: &'a Advice<Fp>,
        openings_proof: &'a OpeningProof<GroupAffine<Fp>, { ledger::proofs::FULL_ROUNDS }>,
        srs: &'a SRS<GroupAffine<Fp>>,
        polynomials: (Vec<CircuitVar<GroupAffine<Fp>>>, Vec<()>),
    }

    fn check_bulletproof(
        params: CheckBulletProofParams,
        w: &mut Witness<Fp>,
    ) -> anyhow::Result<(Boolean, Vec<Fp>)> {
        let CheckBulletProofParams {
            mut sponge,
            xi,
            advice,
            openings_proof:
                OpeningProof {
                    lr,
                    delta,
                    z1,
                    z2,
                    sg,
                },
            srs,
            polynomials,
        } = params;

        let (without_degree_bound, _with_degree_bound) = polynomials;

        let (high, low) = to_high_low(advice.combined_inner_product.shifted_raw());
        sponge.absorb2(&[high, low.to_field()], w);

        let u = {
            let t = sponge.squeeze(w);
            wrap_verifier::group_map(t, w)
        };

        let xi_field: Fq = two_u64_to_field(&xi);

        let point: Point<Fp> = PcsBatch::combine_split_commitments::<Fp, _, _, _, _>(
            |p, _w| p.clone(),
            |acc, _xi, p, w| match acc {
                Point::MaybeFinite(acc_is_finite, acc) => match p {
                    Point::MaybeFinite(p_is_finite, p) => {
                        let is_finite = p_is_finite.or(&acc_is_finite, w);
                        let xi_acc = endo_cvar::<Fp, _, 128>(acc, xi_field, w);

                        let on_true = CircuitVar::Var(w.add_fast(*p.value(), xi_acc));

                        let v = match acc_is_finite.as_boolean() {
                            Boolean::True => on_true,
                            Boolean::False => *p,
                        };
                        if let CircuitVar::Var(_) = acc_is_finite {
                            w.exists_no_check(v.value());
                        };
                        Point::<Fp>::MaybeFinite(is_finite, v)
                    }
                    Point::Finite(p) => {
                        let xi_acc = endo_cvar::<Fp, _, 128>(acc, xi_field, w);
                        let on_true = CircuitVar::Var(w.add_fast(*p.value(), xi_acc));

                        let v = match acc_is_finite.as_boolean() {
                            Boolean::True => on_true,
                            Boolean::False => *p,
                        };
                        if let CircuitVar::Var(_) = acc_is_finite {
                            w.exists_no_check(v.value());
                        };
                        Point::<Fp>::Finite(v)
                    }
                },
                Point::Finite(acc) => {
                    let xi_acc = endo_cvar::<Fp, _, 128>(acc, xi_field, w);

                    let v = match p {
                        Point::Finite(p) => CircuitVar::Var(w.add_fast(*p.value(), xi_acc)),
                        Point::MaybeFinite(p_is_finite, p) => {
                            let p = *p;
                            let on_true = CircuitVar::Var(w.add_fast(*p.value(), xi_acc));

                            let v = match p_is_finite.as_boolean() {
                                Boolean::True => on_true,
                                Boolean::False => CircuitVar::Var(xi_acc),
                            };
                            if let CircuitVar::Var(_) = p_is_finite {
                                w.exists_no_check(v.value());
                            };
                            v
                        }
                    };

                    Point::Finite(v)
                }
            },
            xi,
            &without_degree_bound
                .into_iter()
                .map(Point::Finite)
                .collect::<Vec<_>>(),
            &[],
            w,
        );

        let Point::Finite(combined_polynomial) = point else {
            panic!("invalid state");
        };
        let combined_polynomial = *combined_polynomial.value();

        let (lr_prod, challenges) = bullet_reduce(&mut sponge, lr, w);

        let p_prime = {
            w.exists_no_check(&u); // Made by `plonk_curve_ops.seal` in `scale_fast`
            let combined_inner_product = to_high_low(advice.combined_inner_product.shifted_raw());
            let uc = scale_fast22(CircuitVar::Var(u), combined_inner_product, 255, w);
            w.add_fast(combined_polynomial, uc)
        };

        let q = w.add_fast(p_prime, lr_prod);
        absorb_curve(delta, &mut sponge, w);
        let c = squeeze_scalar(&mut sponge, w);

        let lhs = {
            let cq = endo::<Fp, Fp, 128>(q, c, w);
            w.add_fast(cq, *delta)
        };

        let rhs = {
            let b_u = {
                w.exists_no_check(&u); // Made by `plonk_curve_ops.seal` in `scale_fast`
                let b = to_high_low(advice.b.shifted_raw());
                scale_fast22(CircuitVar::Var(u), b, 255, w)
            };

            let z_1_g_plus_b_u = {
                use plonk_checks::ShiftedValue;

                let z1 = to_high_low(ShiftedValue::<Fq>::of_field(*z1).shifted);
                scale_fast2(CircuitVar::Var(w.add_fast(*sg, b_u)), z1, 255, w)
            };

            let z2_h = {
                use plonk_checks::ShiftedValue;

                let z2 = to_high_low(ShiftedValue::<Fq>::of_field(*z2).shifted);
                scale_fast2(CircuitVar::Constant(srs.h), z2, 255, w)
            };

            w.add_fast(z_1_g_plus_b_u, z2_h)
        };

        Ok((wrap_verifier::equal_g(lhs, rhs, w), challenges))
    }

    struct IncrementallyVerifyProofParams<'a> {
        pub srs: &'a mut poly_commitment::ipa::SRS<Pallas>,
        pub wrap_domain: &'a ForStepKind<Domain, Box<[Boolean]>>,
        pub sponge: Sponge<Fp>,
        pub sponge_after_index: Sponge<Fp>,
        pub wrap_verification_key: &'a CircuitPlonkVerificationKeyEvals<Fp>,
        pub xi: [u64; 2],
        pub public_input: Vec<Packed>,
        pub sg_old: &'a Vec<GroupAffine<Fp>>,
        pub advice: &'a Advice<Fp>,
        pub proof: &'a ProverProof<Fq>,
        pub plonk: &'a Plonk<Fq>,
    }

    fn incrementally_verify_proof(
        params: IncrementallyVerifyProofParams,
        w: &mut Witness<Fp>,
    ) -> anyhow::Result<(Fp, (Boolean, Vec<Fp>))> {
        let IncrementallyVerifyProofParams {
            srs,
            wrap_domain,
            mut sponge,
            sponge_after_index,
            wrap_verification_key,
            xi,
            public_input,
            sg_old,
            advice,
            proof,
            plonk,
        } = params;

        let ProverProof::<Fq> {
            commitments: messages,
            proof: openings_proof,
            ..
            // evals,
            // ft_eval1,
            // prev_challenges
        } = proof;

        let sample = squeeze_challenge;
        let sample_scalar = squeeze_scalar;

        let index_digest = {
            let mut index_sponge = sponge_after_index.clone();
            index_sponge.squeeze(w)
        };

        sponge.absorb2(&[index_digest], w);

        // `Wrap_hack.Checked.pad_commitments`: the accumulators, padded in front with the dummy, to two
        let mut padded = sg_old.clone();
        while padded.len() < 2 {
            padded.insert(0, ledger::proofs::wrap::dummy_ipa_wrap_sg());
        }
        let sg_old = &padded;
        for v in sg_old {
            absorb_curve(v, &mut sponge, w);
        }

        let x_hat = match wrap_domain {
            ForStepKind::Known(domain) => {
                let ts = public_input
                    .iter()
                    .enumerate()
                    .map(|(i, x)| (x, lagrange_commitment::<Fp>(srs, domain, i)))
                    .collect::<Vec<_>>();
                multiscale_known(&ts, w).neg()
            }
            ForStepKind::SideLoaded(_) => unimplemented!("side-loaded verification keys"),
        };

        let x_hat = {
            w.exists(x_hat.y); // Because of `.neg()` above
            w.add_fast(x_hat, srs.h)
        };

        absorb_curve(&x_hat, &mut sponge, w);

        let w_comm = &messages.w_comm;
        for g in w_comm.iter().flat_map(|w| &w.chunks) {
            absorb_curve(g, &mut sponge, w);
        }

        let _beta = sample(&mut sponge, w);
        let _gamma = sample(&mut sponge, w);

        let z_comm = &messages.z_comm;
        for z in z_comm.chunks.iter() {
            absorb_curve(z, &mut sponge, w);
        }

        let _alpha = sample_scalar(&mut sponge, w);

        let t_comm = &messages.t_comm;
        for t in t_comm.chunks.iter() {
            absorb_curve(t, &mut sponge, w);
        }

        let _zeta = sample_scalar(&mut sponge, w);

        let sponge_before_evaluations = sponge.clone();
        let sponge_digest_before_evaluations = sponge.squeeze(w);

        let sigma_comm_init = &wrap_verification_key.sigma[..PERMUTS_MINUS_1_ADD_N1];

        let ft_comm = ft_comm(plonk, t_comm, wrap_verification_key, scale_for_ft_comm, w);

        let bulletproof_challenges = {
            let cvar = CircuitVar::Var;

            let without_degree_bound = {
                let sg_old = sg_old.iter().copied().map(cvar);
                let rest = [cvar(x_hat), cvar(ft_comm)]
                    .into_iter()
                    .chain(z_comm.chunks.iter().cloned().map(cvar))
                    .chain([
                        wrap_verification_key.generic,
                        wrap_verification_key.psm,
                        wrap_verification_key.complete_add,
                        wrap_verification_key.mul,
                        wrap_verification_key.emul,
                        wrap_verification_key.endomul_scalar,
                    ])
                    .chain(
                        w_comm
                            .iter()
                            .flat_map(|w| w.chunks.iter().cloned().map(cvar)),
                    )
                    .chain(wrap_verification_key.coefficients)
                    .chain(sigma_comm_init.iter().cloned());
                sg_old.chain(rest).collect::<Vec<_>>()
            };

            check_bulletproof(
                CheckBulletProofParams {
                    sponge: sponge_before_evaluations,
                    xi,
                    advice,
                    openings_proof,
                    srs,
                    polynomials: (without_degree_bound, vec![]),
                },
                w,
            )?
        };

        Ok((sponge_digest_before_evaluations, bulletproof_challenges))
    }

    pub struct VerifyParams<'a> {
        pub srs: &'a mut poly_commitment::ipa::SRS<Pallas>,
        pub feature_flags: &'a FeatureFlags<OptFlag>,
        pub lookup_parameters: (),
        pub proofs_verified: usize,
        pub wrap_domain: &'a ForStepKind<Domain, Box<[Boolean]>>,
        pub is_base_case: CircuitVar<Boolean>,
        pub sponge_after_index: Sponge<Fp>,
        pub sg_old: &'a Vec<GroupAffine<Fp>>,
        pub proof: &'a ProverProof<Fq>,
        pub wrap_verification_key: &'a CircuitPlonkVerificationKeyEvals<Fp>,
        pub statement: &'a PreparedStatement,
        pub hack_feature_flags: OptFlag,
        pub unfinalized: &'a Unfinalized,
    }

    pub fn verify(params: VerifyParams, w: &mut Witness<Fp>) -> anyhow::Result<Boolean> {
        let VerifyParams {
            srs,
            feature_flags: _,
            lookup_parameters: _,
            proofs_verified: _,
            wrap_domain,
            is_base_case,
            sponge_after_index,
            sg_old,
            proof,
            wrap_verification_key,
            statement,
            hack_feature_flags,
            unfinalized,
        } = params;

        let public_input = {
            let npublic_input = match hack_feature_flags {
                OptFlag::No => 39,
                OptFlag::Maybe => 40,
                OptFlag::Yes => todo!(),
            };
            statement.to_public_input_cvar(hack_feature_flags, npublic_input)?
        };

        let unfinalized::DeferredValues {
            plonk,
            combined_inner_product,
            b,
            xi,
            bulletproof_challenges: _,
        } = &unfinalized.deferred_values;

        let b = b.clone();
        let combined_inner_product = combined_inner_product.clone();
        let sponge = Sponge::new();

        let (
            _sponge_digest_before_evaluations_actual,
            (bulletproof_success, bulletproof_challenges_actual),
        ) = incrementally_verify_proof(
            IncrementallyVerifyProofParams {
                srs,
                wrap_domain,
                sponge,
                sponge_after_index,
                wrap_verification_key,
                xi: *xi,
                public_input,
                sg_old,
                advice: &Advice {
                    b,
                    combined_inner_product,
                },
                proof,
                plonk,
            },
            w,
        )?;

        for (c1, c2) in unfinalized
            .deferred_values
            .bulletproof_challenges
            .iter()
            .zip(&bulletproof_challenges_actual)
        {
            let v = match is_base_case.value() {
                Boolean::True => two_u64_to_field(c1),
                Boolean::False => *c2,
            };
            if let CircuitVar::Var(_) = is_base_case {
                w.exists_no_check(v);
            };
        }

        Ok(bulletproof_success)
    }
}

pub struct VerifyOneParams<'a> {
    pub srs: &'a mut poly_commitment::ipa::SRS<Pallas>,
    pub proof: &'a PerProofWitness,
    pub data: &'a ForStep,
    pub messages_for_next_wrap_proof: Fp,
    pub unfinalized: &'a Unfinalized,
    pub should_verify: CircuitVar<Boolean>,
}

pub fn verify_one(params: VerifyOneParams, w: &mut Witness<Fp>) -> anyhow::Result<(Vec<Fp>, Boolean)> {
    let VerifyOneParams {
        srs,
        proof,
        data,
        messages_for_next_wrap_proof,
        unfinalized,
        should_verify,
    } = params;

    let PerProofWitness {
        app_state,
        wrap_proof,
        proof_state,
        prev_proof_evals,
        prev_challenges,
        prev_challenge_polynomial_commitments,
        hack_feature_flags,
    } = proof;

    let deferred_values = &proof_state.deferred_values;

    let (finalized, chals) = {
        let sponge_digest = proof_state.sponge_digest_before_evaluations;

        let sponge = {
            let mut sponge = ledger::proofs::transaction::poseidon::Sponge::<Fp>::new();
            sponge.absorb2(&[four_u64_to_field(&sponge_digest)?], w);
            sponge
        };

        step_verifier::finalize_other_proof(
            step_verifier::FinalizeOtherProofParams {
                max_proof_verified: data.max_proofs_verified,
                feature_flags: &data.feature_flags,
                step_domains: &data.step_domains,
                sponge,
                prev_challenges,
                deferred_values,
                evals: prev_proof_evals,
                hack_feature_flags: *hack_feature_flags,
                zk_rows: data.zk_rows,
            },
            w,
        )?
    };

    let branch_data = &deferred_values.branch_data;

    let sponge_after_index = step_verifier::sponge_after_index(&data.wrap_key.to_non_cvar(), w);

    let statement = {
        let msg = ReducedMessagesForNextStepProof {
            app_state: app_state.clone().unwrap(),
            challenge_polynomial_commitments: prev_challenge_polynomial_commitments
                .iter()
                .map(|g| InnerCurve::of_affine(*g))
                .collect(),
            old_bulletproof_challenges: prev_challenges.clone(),
        };

        let ntrim_front = 2 - prev_challenge_polynomial_commitments.len();
        let proofs_verified_mask = {
            let proofs_verified_mask = &branch_data.proofs_verified;
            step_verifier::proof_verified_to_prefix(proofs_verified_mask)
        };
        let proofs_verified_mask = &proofs_verified_mask[ntrim_front..];

        let prev_messages_for_next_step_proof =
            step_verifier::hash_messages_for_next_step_proof_opt(
                msg,
                sponge_after_index.clone(),
                &data.proof_verifieds,
                data.max_proofs_verified,
                proofs_verified_mask,
                w,
            );

        PreparedStatement {
            proof_state: ProofState {
                messages_for_next_wrap_proof: { to_bytes(messages_for_next_wrap_proof) },
                ..proof_state.clone()
            },
            messages_for_next_step_proof: { to_bytes(prev_messages_for_next_step_proof) },
        }
    };

    let verified = step_verifier::verify(
        step_verifier::VerifyParams {
            srs,
            feature_flags: &data.feature_flags,
            lookup_parameters: (),
            proofs_verified: data.max_proofs_verified,
            wrap_domain: &data.wrap_domain,
            is_base_case: should_verify.neg(),
            sponge_after_index,
            sg_old: prev_challenge_polynomial_commitments,
            proof: wrap_proof,
            wrap_verification_key: &data.wrap_key,
            statement: &statement,
            hack_feature_flags: *hack_feature_flags,
            unfinalized,
        },
        w,
    )?;

    let a = verified.and(&finalized, w);
    let b = CircuitVar::Var(a).or(&should_verify.neg(), w);

    Ok((chals, b.as_boolean()))
}

pub(super) fn to_bytes(f: Fp) -> [u64; 4] {
    let bigint: BigInteger256 = f.into();
    bigint.0
}
