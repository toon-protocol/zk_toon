//! Verifying one previous proof inside a step circuit, as Pickles' `step_main` does after the method:
//! what the previous proof contributes to the step witness, and to the step statement.
//!
//! `expand_proof` is derived from `expand_proof` in `crates/ledger/src/proofs/step.rs` of
//! `toon-protocol/mina-rust` at rev `6feeb3797fff6dba49fd848cb2d6decd63fee1b4` (itself from
//! `o1-labs/mina-rust` v0.19.0, Apache-2.0), where it is private to the crate. Mina `228c409a` (the
//! commit o1js v3.1.0 bundles), `src/lib/crypto/pickles/step_main.ml`, is the reference. Licensed under
//! Apache-2.0; see `LICENSE-APACHE` and `NOTICE`.

use anyhow::Context as _;
use ark_ff::BigInteger256;
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Radix2EvaluationDomain,
};
use kimchi::proof::PointEvaluations;
use ledger::proofs::{
    field::{Boolean, CircuitVar, FieldWitness, GroupAffine},
    public_input::{
        messages::MessagesForNextWrapProof,
        plonk_checks::{derive_plonk, PlonkMinimal, ShiftingValue},
        prepared_statement::{DeferredValues, Plonk, PreparedStatement, ProofState},
    },
    step::{
        ForStep, ForStepKind,
        expand_deferred, ExpandDeferredParams, FeatureFlags, OptFlag, PerProofWitness,
        StatementProofState,
    },
    to_field_elements::{ToFieldElements, ToFieldElementsDebug},
    transaction::{endos, make_group, messages_for_next_wrap_proof_padding, StepMainProofState, StepMainStatement, CircuitPlonkVerificationKeyEvals, InnerCurve, MessagesForNextStepProof},
    unfinalized::{dummy_ipa_step_challenges_computed, AllEvals, Unfinalized},
    util::{challenge_polynomial, extract_bulletproof, four_u64_to_field, two_u64_to_field},
    verification::{make_scalars_env, prev_evals_from_p2p},
    verifiers::{make_zkapp_verifier_index, wrap_domains},
    wrap::{
        Domain, Domains,
        combined_inner_product, create_oracle_with_public_input, dummy_ipa_wrap_sg, CombinedInnerProductParams, evals_of_split_evals,
        COMMON_MAX_DEGREE_STEP_LOG2, COMMON_MAX_DEGREE_WRAP_LOG2,
    }, VerifierIndex, BACKEND_TICK_ROUNDS_N, BACKEND_TOCK_ROUNDS_N,
};
use ledger::{verifier::{get_srs, get_srs_mut}, VerificationKey};
use super::{pickles::from_fork, step_verifier::{to_bytes, verify_one, VerifyOneParams}, Cs, Field, gadgets::poseidon::Sponge};
use crate::wrap::PreviousProof;
use mina_curves::pasta::{Fp, Fq};
use mina_p2p_messages::{bigint::InvalidBigInt, v2};
use poly_commitment::commitment::b_poly_coefficients;
use std::rc::Rc;

fn wrap_compute_sg(challenges: &[[u64; 2]]) -> GroupAffine<Fp> {
    use ledger::proofs::public_input::scalar_challenge::ScalarChallenge;

    let challenges = challenges
        .iter()
        .map(ScalarChallenge::limbs_to_field)
        .collect::<Vec<_>>();

    let coeffs = b_poly_coefficients(&challenges);
    let p = DensePolynomial::from_coefficients_vec(coeffs);

    let comm = {
        use poly_commitment::SRS;

        let srs = get_srs::<Fq>();
        srs.commit_non_hiding(&p, 1)
    };
    comm.chunks[0]
}

pub struct ExpandProofParams<'a> {
    pub dlog_vk: &'a VerifierIndex<Fq>,
    pub dlog_plonk_index: &'a CircuitPlonkVerificationKeyEvals<Fp>,
    pub app_state: &'a Rc<dyn ToFieldElementsDebug>,
    pub t: &'a v2::PicklesProofProofsVerified2ReprStableV2,
    pub public_input_length: usize,
    pub tag: (),
    pub must_verify: CircuitVar<Boolean>,
    pub hack_feature_flags: OptFlag,
    pub zk_rows: u64,
    /// `maxProofsVerified` of the program that made the proof: how many accumulators it carries.
    pub proofs_verified: usize,
}

pub fn expand_proof(params: ExpandProofParams) -> anyhow::Result<ExpandedProof> {
    let ExpandProofParams {
        dlog_vk,
        dlog_plonk_index,
        app_state,
        t,
        public_input_length,
        tag: _,
        must_verify,
        hack_feature_flags,
        zk_rows,
        proofs_verified,
    } = params;

    use ledger::proofs::public_input::scalar_challenge::ScalarChallenge;

    let plonk0: PlonkMinimal<Fp> = (&t.statement.proof_state.deferred_values.plonk).try_into()?;

    let plonk = {
        let domain: u8 = t
            .statement
            .proof_state
            .deferred_values
            .branch_data
            .domain_log2
            .as_u8();

        let alpha = ScalarChallenge::limbs_to_field(&plonk0.alpha_bytes);
        let zeta = ScalarChallenge::limbs_to_field(&plonk0.zeta_bytes);
        let w: Fp = Radix2EvaluationDomain::new(1 << domain).unwrap().group_gen;
        let zetaw = zeta * w;

        // dbg!(alpha, zeta, zetaw, dlog_vk.domain.log_size_of_group, domain);

        let es = prev_evals_from_p2p(&t.prev_evals.evals.evals)?;
        let combined_evals = evals_of_split_evals(zeta, zetaw, &es, BACKEND_TICK_ROUNDS_N);

        let plonk_minimal = PlonkMinimal::<Fp, 4> {
            alpha,
            beta: plonk0.beta,
            gamma: plonk0.gamma,
            zeta,
            joint_combiner: plonk0.joint_combiner,
            // joint_combiner: plonk0.joint_combiner_bytes.as_ref().map(ScalarChallenge::limbs_to_field),
            alpha_bytes: to_bytes(alpha),
            beta_bytes: to_4limbs(plonk0.beta_bytes),
            gamma_bytes: to_4limbs(plonk0.gamma_bytes),
            zeta_bytes: to_bytes(zeta),
            joint_combiner_bytes: plonk0.joint_combiner_bytes.map(to_4limbs),
            feature_flags: plonk0.feature_flags.clone(),
        };

        let srs_length_log2 = COMMON_MAX_DEGREE_STEP_LOG2;
        let env = make_scalars_env(&plonk_minimal, domain, srs_length_log2, zk_rows);

        derive_plonk(&env, &combined_evals, &plonk_minimal)
    };

    let statement = &t.statement;

    let prev_challenges: Vec<[Fq; BACKEND_TOCK_ROUNDS_N]> = {
        let old_bulletproof_challenges = &statement
            .proof_state
            .messages_for_next_wrap_proof
            .old_bulletproof_challenges;
        extract_bulletproof(&[
            old_bulletproof_challenges.0[0].0.clone(),
            old_bulletproof_challenges.0[1].0.clone(),
        ])
    };

    let old_bulletproof_challenges: Vec<[Fp; 16]> = statement
        .messages_for_next_step_proof
        .old_bulletproof_challenges
        .iter()
        .map(|v| {
            v.0.clone()
                .map(|v| two_u64_to_field(&v.prechallenge.inner.0.map(|v| v.as_u64())))
        })
        .collect();

    let deferred_values_computed = {
        let evals: AllEvals<Fp> = (&t.prev_evals).try_into()?;
        let proof_state: StatementProofState = (&statement.proof_state).try_into()?;

        expand_deferred(ExpandDeferredParams {
            evals: &evals,
            old_bulletproof_challenges: &old_bulletproof_challenges,
            proof_state: &proof_state,
            zk_rows,
        })?
    };

    let old_bulletproof_challenges: Vec<_> = old_bulletproof_challenges
        .iter()
        .map(ScalarChallenge::array_to_fields)
        .collect();

    let messages_for_next_step_proof = MessagesForNextStepProof {
        app_state: Rc::clone(app_state),
        dlog_plonk_index: &dlog_plonk_index.to_non_cvar(),
        challenge_polynomial_commitments: statement
            .messages_for_next_step_proof
            .challenge_polynomial_commitments
            .iter()
            .map(|(x, y)| {
                Ok(InnerCurve::of_affine(make_group(
                    x.to_field::<Fp>()?,
                    y.to_field()?,
                )))
            })
            .collect::<Result<_, InvalidBigInt>>()?,
        old_bulletproof_challenges: old_bulletproof_challenges.clone(),
    }
    .hash();

    let deferred_values = deferred_values_computed;
    let prev_statement_with_hashes = PreparedStatement {
        proof_state: ProofState {
            deferred_values: DeferredValues {
                plonk: Plonk {
                    alpha: plonk0.alpha_bytes,
                    beta: plonk0.beta_bytes,
                    gamma: plonk0.gamma_bytes,
                    zeta: plonk0.zeta_bytes,
                    zeta_to_srs_length: plonk.zeta_to_srs_length,
                    zeta_to_domain_size: plonk.zeta_to_domain_size,
                    perm: plonk.perm,
                    lookup: match plonk.lookup {
                        None => None,
                        Some(_) => Some(plonk0.joint_combiner_bytes.unwrap()),
                    },
                    feature_flags: plonk.feature_flags,
                },
                combined_inner_product: deferred_values.combined_inner_product,
                b: deferred_values.b,
                xi: deferred_values.xi,
                bulletproof_challenges: statement
                    .proof_state
                    .deferred_values
                    .bulletproof_challenges
                    .iter()
                    .map(|challenge| {
                        two_u64_to_field(
                            &challenge.prechallenge.inner.each_ref().map(|v| v.as_u64()),
                        )
                    })
                    .collect(),
                branch_data: deferred_values.branch_data,
            },
            sponge_digest_before_evaluations: statement
                .proof_state
                .sponge_digest_before_evaluations
                .each_ref()
                .map(|v| v.as_u64()),
            messages_for_next_wrap_proof: MessagesForNextWrapProof {
                old_bulletproof_challenges: prev_challenges.clone(),
                challenge_polynomial_commitment: {
                    let (x, y) = &statement
                        .proof_state
                        .messages_for_next_wrap_proof
                        .challenge_polynomial_commitment;
                    InnerCurve::from((x.to_field::<Fq>()?, y.to_field()?))
                },
            }
            .hash(),
        },
        messages_for_next_step_proof,
    };

    let mut proof = crate::wrap::previous::kimchi_proof(t)?;
    let oracle = {
        let public_input = prev_statement_with_hashes.to_public_input(public_input_length)?;
        create_oracle_with_public_input(dlog_vk, &proof, &public_input)
    };

    let x_hat = PointEvaluations {
        zeta: oracle.p_eval_1(),
        zeta_omega: oracle.p_eval_2(),
    };

    let alpha = oracle.alpha();
    let beta = oracle.beta();
    let gamma = oracle.gamma();
    let zeta = oracle.zeta();

    let to_bytes = |f: Fq| {
        let bigint: BigInteger256 = f.into();
        let [a, b, c, d] = bigint.0;
        assert_eq!([c, d], [0, 0]);
        [a, b]
    };

    let plonk0 = PlonkMinimal {
        alpha,
        beta,
        gamma,
        zeta,
        joint_combiner: None,
        alpha_bytes: to_bytes(alpha),
        beta_bytes: to_bytes(beta),
        gamma_bytes: to_bytes(gamma),
        zeta_bytes: to_bytes(zeta),
        joint_combiner_bytes: None, // TODO
        feature_flags: FeatureFlags::empty_bool(),
    };

    let xi = oracle.v();
    let r = oracle.u();
    let sponge_digest_before_evaluations = oracle.digest_before_evaluations;

    let (_, endo) = endos::<Fp>();
    let to_field = |bytes: [u64; 2]| -> Fq { ScalarChallenge::from(bytes).to_field(&endo) };

    let w = dlog_vk.domain.group_gen;

    let zeta = to_field(plonk0.zeta_bytes);
    let zetaw = { zeta * w };

    let (new_bulletproof_challenges, b) = {
        let chals = oracle
            .opening_prechallenges
            .iter()
            .map(|v| to_field(to_bytes(*v)))
            .collect::<Vec<_>>();

        let r = to_field(to_bytes(r.inner()));
        // let zeta = to_field(plonk0.zeta_bytes);
        let challenge_poly = challenge_polynomial(&chals);
        let b = challenge_poly(zeta) + (r * challenge_poly(zetaw));

        let prechals = oracle
            .opening_prechallenges
            .iter()
            .copied()
            .map(to_bytes)
            .collect::<Vec<_>>();

        (prechals, b)
    };

    let challenge_polynomial_commitment = match must_verify.value() {
        Boolean::False => wrap_compute_sg(&new_bulletproof_challenges),
        Boolean::True => proof.proof.sg,
    };

    let witness = PerProofWitness {
        app_state: None,
        proof_state: prev_statement_with_hashes.proof_state.clone(),
        prev_proof_evals: (&t.prev_evals).try_into()?,
        prev_challenge_polynomial_commitments: {
            let mut challenge_polynomial_commitments = t
                .statement
                .messages_for_next_step_proof
                .challenge_polynomial_commitments
                .iter()
                .map(|(x, y)| Ok(make_group::<Fp>(x.to_field()?, y.to_field()?)))
                .collect::<Result<Vec<_>, InvalidBigInt>>()?;

            while challenge_polynomial_commitments.len() < proofs_verified {
                challenge_polynomial_commitments.insert(0, dummy_ipa_wrap_sg());
            }

            challenge_polynomial_commitments
        },
        prev_challenges: {
            let mut prev_challenges = old_bulletproof_challenges.clone();
            while prev_challenges.len() < proofs_verified {
                prev_challenges.insert(0, dummy_ipa_step_challenges_computed())
            }

            prev_challenges
        },
        wrap_proof: {
            proof.proof.sg = challenge_polynomial_commitment;
            proof.clone()
        },
        hack_feature_flags,
    };

    let tock_combined_evals = {
        let zeta = to_field(plonk0.zeta_bytes);
        evals_of_split_evals(zeta, zetaw, &proof.evals, BACKEND_TOCK_ROUNDS_N)
    };

    let tock_plonk_minimal = {
        let alpha = to_field(plonk0.alpha_bytes);
        let zeta = to_field(plonk0.zeta_bytes);

        let to_bytes = |f: Fq| {
            let bigint: BigInteger256 = f.into();
            bigint.0
        };

        PlonkMinimal {
            alpha,
            beta,
            gamma,
            zeta,
            joint_combiner: None,
            alpha_bytes: to_bytes(alpha),
            beta_bytes: to_4limbs(plonk0.beta_bytes),
            gamma_bytes: to_4limbs(plonk0.gamma_bytes),
            zeta_bytes: to_bytes(alpha),
            joint_combiner_bytes: None, // TODO
            feature_flags: FeatureFlags::empty_bool(),
        }
    };

    let domain_log2 = dlog_vk.domain.log_size_of_group;
    let srs_length_log2 = COMMON_MAX_DEGREE_WRAP_LOG2;
    let tock_env = make_scalars_env(
        &tock_plonk_minimal,
        domain_log2 as u8,
        srs_length_log2 as u64,
        zk_rows,
    );

    let public = {
        let PointEvaluations { zeta, zeta_omega } = &x_hat;
        PointEvaluations {
            zeta: vec![*zeta],
            zeta_omega: vec![*zeta_omega],
        }
    };

    let combined_inner_product = combined_inner_product(CombinedInnerProductParams {
        env: &tock_env,
        evals: &proof.evals,
        combined_evals: &tock_combined_evals,
        public: &public,
        minimal: &tock_plonk_minimal,
        ft_eval1: proof.ft_eval1,
        r: to_field(to_bytes(r.inner())),
        old_bulletproof_challenges: &prev_challenges,
        xi: to_field(to_bytes(xi.inner())),
        zetaw,
    });

    let plonk = derive_plonk(&tock_env, &tock_combined_evals, &tock_plonk_minimal);

    let shift = |f: Fq| <Fq as FieldWitness>::Shifting::of_field(f);

    let unfinalized = Unfinalized {
        deferred_values: ledger::proofs::unfinalized::DeferredValues {
            plonk: Plonk {
                alpha: to_bytes(plonk0.alpha),
                beta: to_bytes(plonk0.beta),
                gamma: to_bytes(plonk0.gamma),
                zeta: to_bytes(plonk0.zeta),
                zeta_to_srs_length: plonk.zeta_to_srs_length,
                zeta_to_domain_size: plonk.zeta_to_domain_size,
                perm: plonk.perm,
                lookup: None,
                feature_flags: plonk.feature_flags,
            },
            combined_inner_product: shift(combined_inner_product),
            b: shift(b),
            xi: to_bytes(xi.inner()),
            bulletproof_challenges: new_bulletproof_challenges,
        },
        should_finalize: must_verify.value().as_bool(),
        sponge_digest_before_evaluations: {
            let bigint: BigInteger256 = sponge_digest_before_evaluations.into();
            bigint.0
        },
    };

    Ok(ExpandedProof {
        sg: challenge_polynomial_commitment,
        unfinalized,
        prev_statement_with_hashes,
        x_hat,
        witness,
        actual_wrap_domain: dlog_vk.domain.log_size_of_group,
    })
}

#[derive(Debug)]
pub struct ExpandedProof {
    pub sg: GroupAffine<Fp>,
    pub unfinalized: Unfinalized,
    pub prev_statement_with_hashes: PreparedStatement,
    pub x_hat: PointEvaluations<Fq>,
    pub witness: PerProofWitness,
    pub actual_wrap_domain: u32,
}

fn to_4limbs(v: [u64; 2]) -> [u64; 4] {
    [v[0], v[1], 0, 0]
}

// --- the step circuit's part after the method -----------------------------------------------------

/// A public input the previous proof was made against, as its program's `app_state`.
#[derive(Debug)]
struct PublicInput(Vec<Fp>);

impl ToFieldElements<Fp> for PublicInput {
    fn to_field_elements(&self, fields: &mut Vec<Fp>) {
        fields.extend_from_slice(&self.0);
    }
}

/// What a previous proof leaves for the step statement and the hash of `messages_for_next_step_proof`.
struct Verified {
    unfinalized: Unfinalized,
    messages_for_next_wrap_proof: Fp,
    /// The previous proof's own accumulator.
    sg: GroupAffine<Fp>,
    bulletproof_challenges: [Fp; 16],
}

/// `zk_rows` of a Pickles proof whose circuit is not chunked.
const ZK_ROWS: u64 = 3;

/// The length of a wrap proof's public input: the packed fields of its statement.
const WRAP_PUBLIC_INPUT_LENGTH: usize = 40;

/// The feature flags of a previous program, as Pickles' `For_step` carries them: none of the optional
/// gates (a program only has them when its methods use them), and the statement with the lookup slot
/// that o1js's wrap circuit has.
///
/// The previous program is taken to have one method (`branches: 1`), whose step domain is the one
/// the proof's `branch_data` names. A program with several methods would need each method's domain
/// here; nothing verified so far (the toy's `toy-inner`) has more than one.
fn for_step(previous: &PreviousProof, zk_rows: u64) -> anyhow::Result<ForStep> {
    let vk = previous.verification_key;
    let proofs_verified = vk.max_proofs_verified.to_int();
    let t = previous.proof.repr();
    let step_domain = t.statement.proof_state.deferred_values.branch_data.domain_log2.as_u8() as u64;
    let Domains { h: wrap_domain } = wrap_domains(proofs_verified);
    let no = |_| OptFlag::No;
    Ok(ForStep {
        branches: 1,
        max_proofs_verified: proofs_verified,
        proof_verifieds: ForStepKind::Known(vec![Fp::from(proofs_verified as u64)]),
        public_input: (),
        wrap_key: vk.wrap_index.to_cvar(CircuitVar::Constant),
        wrap_domain: ForStepKind::Known(wrap_domain),
        step_domains: ForStepKind::Known(Box::new([Domains { h: Domain::Pow2RootsOfUnity(step_domain) }])),
        feature_flags: FeatureFlags {
            range_check0: no(()),
            range_check1: no(()),
            foreign_field_add: no(()),
            foreign_field_mul: no(()),
            xor: no(()),
            rot: no(()),
            lookup: no(()),
            runtime_tables: no(()),
        },
        num_chunks: 1,
        zk_rows,
    })
}

/// The part of a step circuit that follows the method, for a method that verifies `previous` (every
/// one of them must verify; Pickles' `must_verify` is the constant true): `step_main` of Pickles. It
/// appends the variables to `cs` and returns the step statement, the public input.
///
/// `own` is the verification key of the program the step circuit belongs to: its wrap index is
/// witnessed and hashed, and `max_proofs_verified` the program's, which the statement's widths
/// follow. The method's variables, with the app state first (two variables: the account update
/// hash and the calls hash), must already be in `cs`.
pub fn step_main_tail(
    cs: &mut Cs,
    own: &VerificationKey,
    max_proofs_verified: usize,
    previous: &[PreviousProof],
) -> anyhow::Result<Vec<Fp>> {
    anyhow::ensure!(previous.len() <= max_proofs_verified && max_proofs_verified <= 2, "too many proofs");
    let start = cs.next_var();
    let (result, aux) = from_fork(|w| -> anyhow::Result<_> {
        let own_index = w.exists((*own.wrap_index).clone());
        let datas = previous.iter().map(|p| for_step(p, ZK_ROWS)).collect::<anyhow::Result<Vec<_>>>()?;
        let apps: Vec<Rc<dyn ToFieldElementsDebug>> = previous
            .iter()
            .map(|p| Rc::new(PublicInput(p.public_input.to_vec())) as Rc<dyn ToFieldElementsDebug>)
            .collect();
        let expanded = previous
            .iter()
            .zip(&apps)
            .map(|(p, app_state)| {
                let vk = p.verification_key;
                let dlog_plonk_index = vk.wrap_index.to_cvar(CircuitVar::Constant);
                expand_proof(ExpandProofParams {
                    dlog_vk: &make_zkapp_verifier_index(vk),
                    dlog_plonk_index: &dlog_plonk_index,
                    app_state,
                    t: p.proof.repr(),
                    public_input_length: WRAP_PUBLIC_INPUT_LENGTH,
                    tag: (),
                    must_verify: CircuitVar::Constant(Boolean::True),
                    hack_feature_flags: OptFlag::No,
                    zk_rows: ZK_ROWS,
                    proofs_verified: vk.max_proofs_verified.to_int(),
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()
            .context("expand_proof")?;
        let prevs: Vec<PerProofWitness> = expanded
            .iter()
            .zip(&apps)
            .map(|(e, app)| w.exists(e.witness.clone()).with_app_state(app.clone()))
            .collect();
        let unfinalized: Vec<Unfinalized> = expanded.iter().map(|e| w.exists(e.unfinalized.clone())).collect();
        let messages: Vec<Fp> = expanded
            .iter()
            .map(|e| four_u64_to_field::<Fp, _>(&e.prev_statement_with_hashes.proof_state.messages_for_next_wrap_proof))
            .collect::<Result<_, _>>()?;
        for i in 0..max_proofs_verified {
            let n_padding = max_proofs_verified - previous.len();
            w.exists(if i < n_padding { messages_for_next_wrap_proof_padding() } else { messages[i - n_padding] });
        }
        let srs = get_srs_mut::<Fq>();
        let mut srs = srs.lock().unwrap();
        let mut verified = Vec::new();
        for (((proof, data), unfinalized), message) in prevs.iter().zip(&datas).zip(&unfinalized).zip(&messages) {
            let (chals, _) = verify_one(
                VerifyOneParams {
                    srs: &mut srs,
                    proof,
                    data,
                    messages_for_next_wrap_proof: *message,
                    unfinalized,
                    should_verify: CircuitVar::Constant(Boolean::True),
                },
                w,
            )
            .context("verify_one")?;
            verified.push(Verified {
                unfinalized: unfinalized.clone(),
                messages_for_next_wrap_proof: *message,
                sg: proof.wrap_proof.proof.sg,
                bulletproof_challenges: chals.try_into().map_err(|_| anyhow::anyhow!("16 challenges"))?,
            });
        }
        Ok((verified, own_index))
    });
    let (verified, own_index) = result?;
    cs.extend(aux);

    // `hash_messages_for_next_step_proof`: the wrap index, the app state, then each proof's accumulator
    // and challenges. The fork lists the fields; they are absorbed here as the variables they are, so
    // that adding one to the sponge's state creates a variable only where snarky's does.
    let app_state = Rc::new(PublicInput(vec![cs.var(1).value(), cs.var(2).value()]));
    let fields = MessagesForNextStepProof {
        app_state,
        dlog_plonk_index: &own_index,
        challenge_polynomial_commitments: verified.iter().map(|v| InnerCurve::of_affine(v.sg)).collect(),
        old_bulletproof_challenges: verified.iter().map(|v| v.bulletproof_challenges).collect(),
    }
    .to_fields();
    let mut sponge = Sponge::new();
    for (i, f) in fields.iter().enumerate() {
        let field = match i {
            // the 56 fields of the wrap index's 28 commitments (every wrap index has 28) are the
            // first variables `exists` created; the app state is variables 1 and 2
            0..=55 => cs.var(start + i),
            56 | 57 => cs.var(i - 55),
            _ => Field::constant(*f),
        };
        sponge.absorb(cs, &field);
    }
    let messages_for_next_step_proof = sponge.squeeze(cs).value();

    let mut unfinalized: Vec<Unfinalized> = verified.iter().map(|v| v.unfinalized.clone()).collect();
    while unfinalized.len() < max_proofs_verified {
        unfinalized.insert(0, Unfinalized::dummy());
    }
    let mut messages: Vec<Fp> = verified.iter().map(|v| v.messages_for_next_wrap_proof).collect();
    while messages.len() < max_proofs_verified {
        messages.insert(0, messages_for_next_wrap_proof_padding());
    }
    Ok(StepMainStatement {
        proof_state: StepMainProofState { unfinalized_proofs: unfinalized, messages_for_next_step_proof },
        messages_for_next_wrap_proof: messages,
    }
    .to_field_elements_owned())
}
