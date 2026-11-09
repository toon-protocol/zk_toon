//! The previous proofs a step proof verified, as the wrap circuit reads them: the unfinalized proofs
//! the step statement carries, and what the wrap circuit witnesses about each proof (its
//! accumulator, evaluations and wrap domain).
//!
//! The accumulator and evaluations are derived from the previous proof (`expand_proof` in
//! `crates/ledger/src/proofs/step.rs` of `toon-protocol/mina-rust` at rev
//! `6feeb3797fff6dba49fd848cb2d6decd63fee1b4`, itself from `o1-labs/mina-rust` v0.19.0, Apache-2.0,
//! which is private there; and `make_padded_proof_from_p2p` in its `prover.rs`). Licensed under
//! Apache-2.0; see `LICENSE-APACHE` and `NOTICE`.

use std::{borrow::Cow, str::FromStr};

use ark_ff::{BigInteger256, PrimeField};
use kimchi::proof::{PointEvaluations, ProofEvaluations, ProverCommitments, RecursionChallenge};
use ledger::{
    proofs::{
        field::GroupAffine,
        public_input::{
            messages::{MessagesForNextStepProof, MessagesForNextWrapProof},
            plonk_checks::ShiftedValue,
            prepared_statement::{DeferredValues, Plonk, PreparedStatement, ProofState},
            scalar_challenge::ScalarChallenge,
        },
        step::{expand_deferred, ExpandDeferredParams, FeatureFlags, StatementProofState},
        to_field_elements::ToFieldElements,
        transaction::{make_group, InnerCurve},
        unfinalized::{
            evals_from_p2p, AllEvals, DeferredValues as UnfinalizedDeferredValues,
            EvalsWithPublicInput, Unfinalized,
        },
        util::{extract_bulletproof, two_u64_to_field},
        verifiers::make_zkapp_verifier_index,
        wrap::create_oracle_with_public_input,
        ProverProof,
    },
    VerificationKey,
};
use mina_curves::pasta::{Fp, Fq, Pallas};
use mina_p2p_messages::{bigint::BigInt, v2::PicklesProofProofsVerified2ReprStableV2};
use poly_commitment::{commitment::CommitmentCurve, ipa::OpeningProof, PolyComm};

use crate::verify::WrapProof;

/// A proof the step proof verified: a Pickles proof as o1js writes it, the verification key of the
/// program that made it, and its public input.
#[derive(Clone, Copy)]
pub struct PreviousProof<'a> {
    pub proof: &'a WrapProof,
    pub verification_key: &'a VerificationKey,
    pub public_input: &'a [Fp],
}

/// What the wrap circuit and its proof take from a previous proof.
pub(super) struct Previous {
    /// `messages_for_next_wrap_proof`: the step-side accumulator the proof carried, at length 2.
    pub sg: InnerCurve<Fq>,
    pub old_bulletproof_challenges: Vec<[Fq; 15]>,
    pub evals: AllEvals<Fq>,
    /// The proof's own accumulator (its opening's `sg`), which the wrap proof takes on in turn.
    pub wrap_sg: GroupAffine<Fp>,
    /// `maxProofsVerified` of the program that made the proof, and the index of its wrap domain among
    /// the possible ones (they run with `maxProofsVerified`).
    pub max_proofs_verified: usize,
    /// The bulletproof challenges of the step proof the previous proof wrapped, as the step statement's
    /// `messages_for_next_step_proof` holds them: the 128-bit prechallenges.
    pub step_bulletproof_challenges: [Fp; 16],
}

struct PublicInput<'a>(&'a [Fp]);

impl ToFieldElements<Fp> for PublicInput<'_> {
    fn to_field_elements(&self, fields: &mut Vec<Fp>) {
        fields.extend_from_slice(self.0);
    }
}

fn four_limbs(f: Fp) -> [u64; 4] {
    let b: BigInteger256 = f.into();
    b.0
}

fn two_limbs(f: Fp) -> anyhow::Result<[u64; 2]> {
    let [a, b, c, d] = four_limbs(f);
    anyhow::ensure!([c, d] == [0, 0], "a challenge of more than 128 bits");
    Ok([a, b])
}

/// The fields an unfinalized proof takes in the step statement (`Unfinalized.to_field_elements` over the
/// step field).
pub(super) const UNFINALIZED_FIELDS: usize = 32;

/// `Unfinalized` from its 32 fields in the step statement. A value of the wrap field is split in two
/// there, its high bits then its lowest bit.
pub(super) fn unfinalized_of_fields(f: &[Fp]) -> anyhow::Result<Unfinalized> {
    anyhow::ensure!(f.len() == UNFINALIZED_FIELDS, "an unfinalized proof has {UNFINALIZED_FIELDS} fields");
    let shifted = |high: Fp, low: Fp| -> anyhow::Result<ShiftedValue<Fq>> {
        let high: BigInteger256 = high.into();
        let high = Fq::from_bigint(high).ok_or_else(|| anyhow::anyhow!("a split value out of range"))?;
        let low = match low {
            v if v == Fp::from(0u64) => Fq::from(0u64),
            v if v == Fp::from(1u64) => Fq::from(1u64),
            _ => anyhow::bail!("the low bit of a split value is not a bit"),
        };
        Ok(ShiftedValue::new(high + high + low))
    };
    let [cip, b, zeta_to_srs_length, zeta_to_domain_size, perm] =
        [0, 2, 4, 6, 8].map(|i| shifted(f[i], f[i + 1]));
    let challenges = f[16..31].iter().map(|c| two_limbs(*c)).collect::<anyhow::Result<Vec<_>>>()?;
    let should_finalize = match f[31] {
        v if v == Fp::from(0u64) => false,
        v if v == Fp::from(1u64) => true,
        _ => anyhow::bail!("should_finalize is not a bit"),
    };
    Ok(Unfinalized {
        deferred_values: UnfinalizedDeferredValues {
            plonk: Plonk {
                alpha: two_limbs(f[13])?,
                beta: two_limbs(f[11])?,
                gamma: two_limbs(f[12])?,
                zeta: two_limbs(f[14])?,
                zeta_to_srs_length: zeta_to_srs_length?,
                zeta_to_domain_size: zeta_to_domain_size?,
                perm: perm?,
                lookup: None,
                feature_flags: FeatureFlags::empty_bool(),
            },
            combined_inner_product: cip?,
            b: b?,
            xi: two_limbs(f[15])?,
            bulletproof_challenges: challenges,
        },
        should_finalize,
        sponge_digest_before_evaluations: four_limbs(f[10]),
    })
}

/// `make_padded_proof_from_p2p`: the proof as kimchi reads it, with two accumulators.
pub(crate) fn kimchi_proof(t: &PicklesProofProofsVerified2ReprStableV2) -> anyhow::Result<ProverProof<Fq>> {
    let PicklesProofProofsVerified2ReprStableV2 { statement, prev_evals: _, proof } = t;
    let of_coord = |(a, b): &(BigInt, BigInt)| -> anyhow::Result<_> {
        Ok(Pallas::of_coordinates(a.to_field()?, b.to_field()?))
    };
    let make_poly = |poly: &(BigInt, BigInt)| -> anyhow::Result<_> {
        Ok(PolyComm { chunks: vec![of_coord(poly)?] })
    };
    let w_comm: [PolyComm<Pallas>; 15] = ledger::try_array_into_with(&proof.commitments.w_comm, make_poly)?;
    let z_comm = make_poly(&proof.commitments.z_comm)?;
    let t_comm = PolyComm {
        chunks: proof.commitments.t_comm.iter().map(of_coord).collect::<Result<_, _>>()?,
    };
    let bulletproof = &proof.bulletproof;
    let lr = bulletproof
        .lr
        .iter()
        .map(|(a, b)| Ok((of_coord(a)?, of_coord(b)?)))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let delta = of_coord(&bulletproof.delta)?;
    let z1: Fq = bulletproof.z_1.to_field()?;
    let z2: Fq = bulletproof.z_2.to_field()?;
    let sg = of_coord(&bulletproof.challenge_polynomial_commitment)?;

    let evals = &proof.evaluations;
    let to_pt_eval = |(first, second): &(BigInt, BigInt)| -> anyhow::Result<_> {
        Ok(PointEvaluations {
            zeta: vec![first.to_field::<Fq>()?],
            zeta_omega: vec![second.to_field::<Fq>()?],
        })
    };
    let evals = ProofEvaluations {
        w: ledger::try_array_into_with(&evals.w, to_pt_eval)?,
        z: to_pt_eval(&evals.z)?,
        s: ledger::try_array_into_with(&evals.s, to_pt_eval)?,
        generic_selector: to_pt_eval(&evals.generic_selector)?,
        coefficients: ledger::try_array_into_with(&evals.coefficients, to_pt_eval)?,
        poseidon_selector: to_pt_eval(&evals.poseidon_selector)?,
        complete_add_selector: to_pt_eval(&evals.complete_add_selector)?,
        mul_selector: to_pt_eval(&evals.mul_selector)?,
        emul_selector: to_pt_eval(&evals.emul_selector)?,
        endomul_scalar_selector: to_pt_eval(&evals.endomul_scalar_selector)?,
        range_check0_selector: None,
        range_check1_selector: None,
        foreign_field_add_selector: None,
        foreign_field_mul_selector: None,
        xor_selector: None,
        rot_selector: None,
        lookup_aggregation: None,
        lookup_table: None,
        lookup_sorted: [None, None, None, None, None],
        runtime_lookup_table: None,
        runtime_lookup_table_selector: None,
        xor_lookup_selector: None,
        lookup_gate_lookup_selector: None,
        range_check_lookup_selector: None,
        foreign_field_mul_lookup_selector: None,
        public: None,
    };
    let ft_eval1: Fq = proof.ft_eval1.to_field()?;

    let old = &statement.proof_state.messages_for_next_wrap_proof.old_bulletproof_challenges;
    let old_bulletproof_challenges: Vec<[Fq; 15]> =
        extract_bulletproof(&[old.0[0].0.clone(), old.0[1].0.clone()]);

    // The padding of `Wrap_hack.pad_accumulator`, in front.
    let mut commitments = Cow::Borrowed(&statement.messages_for_next_step_proof.challenge_polynomial_commitments);
    while commitments.len() < 2 {
        let padding: (BigInt, BigInt) = (
            Fp::from_str("8063668238751197448664615329057427953229339439010717262869116690340613895496")
                .map_err(|_| anyhow::anyhow!("bad constant"))?
                .into(),
            Fp::from_str("2694491010813221541025626495812026140144933943906714931997499229912601205355")
                .map_err(|_| anyhow::anyhow!("bad constant"))?
                .into(),
        );
        commitments.to_mut().push_front(padding);
    }
    let commitments = commitments.iter().map(make_poly).collect::<Result<Vec<_>, _>>()?;
    anyhow::ensure!(
        old_bulletproof_challenges.len() == 2 && commitments.len() == 2,
        "a wrap proof has two accumulators"
    );
    let prev_challenges = old_bulletproof_challenges
        .iter()
        .zip(commitments)
        .map(|(chals, comm)| RecursionChallenge::new(chals.to_vec(), comm))
        .collect();

    Ok(ProverProof::<Fq> {
        commitments: ProverCommitments { w_comm, z_comm, t_comm, lookup: None },
        proof: OpeningProof { lr, delta, z1, z2, sg },
        evals,
        ft_eval1,
        prev_challenges,
    })
}

pub(super) fn expand(prev: &PreviousProof) -> anyhow::Result<Previous> {
    let t = prev.proof.repr();
    let vk = prev.verification_key;
    let statement = &t.statement;

    let step_old_bulletproof_challenges: Vec<[Fp; 16]> = statement
        .messages_for_next_step_proof
        .old_bulletproof_challenges
        .iter()
        .map(|v| v.0.clone().map(|v| two_u64_to_field(&v.prechallenge.inner.0.map(|v| v.as_u64()))))
        .collect();
    let step_challenge_polynomial_commitments: Vec<InnerCurve<Fp>> = statement
        .messages_for_next_step_proof
        .challenge_polynomial_commitments
        .iter()
        .map(|(x, y)| Ok(InnerCurve::of_affine(make_group(x.to_field::<Fp>()?, y.to_field()?))))
        .collect::<anyhow::Result<_>>()?;

    // The public input the previous proof was made against.
    let proof_state: StatementProofState = (&statement.proof_state).try_into()?;
    let proof_state_challenges: Vec<Fp> = statement
        .proof_state
        .deferred_values
        .bulletproof_challenges
        .iter()
        .map(|c| two_u64_to_field(&c.prechallenge.inner.each_ref().map(|v| v.as_u64())))
        .collect();
    let deferred_values = {
        let evals: AllEvals<Fp> = (&t.prev_evals).try_into()?;
        let computed = expand_deferred(ExpandDeferredParams {
            evals: &evals,
            old_bulletproof_challenges: &step_old_bulletproof_challenges,
            proof_state: &proof_state,
            zk_rows: 3,
        })?;
        DeferredValues {
            bulletproof_challenges: proof_state_challenges.clone(),
            ..computed
        }
    };
    let (sg, wrap_old) = {
        let m = &statement.proof_state.messages_for_next_wrap_proof;
        let (x, y) = &m.challenge_polynomial_commitment;
        let old = &m.old_bulletproof_challenges;
        (
            InnerCurve::<Fq>::from((x.to_field::<Fq>()?, y.to_field::<Fq>()?)),
            extract_bulletproof::<Fq, _, 15>(&[old.0[0].0.clone(), old.0[1].0.clone()]),
        )
    };
    let messages_for_next_wrap_proof = MessagesForNextWrapProof {
        challenge_polynomial_commitment: sg.clone(),
        old_bulletproof_challenges: wrap_old.clone(),
    };
    let messages_for_next_step_proof = MessagesForNextStepProof {
        app_state: &PublicInput(prev.public_input),
        dlog_plonk_index: &vk.wrap_index,
        challenge_polynomial_commitments: step_challenge_polynomial_commitments.clone(),
        old_bulletproof_challenges: step_old_bulletproof_challenges.clone(),
    }
    .hash();
    let public_input = PreparedStatement {
        proof_state: ProofState {
            deferred_values,
            sponge_digest_before_evaluations: statement
                .proof_state
                .sponge_digest_before_evaluations
                .each_ref()
                .map(|v| v.as_u64()),
            messages_for_next_wrap_proof: messages_for_next_wrap_proof.hash(),
        },
        messages_for_next_step_proof,
    }
    .to_public_input(40)?;

    let proof = kimchi_proof(t)?;
    let oracle = create_oracle_with_public_input(&make_zkapp_verifier_index(vk), &proof, &public_input);
    let x_hat = PointEvaluations {
        zeta: vec![oracle.p_eval_1()],
        zeta_omega: vec![oracle.p_eval_2()],
    };

    let step_bulletproof_challenges = <[Fp; 16]>::try_from(proof_state_challenges)
        .map_err(|_| anyhow::anyhow!("a step proof has 16 bulletproof challenges"))?;

    Ok(Previous {
        sg,
        old_bulletproof_challenges: wrap_old,
        evals: AllEvals {
            ft_eval1: t.proof.ft_eval1.to_field()?,
            evals: EvalsWithPublicInput {
                evals: evals_from_p2p(&t.proof.evaluations)?,
                public_input: (x_hat.zeta, x_hat.zeta_omega),
            },
        },
        wrap_sg: proof.proof.sg,
        max_proofs_verified: vk.max_proofs_verified.to_int(),
        step_bulletproof_challenges,
    })
}

/// The expanded form of a 128-bit prechallenge of the wrap field.
pub(super) fn expand_prechallenge(prechallenge: &[u64; 2]) -> Fq {
    ScalarChallenge::limbs_to_field::<Fq>(prechallenge)
}
