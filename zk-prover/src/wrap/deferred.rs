//! The deferred values of a step proof: what the wrap circuit checks `incrementally`, computed
//! outside the circuit from the step proof and its verification key.
//!
//! Derived from `crates/ledger/src/proofs/wrap.rs` (`deferred_values`) in `toon-protocol/mina-rust`
//! at rev `6feeb3797fff6dba49fd848cb2d6decd63fee1b4` (itself from `o1-labs/mina-rust` v0.19.0,
//! Apache-2.0), generalised to a step circuit with feature flags and lookups (`lookup: None` and
//! empty flags there). Mina's `wrap.ml` and `wrap_deferred_values.ml` at `aa93c444` are the
//! reference. Licensed under Apache-2.0; see `LICENSE-APACHE` and `NOTICE`.

use ark_ff::{BigInteger256, Zero};
use kimchi::proof::PointEvaluations;
use ledger::proofs::{
    field::FieldWitness,
    public_input::{
        plonk_checks::{derive_plonk, PlonkMinimal, ShiftingValue},
        prepared_statement::{DeferredValues, Plonk},
        scalar_challenge::ScalarChallenge,
    },
    step::FeatureFlags,
    transaction::{endos, ProofWithPublic},
    util::challenge_polynomial,
    verification::make_scalars_env,
    wrap::{
        combined_inner_product, create_oracle, evals_of_split_evals, CombinedInnerProductParams,
        COMMON_MAX_DEGREE_STEP_LOG2,
    },
    ProverIndex, BACKEND_TICK_ROUNDS_N,
};
use mina_curves::pasta::{Fp, Fq};
use mina_p2p_messages::v2::{
    CompositionTypesBranchDataDomainLog2StableV1, CompositionTypesBranchDataStableV1,
    PicklesBaseProofsVerifiedStableV1,
};

/// The feature flags a step circuit's verification key carries.
pub fn step_features(index: &ProverIndex<Fp>) -> FeatureFlags<bool> {
    let vk = index.verifier_index();
    let lookup = vk.lookup_index.as_ref();
    FeatureFlags {
        range_check0: vk.range_check0_comm.is_some(),
        range_check1: vk.range_check1_comm.is_some(),
        foreign_field_add: vk.foreign_field_add_comm.is_some(),
        foreign_field_mul: vk.foreign_field_mul_comm.is_some(),
        xor: vk.xor_comm.is_some(),
        rot: vk.rot_comm.is_some(),
        lookup: lookup.is_some_and(|l| l.lookup_selectors.lookup.is_some()),
        runtime_tables: lookup.is_some_and(|l| l.runtime_tables_selector.is_some()),
    }
}

/// Whether Pickles treats a circuit with these flags as using lookups
/// (`composition_types.ml`, `Features.Full.uses_lookups`).
pub fn uses_lookups(f: &FeatureFlags<bool>) -> bool {
    f.range_check0 || f.range_check1 || f.foreign_field_mul || f.xor || f.rot || f.lookup
}

pub struct DeferredValuesAndHints {
    pub deferred_values: DeferredValues<Fp>,
    pub sponge_digest_before_evaluations: Fp,
    pub x_hat_evals: PointEvaluations<Vec<Fp>>,
}

pub struct DeferredValuesParams<'a> {
    /// The step circuit's `old_bulletproof_challenges`, one per previous proof.
    pub prev_challenges: Vec<[Fp; 16]>,
    pub proof_with_public: &'a ProofWithPublic<Fp>,
    /// The number of proofs the wrapped branch verifies.
    pub actual_proofs_verified: usize,
    pub prover_index: &'a ProverIndex<Fp>,
    pub features: FeatureFlags<bool>,
}

pub fn deferred_values(params: DeferredValuesParams) -> DeferredValuesAndHints {
    let DeferredValuesParams {
        prev_challenges,
        proof_with_public,
        actual_proofs_verified,
        prover_index,
        features,
    } = params;

    let step_vk = prover_index.verifier_index();
    let log_size_of_group = step_vk.domain.log_size_of_group;
    let oracle = create_oracle(&step_vk, proof_with_public);

    let x_hat = match proof_with_public.public_evals() {
        Some(x) => x.clone(),
        None => PointEvaluations {
            zeta: vec![oracle.p_eval.0],
            zeta_omega: vec![oracle.p_eval.1],
        },
    };

    let alpha = oracle.alpha();
    let beta = oracle.beta();
    let gamma = oracle.gamma();
    let zeta = oracle.zeta();

    let to_bytes = |f: Fp| {
        let bigint: BigInteger256 = f.into();
        let [a, b, c, d] = bigint.0;
        assert_eq!([c, d], [0, 0]);
        [a, b]
    };

    // Pickles samples a joint combiner only for circuits with joint lookups, but a circuit that
    // uses lookups at all carries `Some(0)` (see `uses_lookups`).
    let joint_combiner_bytes = match oracle.o.joint_combiner.as_ref() {
        Some((chal, _)) => Some(to_bytes(chal.inner())),
        None => uses_lookups(&features).then_some([0, 0]),
    };

    let (_, endo) = endos::<Fq>();
    let scalar_to_field = |bytes: [u64; 2]| -> Fp { ScalarChallenge::from(bytes).to_field(&endo) };

    let plonk0 = PlonkMinimal::<Fp> {
        alpha,
        beta,
        gamma,
        zeta,
        joint_combiner: joint_combiner_bytes.map(scalar_to_field),
        alpha_bytes: to_bytes(alpha),
        beta_bytes: to_bytes(beta),
        gamma_bytes: to_bytes(gamma),
        zeta_bytes: to_bytes(zeta),
        joint_combiner_bytes,
        feature_flags: features,
    };

    let r = oracle.u();
    let xi = oracle.v();

    let zeta = scalar_to_field(plonk0.zeta_bytes);
    let zetaw = step_vk.domain.group_gen * zeta;

    let tick_plonk_minimal = PlonkMinimal {
        zeta,
        alpha: scalar_to_field(plonk0.alpha_bytes),
        ..plonk0.clone()
    };
    let tick_combined_evals = evals_of_split_evals(
        zeta,
        zetaw,
        &proof_with_public.proof.evals,
        BACKEND_TICK_ROUNDS_N,
    );

    let domain_log2: u8 = log_size_of_group.try_into().unwrap();
    let tick_env = make_scalars_env(
        &tick_plonk_minimal,
        domain_log2,
        COMMON_MAX_DEGREE_STEP_LOG2,
        step_vk.zk_rows,
    );
    let plonk = derive_plonk(&tick_env, &tick_combined_evals, &tick_plonk_minimal);

    let (new_bulletproof_challenges, b) = {
        let chals = oracle
            .opening_prechallenges
            .iter()
            .copied()
            .map(|v| scalar_to_field(to_bytes(v)))
            .collect::<Vec<_>>();

        let r = scalar_to_field(to_bytes(r.inner()));
        let challenge_poly = challenge_polynomial(&chals);
        let b = challenge_poly(zeta) + (r * challenge_poly(zetaw));

        (oracle.opening_prechallenges.to_vec(), b)
    };

    let evals = &proof_with_public.proof.evals;
    let combined_evals = evals_of_split_evals(zeta, zetaw, evals, BACKEND_TICK_ROUNDS_N);

    let combined_inner_product =
        combined_inner_product(CombinedInnerProductParams::<_, { Fp::NROUNDS }, 2> {
            env: &tick_env,
            evals,
            combined_evals: &combined_evals,
            minimal: &tick_plonk_minimal,
            r: scalar_to_field(to_bytes(r.inner())),
            old_bulletproof_challenges: &prev_challenges,
            xi: scalar_to_field(to_bytes(xi.inner())),
            zetaw,
            public: &x_hat,
            ft_eval1: proof_with_public.proof.ft_eval1,
        });

    let shift = |f: Fp| <Fp as FieldWitness>::Shifting::of_field(f);

    DeferredValuesAndHints {
        deferred_values: DeferredValues {
            plonk: Plonk {
                alpha: plonk0.alpha_bytes,
                beta: plonk0.beta_bytes,
                gamma: plonk0.gamma_bytes,
                zeta: plonk0.zeta_bytes,
                zeta_to_srs_length: plonk.zeta_to_srs_length,
                zeta_to_domain_size: plonk.zeta_to_domain_size,
                perm: plonk.perm,
                lookup: plonk.lookup.and(joint_combiner_bytes),
                feature_flags: plonk.feature_flags,
            },
            combined_inner_product: shift(combined_inner_product),
            b: shift(b),
            xi: to_bytes(xi.inner()),
            bulletproof_challenges: {
                assert_eq!(new_bulletproof_challenges.len(), BACKEND_TICK_ROUNDS_N);
                new_bulletproof_challenges
            },
            branch_data: CompositionTypesBranchDataStableV1 {
                proofs_verified: match actual_proofs_verified {
                    0 => PicklesBaseProofsVerifiedStableV1::N0,
                    1 => PicklesBaseProofsVerifiedStableV1::N1,
                    2 => PicklesBaseProofsVerifiedStableV1::N2,
                    n => panic!("a step proof verifies at most 2 proofs, not {n}"),
                },
                domain_log2: CompositionTypesBranchDataDomainLog2StableV1(
                    (log_size_of_group as u8).into(),
                ),
            },
        },
        sponge_digest_before_evaluations: oracle.digest_before_evaluations,
        x_hat_evals: x_hat,
    }
}

#[allow(unused)]
fn _unused(_: Fp) -> bool {
    Fp::zero().is_zero()
}
