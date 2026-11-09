//! The Pickles wrap prover for an o1js program: [`wrap`] takes a step proof and returns the wrap
//! witness (and, once the wrap circuit is proved, the wrap proof).
//!
//! mina-rust's `wrap` / `wrap_main` fix the number of previous proofs at 2, take a single step key
//! and leave out optional gates and lookups. This module is a generalised copy: the number of
//! previous proofs (up to Pickles' maximum, 2) and the proofs the step proof verified, the program's
//! step keys (one per method) and its feature flags are parameters.
//! See the headers of the submodules for what each is derived from.
//!
//! `wrap` and `prepare` are derived from `wrap` in `crates/ledger/src/proofs/wrap.rs` of
//! `toon-protocol/mina-rust` at rev `6feeb3797fff6dba49fd848cb2d6decd63fee1b4` (itself from
//! `o1-labs/mina-rust` v0.19.0, Apache-2.0), following Mina `228c409a` (the commit o1js v3.1.0
//! bundles), `src/lib/crypto/pickles/wrap.ml`. Licensed under Apache-2.0; see `LICENSE-APACHE` and
//! `NOTICE`.

use std::rc::Rc;

use ledger::proofs::{
    public_input::{
        messages::{dummy_ipa_step_sg, MessagesForNextWrapProof},
        prepared_statement::{PreparedStatement, ProofState},
    },
    step::FeatureFlags,
    transaction::{InnerCurve, ProofWithPublic, ReducedMessagesForNextStepProof},
    witness::Witness,
    unfinalized::{AllEvals, EvalsWithPublicInput, Unfinalized},
    wrap::{dummy_ipa_wrap_sg, Domain, Domains, WrapProof, WrapProofState, WrapStatement},
};
use mina_curves::pasta::{Fp, Fq};

use ledger::proofs::constants::ProofConstants;

use crate::StepCircuit;

pub mod constant_term;
pub mod deferred;
pub mod endo;
pub mod finalize;
pub mod group_map;
pub mod key;
pub mod main_circuit;
pub mod opt_sponge;
pub mod previous;
pub mod prove;

pub use prove::WrapCircuit;
pub mod verifier;

use ark_ff::BigInteger256;
use deferred::{deferred_values, step_features, DeferredValuesParams};
use key::StepKey;
use main_circuit::{wrap_main, PreviousSlot, ProgramFlags, WrapMainParams};
pub use previous::PreviousProof;
use previous::{compute_sg, expand, expand_prechallenge, unfinalized_of_fields, UNFINALIZED_FIELDS};

/// Pickles' maximum number of previous proofs: the wrap circuit pads its accumulators to this many. The
/// fixtures exercise programs of 0 and 1 (`tests/wrap.rs`, `tests/wrap_recursive.rs`); 2 goes through the
/// same code, with a second slot.
pub const MAX_PROOFS_VERIFIED: usize = 2;

/// The public input size of a wrap circuit.
const WRAP_PUBLIC_INPUT_SIZE: usize = 40;

/// What the wrap proves.
pub struct WrapParams<'a> {
    /// The most previous proofs any method of the program verifies (`maxProofsVerified`): at most
    /// [`MAX_PROOFS_VERIFIED`]. The step proof's public input has that many unfinalized proofs, the
    /// first of them dummies if the method verifies fewer.
    pub max_proofs_verified: usize,
    /// The program's step circuits, one per method, in method order.
    pub step_circuits: &'a [&'a StepCircuit],
    /// The index of the method the step proof is for.
    pub branch: usize,
    /// The union of the methods' feature flags.
    pub features: FeatureFlags<bool>,
    /// The step proof, with its public input.
    pub step_proof: &'a ProofWithPublic<Fp>,
    /// The proofs the step proof verified, in order: as many as the method (`step_circuits[branch]`)
    /// verifies, none for a program that verifies no proof.
    pub previous_proofs: &'a [PreviousProof<'a>],
    /// For each of the `max_proofs_verified` slots, the most proofs any program whose proof a method
    /// of this program verifies in that slot itself verifies (its `maxProofsVerified`). The wrap
    /// circuit witnesses that many old challenges for the slot. Empty if `max_proofs_verified` is 0.
    pub previous_max_proofs_verified: &'a [usize],
}

/// The values of the wrap circuit: the public input, then the auxiliary values, as o1js dumps them
/// (`external`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrapWitness {
    pub primary: Vec<Fq>,
    pub aux: Vec<Fq>,
}

impl WrapWitness {
    /// `primary` then `aux`.
    pub fn external(&self) -> Vec<Fq> {
        self.primary.iter().chain(&self.aux).copied().collect()
    }

    /// The first index at which `self` and `expected` (in `external` order) differ, if any.
    pub fn first_difference(&self, expected: &[Fq]) -> Option<usize> {
        let ours = self.external();
        (0..ours.len().max(expected.len())).find(|&i| ours.get(i) != expected.get(i))
    }

    /// The vectors inside a [`Witness`]. `ledger` keeps them private, but the witness prints them.
    fn of_witness(w: &Witness<Fq>) -> anyhow::Result<Self> {
        use std::str::FromStr;
        let text = format!("{w:?}");
        let list = |name: &str| -> anyhow::Result<Vec<Fq>> {
            let start = text
                .find(&format!("{name}: ["))
                .ok_or_else(|| anyhow::anyhow!("no {name} in the witness"))?
                + name.len()
                + 3;
            let end = start
                + text[start..]
                    .find(']')
                    .ok_or_else(|| anyhow::anyhow!("no end to {name} in the witness"))?;
            text[start..end]
                .split(", ")
                .filter(|s| !s.is_empty())
                .map(|s| Fq::from_str(s).map_err(|_| anyhow::anyhow!("bad field element {s}")))
                .collect()
        };
        Ok(Self {
            primary: list("primary")?,
            aux: list("aux")?,
        })
    }
}

/// What proving the wrap needs besides its witness.
struct Prepared {
    witness: WrapWitness,
    statement: WrapStatement,
    x_hat_evals: kimchi::proof::PointEvaluations<Vec<Fp>>,
    /// The accumulators of the wrap proof: two, the first the dummy if the program verifies at most one
    /// proof.
    prev_challenges: Vec<kimchi::proof::RecursionChallenge<mina_curves::pasta::Pallas>>,
}

/// The wrap witness for a step proof.
pub fn wrap_witness(params: WrapParams) -> anyhow::Result<WrapWitness> {
    Ok(prepare(params)?.witness)
}

/// The wrap proof and witness for a step proof, proved under `circuit`.
pub fn wrap<C: ProofConstants>(
    params: WrapParams,
    circuit: &WrapCircuit,
) -> anyhow::Result<WrapOutput> {
    let step_proof = params.step_proof;
    let Prepared {
        witness,
        mut statement,
        x_hat_evals,
        prev_challenges,
    } = prepare(params)?;

    let proof = circuit.prove::<C>(&witness, prev_challenges)?;

    // A Pickles proof carries `old_bulletproof_challenges` at length 2, padded in front with the
    // dummy challenges (`Wrap_hack.pad_proof`). The circuit absorbed them already, in their expanded
    // form; the proof holds the 128-bit prechallenges.
    let wrap_messages = &mut statement.proof_state.messages_for_next_wrap_proof;
    while wrap_messages.old_bulletproof_challenges.len() < 2 {
        let prechallenges = ledger::proofs::unfinalized::dummy_ipa_wrap_challenges()
            .map(|[lo, hi]| Fq::from(ark_ff::BigInteger256::new([lo, hi, 0, 0])));
        wrap_messages.old_bulletproof_challenges.insert(0, prechallenges);
    }

    let proof = WrapProof {
        proof,
        statement,
        prev_evals: AllEvals {
            ft_eval1: step_proof.proof.ft_eval1,
            evals: EvalsWithPublicInput {
                public_input: (x_hat_evals.zeta, x_hat_evals.zeta_omega),
                evals: step_proof.proof.evals.clone(),
            },
        },
    };
    Ok(WrapOutput { proof, witness })
}

/// A wrap proof, and the witness it was proved from.
pub struct WrapOutput {
    pub proof: WrapProof,
    pub witness: WrapWitness,
}

/// A dummy slot: what Pickles puts in front of the previous proofs of a method that verifies fewer than
/// the program's maximum.
fn dummy_slot(unfinalized: Unfinalized, local_max: usize, wrap_domain_index: u64) -> PreviousSlot {
    PreviousSlot {
        unfinalized,
        sg: InnerCurve::<Fq>::from(dummy_ipa_step_sg()),
        old_bulletproof_challenges: vec![MessagesForNextWrapProof::dummy_padding(); local_max],
        evals: AllEvals::dummy(),
        wrap_domain_index,
    }
}

fn prepare(params: WrapParams) -> anyhow::Result<Prepared> {
    let WrapParams {
        max_proofs_verified,
        step_circuits,
        branch,
        features,
        step_proof,
        previous_proofs,
        previous_max_proofs_verified,
    } = params;
    anyhow::ensure!(
        max_proofs_verified <= MAX_PROOFS_VERIFIED,
        "a program verifies at most {MAX_PROOFS_VERIFIED} proofs (Pickles' maximum), not {max_proofs_verified}"
    );
    anyhow::ensure!(branch < step_circuits.len(), "no such branch");
    anyhow::ensure!(
        previous_max_proofs_verified.len() == max_proofs_verified,
        "previous_max_proofs_verified has one entry per slot: {max_proofs_verified}, not {}",
        previous_max_proofs_verified.len()
    );
    let step_widths = step_circuits
        .iter()
        .map(|c| c.proofs_verified() as u64)
        .collect::<Vec<_>>();
    anyhow::ensure!(
        step_widths.iter().all(|w| *w as usize <= max_proofs_verified),
        "a method verifies more proofs than the program's maxProofsVerified of {max_proofs_verified}"
    );
    let width = step_widths[branch] as usize;
    anyhow::ensure!(
        previous_proofs.len() == width,
        "method {branch} verifies {width} proofs, but {} previous proofs were given",
        previous_proofs.len()
    );

    let branch_features = step_circuits
        .iter()
        .map(|c| step_features(c.index()))
        .collect::<Vec<_>>();
    anyhow::ensure!(
        format!("{:?}", union_features(&branch_features)) == format!("{features:?}"),
        "the feature flags are not the union of the methods' flags"
    );
    let flags = ProgramFlags::of_branches(&branch_features);
    let step_keys = step_circuits
        .iter()
        .map(|c| StepKey::of_index(c.index()))
        .collect::<Vec<_>>();
    let step_domains = step_circuits
        .iter()
        .map(|c| Domains {
            h: Domain::Pow2RootsOfUnity(c.index().verifier_index().domain.log_size_of_group as u64),
        })
        .collect::<Vec<_>>();
    let step_index = step_circuits[branch].index();

    // The step proof's public input: an unfinalized proof for each slot, the hash of its
    // `messages_for_next_step_proof` and the hash of each slot's `messages_for_next_wrap_proof`.
    let public = &step_proof.public_input;
    let n = max_proofs_verified;
    anyhow::ensure!(
        public.len() == n * UNFINALIZED_FIELDS + 1 + n,
        "a step proof of a program that verifies at most {n} proofs has {} public inputs, not {}",
        n * UNFINALIZED_FIELDS + 1 + n,
        public.len()
    );
    let to_u = |f: Fp| {
        let b: BigInteger256 = f.into();
        b.0
    };
    let unfinalized_proofs = public[..n * UNFINALIZED_FIELDS]
        .chunks(UNFINALIZED_FIELDS)
        .map(unfinalized_of_fields)
        .collect::<anyhow::Result<Vec<_>>>()?;
    let messages_for_next_step_proof_hash = to_u(public[n * UNFINALIZED_FIELDS]);
    let public_messages_for_next_wrap_proof = &public[n * UNFINALIZED_FIELDS + 1..];

    // What the step proof carries of its previous proofs.
    let mut previous = previous_proofs.iter().map(expand).collect::<anyhow::Result<Vec<_>>>()?;
    anyhow::ensure!(
        step_proof.proof.prev_challenges.len() == width,
        "the step proof has {} accumulators, but method {branch} verifies {width} proofs",
        step_proof.proof.prev_challenges.len()
    );
    // A previous proof the step did not verify (a dummy) is accumulated as the challenge polynomial of the
    // challenges the step derived, not as the proof's own `sg`.
    let padding = n - width;
    for (j, prev) in previous.iter_mut().enumerate() {
        let unfinalized = &unfinalized_proofs[padding + j];
        if !unfinalized.should_finalize {
            prev.wrap_sg = compute_sg(&unfinalized.deferred_values.bulletproof_challenges);
        }
    }
    let prev_challenges_of_step_proof = step_proof
        .proof
        .prev_challenges
        .iter()
        .map(|c| {
            <[Fp; 16]>::try_from(c.chals.clone())
                .map_err(|_| anyhow::anyhow!("a step accumulator has 16 challenges"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    // Dummies in front, then the previous proofs.
    let mut slots = Vec::with_capacity(n);
    for (i, unfinalized) in unfinalized_proofs.iter().enumerate() {
        let local_max = previous_max_proofs_verified[i];
        if i < padding {
            slots.push(dummy_slot(unfinalized.clone(), local_max, DUMMY_WRAP_DOMAIN_INDEX));
            continue;
        }
        let prev = &previous[i - padding];
        anyhow::ensure!(
            prev.max_proofs_verified <= local_max,
            "the proof in slot {i} comes from a program that verifies {} proofs, more than slot {i}'s {local_max}",
            prev.max_proofs_verified
        );
        let mut old = prev.old_bulletproof_challenges[2 - prev.max_proofs_verified..].to_vec();
        while old.len() < local_max {
            old.insert(0, MessagesForNextWrapProof::dummy_padding());
        }
        slots.push(PreviousSlot {
            unfinalized: unfinalized.clone(),
            sg: prev.sg.clone(),
            old_bulletproof_challenges: old,
            evals: prev.evals.clone(),
            wrap_domain_index: prev.max_proofs_verified as u64,
        });
    }
    // The step statement hashes the accumulators it was given; they must be the previous proofs'.
    for (i, slot) in slots.iter().enumerate() {
        let mut all = slot.old_bulletproof_challenges.clone();
        while all.len() < 2 {
            all.insert(0, MessagesForNextWrapProof::dummy_padding());
        }
        let hash = MessagesForNextWrapProof {
            challenge_polynomial_commitment: slot.sg.clone(),
            old_bulletproof_challenges: all,
        }
        .hash();
        anyhow::ensure!(
            hash == to_u(public_messages_for_next_wrap_proof[i]),
            "the accumulator of the previous proof in slot {i} is not the one the step proof hashed"
        );
    }

    let d = deferred_values(DeferredValuesParams {
        prev_challenges: prev_challenges_of_step_proof,
        proof_with_public: step_proof,
        actual_proofs_verified: width,
        prover_index: step_index,
        features: branch_features[branch].clone(),
    });

    // `messages_for_next_wrap_proof`: this proof's own accumulator, and the challenges of the proofs it
    // verified, which the circuit finalized. A Pickles proof carries them at length 2.
    let expand_chals = |u: &Unfinalized| {
        u.deferred_values
            .bulletproof_challenges
            .iter()
            .map(expand_prechallenge)
            .collect::<Vec<_>>()
    };
    let to_fq = |[a, b]: [u64; 2]| Fq::from(BigInteger256::new([a, b, 0, 0]));
    let messages_for_next_wrap_proof = MessagesForNextWrapProof {
        challenge_polynomial_commitment: InnerCurve::of_affine(step_proof.proof.proof.sg),
        old_bulletproof_challenges: unfinalized_proofs
            .iter()
            .map(|u| {
                // The 128-bit prechallenges, which the proof carries.
                let chals: Vec<Fq> = u.deferred_values.bulletproof_challenges.iter().copied().map(to_fq).collect();
                <[Fq; 15]>::try_from(chals).map_err(|_| anyhow::anyhow!("15 challenges"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?,
    };
    let messages_for_next_wrap_proof_prepared = MessagesForNextWrapProof {
        challenge_polynomial_commitment: messages_for_next_wrap_proof.challenge_polynomial_commitment.clone(),
        old_bulletproof_challenges: unfinalized_proofs
            .iter()
            .map(|u| <[Fq; 15]>::try_from(expand_chals(u)).map_err(|_| anyhow::anyhow!("15 challenges")))
            .collect::<anyhow::Result<Vec<_>>>()?,
    };
    let messages_for_next_wrap_proof_hash = messages_for_next_wrap_proof_prepared.hash();

    // The wrap proof's accumulators: the dummy in front if the program verifies fewer than 2 proofs, then
    // one for each slot (its proof's own accumulator, or the dummy).
    let mut prev_challenges = Vec::with_capacity(MAX_PROOFS_VERIFIED);
    let dummy_accumulator = || kimchi::proof::RecursionChallenge {
        comm: poly_commitment::PolyComm::<mina_curves::pasta::Pallas> {
            chunks: vec![dummy_ipa_wrap_sg()],
        },
        chals: MessagesForNextWrapProof::dummy_padding().to_vec(),
    };
    for _ in 0..(MAX_PROOFS_VERIFIED - n) {
        prev_challenges.push(dummy_accumulator());
    }
    for (i, unfinalized) in unfinalized_proofs.iter().enumerate() {
        prev_challenges.push(if i < padding {
            dummy_accumulator()
        } else {
            kimchi::proof::RecursionChallenge {
                comm: poly_commitment::PolyComm::<mina_curves::pasta::Pallas> {
                    chunks: vec![previous[i - padding].wrap_sg],
                },
                chals: expand_chals(unfinalized),
            }
        });
    }

    let next_statement = WrapStatement {
        proof_state: WrapProofState {
            deferred_values: d.deferred_values.clone(),
            sponge_digest_before_evaluations: d.sponge_digest_before_evaluations,
            messages_for_next_wrap_proof,
        },
        messages_for_next_step_proof: ReducedMessagesForNextStepProof {
            app_state: Rc::new(()),
            challenge_polynomial_commitments: previous
                .iter()
                .map(|p| InnerCurve::of_affine(p.wrap_sg))
                .collect(),
            old_bulletproof_challenges: previous.iter().map(|p| p.step_bulletproof_challenges).collect(),
        },
    };

    let primary = PreparedStatement {
        proof_state: ProofState {
            deferred_values: d.deferred_values.clone(),
            sponge_digest_before_evaluations: to_u(d.sponge_digest_before_evaluations),
            messages_for_next_wrap_proof: messages_for_next_wrap_proof_hash,
        },
        messages_for_next_step_proof: messages_for_next_step_proof_hash,
    }
    .to_public_input(WRAP_PUBLIC_INPUT_SIZE)?;

    let mut w = Witness::<Fq>::from_parts(primary, Vec::new());
    ledger::proofs::transaction::Check::check(&next_statement, &mut w);

    wrap_main(
        WrapMainParams {
            max_proofs_verified: n,
            step_widths: &step_widths,
            slots: &slots,
            step_keys: &step_keys,
            flags,
            which_index: branch as u64,
            step_domains,
            next_statement: &next_statement,
            messages_for_next_step_proof_hash,
            proof: step_proof,
            step_prover_index: step_index,
            feature_flags: &branch_features[branch],
        },
        &mut w,
    )?;

    Ok(Prepared {
        witness: WrapWitness::of_witness(&w)?,
        statement: next_statement,
        x_hat_evals: d.x_hat_evals,
        prev_challenges,
    })
}

/// The index of the wrap domain Pickles records for a dummy slot (`Vector.extend_front_exn ... Tock.Field.one`).
const DUMMY_WRAP_DOMAIN_INDEX: u64 = 1;

pub fn union_features(branches: &[FeatureFlags<bool>]) -> FeatureFlags<bool> {
    let any = |f: fn(&FeatureFlags<bool>) -> bool| branches.iter().any(f);
    FeatureFlags {
        range_check0: any(|f| f.range_check0),
        range_check1: any(|f| f.range_check1),
        foreign_field_add: any(|f| f.foreign_field_add),
        foreign_field_mul: any(|f| f.foreign_field_mul),
        xor: any(|f| f.xor),
        rot: any(|f| f.rot),
        lookup: any(|f| f.lookup),
        runtime_tables: any(|f| f.runtime_tables),
    }
}
