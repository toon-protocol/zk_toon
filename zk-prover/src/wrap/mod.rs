//! The Pickles wrap prover for an o1js program: [`wrap`] takes a step proof and returns the wrap
//! witness (and, once the wrap circuit is proved, the wrap proof).
//!
//! mina-rust's `wrap` / `wrap_main` fix the number of previous proofs at 2, take a single step key
//! and leave out optional gates and lookups. This module is a generalised copy: the number of
//! previous proofs, the program's step keys (one per method) and its feature flags are parameters.
//! See the headers of the submodules for what each is derived from.

use std::rc::Rc;

use ledger::proofs::{
    public_input::{
        messages::MessagesForNextWrapProof,
        prepared_statement::{PreparedStatement, ProofState},
    },
    step::FeatureFlags,
    transaction::{InnerCurve, ProofWithPublic, ReducedMessagesForNextStepProof},
    witness::Witness,
    wrap::{Domain, Domains, WrapProofState, WrapStatement},
};
use mina_curves::pasta::{Fp, Fq};

use crate::StepCircuit;

pub mod deferred;
pub mod endo;
pub mod group_map;
pub mod key;
pub mod main_circuit;
pub mod opt_sponge;
pub mod verifier;

use ark_ff::BigInteger256;
use deferred::{deferred_values, step_features, DeferredValuesParams};
use key::StepKey;
use main_circuit::{wrap_main, ProgramFlags, WrapMainParams};

/// The public input size of a wrap circuit.
const WRAP_PUBLIC_INPUT_SIZE: usize = 40;

/// What the wrap proves.
pub struct WrapParams<'a> {
    /// The most previous proofs any method of the program verifies (`maxProofsVerified`). Only 0
    /// is supported; recursion lands with #32.
    pub max_proofs_verified: usize,
    /// The program's step circuits, one per method, in method order.
    pub step_circuits: &'a [&'a StepCircuit],
    /// The index of the method the step proof is for.
    pub branch: usize,
    /// The union of the methods' feature flags.
    pub features: FeatureFlags<bool>,
    /// The step proof, with its public input.
    pub step_proof: &'a ProofWithPublic<Fp>,
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
            let end = start + text[start..].find(']').unwrap();
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

thread_local! {
    /// o1js's witness, when a test wants [`trace`] to report where ours leaves it.
    pub static EXPECTED: std::cell::RefCell<Option<Vec<Fq>>> = const { std::cell::RefCell::new(None) };
}

/// Report how far `w` agrees with [`EXPECTED`]: for debugging a port against o1js.
pub(crate) fn trace(label: &str, w: &Witness<Fq>) {
    EXPECTED.with(|e| {
        let e = e.borrow();
        let Some(expected) = e.as_ref() else { return };
        let Ok(ours) = WrapWitness::of_witness(w) else { return };
        let len = ours.external().len();
        match ours.first_difference(&expected[..len.min(expected.len())]) {
            None => eprintln!("trace {label}: {len} values agree"),
            Some(i) => {
                eprintln!(
                    "trace {label}: {len} values, first difference at {i}: ours {:?} o1js {:?}",
                    ours.external().get(i),
                    expected.get(i)
                );
                if std::env::var("TRACE_WINDOW").is_ok() {
                    let short = |f: Option<&Fq>| f.map(|f| { let s = f.to_string(); s.chars().take(12).collect::<String>() }).unwrap_or_default();
                    let ext = ours.external();
                    for j in i.saturating_sub(40)..(i + 40).min(len) {
                        eprintln!("  {j}: ours {} o1js {}", short(ext.get(j)), short(expected.get(j)));
                    }
                }
            }
        }
    });
}

/// The wrap witness for a step proof.
pub fn wrap_witness(params: WrapParams) -> anyhow::Result<WrapWitness> {
    let WrapParams {
        max_proofs_verified,
        step_circuits,
        branch,
        features,
        step_proof,
    } = params;
    anyhow::ensure!(
        max_proofs_verified == 0,
        "wrapping a program that verifies proofs is not supported yet (#32)"
    );
    anyhow::ensure!(branch < step_circuits.len(), "no such branch");

    let branch_features = step_circuits
        .iter()
        .map(|c| step_features(c.index()))
        .collect::<Vec<_>>();
    anyhow::ensure!(
        format!("{:?}", union(&branch_features)) == format!("{features:?}"),
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

    // The step proof's public input is the hash of its `messages_for_next_step_proof`.
    let [messages_for_next_step_proof_hash] = step_proof.public_input.as_slice() else {
        anyhow::bail!("a step proof with no previous proofs has one public input")
    };
    let to_u = |f: Fp| {
        let b: BigInteger256 = f.into();
        b.0
    };
    let messages_for_next_step_proof_hash = to_u(*messages_for_next_step_proof_hash);

    let d = deferred_values(DeferredValuesParams {
        prev_challenges: vec![],
        proof_with_public: step_proof,
        actual_proofs_verified: 0,
        prover_index: step_index,
        features: branch_features[branch].clone(),
    });

    let messages_for_next_wrap_proof = MessagesForNextWrapProof {
        challenge_polynomial_commitment: InnerCurve::of_affine(step_proof.proof.proof.sg),
        old_bulletproof_challenges: vec![],
    };
    let messages_for_next_wrap_proof_hash = messages_for_next_wrap_proof.hash();

    let next_statement = WrapStatement {
        proof_state: WrapProofState {
            deferred_values: d.deferred_values.clone(),
            sponge_digest_before_evaluations: d.sponge_digest_before_evaluations,
            messages_for_next_wrap_proof,
        },
        messages_for_next_step_proof: ReducedMessagesForNextStepProof {
            app_state: Rc::new(()),
            challenge_polynomial_commitments: vec![],
            old_bulletproof_challenges: vec![],
        },
    };

    let primary = PreparedStatement {
        proof_state: ProofState {
            deferred_values: d.deferred_values,
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

    WrapWitness::of_witness(&w)
}

fn union(branches: &[FeatureFlags<bool>]) -> FeatureFlags<bool> {
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
