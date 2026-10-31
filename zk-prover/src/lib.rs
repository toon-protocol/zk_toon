//! Prove an o1js step circuit with mina-rust's kimchi prover, from the pinned fork (see [`pins`]).
//!
//! A [`StepCircuit`] is the circuit o1js dumps (gates JSON, `internal_vars.bin`, `rows_rev.bin`);
//! a [`StepWitness`] is the primary and auxiliary values for it. [`prove_step`] checks every
//! constraint and returns the step proof.
//!
//! The witness can come from o1js's own dump ([`StepWitness::from_o1js_json`]) or be built in Rust:
//! [`witness`] mirrors the o1js gadgets and Pickles' step circuit, and builds `land`'s witness
//! ([`witness::land::land_witness`]) equal to o1js's; [`StepWitness::from_parts`] takes it.
//!
//! [`wrap::wrap`] wraps a step proof into the Pickles wrap proof of an o1js program: given the
//! program's step circuits (one per method), its feature flags and its compiled wrap circuit, it
//! returns the wrap proof and the wrap witness, which equals o1js's value for value.

pub mod pins;
pub mod verify;
pub mod witness;
pub mod wrap;

use std::str::FromStr;

use ledger::proofs::{
    constants::ProofConstants,
    provers::{decode_constraints_data, decode_gates_file},
    toon1561::prove_step as kimchi_prove_step,
    transaction::{make_prover_index, ProofError, Prover},
    witness::Witness,
};
use mina_curves::pasta::Fp;

/// A step proof and its public input.
pub use ledger::proofs::transaction::ProofWithPublic as StepProof;

/// Shape of `land`'s step circuit (`cs003`).
pub use ledger::proofs::toon1561::{StepLand, StepSetup};

/// Shape of the wrap circuit of the toy `land` / `setup` program (`cs005`): 40 public inputs, and
/// the 2 previous challenges every Pickles wrap circuit has.
pub struct WrapLandSetup;
impl ProofConstants for WrapLandSetup {
    const PRIMARY_LEN: usize = 40;
    const AUX_LEN: usize = 99657;
    const PREVIOUS_CHALLENGES: usize = 2;
    const ROWS: usize = 6798;
}

/// Shape of `setup`'s step circuit (`cs004`).
pub use ledger::proofs::toon1561::StepSetup;

/// A compiled step circuit with its prover index.
pub struct StepCircuit {
    prover: Prover<Fp>,
}

impl StepCircuit {
    /// Build the prover index from o1js's circuit dump. `C` fixes the circuit's size.
    pub fn load<C: ProofConstants>(
        gates_json: &[u8],
        internal_vars: &[u8],
        rows_rev: &[u8],
    ) -> anyhow::Result<Self> {
        let gates = decode_gates_file::<Fp>(gates_json)?;
        let (internal_vars, rows_rev) = decode_constraints_data::<Fp>(internal_vars, rows_rev)
            .ok_or_else(|| anyhow::anyhow!("cannot decode internal_vars / rows_rev"))?;
        let index = make_prover_index::<C, Fp>(gates, None);
        Ok(Self {
            prover: Prover {
                internal_vars,
                rows_rev,
                index,
            },
        })
    }

    /// The kimchi prover index, from which the step verification key is read.
    pub fn index(&self) -> &ledger::proofs::ProverIndex<Fp> {
        &self.prover.index
    }
}

impl StepCircuit {
    /// The step circuit's verification key hash: kimchi's digest of its verifier index, which
    /// Pickles absorbs for the step key, as a decimal field element. It depends on the circuit
    /// alone, so a rerun of o1js's compile gives the same value (see [`pins`]).
    pub fn vk_hash(&mut self) -> String {
        use ark_ff::PrimeField;
        let digest = self
            .prover
            .index
            .compute_verifier_index_digest::<<Fp as ledger::proofs::field::FieldWitness>::FqSponge>();
        digest.into_bigint().to_string()
    }
}

/// The values a step circuit is proved from.
pub struct StepWitness(Witness<Fp>);

impl StepWitness {
    /// A witness built in Rust (or anywhere else): public input, then the auxiliary values.
    pub fn from_parts(primary: Vec<Fp>, aux: Vec<Fp>) -> Self {
        Self(Witness::from_parts(primary, aux))
    }

    /// o1js's witness dump: `{ "public_input_size": n, "external": ["decimal", ...] }`.
    pub fn from_o1js_json(json: &[u8]) -> anyhow::Result<Self> {
        let v: serde_json::Value = serde_json::from_slice(json)?;
        let n = v["public_input_size"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("missing public_input_size"))? as usize;
        let external = v["external"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("missing external"))?
            .iter()
            .map(|x| {
                let s = x.as_str().ok_or_else(|| anyhow::anyhow!("non-string value"))?;
                Fp::from_str(s).map_err(|_| anyhow::anyhow!("bad field element {s}"))
            })
            .collect::<anyhow::Result<Vec<Fp>>>()?;
        anyhow::ensure!(n <= external.len(), "public_input_size exceeds the witness");
        Ok(Self::from_parts(external[..n].to_vec(), external[n..].to_vec()))
    }
}

/// Check every constraint of `circuit` against `witness`, without proving.
pub fn check_step<C: ProofConstants>(
    circuit: &StepCircuit,
    witness: &StepWitness,
) -> anyhow::Result<()> {
    // The constraint-only mode reports success as an error, to short-circuit.
    match kimchi_prove_step::<C>(&circuit.prover, &witness.0, true) {
        Err(e) if matches!(e.downcast_ref::<ProofError>(), Some(ProofError::ConstraintsOk)) => {
            Ok(())
        }
        Err(e) => Err(e),
        Ok(_) => anyhow::bail!("constraint check unexpectedly produced a proof"),
    }
}

/// Prove the step circuit. Fails if any constraint is unsatisfied.
pub fn prove_step<C: ProofConstants>(
    circuit: &StepCircuit,
    witness: &StepWitness,
) -> anyhow::Result<StepProof<Fp>> {
    kimchi_prove_step::<C>(&circuit.prover, &witness.0, false)
}
