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
//! returns the wrap proof and the wrap witness, which equals o1js's value for value. A method may
//! verify previous proofs (up to Pickles' maximum of 2): the step proof's previous proofs are
//! [`wrap::PreviousProof`]s.
//!
//! [`land_program::LandProgram`] puts these together: `land`'s arguments in, a proof for its
//! transaction out.

pub mod land_program;
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

/// Shape of `land`'s step circuit (`cs003`) and `setup`'s (`cs004`).
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

/// Shape of the step circuits of the toy zkApp (`fixture-gen/toy.mjs`): `plain` (`toy_plain_*`) verifies
/// no proof and `recurse` (`toy_recurse_*`) verifies one. Both have 34 public inputs: the unfinalized
/// proof (32), the `messages_for_next_step_proof` hash and the `messages_for_next_wrap_proof` hash.
pub struct StepToyPlain;
impl ProofConstants for StepToyPlain {
    const PRIMARY_LEN: usize = 34;
    const AUX_LEN: usize = 13552;
    const PREVIOUS_CHALLENGES: usize = 0;
    const ROWS: usize = 1100;
}

pub struct StepToyRecurse;
impl ProofConstants for StepToyRecurse {
    const PRIMARY_LEN: usize = 34;
    const AUX_LEN: usize = 143968;
    const PREVIOUS_CHALLENGES: usize = 1;
    const ROWS: usize = 10733;
}

/// Shapes of the step circuits of the real vault (`vault_<method>_*`, `fixture-gen/vault-fixtures.ts`), for
/// [`StepCircuit::load`], which reads `ROWS` and `PREVIOUS_CHALLENGES`. Each has the 34 public inputs of a
/// program of `maxProofsVerified` 1. `AUX_LEN` is 0: no step witness is built for them (the step proofs
/// are o1js's), so nothing reads it.
macro_rules! vault_step {
    ($($name:ident: $rows:expr, $verifies:expr;)*) => {$(
        pub struct $name;
        impl ProofConstants for $name {
            const PRIMARY_LEN: usize = 34;
            const AUX_LEN: usize = 0;
            const PREVIOUS_CHALLENGES: usize = $verifies;
            const ROWS: usize = $rows;
        }
    )*};
}
vault_step! {
    StepVaultSetup: 2096, 0;
    StepVaultDeposit: 2461, 0;
    StepVaultMutualClose: 13028, 1;
    StepVaultEscape: 13170, 1;
    StepVaultFinalize: 2335, 0;
    StepVaultDefeat: 12591, 1;
    StepVaultRaise: 12666, 1;
    StepVaultSweepExpired: 7169, 0;
    StepVaultReduce: 56124, 1;
}

/// Shape of the vault's wrap circuit (`vault_wrap_*`), shared by its methods.
pub struct WrapVault;
impl ProofConstants for WrapVault {
    const PRIMARY_LEN: usize = 40;
    const AUX_LEN: usize = 144735;
    const PREVIOUS_CHALLENGES: usize = 2;
    const ROWS: usize = 11814;
}

/// Shape of the wrap circuit of the toy zkApp (`toy_wrap_*`), shared by both methods.
pub struct WrapToy;
impl ProofConstants for WrapToy {
    const PRIMARY_LEN: usize = 40;
    const AUX_LEN: usize = 133337;
    const PREVIOUS_CHALLENGES: usize = 2;
    const ROWS: usize = 10150;
}

/// A compiled step circuit with its prover index.
pub struct StepCircuit {
    prover: Prover<Fp>,
    proofs_verified: usize,
}

impl StepCircuit {
    /// Build the prover index from o1js's circuit dump. `C` fixes the circuit's size; for a step circuit
    /// its `PREVIOUS_CHALLENGES` is how many proofs the method verifies.
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
            proofs_verified: C::PREVIOUS_CHALLENGES,
        })
    }

    /// How many proofs the method verifies: the accumulators its step proof carries.
    pub fn proofs_verified(&self) -> usize {
        self.proofs_verified
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
