//! Proving the wrap circuit.
//!
//! Derived from `create_proof` in `crates/ledger/src/proofs/transaction.rs` of
//! `toon-protocol/mina-rust` at rev `6feeb3797fff6dba49fd848cb2d6decd63fee1b4` (itself from
//! `o1-labs/mina-rust` v0.19.0, Apache-2.0), which is private there. Licensed under Apache-2.0;
//! see `LICENSE-APACHE` and `NOTICE`.

use kimchi::{groupmap::GroupMap, proof::RecursionChallenge};
use ledger::proofs::{
    constants::ProofConstants,
    field::FieldWitness,
    provers::{decode_constraints_data, decode_gates_file},
    transaction::{compute_witness, make_prover_index, ProofError, ProofWithPublic, Prover},
    witness::Witness,
};
use mina_curves::pasta::{Fq, Pallas};
use mina_poseidon::constants::PlonkSpongeConstantsKimchi;
use poly_commitment::commitment::CommitmentCurve;

/// A compiled wrap circuit with its prover index.
pub struct WrapCircuit {
    prover: Prover<Fq>,
}

impl WrapCircuit {
    /// Build the prover index from o1js's circuit dump. `C` fixes the circuit's size; a wrap
    /// circuit always has the 40 public inputs and 2 previous challenges.
    pub fn load<C: ProofConstants>(
        gates_json: &[u8],
        internal_vars: &[u8],
        rows_rev: &[u8],
    ) -> anyhow::Result<Self> {
        let gates = decode_gates_file::<Fq>(gates_json)?;
        let (internal_vars, rows_rev) = decode_constraints_data::<Fq>(internal_vars, rows_rev)
            .ok_or_else(|| anyhow::anyhow!("cannot decode internal_vars / rows_rev"))?;
        let index = make_prover_index::<C, Fq>(gates, None);
        Ok(Self {
            prover: Prover {
                internal_vars,
                rows_rev,
                index,
            },
        })
    }

    pub fn index(&self) -> &ledger::proofs::ProverIndex<Fq> {
        &self.prover.index
    }

    /// Check that `witness` satisfies every constraint of the circuit.
    pub fn check<C: ProofConstants>(&self, witness: &super::WrapWitness) -> anyhow::Result<()> {
        let w = Witness::<Fq>::from_parts(witness.primary.clone(), witness.aux.clone());
        let computed = compute_witness::<C, Fq>(&self.prover, &w);
        let public_input = computed[0][..self.prover.index.cs.public].to_vec();
        self.prover
            .index
            .verify(&computed, &public_input)
            .map_err(|e| ProofError::ConstraintsNotSatisfied(format!("incorrect witness: {e:?}")))?;
        Ok(())
    }

    /// Prove the circuit from `witness`, with the accumulators of the previous proofs.
    pub(super) fn prove<C: ProofConstants>(
        &self,
        witness: &super::WrapWitness,
        prev_challenges: Vec<RecursionChallenge<Pallas>>,
    ) -> anyhow::Result<ProofWithPublic<Fq>> {
        type EFrSponge = mina_poseidon::sponge::DefaultFrSponge<
            Fq,
            PlonkSpongeConstantsKimchi,
            { ledger::proofs::FULL_ROUNDS },
        >;

        let w = Witness::<Fq>::from_parts(witness.primary.clone(), witness.aux.clone());
        let computed_witness = compute_witness::<C, Fq>(&self.prover, &w);
        let prover_index = &self.prover.index;
        let public_input = computed_witness[0][..prover_index.cs.public].to_vec();

        let mut rng = rand::rngs::OsRng;
        let group_map = <<Fq as FieldWitness>::OtherCurve as CommitmentCurve>::Map::setup();
        let proof = kimchi::proof::ProverProof::create_recursive::<
            <Fq as FieldWitness>::FqSponge,
            EFrSponge,
            _,
        >(
            &group_map,
            computed_witness,
            &[],
            prover_index,
            prev_challenges,
            None,
            &mut rng,
        )
        .map_err(|e| anyhow::anyhow!("create_recursive: {e}"))?;

        Ok(ProofWithPublic {
            proof,
            public_input,
        })
    }
}
