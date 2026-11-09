//! The toy zkApp (`fixture-gen/toy.mjs`) proved in Rust: a method's arguments and, for `recurse`, the
//! proof of `toy-inner` it verifies in, a proof for its transaction out. The same layers as
//! [`crate::land_program::LandProgram`], with a previous proof.

use ark_ff::Zero;
use mina_curves::pasta::Fp;

use crate::{
    check_step, prove_step, prove_step_verifying,
    verify::WrapProof,
    witness::toy::{plain_witness, recurse_witness, ToyInputs, ToyWitness},
    wrap::{deferred::step_features, union_features, wrap, PreviousProof, WrapCircuit, WrapParams},
    StepCircuit, StepToyPlain, StepToyRecurse, StepWitness, WrapToy,
};

/// The program's `maxProofsVerified`: `recurse` verifies one proof, so `plain` is wrapped for one too.
const MAX_PROOFS_VERIFIED: usize = 1;
const PLAIN_BRANCH: usize = 0;
const RECURSE_BRANCH: usize = 1;

/// The zkApp's step circuits, one per method, and the wrap circuit both share.
pub struct ToyProgram {
    plain: StepCircuit,
    recurse: StepCircuit,
    wrap: WrapCircuit,
}

/// A proof of a toy method, and the public input it verifies under.
pub struct ProvedToy {
    pub proof: WrapProof,
    /// The account update's hash and its calls' hash, which are `0` since the methods call nothing.
    pub public_input: [Fp; 2],
}

impl ToyProgram {
    /// Load the circuits. `file` returns the contents of a named, uncompressed fixture.
    pub fn load(file: impl Fn(&str) -> Vec<u8>) -> anyhow::Result<Self> {
        let parts = |c: &str| {
            (
                file(&format!("{c}_gates.json")),
                file(&format!("{c}_internal_vars.bin")),
                file(&format!("{c}_rows_rev.bin")),
            )
        };
        let (g, i, r) = parts("toy_plain");
        let plain = StepCircuit::load::<StepToyPlain>(&g, &i, &r)?;
        let (g, i, r) = parts("toy_recurse");
        let recurse = StepCircuit::load::<StepToyRecurse>(&g, &i, &r)?;
        let (g, i, r) = parts("toy_wrap");
        let wrap = WrapCircuit::load::<WrapToy>(&g, &i, &r)?;
        Ok(Self { plain, recurse, wrap })
    }

    /// Prove `plain(x)`.
    pub fn prove_plain(&self, inputs: &ToyInputs) -> anyhow::Result<ProvedToy> {
        self.prove(PLAIN_BRANCH, plain_witness(inputs)?, &[])
    }

    /// Prove `recurse(x, proof)`, `previous` being the proof of `toy-inner` and its public input.
    pub fn prove_recurse(&self, inputs: &ToyInputs, previous: &PreviousProof) -> anyhow::Result<ProvedToy> {
        let witness = recurse_witness(inputs, previous)?;
        let previous = [PreviousProof {
            proof: previous.proof,
            verification_key: previous.verification_key,
            public_input: previous.public_input,
        }];
        self.prove(RECURSE_BRANCH, witness, &previous)
    }

    fn prove(&self, branch: usize, witness: ToyWitness, previous: &[PreviousProof]) -> anyhow::Result<ProvedToy> {
        let previous_proofs: Vec<&WrapProof> = previous.iter().map(|p| p.proof).collect();
        let public_input = [witness.account_update_hash, Fp::zero()];
        let witness = StepWitness::from(witness);
        // kimchi's prover panics on an unsatisfied constraint; this check returns the error instead.
        let step_proof = if branch == PLAIN_BRANCH {
            check_step::<StepToyPlain>(&self.plain, &witness)?;
            prove_step::<StepToyPlain>(&self.plain, &witness)?
        } else {
            check_step::<StepToyRecurse>(&self.recurse, &witness)?;
            prove_step_verifying::<StepToyRecurse>(&self.recurse, &witness, &previous_proofs)?
        };
        let features = union_features(&[step_features(self.plain.index()), step_features(self.recurse.index())]);
        let wrapped = wrap::<WrapToy>(
            WrapParams {
                max_proofs_verified: MAX_PROOFS_VERIFIED,
                step_circuits: &[&self.plain, &self.recurse],
                branch,
                features,
                step_proof: &step_proof,
                previous_proofs: previous,
                // one entry per slot of the program: `toy-inner` verifies no proof
                previous_max_proofs_verified: &[0],
            },
            &self.wrap,
        )?;
        Ok(ProvedToy { proof: WrapProof::from_prover(&wrapped.proof), public_input })
    }
}
