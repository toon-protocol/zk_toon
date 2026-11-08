//! The toy `land` / `setup` program, proved in Rust from `land`'s arguments to the proof a
//! transaction carries: [`witness::land`](crate::witness::land), then [`crate::prove_step`], then
//! [`crate::wrap::wrap`].

use ark_ff::Zero as _;
use mina_curves::pasta::Fp;

use crate::{
    check_step, prove_step,
    verify::WrapProof,
    witness::land::{land_witness, LandInputs},
    wrap::{deferred::step_features, union_features, wrap, WrapCircuit, WrapParams},
    StepCircuit, StepLand, StepSetup, StepWitness, WrapLandSetup,
};

/// `land`'s position among the program's methods (`land`, then `setup`).
const LAND_BRANCH: usize = 0;

/// The program's circuits: both step circuits, since the wrap key covers both methods, and the wrap
/// circuit.
pub struct LandProgram {
    land: StepCircuit,
    setup: StepCircuit,
    wrap: WrapCircuit,
}

/// A proof of `land`, and the public input it verifies under.
pub struct ProvedLand {
    pub proof: WrapProof,
    /// The account update's hash and its calls' hash, which are `0` since `land` calls nothing.
    pub public_input: [Fp; 2],
}

impl LandProgram {
    /// Load the circuits. `file` returns the contents of a named, uncompressed fixture.
    pub fn load(file: impl Fn(&str) -> Vec<u8>) -> anyhow::Result<Self> {
        let parts = |c: &str| {
            (
                file(&format!("{c}_gates.json")),
                file(&format!("{c}_internal_vars.bin")),
                file(&format!("{c}_rows_rev.bin")),
            )
        };
        let (g, i, r) = parts("cs003");
        let land = StepCircuit::load::<StepLand>(&g, &i, &r)?;
        let (g, i, r) = parts("cs004");
        let setup = StepCircuit::load::<StepSetup>(&g, &i, &r)?;
        let (g, i, r) = parts("cs005");
        let wrap = WrapCircuit::load::<WrapLandSetup>(&g, &i, &r)?;
        Ok(Self { land, setup, wrap })
    }

    /// Prove `land`. Fails if the inputs break the method, e.g. `cumulative` is not above `landed`.
    pub fn prove_land(&self, inputs: &LandInputs) -> anyhow::Result<ProvedLand> {
        let witness = land_witness(inputs)?;
        let public_input = [witness.account_update_hash, Fp::zero()];
        let witness = StepWitness::from(witness);
        // kimchi's prover panics on an unsatisfied constraint; this check returns the error instead.
        check_step::<StepLand>(&self.land, &witness)?;
        let step_proof = prove_step::<StepLand>(&self.land, &witness)?;
        let features = union_features(&[step_features(self.land.index()), step_features(self.setup.index())]);
        let wrapped = wrap::<WrapLandSetup>(
            WrapParams {
                max_proofs_verified: 0,
                step_circuits: &[&self.land, &self.setup],
                branch: LAND_BRANCH,
                features,
                step_proof: &step_proof,
                previous_proofs: &[],
                previous_max_proofs_verified: &[],
            },
            &self.wrap,
        )?;
        Ok(ProvedLand { proof: WrapProof::from_prover(&wrapped.proof), public_input })
    }
}
