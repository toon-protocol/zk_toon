//! Wrap `land`'s and `setup`'s step proofs (`stepproof002`, `stepproof001`) in Rust and write each
//! as `rust_<method>_proof.json` in the directory given: `land_proof.json`'s shape, with `proof` the
//! Rust wrap proof in the form o1js's `verify` reads for a program (`maxProofsVerified` 0), for
//! `o1js/src/rust-wrap.test.ts`. `fixture-gen/regenerate.sh --write` runs it.

use std::{io::Read, str::FromStr};

use base64::Engine as _;
use ledger::proofs::transaction::ProofWithPublic;
use mina_curves::pasta::Fp;
use zk_prover::{
    verify::WrapProof,
    wrap::{deferred::step_features, union_features, wrap, WrapCircuit, WrapParams},
    StepCircuit, StepLand, StepSetup, WrapLandSetup,
};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/fixtures/{name}.gz", env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut out)
        .unwrap();
    out
}

fn step_proof(n: &str) -> ProofWithPublic<Fp> {
    let b64 = String::from_utf8(fixture(&format!("stepproof{n}.b64"))).unwrap();
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64.trim()).unwrap();
    let public: Vec<String> =
        serde_json::from_slice(&fixture(&format!("stepproof{n}_public.json"))).unwrap();
    ProofWithPublic {
        proof: rmp_serde::from_slice(&bytes).unwrap(),
        public_input: public.iter().map(|s| Fp::from_str(s).unwrap()).collect(),
    }
}

fn main() -> anyhow::Result<()> {
    let out = std::path::PathBuf::from(
        std::env::args().nth(1).ok_or_else(|| anyhow::anyhow!("usage: rust_wrap_proofs <out dir>"))?,
    );
    let load = |n: &str| {
        (
            fixture(&format!("{n}_gates.json")),
            fixture(&format!("{n}_internal_vars.bin")),
            fixture(&format!("{n}_rows_rev.bin")),
        )
    };
    let (g, i, r) = load("cs003");
    let land = StepCircuit::load::<StepLand>(&g, &i, &r)?;
    let (g, i, r) = load("cs004");
    let setup = StepCircuit::load::<StepSetup>(&g, &i, &r)?;
    let (g, i, r) = load("cs005");
    let circuit = WrapCircuit::load::<WrapLandSetup>(&g, &i, &r)?;
    let features = union_features(&[step_features(land.index()), step_features(setup.index())]);

    // Method order is the branch: `land`, then `setup`.
    for (branch, method, step) in [(0, "land", "002"), (1, "setup", "001")] {
        let proved = wrap::<WrapLandSetup>(
            WrapParams {
                max_proofs_verified: 0,
                step_circuits: &[&land, &setup],
                branch,
                features: features.clone(),
                step_proof: &step_proof(step),
            },
            &circuit,
        )?;
        let mut json: serde_json::Value = serde_json::from_slice(&fixture(&format!("{method}_proof.json")))?;
        json["proof"] = WrapProof::from_prover(&proved.proof).to_o1js_program_base64()?.into();
        std::fs::write(out.join(format!("rust_{method}_proof.json")), serde_json::to_vec(&json)?)?;
    }
    Ok(())
}
