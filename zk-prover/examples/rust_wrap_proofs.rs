//! Wrap `land`'s and `setup`'s step proofs (`stepproof002`, `stepproof001`) in Rust and write each
//! as `rust_<method>_proof.json` in the directory given: `land_proof.json`'s shape, with `proof` the
//! Rust wrap proof in the form o1js's `verify` reads for a program (`maxProofsVerified` 0), for
//! `o1js/src/rust-wrap.test.ts`. Also `rust_witness_land_proof.json`, the same for `land` proved from
//! the Rust step witness rather than o1js's step proof. The toy zkApp's two methods, `plain` and
//! `recurse` (`fixture-gen/toy.mjs`), likewise as `rust_toy_<method>_proof.json`, at the program's
//! `maxProofsVerified` of 1. `fixture-gen/regenerate.sh --write` runs it.

use std::{io::Read, str::FromStr};

use base64::Engine as _;
use ledger::proofs::transaction::ProofWithPublic;
use mina_curves::pasta::Fp;
use zk_prover::{
    land_program::LandProgram,
    verify::{load_vk, WrapProof},
    witness::land::LandInputs,
    wrap::{deferred::step_features, union_features, wrap, PreviousProof, WrapCircuit, WrapParams},
    StepCircuit, StepLand, StepSetup, StepToyPlain, StepToyRecurse, WrapLandSetup, WrapToy,
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

/// `toy_<method>_stepproof` and its public input.
fn toy_step_proof(method: &str) -> ProofWithPublic<Fp> {
    let b64 = String::from_utf8(fixture(&format!("toy_{method}_stepproof.b64"))).unwrap();
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64.trim()).unwrap();
    let public: Vec<String> =
        serde_json::from_slice(&fixture(&format!("toy_{method}_stepproof_public.json"))).unwrap();
    ProofWithPublic {
        proof: rmp_serde::from_slice(&bytes).unwrap(),
        public_input: public.iter().map(|s| Fp::from_str(s).unwrap()).collect(),
    }
}

/// The toy zkApp's two methods: `plain` verifies no proof, `recurse` one proof of `toy-inner`.
fn toy(out: &std::path::Path) -> anyhow::Result<()> {
    let load = |n: &str| {
        (
            fixture(&format!("{n}_gates.json")),
            fixture(&format!("{n}_internal_vars.bin")),
            fixture(&format!("{n}_rows_rev.bin")),
        )
    };
    let (g, i, r) = load("toy_plain");
    let plain = StepCircuit::load::<StepToyPlain>(&g, &i, &r)?;
    let (g, i, r) = load("toy_recurse");
    let recurse = StepCircuit::load::<StepToyRecurse>(&g, &i, &r)?;
    let (g, i, r) = load("toy_wrap");
    let circuit = WrapCircuit::load::<WrapToy>(&g, &i, &r)?;
    let features = union_features(&[step_features(plain.index()), step_features(recurse.index())]);

    let inputs: serde_json::Value = serde_json::from_slice(&fixture("toy_inputs.json"))?;
    let inner_proof: serde_json::Value = serde_json::from_slice(&fixture("toy_inner_proof.json"))?;
    let inner = WrapProof::from_o1js_base64(inner_proof["proof"].as_str().unwrap())?;
    let inner_vk = load_vk(inputs["innerVk"].as_str().unwrap())?;
    let inner_public = [Fp::from_str(inputs["innerPublicInput"].as_str().unwrap()).unwrap()];
    let previous = [PreviousProof { proof: &inner, verification_key: &inner_vk, public_input: &inner_public }];

    // Method order is the branch: `plain`, then `recurse`.
    for (branch, method) in [(0, "plain"), (1, "recurse")] {
        let proved = wrap::<WrapToy>(
            WrapParams {
                max_proofs_verified: 1,
                step_circuits: &[&plain, &recurse],
                branch,
                features: features.clone(),
                step_proof: &toy_step_proof(method),
                previous_proofs: &previous[..branch],
                previous_max_proofs_verified: &[0],
            },
            &circuit,
        )?;
        let mut json: serde_json::Value = serde_json::from_slice(&fixture(&format!("toy_{method}_proof.json")))?;
        json["proof"] = WrapProof::from_prover(&proved.proof).to_o1js_program_base64_for(1)?.into();
        std::fs::write(out.join(format!("rust_toy_{method}_proof.json")), serde_json::to_vec(&json)?)?;
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let out = std::path::PathBuf::from(
        std::env::args().nth(1).ok_or_else(|| anyhow::anyhow!("usage: rust_wrap_proofs <out dir>"))?,
    );
    toy(&out)?;
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
                previous_proofs: &[],
                previous_max_proofs_verified: &[],
            },
            &circuit,
        )?;
        let mut json: serde_json::Value = serde_json::from_slice(&fixture(&format!("{method}_proof.json")))?;
        json["proof"] = WrapProof::from_prover(&proved.proof).to_o1js_program_base64()?.into();
        std::fs::write(out.join(format!("rust_{method}_proof.json")), serde_json::to_vec(&json)?)?;
    }

    // `fixture-gen/prove-local.mjs`'s call: `landed` is 0, and the blinding value is its counter's 4.
    let inputs: serde_json::Value = serde_json::from_slice(&fixture("inputs.json"))?;
    let inputs = LandInputs::from_json(&inputs, 0, Fp::from(4u64))?;
    let proved = LandProgram::load(fixture)?.prove_land(&inputs)?;
    let mut json: serde_json::Value = serde_json::from_slice(&fixture("land_proof.json"))?;
    json["proof"] = proved.proof.to_o1js_program_base64()?.into();
    std::fs::write(out.join("rust_witness_land_proof.json"), serde_json::to_vec(&json)?)?;
    Ok(())
}
