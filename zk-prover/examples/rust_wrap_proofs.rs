//! Wrap `land`'s and `setup`'s step proofs (`stepproof002`, `stepproof001`) in Rust and write each
//! as `rust_<method>_proof.json` in the directory given: `land_proof.json`'s shape, with `proof` the
//! Rust wrap proof in the form o1js's `verify` reads for a program (`maxProofsVerified` 0), for
//! `o1js/src/rust-wrap.test.ts`. Also `rust_witness_land_proof.json`, the same for `land` proved from
//! the Rust step witness rather than o1js's step proof. The toy zkApp's two methods, `plain` and
//! `recurse` (`fixture-gen/toy.mjs`), likewise as `rust_toy_<method>_proof.json`, at the program's
//! `maxProofsVerified` of 1. The real vault's ten cases (`vault_*`, `fixture-gen/vault-fixtures.ts`) likewise,
//! as `rust_vault_<case>_proof.json`. `fixture-gen/regenerate.sh --write` runs it.

use std::{io::Read, str::FromStr};

use base64::Engine as _;
use ledger::proofs::transaction::ProofWithPublic;
use mina_curves::pasta::Fp;
use zk_prover::{
    land_program::LandProgram,
    verify::{load_vk, WrapProof},
    witness::land::LandInputs,
    wrap::{deferred::step_features, union_features, wrap, PreviousProof, WrapCircuit, WrapParams},
    StepCircuit, StepLand, StepSetup, StepToyPlain, StepToyRecurse, StepVaultDefeat, StepVaultDeposit,
    StepVaultEscape, StepVaultFinalize, StepVaultMutualClose, StepVaultRaise, StepVaultReduce, StepVaultSetup,
    StepVaultSweepExpired, WrapLandSetup, WrapToy, WrapVault,
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

/// The real vault's cases, in the branch order of its methods: each fixture prefix with its branch.
const VAULT_CASES: [(&str, usize); 10] = [
    ("vault_setup", 0),
    ("vault_deposit", 1),
    ("vault_mutualClose", 2),
    ("vault_escape", 3),
    ("vault_finalize", 4),
    ("vault_defeat", 5),
    ("vault_raise", 6),
    ("vault_sweepExpired", 7),
    ("vault_reduce", 8),
    ("vault_reduce_recursive", 8),
];

/// The vault's methods, each as o1js proved it: the Rust wrap proof as o1js's `verify` reads it, in the
/// shape of a `JsonProof` (the zkApp public input, no output, `maxProofsVerified` 1).
fn vault(out: &std::path::Path) -> anyhow::Result<()> {
    let load = |n: &str| {
        (
            fixture(&format!("vault_{n}_gates.json")),
            fixture(&format!("vault_{n}_internal_vars.bin")),
            fixture(&format!("vault_{n}_rows_rev.bin")),
        )
    };
    let circuits = {
        let (g, i, r) = load("setup");
        let setup = StepCircuit::load::<StepVaultSetup>(&g, &i, &r)?;
        let (g, i, r) = load("deposit");
        let deposit = StepCircuit::load::<StepVaultDeposit>(&g, &i, &r)?;
        let (g, i, r) = load("mutualClose");
        let mutual_close = StepCircuit::load::<StepVaultMutualClose>(&g, &i, &r)?;
        let (g, i, r) = load("escape");
        let escape = StepCircuit::load::<StepVaultEscape>(&g, &i, &r)?;
        let (g, i, r) = load("finalize");
        let finalize = StepCircuit::load::<StepVaultFinalize>(&g, &i, &r)?;
        let (g, i, r) = load("defeat");
        let defeat = StepCircuit::load::<StepVaultDefeat>(&g, &i, &r)?;
        let (g, i, r) = load("raise");
        let raise = StepCircuit::load::<StepVaultRaise>(&g, &i, &r)?;
        let (g, i, r) = load("sweepExpired");
        let sweep = StepCircuit::load::<StepVaultSweepExpired>(&g, &i, &r)?;
        let (g, i, r) = load("reduce");
        let reduce = StepCircuit::load::<StepVaultReduce>(&g, &i, &r)?;
        [setup, deposit, mutual_close, escape, finalize, defeat, raise, sweep, reduce]
    };
    let refs: Vec<&StepCircuit> = circuits.iter().collect();
    let (g, i, r) = load("wrap");
    let circuit = WrapCircuit::load::<WrapVault>(&g, &i, &r)?;
    let features = union_features(&circuits.iter().map(|c| step_features(c.index())).collect::<Vec<_>>());
    let keys: serde_json::Value = serde_json::from_slice(&fixture("vault_keys.json"))?;

    for (case, branch) in VAULT_CASES {
        let previous_json = std::path::Path::new(&format!("{}/fixtures/{case}_previous.json.gz", env!("CARGO_MANIFEST_DIR")))
            .exists()
            .then(|| serde_json::from_slice::<serde_json::Value>(&fixture(&format!("{case}_previous.json"))))
            .transpose()?;
        let previous = match &previous_json {
            None => None,
            Some(f) => {
                let strs = |v: &serde_json::Value| -> Vec<String> {
                    v.as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect()
                };
                let mut public = Vec::new();
                for v in [&f["publicInput"], &f["publicOutput"]] {
                    public.extend(zk_prover::verify::fields(&strs(v).iter().map(String::as_str).collect::<Vec<_>>())?);
                }
                Some((
                    WrapProof::from_o1js_base64(f["proof"].as_str().unwrap())?,
                    load_vk(keys[f["key"].as_str().unwrap()]["data"].as_str().unwrap())?,
                    public,
                ))
            }
        };
        let previous_proofs: Vec<PreviousProof> = previous
            .iter()
            .map(|(proof, vk, public)| PreviousProof { proof, verification_key: vk, public_input: public })
            .collect();
        let proved = wrap::<WrapVault>(
            WrapParams {
                max_proofs_verified: 1,
                step_circuits: &refs,
                branch,
                features: features.clone(),
                step_proof: &case_step_proof(case),
                previous_proofs: &previous_proofs,
                previous_max_proofs_verified: &[1],
            },
            &circuit,
        )?;
        let public: Vec<String> = serde_json::from_slice(&fixture(&format!("{case}_zkapp_public.json")))?;
        let json = serde_json::json!({
            "publicInputFields": public,
            "publicOutputFields": Vec::<String>::new(),
            "maxProofsVerified": 1,
            "proof": WrapProof::from_prover(&proved.proof).to_o1js_program_base64_for(1)?,
        });
        std::fs::write(out.join(format!("rust_{case}_proof.json")), serde_json::to_vec(&json)?)?;
    }
    Ok(())
}

/// `<case>_stepproof`, o1js's step proof of a vault case, and its public input.
fn case_step_proof(case: &str) -> ProofWithPublic<Fp> {
    let b64 = String::from_utf8(fixture(&format!("{case}_stepproof.b64"))).unwrap();
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64.trim()).unwrap();
    let public: Vec<String> = serde_json::from_slice(&fixture(&format!("{case}_stepproof_public.json"))).unwrap();
    ProofWithPublic {
        proof: rmp_serde::from_slice(&bytes).unwrap(),
        public_input: public.iter().map(|s| Fp::from_str(s).unwrap()).collect(),
    }
}

fn main() -> anyhow::Result<()> {
    let out = std::path::PathBuf::from(
        std::env::args().nth(1).ok_or_else(|| anyhow::anyhow!("usage: rust_wrap_proofs <out dir>"))?,
    );
    toy(&out)?;
    vault(&out)?;
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
