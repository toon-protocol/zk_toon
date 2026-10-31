//! The Rust wrap proofs verify under the program's verification key, the one o1js compiled
//! (`inputs.json`), for both methods, and a tampered proof or public input is refused.

use std::{io::Read, str::FromStr, sync::OnceLock};

use base64::Engine as _;
use ledger::proofs::transaction::ProofWithPublic;
use mina_curves::pasta::Fp;
use zk_prover::{
    pins,
    verify::{fields, load_vk, verify, WrapProof},
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

fn json(name: &str) -> serde_json::Value {
    serde_json::from_slice(&fixture(name)).unwrap()
}

fn strs(v: &serde_json::Value) -> Vec<&str> {
    v.as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect()
}

fn step_proof(n: &str) -> ProofWithPublic<Fp> {
    let b64 = String::from_utf8(fixture(&format!("stepproof{n}.b64"))).unwrap();
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64.trim()).unwrap();
    let public: Vec<String> = serde_json::from_slice(&fixture(&format!("stepproof{n}_public.json"))).unwrap();
    ProofWithPublic {
        proof: rmp_serde::from_slice(&bytes).unwrap(),
        public_input: public.iter().map(|s| Fp::from_str(s).unwrap()).collect(),
    }
}

/// The Rust wrap proof of the step proof of `branch` (0 `land`, 1 `setup`), proved once per method,
/// as o1js reads it. (The prover's own type holds an `Rc`, so it cannot sit in a static.)
fn rust_wrap(branch: usize) -> &'static str {
    static OUT: [OnceLock<String>; 2] = [OnceLock::new(), OnceLock::new()];
    OUT[branch].get_or_init(|| {
        let load = |c: &str| {
            (
                fixture(&format!("{c}_gates.json")),
                fixture(&format!("{c}_internal_vars.bin")),
                fixture(&format!("{c}_rows_rev.bin")),
            )
        };
        let (g, i, r) = load("cs003");
        let land = StepCircuit::load::<StepLand>(&g, &i, &r).unwrap();
        let (g, i, r) = load("cs004");
        let setup = StepCircuit::load::<StepSetup>(&g, &i, &r).unwrap();
        let (g, i, r) = load("cs005");
        let circuit = WrapCircuit::load::<WrapLandSetup>(&g, &i, &r).unwrap();
        let features = union_features(&[step_features(land.index()), step_features(setup.index())]);
        let out = wrap::<WrapLandSetup>(
            WrapParams {
                max_proofs_verified: 0,
                step_circuits: &[&land, &setup],
                branch,
                features,
                step_proof: &step_proof(["002", "001"][branch]),
            },
            &circuit,
        )
        .unwrap();
        WrapProof::from_prover(&out.proof).to_o1js_base64()
    })
}

fn program_vk() -> ledger::VerificationKey {
    let vk = load_vk(json("inputs.json")["vk"].as_str().unwrap()).unwrap();
    use ark_ff::PrimeField;
    assert_eq!(vk.hash().into_bigint().to_string(), pins::PROGRAM_VK_HASH);
    vk
}

/// The public input and output fields o1js proved the method's call under.
fn public(method_proof: &str) -> Vec<Fp> {
    let f = json(method_proof);
    let mut public = fields(&strs(&f["publicInputFields"])).unwrap();
    public.extend(fields(&strs(&f["publicOutputFields"])).unwrap());
    public
}

fn accepted_and_tampering_refused(branch: usize, o1js_proof: &str) {
    let vk = program_vk();
    let b64 = rust_wrap(branch);
    let public = public(o1js_proof);
    let proof = WrapProof::from_o1js_base64(b64).unwrap();
    assert!(verify(&vk, &public, &proof), "the Rust wrap proof is refused under the program VK");

    let mut tampered = public.clone();
    tampered[0] += Fp::from(1u64);
    assert!(!verify(&vk, &tampered, &proof), "a changed public input is accepted");
    let mut tampered = public.clone();
    *tampered.last_mut().unwrap() += Fp::from(1u64);
    assert!(!verify(&vk, &tampered, &proof), "a changed last public input is accepted");

    // A changed wrap challenge and a changed opening-proof scalar still parse, and are refused.
    for marker in ["(alpha((inner(", "(z_1 0x"] {
        let changed = WrapProof::from_o1js_base64(&flip_after(b64, marker)).unwrap();
        assert!(!verify(&vk, &public, &changed), "a changed {marker} is accepted");
    }
}

/// Flip the lowest bit of the hex digit that follows the first `marker`'s last-but-fifteenth place.
fn flip_after(b64: &str, marker: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE;
    let mut sexp = String::from_utf8(URL_SAFE.decode(b64).unwrap()).unwrap();
    let at = sexp.find(marker).unwrap() + marker.len() + 15;
    let digit = sexp[at..at + 1].chars().next().unwrap().to_digit(16).unwrap();
    sexp.replace_range(at..at + 1, &format!("{:X}", digit ^ 1));
    URL_SAFE.encode(sexp)
}

#[test]
fn land_wrap_proof_verifies_under_the_program_vk() {
    accepted_and_tampering_refused(0, "land_proof.json");
}

#[test]
fn setup_wrap_proof_verifies_under_the_program_vk() {
    accepted_and_tampering_refused(1, "setup_proof.json");
}

/// The export reads back as the same proof, and writes o1js's own proof back byte for byte.
#[test]
fn export_round_trips_o1js_proofs() {
    for name in ["land_proof.json", "setup_proof.json"] {
        let b64 = json(name)["proof"].as_str().unwrap().to_string();
        let proof = WrapProof::from_o1js_base64(&b64).unwrap();
        assert_eq!(proof.to_o1js_base64(), b64, "{name}");
    }
}

/// The committed `rust_<method>_proof.json` (what the o1js test verifies) is a Rust wrap proof of
/// the committed step proofs: the program form is the transaction form without the dummy challenges,
/// and the transaction form of the proof proved here verifies in Rust.
#[test]
fn committed_rust_proofs_verify_in_rust() {
    use base64::engine::general_purpose::URL_SAFE;
    let vk = program_vk();
    for (branch, method) in [(0, "land"), (1, "setup")] {
        let f = json(&format!("rust_{method}_proof.json"));
        let program = f["proof"].as_str().unwrap();
        // The committed proof is shorter than the one proved here by exactly the dummy challenges.
        let full = String::from_utf8(URL_SAFE.decode(rust_wrap(branch)).unwrap()).unwrap();
        let committed = String::from_utf8(URL_SAFE.decode(program).unwrap()).unwrap();
        assert!(committed.contains("(old_bulletproof_challenges())"), "{method}");
        assert!(full.len() > committed.len(), "{method}");
        // Reading it back (padding it as a side-loaded verifier does) gives a proof that verifies.
        let proof = WrapProof::from_o1js_base64(program).unwrap();
        assert!(verify(&vk, &public(&format!("{method}_proof.json")), &proof), "{method}");
    }
}
