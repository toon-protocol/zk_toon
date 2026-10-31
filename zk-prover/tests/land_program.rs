//! `land` proved entirely in Rust, from a Rust step witness through the Rust wrap, verifies under
//! the program's verification key, the one o1js compiled.

use std::io::Read;

use ark_ff::Zero as _;
use mina_curves::pasta::Fp;
use zk_prover::{
    land_program::LandProgram,
    pins,
    verify::{load_vk, verify, WrapProof},
    witness::land::LandInputs,
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

/// `fixture-gen/prove-local.mjs`'s call: `landed` is 0, and the blinding value is its counter's 4.
fn land_inputs() -> LandInputs {
    LandInputs::from_json(&json("inputs.json"), 0, Fp::from(4u64)).unwrap()
}

fn program_vk() -> ledger::VerificationKey {
    let vk = load_vk(json("inputs.json")["vk"].as_str().unwrap()).unwrap();
    use ark_ff::PrimeField;
    assert_eq!(vk.hash().into_bigint().to_string(), pins::PROGRAM_VK_HASH);
    vk
}

#[test]
fn rust_proved_land_verifies_under_the_program_vk() {
    let proved = LandProgram::load(fixture).unwrap().prove_land(&land_inputs()).unwrap();
    let vk = program_vk();

    // The same call as o1js's, so the same public input.
    let o1js = json("land_proof.json");
    let expected = o1js["publicInputFields"].as_array().unwrap();
    assert_eq!(proved.public_input[0].to_string(), expected[0].as_str().unwrap());
    assert_eq!(proved.public_input[1].to_string(), expected[1].as_str().unwrap());
    assert!(proved.public_input[1].is_zero());

    assert!(verify(&vk, &proved.public_input, &proved.proof), "refused under the program VK");

    // It reads back as a transaction's proof, and a changed public input is refused.
    let read_back = WrapProof::from_o1js_base64(&proved.proof.to_o1js_base64()).unwrap();
    assert!(verify(&vk, &proved.public_input, &read_back));
    let mut tampered = proved.public_input;
    tampered[0] += Fp::from(1u64);
    assert!(!verify(&vk, &tampered, &proved.proof), "a changed public input is accepted");
}

/// The other arguments a chain would see: a later `landed`, another blinding. The public input
/// follows them, and the proof still verifies under the same key.
#[test]
fn rust_proved_land_verifies_for_other_arguments() {
    let mut inputs = land_inputs();
    inputs.landed = 3;
    inputs.blinding = Fp::from(77u64);
    let proved = LandProgram::load(fixture).unwrap().prove_land(&inputs).unwrap();
    assert_ne!(
        proved.public_input[0].to_string(),
        json("land_proof.json")["publicInputFields"][0].as_str().unwrap()
    );
    assert!(verify(&program_vk(), &proved.public_input, &proved.proof));
}

/// `land` refuses a `cumulative` that isn't above `landed`, and so does the prover.
#[test]
fn a_land_that_breaks_the_method_is_not_proved() {
    let mut inputs = land_inputs();
    inputs.landed = inputs.cumulative;
    let err = LandProgram::load(fixture).unwrap().prove_land(&inputs).err().expect("proved");
    assert!(err.to_string().contains("incorrect witness"), "{err:#}");
}

/// The proof `o1js/src/rust-wrap.test.ts` verifies is one of a Rust witness: it verifies here too.
#[test]
fn committed_rust_witness_proof_verifies_in_rust() {
    let f = json("rust_witness_land_proof.json");
    let public = land_public(&f);
    let proof = WrapProof::from_o1js_base64(f["proof"].as_str().unwrap()).unwrap();
    assert!(verify(&program_vk(), &public, &proof));
}

fn land_public(f: &serde_json::Value) -> Vec<Fp> {
    f["publicInputFields"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().parse().unwrap()).collect()
}
