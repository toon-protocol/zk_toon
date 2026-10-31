//! `setup`'s step circuit (`cs004`), proved from o1js's own witness (`w001`), and o1js's real
//! `setup` proof under the program's key.

use std::io::Read;

use zk_prover::{check_step, prove_step, StepCircuit, StepSetup, StepWitness};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/fixtures/{name}.gz", env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut out)
        .unwrap();
    out
}

#[test]
fn proves_cs004_from_o1js_witness() {
    let circuit = StepCircuit::load::<StepSetup>(
        &fixture("cs004_gates.json"),
        &fixture("cs004_internal_vars.bin"),
        &fixture("cs004_rows_rev.bin"),
    )
    .unwrap();
    let witness = StepWitness::from_o1js_json(&fixture("w001_cs004.json")).unwrap();
    check_step::<StepSetup>(&circuit, &witness).unwrap();
    let proof = prove_step::<StepSetup>(&circuit, &witness).unwrap();
    assert_eq!(proof.public_input.len(), 1);
}

#[test]
fn verifies_o1js_setup_proof() {
    use mina_curves::pasta::Fp;
    use zk_prover::verify::{fields, load_vk, verify, WrapProof};
    let f: serde_json::Value = serde_json::from_slice(&fixture("setup_proof.json")).unwrap();
    let vk = load_vk(f["verificationKey"]["data"].as_str().unwrap()).unwrap();
    let proof = WrapProof::from_o1js_base64(f["proof"].as_str().unwrap()).unwrap();
    let strs: Vec<&str> = f["publicInputFields"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
    let public = fields(&strs).unwrap();
    assert!(verify(&vk, &public, &proof));
    let mut tampered = public.clone();
    tampered[0] += Fp::from(1u64);
    assert!(!verify(&vk, &tampered, &proof));
}
