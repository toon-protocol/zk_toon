//! The verifier accepts o1js's real `land` proof and refuses a changed public input.

use std::io::Read;

use mina_curves::pasta::Fp;
use zk_prover::verify::{fields, load_vk, verify, WrapProof};

fn fixture() -> serde_json::Value {
    let path = format!("{}/fixtures/land_proof.json.gz", env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut out)
        .unwrap();
    serde_json::from_slice(&out).unwrap()
}

fn strs(v: &serde_json::Value) -> Vec<&str> {
    v.as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect()
}

#[test]
fn verifies_o1js_land_proof_and_refuses_tampering() {
    let f = fixture();
    let vk = load_vk(f["verificationKey"]["data"].as_str().unwrap()).unwrap();
    assert_eq!(
        ledger_hash(&vk),
        f["verificationKey"]["hash"].as_str().unwrap()
    );
    let proof = WrapProof::from_o1js_base64(f["proof"].as_str().unwrap()).unwrap();
    let mut public = fields(&strs(&f["publicInputFields"])).unwrap();
    public.extend(fields(&strs(&f["publicOutputFields"])).unwrap());

    assert!(verify(&vk, &public, &proof));

    let mut tampered = public.clone();
    tampered[0] += Fp::from(1u64);
    assert!(!verify(&vk, &tampered, &proof));
    // A trailing zero is implicit, so dropping it is the same input; a changed last field is not.
    let mut tampered = public.clone();
    *tampered.last_mut().unwrap() += Fp::from(1u64);
    assert!(!verify(&vk, &tampered, &proof));
}

fn ledger_hash(vk: &ledger::VerificationKey) -> String {
    use ark_ff::PrimeField;
    vk.hash().into_bigint().to_string()
}
