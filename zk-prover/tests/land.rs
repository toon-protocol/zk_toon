//! `land`'s step circuit (`cs003`), proved from o1js's own witness (`w003`).

use std::io::Read;

use zk_prover::{check_step, prove_step, StepCircuit, StepLand, StepWitness};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/fixtures/{name}.gz", env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut out)
        .unwrap();
    out
}

fn circuit() -> StepCircuit {
    StepCircuit::load::<StepLand>(
        &fixture("cs003_gates.json"),
        &fixture("cs003_internal_vars.bin"),
        &fixture("cs003_rows_rev.bin"),
    )
    .unwrap()
}

#[test]
fn proves_cs003_from_o1js_witness() {
    let circuit = circuit();
    let witness = StepWitness::from_o1js_json(&fixture("w003_cs003.json")).unwrap();
    check_step::<StepLand>(&circuit, &witness).unwrap();
    let proof = prove_step::<StepLand>(&circuit, &witness).unwrap();
    assert_eq!(proof.public_input.len(), 1);
}

#[test]
fn changed_witness_value_fails_the_constraint_check() {
    let circuit = circuit();
    let mut json: serde_json::Value = serde_json::from_slice(&fixture("w003_cs003.json")).unwrap();
    let external = json["external"].as_array_mut().unwrap();
    let last = external.len() - 1;
    external[last] = "12345".into();
    let witness = StepWitness::from_o1js_json(&serde_json::to_vec(&json).unwrap()).unwrap();
    let err = check_step::<StepLand>(&circuit, &witness).unwrap_err();
    assert!(err.to_string().contains("incorrect witness"), "{err:#}");
}
