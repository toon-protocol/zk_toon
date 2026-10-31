//! The VK hashes in `src/pins.rs` are the ones the committed circuits give, and the pins agree with
//! the manifests they mirror. A moved fork rev, proof-systems rev, o1js version or circuit fails here.

use std::io::Read;

use zk_prover::{pins, StepCircuit, StepLand, StepSetup};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/fixtures/{name}.gz", env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut out)
        .unwrap();
    out
}

fn load<C: ledger::proofs::constants::ProofConstants>(name: &str) -> StepCircuit {
    StepCircuit::load::<C>(
        &fixture(&format!("{name}_gates.json")),
        &fixture(&format!("{name}_internal_vars.bin")),
        &fixture(&format!("{name}_rows_rev.bin")),
    )
    .unwrap()
}

#[test]
fn land_step_vk_hash_is_pinned() {
    assert_eq!(load::<StepLand>("cs003").vk_hash(), pins::LAND_STEP_VK_HASH);
}

#[test]
fn setup_step_vk_hash_is_pinned() {
    assert_eq!(load::<StepSetup>("cs004").vk_hash(), pins::SETUP_STEP_VK_HASH);
}

#[test]
fn program_vk_hash_is_pinned() {
    let inputs: serde_json::Value = serde_json::from_slice(&fixture("inputs.json")).unwrap();
    assert_eq!(inputs["vkHash"].as_str().unwrap(), pins::PROGRAM_VK_HASH);
    // The key data in the fixture hashes to the same value.
    let vk = zk_prover::verify::load_vk(inputs["vk"].as_str().unwrap()).unwrap();
    use ark_ff::PrimeField;
    assert_eq!(vk.hash().into_bigint().to_string(), pins::PROGRAM_VK_HASH);
}

#[test]
fn pins_match_the_manifests() {
    let root = env!("CARGO_MANIFEST_DIR");
    let cargo = std::fs::read_to_string(format!("{root}/Cargo.toml")).unwrap();
    assert!(cargo.contains(&format!("rev = \"{}\"", pins::MINA_RUST_REV)));
    assert!(cargo.contains(&format!("rev = \"{}\"", pins::PROOF_SYSTEMS_REV)));
    let package: serde_json::Value =
        serde_json::from_slice(&std::fs::read(format!("{root}/../fixture-gen/package.json")).unwrap()).unwrap();
    assert_eq!(package["dependencies"]["o1js"], pins::O1JS_VERSION);
    let lock: serde_json::Value =
        serde_json::from_slice(&std::fs::read(format!("{root}/../fixture-gen/package-lock.json")).unwrap()).unwrap();
    assert_eq!(lock["packages"]["node_modules/o1js"]["version"], pins::O1JS_VERSION);
}
