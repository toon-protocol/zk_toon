//! Print the hashes `src/pins.rs` pins, from the committed fixtures: `cargo run -p zk-prover --example vk_hashes`.

use std::io::Read;

use zk_prover::{StepCircuit, StepLand, StepSetup};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/fixtures/{name}.gz", env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut out)
        .unwrap();
    out
}

fn main() {
    let load = |n: &str| (fixture(&format!("{n}_gates.json")), fixture(&format!("{n}_internal_vars.bin")), fixture(&format!("{n}_rows_rev.bin")));
    let (g, i, r) = load("cs003");
    println!("LAND_STEP_VK_HASH={}", StepCircuit::load::<StepLand>(&g, &i, &r).unwrap().vk_hash());
    let (g, i, r) = load("cs004");
    println!("SETUP_STEP_VK_HASH={}", StepCircuit::load::<StepSetup>(&g, &i, &r).unwrap().vk_hash());
    let inputs: serde_json::Value = serde_json::from_slice(&fixture("inputs.json")).unwrap();
    println!("PROGRAM_VK_HASH={}", inputs["vkHash"].as_str().unwrap());
}
