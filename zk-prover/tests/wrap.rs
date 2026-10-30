//! The wrap witness of `land`'s step proof against the one o1js produced (`w004_cs005`).

use std::{io::Read, str::FromStr};

use base64::Engine as _;
use ledger::proofs::transaction::ProofWithPublic;
use mina_curves::pasta::{Fp, Fq};
use zk_prover::{
    wrap::{deferred::step_features, wrap_witness, WrapParams},
    StepCircuit, StepLand, StepSetup,
};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/fixtures/{name}.gz", env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut out)
        .unwrap();
    out
}

/// `land`'s step proof, with the public input o1js proved it under.
fn step_proof() -> ProofWithPublic<Fp> {
    let b64 = String::from_utf8(fixture("stepproof002.b64")).unwrap();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .unwrap();
    let proof = rmp_serde::from_slice(&bytes).unwrap();
    let public: Vec<String> = serde_json::from_slice(&fixture("stepproof002_public.json")).unwrap();
    let public_input = public.iter().map(|s| Fp::from_str(s).unwrap()).collect();
    ProofWithPublic {
        proof,
        public_input,
    }
}

fn o1js_wrap_witness() -> Vec<Fq> {
    let json: serde_json::Value = serde_json::from_slice(&fixture("w004_cs005.json")).unwrap();
    json["external"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| Fq::from_str(v.as_str().unwrap()).unwrap())
        .collect()
}

#[test]
fn land_wrap_witness_equals_o1js() {
    let land = StepCircuit::load::<StepLand>(
        &fixture("cs003_gates.json"),
        &fixture("cs003_internal_vars.bin"),
        &fixture("cs003_rows_rev.bin"),
    )
    .unwrap();
    let setup = StepCircuit::load::<StepSetup>(
        &fixture("cs004_gates.json"),
        &fixture("cs004_internal_vars.bin"),
        &fixture("cs004_rows_rev.bin"),
    )
    .unwrap();
    let features = {
        let (a, b) = (step_features(land.index()), step_features(setup.index()));
        ledger::proofs::step::FeatureFlags {
            range_check0: a.range_check0 || b.range_check0,
            range_check1: a.range_check1 || b.range_check1,
            foreign_field_add: a.foreign_field_add || b.foreign_field_add,
            foreign_field_mul: a.foreign_field_mul || b.foreign_field_mul,
            xor: a.xor || b.xor,
            rot: a.rot || b.rot,
            lookup: a.lookup || b.lookup,
            runtime_tables: a.runtime_tables || b.runtime_tables,
        }
    };
    zk_prover::wrap::EXPECTED.with(|e| *e.borrow_mut() = Some(o1js_wrap_witness()));
    let witness = wrap_witness(WrapParams {
        max_proofs_verified: 0,
        step_circuits: &[&land, &setup],
        branch: 0,
        features,
        step_proof: &step_proof(),
    })
    .unwrap();
    let expected = o1js_wrap_witness();
    if let Some(i) = witness.first_difference(&expected) {
        panic!(
            "the wrap witness first differs from o1js's at index {i}: ours {:?}, o1js {:?} ({} vs {} values)",
            witness.external().get(i),
            expected.get(i),
            witness.external().len(),
            expected.len()
        );
    }
}
