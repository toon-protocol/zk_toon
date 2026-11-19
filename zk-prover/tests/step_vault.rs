//! kimchi proves the step circuit of every real-vault case from o1js's step witness
//! (`fixture-gen/vault-fixtures.ts`): the nine methods, `reduce` from a real action-stack chunk, and the two
//! `proveChunk` cases. The step proof's public input is the one in `<case>_stepproof_public.json`, and the
//! step map names the o1js call site of each variable, as the toy's does.

use std::{io::Read, str::FromStr};

use ledger::proofs::constants::ProofConstants;
use mina_curves::pasta::Fp;
use zk_prover::{
    check_step, prove_step, StepChunk, StepCircuit, StepVaultDefeat, StepVaultDeposit, StepVaultEscape,
    StepVaultFinalize, StepVaultMutualClose, StepVaultRaise, StepVaultReduce, StepVaultSetup,
    StepVaultSweepExpired, StepWitness,
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

fn circuit<C: ProofConstants>(name: &str) -> StepCircuit {
    StepCircuit::load::<C>(
        &fixture(&format!("{name}_gates.json")),
        &fixture(&format!("{name}_internal_vars.bin")),
        &fixture(&format!("{name}_rows_rev.bin")),
    )
    .unwrap()
}

/// Proves `case`'s step circuit (`circuit_name`'s) from o1js's step witness and compares the public input
/// with o1js's step proof's.
fn proves_from_o1js<C: ProofConstants>(circuit_name: &str, case: &str) {
    let step = circuit::<C>(circuit_name);
    let witness = StepWitness::from_o1js_json(&fixture(&format!("{case}_step_witness.json"))).unwrap();
    check_step::<C>(&step, &witness).unwrap_or_else(|e| panic!("{case}: {e:#}"));
    let proof = prove_step::<C>(&step, &witness).unwrap_or_else(|e| panic!("{case}: {e:#}"));
    let expected: Vec<Fp> = json(&format!("{case}_stepproof_public.json"))
        .as_array()
        .unwrap()
        .iter()
        .map(|x| Fp::from_str(x.as_str().unwrap()).unwrap())
        .collect();
    assert_eq!(proof.public_input.to_vec(), expected, "{case}: the step proof's public input differs from o1js's");
}

#[test]
fn setup_deposit_and_finalize_prove_from_o1js_witnesses() {
    proves_from_o1js::<StepVaultSetup>("vault_setup", "vault_setup");
    proves_from_o1js::<StepVaultDeposit>("vault_deposit", "vault_deposit");
    proves_from_o1js::<StepVaultFinalize>("vault_finalize", "vault_finalize");
    proves_from_o1js::<StepVaultSweepExpired>("vault_sweepExpired", "vault_sweepExpired");
}

#[test]
fn the_methods_that_verify_a_proof_prove_from_o1js_witnesses() {
    proves_from_o1js::<StepVaultMutualClose>("vault_mutualClose", "vault_mutualClose");
    proves_from_o1js::<StepVaultEscape>("vault_escape", "vault_escape");
    proves_from_o1js::<StepVaultDefeat>("vault_defeat", "vault_defeat");
    proves_from_o1js::<StepVaultRaise>("vault_raise", "vault_raise");
}

#[test]
fn reduce_proves_from_o1js_witnesses_over_a_dummy_and_a_real_chunk() {
    proves_from_o1js::<StepVaultReduce>("vault_reduce", "vault_reduce");
    proves_from_o1js::<StepVaultReduce>("vault_reduce", "vault_reduce_recursive");
}

#[test]
fn prove_chunk_proves_from_o1js_witnesses_from_the_dummy_and_from_a_chunk() {
    proves_from_o1js::<StepChunk>("chunk", "chunk_dummy");
    proves_from_o1js::<StepChunk>("chunk", "chunk_chained");
}

/// Every case has what a later builder needs: the step map, the inputs file naming the method, and a
/// witness whose auxiliary values are as many as its shape's `AUX_LEN`.
#[test]
fn every_case_has_its_step_map_and_inputs_and_the_shapes_aux_len() {
    for (case, method, aux_len) in [
        ("vault_setup", "setup", StepVaultSetup::AUX_LEN),
        ("vault_deposit", "deposit", StepVaultDeposit::AUX_LEN),
        ("vault_mutualClose", "mutualClose", StepVaultMutualClose::AUX_LEN),
        ("vault_escape", "escape", StepVaultEscape::AUX_LEN),
        ("vault_finalize", "finalize", StepVaultFinalize::AUX_LEN),
        ("vault_defeat", "defeat", StepVaultDefeat::AUX_LEN),
        ("vault_raise", "raise", StepVaultRaise::AUX_LEN),
        ("vault_sweepExpired", "sweepExpired", StepVaultSweepExpired::AUX_LEN),
        ("vault_reduce", "reduce", StepVaultReduce::AUX_LEN),
        ("vault_reduce_recursive", "reduce", StepVaultReduce::AUX_LEN),
        ("chunk_dummy", "proveChunk", StepChunk::AUX_LEN),
        ("chunk_chained", "proveChunk", StepChunk::AUX_LEN),
    ] {
        let w = json(&format!("{case}_step_witness.json"));
        let public = w["public_input_size"].as_u64().unwrap() as usize;
        assert_eq!(w["external"].as_array().unwrap().len() - public, aux_len, "{case}: not the shape's AUX_LEN");
        assert_eq!(json(&format!("{case}_inputs.json"))["method"], method, "{case}");
        let map = String::from_utf8(fixture(&format!("{case}_step_map.txt"))).unwrap();
        assert!(map.lines().count() > 1, "{case}: an empty step map");
    }
}
