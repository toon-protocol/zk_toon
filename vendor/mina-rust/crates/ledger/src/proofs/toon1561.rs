//! PROTOTYPE for toon-protocol/connector#1561 — throwaway spike code.
//! Prove an o1js SmartContract method with mina-rust's kimchi/Pickles code.

use std::{path::Path, str::FromStr};

use mina_curves::pasta::{Fp, Fq};

use super::{
    constants::ProofConstants,
    field::FieldWitness,
    provers::{decode_constraints_data, decode_gates_file},
    transaction::{create_proof, make_prover_index, CreateProofParams, ProofWithPublic, Prover},
    witness::Witness,
};

pub struct StepLand;
impl ProofConstants for StepLand {
    const PRIMARY_LEN: usize = 1;
    const AUX_LEN: usize = 17962;
    const PREVIOUS_CHALLENGES: usize = 0;
    const ROWS: usize = 1405;
}

pub struct StepSetup;
impl ProofConstants for StepSetup {
    const PRIMARY_LEN: usize = 1;
    const AUX_LEN: usize = 13556;
    const PREVIOUS_CHALLENGES: usize = 0;
    const ROWS: usize = 1056;
}

pub struct WrapLand;
impl ProofConstants for WrapLand {
    const PRIMARY_LEN: usize = 40;
    const AUX_LEN: usize = 99657;
    const PREVIOUS_CHALLENGES: usize = 0;
    const ROWS: usize = 6798;
}

pub fn load_prover<C: ProofConstants, F: FieldWitness>(dir: &Path, name: &str) -> Prover<F> {
    let gates = decode_gates_file::<F>(std::fs::read(dir.join(format!("{name}_gates.json"))).unwrap().as_slice()).unwrap();
    let iv = std::fs::read(dir.join(format!("{name}_internal_vars.bin"))).unwrap();
    let rr = std::fs::read(dir.join(format!("{name}_rows_rev.bin"))).unwrap();
    let (internal_vars, rows_rev) = decode_constraints_data::<F>(&iv, &rr).unwrap();
    let index = make_prover_index::<C, F>(gates, None);
    Prover { internal_vars, rows_rev, index }
}

/// An o1js witness dump: `{ public_input_size, external: [decimal...] }`.
pub fn load_o1js_witness<F: FieldWitness + FromStr>(path: &Path) -> Witness<F>
where
    <F as FromStr>::Err: std::fmt::Debug,
{
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let n = v["public_input_size"].as_u64().unwrap() as usize;
    let ext: Vec<F> = v["external"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| F::from_str(x.as_str().unwrap()).unwrap())
        .collect();
    Witness::from_parts(ext[..n].to_vec(), ext[n..].to_vec())
}

pub fn prove_step<C: ProofConstants>(
    prover: &Prover<Fp>,
    w: &Witness<Fp>,
    only_verify_constraints: bool,
) -> anyhow::Result<ProofWithPublic<Fp>> {
    create_proof::<C, Fp>(
        CreateProofParams { prover, prev_challenges: vec![], only_verify_constraints },
        w,
    )
}

#[allow(unused)]
fn _keep(_: Fq) {}
