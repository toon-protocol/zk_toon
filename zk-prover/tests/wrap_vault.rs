//! The wrap of the real vault's step proofs (`fixture-gen/vault-fixtures.ts`): for each method, and for
//! `reduce` from a real action-stack chunk, the wrap witness equals o1js's at every index, satisfies the
//! wrap circuit, and the proof verifies against the wrap circuit's verifier index and under the vault's
//! published verification key.
//!
//! `reduce` is proved twice: its first case verifies a dummy action-stack proof (`should_finalize` false),
//! whose accumulator Pickles computes from the challenges the step derived rather than taking the proof's
//! own `sg`; the second verifies a real chunk. The first fails without `compute_sg`.

use std::{io::Read, str::FromStr};

use base64::Engine as _;
use ledger::proofs::{constants::ProofConstants, transaction::ProofWithPublic};
use mina_curves::pasta::{Fp, Fq};
use zk_prover::{
    pins,
    verify::{fields, load_vk, verify, WrapProof},
    wrap::{
        deferred::step_features, union_features, wrap, PreviousProof, WrapCircuit, WrapParams, WrapWitness,
    },
    StepCircuit, StepVaultDefeat, StepVaultDeposit, StepVaultEscape, StepVaultFinalize, StepVaultMutualClose,
    StepVaultRaise, StepVaultReduce, StepVaultSetup, StepVaultSweepExpired, WrapVault,
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

fn step_circuit<C: ProofConstants>(method: &str) -> StepCircuit {
    StepCircuit::load::<C>(
        &fixture(&format!("vault_{method}_gates.json")),
        &fixture(&format!("vault_{method}_internal_vars.bin")),
        &fixture(&format!("vault_{method}_rows_rev.bin")),
    )
    .unwrap()
}

/// The vault's methods in declaration order, which is their branch order.
const METHODS: [&str; 9] =
    ["setup", "deposit", "mutualClose", "escape", "finalize", "defeat", "raise", "sweepExpired", "reduce"];

/// The cases: each fixture prefix with the branch of its method.
const CASES: [(&str, usize); 10] = [
    ("vault_setup", 0),
    ("vault_deposit", 1),
    ("vault_mutualClose", 2),
    ("vault_escape", 3),
    ("vault_finalize", 4),
    ("vault_defeat", 5),
    ("vault_raise", 6),
    ("vault_sweepExpired", 7),
    ("vault_reduce", 8),
    ("vault_reduce_recursive", 8),
];

fn step_proof(case: &str) -> ProofWithPublic<Fp> {
    let b64 = String::from_utf8(fixture(&format!("{case}_stepproof.b64"))).unwrap();
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64.trim()).unwrap();
    let public: Vec<String> = serde_json::from_slice(&fixture(&format!("{case}_stepproof_public.json"))).unwrap();
    ProofWithPublic {
        proof: rmp_serde::from_slice(&bytes).unwrap(),
        public_input: public.iter().map(|s| Fp::from_str(s).unwrap()).collect(),
    }
}

/// o1js's witness of the wrap circuit for the case's step proof.
fn o1js_wrap_witness(case: &str) -> Vec<Fq> {
    json(&format!("{case}_wrap_witness.json"))["external"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| Fq::from_str(v.as_str().unwrap()).unwrap())
        .collect()
}

/// The proof a case's method verified, with its program's key and its public input; `None` for a method
/// that verifies none.
struct Previous {
    proof: WrapProof,
    key: ledger::VerificationKey,
    public_input: Vec<Fp>,
}

fn previous(case: &str, keys: &serde_json::Value) -> Option<Previous> {
    let path = format!("{}/fixtures/{case}_previous.json.gz", env!("CARGO_MANIFEST_DIR"));
    if !std::path::Path::new(&path).exists() {
        return None;
    }
    let f = json(&format!("{case}_previous.json"));
    let mut public = fields(&strs(&f["publicInput"])).unwrap();
    public.extend(fields(&strs(&f["publicOutput"])).unwrap());
    let key = f["key"].as_str().unwrap();
    Some(Previous {
        proof: WrapProof::from_o1js_base64(f["proof"].as_str().unwrap()).unwrap(),
        key: load_vk(keys[key]["data"].as_str().unwrap()).unwrap(),
        public_input: public,
    })
}

fn assert_equals(case: &str, witness: &WrapWitness, expected: &[Fq]) {
    if let Some(i) = witness.first_difference(expected) {
        panic!(
            "{case}: the wrap witness first differs from o1js's at index {i}: ours {:?}, o1js {:?} ({} vs {} values)",
            witness.external().get(i),
            expected.get(i),
            witness.external().len(),
            expected.len()
        );
    }
}

fn assert_kimchi_verifies(circuit: &WrapCircuit, out: &zk_prover::wrap::WrapOutput) {
    use kimchi::{groupmap::GroupMap, mina_curves::pasta::PallasParameters};
    use ledger::proofs::FULL_ROUNDS;
    use mina_curves::pasta::Pallas;
    use mina_poseidon::{
        constants::PlonkSpongeConstantsKimchi,
        sponge::{DefaultFqSponge, DefaultFrSponge},
    };
    use poly_commitment::ipa::OpeningProof;

    type Sponge = DefaultFqSponge<PallasParameters, PlonkSpongeConstantsKimchi, FULL_ROUNDS>;
    type FrSponge = DefaultFrSponge<Fq, PlonkSpongeConstantsKimchi, FULL_ROUNDS>;
    kimchi::verifier::verify::<FULL_ROUNDS, Pallas, Sponge, FrSponge, OpeningProof<Pallas, FULL_ROUNDS>>(
        &GroupMap::<Fp>::setup(),
        &circuit.index().verifier_index(),
        &out.proof.proof.proof,
        &out.proof.proof.public_input,
    )
    .unwrap();
}

#[test]
fn every_vault_case_wraps_equal_to_o1js_and_verifies_under_the_vault_key() {
    use ark_ff::PrimeField;

    let circuits = [
        step_circuit::<StepVaultSetup>("setup"),
        step_circuit::<StepVaultDeposit>("deposit"),
        step_circuit::<StepVaultMutualClose>("mutualClose"),
        step_circuit::<StepVaultEscape>("escape"),
        step_circuit::<StepVaultFinalize>("finalize"),
        step_circuit::<StepVaultDefeat>("defeat"),
        step_circuit::<StepVaultRaise>("raise"),
        step_circuit::<StepVaultSweepExpired>("sweepExpired"),
        step_circuit::<StepVaultReduce>("reduce"),
    ];
    assert_eq!(circuits.len(), METHODS.len());
    let circuit_refs: Vec<&StepCircuit> = circuits.iter().collect();
    let features = union_features(&circuits.iter().map(|c| step_features(c.index())).collect::<Vec<_>>());
    let wrap_circuit = WrapCircuit::load::<WrapVault>(
        &fixture("vault_wrap_gates.json"),
        &fixture("vault_wrap_internal_vars.bin"),
        &fixture("vault_wrap_rows_rev.bin"),
    )
    .unwrap();

    let keys = json("vault_keys.json");
    let vault_vk = load_vk(keys["vault"]["data"].as_str().unwrap()).unwrap();
    assert_eq!(vault_vk.hash().into_bigint().to_string(), pins::VAULT_VK_HASH);

    for (case, branch) in CASES {
        let previous = previous(case, &keys);
        assert_eq!(
            previous.is_some(),
            circuits[branch].proofs_verified() == 1,
            "{case}: a previous proof exactly when the method verifies one"
        );
        let previous_proofs: Vec<PreviousProof> = previous
            .iter()
            .map(|p| PreviousProof { proof: &p.proof, verification_key: &p.key, public_input: &p.public_input })
            .collect();
        let step_proof = step_proof(case);
        let params = WrapParams {
            max_proofs_verified: 1,
            step_circuits: &circuit_refs,
            branch,
            features: features.clone(),
            step_proof: &step_proof,
            previous_proofs: &previous_proofs,
            // The programs the vault verifies in its one slot: the reducer verifies a proof itself.
            previous_max_proofs_verified: &[1],
        };
        let out = wrap::<WrapVault>(params, &wrap_circuit).unwrap_or_else(|e| panic!("{case}: {e:#}"));

        // The witness is o1js's, so it satisfies every constraint of o1js's wrap circuit.
        assert_equals(case, &out.witness, &o1js_wrap_witness(case));
        wrap_circuit.check::<WrapVault>(&out.witness).unwrap_or_else(|e| panic!("{case}: {e:#}"));
        assert_kimchi_verifies(&wrap_circuit, &out);

        // The proof as a transaction carries it (at 2), and as o1js's `verify` reads it for the program
        // (at 1), under the zkApp public input o1js proved the call under.
        let public = fields(&strs(&json(&format!("{case}_zkapp_public.json")))).unwrap();
        let proof = WrapProof::from_prover(&out.proof);
        let in_transaction = WrapProof::from_o1js_base64(&proof.to_o1js_base64()).unwrap();
        assert!(verify(&vault_vk, &public, &in_transaction), "{case}: refused under the vault key");
        let for_program = WrapProof::from_o1js_base64(&proof.to_o1js_program_base64_for(1).unwrap()).unwrap();
        assert!(verify(&vault_vk, &public, &for_program), "{case}: the program form is refused under the vault key");

        let mut tampered = public.clone();
        tampered[0] += Fp::from(1u64);
        assert!(!verify(&vault_vk, &tampered, &in_transaction), "{case}: a changed public input is accepted");
    }
}
