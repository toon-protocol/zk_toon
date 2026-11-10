//! The wrap of the action-stack program's `proveChunk` (`fixture-gen/vault-fixtures.ts`), from the dummy
//! `provableBatches` supplies (`chunk_dummy`) and from the real chunk before it (`chunk_chained`): the wrap
//! witness equals o1js's at every index, satisfies the wrap circuit, and the proof verifies against the wrap
//! circuit's verifier index and under the reducer's published verification key.
//!
//! The dummy is a proof the step does not verify (`should_finalize` false), so its accumulator is
//! `compute_sg` of the challenges the step derived, not the dummy's own `sg`: the first case fails without it.

use std::{io::Read, str::FromStr};

use base64::Engine as _;
use ledger::proofs::transaction::ProofWithPublic;
use mina_curves::pasta::{Fp, Fq};
use zk_prover::{
    pins,
    verify::{fields, load_vk, verify, WrapProof},
    wrap::{
        deferred::step_features, union_features, wrap, PreviousProof, WrapCircuit, WrapParams, WrapWitness,
    },
    StepChunk, StepCircuit, WrapChunk,
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

/// The proof a case's `proveChunk` verified, with its program's key and its public input.
struct Previous {
    proof: WrapProof,
    key: ledger::VerificationKey,
    public_input: Vec<Fp>,
}

fn previous(case: &str, keys: &serde_json::Value) -> Previous {
    let f = json(&format!("{case}_previous.json"));
    let mut public = fields(&strs(&f["publicInput"])).unwrap();
    public.extend(fields(&strs(&f["publicOutput"])).unwrap());
    let key = f["key"].as_str().unwrap();
    Previous {
        proof: WrapProof::from_o1js_base64(f["proof"].as_str().unwrap()).unwrap(),
        key: load_vk(keys[key]["data"].as_str().unwrap()).unwrap(),
        public_input: public,
    }
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
fn every_chunk_case_wraps_equal_to_o1js_and_verifies_under_the_reducer_key() {
    use ark_ff::PrimeField;

    let circuit = StepCircuit::load::<StepChunk>(
        &fixture("chunk_gates.json"),
        &fixture("chunk_internal_vars.bin"),
        &fixture("chunk_rows_rev.bin"),
    )
    .unwrap();
    assert_eq!(circuit.proofs_verified(), 1, "proveChunk verifies one proof");
    let features = union_features(&[step_features(circuit.index())]);
    let wrap_circuit = WrapCircuit::load::<WrapChunk>(
        &fixture("chunk_wrap_gates.json"),
        &fixture("chunk_wrap_internal_vars.bin"),
        &fixture("chunk_wrap_rows_rev.bin"),
    )
    .unwrap();

    let keys = json("vault_keys.json");
    let reducer_vk = load_vk(keys["vaultReducer"]["data"].as_str().unwrap()).unwrap();
    assert_eq!(reducer_vk.hash().into_bigint().to_string(), pins::VAULT_REDUCER_VK_HASH);

    for case in ["chunk_dummy", "chunk_chained"] {
        let previous = previous(case, &keys);
        let previous_proofs = [PreviousProof {
            proof: &previous.proof,
            verification_key: &previous.key,
            public_input: &previous.public_input,
        }];
        let step_proof = step_proof(case);
        let params = WrapParams {
            max_proofs_verified: 1,
            step_circuits: &[&circuit],
            branch: 0,
            features: features.clone(),
            step_proof: &step_proof,
            previous_proofs: &previous_proofs,
            // The proof `proveChunk` verifies is one of the program's own, which verifies a proof itself.
            previous_max_proofs_verified: &[1],
        };
        let out = wrap::<WrapChunk>(params, &wrap_circuit).unwrap_or_else(|e| panic!("{case}: {e:#}"));

        assert_equals(case, &out.witness, &o1js_wrap_witness(case));
        wrap_circuit.check::<WrapChunk>(&out.witness).unwrap_or_else(|e| panic!("{case}: {e:#}"));
        assert_kimchi_verifies(&wrap_circuit, &out);

        // The chunk's public input and output, as o1js's `verify` reads them.
        let proved = json(&format!("{case}_proof.json"));
        let mut public = fields(&strs(&proved["publicInput"])).unwrap();
        public.extend(fields(&strs(&proved["publicOutput"])).unwrap());
        let proof = WrapProof::from_prover(&out.proof);
        let for_program = WrapProof::from_o1js_base64(&proof.to_o1js_program_base64_for(1).unwrap()).unwrap();
        assert!(verify(&reducer_vk, &public, &for_program), "{case}: refused under the reducer key");

        let mut tampered = public.clone();
        tampered[0] += Fp::from(1u64);
        assert!(!verify(&reducer_vk, &tampered, &for_program), "{case}: a changed public input is accepted");
    }
}
