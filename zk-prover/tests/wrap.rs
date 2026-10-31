//! The wrap of `land`'s step proof, in the toy program with the methods `land` and `setup`,
//! against what o1js produced (`w004_cs005`).

use std::{io::Read, str::FromStr};

use base64::Engine as _;
use ledger::proofs::transaction::ProofWithPublic;
use mina_curves::pasta::{Fp, Fq};
use zk_prover::{
    wrap::{deferred::step_features, union_features, wrap, wrap_witness, WrapCircuit, WrapParams},
    StepCircuit, StepLand, StepSetup, WrapLandSetup,
};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/fixtures/{name}.gz", env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut out)
        .unwrap();
    out
}

/// `land`'s step proof, with the public input o1js proved it under: the hash of the proof's
/// `messages_for_next_step_proof`, which is also field 12 of o1js's wrap witness.
fn step_proof() -> ProofWithPublic<Fp> {
    step_proof_of("002")
}

/// `stepproof001` is `setup`'s, `stepproof002` `land`'s.
fn step_proof_of(n: &str) -> ProofWithPublic<Fp> {
    let b64 = String::from_utf8(fixture(&format!("stepproof{n}.b64"))).unwrap();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .unwrap();
    let proof = rmp_serde::from_slice(&bytes).unwrap();
    let public: Vec<String> = serde_json::from_slice(&fixture(&format!("stepproof{n}_public.json"))).unwrap();
    let public_input = public.iter().map(|s| Fp::from_str(s).unwrap()).collect();
    ProofWithPublic {
        proof,
        public_input,
    }
}

/// o1js's witness of the wrap circuit for that proof: the public input, then the rest.
fn o1js_wrap_witness() -> Vec<Fq> {
    o1js_wrap_witness_of("w004_cs005")
}

fn o1js_wrap_witness_of(name: &str) -> Vec<Fq> {
    let json: serde_json::Value = serde_json::from_slice(&fixture(&format!("{name}.json"))).unwrap();
    json["external"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| Fq::from_str(v.as_str().unwrap()).unwrap())
        .collect()
}

/// The program's step circuits, in method order: `land`, then `setup`.
fn step_circuits() -> [StepCircuit; 2] {
    [
        StepCircuit::load::<StepLand>(
            &fixture("cs003_gates.json"),
            &fixture("cs003_internal_vars.bin"),
            &fixture("cs003_rows_rev.bin"),
        )
        .unwrap(),
        StepCircuit::load::<StepSetup>(
            &fixture("cs004_gates.json"),
            &fixture("cs004_internal_vars.bin"),
            &fixture("cs004_rows_rev.bin"),
        )
        .unwrap(),
    ]
}

fn wrap_circuit() -> WrapCircuit {
    WrapCircuit::load::<WrapLandSetup>(
        &fixture("cs005_gates.json"),
        &fixture("cs005_internal_vars.bin"),
        &fixture("cs005_rows_rev.bin"),
    )
    .unwrap()
}

fn assert_equals_o1js(witness: &zk_prover::wrap::WrapWitness) {
    assert_equals(witness, &o1js_wrap_witness());
}

fn assert_equals(witness: &zk_prover::wrap::WrapWitness, expected: &[Fq]) {
    if let Some(i) = witness.first_difference(&expected) {
        panic!(
            "the wrap witness first differs from o1js's at index {i}: ours {:?}, o1js {:?} \
             ({} vs {} values)",
            witness.external().get(i),
            expected.get(i),
            witness.external().len(),
            expected.len()
        );
    }
}

#[test]
fn land_wrap_witness_equals_o1js_at_every_index() {
    let [land, setup] = step_circuits();
    let features = union_features(&[step_features(land.index()), step_features(setup.index())]);
    let witness = wrap_witness(WrapParams {
        max_proofs_verified: 0,
        step_circuits: &[&land, &setup],
        branch: 0,
        features,
        step_proof: &step_proof(),
    })
    .unwrap();
    assert_equals_o1js(&witness);
}

#[test]
fn land_wrap_proof_satisfies_the_circuit_and_verifies() {
    use kimchi::{groupmap::GroupMap, mina_curves::pasta::PallasParameters};
    use ledger::proofs::FULL_ROUNDS;
    use mina_curves::pasta::Pallas;
    use mina_poseidon::{
        constants::PlonkSpongeConstantsKimchi,
        sponge::{DefaultFqSponge, DefaultFrSponge},
    };
    use poly_commitment::ipa::OpeningProof;

    let [land, setup] = step_circuits();
    let features = union_features(&[step_features(land.index()), step_features(setup.index())]);
    let circuit = wrap_circuit();
    let out = wrap::<WrapLandSetup>(
        WrapParams {
            max_proofs_verified: 0,
            step_circuits: &[&land, &setup],
            branch: 0,
            features,
            step_proof: &step_proof(),
        },
        &circuit,
    )
    .unwrap();

    // The witness is o1js's, so it satisfies every constraint of o1js's wrap circuit.
    assert_equals_o1js(&out.witness);
    circuit.check::<WrapLandSetup>(&out.witness).unwrap();

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
fn a_program_that_verifies_proofs_is_refused() {
    let [land, setup] = step_circuits();
    let features = union_features(&[step_features(land.index()), step_features(setup.index())]);
    let err = wrap_witness(WrapParams {
        max_proofs_verified: 1,
        step_circuits: &[&land, &setup],
        branch: 0,
        features,
        step_proof: &step_proof(),
    })
    .unwrap_err();
    assert!(err.to_string().contains("#32"), "{err:#}");
}

/// `setup`'s step proof (`stepproof001`, branch 1) wraps to o1js's witness (`w002_cs005`) at every
/// index: one wrap circuit, two methods, two step keys.
#[test]
fn setup_wrap_witness_equals_o1js_at_every_index() {
    let [land, setup] = step_circuits();
    let features = union_features(&[step_features(land.index()), step_features(setup.index())]);
    let witness = wrap_witness(WrapParams {
        max_proofs_verified: 0,
        step_circuits: &[&land, &setup],
        branch: 1,
        features,
        step_proof: &step_proof_of("001"),
    })
    .unwrap();
    assert_equals(&witness, &o1js_wrap_witness_of("w002_cs005"));
}
