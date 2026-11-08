//! The wrap of the step proofs of the toy zkApp (`fixture-gen/toy.mjs`): `plain` verifies no proof and
//! `recurse` verifies one, a proof of the ZkProgram `toy-inner`, in a program whose `maxProofsVerified`
//! is 1. The wrap witness equals o1js's at every index, and the proof verifies against the wrap
//! circuit's verifier index and, as o1js reads it, under the zkApp's verification key.

use std::{io::Read, str::FromStr};

use base64::Engine as _;
use ledger::proofs::transaction::ProofWithPublic;
use mina_curves::pasta::{Fp, Fq};
use zk_prover::{
    pins,
    verify::{fields, load_vk, verify, WrapProof},
    wrap::{
        deferred::step_features, union_features, wrap, wrap_witness, PreviousProof, WrapCircuit, WrapOutput,
        WrapParams,
    },
    StepCircuit, StepToyPlain, StepToyRecurse, WrapToy,
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

/// The step proof of `plain` or `recurse` and the public input o1js proved it under.
fn step_proof(method: &str) -> ProofWithPublic<Fp> {
    let b64 = String::from_utf8(fixture(&format!("toy_{method}_stepproof.b64"))).unwrap();
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64.trim()).unwrap();
    let public: Vec<String> = serde_json::from_slice(&fixture(&format!("toy_{method}_stepproof_public.json"))).unwrap();
    ProofWithPublic {
        proof: rmp_serde::from_slice(&bytes).unwrap(),
        public_input: public.iter().map(|s| Fp::from_str(s).unwrap()).collect(),
    }
}

/// o1js's witness of the wrap circuit for that step proof: the public input, then the rest.
fn o1js_wrap_witness(method: &str) -> Vec<Fq> {
    json(&format!("toy_{method}_wrap_witness.json"))["external"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| Fq::from_str(v.as_str().unwrap()).unwrap())
        .collect()
}

fn step_circuit<C: ledger::proofs::constants::ProofConstants>(method: &str) -> StepCircuit {
    StepCircuit::load::<C>(
        &fixture(&format!("toy_{method}_gates.json")),
        &fixture(&format!("toy_{method}_internal_vars.bin")),
        &fixture(&format!("toy_{method}_rows_rev.bin")),
    )
    .unwrap()
}

/// What `toy-inner`'s proof of 49 is, for `recurse` to have verified.
struct Inner {
    proof: WrapProof,
    vk: ledger::VerificationKey,
    public_input: Vec<Fp>,
}

fn inner() -> Inner {
    let proof = json("toy_inner_proof.json");
    let inputs = json("toy_inputs.json");
    Inner {
        proof: WrapProof::from_o1js_base64(proof["proof"].as_str().unwrap()).unwrap(),
        vk: load_vk(inputs["innerVk"].as_str().unwrap()).unwrap(),
        public_input: vec![Fp::from_str(inputs["innerPublicInput"].as_str().unwrap()).unwrap()],
    }
}

fn assert_equals(witness: &zk_prover::wrap::WrapWitness, expected: &[Fq]) {
    if let Some(i) = witness.first_difference(expected) {
        panic!(
            "the wrap witness first differs from o1js's at index {i}: ours {:?}, o1js {:?} ({} vs {} values)",
            witness.external().get(i),
            expected.get(i),
            witness.external().len(),
            expected.len()
        );
    }
}

fn wrap_circuit() -> WrapCircuit {
    WrapCircuit::load::<WrapToy>(
        &fixture("toy_wrap_gates.json"),
        &fixture("toy_wrap_internal_vars.bin"),
        &fixture("toy_wrap_rows_rev.bin"),
    )
    .unwrap()
}

/// What `wrap` is given for `branch` (0 `plain`, 1 `recurse`) in the program with `max_proofs_verified`.
fn params_for<'a>(
    branch: usize,
    max_proofs_verified: usize,
    circuits: &'a [&'a StepCircuit; 2],
    step_proof: &'a ProofWithPublic<Fp>,
    previous: &'a [PreviousProof<'a>; 1],
) -> WrapParams<'a> {
    let features = union_features(&[step_features(circuits[0].index()), step_features(circuits[1].index())]);
    WrapParams {
        max_proofs_verified,
        step_circuits: circuits,
        branch,
        features,
        step_proof,
        previous_proofs: &previous[..branch],
        previous_max_proofs_verified: &[0][..max_proofs_verified.min(1)],
    }
}

fn step_proof_of(branch: usize) -> ProofWithPublic<Fp> {
    step_proof(["plain", "recurse"][branch])
}

/// Run `f` on the parameters of `branch`.
fn with_params<T>(branch: usize, max_proofs_verified: usize, f: impl FnOnce(WrapParams) -> T) -> T {
    let plain = step_circuit::<StepToyPlain>("plain");
    let recurse = step_circuit::<StepToyRecurse>("recurse");
    let circuits = [&plain, &recurse];
    let inner = inner();
    let previous = [PreviousProof {
        proof: &inner.proof,
        verification_key: &inner.vk,
        public_input: &inner.public_input,
    }];
    let step_proof = step_proof_of(branch);
    f(params_for(branch, max_proofs_verified, &circuits, &step_proof, &previous))
}

/// The wrap witness of `branch`.
fn witness(branch: usize) -> zk_prover::wrap::WrapWitness {
    with_params(branch, 1, |params| wrap_witness(params).unwrap())
}

fn prove(branch: usize) -> WrapOutput {
    with_params(branch, 1, |params| wrap::<WrapToy>(params, &wrap_circuit()).unwrap())
}

#[test]
fn plain_wrap_witness_equals_o1js_at_every_index() {
    assert_equals(&witness(0), &o1js_wrap_witness("plain"));
}

#[test]
fn recurse_wrap_witness_equals_o1js_at_every_index() {
    assert_equals(&witness(1), &o1js_wrap_witness("recurse"));
}

/// A program that verifies one proof wraps; one that verifies three is refused, as is a branch given the
/// wrong number of previous proofs.
#[test]
fn one_previous_proof_wraps_and_three_are_refused() {
    witness(1);
    let err = with_params(1, 3, |params| wrap_witness(params).unwrap_err());
    assert!(err.to_string().contains("at most 2 proofs"), "{err:#}");
    // `plain` verifies no proof: handing it one is a mistake.
    let plain = step_circuit::<StepToyPlain>("plain");
    let recurse = step_circuit::<StepToyRecurse>("recurse");
    let inner = inner();
    let previous = [PreviousProof {
        proof: &inner.proof,
        verification_key: &inner.vk,
        public_input: &inner.public_input,
    }];
    let circuits = [&plain, &recurse];
    let step_proof = step_proof("plain");
    let mut params = params_for(0, 1, &circuits, &step_proof, &previous);
    params.previous_proofs = &previous;
    let err = wrap_witness(params).unwrap_err();
    assert!(err.to_string().contains("verifies 0 proofs"), "{err:#}");
}

fn program_vk() -> ledger::VerificationKey {
    let vk = load_vk(json("toy_inputs.json")["vk"].as_str().unwrap()).unwrap();
    use ark_ff::PrimeField;
    assert_eq!(vk.hash().into_bigint().to_string(), pins::TOY_PROGRAM_VK_HASH);
    vk
}

/// The public input and output fields o1js proved the method's call under.
fn public(method: &str) -> Vec<Fp> {
    let f = json(&format!("toy_{method}_proof.json"));
    let strs = |v: &serde_json::Value| -> Vec<String> {
        v.as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect()
    };
    let mut public = fields(&strs(&f["publicInputFields"]).iter().map(String::as_str).collect::<Vec<_>>()).unwrap();
    public.extend(fields(&strs(&f["publicOutputFields"]).iter().map(String::as_str).collect::<Vec<_>>()).unwrap());
    public
}

/// The Rust wrap proof of `branch` satisfies the circuit and verifies against the circuit's own verifier index,
/// and as o1js reads it under the zkApp's verification key; a changed public input is refused.
fn proof_verifies(branch: usize) {
    use kimchi::{groupmap::GroupMap, mina_curves::pasta::PallasParameters};
    use ledger::proofs::FULL_ROUNDS;
    use mina_curves::pasta::Pallas;
    use mina_poseidon::{
        constants::PlonkSpongeConstantsKimchi,
        sponge::{DefaultFqSponge, DefaultFrSponge},
    };
    use poly_commitment::ipa::OpeningProof;

    let method = ["plain", "recurse"][branch];
    let circuit = wrap_circuit();
    let out = prove(branch);

    // The witness is o1js's, so it satisfies every constraint of o1js's wrap circuit.
    assert_equals(&out.witness, &o1js_wrap_witness(method));
    circuit.check::<WrapToy>(&out.witness).unwrap();

    type Sponge = DefaultFqSponge<PallasParameters, PlonkSpongeConstantsKimchi, FULL_ROUNDS>;
    type FrSponge = DefaultFrSponge<Fq, PlonkSpongeConstantsKimchi, FULL_ROUNDS>;
    kimchi::verifier::verify::<FULL_ROUNDS, Pallas, Sponge, FrSponge, OpeningProof<Pallas, FULL_ROUNDS>>(
        &GroupMap::<Fp>::setup(),
        &circuit.index().verifier_index(),
        &out.proof.proof.proof,
        &out.proof.proof.public_input,
    )
    .unwrap();

    // The proof as a transaction carries it (at 2), and as o1js's `verify` reads it for the program (at 1).
    let vk = program_vk();
    let public = public(method);
    let proof = WrapProof::from_prover(&out.proof);
    let in_transaction = WrapProof::from_o1js_base64(&proof.to_o1js_base64()).unwrap();
    assert!(verify(&vk, &public, &in_transaction), "the Rust wrap proof is refused under the program VK");
    let for_program = WrapProof::from_o1js_base64(&proof.to_o1js_program_base64_for(1).unwrap()).unwrap();
    assert!(verify(&vk, &public, &for_program), "the program form is refused under the program VK");

    let mut tampered = public.clone();
    tampered[0] += Fp::from(1u64);
    assert!(!verify(&vk, &tampered, &in_transaction), "a changed public input is accepted");
}

#[test]
fn plain_wrap_proof_verifies() {
    proof_verifies(0);
}

#[test]
fn recurse_wrap_proof_verifies() {
    proof_verifies(1);
}
