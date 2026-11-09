//! The step witness of the toy zkApp's methods built in Rust equals o1js's at every index, and
//! kimchi proves the step circuit from it (`fixture-gen/toy.mjs`): `plain` verifies no proof,
//! `recurse` verifies a proof of the ZkProgram `toy-inner`.

use std::{io::Read, str::FromStr};

use mina_curves::pasta::Fp;
use zk_prover::{
    check_step, pins, prove_step,
    toy_program::ToyProgram,
    verify::{load_vk, verify, WrapProof},
    witness::toy::{plain_witness, recurse_witness, ToyInputs},
    wrap::PreviousProof,
    StepCircuit, StepToyPlain, StepToyRecurse, StepWitness,
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

/// The inputs of `plain(3)` and `recurse(49, proof)`: `toy_inputs.json` (the address and the
/// verification key) and what `fixture-gen/prove-toy.mjs` fixes besides: the token id (MINA's, 1) and
/// the blinding value of the call data (`Fp.random()` replaced by a counter, which is at 2 for `plain`
/// and 4 for `recurse`).
fn inputs(method: &str) -> ToyInputs {
    let (x, blinding) = match method {
        "plain" => (3, 2),
        _ => (49, 4),
    };
    ToyInputs::from_json(&json("toy_inputs.json"), Fp::from(x), Fp::from(blinding)).unwrap()
}

/// o1js's witness: the public input, then the auxiliary values.
fn o1js_witness(method: &str) -> Vec<Fp> {
    json(&format!("toy_{method}_step_witness.json"))["external"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| Fp::from_str(x.as_str().unwrap()).unwrap())
        .collect()
}

/// The o1js call site of auxiliary variable `index` (1-based), from `toy_<method>_step_map.txt`: each
/// line is `start +count xN site`, and the (OCaml) lines are Pickles' and snarky's own.
fn call_site(method: &str, index: usize) -> String {
    let map = String::from_utf8(fixture(&format!("toy_{method}_step_map.txt"))).unwrap();
    let mut found = String::from("before the first mapped variable");
    for line in map.lines() {
        let mut parts = line.split_whitespace();
        let start: usize = parts.next().unwrap().parse().unwrap();
        if start > index {
            break;
        }
        parts.next(); // +count
        parts.next(); // xN
        found = parts.collect::<Vec<_>>().join(" ");
    }
    found
}

/// The first variable in which `aux` differs from o1js's witness, with its o1js call site, or else the
/// first public input that differs.
fn first_difference(method: &str, primary: &[Fp], aux: &[Fp]) -> Option<String> {
    let o1js = o1js_witness(method);
    let public = o1js_public_inputs();
    for (i, (rust, theirs)) in aux.iter().zip(&o1js[public..]).enumerate() {
        if rust != theirs {
            return Some(format!(
                "first differing variable: {} (aux index {}), made by {}",
                i + 1,
                i,
                call_site(method, i + 1)
            ));
        }
    }
    // a matching prefix: the first variable only one side has
    let (ours, theirs) = (aux.len(), o1js.len() - public);
    if ours != theirs {
        let first = ours.min(theirs) + 1;
        return Some(format!(
            "{ours} variables, o1js {theirs}: first differing variable: {first} (aux index {}), made by {}",
            first - 1,
            call_site(method, first)
        ));
    }
    (primary != &o1js[..public]).then(|| {
        let i = (0..public).find(|&i| primary.get(i) != o1js.get(i)).unwrap_or(primary.len());
        format!("first differing public input: {i} of {public}")
    })
}

/// Both toy step circuits have 34 public inputs: the unfinalized proof (32), then the hashes of
/// `messages_for_next_step_proof` and `messages_for_next_wrap_proof`.
fn o1js_public_inputs() -> usize {
    34
}

/// What `toy-inner`'s proof of 49 is, for `recurse` to verify.
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

fn recurse() -> zk_prover::witness::toy::ToyWitness {
    let inner = inner();
    let previous = PreviousProof {
        proof: &inner.proof,
        verification_key: &inner.vk,
        public_input: &inner.public_input,
    };
    recurse_witness(&inputs("recurse"), &previous).unwrap()
}

#[test]
fn plain_witness_equals_o1js_at_every_index() {
    let w = plain_witness(&inputs("plain")).unwrap();
    assert_eq!(first_difference("plain", &w.primary, &w.aux), None);
}

#[test]
fn recurse_witness_equals_o1js_at_every_index() {
    let w = recurse();
    assert_eq!(first_difference("recurse", &w.primary, &w.aux), None);
}

fn circuit<C: ledger::proofs::constants::ProofConstants>(method: &str) -> StepCircuit {
    StepCircuit::load::<C>(
        &fixture(&format!("toy_{method}_gates.json")),
        &fixture(&format!("toy_{method}_internal_vars.bin")),
        &fixture(&format!("toy_{method}_rows_rev.bin")),
    )
    .unwrap()
}

#[test]
fn kimchi_proves_the_toy_step_circuits_from_the_rust_witness() {
    let plain = circuit::<StepToyPlain>("plain");
    let witness = StepWitness::from(plain_witness(&inputs("plain")).unwrap());
    check_step::<StepToyPlain>(&plain, &witness).unwrap();
    assert_eq!(prove_step::<StepToyPlain>(&plain, &witness).unwrap().public_input.len(), 34);

    let recurse_circuit = circuit::<StepToyRecurse>("recurse");
    let witness = StepWitness::from(recurse());
    check_step::<StepToyRecurse>(&recurse_circuit, &witness).unwrap();
    assert_eq!(prove_step::<StepToyRecurse>(&recurse_circuit, &witness).unwrap().public_input.len(), 34);
}


/// A changed input is reported at the first variable it changes, with the o1js call site that makes
/// it.
#[test]
fn a_mismatch_names_the_variable_and_its_call_site() {
    // the token id argument is witnessed at variable 92 and read by nothing else
    let mut changed = inputs("recurse");
    changed.token_id = Fp::from(2u64);
    let inner = inner();
    let previous = PreviousProof {
        proof: &inner.proof,
        verification_key: &inner.vk,
        public_input: &inner.public_input,
    };
    let w = recurse_witness(&changed, &previous).unwrap();
    let report = first_difference("recurse", &w.primary, &w.aux).expect("a different token id changes the witness");
    assert!(report.starts_with("first differing variable: 92 "), "{report}");
    assert!(report.contains("main:zkprogram.js:503"), "{report}");

    // the app state, variable 1, is the account update hash, which the blinding value changes
    let mut changed = inputs("plain");
    changed.blinding = Fp::from(5u64);
    let w = plain_witness(&changed).unwrap();
    let report = first_difference("plain", &w.primary, &w.aux).expect("a different blinding changes the witness");
    assert!(report.starts_with("first differing variable: 1 "), "{report}");
    assert!(report.ends_with("(OCaml)"), "{report}");

    // a witness that stops early is reported at the first variable it lacks
    let w = recurse();
    let report = first_difference("recurse", &w.primary, &w.aux[..91]).expect("a short witness differs");
    assert!(report.starts_with("91 variables, o1js 143968: first differing variable: 92 "), "{report}");
    assert!(report.contains("main:zkprogram.js:503"), "{report}");
}

fn program_vk() -> ledger::VerificationKey {
    let vk = load_vk(json("toy_inputs.json")["vk"].as_str().unwrap()).unwrap();
    use ark_ff::PrimeField;
    assert_eq!(vk.hash().into_bigint().to_string(), pins::TOY_PROGRAM_VK_HASH);
    vk
}

/// The toy methods proved wholly in Rust, from their arguments (and, for `recurse`, the proof of
/// `toy-inner`) to the wrap proof, verify under the zkApp's verification key, in the form a transaction
/// carries them and as o1js reads them for the program.
#[test]
fn the_toy_methods_proved_in_rust_verify_under_the_program_vk() {
    let program = ToyProgram::load(fixture).unwrap();
    let inner = inner();
    let previous = PreviousProof {
        proof: &inner.proof,
        verification_key: &inner.vk,
        public_input: &inner.public_input,
    };
    let vk = program_vk();
    for (method, proved) in [
        ("plain", program.prove_plain(&inputs("plain")).unwrap()),
        ("recurse", program.prove_recurse(&inputs("recurse"), &previous).unwrap()),
    ] {
        // o1js's proof of the same call has the same public input
        let o1js = json(&format!("toy_{method}_proof.json"));
        assert_eq!(
            proved.public_input.to_vec(),
            o1js["publicInputFields"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().parse::<Fp>().unwrap())
                .collect::<Vec<_>>(),
            "{method}: the public input differs from o1js's"
        );
        let in_transaction = WrapProof::from_o1js_base64(&proved.proof.to_o1js_base64()).unwrap();
        assert!(verify(&vk, &proved.public_input, &in_transaction), "{method}: refused under the program VK");
        let for_program = WrapProof::from_o1js_base64(&proved.proof.to_o1js_program_base64_for(1).unwrap()).unwrap();
        assert!(verify(&vk, &proved.public_input, &for_program), "{method}: the program form is refused");

        let mut tampered = proved.public_input;
        tampered[0] += Fp::from(1u64);
        assert!(!verify(&vk, &tampered, &in_transaction), "{method}: a changed public input is accepted");
    }
}

/// `recurse` refuses an `x` that is not the proof's public input, and so does the prover.
#[test]
fn a_recurse_that_breaks_the_method_is_not_proved() {
    let mut broken = inputs("recurse");
    broken.x = Fp::from(48u64);
    let inner = inner();
    let previous = PreviousProof {
        proof: &inner.proof,
        verification_key: &inner.vk,
        public_input: &inner.public_input,
    };
    let err = ToyProgram::load(fixture).unwrap().prove_recurse(&broken, &previous).err().expect("proved");
    assert!(err.to_string().contains("incorrect witness"), "{err:#}");
}

/// The proofs `o1js/src/rust-wrap.test.ts` verifies are ones of a Rust witness: they verify here too.
#[test]
fn committed_rust_witness_proofs_verify_in_rust() {
    let vk = program_vk();
    for method in ["plain", "recurse"] {
        let f = json(&format!("rust_witness_toy_{method}_proof.json"));
        let public: Vec<Fp> =
            f["publicInputFields"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().parse().unwrap()).collect();
        let proof = WrapProof::from_o1js_base64(f["proof"].as_str().unwrap()).unwrap();
        assert!(verify(&vk, &public, &proof), "{method}");
    }
}
