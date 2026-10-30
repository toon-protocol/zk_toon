//! `land`'s step witness built in Rust equals o1js's at every index, and kimchi proves `cs003`
//! from it.

use std::{io::Read, str::FromStr};

use mina_curves::pasta::Fp;
use zk_prover::{
    check_step, prove_step,
    witness::land::{land_witness, LandInputs},
    StepCircuit, StepLand, StepWitness,
};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/fixtures/{name}.gz", env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut out)
        .unwrap();
    out
}

/// `land`'s inputs: `inputs.json` (the method's arguments, the addresses and the verification key)
/// and what `fixture-gen/prove-local.mjs` fixes besides: the zkApp's state before the call
/// (`landed` is 0, from `init`), the token id (MINA's, 1) and the blinding value of the call data
/// (`Fp.random()` replaced by a counter, which is at 4 for this call).
fn land_inputs() -> LandInputs {
    let v: serde_json::Value = serde_json::from_slice(&fixture("inputs.json")).unwrap();
    let s = |k: &str| v[k].as_str().unwrap().to_string();
    LandInputs {
        zkapp: s("zkapp"),
        payer: s("payer"),
        cumulative: s("cumulative").parse().unwrap(),
        sig: s("sig"),
        landed: 0,
        token_id: Fp::from(1u64),
        blinding: Fp::from(4u64),
        vk: s("vk"),
        vk_hash: Fp::from_str(&s("vkHash")).unwrap(),
    }
}

/// o1js's witness: the public input, then the auxiliary values.
fn o1js_witness() -> Vec<Fp> {
    let v: serde_json::Value = serde_json::from_slice(&fixture("w003_cs003.json")).unwrap();
    v["external"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| Fp::from_str(x.as_str().unwrap()).unwrap())
        .collect()
}

/// The o1js call site of auxiliary variable `index` (1-based), from `land-step-map.txt`: each line
/// is `start +count xN site`, and the (OCaml) lines are Pickles' and snarky's own.
fn call_site(index: usize) -> String {
    let map = String::from_utf8(fixture("land-step-map.txt")).unwrap();
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

/// The first variable in which `aux` differs from o1js's witness, with its o1js call site.
fn first_difference(aux: &[Fp]) -> Option<String> {
    let o1js = o1js_witness();
    for (i, (rust, theirs)) in aux.iter().zip(&o1js[1..]).enumerate() {
        if rust != theirs {
            return Some(format!(
                "first differing variable: {} (aux index {}), made by {}",
                i + 1,
                i,
                call_site(i + 1)
            ));
        }
    }
    // a matching prefix: the first variable only one side has
    let (ours, theirs) = (aux.len(), o1js.len() - 1);
    (ours != theirs).then(|| {
        let first = ours.min(theirs) + 1;
        format!(
            "{ours} variables, o1js {theirs}: first differing variable: {first} (aux index {}), made by {}",
            first - 1,
            call_site(first)
        )
    })
}

#[test]
fn rust_witness_equals_o1js_at_every_index() {
    let w = land_witness(&land_inputs()).unwrap();
    assert_eq!(w.primary, vec![o1js_witness()[0]], "public input");
    assert_eq!(first_difference(&w.aux), None);
}

/// A changed input is reported at the first variable it changes, with the o1js call site that
/// makes it.
#[test]
fn a_mismatch_names_the_variable_and_its_call_site() {
    // the token id argument is witnessed at variable 92 and read by nothing else
    let mut inputs = land_inputs();
    inputs.token_id = Fp::from(2u64);
    let w = land_witness(&inputs).unwrap();
    let report = first_difference(&w.aux).expect("a different token id changes the witness");
    assert!(report.starts_with("first differing variable: 92 "), "{report}");
    assert!(report.contains("main:zkprogram.js:503"), "{report}");

    // the app state, variable 1, is the account update hash, which the blinding value changes
    let mut inputs = land_inputs();
    inputs.blinding = Fp::from(5u64);
    let w = land_witness(&inputs).unwrap();
    let report = first_difference(&w.aux).expect("a different blinding changes the witness");
    assert!(report.starts_with("first differing variable: 1 "), "{report}");
    assert!(report.ends_with("(OCaml)"), "{report}");

    // a witness that stops early is reported at the first variable it lacks
    let w = land_witness(&land_inputs()).unwrap();
    let report = first_difference(&w.aux[..91]).expect("a short witness differs");
    assert!(report.contains("first differing variable: 92 "), "{report}");
    assert!(report.contains("main:zkprogram.js:503"), "{report}");
}

#[test]
fn kimchi_proves_cs003_from_the_rust_witness() {
    let circuit = StepCircuit::load::<StepLand>(
        &fixture("cs003_gates.json"),
        &fixture("cs003_internal_vars.bin"),
        &fixture("cs003_rows_rev.bin"),
    )
    .unwrap();
    let w = land_witness(&land_inputs()).unwrap();
    let witness = StepWitness::from(w);
    check_step::<StepLand>(&circuit, &witness).unwrap();
    let proof = prove_step::<StepLand>(&circuit, &witness).unwrap();
    assert_eq!(proof.public_input.len(), 1);
}
