//! The verifier accepts o1js's real `RequestProgram` proofs, unsubsidised and subsidised, under the
//! committed key, and refuses a changed public input and a proof of another program. The fixtures are
//! `test-vectors/request-proofs/request-proofs.json`, made by `npm run request-fixtures` in `o1js/`.

use mina_curves::pasta::Fp;
use zk_note::policy::SUBSIDY_PERIOD_SLOTS;
use zk_note::request::{RequestPublic, SubsidyPeriodError};
use zk_prover::verify::{fields, load_vk, verify, WrapProof};

fn fixtures() -> serde_json::Value {
    let path = format!("{}/../test-vectors/request-proofs/request-proofs.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn strs(v: &serde_json::Value) -> Vec<&str> {
    v.as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect()
}

/// A JsonProof's decoded proof and public input fields.
fn parse(json_proof: &serde_json::Value) -> (WrapProof, Vec<Fp>) {
    let proof = WrapProof::from_o1js_base64(json_proof["proof"].as_str().unwrap()).unwrap();
    (proof, fields(&strs(&json_proof["publicInput"])).unwrap())
}

#[test]
fn verifies_both_request_proofs_and_refuses_tampering() {
    let f = fixtures();
    let vk = load_vk(f["verificationKey"]["data"].as_str().unwrap()).unwrap();
    for name in ["unsubsidised", "subsidised"] {
        let (proof, public) = parse(&f[name]["proof"]);
        assert!(verify(&vk, &public, &proof), "{name} proof is refused");

        let decoded = RequestPublic::from_fields(&public).unwrap();
        assert_eq!(decoded.subsidised, name == "subsidised");

        // A changed input is no longer the one the proof is for: the first field, the root, the
        // nullifier and the last (a trailing zero is implicit, so only a changed value shows).
        for i in [0, 2, 5, public.len() - 1] {
            let mut tampered = public.clone();
            tampered[i] += Fp::from(1u64);
            assert!(!verify(&vk, &tampered, &proof), "{name} proof verifies with field {i} changed");
        }
    }
}

#[test]
fn the_subsidised_proof_is_in_a_period_of_the_vault_created_at_the_fixtures_slot() {
    let f = fixtures();
    let creation: u64 = f["vaultCreation"].as_str().unwrap().parse().unwrap();
    let (_, public) = parse(&f["subsidised"]["proof"]);
    let subsidised = RequestPublic::from_fields(&public).unwrap();
    assert!(subsidised.subsidised);
    assert_eq!(subsidised.check_subsidy_period(creation), Ok(()));
    // A vault created a period earlier would put the same request one period later.
    assert!(matches!(
        subsidised.check_subsidy_period(creation - SUBSIDY_PERIOD_SLOTS),
        Err(SubsidyPeriodError::WrongPeriod { .. })
    ));

    let (_, public) = parse(&f["unsubsidised"]["proof"]);
    assert_eq!(RequestPublic::from_fields(&public).unwrap().check_subsidy_period(creation), Ok(()));
}

#[test]
fn refuses_a_proof_of_another_program_under_the_request_key() {
    let f = fixtures();
    let request_vk = load_vk(f["verificationKey"]["data"].as_str().unwrap()).unwrap();
    let other = &f["otherProgram"];
    let other_vk = load_vk(other["verificationKey"]["data"].as_str().unwrap()).unwrap();
    let (proof, public) = parse(&other["proof"]);

    // The proof is real: it verifies under its own key, and only under that one.
    assert!(verify(&other_vk, &public, &proof));
    assert!(!verify(&request_vk, &public, &proof));

    // And a request proof is refused under the other program's key.
    let (proof, public) = parse(&f["unsubsidised"]["proof"]);
    assert!(!verify(&other_vk, &public, &proof));
}
