//! The verifier accepts o1js's real `RequestProgram` proofs, unsubsidised and subsidised, under the
//! committed key, and refuses a changed public input and a proof of another program. The fixtures are
//! `test-vectors/request-proofs/request-proofs.json`, made by `npm run request-fixtures` in `o1js/`, with
//! `recorded-vault.json`, the real vault they were proved against. The two must agree.

use mina_curves::pasta::Fp;
use zk_note::policy::{MIN_SUBSIDY_AGE_SLOTS, SUBSIDY_PERIOD_SLOTS};
use zk_note::field_to_string;
use zk_note::request::{RequestPublic, SubsidyPeriodError};
use zk_prover::verify::{fields, load_vk, verify, WrapProof};

fn fixtures() -> serde_json::Value {
    let path = format!("{}/../test-vectors/request-proofs/request-proofs.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn strs(v: &serde_json::Value) -> Vec<&str> {
    v.as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect()
}

fn ledger_hash(vk: &ledger::VerificationKey) -> String {
    use ark_ff::PrimeField;
    vk.hash().into_bigint().to_string()
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
    // The committed hash is the hash of the committed key, as Mina computes it.
    assert_eq!(ledger_hash(&vk), f["verificationKey"]["hash"].as_str().unwrap());
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
    // A vault created a period later would put the same request one period earlier.
    assert!(matches!(
        subsidised.check_subsidy_period(creation + SUBSIDY_PERIOD_SLOTS),
        Err(SubsidyPeriodError::WrongPeriod { .. })
    ));

    let (_, public) = parse(&f["unsubsidised"]["proof"]);
    assert_eq!(RequestPublic::from_fields(&public).unwrap().check_subsidy_period(creation), Ok(()));
}

/// `recorded-vault.json`: a real vault's daemon and archive answers, recorded with the proofs (#67).
fn recording() -> serde_json::Value {
    let path = format!("{}/../test-vectors/request-proofs/recorded-vault.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

/// Where the vault's state fields sit in its app state: `declareState` in `o1js/src/vault.ts`.
const ROOT_RING: std::ops::Range<usize> = 4..12;
const CREATION_TIME: usize = 13;
const STATE_KEY_X: usize = 20;
const STATE_KEY_IS_ODD: usize = 21;
/// Where a dispatched `VaultAction`'s fields sit: its kind, and the nullifiers a close or escape consumes.
const ACTION_KIND: usize = 0;
const ACTION_NULLIFIER: usize = 2;
const ACTION_NEXT_NULLIFIER: usize = 3;
const ACTION_KIND_DEPOSIT: &str = "1";
const ACTION_TIME: usize = 6;
const ACTION_KIND_MUTUAL_CLOSE: &str = "2";
const ACTION_KIND_ESCAPE: &str = "3";

fn app_state(r: &serde_json::Value) -> Vec<&str> {
    strs(&r["vaultState"]["data"]["account"]["zkappState"])
}

/// The fields of every recorded action.
fn recorded_actions(r: &serde_json::Value) -> Vec<Vec<&str>> {
    let blocks = r["actions"]["data"]["actions"].as_array().unwrap();
    blocks.iter().flat_map(|b| b["actionData"].as_array().unwrap()).map(|a| strs(&a["data"])).collect()
}

/// Every nullifier a recorded close or escape action consumes.
fn consumed_nullifiers(r: &serde_json::Value) -> Vec<&str> {
    let mut consumed = vec![];
    for data in recorded_actions(r) {
        if data[ACTION_KIND] == ACTION_KIND_MUTUAL_CLOSE {
            consumed.push(data[ACTION_NULLIFIER]);
        } else if data[ACTION_KIND] == ACTION_KIND_ESCAPE {
            consumed.extend([data[ACTION_NULLIFIER], data[ACTION_NEXT_NULLIFIER]]);
        }
    }
    consumed
}

fn request(f: &serde_json::Value, name: &str) -> RequestPublic {
    RequestPublic::from_fields(&parse(&f[name]["proof"]).1).unwrap()
}

#[test]
fn the_proofs_agree_with_the_recorded_vault() {
    let (f, r) = (fixtures(), recording());
    let state = app_state(&r);
    let ring = &state[ROOT_RING];
    let creation: u64 = state[CREATION_TIME].parse().unwrap();
    let tip: u64 = r["vaultState"]["data"]["bestChain"][0]["protocolState"]["consensusState"]["slotSinceGenesis"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let consumed = consumed_nullifiers(&r);
    assert_eq!(f["vaultCreation"].as_str().unwrap(), state[CREATION_TIME]);

    for name in ["unsubsidised", "subsidised"] {
        let p = request(&f, name);
        assert!(ring.contains(&field_to_string(p.root).as_str()), "{name}: root is not in the recorded ring");
        assert_eq!(field_to_string(p.vault_x), state[STATE_KEY_X], "{name}: vault is not the recorded state key");
        assert_eq!(p.vault_is_odd, state[STATE_KEY_IS_ODD] == "1", "{name}: vault is not the recorded state key");
        assert!(p.request_time >= creation, "{name}: requested before the vault existed");
        assert_eq!(p.check_subsidy_period(creation), Ok(()), "{name}: not in a period of the recorded vault");
        assert!(!consumed.contains(&field_to_string(p.nullifier).as_str()), "{name}: nullifier is consumed");
    }
    // The unsubsidised request is made at the recording's own slot. The subsidised one is made as soon as a
    // recorded deposit is old enough, a slot the chain had not reached: see docs/verification-keys.md.
    assert_eq!(request(&f, "unsubsidised").request_time, tip);
    let subsidised = request(&f, "subsidised").request_time;
    assert!(recorded_actions(&r).iter().any(|a| a[ACTION_KIND] == ACTION_KIND_DEPOSIT
        && a[ACTION_TIME].parse::<u64>().unwrap() + MIN_SUBSIDY_AGE_SLOTS == subsidised));
}

#[test]
fn the_recording_holds_a_consumed_nullifier_and_not_the_named_absent_values() {
    let mut r = recording();
    let named = r.as_object_mut().unwrap().remove("named").unwrap();
    assert!(consumed_nullifiers(&r).contains(&named["consumedNullifier"].as_str().unwrap()));
    let everything = r.to_string();
    for absent in ["absentRoot", "absentNullifier"] {
        assert!(!everything.contains(named[absent].as_str().unwrap()), "{absent} is in the recording");
    }
}

#[test]
fn the_recorded_action_state_is_the_archives_latest() {
    let r = recording();
    let blocks = r["actions"]["data"]["actions"].as_array().unwrap();
    let latest = blocks.last().unwrap()["actionState"]["actionStateOne"].as_str().unwrap();
    assert_eq!(r["vaultState"]["data"]["account"]["actionState"][0].as_str().unwrap(), latest);
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
