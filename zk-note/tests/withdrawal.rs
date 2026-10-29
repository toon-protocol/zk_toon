//! The withdrawal proof's sample entries in `test-vectors/zk-note.json`: recomputes the nullifier and checks
//! the public inputs' layout and shape. An entry lists `conceded` only for an escape; it is zero otherwise.
use serde_json::Value;
use std::str::FromStr;
use zk_note::withdrawal::*;
use zk_note::{field_to_string, genesis_anchor, commit_secret, next_anchor, nullifier, policy, Field};

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or_else(|| panic!("not a string: {v}"))
}
fn f(v: &Value) -> Field {
    Field::from_str(s(v)).unwrap_or_else(|_| panic!("bad field {v}"))
}
fn u(v: &Value) -> u64 {
    s(v).parse().unwrap()
}
fn public(p: &Value) -> WithdrawalPublic {
    WithdrawalPublic {
        kind: u(&p["kind"]),
        vault_x: f(&p["vault"]["x"]),
        vault_is_odd: s(&p["vault"]["isOdd"]) == "1",
        root: f(&p["root"]),
        nullifier: f(&p["nullifier"]),
        next_nullifier: f(&p["nextNullifier"]),
        amount: u(&p["amount"]),
        size: u(&p["size"]),
        destination_x: f(&p["destination"]["x"]),
        destination_is_odd: s(&p["destination"]["isOdd"]) == "1",
        valid_until: u(&p["validUntil"]),
        request_time: u(&p["requestTime"]),
        conceded: if p["conceded"].is_null() { 0 } else { u(&p["conceded"]) },
    }
}

#[test]
fn withdrawal_samples_are_recomputed() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../test-vectors/zk-note.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let entries = v["withdrawalProofs"].as_array().unwrap();
    assert!(!entries.is_empty());
    println!("vector cases run: {}", entries.len());
    let mut kinds = Vec::new();
    for e in entries {
        let (p, w) = (&e["public"], &e["private"]);
        let pubs = public(p);
        kinds.push(pubs.kind);
        assert!(pubs.shape_is_valid());
        // `conceded` comes last, so the other inputs keep their places.
        assert_eq!(pubs.to_fields().len(), 13);
        assert_eq!(field_to_string(pubs.to_fields()[4]), s(&p["nullifier"]));
        assert_eq!(pubs.to_fields()[12], Field::from(pubs.conceded));

        // The nullifier is this state's, and the state is genesis or a signed next state.
        let secret = f(&w["secret"]);
        let anchor = f(&w["anchor"]);
        let n = nullifier(secret, anchor);
        assert_eq!(n, pubs.nullifier);
        if w["isGenesis"].as_bool().unwrap() {
            assert_eq!(anchor, genesis_anchor(commit_secret(secret)));
            // A genesis state's balance is the deposit.
            assert_eq!(pubs.amount, pubs.size);
        } else {
            let prev = nullifier(secret, genesis_anchor(commit_secret(secret)));
            assert_eq!(anchor, next_anchor(prev));
        }

        // Expiry is private and follows from the deposit time, which comes before the request.
        assert_eq!(policy::expiry_of(u(&w["depositTime"])), u(&w["expiry"]));
        assert!(pubs.request_time < u(&w["expiry"]));
        assert!(policy::is_deposit_size(pubs.size));

        // An escape names the next state's nullifier, and may land only while the note is unexpired.
        if pubs.kind == KIND_ESCAPE {
            assert_eq!(pubs.next_nullifier, pubs.escape_next_nullifier(secret));
            assert!(pubs.valid_until < u(&w["expiry"]));
        } else {
            assert!(p["conceded"].is_null());
        }
    }
    assert_eq!(kinds, [KIND_OWNERSHIP, KIND_MUTUAL_CLOSE, KIND_ESCAPE]);
}

#[test]
fn a_close_and_an_ownership_proof_have_a_zero_escape_tail() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../test-vectors/zk-note.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let base = public(&v["withdrawalProofs"][1]["public"]);
    assert!(base.shape_is_valid());
    for kind in [0, KIND_ESCAPE, 4] {
        assert!(!WithdrawalPublic { kind, ..base }.shape_is_valid());
    }
    assert!(WithdrawalPublic { kind: KIND_OWNERSHIP, ..base }.shape_is_valid());
    assert!(!WithdrawalPublic { valid_until: 1, ..base }.shape_is_valid());
    assert!(!WithdrawalPublic { next_nullifier: Field::from(1u64), ..base }.shape_is_valid());
    assert!(!WithdrawalPublic { amount: base.size + 1, ..base }.shape_is_valid());
    assert!(!WithdrawalPublic { conceded: 1, ..base }.shape_is_valid());
}

#[test]
fn an_escape_has_a_next_nullifier_a_bounded_concession_and_a_validity() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../test-vectors/zk-note.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let base = public(&v["withdrawalProofs"][2]["public"]);
    assert_eq!(base.kind, KIND_ESCAPE);
    assert!(base.shape_is_valid());
    assert!(!WithdrawalPublic { next_nullifier: Field::from(0u64), ..base }.shape_is_valid());
    assert!(!WithdrawalPublic { conceded: base.amount + 1, ..base }.shape_is_valid());
    assert!(WithdrawalPublic { conceded: base.amount, ..base }.shape_is_valid());
    assert!(!WithdrawalPublic { valid_until: base.request_time - 1, ..base }.shape_is_valid());
    assert!(!WithdrawalPublic { amount: base.size + 1, ..base }.shape_is_valid());
}
