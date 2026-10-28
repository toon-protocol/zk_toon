//! Clearances and the withdrawal proof's public inputs: reproduces the `clearances` and
//! `withdrawalProofs` entries of `test-vectors/zk-note.json`.
use mina_signer::{CompressedPubKey, Keypair, NetworkId, SecKey, Signature};
use serde_json::Value;
use std::str::FromStr;
use zk_note::balance::{commit, Scalar};
use zk_note::clearance::*;
use zk_note::state::{verify_state, StateMessage};
use zk_note::withdrawal::{WithdrawalKind, WithdrawalPublic};
use zk_note::{
    commit_secret, field_to_string, genesis_anchor, next_anchor, nullifier, policy, tag_to_field, tags, Field,
    VECTORS_JSON,
};

fn vectors() -> Value {
    serde_json::from_str(VECTORS_JSON).unwrap()
}
fn s(v: &Value) -> &str {
    v.as_str().unwrap_or_else(|| panic!("not a string: {v}"))
}
fn f(v: &Value) -> Field {
    Field::from_str(s(v)).unwrap_or_else(|_| panic!("bad field {v}"))
}
fn sc(v: &Value) -> Scalar {
    Scalar::from_str(s(v)).unwrap_or_else(|_| panic!("bad scalar {v}"))
}
fn u(v: &Value) -> u64 {
    s(v).parse().unwrap()
}
fn key(v: &Value) -> CompressedPubKey {
    CompressedPubKey { x: f(&v["x"]), is_odd: s(&v["isOdd"]) == "1" }
}
fn keypair(secret: &Value) -> Keypair {
    Keypair::try_from(SecKey::new(sc(secret))).unwrap()
}
fn signature(v: &Value) -> Signature {
    Signature::new(f(&v["r"]), sc(&v["s"]))
}
fn strings(fields: Vec<Field>) -> Vec<String> {
    fields.into_iter().map(field_to_string).collect()
}
fn expected(v: &Value) -> Vec<&str> {
    v.as_array().unwrap().iter().map(s).collect()
}
fn message(e: &Value) -> ClearanceMessage {
    ClearanceMessage { state_key: key(&e["stateKey"]), nullifier: f(&e["nullifier"]), destination: key(&e["destination"]) }
}

#[test]
fn the_clearance_tag_is_a_domain_tag() {
    let v = vectors();
    assert_eq!(s(&v["tags"]["clearance"]["text"]), tags::CLEARANCE);
    assert_eq!(field_to_string(tag_to_field(tags::CLEARANCE)), s(&v["tags"]["clearance"]["field"]));
}

#[test]
fn clearances_match() {
    let v = vectors();
    let c = &v["clearances"];
    assert_eq!(s(&c["networkId"]), "devnet");
    let cases = c["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    println!("vector cases run: {}", cases.len());
    for e in cases {
        let kp = keypair(&e["secret"]);
        let msg = message(e);
        assert_eq!(msg.state_key, kp.public.into_compressed());
        assert_eq!(strings(msg.to_fields()), expected(&e["fields"]));
        // Rust signs exactly what o1js signed, and verifies o1js's signature.
        assert_eq!(sign_clearance(&kp, &msg), signature(&e["signature"]));
        assert!(verify_clearance(&signature(&e["signature"]), &kp.public, &msg));
    }
}

#[test]
fn a_changed_clearance_is_refused() {
    let v = vectors();
    let cases = v["clearances"]["cases"].as_array().unwrap();
    let (a, b) = (&cases[0], &cases[2]);
    let kp = keypair(&a["secret"]);
    let sig = signature(&a["signature"]);
    let msg = message(a);
    assert!(verify_clearance(&sig, &kp.public, &msg));
    assert!(!verify_clearance(&sig, &kp.public, &ClearanceMessage { nullifier: f(&b["nullifier"]), ..msg.clone() }));
    let elsewhere = key(&cases[1]["destination"]);
    assert_ne!(elsewhere, msg.destination);
    assert!(!verify_clearance(&sig, &kp.public, &ClearanceMessage { destination: elsewhere, ..msg.clone() }));
    // Another key: refused whether or not the message names it, even over that key's own signature.
    let other = keypair(&b["secret"]);
    assert!(!verify_clearance(&sig, &other.public, &msg));
    let named = ClearanceMessage { state_key: other.public.into_compressed(), ..msg.clone() };
    assert!(!verify_clearance(&sig, &other.public, &named));
    let theirs = sign_clearance(&other, &msg);
    assert!(!verify_clearance(&theirs, &other.public, &msg));
}

#[test]
fn a_state_signature_is_not_a_clearance() {
    let v = vectors();
    let e = &v["stateSignatures"]["cases"][0];
    let kp = keypair(&e["secret"]);
    let state_sig = signature(&e["signature"]);
    let msg = ClearanceMessage {
        state_key: kp.public.into_compressed(),
        nullifier: f(&e["anchor"]),
        destination: kp.public.into_compressed(),
    };
    assert!(!verify_clearance(&state_sig, &kp.public, &msg));
}

#[test]
fn a_mainnet_signed_clearance_is_refused() {
    let v = vectors();
    let e = &v["clearances"]["mainnetClearance"];
    assert_eq!(s(&e["networkId"]), "mainnet");
    let kp = keypair(&e["secret"]);
    let sig = signature(&e["signature"]);
    assert!(verify_clearance_on(NetworkId::MAINNET, &sig, &kp.public, &message(e)));
    assert!(!verify_clearance(&sig, &kp.public, &message(e)));
}

fn public(p: &Value) -> WithdrawalPublic {
    WithdrawalPublic {
        kind: WithdrawalKind::try_from(u(&p["kind"])).unwrap(),
        vault: key(&p["vault"]),
        root: f(&p["root"]),
        nullifier: f(&p["nullifier"]),
        next_nullifier: f(&p["nextNullifier"]),
        amount: u(&p["amount"]),
        size: u(&p["size"]),
        destination: key(&p["destination"]),
        valid_until: u(&p["validUntil"]),
        request_time: u(&p["requestTime"]),
        conceded: u(&p["conceded"]),
    }
}

#[test]
fn withdrawal_kinds_are_fixed() {
    assert_eq!(WithdrawalKind::MutualClose as u64, 1);
    assert_eq!(WithdrawalKind::Escape as u64, 2);
    assert_eq!(WithdrawalKind::Ownership as u64, 3);
    assert!(WithdrawalKind::try_from(0).is_err());
    assert!(WithdrawalKind::try_from(4).is_err());
}

#[test]
fn withdrawal_samples_are_recomputed() {
    let v = vectors();
    let entries = v["withdrawalProofs"].as_array().unwrap();
    assert!(!entries.is_empty());
    println!("vector cases run: {}", entries.len());
    let mut kinds = vec![];
    for e in entries {
        let (p, w) = (&e["public"], &e["private"]);
        let public = public(p);
        kinds.push(public.kind);

        // The public inputs' field layout is the one the connector reads.
        assert_eq!(strings(public.to_fields()), expected(&e["fields"]));
        assert!(public.amount <= public.size);
        assert!(policy::is_deposit_size(public.size));

        // The note: its expiry follows from its deposit time, and the request comes before it.
        let secret = f(&w["secret"]);
        assert_eq!(policy::expiry_of(u(&w["depositTime"])), u(&w["expiry"]));
        assert!(public.request_time < u(&w["expiry"]));

        // The state: genesis with the deposit size as its balance, or one the state key signed.
        let state_key = keypair(&w["stateKeySecret"]);
        assert_eq!(public.vault, state_key.public.into_compressed());
        let anchor = f(&w["anchor"]);
        if w["isGenesis"].as_bool().unwrap() {
            assert_eq!(anchor, genesis_anchor(commit_secret(secret)));
            assert_eq!(public.amount, public.size);
        } else {
            let prev = f(&w["prevNullifier"]);
            assert_eq!(prev, nullifier(secret, f(&w["prevAnchor"])));
            assert_eq!(anchor, next_anchor(prev));
            let commitment = commit(Scalar::from(public.amount), sc(&w["blinding"]));
            let state = StateMessage::new(&public.vault, commitment, anchor);
            assert!(verify_state(&signature(&w["signature"]), &state_key.public, &state));
        }
        assert_eq!(public.nullifier, nullifier(secret, anchor));

        // An escape also names the next state's nullifier, concedes at most its balance, and may
        // land only while the note is unexpired. The other kinds leave those inputs zero.
        if public.kind == WithdrawalKind::Escape {
            assert_eq!(public.next_nullifier, public.escape_next_nullifier(secret));
            assert!(public.conceded <= public.amount);
            assert!(public.request_time <= public.valid_until && public.valid_until < u(&w["expiry"]));
        } else {
            assert_eq!((public.next_nullifier, public.valid_until, public.conceded), (Field::from(0u64), 0, 0));
        }

        // A mutual close carries the clearance of its nullifier to its destination.
        match public.kind {
            WithdrawalKind::MutualClose => {
                let c = &e["clearance"];
                let msg = ClearanceMessage::new(&public.vault, public.nullifier, &public.destination);
                assert_eq!(strings(msg.to_fields()), expected(&c["fields"]));
                assert_eq!(sign_clearance(&state_key, &msg), signature(&c["signature"]));
                assert!(verify_clearance(&signature(&c["signature"]), &state_key.public, &msg));
            }
            _ => assert!(e["clearance"].is_null()),
        }
    }
    assert_eq!(kinds, [WithdrawalKind::MutualClose, WithdrawalKind::Ownership, WithdrawalKind::Escape]);
}

