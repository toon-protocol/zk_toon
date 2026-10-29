//! Clearances: reproduces the `clearances` entries of `test-vectors/zk-note.json` and refuses what a
//! clearance must not cover.
use mina_signer::{CompressedPubKey, Keypair, NetworkId, SecKey, Signature};
use serde_json::Value;
use std::str::FromStr;
use zk_note::balance::Scalar;
use zk_note::clearance::*;
use zk_note::{field_to_string, tag_to_field, tags, Field};

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../test-vectors/zk-note.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
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
fn key(v: &Value) -> CompressedPubKey {
    CompressedPubKey { x: f(&v["x"]), is_odd: s(&v["isOdd"]) == "1" }
}
fn keypair(secret: &Value) -> Keypair {
    Keypair::try_from(SecKey::new(sc(secret))).unwrap()
}
fn message(e: &Value) -> ClearanceMessage {
    ClearanceMessage::new(&key(&e["stateKey"]), f(&e["nullifier"]), &key(&e["destination"]))
}
fn signature(e: &Value) -> Signature {
    Signature::new(f(&e["signature"]["r"]), sc(&e["signature"]["s"]))
}

#[test]
fn clearances_match() {
    let v = vectors();
    let cases = v["clearances"]["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    assert_eq!(s(&v["clearances"]["networkId"]), "devnet");
    println!("vector cases run: {}", cases.len());
    for e in cases {
        let kp = keypair(&e["stateSecret"]);
        let msg = message(e);
        let fields: Vec<String> = msg.to_fields().into_iter().map(field_to_string).collect();
        let expected: Vec<&str> = e["fields"].as_array().unwrap().iter().map(s).collect();
        assert_eq!(fields, expected);
        assert_eq!(field_to_string(msg.to_fields()[0]), s(&v["tags"]["clearance"]["field"]));
        assert_eq!(msg.to_fields()[0], tag_to_field(tags::CLEARANCE));
        // The message names the signer's key, and Rust signs exactly what o1js signed.
        assert_eq!(kp.public.into_compressed(), key(&e["stateKey"]));
        assert_eq!(sign_clearance(&kp, &msg), signature(e));
        assert!(verify_clearance(&signature(e), &kp.public, &msg));
    }
}

#[test]
fn a_clearance_covers_one_nullifier_and_one_destination() {
    let v = vectors();
    let cases = v["clearances"]["cases"].as_array().unwrap();
    let (a, other_nullifier, other_destination) = (&cases[0], &cases[1], &cases[2]);
    let kp = keypair(&a["stateSecret"]);
    let sig = signature(a);
    let mut msg = message(a);
    assert!(verify_clearance(&sig, &kp.public, &msg));
    msg.nullifier = f(&other_nullifier["nullifier"]);
    assert!(!verify_clearance(&sig, &kp.public, &msg));
    msg = message(a);
    let d = key(&other_destination["destination"]);
    msg.destination_x = d.x;
    msg.destination_is_odd = d.is_odd;
    assert!(!verify_clearance(&sig, &kp.public, &msg));
}

#[test]
fn another_key_is_refused() {
    let v = vectors();
    let cases = v["clearances"]["cases"].as_array().unwrap();
    let (a, b) = (&cases[0], &cases[3]);
    let other = keypair(&b["stateSecret"]);
    // The state key's clearance does not verify under another key, named or not.
    assert!(!verify_clearance(&signature(a), &other.public, &message(a)));
    // A key other than the one the message names is refused even over its own signature.
    let theirs = sign_clearance(&other, &message(a));
    assert!(!verify_clearance(&theirs, &other.public, &message(a)));
}

#[test]
fn a_clearance_never_passes_as_a_state_message() {
    let v = vectors();
    let e = &v["clearances"]["cases"][0];
    let kp = keypair(&e["stateSecret"]);
    // The first field is the tag, which no state message's first field (a key's x) can be.
    assert_eq!(message(e).to_fields().len(), 6);
    assert_ne!(message(e).to_fields()[0], kp.public.into_compressed().x);
}

#[test]
fn the_clearance_tag_is_a_domain_tag() {
    let v = vectors();
    assert_eq!(s(&v["tags"]["clearance"]["text"]), tags::CLEARANCE);
    assert_eq!(field_to_string(tag_to_field(tags::CLEARANCE)), s(&v["tags"]["clearance"]["field"]));
}

#[test]
fn a_state_signature_is_not_a_clearance() {
    let v = vectors();
    let e = &v["stateSignatures"]["cases"][0];
    let kp = keypair(&e["secret"]);
    let state_sig = Signature::new(f(&e["signature"]["r"]), sc(&e["signature"]["s"]));
    let named = kp.public.into_compressed();
    let msg = ClearanceMessage::new(&named, f(&e["anchor"]), &named);
    assert!(!verify_clearance(&state_sig, &kp.public, &msg));
}

#[test]
fn a_mainnet_signed_clearance_is_refused() {
    let v = vectors();
    let e = &v["clearances"]["mainnetClearance"];
    assert_eq!(s(&e["networkId"]), "mainnet");
    let kp = keypair(&e["stateSecret"]);
    assert!(verify_clearance_on(NetworkId::MAINNET, &signature(e), &kp.public, &message(e)));
    assert!(!verify_clearance(&signature(e), &kp.public, &message(e)));
}
