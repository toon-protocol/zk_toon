//! Balance commitments and state signatures: reproduces the matching entries of
//! `test-vectors/zk-note.json`, and checks the algebra on many generated cases.
use ark_ec::AffineRepr;
use mina_curves::pasta::Pallas;
use mina_signer::{Keypair, NetworkId, PubKey, SecKey, Signature};
use serde_json::Value;
use std::str::FromStr;
use zk_note::balance::*;
use zk_note::state::*;
use zk_note::{field_to_string, tag_to_field, Field};

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
fn pt(v: &Value) -> Pallas {
    let p = Pallas::new_unchecked(f(&v["x"]), f(&v["y"]));
    assert!(p.is_on_curve(), "not on the curve: {v}");
    p
}
fn same(actual: Pallas, expected: &Value) {
    let (x, y) = actual.xy().unwrap();
    assert_eq!((field_to_string(x), field_to_string(y)), (s(&expected["x"]).into(), s(&expected["y"]).into()));
}

#[test]
fn generators_match() {
    let v = vectors();
    let g = &v["generators"];
    assert_eq!(GENERATOR_SEED, s(&g["seed"]["text"]));
    assert_eq!(field_to_string(tag_to_field(GENERATOR_SEED)), s(&g["seed"]["field"]));
    for (name, index) in [("g", 0u64), ("h", 1)] {
        let (point, counter) = derive_generator(index);
        same(point, &g[name]);
        assert_eq!(counter.to_string(), s(&g[name]["counter"]));
        assert_eq!(index.to_string(), s(&g[name]["index"]));
    }
    let (gen, h, curve) = (generator_g(), generator_h(), Pallas::generator());
    same(curve, &g["curveGenerator"]);
    assert!(gen != h && gen != curve && h != curve);
    assert!(gen.is_on_curve() && h.is_on_curve());
}

#[test]
fn commitments_match() {
    let entries = vectors()["balanceCommitments"].as_array().unwrap().clone();
    assert!(!entries.is_empty());
    println!("vector cases run: {}", entries.len());
    for e in &entries {
        same(commit(sc(&e["balance"]), sc(&e["blinding"])), &e["commitment"]);
    }
}

#[test]
fn rerandomise_matches() {
    let entries = vectors()["rerandomised"].as_array().unwrap().clone();
    assert!(!entries.is_empty());
    for e in &entries {
        let c = commit(sc(&e["balance"]), sc(&e["blinding"]));
        let out = rerandomise(c, sc(&e["extra"]));
        same(out, &e["rerandomised"]);
        assert_eq!(out, pt(&e["recommitted"]));
    }
}

#[test]
fn charge_matches() {
    let entries = vectors()["charged"].as_array().unwrap().clone();
    assert!(!entries.is_empty());
    for e in &entries {
        let c = commit(sc(&e["balance"]), sc(&e["blinding"]));
        let out = charge(c, sc(&e["delta"]));
        same(out, &e["charged"]);
        assert_eq!(out, pt(&e["recommitted"]));
    }
}

/// A small deterministic generator, so the property test needs no dependency.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 11
    }
    fn scalar(&mut self) -> Scalar {
        Scalar::from(self.next()) * Scalar::from(self.next()) + Scalar::from(self.next())
    }
}

#[test]
fn charge_and_rerandomise_agree_with_commit() {
    let mut rng = Lcg(0x5eed);
    for _ in 0..64 {
        let (balance, delta) = {
            let b = rng.next();
            (b, rng.next() % (b + 1))
        };
        let (r, r2) = (rng.scalar(), rng.scalar());
        let c = commit(Scalar::from(balance), r);
        assert_eq!(charge(c, Scalar::from(delta)), commit(Scalar::from(balance - delta), r));
        assert_eq!(rerandomise(c, r2), commit(Scalar::from(balance), r + r2));
    }
}

fn keypair(secret: &Value) -> Keypair {
    Keypair::try_from(SecKey::new(sc(secret))).unwrap()
}
fn message(e: &Value, vault: &PubKey) -> StateMessage {
    StateMessage::new(&vault.into_compressed(), pt(&e["commitment"]), f(&e["anchor"]))
}
fn signature(e: &Value) -> Signature {
    Signature::new(f(&e["signature"]["r"]), sc(&e["signature"]["s"]))
}
/// Checks every pinned part of a state entry except its signature.
fn check_message(e: &Value, msg: &StateMessage) {
    assert_eq!(field_to_string(msg.vault_x), s(&e["vault"]["x"]));
    assert_eq!(msg.vault_is_odd as u8, s(&e["vault"]["isOdd"]).parse::<u8>().unwrap());
    let fields: Vec<String> = msg.to_fields().into_iter().map(field_to_string).collect();
    let expected: Vec<&str> = e["fields"].as_array().unwrap().iter().map(s).collect();
    assert_eq!(fields, expected);
    // The commitment in the message is the one `balance` and `blinding` produce.
    assert_eq!(msg.commitment, commit(sc(&e["balance"]), sc(&e["blinding"])));
}

#[test]
fn state_signatures_match() {
    let v = vectors();
    let cases = v["stateSignatures"]["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    assert_eq!(s(&v["stateSignatures"]["networkId"]), "devnet");
    for e in cases {
        let kp = keypair(&e["secret"]);
        let msg = message(e, &kp.public);
        check_message(e, &msg);
        // Rust signs exactly what o1js signed, and verifies o1js's signature.
        let sig = sign_state(&kp, &msg);
        assert_eq!(sig, signature(e));
        assert!(verify_state(&signature(e), &kp.public, &msg));
    }
}

#[test]
fn a_changed_state_is_refused() {
    let v = vectors();
    let cases = v["stateSignatures"]["cases"].as_array().unwrap();
    let (a, b) = (&cases[0], &cases[1]);
    let kp = keypair(&a["secret"]);
    let sig = signature(a);
    let mut msg = message(a, &kp.public);
    assert!(verify_state(&sig, &kp.public, &msg));
    msg.anchor = f(&b["anchor"]);
    assert!(!verify_state(&sig, &kp.public, &msg));
    msg = message(a, &kp.public);
    msg.commitment = pt(&b["commitment"]);
    assert!(!verify_state(&sig, &kp.public, &msg));
    // Another vault key does not verify it either, whether or not the message names that key.
    let other = keypair(&b["secret"]);
    assert!(!verify_state(&sig, &other.public, &message(a, &kp.public)));
    assert!(!verify_state(&sig, &other.public, &message(a, &other.public)));
    // A key other than the one the message names is refused even over its own signature.
    let theirs = sign_state(&other, &message(a, &kp.public));
    assert!(!verify_state(&theirs, &other.public, &message(a, &kp.public)));
}

#[test]
fn a_mainnet_signed_state_is_refused() {
    let v = vectors();
    let e = &v["stateSignatures"]["mainnetState"];
    assert_eq!(s(&e["networkId"]), "mainnet");
    let kp = keypair(&e["secret"]);
    let msg = message(e, &kp.public);
    check_message(e, &msg);
    let sig = signature(e);
    // Valid under the mainnet ID, which is what makes the refusal under devnet meaningful.
    assert!(verify_state_on(NetworkId::MAINNET, &sig, &kp.public, &msg));
    assert!(!verify_state(&sig, &kp.public, &msg));
}
