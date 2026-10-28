//! The request proof's sample entries in `test-vectors/zk-note.json`: recomputes the public nullifier,
//! authorization tag and re-randomised commitment from the entry's private values.
use ark_ec::AffineRepr;
use mina_curves::pasta::Pallas;
use serde_json::Value;
use std::str::FromStr;
use zk_note::balance::{commit, rerandomise, Scalar};
use zk_note::{
    auth_tag, commit_secret, field_to_string, genesis_anchor, next_anchor, nullifier, policy, Field,
    RequestContext,
};

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
fn same(actual: Pallas, expected: &Value) {
    let (x, y) = actual.xy().unwrap();
    assert_eq!((field_to_string(x), field_to_string(y)), (s(&expected["x"]).into(), s(&expected["y"]).into()));
}

#[test]
fn request_proof_samples_are_recomputed() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../test-vectors/zk-note.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let entries = v["requestProofs"].as_array().unwrap();
    assert!(!entries.is_empty());
    println!("vector cases run: {}", entries.len());
    let (mut genesis_seen, mut signed_seen) = (false, false);
    for e in entries {
        let (p, w) = (&e["public"], &e["private"]);
        let secret = f(&w["secret"]);
        let c = &w["context"];

        // The note's expiry follows from its deposit time, and the request comes before it.
        let (deposit_time, expiry) = (u(&w["depositTime"]), u(&w["expiry"]));
        assert_eq!(policy::expiry_of(deposit_time), expiry);
        assert!(u(&p["requestTime"]) < expiry);

        // The state: genesis, or the next state of a previous nullifier derived from this secret.
        let anchor = f(&w["anchor"]);
        if w["isGenesis"].as_bool().unwrap() {
            genesis_seen = true;
            assert_eq!(anchor, genesis_anchor(commit_secret(secret)));
            assert_eq!(u(&w["balance"]), u(&w["size"]));
        } else {
            signed_seen = true;
            let prev = f(&w["prevNullifier"]);
            assert_eq!(prev, nullifier(secret, f(&w["prevAnchor"])));
            assert_eq!(anchor, next_anchor(prev));
        }
        assert!(u(&w["balance"]) >= u(&p["tier"]));

        let n = nullifier(secret, anchor);
        assert_eq!(field_to_string(n), s(&p["nullifier"]));

        let ctx = RequestContext {
            edge: f(&c["edge"]),
            session_key_x: f(&c["sessionKeyX"]),
            session_key_is_odd: s(&c["sessionKeyIsOdd"]) == "1",
            tier: u(&c["tier"]),
            expiry: u(&c["expiry"]),
        };
        assert_eq!(ctx.tier, u(&p["tier"]));
        assert_eq!(field_to_string(auth_tag(n, &ctx)), s(&p["tag"]));

        let state = commit(Scalar::from(u(&w["balance"])), sc(&w["blinding"]));
        same(state, &w["stateCommitment"]);
        same(rerandomise(state, sc(&w["rerandomBlinding"])), &p["commitment"]);

        assert!(!p["subsidised"].as_bool().unwrap());
        assert_eq!((s(&p["period"]), s(&p["periodNullifier"])), ("0", "0"));
    }
    assert!(genesis_seen && signed_seen);
}
