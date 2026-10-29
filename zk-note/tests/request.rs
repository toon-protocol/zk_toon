//! The request proof's sample entries in `test-vectors/zk-note.json`: recomputes the public nullifier,
//! authorization tag and re-randomised commitment from the entry's private values, and for a
//! subsidised entry its age, period and per-period nullifier.
use ark_ec::AffineRepr;
use mina_curves::pasta::Pallas;
use serde_json::Value;
use std::str::FromStr;
use zk_note::balance::{commit, rerandomise, Scalar};
use zk_note::request::{RequestPublic, SubsidyPeriodError};
use zk_note::{
    auth_tag, commit_secret, field_to_string, genesis_anchor, next_anchor, nullifier, period_nullifier, policy,
    Field, RequestContext,
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
    let mut subsidised_periods = std::collections::BTreeSet::new();
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

        if p["subsidised"].as_bool().unwrap() {
            // Smallest tier, a note at least 7 days old, the period of the request time counted from
            // the vault's creation, and the per-period nullifier of this note in that period.
            let request_time = u(&p["requestTime"]);
            let period = policy::subsidy_period(u(&w["vaultCreation"]), request_time).unwrap();
            assert!(policy::is_smallest_tier(u(&p["tier"])));
            assert!(policy::is_old_enough_for_subsidy(deposit_time, request_time));
            assert_eq!(u(&p["period"]), period);
            let pn = period_nullifier(secret, u(&w["index"]), period);
            assert_eq!(field_to_string(pn), s(&p["periodNullifier"]));
            subsidised_periods.insert(period);
        } else {
            assert_eq!((s(&p["period"]), s(&p["periodNullifier"])), ("0", "0"));
            assert!(w.get("vaultCreation").is_none());
        }
    }
    assert!(genesis_seen && signed_seen);
    assert!(subsidised_periods.len() >= 2, "subsidised samples in two periods");
}

#[test]
fn public_input_array_decodes_to_the_structured_public_values() {
    use zk_note::request::RequestPublicError;
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../test-vectors/zk-note.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let entries = v["requestProofs"].as_array().unwrap();
    assert!(!entries.is_empty());
    println!("vector cases run: {}", entries.len());
    for e in entries {
        let flat: Vec<Field> = e["publicInput"].as_array().unwrap().iter().map(f).collect();
        let r = RequestPublic::from_fields(&flat).unwrap();
        let p = &e["public"];
        assert_eq!(r.vault_x, f(&p["vault"]["x"]));
        assert_eq!(r.vault_is_odd, s(&p["vault"]["isOdd"]) == "1");
        assert_eq!(r.root, f(&p["root"]));
        assert_eq!(r.request_time, u(&p["requestTime"]));
        assert_eq!(r.tier, u(&p["tier"]));
        assert_eq!(r.nullifier, f(&p["nullifier"]));
        assert_eq!(r.tag, f(&p["tag"]));
        assert_eq!((r.commitment.x, r.commitment.y), (f(&p["commitment"]["x"]), f(&p["commitment"]["y"])));
        assert_eq!(r.subsidised, p["subsidised"].as_bool().unwrap());
        assert_eq!(r.period, u(&p["period"]));
        assert_eq!(r.period_nullifier, f(&p["periodNullifier"]));

        assert_eq!(RequestPublic::from_fields(&flat[1..]), Err(RequestPublicError::Length(11)));
        let mut bad = flat.clone();
        bad[9] = Field::from(2u64);
        assert_eq!(RequestPublic::from_fields(&bad), Err(RequestPublicError::NotBool("subsidised")));
        let mut bad = flat.clone();
        bad[4] = -Field::from(1u64);
        assert_eq!(RequestPublic::from_fields(&bad), Err(RequestPublicError::NotU64("tier")));
    }
}

/// The `subsidyPeriods` vector entries: (the vault's creation time, the creation time the proof was
/// made with, its public inputs, whether the period check passes it).
fn subsidy_periods() -> Vec<(u64, u64, RequestPublic, bool)> {
    let v: Value = serde_json::from_str(zk_note::VECTORS_JSON).unwrap();
    v["subsidyPeriods"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            let flat: Vec<Field> = e["publicInput"].as_array().unwrap().iter().map(f).collect();
            let public = RequestPublic::from_fields(&flat).unwrap();
            (u(&e["vaultCreation"]), u(&e["provenWith"]), public, e["passes"].as_bool().unwrap())
        })
        .collect()
}

#[test]
fn the_period_check_refuses_a_proof_made_with_a_forged_creation_time() {
    let cases = subsidy_periods();
    println!("vector cases run: {}", cases.len());
    let (creation, proven_with, honest, _) = &cases[0];
    assert_eq!(creation, proven_with);
    assert_eq!(honest.check_subsidy_period(*creation), Ok(()));
    for (creation, proven_with, forged, _) in &cases[1..] {
        assert!(proven_with < creation, "forged earlier than the vault's creation");
        assert_eq!(
            forged.check_subsidy_period(*creation),
            Err(SubsidyPeriodError::WrongPeriod { claimed: forged.period, expected: 2 })
        );
        // The proof is consistent with the creation time it was made with, which is all the circuit checks.
        assert_eq!(forged.check_subsidy_period(*proven_with), Ok(()));
    }
    // o1js agrees on every entry.
    for (creation, _, public, passes) in &cases {
        assert_eq!(public.check_subsidy_period(*creation).is_ok(), *passes);
    }
}

#[test]
fn two_claims_in_one_real_period_with_forged_creation_times_differ_but_at_most_one_passes() {
    let cases = subsidy_periods();
    let creation = cases[0].0;
    // Every claim is by one note, in the vault's real period 2.
    for (_, _, p, _) in &cases {
        assert_eq!(policy::subsidy_period(creation, p.request_time), Some(2));
        assert_eq!(p.nullifier, cases[0].2.nullifier);
    }
    let (a, b) = (&cases[1].2, &cases[2].2);
    assert_ne!(a.period_nullifier, b.period_nullifier);
    let passing: std::collections::BTreeSet<String> = cases
        .iter()
        .filter(|(c, _, p, _)| p.check_subsidy_period(*c).is_ok())
        .map(|(_, _, p, _)| field_to_string(p.period_nullifier))
        .collect();
    assert_eq!(passing.len(), 1, "one per-period nullifier gets through per real period");
}

#[test]
fn the_period_check_passes_an_unsubsidised_request_only_with_zero_subsidy_fields() {
    let v: Value = serde_json::from_str(zk_note::VECTORS_JSON).unwrap();
    let mut seen = 0;
    for e in v["requestProofs"].as_array().unwrap() {
        let flat: Vec<Field> = e["publicInput"].as_array().unwrap().iter().map(f).collect();
        let p = RequestPublic::from_fields(&flat).unwrap();
        if p.subsidised {
            continue;
        }
        seen += 1;
        assert_eq!(p.check_subsidy_period(0), Ok(()));
        let with_period = RequestPublic { period: 1, ..p };
        assert_eq!(with_period.check_subsidy_period(0), Err(SubsidyPeriodError::Unsubsidised));
        let with_nullifier = RequestPublic { period_nullifier: Field::from(1u64), ..p };
        assert_eq!(with_nullifier.check_subsidy_period(0), Err(SubsidyPeriodError::Unsubsidised));
    }
    assert!(seen > 0);
}

#[test]
fn the_period_check_refuses_a_request_before_the_vaults_creation() {
    let (_, _, p, _) = subsidy_periods().remove(0);
    assert_eq!(p.check_subsidy_period(p.request_time + 1), Err(SubsidyPeriodError::BeforeCreation));
}
