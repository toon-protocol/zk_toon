//! Reproduces every entry of the shared vector file `test-vectors/zk-note.json`.
use serde_json::Value;
use std::str::FromStr;
use zk_note::{policy, *};

fn vectors() -> Value {
    serde_json::from_str(VECTORS_JSON).unwrap()
}

#[test]
fn exported_vectors_are_the_file() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../test-vectors/zk-note.json");
    assert_eq!(VECTORS_JSON, std::fs::read_to_string(path).unwrap());
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or_else(|| panic!("not a string: {v}"))
}
fn f(v: &Value) -> Field {
    Field::from_str(s(v)).unwrap_or_else(|_| panic!("bad field {v}"))
}
fn u(v: &Value) -> u64 {
    s(v).parse().unwrap()
}
fn eq(actual: Field, expected: &Value) {
    assert_eq!(field_to_string(actual), s(expected));
}

#[test]
fn tags_match() {
    let v = vectors();
    for (_, t) in v["tags"].as_object().unwrap() {
        eq(tag_to_field(s(&t["text"])), &t["field"]);
    }
}

#[test]
fn poseidon_matches() {
    for e in vectors()["poseidon"].as_array().unwrap() {
        let inputs: Vec<Field> = e["inputs"].as_array().unwrap().iter().map(f).collect();
        eq(poseidon(&inputs), &e["output"]);
    }
}

#[test]
fn same_inputs_under_different_tags_differ() {
    let v = vectors();
    let d = &v["domainSeparation"];
    let inputs: Vec<Field> = d["inputs"].as_array().unwrap().iter().map(f).collect();
    let outs = d["outputs"].as_object().unwrap();
    for (tag, out) in outs {
        eq(hash_with_tag(tag, &inputs), out);
    }
    let mut distinct: Vec<_> = outs.values().map(|o| s(o).to_string()).collect();
    distinct.sort();
    distinct.dedup();
    assert_eq!(distinct.len(), outs.len());
    assert_eq!(outs.len(), 7);
}

#[test]
fn commitments_match() {
    for e in vectors()["commitment"].as_array().unwrap() {
        eq(commit_secret(f(&e["secret"])), &e["commitment"]);
    }
}

#[test]
fn leaves_match() {
    for e in vectors()["leaves"].as_array().unwrap() {
        assert_eq!(policy::expiry_of(u(&e["depositTime"])), u(&e["expiry"]));
        eq(
            leaf(u(&e["index"]), f(&e["commitment"]), u(&e["size"]), u(&e["depositTime"]), u(&e["expiry"])),
            &e["leaf"],
        );
    }
}

#[test]
fn nullifier_chain_matches() {
    let v = vectors();
    let n = &v["nullifiers"];
    let secret = f(&n["secret"]);
    let genesis = genesis_anchor(commit_secret(secret));
    eq(genesis, &n["genesisAnchor"]);
    let mut anchor = genesis;
    for (i, step) in n["chain"].as_array().unwrap().iter().enumerate() {
        eq(anchor, &step["anchor"]);
        let nul = nullifier(secret, anchor);
        eq(nul, &step["nullifier"]);
        anchor = next_anchor(nul);
        eq(anchor, &n["nextAnchors"][i]);
    }
    let other = Field::from(987654321u64);
    eq(nullifier(other, f(&n["chain"][0]["anchor"])), &n["otherSecretNullifier"]);
}

#[test]
fn auth_tags_match() {
    for e in vectors()["authTags"].as_array().unwrap() {
        let c = &e["context"];
        let ctx = RequestContext {
            edge: f(&c["edge"]),
            session_key_x: f(&c["sessionKeyX"]),
            session_key_is_odd: match s(&c["sessionKeyIsOdd"]) {
                "0" => false,
                "1" => true,
                other => panic!("sessionKeyIsOdd must be 0 or 1, got {other}"),
            },
            tier: u(&c["tier"]),
            expiry: u(&c["expiry"]),
        };
        eq(auth_tag(f(&e["nullifier"]), &ctx), &e["tag"]);
    }
}

#[test]
fn edges_are_vault_key_x_coordinates() {
    let v = vectors();
    let vault_xs: Vec<&str> =
        v["stateSignatures"]["cases"].as_array().unwrap().iter().map(|c| s(&c["vault"]["x"])).collect();
    let tag_edges: Vec<&str> = v["authTags"].as_array().unwrap().iter().map(|e| s(&e["context"]["edge"])).collect();
    assert!(tag_edges.iter().all(|e| vault_xs.contains(e)), "every auth tag's edge is a vault key's x");
    assert!(tag_edges.iter().any(|e| *e != tag_edges[0]), "auth tags cover another edge");
    for r in v["requestProofs"].as_array().unwrap() {
        assert_eq!(s(&r["private"]["context"]["edge"]), s(&r["public"]["vault"]["x"]));
    }
}

#[test]
fn period_nullifiers_match() {
    for e in vectors()["periodNullifiers"].as_array().unwrap() {
        eq(period_nullifier(f(&e["secret"]), u(&e["index"]), u(&e["period"])), &e["periodNullifier"]);
    }
}

#[test]
fn period_nullifiers_need_the_secret() {
    let v = vectors();
    let find = |secret: &str, index: &str, period: &str| {
        v["periodNullifiers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| s(&e["secret"]) == secret && s(&e["index"]) == index && s(&e["period"]) == period)
            .map(|e| s(&e["periodNullifier"]).to_string())
            .unwrap()
    };
    let secret = s(&v["nullifiers"]["secret"]);
    let other = v["periodNullifiers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| s(&e["secret"]))
        .find(|x| *x != secret)
        .unwrap();
    // Same note index and period, another secret: another per-period nullifier.
    assert_ne!(find(secret, "7", "1"), find(other, "7", "1"));
    // One note, different periods: all different.
    let per: Vec<_> = ["0", "1", "2"].iter().map(|p| find(secret, "7", p)).collect();
    assert!(per[0] != per[1] && per[1] != per[2] && per[0] != per[2]);
}

#[test]
fn membership_agrees() {
    let v = vectors();
    let entries = v["membership"].as_array().unwrap();
    assert!(!entries.is_empty());
    for e in entries {
        let amount = u(&e["amount"]);
        assert_eq!(policy::is_tier(amount), e["isTier"].as_bool().unwrap(), "isTier {amount}");
        assert_eq!(policy::is_deposit_size(amount), e["isDepositSize"].as_bool().unwrap(), "isDepositSize {amount}");
        assert_eq!(policy::is_smallest_tier(amount), e["isSmallestTier"].as_bool().unwrap(), "isSmallestTier {amount}");
    }
}

#[test]
fn periods_agree_at_week_boundaries() {
    for e in vectors()["periods"].as_array().unwrap() {
        let expected = e["period"].as_str().map(|p| p.parse::<u64>().unwrap());
        assert_eq!(policy::subsidy_period(u(&e["vaultCreation"]), u(&e["now"])), expected);
    }
}

#[test]
fn note_age_agrees() {
    for e in vectors()["ages"].as_array().unwrap() {
        let now = s(&e["now"]).parse::<i128>().unwrap();
        let ok = now >= 0 && policy::is_old_enough_for_subsidy(u(&e["depositTime"]), now as u64);
        assert_eq!(ok, e["oldEnough"].as_bool().unwrap());
    }
}

#[test]
fn request_times_agree() {
    let entries = vectors()["requestTimes"].as_array().unwrap().clone();
    assert!(entries.iter().any(|e| e["fresh"].as_bool().unwrap()));
    assert!(entries.iter().any(|e| !e["fresh"].as_bool().unwrap()));
    for e in entries {
        let (request_time, now) = (u(&e["requestTime"]), u(&e["now"]));
        assert_eq!(policy::is_request_time_fresh(request_time, now), e["fresh"].as_bool().unwrap(), "{e}");
    }
}

#[test]
fn policy_constants_match() {
    let v = vectors();
    let p = &v["policy"];
    assert_eq!(policy::NOTE_LIFETIME_MS, u(&p["noteLifetimeMs"]));
    assert_eq!(policy::MIN_SUBSIDY_AGE_MS, u(&p["minSubsidyAgeMs"]));
    assert_eq!(policy::SUBSIDY_PERIOD_MS, u(&p["subsidyPeriodMs"]));
    assert_eq!(policy::CHALLENGE_WINDOW_MS, u(&p["challengeWindowMs"]));
    assert_eq!(policy::REQUEST_MAX_AGE_MS, u(&p["requestMaxAgeMs"]));
    assert_eq!(policy::REQUEST_MAX_LEAD_MS, u(&p["requestMaxLeadMs"]));
    let tiers: Vec<u64> = p["tiers"].as_array().unwrap().iter().map(u).collect();
    assert_eq!(tiers, policy::TIERS);
    let sizes: Vec<u64> = p["depositSizes"].as_array().unwrap().iter().map(u).collect();
    assert_eq!(sizes, policy::DEPOSIT_SIZES);
}
