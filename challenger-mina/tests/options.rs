//! The challenger service's options: flags, and the fee payer's key from the environment only.
mod common;

use std::path::PathBuf;
use std::time::Duration;

use common::*;
use zk_toon_challenger_mina::service::{usage, Options, FLAGS};

fn args(extra: &[&str]) -> Vec<String> {
    let vault = fixture()["vault"].as_str().unwrap().to_string();
    let mut a: Vec<String> = [
        "--vault", &vault, "--mina", "http://mina/graphql", "--archive", "http://archive/graphql",
        "--evidence", "/var/zk/evidence", "--journal", "/var/zk/journal", "--o1js", "/opt/zk_toon/o1js",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    a.extend(extra.iter().map(|s| s.to_string()));
    a
}

fn key() -> Option<String> {
    Some(fee_payer().private_key)
}

#[test]
fn the_required_flags_and_the_defaults() {
    let o = Options::parse(&args(&[]), key()).unwrap();
    assert_eq!(o.settings.vault, vault_key());
    assert_eq!(o.settings.fee_payer.private_key, fee_payer().private_key);
    assert_eq!(o.settings.fee_payer.fee, 100_000_000);
    assert_eq!(o.settings.poll, Duration::from_secs(10));
    assert_eq!((o.endpoints.mina.as_str(), o.endpoints.archive.as_str()), ("http://mina/graphql", "http://archive/graphql"));
    assert_eq!(o.endpoints.socks5, None);
    assert_eq!(o.endpoints.timeout, Duration::from_secs(30));
    assert_eq!(o.evidence, PathBuf::from("/var/zk/evidence"));
    assert_eq!(o.journal, PathBuf::from("/var/zk/journal"));
    assert_eq!(o.o1js, PathBuf::from("/opt/zk_toon/o1js"));
    assert_eq!(o.config.min_lead, 40);
    assert_eq!(o.interval, Duration::from_secs(60));
}

#[test]
fn the_optional_flags() {
    let extra = [
        "--socks5", "127.0.0.1:9050", "--fee", "5", "--min-lead", "7", "--interval", "3", "--poll", "2", "--timeout", "9",
    ];
    let o = Options::parse(&args(&extra), key()).unwrap();
    assert_eq!(o.endpoints.socks5.as_deref(), Some("127.0.0.1:9050"));
    assert_eq!(o.settings.fee_payer.fee, 5);
    assert_eq!(o.config.min_lead, 7);
    assert_eq!(o.interval, Duration::from_secs(3));
    assert_eq!(o.settings.poll, Duration::from_secs(2));
    assert_eq!(o.endpoints.timeout, Duration::from_secs(9));
}

#[test]
fn the_builder_gets_fifteen_minutes_an_answer_unless_told_otherwise() {
    assert_eq!(Options::parse(&args(&[]), key()).unwrap().builder_timeout, Duration::from_secs(900));
    assert_eq!(Options::parse(&args(&["--builder-timeout", "5"]), key()).unwrap().builder_timeout, Duration::from_secs(5));
}

#[test]
fn every_flag_is_in_the_usage_and_the_docs() {
    let docs = include_str!("../../docs/challenger-mina.md");
    for flag in FLAGS {
        assert!(usage().contains(flag.name), "{} is missing from the usage", flag.name);
        assert!(docs.contains(&format!("`{}`", flag.name)), "{} is missing from docs/challenger-mina.md", flag.name);
    }
    assert!(Options::parse(&args(&["--nonsense", "1"]), key()).unwrap_err().contains(&usage()));
}

#[test]
fn bad_options_are_refused_by_name() {
    let refused = |a: Vec<String>, k: Option<String>| Options::parse(&a, k).unwrap_err();
    let without = |flag: &str| {
        let a = args(&[]);
        let at = a.iter().position(|s| s == flag).unwrap();
        a.iter().enumerate().filter(|(i, _)| *i != at && *i != at + 1).map(|(_, s)| s.clone()).collect()
    };
    for flag in ["--vault", "--mina", "--archive", "--evidence", "--journal", "--o1js"] {
        assert!(refused(without(flag), key()).contains(flag), "{flag}");
    }
    assert!(refused(args(&["--fee", "lots"]), key()).contains("--fee"));
    assert!(refused(args(&["--min-lead"]), key()).contains("--min-lead"));
    assert!(refused(args(&["--color", "red"]), key()).contains("--color"));
    let mut bad_vault = args(&[]);
    bad_vault[1] = "B62nope".into();
    assert!(refused(bad_vault, key()).contains("--vault"));
}

#[test]
fn the_fee_payers_key_comes_only_from_the_environment() {
    assert!(Options::parse(&args(&[]), None).unwrap_err().contains("ZK_TOON_FEE_PAYER_KEY"));
    assert!(Options::parse(&args(&[]), Some("not a key".into())).unwrap_err().contains("ZK_TOON_FEE_PAYER_KEY"));
    // No flag carries it, so it never shows in a process listing.
    let key = fee_payer().private_key;
    assert!(Options::parse(&args(&["--fee-payer-key", &key]), None).is_err());
    // And it never prints.
    let o = Options::parse(&args(&[]), Some(key.clone())).unwrap();
    assert!(!format!("{o:?}").contains(&key));
}
