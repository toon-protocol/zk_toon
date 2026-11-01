//! The builder's failure answers, and that a note's secrets never leave it: not in an answer, and
//! not on its stderr.
mod common;

use std::fs::File;
use std::process::Stdio;

use common::*;
use zk_note::balance::Scalar;
use zk_note::policy::{DEPOSIT_SIZES, TIERS};
use zk_note::Field;
use zk_toon_tx_builder::{node_command, Error, FailureKind, Note, RequestProofInput, TxBuilder};

fn kind_of<T: std::fmt::Debug>(r: Result<T, Error>) -> (FailureKind, String) {
    match r {
        Err(Error::Failure { kind, message }) => (kind, message),
        other => panic!("expected a failure answer, got {other:?}"),
    }
}

#[test]
fn malformed_requests_are_bad_input() {
    let mut b = local_builder(false);
    assert_eq!(kind_of(b.call_raw("not json")).0, FailureKind::BadInput);
    assert_eq!(kind_of(b.call("noSuchOp", serde_json::json!({}))).0, FailureKind::BadInput);
    let (kind, message) = kind_of(b.call("deposit", serde_json::json!({ "vault": "B62notakey" })));
    assert_eq!(kind, FailureKind::BadInput);
    assert!(message.contains("feePayer"), "{message}");
    // The builder still answers after a bad request.
    assert!(b.local().slot().is_ok());
}

#[test]
fn a_refused_proof_is_a_proving_failure_and_no_secret_leaves_the_builder() {
    // The builder's stderr goes to a file this test reads back.
    let log = std::env::temp_dir().join(format!("tx-builder-stderr-{}.log", std::process::id()));
    let mut cmd = node_command(&o1js_dir(), &["--local", "--proofs=off"]);
    cmd.stderr(Stdio::from(File::create(&log).unwrap()));
    let mut b = TxBuilder::spawn(cmd).unwrap();
    let chain = Chain::new(&mut b);

    let secret = 918_273_645_546_372_819u64;
    let blinding = 192_837_465_564_738_291u64;
    let rerandom = 564_738_291_918_273_645u64;
    let note = deposit_note(&mut b, &chain, secret, DEPOSIT_SIZES[0]);
    let (state, _) = signed_state(&chain, &note, TIERS[0], blinding);
    let request_time = b.local().slot().unwrap();
    let mut input = RequestProofInput {
        vault: chain.vault.clone(),
        note: note.clone(),
        state,
        request_time,
        // The balance is the smallest tier, so it can't cover the largest.
        tier: TIERS[2],
        rerandom_blinding: Scalar::from(rerandom),
        session_key: keypair(5).public.into_compressed(),
        request_expiry: request_time + 60_000,
    };
    let mut messages = vec![];

    let (kind, message) = kind_of(b.request_proof(&input));
    assert_eq!(kind, FailureKind::ProvingFailed);
    messages.push(message);

    // A note the vault doesn't hold is bad input.
    input.note = Note { secret: Field::from(secret + 1), ..note };
    let (kind, message) = kind_of(b.request_proof(&input));
    assert_eq!(kind, FailureKind::BadInput);
    messages.push(message);

    drop(b);
    let stderr = std::fs::read_to_string(&log).unwrap();
    std::fs::remove_file(&log).unwrap();
    for secret in [secret, secret + 1, blinding, rerandom] {
        let s = secret.to_string();
        assert!(!stderr.contains(&s), "stderr holds a secret");
        assert!(messages.iter().all(|m| !m.contains(&s)), "an answer holds a secret");
    }
    // The debug form of a request hides its secrets too.
    let debug = format!("{input:?}");
    for secret in [secret + 1, blinding, rerandom] {
        assert!(!debug.contains(&secret.to_string()), "{debug}");
    }
}
