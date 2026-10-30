//! A submitted defeat or raise is waited on until its outcome is known. A dropped connection or a
//! failed poll never ends the wait.
mod common;

use common::*;
use zk_toon_challenger::{Escape, PortError, VaultChainPort};

fn open_escape() -> Escape {
    let mut id = [3u8; 32];
    id[31] = 0;
    let mut next = [4u8; 32];
    next[31] = 0;
    Escape { id, next_nullifier: next, conceded: 5, balance: 50, deadline: 1_000_000 }
}

#[test]
fn failed_polls_do_not_end_the_wait_for_a_defeat() {
    let e = open_escape();
    let chain = Scripted::new(10, &[e.clone()]);
    chain.0.borrow_mut().failing_polls = 5;
    chain.0.borrow_mut().pooled_polls = 3;
    let mut port = adapter(&chain);

    port.submit_defeat(&e.id).unwrap();
    assert!(chain.0.borrow().status_reads >= 9, "the outcome was read until it was known");
    assert!(port.escapes().unwrap().is_empty());
}

#[test]
fn a_send_whose_answer_was_lost_is_waited_on_not_dropped() {
    let e = open_escape();
    let chain = Scripted::new(10, &[e.clone()]);
    chain.0.borrow_mut().drop_send_answer = true;
    chain.0.borrow_mut().failing_polls = 2;
    let mut port = adapter(&chain);

    port.submit_raise(&e.id, 20).unwrap();
    assert_eq!(port.escapes().unwrap()[0].conceded, 20);
    // Sent once: the transaction had reached the chain, so it was not sent again.
    assert_eq!(chain.0.borrow().sent, 1);
}

#[test]
fn a_transaction_that_lands_failed_is_refused_with_its_reason() {
    let e = open_escape();
    let chain = Scripted::new(10, &[e.clone()]);
    chain.0.borrow_mut().fail_with = Some("Account_app_state_precondition_unsatisfied".into());
    let mut port = adapter(&chain);

    match port.submit_defeat(&e.id) {
        Err(PortError::Refused(why)) => assert!(why.contains("Account_app_state_precondition_unsatisfied"), "{why}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert_eq!(port.escapes().unwrap(), vec![e]);
}

#[test]
fn a_lost_transaction_is_sent_again_until_the_deadline_then_refused() {
    let e = open_escape();
    let chain = Scripted::new(10, &[e.clone()]);
    chain.0.borrow_mut().lose_sends = true;
    chain.0.borrow_mut().advance_per_read = 100_000;
    let mut port = adapter(&chain);

    match port.submit_defeat(&e.id) {
        Err(PortError::Refused(why)) => assert!(why.contains("deadline"), "{why}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert!(chain.0.borrow().sent > 1, "a lost transaction is sent again while it can still land");
}

#[test]
fn a_dropped_connection_while_reading_escapes_is_unavailable_not_empty() {
    struct Down;
    impl zk_toon_challenger_mina::Graphql for Down {
        fn post(&self, _: zk_toon_challenger_mina::Endpoint, _: &serde_json::Value) -> Result<serde_json::Value, String> {
            Err("connection reset by peer".into())
        }
    }
    let settings = zk_toon_challenger_mina::Settings { vault: vault_key(), fee_payer: fee_payer(), poll: std::time::Duration::ZERO };
    let port = zk_toon_challenger_mina::MinaChain::new(settings, Down, Scripted::default(), AnyProof).unwrap();
    assert!(matches!(port.escapes(), Err(PortError::Unavailable(_))));
}
