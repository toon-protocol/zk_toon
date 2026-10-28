//! Rust obtains each vault transaction from the o1js transaction builder, and the vault on the
//! builder's local chain accepts it. Proofs are off: the vault's logic runs, no circuit is proven.
mod common;

use common::*;
use zk_note::clearance::{sign_clearance, ClearanceMessage};
use zk_note::policy::DEPOSIT_SIZES;
use zk_note::withdrawal::WithdrawalKind;
use zk_note::{commit_secret, Field};
use zk_toon_tx_builder::{Deposit, Error, Escape, FailureKind, MutualClose};

const SMALL: u64 = DEPOSIT_SIZES[0];
const MINA: u64 = 1_000_000_000;

#[test]
fn a_deposit_is_accepted_and_becomes_a_note_at_the_reduce() {
    let mut b = local_builder(false);
    let chain = Chain::new(&mut b);
    let before = chain.vault_state(&mut b);

    let deposit_time = b.local().now().unwrap();
    let tx = b
        .deposit(&Deposit {
            vault: chain.vault.clone(),
            fee_payer: chain.payer.clone(),
            commitment: commit_secret(Field::from(1001u64)),
            size: SMALL,
            deposit_time,
        })
        .unwrap();
    let vault_balance = b.local().balance(&chain.vault).unwrap();
    b.local().submit(&tx).unwrap();
    assert_eq!(b.local().balance(&chain.vault).unwrap(), vault_balance + SMALL);

    b.local().reduce(&chain.vault).unwrap();
    let after = chain.vault_state(&mut b);
    assert_eq!(after["nextLeafIndex"], "1");
    assert_ne!(after["noteRoot"], before["noteRoot"]);
}

#[test]
fn a_mutual_close_is_accepted_and_pays_at_the_reduce() {
    let mut b = local_builder(false);
    let chain = Chain::new(&mut b);
    let note = deposit_note(&mut b, &chain, 2002, SMALL);
    let balance = 3 * MINA;
    let (state, n) = signed_state(&chain, &note, balance, 77);
    // The zk edge clears this state's nullifier to alice, signed in Rust.
    let state_key = chain.state_key.public.into_compressed();
    let clearance = sign_clearance(&chain.state_key, &ClearanceMessage::new(&state_key, n, &chain.alice));

    let request_time = b.local().now().unwrap();
    let tx = b
        .mutual_close(&MutualClose {
            vault: chain.vault.clone(),
            fee_payer: chain.payer.clone(),
            note,
            state,
            request_time,
            destination: chain.alice.clone(),
            clearance,
        })
        .unwrap();
    let public = tx.withdrawal.clone().unwrap();
    assert_eq!((public.kind, public.nullifier, public.amount, public.size), (WithdrawalKind::MutualClose, n, balance, SMALL));
    assert_eq!(public.destination, chain.alice);

    let alice = b.local().balance(&chain.alice).unwrap();
    let treasury = b.local().balance(&chain.treasury).unwrap();
    b.local().submit(&tx).unwrap();
    b.local().reduce(&chain.vault).unwrap();
    assert_eq!(b.local().balance(&chain.alice).unwrap(), alice + balance);
    assert_eq!(b.local().balance(&chain.treasury).unwrap(), treasury + SMALL - balance);
}

#[test]
fn an_escape_is_accepted_and_spends_both_nullifiers_at_the_reduce() {
    let mut b = local_builder(false);
    let chain = Chain::new(&mut b);
    let note = deposit_note(&mut b, &chain, 3003, SMALL);
    let (state, n) = signed_state(&chain, &note, 3 * MINA, 88);
    let request_time = b.local().now().unwrap();
    let escape = Escape {
        vault: chain.vault.clone(),
        fee_payer: chain.payer.clone(),
        note: note.clone(),
        state,
        request_time,
        destination: chain.alice.clone(),
        conceded: MINA / 10,
        valid_until: request_time + 10 * 60_000,
    };

    let tx = b.escape(&escape).unwrap();
    let public = tx.withdrawal.clone().unwrap();
    assert_eq!((public.kind, public.nullifier, public.conceded), (WithdrawalKind::Escape, n, MINA / 10));
    assert_eq!(public.next_nullifier, public.escape_next_nullifier(note.secret));

    let before = chain.vault_state(&mut b);
    b.local().submit(&tx).unwrap();
    b.local().reduce(&chain.vault).unwrap();
    let after = chain.vault_state(&mut b);
    assert_ne!(after["pendingEscapesRoot"], before["pendingEscapesRoot"]);
    assert_ne!(after["nullifierRoot"], before["nullifierRoot"]);

    // The escaped state is spent: the vault refuses to build a second escape of it.
    match b.escape(&escape) {
        Err(Error::Failure { kind: FailureKind::ProvingFailed, message }) => assert!(message.contains("nullifier spent"), "{message}"),
        other => panic!("expected a proving failure, got {other:?}"),
    }
}
