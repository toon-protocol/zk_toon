//! Rust obtains each vault transaction from the o1js transaction builder, and the vault on the
//! builder's local chain accepts it. Proofs are off: the vault's logic runs, no circuit is proven.
mod common;

use common::*;
use zk_note::clearance::{sign_clearance, ClearanceMessage};
use zk_note::balance::Scalar;
use zk_note::policy::{DEPOSIT_SIZES, REQUEST_MAX_AGE_SLOTS, TIERS};
use zk_note::withdrawal::{KIND_ESCAPE, KIND_MUTUAL_CLOSE};
use zk_note::{commit_secret, Field};
use zk_toon_tx_builder::{
    Defeat, Deposit, Error, Escape, FailureKind, MutualClose, Note, NoteState, Raise, RequestProof, RequestProofInput,
    TxBuilder,
};

const SMALL: u64 = DEPOSIT_SIZES[0];
const MINA: u64 = 1_000_000_000;

#[test]
fn a_deposit_is_accepted_and_becomes_a_note_at_the_reduce() {
    let mut b = local_builder(false);
    let chain = Chain::new(&mut b);
    let before = chain.vault_state(&mut b);

    let deposit_time = b.local().slot().unwrap();
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

    let request_time = b.local().slot().unwrap();
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
    assert_eq!((public.kind, public.nullifier, public.amount, public.size), (KIND_MUTUAL_CLOSE, n, balance, SMALL));
    assert_eq!((public.destination_x, public.destination_is_odd), (chain.alice.x, chain.alice.is_odd));

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
    let request_time = b.local().slot().unwrap();
    let escape = Escape {
        vault: chain.vault.clone(),
        fee_payer: chain.payer.clone(),
        note: note.clone(),
        state,
        request_time,
        destination: chain.alice.clone(),
        conceded: MINA / 10,
        valid_until: request_time + REQUEST_MAX_AGE_SLOTS,
    };

    let tx = b.escape(&escape).unwrap();
    let public = tx.withdrawal.clone().unwrap();
    assert_eq!((public.kind, public.nullifier, public.conceded), (KIND_ESCAPE, n, MINA / 10));
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

/// `note` escaped from `state` and the escape recorded by a reduce, conceding `conceded`.
fn recorded_escape(b: &mut TxBuilder, chain: &Chain, note: &Note, state: NoteState, conceded: u64) {
    let request_time = b.local().slot().unwrap();
    let tx = b
        .escape(&Escape {
            vault: chain.vault.clone(),
            fee_payer: chain.payer.clone(),
            note: note.clone(),
            state,
            request_time,
            destination: chain.alice.clone(),
            conceded,
            valid_until: request_time + REQUEST_MAX_AGE_SLOTS,
        })
        .unwrap();
    b.local().submit(&tx).unwrap();
    b.local().reduce(&chain.vault).unwrap();
}

/// A request proof of tier `tier` at `state`, as the zk edge records it for an allowance.
fn request_at(b: &mut TxBuilder, chain: &Chain, note: &Note, state: NoteState, tier: u64) -> RequestProof {
    let request_time = b.local().slot().unwrap();
    b.request_proof(&RequestProofInput {
        vault: chain.vault.clone(),
        note: note.clone(),
        state,
        request_time,
        tier,
        rerandom_blinding: Scalar::from(31u64),
        session_key: keypair(777).public.into_compressed(),
        request_expiry: request_time + 60_000,
    })
    .unwrap()
}

#[test]
fn a_defeat_is_accepted_and_cancels_the_escape_at_the_reduce() {
    let mut b = local_builder(false);
    let chain = Chain::new(&mut b);
    let note = deposit_note(&mut b, &chain, 4004, SMALL);
    let (state, n) = genesis(&note, 5);
    recorded_escape(&mut b, &chain, &note, state, 0);
    // The note's successor opened an allowance: a request proof at the escape's next nullifier.
    let (successor, next) = signed_state(&chain, &note, 3 * MINA, 6);
    let evidence = request_at(&mut b, &chain, &note, successor, TIERS[2]);
    assert_eq!(evidence.public.nullifier, next);

    let defeat = Defeat { vault: chain.vault.clone(), fee_payer: chain.payer.clone(), escape: n, evidence: evidence.proof };
    let tx = b.defeat(&defeat).unwrap();
    assert!(!tx.hash.is_empty());
    let before = chain.vault_state(&mut b);
    b.local().submit(&tx.transaction).unwrap();
    b.local().reduce(&chain.vault).unwrap();
    assert_ne!(chain.vault_state(&mut b)["pendingEscapesRoot"], before["pendingEscapesRoot"]);

    // The escape is no longer pending, so nothing can be built against it.
    match b.defeat(&defeat) {
        Err(Error::Failure { kind: FailureKind::BadInput, message }) => assert!(message.contains("no pending escape"), "{message}"),
        other => panic!("expected a bad input, got {other:?}"),
    }
}

#[test]
fn a_raise_is_accepted_and_lifts_the_concession_at_the_reduce() {
    let mut b = local_builder(false);
    let chain = Chain::new(&mut b);
    let note = deposit_note(&mut b, &chain, 5005, SMALL);
    let (state, n) = signed_state(&chain, &note, 3 * MINA, 7);
    recorded_escape(&mut b, &chain, &note, state.clone(), MINA / 100);
    let evidence = request_at(&mut b, &chain, &note, state, TIERS[2]);
    assert_eq!(evidence.public.nullifier, n);

    let raise = Raise { vault: chain.vault.clone(), fee_payer: chain.payer.clone(), escape: n, evidence: evidence.proof, claimed: MINA / 2 };
    let tx = b.raise(&raise).unwrap();
    b.local().submit(&tx.transaction).unwrap();
    b.local().reduce(&chain.vault).unwrap();

    // The concession now stands at the claim: the same raise again would not increase it.
    match b.raise(&raise) {
        Err(Error::Failure { kind: FailureKind::ProvingFailed, message }) => {
            assert!(message.contains("would not increase the concession"), "{message}")
        }
        other => panic!("expected a proving failure, got {other:?}"),
    }
}
