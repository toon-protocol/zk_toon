//! Rust obtains a request proof for an allowance from the o1js transaction builder, and its public
//! inputs are what `zk-note` computes from the same note, state and request.
mod common;

use std::str::FromStr;

use common::*;
use zk_note::balance::{commit, rerandomise, Scalar};
use zk_note::policy::{DEPOSIT_SIZES, TIERS};
use zk_note::{auth_tag, Field, RequestContext};
use zk_toon_tx_builder::{NoteState, RequestProofInput, TxBuilder};

const MINA: u64 = 1_000_000_000;

/// Asks for a request proof of `state` and checks every public input against zk-note.
fn request_matches(b: &mut TxBuilder, chain: &Chain, note: &zk_toon_tx_builder::Note, state: NoteState, n: Field, balance: u64) {
    let session = keypair(777).public.into_compressed();
    let request_time = b.local().slot().unwrap();
    let input = RequestProofInput {
        vault: chain.vault.clone(),
        note: note.clone(),
        state: state.clone(),
        request_time,
        tier: TIERS[1],
        rerandom_blinding: Scalar::from(424_242u64),
        session_key: session.clone(),
        request_expiry: request_time + 60_000,
    };
    let proof = b.request_proof(&input).unwrap();
    let p = &proof.public;

    let state_key = chain.state_key.public.into_compressed();
    let root = Field::from_str(chain.vault_state(b)["noteRoot"].as_str().unwrap()).unwrap();
    let ctx = RequestContext {
        edge: state_key.x,
        session_key_x: session.x,
        session_key_is_odd: session.is_odd,
        tier: TIERS[1],
        expiry: input.request_expiry,
    };
    assert_eq!((p.vault_x, p.vault_is_odd), (state_key.x, state_key.is_odd));
    assert_eq!(p.root, root);
    assert_eq!((p.request_time, p.tier), (request_time, TIERS[1]));
    assert_eq!(p.nullifier, n);
    assert_eq!(p.tag, auth_tag(n, &ctx));
    let commitment = rerandomise(commit(Scalar::from(balance), state.blinding), input.rerandom_blinding);
    assert_eq!((p.commitment.x, p.commitment.y), (commitment.x, commitment.y));
    assert_eq!((p.subsidised, p.period, p.period_nullifier), (false, 0, Field::from(0u64)));
}

#[test]
fn a_request_proofs_public_inputs_are_what_zk_note_computes() {
    let mut b = local_builder(false);
    let chain = Chain::new(&mut b);

    let first = deposit_note(&mut b, &chain, 5005, DEPOSIT_SIZES[0]);
    let (state, n) = genesis(&first, 99);
    request_matches(&mut b, &chain, &first, state, n, DEPOSIT_SIZES[0]);

    let second = deposit_note(&mut b, &chain, 6006, DEPOSIT_SIZES[1]);
    let (state, n) = signed_state(&chain, &second, 40 * MINA, 1234);
    request_matches(&mut b, &chain, &second, state, n, 40 * MINA);
}

/// Proofs on: the builder proves for real, and the proof verifies against the request program's key.
/// The only slow test here: it compiles the request program.
#[test]
fn a_real_request_proof_verifies() {
    let mut b = local_builder(true);
    let chain = Chain::new(&mut b);
    let note = deposit_note(&mut b, &chain, 7007, DEPOSIT_SIZES[0]);
    let (state, n) = genesis(&note, 5);
    let request_time = b.local().slot().unwrap();
    let proof = b
        .request_proof(&RequestProofInput {
            vault: chain.vault.clone(),
            note,
            state,
            request_time,
            tier: TIERS[0],
            rerandom_blinding: Scalar::from(9u64),
            session_key: keypair(8).public.into_compressed(),
            request_expiry: request_time + 60_000,
        })
        .unwrap();
    assert_eq!(proof.public.nullifier, n);
    assert!(b.verify_request_proof(&proof, None).unwrap());
    // An unsubsidised proof's zero period passes the period check against the vault's creation time.
    let creation: u64 = chain.vault_state(&mut b)["creationTime"].as_str().unwrap().parse().unwrap();
    assert_eq!(proof.public.check_subsidy_period(creation), Ok(()));
    assert!(b.verify_request_proof(&proof, Some(creation)).unwrap());

    // The same proof claiming another nullifier does not verify.
    let mut forged = proof.clone();
    forged.proof["publicInput"][5] = serde_json::json!("1");
    assert!(!b.verify_request_proof(&forged, None).unwrap());
}
