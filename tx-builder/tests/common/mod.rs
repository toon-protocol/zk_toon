#![allow(dead_code)]
use std::path::PathBuf;

use mina_curves::pasta::Fq;
use mina_signer::{CompressedPubKey, Keypair, SecKey};
use serde_json::Value;
use zk_note::balance::{commit, Scalar};
use zk_note::state::{sign_state, StateMessage};
use zk_note::{commit_secret, genesis_anchor, next_anchor, nullifier, Field};
use zk_toon_tx_builder::{node_command, Deposit, FeePayer, Note, NoteState, SignedState, TxBuilder};

pub fn o1js_dir() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../o1js"))
}

/// A builder hosting its own local chain.
pub fn local_builder(proofs: bool) -> TxBuilder {
    let proofs = if proofs { "--proofs=on" } else { "--proofs=off" };
    TxBuilder::spawn(node_command(&o1js_dir(), &["--local", proofs])).expect("start the transaction builder")
}

pub fn keypair(secret: u64) -> Keypair {
    Keypair::try_from(SecKey::new(Fq::from(secret))).unwrap()
}

/// A vault deployed on the builder's local chain, with the zk edge's state key and the local accounts.
pub struct Chain {
    pub vault: CompressedPubKey,
    pub state_key: Keypair,
    pub payer: FeePayer,
    pub alice: CompressedPubKey,
    pub treasury: CompressedPubKey,
}

impl Chain {
    pub fn new(b: &mut TxBuilder) -> Self {
        let accounts = b.local().accounts().unwrap();
        let state_key = keypair(4242);
        let treasury = accounts[2].public_key.clone();
        let vault = b.local().deploy_vault(&state_key.public.into_compressed(), &treasury).unwrap();
        Chain {
            vault,
            state_key,
            payer: FeePayer { private_key: accounts[0].private_key.clone(), fee: 0 },
            alice: accounts[1].public_key.clone(),
            treasury,
        }
    }

    pub fn vault_state(&self, b: &mut TxBuilder) -> Value {
        b.local().vault_state(&self.vault).unwrap()
    }
}

/// A reduced note of `size`, deposited now from the chain's payer.
pub fn deposit_note(b: &mut TxBuilder, chain: &Chain, secret: u64, size: u64) -> Note {
    let deposit_time = b.local().slot().unwrap();
    let note = Note { secret: Field::from(secret), size, deposit_time };
    let tx = b
        .deposit(&Deposit {
            vault: chain.vault.clone(),
            fee_payer: chain.payer.clone(),
            commitment: commit_secret(note.secret),
            size,
            deposit_time,
        })
        .unwrap();
    b.local().submit(&tx).unwrap();
    b.local().reduce(&chain.vault).unwrap();
    note
}

/// The note's genesis state, and its nullifier.
pub fn genesis(note: &Note, blinding: u64) -> (NoteState, Field) {
    let state = NoteState { blinding: Scalar::from(blinding), signed: None };
    (state, nullifier(note.secret, genesis_anchor(commit_secret(note.secret))))
}

/// The note's second state, which the zk edge signed with `balance`, and its nullifier.
pub fn signed_state(chain: &Chain, note: &Note, balance: u64, blinding: u64) -> (NoteState, Field) {
    let prev_anchor = genesis_anchor(commit_secret(note.secret));
    let anchor = next_anchor(nullifier(note.secret, prev_anchor));
    let blinding = Scalar::from(blinding);
    let state_key = chain.state_key.public.into_compressed();
    let msg = StateMessage::new(&state_key, commit(Scalar::from(balance), blinding), anchor);
    let signature = sign_state(&chain.state_key, &msg);
    let state = NoteState { blinding, signed: Some(SignedState { balance, prev_anchor, signature }) };
    (state, nullifier(note.secret, anchor))
}
