//! A defeat and a raise submitted through the adapter are accepted by the vault on the transaction
//! builder's local chain (proofs off: the vault's logic runs, no circuit is proven). The adapter reads
//! the local chain through the builder's GraphQL stand-in, which answers in Mina's shapes.
//!
//! With `ZK_TOON_RECORD_VAULT=1` this test also rewrites `fixtures/recorded-vault.json` from what it
//! read; pin the new file's SHA-256 in `common/mod.rs`.
mod common;

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use common::keypair;
use mina_signer::{CompressedPubKey, Keypair};
use serde_json::{json, Value};
use zk_note::balance::{commit, Scalar};
use zk_note::policy::{DEPOSIT_SIZES, TIERS};
use zk_note::state::{sign_state, StateMessage};
use zk_note::{commit_secret, genesis_anchor, next_anchor, nullifier, Field};
use zk_toon_challenger::{EscapeId, PortError, VaultChainPort};
use zk_toon_challenger_mina::{nullifier_of_field, Endpoint, Graphql, MinaChain, RequestProofs, Settings};
use zk_toon_tx_builder::{
    node_command, Deposit, Escape, FeePayer, Note, NoteState, RequestProofInput, SignedState, TxBuilder,
};

const SMALL: u64 = DEPOSIT_SIZES[0];
const MINA: u64 = 1_000_000_000;

type Shared = Rc<RefCell<TxBuilder>>;

/// The local chain's GraphQL, recording the last answer to each operation.
struct LocalGraphql {
    builder: Shared,
    recorded: RefCell<HashMap<String, Value>>,
}

impl Graphql for LocalGraphql {
    fn post(&self, endpoint: Endpoint, request: &Value) -> Result<Value, String> {
        let endpoint = match endpoint {
            Endpoint::Mina => "mina",
            Endpoint::Archive => "archive",
        };
        let response = self.builder.borrow_mut().local().graphql(endpoint, request).map_err(|e| e.to_string())?;
        let op = request["operationName"].as_str().unwrap_or("").to_string();
        self.recorded.borrow_mut().insert(op, response.clone());
        Ok(response)
    }
}

/// The zk edge's recorded request proofs, by nullifier.
#[derive(Default)]
struct Recorded(RefCell<HashMap<EscapeId, Vec<Value>>>);

impl RequestProofs for &Recorded {
    fn at(&self, n: &EscapeId) -> Result<Vec<Value>, PortError> {
        Ok(self.0.borrow().get(n).cloned().unwrap_or_default())
    }
}

struct Chain {
    vault: CompressedPubKey,
    state_key: Keypair,
    payer: FeePayer,
    alice: CompressedPubKey,
}

fn chain(b: &mut TxBuilder) -> Chain {
    let accounts = b.local().accounts().unwrap();
    let state_key = keypair(4242);
    let vault = b.local().deploy_vault(&state_key.public.into_compressed(), &accounts[2].public_key).unwrap();
    Chain {
        vault,
        state_key,
        payer: FeePayer { private_key: accounts[0].private_key.clone(), fee: 0 },
        alice: accounts[1].public_key.clone(),
    }
}

fn deposit_note(b: &mut TxBuilder, c: &Chain, secret: u64) -> Note {
    let deposit_time = b.local().now().unwrap();
    let note = Note { secret: Field::from(secret), size: SMALL, deposit_time };
    let tx = b
        .deposit(&Deposit {
            vault: c.vault.clone(),
            fee_payer: c.payer.clone(),
            commitment: commit_secret(note.secret),
            size: SMALL,
            deposit_time,
        })
        .unwrap();
    b.local().submit(&tx).unwrap();
    b.local().reduce(&c.vault).unwrap();
    note
}

/// The note's state after `steps` signed advances (0 is genesis), with `balance`, and its nullifier.
fn state(c: &Chain, note: &Note, steps: usize, balance: u64) -> (NoteState, Field) {
    let mut anchor = genesis_anchor(commit_secret(note.secret));
    let mut prev = None;
    for _ in 0..steps {
        prev = Some(anchor);
        anchor = next_anchor(nullifier(note.secret, anchor));
    }
    let blinding = Scalar::from(11u64);
    let signed = prev.map(|prev_anchor| {
        let msg = StateMessage::new(&c.state_key.public.into_compressed(), commit(Scalar::from(balance), blinding), anchor);
        SignedState { balance, prev_anchor, signature: sign_state(&c.state_key, &msg) }
    });
    (NoteState { blinding, signed }, nullifier(note.secret, anchor))
}

fn escape(b: &mut TxBuilder, c: &Chain, note: &Note, state: NoteState, conceded: u64) {
    let request_time = b.local().now().unwrap();
    let tx = b
        .escape(&Escape {
            vault: c.vault.clone(),
            fee_payer: c.payer.clone(),
            note: note.clone(),
            state,
            request_time,
            destination: c.alice.clone(),
            conceded,
            valid_until: request_time + 10 * 60_000,
        })
        .unwrap();
    b.local().submit(&tx).unwrap();
}

/// A request proof at `state`, recorded as the zk edge records it when it grants an allowance.
fn record_request(b: &mut TxBuilder, c: &Chain, note: &Note, state: NoteState, tier: u64, evidence: &Recorded) {
    let request_time = b.local().now().unwrap();
    let proof = b
        .request_proof(&RequestProofInput {
            vault: c.vault.clone(),
            note: note.clone(),
            state,
            request_time,
            tier,
            rerandom_blinding: Scalar::from(31u64),
            session_key: keypair(777).public.into_compressed(),
            request_expiry: request_time + 60_000,
        })
        .unwrap();
    evidence.0.borrow_mut().entry(nullifier_of_field(proof.public.nullifier)).or_default().push(proof.proof);
}

#[test]
fn a_defeat_and_a_raise_through_the_adapter_are_accepted_by_the_vault() {
    let o1js = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../o1js"));
    let builder: Shared = Rc::new(RefCell::new(
        TxBuilder::spawn(node_command(&o1js, &["--local", "--proofs=off"])).expect("start the transaction builder"),
    ));
    let mut b = builder.borrow_mut();
    let c = chain(&mut b);

    // Two escapes: one from a stale genesis state, one from a signed state that conceded too little.
    let stale = deposit_note(&mut b, &c, 7007);
    let (genesis, stale_at) = state(&c, &stale, 0, SMALL);
    escape(&mut b, &c, &stale, genesis, 0);
    let low = deposit_note(&mut b, &c, 8008);
    let (signed, low_at) = state(&c, &low, 1, 3 * MINA);
    escape(&mut b, &c, &low, signed.clone(), MINA / 100);
    b.local().reduce(&c.vault).unwrap();

    // The zk edge's evidence: the stale note's successor opened an allowance, and the low one's
    // escaping state opened one of the top tier.
    let evidence = Recorded::default();
    let (successor, _) = state(&c, &stale, 1, 4 * MINA);
    record_request(&mut b, &c, &stale, successor, TIERS[2], &evidence);
    record_request(&mut b, &c, &low, signed, TIERS[2], &evidence);
    drop(b);

    let graphql = LocalGraphql { builder: builder.clone(), recorded: RefCell::default() };
    let settings = Settings { vault: c.vault.clone(), fee_payer: c.payer.clone(), poll: Duration::from_millis(50) };
    let mut port = MinaChain::new(settings, &graphql, builder.clone(), &evidence).unwrap();

    let mut ids: Vec<EscapeId> = port.escapes().unwrap().iter().map(|e| e.id).collect();
    ids.sort();
    let mut expected = vec![nullifier_of_field(stale_at), nullifier_of_field(low_at)];
    expected.sort();
    assert_eq!(ids, expected);

    port.submit_defeat(&nullifier_of_field(stale_at)).unwrap();
    port.submit_raise(&nullifier_of_field(low_at), MINA / 2).unwrap();
    builder.borrow_mut().local().reduce(&c.vault).unwrap();

    let escapes = port.escapes().unwrap();
    assert_eq!(escapes.len(), 1, "the defeated escape is gone");
    assert_eq!(escapes[0].id, nullifier_of_field(low_at));
    assert_eq!((escapes[0].conceded, escapes[0].balance), (MINA / 2, 3 * MINA));

    if std::env::var("ZK_TOON_RECORD_VAULT").as_deref() == Ok("1") {
        record_fixture(&graphql, &c.vault);
    }
}

/// Writes what the adapter last read: the vault after the defeat and the raise's reduce, before it.
fn record_fixture(graphql: &LocalGraphql, vault: &CompressedPubKey) {
    let recorded = graphql.recorded.borrow();
    let fixture = json!({
        "about": "Mina GraphQL answers for a vault with one open escape (3 MINA, raised to 0.5 MINA) and one \
                  defeated, recorded from the transaction builder's local chain by tests/local_chain.rs.",
        "vault": vault.into_address(),
        "vaultState": recorded["VaultState"],
        "escapeEvents": recorded["EscapeEvents"],
    });
    let path = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/recorded-vault.json"));
    std::fs::write(path, serde_json::to_string_pretty(&fixture).unwrap() + "\n").unwrap();
}
