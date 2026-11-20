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
use mina_signer::{CompressedPubKey, Keypair, NetworkId};
use serde_json::{json, Value};
use zk_note::balance::{commit, Scalar};
use zk_note::policy::{DEPOSIT_SIZES, REQUEST_MAX_AGE_SLOTS, TIERS};
use zk_note::state::{sign_state, StateMessage};
use zk_note::{commit_secret, genesis_anchor, next_anchor, nullifier, Field};
use zk_evidence::{extend_running_hash, frame, scan_records, write_header, Checkpoint, Close, FileCopy, Grant, Push, Record};
use zk_toon_challenger::{Action, Challenger, Config, EscapeId, FileEvidence, MemoryJournal, PortError, ProofVerifier, Report, VaultChainPort};
use zk_toon_challenger_mina::{nullifier_of_field, Endpoint, Graphql, Listener, MinaChain, Receiver, RequestProofs, Settings, TxSource};
use zk_toon_tx_builder::{
    node_command, Challenge, Defeat, Deposit, Escape, FeePayer, Note, NoteState, Raise, RequestProofInput,
    RequestProof, SignedState, TxBuilder,
};

const SMALL: u64 = DEPOSIT_SIZES[0];
const MINA: u64 = 1_000_000_000;

type Shared = Rc<RefCell<TxBuilder>>;

/// The local chain's GraphQL, recording the last answer to each operation.
struct LocalGraphql {
    builder: Shared,
    recorded: RefCell<HashMap<String, Value>>,
}

/// The adapter borrows the GraphQL, so the test can read what it recorded.
impl Graphql for &LocalGraphql {
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

/// The builder as the adapter's transaction source, shared with the GraphQL stand-in and the test.
struct SharedTxs(Shared);

impl TxSource for SharedTxs {
    fn defeat(&mut self, d: &Defeat) -> Result<Challenge, zk_toon_tx_builder::Error> {
        self.0.borrow_mut().defeat(d)
    }
    fn raise(&mut self, r: &Raise) -> Result<Challenge, zk_toon_tx_builder::Error> {
        self.0.borrow_mut().raise(r)
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
    let deposit_time = b.local().slot().unwrap();
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
    let request_time = b.local().slot().unwrap();
    let tx = b
        .escape(&Escape {
            vault: c.vault.clone(),
            fee_payer: c.payer.clone(),
            note: note.clone(),
            state,
            request_time,
            destination: c.alice.clone(),
            conceded,
            valid_until: request_time + REQUEST_MAX_AGE_SLOTS,
        })
        .unwrap();
    b.local().submit(&tx).unwrap();
}

/// A request proof at `state`, recorded as the zk edge records it when it grants an allowance.
fn record_request(b: &mut TxBuilder, c: &Chain, note: &Note, state: NoteState, tier: u64, evidence: &Recorded) {
    let proof = request(b, c, note, state, tier);
    evidence.0.borrow_mut().entry(nullifier_of_field(proof.public.nullifier)).or_default().push(proof.proof);
}

/// A request proof at `state` for `tier`.
fn request(b: &mut TxBuilder, c: &Chain, note: &Note, state: NoteState, tier: u64) -> RequestProof {
    let request_time = b.local().slot().unwrap();
    b.request_proof(&RequestProofInput {
            vault: c.vault.clone(),
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
    let mut port = MinaChain::new(settings, &graphql, SharedTxs(builder.clone()), &evidence).unwrap();

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

#[test]
fn a_raise_that_would_strand_less_than_the_creation_fee_concedes_the_whole_balance() {
    let o1js = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../o1js"));
    let builder: Shared = Rc::new(RefCell::new(
        TxBuilder::spawn(node_command(&o1js, &["--local", "--proofs=off"])).expect("start the transaction builder"),
    ));
    let mut b = builder.borrow_mut();
    let c = chain(&mut b);

    // An escape of 1.5 MINA conceding nothing, from a state that opened a top-tier allowance: raising to
    // the tier would leave 0.5 MINA, under the fee, so the vault concedes the whole balance (ADR 0013).
    let note = deposit_note(&mut b, &c, 9009);
    let (signed, at) = state(&c, &note, 1, 3 * MINA / 2);
    escape(&mut b, &c, &note, signed.clone(), 0);
    b.local().reduce(&c.vault).unwrap();
    let evidence = Recorded::default();
    record_request(&mut b, &c, &note, signed, TIERS[2], &evidence);
    drop(b);

    let graphql = LocalGraphql { builder: builder.clone(), recorded: RefCell::default() };
    let settings = Settings { vault: c.vault.clone(), fee_payer: c.payer.clone(), poll: Duration::from_millis(50) };
    let mut port = MinaChain::new(settings, &graphql, SharedTxs(builder.clone()), &evidence).unwrap();

    port.submit_raise(&nullifier_of_field(at), 3 * MINA / 2).unwrap();
    builder.borrow_mut().local().reduce(&c.vault).unwrap();

    let escapes = port.escapes().unwrap();
    assert_eq!(escapes.len(), 1);
    assert_eq!((escapes[0].conceded, escapes[0].balance), (3 * MINA / 2, 3 * MINA / 2));
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

/// Accepts every proof: the local chain runs with proofs off, so there is nothing to verify.
struct AcceptAll;

impl ProofVerifier for AcceptAll {
    fn verifies(&self, _: &[u8]) -> Result<bool, PortError> {
        Ok(true)
    }
}

/// The stand-in zk edge's pushes: each carries `records` after the copy `at`, signed for `vault`.
fn push_of(at: &FileCopy, records: &[Record], vault: &CompressedPubKey, state_key: &Keypair) -> (Push, FileCopy) {
    let bytes: Vec<u8> = records.iter().flat_map(|r| frame(&r.encode().unwrap())).collect();
    let scan = scan_records(&bytes, 0).unwrap();
    let after = FileCopy {
        length: at.length + bytes.len() as u64,
        running_hash: scan.records.iter().fold(at.running_hash, |h, r| extend_running_hash(&h, r.payload)),
    };
    let checkpoint = Checkpoint { vault: vault.clone(), length: after.length, running_hash: after.running_hash };
    (Push { offset: at.length, bytes, signature: checkpoint.sign(NetworkId::TESTNET, state_key) }, after)
}

fn grant_of(proof: &RequestProof, id: &[u8]) -> Record {
    Record::Grant(Grant {
        proof: serde_json::to_vec(&proof.proof).unwrap(),
        allowance_id: id.to_vec(),
        session_key_x: Field::from(1u64),
        session_key_is_odd: false,
        expires_at: 1_700_000_900_000,
        granted_at: 1_700_000_100_000,
    })
}

/// #107's test: the zk edge pushes its grant and close records to the challenger's listener and
/// stops, and its own file is deleted. The challenger decides from its evidence copy alone.
#[test]
fn with_the_zk_edge_gone_the_challenger_acts_from_its_copy() {
    let o1js = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../o1js"));
    let builder: Shared = Rc::new(RefCell::new(
        TxBuilder::spawn(node_command(&o1js, &["--local", "--proofs=off"])).expect("start the transaction builder"),
    ));
    let mut b = builder.borrow_mut();
    let c = chain(&mut b);

    let stale = deposit_note(&mut b, &c, 7007);
    let (genesis, stale_at) = state(&c, &stale, 0, SMALL);
    escape(&mut b, &c, &stale, genesis, 0);
    let low = deposit_note(&mut b, &c, 8008);
    let (signed, low_at) = state(&c, &low, 1, 3 * MINA);
    escape(&mut b, &c, &low, signed.clone(), MINA / 100);
    b.local().reduce(&c.vault).unwrap();

    // The zk edge granted the stale note's successor an allowance, and the low note's escaping state
    // one of the top tier that closed at a charge of half a MINA.
    let (successor, _) = state(&c, &stale, 1, 4 * MINA);
    let successor_proof = request(&mut b, &c, &stale, successor, TIERS[2]);
    let low_proof = request(&mut b, &c, &low, signed, TIERS[2]);
    drop(b);

    let dir = std::env::temp_dir().join(format!("zk-edge-down-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (copy_path, edge_path) = (dir.join("copy"), dir.join("edge"));

    let receiver = Receiver::open(&copy_path, c.vault.clone(), &c.state_key.public.into_compressed()).unwrap();
    let listener = Listener::start("127.0.0.1:0".parse().unwrap(), receiver, None, |_| {}).unwrap();
    let url = format!("http://{}/", listener.local_addr());

    let mut edge = std::fs::File::create(&edge_path).unwrap();
    std::io::Write::write_all(&mut edge, &write_header()).unwrap();
    let mut at = FileCopy::empty();
    let close = Record::Close(Close { nullifier: low_proof.public.nullifier, allowance_id: b"low".to_vec(), charge: MINA / 2 });
    for records in [vec![grant_of(&successor_proof, b"stale"), grant_of(&low_proof, b"low")], vec![close]] {
        let (push, after) = push_of(&at, &records, &c.vault, &c.state_key);
        std::io::Write::write_all(&mut edge, &push.bytes).unwrap();
        let reply = ureq::post(&url).send_bytes(&push.encode()).unwrap().into_string().unwrap();
        assert_eq!(reply, format!(r#"{{"length":{}}}"#, after.length));
        at = after;
    }
    // The zk edge stops, and its file goes with its host.
    drop(edge);
    std::fs::remove_file(&edge_path).unwrap();
    assert_eq!(std::fs::read(&copy_path).unwrap().len() as u64, at.length);

    let evidence = Rc::new(FileEvidence::new(&copy_path, AcceptAll));
    let graphql = LocalGraphql { builder: builder.clone(), recorded: RefCell::default() };
    let settings = Settings { vault: c.vault.clone(), fee_payer: c.payer.clone(), poll: Duration::from_millis(50) };
    let port = MinaChain::new(settings, &graphql, SharedTxs(builder.clone()), evidence.clone()).unwrap();
    let mut challenger = Challenger::new(port, evidence, MemoryJournal::default(), Config { min_lead: 0 });

    let now = challenger.chain.now().unwrap();
    let reports = challenger.tick(now).unwrap();
    let submitted: Vec<_> = reports
        .iter()
        .filter_map(|r| match r {
            Report::Submitted { escape, action } => Some((*escape, action.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(reports.len(), 4, "{reports:?}");
    assert!(submitted.contains(&(nullifier_of_field(stale_at), Action::Defeat)), "{reports:?}");
    assert!(submitted.contains(&(nullifier_of_field(low_at), Action::Raise { to: MINA / 2 })), "{reports:?}");

    builder.borrow_mut().local().reduce(&c.vault).unwrap();
    let escapes = challenger.chain.escapes().unwrap();
    assert_eq!(escapes.len(), 1, "the defeated escape is gone");
    assert_eq!((escapes[0].id, escapes[0].conceded), (nullifier_of_field(low_at), MINA / 2));
}
