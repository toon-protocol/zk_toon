#![allow(dead_code)]
//! A scripted Mina: answers the adapter's GraphQL in the shapes of the recorded fixture, builds
//! defeats and raises as stand-in commands, and applies each one it accepts as the vault and its next
//! reduce would. Knobs make its connection drop and its answers lag.
use std::cell::RefCell;
use std::rc::Rc;
use std::str::FromStr;
use std::time::Duration;

use mina_curves::pasta::Fq;
use mina_signer::{CompressedPubKey, Keypair, SecKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zk_note::Field;
use zk_toon_challenger::{Escape, EscapeId, Millis, PortError};
use zk_toon_challenger_mina::escapes::{replay, Record, Update, PENDING_ESCAPES_ROOT_INDEX};
use zk_toon_challenger_mina::{
    field_of_nullifier, Endpoint, Graphql, MinaChain, RequestProofs, Settings, TxSource,
};
use zk_toon_tx_builder::{Challenge, Defeat, FeePayer, Raise, Transaction};

pub const FIXTURE: &str = include_str!("../fixtures/recorded-vault.json");
/// SHA-256 of `fixtures/recorded-vault.json`. A changed recording must change this too.
pub const FIXTURE_SHA256: &str = "aad20125daee85c11a0f748300b67c542eec691eab9698d3413a85d652e3e9bd";

pub fn fixture() -> Value {
    let digest: String = Sha256::digest(FIXTURE.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(digest, FIXTURE_SHA256, "the recorded vault state is not the one pinned");
    serde_json::from_str(FIXTURE).unwrap()
}

pub fn keypair(secret: u64) -> Keypair {
    Keypair::try_from(SecKey::new(Fq::from(secret))).unwrap()
}

pub fn fee_payer() -> FeePayer {
    FeePayer { private_key: SecKey::new(Fq::from(77u64)).to_base58(), fee: 0 }
}

pub fn vault_key() -> CompressedPubKey {
    CompressedPubKey::from_address(fixture()["vault"].as_str().unwrap()).unwrap()
}

#[derive(Default)]
pub struct State {
    pub now: Millis,
    pub updates: Vec<Update>,
    /// Hashes of the commands in blocks, with their failure if they failed.
    pub included: Vec<(String, Option<String>)>,
    pub sent: usize,
    pub built: usize,
    /// Status reads that fail (the connection drops) before one is answered.
    pub failing_polls: usize,
    /// Status reads that find the command still in the pool before it lands.
    pub pooled_polls: usize,
    /// The next send reaches the chain but its answer is lost.
    pub drop_send_answer: bool,
    /// The next command that lands fails with this reason.
    pub fail_with: Option<String>,
    /// The next sent command is lost before the pool and never lands.
    pub lose_sends: bool,
    pub status_reads: usize,
    /// How far the chain's clock moves on each status read.
    pub advance_per_read: Millis,
    /// Commands accepted but not yet in a block, with their effect.
    pool: Vec<(String, Update)>,
}

#[derive(Clone, Default)]
pub struct Scripted(pub Rc<RefCell<State>>);

pub fn record(e: &Escape) -> Record {
    Record {
        nullifier: field_of_nullifier(&e.id).expect("a canonical nullifier"),
        next_nullifier: field_of_nullifier(&e.next_nullifier).expect("a canonical nullifier"),
        amount: e.balance,
        conceded: e.conceded,
        size: e.balance,
        destination_x: Field::from(7u64),
        destination_is_odd: false,
        deadline: e.deadline,
    }
}

fn strings(fields: &[Field]) -> Value {
    Value::Array(fields.iter().map(|f| json!(zk_note::field_to_string(*f))).collect())
}

impl Scripted {
    pub fn new(now: Millis, escapes: &[Escape]) -> Self {
        let s = Scripted::default();
        {
            let mut st = s.0.borrow_mut();
            st.now = now;
            st.updates = escapes.iter().map(|e| Update { pending: true, record: record(e) }).collect();
        }
        s
    }

    fn pending(&self, at: Field) -> Option<Record> {
        replay(&self.0.borrow().updates).1.into_iter().find(|r| r.nullifier == at)
    }

    /// Lands every pooled command, as a block and the reduce after it would.
    fn land(&self) {
        let mut st = self.0.borrow_mut();
        let pool = std::mem::take(&mut st.pool);
        for (hash, update) in pool {
            let failure = st.fail_with.take();
            if failure.is_none() {
                st.updates.push(update);
            }
            st.included.push((hash, failure));
        }
    }

    fn answer(&self, request: &Value) -> Result<Value, String> {
        let fixture = fixture();
        match request["operationName"].as_str().unwrap_or("") {
            "VaultState" => {
                let st = self.0.borrow();
                let mut response = fixture["vaultState"].clone();
                let (root, _) = replay(&st.updates);
                response["data"]["account"]["zkappState"][PENDING_ESCAPES_ROOT_INDEX] = json!(zk_note::field_to_string(root));
                response["data"]["bestChain"][0]["protocolState"]["blockchainState"]["utcDate"] = json!(st.now.to_string());
                Ok(response)
            }
            "EscapeEvents" => {
                let st = self.0.borrow();
                let mut response = fixture["escapeEvents"].clone();
                let template = response["data"]["events"][0].clone();
                let blocks: Vec<Value> = st
                    .updates
                    .iter()
                    .enumerate()
                    .map(|(i, u)| {
                        let mut block = template.clone();
                        block["blockInfo"]["height"] = json!(i + 1);
                        let mut event = template["eventData"][0].clone();
                        event["data"] = strings(&u.to_fields());
                        block["eventData"] = json!([event]);
                        block
                    })
                    .collect();
                response["data"]["events"] = Value::Array(blocks);
                Ok(response)
            }
            "SendChallenge" => {
                let command = &request["variables"]["input"]["zkappCommand"];
                let hash = command["hash"].as_str().unwrap().to_string();
                let fields: Vec<Field> =
                    command["update"].as_array().unwrap().iter().map(|f| Field::from_str(f.as_str().unwrap()).unwrap()).collect();
                let mut st = self.0.borrow_mut();
                st.sent += 1;
                if st.lose_sends {
                    return Ok(json!({ "data": { "sendZkapp": { "zkapp": { "hash": hash } } } }));
                }
                if st.pool.iter().any(|(h, _)| *h == hash) || st.included.iter().any(|(h, _)| *h == hash) {
                    return Ok(json!({ "errors": [{ "message": "Duplicate zkApp command" }] }));
                }
                st.pool.push((hash.clone(), Update::from_fields(&fields).unwrap()));
                if std::mem::take(&mut st.drop_send_answer) {
                    return Err("connection reset by peer".into());
                }
                Ok(json!({ "data": { "sendZkapp": { "zkapp": { "hash": hash } } } }))
            }
            "ChallengeStatus" => {
                {
                    let mut st = self.0.borrow_mut();
                    st.status_reads += 1;
                    st.now += st.advance_per_read;
                    if st.failing_polls > 0 {
                        st.failing_polls -= 1;
                        return Err("connection refused".into());
                    }
                    if st.pooled_polls > 0 {
                        st.pooled_polls -= 1;
                        let pooled: Vec<Value> = st.pool.iter().map(|(h, _)| json!({ "hash": h })).collect();
                        return Ok(status(&[], st.now, pooled));
                    }
                }
                self.land();
                let st = self.0.borrow();
                Ok(status(&st.included, st.now, vec![]))
            }
            other => Err(format!("the scripted chain doesn't answer {other}")),
        }
    }
}

fn status(included: &[(String, Option<String>)], now: Millis, pooled: Vec<Value>) -> Value {
    let commands: Vec<Value> = included
        .iter()
        .map(|(h, f)| {
            let failure = f.as_ref().map(|why| json!([{ "index": "1", "failures": [why] }]));
            json!({ "hash": h, "failureReason": failure })
        })
        .collect();
    json!({ "data": {
        "bestChain": [{ "transactions": { "zkappCommands": commands },
                        "protocolState": { "blockchainState": { "utcDate": now.to_string() } } }],
        "pooledZkappCommands": pooled,
    } })
}

impl Graphql for Scripted {
    fn post(&self, endpoint: Endpoint, request: &Value) -> Result<Value, String> {
        let expected = match request["operationName"].as_str() {
            Some("EscapeEvents") => Endpoint::Archive,
            _ => Endpoint::Mina,
        };
        assert_eq!(endpoint, expected, "{request}");
        self.answer(request)
    }
}

/// The tier a stand-in request proof carries.
pub const TIER: u64 = 1_000_000;

impl TxSource for Scripted {
    fn defeat(&mut self, d: &Defeat) -> Result<Challenge, zk_toon_tx_builder::Error> {
        let record = self.pending(d.escape).expect("the adapter only defeats a pending escape");
        Ok(self.command(Update { pending: false, record }))
    }

    fn raise(&mut self, r: &Raise) -> Result<Challenge, zk_toon_tx_builder::Error> {
        let mut record = self.pending(r.escape).expect("the adapter only raises a pending escape");
        let tier: u64 = r.evidence["publicInput"][4].as_str().unwrap().parse().unwrap();
        record.conceded = r.claimed.min(tier).min(record.amount);
        Ok(self.command(Update { pending: true, record }))
    }
}

impl Scripted {
    fn command(&self, update: Update) -> Challenge {
        let mut st = self.0.borrow_mut();
        st.built += 1;
        let hash = format!("5Jscripted{}", st.built);
        let zkapp_command = json!({ "hash": hash, "update": strings(&update.to_fields()) });
        Challenge { transaction: Transaction { zkapp_command, withdrawal: None }, hash }
    }
}

/// A stand-in request proof at every nullifier: unsubsidised, of tier [`TIER`].
pub struct AnyProof;

impl RequestProofs for AnyProof {
    fn at(&self, nullifier: &EscapeId) -> Result<Vec<Value>, PortError> {
        let n = zk_note::field_to_string(field_of_nullifier(nullifier).unwrap());
        let mut input = vec![json!("0"); 12];
        input[4] = json!(TIER.to_string());
        input[5] = json!(n);
        Ok(vec![json!({ "publicInput": input, "proof": "" })])
    }
}

pub type ScriptedChain = MinaChain<Scripted, Scripted, AnyProof>;

pub fn adapter(chain: &Scripted) -> ScriptedChain {
    let settings = Settings { vault: vault_key(), fee_payer: fee_payer(), poll: Duration::ZERO };
    MinaChain::new(settings, chain.clone(), chain.clone(), AnyProof).unwrap()
}
