//! [`MinaChain`]: the vault chain port over Mina GraphQL and the o1js transaction builder.
use std::str::FromStr;
use std::thread::sleep;
use std::time::Duration;

use mina_signer::{CompressedPubKey, Keypair, SecKey};
use serde_json::Value;
use zk_note::Field;
use zk_toon_challenger::{Escape, EscapeId, Millis, PortError, VaultChainPort};
use zk_toon_tx_builder::{Challenge, Defeat, FailureKind, FeePayer, Raise};

use crate::escapes::{replay, Record, Update, PENDING_ESCAPES_ROOT_INDEX};
use crate::graphql::{self, data, decimal, Endpoint, Graphql};
use crate::nullifier::{field_of_nullifier, nullifier_of_field};

/// What builds the defeat and raise transactions: the o1js transaction builder, or a stand-in.
pub trait TxSource {
    fn defeat(&mut self, d: &Defeat) -> Result<Challenge, zk_toon_tx_builder::Error>;
    fn raise(&mut self, r: &Raise) -> Result<Challenge, zk_toon_tx_builder::Error>;
}

impl TxSource for zk_toon_tx_builder::TxBuilder {
    fn defeat(&mut self, d: &Defeat) -> Result<Challenge, zk_toon_tx_builder::Error> {
        zk_toon_tx_builder::TxBuilder::defeat(self, d)
    }
    fn raise(&mut self, r: &Raise) -> Result<Challenge, zk_toon_tx_builder::Error> {
        zk_toon_tx_builder::TxBuilder::raise(self, r)
    }
}

impl<T: TxSource> TxSource for std::rc::Rc<std::cell::RefCell<T>> {
    fn defeat(&mut self, d: &Defeat) -> Result<Challenge, zk_toon_tx_builder::Error> {
        self.borrow_mut().defeat(d)
    }
    fn raise(&mut self, r: &Raise) -> Result<Challenge, zk_toon_tx_builder::Error> {
        self.borrow_mut().raise(r)
    }
}

/// The zk edge's recorded request proofs, as the evidence a defeat or raise carries: o1js
/// `JsonProof`s, which hold no secret (the grant records of the evidence file hold them).
pub trait RequestProofs {
    /// Every recorded request proof at `nullifier`.
    fn at(&self, nullifier: &EscapeId) -> Result<Vec<Value>, PortError>;
}

/// Where the adapter acts and how often it reads a submitted transaction's outcome.
#[derive(Clone, Debug)]
pub struct Settings {
    pub vault: CompressedPubKey,
    /// Pays for and signs every defeat and raise. Its key goes only to the transaction builder.
    pub fee_payer: FeePayer,
    /// The pause between two reads of a submitted transaction's outcome.
    pub poll: Duration,
}

/// The vault chain port on Mina.
///
/// It reads the vault's open escapes from Mina GraphQL: the pending escapes rebuilt from the vault's
/// `escape` events (archive) and checked against its `pendingEscapesRoot` (daemon). It submits a
/// defeat or raise built by the o1js transaction builder with the zk edge's recorded request proof as
/// evidence, then waits for its outcome: read again, through dropped connections and failed polls,
/// until the transaction is in a block, or has failed, or can no longer land.
///
/// It logs nothing. Its errors name nullifiers and the chain's messages, never a secret.
pub struct MinaChain<G, T, P> {
    graphql: G,
    txs: T,
    proofs: P,
    settings: Settings,
    vault: String,
    fee_payer: String,
}

/// The vault as read: the chain time and the pending escapes, deadlines included.
struct VaultView {
    now: Millis,
    pending: Vec<Record>,
}

impl<G: Graphql, T: TxSource, P: RequestProofs> MinaChain<G, T, P> {
    pub fn new(settings: Settings, graphql: G, txs: T, proofs: P) -> Result<Self, PortError> {
        let key = SecKey::from_base58(&settings.fee_payer.private_key)
            .map_err(|_| PortError::Refused("the fee payer's private key is not a base58 key".into()))?;
        let keypair = Keypair::try_from(key)
            .map_err(|_| PortError::Refused("the fee payer's private key is not a key".into()))?;
        let fee_payer = keypair.public.into_compressed().into_address();
        let vault = settings.vault.into_address();
        Ok(MinaChain { graphql, txs, proofs, settings, vault, fee_payer })
    }

    fn query(&self, endpoint: Endpoint, request: &Value) -> Result<Value, PortError> {
        let response = self.graphql.post(endpoint, request).map_err(|e| PortError::Unavailable(format!("graphql: {e}")))?;
        data(&response).cloned().map_err(|e| PortError::Unavailable(format!("graphql: {e}")))
    }

    fn view(&self) -> Result<VaultView, PortError> {
        let state = self.query(Endpoint::Mina, &graphql::vault_state(&self.vault))?;
        let bad = |m: &str| PortError::Unavailable(format!("vault state: {m}"));
        let root = state["account"]["zkappState"]
            .get(PENDING_ESCAPES_ROOT_INDEX)
            .and_then(Value::as_str)
            .and_then(|s| Field::from_str(s).ok())
            .ok_or_else(|| bad("no pending escapes root"))?;
        let now = tip_time(&state["bestChain"]).ok_or_else(|| bad("no block time"))?;

        let events = self.query(Endpoint::Archive, &graphql::escape_events(&self.vault))?;
        let orders = escape_updates(&events).map_err(|e| PortError::Unavailable(format!("escape events: {e}")))?;
        for updates in &orders {
            let (rebuilt, pending) = replay(updates);
            if rebuilt == root {
                return Ok(VaultView { now, pending });
            }
        }
        Err(PortError::Unavailable(
            "the vault's escape events don't rebuild its pending escapes root; the archive may lag the daemon".into(),
        ))
    }

    /// The pending escape `id` names, if it is still open.
    fn open(&self, id: &EscapeId) -> Result<(VaultView, Record), PortError> {
        let view = self.view()?;
        let record = view
            .pending
            .iter()
            .find(|r| nullifier_of_field(r.nullifier) == *id && r.deadline > view.now)
            .cloned()
            .ok_or_else(|| PortError::Refused("no open escape at this nullifier".into()))?;
        Ok((view, record))
    }

    /// Sends `challenge` and waits until its outcome is known.
    fn submit(&self, challenge: Challenge, deadline: Millis) -> Result<(), PortError> {
        match self.send(&challenge) {
            Ok(()) => {}
            Err(PortError::Refused(why)) => return Err(PortError::Refused(why)),
            // No answer: it may have been sent all the same. Waiting finds out, and resends it if not.
            Err(PortError::Unavailable(_)) => {}
        }
        loop {
            match self.outcome(&challenge.hash) {
                Ok(Outcome::Included) => return Ok(()),
                Ok(Outcome::Failed(why)) => return Err(PortError::Refused(why)),
                Ok(Outcome::Pooled) => {}
                Ok(Outcome::Absent { now }) if now >= deadline => {
                    return Err(PortError::Refused("not included before the escape's deadline".into()))
                }
                // Lost before it reached the pool, or dropped from it: send it again. A refusal of the
                // resend (for instance as a duplicate) doesn't end the wait; the next read decides.
                Ok(Outcome::Absent { .. }) => {
                    let _ = self.send(&challenge);
                }
                // A dropped connection or a failed poll never ends the wait: the outcome is read again.
                Err(_) => {}
            }
            sleep(self.settings.poll);
        }
    }

    fn send(&self, challenge: &Challenge) -> Result<(), PortError> {
        let request = graphql::send_zkapp(&challenge.transaction.zkapp_command);
        let response = self.graphql.post(Endpoint::Mina, &request).map_err(PortError::Unavailable)?;
        data(&response).map(|_| ()).map_err(|why| PortError::Refused(format!("sendZkapp: {why}")))
    }

    fn outcome(&self, hash: &str) -> Result<Outcome, PortError> {
        let status = self.query(Endpoint::Mina, &graphql::challenge_status(&self.fee_payer))?;
        let blocks = status["bestChain"].as_array().ok_or_else(|| PortError::Unavailable("no best chain".into()))?;
        for block in blocks {
            for command in block["transactions"]["zkappCommands"].as_array().into_iter().flatten() {
                if command["hash"].as_str() == Some(hash) {
                    return Ok(match command["failureReason"].as_array() {
                        Some(failures) if !failures.is_empty() => {
                            Outcome::Failed(format!("the transaction failed: {}", Value::Array(failures.clone())))
                        }
                        _ => Outcome::Included,
                    });
                }
            }
        }
        let pooled = status["pooledZkappCommands"].as_array().into_iter().flatten().any(|c| c["hash"].as_str() == Some(hash));
        if pooled {
            return Ok(Outcome::Pooled);
        }
        let now = tip_time(&status["bestChain"]).ok_or_else(|| PortError::Unavailable("no block time".into()))?;
        Ok(Outcome::Absent { now })
    }

    /// The evidence for a challenge at `nullifier`: the proof `pick` prefers among those recorded there.
    fn evidence(&self, nullifier: &EscapeId, pick: impl Fn(&[Value]) -> Option<Value>) -> Result<Value, PortError> {
        pick(&self.proofs.at(nullifier)?).ok_or_else(|| PortError::Refused("no recorded request proof to act on".into()))
    }
}

enum Outcome {
    Included,
    Failed(String),
    Pooled,
    Absent { now: Millis },
}

/// The latest block time among `blocks` (Mina GraphQL's `bestChain`).
fn tip_time(blocks: &Value) -> Option<Millis> {
    blocks.as_array()?.iter().filter_map(|b| decimal(&b["protocolState"]["blockchainState"]["utcDate"])).max()
}

/// The vault's `escape` events in the archive's response, oldest block first, leaving out those of
/// orphaned blocks and failed transactions; in the two orders they may have been emitted in.
///
/// An account update lists its events newest first (o1js pushes each onto the front), so the first
/// order reverses each transaction's run of events back into the order its reduce emitted them. The
/// second keeps the archive's order. Only an order that rebuilds the vault's root is used.
fn escape_updates(events: &Value) -> Result<[Vec<Update>; 2], String> {
    let blocks = events["events"].as_array().ok_or("no events array")?;
    // (block height, transaction hash, fields)
    let mut listed: Vec<(u64, String, Vec<Field>)> = Vec::new();
    for block in blocks {
        if block["blockInfo"]["chainStatus"].as_str() == Some("orphaned") {
            continue;
        }
        let height = block["blockInfo"]["height"].as_u64().or_else(|| decimal(&block["blockInfo"]["height"])).ok_or("no block height")?;
        for event in block["eventData"].as_array().ok_or("no eventData array")? {
            if event["transactionInfo"]["status"].as_str() == Some("failed") {
                continue;
            }
            let fields = event["data"]
                .as_array()
                .ok_or("event data is not an array")?
                .iter()
                .map(|f| f.as_str().and_then(|s| Field::from_str(s).ok()).ok_or_else(|| format!("{f} is not a field")))
                .collect::<Result<Vec<_>, _>>()?;
            let tx = event["transactionInfo"]["hash"].as_str().unwrap_or("").to_string();
            listed.push((height, tx, fields));
        }
    }
    // Stable: events of one block keep the archive's order.
    listed.sort_by_key(|(h, _, _)| *h);

    let mut reversed: Vec<&Vec<Field>> = Vec::new();
    let mut run: Vec<&Vec<Field>> = Vec::new();
    for (i, (height, tx, fields)) in listed.iter().enumerate() {
        run.push(fields);
        let ends = listed.get(i + 1).map_or(true, |(h, t, _)| h != height || t != tx);
        if ends {
            reversed.extend(run.drain(..).rev());
        }
    }
    let decode = |fs: Vec<&Vec<Field>>| fs.into_iter().map(|f| Update::from_fields(f)).collect::<Result<Vec<_>, _>>();
    Ok([decode(reversed)?, decode(listed.iter().map(|(_, _, f)| f).collect())?])
}

/// A request proof's public input `i` (`RequestPublic` order: 4 is the tier, 9 subsidised).
fn public_input(proof: &Value, i: usize) -> Option<u64> {
    decimal(&proof["publicInput"][i])
}

fn builder_error(e: zk_toon_tx_builder::Error) -> PortError {
    match e {
        // The vault (or its rebuilt state) refused what was asked: retrying the same won't help.
        zk_toon_tx_builder::Error::Failure { kind: FailureKind::BadInput | FailureKind::ProvingFailed, message } => {
            PortError::Refused(format!("transaction builder: {message}"))
        }
        other => PortError::Unavailable(format!("transaction builder: {other}")),
    }
}

impl<G: Graphql, T: TxSource, P: RequestProofs> VaultChainPort for MinaChain<G, T, P> {
    fn escapes(&self) -> Result<Vec<Escape>, PortError> {
        let view = self.view()?;
        Ok(view
            .pending
            .iter()
            .filter(|r| r.deadline > view.now)
            .map(|r| Escape {
                id: nullifier_of_field(r.nullifier),
                next_nullifier: nullifier_of_field(r.next_nullifier),
                conceded: r.conceded,
                balance: r.amount,
                deadline: r.deadline,
            })
            .collect())
    }

    fn submit_defeat(&mut self, id: &EscapeId) -> Result<(), PortError> {
        let escape = field_of_nullifier(id).ok_or_else(|| PortError::Refused("not a nullifier".into()))?;
        let (_, record) = self.open(id)?;
        // Any request proof at the next nullifier defeats, a subsidised one too (ADR 0001).
        let evidence = self.evidence(&nullifier_of_field(record.next_nullifier), |proofs| proofs.first().cloned())?;
        let defeat = Defeat { vault: self.settings.vault.clone(), fee_payer: self.settings.fee_payer.clone(), escape, evidence };
        let challenge = self.txs.defeat(&defeat).map_err(builder_error)?;
        self.submit(challenge, record.deadline)
    }

    fn submit_raise(&mut self, id: &EscapeId, to: u64) -> Result<(), PortError> {
        let escape = field_of_nullifier(id).ok_or_else(|| PortError::Refused("not a nullifier".into()))?;
        let (_, record) = self.open(id)?;
        if to <= record.conceded || to > record.amount {
            return Err(PortError::Refused("a raise must exceed the concession and fit the balance".into()));
        }
        // The vault lifts the concession to min(claimed, b, balance) (ADR 0004): claim `to` with the
        // unsubsidised proof of the largest tier, which a subsidised one never is (ADR 0001).
        let evidence = self.evidence(id, |proofs| {
            proofs
                .iter()
                .filter(|p| public_input(p, 9) == Some(0))
                .max_by_key(|p| public_input(p, 4).unwrap_or(0))
                .filter(|p| public_input(p, 4).unwrap_or(0) >= to)
                .cloned()
        })?;
        let raise = Raise { vault: self.settings.vault.clone(), fee_payer: self.settings.fee_payer.clone(), escape, evidence, claimed: to };
        let challenge = self.txs.raise(&raise).map_err(builder_error)?;
        self.submit(challenge, record.deadline)
    }
}
