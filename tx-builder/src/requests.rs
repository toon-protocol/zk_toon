//! The typed requests and answers. `docs/tx-builder.md` documents their JSON.
use std::fmt;

use mina_curves::pasta::Pallas;
use mina_signer::{CompressedPubKey, Signature};
use serde_json::{json, Value};
use zk_note::balance::Scalar;
use zk_note::withdrawal::{WithdrawalKind, WithdrawalPublic};
use zk_note::Field;

use crate::{dec_field, dec_scalar, parse_field, parse_u64, sig_json, Error};

/// The account that pays the fee and signs the transaction. A deposit is also paid from it.
#[derive(Clone)]
pub struct FeePayer {
    /// Base58 (`EK…`), as o1js and Mina wallets export it.
    pub private_key: String,
    /// Nanomina.
    pub fee: u64,
}

impl fmt::Debug for FeePayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FeePayer").field("private_key", &"[secret]").field("fee", &self.fee).finish()
    }
}

impl FeePayer {
    fn to_json(&self) -> Value {
        json!({ "privateKey": self.private_key, "fee": self.fee.to_string() })
    }
}

/// What the payer keeps about its deposit.
#[derive(Clone)]
pub struct Note {
    pub secret: Field,
    pub size: u64,
    pub deposit_time: u64,
}

impl fmt::Debug for Note {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Note")
            .field("secret", &"[secret]")
            .field("size", &self.size)
            .field("deposit_time", &self.deposit_time)
            .finish()
    }
}

impl Note {
    fn to_json(&self) -> Value {
        json!({
            "secret": dec_field(self.secret),
            "size": self.size.to_string(),
            "depositTime": self.deposit_time.to_string(),
        })
    }
}

/// The note's current state: its genesis state, or one the zk edge signed.
#[derive(Clone)]
pub struct NoteState {
    /// The balance commitment's blinding.
    pub blinding: Scalar,
    /// `None` for the genesis state, whose balance is the deposit size.
    pub signed: Option<SignedState>,
}

impl fmt::Debug for NoteState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoteState").field("blinding", &"[secret]").field("signed", &self.signed).finish()
    }
}

/// A state the zk edge signed: its anchor follows from the previous state's nullifier.
#[derive(Clone, Debug)]
pub struct SignedState {
    pub balance: u64,
    /// The previous state's anchor.
    pub prev_anchor: Field,
    /// The state key's signature of the state message.
    pub signature: Signature,
}

impl NoteState {
    fn to_json(&self) -> Value {
        json!({
            "blinding": dec_scalar(self.blinding),
            "signed": self.signed.as_ref().map(|s| json!({
                "balance": s.balance.to_string(),
                "prevAnchor": dec_field(s.prev_anchor),
                "signature": sig_json(&s.signature),
            })),
        })
    }
}

/// Deposit `size` into `vault` as a note committing to `commitment` (`commit_secret(secret)`).
/// The note's secret never crosses the interface for a deposit.
#[derive(Clone, Debug)]
pub struct Deposit {
    pub vault: CompressedPubKey,
    pub fee_payer: FeePayer,
    pub commitment: Field,
    pub size: u64,
    /// The block time the deposit lands at, to within a slot (90 s).
    pub deposit_time: u64,
}

impl Deposit {
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "vault": self.vault.into_address(),
            "feePayer": self.fee_payer.to_json(),
            "commitment": dec_field(self.commitment),
            "size": self.size.to_string(),
            "depositTime": self.deposit_time.to_string(),
        })
    }
}

/// Close `note` at its current state by agreement, paying its balance to `destination`.
#[derive(Clone, Debug)]
pub struct MutualClose {
    pub vault: CompressedPubKey,
    pub fee_payer: FeePayer,
    pub note: Note,
    pub state: NoteState,
    /// The close lands at most 10 minutes after it.
    pub request_time: u64,
    pub destination: CompressedPubKey,
    /// The zk edge's clearance of this state's nullifier to `destination`.
    pub clearance: Signature,
}

impl MutualClose {
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "vault": self.vault.into_address(),
            "feePayer": self.fee_payer.to_json(),
            "note": self.note.to_json(),
            "state": self.state.to_json(),
            "requestTime": self.request_time.to_string(),
            "destination": self.destination.into_address(),
            "clearance": sig_json(&self.clearance),
        })
    }
}

/// Escape `note` at its current state without the zk edge, conceding `conceded` of its balance.
#[derive(Clone, Debug)]
pub struct Escape {
    pub vault: CompressedPubKey,
    pub fee_payer: FeePayer,
    pub note: Note,
    pub state: NoteState,
    pub request_time: u64,
    pub destination: CompressedPubKey,
    pub conceded: u64,
    /// The last block time the escape may land at; before the note's expiry.
    pub valid_until: u64,
}

impl Escape {
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "vault": self.vault.into_address(),
            "feePayer": self.fee_payer.to_json(),
            "note": self.note.to_json(),
            "state": self.state.to_json(),
            "requestTime": self.request_time.to_string(),
            "destination": self.destination.into_address(),
            "conceded": self.conceded.to_string(),
            "validUntil": self.valid_until.to_string(),
        })
    }
}

/// An unsubsidised request proof that `note`'s current state covers `tier`, bound to one session
/// key and expiry. The zk edge is the vault's state key.
#[derive(Clone)]
pub struct RequestProofInput {
    pub vault: CompressedPubKey,
    pub note: Note,
    pub state: NoteState,
    pub request_time: u64,
    pub tier: u64,
    /// Re-randomises the state's balance commitment.
    pub rerandom_blinding: Scalar,
    pub session_key: CompressedPubKey,
    pub request_expiry: u64,
}

impl fmt::Debug for RequestProofInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestProofInput")
            .field("vault", &self.vault)
            .field("note", &self.note)
            .field("state", &self.state)
            .field("request_time", &self.request_time)
            .field("tier", &self.tier)
            .field("rerandom_blinding", &"[secret]")
            .field("session_key", &self.session_key)
            .field("request_expiry", &self.request_expiry)
            .finish()
    }
}

impl RequestProofInput {
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "vault": self.vault.into_address(),
            "note": self.note.to_json(),
            "state": self.state.to_json(),
            "requestTime": self.request_time.to_string(),
            "tier": self.tier.to_string(),
            "rerandomBlinding": dec_scalar(self.rerandom_blinding),
            "sessionKey": self.session_key.into_address(),
            "requestExpiry": self.request_expiry.to_string(),
        })
    }
}

/// A proved, signed transaction, ready for Mina GraphQL's `sendZkapp`.
#[derive(Clone, Debug)]
pub struct Transaction {
    /// o1js `Transaction.toJSON()`: the zkApp command.
    pub zkapp_command: Value,
    /// A withdrawal's public inputs (mutual close, escape); `None` for a deposit.
    pub withdrawal: Option<WithdrawalPublic>,
}

impl Transaction {
    pub(crate) fn from_answer(mut answer: Value) -> Result<Self, Error> {
        let withdrawal = match answer.get("publicInputFields") {
            Some(fields) => Some(withdrawal_public(&fields_of(fields)?)?),
            None => None,
        };
        Ok(Transaction { zkapp_command: answer["zkappCommand"].take(), withdrawal })
    }
}

/// The request proof's public inputs, in the circuit's order (`RequestPublic` in
/// `o1js/src/request.ts`): twelve field elements,
/// `[vault.x, vault.isOdd, root, requestTime, tier, nullifier, tag, commitment.x, commitment.y,
///   subsidised, period, periodNullifier]`.
#[derive(Clone, Debug, PartialEq)]
pub struct RequestPublic {
    /// The state key.
    pub vault: CompressedPubKey,
    pub root: Field,
    pub request_time: u64,
    pub tier: u64,
    pub nullifier: Field,
    pub tag: Field,
    /// The re-randomised balance commitment.
    pub commitment: Pallas,
    pub subsidised: bool,
    pub period: u64,
    pub period_nullifier: Field,
}

/// A request proof and its public inputs.
#[derive(Clone, Debug)]
pub struct RequestProof {
    pub public: RequestPublic,
    pub fields: Vec<Field>,
    /// o1js `JsonProof`: what the zk edge receives.
    pub proof: Value,
}

impl RequestProof {
    pub(crate) fn from_answer(mut answer: Value) -> Result<Self, Error> {
        let fields = fields_of(&answer["publicInputFields"])?;
        Ok(RequestProof { public: request_public(&fields)?, fields, proof: answer["proof"].take() })
    }
}

fn fields_of(v: &Value) -> Result<Vec<Field>, Error> {
    v.as_array()
        .ok_or_else(|| Error::Protocol("publicInputFields is not an array".into()))?
        .iter()
        .map(parse_field)
        .collect()
}

fn u64_of(f: Field) -> Result<u64, Error> {
    parse_u64(&json!(dec_field(f)))
}

fn bool_of(f: Field) -> Result<bool, Error> {
    match u64_of(f)? {
        0 => Ok(false),
        1 => Ok(true),
        n => Err(Error::Protocol(format!("not a boolean: {n}"))),
    }
}

fn key_of(x: Field, is_odd: Field) -> Result<CompressedPubKey, Error> {
    Ok(CompressedPubKey { x, is_odd: bool_of(is_odd)? })
}

fn withdrawal_public(f: &[Field]) -> Result<WithdrawalPublic, Error> {
    if f.len() != 13 {
        return Err(Error::Protocol(format!("a withdrawal has 13 public inputs, not {}", f.len())));
    }
    Ok(WithdrawalPublic {
        kind: WithdrawalKind::try_from(u64_of(f[0])?).map_err(|k| Error::Protocol(format!("withdrawal kind {k}")))?,
        vault: key_of(f[1], f[2])?,
        root: f[3],
        nullifier: f[4],
        next_nullifier: f[5],
        amount: u64_of(f[6])?,
        size: u64_of(f[7])?,
        destination: key_of(f[8], f[9])?,
        valid_until: u64_of(f[10])?,
        request_time: u64_of(f[11])?,
        conceded: u64_of(f[12])?,
    })
}

fn request_public(f: &[Field]) -> Result<RequestPublic, Error> {
    if f.len() != 12 {
        return Err(Error::Protocol(format!("a request proof has 12 public inputs, not {}", f.len())));
    }
    Ok(RequestPublic {
        vault: key_of(f[0], f[1])?,
        root: f[2],
        request_time: u64_of(f[3])?,
        tier: u64_of(f[4])?,
        nullifier: f[5],
        tag: f[6],
        commitment: Pallas::new_unchecked(f[7], f[8]),
        subsidised: bool_of(f[9])?,
        period: u64_of(f[10])?,
        period_nullifier: f[11],
    })
}
