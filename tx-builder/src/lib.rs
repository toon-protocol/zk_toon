//! The Rust client of the o1js transaction builder, `o1js/src/tx-builder-main.ts`.
//!
//! A Mina zkApp call needs a transaction proof that only o1js can make, so this is the one place
//! Rust reaches o1js. The builder is a Node process speaking newline-delimited JSON on stdin and
//! stdout; [`TxBuilder`] starts it and sends one request at a time. The requests, the answers and
//! the failure answers are documented in `docs/tx-builder.md`.
//!
//! Secrets (a note's secret, its state's blinding, a re-randomising blinding and the fee payer's
//! private key) go only to the builder's stdin. The types that hold them print as `[secret]`.
//! The builder never logs them or writes them to disk.
use std::fmt;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::str::FromStr;

use ark_ff::PrimeField;
use mina_signer::{CompressedPubKey, Signature};
use serde_json::{json, Value};
use zk_note::balance::Scalar;
use zk_note::Field;

mod local;
mod requests;

pub use local::{LocalAccount, LocalChain};
pub use requests::*;

/// The command that runs the builder from the o1js package at `o1js_dir`, which must have its
/// dependencies installed (`npm ci`). `args` are the builder's flags, e.g. `--local`,
/// `--proofs=off`, or `--mina <url> --archive <url>`.
pub fn node_command(o1js_dir: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new("node");
    cmd.current_dir(o1js_dir).args(["--import", "tsx", "src/tx-builder-main.ts"]).args(args);
    cmd
}

/// Why a request failed.
#[derive(Debug)]
pub enum Error {
    /// The builder answered with a failure answer.
    Failure { kind: FailureKind, message: String },
    /// The builder's process could not be reached.
    Io(io::Error),
    /// The builder answered something that is not a valid answer.
    Protocol(String),
}

/// The `error.kind` of a failure answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FailureKind {
    /// The request was malformed, named an unknown operation, or named a note the vault doesn't hold.
    BadInput,
    /// A circuit or a vault method refused the inputs, or proving failed.
    ProvingFailed,
    /// The builder could not read the vault from the chain.
    ChainUnavailable,
    /// The local chain refused a submitted transaction (`--local` only).
    Rejected,
    /// A kind this client doesn't know.
    Other(String),
}

impl FailureKind {
    fn parse(kind: &str) -> Self {
        match kind {
            "badInput" => Self::BadInput,
            "provingFailed" => Self::ProvingFailed,
            "chainUnavailable" => Self::ChainUnavailable,
            "rejected" => Self::Rejected,
            other => Self::Other(other.to_string()),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Failure { kind, message } => write!(f, "{kind:?}: {message}"),
            Error::Io(e) => write!(f, "transaction builder unreachable: {e}"),
            Error::Protocol(m) => write!(f, "transaction builder protocol: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

/// A running builder process. Requests are answered in order, one at a time.
pub struct TxBuilder {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl TxBuilder {
    /// Starts `cmd` with piped stdin and stdout. Its stderr is left as `cmd` sets it.
    pub fn spawn(mut cmd: Command) -> io::Result<Self> {
        let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).spawn()?;
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
        Ok(TxBuilder { child, stdin, stdout, next_id: 0 })
    }

    /// Sends one request and waits for its answer. Returns the answer's `result`.
    pub fn call(&mut self, op: &str, params: Value) -> Result<Value, Error> {
        self.next_id += 1;
        let id = self.next_id;
        let line = json!({ "id": id, "op": op, "params": params }).to_string();
        self.send_line(&line)?;
        let answer = self.read_answer()?;
        if answer["id"] != json!(id) {
            return Err(Error::Protocol(format!("answer to request {} while waiting for {id}", answer["id"])));
        }
        answer_result(answer)
    }

    /// Sends a raw line, as a caller in another language would. For testing the builder.
    pub fn call_raw(&mut self, line: &str) -> Result<Value, Error> {
        self.send_line(line)?;
        let answer = self.read_answer()?;
        answer_result(answer)
    }

    fn send_line(&mut self, line: &str) -> Result<(), Error> {
        self.stdin.write_all(line.as_bytes())?;
        self.stdin.write_all(b"\n")?;
        self.stdin.flush()?;
        Ok(())
    }

    fn read_answer(&mut self) -> Result<Value, Error> {
        let mut line = String::new();
        if self.stdout.read_line(&mut line)? == 0 {
            return Err(Error::Protocol("the builder closed its stdout".into()));
        }
        serde_json::from_str(&line).map_err(|e| Error::Protocol(format!("not JSON: {e}")))
    }

    /// The operations only a builder started with `--local` answers.
    pub fn local(&mut self) -> LocalChain<'_> {
        LocalChain(self)
    }

    /// A proved, signed deposit transaction.
    pub fn deposit(&mut self, d: &Deposit) -> Result<Transaction, Error> {
        Transaction::from_answer(self.call("deposit", d.to_json())?)
    }

    /// A proved, signed mutual-close transaction.
    pub fn mutual_close(&mut self, c: &MutualClose) -> Result<Transaction, Error> {
        Transaction::from_answer(self.call("mutualClose", c.to_json())?)
    }

    /// A proved, signed escape transaction.
    pub fn escape(&mut self, e: &Escape) -> Result<Transaction, Error> {
        Transaction::from_answer(self.call("escape", e.to_json())?)
    }

    /// A proved, signed defeat transaction.
    pub fn defeat(&mut self, d: &Defeat) -> Result<Challenge, Error> {
        Challenge::from_answer(self.call("defeat", d.to_json())?)
    }

    /// A proved, signed raise transaction.
    pub fn raise(&mut self, r: &Raise) -> Result<Challenge, Error> {
        Challenge::from_answer(self.call("raise", r.to_json())?)
    }

    /// A request proof for an allowance.
    pub fn request_proof(&mut self, r: &RequestProofInput) -> Result<RequestProof, Error> {
        RequestProof::from_answer(self.call("requestProof", r.to_json())?)
    }

    /// Whether `proof` verifies against the request proof's verification key, as the builder
    /// compiles it, and, given the vault's creation time, whether its period is that vault's
    /// ([`zk_note::request::RequestPublic::check_subsidy_period`]), which a zk edge must check.
    pub fn verify_request_proof(&mut self, proof: &RequestProof, vault_creation: Option<u64>) -> Result<bool, Error> {
        let mut params = json!({ "proof": proof.proof });
        if let Some(c) = vault_creation {
            params["vaultCreation"] = json!(c.to_string());
        }
        let answer = self.call("verifyRequestProof", params)?;
        answer["valid"].as_bool().ok_or_else(|| Error::Protocol("valid is not a boolean".into()))
    }
}

impl Drop for TxBuilder {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn answer_result(mut answer: Value) -> Result<Value, Error> {
    match answer["ok"].as_bool() {
        Some(true) => Ok(answer["result"].take()),
        Some(false) => {
            let e = &answer["error"];
            Err(Error::Failure {
                kind: FailureKind::parse(e["kind"].as_str().unwrap_or("")),
                message: e["message"].as_str().unwrap_or("").to_string(),
            })
        }
        None => Err(Error::Protocol(format!("answer without ok: {answer}"))),
    }
}

// The interface's encodings: field elements, scalars and 64-bit amounts and times are decimal
// strings; public keys are base58 addresses.

pub(crate) fn dec_field(f: Field) -> String {
    f.into_bigint().to_string()
}

pub(crate) fn dec_scalar(s: Scalar) -> String {
    s.into_bigint().to_string()
}

pub(crate) fn sig_json(s: &Signature) -> Value {
    json!({ "r": dec_field(s.rx), "s": dec_scalar(s.s) })
}

pub(crate) fn parse_field(v: &Value) -> Result<Field, Error> {
    v.as_str()
        .and_then(|s| Field::from_str(s).ok())
        .ok_or_else(|| Error::Protocol(format!("not a decimal field element: {v}")))
}

pub(crate) fn parse_u64(v: &Value) -> Result<u64, Error> {
    v.as_str()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::Protocol(format!("not a 64-bit decimal: {v}")))
}

pub(crate) fn parse_key(v: &Value) -> Result<CompressedPubKey, Error> {
    v.as_str()
        .and_then(|s| CompressedPubKey::from_address(s).ok())
        .ok_or_else(|| Error::Protocol(format!("not a public key: {v}")))
}
