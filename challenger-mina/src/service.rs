//! The challenger service, `zk-toon-challenger`: the decision core over [`MinaChain`], the zk edge's
//! evidence file and a journal file, one pass per interval. `docs/challenger-mina.md` documents it.
use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use mina_signer::{CompressedPubKey, SecKey};
use serde_json::{json, Value};
use zk_toon_challenger::service::pass;
use zk_toon_challenger::{Challenger, Config, EscapeId, FileEvidence, FileJournal, PortError, ProofVerifier};
use zk_toon_tx_builder::{node_command, Challenge, Defeat, Error as BuilderError, FeePayer, Raise, TxBuilder};

use crate::{Endpoints, HttpGraphql, MinaChain, Relay, RequestProofs, Settings, TxSource};

/// The environment variable that holds the fee payer's private key (base58, `EK…`). No flag carries
/// it, so it never shows in a process listing.
pub const FEE_PAYER_KEY: &str = "ZK_TOON_FEE_PAYER_KEY";

/// What the service runs with. Prints the fee payer's key as `[secret]`.
#[derive(Clone, Debug)]
pub struct Options {
    pub settings: Settings,
    pub endpoints: Endpoints,
    /// The zk edge's evidence file.
    pub evidence: PathBuf,
    /// The challenger's journal: every escape seen and action taken, for restarts.
    pub journal: PathBuf,
    /// The o1js package, with its dependencies installed, that runs the transaction builder.
    pub o1js: PathBuf,
    pub config: Config,
    /// The pause between two passes.
    pub interval: Duration,
}

const USAGE: &str = "zk-toon-challenger --vault <B62…> --mina <url> --archive <url> --evidence <file> \
--journal <file> --o1js <dir> [--socks5 <host:port>] [--fee <nanomina>] [--min-lead <slots>] \
[--interval <s>] [--poll <s>] [--timeout <s>], with the fee payer's key in ZK_TOON_FEE_PAYER_KEY";

impl Options {
    /// Reads the flags in `args` (without the program name) and the fee payer's key, the value of
    /// [`FEE_PAYER_KEY`]. An error names the flag or variable at fault.
    pub fn parse(args: &[String], fee_payer_key: Option<String>) -> Result<Options, String> {
        let mut flags: Vec<(&str, &str)> = Vec::new();
        let mut rest = args.iter();
        while let Some(flag) = rest.next() {
            let known = [
                "--vault", "--mina", "--archive", "--evidence", "--journal", "--o1js", "--socks5", "--fee",
                "--min-lead", "--interval", "--poll", "--timeout",
            ];
            if !known.contains(&flag.as_str()) {
                return Err(format!("unknown flag {flag}; usage: {USAGE}"));
            }
            let value = rest.next().ok_or_else(|| format!("{flag} needs a value"))?;
            flags.push((flag, value));
        }
        let get = |flag: &str| flags.iter().rev().find(|(f, _)| *f == flag).map(|(_, v)| v.to_string());
        let need = |flag: &str| get(flag).ok_or_else(|| format!("{flag} is required; usage: {USAGE}"));
        let number = |flag: &str, default: u64| -> Result<u64, String> {
            get(flag).map_or(Ok(default), |v| v.parse().map_err(|_| format!("{flag} is a whole number, not {v:?}")))
        };
        let seconds = |flag: &str, default: u64| number(flag, default).map(Duration::from_secs);

        let vault = need("--vault")?;
        let vault = CompressedPubKey::from_address(&vault).map_err(|_| format!("--vault is not a B62 address: {vault:?}"))?;
        let private_key = fee_payer_key.ok_or_else(|| format!("{FEE_PAYER_KEY} must hold the fee payer's private key"))?;
        if SecKey::from_base58(&private_key).is_err() {
            return Err(format!("{FEE_PAYER_KEY} is not a base58 private key"));
        }
        Ok(Options {
            settings: Settings {
                vault,
                fee_payer: FeePayer { private_key, fee: number("--fee", 100_000_000)? },
                poll: seconds("--poll", 10)?,
            },
            endpoints: Endpoints {
                mina: need("--mina")?,
                archive: need("--archive")?,
                socks5: get("--socks5"),
                timeout: seconds("--timeout", 30)?,
            },
            evidence: need("--evidence")?.into(),
            journal: need("--journal")?.into(),
            o1js: need("--o1js")?.into(),
            config: Config { min_lead: number("--min-lead", 40)? },
            interval: seconds("--interval", 60)?,
        })
    }
}

/// Runs the challenger, printing each pass's lines to stdout. Returns an error if it can't start, or
/// once the transaction builder's process is unreachable (it has died, or answers out of turn): the
/// service then exits for its supervisor to restart it, and the journal makes the restart safe.
pub fn run(options: Options) -> Result<(), String> {
    let graphql = Arc::new(HttpGraphql::new(options.endpoints.clone())?);
    let relay = Relay::start(graphql.clone()).map_err(|e| format!("relay: {e}"))?;
    let (mina, archive) = (relay.mina_url(), relay.archive_url());
    let builder = TxBuilder::spawn(node_command(&options.o1js, &["--mina", &mina, "--archive", &archive]))
        .map_err(|e| format!("transaction builder: {e}"))?;
    let builder = SharedBuilder(Rc::new(RefCell::new(builder)), Rc::default());
    let evidence = Rc::new(FileEvidence::new(&options.evidence, BuilderVerifier(builder.clone())));
    let chain = MinaChain::new(options.settings.clone(), graphql, builder.clone(), evidence.clone())
        .map_err(|e| format!("{e:?}"))?;
    let journal = FileJournal::open(&options.journal).map_err(|e| format!("{e:?}"))?;
    let mut challenger = Challenger::new(chain, evidence, journal, options.config.clone());
    loop {
        let now = challenger.chain.now();
        for line in pass(&mut challenger, now) {
            println!("{line}");
        }
        if let Some(why) = builder.1.take() {
            return Err(format!("transaction builder unreachable, exiting: {why}"));
        }
        sleep(options.interval);
    }
}

/// The transaction builder, shared by the verifier and the chain port. A pass verifies evidence
/// and submits one after the other, never at once. The second field holds why the builder became
/// unreachable, if it did.
#[derive(Clone)]
struct SharedBuilder(Rc<RefCell<TxBuilder>>, Rc<Cell<Option<String>>>);

impl SharedBuilder {
    fn call<A>(&self, f: impl FnOnce(&mut TxBuilder) -> Result<A, BuilderError>) -> Result<A, BuilderError> {
        let answer = f(&mut self.0.borrow_mut());
        if let Err(e @ (BuilderError::Io(_) | BuilderError::Protocol(_))) = &answer {
            self.1.set(Some(e.to_string()));
        }
        answer
    }
}

impl TxSource for SharedBuilder {
    fn defeat(&mut self, d: &Defeat) -> Result<Challenge, BuilderError> {
        self.call(|b| b.defeat(d))
    }
    fn raise(&mut self, r: &Raise) -> Result<Challenge, BuilderError> {
        self.call(|b| b.raise(r))
    }
}

/// Verifies a recorded request proof against the verification key the builder compiles. The subsidy
/// period isn't checked: that is the zk edge's to check when it grants, and any proof defeats (ADR 0001).
struct BuilderVerifier(SharedBuilder);

impl ProofVerifier for BuilderVerifier {
    fn verifies(&self, proof: &[u8]) -> Result<bool, PortError> {
        let Ok(proof) = serde_json::from_slice::<Value>(proof) else { return Ok(false) };
        let answer = self
            .0
            .call(|b| b.call("verifyRequestProof", json!({ "proof": proof })))
            .map_err(|e| PortError::Unavailable(format!("transaction builder: {e}")))?;
        answer["valid"].as_bool().ok_or_else(|| PortError::Unavailable("transaction builder: valid is not a boolean".into()))
    }
}

/// The evidence file's proofs as the evidence a defeat or raise carries.
impl<V: ProofVerifier> RequestProofs for Rc<FileEvidence<V>> {
    fn at(&self, nullifier: &EscapeId) -> Result<Vec<Value>, PortError> {
        self.proofs_at(nullifier)?
            .iter()
            .map(|p| serde_json::from_slice(p).map_err(|_| PortError::Refused("a recorded proof is not JSON".into())))
            .collect()
    }
}
