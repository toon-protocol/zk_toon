//! The operations of a builder started with `--local`, which hosts its own o1js LocalBlockchain:
//! for tests that show the vault accepts what the builder builds.
use mina_signer::CompressedPubKey;
use serde_json::{json, Value};

use crate::{parse_key, parse_u64, Error, Transaction, TxBuilder};

/// A funded account of the local chain. Its key is a test key, not a secret.
#[derive(Clone, Debug)]
pub struct LocalAccount {
    pub public_key: CompressedPubKey,
    /// Base58.
    pub private_key: String,
}

/// The local chain's operations, borrowed from a [`TxBuilder`].
pub struct LocalChain<'a>(pub(crate) &'a mut TxBuilder);

impl LocalChain<'_> {
    /// The chain's funded test accounts.
    pub fn accounts(&mut self) -> Result<Vec<LocalAccount>, Error> {
        let answer = self.0.call("local.accounts", json!({}))?;
        answer["accounts"]
            .as_array()
            .ok_or_else(|| Error::Protocol("accounts is not an array".into()))?
            .iter()
            .map(|a| {
                Ok(LocalAccount {
                    public_key: parse_key(&a["publicKey"])?,
                    private_key: a["privateKey"].as_str().unwrap_or_default().to_string(),
                })
            })
            .collect()
    }

    /// Deploys and sets up a fresh vault with `state_key` and `treasury`; returns its address.
    pub fn deploy_vault(&mut self, state_key: &CompressedPubKey, treasury: &CompressedPubKey) -> Result<CompressedPubKey, Error> {
        let answer = self.0.call(
            "local.deployVault",
            json!({ "stateKey": state_key.into_address(), "treasury": treasury.into_address() }),
        )?;
        parse_key(&answer["vault"])
    }

    /// Sends a transaction to the local chain. A refusal is a [`crate::FailureKind::Rejected`] failure.
    pub fn submit(&mut self, tx: &Transaction) -> Result<(), Error> {
        self.0.call("local.submit", json!({ "zkappCommand": tx.zkapp_command })).map(|_| ())
    }

    /// Reduces every pending action of `vault`, as a keeper would.
    pub fn reduce(&mut self, vault: &CompressedPubKey) -> Result<(), Error> {
        self.0.call("local.reduce", json!({ "vault": vault.into_address() })).map(|_| ())
    }

    /// Moves the chain's clock forward by at least `ms`.
    pub fn advance(&mut self, ms: u64) -> Result<(), Error> {
        self.0.call("local.advance", json!({ "ms": ms.to_string() })).map(|_| ())
    }

    /// The chain's current block time, in ms.
    pub fn now(&mut self) -> Result<u64, Error> {
        parse_u64(&self.0.call("local.now", json!({}))?["now"])
    }

    /// An account's balance, in nanomina.
    pub fn balance(&mut self, account: &CompressedPubKey) -> Result<u64, Error> {
        parse_u64(&self.0.call("local.balance", json!({ "publicKey": account.into_address() }))?["balance"])
    }

    /// Answers one of the challenger adapter's named GraphQL operations from the local chain, in the
    /// shape the Mina daemon (`endpoint` `"mina"`) or the archive node API (`"archive"`) answers it.
    /// A refused `sendZkapp` is a GraphQL error, as from a daemon.
    pub fn graphql(&mut self, endpoint: &str, request: &Value) -> Result<Value, Error> {
        self.0.call("local.graphql", json!({ "endpoint": endpoint, "request": request }))
    }

    /// The vault's on-chain state, by field name, as decimal strings (keys as base58).
    pub fn vault_state(&mut self, vault: &CompressedPubKey) -> Result<Value, Error> {
        self.0.call("local.vaultState", json!({ "vault": vault.into_address() }))
    }
}
