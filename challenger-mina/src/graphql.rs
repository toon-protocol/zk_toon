//! The GraphQL the adapter speaks: the Mina daemon's (account state, chain time, `sendZkapp`, a
//! transaction's inclusion) and the archive node API's (the vault's events). Every request is a named
//! operation with variables, so a recorded or local stand-in can answer it by name.
use serde_json::{json, Value};

/// Which GraphQL endpoint a request is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// The Mina daemon's GraphQL.
    Mina,
    /// The archive node API's GraphQL.
    Archive,
}

/// Something that answers GraphQL requests: over HTTP ([`crate::HttpGraphql`]), or a stand-in.
pub trait Graphql {
    /// Posts `request` (`{"query", "operationName", "variables"}`) and returns the response body
    /// (`{"data", "errors"}`). `Err` when no response was read: the connection failed or dropped, or
    /// the body is not JSON.
    fn post(&self, endpoint: Endpoint, request: &Value) -> Result<Value, String>;
}

/// How many blocks back a submitted transaction is looked for: Mina's transition frontier, `k`.
pub const FRONTIER_BLOCKS: u32 = 290;

fn op(name: &str, query: &str, variables: Value) -> Value {
    json!({ "operationName": name, "query": query, "variables": variables })
}

/// Daemon: the vault's app state and the chain tip's block time.
pub fn vault_state(vault: &str) -> Value {
    op(
        "VaultState",
        "query VaultState($vault: PublicKey!) { account(publicKey: $vault) { zkappState } \
         bestChain(maxLength: 1) { protocolState { blockchainState { utcDate } } } }",
        json!({ "vault": vault }),
    )
}

/// Archive: every event the vault emitted, with the block and transaction status of each.
pub fn escape_events(vault: &str) -> Value {
    op(
        "EscapeEvents",
        "query EscapeEvents($vault: String!) { events(input: { address: $vault }) { \
         blockInfo { height chainStatus } eventData { data transactionInfo { hash status } } } }",
        json!({ "vault": vault }),
    )
}

/// Daemon: send a zkApp command.
pub fn send_zkapp(zkapp_command: &Value) -> Value {
    op(
        "SendChallenge",
        "mutation SendChallenge($input: SendZkappInput!) { sendZkapp(input: $input) { zkapp { hash } } }",
        json!({ "input": { "zkappCommand": zkapp_command } }),
    )
}

/// Daemon: the zkApp commands of the frontier's blocks, with their failures, the chain time, and the
/// fee payer's commands still in the pool.
pub fn challenge_status(fee_payer: &str) -> Value {
    op(
        "ChallengeStatus",
        &format!(
            "query ChallengeStatus($feePayer: PublicKey!) {{ bestChain(maxLength: {FRONTIER_BLOCKS}) {{ \
             transactions {{ zkappCommands {{ hash failureReason {{ failures index }} }} }} \
             protocolState {{ blockchainState {{ utcDate }} }} }} \
             pooledZkappCommands(publicKey: $feePayer) {{ hash }} }}"
        ),
        json!({ "feePayer": fee_payer }),
    )
}

/// The response's `data`, or its errors' messages joined.
pub fn data(response: &Value) -> Result<&Value, String> {
    if let Some(errors) = response.get("errors").and_then(Value::as_array) {
        if !errors.is_empty() {
            let messages: Vec<&str> = errors.iter().map(|e| e["message"].as_str().unwrap_or("(no message)")).collect();
            return Err(messages.join("; "));
        }
    }
    match response.get("data") {
        Some(d) if !d.is_null() => Ok(d),
        _ => Err("a response without data".into()),
    }
}

/// A decimal string's value: Mina GraphQL's encoding of block times, amounts and lengths.
pub fn decimal(v: &Value) -> Option<u64> {
    v.as_str().and_then(|s| s.parse().ok())
}
