//! Reading the vault's escapes: from a recorded vault, and never from an archive that disagrees with
//! the vault's root.
mod common;

use std::time::Duration;

use common::*;
use serde_json::Value;
use zk_toon_challenger::{PortError, VaultChainPort};
use zk_toon_challenger_mina::{Endpoint, Graphql, MinaChain, Settings};

/// Answers with the recorded responses, as the chain gave them.
struct Recorded;

impl Graphql for Recorded {
    fn post(&self, _: Endpoint, request: &Value) -> Result<Value, String> {
        let fixture = fixture();
        match request["operationName"].as_str() {
            Some("VaultState") => Ok(fixture["vaultState"].clone()),
            Some("EscapeEvents") => Ok(fixture["escapeEvents"].clone()),
            other => Err(format!("not recorded: {other:?}")),
        }
    }
}

const MINA: u64 = 1_000_000_000;

#[test]
fn the_recorded_vault_holds_one_open_escape_as_its_note_escaped() {
    let settings = Settings { vault: vault_key(), fee_payer: fee_payer(), poll: Duration::ZERO };
    let port = MinaChain::new(settings, Recorded, Scripted::default(), AnyProof).unwrap();
    let escapes = port.escapes().unwrap();
    // The recording (`local_chain.rs`): a note escaped at a signed balance of 3 MINA conceding 0.01
    // MINA, then raised to 0.5 MINA; and a second escape, defeated.
    assert_eq!(escapes.len(), 1);
    assert_eq!((escapes[0].balance, escapes[0].conceded), (3 * MINA, MINA / 2));
    let recorded = fixture();
    let now: u64 = recorded["vaultState"]["data"]["bestChain"][0]["protocolState"]["consensusState"]["slotSinceGenesis"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    // A full challenge window, from a reduce at most a slot before `now`.
    let window = zk_note::policy::CHALLENGE_WINDOW_SLOTS;
    assert!(escapes[0].deadline > now + window - 1 && escapes[0].deadline <= now + window + 1);
}

/// The scripted chain, with the archive missing the last event.
struct Lagging(Scripted);

impl Graphql for Lagging {
    fn post(&self, endpoint: Endpoint, request: &Value) -> Result<Value, String> {
        let mut response = self.0.post(endpoint, request)?;
        if request["operationName"] == "EscapeEvents" {
            response["data"]["events"].as_array_mut().unwrap().pop();
        }
        Ok(response)
    }
}

#[test]
fn an_archive_that_does_not_rebuild_the_vaults_root_is_unavailable_not_trusted() {
    let mut a = [1u8; 32];
    a[31] = 0;
    let mut b = [2u8; 32];
    b[31] = 0;
    let escapes = vec![
        zk_toon_challenger::Escape { id: a, next_nullifier: b, conceded: 0, balance: 50, deadline: 1_000 },
        zk_toon_challenger::Escape { id: b, next_nullifier: a, conceded: 0, balance: 50, deadline: 1_000 },
    ];
    let chain = Scripted::new(10, &escapes);
    let settings = Settings { vault: vault_key(), fee_payer: fee_payer(), poll: Duration::ZERO };
    let port = MinaChain::new(settings, Lagging(chain.clone()), chain, AnyProof).unwrap();
    assert!(matches!(port.escapes(), Err(PortError::Unavailable(_))));
}

fn escape_with_deadline(deadline: u64) -> zk_toon_challenger::Escape {
    let mut id = [1u8; 32];
    id[31] = 0;
    let mut next = [2u8; 32];
    next[31] = 0;
    zk_toon_challenger::Escape { id, next_nullifier: next, conceded: 0, balance: 50, deadline }
}

/// How many escapes the adapter reports open, at a tip whose slot is `now`.
fn open_at(now: u64, deadline: u64) -> usize {
    let e = escape_with_deadline(deadline);
    let chain = Scripted::new(now, &[e]);
    let settings = Settings { vault: vault_key(), fee_payer: fee_payer(), poll: Duration::ZERO };
    let port = MinaChain::new(settings, TipWithClock(chain.clone()), chain, AnyProof).unwrap();
    port.escapes().unwrap().len()
}

/// The scripted chain's tip, as the daemon answers it: a realistic `utcDate` in milliseconds, which
/// is nowhere near a slot, beside the slot.
struct TipWithClock(Scripted);

impl Graphql for TipWithClock {
    fn post(&self, endpoint: Endpoint, request: &Value) -> Result<Value, String> {
        let mut response = self.0.post(endpoint, request)?;
        if request["operationName"] == "VaultState" {
            response["data"]["bestChain"][0]["protocolState"]["blockchainState"] = serde_json::json!({ "utcDate": "1793243264164" });
        }
        Ok(response)
    }
}

#[test]
fn an_escape_is_open_while_the_tips_slot_is_below_its_deadline_whatever_the_block_time() {
    let deadline = 930_000;
    assert_eq!(open_at(deadline - 1, deadline), 1, "open one slot before the deadline");
    assert_eq!(open_at(deadline, deadline), 0, "not open at the deadline");
    assert_eq!(open_at(deadline + 1, deadline), 0, "not open after it");
}

#[test]
fn the_chain_time_is_the_recorded_tip_slot() {
    let settings = Settings { vault: vault_key(), fee_payer: fee_payer(), poll: Duration::ZERO };
    let port = MinaChain::new(settings, Recorded, Scripted::default(), AnyProof).unwrap();
    let tip = fixture()["vaultState"]["data"]["bestChain"][0]["protocolState"]["consensusState"]["slotSinceGenesis"]
        .as_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert_eq!(port.now().unwrap(), tip);
}

#[test]
fn the_state_key_is_the_one_the_recorded_vault_was_set_up_with() {
    let settings = Settings { vault: vault_key(), fee_payer: fee_payer(), poll: Duration::ZERO };
    let port = MinaChain::new(settings, Recorded, Scripted::default(), AnyProof).unwrap();
    // `local_chain.rs` recorded a vault set up with `keypair(4242)` as its state key.
    assert_eq!(port.state_key().unwrap(), keypair(4242).public.into_compressed());
}
