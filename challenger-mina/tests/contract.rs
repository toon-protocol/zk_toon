//! Seam 3: the Mina adapter passes the vault chain port's contract suite, the same one the in-memory
//! fake passes. Its chain answers in the shapes of a recorded vault (`fixtures/recorded-vault.json`,
//! pinned by its SHA-256), with the escapes each case asks for.
mod common;

use common::*;
use zk_toon_challenger::contract::{self, Harness};
use zk_toon_challenger::{Escape, Millis};

struct OverScriptedMina;

impl Harness for OverScriptedMina {
    type Port = ScriptedChain;
    fn port(now: Millis, escapes: Vec<Escape>) -> ScriptedChain {
        adapter(&Scripted::new(now, &escapes))
    }
}

#[test]
fn the_mina_adapter_passes_the_vault_chain_port_contract() {
    contract::run::<OverScriptedMina>();
}
