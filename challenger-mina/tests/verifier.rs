//! Evidence is checked against this vault's state key before its proof is: a proof made under another
//! key would only ever be refused by the vault, so it reads as not verifying, and the challenger alarms.
mod common;

use std::cell::Cell;
use std::rc::Rc;

use common::keypair;
use mina_signer::CompressedPubKey;
use zk_toon_challenger::{PortError, ProofVerifier};
use zk_toon_challenger_mina::service::ForStateKey;

/// Answers `self.0` and counts how often it was asked.
struct Inner(bool, Rc<Cell<usize>>);
impl ProofVerifier for Inner {
    fn verifies(&self, _: &[u8]) -> Result<bool, PortError> {
        self.1.set(self.1.get() + 1);
        Ok(self.0)
    }
}

fn proof_under(key: &CompressedPubKey) -> Vec<u8> {
    let odd = if key.is_odd { "1" } else { "0" };
    let x = key.x.to_string();
    let input = [x.as_str(), odd, "5", "1000", "10", "11", "9", "3", "4", "0", "0", "0"];
    let input: Vec<String> = input.iter().map(|s| format!("\"{s}\"")).collect();
    format!("{{\"publicInput\":[{}],\"publicOutput\":[],\"maxProofsVerified\":0,\"proof\":\"p\"}}", input.join(","))
        .into_bytes()
}

#[test]
fn a_proof_under_the_state_key_is_as_the_proof_verifies() {
    let key = keypair(4242).public.into_compressed();
    for answer in [true, false] {
        let asked = Rc::new(Cell::new(0));
        let v = ForStateKey { state_key: key.clone(), inner: Inner(answer, asked.clone()) };
        assert_eq!(v.verifies(&proof_under(&key)).unwrap(), answer);
        assert_eq!(asked.get(), 1);
    }
}

#[test]
fn a_proof_under_another_key_does_not_verify() {
    let asked = Rc::new(Cell::new(0));
    let v = ForStateKey { state_key: keypair(4242).public.into_compressed(), inner: Inner(true, asked.clone()) };
    assert!(!v.verifies(&proof_under(&keypair(7).public.into_compressed())).unwrap());
    assert!(!v.verifies(b"not json").unwrap());
    assert!(!v.verifies(b"{}").unwrap());
    assert_eq!(asked.get(), 0);
}
