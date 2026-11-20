//! Signs a full commitment 2-of-3, for `o1js/src/upgrade-key.lightnet.ts`, which runs it.
//!
//! Reads JSON from stdin: `secretKey` (base58, a test key), `commitment` (a decimal field element) and
//! `network` (`testnet` or `mainnet`). The key is split by the trusted dealer, as in the tests, and holders 1 and 3
//! sign. Writes the signature as `{"r", "s"}`, the shape the transaction builder takes.

use std::collections::BTreeMap;

use mina_signer::{BaseField, NetworkId, SecKey};
use rand_core::OsRng;
use upgrade_key::{aggregate, dealer, holder, round1, round2, signature_json, Message};

fn main() -> anyhow::Result<()> {
    let v: serde_json::Value = serde_json::from_reader(std::io::stdin())?;
    let text = |k: &str| v[k].as_str().ok_or_else(|| anyhow::anyhow!("missing {k}"));
    let secret = SecKey::from_base58(text("secretKey")?).map_err(|e| anyhow::anyhow!("secretKey: {e:?}"))?;
    let commitment: BaseField = text("commitment")?.parse().map_err(|_| anyhow::anyhow!("bad commitment"))?;
    let network = match text("network")? {
        "testnet" => NetworkId::TESTNET,
        "mainnet" => NetworkId::MAINNET,
        other => anyhow::bail!("network: {other}"),
    };

    let mut rng = OsRng;
    let (keys, public) = dealer::split(&secret, &mut rng).map_err(|e| anyhow::anyhow!("split: {e:?}"))?;
    let message = Message::new(commitment, network);
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for n in [1, 3] {
        let id = holder(n).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let (signing_nonces, signing_commitments) = round1::commit(&keys[&id], &mut rng);
        nonces.insert(id, signing_nonces);
        commitments.insert(id, signing_commitments);
    }
    let package = round2::package(commitments, &message);
    let mut shares = BTreeMap::new();
    for (id, signing_nonces) in nonces {
        shares.insert(id, round2::sign(&package, signing_nonces, &keys[&id]).map_err(|e| anyhow::anyhow!("{e:?}"))?);
    }
    let signature = aggregate(&package, &message, &shares, &public).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    println!("{}", signature_json(&signature));
    Ok(())
}
