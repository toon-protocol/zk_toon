//! The upgrade key's 2-of-3 signature authorises a vault's delegation and a verification-key install,
//! which the builder prepares and attaches, never holding a key share. Proofs are off; the local chain
//! still checks every signature.
mod common;

use std::collections::BTreeMap;

use common::*;
use mina_signer::{BaseField, CompressedPubKey, NetworkId, SecKey, Signature};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use upgrade_key::{aggregate, dealer, holder, public_key, round1, round2, Identifier, KeyPackage, Message, PublicKeyPackage};
use zk_note::Field;
use zk_toon_tx_builder::{Attachment, Delegation, Error, FailureKind, FeePayerAddress, KeyInstall, Prepared, TxBuilder};

/// A 2-of-3 key split from `secret`, which stands in for a DKG key: the registry needs the whole key's
/// signature once, when it deploys the vault at the key's address.
struct UpgradeKey {
    secret: SecKey,
    keys: BTreeMap<Identifier, KeyPackage>,
    public: PublicKeyPackage,
    rng: ChaCha20Rng,
}

impl UpgradeKey {
    fn new(seed: u64) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let secret = SecKey::rand(&mut rng);
        let (keys, public) = dealer::split(&secret, &mut rng).unwrap();
        UpgradeKey { secret, keys, public, rng }
    }

    fn address(&self) -> CompressedPubKey {
        public_key(&self.public).unwrap().into_compressed()
    }

    /// Holders 1 and 3 sign `commitment` for `network`.
    fn sign(&mut self, commitment: Field, network: &NetworkId) -> Signature {
        let message = Message::new(commitment, network.clone());
        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        for n in [1, 3] {
            let id = holder(n).unwrap();
            let (n_, c) = round1::commit(&self.keys[&id], &mut self.rng);
            nonces.insert(id, n_);
            commitments.insert(id, c);
        }
        let package = round2::package(commitments, &message);
        let shares: BTreeMap<_, _> =
            nonces.into_iter().map(|(id, n)| (id, round2::sign(&package, n, &self.keys[&id]).unwrap())).collect();
        aggregate(&package, &message, &shares, &self.public).unwrap()
    }
}

fn prepared_delegation(b: &mut TxBuilder, vault: &CompressedPubKey, delegate: &CompressedPubKey, payer: &FeePayerAddress) -> Prepared {
    b.prepare_delegation(&Delegation {
        vault: vault.clone(),
        delegate: delegate.clone(),
        fee_payer: payer.clone(),
        network: NetworkId::TESTNET,
    })
    .unwrap()
}

/// The local chain's first account, which pays, and its second, which the vault is delegated to.
fn accounts(b: &mut TxBuilder) -> (zk_toon_tx_builder::FeePayer, FeePayerAddress, CompressedPubKey) {
    let accounts = b.local().accounts().unwrap();
    let payer = zk_toon_tx_builder::FeePayer { private_key: accounts[0].private_key.clone(), fee: 0 };
    let address = FeePayerAddress { public_key: accounts[0].public_key.clone(), fee: 0 };
    (payer, address, accounts[1].public_key.clone())
}

fn attachment(prepared: Prepared, signature: Signature, payer: &zk_toon_tx_builder::FeePayer) -> Attachment {
    Attachment { prepared, signature, fee_payer: payer.clone() }
}

fn rejected(e: Error) -> bool {
    matches!(e, Error::Failure { kind: FailureKind::Rejected, .. })
}

#[test]
fn a_delegation_signed_two_of_three_is_accepted_and_the_delegate_changes() {
    let mut b = local_builder(false);
    let mut upgrade = UpgradeKey::new(1);
    let vault = b.local().deploy_registered_vault(&upgrade.secret.to_base58()).unwrap();
    assert_eq!(vault, upgrade.address());
    let (payer, payer_address, alice) = accounts(&mut b);
    assert_ne!(b.local().delegate(&vault).unwrap(), Some(alice.clone()));

    let prepared = prepared_delegation(&mut b, &vault, &alice, &payer_address);
    let signature = upgrade.sign(prepared.full_commitment, &NetworkId::TESTNET);
    let tx = b.attach_delegation(&attachment(prepared, signature, &payer)).unwrap();
    b.local().submit(&tx).unwrap();
    assert_eq!(b.local().delegate(&vault).unwrap(), Some(alice));
}

#[test]
fn a_key_install_signed_two_of_three_is_accepted_and_the_key_is_the_installed_one() {
    let mut b = local_builder(false);
    let mut upgrade = UpgradeKey::new(2);
    let account = b.local().deploy_stand_in(&upgrade.secret.to_base58()).unwrap();
    assert_eq!(account, upgrade.address());
    let (payer, payer_address, _) = accounts(&mut b);
    let key = b.local().compile_key().unwrap();
    assert!(b.local().verification_key(&account).unwrap().is_none());

    let prepared = b
        .prepare_key_install(&KeyInstall {
            account: account.clone(),
            verification_key: key.clone(),
            fee_payer: payer_address,
            network: NetworkId::TESTNET,
        })
        .unwrap();
    let signature = upgrade.sign(prepared.full_commitment, &NetworkId::TESTNET);
    let tx = b.attach_key_install(&attachment(prepared, signature, &payer)).unwrap();
    b.local().submit(&tx).unwrap();
    let installed = b.local().verification_key(&account).unwrap().expect("a key is installed");
    assert_eq!((installed.data, installed.hash), (key.data, key.hash));
}

#[test]
fn a_signature_from_another_key_over_another_commitment_or_for_another_network_is_refused() {
    let mut b = local_builder(false);
    let mut upgrade = UpgradeKey::new(3);
    let mut other = UpgradeKey::new(4);
    let vault = b.local().deploy_registered_vault(&upgrade.secret.to_base58()).unwrap();
    let (payer, payer_address, alice) = accounts(&mut b);
    let prepared = prepared_delegation(&mut b, &vault, &alice, &payer_address);
    let commitment = prepared.full_commitment;

    let wrong: [(&str, Signature); 3] = [
        ("another key", other.sign(commitment, &NetworkId::TESTNET)),
        ("another commitment", upgrade.sign(commitment + BaseField::from(1u64), &NetworkId::TESTNET)),
        ("the other network", upgrade.sign(commitment, &NetworkId::MAINNET)),
    ];
    for (what, signature) in wrong {
        let tx = b.attach_delegation(&attachment(prepared.clone(), signature, &payer)).unwrap();
        let refusal = b.local().submit(&tx).expect_err(what);
        assert!(rejected(refusal), "{what}");
        assert_ne!(b.local().delegate(&vault).unwrap(), Some(alice.clone()), "{what}");
    }

    // The right signature is still accepted: nothing above spent the fee payer's nonce.
    let signature = upgrade.sign(commitment, &NetworkId::TESTNET);
    let tx = b.attach_delegation(&attachment(prepared, signature, &payer)).unwrap();
    b.local().submit(&tx).unwrap();
    assert_eq!(b.local().delegate(&vault).unwrap(), Some(alice));
}

#[test]
fn a_command_that_is_not_the_payers_or_has_no_update_to_sign_is_bad_input() {
    let mut b = local_builder(false);
    let mut upgrade = UpgradeKey::new(5);
    let vault = b.local().deploy_registered_vault(&upgrade.secret.to_base58()).unwrap();
    let (payer, payer_address, alice) = accounts(&mut b);
    let prepared = prepared_delegation(&mut b, &vault, &alice, &payer_address);
    let signature = upgrade.sign(prepared.full_commitment, &NetworkId::TESTNET);

    // Another fee payer than the one the command names.
    let accounts = b.local().accounts().unwrap();
    let stranger = zk_toon_tx_builder::FeePayer { private_key: accounts[1].private_key.clone(), fee: 0 };
    let e = b.attach_delegation(&attachment(prepared.clone(), signature.clone(), &stranger)).unwrap_err();
    assert!(matches!(e, Error::Failure { kind: FailureKind::BadInput, .. }), "{e}");

    // A command with no account update that wants a signature.
    let mut empty = prepared;
    empty.zkapp_command["accountUpdates"] = serde_json::json!([]);
    let e = b.attach_delegation(&attachment(empty, signature, &payer)).unwrap_err();
    assert!(matches!(e, Error::Failure { kind: FailureKind::BadInput, .. }), "{e}");
}
