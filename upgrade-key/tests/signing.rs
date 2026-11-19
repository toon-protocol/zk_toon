mod common;

use std::collections::BTreeMap;

use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField};
use common::*;
use mina_signer::NetworkId;
use upgrade_key::*;

const SUBSETS: [[u16; 2]; 3] = [[1, 2], [1, 3], [2, 3]];

#[test]
fn every_two_of_three_signs_under_each_network() {
    let mut rng = rng(1);
    let (keys, public) = run_dkg(&mut rng);
    let upgrade_key = public_key(&public).unwrap();
    assert!(upgrade_key.into_address().starts_with("B62"));

    for network in NETWORKS {
        let other = if network == NetworkId::TESTNET { NetworkId::MAINNET } else { NetworkId::TESTNET };
        for signers in SUBSETS {
            let message = Message::new(commitment(123_456_789), network.clone());
            let signature = threshold_sign(&keys, &public, &signers, &message, &mut rng);
            assert!(verify(&signature, &upgrade_key, &message), "{signers:?} on {network:?}");
            assert!(
                !verify(&signature, &upgrade_key, &Message::new(commitment(123_456_789), other.clone())),
                "{signers:?} signed for {network:?} but {other:?} accepted it"
            );
        }
    }
}

#[test]
fn signature_json_is_the_transaction_builders_shape() {
    let mut rng = rng(2);
    let (keys, public) = run_dkg(&mut rng);
    let message = Message::new(commitment(7), NetworkId::TESTNET);
    let signature = threshold_sign(&keys, &public, &[1, 3], &message, &mut rng);
    let json = signature_json(&signature);
    assert_eq!(json["r"], signature.rx.to_string());
    assert_eq!(json["s"], signature.s.to_string());
}

/// Whether the combined R of the two signers' commitments has an odd y, before any signer negates for it.
fn combined_r_is_odd(package: &SigningPackage, public: &PublicKeyPackage) -> bool {
    let factors =
        frost_core::compute_binding_factor_list(package, public.verifying_key(), &[]).unwrap();
    let r = frost_core::compute_group_commitment(package, &factors).unwrap().to_element();
    r.into_affine().y.into_bigint().is_odd()
}

#[test]
fn a_combined_r_with_an_odd_y_still_verifies() {
    let mut rng = rng(3);
    let (keys, public) = run_dkg(&mut rng);
    let upgrade_key = public_key(&public).unwrap();
    let message = Message::new(commitment(42), NetworkId::MAINNET);

    let mut odd = 0;
    let mut even = 0;
    for _ in 0..40 {
        let (nonces, package) = commit(&keys, &[1, 2], &message, &mut rng);
        let is_odd = combined_r_is_odd(&package, &public);
        let shares = sign_shares(&keys, nonces, &package);
        let signature = aggregate(&package, &message, &shares, &public).unwrap();
        assert!(verify(&signature, &upgrade_key, &message), "odd y: {is_odd}");
        if is_odd {
            odd += 1;
        } else {
            even += 1;
        }
    }
    assert!(odd > 0, "no run had a combined R with an odd y");
    assert!(even > 0, "no run had a combined R with an even y");
}

#[test]
fn one_key_share_alone_cannot_sign() {
    let mut rng = rng(4);
    let (keys, public) = run_dkg(&mut rng);
    let message = Message::new(commitment(5), NetworkId::TESTNET);

    let (mut nonces, package) = commit(&keys, &[1], &message, &mut rng);
    let id = holder(1).unwrap();
    assert!(round2::sign(&package, nonces.remove(&id).unwrap(), &keys[&id]).is_err());

    // Nor can one holder's share stand in for the other's.
    let (nonces_pair, package_pair) = commit(&keys, &[1, 2], &message, &mut rng);
    let mut shares = sign_shares(&keys, nonces_pair, &package_pair);
    shares.remove(&holder(2).unwrap());
    assert!(aggregate(&package_pair, &message, &shares, &public).is_err());
}

#[test]
fn a_corrupted_signature_share_names_its_signer() {
    let mut rng = rng(5);
    let (keys, public) = run_dkg(&mut rng);
    let message = Message::new(commitment(5), NetworkId::TESTNET);

    let (nonces, package) = commit(&keys, &[1, 3], &message, &mut rng);
    let mut shares = sign_shares(&keys, nonces, &package);
    let (one, three) = (holder(1).unwrap(), holder(3).unwrap());

    // Holder 3's slot carries holder 1's share.
    shares.insert(three, shares[&one]);
    let error = aggregate(&package, &message, &shares, &public).unwrap_err();
    assert_eq!(error.culprits(), vec![three]);

    // A share with one bit flipped.
    let (nonces, package) = commit(&keys, &[1, 3], &message, &mut rng);
    let mut shares = sign_shares(&keys, nonces, &package);
    let mut bytes = shares[&one].serialize();
    bytes[0] ^= 1;
    shares.insert(one, SignatureShare::deserialize(&bytes).unwrap());
    let error = aggregate(&package, &message, &shares, &public).unwrap_err();
    assert_eq!(error.culprits(), vec![one]);
}

#[test]
fn a_signature_over_one_commitment_does_not_verify_for_the_next() {
    let mut rng = rng(6);
    let (keys, public) = run_dkg(&mut rng);
    let upgrade_key = public_key(&public).unwrap();
    for network in NETWORKS {
        let c = commitment(1_000_000);
        let message = Message::new(c, network.clone());
        let signature = threshold_sign(&keys, &public, &[2, 3], &message, &mut rng);
        assert!(verify(&signature, &upgrade_key, &message));
        assert!(!verify(&signature, &upgrade_key, &Message::new(c + commitment(1), network)));
    }
}

#[test]
fn aggregate_refuses_a_message_the_signers_did_not_sign() {
    let mut rng = rng(7);
    let (keys, public) = run_dkg(&mut rng);
    let signed = Message::new(commitment(9), NetworkId::TESTNET);
    let (nonces, package) = commit(&keys, &[1, 2], &signed, &mut rng);
    let shares = sign_shares(&keys, nonces, &package);
    assert!(aggregate(&package, &Message::new(commitment(10), NetworkId::TESTNET), &shares, &public).is_err());
    assert!(aggregate(&package, &Message::new(commitment(9), NetworkId::MAINNET), &shares, &public).is_err());
    let _: BTreeMap<Identifier, SignatureShare> = shares;
}
