#![allow(dead_code)]

use std::collections::BTreeMap;

use mina_signer::{BaseField, Keypair, NetworkId, PubKey, SecKey, Signature};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use upgrade_key::*;

pub const NETWORKS: [NetworkId; 2] = [NetworkId::TESTNET, NetworkId::MAINNET];

pub fn rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

pub fn commitment(n: u64) -> BaseField {
    BaseField::from(n)
}

/// Three holders make the key by DKG: part 1, part 2 and part 3 for each, exchanging the packages in between.
pub fn run_dkg(rng: &mut ChaCha20Rng) -> (BTreeMap<Identifier, KeyPackage>, PublicKeyPackage) {
    let ids: Vec<Identifier> = (1..=MAX_SIGNERS).map(|n| holder(n).unwrap()).collect();

    let mut secrets1 = BTreeMap::new();
    let mut packages1 = BTreeMap::new();
    for id in &ids {
        let (secret, package) = dkg::part1(*id, &mut *rng).unwrap();
        secrets1.insert(*id, secret);
        packages1.insert(*id, package);
    }

    let mut secrets2 = BTreeMap::new();
    let mut inbox2: BTreeMap<Identifier, BTreeMap<Identifier, _>> = BTreeMap::new();
    for id in &ids {
        let received: BTreeMap<_, _> =
            packages1.iter().filter(|(from, _)| *from != id).map(|(k, v)| (*k, v.clone())).collect();
        let (secret, outgoing) = dkg::part2(secrets1.remove(id).unwrap(), &received).unwrap();
        secrets2.insert(*id, secret);
        for (to, package) in outgoing {
            inbox2.entry(to).or_default().insert(*id, package);
        }
    }

    let mut keys = BTreeMap::new();
    let mut public = None;
    for id in &ids {
        let received1: BTreeMap<_, _> =
            packages1.iter().filter(|(from, _)| *from != id).map(|(k, v)| (*k, v.clone())).collect();
        let (key, public_package) = dkg::part3(&secrets2[id], &received1, &inbox2[id]).unwrap();
        // Every holder ends with the same upgrade key.
        if let Some(first) = &public {
            assert_eq!(&public_package, first);
        }
        public = Some(public_package);
        keys.insert(*id, key);
    }
    (keys, public.unwrap())
}

/// Round 1 for `signers`, then the signing package.
pub fn commit(
    keys: &BTreeMap<Identifier, KeyPackage>,
    signers: &[u16],
    message: &Message,
    rng: &mut ChaCha20Rng,
) -> (BTreeMap<Identifier, SigningNonces>, SigningPackage) {
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for n in signers {
        let id = holder(*n).unwrap();
        let (signing_nonces, signing_commitments) = round1::commit(&keys[&id], rng);
        nonces.insert(id, signing_nonces);
        commitments.insert(id, signing_commitments);
    }
    (nonces, round2::package(commitments, message))
}

/// Round 2 for every signer in `nonces`.
pub fn sign_shares(
    keys: &BTreeMap<Identifier, KeyPackage>,
    nonces: BTreeMap<Identifier, SigningNonces>,
    package: &SigningPackage,
) -> BTreeMap<Identifier, SignatureShare> {
    nonces
        .into_iter()
        .map(|(id, nonces)| (id, round2::sign(package, nonces, &keys[&id]).unwrap()))
        .collect()
}

pub fn threshold_sign(
    keys: &BTreeMap<Identifier, KeyPackage>,
    public: &PublicKeyPackage,
    signers: &[u16],
    message: &Message,
    rng: &mut ChaCha20Rng,
) -> Signature {
    let (nonces, package) = commit(keys, signers, message, rng);
    let shares = sign_shares(keys, nonces, &package);
    aggregate(&package, message, &shares, public).unwrap()
}

pub fn public_of(secret: &SecKey) -> PubKey {
    Keypair::try_from(secret.clone()).unwrap().public
}
