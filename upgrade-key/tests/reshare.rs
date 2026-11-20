mod common;

use std::collections::BTreeMap;

use common::*;
use mina_signer::NetworkId;
use rand_chacha::ChaCha20Rng;
use upgrade_key::*;

type Keys = BTreeMap<Identifier, KeyPackage>;

/// A refresh by DKG for `numbers`, each holder starting from its entry in `old`. Every holder ends with the same new
/// public key package.
fn run_refresh(
    old: &Keys,
    old_public: &PublicKeyPackage,
    numbers: &[u16],
    rng: &mut ChaCha20Rng,
) -> (Keys, PublicKeyPackage) {
    let ids: Vec<Identifier> = numbers.iter().map(|n| holder(*n).unwrap()).collect();

    let mut secrets1 = BTreeMap::new();
    let mut packages1: BTreeMap<Identifier, _> = BTreeMap::new();
    for id in &ids {
        let (secret, package) = refresh::part1(*id, &mut *rng).unwrap();
        secrets1.insert(*id, secret);
        packages1.insert(*id, package);
    }
    let received1 = |id: &Identifier| -> BTreeMap<_, _> {
        packages1.iter().filter(|(from, _)| *from != id).map(|(k, v)| (*k, v.clone())).collect()
    };

    let mut secrets2 = BTreeMap::new();
    let mut inbox: BTreeMap<Identifier, BTreeMap<Identifier, _>> = BTreeMap::new();
    for id in &ids {
        let (secret, outgoing) = refresh::part2(secrets1.remove(id).unwrap(), &received1(id)).unwrap();
        secrets2.insert(*id, secret);
        for (to, package) in outgoing {
            inbox.entry(to).or_default().insert(*id, package);
        }
    }

    let mut keys = BTreeMap::new();
    let mut public = None;
    for id in &ids {
        let (key, public_package) =
            refresh::part3(&secrets2[id], &received1(id), &inbox[id], old_public, &old[id]).unwrap();
        if let Some(first) = &public {
            assert_eq!(&public_package, first);
        }
        public = Some(public_package);
        keys.insert(*id, key);
    }
    (keys, public.unwrap())
}

/// The helpers' steps of a repair of the share at `repaired`: every helper's sigma for the new holder.
fn repair_sigmas(keys: &Keys, helpers: &[u16], repaired: u16, rng: &mut ChaCha20Rng) -> Result<Vec<Sigma>, Error> {
    let helper_ids: Vec<Identifier> = helpers.iter().map(|n| holder(*n).unwrap()).collect();
    let repaired = holder(repaired).unwrap();
    let mut inbox: BTreeMap<Identifier, Vec<Delta>> = BTreeMap::new();
    for id in &helper_ids {
        for (to, delta) in repair::part1(&helper_ids, &keys[id], rng, repaired)? {
            inbox.entry(to).or_default().push(delta);
        }
    }
    Ok(helper_ids.iter().map(|id| repair::part2(&inbox[id])).collect())
}

/// The two remaining holders repair the share at `repaired` for the new holder.
fn run_repair(
    keys: &Keys,
    public: &PublicKeyPackage,
    helpers: &[u16],
    repaired: u16,
    rng: &mut ChaCha20Rng,
) -> Result<KeyPackage, Error> {
    let sigmas = repair_sigmas(keys, helpers, repaired, rng)?;
    repair::part3(&sigmas, holder(repaired).unwrap(), public)
}

fn assert_every_pair_signs(keys: &Keys, public: &PublicKeyPackage, upgrade_key: &mina_signer::PubKey, seed: u64) {
    let mut rng = rng(seed);
    for network in NETWORKS {
        for signers in SUBSETS {
            let message = Message::new(commitment(31_337), network.clone());
            let signature = threshold_sign(keys, public, &signers, &message, &mut rng);
            assert!(verify(&signature, upgrade_key, &message), "{signers:?} on {network:?}");
        }
    }
}

/// Signing with `signers`' shares from `keys` but checking against `public`: the signers the refused aggregate names.
fn culprits(keys: &Keys, public: &PublicKeyPackage, signers: &[u16], rng: &mut ChaCha20Rng) -> Vec<Identifier> {
    let message = Message::new(commitment(99), NetworkId::TESTNET);
    let (nonces, package) = commit(keys, signers, &message, rng);
    let shares = sign_shares(keys, nonces, &package);
    aggregate(&package, &message, &shares, public).expect_err("mixed shares must not aggregate").culprits()
}

fn mix(first: (&Keys, u16), second: (&Keys, u16)) -> Keys {
    let a = holder(first.1).unwrap();
    let b = holder(second.1).unwrap();
    BTreeMap::from([(a, first.0[&a].clone()), (b, second.0[&b].clone())])
}

#[test]
fn a_refresh_keeps_the_public_key_and_every_pair_signs() {
    let mut rng = rng(10);
    let (keys, public) = run_dkg(&mut rng);
    let upgrade_key = public_key(&public).unwrap();

    let (new_keys, new_public) = run_refresh(&keys, &public, &[1, 2, 3], &mut rng);
    assert_eq!(public_key(&new_public).unwrap(), upgrade_key);
    assert_eq!(new_public.verifying_key(), public.verifying_key());
    for n in 1..=MAX_SIGNERS {
        let id = holder(n).unwrap();
        assert_ne!(new_keys[&id].signing_share(), keys[&id].signing_share(), "holder {n}'s share changed");
    }
    assert_every_pair_signs(&new_keys, &new_public, &upgrade_key, 11);
}

#[test]
fn an_old_share_with_a_new_share_is_refused_at_aggregation() {
    let mut rng = rng(12);
    let (keys, public) = run_dkg(&mut rng);
    let (new_keys, new_public) = run_refresh(&keys, &public, &[1, 2, 3], &mut rng);

    for (old, new) in [(1, 2), (2, 1), (1, 3), (3, 2)] {
        let mixed = mix((&keys, old), (&new_keys, new));
        let old_id = holder(old).unwrap();
        // Against the new public package the old share is the culprit; against the old one, the new share.
        assert_eq!(culprits(&mixed, &new_public, &[old, new], &mut rng), vec![old_id]);
        assert_eq!(culprits(&mixed, &public, &[old, new], &mut rng), vec![holder(new).unwrap()]);
    }
}

#[test]
fn two_old_shares_still_sign_after_a_refresh() {
    // The reason old shares and their backups must be destroyed: a refresh doesn't invalidate two of them together.
    let mut rng = rng(13);
    let (keys, public) = run_dkg(&mut rng);
    let upgrade_key = public_key(&public).unwrap();
    let (_new_keys, new_public) = run_refresh(&keys, &public, &[1, 2, 3], &mut rng);
    assert_eq!(public_key(&new_public).unwrap(), upgrade_key);

    assert_every_pair_signs(&keys, &public, &upgrade_key, 14);
}

#[test]
fn a_repair_rebuilds_the_share_and_needs_two_helpers() {
    let mut rng = rng(15);
    let (keys, public) = run_dkg(&mut rng);
    let leaving = holder(3).unwrap();

    let repaired = run_repair(&keys, &public, &[1, 2], 3, &mut rng).unwrap();
    assert_eq!(repaired.identifier(), &leaving);
    assert_eq!(repaired.signing_share(), keys[&leaving].signing_share());
    assert_eq!(repaired, keys[&leaving]);

    assert!(run_repair(&keys, &public, &[1], 3, &mut rng).is_err(), "one helper is below the threshold");
}

#[test]
fn a_repair_with_a_wrong_sigma_fails() {
    let mut rng = rng(20);
    let (keys, public) = run_dkg(&mut rng);
    let leaving = holder(3).unwrap();

    // Two honest runs of the same repair: each run's sigmas sum to the share, but one sigma from each does not.
    let first = repair_sigmas(&keys, &[1, 2], 3, &mut rng).unwrap();
    let second = repair_sigmas(&keys, &[1, 2], 3, &mut rng).unwrap();
    assert!(repair::part3(&[first[0].clone(), second[1].clone()], leaving, &public).is_err());
    assert!(repair::part3(&first[..1], leaving, &public).is_err(), "one sigma is not the share");
}

#[test]
fn replacing_a_holder_keeps_the_key_and_retires_the_leaving_share() {
    let mut rng = rng(16);
    let (keys, public) = run_dkg(&mut rng);
    let upgrade_key = public_key(&public).unwrap();

    // The new holder takes the leaving holder's identifier, 3, and joins the refresh with the repaired share.
    let repaired = run_repair(&keys, &public, &[1, 2], 3, &mut rng).unwrap();
    let mut before_refresh = keys.clone();
    before_refresh.insert(holder(3).unwrap(), repaired);
    let (new_keys, new_public) = run_refresh(&before_refresh, &public, &[1, 2, 3], &mut rng);

    assert_eq!(public_key(&new_public).unwrap(), upgrade_key);
    assert_every_pair_signs(&new_keys, &new_public, &upgrade_key, 17);

    // The leaving holder's share, the same one the new holder started from, combines with neither remaining holder.
    for remaining in [1, 2] {
        let mixed = mix((&new_keys, remaining), (&keys, 3));
        assert_eq!(culprits(&mixed, &new_public, &[remaining, 3], &mut rng), vec![holder(3).unwrap()]);
    }
}

#[test]
fn two_refreshes_in_a_row_do_not_mix() {
    let mut rng = rng(18);
    let (keys, public) = run_dkg(&mut rng);
    let upgrade_key = public_key(&public).unwrap();

    let (first, first_public) = run_refresh(&keys, &public, &[1, 2, 3], &mut rng);
    let (second, second_public) = run_refresh(&first, &first_public, &[1, 2, 3], &mut rng);
    assert_eq!(public_key(&second_public).unwrap(), upgrade_key);
    assert_every_pair_signs(&second, &second_public, &upgrade_key, 19);

    for (a, b) in [(1, 2), (2, 1), (3, 1)] {
        let mixed = mix((&first, a), (&second, b));
        assert_eq!(culprits(&mixed, &second_public, &[a, b], &mut rng), vec![holder(a).unwrap()]);
    }
}
