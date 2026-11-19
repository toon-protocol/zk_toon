//! `mina-signer`'s Kimchi field-signing cases (the `sign_fields_test` kind in its `tests/signer.rs`, at the revision this
//! workspace pins): a secret key, some fields and a network. Each vector's secret key is dealer-split so the upgrade
//! key's public key is the vector's, its fields are threshold-signed, and the pinned `mina-signer` verifies the result
//! under the vector's network. The signature differs from the vector's deterministic one, which is expected.

mod common;

use ark_ff::One;
use common::*;
use mina_signer::{BaseField, NetworkId, ScalarField, SecKey};
use upgrade_key::*;

struct Case {
    name: &'static str,
    secret: SecKey,
    fields: Vec<u64>,
    network: NetworkId,
}

fn cases() -> Vec<Case> {
    let fields = vec![1, 2, 3];
    // `sign_fields_test`: a base58 key, signing under testnet and under mainnet.
    let base58 = || SecKey::from_base58("EKFXH5yESt7nsD1TJy5WNb4agVczkvzPRVexKQ8qYdNqauQRA8Ef").unwrap();
    vec![
        Case { name: "sign_fields_test testnet", secret: base58(), fields: fields.clone(), network: NetworkId::TESTNET },
        Case { name: "sign_fields_test mainnet", secret: base58(), fields: fields.clone(), network: NetworkId::MAINNET },
        // `test_base_field_modulus_minus_one_works`: the secret is -1, above the base field's modulus.
        Case {
            name: "secret minus one",
            secret: SecKey::new(-ScalarField::one()),
            fields: fields.clone(),
            network: NetworkId::TESTNET,
        },
        // `test_scalar_to_base_field_overflow` draws its offset at random; this is one fixed offset.
        Case {
            name: "secret near the scalar modulus",
            secret: SecKey::new(-ScalarField::from(0x1234_5678_9abc_def0u64)),
            fields,
            network: NetworkId::TESTNET,
        },
    ]
}

#[test]
fn threshold_signatures_verify_under_the_vectors_network() {
    let mut rng = rng(10);
    let cases = cases();
    for case in &cases {
        let (shares, public) = dealer::split(&case.secret, &mut rng).unwrap();
        assert_eq!(public_key(&public).unwrap(), public_of(&case.secret), "{}", case.name);

        let message = Message::from_fields(
            case.fields.iter().map(|f| BaseField::from(*f)).collect(),
            case.network.clone(),
        );
        for signers in [[1, 2], [1, 3], [2, 3]] {
            let signature = threshold_sign(&shares, &public, &signers, &message, &mut rng);
            let mut context = mina_signer::create_kimchi::<Fields>(case.network.clone());
            assert!(
                mina_signer::Signer::verify(&mut context, &signature, &public_of(&case.secret), &Fields(case.fields.clone())),
                "{} {signers:?}",
                case.name
            );
        }
    }
    println!("vector cases run: {}", cases.len());
}

/// The input as `mina-signer`'s test defines it, so the check doesn't go through this crate's own verifier.
#[derive(Clone)]
struct Fields(Vec<u64>);

impl mina_hasher::Hashable for Fields {
    type D = NetworkId;

    fn to_roinput(&self) -> mina_hasher::ROInput {
        self.0.iter().fold(mina_hasher::ROInput::new(), |roi, f| roi.append_field(BaseField::from(*f)))
    }

    fn domain_string(network: NetworkId) -> Option<String> {
        Some(network.into_domain_string())
    }
}
