//! The upgrade key: a 2-of-3 FROST key over Pallas (ADR 0012).
//!
//! A thin layer over `frost-bluepallas`. Three share holders make the key by distributed key generation ([`dkg`]) and
//! any two sign one field element, a transaction's full commitment, under a stated network ID ([`round1`], [`round2`],
//! [`aggregate`]). The result is a Mina signature that this workspace's pinned `mina-signer` accepts against the upgrade
//! key's public key.
//!
//! `frost-bluepallas` builds on proof-systems tag 0.3.0 and this workspace on another revision, so their types never
//! meet. Values cross as field elements, here as the shared `ark-ff` big integer, and as base58 addresses.
//!
//! Signing nonces are consumed by [`round2::sign`], so one set can't sign twice. Randomness comes from a CSPRNG the
//! caller supplies. A trusted-dealer split exists only under the `test-utils` feature, for tests.

use std::collections::BTreeMap;

use ark_ff::PrimeField;
use frost_mina_hasher::ROInput;
use mina_signer::{BaseField, NetworkId, PubKey, ScalarField, Signature};
use mina_tx::pallas_message::{translate_pk, translate_sig, PallasMessage};
use mina_tx::NetworkId as FrostNetworkId;
use rand_core::{CryptoRng, RngCore};
use serde_json::{json, Value};

/// How many share holders there are.
pub const MAX_SIGNERS: u16 = 3;
/// How many of them must sign.
pub const MIN_SIGNERS: u16 = 2;

pub type Error = frost_bluepallas::Error<PallasMessage>;
/// A share holder's number, 1 to [`MAX_SIGNERS`].
pub type Identifier = frost_bluepallas::Identifier<PallasMessage>;
/// A share holder's key share. Keep it secret.
pub type KeyPackage = frost_bluepallas::keys::KeyPackage<PallasMessage>;
/// The upgrade key's public key and every holder's verifying share.
pub type PublicKeyPackage = frost_bluepallas::keys::PublicKeyPackage<PallasMessage>;
/// A signer's nonces. Secret, and consumed by [`round2::sign`].
pub type SigningNonces = frost_bluepallas::round1::SigningNonces<PallasMessage>;
pub type SigningCommitments = frost_bluepallas::round1::SigningCommitments<PallasMessage>;
pub type SigningPackage = frost_bluepallas::SigningPackage<PallasMessage>;
pub type SignatureShare = frost_bluepallas::round2::SignatureShare<PallasMessage>;

/// What the upgrade key signs: a transaction's full commitment under a network ID.
///
/// The message is hashed the Kimchi way, never the legacy way.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    fields: Vec<BaseField>,
    network: NetworkId,
}

impl Message {
    /// The full commitment of a transaction, under the network it is for.
    pub fn new(full_commitment: BaseField, network: NetworkId) -> Self {
        Self { fields: vec![full_commitment], network }
    }

    /// Several fields at once. The upgrade key signs one commitment, so this is only for checking against
    /// `mina-signer`'s own multi-field vectors.
    #[cfg(feature = "test-utils")]
    pub fn from_fields(fields: Vec<BaseField>, network: NetworkId) -> Self {
        Self { fields, network }
    }

    /// The bytes the signers sign, which carry the network ID with them.
    pub fn to_bytes(&self) -> Vec<u8> {
        let input = self
            .fields
            .iter()
            .fold(ROInput::new(), |input, field| input.append_field(to_frost_field(*field)));
        let network = match self.network {
            NetworkId::TESTNET => FrostNetworkId::Testnet,
            NetworkId::MAINNET => FrostNetworkId::Mainnet,
        };
        PallasMessage::from_parts(input, network, false)
            .serialize()
            .expect("a testnet or mainnet message always serializes")
    }
}

/// Distributed key generation: three parts, run by every holder. Nobody ever holds the whole key.
pub mod dkg {
    use super::*;
    pub use frost_bluepallas::keys::dkg::{round1, round2};

    /// Part 1: broadcast the package to the other two holders and keep the secret one.
    pub fn part1<R: RngCore + CryptoRng>(
        holder: Identifier,
        rng: R,
    ) -> Result<(round1::SecretPackage<PallasMessage>, round1::Package<PallasMessage>), Error> {
        frost_bluepallas::keys::dkg::part1(holder, MAX_SIGNERS, MIN_SIGNERS, rng)
    }

    /// Part 2: send each other holder its own package, over a confidential and authenticated channel.
    #[allow(clippy::type_complexity)]
    pub fn part2(
        secret: round1::SecretPackage<PallasMessage>,
        received: &BTreeMap<Identifier, round1::Package<PallasMessage>>,
    ) -> Result<
        (round2::SecretPackage<PallasMessage>, BTreeMap<Identifier, round2::Package<PallasMessage>>),
        Error,
    > {
        frost_bluepallas::keys::dkg::part2(secret, received)
    }

    /// Part 3: the holder's key share and the public key package, which names the upgrade key.
    pub fn part3(
        secret: &round2::SecretPackage<PallasMessage>,
        round1_received: &BTreeMap<Identifier, round1::Package<PallasMessage>>,
        round2_received: &BTreeMap<Identifier, round2::Package<PallasMessage>>,
    ) -> Result<(KeyPackage, PublicKeyPackage), Error> {
        frost_bluepallas::keys::dkg::part3(secret, round1_received, round2_received)
    }
}

/// A trusted dealer splitting a key. Tests only: the dealer holds the whole key.
#[cfg(feature = "test-utils")]
pub mod dealer {
    use super::*;

    /// Split `secret` into three shares, two of which sign.
    pub fn split<R: RngCore + CryptoRng>(
        secret: &mina_signer::SecKey,
        rng: &mut R,
    ) -> Result<(BTreeMap<Identifier, KeyPackage>, PublicKeyPackage), Error> {
        let mut bytes: [u8; 32] = secret.to_bytes().try_into().expect("a scalar is 32 bytes");
        bytes.reverse(); // SecKey's bytes are big-endian, frost's little-endian
        let key = frost_bluepallas::SigningKey::<PallasMessage>::deserialize(&bytes)?;
        let (shares, public) = frost_bluepallas::keys::split(
            &key,
            MAX_SIGNERS,
            MIN_SIGNERS,
            frost_bluepallas::keys::IdentifierList::Default,
            rng,
        )?;
        let packages = shares
            .into_iter()
            .map(|(id, share)| KeyPackage::try_from(share).map(|package| (id, package)))
            .collect::<Result<_, _>>()?;
        Ok((packages, public))
    }
}

/// The holder with this number, 1 to [`MAX_SIGNERS`].
pub fn holder(number: u16) -> Result<Identifier, Error> {
    if !(1..=MAX_SIGNERS).contains(&number) {
        return Err(Error::MalformedIdentifier);
    }
    Identifier::try_from(number)
}

/// The upgrade key's public key. Its address is `B62…`.
pub fn public_key(package: &PublicKeyPackage) -> Result<PubKey, Error> {
    let key = translate_pk(package.verifying_key()).map_err(|_| Error::MalformedVerifyingKey)?;
    PubKey::from_address(&key.into_address()).map_err(|_| Error::MalformedVerifyingKey)
}

/// Round 1: a signer makes its nonces and commitments. Send the commitments to the other signer and keep the nonces.
pub mod round1 {
    use super::*;

    pub fn commit<R: RngCore + CryptoRng>(
        key: &KeyPackage,
        rng: &mut R,
    ) -> (SigningNonces, SigningCommitments) {
        frost_bluepallas::round1::commit(key.signing_share(), rng)
    }
}

/// Round 2: a signer makes its signature share.
pub mod round2 {
    use super::*;

    /// The signing package: every signer's commitments, and the message.
    pub fn package(
        commitments: BTreeMap<Identifier, SigningCommitments>,
        message: &Message,
    ) -> SigningPackage {
        SigningPackage::new(commitments, &message.to_bytes())
    }

    /// Takes the nonces by value, so they can't sign twice.
    pub fn sign(
        package: &SigningPackage,
        nonces: SigningNonces,
        key: &KeyPackage,
    ) -> Result<SignatureShare, Error> {
        frost_bluepallas::round2::sign(package, &nonces, key)
    }
}

/// The signature shares become a Mina signature. Each share is checked, so a bad one names its signer in
/// [`Error::culprits`]. The signature is checked against the pinned `mina-signer` before it is returned.
pub fn aggregate(
    package: &SigningPackage,
    message: &Message,
    shares: &BTreeMap<Identifier, SignatureShare>,
    public: &PublicKeyPackage,
) -> Result<Signature, Error> {
    if package.message() != message.to_bytes().as_slice() {
        return Err(Error::InvalidSignature);
    }
    let signature = frost_bluepallas::aggregate(package, shares, public)?;
    let signature = translate_sig(&signature).map_err(|_| Error::InvalidSignature)?;
    let signature = Signature::new(from_frost_field(signature.rx), from_frost_scalar(signature.s));
    let key = public_key(public)?;
    if !verify(&signature, &key, message) {
        return Err(Error::InvalidSignature);
    }
    Ok(signature)
}

/// Whether the pinned `mina-signer` accepts `signature` over `message` for `key`, under the message's network ID.
pub fn verify(signature: &Signature, key: &PubKey, message: &Message) -> bool {
    use mina_signer::Signer;
    let mut context = mina_signer::create_kimchi::<Fields>(message.network.clone());
    context.verify(signature, key, &Fields(message.fields.clone()))
}

/// The signature as the transaction builder takes it: `{"r": <decimal>, "s": <decimal>}`.
pub fn signature_json(signature: &Signature) -> Value {
    json!({ "r": signature.rx.to_string(), "s": signature.s.to_string() })
}

/// A message's fields, hashed the way `mina-signer` hashes a field-signing test input.
#[derive(Clone)]
struct Fields(Vec<BaseField>);

impl mina_hasher::Hashable for Fields {
    type D = NetworkId;

    fn to_roinput(&self) -> mina_hasher::ROInput {
        self.0.iter().fold(mina_hasher::ROInput::new(), |input, field| input.append_field(*field))
    }

    fn domain_string(network: NetworkId) -> Option<String> {
        Some(network.into_domain_string())
    }
}

fn to_frost_field(field: BaseField) -> frost_mina_curves::pasta::Fp {
    frost_mina_curves::pasta::Fp::from_bigint(field.into_bigint()).expect("same field")
}

fn from_frost_field(field: frost_mina_curves::pasta::Fp) -> BaseField {
    BaseField::from_bigint(field.into_bigint()).expect("same field")
}

fn from_frost_scalar(scalar: frost_mina_curves::pasta::Fq) -> ScalarField {
    ScalarField::from_bigint(scalar.into_bigint()).expect("same field")
}
