//! Every derived value of a zk note. Mirrors `o1js/src/primitives.ts` byte for byte and is pinned
//! by `test-vectors/zk-note.json`. No I/O, no clock.

pub mod balance;
pub mod clearance;
pub mod policy;
pub mod state;
pub mod withdrawal;

use ark_ff::PrimeField;
use mina_curves::pasta::Fp;
use mina_poseidon::constants::PlonkSpongeConstantsKimchi;
use mina_poseidon::pasta::{fp_kimchi, FULL_ROUNDS};
use mina_poseidon::poseidon::{ArithmeticSponge, Sponge};

/// An element of the Pallas base field, the field o1js hashes in.
pub type Field = Fp;

/// Domain tags: ASCII, at most 31 bytes, read as a little-endian field element.
pub mod tags {
    pub const COMMITMENT: &str = "toon.zk.commitment.v1";
    pub const LEAF: &str = "toon.zk.leaf.v1";
    pub const GENESIS_ANCHOR: &str = "toon.zk.genesis-anchor.v1";
    pub const NULLIFIER: &str = "toon.zk.nullifier.v1";
    pub const ANCHOR: &str = "toon.zk.anchor.v1";
    pub const AUTH_TAG: &str = "toon.zk.auth-tag.v1";
    pub const PERIOD_NULLIFIER: &str = "toon.zk.period-nullifier.v1";
    pub const CLEARANCE: &str = "toon.zk.clearance.v1";
}

pub fn tag_to_field(tag: &str) -> Field {
    let bytes = tag.as_bytes();
    assert!(bytes.len() <= 31, "domain tag too long: {tag}");
    Field::from_le_bytes_mod_order(bytes)
}

/// Plain Poseidon (kimchi parameters, zero initial state), as o1js `Poseidon.hash`.
pub fn poseidon(inputs: &[Field]) -> Field {
    let mut sponge = ArithmeticSponge::<Field, PlonkSpongeConstantsKimchi, FULL_ROUNDS>::new(fp_kimchi::static_params());
    sponge.absorb(inputs);
    sponge.squeeze()
}

/// Poseidon with the tag as the first input.
pub fn hash_with_tag(tag: &str, inputs: &[Field]) -> Field {
    let mut all = Vec::with_capacity(inputs.len() + 1);
    all.push(tag_to_field(tag));
    all.extend_from_slice(inputs);
    poseidon(&all)
}

pub fn commit_secret(secret: Field) -> Field {
    hash_with_tag(tags::COMMITMENT, &[secret])
}

/// The leaf commits to index, secret commitment, deposit size, deposit time and expiry.
pub fn leaf(index: u64, commitment: Field, size: u64, deposit_time: u64, expiry: u64) -> Field {
    hash_with_tag(
        tags::LEAF,
        &[index.into(), commitment, size.into(), deposit_time.into(), expiry.into()],
    )
}

/// The anchor of a note's first state.
pub fn genesis_anchor(commitment: Field) -> Field {
    hash_with_tag(tags::GENESIS_ANCHOR, &[commitment])
}

/// A state is spent once, through its nullifier; only the secret's holder can compute it.
pub fn nullifier(secret: Field, anchor: Field) -> Field {
    hash_with_tag(tags::NULLIFIER, &[secret, anchor])
}

/// The next state's anchor follows from the nullifier just spent.
pub fn next_anchor(nullifier: Field) -> Field {
    hash_with_tag(tags::ANCHOR, &[nullifier])
}

/// What an authorization tag binds a nullifier to.
#[derive(Clone, Copy, Debug)]
pub struct RequestContext {
    /// The zk edge's identity.
    pub edge: Field,
    /// The session key's x coordinate and whether y is odd (hashed as 0 or 1).
    pub session_key_x: Field,
    pub session_key_is_odd: bool,
    pub tier: u64,
    pub expiry: u64,
}

pub fn auth_tag(nullifier: Field, ctx: &RequestContext) -> Field {
    hash_with_tag(
        tags::AUTH_TAG,
        &[
            nullifier,
            ctx.edge,
            ctx.session_key_x,
            Field::from(ctx.session_key_is_odd as u64),
            ctx.tier.into(),
            ctx.expiry.into(),
        ],
    )
}

/// Unlinkable across periods without the secret.
pub fn period_nullifier(secret: Field, index: u64, period: u64) -> Field {
    hash_with_tag(tags::PERIOD_NULLIFIER, &[secret, index.into(), period.into()])
}

/// Decimal string of a field element, the vector file's encoding.
pub fn field_to_string(f: Field) -> String {
    f.into_bigint().to_string()
}

