//! `Land.land`: the method, the SmartContract wrapper around it and the Pickles step circuit
//! around that, in the order o1js and Pickles create their variables.
//!
//! ```text
//! Pickles   app state (the account update hash and the calls hash), dummy_constraints
//! wrapper   witness the arguments (address, token id, cumulative, signature) and the blinding
//! land      payer and landed from the state; sig.verify(payer, cumulative); cumulative > landed
//! wrapper   call data hash, setKind (the verification key hash), the account update hash
//! Pickles   the verification key index, the hash of the step statement (the public input)
//! ```

use anyhow::Context as _;
use ark_ff::{BigInteger, PrimeField, Zero};
use ledger::proofs::witness::Witness;
use mina_curves::pasta::{Fp, Fq};
use mina_signer::CompressedPubKey;
use num_bigint::BigInt;

use super::{
    account_update::{pack_to_fields, Body},
    gadgets::{
        comparison::assert_less_than_generic_u64,
        foreign_field::big_to_fp,
        native_curve::{fq_modulus, Point, ShiftedScalar},
        poseidon::{self, Sponge},
        range_check::range_check_n_64,
        signature::{self, PublicKey, Signature},
    },
    pickles::{self, from_fork},
    Cs, Field,
};

/// Everything `land`'s witness depends on.
#[derive(Clone, Debug)]
pub struct LandInputs {
    /// The zkApp's address (base58).
    pub zkapp: String,
    /// The payer in the zkApp's state (base58).
    pub payer: String,
    /// The method's `cumulative` argument.
    pub cumulative: u64,
    /// The method's `sig` argument (base58).
    pub sig: String,
    /// The zkApp's `landed` state before the call.
    pub landed: u64,
    /// The token id argument; the zkApp's own token is `1`, MINA.
    pub token_id: Fp,
    /// The blinding value of the call data (`Fp.random()` in o1js).
    pub blinding: Fp,
    /// The verification key `data` (base64) and its hash.
    pub vk: String,
    pub vk_hash: Fp,
}

/// The result: the public input and the auxiliary values.
pub struct LandWitness {
    pub primary: Vec<Fp>,
    pub aux: Vec<Fp>,
}

impl From<LandWitness> for crate::StepWitness {
    /// The witness in the form [`crate::prove_step`] and [`crate::check_step`] take.
    fn from(w: LandWitness) -> Self {
        crate::StepWitness::from_parts(w.primary, w.aux)
    }
}

/// The method name `land` as `Encoding.stringToFields` makes it: bytes, then the stop byte `1`.
fn string_to_field(s: &str) -> Fp {
    assert!(s.len() < 31);
    let mut bytes = s.as_bytes().to_vec();
    bytes.push(1);
    Fp::from_le_bytes_mod_order(&bytes)
}

fn public_key(address: &str) -> anyhow::Result<(Fp, bool)> {
    let pk = CompressedPubKey::from_address(address).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    Ok((pk.x, pk.is_odd))
}

/// A signature `(r, s)` from its base58 encoding: the version byte 154, the version number 1, then
/// `r` and `s` little-endian.
fn signature(sig: &str) -> anyhow::Result<(Fp, Fq)> {
    let bytes = bs58::decode(sig).with_check(None).into_vec().context("signature base58")?;
    anyhow::ensure!(bytes.len() == 66 && bytes[..2] == [154, 1], "not a signature");
    Ok((Fp::from_le_bytes_mod_order(&bytes[2..34]), Fq::from_le_bytes_mod_order(&bytes[34..66])))
}

/// `Scalar` in the shifted representation: `t = s - 2^255 mod q`, `(t & 1, t >> 1)`.
fn shifted_scalar(s: &Fq) -> (Fp, Fp) {
    let q = fq_modulus();
    let s = BigInt::from_bytes_le(num_bigint::Sign::Plus, &s.into_bigint().to_bytes_le());
    let t = (s - (BigInt::from(1) << 255u32)).modpow(&BigInt::from(1), &q);
    let t = ((t % &q) + &q) % &q;
    (big_to_fp(&(&t & BigInt::from(1))), big_to_fp(&(t >> 1u32)))
}

/// Pallas's generator.
fn generator() -> Point {
    Point::constant(
        Fp::from(1u64),
        <Fp as std::str::FromStr>::from_str(
            "12418654782883325593414442427049395787963493412651469444558597405572177144507",
        )
        .unwrap(),
    )
}

/// `Provable.witness(PublicKey, ...)`: the two fields, and the check on the parity.
fn witness_public_key(cs: &mut Cs, x: Fp, is_odd: bool) -> PublicKey {
    let [x, odd] = cs.exists([x, Fp::from(is_odd as u64)]);
    let is_odd = odd.assert_bool(cs);
    PublicKey { x, is_odd }
}

/// The witness of `land`.
///
/// The app state (the first two variables) is the account update hash, which the circuit also
/// computes. The circuit is built with a placeholder there, and the hash put in once it is known:
/// nothing in between reads it.
pub fn land_witness(inputs: &LandInputs) -> anyhow::Result<LandWitness> {
    let mut cs = Cs::new();
    let account_update_hash = method_and_wrapper(&mut cs, inputs)?;
    cs.set(1, account_update_hash);
    let public_input = step_statement_hash(&mut cs, inputs)?;
    Ok(LandWitness { primary: vec![public_input], aux: cs.into_aux() })
}

/// Pickles' prelude, the wrapper, `land` and the account update hash. Returns that hash.
fn method_and_wrapper(cs: &mut Cs, inputs: &LandInputs) -> anyhow::Result<Fp> {
    // Pickles: the app state (a placeholder, see `land_witness`), `dummy_constraints`
    pickles::prelude(cs, Fp::zero(), Fp::zero());

    // Pickles' rule main witnesses the arguments of the method: the address, the token id, then the
    // method's own (`cumulative: UInt64`, `sig: Signature`).
    let (zx, zodd) = public_key(&inputs.zkapp)?;
    let zkapp = witness_public_key(cs, zx, zodd);
    let _token_id = cs.exists_one(inputs.token_id);
    let cumulative = cs.exists_one(Fp::from(inputs.cumulative));
    range_check_n_64(cs, &cumulative);
    let (sig_r, sig_s) = signature(&inputs.sig)?;
    let (low, high) = shifted_scalar(&sig_s);
    let [r, low_bit, high254] = cs.exists([sig_r, low, high]);
    let low_bit = low_bit.assert_bool(cs);
    let sig = Signature { r, s: ShiftedScalar { low_bit, high254 } };

    // the wrapper: the blinding value of the call data
    let blinding = cs.exists_one(inputs.blinding);

    // `land`
    let (px, podd) = public_key(&inputs.payer)?;
    let payer = witness_public_key(cs, px, podd); // payer.getAndRequireEquals()
    let landed = cs.exists_one(Fp::from(inputs.landed)); // landed.getAndRequireEquals()
    range_check_n_64(cs, &landed);
    let prefix = poseidon::salted_state("CodaSignature*******");
    let ok = signature::verify(cs, &sig, &payer, &[cumulative.clone()], prefix, &generator());
    ok.assert_true(cs);
    // cumulative.assertGreaterThan(landed)
    assert_less_than_generic_u64(cs, &landed, &cumulative);

    // the wrapper: call data = hash([argsSize, ...args packed, returnSize, name, blinding])
    let packed_args = cumulative.mul_const(Fp::from(2u64)).add(&sig.s.low_bit.to_field());
    let call_data_fields = vec![
        Field::from_u64(4),
        sig.r.clone(),
        sig.s.high254.clone(),
        packed_args,
        Field::from_u64(0),
        Field::constant(string_to_field("land")),
        blinding,
    ];
    let call_data = poseidon::hash(cs, &call_data_fields);
    // setKind: the proof authorization carries the verification key hash
    let verification_key_hash = cs.exists_one(inputs.vk_hash);
    // the account update hash
    let body = Body {
        public_key_x: zkapp.x.clone(),
        public_key_is_odd: zkapp.is_odd.to_field(),
        app_state0: cumulative.clone(),
        call_data,
        state_preconditions: [landed.clone(), payer.x.clone(), payer.is_odd.to_field()],
        verification_key_hash,
    };
    let (fields, packed) = body.input();
    let input = pack_to_fields(fields, packed);
    let prefix = poseidon::salted_state("TestnetZkappBody****").map(Field::constant);
    Ok(poseidon::update(cs, prefix, &input)[0].value())
}

/// Pickles: the verification key index, hashed with the app state into the public input.
pub fn step_statement_hash(cs: &mut Cs, inputs: &LandInputs) -> anyhow::Result<Fp> {
    let vk = crate::verify::load_vk(&inputs.vk)?;
    let start = cs.next_var();
    let ((), aux) = from_fork(|w: &mut Witness<Fp>| {
        w.exists((*vk.wrap_index).clone());
    });
    cs.extend(aux);
    let mut sponge = Sponge::new();
    // the 56 fields of the 28 commitments are the first variables `exists` created
    for i in 0..56 {
        let index_field = cs.var(start + i);
        sponge.absorb(cs, &index_field);
    }
    for var in [1, 2] {
        let app_state = cs.var(var);
        sponge.absorb(cs, &app_state);
    }
    Ok(sponge.squeeze(cs).value())
}
