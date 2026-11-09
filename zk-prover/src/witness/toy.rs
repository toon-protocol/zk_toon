//! The toy zkApp's methods (`fixture-gen/toy.mjs`): `plain`, which verifies no proof, and `recurse`,
//! which verifies a proof of the ZkProgram `toy-inner`. Each is the method, the SmartContract wrapper
//! around it and the Pickles step circuit around that, in the order o1js and Pickles create their
//! variables (see [`super::land`], which has the same layers).
//!
//! ```text
//! Pickles   app state (the account update hash and the calls hash), dummy_constraints
//! wrapper   witness the arguments (address, token id, then the method's: `x`, and for `recurse` the
//!           public input of the proof) and the blinding
//! method    `plain`: x.assertEquals(x); `recurse`: proof.verify(); proof.publicInput.assertEquals(x)
//! wrapper   call data hash, setKind (the verification key hash), the account update hash
//! Pickles   the verification key index, the previous proof (previous_proof::step_main_tail), the
//!           hash of the step statement
//! ```
//!
//! Neither method creates a variable of its own: an `assertEquals` of two variables is one gate.

use ark_ff::Zero;
use mina_curves::pasta::Fp;

use super::{
    account_update::{pack_to_fields, Body},
    gadgets::{
        poseidon,
        signature::witness_public_key,
        state::set_kind,
    },
    land::{public_key, string_to_field},
    pickles,
    previous_proof::step_main_tail,
    Cs, Field,
};
use crate::{verify::load_vk, wrap::PreviousProof};

/// The toy zkApp's `maxProofsVerified`: `recurse` verifies one proof, `plain` none.
const MAX_PROOFS_VERIFIED: usize = 1;

/// Everything the toy methods' witnesses depend on besides the previous proof.
#[derive(Clone, Debug)]
pub struct ToyInputs {
    /// The zkApp's address (base58).
    pub zkapp: String,
    /// The method's `x` argument.
    pub x: Fp,
    /// The token id argument; the zkApp's own token is `1`, MINA.
    pub token_id: Fp,
    /// The blinding value of the call data (`Fp.random()` in o1js).
    pub blinding: Fp,
    /// The zkApp's verification key `data` (base64) and its hash.
    pub vk: String,
    pub vk_hash: Fp,
}

impl ToyInputs {
    /// Inputs in `toy_inputs.json`'s form (`zkapp`, `vk`, `vkHash`), with what the file leaves out.
    pub fn from_json(v: &serde_json::Value, x: Fp, blinding: Fp) -> anyhow::Result<Self> {
        let s = |k: &str| {
            v[k].as_str().map(String::from).ok_or_else(|| anyhow::anyhow!("missing {k}"))
        };
        Ok(Self {
            zkapp: s("zkapp")?,
            x,
            token_id: Fp::from(1u64),
            blinding,
            vk: s("vk")?,
            vk_hash: s("vkHash")?.parse().map_err(|_| anyhow::anyhow!("bad vkHash"))?,
        })
    }
}

/// The result: the public input and the auxiliary values.
pub struct ToyWitness {
    pub primary: Vec<Fp>,
    pub aux: Vec<Fp>,
    /// The account update's hash, the first field of the method's public input.
    pub account_update_hash: Fp,
}

impl From<ToyWitness> for crate::StepWitness {
    /// The witness in the form [`crate::prove_step`] and [`crate::check_step`] take.
    fn from(w: ToyWitness) -> Self {
        crate::StepWitness::from_parts(w.primary, w.aux)
    }
}

/// The witness of `plain(x)`. The zkApp's program verifies at most one proof.
pub fn plain_witness(inputs: &ToyInputs) -> anyhow::Result<ToyWitness> {
    witness(inputs, "plain", None)
}

/// The witness of `recurse(x, proof)`: `previous` is the proof of `toy-inner` and its public input,
/// which `recurse` checks equals `x`.
pub fn recurse_witness(inputs: &ToyInputs, previous: &PreviousProof) -> anyhow::Result<ToyWitness> {
    witness(inputs, "recurse", Some(previous))
}

fn witness(inputs: &ToyInputs, name: &str, previous: Option<&PreviousProof>) -> anyhow::Result<ToyWitness> {
    let mut cs = Cs::new();
    // Pickles: the app state (a placeholder: see `land::land_witness`), `dummy_constraints`
    pickles::prelude(&mut cs, Fp::zero(), Fp::zero());

    // the arguments: the address, the token id, then the method's own
    let (zx, zodd) = public_key(&inputs.zkapp)?;
    let zkapp = witness_public_key(&mut cs, zx, zodd);
    let _token_id = cs.exists_one(inputs.token_id);
    let x = cs.exists_one(inputs.x);
    let proof_input = previous
        .map(|p| {
            anyhow::ensure!(p.public_input.len() == 1, "toy-inner's public input is one field");
            Ok(cs.exists_one(p.public_input[0]))
        })
        .transpose()?;
    // the wrapper: the blinding value of the call data
    let blinding = cs.exists_one(inputs.blinding);

    // the call data: hash([argsSize, ...args, returnSize, name, blinding]); a proof is not hashable
    // as an input, so it goes in as its size and its fields
    let mut call_data_fields = vec![Field::from_u64(if proof_input.is_some() { 2 } else { 1 }), x];
    if let Some(p) = proof_input {
        call_data_fields.extend([Field::from_u64(1), p]);
    }
    call_data_fields.extend([Field::from_u64(0), Field::constant(string_to_field(name)), blinding]);
    let call_data = poseidon::hash(&mut cs, &call_data_fields);
    // setKind: the proof authorization carries the verification key hash
    let verification_key_hash = set_kind(&mut cs, inputs.vk_hash);
    // the account update hash
    let body = Body {
        public_key_x: zkapp.x.clone(),
        public_key_is_odd: zkapp.is_odd.to_field(),
        app_state0: None,
        call_data,
        state_preconditions: None,
        verification_key_hash,
    };
    let (fields, packed) = body.input();
    let input = pack_to_fields(fields, packed);
    let prefix = poseidon::salted_state("TestnetZkappBody****").map(Field::constant);
    let account_update_hash = poseidon::update(&mut cs, prefix, &input)[0].value();
    cs.set(1, account_update_hash);

    // Pickles: the rest of the step circuit, with the previous proof
    let vk = load_vk(&inputs.vk)?;
    let previous: Vec<PreviousProof> = previous.copied().into_iter().collect();
    let primary = step_main_tail(&mut cs, &vk, MAX_PROOFS_VERIFIED, &previous)?;
    Ok(ToyWitness { primary, aux: cs.into_aux(), account_update_hash })
}
