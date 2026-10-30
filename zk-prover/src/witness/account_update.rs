//! The body of `Land`'s account update, as o1js hashes it.
//!
//! `AccountUpdate.hash` is `Poseidon.hashWithPrefix(prefix, packToFields(Types.AccountUpdate.toInput))`.
//! The input of `toInput` for the account update `land` builds has 86 fields and 178 packed
//! values (value, bit length). All of them are constants of the account update's layout and
//! defaults, except a few that come from the circuit: the zkApp's address, the new `landed` state,
//! the call data hash, the three state preconditions and the verification key hash.
//! [`Body::input`] puts those into the template below.
//!
//! The template was dumped from o1js 3.1.0 by `fixture-gen/trace-land.mjs`, which logs the
//! `toInput` of the account update that `AccountUpdate.hash` hashes inside the circuit.

use ark_ff::Field as _;
use mina_curves::pasta::Fp;
use std::str::FromStr;

use super::Field;

/// The number of fields in `toInput`.
pub const N_FIELDS: usize = 86;

/// The non-zero constants among the fields: the token id (the default, 1), the hashes of the
/// empty events and actions, of the empty zkApp URI and of the empty receipt chain.
const FIELD_CONSTANTS: [(usize, &str); 5] = [
    (1, "1"),
    (36, "22930868938364086394602058221028773520482901241511717002947639863679740444066"),
    (38, "11558119263070965853863267079253872832625419457395008685779236645292569607921"),
    (39, "2965377540200775924504968637505084669999360240500907972788072774778139588064"),
    (84, "25079927036070901246064867767436987657692091363973573142121686150614948079097"),
];

/// `(bit length, value)` of the packed values. The first one, the parity of the zkApp's address,
/// is a variable: its value here is a placeholder.
const PACKED: [(u8, u64); 178] = [
    (1, 0), (1, 1), (1, 0), (1, 0), (1, 0), (1, 0),
    (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0),
    (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0),
    (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0),
    (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0),
    (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0),
    (1, 0), (1, 1), (1, 0), (1, 1), (1, 1), (1, 0),
    (1, 1), (1, 1), (1, 0), (1, 1), (1, 1), (1, 0),
    (1, 1), (1, 1), (1, 0), (1, 1), (1, 1), (1, 0),
    (1, 1), (1, 1), (1, 0), (1, 1), (32, 4), (1, 1),
    (1, 0), (1, 1), (1, 1), (1, 0), (1, 1), (1, 1),
    (1, 0), (1, 1), (1, 1), (1, 0), (1, 1), (1, 1),
    (1, 0), (1, 1), (1, 1), (1, 0), (1, 1), (1, 0),
    (1, 0), (48, 0), (1, 0), (64, 0), (32, 0), (64, 0),
    (32, 0), (64, 0), (1, 0), (64, 0), (1, 1), (1, 0),
    (1, 0), (1, 0), (32, 0), (32, 4294967295), (1, 0), (32, 0),
    (32, 4294967295), (1, 0), (64, 0), (64, 18446744073709551615), (1, 0), (32, 0),
    (32, 4294967295), (1, 0), (1, 0), (64, 0), (64, 18446744073709551615), (1, 0),
    (1, 0), (1, 0), (1, 0), (32, 0), (32, 4294967295), (1, 0),
    (1, 0), (64, 0), (64, 18446744073709551615), (1, 0), (1, 0), (1, 0),
    (1, 0), (32, 0), (32, 4294967295), (1, 0), (64, 0), (64, 18446744073709551615),
    (1, 0), (32, 0), (32, 4294967295), (1, 0), (1, 0), (1, 0),
    (1, 1), (1, 1), (1, 1), (1, 0), (1, 0), (1, 0),
    (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0),
    (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0),
    (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0),
    (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0),
    (1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (1, 0),
    (1, 0), (1, 0), (32, 0), (32, 4294967295), (1, 0), (1, 0),
    (1, 0), (1, 0), (1, 0), (1, 1),
];

/// What the circuit supplies to the account update.
pub struct Body {
    /// The zkApp's address, `publicKey.x` and the parity of `y`.
    pub public_key_x: Field,
    pub public_key_is_odd: Field,
    /// `update.appState[0].value`: the new `landed`.
    pub app_state0: Field,
    /// `callData`.
    pub call_data: Field,
    /// `preconditions.account.state[0..3].value`: `landed`, `payer.x` and `payer.isOdd`.
    pub state_preconditions: [Field; 3],
    /// `authorizationKind.verificationKeyHash`.
    pub verification_key_hash: Field,
}

impl Body {
    /// The `fields` and `packed` of `toInput`.
    pub fn input(&self) -> (Vec<Field>, Vec<(Field, u32)>) {
        let mut fields: Vec<Field> = vec![Field::zero(); N_FIELDS];
        for (i, v) in FIELD_CONSTANTS {
            fields[i] = Field::constant(Fp::from_str(v).unwrap());
        }
        fields[0] = self.public_key_x.clone();
        fields[2] = self.app_state0.clone();
        fields[40] = self.call_data.clone();
        fields[52] = self.state_preconditions[0].clone();
        fields[53] = self.state_preconditions[1].clone();
        fields[54] = self.state_preconditions[2].clone();
        fields[85] = self.verification_key_hash.clone();
        let mut packed: Vec<(Field, u32)> = PACKED
            .iter()
            .map(|&(bits, v)| (Field::constant(Fp::from(v)), bits as u32))
            .collect();
        packed[0].0 = self.public_key_is_odd.clone();
        (fields, packed)
    }
}

/// `packToFields`: the fields, then the packed values combined into as few fields as fit.
pub fn pack_to_fields(fields: Vec<Field>, packed: Vec<(Field, u32)>) -> Vec<Field> {
    if packed.is_empty() {
        return fields;
    }
    let mut out = fields;
    let mut current = Field::zero();
    let mut current_size = 0u32;
    let mut packed_fields = Vec::new();
    for (field, size) in packed {
        current_size += size;
        if current_size < 255 {
            // `currentPackedField.mul(Field(1n << size)).add(field)`: a constant factor, no variable
            let two_to_size = Fp::from(2u64).pow([size as u64]);
            current = current.mul_const(two_to_size).add(&field);
        } else {
            packed_fields.push(current);
            current_size = size;
            current = field;
        }
    }
    packed_fields.push(current);
    out.extend(packed_fields);
    out
}
