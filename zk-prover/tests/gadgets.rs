//! Each gadget mirror against the values of o1js's witness for `land` (`w003_cs003`).

use std::{io::Read, str::FromStr};

use mina_curves::pasta::Fp;
use zk_prover::witness::{
    Bool,
    gadgets::{
        comparison, foreign_field,
        native_curve::{self, Point, ShiftedScalar},
        poseidon, range_check,
        signature::{self, PublicKey, Signature},
    },
    pickles, Cs, Field,
};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/fixtures/{name}.gz", env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut out)
        .unwrap();
    out
}

/// o1js's witness: the public input, then the auxiliary values (`external[i]` is variable `i`).
fn o1js() -> &'static Vec<Fp> {
    static W: std::sync::OnceLock<Vec<Fp>> = std::sync::OnceLock::new();
    W.get_or_init(|| {
        let v: serde_json::Value = serde_json::from_slice(&fixture("w003_cs003.json")).unwrap();
        v["external"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| Fp::from_str(x.as_str().unwrap()).unwrap())
            .collect()
    })
}

/// The auxiliary values `from..to` of o1js's witness (variable `i` is `aux[i - 1]`).
fn expected(from: usize, to: usize) -> &'static [Fp] {
    &o1js()[from..to]
}

/// A `Cs` holding o1js's witness up to (not including) variable `from`.
fn resume(from: usize) -> Cs {
    Cs::resume(&o1js()[1..from])
}

/// Compare what the gadget created (from variable `from`) with o1js's witness, reporting the first
/// differing variable.
fn check(cs: &Cs, from: usize, to: usize) {
    let got = &cs.aux()[from - 1..];
    let want = expected(from, to);
    for (k, (g, w)) in got.iter().zip(want).enumerate() {
        assert_eq!(g, w, "variable {} differs", from + k);
    }
    assert_eq!(got.len(), want.len(), "created {} variables, o1js {}", got.len(), want.len());
}

fn var(cs: &Cs, i: usize) -> Field {
    cs.var(i)
}

#[test]
fn prelude_matches() {
    let mut cs = Cs::new();
    pickles::prelude(&mut cs, o1js()[1], o1js()[2]);
    check(&cs, 1, 89);
}

/// The hash of the signature (`Signature.verify`): two blocks from a constant state.
#[test]
fn poseidon_update_signature_hash() {
    let mut cs = resume(342);
    let state = [
        Field::constant(Fp::from_str("6547874669265470003564181123405173756111990160585052594027544303901364349512").unwrap()),
        Field::constant(Fp::from_str("22191763046611062479784309793717481299019591714391827084400612211604078633201").unwrap()),
        Field::constant(Fp::from_str("15360317550574394687602808211901764964514686767298144053612144955373862517277").unwrap()),
    ];
    let input = [var(&cs, 93), var(&cs, 143), var(&cs, 339), var(&cs, 138)];
    poseidon::update(&mut cs, state, &input);
    check(&cs, 342, 682);
}

/// `UInt64.check` of the witnessed `cumulative`: `rangeCheckN(64, x)`.
#[test]
fn range_check_n_64_uint64_check() {
    let mut cs = resume(94);
    let x = var(&cs, 93);
    range_check::range_check_n_64(&mut cs, &x);
    check(&cs, 94, 138);
}

/// `isOddAndHigh(y)` in `PublicKey.toGroup`.
#[test]
fn is_odd_and_high_public_key_to_group() {
    let mut cs = resume(196);
    let y = var(&cs, 193);
    comparison::is_odd_and_high(&mut cs, &y);
    check(&cs, 196, 336);
}

/// `scaleField(P, h)` of `Group.scale(h)` in `Signature.verify`.
#[test]
fn scale_field_signature_verify() {
    let mut cs = resume(682);
    let p = Point { x: var(&cs, 143), y: var(&cs, 339) };
    let h = var(&cs, 679);
    native_curve::scale_field(&mut cs, &p, &h);
    check(&cs, 682, 2447);
}

/// `scaleShifted(generator, s)` of `Group.generator.scale(this.s)` in `Signature.verify`.
#[test]
fn scale_shifted_signature_verify() {
    let mut cs = resume(2447);
    // Pallas's generator
    let g = Point::constant(
        Fp::from(1u64),
        Fp::from_str("12418654782883325593414442427049395787963493412651469444558597405572177144507").unwrap(),
    );
    let s = ShiftedScalar { low_bit: Bool(var(&cs, 139)), high254: var(&cs, 140) };
    native_curve::scale_shifted(&mut cs, &g, &s, 254);
    check(&cs, 2447, 4094);
}

fn generator() -> Point {
    Point::constant(
        Fp::from(1u64),
        Fp::from_str("12418654782883325593414442427049395787963493412651469444558597405572177144507").unwrap(),
    )
}

/// `Signature.verify(payer, [cumulative])`, with `PublicKey.toGroup` inside: variables 191..4286.
#[test]
fn signature_verify() {
    let mut cs = resume(191);
    let sig = Signature {
        r: var(&cs, 138),
        s: ShiftedScalar { low_bit: Bool(var(&cs, 139)), high254: var(&cs, 140) },
    };
    let payer = PublicKey { x: var(&cs, 143), is_odd: Bool(var(&cs, 144)) };
    let msg = [var(&cs, 93)];
    let prefix = [
        Fp::from_str("6547874669265470003564181123405173756111990160585052594027544303901364349512").unwrap(),
        Fp::from_str("22191763046611062479784309793717481299019591714391827084400612211604078633201").unwrap(),
        Fp::from_str("15360317550574394687602808211901764964514686767298144053612144955373862517277").unwrap(),
    ];
    signature::verify(&mut cs, &sig, &payer, &msg, prefix, &generator());
    check(&cs, 191, 4286);
}

#[test]
fn salted_prefix_states() {
    let s = poseidon::salted_state("CodaSignature*******");
    assert_eq!(
        s[0],
        Fp::from_str("6547874669265470003564181123405173756111990160585052594027544303901364349512").unwrap()
    );
    let s = poseidon::salted_state("TestnetZkappBody****");
    assert_eq!(
        s[0],
        Fp::from_str("20037733640875789833090442509053816933966165101372309054048970230906793051053").unwrap()
    );
}

/// `Field.square`, `Field.mul`, `Field.sqrt` as `PublicKey.toGroup` uses them, and the rest of it
/// up to the Poseidon hash.
#[test]
fn public_key_to_group_up_to_the_hash() {
    let mut cs = resume(191);
    let pk = PublicKey { x: var(&cs, 143), is_odd: Bool(var(&cs, 144)) };
    signature::public_key_to_group(&mut cs, &pk);
    check(&cs, 191, 342);
}

/// `Field.sqrt` alone: the witness and the reduction of its argument (`x^3 + 5`).
#[test]
fn field_square_mul_sqrt() {
    let mut cs = resume(191);
    let x = var(&cs, 143);
    let x2 = x.square(&mut cs);
    let x3 = x2.mul(&mut cs, &x);
    x3.add_const(Fp::from(5u64)).sqrt(&mut cs);
    check(&cs, 191, 196);
}

/// `multiRangeCheck` of the three limbs of a field element.
#[test]
fn multi_range_check_limbs() {
    let mut cs = resume(202);
    let limbs = [var(&cs, 199), var(&cs, 200), var(&cs, 201)];
    range_check::multi_range_check(&mut cs, &limbs);
    check(&cs, 202, 255);
}

/// `fieldToField3`: witness the limbs, range check them, prove they add up to `x`.
#[test]
fn field_to_field3_limbs() {
    let mut cs = resume(199);
    let x = var(&cs, 197);
    comparison::field_to_field3(&mut cs, &x);
    check(&cs, 199, 257);
}

/// `ForeignField.negate`, with its chain row, zero row and range check.
#[test]
fn foreign_field_negate() {
    use num_bigint::BigInt;
    let mut cs = resume(257);
    let x = [var(&cs, 199), var(&cs, 200), var(&cs, 201)];
    // (p + 1) / 2 - 1, the bound `z.assertLessThan((p + 1) / 2)` negates against
    let p = comparison::fp_modulus();
    foreign_field::negate(&mut cs, &x, &(((p + 1) >> 1u32) - BigInt::from(1)));
    check(&cs, 257, 333);
}

/// `assertLessThanFull(z, (p + 1) / 2)`.
#[test]
fn assert_less_than_full_constant_bound() {
    use num_bigint::BigInt;
    let mut cs = resume(199);
    let z = var(&cs, 197);
    let half = comparison::fp_modulus() + BigInt::from(1);
    let half = zk_prover::witness::gadgets::foreign_field::big_to_fp(&(half >> 1u32));
    comparison::assert_less_than_full(&mut cs, &z, &Field::constant(half));
    check(&cs, 199, 333);
}

/// `Field.seal` of `sHi + shiftHi`.
#[test]
fn field_seal_of_a_sum() {
    let mut cs = resume(822);
    let s_hi = var(&cs, 683);
    let shift_hi = Fp::from_str("45560315531506369815346746415080538113").unwrap();
    s_hi.add_const(shift_hi).seal(&mut cs);
    check(&cs, 822, 825);
}

/// `Field.equals(0)`.
#[test]
fn field_equals_zero() {
    let mut cs = resume(825);
    let s_hi = var(&cs, 683);
    s_hi.equals(&mut cs, &Field::zero());
    check(&cs, 825, 830);
}

/// `ifField`, as `Provable.if` uses it for a field.
#[test]
fn if_field_edge_case() {
    let mut cs = resume(830);
    let b = var(&cs, 825);
    let t_hi = var(&cs, 822);
    native_curve::if_field(&mut cs, &b, &Field::zero(), &t_hi);
    check(&cs, 830, 833);
}

/// `Group.add` with its zero cases: `add`, `isZero` twice, `Bool.and`, `Bool.or`, `switch`.
#[test]
fn group_add_with_switch() {
    let mut cs = resume(4094);
    // the operands in `Signature.verify`: -(h * P), from `scaleField`, and g * s, from `scaleShifted`
    let this = Point { x: var(&cs, 2441), y: var(&cs, 2446).neg() };
    let g = Point { x: var(&cs, 4088), y: var(&cs, 4092) };
    native_curve::group_add(&mut cs, &this, &g);
    check(&cs, 4094, 4130);
}

/// `UInt64.assertLessThan`: `cumulative - 1 - landed` is sealed and range checked.
#[test]
fn assert_less_than_generic_uint64() {
    let mut cs = resume(4286);
    let (landed, cumulative) = (var(&cs, 146), var(&cs, 93));
    comparison::assert_less_than_generic_u64(&mut cs, &landed, &cumulative);
    check(&cs, 4286, 4332);
}

/// The call data hash: `Poseidon.hash([4, r, s.high254, 2*cumulative + s.lowBit, 0, "land", blinding])`.
#[test]
fn poseidon_hash_call_data() {
    let mut cs = resume(4332);
    let cumulative = var(&cs, 93);
    let packed = cumulative.mul_const(Fp::from(2u64)).add(&var(&cs, 139));
    let name = Fp::from(0x1_646e_616cu64);
    let input = [
        Field::from_u64(4),
        var(&cs, 138),
        var(&cs, 140),
        packed,
        Field::zero(),
        Field::constant(name),
        var(&cs, 142),
    ];
    poseidon::hash(&mut cs, &input);
    check(&cs, 4332, 5008);
}

/// The account update hash: the template's fields with the circuit's values in, packed.
#[test]
fn account_update_hash() {
    use zk_prover::witness::account_update::{pack_to_fields, Body};
    let mut cs = resume(5009);
    let body = Body {
        public_key_x: var(&cs, 89),
        public_key_is_odd: var(&cs, 90),
        app_state0: var(&cs, 93),
        call_data: var(&cs, 5005),
        state_preconditions: [var(&cs, 146), var(&cs, 143), var(&cs, 144)],
        verification_key_hash: var(&cs, 5008),
    };
    let (fields, packed) = body.input();
    let input = pack_to_fields(fields, packed);
    assert_eq!(input.len(), 94);
    let state = poseidon::salted_state("TestnetZkappBody****").map(Field::constant);
    poseidon::update(&mut cs, state, &input);
    check(&cs, 5009, 12923);
}

/// The verification key index and the hash of the step statement, which is the public input.
#[test]
fn step_statement_hash() {
    let v: serde_json::Value = serde_json::from_slice(&fixture("inputs.json")).unwrap();
    let inputs = zk_prover::witness::land::LandInputs {
        zkapp: String::new(),
        payer: String::new(),
        cumulative: 0,
        sig: String::new(),
        landed: 0,
        token_id: Fp::from(0u64),
        blinding: Fp::from(0u64),
        vk: v["vk"].as_str().unwrap().to_string(),
        vk_hash: Fp::from(0u64),
    };
    let mut cs = resume(12923);
    let public_input = zk_prover::witness::land::step_statement_hash(&mut cs, &inputs).unwrap();
    check(&cs, 12923, 17963);
    assert_eq!(public_input, o1js()[0]);
}
