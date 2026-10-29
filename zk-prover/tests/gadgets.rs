//! Each gadget mirror against the values of o1js's witness for `land` (`w003_cs003`).

use std::{io::Read, str::FromStr};

use mina_curves::pasta::Fp;
use zk_prover::witness::{
    Bool,
    gadgets::{
        comparison,
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
