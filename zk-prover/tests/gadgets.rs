//! Each gadget mirror against the values of o1js's witness for `land` (`w003_cs003`).

use std::{io::Read, str::FromStr};

use mina_curves::pasta::Fp;
use zk_prover::witness::{
    gadgets::poseidon,
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
