//! A nullifier crosses the challenger's ports as 32 bytes: the Pallas field element, little-endian and
//! canonical.
use std::str::FromStr;

use zk_note::Field;
use zk_toon_challenger_mina::{field_of_nullifier, nullifier_of_field};

#[test]
fn a_nullifier_is_its_field_element_little_endian() {
    let mut expected = [0u8; 32];
    expected[0] = 0x02;
    expected[1] = 0x01;
    assert_eq!(nullifier_of_field(Field::from(0x0102u64)), expected);
    assert_eq!(field_of_nullifier(&expected), Some(Field::from(0x0102u64)));
}

#[test]
fn the_largest_field_element_round_trips_and_the_modulus_is_refused() {
    // The Pallas base field's modulus, p = 2^254 + 45560315531419706090280762371685220353.
    let p_minus_1 =
        Field::from_str("28948022309329048855892746252171976963363056481941560715954676764349967630336").unwrap();
    let bytes = nullifier_of_field(p_minus_1);
    assert_eq!(bytes[31], 0x40);
    assert_eq!(bytes[0], 0x00);
    assert_eq!(field_of_nullifier(&bytes), Some(p_minus_1));

    let mut modulus = bytes;
    modulus[0] = 0x01;
    assert_eq!(field_of_nullifier(&modulus), None);
    assert_eq!(field_of_nullifier(&[0xff; 32]), None);
}
