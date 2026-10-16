use o1_utils::FieldHelpers;
use serde::Deserialize;
use zk_note::{poseidon, Field};

#[derive(Deserialize)]
struct VectorFile {
    test_vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    input: Vec<String>,
    output: String,
}

fn field(hex: &str) -> Field {
    Field::from_hex(hex).expect("field element hex")
}

#[test]
fn reproduces_every_shared_vector() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/poseidon-kimchi.json");
    let file: VectorFile = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert!(!file.test_vectors.is_empty(), "zero vector cases ran");
    for (i, v) in file.test_vectors.iter().enumerate() {
        let input: Vec<Field> = v.input.iter().map(|h| field(h)).collect();
        assert_eq!(poseidon(&input), field(&v.output), "vector {i}");
    }
    println!("vector cases run: {}", file.test_vectors.len());
}
