//! Prove `land` in Rust, for a transaction o1js built: `o1js/src/rust-land.lightnet.ts` runs it.
//!
//! Reads JSON from stdin, `inputs.json`'s fields plus `landed` and `blinding` as decimal strings.
//! Writes JSON to stdout: `proof` as a transaction carries it, `programProof` as o1js's `verify`
//! reads it, and `publicInputFields`.

use std::io::Read;

use mina_curves::pasta::Fp;
use zk_prover::{land_program::LandProgram, witness::land::LandInputs};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/fixtures/{name}.gz", env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut out)
        .unwrap();
    out
}

fn main() -> anyhow::Result<()> {
    let v: serde_json::Value = serde_json::from_reader(std::io::stdin())?;
    let field = |k: &str| v[k].as_str().ok_or_else(|| anyhow::anyhow!("missing {k}"));
    let blinding: Fp = field("blinding")?.parse().map_err(|_| anyhow::anyhow!("bad blinding"))?;
    let inputs = LandInputs::from_json(&v, field("landed")?.parse()?, blinding)?;
    let proved = LandProgram::load(fixture)?.prove_land(&inputs)?;
    println!(
        "{}",
        serde_json::json!({
            "proof": proved.proof.to_o1js_base64(),
            "programProof": proved.proof.to_o1js_program_base64()?,
            "publicInputFields": proved.public_input.map(|f| f.to_string()),
        })
    );
    Ok(())
}
