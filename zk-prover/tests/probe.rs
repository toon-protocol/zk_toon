use std::io::Read;
use std::str::FromStr;
use base64::Engine as _;
use ledger::proofs::{
    public_input::{messages::MessagesForNextWrapProof, prepared_statement::*},
    transaction::{InnerCurve, ProofWithPublic},
};
use mina_curves::pasta::{Fp, Fq};
use zk_prover::{StepCircuit, StepLand, StepWitness};
use ark_ff::BigInteger256;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/fixtures/{name}.gz", env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap()).read_to_end(&mut out).unwrap();
    out
}

#[test]
fn probe() {
    let b64 = fixture("stepproof002.b64");
    let bytes = base64::engine::general_purpose::STANDARD.decode(String::from_utf8(b64).unwrap().trim()).unwrap();
    let proof: ledger::proofs::ProverProof<Fp> = rmp_serde::from_slice(&bytes).unwrap();
    let circuit = StepCircuit::load::<StepLand>(&fixture("cs003_gates.json"), &fixture("cs003_internal_vars.bin"), &fixture("cs003_rows_rev.bin")).unwrap();
    let w003: serde_json::Value = serde_json::from_slice(&fixture("w003_cs003.json")).unwrap();
    let hash = Fp::from_str("5479777612847298901252546675711013743755383923775450983093371445166541101881").unwrap(); let _ = &w003;
    let pwp = ProofWithPublic { proof, public_input: vec![hash] };
    let features = zk_prover::wrap::deferred::step_features(circuit.index());
    eprintln!("features {features:?}");
    let d = zk_prover::wrap::deferred::deferred_values(zk_prover::wrap::deferred::DeferredValuesParams {
        prev_challenges: vec![], proof_with_public: &pwp, actual_proofs_verified: 0, prover_index: circuit.index(), features,
    });
    let mfnw = MessagesForNextWrapProof { challenge_polynomial_commitment: InnerCurve::of_affine(pwp.proof.proof.sg), old_bulletproof_challenges: vec![] };
    let h: [u64;4] = mfnw.hash();
    let to_u = |f: Fp| { let b: BigInteger256 = f.into(); b.0 };
    let ps = PreparedStatement {
        proof_state: ProofState { deferred_values: d.deferred_values.clone(), sponge_digest_before_evaluations: to_u(d.sponge_digest_before_evaluations), messages_for_next_wrap_proof: h },
        messages_for_next_step_proof: to_u(hash),
    };
    let pi = ps.to_public_input(40).unwrap();
    let w004: serde_json::Value = serde_json::from_slice(&fixture("w004_cs005.json")).unwrap();
    for i in 0..40 {
        let e = Fq::from_str(w004["external"][i].as_str().unwrap()).unwrap();
        eprintln!("{i}: {} {}", if e == pi[i] {"ok"} else {"DIFF"}, w004["external"][i].as_str().unwrap().chars().take(20).collect::<String>());
    }
}

#[test]
fn probe_verify() {
    use kimchi::{groupmap::GroupMap, mina_curves::pasta::VestaParameters};
    use mina_poseidon::sponge::{DefaultFqSponge, DefaultFrSponge};
    use poly_commitment::ipa::OpeningProof;
    use ledger::proofs::FULL_ROUNDS;
    type SpongeParams = mina_poseidon::constants::PlonkSpongeConstantsKimchi;
    type EFqSponge = DefaultFqSponge<VestaParameters, SpongeParams, FULL_ROUNDS>;
    type EFrSponge = DefaultFrSponge<Fp, SpongeParams, FULL_ROUNDS>;
    let b64 = fixture("stepproof002.b64");
    let bytes = base64::engine::general_purpose::STANDARD.decode(String::from_utf8(b64).unwrap().trim()).unwrap();
    let proof: ledger::proofs::ProverProof<Fp> = rmp_serde::from_slice(&bytes).unwrap();
    let circuit = StepCircuit::load::<StepLand>(&fixture("cs003_gates.json"), &fixture("cs003_internal_vars.bin"), &fixture("cs003_rows_rev.bin")).unwrap();
    let vk = circuit.index().verifier_index();
    let group_map = GroupMap::<Fq>::setup();
    for s in ["798060330016839513246782929849628293102203714151290313274921527397100856306", "5479777612847298901252546675711013743755383923775450983093371445166541101881"] {
        let pi = vec![Fp::from_str(s).unwrap()];
        let r = kimchi::verifier::verify::<FULL_ROUNDS, kimchi::mina_curves::pasta::Vesta, EFqSponge, EFrSponge, OpeningProof<kimchi::mina_curves::pasta::Vesta, FULL_ROUNDS>>(&group_map, &vk, &proof, &pi);
        eprintln!("{s}: {:?}", r.is_ok());
    }
}
