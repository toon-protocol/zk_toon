//! Verify an o1js ZkProgram proof under a verification key.
//!
//! Derived from `toon-protocol/zk-note-vectors` `rust/mesa-toon-1512/src/main.rs` at commit
//! `384a0907078edb50ff840805a7011cae055c28b8` (connector#1512), which builds on mina-rust.
//! Licensed under Apache-2.0; see `LICENSE-APACHE` and `NOTICE`.

use std::str::FromStr;

use base64::Engine as _;
use ledger::{
    proofs::verification::verify_sideloaded,
    verifier::get_srs,
    VerificationKey,
};
use mina_curves::pasta::Fp;
use mina_p2p_messages::{
    binprot::BinProtRead,
    v2::{
        MinaBaseVerificationKeyWireStableV1, PicklesProofProofsVerified2ReprStableV2,
        PicklesProofProofsVerifiedMaxStableV2,
    },
};

/// A Pickles proof, as the side-loaded verifier reads it (at `maxProofsVerified` 2).
pub struct WrapProof(PicklesProofProofsVerified2ReprStableV2);

/// Decode o1js's base64 binprot verification key (`verificationKey.data`).
pub fn load_vk(b64: &str) -> anyhow::Result<VerificationKey> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64)?;
    let mut slice = bytes.as_slice();
    let wire = MinaBaseVerificationKeyWireStableV1::binprot_read(&mut slice)?;
    anyhow::ensure!(slice.is_empty(), "trailing bytes after the verification key");
    VerificationKey::try_from(&wire).map_err(|e| anyhow::anyhow!("bad verification key: {e:?}"))
}

/// `messages_for_next_wrap_proof.old_bulletproof_challenges` of a proof's sexp.
fn old_challenges(sexp: &mut rsexp::Sexp) -> anyhow::Result<&mut Vec<rsexp::Sexp>> {
    use rsexp::Sexp;
    fn field<'a>(record: &'a mut Sexp, name: &str) -> anyhow::Result<&'a mut Sexp> {
        let Sexp::List(fields) = record else {
            anyhow::bail!("not a record")
        };
        for f in fields.iter_mut() {
            if let Sexp::List(pair) = f {
                if matches!(&pair[0], Sexp::Atom(a) if a == name.as_bytes()) {
                    return Ok(&mut pair[1]);
                }
            }
        }
        anyhow::bail!("no field {name}")
    }
    let chals = field(
        field(
            field(field(sexp, "statement")?, "proof_state")?,
            "messages_for_next_wrap_proof",
        )?,
        "old_bulletproof_challenges",
    )?;
    let Sexp::List(chals) = chals else {
        anyhow::bail!("not a list")
    };
    Ok(chals)
}

/// This crate's `SexpOf` writes a 64-bit limb as `0x` and 16 hex digits; OCaml writes the 16 digits
/// alone. (A field element is `0x` and 64 digits, and stays.)
fn hex_limbs(sexp: &mut rsexp::Sexp) {
    match sexp {
        rsexp::Sexp::Atom(a) => {
            if a.len() == 18 && a.starts_with(b"0x") {
                a.drain(..2);
            }
        }
        rsexp::Sexp::List(items) => items.iter_mut().for_each(hex_limbs),
    }
}

/// o1js writes a proof at its own `maxProofsVerified`; a side-loaded verifier reads it at the
/// maximum, 2. Pickles' `Wrap_hack.pad_proof` front-extends
/// `messages_for_next_wrap_proof.old_bulletproof_challenges` to length 2 with
/// `Dummy.Ipa.Wrap.challenges`; the step-side lists stay as they are.
fn pad_proof(sexp: &mut rsexp::Sexp) -> anyhow::Result<()> {
    use rsexp::Sexp;
    let chals = old_challenges(sexp)?;
    // Written by hand: this crate's `SexpOf` for a hex64 limb emits `0x…`, which its own `OfSexp`
    // refuses; OCaml writes 16 bare hex digits.
    let atom = |s: &str| Sexp::Atom(s.as_bytes().to_vec());
    let pair = |name: &str, v: Sexp| Sexp::List(vec![atom(name), v]);
    let dummy = Sexp::List(
        ledger::proofs::unfinalized::dummy_ipa_wrap_challenges()
            .iter()
            .map(|[a, b]| {
                let inner =
                    Sexp::List(vec![atom(&format!("{a:016x}")), atom(&format!("{b:016x}"))]);
                Sexp::List(vec![pair(
                    "prechallenge",
                    Sexp::List(vec![pair("inner", inner)]),
                )])
            })
            .collect(),
    );
    while chals.len() < 2 {
        chals.insert(0, dummy.clone());
    }
    Ok(())
}

impl WrapProof {
    /// A proof made by [`crate::wrap::wrap`].
    pub fn from_prover(proof: &ledger::proofs::wrap::WrapProof) -> Self {
        Self(proof.into())
    }

    fn sexp(&self) -> rsexp::Sexp {
        use rsexp::SexpOf;
        let mut sexp = PicklesProofProofsVerifiedMaxStableV2::from(self.0.clone()).sexp_of();
        hex_limbs(&mut sexp);
        sexp
    }

    /// The proof as o1js writes it into a transaction (`proof`): URL-safe base64 of the sexp, at
    /// `maxProofsVerified` 2. The inverse of [`WrapProof::from_o1js_base64`].
    pub fn to_o1js_base64(&self) -> String {
        base64::engine::general_purpose::URL_SAFE.encode(self.sexp().to_bytes_mach())
    }

    /// The proof as o1js's `verify` reads a `JsonProof` for a program that verifies no proofs
    /// (`maxProofsVerified` 0): [`WrapProof::to_o1js_base64`] without the two dummy wrap challenges.
    pub fn to_o1js_program_base64(&self) -> anyhow::Result<String> {
        let mut sexp = self.sexp();
        old_challenges(&mut sexp)?.clear();
        Ok(base64::engine::general_purpose::URL_SAFE.encode(sexp.to_bytes_mach()))
    }

    /// Decode o1js's URL-safe base64 sexp proof (`proof`).
    pub fn from_o1js_base64(b64: &str) -> anyhow::Result<Self> {
        use rsexp::OfSexp;
        let bytes = base64::engine::general_purpose::URL_SAFE.decode(b64)?;
        let mut sexp = rsexp::from_slice(&bytes).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        pad_proof(&mut sexp)?;
        let max = PicklesProofProofsVerifiedMaxStableV2::of_sexp(&sexp)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        Ok(Self((&max).into()))
    }
}

/// Parse decimal field elements, as o1js writes `publicInputFields` / `publicOutputFields`.
pub fn fields(decimals: &[&str]) -> anyhow::Result<Vec<Fp>> {
    decimals
        .iter()
        .map(|s| Fp::from_str(s).map_err(|_| anyhow::anyhow!("bad field element {s}")))
        .collect()
}

/// Whether `proof` verifies under `vk` for the public input and output fields `public`.
pub fn verify(vk: &VerificationKey, public: &[Fp], proof: &WrapProof) -> bool {
    verify_sideloaded(vk, public, &proof.0, &get_srs::<Fp>())
}
