//! Step verification keys as the wrap circuit reads them, and `Wrap_verifier.choose_key`.
//!
//! Derived from `crates/ledger/src/proofs/wrap.rs` (`choose_key`) in `toon-protocol/mina-rust` at
//! rev `6feeb3797fff6dba49fd848cb2d6decd63fee1b4` (itself from `o1-labs/mina-rust` v0.19.0,
//! Apache-2.0), which picks a single key with no optional commitments. The generalisation follows
//! Mina `aa93c444`, `src/lib/pickles/wrap_verifier.ml` (`choose_key`) and
//! `src/lib/crypto/kimchi_backend/common/plonk_verification_key_evals.ml`. Licensed under
//! Apache-2.0; see `LICENSE-APACHE` and `NOTICE`.

use ark_ec::AffineRepr;
use ledger::proofs::{
    field::{Boolean, CircuitVar, GroupAffine},
    transaction::{InnerCurve, PlonkVerificationKeyEvals},
    witness::Witness,
    ProverIndex,
};
use mina_curves::pasta::{Fp, Fq, Vesta};
use poly_commitment::PolyComm;

/// `Pickles_types.Opt`: an optional value, known (`Just`), unknown (`Maybe`) or absent (`Nothing`).
#[derive(Clone, Debug)]
pub enum Opt<T> {
    Nothing,
    Just(T),
    Maybe(CircuitVar<Boolean>, T),
}

impl<T> Opt<T> {
    pub fn map<V>(&self, f: impl FnOnce(&T) -> V) -> Opt<V> {
        match self {
            Opt::Nothing => Opt::Nothing,
            Opt::Just(x) => Opt::Just(f(x)),
            Opt::Maybe(b, x) => Opt::Maybe(*b, f(x)),
        }
    }

    pub fn is_nothing(&self) -> bool {
        matches!(self, Opt::Nothing)
    }
}

/// A commitment, as its chunks (`Inner_curve.t array`).
pub type Comm = Vec<GroupAffine<Fq>>;

/// One step circuit's verification key, as constants for the wrap circuit.
#[derive(Clone, Debug)]
pub struct StepKey {
    pub base: PlonkVerificationKeyEvals<Fq>,
    pub xor: Option<Comm>,
    pub range_check0: Option<Comm>,
    pub range_check1: Option<Comm>,
    pub foreign_field_add: Option<Comm>,
    pub foreign_field_mul: Option<Comm>,
    pub rot: Option<Comm>,
    pub lookup_table: [Option<Comm>; 4],
    pub lookup_table_ids: Option<Comm>,
    pub runtime_tables_selector: Option<Comm>,
    pub lookup_selector_lookup: Option<Comm>,
    pub lookup_selector_xor: Option<Comm>,
    pub lookup_selector_range_check: Option<Comm>,
    pub lookup_selector_ffmul: Option<Comm>,
}

fn comm(c: &PolyComm<Vesta>) -> Comm {
    c.chunks.clone()
}

impl StepKey {
    /// Read the key off a step circuit's kimchi index.
    pub fn of_index(index: &ProverIndex<Fp>) -> Self {
        let vk = index.verifier_index();
        let to_curve = |v: &PolyComm<Vesta>| InnerCurve::<Fq>::of_affine(v.chunks[0]);
        let base = PlonkVerificationKeyEvals {
            sigma: vk.sigma_comm.each_ref().map(to_curve),
            coefficients: vk.coefficients_comm.each_ref().map(to_curve),
            generic: to_curve(&vk.generic_comm),
            psm: to_curve(&vk.psm_comm),
            complete_add: to_curve(&vk.complete_add_comm),
            mul: to_curve(&vk.mul_comm),
            emul: to_curve(&vk.emul_comm),
            endomul_scalar: to_curve(&vk.endomul_scalar_comm),
        };
        let opt = |c: &Option<PolyComm<Vesta>>| c.as_ref().map(comm);
        let lookup = vk.lookup_index.as_ref();
        let mut lookup_table: [Option<Comm>; 4] = Default::default();
        if let Some(l) = lookup {
            assert!(l.lookup_table.len() <= 4, "a lookup table has at most 4 columns");
            for (slot, c) in lookup_table.iter_mut().zip(&l.lookup_table) {
                *slot = Some(comm(c));
            }
        }
        Self {
            base,
            xor: opt(&vk.xor_comm),
            range_check0: opt(&vk.range_check0_comm),
            range_check1: opt(&vk.range_check1_comm),
            foreign_field_add: opt(&vk.foreign_field_add_comm),
            foreign_field_mul: opt(&vk.foreign_field_mul_comm),
            rot: opt(&vk.rot_comm),
            lookup_table,
            lookup_table_ids: lookup.and_then(|l| opt(&l.table_ids)),
            runtime_tables_selector: lookup.and_then(|l| opt(&l.runtime_tables_selector)),
            lookup_selector_lookup: lookup.and_then(|l| opt(&l.lookup_selectors.lookup)),
            lookup_selector_xor: lookup.and_then(|l| opt(&l.lookup_selectors.xor)),
            lookup_selector_range_check: lookup.and_then(|l| opt(&l.lookup_selectors.range_check)),
            lookup_selector_ffmul: lookup.and_then(|l| opt(&l.lookup_selectors.ffmul)),
        }
    }
}

/// The key `choose_key` selects: constants for the base commitments, and an `Opt` for each
/// optional one.
#[derive(Clone, Debug)]
pub struct ChosenKey {
    pub base: PlonkVerificationKeyEvals<Fq>,
    pub xor: Opt<Comm>,
    pub range_check0: Opt<Comm>,
    pub range_check1: Opt<Comm>,
    pub foreign_field_add: Opt<Comm>,
    pub foreign_field_mul: Opt<Comm>,
    pub rot: Opt<Comm>,
    pub lookup_table: [Opt<Comm>; 4],
    pub lookup_table_ids: Opt<Comm>,
    pub runtime_tables_selector: Opt<Comm>,
    pub lookup_selector_lookup: Opt<Comm>,
    pub lookup_selector_xor: Opt<Comm>,
    pub lookup_selector_range_check: Opt<Comm>,
    pub lookup_selector_ffmul: Opt<Comm>,
}

fn generator() -> GroupAffine<Fq> {
    Vesta::generator()
}

/// One optional commitment across the branches, after the one-hot selection and before sealing.
///
/// `is_yes_terms` counts the branches that have it: `Util.Wrap.seal` creates a witness for the
/// sum of the `which_branch` bits unless that sum is a single bit.
fn choose_opt(
    keys: &[Option<&Comm>],
    branch: usize,
    w: &mut Witness<Fq>,
) -> Opt<Comm> {
    let justs = keys.iter().filter(|k| k.is_some()).count();
    let nones = keys.len() - justs;
    // The sealed sum's coordinates, `y` before `x`, chunk by chunk.
    let mut seal_comm = |c: &Comm, w: &mut Witness<Fq>| {
        for GroupAffine::<Fq> { x, y, .. } in c {
            w.exists_no_check([*y, *x]);
        }
    };
    match (justs, nones) {
        (0, _) => Opt::Nothing,
        (_, 0) => {
            let c = keys[branch].unwrap().clone();
            seal_comm(&c, w);
            Opt::Just(c)
        }
        _ => {
            let is_yes = keys[branch].is_some();
            // Where the branch lacks the commitment, the sum holds `Inner_curve.one`.
            let c = match keys[branch] {
                Some(c) => c.clone(),
                None => {
                    let len = keys.iter().flatten().next().unwrap().len();
                    vec![generator(); len]
                }
            };
            seal_comm(&c, w);
            // `Boolean.Unsafe.of_cvar (seal (sum of the justs' bits))`.
            if justs > 1 {
                w.exists_no_check(is_yes.then_some(Fq::from(1u64)).unwrap_or_default());
            }
            Opt::Maybe(CircuitVar::Var(Boolean::of_field(Fq::from(is_yes as u64))), c)
        }
    }
}

/// `Wrap_verifier.choose_key`: the key of the branch `which_branch` selects, with the witnesses
/// the OCaml circuit creates. The bits of `which_branch` are one-hot.
pub fn choose_key(keys: &[StepKey], which_branch: &[Boolean], w: &mut Witness<Fq>) -> ChosenKey {
    assert_eq!(keys.len(), which_branch.len());
    let branch = which_branch
        .iter()
        .position(Boolean::as_bool)
        .expect("which_branch is one-hot");

    // OCaml builds the record right to left, so the optional commitments come first, last field
    // first, and a vector is mapped from its last element.
    let col = |f: &dyn Fn(&StepKey) -> Option<&Comm>| keys.iter().map(f).collect::<Vec<_>>();
    let lookup_selector_ffmul = choose_opt(&col(&|k| k.lookup_selector_ffmul.as_ref()), branch, w);
    let lookup_selector_range_check =
        choose_opt(&col(&|k| k.lookup_selector_range_check.as_ref()), branch, w);
    let lookup_selector_xor = choose_opt(&col(&|k| k.lookup_selector_xor.as_ref()), branch, w);
    let lookup_selector_lookup =
        choose_opt(&col(&|k| k.lookup_selector_lookup.as_ref()), branch, w);
    let runtime_tables_selector =
        choose_opt(&col(&|k| k.runtime_tables_selector.as_ref()), branch, w);
    let lookup_table_ids = choose_opt(&col(&|k| k.lookup_table_ids.as_ref()), branch, w);
    let mut lookup_table: [Opt<Comm>; 4] = std::array::from_fn(|_| Opt::Nothing);
    for i in (0..4).rev() {
        lookup_table[i] = choose_opt(&col(&|k| k.lookup_table[i].as_ref()), branch, w);
    }
    let rot = choose_opt(&col(&|k| k.rot.as_ref()), branch, w);
    let foreign_field_mul = choose_opt(&col(&|k| k.foreign_field_mul.as_ref()), branch, w);
    let foreign_field_add = choose_opt(&col(&|k| k.foreign_field_add.as_ref()), branch, w);
    let range_check1 = choose_opt(&col(&|k| k.range_check1.as_ref()), branch, w);
    let range_check0 = choose_opt(&col(&|k| k.range_check0.as_ref()), branch, w);
    let xor = choose_opt(&col(&|k| k.xor.as_ref()), branch, w);

    let base = keys[branch].base.clone();
    let mut exists = |c: &InnerCurve<Fq>| {
        let GroupAffine::<Fq> { x, y, .. } = c.to_affine();
        w.exists_no_check([y, x]); // Note: `y` first
    };
    exists(&base.endomul_scalar);
    exists(&base.emul);
    exists(&base.mul);
    exists(&base.complete_add);
    exists(&base.psm);
    exists(&base.generic);
    base.coefficients.iter().rev().for_each(&mut exists);
    base.sigma.iter().rev().for_each(&mut exists);

    ChosenKey {
        base,
        xor,
        range_check0,
        range_check1,
        foreign_field_add,
        foreign_field_mul,
        rot,
        lookup_table,
        lookup_table_ids,
        runtime_tables_selector,
        lookup_selector_lookup,
        lookup_selector_xor,
        lookup_selector_range_check,
        lookup_selector_ffmul,
    }
}
