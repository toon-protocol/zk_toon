//! `wrap_main`: the witness of the wrap circuit, for any number of previous proofs, any list of
//! step keys and any feature flags.
//!
//! Derived from `wrap_main` in `crates/ledger/src/proofs/wrap.rs` of `toon-protocol/mina-rust` at
//! rev `6feeb3797fff6dba49fd848cb2d6decd63fee1b4` (itself from `o1-labs/mina-rust` v0.19.0,
//! Apache-2.0), which fixes `MAX_PROOFS_VERIFIED_N = 2`, takes one step key and leaves out
//! optional gates and lookups. The generalisation follows Mina `228c409a` (the commit o1js v3.1.0 bundles),
//! `src/lib/pickles/wrap_main.ml`. Licensed under Apache-2.0; see `LICENSE-APACHE` and `NOTICE`.

use kimchi::{circuits::wires::COLUMNS, proof::ProverCommitments};
use ledger::proofs::{
    field::{Boolean, CircuitVar, GroupAffine, ToBoolean},
    public_input::{messages::MessagesForNextWrapProof, prepared_statement::DeferredValues},
    step::{FeatureFlags, OptFlag},
    transaction::{poseidon::Sponge, Check, ProofWithPublic},
    util::four_u64_to_field,
    witness::Witness,
    wrap::{one_hot_vector, Domains, Packed, WrapStatement},
    ProverIndex,
};
use mina_curves::pasta::{Fp, Fq, Vesta};

use super::{
    key::{choose_key, Comm, Opt, StepKey},
    opt_sponge::OptSponge,
    verifier::{self, IncrementallyVerifyProofParams, LookupMessages, Messages},
};

/// The `Opt.Flag` of each feature across a program's branches: `Yes` if every branch has it,
/// `No` if none does, `Maybe` otherwise.
#[derive(Clone, Copy, Debug)]
pub struct ProgramFlags {
    pub range_check0: OptFlag,
    pub range_check1: OptFlag,
    pub foreign_field_add: OptFlag,
    pub foreign_field_mul: OptFlag,
    pub xor: OptFlag,
    pub rot: OptFlag,
    pub lookup: OptFlag,
    pub runtime_tables_flag: OptFlag,
    pub uses_lookups: OptFlag,
    pub lookups_per_row_4: OptFlag,
    pub runtime_tables: OptFlag,
}

fn flag_of(bs: impl Iterator<Item = bool> + Clone) -> OptFlag {
    if bs.clone().all(|b| b) {
        OptFlag::Yes
    } else if bs.clone().any(|b| b) {
        OptFlag::Maybe
    } else {
        OptFlag::No
    }
}

fn or_flag(flags: &[OptFlag]) -> OptFlag {
    flags.iter().fold(OptFlag::No, |acc, f| match (acc, f) {
        (OptFlag::Yes, _) | (_, OptFlag::Yes) => OptFlag::Yes,
        (OptFlag::Maybe, _) | (_, OptFlag::Maybe) => OptFlag::Maybe,
        (OptFlag::No, OptFlag::No) => OptFlag::No,
    })
}

impl ProgramFlags {
    pub fn of_branches(branches: &[FeatureFlags<bool>]) -> Self {
        let f = |get: fn(&FeatureFlags<bool>) -> bool| flag_of(branches.iter().map(get));
        let range_check0 = f(|f| f.range_check0);
        let range_check1 = f(|f| f.range_check1);
        let foreign_field_add = f(|f| f.foreign_field_add);
        let foreign_field_mul = f(|f| f.foreign_field_mul);
        let xor = f(|f| f.xor);
        let rot = f(|f| f.rot);
        let lookup = f(|f| f.lookup);
        let runtime_tables = f(|f| f.runtime_tables);
        let range_check_lookup = or_flag(&[range_check0, range_check1, rot]);
        Self {
            range_check0,
            range_check1,
            foreign_field_add,
            foreign_field_mul,
            xor,
            rot,
            lookup,
            runtime_tables_flag: runtime_tables,
            uses_lookups: or_flag(&[
                range_check0,
                range_check1,
                foreign_field_mul,
                xor,
                rot,
                lookup,
            ]),
            lookups_per_row_4: or_flag(&[xor, range_check_lookup, foreign_field_mul]),
            runtime_tables,
        }
    }
}

/// `Pickles_types.Opt.Typ.wrap_typ`: how a flag lays an optional value out.
fn opt_layout<T>(flag: OptFlag, present: Option<T>, dummy: T) -> Opt<T> {
    match (flag, present) {
        (OptFlag::No, _) => Opt::Nothing,
        (OptFlag::Yes, Some(x)) => Opt::Just(x),
        (OptFlag::Yes, None) => panic!("a feature every branch has is missing"),
        (OptFlag::Maybe, Some(x)) => Opt::Maybe(CircuitVar::Var(Boolean::True), x),
        (OptFlag::Maybe, None) => Opt::Maybe(CircuitVar::Var(Boolean::False), dummy),
    }
}

/// The values `Messages.wrap_typ` lays out, then the checks of each point.
fn exists_messages(
    commitments: &ProverCommitments<Vesta>,
    flags: ProgramFlags,
    w: &mut Witness<Fq>,
) -> Messages {
    let dummy: Comm = vec![<Vesta as ark_ec::AffineRepr>::generator()];
    struct Out {
        fields: Vec<Fq>,
        points: Vec<GroupAffine<Fq>>,
    }
    impl Out {
        fn comm(&mut self, c: &Comm) {
            for g in c {
                self.fields.extend([g.x, g.y]);
                self.points.push(*g);
            }
        }

        fn opt(&mut self, o: &Opt<Comm>) {
            match o {
                Opt::Nothing => {}
                Opt::Just(c) => self.comm(c),
                Opt::Maybe(b, c) => {
                    self.fields.push(b.as_boolean().to_field::<Fq>());
                    self.comm(c);
                }
            }
        }
    }
    let mut out = Out {
        fields: Vec::new(),
        points: Vec::new(),
    };
    let comm = |c: &poly_commitment::PolyComm<Vesta>| -> Comm { c.chunks.clone() };

    let w_comm: [Comm; COLUMNS] = std::array::from_fn(|i| comm(&commitments.w_comm[i]));
    for c in &w_comm {
        out.comm(c);
    }
    let z_comm = comm(&commitments.z_comm);
    out.comm(&z_comm);
    let t_comm = comm(&commitments.t_comm);
    out.comm(&t_comm);

    let lookup_msgs = commitments.lookup.as_ref();
    let lookup = opt_layout(
        flags.uses_lookups,
        lookup_msgs.map(|l| {
            let sorted: Vec<Comm> = l.sorted.iter().map(comm).collect();
            LookupMessages {
                sorted: sorted[..4].to_vec(),
                sorted_5th_column: opt_layout(flags.lookups_per_row_4, sorted.get(4).cloned(), dummy.clone()),
                aggreg: comm(&l.aggreg),
                runtime: opt_layout(flags.runtime_tables, l.runtime.as_ref().map(comm), dummy.clone()),
            }
        }),
        LookupMessages {
            sorted: vec![dummy.clone(); 4],
            sorted_5th_column: opt_layout(flags.lookups_per_row_4, None, dummy.clone()),
            aggreg: dummy.clone(),
            runtime: opt_layout(flags.runtime_tables, None, dummy.clone()),
        },
    );
    // Layout of the lookup messages: the flag if maybe, then `sorted`, the 5th column (flag,
    // value), `aggreg`, the runtime table (flag, value).
    match &lookup {
        Opt::Nothing => {}
        Opt::Just(l) | Opt::Maybe(_, l) => {
            if let Opt::Maybe(b, _) = &lookup {
                out.fields.push(b.as_boolean().to_field::<Fq>());
            }
            for c in &l.sorted {
                out.comm(c);
            }
            out.opt(&l.sorted_5th_column);
            out.comm(&l.aggreg);
            out.opt(&l.runtime);
        }
    }
    let Out { fields, points } = out;

    w.exists_no_check(fields);
    for g in points {
        g.check(w);
    }
    Messages {
        w_comm,
        z_comm,
        t_comm,
        lookup,
    }
}

/// `Plonk_checks.expand_feature_flags` on the statement's flags: a flag every method of the program
/// has (or none has) is a constant, so the operations on it add no witness.
struct AllFlags {
    range_check0: CircuitVar<Boolean>,
    range_check1: CircuitVar<Boolean>,
    foreign_field_add: CircuitVar<Boolean>,
    foreign_field_mul: CircuitVar<Boolean>,
    xor: CircuitVar<Boolean>,
    rot: CircuitVar<Boolean>,
    lookup: CircuitVar<Boolean>,
    runtime_tables: CircuitVar<Boolean>,
    // The lazy ones, once forced.
    range: Option<CircuitVar<Boolean>>,
    width_2: Option<CircuitVar<Boolean>>,
    width_1: Option<CircuitVar<Boolean>>,
}

impl AllFlags {
    fn new(p: ProgramFlags, f: &FeatureFlags<bool>) -> Self {
        let cv = |flag: OptFlag, value: bool| match flag {
            OptFlag::Yes => CircuitVar::Constant(Boolean::True),
            OptFlag::No => CircuitVar::Constant(Boolean::False),
            OptFlag::Maybe => CircuitVar::Var(value.to_boolean()),
        };
        Self {
            range_check0: cv(p.range_check0, f.range_check0),
            range_check1: cv(p.range_check1, f.range_check1),
            foreign_field_add: cv(p.foreign_field_add, f.foreign_field_add),
            foreign_field_mul: cv(p.foreign_field_mul, f.foreign_field_mul),
            xor: cv(p.xor, f.xor),
            rot: cv(p.rot, f.rot),
            lookup: cv(p.lookup, f.lookup),
            runtime_tables: cv(p.runtime_tables_flag, f.runtime_tables),
            range: None,
            width_2: None,
            width_1: None,
        }
    }

    fn lookup_pattern_range_check(&mut self, w: &mut Witness<Fq>) -> CircuitVar<Boolean> {
        if let Some(v) = self.range {
            return v;
        }
        let first = self.range_check0.or(&self.range_check1, w);
        let v = first.or(&self.rot, w);
        self.range = Some(v);
        v
    }

    fn table_width_at_least_2(&mut self, w: &mut Witness<Fq>) -> CircuitVar<Boolean> {
        if let Some(v) = self.width_2 {
            return v;
        }
        let v = self.xor.or(&self.lookup, w);
        self.width_2 = Some(v);
        v
    }

    fn table_width_at_least_1(&mut self, w: &mut Witness<Fq>) -> CircuitVar<Boolean> {
        if let Some(v) = self.width_1 {
            return v;
        }
        let width_2 = self.table_width_at_least_2(w);
        let range = self.lookup_pattern_range_check(w);
        let v = CircuitVar::any(&[width_2, range, self.foreign_field_mul], w);
        self.width_1 = Some(v);
        v
    }
}

pub struct WrapMainParams<'a> {
    /// The step keys, one per branch.
    pub step_keys: &'a [StepKey],
    pub flags: ProgramFlags,
    pub which_index: u64,
    pub step_domains: Vec<Domains>,
    pub next_statement: &'a WrapStatement,
    pub messages_for_next_step_proof_hash: [u64; 4],
    pub proof: &'a ProofWithPublic<Fp>,
    pub step_prover_index: &'a ProverIndex<Fp>,
    pub feature_flags: &'a FeatureFlags<bool>,
}

/// `Wrap_hack.Checked.hash_messages_for_next_wrap_proof`: the hash starts from the sponge state
/// the padding challenges lead to, which is a constant.
fn hash_messages_for_next_wrap_proof(
    max_proofs_verified: usize,
    challenge_polynomial_commitment: GroupAffine<Fq>,
    old_bulletproof_challenges: &[[Fq; 15]],
    w: &mut Witness<Fq>,
) -> Fq {
    let mut sponge = Sponge::<Fq>::new();
    let mut scratch = Witness::<Fq>::empty();
    for _ in 0..(2 - max_proofs_verified) {
        for chal in MessagesForNextWrapProof::dummy_padding() {
            sponge.absorb(&[chal], &mut scratch);
        }
    }
    for chals in old_bulletproof_challenges {
        for chal in chals {
            sponge.absorb(&[*chal], w);
        }
    }
    sponge.absorb(&[challenge_polynomial_commitment.x], w);
    sponge.absorb(&[challenge_polynomial_commitment.y], w);
    sponge.squeeze(w)
}

pub fn wrap_main(params: WrapMainParams, w: &mut Witness<Fq>) -> anyhow::Result<()> {
    let WrapMainParams {
        step_keys,
        flags,
        which_index,
        step_domains,
        next_statement,
        messages_for_next_step_proof_hash,
        proof,
        step_prover_index,
        feature_flags,
    } = params;

    let branches = step_keys.len() as u64;
    let which_branch = w.exists(Fq::from(which_index));
    let which_branch = one_hot_vector::of_index(which_branch, branches, w);

    // `prev_proof_state`: no unfinalized proofs, then the digest.
    w.exists(four_u64_to_field::<Fq, _>(&messages_for_next_step_proof_hash)?);

    let step_plonk_index = choose_key(step_keys, &which_branch, w);

    // Check consistency between index and feature flags.
    {
        let mut all = AllFlags::new(flags, feature_flags);
        let flag = |c: &Opt<Comm>| match c {
            Opt::Just(_) => Boolean::True,
            Opt::Maybe(b, _) => b.as_boolean(),
            Opt::Nothing => Boolean::False,
        };
        let assert_consistent = |comm: &Opt<Comm>, flag_value: CircuitVar<Boolean>| {
            assert_eq!(
                flag(comm).as_bool(),
                flag_value.as_boolean().as_bool(),
                "the step key and the feature flags disagree"
            );
        };
        let k = &step_plonk_index;
        assert_consistent(&k.xor, all.xor);
        assert_consistent(&k.range_check0, all.range_check0);
        assert_consistent(&k.range_check1, all.range_check1);
        assert_consistent(&k.foreign_field_add, all.foreign_field_add);
        assert_consistent(&k.foreign_field_mul, all.foreign_field_mul);
        assert_consistent(&k.rot, all.rot);
        let v = all.table_width_at_least_1(w);
        assert_consistent(&k.lookup_table[0], v);
        let v = all.table_width_at_least_2(w);
        assert_consistent(&k.lookup_table[1], v);
        assert_consistent(&k.lookup_table[2], all.xor);
        assert_consistent(&k.lookup_table[3], CircuitVar::Constant(Boolean::False));
        assert_consistent(&k.runtime_tables_selector, all.runtime_tables);
        assert_consistent(&k.lookup_selector_lookup, all.lookup);
        assert_consistent(&k.lookup_selector_xor, all.xor);
        let v = all.lookup_pattern_range_check(w);
        assert_consistent(&k.lookup_selector_range_check, v);
        assert_consistent(&k.lookup_selector_ffmul, all.foreign_field_mul);
    }

    // No previous proofs: no accumulators, challenges, evaluations or wrap domains.

    let openings_proof = w.exists(&proof.proof.proof);
    let messages = exists_messages(&proof.proof.commitments, flags, w);

    let public_input = vec![Packed::PackedBits(
        CircuitVar::Var(four_u64_to_field::<Fq, _>(&messages_for_next_step_proof_hash)?),
        255,
    )];

    let DeferredValues {
        plonk,
        combined_inner_product,
        b,
        xi,
        bulletproof_challenges: _,
        branch_data: _,
    } = &next_statement.proof_state.deferred_values;

    let sponge = OptSponge::create();
    verifier::incrementally_verify_proof(
        IncrementallyVerifyProofParams {
            actual_proofs_verified_mask: vec![],
            step_domains: &step_domains,
            verification_key: &step_plonk_index,
            srs: step_prover_index.srs.clone(),
            xi,
            sponge,
            public_input,
            sg_old: vec![],
            advice: ledger::proofs::wrap::wrap_verifier::Advice {
                b: b.clone(),
                combined_inner_product: combined_inner_product.clone(),
            },
            messages: &messages,
            which_branch,
            openings_proof,
            plonk,
        },
        w,
    );

    hash_messages_for_next_wrap_proof(0, openings_proof.sg, &[], w);

    Ok(())
}
