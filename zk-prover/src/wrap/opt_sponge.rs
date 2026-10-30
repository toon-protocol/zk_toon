//! `Opt_sponge`: a sponge that can conditionally absorb.
//!
//! Derived from `crates/ledger/src/proofs/opt_sponge.rs` in `toon-protocol/mina-rust` at rev
//! `6feeb3797fff6dba49fd848cb2d6decd63fee1b4` (itself from `o1-labs/mina-rust` v0.19.0,
//! Apache-2.0), with `copy`, `consume_all_pending` and `recombine` added, and
//! `needs_final_permute_if_empty` reset after a squeeze, from Mina `aa93c444`,
//! `src/lib/pickles/opt_sponge.ml`. Licensed under Apache-2.0; see `LICENSE-APACHE` and `NOTICE`.

use ledger::proofs::{
    field::{field, Boolean, CircuitVar, FieldWitness},
    witness::Witness,
};
use poseidon::SpongeParams;

const M: usize = 3;
const CAPACITY: usize = 1;
const RATE: usize = M - CAPACITY;
const PERM_ROUNDS_FULL: usize = 55;

#[derive(Clone)]
pub enum SpongeState<F: FieldWitness> {
    Absorbing {
        next_index: CircuitVar<Boolean>,
        xs: Vec<(CircuitVar<Boolean>, F)>,
    },
    Squeezed(usize),
}

#[derive(Clone)]
pub struct OptSponge<F: FieldWitness> {
    pub state: [F; M],
    params: &'static SpongeParams<F>,
    pub needs_final_permute_if_empty: bool,
    pub sponge_state: SpongeState<F>,
}

impl<F: FieldWitness> OptSponge<F> {
    pub fn create() -> Self {
        Self {
            state: [F::zero(); M],
            params: F::get_params(),
            needs_final_permute_if_empty: true,
            sponge_state: SpongeState::Absorbing {
                next_index: CircuitVar::Constant(Boolean::False),
                xs: Vec::with_capacity(32),
            },
        }
    }

    pub fn of_sponge(sponge: ledger::proofs::transaction::poseidon::Sponge<F>, w: &mut Witness<F>) -> Self {
        use ledger::proofs::transaction::poseidon::Sponge;

        let Sponge {
            sponge_state,
            state,
            ..
        } = sponge;

        match sponge_state {
            ::poseidon::SpongeState::Squeezed(n) => Self {
                state,
                params: F::get_params(),
                needs_final_permute_if_empty: true,
                sponge_state: SpongeState::Squeezed(n),
            },
            ::poseidon::SpongeState::Absorbed(n) => {
                let abs = |i: Boolean| Self {
                    state,
                    params: F::get_params(),
                    needs_final_permute_if_empty: true,
                    sponge_state: SpongeState::Absorbing {
                        next_index: CircuitVar::Constant(i),
                        xs: vec![],
                    },
                };

                match n {
                    0 => abs(Boolean::False),
                    1 => abs(Boolean::True),
                    2 => Self {
                        state: { block_cipher(state, F::get_params(), w) },
                        params: F::get_params(),
                        needs_final_permute_if_empty: false,
                        sponge_state: SpongeState::Absorbing {
                            next_index: CircuitVar::Constant(Boolean::False),
                            xs: vec![],
                        },
                    },
                    _ => panic!(),
                }
            }
        }
    }

    pub fn absorb(&mut self, x: (CircuitVar<Boolean>, F)) {
        match &mut self.sponge_state {
            SpongeState::Absorbing { next_index: _, xs } => {
                xs.push(x);
            }
            SpongeState::Squeezed(_) => {
                self.sponge_state = SpongeState::Absorbing {
                    next_index: CircuitVar::Constant(Boolean::False),
                    xs: {
                        let mut vec = Vec::with_capacity(32);
                        vec.push(x);
                        vec
                    },
                }
            }
        }
    }

    pub fn squeeze(&mut self, w: &mut Witness<F>) -> F {
        match &self.sponge_state {
            SpongeState::Squeezed(n) => {
                let n = *n;
                if n == RATE {
                    self.state = block_cipher(self.state, self.params, w);
                    self.sponge_state = SpongeState::Squeezed(1);
                    self.state[0]
                } else {
                    self.sponge_state = SpongeState::Squeezed(n + 1);
                    self.state[n]
                }
            }
            SpongeState::Absorbing { next_index, xs } => {
                self.state = consume(
                    ConsumeParams {
                        needs_final_permute_if_empty: self.needs_final_permute_if_empty,
                        start_pos: *next_index,
                        params: self.params,
                        input: xs,
                        state: self.state,
                    },
                    w,
                );
                self.needs_final_permute_if_empty = true;
                self.sponge_state = SpongeState::Squeezed(1);
                self.state[0]
            }
        }
    }
}

fn add_in<F: FieldWitness>(a: &mut [F; 3], i: CircuitVar<Boolean>, x: F, w: &mut Witness<F>) {
    let i = i.as_boolean();
    let i_equals_0 = i.neg();
    let i_equals_1 = i;

    for (j, i_equals_j) in [i_equals_0, i_equals_1].iter().enumerate() {
        let a_j = w.exists({
            let a_j = a[j];
            match i_equals_j {
                Boolean::True => a_j + x,
                Boolean::False => a_j,
            }
        });
        a[j] = a_j;
    }
}

fn mul_by_boolean<F>(x: F, y: CircuitVar<Boolean>, w: &mut Witness<F>) -> F
where
    F: FieldWitness,
{
    match y {
        CircuitVar::Var(y) => field::mul(x, y.to_field::<F>(), w),
        CircuitVar::Constant(y) => x * y.to_field::<F>(),
    }
}

struct ConsumeParams<'a, F: FieldWitness> {
    needs_final_permute_if_empty: bool,
    start_pos: CircuitVar<Boolean>,
    params: &'static SpongeParams<F>,
    input: &'a [(CircuitVar<Boolean>, F)],
    state: [F; 3],
}

fn cond_permute<F: FieldWitness>(
    permute: CircuitVar<Boolean>,
    state: &mut [F; M],
    params: &'static SpongeParams<F>,
    w: &mut Witness<F>,
) {
    let permuted = block_cipher(*state, params, w);
    for (i, state) in state.iter_mut().enumerate() {
        let v = match permute.as_boolean() {
            Boolean::True => permuted[i],
            Boolean::False => *state,
        };
        if let CircuitVar::Var(_) = permute {
            w.exists_no_check(v);
        }
        *state = v;
    }
}

/// `consume_pairs`: absorb the inputs two at a time, returning the position after them.
fn consume_pairs<F: FieldWitness>(
    params: &'static SpongeParams<F>,
    state: &mut [F; M],
    start_pos: CircuitVar<Boolean>,
    input: &[(CircuitVar<Boolean>, F)],
    w: &mut Witness<F>,
) -> CircuitVar<Boolean> {
    let mut pos = start_pos;
    for pairs in input.chunks_exact(2) {
        let (b, x) = pairs[0];
        let (b2, y) = pairs[1];

        let p = pos;
        let p2 = p.lxor(&b, w);
        pos = p2.lxor(&b2, w);

        let y = mul_by_boolean(y, b2, w);

        let add_in_y_after_perm = CircuitVar::all(&[b, b2, p], w);
        let add_in_y_before_perm = add_in_y_after_perm.neg();

        let product = mul_by_boolean(x, b, w);
        add_in(state, p, product, w);

        let product = mul_by_boolean(y, add_in_y_before_perm, w);
        add_in(state, p2, product, w);

        let permute = {
            // We decompose this way because of OCaml evaluation order
            let b3 = CircuitVar::all(&[p, b.or(&b2, w)], w);
            let a = CircuitVar::all(&[b, b2], w);
            CircuitVar::any(&[a, b3], w)
        };

        cond_permute(permute, state, params, w);

        let product = mul_by_boolean(y, add_in_y_after_perm, w);
        add_in(state, p2, product, w);
    }
    pos
}

fn consume<F: FieldWitness>(params: ConsumeParams<F>, w: &mut Witness<F>) -> [F; 3] {
    let ConsumeParams {
        needs_final_permute_if_empty,
        start_pos,
        params,
        input,
        mut state,
    } = params;

    let mut pos = consume_pairs(params, &mut state, start_pos, input, w);

    let fst = |(f, _): &(CircuitVar<Boolean>, F)| *f;
    let fst_input = input.iter().map(fst).collect::<Vec<_>>();

    // Note: It's Boolean.Array.any here, not sure if there is a difference
    let empty_input = CircuitVar::any(&fst_input, w).map(Boolean::neg);

    let should_permute = match *input.chunks_exact(2).remainder() {
        [] => {
            if needs_final_permute_if_empty {
                empty_input.or(&pos, w)
            } else {
                pos
            }
        }
        [(b, x)] => {
            let p = pos;
            pos = p.lxor(&b, w);

            let product = mul_by_boolean(x, b, w);
            add_in(&mut state, p, product, w);

            if needs_final_permute_if_empty {
                CircuitVar::any(&[p, b, empty_input], w)
            } else {
                CircuitVar::any(&[p, b], w)
            }
        }
        _ => unreachable!(),
    };

    let _ = pos;
    cond_permute(should_permute, &mut state, params, w);

    state
}

impl<F: FieldWitness> OptSponge<F> {
    /// `Opt_sponge.copy`
    pub fn copy(&self) -> Self {
        self.clone()
    }

    /// `Opt_sponge.consume_all_pending`: absorb everything pending, without permuting the
    /// last, possibly partial, block.
    pub fn consume_all_pending(&mut self, w: &mut Witness<F>) {
        let SpongeState::Absorbing { next_index, xs } = &self.sponge_state else {
            panic!("Nothing pending");
        };
        let input = xs.clone();
        let mut pos = consume_pairs(
            self.params,
            &mut self.state,
            *next_index,
            &input,
            w,
        );
        if let [(b, x)] = *input.chunks_exact(2).remainder() {
            let p = pos;
            pos = p.lxor(&b, w);
            let product = mul_by_boolean(x, b, w);
            add_in(&mut self.state, p, product, w);
        }
        self.sponge_state = SpongeState::Absorbing {
            next_index: pos,
            xs: vec![],
        };
    }

    /// `Opt_sponge.recombine`: keep `self` where `b` holds, and `original` elsewhere.
    pub fn recombine(&mut self, original: &Self, b: Boolean, w: &mut Witness<F>) {
        let pick = |then_: F, else_: F, w: &mut Witness<F>| match b {
            Boolean::True => w.exists_no_check(then_),
            Boolean::False => w.exists_no_check(else_),
        };
        match (&original.sponge_state, &self.sponge_state) {
            (SpongeState::Squeezed(orig_i), SpongeState::Squeezed(curr_i)) => {
                assert_eq!(orig_i, curr_i, "Squeezed {orig_i} vs {curr_i}");
                for i in 0..M {
                    self.state[i] = pick(self.state[i], original.state[i], w);
                }
            }
            (
                SpongeState::Absorbing {
                    next_index: next_index_orig,
                    xs: xs_orig,
                },
                SpongeState::Absorbing {
                    next_index: next_index_curr,
                    xs: xs_curr,
                },
            ) => {
                assert_eq!(
                    xs_orig.len(),
                    xs_curr.len(),
                    "Pending absorptions {} vs {}",
                    xs_orig.len(),
                    xs_curr.len()
                );
                for i in 0..M {
                    self.state[i] = pick(self.state[i], original.state[i], w);
                }
                // `Boolean.if_ b ~then_ ~else_`: no witness when both are constants
                let next_index = match b {
                    Boolean::True => *next_index_curr,
                    Boolean::False => *next_index_orig,
                };
                let next_index = if next_index_curr.is_const() && next_index_orig.is_const() {
                    CircuitVar::Constant(next_index.as_boolean())
                } else {
                    CircuitVar::Var(Boolean::of_field(
                        w.exists_no_check(next_index.as_boolean().to_field::<F>()),
                    ))
                };
                let xs = xs_curr.clone();
                self.sponge_state = SpongeState::Absorbing { next_index, xs };
            }
            _ => panic!("Incompatible states"),
        }
    }
}

fn block_cipher<F: FieldWitness>(
    mut state: [F; M],
    params: &SpongeParams<F>,
    w: &mut Witness<F>,
) -> [F; M] {
    w.exists(state);
    for r in 0..PERM_ROUNDS_FULL {
        full_round(&mut state, r, params, w);
    }
    state
}

fn full_round<F: FieldWitness>(
    state: &mut [F; M],
    r: usize,
    params: &SpongeParams<F>,
    w: &mut Witness<F>,
) {
    for state_i in state.iter_mut() {
        *state_i = sbox::<F>(*state_i);
    }
    *state = apply_mds_matrix::<F>(params, state);
    for (i, x) in params.round_constants[r].iter().enumerate() {
        state[i].add_assign(x);
    }
    w.exists(*state);
}

fn sbox<F: FieldWitness>(x: F) -> F {
    let mut res = x.square();
    res *= x;
    let res = res.square();
    res * x
}

fn apply_mds_matrix<F: FieldWitness>(params: &SpongeParams<F>, state: &[F; 3]) -> [F; 3] {
    std::array::from_fn(|i| {
        state
            .iter()
            .zip(params.mds[i].iter())
            .fold(F::zero(), |x, (s, &m)| m * s + x)
    })
}
