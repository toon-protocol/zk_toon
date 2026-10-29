//! Mirrors the checked Poseidon of Mina (`Sponge_inputs.Make` in Pickles and `Sponge.Make_hash`),
//! which o1js reaches through `Snarky.poseidon.update`.
//!
//! One permutation creates 168 variables: the 56 states (the input and the 55 rounds) of three
//! fields each, with the gate's input state copied into the first. Adding an input into the state
//! first `seal`s it, which creates a variable only when the sum is not already one.

use ark_ff::{AdditiveGroup as _, Field as _, One, Zero};
use mina_curves::pasta::Fp;
use mina_poseidon::pasta::fp_kimchi::static_params;

use crate::witness::{Cs, Field};

const ROUNDS: usize = 55;

/// `round_table`: the input state and the state after each round.
fn round_table(start: [Fp; 3]) -> Vec<[Fp; 3]> {
    let params = static_params();
    let mut rows = Vec::with_capacity(ROUNDS + 1);
    rows.push(start);
    for r in 0..ROUNDS {
        let s = rows[r].map(|x| {
            let x2 = x.square();
            let x4 = x2.square();
            x4 * x2 * x
        });
        let mut next = [Fp::zero(); 3];
        for (i, n) in next.iter_mut().enumerate() {
            *n = params.mds[i][0] * s[0]
                + params.mds[i][1] * s[1]
                + params.mds[i][2] * s[2]
                + params.round_constants[r][i];
        }
        rows.push(next);
    }
    rows
}

/// `block_cipher`: one permutation, whose gate input is `init`. Returns the output state.
pub fn block_cipher(cs: &mut Cs, init: &[Field; 3]) -> [Field; 3] {
    let rows = round_table([init[0].value(), init[1].value(), init[2].value()]);
    let mut last = None;
    for row in rows {
        last = Some(cs.exists(row));
    }
    last.unwrap()
}

/// `Util.seal` of Pickles: a constant stays one, a variable stays itself, anything else gets a
/// fresh variable constrained equal to it. Unlike o1js's `Field.seal`, snarky's `Field.Assert.equal`
/// creates no further variable.
pub(crate) fn seal(cs: &mut Cs, x: &Field) -> Field {
    let lc = x.linear_combination();
    if lc.terms.is_empty() {
        return Field::constant(lc.constant);
    }
    if lc.terms.len() == 1 && lc.constant.is_zero() && lc.terms[0].0.is_one() {
        return cs.var(lc.terms[0].1);
    }
    cs.exists_one(x.value())
}

/// `Poseidon.update` (`Random_oracle.Checked.update`): absorb `input` in blocks of two into
/// `state`, permuting after each. An empty input is one permutation.
pub fn update(cs: &mut Cs, state: [Field; 3], input: &[Field]) -> [Field; 3] {
    if input.is_empty() {
        return block_cipher(cs, &state);
    }
    let mut state = state;
    for block in input.chunks(2) {
        for (i, x) in block.iter().enumerate() {
            let sum = state[i].add(x);
            state[i] = seal(cs, &sum);
        }
        state = block_cipher(cs, &state);
    }
    state
}

/// `Poseidon.hash`: `update` from the zero state, the first output.
pub fn hash(cs: &mut Cs, input: &[Field]) -> Field {
    let zero = [Field::zero(), Field::zero(), Field::zero()];
    update(cs, zero, input)[0].clone()
}

/// Pickles' checked sponge (`Sponge.Make_sponge` over `Sponge_inputs`), which absorbs one field at
/// a time and permutes lazily.
pub struct Sponge {
    state: [Field; 3],
    /// `Absorbed n` (`true`) or `Squeezed n` (`false`), with `n`.
    absorbed: bool,
    n: usize,
}

const RATE: usize = 2;

impl Sponge {
    pub fn new() -> Self {
        Self { state: [Field::zero(), Field::zero(), Field::zero()], absorbed: true, n: 0 }
    }

    fn add_assign(&mut self, cs: &mut Cs, i: usize, x: &Field) {
        let sum = self.state[i].add(x);
        self.state[i] = seal(cs, &sum);
    }

    pub fn absorb(&mut self, cs: &mut Cs, x: &Field) {
        if self.absorbed {
            if self.n == RATE {
                self.state = block_cipher(cs, &self.state);
                self.add_assign(cs, 0, x);
                self.n = 1;
            } else {
                self.add_assign(cs, self.n, x);
                self.n += 1;
            }
        } else {
            self.add_assign(cs, 0, x);
            self.absorbed = true;
            self.n = 1;
        }
    }

    pub fn squeeze(&mut self, cs: &mut Cs) -> Field {
        if self.absorbed {
            self.state = block_cipher(cs, &self.state);
            self.absorbed = false;
            self.n = 1;
            self.state[0].clone()
        } else if self.n == RATE {
            self.state = block_cipher(cs, &self.state);
            self.n = 1;
            self.state[0].clone()
        } else {
            self.n += 1;
            self.state[self.n - 1].clone()
        }
    }
}

impl Default for Sponge {
    fn default() -> Self {
        Self::new()
    }
}

/// The permutation on constants (`PoseidonBigint.update`'s core), for the salted initial states
/// o1js computes outside the circuit.
fn permutation(state: [Fp; 3]) -> [Fp; 3] {
    *round_table(state).last().unwrap()
}

/// `Poseidon.update` on constants.
pub fn update_constant(state: [Fp; 3], input: &[Fp]) -> [Fp; 3] {
    if input.is_empty() {
        return permutation(state);
    }
    let mut state = state;
    for block in input.chunks(2) {
        for (i, x) in block.iter().enumerate() {
            state[i] += x;
        }
        state = permutation(state);
    }
    state
}

/// `prefixToField`: the bits of the prefix's characters, least significant first, as a field
/// element (`Random_oracle.prefix_to_field`).
pub fn prefix_to_field(prefix: &str) -> Fp {
    assert!(prefix.len() * 8 < 255, "prefix too long");
    let mut acc = Fp::zero();
    let mut two_k = Fp::one();
    for byte in prefix.bytes() {
        assert!(byte < 128, "only ASCII characters are supported");
        for j in 0..8 {
            if (byte >> j) & 1 == 1 {
                acc += two_k;
            }
            two_k.double_in_place();
        }
    }
    acc
}

/// `salt`/`hashWithPrefix`'s state: `update([0, 0, 0], [prefixToField(prefix)])`.
pub fn salted_state(prefix: &str) -> [Fp; 3] {
    update_constant([Fp::zero(); 3], &[prefix_to_field(prefix)])
}
