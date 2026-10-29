//! A step witness built in Rust, in o1js's order.
//!
//! The witness of a step circuit is the list of values of its variables, in the order the circuit
//! created them (`aux`; variable `i` is `aux[i - 1]`, variable 0 is the public input). o1js and
//! Pickles create variables as a side effect of their gadgets, so equality with o1js's witness
//! needs the same gadgets, creating the same variables in the same order. This module is that
//! mirror:
//!
//! - [`Cs`] holds the witness under construction; [`Field`] and [`Bool`] mirror o1js's `Field`
//!   and `Bool`, including its `FieldVar` expression tree, since whether an operation creates a
//!   variable depends on the shape of its operands.
//! - [`gadgets`] mirrors the o1js gadgets, each named after the o1js function it mirrors.
//! - [`land`] is the `Land` zkApp's `land` method, the SmartContract wrapper around it and the
//!   Pickles step circuit around that.
//!
//! No constraint is built here: kimchi checks the constraints against the committed circuit
//! (`check_step`). Gates that o1js adds contribute to the witness only through the variables they
//! create, which are mirrored; the gates themselves are not.

use std::rc::Rc;

use ark_ff::{BigInteger, BigInteger256, Field as _, One, PrimeField, Zero};
use mina_curves::pasta::Fp;

pub mod gadgets;
pub mod account_update;
pub mod land;
pub mod pickles;

/// The expression tree of an o1js `FieldVar` (`lib/provable/core/fieldvar.js`).
#[derive(Debug)]
enum Expr {
    Constant(Fp),
    Var(usize),
    Add(Rc<Expr>, Rc<Expr>),
    Scale(Fp, Rc<Expr>),
}

/// A field element in the circuit: an o1js `Field`. It carries its value and the `FieldVar` tree
/// that o1js would have built for it.
#[derive(Clone, Debug)]
pub struct Field {
    e: Rc<Expr>,
    v: Fp,
}

/// A boolean in the circuit: an o1js `Bool`.
#[derive(Clone, Debug)]
pub struct Bool(pub Field);

/// The witness under construction.
#[derive(Default)]
pub struct Cs {
    aux: Vec<Fp>,
}

impl Cs {
    pub fn new() -> Self {
        Self::default()
    }

    /// Continue from the first `aux.len()` auxiliary values of an existing witness. Gadget tests
    /// use this to run one gadget on the variables o1js's witness gives it.
    pub fn resume(aux: &[Fp]) -> Self {
        Self { aux: aux.to_vec() }
    }

    /// The auxiliary values created so far.
    pub fn aux(&self) -> &[Fp] {
        &self.aux
    }

    pub fn into_aux(self) -> Vec<Fp> {
        self.aux
    }

    /// The index the next variable gets (variable 0 is the public input).
    pub fn next_var(&self) -> usize {
        self.aux.len() + 1
    }

    /// The variable `i` as a `Field`.
    pub fn var(&self, i: usize) -> Field {
        Field { e: Rc::new(Expr::Var(i)), v: self.aux[i - 1] }
    }

    /// A fresh variable (o1js `existsOne`).
    pub fn exists_one(&mut self, v: Fp) -> Field {
        self.aux.push(v);
        Field { e: Rc::new(Expr::Var(self.aux.len())), v }
    }

    /// Fresh variables (o1js `exists`).
    pub fn exists<const N: usize>(&mut self, vs: [Fp; N]) -> [Field; N] {
        vs.map(|v| self.exists_one(v))
    }

    /// Append values created by code outside this module (the fork's gadgets), as fresh
    /// variables.
    pub fn extend(&mut self, vs: impl IntoIterator<Item = Fp>) {
        self.aux.extend(vs);
    }

    /// `emptyCell` (`gadgets/basic.js`): a variable with value 0, for an unused gate cell.
    pub fn empty_cell(&mut self) -> Field {
        self.exists_one(Fp::zero())
    }
}

// --- Field --------------------------------------------------------------------------------------

impl Field {
    pub fn constant(c: Fp) -> Self {
        Self { e: Rc::new(Expr::Constant(c)), v: c }
    }

    pub fn from_u64(c: u64) -> Self {
        Self::constant(Fp::from(c))
    }

    pub fn zero() -> Self {
        Self::constant(Fp::zero())
    }

    pub fn one() -> Self {
        Self::constant(Fp::one())
    }

    /// The value (o1js `toBigInt`, readable because we always run as the prover).
    pub fn value(&self) -> Fp {
        self.v
    }

    /// `Field.isConstant`: whether the expression is a constant (not whether it evaluates to one).
    pub fn is_constant(&self) -> bool {
        matches!(*self.e, Expr::Constant(_))
    }

    /// `FieldVar.isVar`: a pure variable.
    pub fn is_var(&self) -> bool {
        matches!(*self.e, Expr::Var(_))
    }

    /// `FieldVar.add`.
    pub fn add(&self, y: &Field) -> Field {
        if let Expr::Constant(c) = *self.e {
            if c.is_zero() {
                return y.clone();
            }
        }
        if let Expr::Constant(c) = *y.e {
            if c.is_zero() {
                return self.clone();
            }
        }
        if self.is_constant() && y.is_constant() {
            return Field::constant(self.v + y.v);
        }
        Field { e: Rc::new(Expr::Add(self.e.clone(), y.e.clone())), v: self.v + y.v }
    }

    /// `FieldVar.scale`.
    pub fn scale(&self, c: Fp) -> Field {
        if c.is_zero() {
            return Field::zero();
        }
        if c.is_one() {
            return self.clone();
        }
        let v = c * self.v;
        match &*self.e {
            Expr::Constant(_) => Field::constant(v),
            Expr::Scale(s, inner) => {
                Field { e: Rc::new(Expr::Scale(c * *s, inner.clone())), v }
            }
            _ => Field { e: Rc::new(Expr::Scale(c, self.e.clone())), v },
        }
    }

    /// `Field.neg`.
    pub fn neg(&self) -> Field {
        if self.is_constant() {
            return Field::constant(-self.v);
        }
        self.scale(-Fp::one())
    }

    /// `Field.sub`.
    pub fn sub(&self, y: &Field) -> Field {
        self.add(&y.neg())
    }

    pub fn add_const(&self, c: Fp) -> Field {
        self.add(&Field::constant(c))
    }

    pub fn sub_const(&self, c: Fp) -> Field {
        self.sub(&Field::constant(c))
    }

    /// `Field.mul` by a constant: a `Scale` node, no variable.
    pub fn mul_const(&self, c: Fp) -> Field {
        if self.is_constant() {
            return Field::constant(self.v * c);
        }
        self.scale(c)
    }

    /// `Field.mul`.
    pub fn mul(&self, cs: &mut Cs, y: &Field) -> Field {
        if self.is_constant() && y.is_constant() {
            return Field::constant(self.v * y.v);
        }
        if y.is_constant() {
            return self.scale(y.v);
        }
        if self.is_constant() {
            return y.scale(self.v);
        }
        let z = cs.exists_one(self.v * y.v);
        basic::assert_mul_compatible(cs, self, y, &z);
        z
    }

    /// `Field.square`.
    pub fn square(&self, cs: &mut Cs) -> Field {
        if self.is_constant() {
            return Field::constant(self.v.square());
        }
        let z = cs.exists_one(self.v.square());
        basic::assert_square_compatible(cs, self, &z);
        z
    }

    /// `Field.sqrt`, as the prover computes it: a square root, or 0 if there is none.
    pub fn sqrt(&self, cs: &mut Cs) -> Field {
        if self.is_constant() {
            return Field::constant(self.v.sqrt().expect("Field.sqrt(): no square root"));
        }
        let z = cs.exists_one(field_sqrt(self.v).unwrap_or_else(Fp::zero));
        basic::assert_square_compatible(cs, &z, self);
        z
    }

    /// `Field.equals`.
    pub fn equals(&self, cs: &mut Cs, y: &Field) -> Bool {
        if self.is_constant() && y.is_constant() {
            return Bool::constant(self.v == y.v);
        }
        let x_minus_y = self.sub(y).seal(cs);
        let xmy = x_minus_y.v;
        let z = xmy.inverse().unwrap_or_else(Fp::zero);
        let b = Fp::one() - z * xmy;
        let [b, z] = cs.exists([b, z]);
        basic::assert_mul_compatible(cs, &b, &x_minus_y, &Field::zero());
        basic::assert_mul_compatible(cs, &z, &x_minus_y, &Field::one().sub(&b));
        Bool(b)
    }

    /// `Field.assertEquals`.
    pub fn assert_equals(&self, cs: &mut Cs, y: &Field) {
        if self.is_constant() && y.is_constant() {
            assert_eq!(self.v, y.v, "Field.assertEquals()");
            return;
        }
        basic::assert_equal_compatible(cs, self, y);
    }

    /// `Field.assertBool`.
    pub fn assert_bool(&self, cs: &mut Cs) -> Bool {
        if self.is_constant() {
            assert!(self.v.is_zero() || self.v.is_one(), "Field.assertBool()");
            return Bool::constant(self.v.is_one());
        }
        basic::assert_boolean_compatible(cs, self);
        Bool(self.clone())
    }

    /// The linear combination the expression flattens to.
    pub fn linear_combination(&self) -> basic::LinearCombination {
        basic::to_linear_combination(self)
    }

    /// `Field.seal`: reduce to a pure variable (constants stay).
    pub fn seal(&self, cs: &mut Cs) -> Field {
        let lc = basic::to_linear_combination(self);
        if lc.terms.is_empty() {
            return Field::constant(lc.constant);
        }
        if lc.terms.len() == 1 && lc.constant.is_zero() {
            let (c, i) = lc.terms[0];
            if c.is_one() {
                return cs.var(i);
            }
        }
        let x = cs.exists_one(self.v);
        self.assert_equals(cs, &x);
        x
    }

    /// `toVar` (`gadgets/common.js`): like [`Field::seal`], but constants become variables too.
    pub fn to_var(&self, cs: &mut Cs) -> Field {
        if self.is_var() {
            return self.clone();
        }
        let x = cs.exists_one(self.v);
        x.assert_equals(cs, self);
        x
    }
}

/// `sqrt` of o1js's bindings (`bindings/crypto/finite-field.js`): Tonelli-Shanks. Of the two roots
/// it returns the one this algorithm finds, so the witness holds the same value as o1js's.
fn field_sqrt(n: Fp) -> Option<Fp> {
    // The odd factor of p - 1, a primitive 2^32-th root of unity and the 2-adicity, as in o1js.
    const ODD_FACTOR: &str = "40000000000000000000000000000000224698fc094cf91b992d30ed";
    const TWOADIC_ROOT: &str =
        "2bce74deac30ebda362120830561f81aea322bf2b7bb7584bdad6fabd87ea32f";
    let hex = |s: &str| Fp::from_be_bytes_mod_order(&hex_bytes(s));
    let q = hex(ODD_FACTOR).into_bigint();
    let mut c = hex(TWOADIC_ROOT);
    let mut m = 32u32;
    if n.is_zero() {
        return Some(Fp::zero());
    }
    // t = n^((Q - 1) / 2); R = t * n; t = t * R
    let mut q_minus_1_half = q;
    q_minus_1_half.sub_with_borrow(&BigInteger256::from(1u64));
    q_minus_1_half.div2();
    let mut t = n.pow(q_minus_1_half);
    let mut r = t * n;
    t *= r;
    loop {
        if t.is_one() {
            return Some(r);
        }
        let mut i = 0u32;
        let mut s = t;
        while !s.is_one() {
            s = s.square();
            i += 1;
        }
        if i == m {
            return None;
        }
        let mut b = c;
        for _ in 0..(m - i - 1) {
            b = b.square();
        }
        m = i;
        c = b.square();
        t *= c;
        r *= b;
    }
}

fn hex_bytes(s: &str) -> Vec<u8> {
    let s = if s.len() % 2 == 1 { format!("0{s}") } else { s.to_string() };
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

// --- Bool ---------------------------------------------------------------------------------------

impl Bool {
    pub fn constant(b: bool) -> Self {
        Bool(Field::constant(Fp::from(b as u64)))
    }

    pub fn is_constant(&self) -> bool {
        self.0.is_constant()
    }

    pub fn value(&self) -> bool {
        self.0.v.is_one()
    }

    pub fn to_field(&self) -> Field {
        self.0.clone()
    }

    /// `Bool.not`.
    pub fn not(&self) -> Bool {
        if self.is_constant() {
            return Bool::constant(!self.value());
        }
        Bool(Field::one().sub(&self.0))
    }

    /// `Bool.and`.
    pub fn and(&self, cs: &mut Cs, y: &Bool) -> Bool {
        if self.is_constant() && y.is_constant() {
            return Bool::constant(self.value() && y.value());
        }
        Bool(self.0.mul(cs, &y.0))
    }

    /// `Bool.or`.
    pub fn or(&self, cs: &mut Cs, y: &Bool) -> Bool {
        if self.is_constant() && y.is_constant() {
            return Bool::constant(self.value() || y.value());
        }
        self.not().and(cs, &y.not()).not()
    }

    /// `Bool.assertEquals`.
    pub fn assert_equals(&self, cs: &mut Cs, y: &Bool) {
        if self.is_constant() && y.is_constant() {
            assert_eq!(self.value(), y.value(), "Bool.assertEquals()");
            return;
        }
        self.0.assert_equals(cs, &y.0);
    }

    pub fn assert_true(&self, cs: &mut Cs) {
        self.assert_equals(cs, &Bool::constant(true));
    }

    pub fn assert_false(&self, cs: &mut Cs) {
        self.assert_equals(cs, &Bool::constant(false));
    }

    /// `Bool.equals`.
    pub fn equals(&self, cs: &mut Cs, y: &Bool) -> Bool {
        if self.is_constant() && y.is_constant() {
            return Bool::constant(self.value() == y.value());
        }
        if y.is_constant() {
            return if y.value() { self.clone() } else { self.not() };
        }
        if self.is_constant() {
            return y.equals(cs, self);
        }
        let z = cs.exists_one(Fp::from((self.value() != y.value()) as u64));
        let x = self.0.clone();
        let y_ = y.0.clone();
        basic::assert_mul_compatible(cs, &x.add(&x), &y_, &x.add(&y_).sub(&z));
        Bool(z).not()
    }

    /// `Bool.Unsafe.fromField`.
    pub fn from_field_unsafe(f: Field) -> Bool {
        Bool(f)
    }
}

mod basic;

pub use basic::{assert_boolean_compatible, assert_equal_compatible, assert_mul_compatible};

/// The bits of `x`, least significant first, as `u128` limbs: `[lo, hi]`.
pub(crate) fn limbs(x: &Fp) -> [u128; 2] {
    let b = x.into_bigint().0;
    [b[0] as u128 | (b[1] as u128) << 64, b[2] as u128 | (b[3] as u128) << 64]
}

/// `bitSlice(x, start, length)` (`gadgets/common.js`) for `length <= 128`.
pub(crate) fn bit_slice(x: &Fp, start: usize, length: usize) -> Fp {
    let [lo, hi] = limbs(x);
    let shifted = if start >= 128 {
        hi >> (start - 128)
    } else if start == 0 {
        lo
    } else {
        (lo >> start) | (hi << (128 - start))
    };
    let masked = if length >= 128 { shifted } else { shifted & ((1u128 << length) - 1) };
    Fp::from(masked)
}

/// `Fp.from(u128)`.
pub(crate) fn fp_from_u128(x: u128) -> Fp {
    Fp::from(x)
}
