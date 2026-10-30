//! Mirrors o1js `lib/provable/gadgets/basic.js` and `compatible.js`: the generic-gate helpers that
//! reduce a `FieldVar` to a variable and add the assertions. Only the variables they create are
//! mirrored (the generic gates themselves are in the committed circuit).

use ark_ff::{One, Zero};
use mina_curves::pasta::Fp;

use super::{Cs, Expr, Field};

/// `toLinearCombination`'s result: `constant + sum(scale * var)`.
pub struct LinearCombination {
    pub constant: Fp,
    /// `(scale, variable index)`, with no variable twice.
    pub terms: Vec<(Fp, usize)>,
}

/// `toLinearCombination` (`basic.js`): flatten the expression tree.
pub fn to_linear_combination(x: &Field) -> LinearCombination {
    let mut lc = LinearCombination { constant: Fp::zero(), terms: Vec::new() };
    walk(&x.e, Fp::one(), &mut lc);
    lc
}

fn walk(x: &Expr, sx: Fp, lc: &mut LinearCombination) {
    if sx.is_zero() {
        return;
    }
    match x {
        Expr::Constant(c) => lc.constant += sx * c,
        Expr::Var(i) => match lc.terms.iter().position(|t| t.1 == *i) {
            None => lc.terms.insert(0, (sx, *i)),
            Some(p) => {
                lc.terms[p].0 += sx;
                if lc.terms[p].0.is_zero() {
                    lc.terms.remove(p);
                }
            }
        },
        Expr::Scale(s, v) => walk(v, sx * s, lc),
        Expr::Add(x1, x2) => {
            walk(x1, sx, lc);
            walk(x2, sx, lc);
        }
    }
}

/// `ScaledVar | Constant`, the result of [`reduce_to_scaled_var`].
pub enum Scaled {
    Constant(Fp),
    /// `scale * var`. Only the scale is kept: nothing here needs the variable.
    Var(Fp),
}

impl Scaled {
    fn is_var(&self) -> bool {
        matches!(self, Scaled::Var(_))
    }
}

/// `linear(x, [a, b])`: `z = a*x + b`, with the gate's unused cell.
pub fn linear(cs: &mut Cs, x: &Field, a: Fp, b: Fp) -> Field {
    let z = cs.exists_one(a * x.v + b);
    cs.empty_cell();
    z
}

/// `bilinear(x, y, [a, b, c, d])`: `z = a*x*y + b*x + c*y + d`.
pub fn bilinear(cs: &mut Cs, x: &Field, y: &Field, [a, b, c, d]: [Fp; 4]) -> Field {
    cs.exists_one(a * x.v * y.v + b * x.v + c * y.v + d)
}

/// `reduceToScaledVar`: add the constraints that reduce `x` to `scale * var + 0`, or a constant.
pub fn reduce_to_scaled_var(cs: &mut Cs, x: &Field) -> Scaled {
    let lc = to_linear_combination(x);
    let c = lc.constant;
    let mut terms = lc.terms;
    // sort terms by variable index, to match snarky
    terms.sort_by_key(|t| t.1);
    if terms.is_empty() {
        return Scaled::Constant(c);
    }
    if terms.len() == 1 {
        let (s, i) = terms[0];
        if c.is_zero() {
            return Scaled::Var(s);
        }
        let xv = cs.var(i);
        linear(cs, &xv, s, c);
        return Scaled::Var(Fp::one());
    }
    let (s0, i0) = terms[0];
    let mut rest: Vec<(Fp, usize)> = terms[1..].to_vec();
    let (mut s1, i1) = rest.pop().unwrap();
    let mut x1 = cs.var(i1);
    for (si, xi) in rest.into_iter().rev() {
        let xi = cs.var(xi);
        x1 = bilinear(cs, &xi, &x1, [Fp::zero(), si, s1, Fp::zero()]);
        s1 = Fp::one();
    }
    let x0 = cs.var(i0);
    bilinear(cs, &x0, &x1, [Fp::zero(), s0, s1, c]);
    Scaled::Var(Fp::one())
}

/// `assertMulCompatible`: `x * y === z`, creating the variables snarky's `assert_r1cs` does.
pub fn assert_mul_compatible(cs: &mut Cs, x: &Field, y: &Field, z: &Field) {
    let xv = reduce_to_scaled_var(cs, x);
    let yv = reduce_to_scaled_var(cs, y);
    let zv = reduce_to_scaled_var(cs, z);
    // each constant operand is an unused gate cell: an empty cell. (Which cell does not matter,
    // all hold 0.)
    let vars = [&xv, &yv, &zv].iter().filter(|s| s.is_var()).count();
    match vars {
        3 => {}
        2 | 1 => {
            for _ in vars..3 {
                cs.empty_cell();
            }
        }
        _ => {
            let (Scaled::Constant(sx), Scaled::Constant(sy), Scaled::Constant(sz)) = (xv, yv, zv)
            else {
                unreachable!()
            };
            assert_eq!(sx * sy, sz, "assertMul()");
        }
    }
}

/// `assertSquareCompatible`: `x^2 === z`.
pub fn assert_square_compatible(cs: &mut Cs, x: &Field, z: &Field) {
    let xv = reduce_to_scaled_var(cs, x);
    let zv = reduce_to_scaled_var(cs, z);
    match (xv, zv) {
        (Scaled::Var(_), Scaled::Var(_)) => {}
        (Scaled::Var(_), Scaled::Constant(_)) => {
            cs.empty_cell();
        }
        (Scaled::Constant(_), Scaled::Var(_)) => {
            cs.empty_cell();
            cs.empty_cell();
        }
        (Scaled::Constant(sx), Scaled::Constant(sz)) => {
            assert_eq!(sx * sx, sz, "assertSquare()");
        }
    }
}

/// `assertBooleanCompatible`: `x` is 0 or 1.
pub fn assert_boolean_compatible(cs: &mut Cs, x: &Field) {
    match reduce_to_scaled_var(cs, x) {
        Scaled::Var(_) => {
            cs.empty_cell();
        }
        Scaled::Constant(x0) => assert_eq!(x0 * x0, x0, "assertBoolean()"),
    }
}

/// `assertEqualCompatible`: `x === y`. Note that `y` is reduced first.
pub fn assert_equal_compatible(cs: &mut Cs, x: &Field, y: &Field) {
    let yv = reduce_to_scaled_var(cs, y);
    let xv = reduce_to_scaled_var(cs, x);
    match (xv, yv) {
        (Scaled::Var(sx), Scaled::Var(sy)) => {
            if sx != sy {
                cs.empty_cell();
            }
            // otherwise a wire
        }
        (Scaled::Var(_), Scaled::Constant(_)) | (Scaled::Constant(_), Scaled::Var(_)) => {}
        (Scaled::Constant(sx), Scaled::Constant(sy)) => assert_eq!(sx, sy, "assertEqual()"),
    }
}
