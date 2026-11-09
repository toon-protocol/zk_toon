#!/usr/bin/env python3
"""Generate `src/wrap/constant_term.rs` and `src/witness/constant_term.rs` (then `rustfmt` them) from Mina's
`plonk_checks/scalars.ml`: `Tock.constant_term`, evaluated in the wrap circuit (over Fq), and `Tick.constant_term`, evaluated
in the step circuit (over Fp).

Usage: gen/constant_term.py <path to scalars.ml at Mina 228c409a> > src/wrap/constant_term.rs
       gen/constant_term.py <path to scalars.ml at Mina 228c409a> Tick > src/witness/constant_term.rs

Tick's linearization has the optional gates (range checks, foreign field, xor, rot, lookups) under `if_feature`. This
generates it for a circuit that uses none of them, as Pickles evaluates it for flags that are `No`: only the `else` branch of
each `if_feature`. The `then` branches are parsed and dropped.

The OCaml is code generated from kimchi's linearization; this translates it one to one, keeping its
evaluation order (OCaml evaluates the right operand of an operator first, and every `let`, used or not)
and its `Field` semantics: a product of two variables is a witness, a product with a constant is not.
"""
import re
import sys

src = open(sys.argv[1]).read()
MODULE = sys.argv[2] if len(sys.argv) > 2 else "Tock"
assert MODULE in ("Tock", "Tick")
FIELD = "Fq" if MODULE == "Tock" else "Fp"
start = src.index(f"module {MODULE} : S = struct")
body_start = src.index("a Env.t ) =", start) + len("a Env.t ) =")
body = src[body_start : src.index("\nend", body_start)]
# `if_feature (F, (fun () -> then), fun () -> else)` as a plain tuple
body = body.replace("(fun () ->", "(").replace(", fun () ->", ",")

TOKEN = re.compile(r'\s*(?:(?P<str>"[^"]*")|(?P<num>\d+)|(?P<id>[A-Za-z_][A-Za-z_0-9]*)|(?P<op>[()+\-*,=]))')


def tokenize(text):
    pos, out = 0, []
    while pos < len(text):
        m = TOKEN.match(text, pos)
        if not m:
            if text[pos:].strip() == "":
                break
            raise SystemExit(f"cannot tokenize at {text[pos:pos+40]!r}")
        pos = m.end()
        kind = m.lastgroup
        out.append((kind, m.group(kind)))
    return out


toks = tokenize(body)
i = 0


def peek():
    return toks[i] if i < len(toks) else (None, None)


def take(expected=None):
    global i
    t = toks[i]
    if expected is not None and t[1] != expected:
        raise SystemExit(f"expected {expected} at token {i}, got {t}")
    i += 1
    return t


def parse_expr():
    if peek() == ("id", "let"):
        take()
        name = take()[1]
        take("=")
        value = parse_expr()
        take("in")
        return ("let", name, value, parse_expr())
    return parse_sum()


def parse_sum():
    left = parse_product()
    while peek()[1] in ("+", "-") and peek()[0] == "op":
        op = take()[1]
        left = (op, left, parse_product())
    return left


def parse_product():
    left = parse_app()
    while peek() == ("op", "*"):
        take()
        left = ("*", left, parse_app())
    return left


def starts_atom():
    k, v = peek()
    return k in ("str", "num") or (k == "id" and v not in ("in", "let")) or v == "("


def parse_atom():
    k, v = peek()
    if (k, v) == ("op", "-"):
        take()
        return ("num", "-" + take()[1])
    if v == "(" and k == "op":
        take()
        e = parse_expr()
        if peek() == ("op", ","):
            items = [e]
            while peek() == ("op", ","):
                take()
                items.append(parse_expr())
            take(")")
            return ("tuple", items)
        take(")")
        return e
    take()
    return (k, v)


def parse_app():
    head = parse_atom()
    if head[0] == "id" and head[1] in FUNCS:
        args = []
        while starts_atom():
            args.append(parse_atom())
        return ("app", head[1], args)
    return head


FUNCS = {"pow", "cell", "var", "field", "alpha_pow", "double", "square", "mds", "if_feature", "unnormalized_lagrange_basis"}

COLUMNS = {"Poseidon": "poseidon_selector", "Generic": "generic_selector", "VarBaseMul": "mul_selector",
           "CompleteAdd": "complete_add_selector", "EndoMul": "emul_selector",
           "EndoMulScalar": "endomul_scalar_selector"}


# `var (Witness 7, Next)`: the first component is `Witness 7` (an identifier applied to a number) or an
# identifier (`Index Generic`, `Coefficient 3`), which this grammar parses as a sequence of atoms. Parse
# those by pre-processing the token stream into single atoms.
def preprocess(tokens):
    out, j = [], 0
    while j < len(tokens):
        k, v = tokens[j]
        if k == "id" and v in ("Witness", "Coefficient", "Index", "LookupSorted", "LookupKindIndex", "LookupsPerRow", "LookupPattern", "TableWidth"):
            out.append(("id", f"{v}_{tokens[j+1][1]}"))
            j += 2
        else:
            out.append((k, v))
            j += 1
    return out


toks = preprocess(toks)
i = 0
tree = parse_expr()
assert i == len(toks), f"unparsed tokens from {i}: {toks[i:i+5]}"


def cell_of(col, row):
    side = "zeta" if row == "Curr" else "zeta_omega"
    m = re.fullmatch(r"(Witness|Coefficient)_(\d+)", col)
    if m:
        field = "w" if m.group(1) == "Witness" else "coefficients"
        return f"V::var(evals.{field}[{m.group(2)}].{side})"
    m = re.fullmatch(r"Index_(\w+)", col)
    if m:
        return f"V::var(evals.{COLUMNS[m.group(1)]}.{side})"
    raise SystemExit(f"unknown column {col}")


def rust(e):
    k = e[0]
    if k == "id":
        if e[1] == "endo_coefficient":
            return "k(endo)"
        if e[1].startswith("x_"):
            return e[1]
        raise SystemExit(f"unknown identifier {e[1]}")
    if k == "let":
        return "{ let %s = %s; %s }" % (e[1], rust(e[2]), rust(e[3]))
    if k in ("+", "-"):
        return "{ let r = %s; let l = %s; %s(l, r) }" % (rust(e[2]), rust(e[1]), "add" if k == "+" else "sub")
    if k == "*":
        return "{ let r = %s; let l = %s; mul(l, r, w) }" % (rust(e[2]), rust(e[1]))
    if k == "app":
        name, args = e[1], e[2]
        if name == "cell":
            return rust(args[0])
        if name == "var":
            col, row = args[0][1]
            return cell_of(col[1], row[1])
        if name == "field":
            return 'k(dec("%d"))' % int(args[0][1].strip('"'), 16)
        if name == "alpha_pow":
            return "V::var(alpha_pows[%s])" % args[0][1]
        if name == "double":
            return "dbl(%s)" % rust(args[0])
        if name == "square":
            return "{ let a = %s; mul(a, a, w) }" % rust(args[0])
        if name == "mds":
            r, c = args[0][1]
            return "k(mds[%s][%s])" % (r[1], c[1])
        if name == "if_feature":
            # no optional gate is used: the `else` branch
            return rust(args[0][1][2])
        if name == "pow":
            x, n = args[0][1]
            return "pw(%s, %s, w)" % (rust(x), n[1])
    raise SystemExit(f"cannot translate {e}")


HEADER = '''//! `Tock.constant_term`: the constant term of the linearization of a wrap proof, evaluated in the wrap
//! circuit. Generated by `gen/constant_term.py` from `src/lib/crypto/pickles/plonk_checks/scalars.ml` of
//! Mina `228c409a` (the commit o1js v3.1.0 bundles), which is itself generated from kimchi's
//! linearization: do not edit. The operations are `Field`'s: a product of two variables is a witness, a
//! product with a constant is not, and the right operand of an operator is evaluated first.
//!
//! mina-rust (`toon-protocol/mina-rust` at rev `6feeb3797fff6dba49fd848cb2d6decd63fee1b4`) evaluates
//! kimchi's own expression tree instead, which orders the witnesses differently.

#![allow(clippy::all, unused_parens, unused_braces)]

use ark_ff::AdditiveGroup;
use kimchi::proof::{PointEvaluations, ProofEvaluations};
use ledger::proofs::{field::field, witness::Witness};
use mina_curves::pasta::Fq;
use std::str::FromStr;

/// A value of the circuit: whether it is a constant decides whether a product of it is a witness.
#[derive(Clone, Copy)]
struct V {
    v: Fq,
    c: bool,
}

impl V {
    fn var(v: Fq) -> Self {
        Self { v, c: false }
    }
}

fn k(v: Fq) -> V {
    V { v, c: true }
}

fn dec(s: &str) -> Fq {
    Fq::from_str(s).expect("a field element")
}

fn add(a: V, b: V) -> V {
    V { v: a.v + b.v, c: a.c && b.c }
}

fn sub(a: V, b: V) -> V {
    V { v: a.v - b.v, c: a.c && b.c }
}

fn mul(a: V, b: V, w: &mut Witness<Fq>) -> V {
    if a.c || b.c {
        V { v: a.v * b.v, c: a.c && b.c }
    } else {
        V::var(field::mul(a.v, b.v, w))
    }
}

/// `double x = of_int 2 * x`
fn dbl(a: V) -> V {
    V { v: a.v.double(), c: a.c }
}

/// `Plonk_checks.scalars_env`'s `pow`.
fn pw(x: V, n: u64, w: &mut Witness<Fq>) -> V {
    if n == 0 {
        k(Fq::from(1u64))
    } else if n == 1 {
        x
    } else {
        let y = pw(mul(x, x, w), n / 2, w);
        if n % 2 == 0 {
            y
        } else {
            mul(x, y, w)
        }
    }
}

/// `alpha_pows` are the powers of alpha the circuit already computed.
pub fn constant_term(
    evals: &ProofEvaluations<PointEvaluations<Fq>>,
    alpha_pows: &[Fq],
    mds: &[[Fq; 3]; 3],
    endo: Fq,
    w: &mut Witness<Fq>,
) -> Fq {'''
if MODULE == "Tick":
    HEADER = HEADER.replace(
        "`Tock.constant_term`: the constant term of the linearization of a wrap proof, evaluated in the wrap\n//! circuit. ",
        "`Tick.constant_term`: the constant term of the linearization of a step proof, evaluated in the step\n//! circuit, for a circuit that uses none of the optional gates (the `else` of each `if_feature`).\n//! ",
    )
print(HEADER.replace("Fq", FIELD))

# The top-level `let`s become statements; nested ones stay blocks.
while tree[0] == "let":
    print("    let %s = %s;" % (tree[1], rust(tree[2])))
    tree = tree[3]
print("    " + rust(tree) + ".v")
print("}")
