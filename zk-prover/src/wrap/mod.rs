//! The Pickles wrap prover for an o1js program: [`wrap`] takes a step proof and returns the wrap
//! proof and the wrap witness.
//!
//! mina-rust's `wrap` / `wrap_main` fix the number of previous proofs at 2, take a single step key
//! and leave out optional gates and lookups. This module is a generalised copy: the number of
//! previous proofs, the program's step keys (one per method) and its feature flags are parameters.

pub mod deferred;
