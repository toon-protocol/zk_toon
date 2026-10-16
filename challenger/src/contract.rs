//! The contract suite for [`VaultChainPort`]. Every implementation, the in-memory fake and the
//! Mina GraphQL adapter, must pass it. Run it with [`run`].

use crate::ports::*;
use crate::types::*;

/// Builds a port over a chain at time `now` holding exactly `escapes`.
pub trait Harness {
    type Port: VaultChainPort;
    fn port(now: Millis, escapes: Vec<Escape>) -> Self::Port;
}

fn esc(n: u8, conceded: u64, balance: u64, deadline: Millis) -> Escape {
    Escape { id: [n; 32], next_nullifier: [n + 100; 32], conceded, balance, deadline }
}

pub fn run<H: Harness>() {
    lists_open_escapes_with_deadlines::<H>();
    hides_escapes_past_their_deadline::<H>();
    defeat_closes_the_escape::<H>();
    raise_lifts_the_concession::<H>();
    raise_must_exceed_concession_and_fit_balance::<H>();
    refuses_unknown_escapes::<H>();
}

fn lists_open_escapes_with_deadlines<H: Harness>() {
    let e = esc(1, 5, 50, 1_000);
    let port = H::port(10, vec![e.clone()]);
    assert_eq!(port.escapes().unwrap(), vec![e]);
}

fn hides_escapes_past_their_deadline<H: Harness>() {
    let port = H::port(1_000, vec![esc(1, 5, 50, 1_000)]);
    assert!(port.escapes().unwrap().is_empty());
}

fn defeat_closes_the_escape<H: Harness>() {
    let mut port = H::port(10, vec![esc(1, 5, 50, 1_000), esc(2, 5, 50, 1_000)]);
    port.submit_defeat(&[1; 32]).unwrap();
    let left = port.escapes().unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].id, [2; 32]);
    assert!(matches!(port.submit_defeat(&[1; 32]), Err(PortError::Refused(_))));
}

fn raise_lifts_the_concession<H: Harness>() {
    let mut port = H::port(10, vec![esc(1, 5, 50, 1_000)]);
    port.submit_raise(&[1; 32], 20).unwrap();
    assert_eq!(port.escapes().unwrap()[0].conceded, 20);
}

fn raise_must_exceed_concession_and_fit_balance<H: Harness>() {
    let mut port = H::port(10, vec![esc(1, 5, 50, 1_000)]);
    assert!(matches!(port.submit_raise(&[1; 32], 5), Err(PortError::Refused(_))));
    assert!(matches!(port.submit_raise(&[1; 32], 51), Err(PortError::Refused(_))));
    assert_eq!(port.escapes().unwrap()[0].conceded, 5);
}

fn refuses_unknown_escapes<H: Harness>() {
    let mut port = H::port(10, vec![]);
    assert!(matches!(port.submit_defeat(&[9; 32]), Err(PortError::Refused(_))));
    assert!(matches!(port.submit_raise(&[9; 32], 1), Err(PortError::Refused(_))));
}
