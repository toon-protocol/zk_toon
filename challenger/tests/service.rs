//! One pass of the challenger service: read the chain time, tick, and log what happened as lines.
use zk_toon_challenger::fake::{FakeChain, FakeEvidence};
use zk_toon_challenger::service::{pass, serve};
use zk_toon_challenger::*;

const ID: Nullifier = [1; 32];
const NEXT: Nullifier = [2; 32];
const CFG: Config = Config { min_lead: 5 };

fn escape() -> Escape {
    Escape { id: ID, next_nullifier: NEXT, conceded: 0, balance: 100, deadline: 1_000 }
}

fn ev(nullifier: Nullifier, charge: u64, verifies: bool) -> Evidence {
    Evidence { nullifier, tier: 10, charge: Some(charge), subsidised: false, verifies }
}

fn id_hex() -> String {
    "01".repeat(32)
}

#[test]
fn a_pass_logs_each_escape_seen_and_each_action_by_nullifier() {
    let chain = FakeChain::new(0, vec![escape()]);
    let mut c = Challenger::new(chain.clone(), FakeEvidence::default().with(ev(ID, 7, true)), MemoryJournal::default(), CFG);
    assert_eq!(pass(&mut c, Ok(0)), vec![format!("seen {}", id_hex()), format!("submitted {} raise 7", id_hex())]);
    // Nothing new on the next pass: nothing logged.
    assert!(pass(&mut c, Ok(0)).is_empty());
}

#[test]
fn a_pass_logs_alarms_and_failures_with_their_reason() {
    let chain = FakeChain::new(0, vec![escape()]);
    let mut c = Challenger::new(chain, FakeEvidence::default().with(ev(NEXT, 0, false)), MemoryJournal::default(), CFG);
    assert_eq!(pass(&mut c, Ok(0))[1], format!("alarm {} evidence-invalid", id_hex()));

    let chain = FakeChain::new(997, vec![escape()]);
    let mut c = Challenger::new(chain, FakeEvidence::default().with(ev(NEXT, 0, true)), MemoryJournal::default(), CFG);
    assert_eq!(pass(&mut c, Ok(997))[1], format!("alarm {} deadline-too-close 3", id_hex()));

    let chain = FakeChain::new(0, vec![escape()]);
    let mut c = Challenger::new(chain, FakeEvidence::default().unavailable(), MemoryJournal::default(), CFG);
    assert_eq!(pass(&mut c, Ok(0))[1], format!("evidence-unavailable {}", id_hex()));
}

#[test]
fn an_unreadable_chain_is_logged_and_the_next_pass_acts() {
    let chain = FakeChain::new(0, vec![escape()]);
    let mut c = Challenger::new(chain.clone(), FakeEvidence::default().with(ev(NEXT, 0, true)), MemoryJournal::default(), CFG);

    assert_eq!(pass(&mut c, Err(PortError::Unavailable("no tip".into()))), vec!["unavailable: no tip".to_string()]);
    chain.set_unavailable(true);
    assert_eq!(pass(&mut c, Ok(0)), vec!["unavailable: fake chain down".to_string()]);
    assert!(chain.submissions().is_empty());

    chain.set_unavailable(false);
    assert_eq!(pass(&mut c, Ok(0)), vec![format!("seen {}", id_hex()), format!("submitted {} defeat", id_hex())]);
    assert_eq!(chain.submissions(), vec![(ID, Action::Defeat)]);
}

#[test]
fn the_service_passes_at_the_chain_time_until_told_to_stop() {
    // At slot 997 the escape's deadline is 3 slots away, inside `min_lead`: the alarm shows the pass
    // read the chain's time.
    let chain = FakeChain::new(997, vec![escape()]);
    let mut c = Challenger::new(chain, FakeEvidence::default().with(ev(NEXT, 0, true)), MemoryJournal::default(), CFG);
    let (mut lines, mut checks, mut waits) = (Vec::new(), 0, 0);
    let why = serve(
        &mut c,
        || {
            checks += 1;
            (checks == 2).then(|| "the builder died".to_string())
        },
        || waits += 1,
        |line| lines.push(line.to_string()),
    );
    assert_eq!(why, "the builder died");
    assert_eq!((checks, waits), (2, 1));
    assert_eq!(
        lines,
        vec![
            format!("seen {}", id_hex()),
            format!("alarm {} deadline-too-close 3", id_hex()),
            format!("alarm {} deadline-too-close 3", id_hex()),
        ]
    );
}

#[test]
fn a_restarted_service_neither_repeats_nor_misses() {
    let path = std::env::temp_dir().join(format!("challenger-service-journal-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let evidence = FakeEvidence::default().with(ev(ID, 7, true));
    let once = || {
        let mut done = false;
        move || std::mem::replace(&mut done, true).then(|| "stopped".to_string())
    };

    let chain = FakeChain::new(0, vec![escape()]);
    let mut c = Challenger::new(chain.clone(), evidence.clone(), FileJournal::open(&path).unwrap(), CFG);
    serve(&mut c, once(), || {}, |_| {});
    assert_eq!(chain.submissions(), vec![(ID, Action::Raise { to: 7 })]);

    // After the restart the chain still shows the escape unraised, and another escape opened.
    let other = Escape { id: [3; 32], next_nullifier: [4; 32], ..escape() };
    let stale = FakeChain::new(0, vec![escape(), other]);
    let evidence = evidence.with(ev([4; 32], 0, true));
    let mut c = Challenger::new(stale.clone(), evidence, FileJournal::open(&path).unwrap(), CFG);
    let mut lines = Vec::new();
    serve(&mut c, once(), || {}, |l| lines.push(l.to_string()));
    assert_eq!(stale.submissions(), vec![([3; 32], Action::Defeat)]);
    assert_eq!(lines, vec![format!("seen {}", "03".repeat(32)), format!("submitted {} defeat", "03".repeat(32))]);
    let _ = std::fs::remove_file(&path);
}
