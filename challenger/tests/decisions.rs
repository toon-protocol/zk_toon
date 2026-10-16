use zk_toon_challenger::contract;
use zk_toon_challenger::fake::{FakeChain, FakeEvidence};
use zk_toon_challenger::*;

struct FakeHarness;
impl contract::Harness for FakeHarness {
    type Port = FakeChain;
    fn port(now: Millis, escapes: Vec<Escape>) -> FakeChain {
        FakeChain::new(now, escapes)
    }
}

#[test]
fn fake_passes_the_vault_chain_port_contract() {
    contract::run::<FakeHarness>();
}

const ID: Nullifier = [1; 32];
const NEXT: Nullifier = [2; 32];
const DEADLINE: Millis = 100_000;
const CFG: Config = Config { min_lead: 10_000 };

fn escape(conceded: u64, balance: u64) -> Escape {
    Escape { id: ID, next_nullifier: NEXT, conceded, balance, deadline: DEADLINE }
}

fn ev(nullifier: Nullifier, tier: u64, charge: u64, subsidised: bool, verifies: bool) -> Evidence {
    Evidence { nullifier, tier, charge, subsidised, verifies }
}

fn decide_with(e: &Escape, evidence: FakeEvidence, now: Millis) -> Decision {
    decide(e, &evidence, now, &CFG).unwrap()
}

#[test]
fn evidence_at_next_nullifier_defeats() {
    let d = decide_with(&escape(0, 100), FakeEvidence::default().with(ev(NEXT, 10, 3, false, true)), 0);
    assert_eq!(d, Decision::Defeat);
}

#[test]
fn subsidised_evidence_at_next_nullifier_still_defeats() {
    let d = decide_with(&escape(0, 100), FakeEvidence::default().with(ev(NEXT, 1, 0, true, true)), 0);
    assert_eq!(d, Decision::Defeat);
}

#[test]
fn charge_above_concession_raises_to_min_of_charge_tier_and_balance() {
    let raise = |tier, charge, balance| {
        decide_with(&escape(2, balance), FakeEvidence::default().with(ev(ID, tier, charge, false, true)), 0)
    };
    assert_eq!(raise(10, 7, 100), Decision::Raise { to: 7 });
    assert_eq!(raise(5, 7, 100), Decision::Raise { to: 5 });
    assert_eq!(raise(10, 7, 4), Decision::Raise { to: 4 });
}

#[test]
fn charge_not_above_concession_does_nothing() {
    let d = decide_with(&escape(7, 100), FakeEvidence::default().with(ev(ID, 10, 7, false, true)), 0);
    assert_eq!(d, Decision::NoOp);
    assert_eq!(decide_with(&escape(7, 100), FakeEvidence::default(), 0), Decision::NoOp);
}

#[test]
fn subsidised_evidence_never_raises() {
    let d = decide_with(&escape(0, 100), FakeEvidence::default().with(ev(ID, 10, 10, true, true)), 0);
    assert_eq!(d, Decision::NoOp);
}

#[test]
fn unverifying_evidence_alarms() {
    for at in [ID, NEXT] {
        let d = decide_with(&escape(0, 100), FakeEvidence::default().with(ev(at, 10, 10, false, false)), 0);
        assert_eq!(d, Decision::Alarm(AlarmReason::EvidenceInvalid));
    }
}

#[test]
fn unverifying_evidence_is_never_submitted() {
    let chain = FakeChain::new(0, vec![escape(0, 100)]);
    let evidence = FakeEvidence::default().with(ev(NEXT, 10, 10, false, false));
    let mut c = Challenger::new(chain.clone(), evidence, MemoryJournal::default(), CFG);
    let reports = c.tick(0).unwrap();
    assert!(reports.contains(&Report::Alarm { escape: ID, reason: AlarmReason::EvidenceInvalid }));
    assert!(chain.submissions().is_empty());
}

#[test]
fn deadline_too_close_is_reported_not_skipped() {
    let evidence = FakeEvidence::default().with(ev(NEXT, 10, 3, false, true));
    let late = DEADLINE - 5_000;
    assert_eq!(
        decide_with(&escape(0, 100), evidence.clone(), late),
        Decision::Alarm(AlarmReason::DeadlineTooClose { remaining: 5_000 })
    );
    let chain = FakeChain::new(late, vec![escape(0, 100)]);
    let mut c = Challenger::new(chain.clone(), evidence, MemoryJournal::default(), CFG);
    let reports = c.tick(late).unwrap();
    assert!(reports.contains(&Report::Alarm {
        escape: ID,
        reason: AlarmReason::DeadlineTooClose { remaining: 5_000 }
    }));
    assert!(chain.submissions().is_empty());
}

#[test]
fn restart_neither_repeats_nor_misses() {
    let chain = FakeChain::new(0, vec![escape(0, 100)]);
    let evidence = FakeEvidence::default().with(ev(ID, 10, 7, false, true));
    let path = std::env::temp_dir().join(format!("challenger-journal-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);

    let mut c = Challenger::new(chain.clone(), evidence.clone(), FileJournal::open(&path).unwrap(), CFG);
    c.tick(0).unwrap();
    assert_eq!(chain.submissions(), vec![(ID, Action::Raise { to: 7 })]);
    drop(c);

    // Restart: a fresh challenger over the same journal file. The chain still shows the escape
    // (the raise is not yet reflected), so only the journal stops a repeat.
    let stale = FakeChain::new(0, vec![escape(0, 100)]);
    let mut c = Challenger::new(stale.clone(), evidence.clone(), FileJournal::open(&path).unwrap(), CFG);
    let reports = c.tick(0).unwrap();
    assert!(stale.submissions().is_empty());
    assert!(!reports.iter().any(|r| matches!(r, Report::Seen { .. })));

    // An escape that appeared while the challenger was down is still acted on.
    let other = Escape { id: [3; 32], next_nullifier: [4; 32], ..escape(0, 100) };
    stale.add_escape(other);
    let evidence = evidence.with(ev([4; 32], 10, 0, false, true));
    let mut c = Challenger::new(stale.clone(), evidence, FileJournal::open(&path).unwrap(), CFG);
    c.tick(0).unwrap();
    assert_eq!(stale.submissions(), vec![([3; 32], Action::Defeat)]);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn reports_carry_only_escape_ids_and_actions() {
    let chain = FakeChain::new(0, vec![escape(0, 100)]);
    let evidence = FakeEvidence::default().with(ev(NEXT, 10, 3, false, true));
    let mut c = Challenger::new(chain, evidence, MemoryJournal::default(), CFG);
    let reports = c.tick(0).unwrap();
    assert_eq!(
        reports,
        vec![
            Report::Seen { escape: ID },
            Report::Submitted { escape: ID, action: Action::Defeat }
        ]
    );
}

#[test]
fn chain_outage_is_an_error_not_a_silent_skip() {
    let chain = FakeChain::new(0, vec![escape(0, 100)]);
    chain.set_unavailable(true);
    let mut c = Challenger::new(chain, FakeEvidence::default(), MemoryJournal::default(), CFG);
    assert!(matches!(c.tick(0), Err(PortError::Unavailable(_))));
}

#[test]
fn evidence_outage_is_reported_not_skipped() {
    let chain = FakeChain::new(0, vec![escape(0, 100)]);
    let mut c = Challenger::new(chain.clone(), FakeEvidence::default().unavailable(), MemoryJournal::default(), CFG);
    let reports = c.tick(0).unwrap();
    assert!(reports.contains(&Report::EvidenceUnavailable { escape: ID }));
    assert!(chain.submissions().is_empty());
}

#[test]
fn a_submitted_action_is_not_alarmed_on_as_its_deadline_nears() {
    // The raise is submitted but not yet reflected on chain, so the evidence still calls for it.
    let chain = FakeChain::new(0, vec![escape(0, 100)]);
    let evidence = FakeEvidence::default().with(ev(ID, 10, 7, false, true));
    let mut c = Challenger::new(chain.clone(), evidence, MemoryJournal::default(), CFG);
    c.tick(0).unwrap();
    let stale = FakeChain::new(DEADLINE - 5_000, vec![escape(0, 100)]);
    c.chain = stale.clone();
    assert!(c.tick(DEADLINE - 5_000).unwrap().is_empty());
    assert!(stale.submissions().is_empty());
}

/// Lists its escapes but refuses every submission.
struct Refusing(Vec<Escape>);
impl VaultChainPort for Refusing {
    fn escapes(&self) -> Result<Vec<Escape>, PortError> {
        Ok(self.0.clone())
    }
    fn submit_defeat(&mut self, _: &EscapeId) -> Result<(), PortError> {
        Err(PortError::Refused("already defeated".into()))
    }
    fn submit_raise(&mut self, _: &EscapeId, _: u64) -> Result<(), PortError> {
        Err(PortError::Refused("already raised".into()))
    }
}

#[test]
fn a_failed_submission_reports_why() {
    let evidence = FakeEvidence::default().with(ev(NEXT, 10, 3, false, true));
    let mut c = Challenger::new(Refusing(vec![escape(0, 100)]), evidence, MemoryJournal::default(), CFG);
    assert!(c.tick(0).unwrap().contains(&Report::SubmitFailed {
        escape: ID,
        action: Action::Defeat,
        error: PortError::Refused("already defeated".into()),
    }));
}
