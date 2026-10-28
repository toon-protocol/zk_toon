//! Decisions over the file-backed evidence port, with a fake verifier.
use std::cell::Cell;
use std::io::Write;
use std::path::PathBuf;
use std::rc::Rc;

use zk_evidence::{frame, write_header, Close, Grant, Record};
use zk_note::Field;
use zk_toon_challenger::*;

const ID: u64 = 11;
const NEXT: u64 = 12;
const CFG: Config = Config { min_lead: 10_000 };

fn nullifier(n: u64) -> Nullifier {
    zk_evidence::field_to_bytes(Field::from(n))
}

fn escape(conceded: u64, balance: u64) -> Escape {
    Escape { id: nullifier(ID), next_nullifier: nullifier(NEXT), conceded, balance, deadline: 100_000 }
}

fn grant(n: u64, tier: u64, subsidised: bool, allowance: &[u8]) -> Record {
    let input = [
        "1", "0", "5", "1700000000000", &tier.to_string(), &n.to_string(), "9", "3", "4",
        if subsidised { "1" } else { "0" }, "0", "0",
    ];
    let proof = format!(
        "{{\"publicInput\":[{}],\"publicOutput\":[],\"maxProofsVerified\":0,\"proof\":\"fake\"}}",
        input.iter().map(|s| format!("\"{s}\"")).collect::<Vec<_>>().join(",")
    );
    Record::Grant(Grant {
        proof: proof.into_bytes(),
        allowance_id: allowance.to_vec(),
        session_key_x: Field::from(7u64),
        session_key_is_odd: false,
        expires_at: 2,
        granted_at: 1,
    })
}

fn close(n: u64, charge: u64, allowance: &[u8]) -> Record {
    Record::Close(Close { nullifier: Field::from(n), allowance_id: allowance.to_vec(), charge })
}

struct Verifier(bool, Rc<Cell<usize>>);
impl ProofVerifier for Verifier {
    fn verifies(&self, _: &[u8]) -> Result<bool, PortError> {
        self.1.set(self.1.get() + 1);
        Ok(self.0)
    }
}

struct TempFile(PathBuf);
impl TempFile {
    fn new(name: &str, records: &[Record]) -> Self {
        let path = std::env::temp_dir().join(format!("zk-evidence-{}-{name}", std::process::id()));
        let mut bytes = write_header();
        for r in records {
            bytes.extend(frame(&r.encode().unwrap()));
        }
        std::fs::write(&path, bytes).unwrap();
        Self(path)
    }
    fn append(&self, record: &Record) {
        let mut f = std::fs::OpenOptions::new().append(true).open(&self.0).unwrap();
        f.write_all(&frame(&record.encode().unwrap())).unwrap();
    }
}
impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn decide_over(file: &TempFile, verifies: bool, e: &Escape) -> Decision {
    let port = FileEvidence::new(&file.0, Verifier(verifies, Rc::default()));
    decide(e, &port, 0, &CFG).unwrap()
}

#[test]
fn evidence_at_the_next_nullifier_defeats() {
    let f = TempFile::new("defeat", &[grant(NEXT, 10, false, b"a")]);
    assert_eq!(decide_over(&f, true, &escape(0, 100)), Decision::Defeat);
    assert_eq!(decide_over(&f, false, &escape(0, 100)), Decision::Alarm(AlarmReason::EvidenceInvalid));
}

#[test]
fn a_close_record_raises_to_the_charge_capped_at_tier_and_balance() {
    let f = TempFile::new("charge", &[grant(ID, 10, false, b"a"), close(ID, 7, b"a")]);
    assert_eq!(decide_over(&f, true, &escape(2, 100)), Decision::Raise { to: 7 });
    assert_eq!(decide_over(&f, true, &escape(2, 4)), Decision::Raise { to: 4 });
    assert_eq!(decide_over(&f, true, &escape(7, 100)), Decision::NoOp);
}

#[test]
fn a_grant_with_no_close_record_raises_to_the_tier() {
    let f = TempFile::new("no-close", &[grant(ID, 10, false, b"a")]);
    assert_eq!(decide_over(&f, true, &escape(2, 100)), Decision::Raise { to: 10 });
    assert_eq!(decide_over(&f, true, &escape(2, 6)), Decision::Raise { to: 6 });
}

#[test]
fn subsidised_evidence_never_raises() {
    let f = TempFile::new("subsidised", &[grant(ID, 10, true, b"a")]);
    assert_eq!(decide_over(&f, true, &escape(0, 100)), Decision::NoOp);
    let f = TempFile::new("subsidised-closed", &[grant(ID, 10, true, b"a"), close(ID, 10, b"a")]);
    assert_eq!(decide_over(&f, true, &escape(0, 100)), Decision::NoOp);
}

#[test]
fn records_that_do_not_make_sense_give_evidence_invalid() {
    let invalid = Decision::Alarm(AlarmReason::EvidenceInvalid);
    let cases: Vec<(&str, Vec<Record>)> = vec![
        ("two-grants", vec![grant(ID, 10, false, b"a"), grant(ID, 10, false, b"b")]),
        ("orphan-close", vec![close(ID, 3, b"a")]),
        ("close-for-another-allowance", vec![grant(ID, 10, false, b"a"), close(ID, 3, b"b")]),
        ("two-closes", vec![grant(ID, 10, false, b"a"), close(ID, 3, b"a"), close(ID, 4, b"a")]),
        ("charge-above-tier", vec![grant(ID, 10, false, b"a"), close(ID, 11, b"a")]),
    ];
    for (name, records) in cases {
        let f = TempFile::new(name, &records);
        assert_eq!(decide_over(&f, true, &escape(0, 100)), invalid, "{name}");
    }
    // An orphan at the next nullifier raises the alarm too, rather than defeating.
    let f = TempFile::new("orphan-next", &[close(NEXT, 3, b"a")]);
    assert_eq!(decide_over(&f, true, &escape(0, 100)), invalid);
}

#[test]
fn one_nullifiers_bad_records_do_not_hide_anothers_evidence() {
    let f = TempFile::new("isolated", &[grant(ID, 10, false, b"a"), grant(ID, 10, false, b"b"), grant(NEXT, 10, false, b"c")]);
    let port = FileEvidence::new(&f.0, Verifier(true, Rc::default()));
    assert!(port.at_nullifier(&nullifier(NEXT)).unwrap().iter().all(|e| e.verifies));
    assert!(port.at_nullifier(&nullifier(ID)).unwrap().iter().all(|e| !e.verifies));
    assert!(port.at_nullifier(&nullifier(99)).unwrap().is_empty());
}

#[test]
fn a_record_that_does_not_decode_does_not_hide_the_rest_of_the_file() {
    let f = TempFile::new("undecodable", &[grant(ID, 10, false, b"a")]);
    let mut bytes = std::fs::read(&f.0).unwrap();
    bytes.extend(frame(&[9, 1, 2, 3]));
    let mut no_public_input = grant(NEXT, 10, false, b"c");
    if let Record::Grant(g) = &mut no_public_input {
        g.proof = b"{}".to_vec();
    }
    bytes.extend(frame(&no_public_input.encode().unwrap()));
    std::fs::write(&f.0, bytes).unwrap();
    f.append(&close(ID, 6, b"a"));
    assert_eq!(decide_over(&f, true, &escape(2, 100)), Decision::Raise { to: 6 });
}

#[test]
fn records_appended_after_the_port_opened_are_seen() {
    let f = TempFile::new("append", &[grant(ID, 10, false, b"a")]);
    let calls = Rc::new(Cell::new(0));
    let port = FileEvidence::new(&f.0, Verifier(true, calls.clone()));
    let e = escape(2, 100);
    assert_eq!(decide(&e, &port, 0, &CFG).unwrap(), Decision::Raise { to: 10 });
    f.append(&close(ID, 6, b"a"));
    assert_eq!(decide(&e, &port, 0, &CFG).unwrap(), Decision::Raise { to: 6 });
    f.append(&grant(NEXT, 10, false, b"c"));
    assert_eq!(decide(&e, &port, 0, &CFG).unwrap(), Decision::Defeat);
    // Each proof is verified once, however many times it is read.
    assert_eq!(calls.get(), 2);
}

#[test]
fn a_torn_tail_is_ignored_until_it_is_completed() {
    let f = TempFile::new("torn", &[grant(ID, 10, false, b"a")]);
    let whole = frame(&close(ID, 6, b"a").encode().unwrap());
    let mut file = std::fs::OpenOptions::new().append(true).open(&f.0).unwrap();
    file.write_all(&whole[..whole.len() - 3]).unwrap();
    let port = FileEvidence::new(&f.0, Verifier(true, Rc::default()));
    let e = escape(2, 100);
    assert_eq!(decide(&e, &port, 0, &CFG).unwrap(), Decision::Raise { to: 10 });
    file.write_all(&whole[whole.len() - 3..]).unwrap();
    assert_eq!(decide(&e, &port, 0, &CFG).unwrap(), Decision::Raise { to: 6 });
}

#[test]
fn an_unreadable_file_is_unavailable_not_empty() {
    let path = std::env::temp_dir().join(format!("zk-evidence-{}-missing", std::process::id()));
    let port = FileEvidence::new(&path, Verifier(true, Rc::default()));
    assert!(matches!(port.at_nullifier(&nullifier(ID)), Err(PortError::Unavailable(_))));

    let f = TempFile::new("corrupt", &[grant(ID, 10, false, b"a"), close(ID, 1, b"a")]);
    let mut bytes = std::fs::read(&f.0).unwrap();
    bytes[10 + 5] ^= 0xff;
    std::fs::write(&f.0, bytes).unwrap();
    let port = FileEvidence::new(&f.0, Verifier(true, Rc::default()));
    assert!(matches!(port.at_nullifier(&nullifier(ID)), Err(PortError::Unavailable(_))));
}
