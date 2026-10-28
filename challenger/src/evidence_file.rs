//! An [`EvidencePort`] over the zk edge's evidence file (see the `zk-evidence` crate).
//!
//! The file is scanned once at the first read and indexed by nullifier. Each later read picks up
//! the records appended since, resuming after the last intact record, so a record that was torn
//! when first seen is read once it is complete. Whether a proof verifies is the injected
//! [`ProofVerifier`]'s answer.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

use zk_evidence::{evidence_hash, field_to_bytes, read_header, scan_records, Close, FileError, Grant, Record};

use crate::ports::{EvidencePort, PortError};
use crate::types::{Evidence, Nullifier};

/// Checks a request proof against the published verification key.
pub trait ProofVerifier {
    /// `proof` is the o1js `JsonProof` as UTF-8 bytes. `Err` means the verifier could not answer.
    fn verifies(&self, proof: &[u8]) -> Result<bool, PortError>;
}

struct GrantEntry {
    grant: Grant,
    tier: u64,
    subsidised: bool,
    hash: [u8; 32],
}

#[derive(Default)]
struct Slot {
    grants: Vec<GrantEntry>,
    closes: Vec<Close>,
}

#[derive(Default)]
struct Index {
    /// Whether the header has been read.
    opened: bool,
    /// How much of the file has been read: the end of its last intact record.
    consumed: u64,
    by_nullifier: HashMap<Nullifier, Slot>,
}

/// The evidence file at `path`, read through `verifier`.
pub struct FileEvidence<V> {
    path: PathBuf,
    verifier: V,
    index: RefCell<Index>,
    verified: RefCell<HashMap<[u8; 32], bool>>,
}

impl<V: ProofVerifier> FileEvidence<V> {
    /// Nothing is read until the first [`EvidencePort::at_nullifier`].
    pub fn new(path: impl Into<PathBuf>, verifier: V) -> Self {
        Self { path: path.into(), verifier, index: RefCell::default(), verified: RefCell::default() }
    }

    /// Read what was appended since the last refresh.
    fn refresh(&self) -> Result<(), PortError> {
        let unavailable = |what: &str| PortError::Unavailable(format!("evidence file: {what}"));
        let mut file = File::open(&self.path).map_err(|e| unavailable(&e.to_string()))?;
        let mut index = self.index.borrow_mut();
        let start = if index.opened { index.consumed } else { 0 };
        file.seek(SeekFrom::Start(start)).map_err(|e| unavailable(&e.to_string()))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|e| unavailable(&e.to_string()))?;

        let from = if index.opened { 0 } else { read_header(&bytes).map_err(|e| unavailable(&format!("{e:?}")))? };
        let scan = scan_records(&bytes, from).map_err(|e| match e {
            FileError::Corrupt { offset } => unavailable(&format!("corrupt record at byte {}", start + offset as u64)),
            other => unavailable(&format!("{other:?}")),
        })?;
        // A record whose CRC holds but which does not decode names no nullifier it could be
        // evidence at, so it is skipped rather than stopping the rest of the file being read.
        for framed in &scan.records {
            match Record::decode(framed.payload) {
                Ok(Record::Grant(grant)) => {
                    let Ok(public) = grant.request_public() else { continue };
                    let hash = evidence_hash(framed.payload);
                    let slot = index.by_nullifier.entry(field_to_bytes(public.nullifier)).or_default();
                    slot.grants.push(GrantEntry { grant, tier: public.tier, subsidised: public.subsidised, hash });
                }
                Ok(Record::Close(close)) => {
                    index.by_nullifier.entry(field_to_bytes(close.nullifier)).or_default().closes.push(close);
                }
                Err(_) => continue,
            }
        }
        index.consumed = start + scan.valid_len as u64;
        index.opened = true;
        Ok(())
    }

    fn verifies(&self, entry: &GrantEntry) -> Result<bool, PortError> {
        if let Some(v) = self.verified.borrow().get(&entry.hash) {
            return Ok(*v);
        }
        let v = self.verifier.verifies(&entry.grant.proof)?;
        self.verified.borrow_mut().insert(entry.hash, v);
        Ok(v)
    }
}

impl<V: ProofVerifier> EvidencePort for FileEvidence<V> {
    /// One [`Evidence`] per grant record at `nullifier`. When the records there don't make sense
    /// (two grants, a close with no grant or a second close, a charge above the tier) the evidence
    /// reads as not verifying, so the challenger alarms with `EvidenceInvalid`.
    fn at_nullifier(&self, nullifier: &Nullifier) -> Result<Vec<Evidence>, PortError> {
        self.refresh()?;
        let index = self.index.borrow();
        let Some(slot) = index.by_nullifier.get(nullifier) else { return Ok(Vec::new()) };

        let invalid = |tier: u64, subsidised: bool| Evidence {
            nullifier: *nullifier,
            tier,
            charge: None,
            subsidised,
            verifies: false,
        };
        let [entry] = slot.grants.as_slice() else {
            return Ok(match slot.grants.first() {
                Some(g) => vec![invalid(g.tier, g.subsidised)],
                None => vec![invalid(0, false)],
            });
        };
        let matching: Vec<&Close> = slot.closes.iter().filter(|c| c.allowance_id == entry.grant.allowance_id).collect();
        if matching.len() != slot.closes.len() || matching.len() > 1 || matching.iter().any(|c| c.charge > entry.tier) {
            return Ok(vec![invalid(entry.tier, entry.subsidised)]);
        }
        Ok(vec![Evidence {
            nullifier: *nullifier,
            tier: entry.tier,
            charge: matching.first().map(|c| c.charge),
            subsidised: entry.subsidised,
            verifies: self.verifies(entry)?,
        }])
    }
}
