//! The running hash, the signed checkpoint and the push: how evidence bytes reach a challenger on
//! another host and how it knows they came from the zk edge (ADR 0014). Pure functions over byte
//! slices; nothing here listens, connects or writes.
//!
//! # Running hash
//!
//! `h_0` is 32 zero bytes and `h_n = SHA-256(h_{n-1} ‖ evidence_hash(record_n))` over the records in
//! file order. The header is not a record.
//!
//! # Checkpoint
//!
//! The vault (a compressed public key), a length (the file's length in bytes, header included) and
//! the running hash of every record within that length. The state key signs six field elements:
//!
//! ```text
//! [evidenceCheckpointTag, vault.x, vault.isOdd, length, hash.hi, hash.lo]
//! ```
//!
//! `hash.hi` and `hash.lo` are the first and last 16 bytes of the running hash, each read big-endian.
//! The signature is Mina Schnorr with the chunked nonce, as for a clearance; the network ID is an
//! argument, and the zk edge and challengers use the devnet one.
//!
//! # Push
//!
//! `u64 LE offset ‖ u32 LE byte count ‖ bytes ‖ r (32 bytes LE) ‖ s (32 bytes LE)`. `bytes` are whole
//! framed records that extend a file of length `offset`, and the signature signs the checkpoint at
//! `offset + bytes.len()`. Decoding refuses truncated and trailing input.

use mina_signer::{CompressedPubKey, Keypair, NetworkId, PubKey, Signature};
use sha2::{Digest, Sha256};
use zk_note::balance::Scalar;
use zk_note::state::{sign_fields, verify_fields};
use zk_note::{tag_to_field, tags, Field};

use crate::file::{scan, scan_records, write_header, FileError};
use crate::record::{evidence_hash, field_from_bytes, field_to_bytes, DecodeError, Record};

/// The running hash of a file with no records.
pub const EMPTY_RUNNING_HASH: [u8; 32] = [0; 32];

/// `h_n` from `h_{n-1}` and the payload of record `n`.
pub fn extend_running_hash(prev: &[u8; 32], payload: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(prev);
    h.update(evidence_hash(payload));
    h.finalize().into()
}

/// The running hash over the payloads of `records`, in order.
pub fn running_hash<'a>(records: impl IntoIterator<Item = &'a [u8]>) -> [u8; 32] {
    records.into_iter().fold(EMPTY_RUNNING_HASH, |h, p| extend_running_hash(&h, p))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub vault: CompressedPubKey,
    /// The evidence file's length in bytes, header included.
    pub length: u64,
    pub running_hash: [u8; 32],
}

impl Checkpoint {
    /// The field elements that are signed.
    pub fn to_fields(&self) -> Vec<Field> {
        let half = |b: &[u8]| Field::from(u128::from_be_bytes(b.try_into().unwrap()));
        vec![
            tag_to_field(tags::EVIDENCE_CHECKPOINT),
            self.vault.x,
            Field::from(self.vault.is_odd as u64),
            Field::from(self.length),
            half(&self.running_hash[..16]),
            half(&self.running_hash[16..]),
        ]
    }

    pub fn sign(&self, network: NetworkId, state_keypair: &Keypair) -> Signature {
        sign_fields(network, state_keypair, self.to_fields())
    }

    pub fn verify(&self, network: NetworkId, state_key: &PubKey, sig: &Signature) -> bool {
        verify_fields(network, sig, state_key, self.to_fields())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Push {
    /// The length of the file these bytes extend.
    pub offset: u64,
    /// Whole framed records.
    pub bytes: Vec<u8>,
    /// Signs the checkpoint at `offset + bytes.len()`.
    pub signature: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PushDecodeError {
    Truncated,
    TrailingBytes,
    /// A signature part at or above its modulus.
    NonCanonicalSignature,
}

impl Push {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.bytes.len() + 76);
        out.extend_from_slice(&self.offset.to_le_bytes());
        out.extend_from_slice(&(self.bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.bytes);
        out.extend_from_slice(&field_to_bytes(self.signature.rx));
        out.extend_from_slice(&scalar_to_bytes(self.signature.s));
        out
    }

    pub fn decode(input: &[u8]) -> Result<Self, PushDecodeError> {
        use PushDecodeError::*;
        let mut at = 0usize;
        let mut take = |n: usize| -> Result<&[u8], PushDecodeError> {
            let end = at.checked_add(n).filter(|e| *e <= input.len()).ok_or(Truncated)?;
            let s = &input[at..end];
            at = end;
            Ok(s)
        };
        let offset = u64::from_le_bytes(take(8)?.try_into().unwrap());
        let len = u32::from_le_bytes(take(4)?.try_into().unwrap()) as usize;
        let bytes = take(len)?.to_vec();
        let r = field_from_bytes(take(32)?.try_into().unwrap()).map_err(|_| NonCanonicalSignature)?;
        let s = scalar_from_bytes(take(32)?.try_into().unwrap()).ok_or(NonCanonicalSignature)?;
        if at != input.len() {
            return Err(TrailingBytes);
        }
        Ok(Push { offset, bytes, signature: Signature::new(r, s) })
    }
}

fn scalar_to_bytes(s: Scalar) -> [u8; 32] {
    use ark_ff::{BigInteger, PrimeField};
    let mut out = [0u8; 32];
    out.copy_from_slice(&s.into_bigint().to_bytes_le());
    out
}

fn scalar_from_bytes(b: &[u8; 32]) -> Option<Scalar> {
    use ark_ff::PrimeField;
    let s = Scalar::from_le_bytes_mod_order(b);
    (&scalar_to_bytes(s) == b).then_some(s)
}

/// The evidence file a challenger holds: its length and running hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileCopy {
    pub length: u64,
    pub running_hash: [u8; 32],
}

impl FileCopy {
    /// The copy of a file that holds only its header.
    pub fn empty() -> Self {
        FileCopy { length: write_header().len() as u64, running_hash: EMPTY_RUNNING_HASH }
    }

    /// The copy of whole file bytes. A torn tail is not part of a copy: it is refused.
    pub fn of_file(file: &[u8]) -> Result<Self, PushRefusal> {
        let scan = scan(file).map_err(PushRefusal::BadCopy)?;
        if scan.torn_tail {
            return Err(PushRefusal::BadCopy(FileError::Corrupt { offset: scan.valid_len }));
        }
        Ok(FileCopy {
            length: file.len() as u64,
            running_hash: running_hash(scan.records.iter().map(|r| r.payload)),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PushRefusal {
    /// The copy the push was checked against is not a whole file.
    BadCopy(FileError),
    /// The push's offset is not the copy's length.
    WrongOffset { copy_length: u64, offset: u64 },
    /// The push carries no records.
    Empty,
    /// The bytes are not whole intact records: a torn tail, or a corrupt record.
    NotWholeRecords,
    /// A record's payload does not decode.
    BadRecord(DecodeError),
    /// The signature does not verify over the checkpoint the extended copy would have.
    BadSignature,
}

/// Check a push against the copy a challenger holds. On success, returns the extended copy.
pub fn check_push(
    network: NetworkId,
    state_key: &PubKey,
    vault: &CompressedPubKey,
    copy: &FileCopy,
    push: &Push,
) -> Result<FileCopy, PushRefusal> {
    if push.offset != copy.length {
        return Err(PushRefusal::WrongOffset { copy_length: copy.length, offset: push.offset });
    }
    if push.bytes.is_empty() {
        return Err(PushRefusal::Empty);
    }
    let scan = scan_records(&push.bytes, 0).map_err(|_| PushRefusal::NotWholeRecords)?;
    if scan.torn_tail {
        return Err(PushRefusal::NotWholeRecords);
    }
    for r in &scan.records {
        Record::decode(r.payload).map_err(PushRefusal::BadRecord)?;
    }
    let extended = FileCopy {
        length: copy.length + push.bytes.len() as u64,
        running_hash: scan.records.iter().fold(copy.running_hash, |h, r| extend_running_hash(&h, r.payload)),
    };
    let checkpoint = Checkpoint { vault: vault.clone(), length: extended.length, running_hash: extended.running_hash };
    if !checkpoint.verify(network, state_key, &push.signature) {
        return Err(PushRefusal::BadSignature);
    }
    Ok(extended)
}
