//! Grant and close records: their payload bytes and the evidence hash.

use ark_ff::{BigInteger, PrimeField};
use sha2::{Digest, Sha256};
use zk_note::request::{RequestPublic, RequestPublicError};
use zk_note::Field;

/// The longest allowance id, in bytes.
pub const MAX_ALLOWANCE_ID: usize = 64;

const KIND_GRANT: u8 = 1;
const KIND_CLOSE: u8 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The payload ended before a field did.
    Truncated,
    /// Bytes remain after the last field.
    TrailingBytes,
    UnknownKind(u8),
    /// A field element's bytes are not the canonical encoding (they are at or above the modulus).
    NonCanonicalField,
    /// A flag byte is neither 0 nor 1.
    BadFlag,
    /// An allowance id longer than [`MAX_ALLOWANCE_ID`].
    AllowanceIdTooLong(usize),
    /// A grant's proof is not an o1js `JsonProof` with a decodable `publicInput`.
    BadProof(String),
}

/// A Pallas field element as 32 bytes, little-endian and canonical.
pub fn field_to_bytes(f: Field) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&f.into_bigint().to_bytes_le());
    out
}

/// The inverse of [`field_to_bytes`]; refuses a value at or above the modulus.
pub fn field_from_bytes(bytes: &[u8; 32]) -> Result<Field, DecodeError> {
    let f = Field::from_le_bytes_mod_order(bytes);
    if &field_to_bytes(f) == bytes {
        Ok(f)
    } else {
        Err(DecodeError::NonCanonicalField)
    }
}

/// SHA-256 over a record's payload bytes, without the length prefix or the CRC.
pub fn evidence_hash(payload: &[u8]) -> [u8; 32] {
    Sha256::digest(payload).into()
}

/// A grant record: written and fsynced before an allowance is granted. It holds no secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// The request proof as o1js `JsonProof` UTF-8 bytes, verbatim.
    pub proof: Vec<u8>,
    /// Opaque, at most [`MAX_ALLOWANCE_ID`] bytes; kept for audit only.
    pub allowance_id: Vec<u8>,
    /// The session public key: x coordinate and whether y is odd.
    pub session_key_x: Field,
    pub session_key_is_odd: bool,
    /// When the allowance expires, in milliseconds.
    pub expires_at: u64,
    /// When the allowance was granted, in milliseconds.
    pub granted_at: u64,
}

impl Grant {
    /// The proof's public inputs: the tier, nullifier and subsidised flag come from here.
    pub fn request_public(&self) -> Result<RequestPublic, DecodeError> {
        let bad = |m: String| DecodeError::BadProof(m);
        let json: serde_json::Value = serde_json::from_slice(&self.proof).map_err(|e| bad(e.to_string()))?;
        let input = json["publicInput"].as_array().ok_or_else(|| bad("no publicInput array".into()))?;
        let fields = input
            .iter()
            .map(|v| {
                let s = v.as_str().ok_or_else(|| bad("publicInput entry is not a string".into()))?;
                s.parse::<Field>().map_err(|_| bad(format!("publicInput entry {s:?} is not a field")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        RequestPublic::from_fields(&fields).map_err(|e: RequestPublicError| bad(format!("{e:?}")))
    }
}

/// A close record: written and fsynced before the zk edge releases the signed next state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Close {
    /// The nullifier of the state the allowance was granted at.
    pub nullifier: Field,
    pub allowance_id: Vec<u8>,
    /// What the state actually owed.
    pub charge: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    Grant(Grant),
    Close(Close),
}

fn put_id(out: &mut Vec<u8>, id: &[u8]) -> Result<(), DecodeError> {
    if id.len() > MAX_ALLOWANCE_ID {
        return Err(DecodeError::AllowanceIdTooLong(id.len()));
    }
    out.push(id.len() as u8);
    out.extend_from_slice(id);
    Ok(())
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.0.len() < n {
            return Err(DecodeError::Truncated);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn field(&mut self) -> Result<Field, DecodeError> {
        field_from_bytes(self.take(32)?.try_into().unwrap())
    }
    fn flag(&mut self) -> Result<bool, DecodeError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(DecodeError::BadFlag),
        }
    }
    fn id(&mut self) -> Result<Vec<u8>, DecodeError> {
        let n = self.u8()? as usize;
        if n > MAX_ALLOWANCE_ID {
            return Err(DecodeError::AllowanceIdTooLong(n));
        }
        Ok(self.take(n)?.to_vec())
    }
}

impl Record {
    /// The payload bytes: what the evidence hash covers and what framing wraps.
    pub fn encode(&self) -> Result<Vec<u8>, DecodeError> {
        let mut out = Vec::new();
        match self {
            Record::Grant(g) => {
                out.push(KIND_GRANT);
                out.extend_from_slice(&(g.proof.len() as u32).to_le_bytes());
                out.extend_from_slice(&g.proof);
                put_id(&mut out, &g.allowance_id)?;
                out.extend_from_slice(&field_to_bytes(g.session_key_x));
                out.push(g.session_key_is_odd as u8);
                out.extend_from_slice(&g.expires_at.to_le_bytes());
                out.extend_from_slice(&g.granted_at.to_le_bytes());
            }
            Record::Close(c) => {
                out.push(KIND_CLOSE);
                out.extend_from_slice(&field_to_bytes(c.nullifier));
                put_id(&mut out, &c.allowance_id)?;
                out.extend_from_slice(&c.charge.to_le_bytes());
            }
        }
        Ok(out)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader(payload);
        let record = match r.u8()? {
            KIND_GRANT => {
                let len = r.u32()? as usize;
                Record::Grant(Grant {
                    proof: r.take(len)?.to_vec(),
                    allowance_id: r.id()?,
                    session_key_x: r.field()?,
                    session_key_is_odd: r.flag()?,
                    expires_at: r.u64()?,
                    granted_at: r.u64()?,
                })
            }
            KIND_CLOSE => Record::Close(Close { nullifier: r.field()?, allowance_id: r.id()?, charge: r.u64()? }),
            k => return Err(DecodeError::UnknownKind(k)),
        };
        if !r.0.is_empty() {
            return Err(DecodeError::TrailingBytes);
        }
        Ok(record)
    }
}
