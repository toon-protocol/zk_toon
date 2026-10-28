//! The evidence file's byte format (GLOSSARY.md → Evidence, ADR 0004), pinned by
//! `test-vectors/zk-evidence.json`. The connector writes with this crate and the challenger reads
//! with it. Nothing here does file I/O: it works over byte slices.
//!
//! A file is a header (`TOONZKEV`, then a `u16` LE format version) and records. Each record is
//! `u32 LE payload length ‖ payload ‖ CRC32C(payload)`. A payload starts with a kind byte: `1` for
//! a grant record, `2` for a close record.

pub mod file;
pub mod record;

pub use file::{frame, read_header, scan, scan_records, write_header, FileError, Framed, Scan, MAGIC, VERSION};
pub use record::{
    evidence_hash, field_from_bytes, field_to_bytes, Close, DecodeError, Grant, Record, MAX_ALLOWANCE_ID,
};
