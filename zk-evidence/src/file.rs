//! The file header and record framing, over byte slices.

/// The first eight bytes of an evidence file.
pub const MAGIC: &[u8; 8] = b"TOONZKEV";
/// The format version this crate reads and writes.
pub const VERSION: u16 = 1;

const HEADER_LEN: usize = MAGIC.len() + 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileError {
    /// The file is shorter than the header.
    TruncatedHeader,
    BadMagic,
    /// A format version this reader does not know.
    UnsupportedVersion(u16),
    /// A record that is not at the end of the file fails its CRC32C. `offset` is where it starts.
    Corrupt { offset: usize },
}

/// The header of a new file.
pub fn write_header() -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&VERSION.to_le_bytes());
    out
}

/// Check the header and return the offset of the first record.
pub fn read_header(file: &[u8]) -> Result<usize, FileError> {
    if file.len() < HEADER_LEN {
        return Err(FileError::TruncatedHeader);
    }
    if &file[..MAGIC.len()] != MAGIC {
        return Err(FileError::BadMagic);
    }
    let version = u16::from_le_bytes([file[MAGIC.len()], file[MAGIC.len() + 1]]);
    if version != VERSION {
        return Err(FileError::UnsupportedVersion(version));
    }
    Ok(HEADER_LEN)
}

/// Wrap a payload as `u32 LE length ‖ payload ‖ CRC32C(payload)`.
pub fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 8);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(&crc32c::crc32c(payload).to_le_bytes());
    out
}

/// One intact record found by a scan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Framed<'a> {
    /// Where the record starts, counted from the start of the slice that was scanned.
    pub offset: usize,
    pub payload: &'a [u8],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scan<'a> {
    pub records: Vec<Framed<'a>>,
    /// The length of the intact prefix. A writer cuts the file off here before appending, and a
    /// reader that wants records appended later resumes from here.
    pub valid_len: usize,
    /// Whether a torn write follows the intact prefix.
    pub torn_tail: bool,
}

/// Scan a whole file: check its header, then its records.
pub fn scan(file: &[u8]) -> Result<Scan<'_>, FileError> {
    scan_records(file, read_header(file)?)
}

/// Scan the records of `file` from `start`. A short or CRC-failing record at the end is a torn
/// write: it is left out and reported as `torn_tail`. A CRC failure anywhere else is
/// [`FileError::Corrupt`].
pub fn scan_records(file: &[u8], start: usize) -> Result<Scan<'_>, FileError> {
    let mut records = Vec::new();
    let mut at = start;
    let mut torn_tail = false;
    while at < file.len() {
        let Some(len) = file.get(at..at + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize) else {
            torn_tail = true;
            break;
        };
        let end = at.saturating_add(4).saturating_add(len).saturating_add(4);
        if end > file.len() {
            torn_tail = true;
            break;
        }
        let payload = &file[at + 4..at + 4 + len];
        let crc = u32::from_le_bytes(file[at + 4 + len..end].try_into().unwrap());
        if crc != crc32c::crc32c(payload) {
            if end == file.len() {
                torn_tail = true;
                break;
            }
            return Err(FileError::Corrupt { offset: at });
        }
        records.push(Framed { offset: at, payload });
        at = end;
    }
    Ok(Scan { records, valid_len: at, torn_tail })
}
