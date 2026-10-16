use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use crate::ports::PortError;
use crate::types::*;

/// Durable record of every escape seen and every action submitted.
pub trait Journal {
    fn seen(&self) -> Result<Vec<EscapeId>, PortError>;
    fn submitted(&self) -> Result<Vec<(EscapeId, Action)>, PortError>;
    fn record_seen(&mut self, id: &EscapeId) -> Result<(), PortError>;
    fn record_submitted(&mut self, id: &EscapeId, action: &Action) -> Result<(), PortError>;
}

#[derive(Default, Clone)]
pub struct MemoryJournal {
    seen: Vec<EscapeId>,
    submitted: Vec<(EscapeId, Action)>,
}

impl Journal for MemoryJournal {
    fn seen(&self) -> Result<Vec<EscapeId>, PortError> {
        Ok(self.seen.clone())
    }
    fn submitted(&self) -> Result<Vec<(EscapeId, Action)>, PortError> {
        Ok(self.submitted.clone())
    }
    fn record_seen(&mut self, id: &EscapeId) -> Result<(), PortError> {
        self.seen.push(*id);
        Ok(())
    }
    fn record_submitted(&mut self, id: &EscapeId, action: &Action) -> Result<(), PortError> {
        self.submitted.push((*id, action.clone()));
        Ok(())
    }
}

/// An append-only line file: `seen <hex>`, `defeat <hex>`, `raise <hex> <amount>`.
pub struct FileJournal {
    path: PathBuf,
}

impl FileJournal {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, PortError> {
        let path = path.into();
        OpenOptions::new().create(true).append(true).open(&path).map_err(io)?;
        Ok(Self { path })
    }

    fn lines(&self) -> Result<Vec<String>, PortError> {
        let file = File::open(&self.path).map_err(io)?;
        BufReader::new(file).lines().collect::<Result<_, _>>().map_err(io)
    }

    fn append(&self, line: &str) -> Result<(), PortError> {
        let mut f = OpenOptions::new().append(true).open(&self.path).map_err(io)?;
        writeln!(f, "{line}").map_err(io)?;
        f.sync_all().map_err(io)
    }
}

fn io(e: std::io::Error) -> PortError {
    PortError::Unavailable(format!("journal: {e}"))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<EscapeId> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

impl Journal for FileJournal {
    fn seen(&self) -> Result<Vec<EscapeId>, PortError> {
        Ok(self
            .lines()?
            .iter()
            .filter_map(|l| l.strip_prefix("seen ").and_then(unhex))
            .collect())
    }
    fn submitted(&self) -> Result<Vec<(EscapeId, Action)>, PortError> {
        Ok(self
            .lines()?
            .iter()
            .filter_map(|l| {
                let mut p = l.split(' ');
                match p.next()? {
                    "defeat" => Some((unhex(p.next()?)?, Action::Defeat)),
                    "raise" => Some((unhex(p.next()?)?, Action::Raise { to: p.next()?.parse().ok()? })),
                    _ => None,
                }
            })
            .collect())
    }
    fn record_seen(&mut self, id: &EscapeId) -> Result<(), PortError> {
        self.append(&format!("seen {}", hex(id)))
    }
    fn record_submitted(&mut self, id: &EscapeId, action: &Action) -> Result<(), PortError> {
        match action {
            Action::Defeat => self.append(&format!("defeat {}", hex(id))),
            Action::Raise { to } => self.append(&format!("raise {} {to}", hex(id))),
        }
    }
}
