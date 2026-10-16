use crate::types::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortError {
    /// The vault refused the submission, with its reason.
    Refused(String),
    /// The backend could not be reached or answered badly. Retry later.
    Unavailable(String),
}

/// The challenger's view of the vault chain.
pub trait VaultChainPort {
    /// Open escapes (challenge window not ended, not defeated), with their current concession and
    /// deadline.
    fn escapes(&self) -> Result<Vec<Escape>, PortError>;
    /// Defeat an open escape. Refused for an unknown or closed escape.
    fn submit_defeat(&mut self, id: &EscapeId) -> Result<(), PortError>;
    /// Raise an open escape's concession to `to`. Refused unless `to` exceeds the current
    /// concession and is within the escape's balance, or for an unknown or closed escape.
    fn submit_raise(&mut self, id: &EscapeId, to: u64) -> Result<(), PortError>;
}

/// The zk edge's recorded request proofs.
pub trait EvidencePort {
    /// Every recorded request proof at `nullifier`.
    fn at_nullifier(&self, nullifier: &Nullifier) -> Result<Vec<Evidence>, PortError>;
}
