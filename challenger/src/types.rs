use crate::ports::PortError;

/// A nullifier, 32 bytes.
pub type Nullifier = [u8; 32];

/// Milliseconds since the Unix epoch.
pub type Millis = u64;

/// An escape is identified by the current nullifier it consumed.
pub type EscapeId = Nullifier;

/// An open escape on the vault: its challenge window has not ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Escape {
    pub id: EscapeId,
    /// The next nullifier the escape consumed. A request proof here defeats the escape.
    pub next_nullifier: Nullifier,
    /// The amount conceded so far (the escape's own, or a raise).
    pub conceded: u64,
    /// The most the vault can pay this note.
    pub balance: u64,
    /// When the challenge window ends.
    pub deadline: Millis,
}

/// A request proof the zk edge recorded, as read through the evidence port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    /// The state's nullifier the proof was made at.
    pub nullifier: Nullifier,
    /// The tier `b` the allowance was opened at.
    pub tier: u64,
    /// What the state actually owed, from the close record. `None` when the allowance never
    /// closed, and the challenger claims the tier (ADR 0004).
    pub charge: Option<u64>,
    /// Whether the proof states it is subsidised.
    pub subsidised: bool,
    /// Whether the proof verifies against the published verification key.
    pub verifies: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Defeat,
    Raise { to: u64 },
    NoOp,
    Alarm(AlarmReason),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AlarmReason {
    /// Evidence for this escape does not verify. Nothing is submitted.
    EvidenceInvalid,
    /// The deadline is too close (or past) to act on safely.
    DeadlineTooClose { remaining: Millis },
}

/// An action the challenger submitted to the vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Defeat,
    Raise { to: u64 },
}

/// What the challenger saw or did, for the operator's audit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Report {
    Seen { escape: EscapeId },
    Submitted { escape: EscapeId, action: Action },
    SubmitFailed { escape: EscapeId, action: Action, error: PortError },
    /// The evidence port could not be read for this escape. Nothing was decided; retried next tick.
    EvidenceUnavailable { escape: EscapeId },
    Alarm { escape: EscapeId, reason: AlarmReason },
}
