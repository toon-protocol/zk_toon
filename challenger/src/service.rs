//! The challenger as a service: [`serve`] runs one [`pass`] per interval, each logged as lines.
//!
//! A line names an escape only by its nullifier, which the vault's escape already made public, and
//! says what was seen or done. A pass never stops the service: a chain or journal that can't be read
//! is logged, and the next pass reads everything afresh.

use crate::core::Challenger;
use crate::journal::{hex, Journal};
use crate::ports::{EvidencePort, PortError, VaultChainPort};
use crate::types::*;

/// Runs passes, each at the chain time as read then, writing their lines to `out`. After each pass it
/// asks `stop` whether to stop, and returns its reason if so; otherwise it calls `wait` and runs
/// the next. Nothing a pass meets stops it: that is `stop`'s to decide.
pub fn serve<C: VaultChainPort, E: EvidencePort, J: Journal>(
    challenger: &mut Challenger<C, E, J>,
    mut stop: impl FnMut() -> Option<String>,
    mut wait: impl FnMut(),
    mut out: impl FnMut(&str),
) -> String {
    loop {
        let now = challenger.chain.now();
        for line in pass(challenger, now) {
            out(&line);
        }
        if let Some(why) = stop() {
            return why;
        }
        wait();
    }
}

/// Ticks `challenger` at `now`, the chain time as read, and returns what happened as log lines.
pub fn pass<C: VaultChainPort, E: EvidencePort, J: Journal>(
    challenger: &mut Challenger<C, E, J>,
    now: Result<Slot, PortError>,
) -> Vec<String> {
    match now.and_then(|now| challenger.tick(now)) {
        Ok(reports) => reports.iter().map(line).collect(),
        Err(e) => vec![error(&e)],
    }
}

fn line(report: &Report) -> String {
    match report {
        Report::Seen { escape } => format!("seen {}", hex(escape)),
        Report::Submitted { escape, action } => format!("submitted {} {}", hex(escape), act(action)),
        Report::SubmitFailed { escape, action, error: e } => {
            format!("submit-failed {} {}: {}", hex(escape), act(action), error(e))
        }
        Report::EvidenceUnavailable { escape } => format!("evidence-unavailable {}", hex(escape)),
        Report::Alarm { escape, reason: AlarmReason::EvidenceInvalid } => {
            format!("alarm {} evidence-invalid", hex(escape))
        }
        Report::Alarm { escape, reason: AlarmReason::DeadlineTooClose { remaining } } => {
            format!("alarm {} deadline-too-close {remaining}", hex(escape))
        }
    }
}

fn act(action: &Action) -> String {
    match action {
        Action::Defeat => "defeat".into(),
        Action::Raise { to } => format!("raise {to}"),
    }
}

fn error(e: &PortError) -> String {
    match e {
        PortError::Refused(m) => format!("refused: {m}"),
        PortError::Unavailable(m) => format!("unavailable: {m}"),
    }
}
