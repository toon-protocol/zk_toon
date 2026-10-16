use std::collections::HashSet;

use crate::journal::Journal;
use crate::ports::{EvidencePort, PortError, VaultChainPort};
use crate::types::*;

#[derive(Clone, Debug)]
pub struct Config {
    /// The least time before a deadline at which the challenger still submits. It leaves room for
    /// Mina's inclusion time.
    pub min_lead: Millis,
}

/// Decide what to do about one escape.
///
/// A subsidised proof can defeat but never raise (ADR 0001). A proof that does not verify yields
/// an alarm and no submission.
pub fn decide(escape: &Escape, evidence: &dyn EvidencePort, now: Millis, cfg: &Config) -> Result<Decision, PortError> {
    Ok(within_deadline(escape, from_evidence(escape, evidence)?, now, cfg))
}

/// What the evidence calls for, before the deadline is considered.
fn from_evidence(escape: &Escape, evidence: &dyn EvidencePort) -> Result<Decision, PortError> {
    let next = evidence.at_nullifier(&escape.next_nullifier)?;
    let current = evidence.at_nullifier(&escape.id)?;
    if next.iter().chain(current.iter()).any(|e| !e.verifies) {
        return Ok(Decision::Alarm(AlarmReason::EvidenceInvalid));
    }
    if !next.is_empty() {
        return Ok(Decision::Defeat);
    }
    let raise_to = current
        .iter()
        .filter(|e| !e.subsidised)
        .map(|e| e.charge.min(e.tier).min(escape.balance))
        .filter(|to| *to > escape.conceded)
        .max();
    Ok(raise_to.map_or(Decision::NoOp, |to| Decision::Raise { to }))
}

/// Turn a submission into an alarm when the deadline is too close to act on safely.
fn within_deadline(escape: &Escape, decision: Decision, now: Millis, cfg: &Config) -> Decision {
    if !matches!(decision, Decision::Defeat | Decision::Raise { .. }) {
        return decision;
    }
    let remaining = escape.deadline.saturating_sub(now);
    if now >= escape.deadline || remaining < cfg.min_lead {
        return Decision::Alarm(AlarmReason::DeadlineTooClose { remaining });
    }
    decision
}

pub struct Challenger<C, E, J> {
    pub chain: C,
    pub evidence: E,
    pub journal: J,
    pub config: Config,
}

impl<C: VaultChainPort, E: EvidencePort, J: Journal> Challenger<C, E, J> {
    pub fn new(chain: C, evidence: E, journal: J, config: Config) -> Self {
        Self { chain, evidence, journal, config }
    }

    /// One pass over the vault's open escapes. Safe to call repeatedly and after a restart: an
    /// action already journalled as submitted is not repeated, and every open escape is read
    /// afresh from the chain, so none is missed.
    pub fn tick(&mut self, now: Millis) -> Result<Vec<Report>, PortError> {
        let escapes = self.chain.escapes()?;
        let mut seen: HashSet<EscapeId> = self.journal.seen()?.into_iter().collect();
        let mut done = self.journal.submitted()?;
        let mut reports = Vec::new();
        for escape in escapes {
            if seen.insert(escape.id) {
                self.journal.record_seen(&escape.id)?;
                reports.push(Report::Seen { escape: escape.id });
            }
            // An action already submitted is not repeated, nor alarmed on as its deadline nears.
            let decision = match from_evidence(&escape, &self.evidence) {
                Ok(d) => d,
                Err(PortError::Unavailable(_)) => {
                    reports.push(Report::EvidenceUnavailable { escape: escape.id });
                    continue;
                }
                Err(e) => return Err(e),
            };
            if let Some(action) = as_action(&decision) {
                if done.iter().any(|(id, a)| *id == escape.id && *a == action) {
                    continue;
                }
            }
            let action = match within_deadline(&escape, decision, now, &self.config) {
                Decision::NoOp => continue,
                Decision::Alarm(reason) => {
                    reports.push(Report::Alarm { escape: escape.id, reason });
                    continue;
                }
                Decision::Defeat => Action::Defeat,
                Decision::Raise { to } => Action::Raise { to },
            };
            let sent = match action {
                Action::Defeat => self.chain.submit_defeat(&escape.id),
                Action::Raise { to } => self.chain.submit_raise(&escape.id, to),
            };
            match sent {
                Ok(()) => {
                    self.journal.record_submitted(&escape.id, &action)?;
                    done.push((escape.id, action.clone()));
                    reports.push(Report::Submitted { escape: escape.id, action });
                }
                Err(error) => reports.push(Report::SubmitFailed { escape: escape.id, action, error }),
            }
        }
        Ok(reports)
    }
}

fn as_action(decision: &Decision) -> Option<Action> {
    match decision {
        Decision::Defeat => Some(Action::Defeat),
        Decision::Raise { to } => Some(Action::Raise { to: *to }),
        Decision::NoOp | Decision::Alarm(_) => None,
    }
}
