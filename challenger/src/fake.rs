//! In-memory fakes of both ports.

use std::collections::HashMap;
use std::{cell::RefCell, rc::Rc};

use crate::ports::*;
use crate::types::*;

/// A fake vault chain. Clones share state, so a test can keep a handle while the challenger owns
/// another (and "restart" by building a new challenger over the same chain).
#[derive(Clone, Default)]
pub struct FakeChain {
    inner: Rc<RefCell<ChainState>>,
}

#[derive(Default)]
struct ChainState {
    now: Millis,
    escapes: Vec<Escape>,
    unavailable: bool,
    /// Every accepted submission, in order.
    log: Vec<(EscapeId, Action)>,
}

impl FakeChain {
    pub fn new(now: Millis, escapes: Vec<Escape>) -> Self {
        let c = Self::default();
        {
            let mut s = c.inner.borrow_mut();
            s.now = now;
            s.escapes = escapes;
        }
        c
    }
    pub fn set_now(&self, now: Millis) {
        self.inner.borrow_mut().now = now;
    }
    pub fn add_escape(&self, e: Escape) {
        self.inner.borrow_mut().escapes.push(e);
    }
    pub fn set_unavailable(&self, v: bool) {
        self.inner.borrow_mut().unavailable = v;
    }
    pub fn submissions(&self) -> Vec<(EscapeId, Action)> {
        self.inner.borrow().log.clone()
    }
}

impl VaultChainPort for FakeChain {
    fn escapes(&self) -> Result<Vec<Escape>, PortError> {
        let s = self.inner.borrow();
        if s.unavailable {
            return Err(PortError::Unavailable("fake chain down".into()));
        }
        Ok(s.escapes.iter().filter(|e| e.deadline > s.now).cloned().collect())
    }

    fn submit_defeat(&mut self, id: &EscapeId) -> Result<(), PortError> {
        let mut s = self.inner.borrow_mut();
        if s.unavailable {
            return Err(PortError::Unavailable("fake chain down".into()));
        }
        let now = s.now;
        let pos = s.escapes.iter().position(|e| e.id == *id && e.deadline > now);
        let Some(pos) = pos else { return Err(PortError::Refused("no open escape".into())) };
        s.escapes.remove(pos);
        s.log.push((*id, Action::Defeat));
        Ok(())
    }

    fn submit_raise(&mut self, id: &EscapeId, to: u64) -> Result<(), PortError> {
        let mut s = self.inner.borrow_mut();
        if s.unavailable {
            return Err(PortError::Unavailable("fake chain down".into()));
        }
        let now = s.now;
        let Some(e) = s.escapes.iter_mut().find(|e| e.id == *id && e.deadline > now) else {
            return Err(PortError::Refused("no open escape".into()));
        };
        if to <= e.conceded || to > e.balance {
            return Err(PortError::Refused("raise out of range".into()));
        }
        e.conceded = to;
        s.log.push((*id, Action::Raise { to }));
        Ok(())
    }
}

/// A fake evidence store.
#[derive(Clone, Default)]
pub struct FakeEvidence {
    by_nullifier: HashMap<Nullifier, Vec<Evidence>>,
}

impl FakeEvidence {
    pub fn with(mut self, e: Evidence) -> Self {
        self.by_nullifier.entry(e.nullifier).or_default().push(e);
        self
    }
}

impl EvidencePort for FakeEvidence {
    fn at_nullifier(&self, n: &Nullifier) -> Result<Vec<Evidence>, PortError> {
        Ok(self.by_nullifier.get(n).cloned().unwrap_or_default())
    }
}
