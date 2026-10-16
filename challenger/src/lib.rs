//! The challenger's decision core.
//!
//! The core reads the vault's open escapes through a [`VaultChainPort`] and the zk edge's recorded
//! request proofs through an [`EvidencePort`]. For each escape it decides to defeat, raise, do
//! nothing or alarm (see [`decide`]). A [`Journal`] makes it safe to restart.
//!
//! Nothing here holds a note secret, and reports name only the escape's nullifier and the action.

pub mod contract;
pub mod core;
pub mod fake;
pub mod journal;
pub mod ports;
pub mod types;

pub use crate::core::{decide, Challenger, Config};
pub use journal::{FileJournal, Journal, MemoryJournal};
pub use ports::{EvidencePort, PortError, VaultChainPort};
pub use types::*;
