//! The challenger's Mina adapter: [`MinaChain`] implements the challenger's
//! [`VaultChainPort`](zk_toon_challenger::VaultChainPort) on a Mina vault. `docs/challenger-mina.md`
//! documents it.
//!
//! - **Reading.** The vault's pending escapes, deadlines included, are rebuilt from its `escape` events
//!   (the archive node API's GraphQL) and checked against its `pendingEscapesRoot` (the daemon's
//!   GraphQL); see [`escapes`].
//! - **Submitting.** Defeats and raises are built by the o1js transaction builder
//!   ([`zk_toon_tx_builder`]) and sent with `sendZkapp`. A submission waits for its outcome, read
//!   again through dropped connections and failed polls until it is known.
//! - **Reaching Mina.** [`HttpGraphql`] speaks to both endpoints, through a SOCKS5 proxy when opted
//!   in, with no direct fallback. [`Relay`] gives the builder the same path.
//! - **Nullifiers** cross the port as [`nullifier_of_field`] encodes them.
//!
//! The challenger's core stays free of all this: it depends on nothing, and this crate depends on it.
//! Nothing here logs; errors name nullifiers and the chain's messages, never a secret.

mod chain;
pub mod escapes;
pub mod graphql;
mod http;
mod nullifier;
mod relay;

pub use chain::{MinaChain, RequestProofs, Settings, TxSource};
pub use graphql::{Endpoint, Graphql};
pub use http::{Endpoints, HttpGraphql};
pub use nullifier::{field_of_nullifier, nullifier_of_field};
pub use relay::Relay;
