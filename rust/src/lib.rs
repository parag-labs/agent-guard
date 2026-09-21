//! AgentGuard: a zero-trust runtime for AI agents.
//!
//! Three pieces, mirroring the Python reference: a deny-by-default [`policy`]
//! engine, a [`runtime`] mediator that routes high-risk tools through a human
//! approval callback, and an Ed25519-signed, hash-chained [`audit`] log whose
//! `verify_chain` proves the trail was not tampered with.

pub mod audit;
pub mod policy;
pub mod runtime;

pub use audit::{AuditEntry, AuditLog};
pub use policy::{ArgValue, Decision, Policy, ToolCall, ToolPolicy};
pub use runtime::{AgentGuard, ToolBlockedError};
