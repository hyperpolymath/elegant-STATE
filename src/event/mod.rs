//! Event sourcing infrastructure
//!
//! Captures all state mutations as immutable events, enabling:
//! - Full audit trail of all changes
//! - Point-in-time state reconstruction
//! - Change replay and undo capabilities

mod sourcing;

pub use sourcing::EventSourcer;
