//! State graph schema types
//!
//! This module defines the core data structures for the state graph:
//! - [`StateNode`]: Vertices in the graph with typed content
//! - [`StateEdge`]: Directed edges connecting nodes
//! - [`StateEvent`]: Event sourcing records for all mutations

mod node;
mod edge;
mod event;

pub use node::{NodeId, NodeKind, StateNode, Metadata};
pub use edge::{EdgeId, EdgeKind, StateEdge};
pub use event::{EventId, StateEvent, Operation, AgentId, Target};
