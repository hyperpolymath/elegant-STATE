//! elegant-STATE: Local-first state graph for multi-agent orchestration
//!
//! This library provides a persistent knowledge graph that multiple agents
//! (Claude, Llama, custom modules) can query and modify via GraphQL.
//!
//! ## Features
//!
//! - **State Graph**: Nodes and edges with event sourcing
//! - **Full-Text Search**: Powered by tantivy
//! - **Fuzzy Search**: agrep-like approximate matching
//! - **Document Conversion**: pandoc integration
//! - **OCR**: tesseract integration for image text extraction
//! - **Multi-Agent Coordination**: Proposal mode, voting, reputation

pub mod schema;
pub mod store;
pub mod graphql;
pub mod event;
pub mod coordinator;

pub use schema::{StateNode, StateEdge, StateEvent, NodeKind, EdgeKind, AgentId, Operation};
pub use store::{SledStore, Store, StoreError};
pub use store::{FullTextIndex, FuzzySearch, PandocConverter, OcrEngine};
pub use graphql::{build_schema, StateSchema};
pub use event::EventSourcer;
pub use coordinator::{
    CapabilityMode, AgentCapabilities, CapabilityConfig,
    Proposal, ProposalStatus, ProposalManager, ProposalTarget,
    Vote, VoteDecision, VotingStrategy, VotingCoordinator, VotingResult,
    Reputation, ReputationTracker,
};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
