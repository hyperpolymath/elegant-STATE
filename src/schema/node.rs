//! State graph node types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use ulid::Ulid;

/// Unique identifier for a node (ULID-based)
pub type NodeId = Ulid;

/// Arbitrary key-value metadata attached to nodes
pub type Metadata = HashMap<String, Value>;

/// Classification of node purpose in the state graph
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    /// Chat or message thread
    Conversation,
    /// Project or workspace container
    Project,
    /// Knowledge or learning extracted from interactions
    Insight,
    /// Action item or todo
    Task,
    /// Contextual information for agents
    Context,
    /// External module or tool
    Module,
    /// AI agent or human participant
    Agent,
    /// User-defined custom type
    Custom(String),
}

impl std::fmt::Display for NodeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeKind::Conversation => write!(f, "conversation"),
            NodeKind::Project => write!(f, "project"),
            NodeKind::Insight => write!(f, "insight"),
            NodeKind::Task => write!(f, "task"),
            NodeKind::Context => write!(f, "context"),
            NodeKind::Module => write!(f, "module"),
            NodeKind::Agent => write!(f, "agent"),
            NodeKind::Custom(s) => write!(f, "custom:{}", s),
        }
    }
}

impl std::str::FromStr for NodeKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "conversation" => Ok(NodeKind::Conversation),
            "project" => Ok(NodeKind::Project),
            "insight" => Ok(NodeKind::Insight),
            "task" => Ok(NodeKind::Task),
            "context" => Ok(NodeKind::Context),
            "module" => Ok(NodeKind::Module),
            "agent" => Ok(NodeKind::Agent),
            s if s.starts_with("custom:") => Ok(NodeKind::Custom(s[7..].to_string())),
            _ => Err(format!("Unknown node kind: {}", s)),
        }
    }
}

/// A vertex in the state graph containing typed, JSON content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateNode {
    /// Unique identifier (ULID)
    pub id: NodeId,
    /// Node classification
    pub kind: NodeKind,
    /// JSON content payload
    pub content: Value,
    /// Additional key-value metadata
    pub metadata: Metadata,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
}

impl StateNode {
    /// Create a new node with the given kind and content
    pub fn new(kind: NodeKind, content: Value) -> Self {
        let now = Utc::now();
        Self {
            id: Ulid::new(),
            kind,
            content,
            metadata: HashMap::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Attach metadata to the node
    pub fn with_metadata(mut self, metadata: Metadata) -> Self {
        self.metadata = metadata;
        self
    }

    /// Set a specific node ID (useful for reconstruction)
    pub fn with_id(mut self, id: NodeId) -> Self {
        self.id = id;
        self
    }
}
