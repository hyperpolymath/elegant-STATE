//! GraphQL API for the state graph
//!
//! Provides a complete GraphQL interface for querying and mutating state:
//! - [`QueryRoot`]: Read operations (nodes, edges, search, history)
//! - [`MutationRoot`]: Write operations (create, update, delete)
//! - [`SubscriptionRoot`]: Real-time event streaming via WebSocket

mod query;
mod mutation;
mod types;
mod subscription;

pub use query::QueryRoot;
pub use mutation::MutationRoot;
pub use types::*;
pub use subscription::{
    SubscriptionRoot, SubscriptionEvent, EventPublisher,
    EventSender, EventReceiver, create_event_channel,
};

use async_graphql::Schema;
use crate::store::SledStore;
use std::sync::Arc;

/// Schema without subscriptions (simpler setup)
pub type StateSchema = Schema<QueryRoot, MutationRoot, async_graphql::EmptySubscription>;

/// Schema with subscriptions
pub type StateSchemaWithSubs = Schema<QueryRoot, MutationRoot, SubscriptionRoot>;

/// Build schema without subscriptions
pub fn build_schema(store: Arc<SledStore>) -> StateSchema {
    Schema::build(QueryRoot, MutationRoot, async_graphql::EmptySubscription)
        .data(store)
        .finish()
}

/// Build schema with subscriptions
pub fn build_schema_with_subscriptions(
    store: Arc<SledStore>,
    event_sender: EventSender,
) -> StateSchemaWithSubs {
    Schema::build(QueryRoot, MutationRoot, SubscriptionRoot)
        .data(store)
        .data(event_sender)
        .finish()
}
