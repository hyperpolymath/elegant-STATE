# elegant-STATE

Local-first state graph for multi-agent orchestration.

## What is this?

elegant-STATE replaces manual state tracking (like `STATE.adoc`) with a queryable, event-sourced graph database. Multiple agents (Claude, Llama, custom modules) can query and modify the state via GraphQL.

## Quick Start

```bash
# Development shell (with Guix)
guix shell

# Build
cargo build --release

# Create a project
state-cli node create --kind project --content '{"name": "NeuroPhone"}'

# Create an insight
state-cli node create --kind insight --content '{"text": "Use sled for embedded storage"}'

# Link them
state-cli edge create --from <project-id> --to <insight-id> --kind part_of

# Start GraphQL server
state-cli serve http --port 4000
```

## GraphQL API

```graphql
# Query nodes
query {
  nodes(kind: PROJECT) {
    id
    content
    createdAt
  }
}

# Create a node
mutation {
  createNode(input: {
    kind: INSIGHT
    content: {text: "hello"}
  }, agent: CLAUDE) {
    id
  }
}

# Search
query {
  search(query: "NeuroPhone", kinds: [PROJECT, INSIGHT]) {
    id
    kind
    content
  }
}

# Get neighbors
query {
  neighbors(id: "...", depth: 2) {
    id
    kind
  }
}
```

## Guix Channel

Add to your `~/.config/guix/channels.scm`:

```scheme
(cons*
 (channel
  (name 'elegant-state)
  (url "https://github.com/Hyperpolymath/elegant-STATE")
  (branch "main"))
 %default-channels)
```

Then:

```bash
guix pull
guix install elegant-state
```

## System Service

In your Guix system configuration:

```scheme
(use-modules (elegant-state services))

(operating-system
  ...
  (services
   (append
    (list
     (service elegant-state-service-type
              (elegant-state-configuration
               (port 4000)
               (data-dir "/var/lib/elegant-state"))))
    %base-services)))
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         elegant-STATE                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌─────────┐     ┌─────────┐     ┌─────────┐                  │
│   │  CLI    │     │ GraphQL │     │  Rust   │                  │
│   │state-cli│     │  API    │     │  lib    │                  │
│   └────┬────┘     └────┬────┘     └────┬────┘                  │
│        │               │               │                        │
│        └───────────────┼───────────────┘                        │
│                        │                                        │
│                  ┌─────▼─────┐                                  │
│                  │   Store   │                                  │
│                  │   Layer   │                                  │
│                  └─────┬─────┘                                  │
│                        │                                        │
│              ┌─────────┼─────────┐                              │
│              │         │         │                              │
│         ┌────▼───┐ ┌───▼───┐ ┌───▼────┐                        │
│         │ Nodes  │ │ Edges │ │ Events │                        │
│         └────┬───┘ └───┬───┘ └───┬────┘                        │
│              │         │         │                              │
│              └─────────┼─────────┘                              │
│                        │                                        │
│                  ┌─────▼─────┐                                  │
│                  │   sled    │                                  │
│                  │(embedded) │                                  │
│                  └───────────┘                                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Data Model

- **StateNode**: Vertices in the knowledge graph (conversations, projects, insights, tasks)
- **StateEdge**: Relationships between nodes (references, derived_from, part_of, etc.)
- **StateEvent**: Append-only changelog of all mutations

## License

MIT
