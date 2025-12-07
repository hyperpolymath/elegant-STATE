mod node;
mod edge;
mod serve;
mod search;
mod config;
mod agent;
mod proposal;
mod db;
mod graphql;

pub use node::NodeCommands;
pub use edge::EdgeCommands;
pub use serve::ServeCommands;
pub use search::SearchCommands;
pub use config::ConfigCommands;
pub use agent::AgentCommands;
pub use proposal::ProposalCommands;
pub use db::DbCommands;
pub use graphql::GraphqlCommands;

use clap::{Parser, Subcommand, ValueEnum, Args};

// ══════════════════════════════════════════════════════════════════════════════
// GLOBAL OPTIONS
// ══════════════════════════════════════════════════════════════════════════════

#[derive(Parser)]
#[command(name = "state-cli")]
#[command(author = "elegant-STATE contributors")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Local-first state graph for multi-agent orchestration")]
#[command(long_about = r#"
elegant-STATE is a persistent knowledge graph that multiple agents
(Claude, Llama, custom modules) can query and modify via GraphQL.

FEATURES:
  • State Graph: Nodes and edges with event sourcing
  • Full-Text Search: Powered by tantivy
  • Fuzzy Search: agrep-like approximate matching
  • Document Conversion: pandoc integration
  • OCR: tesseract integration for image text extraction
  • Multi-Agent Coordination: Proposal mode, voting, reputation
  • GraphQL API with subscriptions

EXAMPLES:
  # Create a project node
  state-cli node create --kind project --content '{"name": "MyProject"}'

  # Search for nodes
  state-cli search fulltext "rust programming" --kinds insight,context

  # Start GraphQL server
  state-cli serve http --port 4000

  # Configure agent capabilities
  state-cli agent set claude --mode proposal --vote-weight 0.8

ENVIRONMENT VARIABLES:
  STATE_DB        Database path (default: ~/.local/share/elegant-state/db)
  STATE_CONFIG    Config file path
  STATE_LOG       Log level (trace, debug, info, warn, error)
  STATE_HOST      Server host (default: 127.0.0.1)
  STATE_PORT      Server port (default: 4000)
"#)]
#[command(propagate_version = true)]
#[command(args_conflicts_with_subcommands = true)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalOptions,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Args, Debug, Clone)]
pub struct GlobalOptions {
    /// Path to the state database
    #[arg(short, long, env = "STATE_DB", global = true)]
    #[arg(default_value = "~/.local/share/elegant-state/db")]
    pub db_path: String,

    /// Path to configuration file (Nickel, JSON, TOML, or YAML)
    #[arg(short, long, env = "STATE_CONFIG", global = true)]
    pub config: Option<String>,

    /// Log level
    #[arg(short, long, env = "STATE_LOG", global = true)]
    #[arg(value_enum, default_value = "info")]
    pub log_level: LogLevel,

    /// Output format for commands that produce output
    #[arg(short, long, global = true)]
    #[arg(value_enum, default_value = "text")]
    pub output: OutputFormat,

    /// Agent identity for operations
    #[arg(short, long, global = true, default_value = "user")]
    pub agent: String,

    /// Quiet mode - suppress non-essential output
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Verbose mode - show detailed output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Dry run - show what would be done without executing
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Force operation without confirmation
    #[arg(long, global = true)]
    pub force: bool,

    /// No color output
    #[arg(long, global = true)]
    pub no_color: bool,
}

// ══════════════════════════════════════════════════════════════════════════════
// VALUE ENUMS
// ══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Yaml,
    Toml,
    Table,
    Csv,
    Ndjson,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum NodeKindArg {
    Conversation,
    Project,
    Insight,
    Task,
    Context,
    Module,
    Agent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum EdgeKindArg {
    References,
    DerivedFrom,
    RelatedTo,
    PartOf,
    Blocks,
    Enables,
    Supersedes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CapabilityModeArg {
    Direct,
    Proposal,
    Observer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum VotingStrategyArg {
    Unanimous,
    SimpleMajority,
    Supermajority,
    Weighted,
    FirstVote,
    SingleApprover,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SearchAlgorithm {
    Fulltext,
    Fuzzy,
    Agrep,
    Exact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ExportFormat {
    Json,
    Yaml,
    Toml,
    Csv,
    Ndjson,
    Graphml,
    Dot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
    Elvish,
    PowerShell,
}

// ══════════════════════════════════════════════════════════════════════════════
// COMMANDS
// ══════════════════════════════════════════════════════════════════════════════

#[derive(Subcommand)]
pub enum Commands {
    // ─────────────────────────────────────────────────────────────────────────
    // CORE OPERATIONS
    // ─────────────────────────────────────────────────────────────────────────

    /// Node operations (create, read, update, delete, list)
    #[command(visible_alias = "n")]
    Node {
        #[command(subcommand)]
        command: NodeCommands,
    },

    /// Edge operations (create, delete, list, traverse)
    #[command(visible_alias = "e")]
    Edge {
        #[command(subcommand)]
        command: EdgeCommands,
    },

    /// Search operations (fulltext, fuzzy, agrep, semantic)
    #[command(visible_alias = "s")]
    Search {
        #[command(subcommand)]
        command: SearchCommands,
    },

    // ─────────────────────────────────────────────────────────────────────────
    // EVENTS & HISTORY
    // ─────────────────────────────────────────────────────────────────────────

    /// Show recent events from the event log
    #[command(visible_alias = "ev")]
    Events {
        /// Number of events to show
        #[arg(short, long, default_value = "20")]
        limit: usize,

        /// Filter by agent (user, claude, llama, system, module:*)
        #[arg(short, long)]
        agent: Option<String>,

        /// Filter by operation (create, update, delete, link, unlink)
        #[arg(short, long)]
        operation: Option<String>,

        /// Show events since timestamp (ISO 8601 or relative like "1h", "2d")
        #[arg(long)]
        since: Option<String>,

        /// Show events until timestamp
        #[arg(long)]
        until: Option<String>,

        /// Follow events in real-time
        #[arg(short, long)]
        follow: bool,

        /// Show full event details
        #[arg(long)]
        full: bool,
    },

    /// Show event history for a specific node or edge
    History {
        /// ID of the node or edge
        id: String,

        /// Number of history entries to show
        #[arg(short, long, default_value = "50")]
        limit: usize,

        /// Show diffs between versions
        #[arg(long)]
        diff: bool,
    },

    // ─────────────────────────────────────────────────────────────────────────
    // COORDINATION
    // ─────────────────────────────────────────────────────────────────────────

    /// Agent configuration and management
    #[command(visible_alias = "ag")]
    Agent {
        #[command(subcommand)]
        command: AgentCommands,
    },

    /// Proposal management (for proposal mode)
    #[command(visible_alias = "pr")]
    Proposal {
        #[command(subcommand)]
        command: ProposalCommands,
    },

    /// Vote on a proposal
    Vote {
        /// Proposal ID to vote on
        proposal_id: String,

        /// Vote decision
        #[arg(value_enum)]
        decision: VoteDecision,

        /// Reason for the vote
        #[arg(short, long)]
        reason: Option<String>,
    },

    // ─────────────────────────────────────────────────────────────────────────
    // IMPORT/EXPORT
    // ─────────────────────────────────────────────────────────────────────────

    /// Export state to file
    Export {
        /// Output file (- for stdout)
        #[arg(default_value = "-")]
        output: String,

        /// Export format
        #[arg(short, long, value_enum, default_value = "json")]
        format: ExportFormat,

        /// Filter by node kinds
        #[arg(short, long)]
        kinds: Option<String>,

        /// Include edges
        #[arg(long, default_value = "true")]
        edges: bool,

        /// Include events
        #[arg(long)]
        events: bool,

        /// Pretty print output
        #[arg(short, long)]
        pretty: bool,
    },

    /// Import state from file
    Import {
        /// Input file (- for stdin)
        file: String,

        /// Import format (auto-detected if not specified)
        #[arg(short, long, value_enum)]
        format: Option<ExportFormat>,

        /// Merge with existing data (default: replace)
        #[arg(long)]
        merge: bool,

        /// Skip validation
        #[arg(long)]
        no_validate: bool,
    },

    // ─────────────────────────────────────────────────────────────────────────
    // SERVER
    // ─────────────────────────────────────────────────────────────────────────

    /// Start GraphQL server
    #[command(visible_alias = "srv")]
    Serve {
        #[command(subcommand)]
        command: ServeCommands,
    },

    /// GraphQL operations
    #[command(visible_alias = "gql")]
    Graphql {
        #[command(subcommand)]
        command: GraphqlCommands,
    },

    // ─────────────────────────────────────────────────────────────────────────
    // DATABASE
    // ─────────────────────────────────────────────────────────────────────────

    /// Database operations (backup, restore, compact, stats)
    #[command(visible_alias = "database")]
    Db {
        #[command(subcommand)]
        command: DbCommands,
    },

    // ─────────────────────────────────────────────────────────────────────────
    // CONFIGURATION
    // ─────────────────────────────────────────────────────────────────────────

    /// Configuration management
    #[command(visible_alias = "cfg")]
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },

    // ─────────────────────────────────────────────────────────────────────────
    // DOCUMENT PROCESSING
    // ─────────────────────────────────────────────────────────────────────────

    /// Convert document using pandoc
    Convert {
        /// Input file
        input: String,

        /// Output file (- for stdout)
        #[arg(default_value = "-")]
        output: String,

        /// Input format (auto-detected if not specified)
        #[arg(short, long)]
        from: Option<String>,

        /// Output format
        #[arg(short, long, default_value = "markdown")]
        to: String,
    },

    /// Extract text from image using OCR
    Ocr {
        /// Image file
        image: String,

        /// OCR language
        #[arg(short, long, default_value = "eng")]
        lang: String,

        /// Output format (text, hocr, json)
        #[arg(short, long, default_value = "text")]
        format: String,

        /// Create a node from OCR result
        #[arg(long)]
        create_node: bool,

        /// Node kind if creating node
        #[arg(long, value_enum, default_value = "context")]
        node_kind: NodeKindArg,
    },

    // ─────────────────────────────────────────────────────────────────────────
    // UTILITIES
    // ─────────────────────────────────────────────────────────────────────────

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },

    /// Print version information
    Version {
        /// Show detailed version info
        #[arg(short, long)]
        verbose: bool,
    },

    /// Show system information and health
    Info {
        /// Show all information
        #[arg(short, long)]
        all: bool,

        /// Check external tools
        #[arg(long)]
        check_tools: bool,
    },

    /// Interactive REPL mode
    Repl {
        /// History file
        #[arg(long)]
        history: Option<String>,
    },

    /// Watch for changes and execute command
    Watch {
        /// Command to execute on changes
        command: Vec<String>,

        /// Debounce interval in milliseconds
        #[arg(long, default_value = "500")]
        debounce: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum VoteDecision {
    Approve,
    Reject,
    Abstain,
}
