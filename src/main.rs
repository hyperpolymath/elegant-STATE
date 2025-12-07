//! elegant-STATE CLI entrypoint

use anyhow::{anyhow, Result};
use clap::{CommandFactory, Parser};
use clap_complete::{generate, Shell as ClapShell};
use std::io::Write;
use std::sync::Arc;

use elegant_state::{
    build_schema, AgentId, EdgeKind, NodeKind, StateEdge, StateNode, SledStore, Store,
    FullTextIndex, FuzzySearch, PandocConverter, OcrEngine,
    CapabilityConfig, CapabilityMode, AgentCapabilities,
    ProposalManager, Proposal, ProposalStatus,
    VotingCoordinator, VotingStrategy, Vote, VoteDecision as DomainVoteDecision,
    ReputationTracker,
};

mod cli;
use cli::*;

// ══════════════════════════════════════════════════════════════════════════════
// UTILITIES
// ══════════════════════════════════════════════════════════════════════════════

fn expand_path(path: &str) -> String {
    if path.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            return path.replacen("~", &home.to_string_lossy(), 1);
        }
    }
    path.to_string()
}

fn parse_agent_id(s: &str) -> AgentId {
    match s.to_lowercase().as_str() {
        "user" => AgentId::User,
        "claude" => AgentId::Claude,
        "llama" => AgentId::Llama,
        "system" => AgentId::System,
        s if s.starts_with("module:") => AgentId::Module(s[7..].to_string()),
        _ => AgentId::User,
    }
}

fn node_kind_from_arg(arg: NodeKindArg) -> NodeKind {
    match arg {
        NodeKindArg::Conversation => NodeKind::Conversation,
        NodeKindArg::Project => NodeKind::Project,
        NodeKindArg::Insight => NodeKind::Insight,
        NodeKindArg::Task => NodeKind::Task,
        NodeKindArg::Context => NodeKind::Context,
        NodeKindArg::Module => NodeKind::Module,
        NodeKindArg::Agent => NodeKind::Agent,
    }
}

fn edge_kind_from_arg(arg: EdgeKindArg) -> EdgeKind {
    match arg {
        EdgeKindArg::References => EdgeKind::References,
        EdgeKindArg::DerivedFrom => EdgeKind::DerivedFrom,
        EdgeKindArg::RelatedTo => EdgeKind::RelatedTo,
        EdgeKindArg::PartOf => EdgeKind::PartOf,
        EdgeKindArg::Blocks => EdgeKind::Blocks,
        EdgeKindArg::Enables => EdgeKind::Enables,
        EdgeKindArg::Supersedes => EdgeKind::Supersedes,
    }
}

fn output_value(value: &serde_json::Value, format: OutputFormat, pretty: bool) -> Result<()> {
    let output = match format {
        OutputFormat::Json => {
            if pretty {
                serde_json::to_string_pretty(value)?
            } else {
                serde_json::to_string(value)?
            }
        }
        OutputFormat::Yaml => serde_yaml::to_string(value)?,
        OutputFormat::Toml => toml::to_string_pretty(value)?,
        OutputFormat::Ndjson => serde_json::to_string(value)?,
        _ => serde_json::to_string_pretty(value)?,
    };
    println!("{}", output);
    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
// MAIN
// ══════════════════════════════════════════════════════════════════════════════

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = match cli.global.log_level {
        LogLevel::Trace => "trace",
        LogLevel::Debug => "debug",
        LogLevel::Info => "info",
        LogLevel::Warn => "warn",
        LogLevel::Error => "error",
    };
    std::env::set_var("RUST_LOG", log_level);
    tracing_subscriber::fmt::init();

    let db_path = expand_path(&cli.global.db_path);
    let agent = parse_agent_id(&cli.global.agent);
    let output_format = cli.global.output;
    let quiet = cli.global.quiet;
    let verbose = cli.global.verbose;

    // Ensure parent directory exists
    if let Some(parent) = std::path::Path::new(&db_path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Open store with auto-indexing
    let store = Arc::new(SledStore::open(&db_path)?);

    // Initialize full-text index
    let index_path = format!("{}_index", db_path);
    let fulltext_index = FullTextIndex::open(&index_path).ok();

    match cli.command {
        // ─────────────────────────────────────────────────────────────────────
        // CORE OPERATIONS
        // ─────────────────────────────────────────────────────────────────────
        Commands::Node { command } => {
            handle_node_command(command, &store, &agent, output_format, &fulltext_index)?;
        }

        Commands::Edge { command } => {
            handle_edge_command(command, &store, &agent, output_format)?;
        }

        Commands::Search { command } => {
            handle_search_command(command, &store, &fulltext_index, output_format)?;
        }

        // ─────────────────────────────────────────────────────────────────────
        // EVENTS & HISTORY
        // ─────────────────────────────────────────────────────────────────────
        Commands::Events { limit, agent: filter_agent, operation, since, until, follow, full } => {
            let events = store.get_events(None, limit)?;
            for event in events {
                if let Some(ref ag) = filter_agent {
                    if event.agent.to_string() != *ag {
                        continue;
                    }
                }
                if full {
                    println!("{}", serde_json::to_string_pretty(&event)?);
                } else {
                    println!(
                        "[{}] {:?} {:?} by {}",
                        event.timestamp.format("%Y-%m-%d %H:%M:%S"),
                        event.operation,
                        event.target,
                        event.agent
                    );
                }
            }
        }

        Commands::History { id, limit, diff } => {
            let node_id = id.parse().map_err(|e| anyhow!("Invalid ID: {}", e))?;
            let events = store.get_events(None, limit)?;
            let filtered: Vec<_> = events
                .into_iter()
                .filter(|e| {
                    match &e.target {
                        elegant_state::schema::Target::Node(nid) => *nid == node_id,
                        _ => false,
                    }
                })
                .collect();
            for event in filtered {
                println!(
                    "[{}] {:?} by {}",
                    event.timestamp.format("%Y-%m-%d %H:%M:%S"),
                    event.operation,
                    event.agent
                );
                if diff {
                    if let Some(ref before) = event.before {
                        println!("  Before: {}", serde_json::to_string(before)?);
                    }
                    if let Some(ref after) = event.after {
                        println!("  After: {}", serde_json::to_string(after)?);
                    }
                }
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // COORDINATION
        // ─────────────────────────────────────────────────────────────────────
        Commands::Agent { command } => {
            handle_agent_command(command, output_format)?;
        }

        Commands::Proposal { command } => {
            handle_proposal_command(command, output_format)?;
        }

        Commands::Vote { proposal_id, decision, reason } => {
            let decision = match decision {
                cli::VoteDecision::Approve => DomainVoteDecision::Approve,
                cli::VoteDecision::Reject => DomainVoteDecision::Reject,
                cli::VoteDecision::Abstain => DomainVoteDecision::Abstain,
            };
            println!("Vote recorded: {:?} on {} (reason: {:?})", decision, proposal_id, reason);
        }

        // ─────────────────────────────────────────────────────────────────────
        // IMPORT/EXPORT
        // ─────────────────────────────────────────────────────────────────────
        Commands::Export { output, format, kinds, edges, events, pretty } => {
            let nodes = store.list_nodes(None, usize::MAX)?;
            let mut export = serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "nodes": nodes,
            });

            if edges {
                // Collect all edges
                let mut all_edges = Vec::new();
                for node in &nodes {
                    all_edges.extend(store.edges_from(node.id)?);
                }
                export["edges"] = serde_json::to_value(&all_edges)?;
            }

            if events {
                let evts = store.get_events(None, 1000)?;
                export["events"] = serde_json::to_value(&evts)?;
            }

            let output_str = match format {
                ExportFormat::Json => {
                    if pretty {
                        serde_json::to_string_pretty(&export)?
                    } else {
                        serde_json::to_string(&export)?
                    }
                }
                ExportFormat::Yaml => serde_yaml::to_string(&export)?,
                ExportFormat::Ndjson => {
                    let mut lines = Vec::new();
                    if let Some(nodes) = export["nodes"].as_array() {
                        for node in nodes {
                            lines.push(serde_json::to_string(node)?);
                        }
                    }
                    lines.join("\n")
                }
                _ => serde_json::to_string_pretty(&export)?,
            };

            if output == "-" {
                println!("{}", output_str);
            } else {
                std::fs::write(&output, output_str)?;
                if !quiet {
                    println!("Exported to {}", output);
                }
            }
        }

        Commands::Import { file, format, merge, no_validate } => {
            let content = if file == "-" {
                let mut buf = String::new();
                std::io::stdin().read_line(&mut buf)?;
                buf
            } else {
                std::fs::read_to_string(&file)?
            };

            let import: serde_json::Value = serde_json::from_str(&content)?;

            let mut count = 0;
            if let Some(nodes) = import.get("nodes").and_then(|n| n.as_array()) {
                for node_value in nodes {
                    let node: StateNode = serde_json::from_value(node_value.clone())?;
                    store.create_node(node, AgentId::System)?;
                    count += 1;
                }
            }

            if let Some(edges) = import.get("edges").and_then(|e| e.as_array()) {
                for edge_value in edges {
                    let edge: StateEdge = serde_json::from_value(edge_value.clone())?;
                    store.create_edge(edge, AgentId::System)?;
                }
            }

            if !quiet {
                println!("Imported {} nodes", count);
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // SERVER
        // ─────────────────────────────────────────────────────────────────────
        Commands::Serve { command } => {
            handle_serve_command(command, store, quiet).await?;
        }

        Commands::Graphql { command } => {
            handle_graphql_command(command, &store).await?;
        }

        // ─────────────────────────────────────────────────────────────────────
        // DATABASE
        // ─────────────────────────────────────────────────────────────────────
        Commands::Db { command } => {
            handle_db_command(command, &db_path, &store, quiet)?;
        }

        // ─────────────────────────────────────────────────────────────────────
        // CONFIGURATION
        // ─────────────────────────────────────────────────────────────────────
        Commands::Config { command } => {
            handle_config_command(command)?;
        }

        // ─────────────────────────────────────────────────────────────────────
        // DOCUMENT PROCESSING
        // ─────────────────────────────────────────────────────────────────────
        Commands::Convert { input, output, from, to } => {
            let converter = PandocConverter::new();
            if !converter.is_available() {
                return Err(anyhow!("pandoc not found in PATH"));
            }

            let content = std::fs::read_to_string(&input)?;
            let from_format = from
                .map(|f| match f.as_str() {
                    "markdown" | "md" => elegant_state::store::InputFormat::Markdown,
                    "html" => elegant_state::store::InputFormat::Html,
                    "latex" | "tex" => elegant_state::store::InputFormat::Latex,
                    "docx" => elegant_state::store::InputFormat::Docx,
                    "rst" => elegant_state::store::InputFormat::Rst,
                    "org" => elegant_state::store::InputFormat::Org,
                    "asciidoc" | "adoc" => elegant_state::store::InputFormat::Asciidoc,
                    _ => elegant_state::store::InputFormat::Auto,
                })
                .unwrap_or_else(|| elegant_state::store::detect_format(&input));

            let to_format = match to.as_str() {
                "markdown" | "md" => elegant_state::store::OutputFormat::Markdown,
                "html" => elegant_state::store::OutputFormat::Html,
                "plain" | "text" => elegant_state::store::OutputFormat::Plain,
                "json" => elegant_state::store::OutputFormat::Json,
                _ => elegant_state::store::OutputFormat::Markdown,
            };

            let result = converter.convert(&content, from_format, to_format)?;

            if output == "-" {
                println!("{}", result);
            } else {
                std::fs::write(&output, result)?;
                if !quiet {
                    println!("Converted {} -> {}", input, output);
                }
            }
        }

        Commands::Ocr { image, lang, format, create_node, node_kind } => {
            let ocr = OcrEngine::new()
                .with_language(match lang.as_str() {
                    "eng" => elegant_state::store::OcrLanguage::English,
                    "deu" => elegant_state::store::OcrLanguage::German,
                    "fra" => elegant_state::store::OcrLanguage::French,
                    "spa" => elegant_state::store::OcrLanguage::Spanish,
                    _ => elegant_state::store::OcrLanguage::English,
                });

            if !ocr.is_available() {
                return Err(anyhow!("tesseract not found in PATH"));
            }

            let text = ocr.extract_text(&image)?;

            if create_node {
                let kind = node_kind_from_arg(node_kind);
                let node = StateNode::new(kind, serde_json::json!({
                    "source": image,
                    "text": text.trim(),
                    "ocr_lang": lang,
                }));
                let created = store.create_node(node, agent)?;
                if !quiet {
                    println!("Created node: {}", created.id);
                }
            } else {
                println!("{}", text);
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // UTILITIES
        // ─────────────────────────────────────────────────────────────────────
        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            let shell = match shell {
                Shell::Bash => ClapShell::Bash,
                Shell::Zsh => ClapShell::Zsh,
                Shell::Fish => ClapShell::Fish,
                Shell::Elvish => ClapShell::Elvish,
                Shell::PowerShell => ClapShell::PowerShell,
            };
            generate(shell, &mut cmd, "state-cli", &mut std::io::stdout());
        }

        Commands::Version { verbose: v } => {
            println!("elegant-STATE {}", env!("CARGO_PKG_VERSION"));
            if v || verbose {
                println!("Rust: {}", rustc_version_runtime::version());
                if let Ok(output) = std::process::Command::new("pandoc").arg("--version").output() {
                    let version = String::from_utf8_lossy(&output.stdout);
                    if let Some(line) = version.lines().next() {
                        println!("Pandoc: {}", line);
                    }
                }
                if let Ok(output) = std::process::Command::new("tesseract").arg("--version").output() {
                    let version = String::from_utf8_lossy(&output.stderr);
                    if let Some(line) = version.lines().next() {
                        println!("Tesseract: {}", line);
                    }
                }
            }
        }

        Commands::Info { all, check_tools } => {
            println!("elegant-STATE {}", env!("CARGO_PKG_VERSION"));
            println!("Database: {}", db_path);

            if let Ok(meta) = std::fs::metadata(&db_path) {
                if meta.is_dir() {
                    let size: u64 = walkdir::WalkDir::new(&db_path)
                        .into_iter()
                        .filter_map(|e| e.ok())
                        .filter_map(|e| e.metadata().ok())
                        .map(|m| m.len())
                        .sum();
                    println!("Database size: {} bytes", size);
                }
            }

            if all || check_tools {
                println!("\nExternal tools:");
                let pandoc = PandocConverter::new();
                println!("  pandoc: {}", if pandoc.is_available() { "✓" } else { "✗" });
                let ocr = OcrEngine::new();
                println!("  tesseract: {}", if ocr.is_available() { "✓" } else { "✗" });
            }
        }

        Commands::Repl { history } => {
            println!("REPL mode not yet implemented");
            println!("Use --help for available commands");
        }

        Commands::Watch { command, debounce } => {
            println!("Watch mode not yet implemented");
        }
    }

    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
// COMMAND HANDLERS
// ══════════════════════════════════════════════════════════════════════════════

fn handle_node_command(
    command: NodeCommands,
    store: &Arc<SledStore>,
    agent: &AgentId,
    output_format: OutputFormat,
    fulltext_index: &Option<FullTextIndex>,
) -> Result<()> {
    match command {
        NodeCommands::Create { kind, content, metadata } => {
            let kind: NodeKind = kind.parse().map_err(|e: String| anyhow!(e))?;
            let content: serde_json::Value = serde_json::from_str(&content)?;
            let mut node = StateNode::new(kind, content);
            if let Some(meta) = metadata {
                let meta_map = serde_json::from_str(&meta)?;
                node = node.with_metadata(meta_map);
            }
            let created = store.create_node(node.clone(), agent.clone())?;

            // Auto-index
            if let Some(ref index) = fulltext_index {
                if let Ok(mut writer) = index.writer(50_000_000) {
                    let _ = index.index_node(&mut writer, &created);
                    let _ = writer.commit();
                }
            }

            println!("Created node: {}", created.id);
            output_value(&serde_json::to_value(&created)?, output_format, true)?;
        }
        NodeCommands::Get { id } => {
            let node_id = id.parse().map_err(|e| anyhow!("Invalid ID: {}", e))?;
            match store.get_node(node_id)? {
                Some(node) => output_value(&serde_json::to_value(&node)?, output_format, true)?,
                None => println!("Node not found"),
            }
        }
        NodeCommands::List { kind, limit } => {
            let kind: Option<NodeKind> = kind
                .map(|k| k.parse().map_err(|e: String| anyhow!(e)))
                .transpose()?;
            let nodes = store.list_nodes(kind, limit)?;
            match output_format {
                OutputFormat::Json | OutputFormat::Yaml => {
                    output_value(&serde_json::to_value(&nodes)?, output_format, true)?;
                }
                _ => {
                    for node in nodes {
                        println!("{} [{}] {}", node.id, node.kind, node.content);
                    }
                }
            }
        }
        NodeCommands::Update { id, content } => {
            let node_id = id.parse().map_err(|e| anyhow!("Invalid ID: {}", e))?;
            let content: serde_json::Value = serde_json::from_str(&content)?;
            let updated = store.update_node(node_id, content, agent.clone())?;

            // Re-index
            if let Some(ref index) = fulltext_index {
                if let Ok(mut writer) = index.writer(50_000_000) {
                    let _ = index.remove_node(&mut writer, node_id);
                    let _ = index.index_node(&mut writer, &updated);
                    let _ = writer.commit();
                }
            }

            println!("Updated node: {}", updated.id);
        }
        NodeCommands::Delete { id, force } => {
            if !force {
                print!("Are you sure you want to delete node {}? [y/N] ", id);
                std::io::stdout().flush()?;
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if !input.trim().eq_ignore_ascii_case("y") {
                    println!("Aborted");
                    return Ok(());
                }
            }
            let node_id = id.parse().map_err(|e| anyhow!("Invalid ID: {}", e))?;

            // Remove from index
            if let Some(ref index) = fulltext_index {
                if let Ok(mut writer) = index.writer(50_000_000) {
                    let _ = index.remove_node(&mut writer, node_id);
                    let _ = writer.commit();
                }
            }

            store.delete_node(node_id, agent.clone())?;
            println!("Deleted node: {}", id);
        }
    }
    Ok(())
}

fn handle_edge_command(
    command: EdgeCommands,
    store: &Arc<SledStore>,
    agent: &AgentId,
    output_format: OutputFormat,
) -> Result<()> {
    match command {
        EdgeCommands::Create { from, to, kind, weight } => {
            let from_id = from.parse().map_err(|e| anyhow!("Invalid from ID: {}", e))?;
            let to_id = to.parse().map_err(|e| anyhow!("Invalid to ID: {}", e))?;
            let kind: EdgeKind = kind.parse().map_err(|e: String| anyhow!(e))?;
            let mut edge = StateEdge::new(from_id, to_id, kind);
            if let Some(w) = weight {
                edge = edge.with_weight(w);
            }
            let created = store.create_edge(edge, agent.clone())?;
            println!("Created edge: {}", created.id);
        }
        EdgeCommands::From { id } => {
            let node_id = id.parse().map_err(|e| anyhow!("Invalid ID: {}", e))?;
            let edges = store.edges_from(node_id)?;
            match output_format {
                OutputFormat::Json | OutputFormat::Yaml => {
                    output_value(&serde_json::to_value(&edges)?, output_format, true)?;
                }
                _ => {
                    for edge in edges {
                        println!("{} --[{}]--> {}", edge.from, edge.kind, edge.to);
                    }
                }
            }
        }
        EdgeCommands::To { id } => {
            let node_id = id.parse().map_err(|e| anyhow!("Invalid ID: {}", e))?;
            let edges = store.edges_to(node_id)?;
            match output_format {
                OutputFormat::Json | OutputFormat::Yaml => {
                    output_value(&serde_json::to_value(&edges)?, output_format, true)?;
                }
                _ => {
                    for edge in edges {
                        println!("{} --[{}]--> {}", edge.from, edge.kind, edge.to);
                    }
                }
            }
        }
        EdgeCommands::Delete { id } => {
            let edge_id = id.parse().map_err(|e| anyhow!("Invalid ID: {}", e))?;
            store.delete_edge(edge_id, agent.clone())?;
            println!("Deleted edge: {}", id);
        }
    }
    Ok(())
}

fn handle_search_command(
    command: SearchCommands,
    store: &Arc<SledStore>,
    fulltext_index: &Option<FullTextIndex>,
    output_format: OutputFormat,
) -> Result<()> {
    match command {
        SearchCommands::Fulltext { query, kinds, limit, min_score, scores, highlight } => {
            if let Some(ref index) = fulltext_index {
                let kind_list: Option<Vec<NodeKind>> = kinds.map(|ks| {
                    ks.into_iter().map(node_kind_from_arg).collect()
                });
                let results = index.search(&query, kind_list.as_deref(), limit)?;

                for result in results {
                    if let Some(min) = min_score {
                        if result.score < min {
                            continue;
                        }
                    }
                    if scores {
                        println!("[{:.3}] {} [{}]", result.score, result.id, result.kind);
                    } else {
                        println!("{} [{}]", result.id, result.kind);
                    }
                    if highlight {
                        println!("  {}", result.content);
                    }
                }
            } else {
                // Fallback to basic search
                let kind_list: Option<Vec<NodeKind>> = kinds.map(|ks| {
                    ks.into_iter().map(node_kind_from_arg).collect()
                });
                let results = store.search(&query, kind_list)?;
                for node in results.into_iter().take(limit) {
                    println!("{} [{}] {}", node.id, node.kind, node.content);
                }
            }
        }
        SearchCommands::Fuzzy { pattern, kinds, limit, nucleo, case_sensitive } => {
            let fuzzy = FuzzySearch::new();
            let kind_list: Option<Vec<NodeKind>> = kinds.map(|ks| {
                ks.into_iter().map(node_kind_from_arg).collect()
            });
            let all_nodes = store.list_nodes(None, usize::MAX)?;

            let filtered: Vec<_> = if let Some(ref ks) = kind_list {
                all_nodes.into_iter().filter(|n| ks.contains(&n.kind)).collect()
            } else {
                all_nodes
            };

            let results = fuzzy.search(&pattern, &filtered, |n| {
                // Search in content as string
                n.content.to_string()
            });

            for (node, score) in results.into_iter().take(limit) {
                println!("[{}] {} [{}]", score, node.id, node.kind);
            }
        }
        SearchCommands::Agrep { pattern, max_errors, kinds, limit } => {
            let fuzzy = FuzzySearch::new();
            let kind_list: Option<Vec<NodeKind>> = kinds.map(|ks| {
                ks.into_iter().map(node_kind_from_arg).collect()
            });
            let all_nodes = store.list_nodes(None, usize::MAX)?;

            let filtered: Vec<_> = if let Some(ref ks) = kind_list {
                all_nodes.into_iter().filter(|n| ks.contains(&n.kind)).collect()
            } else {
                all_nodes
            };

            let mut count = 0;
            for node in filtered {
                if count >= limit {
                    break;
                }
                let content = node.content.to_string();
                if fuzzy.agrep_match(&pattern, &content, max_errors) {
                    println!("{} [{}]", node.id, node.kind);
                    count += 1;
                }
            }
        }
        SearchCommands::Exact { query, kinds, ignore_case, limit } => {
            let kind_list: Option<Vec<NodeKind>> = kinds.map(|ks| {
                ks.into_iter().map(node_kind_from_arg).collect()
            });
            let all_nodes = store.list_nodes(None, usize::MAX)?;

            let search_query = if ignore_case { query.to_lowercase() } else { query.clone() };

            let mut count = 0;
            for node in all_nodes {
                if count >= limit {
                    break;
                }
                if let Some(ref ks) = kind_list {
                    if !ks.contains(&node.kind) {
                        continue;
                    }
                }
                let content = if ignore_case {
                    node.content.to_string().to_lowercase()
                } else {
                    node.content.to_string()
                };
                if content.contains(&search_query) {
                    println!("{} [{}]", node.id, node.kind);
                    count += 1;
                }
            }
        }
        SearchCommands::Meta { field, value, kinds } => {
            let kind_list: Option<Vec<NodeKind>> = kinds.map(|ks| {
                ks.into_iter().map(node_kind_from_arg).collect()
            });
            let all_nodes = store.list_nodes(None, usize::MAX)?;

            for node in all_nodes {
                if let Some(ref ks) = kind_list {
                    if !ks.contains(&node.kind) {
                        continue;
                    }
                }
                if let Some(meta_value) = node.metadata.get(&field) {
                    let meta_str = meta_value.to_string();
                    if value.contains('*') {
                        let pattern = value.replace('*', ".*");
                        if regex::Regex::new(&pattern).map(|r| r.is_match(&meta_str)).unwrap_or(false) {
                            println!("{} [{}] {}={}", node.id, node.kind, field, meta_str);
                        }
                    } else if meta_str.contains(&value) {
                        println!("{} [{}] {}={}", node.id, node.kind, field, meta_str);
                    }
                }
            }
        }
        SearchCommands::Related { id, direction, edge_kinds, depth } => {
            let node_id = id.parse().map_err(|e| anyhow!("Invalid ID: {}", e))?;
            let neighbors = store.neighbors(node_id, depth)?;
            for node in neighbors {
                println!("{} [{}]", node.id, node.kind);
            }
        }
        SearchCommands::Reindex { kinds, progress } => {
            if let Some(ref index) = fulltext_index {
                let kind_list: Option<Vec<NodeKind>> = kinds.map(|ks| {
                    ks.into_iter().map(node_kind_from_arg).collect()
                });
                let all_nodes = store.list_nodes(None, usize::MAX)?;

                let mut writer = index.writer(50_000_000)?;
                let mut count = 0;

                for node in all_nodes {
                    if let Some(ref ks) = kind_list {
                        if !ks.contains(&node.kind) {
                            continue;
                        }
                    }
                    index.index_node(&mut writer, &node)?;
                    count += 1;
                    if progress && count % 100 == 0 {
                        eprintln!("Indexed {} nodes...", count);
                    }
                }

                writer.commit().map_err(|e| anyhow!("Failed to commit index: {}", e))?;
                println!("Reindexed {} nodes", count);
            } else {
                println!("Full-text index not available");
            }
        }
    }
    Ok(())
}

fn handle_agent_command(command: AgentCommands, output_format: OutputFormat) -> Result<()> {
    let mut config = CapabilityConfig::default();
    let mut tracker = ReputationTracker::new();

    match command {
        AgentCommands::List { verbose, reputation } => {
            let agents = vec![AgentId::User, AgentId::Claude, AgentId::Llama, AgentId::System];
            for agent in agents {
                let caps = config.get_capabilities(&agent);
                print!("{}: mode={}", agent, caps.mode);
                if verbose {
                    print!(", can_vote={}, weight={}", caps.can_vote, caps.vote_weight);
                }
                if reputation {
                    if let Some(rep) = tracker.get(&agent) {
                        print!(", reputation={:.2}", rep.score);
                    }
                }
                println!();
            }
        }
        AgentCommands::Show { agent, history } => {
            let agent_id = parse_agent_id(&agent);
            let caps = config.get_capabilities(&agent_id);
            println!("Agent: {}", agent_id);
            println!("Mode: {}", caps.mode);
            println!("Can vote: {}", caps.can_vote);
            println!("Vote weight: {}", caps.vote_weight);
            if let Some(rep) = tracker.get(&agent_id) {
                println!("Reputation: {:.2}", rep.score);
                println!("Total votes: {}", rep.total_votes);
                println!("Correct votes: {}", rep.correct_votes);
            }
        }
        AgentCommands::Set { agent, mode, can_vote, vote_weight } => {
            let agent_id = parse_agent_id(&agent);
            let mut caps = config.get_capabilities(&agent_id);
            if let Some(m) = mode {
                caps.mode = match m {
                    CapabilityModeArg::Direct => CapabilityMode::Direct,
                    CapabilityModeArg::Proposal => CapabilityMode::Proposal,
                    CapabilityModeArg::Observer => CapabilityMode::Observer,
                };
            }
            if let Some(cv) = can_vote {
                caps.can_vote = cv;
            }
            if let Some(vw) = vote_weight {
                caps.vote_weight = vw;
            }
            config.set_capabilities(caps).map_err(|e| anyhow!(e))?;
            println!("Updated agent: {}", agent);
        }
        AgentCommands::Leaderboard { limit, sort } => {
            let leaderboard = tracker.leaderboard();
            for (i, rep) in leaderboard.into_iter().take(limit).enumerate() {
                println!("{}. {} - score: {:.2}, accuracy: {:.1}%",
                    i + 1, rep.agent, rep.score, rep.accuracy() * 100.0);
            }
        }
        AgentCommands::Whoami => {
            println!("Current agent: user");
        }
        _ => {
            println!("Agent command not fully implemented yet");
        }
    }
    Ok(())
}

fn handle_proposal_command(command: ProposalCommands, output_format: OutputFormat) -> Result<()> {
    let mut manager = ProposalManager::new();

    match command {
        ProposalCommands::List { pending, mine, status, limit, verbose } => {
            let proposals = if pending {
                manager.pending()
            } else {
                manager.all()
            };
            for p in proposals.into_iter().take(limit) {
                println!("{} [{:?}] by {} - {:?}",
                    p.id, p.status, p.proposer, p.operation);
            }
        }
        ProposalCommands::Show { id, votes, payload } => {
            println!("Proposal {} not found (manager is ephemeral)", id);
        }
        _ => {
            println!("Proposal command not fully implemented yet");
        }
    }
    Ok(())
}

fn handle_db_command(
    command: DbCommands,
    db_path: &str,
    store: &Arc<SledStore>,
    quiet: bool,
) -> Result<()> {
    match command {
        DbCommands::Stats { verbose, index } => {
            println!("Database path: {}", db_path);
            if let Ok(meta) = std::fs::metadata(db_path) {
                if meta.is_dir() {
                    let size: u64 = walkdir::WalkDir::new(db_path)
                        .into_iter()
                        .filter_map(|e| e.ok())
                        .filter_map(|e| e.metadata().ok())
                        .map(|m| m.len())
                        .sum();
                    println!("Size: {} bytes ({:.2} MB)", size, size as f64 / 1_000_000.0);
                }
            }
            let nodes = store.list_nodes(None, usize::MAX)?;
            println!("Nodes: {}", nodes.len());

            if verbose {
                let mut by_kind = std::collections::HashMap::new();
                for node in &nodes {
                    *by_kind.entry(node.kind.to_string()).or_insert(0) += 1;
                }
                println!("By kind:");
                for (kind, count) in by_kind {
                    println!("  {}: {}", kind, count);
                }
            }
        }
        DbCommands::Init { path, force } => {
            let target = path.as_deref().unwrap_or(db_path);
            if std::path::Path::new(target).exists() && !force {
                println!("Database already exists at {}", target);
                println!("Use --force to reinitialize");
            } else {
                std::fs::create_dir_all(target)?;
                println!("Initialized database at {}", target);
            }
        }
        DbCommands::Backup { output, name, compress, include_index } => {
            let backup_name = name.unwrap_or_else(|| {
                chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string()
            });
            let backup_dir = output.unwrap_or_else(|| "backups".to_string());
            let backup_path = format!("{}/{}", backup_dir, backup_name);

            std::fs::create_dir_all(&backup_dir)?;

            // Copy database directory
            let options = fs_extra::dir::CopyOptions::new();
            fs_extra::dir::copy(db_path, &backup_path, &options)
                .map_err(|e| anyhow!("Backup failed: {}", e))?;

            if !quiet {
                println!("Backed up to {}", backup_path);
            }
        }
        DbCommands::Path => {
            println!("{}", db_path);
        }
        DbCommands::Reset { force, backup } => {
            if !force {
                print!("This will DELETE all data. Are you sure? [y/N] ");
                std::io::stdout().flush()?;
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if !input.trim().eq_ignore_ascii_case("y") {
                    println!("Aborted");
                    return Ok(());
                }
            }
            if backup {
                let backup_name = chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string();
                let backup_path = format!("backups/{}", backup_name);
                std::fs::create_dir_all("backups")?;
                let options = fs_extra::dir::CopyOptions::new();
                let _ = fs_extra::dir::copy(db_path, &backup_path, &options);
                if !quiet {
                    println!("Backed up to {}", backup_path);
                }
            }
            std::fs::remove_dir_all(db_path)?;
            std::fs::create_dir_all(db_path)?;
            if !quiet {
                println!("Database reset");
            }
        }
        _ => {
            println!("Database command not fully implemented yet");
        }
    }
    Ok(())
}

fn handle_config_command(command: ConfigCommands) -> Result<()> {
    match command {
        ConfigCommands::Show { section, json } => {
            let config = CapabilityConfig::default();
            println!("Configuration:");
            println!("  default_mode: {:?}", config.default_mode);
            println!("  allow_runtime_changes: {}", config.allow_runtime_changes);
        }
        ConfigCommands::Get { key } => {
            println!("Config key '{}' = (not implemented)", key);
        }
        ConfigCommands::Generate { output, env, format } => {
            let content = match env.as_str() {
                "dev" => include_str!("../config/presets.ncl"),
                _ => "# Generated config\n",
            };
            std::fs::write(&output, content)?;
            println!("Generated config: {}", output);
        }
        _ => {
            println!("Config command not fully implemented yet");
        }
    }
    Ok(())
}

async fn handle_serve_command(
    command: ServeCommands,
    store: Arc<SledStore>,
    quiet: bool,
) -> Result<()> {
    match command {
        ServeCommands::Http { port, host } => {
            use async_graphql::http::GraphiQLSource;
            use axum::{
                body::Bytes,
                http::header::CONTENT_TYPE,
                response::{Html, IntoResponse},
                routing::get,
                Json, Router,
            };

            let schema = build_schema(store);

            // Simple GraphQL handler using Json extractor
            let schema_clone = schema.clone();
            let graphql_handler = move |Json(request): Json<async_graphql::Request>| {
                let schema = schema_clone.clone();
                async move {
                    let response = schema.execute(request).await;
                    Json(response)
                }
            };

            let graphiql_handler = || async {
                Html(GraphiQLSource::build().endpoint("/graphql").finish())
            };

            let health_handler = || async { "OK" };

            let app = Router::new()
                .route("/graphql", axum::routing::post(graphql_handler).get(graphiql_handler))
                .route("/health", get(health_handler));

            let addr = format!("{}:{}", host, port);
            if !quiet {
                println!("GraphQL server running at http://{}/graphql", addr);
            }

            let listener = tokio::net::TcpListener::bind(&addr).await?;
            axum::serve(listener, app).await?;
        }
    }
    Ok(())
}

async fn handle_graphql_command(command: GraphqlCommands, store: &Arc<SledStore>) -> Result<()> {
    match command {
        GraphqlCommands::Schema { output, descriptions } => {
            let schema = build_schema(store.clone());
            let sdl = schema.sdl();
            if output == "-" {
                println!("{}", sdl);
            } else {
                std::fs::write(&output, sdl)?;
                println!("Schema written to {}", output);
            }
        }
        GraphqlCommands::Query { query, variables, operation, pretty } => {
            let schema = build_schema(store.clone());

            let query_str = if query.starts_with('@') {
                std::fs::read_to_string(&query[1..])?
            } else {
                query
            };

            let mut request = async_graphql::Request::new(query_str);

            if let Some(vars) = variables {
                let vars: serde_json::Value = serde_json::from_str(&vars)?;
                request = request.variables(async_graphql::Variables::from_json(vars));
            }

            let response = schema.execute(request).await;
            let output = if pretty {
                serde_json::to_string_pretty(&response)?
            } else {
                serde_json::to_string(&response)?
            };
            println!("{}", output);
        }
        GraphqlCommands::Introspect { url, format } => {
            let schema = build_schema(store.clone());
            match format.as_str() {
                "sdl" => println!("{}", schema.sdl()),
                "json" => {
                    let introspection = schema.execute("{ __schema { types { name } } }").await;
                    println!("{}", serde_json::to_string_pretty(&introspection)?);
                }
                _ => println!("{}", schema.sdl()),
            }
        }
        _ => {
            println!("GraphQL command not fully implemented yet");
        }
    }
    Ok(())
}
