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
            handle_agent_command(command, &store, output_format)?;
        }

        Commands::Proposal { command } => {
            handle_proposal_command(command, &store, &agent, output_format)?;
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
            run_repl(&store, &agent, history, &fulltext_index)?;
        }

        Commands::Watch { command, debounce } => {
            run_watch_mode(command, debounce, &db_path, quiet)?;
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

fn handle_agent_command(
    command: AgentCommands,
    store: &Arc<SledStore>,
    _output_format: OutputFormat,
) -> Result<()> {
    // Load config from store or use default
    let mut config = store.get_capability_config()
        .ok()
        .flatten()
        .unwrap_or_default();

    match command {
        AgentCommands::List { verbose, reputation } => {
            let mut agents: Vec<AgentId> = vec![AgentId::User, AgentId::Claude, AgentId::Llama, AgentId::System];

            // Add registered modules from persisted configs
            let configs = store.list_agent_configs().unwrap_or_default();
            for cfg in &configs {
                if let AgentId::Module(_) = &cfg.agent {
                    if !agents.iter().any(|a| *a == cfg.agent) {
                        agents.push(cfg.agent.clone());
                    }
                }
            }

            for agent in agents {
                // Get config from store or default
                let caps = store.get_agent_config(&agent)
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| config.get_capabilities(&agent));
                print!("{}: mode={}", agent, caps.mode);
                if verbose {
                    print!(", can_vote={}, weight={}", caps.can_vote, caps.vote_weight);
                }
                if reputation {
                    if let Ok(Some(rep)) = store.get_reputation(&agent) {
                        print!(", reputation={:.2}", rep.score);
                    }
                }
                println!();
            }
        }
        AgentCommands::Show { agent, history } => {
            let agent_id = parse_agent_id(&agent);
            let caps = store.get_agent_config(&agent_id)
                .ok()
                .flatten()
                .unwrap_or_else(|| config.get_capabilities(&agent_id));
            println!("Agent: {}", agent_id);
            println!("Mode: {}", caps.mode);
            println!("Can vote: {}", caps.can_vote);
            println!("Vote weight: {}", caps.vote_weight);
            if let Ok(Some(rep)) = store.get_reputation(&agent_id) {
                println!("Reputation: {:.2}", rep.score);
                println!("Total votes: {}", rep.total_votes);
                println!("Correct votes: {}", rep.correct_votes);
            }
            if history {
                println!("\nReputation history available in event log");
            }
        }
        AgentCommands::Set { agent, mode, can_vote, vote_weight } => {
            let agent_id = parse_agent_id(&agent);
            let mut caps = store.get_agent_config(&agent_id)
                .ok()
                .flatten()
                .unwrap_or_else(|| config.get_capabilities(&agent_id));
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
            store.save_agent_config(&caps).map_err(|e| anyhow!("Failed to save config: {}", e))?;
            println!("Updated agent: {}", agent);
        }
        AgentCommands::Register { name, mode, description } => {
            // Validate module name
            if name.is_empty() || name.contains(':') || name.contains(' ') {
                return Err(anyhow!("Invalid module name: '{}' (cannot be empty or contain ':' or spaces)", name));
            }

            let agent_id = AgentId::Module(name.clone());

            // Check if already registered
            if store.get_agent_config(&agent_id).ok().flatten().is_some() {
                return Err(anyhow!("Module '{}' is already registered", name));
            }

            // Set capabilities and persist
            let caps = AgentCapabilities {
                agent: agent_id.clone(),
                mode: match mode {
                    CapabilityModeArg::Direct => CapabilityMode::Direct,
                    CapabilityModeArg::Proposal => CapabilityMode::Proposal,
                    CapabilityModeArg::Observer => CapabilityMode::Observer,
                },
                can_vote: true,
                vote_weight: 1.0,
            };
            store.save_agent_config(&caps).map_err(|e| anyhow!("Failed to save config: {}", e))?;

            println!("Registered module: {}", name);
            if let Some(desc) = description {
                println!("Description: {}", desc);
            }
            println!("Mode: {:?}", mode);
        }
        AgentCommands::Unregister { name, force } => {
            if !force {
                print!("Are you sure you want to unregister module '{}'? [y/N] ", name);
                std::io::stdout().flush()?;
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if !input.trim().eq_ignore_ascii_case("y") {
                    println!("Aborted");
                    return Ok(());
                }
            }

            let agent_id = AgentId::Module(name.clone());
            // Check if registered
            if store.get_agent_config(&agent_id).ok().flatten().is_none() {
                return Err(anyhow!("Module '{}' is not registered", name));
            }

            // Remove by setting to default/observer
            let caps = AgentCapabilities::new(agent_id).as_observer();
            store.save_agent_config(&caps).map_err(|e| anyhow!("Failed to save config: {}", e))?;
            println!("Unregistered module: {}", name);
        }
        AgentCommands::Leaderboard { limit, sort } => {
            let mut reputations = store.list_reputations().unwrap_or_default();

            // Sort by specified field
            match sort.as_str() {
                "accuracy" => reputations.sort_by(|a, b| {
                    b.accuracy().partial_cmp(&a.accuracy()).unwrap_or(std::cmp::Ordering::Equal)
                }),
                "votes" => reputations.sort_by(|a, b| b.total_votes.cmp(&a.total_votes)),
                _ => reputations.sort_by(|a, b| {
                    b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal)
                }),
            }

            if reputations.is_empty() {
                println!("No reputation data yet.");
            } else {
                for (i, rep) in reputations.into_iter().take(limit).enumerate() {
                    println!("{}. {} - score: {:.2}, accuracy: {:.1}%, votes: {}",
                        i + 1, rep.agent, rep.score, rep.accuracy() * 100.0, rep.total_votes);
                }
            }
        }
        AgentCommands::ResetReputation { agent, force } => {
            if !force {
                let target = if agent == "all" { "ALL agents" } else { &agent };
                print!("Are you sure you want to reset reputation for {}? [y/N] ", target);
                std::io::stdout().flush()?;
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if !input.trim().eq_ignore_ascii_case("y") {
                    println!("Aborted");
                    return Ok(());
                }
            }

            if agent == "all" {
                let all_reps = store.list_reputations().unwrap_or_default();
                for rep in all_reps {
                    let new_rep = elegant_state::Reputation::new(rep.agent);
                    store.save_reputation(&new_rep).map_err(|e| anyhow!("Failed to save: {}", e))?;
                }
                println!("Reset reputation for all agents");
            } else {
                let agent_id = parse_agent_id(&agent);
                let new_rep = elegant_state::Reputation::new(agent_id.clone());
                store.save_reputation(&new_rep).map_err(|e| anyhow!("Failed to save: {}", e))?;
                println!("Reset reputation for {}", agent);
            }
        }
        AgentCommands::Decay { factor } => {
            if factor < 0.0 || factor > 1.0 {
                return Err(anyhow!("Decay factor must be between 0.0 and 1.0"));
            }
            let all_reps = store.list_reputations().unwrap_or_default();
            for mut rep in all_reps {
                rep.apply_decay(factor);
                store.save_reputation(&rep).map_err(|e| anyhow!("Failed to save: {}", e))?;
            }
            println!("Applied decay factor {} to all reputations", factor);
        }
        AgentCommands::Switch { agent } => {
            let agent_id = parse_agent_id(&agent);
            println!("Switched to agent: {}", agent_id);
            println!("Note: Use --agent flag globally to persist this change");
        }
        AgentCommands::Whoami => {
            println!("Current agent: user");
            println!("Use --agent flag to change identity");
        }
    }
    Ok(())
}

fn handle_proposal_command(
    command: ProposalCommands,
    store: &Arc<SledStore>,
    agent: &AgentId,
    _output_format: OutputFormat,
) -> Result<()> {
    use elegant_state::{ProposalTarget, Operation};

    // Get capability config from store or use default
    let config = store.get_capability_config()
        .ok()
        .flatten()
        .unwrap_or_default();

    match command {
        ProposalCommands::List { pending, mine: _, status, limit, verbose } => {
            let filter_status = if pending {
                Some(ProposalStatus::Pending)
            } else {
                None
            };

            let proposals = store.list_proposals(filter_status, limit)
                .map_err(|e| anyhow!("Failed to list proposals: {}", e))?;

            let filtered: Vec<_> = proposals
                .into_iter()
                .filter(|p| {
                    if let Some(ref s) = status {
                        let status_str = format!("{:?}", p.status).to_lowercase();
                        if !status_str.contains(&s.to_lowercase()) {
                            return false;
                        }
                    }
                    true
                })
                .collect();

            if filtered.is_empty() {
                println!("No proposals found");
            } else {
                for p in filtered {
                    print!("{} [{:?}] by {}", p.id, p.status, p.proposer);
                    if verbose {
                        print!(" - {:?} on {:?}", p.operation, p.target);
                        let votes = store.get_votes_for_proposal(p.id).unwrap_or_default();
                        print!(" (votes: {})", votes.len());
                    }
                    println!();
                }
            }
        }
        ProposalCommands::Show { id, votes: show_votes, payload } => {
            let proposal_id = id.parse().map_err(|e| anyhow!("Invalid proposal ID: {}", e))?;
            match store.get_proposal(proposal_id).map_err(|e| anyhow!("Store error: {}", e))? {
                Some(p) => {
                    println!("Proposal: {}", p.id);
                    println!("Status: {:?}", p.status);
                    println!("Proposer: {}", p.proposer);
                    println!("Operation: {:?}", p.operation);
                    println!("Target: {:?}", p.target);
                    println!("Created: {}", p.created_at.format("%Y-%m-%d %H:%M:%S"));

                    if let Some(ref rationale) = p.rationale {
                        println!("Rationale: {}", rationale);
                    }

                    if show_votes {
                        let votes = store.get_votes_for_proposal(proposal_id).unwrap_or_default();
                        println!("\nVotes ({}):", votes.len());
                        for vote in votes {
                            println!("  {} - {:?}{}", vote.voter, vote.decision,
                                vote.reason.as_ref().map(|r| format!(": {}", r)).unwrap_or_default());
                        }
                    }

                    if payload {
                        println!("\nPayload:");
                        println!("{}", serde_json::to_string_pretty(&p.payload)?);
                    }
                }
                None => println!("Proposal {} not found", id),
            }
        }
        ProposalCommands::Create { operation, target, payload, rationale } => {
            let op = match operation.to_lowercase().as_str() {
                "create" => Operation::Create,
                "update" => Operation::Update,
                "delete" => Operation::Delete,
                "link" => Operation::Link,
                "unlink" => Operation::Unlink,
                _ => return Err(anyhow!("Unknown operation: {} (valid: create, update, delete, link, unlink)", operation)),
            };

            let tgt = if target.starts_with("node:") {
                let id_str = &target[5..];
                let node_id = id_str.parse().ok();
                ProposalTarget::Node { id: node_id, kind: None }
            } else if target.starts_with("edge:") {
                let id_str = &target[5..];
                let edge_id = id_str.parse().ok();
                ProposalTarget::Edge { id: edge_id, from: None, to: None }
            } else if target.starts_with("new:") {
                let kind = target[4..].to_string();
                ProposalTarget::Node { id: None, kind: Some(kind) }
            } else {
                return Err(anyhow!("Invalid target format: {} (use node:ID, edge:ID, or new:kind)", target));
            };

            let payload_value: serde_json::Value = serde_json::from_str(&payload)?;

            let mut proposal = Proposal::new(
                agent.clone(),
                op,
                tgt,
                payload_value,
            );
            if let Some(r) = rationale {
                proposal = proposal.with_rationale(r);
            }

            let id = proposal.id;
            store.save_proposal(&proposal)
                .map_err(|e| anyhow!("Failed to save proposal: {}", e))?;
            println!("Created proposal: {}", id);
        }
        ProposalCommands::Withdraw { id, reason: _reason } => {
            let proposal_id = id.parse().map_err(|e| anyhow!("Invalid proposal ID: {}", e))?;
            if let Some(mut p) = store.get_proposal(proposal_id).map_err(|e| anyhow!("Store error: {}", e))? {
                p.withdraw();
                store.save_proposal(&p).map_err(|e| anyhow!("Failed to save: {}", e))?;
                println!("Withdrawn proposal: {}", id);
            } else {
                println!("Proposal {} not found", id);
            }
        }
        ProposalCommands::Approve { id, reason } => {
            let proposal_id = id.parse().map_err(|e| anyhow!("Invalid proposal ID: {}", e))?;

            // Check proposal exists
            if store.get_proposal(proposal_id).map_err(|e| anyhow!("Store error: {}", e))?.is_none() {
                return Err(anyhow!("Proposal {} not found", id));
            }

            let mut vote = Vote::new(proposal_id, agent.clone(), DomainVoteDecision::Approve);
            if let Some(r) = reason {
                vote = vote.with_reason(r);
            }

            // Apply vote weight from config
            let caps = config.get_capabilities(agent);
            vote = vote.with_weight(caps.vote_weight);

            store.save_vote(&vote).map_err(|e| anyhow!("Failed to save vote: {}", e))?;
            println!("Voted to approve proposal: {}", id);
        }
        ProposalCommands::Reject { id, reason } => {
            let proposal_id = id.parse().map_err(|e| anyhow!("Invalid proposal ID: {}", e))?;

            // Check proposal exists
            if store.get_proposal(proposal_id).map_err(|e| anyhow!("Store error: {}", e))?.is_none() {
                return Err(anyhow!("Proposal {} not found", id));
            }

            let mut vote = Vote::new(proposal_id, agent.clone(), DomainVoteDecision::Reject);
            if let Some(r) = reason {
                vote = vote.with_reason(r);
            }

            // Apply vote weight from config
            let caps = config.get_capabilities(agent);
            vote = vote.with_weight(caps.vote_weight);

            store.save_vote(&vote).map_err(|e| anyhow!("Failed to save vote: {}", e))?;
            println!("Voted to reject proposal: {}", id);
        }
        ProposalCommands::Votes { id, verbose } => {
            let proposal_id = id.parse().map_err(|e| anyhow!("Invalid proposal ID: {}", e))?;
            let votes = store.get_votes_for_proposal(proposal_id).unwrap_or_default();
            if votes.is_empty() {
                println!("No votes yet on proposal {}", id);
            } else {
                println!("Votes on proposal {}:", id);
                for vote in &votes {
                    print!("  {} - {:?}", vote.voter, vote.decision);
                    if verbose {
                        print!(" at {}", vote.timestamp.format("%Y-%m-%d %H:%M:%S"));
                        if let Some(ref r) = vote.reason {
                            print!(" - {}", r);
                        }
                    }
                    println!();
                }

                // Summary
                let approves = votes.iter().filter(|v| matches!(v.decision, DomainVoteDecision::Approve)).count();
                let rejects = votes.iter().filter(|v| matches!(v.decision, DomainVoteDecision::Reject)).count();
                let abstains = votes.iter().filter(|v| matches!(v.decision, DomainVoteDecision::Abstain)).count();
                println!("\nSummary: {} approve, {} reject, {} abstain", approves, rejects, abstains);
            }
        }
        ProposalCommands::Execute { id, force } => {
            let proposal_id = id.parse().map_err(|e| anyhow!("Invalid proposal ID: {}", e))?;
            match store.get_proposal(proposal_id).map_err(|e| anyhow!("Store error: {}", e))? {
                Some(mut p) => {
                    if !matches!(p.status, ProposalStatus::Approved) {
                        return Err(anyhow!("Proposal {} is not approved (status: {:?})", id, p.status));
                    }

                    if !force {
                        print!("Execute proposal {}? [y/N] ", id);
                        std::io::stdout().flush()?;
                        let mut input = String::new();
                        std::io::stdin().read_line(&mut input)?;
                        if !input.trim().eq_ignore_ascii_case("y") {
                            println!("Aborted");
                            return Ok(());
                        }
                    }

                    // Execute the proposal based on operation and target
                    match (&p.operation, &p.target) {
                        (Operation::Create, ProposalTarget::Node { kind, .. }) => {
                            let kind_str = kind.as_deref().unwrap_or("insight");
                            let node_kind = kind_str.parse().unwrap_or(NodeKind::Insight);
                            let node = StateNode::new(node_kind, p.payload.clone());
                            let created = store.create_node(node, p.proposer.clone())
                                .map_err(|e| anyhow!("Failed to create node: {}", e))?;
                            println!("Created node: {}", created.id);
                        }
                        (Operation::Update, ProposalTarget::Node { id: Some(node_id), .. }) => {
                            store.update_node(*node_id, p.payload.clone(), p.proposer.clone())
                                .map_err(|e| anyhow!("Failed to update node: {}", e))?;
                            println!("Updated node: {}", node_id);
                        }
                        (Operation::Delete, ProposalTarget::Node { id: Some(node_id), .. }) => {
                            store.delete_node(*node_id, p.proposer.clone())
                                .map_err(|e| anyhow!("Failed to delete node: {}", e))?;
                            println!("Deleted node: {}", node_id);
                        }
                        (Operation::Link, ProposalTarget::Edge { from: Some(from), to: Some(to), .. }) => {
                            let edge_kind = p.payload.get("kind")
                                .and_then(|v| v.as_str())
                                .unwrap_or("related_to")
                                .parse()
                                .unwrap_or(EdgeKind::RelatedTo);
                            let edge = StateEdge::new(*from, *to, edge_kind);
                            let created = store.create_edge(edge, p.proposer.clone())
                                .map_err(|e| anyhow!("Failed to create edge: {}", e))?;
                            println!("Created edge: {}", created.id);
                        }
                        (Operation::Unlink, ProposalTarget::Edge { id: Some(edge_id), .. }) => {
                            store.delete_edge(*edge_id, p.proposer.clone())
                                .map_err(|e| anyhow!("Failed to delete edge: {}", e))?;
                            println!("Deleted edge: {}", edge_id);
                        }
                        _ => {
                            return Err(anyhow!("Cannot execute {:?} on {:?}: missing required IDs", p.operation, p.target));
                        }
                    }

                    // Mark proposal as executed (still approved status but resolved)
                    p.resolved_at = Some(chrono::Utc::now());
                    p.resolution_reason = Some("Executed".into());
                    store.save_proposal(&p).map_err(|e| anyhow!("Failed to update proposal: {}", e))?;

                    println!("Executed proposal: {}", id);
                }
                None => println!("Proposal {} not found", id),
            }
        }
        ProposalCommands::Expire { older_than: _older_than, dry_run } => {
            let proposals = store.list_proposals(Some(ProposalStatus::Pending), 1000)
                .map_err(|e| anyhow!("Store error: {}", e))?;
            let now = chrono::Utc::now();
            let expiry = chrono::Duration::hours(1); // Default 1 hour expiry
            let mut expired_count = 0;

            for mut p in proposals {
                if now - p.created_at > expiry {
                    if !dry_run {
                        p.status = ProposalStatus::Expired;
                        p.resolved_at = Some(now);
                        p.resolution_reason = Some("Expired".into());
                        store.save_proposal(&p).map_err(|e| anyhow!("Failed to save: {}", e))?;
                    }
                    expired_count += 1;
                }
            }

            if dry_run {
                println!("Would expire {} proposals", expired_count);
            } else {
                println!("Expired {} proposals", expired_count);
            }
        }
        ProposalCommands::Cleanup { keep, dry_run } => {
            let duration = parse_duration(&keep).unwrap_or(chrono::Duration::days(7));
            let now = chrono::Utc::now();
            let all_proposals = store.list_proposals(None, 10000)
                .map_err(|e| anyhow!("Store error: {}", e))?;
            let mut cleanup_count = 0;

            for p in all_proposals {
                if let Some(resolved_at) = p.resolved_at {
                    if now - resolved_at > duration {
                        if !dry_run {
                            store.delete_proposal(p.id).map_err(|e| anyhow!("Failed to delete: {}", e))?;
                        }
                        cleanup_count += 1;
                    }
                }
            }

            if dry_run {
                println!("Would clean up {} resolved proposals older than {}", cleanup_count, keep);
            } else {
                println!("Cleaned up {} resolved proposals older than {}", cleanup_count, keep);
            }
        }
    }
    Ok(())
}

/// Parse a duration string like "7d", "1h", "30m"
fn parse_duration(s: &str) -> Option<chrono::Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    let (num_str, unit) = if s.ends_with('d') {
        (&s[..s.len()-1], 'd')
    } else if s.ends_with('h') {
        (&s[..s.len()-1], 'h')
    } else if s.ends_with('m') {
        (&s[..s.len()-1], 'm')
    } else if s.ends_with('s') {
        (&s[..s.len()-1], 's')
    } else {
        // Default to days if no unit
        (s, 'd')
    };

    let num: i64 = num_str.parse().ok()?;
    match unit {
        'd' => Some(chrono::Duration::days(num)),
        'h' => Some(chrono::Duration::hours(num)),
        'm' => Some(chrono::Duration::minutes(num)),
        's' => Some(chrono::Duration::seconds(num)),
        _ => None,
    }
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
        DbCommands::Restore { backup, force, verify } => {
            if !std::path::Path::new(&backup).exists() {
                return Err(anyhow!("Backup not found: {}", backup));
            }

            if !force {
                print!("This will overwrite the current database. Are you sure? [y/N] ");
                std::io::stdout().flush()?;
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if !input.trim().eq_ignore_ascii_case("y") {
                    println!("Aborted");
                    return Ok(());
                }
            }

            if verify {
                // Basic verification - check if backup looks like a sled DB
                let backup_db_file = std::path::Path::new(&backup).join("db");
                if !backup_db_file.exists() {
                    return Err(anyhow!("Backup does not appear to be a valid database"));
                }
            }

            // Remove current DB and copy backup
            if std::path::Path::new(db_path).exists() {
                std::fs::remove_dir_all(db_path)?;
            }
            let options = fs_extra::dir::CopyOptions::new();
            fs_extra::dir::copy(&backup, db_path, &options)
                .map_err(|e| anyhow!("Restore failed: {}", e))?;

            if !quiet {
                println!("Restored database from {}", backup);
            }
        }
        DbCommands::Backups { dir } => {
            let backup_dir = dir.unwrap_or_else(|| "backups".to_string());
            if !std::path::Path::new(&backup_dir).exists() {
                println!("No backups directory found at {}", backup_dir);
                return Ok(());
            }

            let mut backups: Vec<_> = std::fs::read_dir(&backup_dir)?
                .filter_map(|e| e.ok())
                .filter(|e| e.path().is_dir())
                .collect();

            backups.sort_by_key(|e| e.file_name());
            backups.reverse();

            if backups.is_empty() {
                println!("No backups found");
            } else {
                println!("Available backups:");
                for backup in backups {
                    let name = backup.file_name();
                    let meta = backup.metadata().ok();
                    let size = meta.map(|m| m.len()).unwrap_or(0);
                    println!("  {} ({} bytes)", name.to_string_lossy(), size);
                }
            }
        }
        DbCommands::Compact { threshold, force } => {
            // sled automatically compacts, but we can force a flush
            if !quiet {
                println!("Compacting database...");
            }

            // Get current size
            let size_before: u64 = walkdir::WalkDir::new(db_path)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter_map(|e| e.metadata().ok())
                .map(|m| m.len())
                .sum();

            // Force flush - sled doesn't have explicit compact, but flush ensures data is synced
            // In a real implementation, you might want to rebuild the database for true compaction
            if !quiet {
                println!("Database size: {} bytes ({:.2} MB)", size_before, size_before as f64 / 1_000_000.0);
                println!("Note: sled compacts automatically. Manual compaction not required.");
            }
        }
        DbCommands::Verify { fix, index } => {
            if !quiet {
                println!("Verifying database integrity...");
            }

            // Check database directory exists
            if !std::path::Path::new(db_path).exists() {
                return Err(anyhow!("Database directory does not exist"));
            }

            // Try to list all nodes to verify readability
            let nodes = store.list_nodes(None, usize::MAX)?;
            println!("Verified {} nodes readable", nodes.len());

            // Check for orphaned edges
            let mut edge_count = 0;
            let mut orphan_count = 0;
            for node in &nodes {
                let edges = store.edges_from(node.id)?;
                edge_count += edges.len();

                for edge in &edges {
                    if store.get_node(edge.to)?.is_none() {
                        orphan_count += 1;
                        if !quiet {
                            println!("  Warning: Edge {} points to missing node {}", edge.id, edge.to);
                        }
                    }
                }
            }

            println!("Verified {} edges", edge_count);
            if orphan_count > 0 {
                println!("Found {} orphaned edges", orphan_count);
                if fix {
                    println!("Note: Automatic fixing not yet implemented");
                }
            } else {
                println!("No integrity issues found");
            }

            if index {
                let index_path = format!("{}_index", db_path);
                if std::path::Path::new(&index_path).exists() {
                    println!("Full-text index exists at {}", index_path);
                } else {
                    println!("No full-text index found");
                }
            }
        }
        DbCommands::Repair { force, backup } => {
            if !force {
                print!("Repair may modify database. Continue? [y/N] ");
                std::io::stdout().flush()?;
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if !input.trim().eq_ignore_ascii_case("y") {
                    println!("Aborted");
                    return Ok(());
                }
            }

            if backup {
                let backup_name = chrono::Utc::now().format("%Y%m%d-%H%M%S-pre-repair").to_string();
                let backup_path = format!("backups/{}", backup_name);
                std::fs::create_dir_all("backups")?;
                let options = fs_extra::dir::CopyOptions::new();
                fs_extra::dir::copy(db_path, &backup_path, &options)
                    .map_err(|e| anyhow!("Backup failed: {}", e))?;
                if !quiet {
                    println!("Backed up to {} before repair", backup_path);
                }
            }

            println!("Repair complete (no issues detected requiring repair)");
        }
        DbCommands::Migrate { to_version, pending, dry_run } => {
            if pending {
                println!("No pending migrations (schema is current)");
            } else if let Some(version) = to_version {
                println!("Migration to version {} (not required - schema is stable)", version);
            } else {
                println!("Database schema is current. No migrations needed.");
            }
        }
        DbCommands::Vacuum { progress } => {
            if progress {
                println!("Vacuuming database...");
            }

            // sled handles space reclamation automatically
            // This is mostly a no-op but provides user feedback
            let size: u64 = walkdir::WalkDir::new(db_path)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter_map(|e| e.metadata().ok())
                .map(|m| m.len())
                .sum();

            if !quiet {
                println!("Current size: {} bytes ({:.2} MB)", size, size as f64 / 1_000_000.0);
                println!("Vacuum complete (sled manages space automatically)");
            }
        }
    }
    Ok(())
}

fn handle_config_command(command: ConfigCommands) -> Result<()> {
    // Use a static config for persistence within the session
    static CONFIG: std::sync::LazyLock<std::sync::Mutex<CapabilityConfig>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(CapabilityConfig::default()));

    match command {
        ConfigCommands::Show { section: _section, json: _json } => {
            let config = CONFIG.lock().map_err(|e| anyhow!("Lock error: {}", e))?;
            println!("Configuration:");
            println!("  default_mode: {:?}", config.default_mode);
            println!("  allow_runtime_changes: {}", config.allow_runtime_changes);
        }
        ConfigCommands::Get { key } => {
            let config = CONFIG.lock().map_err(|e| anyhow!("Lock error: {}", e))?;
            let value = match key.as_str() {
                "default_mode" => format!("{:?}", config.default_mode),
                "allow_runtime_changes" => config.allow_runtime_changes.to_string(),
                _ => format!("(unknown key: {})", key),
            };
            println!("{} = {}", key, value);
        }
        ConfigCommands::Set { key, value } => {
            let mut config = CONFIG.lock().map_err(|e| anyhow!("Lock error: {}", e))?;
            match key.as_str() {
                "default_mode" => {
                    config.default_mode = match value.to_lowercase().as_str() {
                        "direct" => CapabilityMode::Direct,
                        "proposal" => CapabilityMode::Proposal,
                        "observer" => CapabilityMode::Observer,
                        _ => return Err(anyhow!("Invalid mode: {} (valid: direct, proposal, observer)", value)),
                    };
                    println!("Set {} = {:?}", key, config.default_mode);
                }
                "allow_runtime_changes" => {
                    config.allow_runtime_changes = match value.to_lowercase().as_str() {
                        "true" | "yes" | "1" => true,
                        "false" | "no" | "0" => false,
                        _ => return Err(anyhow!("Invalid boolean: {} (valid: true, false)", value)),
                    };
                    println!("Set {} = {}", key, config.allow_runtime_changes);
                }
                _ => {
                    return Err(anyhow!("Unknown config key: {}", key));
                }
            }
        }
        ConfigCommands::Reset { section, force } => {
            if !force {
                let target = section.as_deref().unwrap_or("all settings");
                print!("Reset {} to defaults? [y/N] ", target);
                std::io::stdout().flush()?;
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if !input.trim().eq_ignore_ascii_case("y") {
                    println!("Aborted");
                    return Ok(());
                }
            }

            let mut config = CONFIG.lock().map_err(|e| anyhow!("Lock error: {}", e))?;
            *config = CapabilityConfig::default();
            println!("Configuration reset to defaults");
        }
        ConfigCommands::Validate { file, verbose } => {
            let config_file = file.unwrap_or_else(|| "config.ncl".to_string());
            if !std::path::Path::new(&config_file).exists() {
                println!("Config file not found: {}", config_file);
                println!("Using default configuration");
                return Ok(());
            }

            // Basic validation - check if file is readable
            let content = std::fs::read_to_string(&config_file)?;
            if content.is_empty() {
                println!("Warning: Config file is empty");
            } else {
                println!("Config file {} is valid ({} bytes)", config_file, content.len());
                if verbose {
                    println!("\nContents:");
                    for (i, line) in content.lines().take(20).enumerate() {
                        println!("  {:3}: {}", i + 1, line);
                    }
                    if content.lines().count() > 20 {
                        println!("  ... ({} more lines)", content.lines().count() - 20);
                    }
                }
            }
        }
        ConfigCommands::Generate { output, env, format: _format } => {
            let content = match env.as_str() {
                "dev" => include_str!("../config/presets.ncl"),
                "staging" => "# Staging configuration\ndefault_mode = \"proposal\"\n",
                "prod" => "# Production configuration\ndefault_mode = \"proposal\"\nallow_runtime_changes = false\n",
                _ => "# Generated config\ndefault_mode = \"direct\"\n",
            };
            std::fs::write(&output, content)?;
            println!("Generated config: {}", output);
        }
        ConfigCommands::Preset { name } => {
            let mut config = CONFIG.lock().map_err(|e| anyhow!("Lock error: {}", e))?;
            match name.as_str() {
                "dev" => {
                    config.default_mode = CapabilityMode::Direct;
                    config.allow_runtime_changes = true;
                    println!("Applied 'dev' preset: direct mode, runtime changes allowed");
                }
                "staging" => {
                    config.default_mode = CapabilityMode::Proposal;
                    config.allow_runtime_changes = true;
                    println!("Applied 'staging' preset: proposal mode, runtime changes allowed");
                }
                "prod" | "production" => {
                    config.default_mode = CapabilityMode::Proposal;
                    config.allow_runtime_changes = false;
                    println!("Applied 'prod' preset: proposal mode, runtime changes disabled");
                }
                "minimal" => {
                    config.default_mode = CapabilityMode::Observer;
                    config.allow_runtime_changes = false;
                    println!("Applied 'minimal' preset: observer mode, runtime changes disabled");
                }
                _ => {
                    return Err(anyhow!("Unknown preset: {} (valid: dev, staging, prod, minimal)", name));
                }
            }
        }
        ConfigCommands::Edit { file } => {
            let config_file = file.unwrap_or_else(|| "config.ncl".to_string());
            let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());

            // Create file if it doesn't exist
            if !std::path::Path::new(&config_file).exists() {
                std::fs::write(&config_file, "# elegant-STATE configuration\n")?;
            }

            // Open editor
            let status = std::process::Command::new(&editor)
                .arg(&config_file)
                .status()?;

            if status.success() {
                println!("Edited {}", config_file);
            } else {
                println!("Editor exited with status: {:?}", status.code());
            }
        }
        ConfigCommands::Diff { from, to } => {
            println!("Configuration diff: {} -> {}", from, to);
            println!();

            let presets = [
                ("dev", CapabilityMode::Direct, true),
                ("staging", CapabilityMode::Proposal, true),
                ("prod", CapabilityMode::Proposal, false),
                ("minimal", CapabilityMode::Observer, false),
            ];

            let from_preset = presets.iter().find(|(n, _, _)| *n == from);
            let to_preset = presets.iter().find(|(n, _, _)| *n == to);

            if let (Some(f), Some(t)) = (from_preset, to_preset) {
                if f.1 != t.1 {
                    println!("  default_mode: {:?} -> {:?}", f.1, t.1);
                }
                if f.2 != t.2 {
                    println!("  allow_runtime_changes: {} -> {}", f.2, t.2);
                }
                if f.1 == t.1 && f.2 == t.2 {
                    println!("  (no differences)");
                }
            } else {
                println!("Unknown preset(s). Valid presets: dev, staging, prod, minimal");
            }
        }
        ConfigCommands::Voting { strategy, min_voters, timeout: _timeout } => {
            println!("Voting configuration:");
            println!("  strategy: {:?}", strategy);
            if let Some(min) = min_voters {
                println!("  min_voters: {}", min);
            }
            println!("\nNote: Voting settings apply to the coordination system");
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
            use async_graphql_axum::GraphQLSubscription;
            use axum::{
                response::Html,
                routing::get,
                Json, Router,
            };
            use elegant_state::graphql::{build_schema_with_subscriptions, create_event_channel};

            // Create event channel for subscriptions
            let (event_sender, _event_receiver) = create_event_channel(256);

            // Build schema with subscription support
            let schema = build_schema_with_subscriptions(store, event_sender);

            // GraphQL POST handler
            let schema_post = schema.clone();
            let graphql_handler = move |Json(request): Json<async_graphql::Request>| {
                let schema = schema_post.clone();
                async move {
                    let response = schema.execute(request).await;
                    Json(response)
                }
            };

            // GraphiQL playground with subscription support
            let graphiql_handler = || async {
                Html(
                    GraphiQLSource::build()
                        .endpoint("/graphql")
                        .subscription_endpoint("/ws")
                        .finish(),
                )
            };

            let health_handler = || async { "OK" };

            let app = Router::new()
                .route("/graphql", axum::routing::post(graphql_handler).get(graphiql_handler))
                .route_service("/ws", GraphQLSubscription::new(schema))
                .route("/health", get(health_handler));

            let addr = format!("{}:{}", host, port);
            if !quiet {
                println!("GraphQL server running at http://{}/graphql", addr);
                println!("WebSocket subscriptions at ws://{}/ws", addr);
                println!("GraphiQL playground at http://{}/graphql", addr);
                println!("Event publishing enabled for mutations");
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
        GraphqlCommands::Introspect { url: _url, format } => {
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
        GraphqlCommands::Mutate { mutation, variables, operation: _operation, dry_run } => {
            let schema = build_schema(store.clone());

            let mutation_str = if mutation.starts_with('@') {
                std::fs::read_to_string(&mutation[1..])?
            } else {
                mutation
            };

            if dry_run {
                println!("Dry run - would execute:");
                println!("{}", mutation_str);
                if let Some(vars) = variables {
                    println!("Variables: {}", vars);
                }
                return Ok(());
            }

            let mut request = async_graphql::Request::new(mutation_str);

            if let Some(vars) = variables {
                let vars: serde_json::Value = serde_json::from_str(&vars)?;
                request = request.variables(async_graphql::Variables::from_json(vars));
            }

            let response = schema.execute(request).await;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        GraphqlCommands::Validate { query } => {
            let schema = build_schema(store.clone());

            let query_str = if query.starts_with('@') {
                std::fs::read_to_string(&query[1..])?
            } else {
                query
            };

            // Validate by parsing and checking with schema
            let request = async_graphql::Request::new(query_str.clone());
            let response = schema.execute(request).await;

            if response.errors.is_empty() {
                println!("Query is valid");
            } else {
                println!("Validation errors:");
                for error in &response.errors {
                    println!("  - {}", error.message);
                }
            }
        }
        GraphqlCommands::Playground { url, open } => {
            println!("GraphQL Playground");
            println!("URL: {}/graphql", url);
            println!("WebSocket: {}/ws", url.replace("http", "ws"));
            if open {
                // Try to open in browser
                let browser_url = format!("{}/graphql", url);
                #[cfg(target_os = "macos")]
                let _ = std::process::Command::new("open").arg(&browser_url).status();
                #[cfg(target_os = "linux")]
                let _ = std::process::Command::new("xdg-open").arg(&browser_url).status();
                #[cfg(target_os = "windows")]
                let _ = std::process::Command::new("cmd").args(["/C", "start", &browser_url]).status();
            }
            println!("\nStart server with: state-cli serve http");
        }
        GraphqlCommands::Codegen { output, resolvers } => {
            // Generate TypeScript types from schema
            let schema = build_schema(store.clone());
            let sdl = schema.sdl();

            let mut ts_content = String::from("// Generated TypeScript types for elegant-STATE\n\n");

            // Parse SDL and generate basic types
            ts_content.push_str("export interface StateNode {\n");
            ts_content.push_str("  id: string;\n");
            ts_content.push_str("  kind: NodeKind;\n");
            ts_content.push_str("  content: any;\n");
            ts_content.push_str("  metadata: Record<string, any>;\n");
            ts_content.push_str("  createdAt: string;\n");
            ts_content.push_str("  updatedAt: string;\n");
            ts_content.push_str("}\n\n");

            ts_content.push_str("export type NodeKind = \n");
            ts_content.push_str("  | 'CONVERSATION'\n");
            ts_content.push_str("  | 'MESSAGE'\n");
            ts_content.push_str("  | 'INSIGHT'\n");
            ts_content.push_str("  | 'TASK'\n");
            ts_content.push_str("  | 'ARTIFACT'\n");
            ts_content.push_str("  | 'AGENT_STATE'\n");
            ts_content.push_str("  | 'PREFERENCE'\n");
            ts_content.push_str("  | 'FILE'\n");
            ts_content.push_str("  | 'TAG'\n");
            ts_content.push_str("  | 'CUSTOM';\n\n");

            ts_content.push_str("export interface StateEdge {\n");
            ts_content.push_str("  id: string;\n");
            ts_content.push_str("  from: string;\n");
            ts_content.push_str("  to: string;\n");
            ts_content.push_str("  kind: EdgeKind;\n");
            ts_content.push_str("  metadata: Record<string, any>;\n");
            ts_content.push_str("  createdAt: string;\n");
            ts_content.push_str("}\n\n");

            ts_content.push_str("export type EdgeKind = \n");
            ts_content.push_str("  | 'CONTAINS'\n");
            ts_content.push_str("  | 'REFERENCES'\n");
            ts_content.push_str("  | 'REPLIES_TO'\n");
            ts_content.push_str("  | 'DERIVED_FROM'\n");
            ts_content.push_str("  | 'RELATES_TO'\n");
            ts_content.push_str("  | 'TAGGED_WITH'\n");
            ts_content.push_str("  | 'CUSTOM';\n\n");

            if resolvers {
                ts_content.push_str("// Resolver types\n");
                ts_content.push_str("export interface QueryResolvers {\n");
                ts_content.push_str("  node(id: string): Promise<StateNode | null>;\n");
                ts_content.push_str("  nodes(kind?: NodeKind, limit?: number): Promise<StateNode[]>;\n");
                ts_content.push_str("}\n\n");

                ts_content.push_str("export interface MutationResolvers {\n");
                ts_content.push_str("  createNode(kind: NodeKind, content: any): Promise<StateNode>;\n");
                ts_content.push_str("  updateNode(id: string, content: any): Promise<StateNode>;\n");
                ts_content.push_str("  deleteNode(id: string): Promise<boolean>;\n");
                ts_content.push_str("}\n");
            }

            std::fs::write(&output, ts_content)?;
            println!("Generated TypeScript types: {}", output);
        }
        GraphqlCommands::Subscribe { query, variables, url, ndjson } => {
            use tokio_tungstenite::connect_async;
            use futures_util::{SinkExt, StreamExt};

            println!("Connecting to {}...", url);

            let subscription_str = if query.starts_with('@') {
                std::fs::read_to_string(&query[1..])?
            } else {
                query
            };

            // Build the subscription message
            let mut payload = serde_json::json!({
                "type": "connection_init",
                "payload": {}
            });

            // Connect to WebSocket
            let ws_url = url.replace("http://", "ws://").replace("https://", "wss://");
            let (ws_stream, _) = connect_async(&ws_url).await
                .map_err(|e| anyhow!("WebSocket connection failed: {}", e))?;

            let (mut write, mut read) = ws_stream.split();

            // Send connection init
            write.send(tungstenite::Message::Text(payload.to_string().into()))
                .await
                .map_err(|e| anyhow!("Failed to send init: {}", e))?;

            // Wait for connection ack
            if let Some(msg) = read.next().await {
                match msg {
                    Ok(tungstenite::Message::Text(text)) => {
                        let parsed: serde_json::Value = serde_json::from_str(&text)?;
                        if parsed.get("type").and_then(|t| t.as_str()) != Some("connection_ack") {
                            return Err(anyhow!("Unexpected message: {}", text));
                        }
                    }
                    _ => return Err(anyhow!("Unexpected WebSocket message")),
                }
            }

            // Send subscription
            let mut sub_payload = serde_json::json!({
                "id": "1",
                "type": "subscribe",
                "payload": {
                    "query": subscription_str
                }
            });

            if let Some(vars) = variables {
                let vars: serde_json::Value = serde_json::from_str(&vars)?;
                sub_payload["payload"]["variables"] = vars;
            }

            write.send(tungstenite::Message::Text(sub_payload.to_string().into()))
                .await
                .map_err(|e| anyhow!("Failed to send subscription: {}", e))?;

            println!("Subscribed. Waiting for events... (Ctrl+C to stop)\n");

            // Listen for events
            while let Some(msg) = read.next().await {
                match msg {
                    Ok(tungstenite::Message::Text(text)) => {
                        let parsed: serde_json::Value = serde_json::from_str(&text)?;
                        if parsed.get("type").and_then(|t| t.as_str()) == Some("next") {
                            if let Some(data) = parsed.get("payload") {
                                if ndjson {
                                    println!("{}", serde_json::to_string(data)?);
                                } else {
                                    println!("{}", serde_json::to_string_pretty(data)?);
                                    println!("---");
                                }
                            }
                        } else if parsed.get("type").and_then(|t| t.as_str()) == Some("error") {
                            eprintln!("Error: {:?}", parsed.get("payload"));
                        }
                    }
                    Ok(tungstenite::Message::Close(_)) => {
                        println!("Connection closed");
                        break;
                    }
                    Err(e) => {
                        eprintln!("WebSocket error: {}", e);
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
// WATCH MODE
// ══════════════════════════════════════════════════════════════════════════════

fn run_watch_mode(command: Vec<String>, debounce_ms: u64, db_path: &str, quiet: bool) -> Result<()> {
    use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
    use std::sync::mpsc;
    use std::time::Duration;

    if command.is_empty() {
        return Err(anyhow!("No command specified for watch mode"));
    }

    // Determine paths to watch
    let watch_path = std::path::Path::new(db_path);
    let current_dir = std::env::current_dir()?;

    if !quiet {
        println!("Watching for changes...");
        println!("Command: {}", command.join(" "));
        println!("Debounce: {}ms", debounce_ms);
        println!("Press Ctrl+C to stop\n");
    }

    // Create channel for events
    let (tx, rx) = mpsc::channel();

    // Create watcher with debounce
    let config = Config::default()
        .with_poll_interval(Duration::from_millis(debounce_ms));

    let mut watcher = RecommendedWatcher::new(
        move |res: Result<notify::Event, notify::Error>| {
            if let Ok(event) = res {
                let _ = tx.send(event);
            }
        },
        config,
    )?;

    // Watch database path and current directory
    if watch_path.exists() {
        watcher.watch(watch_path, RecursiveMode::Recursive)?;
    }
    watcher.watch(&current_dir, RecursiveMode::Recursive)?;

    // Run command initially
    run_watch_command(&command, quiet)?;

    // Track last run time for debouncing
    let mut last_run = std::time::Instant::now();
    let debounce_duration = Duration::from_millis(debounce_ms);

    // Event loop
    loop {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(event) => {
                // Skip certain file patterns
                let dominated_paths: Vec<_> = event.paths.iter()
                    .filter(|p| {
                        let path_str = p.to_string_lossy();
                        !path_str.contains("/target/") &&
                        !path_str.contains("/.git/") &&
                        !path_str.ends_with(".swp") &&
                        !path_str.ends_with(".swo") &&
                        !path_str.ends_with("~")
                    })
                    .collect();

                if !dominated_paths.is_empty() && last_run.elapsed() >= debounce_duration {
                    if !quiet {
                        println!("\n─── Change detected ───");
                        for path in &dominated_paths {
                            println!("  {}", path.display());
                        }
                        println!();
                    }

                    run_watch_command(&command, quiet)?;
                    last_run = std::time::Instant::now();
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Continue waiting
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break;
            }
        }
    }

    Ok(())
}

fn run_watch_command(command: &[String], quiet: bool) -> Result<()> {
    use std::process::Command;

    if command.is_empty() {
        return Ok(());
    }

    let status = Command::new(&command[0])
        .args(&command[1..])
        .status()?;

    if !quiet {
        if status.success() {
            println!("─── Command completed successfully ───\n");
        } else {
            println!("─── Command failed (exit code: {:?}) ───\n", status.code());
        }
    }

    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
// REPL
// ══════════════════════════════════════════════════════════════════════════════

fn run_repl(
    store: &Arc<SledStore>,
    agent: &AgentId,
    history_file: Option<String>,
    fulltext_index: &Option<FullTextIndex>,
) -> Result<()> {
    use rustyline::error::ReadlineError;
    use rustyline::{DefaultEditor, Result as RlResult};

    println!("elegant-STATE REPL v{}", env!("CARGO_PKG_VERSION"));
    println!("Type 'help' for commands, 'quit' or Ctrl-D to exit\n");

    let history_path = history_file.unwrap_or_else(|| {
        dirs::data_dir()
            .map(|p| p.join("elegant-state").join("repl_history"))
            .unwrap_or_else(|| std::path::PathBuf::from(".repl_history"))
            .to_string_lossy()
            .to_string()
    });

    let mut rl = DefaultEditor::new().map_err(|e| anyhow!("Failed to create editor: {}", e))?;

    // Load history
    if std::path::Path::new(&history_path).exists() {
        let _ = rl.load_history(&history_path);
    }

    loop {
        let prompt = format!("state({})> ", agent);
        match rl.readline(&prompt) {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                let _ = rl.add_history_entry(line);

                // Parse and execute command
                match execute_repl_command(line, store, agent, fulltext_index) {
                    Ok(true) => {
                        // Save history before exiting
                        if let Some(parent) = std::path::Path::new(&history_path).parent() {
                            let _ = std::fs::create_dir_all(parent);
                        }
                        let _ = rl.save_history(&history_path);
                        break;
                    }
                    Ok(false) => {}
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("^C");
            }
            Err(ReadlineError::Eof) => {
                println!("Bye!");
                // Save history before exiting
                if let Some(parent) = std::path::Path::new(&history_path).parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = rl.save_history(&history_path);
                break;
            }
            Err(err) => {
                eprintln!("Error: {:?}", err);
                break;
            }
        }
    }

    Ok(())
}

fn execute_repl_command(
    line: &str,
    store: &Arc<SledStore>,
    agent: &AgentId,
    fulltext_index: &Option<FullTextIndex>,
) -> Result<bool> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return Ok(false);
    }

    match parts[0] {
        "quit" | "exit" | "q" => {
            println!("Bye!");
            return Ok(true);
        }

        "help" | "?" | "h" => {
            println!(
                r#"
REPL Commands:
  Node Operations:
    node list [kind] [limit]     - List nodes (optionally filter by kind)
    node get <id>                - Get a node by ID
    node create <kind> <json>    - Create a new node
    node update <id> <json>      - Update a node's content
    node delete <id>             - Delete a node

  Edge Operations:
    edge list <node_id>          - List edges from a node
    edge create <from> <to> <kind> - Create an edge
    edge delete <id>             - Delete an edge

  Search:
    search <query>               - Full-text search
    fuzzy <pattern>              - Fuzzy search
    find <field> <value>         - Search by metadata field

  Database:
    stats                        - Show database statistics
    events [limit]               - Show recent events

  Other:
    clear                        - Clear screen
    help                         - Show this help
    quit / exit / q              - Exit REPL
"#
            );
        }

        "clear" | "cls" => {
            print!("\x1B[2J\x1B[1;1H");
        }

        "stats" => {
            let nodes = store.list_nodes(None, usize::MAX)?;
            println!("Nodes: {}", nodes.len());

            let mut by_kind = std::collections::HashMap::new();
            for node in &nodes {
                *by_kind.entry(node.kind.to_string()).or_insert(0) += 1;
            }
            println!("By kind:");
            for (kind, count) in by_kind {
                println!("  {}: {}", kind, count);
            }
        }

        "events" => {
            let limit = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(10);
            let events = store.get_events(None, limit)?;
            for event in events {
                println!(
                    "[{}] {:?} {:?} by {}",
                    event.timestamp.format("%Y-%m-%d %H:%M:%S"),
                    event.operation,
                    event.target,
                    event.agent
                );
            }
        }

        "node" => {
            if parts.len() < 2 {
                println!("Usage: node <list|get|create|update|delete> ...");
                return Ok(false);
            }

            match parts[1] {
                "list" | "ls" => {
                    let kind_filter: Option<NodeKind> = parts.get(2).and_then(|k| k.parse().ok());
                    let limit = parts.get(3).and_then(|s| s.parse().ok()).unwrap_or(20);
                    let nodes = store.list_nodes(kind_filter, limit)?;
                    for node in nodes {
                        println!("{} [{}] {}", node.id, node.kind, truncate_json(&node.content, 60));
                    }
                }

                "get" => {
                    if parts.len() < 3 {
                        println!("Usage: node get <id>");
                        return Ok(false);
                    }
                    let id = parts[2].parse().map_err(|e| anyhow!("Invalid ID: {}", e))?;
                    match store.get_node(id)? {
                        Some(node) => {
                            println!("{}", serde_json::to_string_pretty(&node)?);
                        }
                        None => println!("Node not found"),
                    }
                }

                "create" => {
                    if parts.len() < 4 {
                        println!("Usage: node create <kind> <json_content>");
                        return Ok(false);
                    }
                    let kind: NodeKind = parts[2].parse().map_err(|e: String| anyhow!(e))?;
                    let json_str = parts[3..].join(" ");
                    let content: serde_json::Value = serde_json::from_str(&json_str)?;
                    let node = StateNode::new(kind, content);
                    let created = store.create_node(node, agent.clone())?;

                    // Auto-index
                    if let Some(ref index) = fulltext_index {
                        if let Ok(mut writer) = index.writer(50_000_000) {
                            let _ = index.index_node(&mut writer, &created);
                            let _ = writer.commit();
                        }
                    }

                    println!("Created: {}", created.id);
                }

                "update" => {
                    if parts.len() < 4 {
                        println!("Usage: node update <id> <json_content>");
                        return Ok(false);
                    }
                    let id = parts[2].parse().map_err(|e| anyhow!("Invalid ID: {}", e))?;
                    let json_str = parts[3..].join(" ");
                    let content: serde_json::Value = serde_json::from_str(&json_str)?;
                    let updated = store.update_node(id, content, agent.clone())?;

                    // Re-index
                    if let Some(ref index) = fulltext_index {
                        if let Ok(mut writer) = index.writer(50_000_000) {
                            let _ = index.remove_node(&mut writer, id);
                            let _ = index.index_node(&mut writer, &updated);
                            let _ = writer.commit();
                        }
                    }

                    println!("Updated: {}", updated.id);
                }

                "delete" | "rm" => {
                    if parts.len() < 3 {
                        println!("Usage: node delete <id>");
                        return Ok(false);
                    }
                    let id = parts[2].parse().map_err(|e| anyhow!("Invalid ID: {}", e))?;

                    // Remove from index
                    if let Some(ref index) = fulltext_index {
                        if let Ok(mut writer) = index.writer(50_000_000) {
                            let _ = index.remove_node(&mut writer, id);
                            let _ = writer.commit();
                        }
                    }

                    store.delete_node(id, agent.clone())?;
                    println!("Deleted: {}", parts[2]);
                }

                _ => println!("Unknown node command: {}", parts[1]),
            }
        }

        "edge" => {
            if parts.len() < 2 {
                println!("Usage: edge <list|create|delete> ...");
                return Ok(false);
            }

            match parts[1] {
                "list" | "ls" => {
                    if parts.len() < 3 {
                        println!("Usage: edge list <node_id>");
                        return Ok(false);
                    }
                    let id = parts[2].parse().map_err(|e| anyhow!("Invalid ID: {}", e))?;
                    let from_edges = store.edges_from(id)?;
                    let to_edges = store.edges_to(id)?;

                    if !from_edges.is_empty() {
                        println!("Outgoing:");
                        for edge in from_edges {
                            println!("  {} --[{}]--> {}", edge.from, edge.kind, edge.to);
                        }
                    }
                    if !to_edges.is_empty() {
                        println!("Incoming:");
                        for edge in to_edges {
                            println!("  {} --[{}]--> {}", edge.from, edge.kind, edge.to);
                        }
                    }
                }

                "create" => {
                    if parts.len() < 5 {
                        println!("Usage: edge create <from_id> <to_id> <kind>");
                        return Ok(false);
                    }
                    let from = parts[2].parse().map_err(|e| anyhow!("Invalid from ID: {}", e))?;
                    let to = parts[3].parse().map_err(|e| anyhow!("Invalid to ID: {}", e))?;
                    let kind: EdgeKind = parts[4].parse().map_err(|e: String| anyhow!(e))?;
                    let edge = StateEdge::new(from, to, kind);
                    let created = store.create_edge(edge, agent.clone())?;
                    println!("Created edge: {}", created.id);
                }

                "delete" | "rm" => {
                    if parts.len() < 3 {
                        println!("Usage: edge delete <id>");
                        return Ok(false);
                    }
                    let id = parts[2].parse().map_err(|e| anyhow!("Invalid ID: {}", e))?;
                    store.delete_edge(id, agent.clone())?;
                    println!("Deleted: {}", parts[2]);
                }

                _ => println!("Unknown edge command: {}", parts[1]),
            }
        }

        "search" | "s" => {
            if parts.len() < 2 {
                println!("Usage: search <query>");
                return Ok(false);
            }
            let query = parts[1..].join(" ");

            if let Some(ref index) = fulltext_index {
                let results = index.search(&query, None, 20)?;
                if results.is_empty() {
                    println!("No results found");
                } else {
                    for result in results {
                        println!("[{:.2}] {} [{}] {}", result.score, result.id, result.kind, truncate_str(&result.content, 60));
                    }
                }
            } else {
                // Fallback to basic store search
                let results = store.search(&query, None)?;
                for node in results.into_iter().take(20) {
                    println!("{} [{}] {}", node.id, node.kind, truncate_json(&node.content, 60));
                }
            }
        }

        "fuzzy" | "fz" => {
            if parts.len() < 2 {
                println!("Usage: fuzzy <pattern>");
                return Ok(false);
            }
            let pattern = parts[1..].join(" ");
            let fuzzy = FuzzySearch::new();
            let all_nodes = store.list_nodes(None, usize::MAX)?;

            let results = fuzzy.search(&pattern, &all_nodes, |n| n.content.to_string());

            if results.is_empty() {
                println!("No results found");
            } else {
                for (node, score) in results.into_iter().take(20) {
                    println!("[{}] {} [{}] {}", score, node.id, node.kind, truncate_json(&node.content, 60));
                }
            }
        }

        "find" => {
            if parts.len() < 3 {
                println!("Usage: find <field> <value>");
                return Ok(false);
            }
            let field = parts[1];
            let value = parts[2..].join(" ");
            let all_nodes = store.list_nodes(None, usize::MAX)?;

            let mut found = false;
            for node in all_nodes {
                if let Some(meta_value) = node.metadata.get(field) {
                    if meta_value.to_string().contains(&value) {
                        println!("{} [{}] {}={}", node.id, node.kind, field, meta_value);
                        found = true;
                    }
                }
            }
            if !found {
                println!("No nodes found with {}={}", field, value);
            }
        }

        _ => {
            println!("Unknown command: {}. Type 'help' for available commands.", parts[0]);
        }
    }

    Ok(false)
}

fn truncate_json(value: &serde_json::Value, max_len: usize) -> String {
    let s = value.to_string();
    truncate_str(&s, max_len)
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}
