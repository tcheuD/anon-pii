use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use dirs;
use serde::Serialize;
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;

use anon::detection::{Anonymizer, Detection};
use anon::format::{detect_format, detect_json_indent, DetectedFormat};
use anon::mapping::Mapping;
use anon::patterns::{MAX_INPUT_SIZE, PATTERNS};
use anon::proxy;

// ─── CLI ────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "anon")]
#[command(about = "Fast CLI tool to anonymize PII in debug data")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Input file (reads from stdin if not provided)
    #[arg(short, long)]
    input: Option<PathBuf>,

    /// Output file (writes to stdout if not provided)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Save mapping to file for later restoration
    #[arg(short, long)]
    mapping: Option<PathBuf>,

    /// Output mapping to stderr
    #[arg(long)]
    mapping_stderr: bool,

    /// Include mapping as comment in output
    #[arg(long)]
    include_mapping: bool,

    /// Show detected entities
    #[arg(short, long)]
    verbose: bool,

    /// Force input format
    #[arg(short, long, value_enum, default_value = "auto")]
    format: Format,

    /// Minimum confidence score (0.0-1.0)
    #[arg(long, default_value = "0.5")]
    threshold: f64,

    /// Language for detection
    #[arg(short, long, default_value = "en")]
    language: String,

    /// Enable NER-based PERSON detection (requires ner or ner-lite feature)
    #[cfg(any(feature = "ner", feature = "ner-lite"))]
    #[arg(long)]
    ner: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Restore original values from anonymized data
    Restore {
        /// Input file (positional, optional)
        #[arg(value_name = "INPUT")]
        input_positional: Option<PathBuf>,

        /// Input file (flag, optional — overrides positional)
        #[arg(short, long)]
        input: Option<PathBuf>,

        /// Mapping file (defaults to ~/.anon/mapping.json)
        #[arg(short, long)]
        mapping: Option<PathBuf>,

        /// Output file (writes to stdout if not provided)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// List all supported entity types
    ListEntities,
    /// Download NER model from HuggingFace
    #[cfg(feature = "ner")]
    DownloadModel {
        /// Custom model directory
        #[arg(long)]
        model_dir: Option<PathBuf>,
    },
    /// Start anonymizing proxy server
    Proxy {
        /// Port to listen on
        #[arg(short, long, default_value = "9100")]
        port: u16,

        /// Upstream API URL
        #[arg(short, long, default_value = proxy::DEFAULT_UPSTREAM)]
        upstream: String,

        /// Minimum confidence score (0.0-1.0)
        #[arg(long, default_value = "0.5")]
        threshold: f64,

        /// Directory to store session data (mapping files)
        #[arg(long)]
        session_dir: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq)]
enum Format {
    Auto,
    Json,
    Text,
    Sql,
    Csv,
}

// ─── Default mapping path ────────────────────────────────────────────────────

fn default_mapping_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".anon")
}

fn default_mapping_path() -> PathBuf {
    default_mapping_dir().join("mapping.json")
}

// ─── I/O helpers ────────────────────────────────────────────────────────────

fn read_input(path: Option<&PathBuf>) -> io::Result<String> {
    match path {
        Some(p) => fs::read_to_string(p),
        None => {
            let mut buffer = String::new();
            io::stdin()
                .take(MAX_INPUT_SIZE)
                .read_to_string(&mut buffer)?;
            Ok(buffer)
        }
    }
}

fn write_output(path: Option<&PathBuf>, content: &str) -> io::Result<()> {
    match path {
        Some(p) => fs::write(p, content),
        None => {
            print!("{}", content);
            if !content.ends_with('\n') {
                println!();
            }
            io::stdout().flush()
        }
    }
}

fn write_mapping_file(path: &PathBuf, content: &str) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(content.as_bytes())?;
        return Ok(());
    }
    #[cfg(not(unix))]
    {
        fs::write(path, content)
    }
}

// ─── Verbose output ─────────────────────────────────────────────────────────

fn print_detections(detections: &[Detection]) {
    if detections.is_empty() {
        return;
    }

    // Deduplicate
    let mut seen = std::collections::HashSet::new();
    let unique: Vec<&Detection> = detections
        .iter()
        .filter(|d| seen.insert((&d.entity_type, &d.original)))
        .collect();

    let type_width = unique.iter().map(|d| d.entity_type.len()).max().unwrap_or(10);
    let val_width = 40;

    eprintln!();
    eprintln!(
        "  {:<tw$}  {:<vw$}  {}",
        "Entity".bold(),
        "Original".bold(),
        "Score".bold(),
        tw = type_width,
        vw = val_width
    );
    eprintln!(
        "  {:<tw$}  {:<vw$}  {}",
        "─".repeat(type_width),
        "─".repeat(val_width),
        "─────",
        tw = type_width,
        vw = val_width
    );

    for det in &unique {
        let truncated: String = if det.original.chars().count() > val_width {
            let s: String = det.original.chars().take(val_width - 1).collect();
            format!("{s}…")
        } else {
            det.original.clone()
        };

        eprintln!(
            "  {:<tw$}  {:<vw$}  {:.2}",
            det.entity_type.green(),
            truncated,
            det.score,
            tw = type_width,
            vw = val_width
        );
    }
    eprintln!();
}

// ─── Main ───────────────────────────────────────────────────────────────────

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Restore {
            input_positional,
            input,
            mapping,
            output,
        }) => {
            let resolved_input = input.or(input_positional);
            let content = read_input(resolved_input.as_ref())?;
            let mapping_path = mapping.unwrap_or_else(default_mapping_path);
            let mapping_content = fs::read_to_string(&mapping_path)?;
            let mut mapping: Mapping = match serde_json::from_str(&mapping_content) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("Error: invalid mapping file: {e}");
                    std::process::exit(1);
                }
            };
            mapping.rebuild_caches();

            let result = mapping.restore(&content);
            write_output(output.as_ref(), &result)?;

            eprintln!("Restored {} entities", mapping.mappings.len());
        }
        #[cfg(feature = "ner")]
        Some(Commands::DownloadModel { model_dir }) => {
            let mut config = anon::ner::NerConfig::default();
            if let Some(dir) = model_dir {
                config.model_dir = dir;
            }
            eprintln!("Downloading NER model...");
            if let Err(e) = anon::ner::download::download_model(&config) {
                eprintln!("Error downloading model: {e}");
                std::process::exit(1);
            }
        }
        Some(Commands::Proxy {
            port,
            upstream,
            threshold,
            session_dir,
        }) => {
            let session_dir = session_dir.unwrap_or_else(|| {
                let dir = std::env::temp_dir().join("anon-proxy");
                dir
            });

            let state = Arc::new(proxy::ProxyState::new(
                upstream, threshold, session_dir,
            ));

            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(proxy::run(state, port))?;
        }
        Some(Commands::ListEntities) => {
            eprintln!("{}", "Supported entity types:".bold());
            eprintln!();

            let mut seen = std::collections::HashSet::new();
            let type_width = PATTERNS
                .iter()
                .map(|p| p.entity_type.len())
                .max()
                .unwrap_or(10);

            for p in PATTERNS {
                if seen.insert(p.entity_type) {
                    // Check context across all patterns for this entity type
                    let has_required = PATTERNS.iter()
                        .filter(|pp| pp.entity_type == p.entity_type)
                        .any(|pp| pp.context_required && !pp.context_keywords.is_empty());
                    let has_boost = PATTERNS.iter()
                        .filter(|pp| pp.entity_type == p.entity_type)
                        .any(|pp| !pp.context_required && !pp.context_keywords.is_empty());

                    let context = if has_required {
                        " (context-aware)".dimmed().to_string()
                    } else if has_boost {
                        " (context-boosted)".dimmed().to_string()
                    } else {
                        String::new()
                    };
                    eprintln!(
                        "  {:<tw$}  {}{}",
                        p.entity_type.green(),
                        p.name,
                        context,
                        tw = type_width
                    );
                }
            }
            #[cfg(any(feature = "ner", feature = "ner-lite"))]
            {
                let backend = if cfg!(feature = "ner") { "ML" } else { "heuristic" };
                eprintln!(
                    "  {:<tw$}  NER-based person detection ({backend})",
                    "PERSON".green(),
                    tw = type_width
                );
            }
        }
        None => {
            if cli.input.is_none() && io::stdin().is_terminal() {
                eprintln!("No input provided. Use --help for usage.");
                std::process::exit(1);
            }

            let content = read_input(cli.input.as_ref())?;

            // Empty input short-circuit (match Python behavior)
            if content.trim().is_empty() {
                write_output(cli.output.as_ref(), &content)?;
                return Ok(());
            }

            let mut anonymizer = Anonymizer::new(cli.threshold);

            // Wire up NER detector if requested (ML takes precedence over heuristic)
            #[cfg(feature = "ner")]
            if cli.ner {
                let config = anon::ner::NerConfig::default();
                // ort panics if libonnxruntime is not found; catch that gracefully
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    anon::ner::ml::MlNerDetector::new(&config)
                })) {
                    Ok(Ok(detector)) => {
                        anonymizer.set_ner_detector(Box::new(detector));
                        if cli.verbose {
                            eprintln!("NER: ML backend enabled");
                        }
                    }
                    Ok(Err(e)) => {
                        eprintln!("Warning: ML NER init failed: {e}");
                        eprintln!("Hint: run `anon download-model` first");
                    }
                    Err(_) => {
                        eprintln!("Warning: ONNX Runtime not found.");
                        eprintln!("Install it:  brew install onnxruntime");
                        eprintln!("Then set:    export ORT_DYLIB_PATH=$(brew --prefix onnxruntime)/lib/libonnxruntime.dylib");
                    }
                }
            }
            #[cfg(all(feature = "ner-lite", not(feature = "ner")))]
            if cli.ner {
                let detector = anon::ner::heuristic::HeuristicNerDetector::new();
                anonymizer.set_ner_detector(Box::new(detector));
                if cli.verbose {
                    eprintln!("NER: heuristic backend enabled");
                }
            }

            // Determine format and process
            let (parsed_json, format_name) = match cli.format {
                Format::Json => match serde_json::from_str::<serde_json::Value>(content.trim()) {
                    Ok(v) => (Some(v), "json"),
                    Err(e) => {
                        eprintln!("Error: invalid JSON input: {e}");
                        eprintln!("Hint: use --format text to force text mode");
                        std::process::exit(1);
                    }
                },
                Format::Auto => match detect_format(&content) {
                    DetectedFormat::Json(v) => (Some(v), "json"),
                    DetectedFormat::Sql => (None, "sql"),
                    DetectedFormat::Csv => (None, "csv"),
                    DetectedFormat::Text => (None, "text"),
                },
                Format::Text => (None, "text"),
                Format::Sql => (None, "sql"),
                Format::Csv => (None, "csv"),
            };

            let (result, detections) = if let Some(parsed) = parsed_json {
                let indent = detect_json_indent(&content);
                let (anon_value, dets) = anonymizer.anonymize_json_value(&parsed);

                let indent_bytes = b" ".repeat(indent);
                let formatter =
                    serde_json::ser::PrettyFormatter::with_indent(&indent_bytes);
                let mut buf = Vec::new();
                let mut ser =
                    serde_json::Serializer::with_formatter(&mut buf, formatter);
                anon_value.serialize(&mut ser).unwrap();
                let json_str = String::from_utf8(buf).unwrap();

                (format!("{}\n", json_str), dets)
            } else {
                anonymizer.anonymize_text(&content)
            };

            // Handle --include-mapping: append mapping as comment at end
            let final_output = if cli.include_mapping {
                eprintln!("Warning: --include-mapping embeds original PII values in the output");
                let mapping_json = serde_json::to_string_pretty(&anonymizer.mapping)?;
                format!("{}\n\n/* MAPPING:\n{}\n*/", result.trim_end(), mapping_json)
            } else {
                result
            };

            write_output(cli.output.as_ref(), &final_output)?;

            // Save mapping file (contains original PII — restrict permissions)
            let mapping_path = cli.mapping.unwrap_or_else(default_mapping_path);
            if let Some(parent) = mapping_path.parent() {
                fs::create_dir_all(parent)?;
            }
            let mapping_json = serde_json::to_string_pretty(&anonymizer.mapping)?;
            write_mapping_file(&mapping_path, &mapping_json)?;
            if cli.verbose {
                eprintln!("Mapping saved to {:?}", mapping_path);
            }

            // Output mapping to stderr
            if cli.mapping_stderr {
                let mapping_json = serde_json::to_string_pretty(&anonymizer.mapping)?;
                eprintln!("{}", mapping_json);
            }

            // Verbose detection table
            if cli.verbose {
                print_detections(&detections);
                eprintln!(
                    "  {} entities detected (format: {}, language: {})",
                    detections.len().to_string().bold(),
                    format_name,
                    cli.language,
                );
            }
        }
    }

    Ok(())
}
