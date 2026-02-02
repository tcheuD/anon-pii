use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use dirs;
use serde::Serialize;
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
#[cfg(feature = "proxy")]
use std::sync::Arc;

use anon::detection::{Anonymizer, Detection};
use anon::format::{detect_format, detect_json_indent, DetectedFormat};
use anon::mapping::Mapping;
use anon::patterns::{MAX_INPUT_SIZE, PATTERNS};
#[cfg(feature = "proxy")]
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
    /// Start web UI for interactive anonymization
    #[cfg(feature = "proxy")]
    Ui {
        /// Port to listen on
        #[arg(short, long, default_value = "9200")]
        port: u16,
    },
    /// Import first/last names from a CSV file into ~/.anon/ for heuristic NER
    UpdateNames {
        /// CSV file with firstname,lastname columns (one pair per row)
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Replace existing name lists instead of merging
        #[arg(long)]
        replace: bool,
    },
    /// Start anonymizing proxy server
    #[cfg(feature = "proxy")]
    Proxy {
        /// Port to listen on
        #[arg(short, long, default_value = "9100")]
        port: u16,

        /// Upstream API URL
        #[arg(short, long, default_value = "https://api.anthropic.com")]
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
        Some(p) => {
            let size = fs::metadata(p)?.len();
            if size > MAX_INPUT_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "File too large: {} bytes (max {} bytes)",
                        size, MAX_INPUT_SIZE
                    ),
                ));
            }
            fs::read_to_string(p)
        }
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

/// Create directory with mode 0o700 (owner-only) on Unix.
fn create_private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Write mapping file atomically via temp-file-then-rename.
/// This eliminates TOCTOU races: no window between check and open, and
/// rename() replaces the directory entry atomically (even if target is a symlink,
/// the symlink itself is replaced, not followed).
fn write_mapping_file(path: &PathBuf, content: &str) -> io::Result<()> {
    let dir = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "mapping path has no parent directory")
    })?;

    // Write to a temp file in the same directory (same filesystem = atomic rename)
    let tmp_path = dir.join(".mapping.json.tmp");

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&tmp_path, content)?;
    }

    // Atomic rename — replaces target directory entry, never follows symlinks
    fs::rename(&tmp_path, path)?;
    Ok(())
}

// ─── Verbose output ─────────────────────────────────────────────────────────

/// Mask a PII value for safe display: show first and last char with `***` in between.
/// Short values (≤2 chars) are fully masked.
fn mask_pii(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 2 {
        "*".repeat(chars.len())
    } else {
        format!("{}***{}", chars[0], chars[chars.len() - 1])
    }
}

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
        let masked = mask_pii(&det.original);
        let display: String = if masked.chars().count() > val_width {
            let s: String = masked.chars().take(val_width - 1).collect();
            format!("{s}…")
        } else {
            masked
        };

        eprintln!(
            "  {:<tw$}  {:<vw$}  {:.2}",
            det.entity_type.green(),
            display,
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
        Some(Commands::UpdateNames { file, replace }) => {
            let content = fs::read_to_string(&file).map_err(|e| {
                io::Error::new(e.kind(), format!("cannot read {}: {e}", file.display()))
            })?;

            let mut firstnames: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
            let mut lastnames: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

            for (i, line) in content.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() { continue; }
                // Skip header row
                if i == 0 {
                    let lower = line.to_lowercase();
                    if lower.contains("firstname") || lower.contains("lastname")
                        || lower.contains("first_name") || lower.contains("last_name")
                        || lower.contains("prénom") || lower.contains("nom")
                    {
                        continue;
                    }
                }
                let parts: Vec<&str> = line.splitn(2, ',').collect();
                if parts.len() == 2 {
                    let first = parts[0].trim();
                    let last = parts[1].trim();
                    if !first.is_empty() { firstnames.insert(first.to_string()); }
                    if !last.is_empty() { lastnames.insert(last.to_string()); }
                } else {
                    // Single column — treat as firstname
                    let name = parts[0].trim();
                    if !name.is_empty() { firstnames.insert(name.to_string()); }
                }
            }

            let anon_dir = default_mapping_dir();
            create_private_dir(&anon_dir)?;

            let first_path = anon_dir.join("firstnames.txt");
            let last_path = anon_dir.join("lastnames.txt");

            // Merge with existing if not --replace
            if !replace {
                if let Ok(existing) = fs::read_to_string(&first_path) {
                    for line in existing.lines() {
                        let name = line.trim();
                        if !name.is_empty() && !name.starts_with('#') {
                            firstnames.insert(name.to_string());
                        }
                    }
                }
                if let Ok(existing) = fs::read_to_string(&last_path) {
                    for line in existing.lines() {
                        let name = line.trim();
                        if !name.is_empty() && !name.starts_with('#') {
                            lastnames.insert(name.to_string());
                        }
                    }
                }
            }

            let first_content: Vec<&str> = firstnames.iter().map(|s| s.as_str()).collect();
            let last_content: Vec<&str> = lastnames.iter().map(|s| s.as_str()).collect();

            fs::write(&first_path, first_content.join("\n") + "\n")?;
            fs::write(&last_path, last_content.join("\n") + "\n")?;

            eprintln!(
                "Updated: {} firstnames, {} lastnames ({})",
                firstnames.len(),
                lastnames.len(),
                if replace { "replaced" } else { "merged" },
            );
            eprintln!("  {}", first_path.display());
            eprintln!("  {}", last_path.display());
        }
        #[cfg(feature = "proxy")]
        Some(Commands::Ui { port }) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(anon::ui::run(port))?;
        }
        #[cfg(feature = "proxy")]
        Some(Commands::Proxy {
            port,
            upstream,
            threshold,
            session_dir,
        }) => {
            let session_dir = session_dir.unwrap_or_else(|| {
                let suffix = anon::mapping::crypto_random_hex(8);
                std::env::temp_dir().join(format!("anon-proxy-{suffix}"))
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

            // Wire up NER detector if requested (ML + heuristic combined)
            #[cfg(feature = "ner")]
            if cli.ner {
                let config = anon::ner::NerConfig::default();
                let heuristic = anon::ner::heuristic::HeuristicNerDetector::new();
                // ort panics if libonnxruntime is not found; catch that gracefully
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    anon::ner::ml::MlNerDetector::new(&config)
                })) {
                    Ok(Ok(ml_detector)) => {
                        let combined = anon::ner::CombinedNerDetector::new(vec![
                            Box::new(ml_detector),
                            Box::new(heuristic),
                        ]);
                        anonymizer.set_ner_detector(Box::new(combined));
                        if cli.verbose {
                            eprintln!("NER: ML + heuristic backend enabled");
                        }
                    }
                    Ok(Err(e)) => {
                        eprintln!("Warning: ML NER init failed: {e}");
                        eprintln!("Hint: run `anon download-model` first");
                        // Fall back to heuristic only
                        anonymizer.set_ner_detector(Box::new(heuristic));
                        if cli.verbose {
                            eprintln!("NER: falling back to heuristic backend");
                        }
                    }
                    Err(_) => {
                        eprintln!("Warning: ONNX Runtime not found.");
                        eprintln!("Install it:  brew install onnxruntime");
                        eprintln!("Then set:    export ORT_DYLIB_PATH=$(brew --prefix onnxruntime)/lib/libonnxruntime.dylib");
                        // Fall back to heuristic only
                        anonymizer.set_ner_detector(Box::new(heuristic));
                        if cli.verbose {
                            eprintln!("NER: falling back to heuristic backend");
                        }
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
            } else if format_name == "csv" {
                anonymizer.anonymize_csv(&content)
            } else if format_name == "sql" {
                anonymizer.anonymize_sql(&content)
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
                create_private_dir(parent)?;
            }
            let mapping_json = serde_json::to_string_pretty(&anonymizer.mapping)?;
            write_mapping_file(&mapping_path, &mapping_json)?;
            if cli.verbose {
                eprintln!("Mapping saved to {:?}", mapping_path);
            }

            // Output mapping to stderr
            if cli.mapping_stderr {
                eprintln!("WARNING: mapping output contains original PII values in cleartext");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_mapping_file_creates_new() {
        let dir = std::env::temp_dir().join("anon-test-toctou-new");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let path = dir.join("mapping.json");
        write_mapping_file(&path, r#"{"test": true}"#).unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), r#"{"test": true}"#);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_write_mapping_file_overwrites_existing() {
        let dir = std::env::temp_dir().join("anon-test-toctou-overwrite");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let path = dir.join("mapping.json");
        fs::write(&path, "old content").unwrap();

        write_mapping_file(&path, "new content").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "new content");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn test_write_mapping_file_replaces_symlink_atomically() {
        use std::os::unix::fs as unix_fs;

        // The atomic rename pattern replaces the symlink directory entry
        // itself rather than following it. Verify the symlink is gone
        // and the file contains the correct content.
        let dir = std::env::temp_dir().join("anon-test-toctou-symlink");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let target = dir.join("attacker-controlled.txt");
        fs::write(&target, "attacker file").unwrap();

        let path = dir.join("mapping.json");
        unix_fs::symlink(&target, &path).unwrap();
        assert!(path.is_symlink());

        // write_mapping_file should replace the symlink with a regular file
        write_mapping_file(&path, "safe content").unwrap();

        // The path should now be a regular file, not a symlink
        assert!(!path.is_symlink());
        assert_eq!(fs::read_to_string(&path).unwrap(), "safe content");

        // The attacker's file should NOT have been modified
        assert_eq!(fs::read_to_string(&target).unwrap(), "attacker file");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_mask_pii_long_value() {
        let masked = mask_pii("john@example.com");
        assert_eq!(masked, "j***m");
        assert!(!masked.contains("@"));
        assert!(!masked.contains("example"));
    }

    #[test]
    fn test_mask_pii_short_value() {
        assert_eq!(mask_pii("ab"), "**");
        assert_eq!(mask_pii("a"), "*");
    }

    #[test]
    fn test_mask_pii_three_chars() {
        let masked = mask_pii("abc");
        assert_eq!(masked, "a***c");
    }

    #[test]
    fn test_default_session_dir_has_random_suffix() {
        // Simulate what the proxy command does: generate a random session dir name
        let suffix = anon::mapping::crypto_random_hex(8);
        let dir = std::env::temp_dir().join(format!("anon-proxy-{suffix}"));
        let name = dir.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with("anon-proxy-"), "dir name should start with anon-proxy-");
        // 8 bytes = 16 hex chars
        let hex_part = &name["anon-proxy-".len()..];
        assert_eq!(hex_part.len(), 16, "random suffix should be 16 hex chars");
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_default_session_dir_is_unique() {
        let dirs: std::collections::HashSet<String> = (0..50)
            .map(|_| {
                let suffix = anon::mapping::crypto_random_hex(8);
                format!("anon-proxy-{suffix}")
            })
            .collect();
        assert!(dirs.len() >= 48, "50 generated dirs should be nearly all unique");
    }

    #[cfg(unix)]
    #[test]
    fn test_create_dir_rejects_symlink() {
        use std::os::unix::fs as unix_fs;
        let base = std::env::temp_dir().join("anon-test-symlink-dir");
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();

        let target = base.join("real-dir");
        fs::create_dir_all(&target).unwrap();

        let symlink_path = base.join("symlink-dir");
        unix_fs::symlink(&target, &symlink_path).unwrap();

        // create_dir should fail because the path already exists (as a symlink)
        let result = fs::create_dir(&symlink_path);
        assert!(result.is_err(), "create_dir should reject existing symlink");

        let _ = fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn test_write_mapping_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join("anon-test-toctou-perms");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let path = dir.join("mapping.json");
        write_mapping_file(&path, "secret PII").unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mapping file should be owner-only (0o600), got {:o}", mode);

        let _ = fs::remove_dir_all(&dir);
    }
}
