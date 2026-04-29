//! CLI argument definitions for the `anon-pii` tool.
//!
//! This module provides the `Cli` struct, `Commands` enum, and `Format` enum
//! that define the command-line interface. These are exported from the library
//! so that examples and tools can use `clap::CommandFactory` for introspection.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

use crate::detection::{HashAlgo, Operator};

#[derive(Parser)]
#[command(name = "anon-pii")]
#[command(about = "Fast CLI tool to anonymize PII in debug data")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Input file (reads from stdin if not provided)
    #[arg(short, long)]
    pub input: Option<PathBuf>,

    /// Output file (writes to stdout if not provided)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Save mapping to file for later restoration
    #[arg(short, long)]
    pub mapping: Option<PathBuf>,

    /// Output mapping to stderr
    #[arg(long)]
    pub mapping_stderr: bool,

    /// Include mapping as comment in output
    #[arg(long)]
    pub include_mapping: bool,

    /// Output a share-ready Markdown snippet (safe to paste into issues / AI tools)
    #[arg(long)]
    pub share: bool,

    /// Copy output to clipboard (best effort). Requires --share.
    #[arg(long)]
    pub copy: bool,

    /// Show detected entities
    #[arg(short, long)]
    pub verbose: bool,

    /// Force input format
    #[arg(short, long, value_enum, default_value = "auto")]
    pub format: Format,

    /// Minimum confidence score (0.0-1.0)
    #[arg(long, default_value = "0.5")]
    pub threshold: f64,

    /// Anonymization operator
    #[arg(long, value_enum, default_value = "token")]
    pub operator: Operator,

    /// Masking character (used with --operator mask)
    #[arg(long, default_value = "*")]
    pub mask_char: char,

    /// Fixed mask length (default: match original length)
    #[arg(long)]
    pub mask_count: Option<usize>,

    /// Mask from end instead of start
    #[arg(long)]
    pub mask_from_end: bool,

    /// Hash algorithm (used with --operator hash)
    #[arg(long, value_enum, default_value = "sha256")]
    pub hash_algo: HashAlgo,

    /// AES encryption key, hex-encoded (used with --operator encrypt)
    /// Must be 32 (128-bit), 48 (192-bit), or 64 (256-bit) hex characters
    #[arg(long)]
    pub encrypt_key: Option<String>,

    /// Custom replacement format string (used with --operator custom)
    /// Use {entity_type} as placeholder, e.g. '<{entity_type}>' or 'REDACTED'
    #[arg(long)]
    pub replace_with: Option<String>,

    /// Context score boost factor when keywords are found nearby (0.0-1.0)
    #[arg(long, default_value = "0.15")]
    pub context_boost: f64,

    /// Minimum score for context-boosted detections (0.0 = disabled)
    #[arg(long, default_value = "0.0")]
    pub min_score_with_context: f64,

    /// Language for detection
    #[arg(short, long, default_value = "en")]
    pub language: String,

    /// Enable NER-based PERSON detection (requires ner or ner-lite feature)
    #[cfg(any(feature = "ner", feature = "ner-lite"))]
    #[arg(long)]
    pub ner: bool,

    /// Path to YAML recognizer configuration file for custom patterns
    #[arg(short = 'c', long, global = true)]
    pub config: Option<PathBuf>,

    /// Batch size for NER inference when processing text (default: 32)
    /// Set to 0 to disable batching. Only affects text format with --ner.
    #[cfg(any(feature = "ner", feature = "ner-lite"))]
    #[arg(long, default_value = "32")]
    pub batch_size: usize,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Restore original values from anonymized data
    Restore {
        /// Input file (positional, optional)
        #[arg(value_name = "INPUT")]
        input_positional: Option<PathBuf>,

        /// Input file (flag, optional — overrides positional)
        #[arg(short, long)]
        input: Option<PathBuf>,

        /// Mapping file (defaults to ~/.anon-pii/mapping.json)
        #[arg(short, long)]
        mapping: Option<PathBuf>,

        /// Output file (writes to stdout if not provided)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// AES decryption key, hex-encoded (decrypts ENC[...] tokens)
        /// Must be 32 (128-bit), 48 (192-bit), or 64 (256-bit) hex characters
        #[arg(long)]
        decrypt_key: Option<String>,
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
    /// Start Presidio-compatible REST API server
    #[cfg(feature = "proxy")]
    Api {
        /// Port to listen on
        #[arg(short, long, default_value = "8080")]
        port: u16,
    },
    /// Start web UI for interactive anonymization
    #[cfg(feature = "proxy")]
    Ui {
        /// Port to listen on
        #[arg(short, long, default_value = "9200")]
        port: u16,

        /// Persist reversible mappings on disk instead of keeping them in memory only
        #[arg(long)]
        persist_mapping: bool,
    },
    /// Import first/last names from a CSV file into ~/.anon-pii/ for heuristic NER
    UpdateNames {
        /// CSV file with firstname,lastname columns (one pair per row)
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Replace existing name lists instead of merging
        #[arg(long)]
        replace: bool,
    },
    /// Anonymize PII in images via OCR and redaction
    #[cfg(feature = "image")]
    Image {
        /// Input image file
        #[arg(value_name = "PATH")]
        input: PathBuf,

        /// Output image file
        #[arg(short, long)]
        output: PathBuf,

        /// Minimum confidence score (0.0-1.0)
        #[arg(long, default_value = "0.5")]
        threshold: f64,

        /// Fill color for redacted regions
        #[arg(long, default_value = "black")]
        fill_color: String,

        /// Padding around detected PII regions (pixels)
        #[arg(long, default_value = "2")]
        padding: u32,
    },
    /// Anonymize PII in PDF documents with destructive text redaction
    #[cfg(feature = "pdf")]
    Pdf {
        /// Input PDF file
        #[arg(value_name = "PATH")]
        input: PathBuf,

        /// Output redacted PDF file
        #[arg(short, long)]
        output: PathBuf,

        /// Minimum confidence score (0.0-1.0)
        #[arg(long, default_value = "0.5")]
        threshold: f64,

        /// Fill color for redacted regions
        #[arg(long, default_value = "black")]
        fill_color: String,

        /// Padding around detected PII regions (points)
        #[arg(long, default_value = "2")]
        padding: f64,

        /// Draw visual masks only; underlying PDF text may remain extractable
        #[arg(long)]
        visual_mask_only: bool,
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

        /// Directory to store session data when --persist-mapping is enabled
        #[arg(long)]
        session_dir: Option<PathBuf>,

        /// Persist reversible mappings on disk instead of keeping them in memory only
        #[arg(long)]
        persist_mapping: bool,

        /// API provider (anthropic, openai, generic)
        #[arg(long, default_value = "anthropic")]
        provider: String,

        /// Allow a generic-provider fallback path prefix (repeatable)
        #[arg(long = "generic-allow-path-prefix", value_name = "PREFIX")]
        generic_allow_path_prefixes: Vec<String>,

        /// UNSAFE: allow generic-provider fallback forwarding for any path
        #[arg(long)]
        unsafe_generic_allow_all_paths: bool,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq)]
pub enum Format {
    Auto,
    Json,
    Text,
    Sql,
    Csv,
    #[cfg(feature = "xlsx")]
    Xlsx,
}
