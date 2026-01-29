use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::PathBuf;

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
    #[arg(long, default_value = "0.0")]
    threshold: f64,
}

#[derive(Subcommand)]
enum Commands {
    /// Restore original values from anonymized data
    Restore {
        /// Input file (reads from stdin if not provided)
        #[arg(short, long)]
        input: Option<PathBuf>,

        /// Mapping file to use for restoration
        #[arg(short, long, required = true)]
        mapping: PathBuf,

        /// Output file (writes to stdout if not provided)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// List all supported entity types
    ListEntities,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq)]
enum Format {
    Auto,
    Json,
    Text,
}

// ─── Mapping ────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct Mapping {
    session_id: String,
    created_at: String,
    mappings: HashMap<String, String>,
}

impl Mapping {
    fn new() -> Self {
        Self {
            session_id: uuid::Uuid::new_v4().to_string()[..8].to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            mappings: HashMap::new(),
        }
    }

    fn add(&mut self, entity_type: &str, original: &str) -> String {
        for (token, val) in &self.mappings {
            if val == original {
                return token.clone();
            }
        }

        let count = self
            .mappings
            .keys()
            .filter(|k| k.starts_with(&format!("[{}_", entity_type)))
            .count()
            + 1;

        let token = format!("[{}_{count}]", entity_type);
        self.mappings.insert(token.clone(), original.to_string());
        token
    }

    fn restore(&self, text: &str) -> String {
        let mut result = text.to_string();
        let mut tokens: Vec<_> = self.mappings.iter().collect();
        tokens.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        for (token, original) in tokens {
            result = result.replace(token, original);
        }
        result
    }
}

// ─── Patterns ───────────────────────────────────────────────────────────────

struct PiiPattern {
    name: &'static str,
    entity_type: &'static str,
    pattern: &'static str,
    score: f64,
    context_keywords: &'static [&'static str],
}

const PATTERNS: &[PiiPattern] = &[
    // ── Email ──
    PiiPattern {
        name: "email",
        entity_type: "EMAIL",
        pattern: r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        score: 0.9,
        context_keywords: &[],
    },
    // ── URL ──
    PiiPattern {
        name: "url",
        entity_type: "URL",
        pattern: r#"https?://[^\s\)\]>"']+[^\s\)\]>"'.,;:!?]"#,
        score: 0.9,
        context_keywords: &[],
    },
    // ── French phone numbers ──
    PiiPattern {
        name: "fr_phone_intl",
        entity_type: "FR_PHONE",
        pattern: r"\+33\s?[1-9](?:[\s.\-]?\d{2}){4}",
        score: 0.9,
        context_keywords: &[],
    },
    PiiPattern {
        name: "fr_phone_national",
        entity_type: "FR_PHONE",
        pattern: r"\b0[1-9](?:[\s.\-]?\d{2}){4}\b",
        score: 0.7,
        context_keywords: &[],
    },
    // ── French IBAN ──
    PiiPattern {
        name: "fr_iban",
        entity_type: "FR_IBAN",
        pattern: r"FR\d{2}[\s]?(?:\d{4}[\s]?){5}\d{3}",
        score: 0.95,
        context_keywords: &[],
    },
    // ── French SSN (NIR) ──
    PiiPattern {
        name: "fr_ssn",
        entity_type: "FR_SSN",
        pattern: r"[12]\s?\d{2}\s?(?:0[1-9]|1[0-2]|[2-9]\d)\s?(?:\d{2}|2[AB])\s?\d{3}\s?\d{3}(?:\s?\d{2})?",
        score: 0.85,
        context_keywords: &[],
    },
    // ── French passport ──
    PiiPattern {
        name: "fr_passport",
        entity_type: "FR_PASSPORT",
        pattern: r"\b\d{2}[A-Z]{2}\d{5}\b",
        score: 0.7,
        context_keywords: &["passeport", "passport", "document", "identite", "identité"],
    },
    // ── Aircraft registration ──
    PiiPattern {
        name: "aircraft_fr",
        entity_type: "AIRCRAFT",
        pattern: r"\bF-[A-Z]{4}\b",
        score: 0.95,
        context_keywords: &[],
    },
    PiiPattern {
        name: "aircraft_eu",
        entity_type: "AIRCRAFT",
        pattern: r"\b(?:D|G|I|EC|HB|OO|PH|OE|SE|LN|OH|CS|EI|9H)-[A-Z]{3,4}\b",
        score: 0.9,
        context_keywords: &[],
    },
    PiiPattern {
        name: "aircraft_us",
        entity_type: "AIRCRAFT",
        pattern: r"\bN[1-9][0-9]{0,4}[A-Z]?\b",
        score: 0.7,
        context_keywords: &["aircraft", "avion", "registration", "immat", "appareil", "tail"],
    },
    // ── Flight numbers ──
    PiiPattern {
        name: "flight_amelia",
        entity_type: "FLIGHT",
        pattern: r"\b(?:IZM|RLA|AME|GJT|AF)[0-9]{1,4}\b",
        score: 0.9,
        context_keywords: &[],
    },
    PiiPattern {
        name: "flight_iata",
        entity_type: "FLIGHT",
        pattern: r"\b[A-Z]{2}[0-9]{1,4}\b",
        score: 0.4,
        context_keywords: &["flight", "vol", "departure", "arrival", "schedule", "rotation", "leg", "sector"],
    },
    PiiPattern {
        name: "flight_icao",
        entity_type: "FLIGHT",
        pattern: r"\b[A-Z]{3}[0-9]{1,4}\b",
        score: 0.5,
        context_keywords: &["flight", "vol", "departure", "arrival", "schedule", "rotation", "leg", "sector"],
    },
    // ── Crew codes ──
    PiiPattern {
        name: "crew_code",
        entity_type: "CREW_CODE",
        pattern: r"\b[A-Z]{3}\b",
        score: 0.85,
        context_keywords: &[
            "crew", "equipage", "équipage", "pilot", "pilote", "captain", "cdb",
            "commandant", "copilot", "copilote", "opl", "cabin", "pnc", "pnt",
            "steward", "hostess", "hôtesse", "hotesse", "first officer", "fo",
            "member", "membre", "roster", "planning", "duty", "service",
        ],
    },
    // ── IP addresses ──
    PiiPattern {
        name: "ipv4",
        entity_type: "IP",
        pattern: r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        score: 0.9,
        context_keywords: &[],
    },
    // ── Credit card ──
    PiiPattern {
        name: "credit_card",
        entity_type: "CREDIT_CARD",
        pattern: r"\b(?:\d{4}[\s\-]?){3}\d{4}\b",
        score: 0.7,
        context_keywords: &[],
    },
    // ── UUID ──
    PiiPattern {
        name: "uuid",
        entity_type: "UUID",
        pattern: r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
        score: 0.95,
        context_keywords: &[],
    },
];

const CREW_CODE_BLOCKLIST: &[&str] = &[
    "THE", "AND", "FOR", "NOT", "YOU", "ALL", "CAN", "HAD", "HER", "WAS",
    "ONE", "OUR", "OUT", "ARE", "BUT", "HIS", "HAS", "NEW", "NOW", "OLD",
    "SEE", "WAY", "WHO", "BOY", "DID", "GET", "LET", "PUT", "SAY", "SHE",
    "TOO", "USE", "DAY", "MAN", "END", "MAY", "SET", "TRY", "ASK", "BIG",
    "VOL", "VIA", "PAX", "ETA", "ETD", "UTC", "GMT", "AOG", "MEL", "CDM",
    "IZM", "RLA", "AME", "GJT",
];

const CONTEXT_WINDOW: usize = 80;
const MAX_INPUT_SIZE: u64 = 512 * 1024 * 1024; // 512 MB

fn luhn_check(number: &str) -> bool {
    let digits: Vec<u32> = number
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() < 13 {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                d
            }
        })
        .sum();
    sum % 10 == 0
}

// ─── Anonymizer ─────────────────────────────────────────────────────────────

struct Anonymizer {
    patterns: Vec<CompiledPattern>,
    mapping: Mapping,
    threshold: f64,
}

struct CompiledPattern {
    entity_type: String,
    #[allow(dead_code)]
    name: String,
    regex: Regex,
    score: f64,
    context_keywords: Vec<String>,
}

#[derive(Debug)]
struct Detection {
    entity_type: String,
    original: String,
    start: usize,
    end: usize,
    score: f64,
}

impl Anonymizer {
    fn new(threshold: f64) -> Self {
        let patterns = PATTERNS
            .iter()
            .map(|p| CompiledPattern {
                entity_type: p.entity_type.to_string(),
                name: p.name.to_string(),
                regex: Regex::new(p.pattern)
                    .unwrap_or_else(|e| panic!("invalid regex for pattern '{}': {}", p.name, e)),
                score: p.score,
                context_keywords: p.context_keywords.iter().map(|k| k.to_lowercase()).collect(),
            })
            .collect();

        Self {
            patterns,
            mapping: Mapping::new(),
            threshold,
        }
    }

    fn has_context(&self, text: &str, start: usize, end: usize, keywords: &[String]) -> bool {
        if keywords.is_empty() {
            return true;
        }
        let mut window_start = start.saturating_sub(CONTEXT_WINDOW);
        let mut window_end = (end + CONTEXT_WINDOW).min(text.len());
        while !text.is_char_boundary(window_start) {
            window_start += 1;
        }
        while !text.is_char_boundary(window_end) {
            window_end -= 1;
        }
        let window = &text[window_start..window_end];
        let lower = window.to_lowercase();
        keywords.iter().any(|kw| lower.contains(kw.as_str()))
    }

    fn anonymize_text(&mut self, text: &str) -> (String, Vec<Detection>) {
        let mut detections: Vec<Detection> = Vec::new();

        for pat in &self.patterns {
            if pat.score < self.threshold {
                continue;
            }

            for mat in pat.regex.find_iter(text) {
                // Context check
                if !pat.context_keywords.is_empty()
                    && !self.has_context(text, mat.start(), mat.end(), &pat.context_keywords)
                {
                    continue;
                }

                // Crew code blocklist
                if pat.entity_type == "CREW_CODE" {
                    let matched = mat.as_str();
                    if CREW_CODE_BLOCKLIST.contains(&matched) {
                        continue;
                    }
                }

                // Credit card Luhn validation
                if pat.entity_type == "CREDIT_CARD" && !luhn_check(mat.as_str()) {
                    continue;
                }

                detections.push(Detection {
                    entity_type: pat.entity_type.clone(),
                    original: mat.as_str().to_string(),
                    start: mat.start(),
                    end: mat.end(),
                    score: pat.score,
                });
            }
        }

        // Sort by span length desc, then score desc, then position asc
        // This ensures longer/higher-confidence matches win overlap resolution
        detections.sort_by(|a, b| {
            (b.end - b.start).cmp(&(a.end - a.start))
                .then_with(|| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal))
                .then_with(|| a.start.cmp(&b.start))
        });

        // Remove overlapping detections (keep first = longest/highest score)
        let mut filtered: Vec<Detection> = Vec::new();
        for det in detections {
            let overlaps = filtered
                .iter()
                .any(|f| det.start < f.end && det.end > f.start);
            if !overlaps {
                filtered.push(det);
            }
        }

        // Sort by position for display
        filtered.sort_by(|a, b| a.start.cmp(&b.start));

        // Replace from end to start
        let mut result = text.to_string();
        for det in filtered.iter().rev() {
            let token = self.mapping.add(&det.entity_type, &det.original);
            result = format!(
                "{}{}{}",
                &result[..det.start],
                token,
                &result[det.end..]
            );
        }

        (result, filtered)
    }

    fn anonymize_json_value(&mut self, value: &Value) -> (Value, Vec<Detection>) {
        let mut all_detections = Vec::new();
        let new_value = self.walk_json(value, &mut all_detections);
        (new_value, all_detections)
    }

    fn walk_json(&mut self, value: &Value, detections: &mut Vec<Detection>) -> Value {
        match value {
            Value::String(s) => {
                let (anonymized, dets) = self.anonymize_text(s);
                detections.extend(dets);
                Value::String(anonymized)
            }
            Value::Array(arr) => {
                let new_arr: Vec<Value> = arr.iter().map(|v| self.walk_json(v, detections)).collect();
                Value::Array(new_arr)
            }
            Value::Object(map) => {
                let new_map = map
                    .iter()
                    .map(|(k, v)| (k.clone(), self.walk_json(v, detections)))
                    .collect();
                Value::Object(new_map)
            }
            other => other.clone(),
        }
    }
}

// ─── Format detection ───────────────────────────────────────────────────────

fn detect_format(content: &str) -> Format {
    let trimmed = content.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        if serde_json::from_str::<Value>(trimmed).is_ok() {
            return Format::Json;
        }
    }
    Format::Text
}

fn detect_json_indent(content: &str) -> usize {
    for line in content.lines().skip(1) {
        let stripped = line.trim_start();
        if !stripped.is_empty() && line.len() > stripped.len() {
            let indent = line.chars().count() - stripped.chars().count();
            if indent <= 8 {
                return indent;
            }
        }
    }
    2
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
            input,
            mapping,
            output,
        }) => {
            let content = read_input(input.as_ref())?;
            let mapping_content = fs::read_to_string(&mapping)?;
            let mapping: Mapping = match serde_json::from_str(&mapping_content) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("Error: invalid mapping file: {e}");
                    std::process::exit(1);
                }
            };

            let result = mapping.restore(&content);
            write_output(output.as_ref(), &result)?;

            eprintln!("Restored {} entities", mapping.mappings.len());
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
                    let context = if !p.context_keywords.is_empty() {
                        " (context-aware)".dimmed().to_string()
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
        }
        None => {
            if cli.input.is_none() && io::stdin().is_terminal() {
                eprintln!("No input provided. Use --help for usage.");
                std::process::exit(1);
            }

            let content = read_input(cli.input.as_ref())?;
            let mut anonymizer = Anonymizer::new(cli.threshold);

            // Determine format
            let format = if cli.format == Format::Auto {
                detect_format(&content)
            } else {
                cli.format
            };

            let (result, detections) = match format {
                Format::Json => {
                    let parsed: Value = match serde_json::from_str(content.trim()) {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("Error: invalid JSON input: {e}");
                            eprintln!("Hint: use --format text to force text mode");
                            std::process::exit(1);
                        }
                    };
                    let indent = detect_json_indent(&content);
                    let (anon_value, dets) = anonymizer.anonymize_json_value(&parsed);

                    let indent_bytes = b" ".repeat(indent);
                    let formatter = serde_json::ser::PrettyFormatter::with_indent(
                        &indent_bytes,
                    );
                    let mut buf = Vec::new();
                    let mut ser =
                        serde_json::Serializer::with_formatter(&mut buf, formatter);
                    anon_value.serialize(&mut ser).unwrap();
                    let json_str = String::from_utf8(buf).unwrap();

                    (format!("{}\n", json_str), dets)
                }
                _ => anonymizer.anonymize_text(&content),
            };

            // Handle --include-mapping: prepend mapping as comment
            let final_output = if cli.include_mapping {
                eprintln!("Warning: --include-mapping embeds original PII values in the output");
                let mapping_json = serde_json::to_string(&anonymizer.mapping)?;
                format!("/* MAPPING: {} */\n{}", mapping_json, result)
            } else {
                result
            };

            write_output(cli.output.as_ref(), &final_output)?;

            // Save mapping file (contains original PII — restrict permissions)
            if let Some(mapping_path) = cli.mapping {
                let mapping_json = serde_json::to_string_pretty(&anonymizer.mapping)?;
                write_mapping_file(&mapping_path, &mapping_json)?;
                if cli.verbose {
                    eprintln!("Mapping saved to {:?}", mapping_path);
                }
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
                    "  {} entities detected (format: {:?})",
                    detections.len().to_string().bold(),
                    if format == Format::Json { "json" } else { "text" }
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
    fn test_email() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("contact john@example.com now");
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].entity_type, "EMAIL");
        assert!(result.contains("[EMAIL_1]"));
    }

    #[test]
    fn test_url() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("visit https://example.com/path?q=1 now");
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].entity_type, "URL");
        assert!(result.contains("[URL_1]"));
    }

    #[test]
    fn test_fr_phone_intl() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("call +33 6 12 34 56 78");
        assert!(result.contains("[FR_PHONE_1]"));
    }

    #[test]
    fn test_fr_phone_national() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("call 06 12 34 56 78");
        assert!(result.contains("[FR_PHONE_1]"));
    }

    #[test]
    fn test_fr_iban() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("IBAN: FR76 1234 5678 9012 3456 7890 123");
        assert!(result.contains("[FR_IBAN_1]"));
    }

    #[test]
    fn test_fr_ssn() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("NIR: 1 85 12 75 123 456 78");
        assert!(result.contains("[FR_SSN_1]"));
    }

    #[test]
    fn test_fr_passport_with_context() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("passeport: 12AB34567");
        assert!(dets.iter().any(|d| d.entity_type == "FR_PASSPORT"));
        assert!(result.contains("[FR_PASSPORT_1]"));
    }

    #[test]
    fn test_fr_passport_without_context() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("code: 12AB34567");
        assert!(!dets.iter().any(|d| d.entity_type == "FR_PASSPORT"));
    }

    #[test]
    fn test_aircraft_fr() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("aircraft F-HOPA ready");
        assert!(result.contains("[AIRCRAFT_1]"));
    }

    #[test]
    fn test_aircraft_us_with_context() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("aircraft N12345 ready");
        assert!(dets.iter().any(|d| d.entity_type == "AIRCRAFT"));
        assert!(result.contains("[AIRCRAFT_1]"));
    }

    #[test]
    fn test_crew_code_with_context() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("pilot: JDU is on duty");
        assert!(dets.iter().any(|d| d.entity_type == "CREW_CODE"));
        assert!(result.contains("[CREW_CODE_1]"));
    }

    #[test]
    fn test_crew_code_without_context() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("hello JDU world");
        assert!(!dets.iter().any(|d| d.entity_type == "CREW_CODE"));
    }

    #[test]
    fn test_crew_code_blocklist() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("crew member THE");
        assert!(!dets.iter().any(|d| d.entity_type == "CREW_CODE" && d.original == "THE"));
    }

    #[test]
    fn test_ip() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("server at 192.168.1.100");
        assert!(result.contains("[IP_1]"));
    }

    #[test]
    fn test_uuid() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("id: 550e8400-e29b-41d4-a716-446655440000");
        assert!(result.contains("[UUID_1]"));
    }

    #[test]
    fn test_threshold() {
        let mut a = Anonymizer::new(0.8);
        let (_, dets) = a.anonymize_text("visit https://example.com call 06 12 34 56 78");
        // URL (0.9) should pass, fr_phone_national (0.7) should be filtered
        assert!(dets.iter().any(|d| d.entity_type == "URL"));
        assert!(!dets.iter().any(|d| d.entity_type == "FR_PHONE"));
    }

    #[test]
    fn test_consistency() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("john@example.com and john@example.com again");
        assert_eq!(result.matches("[EMAIL_1]").count(), 2);
    }

    #[test]
    fn test_json_processing() {
        let mut a = Anonymizer::new(0.0);
        let json = serde_json::json!({
            "email": "john@example.com",
            "count": 42,
            "active": true,
            "nested": {
                "phone": "+33 6 12 34 56 78"
            }
        });
        let (result, dets) = a.anonymize_json_value(&json);
        assert_eq!(dets.len(), 2);
        assert_eq!(result["count"], 42);
        assert_eq!(result["active"], true);
        assert!(result["email"].as_str().unwrap().contains("[EMAIL_1]"));
        assert!(result["nested"]["phone"].as_str().unwrap().contains("[FR_PHONE_1]"));
    }

    #[test]
    fn test_mapping_roundtrip() {
        let mut a = Anonymizer::new(0.0);
        let original = "contact john@example.com at 192.168.1.1";
        let (anonymized, _) = a.anonymize_text(original);
        let restored = a.mapping.restore(&anonymized);
        assert_eq!(restored, original);
    }

    #[test]
    fn test_format_detection_json() {
        assert_eq!(detect_format(r#"{"key": "value"}"#), Format::Json);
        assert_eq!(detect_format(r#"[1, 2, 3]"#), Format::Json);
    }

    #[test]
    fn test_format_detection_text() {
        assert_eq!(detect_format("hello world"), Format::Text);
        assert_eq!(detect_format("{invalid json"), Format::Text);
    }

    #[test]
    fn test_utf8_context_window() {
        let mut a = Anonymizer::new(0.0);
        // French accented text with crew code context — should not panic
        let input = "L'équipage était composé du pilote JDU et du copilote André résumé";
        let (result, dets) = a.anonymize_text(input);
        assert!(dets.iter().any(|d| d.entity_type == "CREW_CODE"));
        assert!(result.contains("[CREW_CODE_1]"));
    }

    #[test]
    fn test_utf8_email_in_accented_text() {
        let mut a = Anonymizer::new(0.0);
        let input = "Héloïse a envoyé un mail à héloïse@example.com depuis Zürich";
        let (result, _) = a.anonymize_text(input);
        assert!(result.contains("[EMAIL_1]"));
        // Verify the surrounding accented text is preserved
        assert!(result.contains("Héloïse"));
        assert!(result.contains("Zürich"));
    }
}
