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
    #[arg(long, default_value = "0.5")]
    threshold: f64,

    /// Language for detection
    #[arg(short, long, default_value = "en")]
    language: String,
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
    Sql,
    Csv,
}

// ─── Mapping ────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct Mapping {
    session_id: String,
    created_at: String,
    mappings: HashMap<String, String>,
    #[serde(skip)]
    reverse: HashMap<String, String>,
    #[serde(skip)]
    counters: HashMap<String, usize>,
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Howard Hinnant's civil calendar algorithm
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { yoe + era * 400 + 1 } else { yoe + era * 400 };
    (y, m, d)
}

impl Mapping {
    fn new() -> Self {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hasher};
        use std::time::{SystemTime, UNIX_EPOCH};

        let session_id = format!(
            "{:08x}",
            RandomState::new().build_hasher().finish() as u32
        );

        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let day_secs = secs % 86400;
        let (year, month, day) = days_to_ymd(secs / 86400);
        let created_at = format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}+00:00",
            day_secs / 3600,
            (day_secs % 3600) / 60,
            day_secs % 60
        );

        Self {
            session_id,
            created_at,
            mappings: HashMap::new(),
            reverse: HashMap::new(),
            counters: HashMap::new(),
        }
    }

    fn add(&mut self, entity_type: &str, original: &str) -> String {
        if let Some(token) = self.reverse.get(original) {
            return token.clone();
        }

        let counter = self.counters.entry(entity_type.to_string()).or_insert(0);
        *counter += 1;
        let token = format!("[{}_{counter}]", entity_type);

        self.mappings.insert(token.clone(), original.to_string());
        self.reverse.insert(original.to_string(), token.clone());
        token
    }

    fn rebuild_caches(&mut self) {
        self.reverse.clear();
        self.counters.clear();
        for (token, original) in &self.mappings {
            self.reverse.insert(original.clone(), token.clone());
            if let Some(inner) = token.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
                if let Some(pos) = inner.rfind('_') {
                    if let Ok(n) = inner[pos + 1..].parse::<usize>() {
                        let counter = self.counters.entry(inner[..pos].to_string()).or_insert(0);
                        *counter = (*counter).max(n);
                    }
                }
            }
        }
    }

    fn restore(&self, text: &str) -> String {
        let mut result = String::with_capacity(text.len());
        let bytes = text.as_bytes();
        let mut i = 0;

        while i < bytes.len() {
            if bytes[i] == b'[' {
                if let Some(close) = text[i..].find(']') {
                    let candidate = &text[i..i + close + 1];
                    if let Some(original) = self.mappings.get(candidate) {
                        result.push_str(original);
                        i += close + 1;
                        continue;
                    }
                }
            }
            let ch = text[i..].chars().next().unwrap();
            result.push(ch);
            i += ch.len_utf8();
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
    /// If true, context keywords are required (no keyword = no match).
    /// If false and context_keywords is non-empty, keywords boost the score.
    context_required: bool,
}

const PATTERNS: &[PiiPattern] = &[
    // ── Email ──
    PiiPattern {
        name: "email",
        entity_type: "EMAIL_ADDRESS",
        pattern: r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        score: 0.9,
        context_keywords: &[],
        context_required: false,
    },
    // ── URL ──
    PiiPattern {
        name: "url",
        entity_type: "URL",
        pattern: r#"https?://[^\s\)\]>"']+[^\s\)\]>"'.,;:!?]"#,
        score: 0.9,
        context_keywords: &[],
        context_required: false,
    },
    // ── French phone numbers ──
    PiiPattern {
        name: "fr_phone_intl",
        entity_type: "FR_PHONE_NUMBER",
        pattern: r"\+33\s?[1-9](?:[\s.\-]?\d{2}){4}",
        score: 0.9,
        context_keywords: &[
            "telephone", "tel", "phone", "mobile", "contact", "appeler", "numero", "portable",
        ],
        context_required: false,
    },
    PiiPattern {
        name: "fr_phone_national",
        entity_type: "FR_PHONE_NUMBER",
        pattern: r"\b0[1-9](?:[\s.\-]?\d{2}){4}\b",
        score: 0.7,
        context_keywords: &[
            "telephone", "tel", "phone", "mobile", "contact", "appeler", "numero", "portable",
        ],
        context_required: false,
    },
    PiiPattern {
        name: "fr_phone_compact",
        entity_type: "FR_PHONE_NUMBER",
        pattern: r"\b0[1-9]\d{8}\b",
        score: 0.6,
        context_keywords: &[
            "telephone", "tel", "phone", "mobile", "contact", "appeler", "numero", "portable",
        ],
        context_required: false,
    },
    // ── French IBAN ──
    PiiPattern {
        name: "fr_iban",
        entity_type: "FR_IBAN",
        pattern: r"FR\d{2}[\s]?(?:\d{4}[\s]?){5}\d{3}",
        score: 0.95,
        context_keywords: &[
            "iban", "compte", "account", "virement", "bank", "banque", "bancaire",
        ],
        context_required: false,
    },
    PiiPattern {
        name: "fr_iban_compact",
        entity_type: "FR_IBAN",
        pattern: r"FR\d{25}",
        score: 0.9,
        context_keywords: &[
            "iban", "compte", "account", "virement", "bank", "banque", "bancaire",
        ],
        context_required: false,
    },
    // ── French SSN (NIR) ──
    PiiPattern {
        name: "fr_ssn",
        entity_type: "FR_SSN",
        pattern: r"[12]\s?\d{2}\s?(?:0[1-9]|1[0-2]|[2-9]\d)\s?(?:\d{2}|2[AB])\s?\d{3}\s?\d{3}(?:\s?\d{2})?",
        score: 0.85,
        context_keywords: &[
            "secu", "securite sociale", "ssn", "nir", "carte vitale", "numero", "immatriculation",
        ],
        context_required: false,
    },
    PiiPattern {
        name: "fr_ssn_compact",
        entity_type: "FR_SSN",
        pattern: r"[12]\d{2}(?:0[1-9]|1[0-2]|[2-9]\d)(?:\d{2}|2[AB])\d{6}(?:\d{2})?",
        score: 0.8,
        context_keywords: &[
            "secu", "securite sociale", "ssn", "nir", "carte vitale", "numero", "immatriculation",
        ],
        context_required: false,
    },
    // ── French passport ──
    PiiPattern {
        name: "fr_passport",
        entity_type: "FR_PASSPORT",
        pattern: r"\b\d{2}[A-Z]{2}\d{5}\b",
        score: 0.7,
        context_keywords: &["passeport", "passport", "document", "identite", "identité"],
        context_required: true,
    },
    // ── Aircraft registration ──
    PiiPattern {
        name: "aircraft_fr",
        entity_type: "AIRCRAFT_REGISTRATION",
        pattern: r"\bF-[A-Z]{4}\b",
        score: 0.95,
        context_keywords: &[],
        context_required: false,
    },
    PiiPattern {
        name: "aircraft_eu",
        entity_type: "AIRCRAFT_REGISTRATION",
        pattern: r"\b(?:D|G|I|EC|HB|OO|PH|OE|SE|LN|OH|CS|EI|9H)-[A-Z]{3,4}\b",
        score: 0.9,
        context_keywords: &[],
        context_required: false,
    },
    PiiPattern {
        name: "aircraft_us",
        entity_type: "AIRCRAFT_REGISTRATION",
        pattern: r"\bN[1-9][0-9]{0,4}[A-Z]{0,2}\b",
        score: 0.85,
        context_keywords: &[
            "aircraft", "avion", "registration", "immat", "appareil", "tail", "immatriculation",
        ],
        context_required: true,
    },
    // ── Flight numbers ──
    PiiPattern {
        name: "flight_amelia",
        entity_type: "FLIGHT_NUMBER",
        pattern: r"\b(?:IZM|RLA|AME|GJT|AF)[0-9]{1,4}\b",
        score: 0.9,
        context_keywords: &[],
        context_required: false,
    },
    PiiPattern {
        name: "flight_iata",
        entity_type: "FLIGHT_NUMBER",
        pattern: r"\b[A-Z]{2}[0-9]{1,4}\b",
        score: 0.4,
        context_keywords: &[
            "flight", "vol", "departure", "arrival", "schedule", "rotation", "leg", "sector",
        ],
        context_required: true,
    },
    PiiPattern {
        name: "flight_icao",
        entity_type: "FLIGHT_NUMBER",
        pattern: r"\b[A-Z]{3}[0-9]{1,4}\b",
        score: 0.5,
        context_keywords: &[
            "flight", "vol", "departure", "arrival", "schedule", "rotation", "leg", "sector",
        ],
        context_required: true,
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
        context_required: true,
    },
    // ── IP addresses ──
    PiiPattern {
        name: "ipv4",
        entity_type: "IP_ADDRESS",
        pattern: r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        score: 0.9,
        context_keywords: &[],
        context_required: false,
    },
    // ── Credit card ──
    PiiPattern {
        name: "credit_card",
        entity_type: "CREDIT_CARD",
        pattern: r"\b(?:\d{4}[\s\-]?){3}\d{4}\b",
        score: 0.7,
        context_keywords: &[
            "card", "credit", "payment", "cc", "visa", "mastercard", "amex",
            "cb", "carte", "bancaire", "debit", "paiement",
        ],
        context_required: true,
    },
    // ── UUID ──
    PiiPattern {
        name: "uuid",
        entity_type: "UUID",
        pattern: r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
        score: 0.95,
        context_keywords: &[],
        context_required: false,
    },
    // ── Cryptocurrency ──
    PiiPattern {
        name: "crypto_bitcoin",
        entity_type: "CRYPTO",
        pattern: r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
        score: 0.9,
        context_keywords: &[],
        context_required: false,
    },
    PiiPattern {
        name: "crypto_ethereum",
        entity_type: "CRYPTO",
        pattern: r"\b0x[0-9a-fA-F]{40}\b",
        score: 0.9,
        context_keywords: &[],
        context_required: false,
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
const CONTEXT_SCORE_BOOST: f64 = 0.15;
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
    entity_type: &'static str,
    #[allow(dead_code)]
    name: &'static str,
    regex: Regex,
    score: f64,
    context_keywords: &'static [&'static str],
    context_required: bool,
}

#[derive(Debug)]
struct Detection {
    entity_type: &'static str,
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
                entity_type: p.entity_type,
                name: p.name,
                regex: Regex::new(p.pattern)
                    .unwrap_or_else(|e| panic!("invalid regex for pattern '{}': {}", p.name, e)),
                score: p.score,
                context_keywords: p.context_keywords,
                context_required: p.context_required,
            })
            .collect();

        Self {
            patterns,
            mapping: Mapping::new(),
            threshold,
        }
    }

    fn has_context(&self, text: &str, start: usize, end: usize, keywords: &[&str]) -> bool {
        if keywords.is_empty() {
            return false;
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
        keywords.iter().any(|kw| lower.contains(*kw))
    }

    fn anonymize_text(&mut self, text: &str) -> (String, Vec<Detection>) {
        let mut detections: Vec<Detection> = Vec::new();

        for pat in &self.patterns {
            // Early threshold check: consider maximum possible score (with boost)
            let max_score = if !pat.context_keywords.is_empty() && !pat.context_required {
                (pat.score + CONTEXT_SCORE_BOOST).min(1.0)
            } else {
                pat.score
            };
            if max_score < self.threshold {
                continue;
            }

            for mat in pat.regex.find_iter(text) {
                // Check context presence
                let has_ctx = if !pat.context_keywords.is_empty() {
                    self.has_context(text, mat.start(), mat.end(), pat.context_keywords)
                } else {
                    false
                };

                // Context gating: required mode skips when no context found
                if pat.context_required && !pat.context_keywords.is_empty() && !has_ctx {
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

                // Compute detection score with optional context boost
                let detection_score = if !pat.context_required && !pat.context_keywords.is_empty() && has_ctx {
                    (pat.score + CONTEXT_SCORE_BOOST).min(1.0)
                } else {
                    pat.score
                };

                // Per-detection threshold check (for boost patterns without context)
                if detection_score < self.threshold {
                    continue;
                }

                detections.push(Detection {
                    entity_type: pat.entity_type,
                    original: mat.as_str().to_string(),
                    start: mat.start(),
                    end: mat.end(),
                    score: detection_score,
                });
            }
        }

        // Sort by position asc, then span length desc, then score desc
        // Matches Python/Presidio overlap resolution: position-first
        detections.sort_by(|a, b| {
            a.start.cmp(&b.start)
                .then_with(|| (b.end - b.start).cmp(&(a.end - a.start)))
                .then_with(|| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal))
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
            let token = self.mapping.add(det.entity_type, &det.original);
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

enum DetectedFormat {
    Json(Value),
    Sql,
    Csv,
    Text,
}

fn detect_format(content: &str) -> DetectedFormat {
    let trimmed = content.trim_start();

    // JSON
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
            return DetectedFormat::Json(value);
        }
    }

    // SQL
    if let Some(first_word) = trimmed.split_whitespace().next() {
        match first_word.to_uppercase().as_str() {
            "SELECT" | "INSERT" | "UPDATE" | "DELETE" | "CREATE" | "ALTER" | "DROP" => {
                return DetectedFormat::Sql;
            }
            _ => {}
        }
    }

    // CSV: multiple lines with consistent comma counts
    let lines: Vec<&str> = trimmed.lines().collect();
    if lines.len() > 1 && lines[0].contains(',') {
        let counts: Vec<usize> = lines
            .iter()
            .take(5)
            .filter(|l| !l.trim().is_empty())
            .map(|l| l.matches(',').count())
            .collect();
        if !counts.is_empty() {
            let first = counts[0] as isize;
            if counts.iter().all(|&c| (c as isize - first).abs() <= 1) {
                return DetectedFormat::Csv;
            }
        }
    }

    DetectedFormat::Text
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
            input_positional,
            input,
            mapping,
            output,
        }) => {
            let resolved_input = input.or(input_positional);
            let content = read_input(resolved_input.as_ref())?;
            let mapping_content = fs::read_to_string(&mapping)?;
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

            // Determine format and process
            let (parsed_json, format_name) = match cli.format {
                Format::Json => match serde_json::from_str::<Value>(content.trim()) {
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
    fn test_email() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("contact john@example.com now");
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].entity_type, "EMAIL_ADDRESS");
        assert!(result.contains("[EMAIL_ADDRESS_1]"));
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
        assert!(result.contains("[FR_PHONE_NUMBER_1]"));
    }

    #[test]
    fn test_fr_phone_national() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("call 06 12 34 56 78");
        assert!(result.contains("[FR_PHONE_NUMBER_1]"));
    }

    #[test]
    fn test_fr_phone_compact() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("appeler 0612345678 rapidement");
        assert!(result.contains("[FR_PHONE_NUMBER_"));
        assert!(!result.contains("0612345678"));
    }

    #[test]
    fn test_fr_iban() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("IBAN: FR76 1234 5678 9012 3456 7890 123");
        assert!(result.contains("[FR_IBAN_1]"));
    }

    #[test]
    fn test_fr_iban_compact() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("IBAN: FR7630006000011234567890189");
        assert!(result.contains("[FR_IBAN_"));
    }

    #[test]
    fn test_fr_ssn() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("NIR: 1 85 12 75 123 456 78");
        assert!(result.contains("[FR_SSN_1]"));
    }

    #[test]
    fn test_fr_ssn_compact() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("NIR: 185127512345678");
        assert!(result.contains("[FR_SSN_"));
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
        assert!(result.contains("[AIRCRAFT_REGISTRATION_1]"));
    }

    #[test]
    fn test_aircraft_us_with_context() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("aircraft N12345 ready");
        assert!(dets.iter().any(|d| d.entity_type == "AIRCRAFT_REGISTRATION"));
        assert!(result.contains("[AIRCRAFT_REGISTRATION_1]"));
    }

    #[test]
    fn test_aircraft_us_two_letter_suffix() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("aircraft N12345AB ready");
        assert!(result.contains("[AIRCRAFT_REGISTRATION_"));
        assert!(!result.contains("N12345AB"));
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
        assert!(result.contains("[IP_ADDRESS_1]"));
    }

    #[test]
    fn test_uuid() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("id: 550e8400-e29b-41d4-a716-446655440000");
        assert!(result.contains("[UUID_1]"));
    }

    #[test]
    fn test_crypto_ethereum() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("wallet: 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18");
        assert!(dets.iter().any(|d| d.entity_type == "CRYPTO"));
        assert!(result.contains("[CRYPTO_1]"));
    }

    #[test]
    fn test_threshold() {
        let mut a = Anonymizer::new(0.8);
        let (_, dets) = a.anonymize_text("visit https://example.com call 06 12 34 56 78");
        // URL (0.9) should pass, fr_phone_national (0.7) should be filtered
        assert!(dets.iter().any(|d| d.entity_type == "URL"));
        assert!(!dets.iter().any(|d| d.entity_type == "FR_PHONE_NUMBER"));
    }

    #[test]
    fn test_consistency() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("john@example.com and john@example.com again");
        assert_eq!(result.matches("[EMAIL_ADDRESS_1]").count(), 2);
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
        assert!(result["email"].as_str().unwrap().contains("[EMAIL_ADDRESS_1]"));
        assert!(result["nested"]["phone"].as_str().unwrap().contains("[FR_PHONE_NUMBER_1]"));
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
        assert!(matches!(detect_format(r#"{"key": "value"}"#), DetectedFormat::Json(_)));
        assert!(matches!(detect_format(r#"[1, 2, 3]"#), DetectedFormat::Json(_)));
    }

    #[test]
    fn test_format_detection_text() {
        assert!(matches!(detect_format("hello world"), DetectedFormat::Text));
        assert!(matches!(detect_format("{invalid json"), DetectedFormat::Text));
    }

    #[test]
    fn test_format_detection_sql() {
        assert!(matches!(detect_format("SELECT * FROM users WHERE id = 1"), DetectedFormat::Sql));
        assert!(matches!(detect_format("INSERT INTO logs VALUES (1, 'test')"), DetectedFormat::Sql));
        assert!(matches!(detect_format("  DELETE FROM sessions"), DetectedFormat::Sql));
    }

    #[test]
    fn test_format_detection_csv() {
        let csv = "name,email,phone\nJohn,john@test.com,0612345678\nJane,jane@test.com,0698765432";
        assert!(matches!(detect_format(csv), DetectedFormat::Csv));
        // Single line with commas is not CSV
        assert!(!matches!(detect_format("hello, world, foo"), DetectedFormat::Csv));
    }

    #[test]
    fn test_context_score_boost() {
        // Without context keyword: base score
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("call 06 12 34 56 78");
        let phone_det = dets.iter().find(|d| d.entity_type == "FR_PHONE_NUMBER").unwrap();
        assert!((phone_det.score - 0.7).abs() < 0.01);

        // With context keyword "telephone": boosted score
        let mut a2 = Anonymizer::new(0.0);
        let (_, dets2) = a2.anonymize_text("telephone 06 12 34 56 78");
        let phone_det2 = dets2.iter().find(|d| d.entity_type == "FR_PHONE_NUMBER").unwrap();
        assert!((phone_det2.score - 0.85).abs() < 0.01); // 0.7 + 0.15 boost
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
        assert!(result.contains("[EMAIL_ADDRESS_1]"));
        // Verify the surrounding accented text is preserved
        assert!(result.contains("Héloïse"));
        assert!(result.contains("Zürich"));
    }
}
