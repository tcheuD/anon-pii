use clap::{Parser, Subcommand};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

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

    /// Show detected entities
    #[arg(short, long)]
    verbose: bool,
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
        // Check if already mapped
        for (token, val) in &self.mappings {
            if val == original {
                return token.clone();
            }
        }

        // Count existing tokens of this type
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
        for (token, original) in &self.mappings {
            result = result.replace(token, original);
        }
        result
    }
}

struct PiiPattern {
    name: &'static str,
    entity_type: &'static str,
    pattern: &'static str,
}

const PATTERNS: &[PiiPattern] = &[
    // Email
    PiiPattern {
        name: "email",
        entity_type: "EMAIL",
        pattern: r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    },
    // French phone numbers
    PiiPattern {
        name: "fr_phone_intl",
        entity_type: "FR_PHONE",
        pattern: r"\+33\s?[1-9](?:[\s.\-]?\d{2}){4}",
    },
    PiiPattern {
        name: "fr_phone_national",
        entity_type: "FR_PHONE",
        pattern: r"\b0[1-9](?:[\s.\-]?\d{2}){4}\b",
    },
    // French IBAN
    PiiPattern {
        name: "fr_iban",
        entity_type: "FR_IBAN",
        pattern: r"FR\d{2}[\s]?(?:\d{4}[\s]?){5}\d{3}",
    },
    // French SSN (NIR)
    PiiPattern {
        name: "fr_ssn",
        entity_type: "FR_SSN",
        pattern: r"[12]\s?\d{2}\s?(?:0[1-9]|1[0-2]|[2-9]\d)\s?(?:\d{2}|2[AB])\s?\d{3}\s?\d{3}(?:\s?\d{2})?",
    },
    // Aircraft registration (French)
    PiiPattern {
        name: "aircraft_fr",
        entity_type: "AIRCRAFT",
        pattern: r"\bF-[A-Z]{4}\b",
    },
    // Aircraft registration (other European)
    PiiPattern {
        name: "aircraft_eu",
        entity_type: "AIRCRAFT",
        pattern: r"\b(?:D|G|I|EC|HB|OO|PH|OE|SE|LN|OH|CS|EI|9H)-[A-Z]{3,4}\b",
    },
    // Flight numbers (Amelia + common)
    PiiPattern {
        name: "flight_amelia",
        entity_type: "FLIGHT",
        pattern: r"\b(?:IZM|RLA|AME|GJT|AF)[0-9]{1,4}\b",
    },
    // IP addresses
    PiiPattern {
        name: "ipv4",
        entity_type: "IP",
        pattern: r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    },
    // Credit card (basic)
    PiiPattern {
        name: "credit_card",
        entity_type: "CREDIT_CARD",
        pattern: r"\b(?:\d{4}[\s\-]?){3}\d{4}\b",
    },
    // UUID
    PiiPattern {
        name: "uuid",
        entity_type: "UUID",
        pattern: r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
    },
];

struct Anonymizer {
    patterns: Vec<(String, Regex)>,
    mapping: Mapping,
}

#[derive(Debug)]
struct Detection {
    entity_type: String,
    original: String,
    start: usize,
    end: usize,
}

impl Anonymizer {
    fn new() -> Self {
        let patterns = PATTERNS
            .iter()
            .map(|p| (p.entity_type.to_string(), Regex::new(p.pattern).unwrap()))
            .collect();

        Self {
            patterns,
            mapping: Mapping::new(),
        }
    }

    fn anonymize(&mut self, text: &str) -> (String, Vec<Detection>) {
        let mut detections: Vec<Detection> = Vec::new();

        // Find all matches
        for (entity_type, regex) in &self.patterns {
            for mat in regex.find_iter(text) {
                detections.push(Detection {
                    entity_type: entity_type.clone(),
                    original: mat.as_str().to_string(),
                    start: mat.start(),
                    end: mat.end(),
                });
            }
        }

        // Sort by start position (descending) for safe replacement
        detections.sort_by(|a, b| b.start.cmp(&a.start));

        // Remove overlapping detections (keep first/longer)
        let mut filtered: Vec<Detection> = Vec::new();
        for det in detections {
            let overlaps = filtered
                .iter()
                .any(|f| det.start < f.end && det.end > f.start);
            if !overlaps {
                filtered.push(det);
            }
        }

        // Sort back for display
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
}

fn read_input(path: Option<&PathBuf>) -> io::Result<String> {
    match path {
        Some(p) => fs::read_to_string(p),
        None => {
            let mut buffer = String::new();
            io::stdin().read_to_string(&mut buffer)?;
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

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Restore { input, mapping, output }) => {
            let content = read_input(input.as_ref())?;
            let mapping_content = fs::read_to_string(&mapping)?;
            let mapping: Mapping = serde_json::from_str(&mapping_content)
                .expect("Invalid mapping file");

            let result = mapping.restore(&content);
            write_output(output.as_ref(), &result)?;

            eprintln!("Restored {} entities", mapping.mappings.len());
        }
        Some(Commands::ListEntities) => {
            println!("Supported entity types:\n");
            let mut seen = std::collections::HashSet::new();
            for p in PATTERNS {
                if seen.insert(p.entity_type) {
                    println!("  {} - {}", p.entity_type, p.name);
                }
            }
        }
        None => {
            // Check if we have input
            if cli.input.is_none() && atty::is(atty::Stream::Stdin) {
                eprintln!("No input provided. Use --help for usage.");
                std::process::exit(1);
            }

            let content = read_input(cli.input.as_ref())?;
            let mut anonymizer = Anonymizer::new();
            let (result, detections) = anonymizer.anonymize(&content);

            write_output(cli.output.as_ref(), &result)?;

            if let Some(mapping_path) = cli.mapping {
                let mapping_json = serde_json::to_string_pretty(&anonymizer.mapping)?;
                fs::write(&mapping_path, &mapping_json)?;
                if cli.verbose {
                    eprintln!("Mapping saved to {:?}", mapping_path);
                }
            }

            if cli.verbose && !detections.is_empty() {
                eprintln!("\nDetected entities:");
                for det in &detections {
                    eprintln!(
                        "  {} : {:?} -> [{}]",
                        det.entity_type,
                        det.original,
                        det.entity_type
                    );
                }
            }
        }
    }

    Ok(())
}
