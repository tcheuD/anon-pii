//! README.md auto-updater for anon.
//!
//! Parses marker sections (`<!-- BEGIN X -->...<!-- END X -->`) and replaces
//! them with dynamically generated content from the codebase.

use std::collections::HashSet;
use std::fs;
use std::process;

use anon::cli::Cli;
use anon::patterns::PATTERNS;
use clap::CommandFactory;

/// Known 2-letter country prefixes for entity types.
const COUNTRY_PREFIXES: &[&str] = &[
    "FR", "US", "UK", "ES", "IT", "IN", "AU", "KR", "SG", "PL", "SI", "FI", "TH",
];

/// Replaces content between `<!-- BEGIN {name} -->` and `<!-- END {name} -->`
/// markers with new content.
///
/// Returns `Some(updated_string)` if markers are found, `None` otherwise.
/// The markers themselves are preserved; only the content between them is replaced.
fn replace_marker(readme: &str, name: &str, new_content: &str) -> Option<String> {
    let begin_marker = format!("<!-- BEGIN {} -->", name);
    let end_marker = format!("<!-- END {} -->", name);

    let begin_pos = readme.find(&begin_marker)?;
    let end_pos = readme.find(&end_marker)?;

    // Sanity check: BEGIN must come before END
    if begin_pos >= end_pos {
        return None;
    }

    let before = &readme[..begin_pos + begin_marker.len()];
    let after = &readme[end_pos..];

    Some(format!("{}\n{}\n{}", before, new_content, after))
}

/// Extracts a country code from an entity type prefix if it matches a known country.
///
/// Returns `Some("FR")` for `FR_SSN`, `None` for `EMAIL_ADDRESS`.
fn country_from_prefix(entity_type: &str) -> Option<&'static str> {
    // Split on first underscore
    let prefix = entity_type.split('_').next()?;

    // Check if it's a known 2-letter country prefix
    if prefix.len() == 2 {
        for &country in COUNTRY_PREFIXES {
            if prefix.eq_ignore_ascii_case(country) {
                return Some(country);
            }
        }
    }
    None
}

/// Generates the entities section paragraph for README.md.
///
/// Introspects `PATTERNS` to compute counts and produce a formatted description.
fn generate_entities_section() -> String {
    // Collect unique entity types
    let entity_types: HashSet<&str> = PATTERNS.iter().map(|p| p.entity_type).collect();
    let entity_count = entity_types.len();
    let pattern_count = PATTERNS.len();

    // Extract unique countries
    let countries: HashSet<&str> = entity_types
        .iter()
        .filter_map(|et| country_from_prefix(et))
        .collect();
    let country_count = countries.len();

    // Sort countries alphabetically
    let mut country_list: Vec<&str> = countries.into_iter().collect();
    country_list.sort();
    let country_list_str = country_list.join(", ");

    format!(
        "{} entity types across {} patterns covering {} countries: emails, URLs, IPs, UUIDs, \
         credit cards, IBANs, phones, dates, crypto addresses, MAC addresses, secrets/tokens, \
         and person names (with `--ner`). Country-specific patterns include SSNs, passports, \
         driver's licenses, tax IDs, and national IDs for {} \u{2014} each with checksum \
         validation where applicable. Detection works through URL-encoded and Unicode-escaped text.\n\n\
         See [docs/entities.md](docs/entities.md) for the full reference with confidence scores and context keywords.",
        entity_count, pattern_count, country_count, country_list_str
    )
}

/// Returns the feature requirement note for a subcommand, if any.
fn feature_note(name: &str) -> Option<&'static str> {
    match name {
        "download-model" => Some("requires `ner` feature"),
        "api" | "ui" | "proxy" => Some("requires `proxy` feature"),
        "image" => Some("requires `image` feature"),
        "pdf" => Some("requires `pdf` feature"),
        _ => None,
    }
}

/// Generates the commands section listing all subcommands.
///
/// Uses `clap::CommandFactory` to introspect the CLI and produce a bash code block
/// showing each subcommand with its description.
fn generate_commands_section() -> String {
    let cmd = Cli::command();
    let mut lines = Vec::new();

    for sub in cmd.get_subcommands() {
        let name = sub.get_name();
        let about = sub.get_about().map(|s| s.to_string()).unwrap_or_default();

        // Collect positional arguments
        let positionals: Vec<String> = sub
            .get_arguments()
            .filter(|arg| arg.is_positional())
            .map(|arg| {
                let id = arg.get_id().as_str().to_uppercase();
                if arg.is_required_set() {
                    format!("<{}>", id)
                } else {
                    format!("[{}]", id)
                }
            })
            .collect();

        let args_str = if positionals.is_empty() {
            String::new()
        } else {
            format!(" {}", positionals.join(" "))
        };

        // Build the line with optional feature note
        let line = if let Some(note) = feature_note(name) {
            format!("anon {}{:<16} # {} ({})", name, args_str, about, note)
        } else {
            format!("anon {}{:<16} # {}", name, args_str, about)
        };

        lines.push(line);
    }

    format!("```bash\n{}\n```", lines.join("\n"))
}

/// Formats a CLI table from a clap Command's arguments.
fn format_cli_table(cmd: &clap::Command) -> String {
    let mut rows = Vec::new();

    for arg in cmd.get_arguments() {
        let id = arg.get_id().as_str();

        // Skip help and version
        if id == "help" || id == "version" {
            continue;
        }

        // Option column: --name or POSITIONAL
        let option_col = if let Some(long) = arg.get_long() {
            format!("`--{}`", long)
        } else if arg.is_positional() {
            format!("`{}`", id.to_uppercase())
        } else {
            continue; // Skip if no long option and not positional
        };

        // Short column
        let short_col = arg
            .get_short()
            .map(|c| format!("`-{}`", c))
            .unwrap_or_default();

        // Default column
        let default_col = arg
            .get_default_values()
            .first()
            .map(|v| format!("`{}`", v.to_string_lossy()))
            .unwrap_or_default();

        // Description column
        let desc_col = arg.get_help().map(|s| s.to_string()).unwrap_or_default();

        rows.push(format!(
            "| {} | {} | {} | {} |",
            option_col, short_col, default_col, desc_col
        ));
    }

    let header =
        "| Option | Short | Default | Description |\n|--------|-------|---------|-------------|";
    format!("{}\n{}", header, rows.join("\n"))
}

/// Generates the CLI options table for the main anonymize command.
fn generate_cli_anonymize_section() -> String {
    let cmd = Cli::command();
    format_cli_table(&cmd)
}

/// Generates the CLI options table for the restore subcommand.
fn generate_cli_restore_section() -> String {
    let cmd = Cli::command();
    for sub in cmd.get_subcommands() {
        if sub.get_name() == "restore" {
            return format_cli_table(sub);
        }
    }
    // Fallback if restore not found
    "| Option | Short | Default | Description |\n|--------|-------|---------|-------------|"
        .to_string()
}

/// Generates the benchmark section from cached results.
///
/// Returns `None` if the cache file doesn't exist or is invalid.
fn generate_benchmark_section_from(path: &str) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;
    let features = json.get("features")?.as_object()?;

    let feature_order = ["regex-only", "ner-lite (heuristic)", "ner (ML)"];

    let mut rows = Vec::new();
    for &feature in &feature_order {
        if let Some(data) = features.get(feature) {
            let lines_per_sec = data.get("lines_per_sec")?.as_u64()?;
            let simple_avg = data.get("simple_avg_us")?.as_str()?;
            let complex_avg = data.get("complex_avg_us")?.as_str()?;
            let penalty = data.get("penalty")?.as_str()?;

            // Format throughput as Nk if >= 1000
            let throughput_str = if lines_per_sec >= 1000 {
                format!("{}k", lines_per_sec / 1000)
            } else {
                lines_per_sec.to_string()
            };

            rows.push(format!(
                "| {} | {} lines/s | {} \u{03bc}s | {} \u{03bc}s | {}x |",
                feature, throughput_str, simple_avg, complex_avg, penalty
            ));
        }
    }

    if rows.is_empty() {
        return None;
    }

    let header = "| Feature | Throughput | Simple avg | Complex avg | Penalty |\n|---------|------------|------------|-------------|---------|";
    Some(format!("{}\n{}", header, rows.join("\n")))
}

/// Generates the benchmark section from the default cache file.
fn generate_benchmark_section() -> Option<String> {
    generate_benchmark_section_from("bench-results.json")
}

fn main() {
    let readme_path = "README.md";
    let original = fs::read_to_string(readme_path).unwrap_or_else(|e| {
        eprintln!("Failed to read {}: {}", readme_path, e);
        process::exit(2);
    });

    let mut readme = original.clone();
    let mut updated_sections = Vec::new();

    // Apply each generator
    let sections: Vec<(&str, Option<String>)> = vec![
        ("ENTITIES", Some(generate_entities_section())),
        ("COMMANDS", Some(generate_commands_section())),
        ("CLI_ANONYMIZE", Some(generate_cli_anonymize_section())),
        ("CLI_RESTORE", Some(generate_cli_restore_section())),
        ("BENCHMARK", generate_benchmark_section()),
    ];

    for (name, content) in sections {
        if let Some(content) = content {
            if let Some(r) = replace_marker(&readme, name, &content) {
                readme = r;
                updated_sections.push(name);
            }
        }
    }

    if readme == original {
        eprintln!("README.md is up to date.");
        process::exit(0);
    }

    fs::write(readme_path, &readme).unwrap_or_else(|e| {
        eprintln!("Failed to write {}: {}", readme_path, e);
        process::exit(2);
    });

    eprintln!(
        "README.md updated: {} section(s) refreshed ({}).",
        updated_sections.len(),
        updated_sections.join(", ")
    );
    process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replace_marker_basic() {
        let input = "before\n<!-- BEGIN FOO -->\nold content\n<!-- END FOO -->\nafter";
        let result = replace_marker(input, "FOO", "new content").unwrap();
        assert_eq!(
            result,
            "before\n<!-- BEGIN FOO -->\nnew content\n<!-- END FOO -->\nafter"
        );
    }

    #[test]
    fn test_replace_marker_not_found() {
        assert!(replace_marker("no markers here", "FOO", "content").is_none());
    }

    #[test]
    fn test_replace_marker_multiline_content() {
        let input = "<!-- BEGIN X -->\nold\n<!-- END X -->";
        let result = replace_marker(input, "X", "line1\nline2\nline3").unwrap();
        assert!(result.contains("line1\nline2\nline3"));
        assert!(result.starts_with("<!-- BEGIN X -->\n"));
        assert!(result.ends_with("\n<!-- END X -->"));
    }

    #[test]
    fn test_replace_marker_preserves_surrounding() {
        let input = "header\n\n<!-- BEGIN TEST -->\nwill be replaced\n<!-- END TEST -->\n\nfooter";
        let result = replace_marker(input, "TEST", "new stuff").unwrap();
        assert!(result.starts_with("header\n\n<!-- BEGIN TEST -->\n"));
        assert!(result.ends_with("\n<!-- END TEST -->\n\nfooter"));
        assert!(result.contains("new stuff"));
    }

    #[test]
    fn test_replace_marker_end_before_begin_returns_none() {
        let input = "<!-- END FOO -->\n<!-- BEGIN FOO -->";
        assert!(replace_marker(input, "FOO", "content").is_none());
    }

    #[test]
    fn test_replace_marker_missing_begin() {
        let input = "text\n<!-- END FOO -->";
        assert!(replace_marker(input, "FOO", "content").is_none());
    }

    #[test]
    fn test_replace_marker_missing_end() {
        let input = "<!-- BEGIN FOO -->\ntext";
        assert!(replace_marker(input, "FOO", "content").is_none());
    }

    #[test]
    fn test_country_from_prefix_known() {
        assert_eq!(country_from_prefix("FR_SSN"), Some("FR"));
        assert_eq!(country_from_prefix("US_PASSPORT"), Some("US"));
        assert_eq!(country_from_prefix("UK_NHS"), Some("UK"));
        assert_eq!(country_from_prefix("AU_ABN"), Some("AU"));
        assert_eq!(country_from_prefix("KR_RRN"), Some("KR"));
        assert_eq!(country_from_prefix("SG_NRIC_FIN"), Some("SG"));
        assert_eq!(country_from_prefix("PL_PESEL"), Some("PL"));
        assert_eq!(country_from_prefix("SI_EMSO"), Some("SI"));
        assert_eq!(country_from_prefix("FI_PERSONAL_IDENTITY_CODE"), Some("FI"));
        assert_eq!(country_from_prefix("TH_TNIN"), Some("TH"));
    }

    #[test]
    fn test_country_from_prefix_global() {
        assert_eq!(country_from_prefix("EMAIL_ADDRESS"), None);
        assert_eq!(country_from_prefix("CREDIT_CARD"), None);
        assert_eq!(country_from_prefix("AUTH_TOKEN"), None);
        assert_eq!(country_from_prefix("IP_ADDRESS"), None);
        assert_eq!(country_from_prefix("IBAN_CODE"), None);
    }

    #[test]
    fn test_country_from_prefix_no_underscore() {
        assert_eq!(country_from_prefix("UUID"), None);
        assert_eq!(country_from_prefix("URL"), None);
    }

    #[test]
    fn test_generate_entities_section() {
        let section = generate_entities_section();
        assert!(section.contains("entity types across"));
        assert!(section.contains("patterns covering"));
        assert!(section.contains("countries"));
        assert!(section.contains("emails"));
        assert!(section.contains("IBANs"));
        assert!(section.contains("docs/entities.md"));
    }

    #[test]
    fn test_generate_entities_section_has_country_list() {
        let section = generate_entities_section();
        // Should contain comma-separated country codes
        assert!(section.contains("AU"));
        assert!(section.contains("FR"));
        assert!(section.contains("US"));
    }

    #[test]
    fn test_generate_entities_section_counts_match_patterns() {
        let entity_types: HashSet<&str> = PATTERNS.iter().map(|p| p.entity_type).collect();
        let section = generate_entities_section();

        // The section should contain the actual counts from PATTERNS
        let entity_count_str = format!("{} entity types", entity_types.len());
        let pattern_count_str = format!("{} patterns", PATTERNS.len());

        assert!(
            section.contains(&entity_count_str),
            "Expected '{}' in section",
            entity_count_str
        );
        assert!(
            section.contains(&pattern_count_str),
            "Expected '{}' in section",
            pattern_count_str
        );
    }

    #[test]
    fn test_generate_commands_section() {
        let section = generate_commands_section();
        assert!(section.contains("anon list-entities"));
        assert!(section.contains("anon restore"));
        assert!(section.starts_with("```bash\n"));
        assert!(section.ends_with("\n```"));
    }

    #[test]
    fn test_generate_cli_anonymize_section() {
        let section = generate_cli_anonymize_section();
        assert!(section.contains("| Option |"));
        assert!(section.contains("`--input`"));
        assert!(section.contains("`--operator`"));
        assert!(section.contains("`--threshold`"));
    }

    #[test]
    fn test_generate_cli_restore_section() {
        let section = generate_cli_restore_section();
        assert!(section.contains("| Option |"));
        assert!(section.contains("`--mapping`"));
        assert!(section.contains("`--decrypt-key`"));
    }

    #[test]
    fn test_generate_benchmark_section_with_cache() {
        let cache = r#"{"features":{"regex-only":{"lines_per_sec":251000,"simple_avg_us":"2.8","complex_avg_us":"8.9","penalty":"3.2"}}}"#;
        let tmp = std::env::temp_dir().join("bench-results-test.json");
        fs::write(&tmp, cache).unwrap();
        let section = generate_benchmark_section_from(tmp.to_str().unwrap()).unwrap();
        assert!(section.contains("| Feature |"));
        assert!(section.contains("regex-only"));
        assert!(section.contains("251k"));
        fs::remove_file(&tmp).expect("cleanup failed");
    }

    #[test]
    fn test_generate_benchmark_section_no_cache() {
        assert!(generate_benchmark_section_from("nonexistent-file.json").is_none());
    }
}
