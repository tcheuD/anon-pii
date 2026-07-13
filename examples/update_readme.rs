//! README.md auto-updater for anon.
//!
//! Parses marker sections (`<!-- BEGIN X -->...<!-- END X -->`) and replaces
//! them with dynamically generated content from the codebase.

use std::fs;
use std::process;

use anon_pii::cli::Cli;
use clap::CommandFactory;

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

/// Generates the entities section paragraph for README.md.
fn generate_entities_section() -> String {
    "The default recognizers cover common contact, network, payment, credential, and \
     country-specific identifiers. Some formats use checksum or context validation; \
     others remain heuristic. Optional name detection changes the configuration and \
     must be evaluated separately. Detection also inspects supported normalized and \
     encoded representations while applying replacements to the original spans.\n\n\
     See [docs/entities.md](docs/entities.md) for the exact entity inventory, confidence \
     scores, validators, and context requirements in this revision."
        .to_string()
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
    let bin = cmd.get_name().to_string();
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
            format!("{} {}{:<16} # {} ({})", bin, name, args_str, about, note)
        } else {
            format!("{} {}{:<16} # {}", bin, name, args_str, about)
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
    fn test_generate_entities_section() {
        let section = generate_entities_section();
        assert!(section.contains("default recognizers"));
        assert!(section.contains("checksum or context validation"));
        assert!(section.contains("remain heuristic"));
        assert!(section.contains("docs/entities.md"));
        assert!(!section.contains("entity types across"));
    }

    #[test]
    fn test_generate_commands_section() {
        let section = generate_commands_section();
        assert!(section.contains("anon-pii list-entities"));
        assert!(section.contains("anon-pii restore"));
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
