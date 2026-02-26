# Auto-Updating README Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Keep README.md automatically in sync with code via a Rust example binary and git pre-commit hook.

**Architecture:** A marker-based system where `examples/update_readme.rs` imports `anon::patterns::PATTERNS` and `anon::cli::Cli` at compile time, replaces content between `<!-- BEGIN X -->` / `<!-- END X -->` HTML comment markers in README.md, and exits with code 1 if anything changed. A pre-commit hook triggers this on every commit touching `.rs` or `.toml` files.

**Tech Stack:** Rust (clap CommandFactory for CLI introspection), serde_json (benchmark cache), git pre-commit hook (shell)

**Design doc:** `docs/plans/2026-02-26-auto-readme-design.md`

---

### Task 1: Extract CLI types from main.rs to src/cli.rs

This is a pure refactor — zero behavioral change. The `Cli` struct, `Commands` enum, and `Format` enum move to the library so examples can import them.

**Files:**
- Create: `src/cli.rs`
- Modify: `src/lib.rs:1-15`
- Modify: `src/main.rs:1-250`

**Step 1: Create `src/cli.rs` with the extracted types**

Copy the following from `main.rs` into a new `src/cli.rs`:
- Lines 1 (imports: `clap::{Parser, Subcommand, ValueEnum}`)
- Lines 26-116 (`Cli` struct with all fields)
- Lines 118-241 (`Commands` enum with all variants)
- Lines 243-250 (`Format` enum)

Adjust imports: the file is now inside the library crate, so `Operator` and `HashAlgo` are at `crate::detection::{Operator, HashAlgo}`, and `PathBuf` comes from `std::path::PathBuf`.

The top of `src/cli.rs` should be:
```rust
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

use crate::detection::{HashAlgo, Operator};
```

All `#[cfg(feature = "...")]` attributes on `Commands` variants and `Cli` fields stay exactly as-is.

**Step 2: Add `pub mod cli` to `src/lib.rs`**

Add this line after the existing module declarations (after line 9, before the `mapping` line):
```rust
pub mod cli;
```

Since `cli.rs` references `crate::detection`, it should be placed after the `detection` module declaration. The full lib.rs should read:
```rust
#[cfg(feature = "proxy")]
pub mod api;
pub mod cli;
pub mod detection;
pub mod format;
#[cfg(feature = "image")]
pub mod image_redact;
pub mod mapping;
pub mod ner;
pub mod patterns;
#[cfg(feature = "pdf")]
pub mod pdf_redact;
#[cfg(feature = "proxy")]
pub mod proxy;
#[cfg(feature = "proxy")]
pub mod ui;
```

**Step 3: Update `main.rs` to import from the library**

Replace the local struct definitions with imports. Remove lines 26-250 (the `Cli`, `Commands`, `Format` definitions) and add:
```rust
use anon::cli::{Cli, Commands, Format};
```

near the top, alongside the existing `use anon::detection::...` and `use anon::patterns::...` imports (around line 11-16). Keep `use clap::Parser;` since main.rs still calls `Cli::parse()`.

Remove `use clap::{Parser, Subcommand, ValueEnum};` and replace with just `use clap::Parser;`.

**Step 4: Run tests to verify no behavioral change**

Run: `cargo test`
Expected: All tests pass — this is a pure extraction refactor.

Run: `cargo clippy -- -D warnings`
Expected: No warnings.

**Step 5: Commit**

```bash
git add src/cli.rs src/lib.rs src/main.rs
git commit -m "refactor: extract CLI types to src/cli.rs for library access"
```

---

### Task 2: Add README markers

Add the 5 pairs of HTML comment markers to README.md around the sections that will be auto-generated.

**Files:**
- Modify: `README.md:182-184` (entities paragraph)
- Modify: `README.md:170-180` (commands list)
- Modify: `README.md:134-158` (CLI anonymize options)
- Modify: `README.md:160-169` (CLI restore options)
- Modify: `README.md:236-241` (benchmark table)

**Step 1: Add ENTITIES markers**

Around the "Detected entities" paragraph (line 184), wrap it:
```markdown
## Detected entities

<!-- BEGIN ENTITIES -->
63 entity types across 97 patterns covering 13 countries: ...
<!-- END ENTITIES -->
```

**Step 2: Add COMMANDS markers**

Around the commands code block (lines 172-180):
```markdown
### Commands

<!-- BEGIN COMMANDS -->
```bash
anon list-entities        # List all supported entity types
...
```
<!-- END COMMANDS -->
```

**Step 3: Add CLI_ANONYMIZE markers**

Around the anonymize options table (lines 136-158):
```markdown
### Anonymize (default)

<!-- BEGIN CLI_ANONYMIZE -->
| Option | Short | Default | Description |
...
<!-- END CLI_ANONYMIZE -->
```

**Step 4: Add CLI_RESTORE markers**

Around the restore options table (lines 162-169):
```markdown
### Restore

<!-- BEGIN CLI_RESTORE -->
| Option | Short | Default | Description |
...
<!-- END CLI_RESTORE -->
```

**Step 5: Add BENCHMARK markers**

Around the benchmark results table (lines 238-241):
```markdown
Typical results (Apple Silicon):

<!-- BEGIN BENCHMARK -->
| Feature | Throughput | Simple avg | Complex avg | Penalty |
...
<!-- END BENCHMARK -->
```

**Step 6: Verify README still renders correctly**

Run: `cat README.md | head -245` and visually inspect that markers are in the right places. HTML comments are invisible in rendered markdown.

**Step 7: Commit**

```bash
git add README.md
git commit -m "doc: add auto-generation markers to README.md"
```

---

### Task 3: Write the update_readme example — marker parser

Build the core marker replacement engine first, test it in isolation.

**Files:**
- Create: `examples/update_readme.rs`

**Step 1: Write the marker replacement function**

Create `examples/update_readme.rs` with:

```rust
use std::fs;
use std::process;

/// Replace content between `<!-- BEGIN {name} -->` and `<!-- END {name} -->` markers.
/// Returns the updated string, or None if the marker pair was not found.
fn replace_marker(readme: &str, name: &str, new_content: &str) -> Option<String> {
    let begin = format!("<!-- BEGIN {} -->", name);
    let end = format!("<!-- END {} -->", name);

    let begin_idx = readme.find(&begin)?;
    let after_begin = begin_idx + begin.len();
    let end_idx = readme[after_begin..].find(&end)? + after_begin;

    let mut result = String::with_capacity(readme.len());
    result.push_str(&readme[..after_begin]);
    result.push('\n');
    result.push_str(new_content);
    result.push('\n');
    result.push_str(&readme[end_idx..]);
    Some(result)
}

fn main() {
    // Placeholder — will add generation functions in subsequent tasks
    let readme_path = "README.md";
    let readme = fs::read_to_string(readme_path).unwrap_or_else(|e| {
        eprintln!("Failed to read {}: {}", readme_path, e);
        process::exit(2);
    });

    let _ = readme; // will use in next tasks
    println!("update_readme: marker parser ready");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replace_marker_basic() {
        let input = "before\n<!-- BEGIN FOO -->\nold content\n<!-- END FOO -->\nafter";
        let result = replace_marker(input, "FOO", "new content").unwrap();
        assert_eq!(result, "before\n<!-- BEGIN FOO -->\nnew content\n<!-- END FOO -->\nafter");
    }

    #[test]
    fn test_replace_marker_not_found() {
        let input = "no markers here";
        assert!(replace_marker(input, "FOO", "content").is_none());
    }

    #[test]
    fn test_replace_marker_multiline_content() {
        let input = "<!-- BEGIN X -->\nold\n<!-- END X -->";
        let result = replace_marker(input, "X", "line1\nline2\nline3").unwrap();
        assert!(result.contains("line1\nline2\nline3"));
    }
}
```

**Step 2: Run the test**

Run: `cargo test --example update_readme`
Expected: 3 tests pass.

**Step 3: Commit**

```bash
git add examples/update_readme.rs
git commit -m "feat(readme): add marker replacement engine for update_readme"
```

---

### Task 4: Add entity summary generation

Generate the "X entity types across Y patterns covering Z countries" paragraph from `PATTERNS`.

**Files:**
- Modify: `examples/update_readme.rs`

**Step 1: Write the failing test**

Add to the test module in `examples/update_readme.rs`:
```rust
#[test]
fn test_generate_entities_section() {
    let section = generate_entities_section();
    // Must contain dynamic counts from the real PATTERNS array
    assert!(section.contains("entity types across"));
    assert!(section.contains("patterns covering"));
    assert!(section.contains("countries"));
    // Must mention specific entity categories
    assert!(section.contains("emails"));
    assert!(section.contains("IBANs"));
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --example update_readme -- test_generate_entities_section`
Expected: FAIL — `generate_entities_section` not found.

**Step 3: Implement `generate_entities_section()`**

Add to `examples/update_readme.rs`:

```rust
use std::collections::HashSet;
use anon::patterns::PATTERNS;

/// Map 2-letter entity type prefixes to country names.
fn country_from_prefix(prefix: &str) -> Option<&'static str> {
    match prefix {
        "FR" => Some("FR"),
        "US" => Some("US"),
        "UK" => Some("UK"),
        "ES" => Some("ES"),
        "IT" => Some("IT"),
        "IN" => Some("IN"),
        "AU" => Some("AU"),
        "KR" => Some("KR"),
        "SG" => Some("SG"),
        "PL" => Some("PL"),
        "SI" => Some("SI"),
        "FI" => Some("FI"),
        "TH" => Some("TH"),
        _ => None,
    }
}

fn generate_entities_section() -> String {
    let entity_types: HashSet<&str> = PATTERNS.iter().map(|p| p.entity_type).collect();
    let pattern_count = PATTERNS.len();
    let entity_count = entity_types.len();

    // Extract countries from entity type prefixes (e.g., "FR_SSN" -> "FR")
    let countries: HashSet<&str> = entity_types
        .iter()
        .filter_map(|et| {
            let parts: Vec<&str> = et.splitn(2, '_').collect();
            if parts.len() == 2 {
                country_from_prefix(parts[0])
            } else {
                None
            }
        })
        .collect();
    let country_count = countries.len();

    // Build sorted country list for the prose
    let mut sorted_countries: Vec<&str> = countries.into_iter().collect();
    sorted_countries.sort();

    format!(
        "{} entity types across {} patterns covering {} countries: \
        emails, URLs, IPs, UUIDs, credit cards, IBANs, phones, dates, \
        crypto addresses, MAC addresses, secrets/tokens, and person names (with `--ner`). \
        Country-specific patterns include SSNs, passports, driver's licenses, tax IDs, \
        and national IDs for {} \u{2014} each with checksum validation where applicable. \
        Detection works through URL-encoded and Unicode-escaped text.\n\n\
        See [docs/entities.md](docs/entities.md) for the full reference with confidence scores and context keywords.",
        entity_count,
        pattern_count,
        country_count,
        sorted_countries.join(", "),
    )
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test --example update_readme -- test_generate_entities_section`
Expected: PASS

**Step 5: Commit**

```bash
git add examples/update_readme.rs
git commit -m "feat(readme): add entity summary generation from PATTERNS"
```

---

### Task 5: Add commands list generation

Generate the subcommands code block from `clap::CommandFactory`.

**Files:**
- Modify: `examples/update_readme.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn test_generate_commands_section() {
    let section = generate_commands_section();
    assert!(section.contains("anon list-entities"));
    assert!(section.contains("anon restore"));
    // Should be a code block
    assert!(section.starts_with("```bash\n"));
    assert!(section.ends_with("```"));
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --features ner-lite,proxy,image,pdf --example update_readme -- test_generate_commands_section`
Expected: FAIL

**Step 3: Implement `generate_commands_section()`**

```rust
use clap::CommandFactory;
use anon::cli::Cli;

fn generate_commands_section() -> String {
    let cmd = Cli::command();
    let mut lines = Vec::new();

    for sub in cmd.get_subcommands() {
        let name = sub.get_name();
        let about = sub.get_about().map(|s| s.to_string()).unwrap_or_default();

        // Build arg summary for the command
        let args: Vec<String> = sub
            .get_arguments()
            .filter(|a| a.get_id() != "help" && a.get_id() != "version")
            .map(|a| {
                if a.is_required_set() {
                    format!("<{}>", a.get_id().as_str().to_uppercase())
                } else {
                    String::new()
                }
            })
            .filter(|s| !s.is_empty())
            .collect();

        let arg_str = if args.is_empty() {
            String::new()
        } else {
            format!(" {}", args.join(" "))
        };

        // Detect feature requirements from the about text or name
        let feature_note = match name {
            "download-model" => " (requires `ner` feature)",
            "api" | "ui" | "proxy" => " (requires `proxy` feature)",
            "image" => " (requires `image` feature)",
            "pdf" => " (requires `pdf` feature)",
            _ => "",
        };

        lines.push(format!(
            "anon {}{:<20} # {}{}",
            name,
            arg_str,
            about,
            feature_note
        ));
    }

    format!("```bash\n{}\n```", lines.join("\n"))
}
```

Note: The exact formatting of the command list may need tweaking. The column alignment should match the existing README style. Adjust padding as needed.

**Step 4: Run test to verify it passes**

Run: `cargo test --features ner-lite,proxy,image,pdf --example update_readme -- test_generate_commands_section`
Expected: PASS

**Step 5: Commit**

```bash
git add examples/update_readme.rs
git commit -m "feat(readme): add commands list generation via clap introspection"
```

---

### Task 6: Add CLI options table generation

Generate markdown tables for the anonymize and restore CLI options.

**Files:**
- Modify: `examples/update_readme.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn test_generate_cli_anonymize_section() {
    let section = generate_cli_anonymize_section();
    assert!(section.contains("| Option |"));
    assert!(section.contains("--input"));
    assert!(section.contains("--operator"));
    assert!(section.contains("--threshold"));
}

#[test]
fn test_generate_cli_restore_section() {
    let section = generate_cli_restore_section();
    assert!(section.contains("| Option |"));
    assert!(section.contains("--mapping"));
    assert!(section.contains("--decrypt-key"));
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --features ner-lite,proxy,image,pdf --example update_readme -- test_generate_cli`
Expected: FAIL

**Step 3: Implement CLI table generation**

```rust
fn format_cli_table(cmd: &clap::Command) -> String {
    let mut rows = Vec::new();
    rows.push("| Option | Short | Default | Description |".to_string());
    rows.push("|--------|-------|---------|-------------|".to_string());

    for arg in cmd.get_arguments() {
        let id = arg.get_id().as_str();
        if id == "help" || id == "version" {
            continue;
        }

        let long = arg
            .get_long()
            .map(|l| format!("`--{}`", l))
            .unwrap_or_else(|| {
                // Positional argument
                format!("`{}`", id.to_uppercase())
            });

        let short = arg
            .get_short()
            .map(|s| format!("`-{}`", s))
            .unwrap_or_default();

        let default = arg
            .get_default_values()
            .first()
            .map(|v| format!("`{}`", v.to_str().unwrap_or("")))
            .unwrap_or_default();

        let help = arg
            .get_help()
            .map(|h| h.to_string())
            .unwrap_or_default();

        rows.push(format!("| {} | {} | {} | {} |", long, short, default, help));
    }

    rows.join("\n")
}

fn generate_cli_anonymize_section() -> String {
    let cmd = Cli::command();
    format_cli_table(&cmd)
}

fn generate_cli_restore_section() -> String {
    let cmd = Cli::command();
    let restore = cmd
        .get_subcommands()
        .find(|s| s.get_name() == "restore")
        .expect("restore subcommand not found");
    format_cli_table(restore)
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test --features ner-lite,proxy,image,pdf --example update_readme -- test_generate_cli`
Expected: PASS

**Step 5: Commit**

```bash
git add examples/update_readme.rs
git commit -m "feat(readme): add CLI options table generation from clap introspection"
```

---

### Task 7: Add benchmark cache to examples/benchmark.rs

Modify the existing benchmark to also write `bench-results.json`.

**Files:**
- Modify: `examples/benchmark.rs:107-228`
- Modify: `.gitignore`

**Step 1: Add JSON output to benchmark.rs**

At the end of `main()` in `examples/benchmark.rs` (after line 228, before the closing brace), add:

```rust
// Write cached results for update_readme
let cache = serde_json::json!({
    "features": {
        feature_label(): {
            "lines_per_sec": throughput as u64,
            "simple_avg_us": format!("{:.1}", simple_avg.as_secs_f64() * 1e6),
            "complex_avg_us": format!("{:.1}", complex_avg.as_secs_f64() * 1e6),
            "penalty": format!("{:.1}", penalty),
        }
    }
});

// Merge with existing cache (other feature variants may already be there)
let cache_path = "bench-results.json";
let mut existing: serde_json::Value = fs::read_to_string(cache_path)
    .ok()
    .and_then(|s| serde_json::from_str(&s).ok())
    .unwrap_or_else(|| serde_json::json!({"features": {}}));

if let (Some(existing_features), Some(new_features)) = (
    existing.get_mut("features").and_then(|v| v.as_object_mut()),
    cache["features"].as_object(),
) {
    for (k, v) in new_features {
        existing_features.insert(k.clone(), v.clone());
    }
}

if let Ok(json_str) = serde_json::to_string_pretty(&existing) {
    let _ = fs::write(cache_path, json_str);
    eprintln!("Benchmark results cached to {}", cache_path);
}
```

Also add `use std::fs;` and `use serde_json;` to the imports at the top of `benchmark.rs`. `serde_json` is already a dependency in Cargo.toml.

**Step 2: Add bench-results.json to .gitignore**

Append to `.gitignore`:
```
# Benchmark cache (local, machine-specific)
bench-results.json
```

**Step 3: Run the benchmark to verify cache is created**

Run: `cargo run --release --example benchmark 2>&1 | tail -3`
Expected: Output includes "Benchmark results cached to bench-results.json"

Verify: `cat bench-results.json | python3 -m json.tool`
Expected: Valid JSON with `features.regex-only` key.

**Step 4: Commit**

```bash
git add examples/benchmark.rs .gitignore
git commit -m "feat(bench): write bench-results.json cache for README auto-update"
```

---

### Task 8: Add benchmark section generation to update_readme

Read the cached `bench-results.json` and generate the markdown table.

**Files:**
- Modify: `examples/update_readme.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn test_generate_benchmark_section_with_cache() {
    // Write a temporary cache file
    let cache = r#"{"features":{"regex-only":{"lines_per_sec":251000,"simple_avg_us":"2.8","complex_avg_us":"8.9","penalty":"3.2"}}}"#;
    fs::write("bench-results-test.json", cache).unwrap();

    let section = generate_benchmark_section_from("bench-results-test.json");
    assert!(section.contains("| Feature |"));
    assert!(section.contains("regex-only"));
    assert!(section.contains("251"));

    fs::remove_file("bench-results-test.json").ok();
}

#[test]
fn test_generate_benchmark_section_no_cache() {
    let section = generate_benchmark_section_from("nonexistent.json");
    // Should return None when no cache exists
    assert!(section.is_none());
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --example update_readme -- test_generate_benchmark`
Expected: FAIL

**Step 3: Implement benchmark section generation**

```rust
fn generate_benchmark_section_from(path: &str) -> Option<String> {
    let data = fs::read_to_string(path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&data).ok()?;
    let features = json.get("features")?.as_object()?;

    let mut rows = Vec::new();
    rows.push("| Feature | Throughput | Simple avg | Complex avg | Penalty |".to_string());
    rows.push("|---------|-----------|-----------|-------------|---------|".to_string());

    // Sort features in a stable order
    let order = ["regex-only", "ner-lite (heuristic)", "ner (ML)"];
    for name in &order {
        if let Some(data) = features.get(*name) {
            let lps = data.get("lines_per_sec").and_then(|v| v.as_u64()).unwrap_or(0);
            let simple = data.get("simple_avg_us").and_then(|v| v.as_str()).unwrap_or("?");
            let complex = data.get("complex_avg_us").and_then(|v| v.as_str()).unwrap_or("?");
            let penalty = data.get("penalty").and_then(|v| v.as_str()).unwrap_or("?");

            let throughput = if lps >= 1000 {
                format!("{}k lines/s", lps / 1000)
            } else {
                format!("{} lines/s", lps)
            };

            rows.push(format!(
                "| {} | {} | {} \u{03bc}s | {} \u{03bc}s | {}x |",
                name, throughput, simple, complex, penalty
            ));
        }
    }

    if rows.len() <= 2 {
        return None; // No data rows
    }

    Some(rows.join("\n"))
}

fn generate_benchmark_section() -> Option<String> {
    generate_benchmark_section_from("bench-results.json")
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test --example update_readme -- test_generate_benchmark`
Expected: PASS

**Step 5: Commit**

```bash
git add examples/update_readme.rs
git commit -m "feat(readme): add benchmark table generation from cached results"
```

---

### Task 9: Wire everything together in main()

Connect all generators to the marker replacement engine and add the exit code logic.

**Files:**
- Modify: `examples/update_readme.rs` (the `main()` function)

**Step 1: Implement the full main() function**

Replace the placeholder `main()` with:

```rust
fn main() {
    let readme_path = "README.md";
    let original = fs::read_to_string(readme_path).unwrap_or_else(|e| {
        eprintln!("Failed to read {}: {}", readme_path, e);
        process::exit(2);
    });

    let mut readme = original.clone();
    let mut updated_sections = Vec::new();

    // 1. Entity summary
    let entities = generate_entities_section();
    if let Some(r) = replace_marker(&readme, "ENTITIES", &entities) {
        readme = r;
        updated_sections.push("ENTITIES");
    }

    // 2. Commands list
    let commands = generate_commands_section();
    if let Some(r) = replace_marker(&readme, "COMMANDS", &commands) {
        readme = r;
        updated_sections.push("COMMANDS");
    }

    // 3. CLI anonymize options
    let cli_anon = generate_cli_anonymize_section();
    if let Some(r) = replace_marker(&readme, "CLI_ANONYMIZE", &cli_anon) {
        readme = r;
        updated_sections.push("CLI_ANONYMIZE");
    }

    // 4. CLI restore options
    let cli_restore = generate_cli_restore_section();
    if let Some(r) = replace_marker(&readme, "CLI_RESTORE", &cli_restore) {
        readme = r;
        updated_sections.push("CLI_RESTORE");
    }

    // 5. Benchmark (only if cache exists)
    if let Some(bench) = generate_benchmark_section() {
        if let Some(r) = replace_marker(&readme, "BENCHMARK", &bench) {
            readme = r;
            updated_sections.push("BENCHMARK");
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
```

**Step 2: Test the full pipeline manually**

Run: `cargo run --features ner-lite,proxy,image,pdf --example update_readme`
Expected: Either "README.md is up to date." (exit 0) or "README.md updated: N section(s) refreshed" (exit 1).

Verify: `git diff README.md` to see what changed.

**Step 3: Run all tests**

Run: `cargo test --features ner-lite,proxy,image,pdf --example update_readme`
Expected: All tests pass.

Run: `cargo test`
Expected: All existing tests still pass (the refactor didn't break anything).

**Step 4: Commit**

```bash
git add examples/update_readme.rs
git commit -m "feat(readme): wire all generators into update_readme main()"
```

---

### Task 10: Create the pre-commit hook and installer

**Files:**
- Create: `scripts/install-hooks.sh`

**Step 1: Create the hook installer**

Create `scripts/install-hooks.sh`:

```bash
#!/bin/sh
# Install git hooks for anon development
set -e

HOOK_DIR="$(git rev-parse --git-dir)/hooks"
mkdir -p "$HOOK_DIR"

cat > "$HOOK_DIR/pre-commit" << 'HOOK'
#!/bin/sh
# Auto-update README.md when Rust source changes
if git diff --cached --name-only | grep -qE '\.(rs|toml)$'; then
    cargo run --example update_readme --features ner-lite,proxy,image,pdf 2>/dev/null
    EXIT_CODE=$?
    if [ "$EXIT_CODE" -eq 1 ]; then
        git add README.md
        echo "README.md auto-updated and staged."
    elif [ "$EXIT_CODE" -ne 0 ]; then
        echo "warning: update_readme failed (exit $EXIT_CODE), skipping README update."
    fi
fi
HOOK

chmod +x "$HOOK_DIR/pre-commit"
echo "Pre-commit hook installed at $HOOK_DIR/pre-commit"
```

**Step 2: Make it executable**

Run: `chmod +x scripts/install-hooks.sh`

**Step 3: Test the installer**

Run: `./scripts/install-hooks.sh`
Expected: "Pre-commit hook installed at .git/hooks/pre-commit"

Verify: `cat .git/hooks/pre-commit` shows the hook content.

**Step 4: Test the hook end-to-end**

Make a trivial change to a `.rs` file, stage it, and commit:

Run: `git stash` (to save current changes)
Run: `echo "// test" >> src/lib.rs && git add src/lib.rs && git commit -m "test: hook test"`
Expected: See "README.md auto-updated and staged." or "README.md is up to date."

Then: `git reset HEAD~1 && git checkout src/lib.rs && git stash pop`

**Step 5: Commit**

```bash
git add scripts/install-hooks.sh
git commit -m "feat: add pre-commit hook installer for README auto-update"
```

---

### Task 11: Update Development section in README

Document the new tooling in the README's Development section.

**Files:**
- Modify: `README.md` (Development section, around line 200)

**Step 1: Add hook installation docs**

Add after the existing Development section (before the Benchmark subsection):

```markdown
### Setup

```bash
# Install git hooks (auto-updates README on commit)
./scripts/install-hooks.sh
```

### Updating README

The README is auto-updated by a pre-commit hook. To manually trigger:

```bash
# Update README from current code
cargo run --features ner-lite,proxy,image,pdf --example update_readme

# Update benchmark numbers first, then README
cargo run --release --example benchmark  # writes bench-results.json
cargo run --features ner-lite,proxy,image,pdf --example update_readme
```
```

**Step 2: Commit**

```bash
git add README.md
git commit -m "doc: add README auto-update setup instructions"
```

---

### Task 12: Final verification

Run all tests, lints, and verify the full pipeline.

**Step 1: Run full test suite**

Run: `cargo test`
Expected: All tests pass.

Run: `cargo test --features ner-lite,proxy`
Expected: All tests pass.

Run: `cargo test --features ner-lite,proxy,image,pdf --example update_readme`
Expected: All example tests pass.

**Step 2: Run lints**

Run: `cargo fmt --all --check`
Expected: No formatting issues.

Run: `cargo clippy -- -D warnings`
Expected: No warnings.

Run: `cargo clippy --features ner-lite,proxy -- -D warnings`
Expected: No warnings.

**Step 3: Run the updater one final time**

Run: `cargo run --features ner-lite,proxy,image,pdf --example update_readme`
Expected: "README.md is up to date." (exit 0) — confirming everything is in sync.

**Step 4: Verify README renders correctly**

Visually inspect the rendered README.md (e.g., via `grip` or GitHub preview). All markers should be invisible, and generated content should match the code.
