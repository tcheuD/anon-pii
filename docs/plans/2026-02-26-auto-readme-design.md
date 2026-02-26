# Auto-Updating README Design

**Date:** 2026-02-26
**Status:** Approved

## Problem

The README.md contains hardcoded numbers and tables (entity counts, pattern counts, country counts, CLI options, subcommands, benchmark numbers) that drift out of sync every time code is pushed.

## Solution

A Rust example binary (`examples/update_readme.rs`) that introspects the actual code at compile time and updates marked sections of the README. A git pre-commit hook triggers it automatically.

## Architecture

### Marker System

README.md uses HTML comment markers to delimit 5 auto-generated sections:

| Section | Marker | Generated from |
|---|---|---|
| Entity summary | `<!-- BEGIN ENTITIES -->` / `<!-- END ENTITIES -->` | `anon::patterns::PATTERNS` array |
| Commands list | `<!-- BEGIN COMMANDS -->` / `<!-- END COMMANDS -->` | `anon::cli::Commands` enum via clap |
| CLI options (anonymize) | `<!-- BEGIN CLI_ANONYMIZE -->` / `<!-- END CLI_ANONYMIZE -->` | `anon::cli::Cli` struct via clap |
| CLI options (restore) | `<!-- BEGIN CLI_RESTORE -->` / `<!-- END CLI_RESTORE -->` | `anon::cli::Commands::Restore` via clap |
| Benchmark table | `<!-- BEGIN BENCHMARK -->` / `<!-- END BENCHMARK -->` | `bench-results.json` cache file |

Everything outside markers is hand-written and untouched.

### Rust Example Binary

`examples/update_readme.rs` imports:
- `anon::patterns::PATTERNS` — the real pattern array for entity/pattern/country counts
- `anon::cli::Cli` — the real clap struct for CLI introspection via `CommandFactory`

The binary:
1. Reads `README.md` from the project root
2. For each marker pair, generates replacement content
3. Writes back only if content changed
4. Exits 0 (unchanged) or 1 (changed) for hook integration

Must be compiled with all features (`--features ner-lite,proxy,image,pdf`) to see all subcommands.

### CLI Type Extraction

The `Cli`, `Commands`, and `Format` types currently in `main.rs` move to `src/cli.rs`, re-exported from `lib.rs`. This is a pure extraction refactor — `main.rs` imports from the library instead of defining them locally.

### Country Extraction

Countries are derived from entity type prefixes: `FR_` -> France, `US_` -> United States, etc. Patterns without a country prefix (like `EMAIL_ADDRESS`) are "Global". No hardcoded country list.

### Benchmark Cache

- The existing `examples/benchmark.rs` is modified to write `bench-results.json` alongside its stderr output
- `bench-results.json` is gitignored (local machine cache)
- The updater reads it if present; if missing, leaves the benchmark section unchanged
- Users run the benchmark separately when they want fresh numbers

### Pre-commit Hook

```bash
#!/bin/sh
if git diff --cached --name-only | grep -qE '\.(rs|toml)$'; then
    cargo run --example update_readme --features ner-lite,proxy,image,pdf 2>/dev/null
    if [ $? -eq 1 ]; then
        git add README.md
        echo "README.md auto-updated and staged."
    fi
fi
```

Only triggers when `.rs` or `.toml` files are staged. Auto-stages README.md if it changed.

Installed via `scripts/install-hooks.sh`.

## Files

### Created
- `examples/update_readme.rs` — README updater binary
- `src/cli.rs` — CLI types extracted from main.rs
- `scripts/install-hooks.sh` — hook installer

### Modified
- `README.md` — add 10 marker comments (5 pairs)
- `src/main.rs` — import CLI types from library instead of defining locally
- `src/lib.rs` — add `pub mod cli`
- `examples/benchmark.rs` — add JSON cache output
- `.gitignore` — add `bench-results.json`

## What Stays Hand-Written

Installation, Quick Start, How It Works (mermaid diagrams), Documentation links table, Development notes, License.
