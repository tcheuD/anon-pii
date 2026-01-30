# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`anon` — CLI tool to anonymize PII in debug data. Two implementations: Rust (primary, fast) and Python (Presidio-based, more entity types).

## Build & Test

```bash
# Rust
cargo build --release      # binary at target/release/anon
cargo test                  # 31 inline unit tests in src/main.rs

# Python
uv sync                    # install deps (uses uv, not pip)
uv run pytest              # tests dir exists but is empty
uv run ruff check src/     # lint
uv run mypy src/            # type check (strict mode)
```

## Architecture

### Rust (`src/main.rs` — single file, ~1000 lines)

Everything is in one file. Key flow: CLI (clap derive) → format detection → `Anonymizer` dispatches to `anonymize_text()` or `anonymize_json_value()` → regex matching with overlap resolution → token replacement via `Mapping`.

**Pattern system**: `PATTERNS` const array of 22 `PiiPattern` structs (14 entity types), each with a regex, entity type, confidence score, optional `context_keywords`, and `context_required` bool. Two context modes: `context_required: true` = binary gate (no keyword = no match); `context_required: false` + keywords = score boost (+0.15). CREW_CODE also uses a blocklist of common 3-letter words.

**Overlap resolution**: sorts detections by position asc → span length desc → score desc. Earlier/longer/higher-confidence matches win.

**JSON mode**: auto-detected, recursively walks `serde_json::Value` tree anonymizing only strings. Preserves original indentation.

### Python (`src/anon/`)

Modular, built on Microsoft Presidio. `core/analyzer.py` wires up Presidio with custom recognizers from `recognizers/french.py` and `recognizers/aviation.py`. `core/anonymizer.py` runs detection and replacement. `formats/` handles JSON structure-aware and text processing. `cli.py` is the Typer entry point.

Key difference from Rust: optional spaCy NLP for name detection (`PERSON` entity).

## Entity Naming

Both Rust and Python use Presidio-style names: `EMAIL_ADDRESS`, `FR_PHONE_NUMBER`, `AIRCRAFT_REGISTRATION`, `FLIGHT_NUMBER`, `IP_ADDRESS`.

Tokens follow `[ENTITY_TYPE_N]` format (e.g., `[EMAIL_ADDRESS_1]`, `[AIRCRAFT_REGISTRATION_2]`).
