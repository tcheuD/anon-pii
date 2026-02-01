# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`anon` — CLI tool to anonymize PII in debug data. Two implementations: Rust (primary, fast) and Python (Presidio-based, more entity types).

## Build & Test

```bash
# Rust (default — regex-only, no NER)
cargo build --release      # binary at target/release/anon
cargo test                 # ~144 tests (lib + integration)

# Rust with NER features
cargo build --features ner-lite   # heuristic name detection (zero deps)
cargo build --features ner        # ML name detection (requires ONNX Runtime)
cargo test --features ner-lite    # ~157 tests (includes NER tests)

# Python
uv sync                    # install deps (uses uv, not pip)
uv run pytest              # tests dir exists but is empty
uv run ruff check src/     # lint
uv run mypy src/            # type check (strict mode)
```

Note: `cargo test` (no features) runs all tests except NER-specific ones. Always run the default `cargo test` after changes — it covers patterns, detection, normalization, format handling, mapping, and proxy.

```bash
# Benchmark (100k lines, simple vs complex)
cargo run --release --example benchmark
cargo run --release --features ner-lite --example benchmark
cargo run --release --features ner --example benchmark
```

NER ML setup: `brew install onnxruntime`, then persist `ORT_DYLIB_PATH` in `~/.zshrc`. Model cached at `~/.anon/models/distilbert-ner-int8/` after `anon download-model`.

## Architecture

### Rust (multi-module)

```
src/
├── main.rs          # CLI (clap derive), Commands enum
├── lib.rs           # pub mod re-exports
├── detection.rs     # Anonymizer: normalization pipeline, detection, overlap resolution
├── patterns.rs      # PATTERNS array, PiiPattern structs, CREW_CODE_BLOCKLIST
├── mapping.rs       # Token↔original mapping, file persistence
├── format.rs        # Format detection (auto/json/sql/csv/text)
├── ner/             # Named entity recognition (behind feature flags)
│   ├── mod.rs       # NER trait + dispatch
│   ├── heuristic.rs # ner-lite: rule-based name detection
│   ├── ml.rs        # ner: ONNX-based transformer model
│   └── download.rs  # Model download logic
├── proxy/           # Anonymizing reverse proxy (axum)
│   ├── mod.rs       # Server setup, host validation
│   ├── handler.rs   # Request/response anonymization
│   ├── anthropic.rs # Anthropic API specifics
│   └── sse.rs       # Server-sent events streaming
└── ui/              # Web GUI (axum, embedded HTML)
    └── mod.rs       # Serves single-page app on localhost
```

Key flow: CLI → format detection → `Anonymizer` dispatches to `anonymize_text()` or `anonymize_json_value()` → normalization pipeline (NFKC → unicode escapes → percent encoding) → regex matching with overlap resolution → token replacement via `Mapping`.

**Pattern system**: `PATTERNS` array of `PiiPattern` structs (~23 patterns, 15 entity types), each with a regex, entity type, confidence score, optional `context_keywords`, and `context_required` bool. Two context modes: `context_required: true` = binary gate (no keyword = no match); `context_required: false` + keywords = score boost (+0.15). CREW_CODE uses a ~250-entry blocklist of common words/abbreviations.

**Overlap resolution**: sorts detections by position asc → span length desc → score desc. Earlier/longer/higher-confidence matches win. URL detections get a second pass to report inner PII from query parameters.

**JSON mode**: auto-detected, recursively walks `serde_json::Value` tree anonymizing only strings. Preserves original indentation.

### Python (`src/anon/`)

Modular, built on Microsoft Presidio. `core/analyzer.py` wires up Presidio with custom recognizers from `recognizers/french.py` and `recognizers/aviation.py`. `core/anonymizer.py` runs detection and replacement. `formats/` handles JSON structure-aware and text processing. `cli.py` is the Typer entry point.

Key difference from Rust: optional spaCy NLP for name detection (`PERSON` entity).

## Entity Naming

Both Rust and Python use Presidio-style names: `EMAIL_ADDRESS`, `FR_PHONE_NUMBER`, `AIRCRAFT_REGISTRATION`, `FLIGHT_NUMBER`, `IP_ADDRESS`.

Tokens follow `[ENTITY_TYPE_N]` format (e.g., `[EMAIL_ADDRESS_1]`, `[AIRCRAFT_REGISTRATION_2]`).
