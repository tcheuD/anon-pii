# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`anon` — Fast CLI tool to anonymize PII in debug data. Written in Rust with regex-based pattern matching, optional NER (heuristic or ML), and an anonymizing reverse proxy mode.

## Build & Test

```bash
# Rust (default — regex-only, no NER, no proxy)
cargo build --release      # binary at target/release/anon
cargo test                 # ~321 tests (lib + integration)

# With features
cargo build --features ner-lite        # heuristic name detection (zero deps)
cargo build --features ner             # ML name detection (requires ONNX Runtime, implies ner-lite)
cargo build --features proxy           # reverse proxy + web UI
cargo build --features ner-lite,proxy  # recommended full build (no ML deps)
cargo test --features ner-lite,proxy   # ~381 tests (includes NER + proxy tests)
```

**Always run `cargo test` (default, no features) after changes.** It covers patterns, detection, normalization, format handling, mapping, and core logic. If you changed NER or proxy code, also run with those features.

```bash
# Lint & format (matches CI)
cargo fmt --all --check
cargo clippy -- -D warnings
cargo clippy --features ner-lite,proxy -- -D warnings

# Benchmark (100k-line throughput)
cargo run --release --example benchmark
cargo run --release --features ner-lite --example benchmark
```

NER ML setup: `brew install onnxruntime`, then set `ORT_DYLIB_PATH` to the dylib path. Model cached at `~/.anon/models/distilbert-ner-int8/` after `anon download-model`.

## Architecture

### Source layout

```
src/
├── main.rs            # CLI (clap derive), Commands enum, I/O, mapping file ops
├── lib.rs             # pub mod re-exports (proxy/ui gated on "proxy" feature)
├── detection.rs       # Anonymizer: normalization pipeline, detection, overlap resolution
├── patterns.rs        # PATTERNS array, PiiPattern structs, validators, CREW_CODE_BLOCKLIST
├── mapping.rs         # Token↔original mapping, persistence, LRU eviction
├── format.rs          # Format auto-detection (JSON/SQL/CSV/text)
├── ner/               # Named entity recognition (behind feature flags)
│   ├── mod.rs         # NerDetector trait, dispatch, CombinedNerDetector
│   ├── heuristic.rs   # ner-lite: rule-based name detection (titles, dictionaries)
│   ├── ml.rs          # ner: ONNX DistilBERT transformer model
│   ├── download.rs    # Model download from HuggingFace
│   └── names_insee.rs # Top 2000 French first names (generated data)
├── proxy/             # Anonymizing reverse proxy (axum, behind "proxy" feature)
│   ├── mod.rs         # Server setup, ProxyState, host validation middleware
│   ├── handler.rs     # Request/response anonymization, header filtering
│   ├── anthropic.rs   # Anthropic API specifics
│   └── sse.rs         # TokenBuffer: SSE stream bracket-aware token restoration
└── ui/                # Web GUI (axum, behind "proxy" feature)
    ├── mod.rs         # Serves single-page app on localhost
    └── index.html     # Embedded SPA (HTML/CSS/JS)
```

### Key flow

CLI → format detection → `Anonymizer` dispatches to `anonymize_text()` or `anonymize_json_value()` → normalization pipeline (NFKC → unicode escapes → percent encoding) → regex matching with overlap resolution → token replacement via `Mapping`.

### Pattern system

`PATTERNS` array of `PiiPattern` structs (~45 patterns, 15+ entity types), each with a regex, entity type, confidence score, optional `context_keywords`, and `context_required` bool.

- `context_required: true` = binary gate (no keyword nearby → no match). Used by IBAN, CREDIT_CARD, PHONE_NUMBER, some AIRCRAFT_REGISTRATION patterns.
- `context_required: false` + keywords = score boost (+0.15). Used by FR_PHONE_NUMBER, FR_IBAN, FR_SSN.
- CREW_CODE uses a ~250-entry blocklist of common words/abbreviations to reduce false positives.
- Validators: Luhn (credit cards), mod-97 (IBAN), SSN prefix blocklist, MAC broadcast/null rejection.

### Overlap resolution

Sorts detections by (start ASC, span length DESC, score DESC). Earlier/longer/higher-confidence matches win. URL detections get a second pass to extract inner PII from query parameters.

### Format handling

- **JSON**: auto-detected, recursively walks `serde_json::Value` tree anonymizing only strings, preserves indentation.
- **CSV**: parses RFC 4180 (respects quotes), anonymizes each cell.
- **SQL**: processes string literals only.
- **Text**: whole-text processing (default fallback).

### Proxy mode

```
User → HTTP (localhost:9100) → [anon proxy] → HTTPS upstream (api.anthropic.com)
```

Intercepts `/v1/messages` POST requests: anonymizes the request body, streams the response, and restores tokens in SSE chunks using `TokenBuffer` (bracket-aware buffering handles tokens split across chunks). Other endpoints pass through unchanged.

### Mapping system

Tokens follow `[ENTITY_TYPE_XXXX]` format with random hex suffix (e.g., `[EMAIL_ADDRESS_a1b2c3d4]`). Mapping persisted atomically to `~/.anon/mapping.json` (temp-file-then-rename). Two restoration modes: `restore_bracketed()` (safe, proxy use) and `restore()` (CLI, restores bare tokens too).

## Feature flags

| Flag | Effect | Dependencies |
|------|--------|-------------|
| (default) | Regex-only detection | None beyond core |
| `ner-lite` | Heuristic name detection (titles, name dictionaries) | None (zero deps) |
| `ner` | ML name detection via ONNX DistilBERT (implies `ner-lite`) | ort, tokenizers, ndarray, ureq, sha2 |
| `proxy` | Reverse proxy + web UI | tokio, axum, reqwest, futures, bytes |

## Entity naming

Presidio-style names: `EMAIL_ADDRESS`, `FR_PHONE_NUMBER`, `AIRCRAFT_REGISTRATION`, `FLIGHT_NUMBER`, `IP_ADDRESS`, `CREW_CODE`, `EMPLOYEE_ID`, `AUTH_TOKEN`, `MEDICAL_LICENSE`, etc.

Tokens follow `[ENTITY_TYPE_XXXXXXXX]` format with random 8-character hex suffix (e.g., `[EMAIL_ADDRESS_a1b2c3d4]`, `[AIRCRAFT_REGISTRATION_deadbeef]`).

## CI

GitHub Actions (`.github/workflows/ci.yml`):

- **rust-fmt** — `cargo fmt --all --check` (always required)
- **rust-clippy** — `cargo clippy -- -D warnings` + `cargo clippy --features ner-lite,proxy -- -D warnings`
- **rust-test** — Matrix: default features + `ner-lite,proxy` (Ubuntu always, macOS on main)
- **rust-build** — Release build (Ubuntu always, macOS on main)
- **security-deny/audit** — `cargo deny check` + `cargo audit` (main branch only)

CI skips on docs-only changes (`**.md`, `docs/**`).

## Security conventions

- Atomic file writes (temp + rename) to prevent TOCTOU races
- Mapping files: mode 0o600 (owner-only), directory mode 0o700
- Symlink defense: never follows symlinks in mapping paths
- Proxy host validation: only allows 127.0.0.1, localhost, [::1] (DNS rebinding defense)
- Proxy header allowlist: only safe headers forwarded upstream
- Cryptographic RNG (`getrandom`) for token generation
- NER `ORT_DYLIB_PATH` validated against system library path allowlist
- Dependencies pinned to exact versions for supply chain safety (proxy + NER deps)

## Test data

`testdata/` contains sample files for testing: `api-error.json`, `crew-roster.csv`, `debug-log.txt`, `queries.sql`.

## Other directories

- `docs/` — Entity reference, NER setup, proxy docs, threat model
- `examples/benchmark.rs` — 100k-line throughput benchmark
- `scripts/` — `build_names.py` (generate French name lists), `yt` (YouTrack fetcher)
- `tickets/` — Feature/bug ticket descriptions
