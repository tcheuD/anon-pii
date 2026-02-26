# anon

Fast CLI tool to anonymize PII in debug data before sharing with AI tools.

## Installation

```bash
# Default (regex-only, no NER)
cargo install --path .

# With heuristic name detection (zero deps, +0 binary size)
cargo install --path . --features ner-lite

# With reverse proxy + web UI + REST API
cargo install --path . --features proxy

# Recommended full build (heuristic NER + proxy, no ML deps)
cargo install --path . --features ner-lite,proxy

# With ML name detection (requires ONNX Runtime)
brew install onnxruntime
export ORT_DYLIB_PATH=$(brew --prefix onnxruntime)/lib/libonnxruntime.dylib
cargo install --path . --features ner
anon download-model  # one-time, cached at ~/.anon/models/

# With image redaction (requires Tesseract)
brew install tesseract  # macOS
cargo install --path . --features image
```

To make `ORT_DYLIB_PATH` persist across terminal sessions, add it to your shell profile:

```bash
echo 'export ORT_DYLIB_PATH=$(brew --prefix onnxruntime)/lib/libonnxruntime.dylib' >> ~/.zshrc
```

This installs to `~/.cargo/bin/anon`. If your PATH uses a different directory (e.g. `~/.local/bin`), create a symlink:

```bash
ln -sf ~/.cargo/bin/anon ~/.local/bin/anon
```

To update after code changes, re-run the same `cargo install` command.

## Quick Start

```bash
# Anonymize from stdin
echo 'Error for user john@example.com on F-GRHK' | anon
# Output: Error for user [EMAIL_ADDRESS_1] on [AIRCRAFT_REGISTRATION_1]

# Anonymize JSON (auto-detected, structure preserved)
echo '{"email": "john@example.com", "count": 42}' | anon
# Output: {"count": 42, "email": "[EMAIL_ADDRESS_1]"}

# Redact instead of tokenize
echo 'User john@example.com logged in' | anon --operator redact
# Output: User [REDACTED] logged in

# Mask with partial visibility
echo 'Card: 4111111111111111' | anon --operator mask --mask-from-end
# Output: Card: ************1111

# Roundtrip: anonymize, share, restore
cat debug.json | anon > safe.json
cat response.json | anon restore

# Pipe through Claude
cat debug.json | anon | claude -p "explain this error" | anon restore

# Share-ready Markdown snippet (safe to paste into issues / AI tools)
cat debug.json | anon --share --copy

# Redact PII in images (OCR + fill)
anon image screenshot.png -o redacted.png
```

Mapping is auto-saved to `~/.anon/mapping.json` — no need to pass `-m` manually.

## How It Works

### 1) End-to-end anonymization path

```mermaid
flowchart LR
    A[Input file or stdin] --> B{Format detection}
    B -->|JSON| C[Walk JSON values]
    B -->|CSV| D[Process each CSV cell]
    B -->|SQL| E[Process SQL string literals]
    B -->|Text| F[Process whole text]
    C --> G[Regex + context + optional NER]
    D --> G
    E --> G
    F --> G
    G --> H[Generate stable random tokens]
    H --> I[Write mapping to ~/.anon/mapping.json]
    H --> J[Return anonymized output]
```

### 2) Detection pipeline (inside `anonymize_text`)

```mermaid
flowchart TD
    A[Raw text] --> B[NFKC normalize]
    B --> C[Decode \\uXXXX escapes]
    C --> D[Decode %XX URL encoding]
    D --> E[Regex pattern scan]
    E --> F[Context required or score boost]
    F --> G[Validators: Luhn, blocklists, boundaries]
    G --> H[Multiline pass for card/IBAN]
    H --> I[Optional PERSON NER]
    I --> J[Sign-off + name consistency passes]
    J --> K[Overlap resolution]
    K --> L[Replace spans with tokens from end to start]
```

### 3) Restore flow

```mermaid
sequenceDiagram
    participant U as User
    participant A as anon
    participant M as mapping.json
    U->>A: anon < debug-data
    A->>M: save token->original map
    A-->>U: anonymized payload
    U->>A: anon restore < model-response
    A->>M: load map
    A-->>U: restored payload
```

## Usage

### Anonymize (default)

<!-- BEGIN CLI_ANONYMIZE -->
| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--input` | `-i` |  | Input file (reads from stdin if not provided) |
| `--output` | `-o` |  | Output file (writes to stdout if not provided) |
| `--mapping` | `-m` |  | Save mapping to file for later restoration |
| `--mapping-stderr` |  |  | Output mapping to stderr |
| `--include-mapping` |  |  | Include mapping as comment in output |
| `--share` |  |  | Output a share-ready Markdown snippet (safe to paste into issues / AI tools) |
| `--copy` |  |  | Copy output to clipboard (best effort). Requires --share |
| `--verbose` | `-v` |  | Show detected entities |
| `--format` | `-f` | `auto` | Force input format |
| `--threshold` |  | `0.5` | Minimum confidence score (0.0-1.0) |
| `--operator` |  | `token` | Anonymization operator |
| `--mask-char` |  | `*` | Masking character (used with --operator mask) |
| `--mask-count` |  |  | Fixed mask length (default: match original length) |
| `--mask-from-end` |  |  | Mask from end instead of start |
| `--hash-algo` |  | `sha256` | Hash algorithm (used with --operator hash) |
| `--encrypt-key` |  |  | AES encryption key, hex-encoded (used with --operator encrypt) Must be 32 (128-bit), 48 (192-bit), or 64 (256-bit) hex characters |
| `--replace-with` |  |  | Custom replacement format string (used with --operator custom) Use {entity_type} as placeholder, e.g. '<{entity_type}>' or 'REDACTED' |
| `--context-boost` |  | `0.15` | Context score boost factor when keywords are found nearby (0.0-1.0) |
| `--min-score-with-context` |  | `0.0` | Minimum score for context-boosted detections (0.0 = disabled) |
| `--language` | `-l` | `en` | Language for detection |
| `--ner` |  |  | Enable NER-based PERSON detection (requires ner or ner-lite feature) |
<!-- END CLI_ANONYMIZE -->

### Restore

<!-- BEGIN CLI_RESTORE -->
| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `INPUT_POSITIONAL` |  |  | Input file (positional, optional) |
| `--input` | `-i` |  | Input file (flag, optional — overrides positional) |
| `--mapping` | `-m` |  | Mapping file (defaults to ~/.anon/mapping.json) |
| `--output` | `-o` |  | Output file (writes to stdout if not provided) |
| `--decrypt-key` |  |  | AES decryption key, hex-encoded (decrypts ENC[...] tokens) Must be 32 (128-bit), 48 (192-bit), or 64 (256-bit) hex characters |
<!-- END CLI_RESTORE -->

### Commands

<!-- BEGIN COMMANDS -->
```bash
anon restore [INPUT_POSITIONAL] # Restore original values from anonymized data
anon list-entities                 # List all supported entity types
anon api                 # Start Presidio-compatible REST API server (requires `proxy` feature)
anon ui                 # Start web UI for interactive anonymization (requires `proxy` feature)
anon update-names <FILE>          # Import first/last names from a CSV file into ~/.anon/ for heuristic NER
anon image <INPUT>         # Anonymize PII in images via OCR and redaction (requires `image` feature)
anon pdf <INPUT>         # Anonymize PII in PDF documents via text extraction and redaction (requires `pdf` feature)
anon proxy                 # Start anonymizing proxy server (requires `proxy` feature)
```
<!-- END COMMANDS -->

## Detected entities

<!-- BEGIN ENTITIES -->
63 entity types across 99 patterns covering 13 countries: emails, URLs, IPs, UUIDs, credit cards, IBANs, phones, dates, crypto addresses, MAC addresses, secrets/tokens, and person names (with `--ner`). Country-specific patterns include SSNs, passports, driver's licenses, tax IDs, and national IDs for AU, ES, FI, FR, IN, IT, KR, PL, SG, SI, TH, UK, US — each with checksum validation where applicable. Detection works through URL-encoded and Unicode-escaped text.

See [docs/entities.md](docs/entities.md) for the full reference with confidence scores and context keywords.
<!-- END ENTITIES -->

## Documentation

| Guide | Description |
|-------|-------------|
| [Entity types](docs/entities.md) | All 63 entity types, scores, context-aware detection |
| [Proxy mode](docs/proxy.md) | Anonymizing reverse proxy for the Anthropic API |
| [NER setup](docs/ner.md) | Person name detection — heuristic and ML backends |
| [REST API spec](docs/openapi.yaml) | OpenAPI 3.0 specification (Swagger) |
| [Threat model](docs/threat-model.md) | Security threat model and mitigations |
| [YouTrack integration](docs/youtrack.md) | `scripts/yt` — fetch issues with human review |
| [Image redaction](docs/image-redaction.md) | OCR-based image PII redaction |

## Development

```bash
# Run tests (default — regex-only, no NER)
cargo test

# Run tests including NER heuristic + proxy tests (matches CI)
cargo test --features ner-lite,proxy

# Run tests including NER heuristic tests only
cargo test --features ner-lite

# Run tests including image tests (requires Tesseract)
cargo test --features image
cargo test --features image -- --ignored  # end-to-end OCR tests

# Build release binary
cargo build --release

# Build release with NER
cargo build --release --features ner-lite
cargo build --release --features ner
```

`cargo test` without feature flags runs all tests except NER-specific and proxy-specific ones. This is the standard check after any change.

### Benchmark

```bash
cargo run --release --example benchmark
cargo run --release --features ner-lite --example benchmark
cargo run --release --features ner --example benchmark
```

Typical results (Apple Silicon):

<!-- BEGIN BENCHMARK -->
| Feature | Throughput | Simple avg | Complex avg | Penalty |
|---------|------------|------------|-------------|---------|
| regex-only | 51k lines/s | 14.2 μs | 39.5 μs | 2.8x |
| ner-lite (heuristic) | 49k lines/s | 14.7 μs | 41.5 μs | 2.8x |
<!-- END BENCHMARK -->

## License

MIT
