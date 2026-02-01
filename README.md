# anon

Fast CLI tool to anonymize PII in debug data before sharing with AI tools.

## Installation

```bash
# Default (regex-only, no NER)
cargo install --path .

# With heuristic name detection (zero deps, +0 binary size)
cargo install --path . --features ner-lite

# With ML name detection (requires ONNX Runtime)
brew install onnxruntime
export ORT_DYLIB_PATH=$(brew --prefix onnxruntime)/lib/libonnxruntime.dylib
cargo install --path . --features ner
anon download-model  # one-time, cached at ~/.anon/models/
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

# Roundtrip: anonymize, share, restore
cat debug.json | anon > safe.json
cat response.json | anon restore

# Pipe through Claude
cat debug.json | anon | claude -p "explain this error" | anon restore
```

Mapping is auto-saved to `~/.anon/mapping.json` — no need to pass `-m` manually.

## Usage

### Anonymize (default)

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--input` | `-i` | stdin | Input file |
| `--output` | `-o` | stdout | Output file |
| `--mapping` | `-m` | `~/.anon/mapping.json` | Save mapping to file for later restoration |
| `--mapping-stderr` | | | Output mapping to stderr |
| `--include-mapping` | | | Embed mapping as `/* MAPPING: ... */` comment in output |
| `--verbose` | `-v` | | Show detected entities table on stderr |
| `--format` | `-f` | `auto` | Force input format: `auto`, `json`, `text`, `sql`, `csv` |
| `--threshold` | | `0.5` | Minimum confidence score (0.0-1.0) |
| `--ner` | | | Enable NER-based PERSON detection (requires `ner` or `ner-lite` feature) |

### Restore

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `INPUT` | | | Positional input file |
| `--input` | `-i` | | Input file flag (overrides positional) |
| `--mapping` | `-m` | `~/.anon/mapping.json` | Mapping file for restoration |
| `--output` | `-o` | | Output file (stdout if omitted) |

### List Entities

```bash
anon list-entities
```

## Detected entities

Emails, URLs, IPs, UUIDs, credit cards, crypto addresses, French phones, IBANs, SSNs, passports, aircraft registrations, flight numbers, crew codes, JWT/auth tokens, and person names (with `--ner`). Detection works through URL-encoded and Unicode-escaped text.

See [docs/entities.md](docs/entities.md) for the full reference with confidence scores and context keywords.

## Documentation

| Guide | Description |
|-------|-------------|
| [Entity types](docs/entities.md) | All 14+ entity types, scores, context-aware detection |
| [Proxy mode](docs/proxy.md) | Anonymizing reverse proxy for the Anthropic API |
| [NER setup](docs/ner.md) | Person name detection — heuristic and ML backends |
| [YouTrack integration](docs/youtrack.md) | `scripts/yt` — fetch issues with human review |

## Development

```bash
# Run tests (default — regex-only, no NER)
cargo test

# Run tests including NER heuristic tests
cargo test --features ner-lite

# Build release binary
cargo build --release
```

`cargo test` without feature flags runs all tests except NER-specific ones. This is the standard check after any change.

### Benchmark

```bash
cargo run --release --example benchmark
cargo run --release --features ner-lite --example benchmark
cargo run --release --features ner --example benchmark
```

Typical results (Apple Silicon):

| Feature | Throughput | Simple avg | Complex avg | Penalty |
|---------|-----------|-----------|-------------|---------|
| none | 251k lines/s | 2.8 μs | 8.9 μs | 3.2x |
| ner-lite | 184k lines/s | 3.9 μs | 11.4 μs | 2.9x |
| ner | 247k lines/s | 2.8 μs | 8.9 μs | 3.1x |

## Python Version

A Python implementation using Microsoft Presidio is also available on the `main` branch in `src/anon/`. It supports NLP-based name detection (via spaCy) and more international entity types.

```bash
pip install -e .
anon -i debug.json -o safe.json
```

## License

MIT
