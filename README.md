# anon

Fast CLI tool to anonymize PII in debug data before sharing with AI tools.

## Installation

```bash
cargo build --release
cp target/release/anon ~/.local/bin/  # or anywhere on your PATH
```
 
## Quick Start

```bash
# Anonymize from stdin
echo 'Error for user john@example.com on F-GRHK' | anon
# Output: Error for user [EMAIL_1] on [AIRCRAFT_1]

# Anonymize JSON (auto-detected, structure preserved)
echo '{"email": "john@example.com", "count": 42}' | anon
# Output: {"count": 42, "email": "[EMAIL_1]"}

# Roundtrip: anonymize, share, restore
cat debug.json | anon -m map.json > safe.json
cat response.json | anon restore -m map.json
```

## Usage

### Anonymize

```bash
# From stdin
cat file.json | anon

# From file
anon -i debug.log -o anonymized.log

# With mapping + verbose
anon -i input.json -m mapping.json -o output.json -v
```

### Restore

```bash
# Restore using mapping file
cat anonymized.json | anon restore -m mapping.json

# From file to file
anon restore -i anonymized.json -m mapping.json -o restored.json
```

### List Entities

```bash
anon list-entities
```

## CLI Reference

### Anonymize (default)

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--input` | `-i` | stdin | Input file |
| `--output` | `-o` | stdout | Output file |
| `--mapping` | `-m` | | Save mapping to file for later restoration |
| `--mapping-stderr` | | | Output mapping to stderr |
| `--include-mapping` | | | Embed mapping as `/* MAPPING: ... */` comment in output |
| `--verbose` | `-v` | | Show detected entities table on stderr |
| `--format` | `-f` | `auto` | Force input format: `auto`, `json`, `text` |
| `--threshold` | | `0.0` | Minimum confidence score (0.0-1.0) |

### Restore

| Option | Short | Required | Description |
|--------|-------|----------|-------------|
| `--input` | `-i` | | Input file (stdin if omitted) |
| `--mapping` | `-m` | Yes | Mapping file for restoration |
| `--output` | `-o` | | Output file (stdout if omitted) |

## Supported Entity Types

### Common

| Entity | Description | Score |
|--------|-------------|-------|
| `EMAIL` | Email addresses | 0.9 |
| `URL` | HTTP/HTTPS URLs | 0.9 |
| `IP` | IPv4 addresses | 0.9 |
| `CREDIT_CARD` | 16-digit card numbers | 0.7 |
| `UUID` | Standard UUIDs | 0.95 |

### French

| Entity | Description | Score |
|--------|-------------|-------|
| `FR_PHONE` | French phone numbers (+33, 06...) | 0.7 - 0.9 |
| `FR_IBAN` | French IBANs (FR76...) | 0.95 |
| `FR_SSN` | Social security numbers (NIR), Corsica support | 0.85 |
| `FR_PASSPORT` | French passport numbers (context-aware) | 0.7 |

### Aviation

| Entity | Description | Score |
|--------|-------------|-------|
| `AIRCRAFT` | French (F-XXXX), European, US N-numbers (context-aware) | 0.7 - 0.95 |
| `FLIGHT` | Amelia codes (IZM, RLA, AME, GJT, AF), IATA/ICAO (context-aware) | 0.4 - 0.9 |
| `CREW_CODE` | 3-letter crew codes (context-aware, with blocklist) | 0.85 |

## Format Handling

Format is auto-detected by default (`--format auto`):

- **JSON** — Detected when content starts with `{` or `[` and parses as valid JSON. Recursively processes the JSON tree, anonymizing only string values. Numbers, booleans, and structure are preserved. Original indentation is maintained.
- **Text** — Default fallback. Applies regex patterns across the full text.

Force a format with `--format json` or `--format text`.

## Context-Aware Detection

Some patterns require aviation or identity keywords within 80 characters to trigger, reducing false positives:

| Entity | Requires context keywords |
|--------|--------------------------|
| `CREW_CODE` | crew, pilot, equipage, captain, roster, planning, duty... |
| `FR_PASSPORT` | passeport, passport, document, identite |
| `FLIGHT` (IATA/ICAO) | flight, vol, departure, arrival, schedule, rotation |
| `AIRCRAFT` (US) | aircraft, avion, registration, immat, tail |

Crew codes also use a blocklist to avoid matching common 3-letter words (THE, AND, FOR, VOL, PAX, ETA, UTC, AOG, etc.).

## Examples

### Debug Logs

```bash
tail -100 /var/log/app/error.log | anon | pbcopy
```

### API Responses

```bash
curl -s https://api.internal/users/123 | anon -m map.json
```

### Reversible Workflow

```bash
# 1. Anonymize and save mapping
cat debug_data.json | anon -m session.json > safe.json

# 2. Share safe.json with AI tools...

# 3. Restore AI response using the same mapping
echo '[EMAIL_1] caused the error' | anon restore -m session.json
# Output: john@example.com caused the error
```

### Threshold Filtering

```bash
# Only detect high-confidence patterns (>= 0.8)
cat logs.txt | anon --threshold 0.8
```

### Mapping to stderr

```bash
# Pipe anonymized data forward, capture mapping separately
cat data.json | anon --mapping-stderr > anonymized.json 2> mapping.json
```

## Python Version

A Python implementation using Microsoft Presidio is also available in `src/anon/`. It supports NLP-based name detection (via spaCy), more international entity types, and SQL/CSV format detection.

```bash
pip install -e .
# Optional: pip install -e ".[nlp]" for spaCy name detection
anon -i debug.json -o safe.json
```

## License

MIT
