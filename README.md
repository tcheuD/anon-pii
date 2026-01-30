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
# Output: Error for user [EMAIL_ADDRESS_1] on [AIRCRAFT_REGISTRATION_1]

# Anonymize JSON (auto-detected, structure preserved)
echo '{"email": "john@example.com", "count": 42}' | anon
# Output: {"count": 42, "email": "[EMAIL_ADDRESS_1]"}

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
| `--format` | `-f` | `auto` | Force input format: `auto`, `json`, `text`, `sql`, `csv` |
| `--threshold` | | `0.5` | Minimum confidence score (0.0-1.0) |
| `--language` | `-l` | `en` | Language for NLP detection (reserved for future use) |

### Restore

| Option | Short | Required | Description |
|--------|-------|----------|-------------|
| `INPUT` | | | Positional input file |
| `--input` | `-i` | | Input file flag (overrides positional) |
| `--mapping` | `-m` | Yes | Mapping file for restoration |
| `--output` | `-o` | | Output file (stdout if omitted) |

Both `anon restore INPUT -m map.json` and `anon restore -i INPUT -m map.json` work. Reads from stdin if neither is provided.

## Supported Entity Types

### Common

| Entity | Description | Score |
|--------|-------------|-------|
| `EMAIL_ADDRESS` | Email addresses | 0.9 |
| `URL` | HTTP/HTTPS URLs | 0.9 |
| `IP_ADDRESS` | IPv4 addresses | 0.9 |
| `CREDIT_CARD` | 16-digit card numbers (Luhn validated, context-aware) | 0.7 |
| `UUID` | Standard UUIDs | 0.95 |
| `CRYPTO` | Bitcoin and Ethereum addresses | 0.9 |

### French

| Entity | Description | Score |
|--------|-------------|-------|
| `FR_PHONE_NUMBER` | French phone numbers — intl, national, compact (+33, 06, 0612345678) | 0.6 - 0.9 |
| `FR_IBAN` | French IBANs — spaced and compact (FR76...) | 0.9 - 0.95 |
| `FR_SSN` | Social security numbers (NIR) — spaced and compact, Corsica support | 0.8 - 0.85 |
| `FR_PASSPORT` | French passport numbers (context-aware) | 0.7 |

### Aviation

| Entity | Description | Score |
|--------|-------------|-------|
| `AIRCRAFT_REGISTRATION` | French (F-XXXX), European, US N-numbers (context-aware) | 0.85 - 0.95 |
| `FLIGHT_NUMBER` | Amelia codes (IZM, RLA, AME, GJT, AF), IATA/ICAO (context-aware) | 0.4 - 0.9 |
| `CREW_CODE` | 3-letter crew codes (context-aware, with blocklist) | 0.85 |

## Format Handling

Format is auto-detected by default (`--format auto`):

- **JSON** — Detected when content starts with `{` or `[` and parses as valid JSON. Recursively processes the JSON tree, anonymizing only string values. Numbers, booleans, and structure are preserved. Original indentation is maintained.
- **SQL** — Detected when the first word is a SQL keyword (SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, DROP). Processed as text.
- **CSV** — Detected when multiple lines have consistent comma counts. Processed as text.
- **Text** — Default fallback. Applies regex patterns across the full text.

Force a format with `--format json`, `--format text`, `--format sql`, or `--format csv`.

## Context-Aware Detection

Context keywords work in two modes:

**Required** — Pattern only matches when a keyword appears within 80 characters:

| Entity | Context keywords |
|--------|-----------------|
| `CREW_CODE` | crew, pilot, equipage, captain, roster, planning, duty... |
| `FR_PASSPORT` | passeport, passport, document, identite |
| `FLIGHT_NUMBER` (IATA/ICAO) | flight, vol, departure, arrival, schedule, rotation |
| `AIRCRAFT_REGISTRATION` (US) | aircraft, avion, registration, immat, immatriculation, tail |
| `CREDIT_CARD` | card, carte, credit, debit, payment, paiement, cb |

**Score boost** — Pattern always matches, but confidence gets +0.15 when keywords are nearby:

| Entity | Context keywords |
|--------|-----------------|
| `FR_PHONE_NUMBER` | telephone, tel, phone, mobile, contact, appeler, numero, portable |
| `FR_IBAN` | iban, compte, account, virement, bank, banque, bancaire |
| `FR_SSN` | secu, securite sociale, ssn, nir, carte vitale, numero, immatriculation |

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
echo '[EMAIL_ADDRESS_1] caused the error' | anon restore -m session.json
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

A Python implementation using Microsoft Presidio is also available on the `main` branch in `src/anon/`. It supports NLP-based name detection (via spaCy) and more international entity types.

```bash
pip install -e .
# Optional: pip install -e ".[nlp]" for spaCy name detection
anon -i debug.json -o safe.json
```

## License

MIT
