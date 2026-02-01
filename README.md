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
| `--mapping` | `-m` | `~/.anon/mapping.json` | Save mapping to file for later restoration |
| `--mapping-stderr` | | | Output mapping to stderr |
| `--include-mapping` | | | Embed mapping as `/* MAPPING: ... */` comment in output |
| `--verbose` | `-v` | | Show detected entities table on stderr |
| `--format` | `-f` | `auto` | Force input format: `auto`, `json`, `text`, `sql`, `csv` |
| `--threshold` | | `0.5` | Minimum confidence score (0.0-1.0) |
| `--language` | `-l` | `en` | Language for NLP detection (reserved for future use) |
| `--ner` | | | Enable NER-based PERSON detection (requires `ner` or `ner-lite` feature) |

### Restore

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `INPUT` | | | Positional input file |
| `--input` | `-i` | | Input file flag (overrides positional) |
| `--mapping` | `-m` | `~/.anon/mapping.json` | Mapping file for restoration |
| `--output` | `-o` | | Output file (stdout if omitted) |

Both `anon restore INPUT -m map.json` and `anon restore -i INPUT -m map.json` work. Reads from stdin if neither is provided. Mapping defaults to `~/.anon/mapping.json` when `-m` is omitted.

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

### Person Names (NER)

| Entity | Backend | Score | Feature flag |
|--------|---------|-------|--------------|
| `PERSON` | ML — DistilBERT multilingual NER (ONNX, INT8) | 0.6 - 1.0 | `ner` |
| `PERSON` | Heuristic — title patterns + name dictionary | 0.55 - 0.80 | `ner-lite` |

Enabled with `--ner`. See [NER — Person Name Detection](#ner--person-name-detection) below.

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

## Proxy Mode

Anonymizing reverse proxy that sits between AI coding tools and the Anthropic API. PII is stripped from outgoing prompts and restored in incoming responses — including SSE streams.

### Start the proxy

```bash
anon proxy
# anon proxy listening on http://127.0.0.1:9100
# upstream: https://api.anthropic.com
```

### Use with Claude Code

```bash
ANTHROPIC_BASE_URL=http://127.0.0.1:9100 claude
```

All prompts are anonymized before reaching the API. Responses have tokens restored automatically.

### Proxy options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--port` | `-p` | `9100` | Port to listen on |
| `--upstream` | `-u` | `https://api.anthropic.com` | Upstream API URL |
| `--threshold` | | `0.5` | Minimum confidence score (0.0-1.0) |
| `--session-dir` | | `/tmp/anon-proxy-<random>` | Directory for mapping files |

### Testing without an API key

Point the proxy at a local echo server to inspect what gets sent upstream:

```bash
# Terminal 1 — echo server
python3 -c "
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers['Content-Length']))
        print(json.dumps(json.loads(body), indent=2))
        self.send_response(200)
        self.send_header('content-type','application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'content':[{'type':'text','text':'ok'}]}).encode())
http.server.HTTPServer(('127.0.0.1',8888),H).serve_forever()
"

# Terminal 2 — proxy pointing at echo server
anon proxy --upstream http://127.0.0.1:8888

# Terminal 3 — send a request
curl -s http://127.0.0.1:9100/v1/messages \
  -H "content-type: application/json" \
  -d '{"messages":[{"role":"user","content":"Email me at john@secret.com"}]}' | jq .
```

The echo server prints the anonymized body — `[EMAIL_ADDRESS_1]` instead of `john@secret.com`.

### Monitoring

The mapping file is written after each request and on shutdown. The session directory path is printed at startup:

```bash
# Watch the mapping grow (use the path printed by the proxy)
watch -n1 'jq . /tmp/anon-proxy-*/mapping.json 2>/dev/null'

# Or use a fixed session dir
anon proxy --session-dir /tmp/my-session
watch -n1 'jq . /tmp/my-session/mapping.json'
```

### Test with curl

```bash
# Non-streaming
curl -s http://127.0.0.1:9100/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 256,
    "messages": [
      {"role": "user", "content": "Summarize: John lives at john@example.com, IP 192.168.1.42"}
    ]
  }' | jq .

# Streaming
curl -s --no-buffer http://127.0.0.1:9100/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 256,
    "stream": true,
    "messages": [
      {"role": "user", "content": "What about pilot JDU on aircraft F-HOPA?"}
    ]
  }'
```

### Security notes

- Binds to `127.0.0.1` only — not accessible from the network
- Host header validation blocks DNS rebinding attacks
- Mapping file contains original PII — treat it as sensitive
- API keys are forwarded but never logged or stored

## NER — Person Name Detection

Person names aren't reliably detectable with regex. The `--ner` flag enables NER-based detection with two backends, selected at compile time via feature flags.

### Heuristic (`ner-lite`)

Zero dependencies. Detects names using title patterns (M., Mme, Dr, Captain...) and a ~500 entry French/English first name dictionary.

```bash
cargo install --path . --features ner-lite

echo "M. Dupont est pilote, Dr Martin en copilote" | anon --ner
# M. [PERSON_2] est pilote, Dr [PERSON_1] en copilote
```

### ML (`ner`)

Uses DistilBERT multilingual NER (Davlan/distilbert-base-multilingual-cased-ner-hrl) via ONNX Runtime. INT8 quantized, ~130MB model.

```bash
# 1. Install ONNX Runtime
brew install onnxruntime  # macOS
# apt install libonnxruntime-dev  # Debian/Ubuntu
export ORT_DYLIB_PATH=$(brew --prefix onnxruntime)/lib/libonnxruntime.dylib

# 2. Install with ner feature
cargo install --path . --features ner

# 3. Download model (~130MB, cached at ~/.anon/models/)
anon download-model

# 4. Use
echo "Jean Dupont called from Paris" | anon --ner
# [PERSON_1] called from Paris
```

The ML backend detects names in French, English, German, Spanish, Portuguese, Dutch, Arabic, and Chinese without any keyword context.

When both features are compiled (`--features ner,ner-lite`), ML takes precedence.

## Python Version

A Python implementation using Microsoft Presidio is also available on the `main` branch in `src/anon/`. It supports NLP-based name detection (via spaCy) and more international entity types.

```bash
pip install -e .
# Optional: pip install -e ".[nlp]" for spaCy name detection
anon -i debug.json -o safe.json
```

## License

MIT
