# anon

CLI tool to anonymize PII in debug data before sharing with AI tools like Claude Code.

## Installation

```bash
pip install -e .
```

Or add to your PATH after install:
```bash
export PATH="$HOME/Library/Python/3.11/bin:$PATH"
```

## Quick Start

```bash
# Anonymize from stdin
echo 'Error for user john@example.com on F-GRHK' | anon
# Output: Error for user [EMAIL_ADDRESS_1] on [AIRCRAFT_REGISTRATION_1]

# Anonymize with mapping file (for later restoration)
cat debug.json | anon -m mapping.json > anonymized.json

# Restore original values
cat anonymized.json | anon restore -m mapping.json
```

## Usage

### Anonymize

```bash
# From stdin
cat file.json | anon

# From file
anon -i debug.log

# With options
anon -i input.json \
  -m mapping.json \      # Save mapping for restoration
  -o output.json \       # Output to file
  -v                     # Verbose: show detected entities
```

### Restore

```bash
# Restore using mapping file
cat anonymized.json | anon restore -m mapping.json

# Or from file
anon restore anonymized.json -m mapping.json
```

### List Entities

```bash
anon list-entities
```

## Supported PII Types

### Standard (via Presidio)
- `EMAIL_ADDRESS` - Email addresses
- `PHONE_NUMBER` - Phone numbers
- `PERSON` - Names (requires spaCy model)
- `IP_ADDRESS` - IP addresses
- `CREDIT_CARD` - Credit card numbers
- `URL` - URLs
- And 20+ more...

### French-specific
- `FR_PHONE_NUMBER` - French phone numbers (+33, 06, etc.)
- `FR_IBAN` - French IBANs (FR76...)
- `FR_SSN` - French social security numbers (NIR)
- `FR_PASSPORT` - French passport numbers

### Aviation-specific
- `AIRCRAFT_REGISTRATION` - Aircraft tail numbers (F-XXXX, N12345, etc.)
- `CREW_CODE` - 3-letter crew codes with context (JDU, MMA)
- `FLIGHT_NUMBER` - Flight numbers (IZM1234, RLA567)

## Examples

### Debug Logs

```bash
# Anonymize error logs before sharing
tail -100 /var/log/app/error.log | anon | pbcopy
```

### API Responses

```bash
# Anonymize JSON API response
curl -s https://api.internal/users/123 | anon -m map.json
```

### Stack Traces

```bash
# Anonymize stack trace
python script.py 2>&1 | anon
```

### Reversible Workflow

```bash
# 1. Anonymize and save mapping
cat debug_data.json | anon -m session_map.json > safe_data.json

# 2. Share safe_data.json with AI tools...

# 3. If AI returns anonymized data, restore it
echo '[PERSON_1] caused the error' | anon restore -m session_map.json
# Output: Jean Dupont caused the error
```

## Options

| Option | Short | Description |
|--------|-------|-------------|
| `--input` | `-i` | Input file (reads from stdin if not provided) |
| `--mapping` | `-m` | Save/load mapping file |
| `--output` | `-o` | Output to file instead of stdout |
| `--format` | `-f` | Force format (json, text, sql, csv) |
| `--verbose` | `-v` | Show detected entities table |
| `--language` | `-l` | Language for detection (en, fr) |
| `--threshold` | | Minimum confidence score (0.0-1.0) |

## License

MIT
