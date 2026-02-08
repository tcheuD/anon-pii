# Ticket #14: Expand CREW_CODE Blocklist

**Priority:** High
**Complexity:** Low
**Status:** DONE
**File:** `src/patterns.rs`

## Description

The `CREW_CODE` pattern (`\b[A-Z]{3}\b`) produces false positives on common 3-letter uppercase abbreviations that are not crew member codes. Despite `context_required: true`, these abbreviations leak through and get masked incorrectly.

## Observed False Positives (Stress Test)

| Input | Masked As | Context |
|-------|-----------|---------|
| `URL` | `[CREW_CODE_d88a2ab5]` | "sensitive tokens in a URL string" |
| `PII` | `[CREW_CODE_8ed2e85d]` | "PII split across lines" |
| `XYZ` | `[CREW_CODE_a4bbf7cf]` | "Auth-Token=XYZ-123" |

## Root Cause

Two potential issues:

1. **Blocklist too narrow** — `URL`, `PII`, `XYZ` and many other common uppercase trigrams are missing from `CREW_CODE_BLOCKLIST`
2. **Possible context gate bypass** — `context_required: true` should prevent matches when no crew keyword is within 80 chars, yet these matches appeared in text with zero crew context. Investigate whether the binary gate is actually enforced at the threshold being used.

## Fix

### 1. Add missing abbreviations to `CREW_CODE_BLOCKLIST` in `src/patterns.rs`

Suggested additions (non-exhaustive):

```
"URL", "API", "CSS", "DNS", "FTP", "GPS", "GUI", "HTML", "HTTP", "IDE",
"JSON", "PDF", "PHP", "RAM", "ROM", "SDK", "SQL", "SSH", "SSL", "TCP",
"UDP", "USB", "VPN", "XML", "ZIP", "PII", "SSN", "DOB", "DOC", "REF",
"XYZ", "ABC", "DEF", "QRS", "JFK", "LAX", "CDG", "ORY", "LHR", "AMS",
"FRA", "BCN", "MAD", "MUC", "FCO", "ZRH", "BRU", "LIS", "OSL", "ARN",
"CPH", "HEL", "WAW", "PRG", "VIE", "ATH", "IST", "DXB", "SIN", "HKG",
"NRT", "ICN", "PEK", "SYD", "YYZ", "YUL", "GRU", "EZE", "SCL", "BOG",
"MIA", "ATL", "ORD", "DFW", "DEN", "SFO", "SEA", "BOS", "IAD", "EWR",
"LOG", "ERR", "MSG", "SRC", "ENV", "VAR", "KEY", "VAL", "ROW", "COL",
"TMP", "BIN", "LIB", "OBJ", "RUN", "CMD", "BAT", "EXE", "DLL", "SYS",
"EOF", "NUL", "NIL", "MAX", "MIN", "AVG", "SUM", "CNT", "LEN", "IDX",
"ACK", "NAK", "SYN", "FIN", "RST",
```

Note: IATA airport codes (CDG, ORY, etc.) are particularly important — they appear constantly in aviation logs alongside crew codes but are not crew members.

### 2. Audit `context_required` enforcement

Verify that when `context_required: true` and threshold > 0, detections without a context keyword are actually dropped — not just scored at 0.

## Test Cases

```text
# Should NOT be masked
"sensitive tokens in a URL string"
"PII split across lines"
"Auth-Token=XYZ-123"
"GET /api/v1/booking"
"departure CDG arrival ORY"

# Should still be masked (crew context present)
"crew member JDU on duty"
"pilote PLR en service"
```
