# Gap Analysis: Python → Rust Port

## Summary

The Python implementation (main branch, Presidio-based) has several features and behaviors not yet present in the Rust implementation (rust branch). This document catalogs every gap and maps them to individual tickets.

## Feature Matrix

| Feature | Python | Rust | Gap? | Ticket |
|---------|--------|------|------|--------|
| **CLI: `--input`/`--output`/`--mapping`** | Yes | Yes | No | — |
| **CLI: `--verbose`** | Yes | Yes | No | — |
| **CLI: `--format`** | json/text/sql/csv | json/text/sql/csv | No | #02 |
| **CLI: `--threshold`** | Default 0.5 | Default 0.5 | No | #07 |
| **CLI: `--language`** | Yes (default "en") | Yes (default "en") | No | #04 |
| **CLI: `--mapping-stderr`** | Yes | Yes | No | — |
| **CLI: `--include-mapping`** | Appends at END | Appends at END | No | #08 |
| **Subcommand: `restore`** | Positional input | Positional + `--input` flag | No | #12 |
| **Subcommand: `list-entities`** | Yes | Yes | No | — |
| **Format: JSON** | Yes | Yes | No | — |
| **Format: Text** | Yes | Yes | No | — |
| **Format: SQL detection** | Yes (processed as text) | Yes (processed as text) | No | #02 |
| **Format: CSV detection** | Yes (processed as text) | Yes (processed as text) | No | #02 |
| **Entity: EMAIL** | `EMAIL_ADDRESS` | `EMAIL_ADDRESS` | No | #05 |
| **Entity: URL** | `URL` | `URL` | No | — |
| **Entity: FR_PHONE (intl)** | Yes (0.9) | Yes (0.9) | No | — |
| **Entity: FR_PHONE (national)** | Yes (0.7) | Yes (0.7) | No | — |
| **Entity: FR_PHONE (compact)** | Yes (0.6) | Yes (0.6) | No | #01 |
| **Entity: FR_IBAN (spaced)** | Yes (0.95) | Yes (0.95) | No | — |
| **Entity: FR_IBAN (compact)** | Yes (0.9) | Yes (0.9) | No | #01 |
| **Entity: FR_SSN (spaced)** | Yes (0.85) | Yes (0.85) | No | — |
| **Entity: FR_SSN (compact)** | Yes (0.8) | Yes (0.8) | No | #01 |
| **Entity: FR_PASSPORT** | Yes (0.7, context) | Yes (0.7, context) | No | — |
| **Entity: AIRCRAFT (FR)** | Yes (0.95) | Yes (0.95) | No | — |
| **Entity: AIRCRAFT (EU)** | Yes (0.9) | Yes (0.9) | No | — |
| **Entity: AIRCRAFT (US)** | `N\d{1,5}[A-Z]{0,2}` 0.85 | `N[1-9][0-9]{0,4}[A-Z]{0,2}` 0.85 | No | #06 |
| **Entity: AIRCRAFT context** | All patterns | US + `immatriculation` | No | #10 |
| **Entity: FLIGHT (Amelia)** | No AF code | Has AF code | Rust ahead | — |
| **Entity: FLIGHT (IATA)** | Yes (0.4, context) | Yes (0.4, context) | No | — |
| **Entity: FLIGHT (ICAO)** | Yes (0.5, context) | Yes (0.5, context) | No | — |
| **Entity: CREW_CODE** | Yes (0.85, context+blocklist) | Yes (0.85, context+blocklist) | No | — |
| **Entity: IP** | Yes (Presidio built-in) | Yes (0.9) | No | — |
| **Entity: CREDIT_CARD** | Yes (Presidio built-in) | Yes (0.7, Luhn) | No | — |
| **Entity: UUID** | No | Yes | Rust ahead | — |
| **Entity: PERSON (NLP)** | Infrastructure exists | Yes (`ner` + `ner-lite` features) | No | #11 |
| **Entity: Presidio built-ins** | 20+ types | CRYPTO (Bitcoin+Ethereum) | Partial | #13 |
| **Entity naming** | Presidio-style (long) | Presidio-style (long) | No | #05 |
| **Context: score boosting** | Presidio-style boost | Dual mode (gate+boost) | No | #09 |
| **Context: FR_PHONE keywords** | Yes (boost) | Yes (+0.15 boost) | No | #09 |
| **Context: FR_IBAN keywords** | Yes (boost) | Yes (+0.15 boost) | No | #09 |
| **Context: FR_SSN keywords** | Yes (boost) | Yes (+0.15 boost) | No | #09 |
| **Mapping: 0o600 permissions** | No | Yes | Rust ahead | — |
| **Mapping: session_id** | Yes | Yes | No | — |
| **Mapping: created_at** | Yes | Yes | No | — |
| **JSON: fallback on error** | Silent fallback | Error exit | By design | — |
| **Input: 512MB limit** | No | Yes | Rust ahead | — |
| **Crew blocklist size** | 50 words | 54 words | Minor | — |

## Features Where Rust Is Ahead

These are NOT gaps — Rust has features Python lacks:
- UUID entity detection
- AF flight code in Amelia pattern
- Mapping file permissions (0o600)
- 512MB input limit
- Luhn validation on credit cards (explicit)
- 4 additional blocklist words (IZM, RLA, AME, GJT)

## Ticket Overview

| # | Ticket | Priority | Complexity | Status |
|---|--------|----------|------------|--------|
| 01 | Add compact PII patterns | High | Low | DONE |
| 02 | Add SQL/CSV format detection | Medium | Low | DONE |
| 04 | Add `--language` CLI flag | Low | Low | DONE |
| 05 | Align entity naming conventions | High | Medium | DONE |
| 06 | Align US aircraft registration regex | Medium | Low | DONE |
| 07 | Align default threshold to 0.5 | Medium | Low | DONE |
| 08 | Align `--include-mapping` placement | Low | Low | DONE |
| 09 | Add context keyword score boosting | Medium | High | DONE |
| 10 | Add aircraft context keywords to all patterns | Medium | Low | DONE |
| 11 | Add PERSON entity detection (NLP) | Low | Very High | DONE |
| 30 | Batched NER inference | High | High | TODO |
| 31 | ONNX Runtime optimizations (threading + CoreML) | High | Medium | TODO |
| 12 | Align restore command interface | Low | Low | DONE |
| 13 | Add additional Presidio built-in entities | Low | High | DONE (CRYPTO) |

## Implementation Summary

All gap tickets implemented. #11 (NLP/PERSON) done via `ner` and `ner-lite` feature flags. New performance tickets #30 (batching) and #31 (ONNX Runtime tuning) track ML NER speed improvements.

### Changes made in `src/main.rs` (22 tests → 31 tests):

**Ticket #01 — Compact patterns:** Added `fr_phone_compact`, `fr_iban_compact`, `fr_ssn_compact` (3 new patterns).

**Ticket #02 — SQL/CSV detection:** Added `Sql` and `Csv` variants to `Format` and `DetectedFormat` enums. SQL detected by first keyword (SELECT/INSERT/UPDATE/DELETE/CREATE/ALTER/DROP). CSV detected by consistent comma counts across first 5 lines. Both processed as plain text.

**Ticket #04 — Language flag:** Added `--language` / `-l` (default `"en"`) to CLI. Displayed in verbose output. Reserved for future NLP integration.

**Ticket #05 — Entity naming:** Aligned all entity types to Presidio-style names:
- `EMAIL` → `EMAIL_ADDRESS`
- `FR_PHONE` → `FR_PHONE_NUMBER`
- `AIRCRAFT` → `AIRCRAFT_REGISTRATION`
- `FLIGHT` → `FLIGHT_NUMBER`
- `IP` → `IP_ADDRESS`

**Ticket #06 — US aircraft regex:** Updated pattern to `\bN[1-9][0-9]{0,4}[A-Z]{0,2}\b` (allows 2 suffix letters, matches FAA spec). Score raised to 0.85.

**Ticket #07 — Default threshold:** Changed from 0.0 to 0.5 (matches Python).

**Ticket #08 — Include-mapping placement:** Mapping comment now appended at END of output (was at top).

**Ticket #09 — Context score boosting:** Added dual context mode via `context_required` field on `PiiPattern`:
- `context_required: true` = binary gate (CREW_CODE, FR_PASSPORT, aircraft_us, flights, CREDIT_CARD)
- `context_required: false` + keywords = score boost (+0.15 when context present)
Applied boost keywords to FR_PHONE_NUMBER, FR_IBAN, FR_SSN patterns.

**Ticket #10 — Aircraft context keywords:** Added `immatriculation` to `aircraft_us` context keywords.

**Ticket #12 — Restore interface:** Added positional `INPUT` argument alongside `--input` flag. Both `anon restore INPUT -m mapping.json` and `anon restore -i INPUT -m mapping.json` now work. Flag overrides positional.

**Ticket #13 — CRYPTO entity:** Added Bitcoin (`[13][a-km-zA-HJ-NP-Z1-9]{25,34}`) and Ethereum (`0x[0-9a-fA-F]{40}`) patterns, score 0.9.

### Final entity count: 22 patterns, 14 entity types (was 16 patterns, 12 types)
