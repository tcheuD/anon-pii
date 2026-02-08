# Ticket #13: Add Additional Presidio Built-in Entities

**Priority:** Low
**Complexity:** High
**Status:** DONE (CRYPTO — Bitcoin + Ethereum)
**File:** `src/main.rs`

## Description

Python via Presidio has 20+ built-in entity recognizers. Most are irrelevant to the French aviation domain, but some may be useful additions to the Rust implementation.

## Presidio Built-in Entities (Full List)

| Entity | Relevant? | Already in Rust? | Action |
|--------|-----------|------------------|--------|
| `EMAIL_ADDRESS` | Yes | Yes (as EMAIL) | — |
| `PHONE_NUMBER` | Generic | Partially (FR only) | Consider |
| `IP_ADDRESS` | Yes | Yes (as IP) | — |
| `CREDIT_CARD` | Yes | Yes | — |
| `URL` | Yes | Yes | — |
| `IBAN_CODE` | Generic | Partially (FR only) | Consider |
| `US_SSN` | No (French context) | No | Skip |
| `US_DRIVER_LICENSE` | No | No | Skip |
| `CRYPTO` | Maybe | No | Consider |
| `DATE_TIME` | Maybe | No | Consider |
| `LOCATION` | Maybe (NLP) | No | Defer to #11 |
| `PERSON` | Yes (NLP) | No | See #11 |
| `MEDICAL_LICENSE` | No | No | Skip |
| `NRP` | No | No | Skip |
| `US_BANK_NUMBER` | No | No | Skip |
| `US_ITIN` | No | No | Skip |
| `US_PASSPORT` | No | No | Skip |
| `UK_NHS` | No | No | Skip |
| Other intl entities | No | No | Skip |

## Recommended Additions

### 1. CRYPTO (cryptocurrency addresses)

Bitcoin: `\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b`
Ethereum: `\b0x[0-9a-fA-F]{40}\b`

Useful for anonymizing debug logs from fintech or payment systems.

### 2. DATE_TIME

Complex to implement well. Consider a focused subset:
- ISO 8601 dates: `\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2})?`
- French dates: `\d{2}/\d{2}/\d{4}`

**Caution:** Date detection has very high false-positive risk. Consider making it context-aware or opt-in.

### 3. Generic PHONE_NUMBER

International phone numbers beyond French:
- Generic international: `\+\d{1,3}[\s.-]?\d{4,14}`

### 4. Generic IBAN

Extend beyond French IBANs:
- `[A-Z]{2}\d{2}[\s]?[\dA-Z]{4}[\s]?(?:[\dA-Z]{4}[\s]?){2,7}[\dA-Z]{1,4}`

## Implementation Strategy

Add these as new `PiiPattern` entries. Consider:
- Lower default scores for generic patterns
- Context-awareness for high false-positive patterns (DATE_TIME)
- Feature flags for optional entity groups

## Acceptance Criteria

- [x] Decision made on which entities to add (CRYPTO only — others skipped or deferred)
- [x] Selected entities implemented with appropriate patterns (Bitcoin + Ethereum, score 0.9)
- [x] Context keywords added where needed to reduce false positives
- [x] Tests added for each new entity
- [x] `list-entities` updated to show new entities
- [x] No regressions in existing detection
