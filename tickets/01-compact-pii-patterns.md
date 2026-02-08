# Ticket #01: Add Compact PII Patterns

**Priority:** High
**Complexity:** Low
**Status:** DONE
**File:** `src/main.rs`

## Description

The Python implementation has additional "compact" regex patterns for French PII that detect values written without separators. The Rust implementation only has spaced/formatted variants. Add the missing compact patterns to improve detection coverage.

## Missing Patterns

### 1. FR_PHONE compact (score: 0.6)

```regex
(?<!\d)0[1-9]\d{8}(?!\d)
```

Matches French phone numbers written without any separator: `0612345678`.

**Note:** Uses lookbehind/lookahead. Rust's `regex` crate supports these. Verify with `regex` crate docs.

### 2. FR_IBAN compact (score: 0.9)

```regex
FR\d{25}
```

Matches French IBANs written without spaces: `FR7630006000011234567890189`.

### 3. FR_SSN compact (score: 0.8)

```regex
[12]\d{2}(?:0[1-9]|1[0-2]|[2-9]\d)(?:\d{2}|2[AB])\d{6}(?:\d{2})?
```

Matches French SSN/NIR numbers written without spaces: `197032B12345678`.

## Implementation

Add 3 new entries to the `PATTERNS` const array in `src/main.rs`:

```rust
PiiPattern {
    name: "fr_phone_compact",
    regex: r"(?<!\d)0[1-9]\d{8}(?!\d)",
    entity_type: "FR_PHONE",
    score: 0.6,
    context_keywords: &[],
},
PiiPattern {
    name: "fr_iban_compact",
    regex: r"FR\d{25}",
    entity_type: "FR_IBAN",
    score: 0.9,
    context_keywords: &[],
},
PiiPattern {
    name: "fr_ssn_compact",
    regex: r"[12]\d{2}(?:0[1-9]|1[0-2]|[2-9]\d)(?:\d{2}|2[AB])\d{6}(?:\d{2})?",
    entity_type: "FR_SSN",
    score: 0.8,
    context_keywords: &[],
},
```

## Tests to Add

```rust
#[test]
fn test_fr_phone_compact() {
    let anon = Anonymizer::new(0.0);
    let (result, _) = anon.anonymize_text("Appeler 0612345678 rapidement");
    assert!(result.contains("[FR_PHONE_"));
    assert!(!result.contains("0612345678"));
}

#[test]
fn test_fr_iban_compact() {
    let anon = Anonymizer::new(0.0);
    let (result, _) = anon.anonymize_text("IBAN: FR7630006000011234567890189");
    assert!(result.contains("[FR_IBAN_"));
}

#[test]
fn test_fr_ssn_compact() {
    let anon = Anonymizer::new(0.0);
    let (result, _) = anon.anonymize_text("NIR: 1970312345678901");
    assert!(result.contains("[FR_SSN_"));
}
```

## Acceptance Criteria

- [x] All 3 compact patterns added to `PATTERNS` array
- [x] Overlap resolution correctly prefers longer/spaced matches when both match
- [x] Unit tests pass for all 3 compact patterns
- [x] `cargo test` passes with no regressions
- [x] `fr_phone_compact` does NOT match numbers embedded in longer digit sequences
