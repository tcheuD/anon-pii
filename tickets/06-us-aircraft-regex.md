# Ticket #06: Align US Aircraft Registration Regex

**Priority:** Medium
**Complexity:** Low
**Status:** DONE
**File:** `src/main.rs`

## Description

The US aircraft registration (N-number) pattern differs between Python and Rust.

## Current Patterns

| | Pattern | Score |
|---|---------|-------|
| **Python** | `\bN\d{1,5}[A-Z]{0,2}\b` | 0.85 |
| **Rust** | `\bN[1-9][0-9]{0,4}[A-Z]?\b` | 0.7 |

## Differences

1. **First digit**: Rust requires `[1-9]` (non-zero), Python allows `\d` (any digit). FAA N-numbers do start with a non-zero digit, so Rust is more correct here.
2. **Trailing letters**: Python allows 0-2 letters `[A-Z]{0,2}`, Rust allows 0-1 `[A-Z]?`. FAA allows up to 2 suffix letters (e.g., `N12345AB`), so Python is more correct here.
3. **Score**: Python uses 0.85, Rust uses 0.7.

## Proposed Change

Combine the best of both:

```rust
PiiPattern {
    name: "aircraft_us",
    regex: r"\bN[1-9][0-9]{0,4}[A-Z]{0,2}\b",  // non-zero start + up to 2 letters
    entity_type: "AIRCRAFT",
    score: 0.85,  // align with Python
    context_keywords: &["aircraft", "avion", "registration", "immat", "appareil", "tail"],
}
```

This is the most accurate representation of real FAA N-numbers.

## Tests to Update

Update `test_aircraft_us_with_context` to also verify 2-letter suffixes:

```rust
#[test]
fn test_aircraft_us_with_context() {
    let anon = Anonymizer::new(0.0);
    let (result, _) = anon.anonymize_text("aircraft N12345AB was delayed");
    assert!(result.contains("[AIRCRAFT_"));
    assert!(!result.contains("N12345AB"));
}
```

## Acceptance Criteria

- [x] US aircraft regex updated to `\bN[1-9][0-9]{0,4}[A-Z]{0,2}\b`
- [x] Score updated to 0.85
- [x] Existing test updated, new test for 2-letter suffix added
- [x] `cargo test` passes
