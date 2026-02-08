# Ticket #09: Add Context Keyword Score Boosting

**Priority:** Medium
**Complexity:** High
**Status:** DONE
**File:** `src/main.rs`

## Description

Python (via Presidio) uses context keywords as **score boosters**: a pattern always matches, but the confidence score increases when context keywords are nearby. Rust uses context keywords as **binary gates**: no keyword = no match.

This is a fundamental architectural difference. Python's French recognizers (FR_PHONE, FR_IBAN, FR_SSN) have context keywords that boost their scores, while in Rust these patterns have no context keywords at all.

## Current Rust Architecture

```rust
struct PiiPattern {
    context_keywords: &'static [&'static str],
    // If non-empty: match ONLY when a keyword is within 80 chars
    // If empty: always match
}
```

## Proposed Architecture

Add a `context_boost` field to support both behaviors:

```rust
struct PiiPattern {
    name: &'static str,
    regex: &'static str,
    entity_type: &'static str,
    score: f64,
    context_keywords: &'static [&'static str],
    context_mode: ContextMode,
}

enum ContextMode {
    /// Always match, ignore context keywords
    None,
    /// Only match when context keyword is present (current behavior)
    Required,
    /// Always match, but boost score when context keyword is present
    Boost { base_score: f64 },
}
```

With `Boost`, the pattern's `score` is the boosted score (with context), and `base_score` is the score without context. This way, patterns always detect but have lower confidence without supporting context.

## Patterns to Add Context Boosting

### FR_PHONE (all patterns)
- **Keywords:** `telephone`, `tel`, `phone`, `mobile`, `contact`, `appeler`, `numero`, `portable`
- **Base score:** Keep current scores
- **Boosted score:** +0.1 (or match Presidio behavior)

### FR_IBAN (all patterns)
- **Keywords:** `iban`, `compte`, `account`, `virement`, `bank`, `banque`, `bancaire`
- **Base score:** Keep current scores
- **Boosted score:** +0.1

### FR_SSN (all patterns)
- **Keywords:** `secu`, `securite sociale`, `ssn`, `nir`, `carte vitale`, `numero`, `immatriculation`
- **Base score:** Keep current scores
- **Boosted score:** +0.1

## Alternative: Simpler Approach

Instead of the full `ContextMode` enum, just add the context keywords to these patterns WITHOUT changing the gating behavior. This gives context keywords a different meaning when paired with high-confidence patterns: the keywords don't gate but provide future extensibility.

However, this changes the behavior of these patterns (they'd stop matching without context). So the enum approach is more correct.

## Impact

This is an architectural change to the pattern system. All context-aware code paths need to be updated to handle both modes.

## Acceptance Criteria

- [x] `context_required` bool field implemented (simpler than full enum — `true` = gate, `false` + keywords = boost)
- [x] FR_PHONE patterns have context keywords with boost behavior (+0.15)
- [x] FR_IBAN patterns have context keywords with boost behavior (+0.15)
- [x] FR_SSN patterns have context keywords with boost behavior (+0.15)
- [x] Existing gated patterns (CREW_CODE, FR_PASSPORT, etc.) still use required mode
- [x] Tests cover both boosted and non-boosted scenarios
- [x] No regressions in existing behavior
