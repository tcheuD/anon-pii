# Ticket #37: Last-name Consistency Pass

**Priority:** Medium
**Complexity:** Low
**Status:** TODO
**Files:** `src/detection.rs`

## Description

The name consistency pass only extracts and searches for bare **first names** from detected "Firstname LASTNAME" pairs. Bare last names appearing elsewhere in the text are not caught.

This is less common than bare first names but does occur in formal/business contexts (e.g., "Please contact Kowalski" or "Kowalski confirmed the schedule").

## Current Behavior

The consistency pass at detection.rs:485 does:
```rust
.filter_map(|d| d.original.split_whitespace().next().map(|s| s.to_string()))
```

This only extracts the first word (first name). Last names are ignored.

## Proposed Fix

Also extract last names from multi-word PERSON detections and search for bare occurrences at word boundaries. Use the same logic (score 0.50, skip if already covered). Only search for last names that are at least 3 characters long to avoid false positives.

## Acceptance Criteria

- [ ] Bare last names from detected full names are caught
- [ ] Short last names (< 3 chars) are skipped
- [ ] `cargo test --features ner-lite` passes
- [ ] No regressions on existing tests
