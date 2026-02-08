# Ticket #36: Accent-insensitive Name Consistency Pass

**Priority:** High
**Complexity:** Low
**Status:** TODO
**Files:** `src/detection.rs`

## Description

The name consistency pass in `anonymize_text()` searches for bare first-name occurrences using exact string matching (`text.find(first_name)`). This misses accent variations: when "Gaël SALVA" is detected, bare "Gael" (without accent) is not caught.

This is common in French email threads where accents are sometimes dropped (especially by non-French speakers or in informal contexts).

## Current Behavior

Input: `Gaël SALVA raised this.\nDear Gael,\nBrgds, Julia`
Output: `[PERSON_abc] raised this.\nDear Gael,\nBrgds, [PERSON_def]`

"Gael" leaks because it doesn't exactly match "Gaël".

## Proposed Fix

In the name consistency pass, normalize both the first name and search text by stripping Unicode diacritics (NFD decomposition → strip combining marks). This makes the search accent-insensitive while preserving exact byte offsets for replacement.

## Acceptance Criteria

- [ ] "Gael" is caught when "Gaël" was detected (and vice versa)
- [ ] Byte offsets are correct (replacement doesn't corrupt multi-byte chars)
- [ ] `cargo test --features ner-lite` passes
- [ ] No regressions on existing tests
