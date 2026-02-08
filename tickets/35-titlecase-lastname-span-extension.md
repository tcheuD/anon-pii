# Ticket #35: Extend Person Span to Title-case Last Names

**Priority:** High
**Complexity:** Low
**Status:** TODO
**Files:** `src/detection.rs`

## Description

`extend_person_span_to_allcaps()` only extends a detected first name to include following ALL-CAPS words (e.g., "Damien" → "Damien DUPONT"). It does not extend to Title-case last names (e.g., "Przemysław" → "Przemysław Kowalski").

This causes last names to leak in plain text when they are not written in ALL-CAPS convention.

## Current Behavior

Input: `Przemysław Kowalski\n13/Jan/26, 22:33\nDear Gaël,`
Output: `[PERSON_xxx] Kowalski\n13/Jan/26, 22:33\nDear [PERSON_yyy],`

"Kowalski" leaks because it's Title-case, not ALL-CAPS.

## Proposed Fix

Rename `extend_person_span_to_allcaps` → `extend_person_span` and accept both ALL-CAPS and Title-case words following a detected first name. A Title-case word is one starting with an uppercase letter followed by lowercase letters.

Guard against false positives: only extend to Title-case if the detected first name is a known dictionary name (INSEE or English list). This prevents extending random capitalized words.

## Acceptance Criteria

- [ ] `extend_person_span` extends to Title-case last names (e.g., "Kowalski", "Salva")
- [ ] ALL-CAPS extension still works ("DUPONT")
- [ ] `cargo test --features ner-lite` passes
- [ ] No regressions on existing tests
