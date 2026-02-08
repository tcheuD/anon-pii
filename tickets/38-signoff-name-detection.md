# Ticket #38: Sign-off Name Detection

**Priority:** High
**Complexity:** Low
**Status:** TODO
**Files:** `src/detection.rs`

## Description

Names appearing in email/ticket sign-offs are not detected when they differ from the formal name in the message header. Common case: nicknames or informal names used as sign-offs.

Example: "Przemysław Kowalski" is detected in the header, but the sign-off "Best regards,\nPrzemek" leaks "Przemek" because it's a nickname — not a substring, not in any dictionary, and not found by NER.

## Current Behavior

Input:
```
Przemysław Kowalski
13/Jan/26, 22:33
Dear Gaël,
...
Best regards,
Przemek
```

Output: `Przemek` leaks in plain text on every sign-off line.

## Proposed Fix

Add a sign-off detection pass in `anonymize_text()`: scan for common closing salutations (Best regards, Brgds, Cordialement, Regards, Cheers, Sincerely, etc.) followed by a capitalized word on the same or next line. If the word is not blocklisted and looks like a name (`is_name_like_word`), add it as a PERSON detection.

This catches nicknames, informal names, and any name in sign-off context regardless of dictionary presence.

## Acceptance Criteria

- [ ] "Przemek" after "Best regards," is detected as PERSON
- [ ] Common French and English sign-off patterns are covered
- [ ] Blocklisted words (company names, etc.) are still filtered
- [ ] `cargo test --features ner-lite` passes
- [ ] No regressions
