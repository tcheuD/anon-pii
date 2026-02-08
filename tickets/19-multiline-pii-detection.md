# Ticket #19: Detect PII Split Across Line Breaks

**Priority:** Low
**Complexity:** High
**Status:** DONE
**File:** `src/detection.rs`

## Description

PII values split across newlines are not detected. This happens when loggers wrap long lines or when raw socket/protocol dumps break mid-value.

## Observed Miss (Stress Test)

```text
Input:
  Body: User: Alice | CC: 4532
  0155 8766 1234 (Credit card split across a newline)

Output: (credit card passed through unmasked)
```

The credit card number `4532 0155 8766 1234` is split across two lines. The regex only sees `4532` on one line and `0155 8766 1234` on the next — neither matches the credit card pattern alone.

## Root Cause

All detection patterns operate on a per-line or per-input basis, but the regex engine doesn't match across `\n` boundaries for most patterns. The credit card regex expects all 16 digits (with optional separators) on a single line.

## Proposed Approach

### Option A: Line-joining pre-processing (Recommended)

For text mode, detect lines that end with a partial pattern match and join them with the next line before running detection:

1. Identify "suspicious" line endings — lines ending with 4 digits that could be start of a credit card, partial phone number, etc.
2. Temporarily join with the next line (replacing `\n` with a space)
3. Run detection on the joined text
4. Map results back to original line positions

This is heuristic-based and won't catch all cases, but handles the most common log-wrapping scenarios.

### Option B: Whitespace normalization

Before detection, create a copy with all `\n` replaced by spaces, run detection, map back. Simple but may cause false positives on multi-line content where line breaks are meaningful separators.

### Option C: Accept the limitation

Document that PII split across lines is not detected. This is a known limitation of regex-based tokenizers and even commercial DLP tools struggle with it. Focus engineering effort on higher-impact issues.

## Complexity Note

This is a **hard problem** with diminishing returns. A regex-based approach will always struggle with arbitrarily split content. This ticket is low priority relative to #14-#17.

## Test Cases

```text
# Should detect (if implemented)
"CC: 4532\n0155 8766 1234"
"IBAN: FR76 3000\n6000 0112 3456 7890 123"

# Should NOT false-positive
"count: 4532\ntotal: 0155" (unrelated numbers on separate lines)
```
