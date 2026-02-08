# Ticket #15: Detect PII with Unicode Escape Sequences

**Priority:** Medium
**Complexity:** Medium
**Status:** DONE
**File:** `src/detection.rs`

## Description

PII containing unicode escape sequences (e.g. `\u0040` for `@`) passes through undetected. This is common in JSON log output where special characters get escaped.

## Observed Miss (Stress Test)

```text
Input:  "client\u0040company.com requested refund to FR76 3000 6000 0112 3456 7890 123"
Output: (email passed through unmasked, IBAN was correctly detected)
```

`client\u0040company.com` is an email address (`client@company.com`) but the `\u0040` encoding hides the `@` from the email regex.

## Root Cause

The regex engine matches against the raw input bytes. When a JSON logger writes `\u0040` instead of `@`, the 6-character literal string `\u0040` doesn't match the `@` in the email regex pattern.

## Proposed Fix

Add a **pre-processing normalization step** in text mode that decodes common unicode escapes before running detection:

1. Before pattern matching, create a normalized copy of the input by replacing `\uXXXX` sequences with their UTF-8 equivalents
2. Run detection on the normalized copy to find PII positions
3. Map detected positions back to the original string for replacement

### Key escapes to handle

| Escape | Character | Relevance |
|--------|-----------|-----------|
| `\u0040` | `@` | Email addresses |
| `\u002E` | `.` | Domain names, IPs |
| `\u002B` | `+` | Phone numbers |
| `\u002D` | `-` | IBANs, phone numbers |

### Alternative (simpler)

Run detection twice — once on raw input, once on a `\uXXXX`-decoded copy — and merge results. This avoids the position-mapping complexity.

## Scope

This should only apply to **text mode**. In JSON mode, `serde_json` already decodes unicode escapes when parsing, so JSON values like `{"email": "client\u0040company.com"}` are already handled by the JSON processing path.

The gap is specifically when JSON-like content appears inside a **text-mode** log line.

## Test Cases

```text
# Should detect email
"client\u0040company.com"
"user\u0040domain\u002Ecom"

# Should NOT double-mask already-detected values
"contact jane@example.com" (no unicode escapes, already works)
```
