# Ticket #16: Detect PII with URL-Encoded Characters

**Priority:** Medium
**Complexity:** Medium
**Status:** DONE
**File:** `src/detection.rs`

## Description

PII inside URL query parameters using percent-encoding passes through undetected. This is extremely common in HTTP access logs.

## Observed Miss (Stress Test)

```text
Input:  GET /api/v1/booking?ref=BK-123&q=john+doe&email=j.smith%40provider.net&loyalty_id=9928374
Output: (entire line passed through unmasked)
```

`j.smith%40provider.net` is an email address (`j.smith@provider.net`) but `%40` encoding hides the `@` from the email regex.

## Root Cause

Same category as #15 — the regex matches raw bytes and percent-encoded characters don't match their decoded equivalents.

## Proposed Fix

Add **URL percent-decoding normalization** as a pre-processing step, similar to ticket #15:

1. Detect URL-like segments in the input (query strings, `%XX` sequences)
2. Create a percent-decoded copy for detection
3. Map detected positions back to original string

### Key encodings to handle

| Encoding | Character | Relevance |
|----------|-----------|-----------|
| `%40` | `@` | Email addresses |
| `%2B` | `+` | Phone numbers |
| `%2E` | `.` | Domain names |
| `%20` | ` ` | Separators in names, IBANs |
| `%3A` | `:` | IPv6 addresses |

### Combined approach with #15

Tickets #15 and #16 can share a single normalization pipeline:
1. Decode `\uXXXX` sequences
2. Decode `%XX` sequences
3. Run detection on normalized text
4. Map results back

## Test Cases

```text
# Should detect email
"email=j.smith%40provider.net"
"contact%3Auser%40domain.com"

# Should detect phone
"tel=%2B33612345678"

# Should NOT decode inside already-detected URLs
# (if URL entity is detected first, inner params don't need separate handling)
```
