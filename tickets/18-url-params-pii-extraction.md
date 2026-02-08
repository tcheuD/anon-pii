# Ticket #18: Extract PII from URL Query Parameters Before URL Masking

**Priority:** Low
**Complexity:** High
**Status:** DONE
**File:** `src/detection.rs`

## Description

When the URL pattern matches an entire URL, any PII embedded in query parameters is swallowed by the `[URL_...]` token. The PII inside the URL is effectively hidden rather than individually tracked.

## Observed Behavior (Stress Test)

```text
Input:  Referer: https://external-site.com/search?p=passport%20number%2012AB34567
Output: Referer: [URL_eaa81cf7]
```

The URL was correctly detected and masked. However, the passport number `12AB34567` inside the `p=` query parameter was lost — it's now invisible in both the anonymized output and the detection table.

## The Dilemma

This is a **design trade-off**, not a bug:

| Approach | Pros | Cons |
|----------|------|------|
| Mask entire URL (current) | Simple, safe — no PII leaks | Loses granularity, can't see what PII was in the URL |
| Extract PII from params first | Each PII item tracked individually | Complex: need to parse URL, decode params, detect PII, reconstruct |
| Both: mask URL but also log inner detections | Full visibility | Anonymized output still has `[URL_...]` so inner PII isn't separately restorable |

## Proposed Approach

**Two-pass detection for URLs:**

1. When a URL is detected, parse its query string
2. URL-decode each parameter value
3. Run PII detection on decoded values
4. Report inner PII as separate detections (for the detection table / audit trail)
5. Still mask the entire URL as `[URL_...]` in the output

This way:
- The anonymized output is safe (full URL masked)
- The detection report shows what specific PII was inside the URL
- The mapping contains both the URL token and the inner PII tokens (for audit)

## Complexity Note

This interacts with ticket #16 (URL-encoded PII). If #16 is implemented first with a general normalization pipeline, this ticket becomes simpler — just need to run the pipeline on extracted query parameter values.

## Test Cases

```text
# Should mask URL AND report inner PII in detections
"https://site.com/search?email=user%40example.com"
→ Output: "[URL_abc123]"
→ Detections: [{entity: URL, ...}, {entity: EMAIL_ADDRESS, original: "user@example.com", ...}]

# Should still work for URLs without PII
"https://example.com/page?id=123"
→ Output: "[URL_abc123]"
→ Detections: [{entity: URL, ...}]
```
