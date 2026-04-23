# Ticket #17: Add JWT / Bearer Token Detection

**Priority:** Medium
**Complexity:** Low
**Status:** DONE
**File:** `src/patterns.rs`

## Description

JWT (JSON Web Tokens) and bearer tokens in log lines are not detected. These are sensitive credentials that should be masked.

## Observed Miss (Stress Test)

```text
Input:  POST /payment/callback?token=<JWT_TWO_SEGMENT_FIXTURE>&cc_last4=4242
Output: (JWT passed through unmasked)
```

The JWT fixture is a base64-encoded authentication credential containing user identity (`"name": "John Doe"`) and should be masked.

## Proposed Pattern

### JWT Token

JWTs have a recognizable structure: three base64url segments separated by dots.

```regex
eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}
```

| Field | Value |
|-------|-------|
| Entity type | `AUTH_TOKEN` |
| Score | 0.95 |
| Context keywords | `"token", "bearer", "authorization", "auth", "jwt", "session", "cookie"` |
| `context_required` | `false` |

JWTs always start with `eyJ` (base64 for `{"`) which makes the pattern highly specific. No context should be required — the structure itself is distinctive enough.

### Alternative: Generic Bearer Token

For non-JWT bearer tokens (opaque strings), a broader pattern could be added with context required:

```regex
(?:Bearer|token[=:])\s*[A-Za-z0-9_-]{20,}
```

This is lower priority and higher false-positive risk, so it could be a separate follow-up.

## Test Cases

```text
# Should detect
"Authorization: Bearer <JWT_THREE_SEGMENT_FIXTURE>"
"token=<JWT_TWO_SEGMENT_FIXTURE>"

# Should NOT detect
"version=eyJub3QiOiJhIHRva2VuIn0" (only 2 segments, not a valid JWT)
"file.name.extension" (dots but not base64)
```
