# Ticket #07: Align Default Threshold to 0.5

**Priority:** Medium
**Complexity:** Low
**Status:** DONE
**File:** `src/main.rs`

## Description

Python defaults `--threshold` to `0.5`. Rust defaults to `0.0`. This means Rust is more aggressive by default, catching lower-confidence matches that Python would skip.

## Impact Analysis

Patterns affected by a 0.5 threshold (would be filtered out):

| Pattern | Score | Filtered at 0.5? |
|---------|-------|-------------------|
| `flight_iata` | 0.4 | **Yes** |
| `flight_icao` | 0.5 | **No** (>=) |
| `fr_phone_compact` | 0.6 | No |
| `fr_passport` | 0.7 | No |
| `fr_phone_national` | 0.7 | No |
| `aircraft_us` | 0.7 | No |
| `credit_card` | 0.7 | No |
| All others | ≥0.85 | No |

Only `flight_iata` (0.4) would be affected. This is a context-aware pattern that already has strong gating, so losing it at default threshold is debatable.

## Proposed Change

```rust
/// Minimum confidence score (0.0-1.0)
#[arg(long, default_value = "0.5")]
threshold: f64,
```

## Consideration

If this change is too aggressive, consider:
- Setting default to `0.3` as a compromise
- Only changing if entity naming is also aligned (Ticket #05) to do a single breaking change

## Acceptance Criteria

- [x] Default threshold changed to 0.5
- [x] `test_threshold` updated to reflect new default behavior
- [x] Documented as a behavior change
