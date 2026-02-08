# Ticket #10: Add Aircraft Context Keywords to All Patterns

**Priority:** Medium
**Complexity:** Low
**Status:** DONE
**File:** `src/main.rs`

## Description

In Python, the `AircraftRegistrationRecognizer` is a single Presidio recognizer with context keywords applied to **all** its patterns (French, European, US). In Rust, only the US aircraft pattern (`aircraft_us`) has context keywords — French and European patterns match unconditionally.

## Current State (Rust)

| Pattern | Context Keywords |
|---------|-----------------|
| `aircraft_fr` (F-XXXX) | None |
| `aircraft_eu` (D-XXXX, etc.) | None |
| `aircraft_us` (N12345) | `aircraft`, `avion`, `registration`, `immat`, `appareil`, `tail` |

## Python Behavior

All aircraft patterns share keywords: `aircraft`, `avion`, `registration`, `immat`, `appareil`, `tail`, `immatriculation`

Note the extra keyword `immatriculation` in Python vs Rust.

## Decision Required

French registrations (`F-XXXX`) are very distinctive and unlikely to false-positive. European registrations are also fairly distinctive. Making them context-required would reduce recall.

**Options:**

### Option A: Use score boosting (depends on Ticket #09)

Apply context keywords with `ContextMode::Boost` so all aircraft patterns benefit from context without losing non-context matches.

### Option B: Add context as required to EU only

Keep French as unconditional (very distinctive), add context to European (somewhat distinctive), keep US as context-required (high false positive risk).

### Option C: Add `immatriculation` keyword to US pattern only

Minimal change: just add the missing keyword to the US pattern.

**Recommendation:** Option C as a quick win, Option A when Ticket #09 is implemented.

## Quick Win Implementation (Option C)

```rust
PiiPattern {
    name: "aircraft_us",
    regex: r"\bN[1-9][0-9]{0,4}[A-Z]{0,2}\b",
    entity_type: "AIRCRAFT",
    score: 0.85,
    context_keywords: &["aircraft", "avion", "registration", "immat", "appareil", "tail", "immatriculation"],
},
```

## Acceptance Criteria

- [x] `immatriculation` keyword added to US aircraft pattern
- [x] Decision made on whether French/EU patterns need context (kept unconditional — too distinctive to gate)
- [x] Tests updated if behavior changes
