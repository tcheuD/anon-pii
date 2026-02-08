# Ticket #04: Add `--language` CLI Flag

**Priority:** Low
**Complexity:** Low
**Status:** DONE
**File:** `src/main.rs`

## Description

The Python implementation supports a `--language` / `-l` flag (default `"en"`) passed to Presidio's analyzer. While the Rust implementation doesn't use Presidio, adding this flag provides CLI parity and prepares for future NLP integration (see Ticket #11).

## Current State

No language flag exists in Rust CLI.

## Required Changes

### 1. Add CLI argument

```rust
/// Language for NLP detection (reserved for future use)
#[arg(short, long, default_value = "en")]
language: String,
```

### 2. Behavior

For now, the flag is accepted and stored but has no effect on pattern-based detection. It should:
- Be displayed in verbose output: `Language: en`
- Be stored for future NLP use
- Be validated to a reasonable set: `en`, `fr` (or accept any string like Python does)

### 3. Future integration point

When PERSON/NLP detection is added (Ticket #11), this flag will determine which language model to load.

## Acceptance Criteria

- [x] `--language` / `-l` flag added to CLI
- [x] Default value is `"en"`
- [x] Flag value displayed in verbose mode
- [x] No behavioral change to existing detection
- [x] Help text documents the flag's purpose
