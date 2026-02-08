# Ticket #34: Clean Up Feature Flag Architecture

**Priority:** Medium
**Complexity:** Medium
**Status:** ~~TODO~~ DONE (FIXED)
**Files:** `src/lib.rs`, `src/detection.rs`, `src/ner/mod.rs`

## Description

The NER-related code has `#[cfg(feature)]` annotations scattered through `detection.rs` (6 occurrences), creating invisible code paths within the main `anonymize_text()` method. This makes the code harder to read, test, and extend. Adding a new NER backend (e.g., a fine-tuned model) requires editing the same growing method and adding more conditional compilation branches.

Refactor so that feature flags only control which *implementations* are available, not the core detection pipeline logic.

## Current State

### `detection.rs` has 6 `#[cfg]` annotations:

1. **Line ~10:** Conditional import of `PERSON_BLOCKLIST`
2. **Line ~136:** Conditional import of `NerDetector`
3. **Lines ~207-208:** Conditional `ner_detector` field on `Anonymizer`
4. **Lines ~254-257:** Conditional `set_ner_detector()` method
5. **Lines ~466-488:** NER injection block inside `anonymize_text()`
6. **Lines ~493-535:** Name consistency pass inside `anonymize_text()`

### `lib.rs` conditionally compiles the entire NER module:

```rust
#[cfg(any(feature = "ner", feature = "ner-lite"))]
pub mod ner;
```

### Problem

- Cannot test NER pipeline logic (blocklist filtering, span extension, consistency pass) without compiling `ner-lite` or `ner`
- Every NER-related change touches the same method and requires reasoning about 3 code paths
- Adding a mock NER detector for tests requires feature flags

## Proposed Changes

### 1. Always compile the NER trait and core types

Move `NerDetector` trait, `NerSpan`, `CombinedNerDetector`, and `NerConfig` out of the feature-gated module. They have zero dependencies and are just trait definitions.

```rust
// src/lib.rs
pub mod ner;  // always compiled (trait + types only)

// src/ner/mod.rs
#[cfg(feature = "ner")]
pub mod ml;
#[cfg(feature = "ner")]
pub mod download;
#[cfg(feature = "ner-lite")]
pub mod heuristic;

// These are always available:
pub struct NerSpan { ... }
pub trait NerDetector: Send + Sync { ... }
pub struct CombinedNerDetector { ... }
```

### 2. Remove `#[cfg]` from `detection.rs` entirely

The `Anonymizer` always has:

```rust
pub struct Anonymizer {
    // ...
    ner_detector: Option<Box<dyn NerDetector>>,  // always present, None by default
}
```

The NER injection block, blocklist filtering, span extension, and consistency pass all run unconditionally. When `ner_detector` is `None`, the code does nothing:

```rust
// No #[cfg] needed
if let Some(ref ner) = self.ner_detector {
    let ner_spans = ner.detect_persons(&normalized);
    // ... blocklist, span extension, consistency pass
}
```

### 3. Move `PERSON_BLOCKLIST` to `ner/mod.rs`

Since the blocklist is only used in the NER injection path, it belongs with the NER module, not in `patterns.rs`.

### 4. Add `MockNerDetector` for tests

```rust
// src/ner/mod.rs (always compiled)
#[cfg(test)]
pub struct MockNerDetector {
    pub spans: Vec<NerSpan>,
}

#[cfg(test)]
impl NerDetector for MockNerDetector {
    fn detect_persons(&self, _text: &str) -> Vec<NerSpan> {
        self.spans.clone()
    }
}
```

This enables testing:
- Blocklist filtering without any NER implementation
- Span extension logic with controlled inputs
- Name consistency pass in isolation
- Overlap resolution between regex and NER detections

### 5. Feature flags only at the edges

After refactoring, `#[cfg(feature)]` appears only in:

| Location | Purpose |
|----------|---------|
| `src/ner/mod.rs` | Gate `mod heuristic` and `mod ml` declarations |
| `src/main.rs` | Choose which NER detector to instantiate at startup |
| `Cargo.toml` | Dependency declarations (`ort`, `tokenizers`) |

Zero `#[cfg]` in `detection.rs`, `patterns.rs`, or `mapping.rs`.

## Migration

This is a refactor with no behavior change. Every step should pass `cargo test` across all 3 configs.

### Step 1: Move `NerSpan`, `NerDetector`, `CombinedNerDetector` to always-compiled module

```diff
// src/lib.rs
-#[cfg(any(feature = "ner", feature = "ner-lite"))]
 pub mod ner;
```

Verify: `cargo test` (no features) compiles `ner/mod.rs` without pulling in ONNX deps.

### Step 2: Make `ner_detector` field unconditional

Remove `#[cfg]` from the field and `set_ner_detector()`. When no features are enabled, no one calls `set_ner_detector()`, so `ner_detector` stays `None`.

### Step 3: Remove `#[cfg]` from the NER block in `anonymize_text()`

Replace:
```rust
#[cfg(any(feature = "ner", feature = "ner-lite"))]
{
    if let Some(ref ner) = self.ner_detector { ... }
}
```

With:
```rust
if let Some(ref ner) = self.ner_detector { ... }
```

### Step 4: Add `MockNerDetector` and port NER-dependent tests

Convert tests like `test_ner_lite_person_detected` from:
```rust
#[cfg(feature = "ner-lite")]
#[test]
fn test_ner_lite_person_detected() {
    use crate::ner::heuristic::HeuristicNerDetector;
    let mut a = Anonymizer::new(0.0);
    a.set_ner_detector(Box::new(HeuristicNerDetector::new()));
```

To two tests:
```rust
// Always runs -- tests pipeline logic
#[test]
fn test_ner_pipeline_person_blocklist() {
    let mock = MockNerDetector { spans: vec![
        NerSpan { text: "Amelia".into(), start: 0, end: 6, score: 0.9, label: "PERSON".into() },
    ]};
    let mut a = Anonymizer::new(0.0);
    a.set_ner_detector(Box::new(mock));
    let (result, _) = a.anonymize_text("Amelia said hello");
    assert!(result.contains("Amelia"), "Blocklisted name should not be anonymized");
}

// Only runs with ner-lite -- tests the actual heuristic detector
#[cfg(feature = "ner-lite")]
#[test]
fn test_heuristic_detects_french_names() { ... }
```

### Step 5: Verify all 3 configs

```bash
cargo test                    # NER module compiles, pipeline tests run, mock tests run
cargo test --features ner-lite # + heuristic implementation tests
cargo test --features ner      # + ML implementation tests
```

## Acceptance Criteria

- [ ] Zero `#[cfg(feature)]` annotations in `detection.rs`
- [ ] `NerDetector` trait and `NerSpan` compile without any feature flag
- [ ] `MockNerDetector` available in test builds
- [ ] Pipeline tests (blocklist, span extension, consistency pass) run in default `cargo test`
- [ ] All 3 configs pass: `cargo test`, `cargo test --features ner-lite`, `cargo test --features ner`
- [ ] No behavior change -- purely structural refactor

## Fix Applied

Removed all 6 `#[cfg(feature)]` annotations from `detection.rs`. The `ner` module is now always compiled (`lib.rs`), with feature flags only gating the concrete implementations (`heuristic`, `ml`, `download`) in `ner/mod.rs` and detector instantiation in `main.rs`/`proxy/mod.rs`/`ui/mod.rs`. Moved `PERSON_BLOCKLIST` from `patterns.rs` to `ner/mod.rs`. Added `MockNerDetector` (test-only) and 5 pipeline tests that run in default `cargo test` without any feature flags. `NerSpan` gained `Clone` derive to support the mock.

## Depends On

Nothing. Can be done independently. Recommended before ticket #33 (fine-tuned model integration).
