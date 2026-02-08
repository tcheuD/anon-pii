# Ticket #11: Add PERSON Entity Detection (NLP)

**Priority:** Low
**Complexity:** Very High
**Status:** DONE (implemented via `ner` and `ner-lite` feature flags)
**File:** `src/ner/mod.rs`, `src/ner/ml.rs`, `src/ner/heuristic.rs`, `src/detection.rs`, `src/main.rs`

## Description

Python has infrastructure for NLP-based PERSON entity detection using spaCy (`fr_core_news_sm` model). Rust now has two NER backends behind feature flags.

## Implementation

### Two NER backends via feature flags

```bash
# Heuristic: rule-based name detection (zero deps, ~1us overhead)
cargo build --features ner-lite

# ML: ONNX-based transformer model (requires ONNX Runtime, ~2.7ms/line)
cargo build --features ner
```

Both activated via `--ner` CLI flag at runtime.

### Backend details

**`ner-lite` (heuristic):** `src/ner/heuristic.rs`
- Rule-based: capitalized words near name-context keywords
- Zero external dependencies, negligible overhead
- Lower accuracy but no model download needed

**`ner` (ML):** `src/ner/ml.rs`
- Uses `Davlan/distilbert-base-multilingual-cased-ner-hrl` (INT8 quantized)
- 135MB ONNX model, downloaded via `anon download-model`
- Requires ONNX Runtime (`ORT_DYLIB_PATH`)
- Detects B-PER/I-PER BIO tags, supports sliding window for >512 token inputs
- Path validation for ORT_DYLIB_PATH (security hardening)

### Architecture

- `NerDetector` trait in `src/ner/mod.rs` with `detect_persons(&self, text: &str) -> Vec<NerSpan>`
- `Anonymizer::set_ner_detector()` wires NER into the detection pipeline
- NER spans merged with regex detections using existing overlap resolution

## Performance (2026-02-01)

| Backend | Per-line latency | Startup | Memory |
|---------|-----------------|---------|--------|
| ner-lite | ~1us | instant | negligible |
| ner (ML) | ~2.7ms | ~270ms (model load) | ~375MB RSS |

See ticket #30 for batch optimization plans and ticket #31 for ONNX Runtime tuning.

## Research completed

| Question | Answer |
|----------|--------|
| rust-bert vs candle vs ONNX? | ONNX Runtime chosen (mature, cross-platform, INT8 support) |
| French NER model? | `distilbert-base-multilingual-cased-ner-hrl` (multilingual, covers French) |
| Model loading time? | ~270ms on Apple Silicon |
| Binary size impact? | `ner` feature adds ~2MB to binary (ort + tokenizers crates) |
| Integration point? | `NerDetector` trait + `set_ner_detector()` on `Anonymizer` |

## Acceptance Criteria

- [x] Research completed on Rust NLP options
- [x] Feature flags `ner` and `ner-lite` added to Cargo.toml
- [x] PERSON entity detected when `--features ner` or `--features ner-lite` is enabled
- [x] `--ner` CLI flag activates NER at runtime
- [ ] `--language` flag (Ticket #04) selects the appropriate model (not yet wired)
- [x] Performance acceptable (< 2s for typical input with ner-lite; ML needs optimization -- see #30, #31)
- [x] Binary size without `ner`/`ner-lite` features unchanged
- [x] Model download via `anon download-model`
