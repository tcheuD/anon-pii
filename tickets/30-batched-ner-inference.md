# Ticket #30: Batched NER Inference

**Priority:** High
**Complexity:** High
**Status:** TODO
**File:** `src/ner/ml.rs`, `src/detection.rs`

## Description

The ML NER backend (`--features ner`) runs one DistilBERT forward pass per input line. Transformer models are optimized for batched inference — processing 32 lines in one pass is barely slower than 1. Current per-line inference makes the ML backend ~50x slower than regex-only.

## Benchmark Data (2026-02-01)

End-to-end CLI benchmark, 100 lines (80 simple / 20 complex):

| Variant | Total time | Throughput | vs Python |
|---------|-----------|------------|-----------|
| Python (Presidio) | 2.42 s | 41 lines/s | baseline |
| Rust (regex-only) | 0.019 s | 5,187 lines/s | 126x faster |
| Rust (ner-lite) | 0.018 s | 5,437 lines/s | 132x faster |
| **Rust (ner ML)** | **1.01 s** | **99 lines/s** | **2.4x faster** |

### Time breakdown (NER ML)

Measured with `/usr/bin/time`:

| Input | Wall time | Notes |
|-------|----------|-------|
| 1 line | 0.27 s | Pure startup (ONNX model load) |
| 100 lines | 0.46 s | +0.19s for 100 inferences (~1.9ms/line) |
| 1000 lines | 2.94 s | +2.67s for 1000 inferences (~2.7ms/line) |

**Model load: ~270ms** (135MB INT8 DistilBERT, graph optimization Level3).
**Per-line inference: ~2-3ms** (tokenize + single forward pass).
**Memory: ~375MB RSS** (vs ~5MB for regex-only).

## Current Behavior

```
Anonymizer::anonymize_text(line)
  -> ner.detect_persons(line)     # 1 forward pass per call
  -> ~2.7ms per line on Apple Silicon (INT8, no GPU)
  -> 100k lines ~ 270s + 0.27s startup
```

## Proposed Approach

### Option A: Batch at the Anonymizer level (recommended)

Add `anonymize_texts(lines: &[&str])` that:

1. Runs regex detection per-line (fast, no change)
2. Collects all lines into a batch
3. Calls `ner.detect_persons_batch(&lines)` -- single forward pass for N lines
4. Distributes NER spans back to individual line results

Requires a new `detect_persons_batch` method on the `NerDetector` trait.

### Option B: Sliding window batch

Keep the per-line API but buffer internally:

1. `detect_persons()` accumulates lines in an internal buffer
2. When buffer reaches batch size (e.g. 32), run one forward pass
3. Return cached results for subsequent calls
4. Flush remaining buffer on drop

Less invasive but adds state to what's currently a stateless detector.

### Option C: Async pipeline

Run NER inference in a background thread with a channel. The anonymizer sends lines, the NER thread batches them and returns results. Best throughput but most complex.

## Expected Impact

| Mode | Per-line (current) | Per-line (batched, est.) | Speedup |
|------|-------------------|-------------------------|---------|
| Batch=1 | ~2.7ms | ~2.7ms | 1x |
| Batch=32 | ~2.7ms | ~100-200us | 15-25x |
| Batch=64 | ~2.7ms | ~60-120us | 20-40x |

With batching, 100k lines would drop from ~270s to ~10-15s.

## Constraints

- `ner-lite` (heuristic) is already fast (~1us overhead) -- batching is irrelevant for it
- The `NerDetector` trait must remain compatible with both backends
- CLI pipe mode reads stdin line-by-line -- needs buffering strategy
- UI and proxy modes process single requests -- batching helps less there

## Depends on

- Ticket #31 (ONNX Runtime optimizations) -- threading and CoreML can stack with batching
