# Ticket #30: Batched NER Inference

**Priority:** Medium
**Complexity:** High
**Status:** TODO
**File:** `src/ner/ml.rs`, `src/detection.rs`

## Description

The ML NER backend (`--features ner`) runs one DistilBERT forward pass per input line. Transformer models are optimized for batched inference — processing 32 lines in one pass is barely slower than 1. Current per-line inference is ~1ms on CPU, making large inputs (10k+ lines) impractical.

## Current Behavior

```
Anonymizer::anonymize_text(line)
  → ner.detect_persons(line)     # 1 forward pass per call
  → ~1ms per line on Apple Silicon (INT8, no GPU)
  → 100k lines ≈ 100s
```

## Proposed Approach

### Option A: Batch at the Anonymizer level

Add `anonymize_texts(lines: &[&str])` that:

1. Runs regex detection per-line (fast, no change)
2. Collects all lines into a batch
3. Calls `ner.detect_persons_batch(&lines)` — single forward pass for N lines
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
| Batch=1 | ~1ms | ~1ms | 1x |
| Batch=32 | ~1ms | ~50-100μs | 10-20x |
| Batch=64 | ~1ms | ~30-60μs | 15-30x |

## Constraints

- `ner-lite` (heuristic) is already fast (~1μs overhead) — batching is irrelevant for it
- The `NerDetector` trait must remain compatible with both backends
- CLI pipe mode reads stdin line-by-line — needs buffering strategy
- UI and proxy modes process single requests — batching helps less there
