# Ticket #31: ONNX Runtime Optimizations (Threading + CoreML)

**Priority:** High
**Complexity:** Medium
**Status:** ~~TODO~~ DONE (FIXED)
**File:** `src/ner/ml.rs`

## Description

The ML NER backend loads a 135MB DistilBERT model with default ONNX Runtime settings. Two low-hanging optimizations can significantly reduce both startup time and per-line inference cost without changing the inference logic.

## Current Code

```rust
// src/ner/ml.rs:94-96
let session = ort::session::Session::builder()?
    .with_optimization_level(ort::session::builder::GraphOptimizationLevel::Level3)?
    .commit_from_file(&model_path)?;
```

No thread config. No execution providers. Single-threaded inference on CPU.

## Current Performance

| Metric | Value |
|--------|-------|
| Model load | ~270ms |
| Per-line inference | ~2.7ms |
| Memory | ~375MB RSS |
| Threads used | 1 (default) |

## Proposed Changes

### 1. Intra-op parallelism (quick win)

ONNX Runtime defaults to 1 intra-op thread. Setting this to the number of CPU cores enables SIMD parallelism on matrix multiplications within each inference call.

```rust
let num_cores = std::thread::available_parallelism()
    .map(|n| n.get())
    .unwrap_or(1);

let session = ort::session::Session::builder()?
    .with_optimization_level(ort::session::builder::GraphOptimizationLevel::Level3)?
    .with_intra_threads(num_cores)?
    .commit_from_file(&model_path)?;
```

**Expected impact:** 2-4x speedup on per-line inference (Apple M-series has 8-10 cores). Minimal code change.

### 2. CoreML execution provider (macOS)

On Apple Silicon, the CoreML EP offloads transformer inference to the Neural Engine, which is purpose-built for this workload.

```rust
#[cfg(target_os = "macos")]
{
    use ort::execution_providers::CoreMLExecutionProvider;
    session_builder = session_builder
        .with_execution_providers([
            CoreMLExecutionProvider::default()
                .with_subgraphs()
                .build(),
        ])?;
}
```

**Expected impact:**
- Per-line inference: 5-10x faster (Neural Engine vs CPU)
- Model load: may increase slightly (CoreML compilation on first run, cached after)
- Only benefits macOS; Linux/Windows fall back to CPU automatically

**Requirements:**
- `ort` crate feature: `coreml`
- macOS 12+ (Monterey)
- Apple Silicon or Intel with ANE

### 3. Pre-optimized model caching (optional)

ONNX Runtime's Level3 optimization re-optimizes the graph on every load. Saving the optimized model to disk avoids this on subsequent runs.

```rust
let optimized_path = model_path.with_extension("optimized.onnx");
let session = if optimized_path.exists() {
    Session::builder()?
        .commit_from_file(&optimized_path)?
} else {
    Session::builder()?
        .with_optimization_level(GraphOptimizationLevel::Level3)?
        .with_optimized_model_filepath(&optimized_path)?
        .commit_from_file(&model_path)?
};
```

**Expected impact:** ~50-100ms saved on model load after first run.

## Implementation Plan

1. Add `with_intra_threads(num_cores)` to session builder (1 line change)
2. Add `coreml` feature to `ort` dependency in `Cargo.toml`
3. Conditionally register CoreML EP on macOS
4. Re-run `bench_compare.py` to measure impact
5. (Optional) Add optimized model caching

## Expected Combined Impact

| Optimization | Startup | Per-line | Effort |
|-------------|---------|----------|--------|
| Intra-op threads | same | ~0.7-1.3ms (2-4x) | 1 line |
| CoreML EP | +100ms first run | ~0.3-0.5ms (5-10x) | ~10 lines |
| Model caching | -50-100ms | same | ~15 lines |
| **Combined** | **~same** | **~0.3-0.5ms** | **low** |

These stack with batching (ticket #30). With both:
- Batched + threaded + CoreML: estimated ~10-30us/line
- 100k lines: ~1-3s (vs current ~270s)

## Fix Applied

- Added `with_intra_threads(num_cores)` using `std::thread::available_parallelism()` for intra-op SIMD parallelism
- Added regression tests for threading config and detector loading with new settings
- Verified no impact on `ner-lite` or regex-only builds (all 151+ tests pass)

### CoreML Investigation

Built ONNX Runtime v1.23.2 from source with `--use_coreml`. CoreML EP registered
successfully but benchmarked **~1.4x slower** than CPU-only with threading:

| Config | Simple avg | Complex avg |
|--------|-----------|-------------|
| CPU + threading | 14ms | 32ms |
| CoreML + threading | 20ms | 48ms |

Root cause: CPU↔Neural Engine transfer overhead dominates for single-line inference
with a small int8 DistilBERT model. CoreML EP is better suited for large batch sizes
or larger models. Reverted CoreML code — may revisit after batching (ticket #30).

## Acceptance Criteria

- [x] `with_intra_threads` set to available parallelism
- [x] ~~CoreML EP registered on macOS builds~~ Investigated, slower for this workload — deferred
- [x] Fallback to CPU-only when CoreML unavailable (N/A, CoreML removed)
- [x] Benchmark shows measurable improvement (threading only)
- [x] No impact on `ner-lite` or regex-only builds
