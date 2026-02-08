# Ticket #33: Fine-Tune DistilCamemBERT for Domain-Specific NER

**Priority:** Medium
**Complexity:** High
**Status:** TODO
**Files:** new `training/` directory, `src/ner/ml.rs`, `src/ner/mod.rs`, `src/ner/download.rs`

## Description

The current ML NER backend uses a generic `distilbert-base-multilingual-cased-ner-hrl` model trained on CoNLL/WikiNER. It performs poorly on French aviation email text: misses accented names, doesn't understand ALL-CAPS lastname convention, produces false positives on company names.

Fine-tune `cmarkea/distilcamembert-base-ner` on labeled email/log data from Amelia operations. This model is already French-NER-aware (PER F1: 96.82% on WikiNER) and only needs domain adaptation.

## Why DistilCamemBERT over CamemBERT-base

| Model | Params | PER F1 (WikiNER) | ONNX INT8 size | Inference (512 tok) |
|-------|--------|-------------------|----------------|---------------------|
| distilbert-multilingual (current) | 135M | ~80% on French | ~65 MB | ~15 ms |
| **cmarkea/distilcamembert-base-ner** | **68M** | **96.82%** | **~55-65 MB** | **~10 ms** |
| Jean-Baptiste/camembert-ner | 110M | 94.83% | ~110 MB | ~20 ms |
| almanach/camembertav2-base-ftb-ner | 100M | 93.97% (FTB) | ONNX broken | N/A |

DistilCamemBERT is smaller, faster, and scores higher on PERSON. It uses SentencePiece tokenizer which handles accented characters natively (no "Ga" + "##el" splitting).

**HuggingFace repo:** https://huggingface.co/cmarkea/distilcamembert-base-ner
**Quantized ONNX available:** https://huggingface.co/cmarkea/distilcamembert-base-ner (via optimum)

## Training Data Strategy

### Phase 1: Bootstrap (1-2 days)

1. Collect 300-500 real email threads and debug logs from Amelia operations
2. Run current `anon --features ner-lite` on the corpus, export detections as pre-annotations
3. Store raw data in `training/data/raw/` (gitignored -- contains real PII)

### Phase 2: Annotate (3-5 days)

1. Import pre-annotations into Label Studio (open source, local)
2. Single annotator reviews each PERSON candidate: confirm, correct span, or reject
3. Label LOCATION and ORGANIZATION entities (free bonus from CamemBERT-NER)
4. Export as CoNLL BIO format

```
Bonjour O
M. O
Gael B-PER
FONTAINE I-PER
, O
votre O
vol O
depuis O
Paris B-LOC
CDG I-LOC
. O
```

5. Split: 80% train, 10% dev, 10% test
6. Store in `training/data/{train,dev,test}.conll`

### Phase 3: Augment

- Swap names using INSEE data (ticket #32) -- replace detected names with random alternatives preserving casing conventions
- Swap company names, locations
- Effective dataset multiplier: 5-10x

### Target: 300-500 hand-reviewed samples + augmentation = ~2000+ effective training examples

## Training

### Directory structure

```
training/
  finetune.py          # HuggingFace Trainer script
  export_onnx.py       # PyTorch -> ONNX + INT8 quantization
  evaluate.py          # Per-entity F1 on test set
  augment.py           # Name-swapping augmentation
  bootstrap.py         # Pre-annotate with current anon tool
  requirements.txt     # transformers, datasets, optimum, onnxruntime
  data/
    train.conll
    dev.conll
    test.conll
    README.md          # Annotation guidelines
```

### Hyperparameters

```python
learning_rate = 2e-5
batch_size = 16
epochs = 5-10          # early stopping on dev F1
warmup_ratio = 0.1
weight_decay = 0.01
max_seq_length = 512
```

Training time: ~10-20 minutes on a single GPU (or free Google Colab T4).

### Export

```python
from optimum.exporters.onnx import main_export
from onnxruntime.quantization import quantize_dynamic, QuantType

main_export("./fine-tuned/", "./onnx/", task="token-classification", opset=14)
quantize_dynamic("./onnx/model.onnx", "./onnx/model_int8.onnx", weight_type=QuantType.QInt8)
```

## Rust Integration Changes

### 1. Generalize NerDetector trait (`src/ner/mod.rs`)

```rust
pub trait NerDetector: Send + Sync {
    fn detect(&self, text: &str) -> Vec<NerSpan>;

    fn detect_persons(&self, text: &str) -> Vec<NerSpan> {
        self.detect(text).into_iter().filter(|s| s.label == "PERSON").collect()
    }
}
```

### 2. Generalize label mapping (`src/ner/ml.rs`)

Replace hardcoded B-PER/I-PER matching with configurable label map:

```rust
const LABEL_MAP: &[(&str, &str)] = &[
    ("PER", "PERSON"),
    ("LOC", "LOCATION"),
    ("ORG", "ORGANIZATION"),
];
```

### 3. SentencePiece tokenizer support

Current code uses WordPiece (`tokenizers` crate). DistilCamemBERT uses SentencePiece (Unigram). The `tokenizers` crate supports both via `tokenizer.json` -- verify that `from_file()` loads the CamemBERT tokenizer correctly.

### 4. Model versioning (`src/ner/download.rs`)

Add model manifest with SHA-256 hashes for integrity checking:

```rust
pub struct ModelManifest {
    pub name: &'static str,
    pub files: &'static [(&'static str, &'static str)], // (filename, sha256)
    pub min_score: f64,
}
```

Download destination: `~/.anon/models/distilcamembert-ner-aviation-v1/`

## Acceptance Criteria

- [ ] Training pipeline (`training/`) produces a fine-tuned ONNX INT8 model
- [ ] PER F1 > 90% on held-out test set of domain data
- [ ] Model loads and runs via existing `--features ner` path
- [ ] `anon download-model` fetches the fine-tuned model (fallback to generic if unavailable)
- [ ] Regression: existing email thread test passes with fine-tuned model
- [ ] Benchmark: throughput within 2x of current DistilBERT (before batching, ticket #30)
- [ ] No real PII in committed code or model weights

## Depends On

- Ticket #32 (INSEE names) -- augmentation uses the name list
- Ticket #30 (batched inference) -- recommended for production throughput

## Risks

| Risk | Mitigation |
|------|------------|
| 300 samples insufficient | Name-swapping augmentation (5-10x multiplier). Collect more if F1 < 85%. |
| SentencePiece tokenizer issues in Rust | Test early. The `tokenizers` crate handles `tokenizer.json` from HF. |
| Training data contains real PII | `training/data/` in `.gitignore`. Encrypted local storage. Model weights don't memorize individual names. |
| Model too large for CLI distribution | DistilCamemBERT INT8 is ~55-65 MB. Acceptable for download-on-first-use. |
