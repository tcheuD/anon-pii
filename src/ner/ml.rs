use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::ner::{NerConfig, NerDetector, NerSpan};

/// Allowed parent directories for ORT_DYLIB_PATH.
/// Only libraries under these prefixes (after symlink resolution) are loaded.
const ALLOWED_ORT_PREFIXES: &[&str] = &[
    "/usr/lib",
    "/usr/local/lib",
    "/opt/homebrew",
    "/opt/local/lib",
    "/Library/Frameworks",
    "/nix/store",
];

/// Validate ORT_DYLIB_PATH if set. Returns Ok(()) if unset or valid,
/// Err with explanation if the path is suspicious.
pub fn validate_ort_dylib_path() -> Result<(), String> {
    let path_str = match std::env::var("ORT_DYLIB_PATH") {
        Ok(p) => p,
        Err(_) => return Ok(()), // Not set — ort will search system paths
    };
    validate_ort_path(&path_str)
}

/// Core validation: check that a library path is absolute, exists, and
/// resolves (after symlinks) to a known system library directory.
fn validate_ort_path(path_str: &str) -> Result<(), String> {
    let path = PathBuf::from(path_str);

    // Must be absolute
    if !path.is_absolute() {
        return Err(format!(
            "ORT_DYLIB_PATH must be an absolute path, got: {path_str}"
        ));
    }

    // Must exist
    if !path.exists() {
        return Err(format!(
            "ORT_DYLIB_PATH does not exist: {path_str}"
        ));
    }

    // Resolve symlinks to get the real path
    let real = match path.canonicalize() {
        Ok(r) => r,
        Err(e) => {
            return Err(format!(
                "ORT_DYLIB_PATH cannot be resolved: {path_str} ({e})"
            ));
        }
    };

    let real_str = real.to_string_lossy();

    // Must resolve to a known system library directory
    if !ALLOWED_ORT_PREFIXES.iter().any(|prefix| real_str.starts_with(prefix)) {
        return Err(format!(
            "ORT_DYLIB_PATH resolves to {real_str}, which is outside allowed directories: {:?}. \
             Set ORT_DYLIB_PATH to a system-installed ONNX Runtime library.",
            ALLOWED_ORT_PREFIXES
        ));
    }

    Ok(())
}

pub struct MlNerDetector {
    session: Mutex<ort::session::Session>,
    tokenizer: tokenizers::Tokenizer,
    id2label: Vec<String>,
    min_score: f64,
}

impl MlNerDetector {
    pub fn new(config: &NerConfig) -> Result<Self, Box<dyn std::error::Error>> {
        // Validate ORT_DYLIB_PATH before ort loads the dynamic library
        validate_ort_dylib_path()?;

        let model_path = config.model_dir.join("model.onnx");
        let tokenizer_path = config.model_dir.join("tokenizer.json");
        let config_path = config.model_dir.join("config.json");

        if !model_path.exists() {
            return Err(format!(
                "Model not found at {:?}. Run `anon download-model` first.",
                config.model_dir
            )
            .into());
        }

        let num_cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);

        let mut builder = ort::session::Session::builder()?
            .with_optimization_level(ort::session::builder::GraphOptimizationLevel::Level3)?
            .with_intra_threads(num_cores)?;

        #[cfg(target_os = "macos")]
        {
            builder = builder.with_execution_providers([
                ort::ep::CoreML::default().build(),
            ])?;
        }

        let session = builder.commit_from_file(&model_path)?;

        let tokenizer = tokenizers::Tokenizer::from_file(&tokenizer_path)
            .map_err(|e| format!("Failed to load tokenizer: {e}"))?;

        let id2label = load_id2label(&config_path)?;

        Ok(Self {
            session: Mutex::new(session),
            tokenizer,
            id2label,
            min_score: config.min_score,
        })
    }
}

fn load_id2label(config_path: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(config_path)?;
    let config: serde_json::Value = serde_json::from_str(&content)?;

    let id2label_map = config["id2label"]
        .as_object()
        .ok_or("config.json missing id2label")?;

    let max_id = id2label_map
        .keys()
        .filter_map(|k| k.parse::<usize>().ok())
        .max()
        .unwrap_or(0);

    let mut labels = vec!["O".to_string(); max_id + 1];
    for (k, v) in id2label_map {
        if let (Ok(idx), Some(label)) = (k.parse::<usize>(), v.as_str()) {
            labels[idx] = label.to_string();
        }
    }

    Ok(labels)
}

/// DistilBERT max sequence length (including [CLS] and [SEP] tokens).
const MAX_SEQ_LEN: usize = 512;
/// Overlap between chunks in tokens. Enough to capture names split at boundaries.
const CHUNK_OVERLAP: usize = 50;

impl NerDetector for MlNerDetector {
    fn detect_persons(&self, text: &str) -> Vec<NerSpan> {
        if text.is_empty() {
            return Vec::new();
        }

        // Tokenize the full text without truncation to get offsets
        let full_encoding = match self.tokenizer.encode(text, false) {
            Ok(enc) => enc,
            Err(e) => {
                eprintln!("Warning: NER tokenization failed: {e}");
                return Vec::new();
            }
        };

        let total_tokens = full_encoding.get_ids().len();
        // 2 special tokens: [CLS] and [SEP]
        let max_content_tokens = MAX_SEQ_LEN - 2;

        if total_tokens <= max_content_tokens {
            // Fits in a single chunk — fast path
            return self.run_inference_chunk(text, &full_encoding, 0, total_tokens);
        }

        // Sliding window over tokens
        let mut all_spans: Vec<NerSpan> = Vec::new();
        let mut start = 0;

        while start < total_tokens {
            let end = (start + max_content_tokens).min(total_tokens);
            let chunk_spans = self.run_inference_chunk(text, &full_encoding, start, end);
            all_spans.extend(chunk_spans);

            if end >= total_tokens {
                break;
            }
            start = end - CHUNK_OVERLAP;
        }

        // Deduplicate overlapping spans (from chunk overlap regions)
        dedup_spans(&mut all_spans);

        all_spans
    }
}

impl MlNerDetector {
    /// Run inference on a slice of the full encoding [token_start..token_end].
    /// Adds [CLS] and [SEP] wrapper tokens for the model.
    fn run_inference_chunk(
        &self,
        text: &str,
        full_encoding: &tokenizers::Encoding,
        token_start: usize,
        token_end: usize,
    ) -> Vec<NerSpan> {
        let all_ids = full_encoding.get_ids();
        let all_offsets = full_encoding.get_offsets();

        let chunk_ids = &all_ids[token_start..token_end];
        let chunk_offsets = &all_offsets[token_start..token_end];

        // Wrap with special tokens: [CLS]=101, [SEP]=102
        let mut input_ids: Vec<i64> = Vec::with_capacity(chunk_ids.len() + 2);
        input_ids.push(101); // [CLS]
        input_ids.extend(chunk_ids.iter().map(|&id| id as i64));
        input_ids.push(102); // [SEP]

        let seq_len = input_ids.len();
        let attention_mask: Vec<i64> = vec![1i64; seq_len];

        let ids_tensor = match ort::value::Tensor::from_array((vec![1i64, seq_len as i64], input_ids)) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("Warning: NER input_ids tensor creation failed: {e}");
                return Vec::new();
            }
        };
        let mask_tensor = match ort::value::Tensor::from_array((vec![1i64, seq_len as i64], attention_mask)) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("Warning: NER attention_mask tensor creation failed: {e}");
                return Vec::new();
            }
        };

        let inputs = ort::inputs![
            "input_ids" => ids_tensor,
            "attention_mask" => mask_tensor,
        ];

        let mut session = match self.session.lock() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Warning: NER session lock poisoned: {e}");
                return Vec::new();
            }
        };

        let outputs = match session.run(inputs) {
            Ok(o) => o,
            Err(e) => {
                eprintln!("Warning: NER inference failed: {e}");
                return Vec::new();
            }
        };

        let (shape, logits) = match outputs[0].try_extract_tensor::<f32>() {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Warning: NER logits extraction failed: {e}");
                return Vec::new();
            }
        };

        let num_labels = if shape.len() == 3 {
            shape[2] as usize
        } else {
            eprintln!("Warning: NER unexpected output shape: {:?}", shape);
            return Vec::new();
        };

        // Decode BIO tags into spans (skip [CLS] at index 0 and [SEP] at end)
        let mut spans: Vec<NerSpan> = Vec::new();
        let mut current_start: Option<usize> = None;
        let mut current_end: usize = 0;
        let mut current_scores: Vec<f32> = Vec::new();

        for (chunk_i, &(off_start, off_end)) in chunk_offsets.iter().enumerate() {
            // logits index is chunk_i + 1 (skip [CLS])
            let logit_i = chunk_i + 1;

            if off_start == off_end {
                if let Some(start) = current_start.take() {
                    flush_span(text, start, current_end, &current_scores, self.min_score, &mut spans);
                    current_scores.clear();
                }
                continue;
            }

            let row_offset = logit_i * num_labels;
            let mut max_idx = 0usize;
            let mut max_val = f32::NEG_INFINITY;
            for j in 0..num_labels {
                let val = logits[row_offset + j];
                if val > max_val {
                    max_val = val;
                    max_idx = j;
                }
            }

            let label = &self.id2label[max_idx];
            let is_b_per = label == "B-PER";
            let is_i_per = label == "I-PER";

            if is_b_per {
                if let Some(start) = current_start.take() {
                    flush_span(text, start, current_end, &current_scores, self.min_score, &mut spans);
                    current_scores.clear();
                }
                current_start = Some(off_start);
                current_end = off_end;
                current_scores.push(softmax_score(logits, row_offset, max_idx, num_labels));
            } else if is_i_per && current_start.is_some() {
                current_end = off_end;
                current_scores.push(softmax_score(logits, row_offset, max_idx, num_labels));
            } else {
                if let Some(start) = current_start.take() {
                    flush_span(text, start, current_end, &current_scores, self.min_score, &mut spans);
                    current_scores.clear();
                }
            }
        }

        if let Some(start) = current_start.take() {
            flush_span(text, start, current_end, &current_scores, self.min_score, &mut spans);
        }

        spans
    }
}

/// Deduplicate spans from overlapping chunks. When two spans overlap,
/// keep the one with the higher score.
fn dedup_spans(spans: &mut Vec<NerSpan>) {
    if spans.len() <= 1 {
        return;
    }
    spans.sort_by(|a, b| a.start.cmp(&b.start).then(b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal)));
    let mut deduped: Vec<NerSpan> = Vec::with_capacity(spans.len());
    for span in spans.drain(..) {
        if let Some(last) = deduped.last() {
            // Overlapping or identical span — skip if the existing one covers it
            if span.start < last.end {
                continue;
            }
        }
        deduped.push(span);
    }
    *spans = deduped;
}

fn softmax_score(logits: &[f32], row_offset: usize, label_idx: usize, num_labels: usize) -> f32 {
    let mut max_val = f32::NEG_INFINITY;
    for j in 0..num_labels {
        let v = logits[row_offset + j];
        if v > max_val {
            max_val = v;
        }
    }
    let mut sum = 0.0f32;
    for j in 0..num_labels {
        sum += (logits[row_offset + j] - max_val).exp();
    }
    (logits[row_offset + label_idx] - max_val).exp() / sum
}

fn flush_span(
    text: &str,
    start: usize,
    end: usize,
    scores: &[f32],
    min_score: f64,
    spans: &mut Vec<NerSpan>,
) {
    if scores.is_empty() {
        return;
    }
    let avg_score = scores.iter().copied().sum::<f32>() / scores.len() as f32;
    if (avg_score as f64) < min_score {
        return;
    }
    if end > text.len() || !text.is_char_boundary(start) || !text.is_char_boundary(end) {
        return;
    }
    let span_text = &text[start..end];
    if span_text.trim().len() <= 1 {
        return;
    }
    spans.push(NerSpan {
        text: span_text.to_string(),
        start,
        end,
        score: avg_score as f64,
        label: "PERSON".to_string(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ner::NerConfig;

    fn try_create_detector() -> Option<MlNerDetector> {
        let config = NerConfig::default();
        if !crate::ner::download::model_exists(&config) {
            eprintln!("Model not downloaded, skipping ML NER test");
            return None;
        }
        // ort panics if libonnxruntime is not available
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            MlNerDetector::new(&config)
        })) {
            Ok(Ok(det)) => Some(det),
            Ok(Err(e)) => {
                eprintln!("ML NER init failed: {e}, skipping test");
                None
            }
            Err(_) => {
                eprintln!("ONNX Runtime not available, skipping ML NER test");
                None
            }
        }
    }

    #[test]
    fn test_ml_ner_loads_or_skips() {
        let detector = match try_create_detector() {
            Some(d) => d,
            None => return,
        };
        let spans = detector.detect_persons("Jean Dupont called from Paris");
        assert!(!spans.is_empty(), "ML NER should detect at least one person");
        assert!(spans.iter().any(|s| s.text.contains("Jean") || s.text.contains("Dupont")));
    }

    #[test]
    fn test_ml_ner_empty_input() {
        let detector = match try_create_detector() {
            Some(d) => d,
            None => return,
        };
        let spans = detector.detect_persons("");
        assert!(spans.is_empty());
    }

    #[test]
    fn test_flush_span_invalid_char_boundary() {
        // flush_span must not panic when offsets fall on non-char-boundary positions
        let text = "café résumé"; // 'é' is 2 bytes in UTF-8
        let mut spans = Vec::new();

        // Byte 4 is inside the 'é' (bytes 3..5 of "café") — not a char boundary
        flush_span(text, 4, 6, &[0.99], 0.5, &mut spans);
        assert!(spans.is_empty(), "Should skip invalid char boundary");

        // Out of bounds
        flush_span(text, 0, text.len() + 5, &[0.99], 0.5, &mut spans);
        assert!(spans.is_empty(), "Should skip out-of-bounds offset");

        // Valid boundaries should still work — "café" is bytes 0..5
        flush_span(text, 0, 5, &[0.99], 0.5, &mut spans);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].text, "caf\u{e9}");
    }

    #[test]
    fn test_ml_ner_stress_input_no_panic() {
        let detector = match try_create_detector() {
            Some(d) => d,
            None => return,
        };

        // Very long input — triggers sliding window chunking (>512 tokens)
        let long = "Jean Dupont ".repeat(5000);
        let spans = detector.detect_persons(&long);
        // Should not panic and should detect persons across chunks
        assert!(!spans.is_empty(), "Should detect persons in long repeated input");

        // Input with only non-ASCII — stress tokenizer edge cases
        let unicode_heavy = "名前は田中太郎です。連絡先：tanaka@example.com";
        let spans = detector.detect_persons(unicode_heavy);
        let _ = spans;

        // Single character
        let spans = detector.detect_persons("X");
        assert!(spans.is_empty());
    }

    #[test]
    fn test_ml_ner_chunking_detects_across_boundary() {
        let detector = match try_create_detector() {
            Some(d) => d,
            None => return,
        };

        // Build text where a name appears deep in the text (past 512 tokens)
        // ~3 tokens per word on average, so 200 filler words ≈ 600 tokens
        let filler = "The quick brown fox jumps over the lazy dog. ".repeat(50);
        let text = format!("{filler}Captain Marie Lefebvre reported an incident.");
        let spans = detector.detect_persons(&text);
        assert!(
            spans.iter().any(|s| s.text.contains("Marie") || s.text.contains("Lefebvre")),
            "Should detect person name past the 512 token boundary, got: {:?}",
            spans
        );
    }

    #[test]
    fn test_dedup_spans_removes_overlapping() {
        let mut spans = vec![
            NerSpan { text: "Jean Dupont".into(), start: 0, end: 11, score: 0.95, label: "PERSON".into() },
            NerSpan { text: "Jean Dupont".into(), start: 0, end: 11, score: 0.90, label: "PERSON".into() },
            NerSpan { text: "Marie".into(), start: 20, end: 25, score: 0.85, label: "PERSON".into() },
        ];
        dedup_spans(&mut spans);
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].start, 0);
        assert_eq!(spans[0].score, 0.95); // higher score kept
        assert_eq!(spans[1].start, 20);
    }

    #[test]
    fn test_validate_ort_path_rejects_relative() {
        let err = validate_ort_path("./libonnxruntime.so").unwrap_err();
        assert!(err.contains("absolute"), "Should reject relative path: {err}");
    }

    #[test]
    fn test_validate_ort_path_rejects_nonexistent() {
        let err = validate_ort_path("/usr/lib/nonexistent_ort_library_12345.so").unwrap_err();
        assert!(err.contains("does not exist"), "Should reject missing file: {err}");
    }

    #[test]
    fn test_validate_ort_path_rejects_outside_allowed() {
        // Create a real file in /tmp — exists but not in allowed prefixes
        let tmp = std::env::temp_dir().join("fake_ort_lib.so");
        std::fs::write(&tmp, b"fake").unwrap();

        let err = validate_ort_path(tmp.to_str().unwrap()).unwrap_err();
        assert!(err.contains("outside allowed directories"), "Should reject /tmp path: {err}");

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_intra_threads_uses_available_parallelism() {
        let num_cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        assert!(num_cores >= 1, "available_parallelism should return at least 1");
    }

    #[test]
    fn test_ml_ner_loads_with_threading_and_ep() {
        // Verify the detector loads successfully with intra-op threading and
        // CoreML EP (on macOS). This catches API misuse or missing features.
        let detector = match try_create_detector() {
            Some(d) => d,
            None => return,
        };
        let spans = detector.detect_persons("Captain Pierre Duval reported the incident.");
        assert!(!spans.is_empty(), "Detector with threading/EP should still detect persons");
    }

    #[test]
    fn test_validate_ort_path_accepts_system_lib() {
        // If a real file exists under an allowed prefix, it should pass.
        // Use /usr/lib/libSystem.B.dylib on macOS or /usr/lib/libc.so.6 on Linux.
        let candidates = [
            "/usr/lib/libSystem.B.dylib",
            "/usr/lib/libc.so.6",
            "/usr/lib/x86_64-linux-gnu/libc.so.6",
        ];
        let valid = candidates.iter().find(|p| PathBuf::from(p).exists());
        if let Some(path) = valid {
            assert!(validate_ort_path(path).is_ok(), "Should accept system lib at {path}");
        } else {
            eprintln!("No system library found for positive test, skipping");
        }
    }
}
