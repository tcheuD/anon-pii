use std::path::Path;
use std::sync::Mutex;

use crate::ner::{NerConfig, NerDetector, NerSpan};

pub struct MlNerDetector {
    session: Mutex<ort::session::Session>,
    tokenizer: tokenizers::Tokenizer,
    id2label: Vec<String>,
    min_score: f64,
}

impl MlNerDetector {
    pub fn new(config: &NerConfig) -> Result<Self, Box<dyn std::error::Error>> {
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

        let session = ort::session::Session::builder()?
            .with_optimization_level(ort::session::builder::GraphOptimizationLevel::Level3)?
            .commit_from_file(&model_path)?;

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

impl NerDetector for MlNerDetector {
    fn detect_persons(&self, text: &str) -> Vec<NerSpan> {
        if text.is_empty() {
            return Vec::new();
        }

        let encoding = match self.tokenizer.encode(text, true) {
            Ok(enc) => enc,
            Err(_) => return Vec::new(),
        };

        let input_ids: Vec<i64> = encoding.get_ids().iter().map(|&id| id as i64).collect();
        let attention_mask: Vec<i64> = encoding.get_attention_mask().iter().map(|&m| m as i64).collect();

        let seq_len = input_ids.len();

        // Build input tensors — DistilBERT only needs input_ids + attention_mask
        let ids_tensor = match ort::value::Tensor::from_array((vec![1i64, seq_len as i64], input_ids)) {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        };
        let mask_tensor = match ort::value::Tensor::from_array((vec![1i64, seq_len as i64], attention_mask)) {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        };

        let inputs = ort::inputs![
            "input_ids" => ids_tensor,
            "attention_mask" => mask_tensor,
        ];

        let mut session = match self.session.lock() {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let outputs = match session.run(inputs) {
            Ok(o) => o,
            Err(_) => return Vec::new(),
        };

        // Extract logits: shape [1, seq_len, num_labels], flat array
        let (shape, logits) = match outputs[0].try_extract_tensor::<f32>() {
            Ok(l) => l,
            Err(_) => return Vec::new(),
        };

        let num_labels = if shape.len() == 3 { shape[2] as usize } else { return Vec::new() };
        let offsets = encoding.get_offsets();

        // Decode BIO tags into spans
        let mut spans: Vec<NerSpan> = Vec::new();
        let mut current_start: Option<usize> = None;
        let mut current_end: usize = 0;
        let mut current_scores: Vec<f32> = Vec::new();

        for i in 0..seq_len {
            let (off_start, off_end) = offsets[i];
            if off_start == off_end {
                if let Some(start) = current_start.take() {
                    flush_span(text, start, current_end, &current_scores, self.min_score, &mut spans);
                    current_scores.clear();
                }
                continue;
            }

            // Find predicted label (argmax)
            let row_offset = i * num_labels;
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
}
