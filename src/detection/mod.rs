use std::borrow::Cow;

use regex::Regex;
use serde_json::Value;

use crate::mapping::Mapping;
use crate::ner::NerDetector;
use crate::patterns::{CONTEXT_SCORE_BOOST, PATTERNS};

mod context;
mod engine;
mod names;
mod normalize;
mod operators;
mod types;

// Re-exports for external callers
pub use operators::{
    apply_custom_replacement, apply_encrypt, apply_hash, apply_mask, decrypt_encrypted,
    parse_encrypt_key,
};
pub use types::{CompiledPattern, Detection, HashAlgo, MaskConfig, Operator};

use normalize::parse_csv_line;
use types::CompiledPattern as CompiledPatternInternal;

pub struct Anonymizer {
    pub patterns: Vec<CompiledPattern>,
    pub mapping: Mapping,
    pub threshold: f64,
    pub operator: Operator,
    pub mask_config: MaskConfig,
    pub hash_algo: HashAlgo,
    pub encrypt_key: Option<Vec<u8>>,
    pub replace_with: Option<String>,
    pub context_boost: f64,
    pub min_score_with_context: f64,
    ner_detector: Option<Box<dyn NerDetector>>,
}

impl Anonymizer {
    pub fn new(threshold: f64) -> Self {
        let patterns = PATTERNS
            .iter()
            .map(|p| CompiledPatternInternal {
                entity_type: Cow::Borrowed(p.entity_type),
                name: Cow::Borrowed(p.name),
                regex: Regex::new(p.pattern)
                    .unwrap_or_else(|e| panic!("invalid regex for pattern '{}': {}", p.name, e)),
                score: p.score,
                context_keywords: Cow::Borrowed(p.context_keywords),
                context_required: p.context_required,
            })
            .collect();

        Self {
            patterns,
            mapping: Mapping::new(),
            threshold,
            operator: Operator::default(),
            mask_config: MaskConfig::default(),
            hash_algo: HashAlgo::default(),
            encrypt_key: None,
            replace_with: None,
            context_boost: CONTEXT_SCORE_BOOST,
            min_score_with_context: 0.0,
            ner_detector: None,
        }
    }

    pub fn set_ner_detector(&mut self, detector: Box<dyn NerDetector>) {
        self.ner_detector = Some(detector);
    }

    /// Run the full detection pipeline (normalization, pattern matching, validators,
    /// NER, overlap resolution) without performing any replacement or writing to the
    /// mapping. Returns raw detections suitable for the Presidio `/analyze` endpoint.
    pub fn analyze(&mut self, text: &str) -> Vec<Detection> {
        let saved = self.operator;
        self.operator = Operator::Keep;
        let (_, detections) = self.anonymize_text(text);
        self.operator = saved;
        detections
    }

    /// Anonymize CSV content cell-by-cell, respecting RFC 4180 quoting.
    /// Quoted fields (e.g. `"Doe, John"`) are extracted whole before anonymization.
    pub fn anonymize_csv(&mut self, text: &str) -> (String, Vec<Detection>) {
        let mut all_detections = Vec::new();
        let mut output = String::with_capacity(text.len());

        for (line_idx, line) in text.lines().enumerate() {
            if line_idx > 0 {
                output.push('\n');
            }
            let cells = parse_csv_line(line);
            for (i, cell) in cells.iter().enumerate() {
                if i > 0 {
                    output.push(',');
                }
                let needs_quoting = cell.contains(',') || cell.contains('"') || cell.contains('\n');
                let (anon, dets) = self.anonymize_text(cell);
                all_detections.extend(dets);
                if needs_quoting {
                    output.push('"');
                    output.push_str(&anon.replace('"', "\"\""));
                    output.push('"');
                } else {
                    output.push_str(&anon);
                }
            }
        }
        if text.ends_with('\n') {
            output.push('\n');
        }

        (output, all_detections)
    }

    /// Anonymize SQL content by only processing single-quoted string literals.
    /// Identifiers, keywords, and non-string content are preserved as-is.
    pub fn anonymize_sql(&mut self, text: &str) -> (String, Vec<Detection>) {
        let mut all_detections = Vec::new();
        let mut output = String::with_capacity(text.len());
        let bytes = text.as_bytes();
        let mut i = 0;

        while i < bytes.len() {
            if bytes[i] == b'\'' {
                // Extract the string literal (handling escaped quotes '')
                let start = i;
                i += 1; // skip opening quote
                let mut literal = String::new();
                while i < bytes.len() {
                    if bytes[i] == b'\'' {
                        if i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                            literal.push('\'');
                            i += 2;
                        } else {
                            break;
                        }
                    } else {
                        literal.push(bytes[i] as char);
                        i += 1;
                    }
                }
                if i < bytes.len() {
                    i += 1; // skip closing quote
                }
                let (anon, dets) = self.anonymize_text(&literal);
                all_detections.extend(dets);
                output.push('\'');
                output.push_str(&anon.replace('\'', "''"));
                output.push('\'');
                let _ = start; // suppress unused warning
            } else {
                output.push(bytes[i] as char);
                i += 1;
            }
        }

        (output, all_detections)
    }

    /// Maximum JSON nesting depth for `walk_json`. Matches serde_json's default
    /// recursion limit. Prevents stack overflow on deeply nested input.
    const MAX_JSON_DEPTH: usize = 128;

    pub fn anonymize_json_value(&mut self, value: &Value) -> (Value, Vec<Detection>) {
        let mut all_detections = Vec::new();
        let new_value = self.walk_json(value, &mut all_detections, 0);
        (new_value, all_detections)
    }

    fn walk_json(&mut self, value: &Value, detections: &mut Vec<Detection>, depth: usize) -> Value {
        if depth >= Self::MAX_JSON_DEPTH {
            return value.clone();
        }

        match value {
            Value::String(s) => {
                let (anonymized, dets) = self.anonymize_text(s);
                detections.extend(dets);
                Value::String(anonymized)
            }
            Value::Array(arr) => {
                let new_arr: Vec<Value> = arr
                    .iter()
                    .map(|v| self.walk_json(v, detections, depth + 1))
                    .collect();
                Value::Array(new_arr)
            }
            Value::Object(map) => {
                let new_map = map
                    .iter()
                    .map(|(k, v)| {
                        let (anon_key, key_dets) = self.anonymize_text(k);
                        detections.extend(key_dets);
                        (anon_key, self.walk_json(v, detections, depth + 1))
                    })
                    .collect();
                Value::Object(new_map)
            }
            other => other.clone(),
        }
    }
}

#[cfg(test)]
mod tests;
