//! WebAssembly bindings for the browser playground.
//!
//! Exposes the same detection engine the CLI uses, compiled to wasm32.
//! Everything runs client-side; no text ever leaves the page.

use regex::Regex;
use std::sync::LazyLock;
use wasm_bindgen::prelude::*;

use crate::detection::Anonymizer;
use crate::patterns::PATTERNS;

#[cfg(feature = "ner-lite")]
use crate::ner::heuristic::HeuristicNerDetector;

/// A stateful engine session: anonymize keeps a local mapping so that
/// restore can put original values back, exactly like the CLI.
#[wasm_bindgen]
pub struct Engine {
    anon: Anonymizer,
}

#[wasm_bindgen]
impl Engine {
    /// threshold matches the CLI default (0.5); heuristic PERSON detection
    /// is enabled when the ner-lite feature is compiled in.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Engine {
        let mut anon = Anonymizer::new(0.5);
        #[cfg(feature = "ner-lite")]
        anon.set_ner_detector(Box::new(HeuristicNerDetector::new()));
        Engine { anon }
    }

    /// Anonymize text. Returns a JSON string:
    /// {"output": "...", "detections":[{"entity_type","original","start","end","score"}]}
    pub fn anonymize(&mut self, text: &str) -> String {
        let (output, detections) = self.anon.anonymize_text(text);
        let dets: Vec<serde_json::Value> = detections
            .iter()
            .map(|d| {
                serde_json::json!({
                    "entity_type": d.entity_type,
                    "original": d.original,
                    "start": d.start,
                    "end": d.end,
                    "score": d.score,
                })
            })
            .collect();
        serde_json::json!({ "output": output, "detections": dets }).to_string()
    }

    /// Protect one selected value using UTF-8 byte offsets. Returns JSON with
    /// output and token, preserving all other bytes and existing mappings.
    /// Invalid ranges and selections intersecting placeholders leave the
    /// session unchanged.
    pub fn protect_range(
        &mut self,
        text: &str,
        start: usize,
        end: usize,
    ) -> Result<String, JsValue> {
        if start >= end || end > text.len() {
            return Err(JsValue::from_str(
                "Select a nonempty range within the prepared ticket.",
            ));
        }
        if !text.is_char_boundary(start) || !text.is_char_boundary(end) {
            return Err(JsValue::from_str("Select whole characters only."));
        }

        static TOKEN_SHAPE: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r"\[[A-Z][A-Z0-9_]*_[0-9a-f]{8}\]").unwrap());
        let intersects =
            |token_start: usize, token_end: usize| start < token_end && token_start < end;
        let overlaps_known = self.anon.mapping.mappings.keys().any(|token| {
            text.match_indices(token.as_str())
                .any(|(offset, _)| intersects(offset, offset + token.len()))
        });
        if overlaps_known
            || TOKEN_SHAPE
                .find_iter(text)
                .any(|token| intersects(token.start(), token.end()))
        {
            return Err(JsValue::from_str(
                "Selection cannot include an existing token-shaped placeholder.",
            ));
        }

        let token = self.anon.mapping.add("MANUAL", &text[start..end]);
        let mut output = String::with_capacity(text.len() - (end - start) + token.len());
        output.push_str(&text[..start]);
        output.push_str(&token);
        output.push_str(&text[end..]);
        Ok(serde_json::json!({ "output": output, "token": token }).to_string())
    }

    /// Restore bracketed tokens from this session's mapping.
    pub fn restore(&self, text: &str) -> String {
        self.anon.mapping.restore_bracketed(text)
    }

    /// Restore exact tokens and return JSON with output, restored_count, and
    /// unresolved_count. Unresolved counts only built-in-shaped input tokens;
    /// changed or incomplete placeholders may not be recognized.
    pub fn restore_report(&self, text: &str) -> String {
        let report = self.anon.mapping.restore_bracketed_report(text);
        serde_json::json!({
            "output": report.output,
            "restored_count": report.restored_count,
            "unresolved_count": report.unresolved_count,
        })
        .to_string()
    }

    /// Number of entries currently in the session mapping.
    pub fn mapping_len(&self) -> usize {
        self.anon.mapping.mappings.len()
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

/// Distinct built-in entity types (compile-time patterns).
#[wasm_bindgen]
pub fn entity_type_count() -> usize {
    let mut seen: Vec<&str> = Vec::new();
    for p in PATTERNS {
        if !seen.contains(&p.entity_type) {
            seen.push(p.entity_type);
        }
    }
    seen.len()
}

/// Total number of built-in patterns.
#[wasm_bindgen]
pub fn pattern_count() -> usize {
    PATTERNS.len()
}
