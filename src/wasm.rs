//! WebAssembly bindings for the browser playground.
//!
//! Exposes the same detection engine the CLI uses, compiled to wasm32.
//! Everything runs client-side; no text ever leaves the page.

use wasm_bindgen::prelude::*;

use crate::detection::Anonymizer;
use crate::patterns::PATTERNS;

/// A stateful engine session: anonymize keeps a local mapping so that
/// restore can put original values back, exactly like the CLI.
#[wasm_bindgen]
pub struct Engine {
    anon: Anonymizer,
}

#[wasm_bindgen]
impl Engine {
    /// threshold matches the CLI default (0.5).
    #[wasm_bindgen(constructor)]
    pub fn new() -> Engine {
        Engine {
            anon: Anonymizer::new(0.5),
        }
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

    /// Restore bracketed tokens from this session's mapping.
    pub fn restore(&self, text: &str) -> String {
        self.anon.mapping.restore_bracketed(text)
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
