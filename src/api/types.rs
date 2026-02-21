use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── /analyze ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AnalyzeRequest {
    pub text: String,
    pub language: String,
    #[serde(default = "default_threshold")]
    pub score_threshold: f64,
    pub entities: Option<Vec<String>>,
    #[serde(default)]
    pub return_decision_process: bool,
}

fn default_threshold() -> f64 {
    0.5
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RecognizerResult {
    pub entity_type: String,
    pub start: usize,
    pub end: usize,
    pub score: f64,
}

// ─── /anonymize ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AnonymizeRequest {
    pub text: String,
    pub analyzer_results: Vec<AnalyzerResult>,
    #[serde(default)]
    pub anonymizers: HashMap<String, AnonymizerConfig>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct AnalyzerResult {
    pub entity_type: String,
    pub start: usize,
    pub end: usize,
    pub score: f64,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AnonymizerConfig {
    Replace {
        new_value: Option<String>,
    },
    Redact,
    Mask {
        masking_char: Option<char>,
        chars_to_mask: Option<usize>,
        from_end: Option<bool>,
    },
    Hash {
        hash_type: Option<String>,
    },
    Encrypt {
        key: String,
    },
    Keep,
    Custom {
        lambda: String,
    },
}

impl Default for AnonymizerConfig {
    fn default() -> Self {
        Self::Replace { new_value: None }
    }
}

#[derive(Serialize, Deserialize)]
pub struct AnonymizeResponse {
    pub text: String,
    pub items: Vec<OperatorResult>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OperatorResult {
    pub operator: String,
    pub entity_type: String,
    pub start: usize,
    pub end: usize,
    pub text: String,
}
