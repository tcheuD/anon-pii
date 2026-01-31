#[cfg(feature = "ner")]
pub mod ml;
#[cfg(feature = "ner")]
pub mod download;
#[cfg(feature = "ner-lite")]
pub mod heuristic;

use std::path::PathBuf;

/// A span detected by NER.
pub struct NerSpan {
    pub text: String,
    pub start: usize, // byte offset
    pub end: usize,   // byte offset
    pub score: f64,
    pub label: String, // mapped to "PERSON"
}

/// Trait for NER backends.
pub trait NerDetector: Send + Sync {
    fn detect_persons(&self, text: &str) -> Vec<NerSpan>;
}

/// Configuration for NER.
pub struct NerConfig {
    pub model_dir: PathBuf,
    pub min_score: f64,
}

impl Default for NerConfig {
    fn default() -> Self {
        let model_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".anon")
            .join("models")
            .join("distilbert-ner-int8");
        Self {
            model_dir,
            min_score: 0.6,
        }
    }
}
