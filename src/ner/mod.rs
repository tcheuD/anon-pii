#[cfg(feature = "ner")]
pub mod ml;
#[cfg(feature = "ner")]
pub mod download;
#[cfg(feature = "ner-lite")]
pub mod heuristic;

use std::path::PathBuf;

/// A span detected by NER.
#[derive(Debug, Clone)]
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

/// Combines multiple NER detectors, merging their results with deduplication.
pub struct CombinedNerDetector {
    detectors: Vec<Box<dyn NerDetector>>,
}

impl CombinedNerDetector {
    pub fn new(detectors: Vec<Box<dyn NerDetector>>) -> Self {
        Self { detectors }
    }
}

impl NerDetector for CombinedNerDetector {
    fn detect_persons(&self, text: &str) -> Vec<NerSpan> {
        let mut all_spans: Vec<NerSpan> = Vec::new();
        for det in &self.detectors {
            let spans = det.detect_persons(text);
            // Only add non-overlapping spans
            for span in spans {
                let overlaps = all_spans
                    .iter()
                    .any(|s| span.start < s.end && span.end > s.start);
                if !overlaps {
                    all_spans.push(span);
                }
            }
        }
        all_spans.sort_by(|a, b| a.start.cmp(&b.start));
        all_spans
    }
}

/// Words that should never be detected as PERSON names.
/// Company names, product names, and common false positives.
pub const PERSON_BLOCKLIST: &[&str] = &[
    // Company / product names
    "Amelia", "Factorial", "Leon",
    // Job titles / roles often misdetected
    "Captain", "Full", "Stack", "Developer", "Director",
    // Common non-person capitalized words in aviation context
    "Crew", "Planning", "Bonjour", "Cordialement",
];

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

#[cfg(test)]
pub struct MockNerDetector {
    pub spans: Vec<NerSpan>,
}

#[cfg(test)]
impl NerDetector for MockNerDetector {
    fn detect_persons(&self, _text: &str) -> Vec<NerSpan> {
        self.spans.clone()
    }
}
