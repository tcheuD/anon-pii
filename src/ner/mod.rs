#[cfg(feature = "ner")]
pub mod download;
#[cfg(feature = "ner-lite")]
pub mod heuristic;
#[cfg(feature = "ner")]
pub mod ml;

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

    /// Batch detection: process multiple texts at once.
    /// Default implementation falls back to per-text `detect_persons()`.
    /// ML backends can override this for efficient batched inference.
    fn detect_persons_batch(&self, texts: &[&str]) -> Vec<Vec<NerSpan>> {
        texts.iter().map(|text| self.detect_persons(text)).collect()
    }
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
        all_spans.sort_by_key(|span| span.start);
        all_spans
    }

    fn detect_persons_batch(&self, texts: &[&str]) -> Vec<Vec<NerSpan>> {
        // Initialize result vectors for each text
        let mut results: Vec<Vec<NerSpan>> = texts.iter().map(|_| Vec::new()).collect();

        // For each detector, get batch results and merge
        for det in &self.detectors {
            let det_results = det.detect_persons_batch(texts);
            for (i, spans) in det_results.into_iter().enumerate() {
                // Only add non-overlapping spans
                for span in spans {
                    let overlaps = results[i]
                        .iter()
                        .any(|s| span.start < s.end && span.end > s.start);
                    if !overlaps {
                        results[i].push(span);
                    }
                }
            }
        }

        // Sort each result by start position
        for spans in &mut results {
            spans.sort_by_key(|span| span.start);
        }

        results
    }
}

/// Words that should never be detected as PERSON names.
/// Company names, product names, and common false positives.
pub const PERSON_BLOCKLIST: &[&str] = &[
    // Company / product names
    "Amelia",
    "Factorial",
    "Leon",
    // Job titles / roles often misdetected
    "Captain",
    "Full",
    "Stack",
    "Developer",
    "Director",
    // Common non-person capitalized words in aviation context
    "Crew",
    "Planning",
    "Bonjour",
    "Cordialement",
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
            .join(".anon-pii")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ner_config_default_uses_anon_pii_dir() {
        // NerConfig model_dir should be under ~/.anon-pii/ (not ~/.anon/)
        // to match the package rename from #144
        let config = NerConfig::default();
        let path_str = config.model_dir.to_string_lossy();
        assert!(
            path_str.contains(".anon-pii"),
            "NerConfig model_dir should use .anon-pii, got: {}",
            path_str
        );
        assert!(
            !path_str.contains("/.anon/"),
            "NerConfig model_dir should not use old .anon dir, got: {}",
            path_str
        );
    }

    #[test]
    fn test_detect_persons_batch_default_fallback() {
        // Test that the default batch implementation correctly delegates to detect_persons
        let mock = MockNerDetector {
            spans: vec![NerSpan {
                text: "Jean Dupont".to_string(),
                start: 0,
                end: 11,
                score: 0.9,
                label: "PERSON".to_string(),
            }],
        };

        let texts = vec!["Hello Jean Dupont", "Another text", "Third text"];
        let results = mock.detect_persons_batch(&texts);

        assert_eq!(results.len(), 3);
        // Each call should return the same mock spans
        assert_eq!(results[0].len(), 1);
        assert_eq!(results[0][0].text, "Jean Dupont");
        assert_eq!(results[1].len(), 1);
        assert_eq!(results[2].len(), 1);
    }

    #[test]
    fn test_detect_persons_batch_empty_input() {
        let mock = MockNerDetector {
            spans: vec![NerSpan {
                text: "Test".to_string(),
                start: 0,
                end: 4,
                score: 0.8,
                label: "PERSON".to_string(),
            }],
        };

        let texts: Vec<&str> = vec![];
        let results = mock.detect_persons_batch(&texts);

        assert!(results.is_empty());
    }

    #[test]
    fn test_combined_ner_detector_batch() {
        // Test that CombinedNerDetector properly delegates batch calls
        let mock1 = MockNerDetector {
            spans: vec![NerSpan {
                text: "Alice".to_string(),
                start: 0,
                end: 5,
                score: 0.85,
                label: "PERSON".to_string(),
            }],
        };
        let mock2 = MockNerDetector {
            spans: vec![NerSpan {
                text: "Bob".to_string(),
                start: 10,
                end: 13,
                score: 0.9,
                label: "PERSON".to_string(),
            }],
        };

        let combined = CombinedNerDetector::new(vec![Box::new(mock1), Box::new(mock2)]);

        let texts = vec!["Hello Alice and Bob"];
        let results = combined.detect_persons_batch(&texts);

        assert_eq!(results.len(), 1);
        // Combined should merge results from both detectors
        assert_eq!(results[0].len(), 2);
    }

    #[test]
    fn test_detect_persons_batch_single_text() {
        let mock = MockNerDetector {
            spans: vec![NerSpan {
                text: "Marie".to_string(),
                start: 0,
                end: 5,
                score: 0.95,
                label: "PERSON".to_string(),
            }],
        };

        let texts = vec!["Just Marie here"];
        let results = mock.detect_persons_batch(&texts);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].len(), 1);
        assert_eq!(results[0][0].text, "Marie");
    }
}
