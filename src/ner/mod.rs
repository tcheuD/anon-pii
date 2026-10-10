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
/// Nested PERSON alternatives with different confidence are retained so the
/// anonymizer can apply its threshold before resolving overlapping spans.
pub struct CombinedNerDetector {
    detectors: Vec<Box<dyn NerDetector>>,
}

impl CombinedNerDetector {
    pub fn new(detectors: Vec<Box<dyn NerDetector>>) -> Self {
        Self { detectors }
    }

    fn merge_span(spans: &mut Vec<NerSpan>, candidate: NerSpan) {
        let overlaps = |span: &NerSpan| candidate.start < span.end && candidate.end > span.start;
        let overlapping: Vec<_> = spans.iter().filter(|span| overlaps(span)).collect();
        if overlapping.is_empty() {
            spans.push(candidate);
            return;
        }

        let contains =
            |outer: &NerSpan, inner: &NerSpan| outer.start <= inner.start && outer.end >= inner.end;
        // A later detector can complete a PERSON span recognized only in part.
        // Keep a more confident short span until the anonymizer applies its
        // threshold; confidence in that span does not establish confidence in
        // the full name. Equal spans, partial overlaps, and differing labels
        // continue to respect detector priority.
        let nested_person = candidate.label == "PERSON"
            && overlapping.iter().all(|span| {
                span.label == "PERSON"
                    && (contains(&candidate, span) || contains(span, &candidate))
                    && (candidate.start != span.start || candidate.end != span.end)
            });
        if !nested_person
            || overlapping
                .iter()
                .any(|span| contains(span, &candidate) && span.score >= candidate.score)
        {
            return;
        }
        spans.retain(|span| {
            !overlaps(span) || !contains(&candidate, span) || span.score > candidate.score
        });
        spans.push(candidate);
    }
}

impl NerDetector for CombinedNerDetector {
    fn detect_persons(&self, text: &str) -> Vec<NerSpan> {
        let mut all_spans: Vec<NerSpan> = Vec::new();
        for det in &self.detectors {
            let spans = det.detect_persons(text);
            for span in spans {
                Self::merge_span(&mut all_spans, span);
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
                for span in spans {
                    Self::merge_span(&mut results[i], span);
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

    fn fixture_span(text: &str, start: usize, end: usize, label: &str, score: f64) -> NerSpan {
        NerSpan {
            text: text[start..end].to_string(),
            start,
            end,
            label: label.to_string(),
            score,
        }
    }

    #[test]
    fn combined_preserves_more_confident_contained_person_in_either_order() {
        let text = "Avery quill";
        for short_range in [0..5, 6..11] {
            for short_score in [0.60, 0.70, 0.95] {
                for fuller_first in [false, true] {
                    let short = fixture_span(
                        text,
                        short_range.start,
                        short_range.end,
                        "PERSON",
                        short_score,
                    );
                    let full = fixture_span(text, 0, text.len(), "PERSON", 0.70);
                    let mut spans = if fuller_first {
                        vec![full.clone()]
                    } else {
                        vec![short.clone()]
                    };
                    CombinedNerDetector::merge_span(
                        &mut spans,
                        if fuller_first { short } else { full },
                    );
                    assert_eq!(spans.len(), if short_score > 0.70 { 2 } else { 1 });
                    let full = spans.iter().find(|span| span.text == text).unwrap();
                    assert_eq!(full.start, 0);
                    assert_eq!(full.end, text.len());
                    assert_eq!(full.score, 0.70);
                    if short_score > 0.70 {
                        let short = spans.iter().find(|span| span.text != text).unwrap();
                        assert_eq!(short.start, short_range.start);
                        assert_eq!(short.end, short_range.end);
                        assert_eq!(short.score, short_score);
                    }
                }
            }
        }
        let mut parts = vec![
            fixture_span(text, 0, 5, "PERSON", 0.95),
            fixture_span(text, 6, 11, "PERSON", 0.90),
        ];
        CombinedNerDetector::merge_span(
            &mut parts,
            fixture_span(text, 0, text.len(), "PERSON", 0.70),
        );
        assert_eq!(parts.len(), 3);
        assert!(
            parts
                .iter()
                .any(|span| span.text == text && span.score == 0.70)
        );
    }

    #[test]
    fn combined_retains_priority_for_equal_partial_and_different_label_overlaps() {
        let text = "Avery quill";
        for (first_range, first_label, later_range, later_label) in [
            (0..5, "PERSON", 0..5, "PERSON"),
            (0..7, "PERSON", 6..11, "PERSON"),
            (0..5, "LOCATION", 0..11, "PERSON"),
            (0..5, "PERSON", 0..11, "LOCATION"),
            (0..5, "LOCATION", 0..11, "LOCATION"),
        ] {
            let first = fixture_span(text, first_range.start, first_range.end, first_label, 0.95);
            let mut spans = vec![first.clone()];
            CombinedNerDetector::merge_span(
                &mut spans,
                fixture_span(text, later_range.start, later_range.end, later_label, 0.70),
            );
            assert_eq!(spans.len(), 1);
            assert_eq!(spans[0].text, first.text);
            assert_eq!(spans[0].label, first.label);
            assert_eq!(spans[0].score, first.score);
        }

        let mut spans = vec![
            fixture_span(text, 0, 5, "PERSON", 0.95),
            fixture_span(text, 6, 11, "LOCATION", 0.90),
        ];
        CombinedNerDetector::merge_span(
            &mut spans,
            fixture_span(text, 0, text.len(), "PERSON", 0.70),
        );
        assert_eq!(
            spans.len(),
            2,
            "a conflicting label must leave both spans intact"
        );
        assert_eq!(spans[0].text, "Avery");
        assert_eq!(spans[1].label, "LOCATION");
    }

    #[cfg(feature = "ner-lite")]
    #[test]
    fn combined_ml_first_name_and_introduced_surname_match_single_and_batch() {
        let text = "Hello my name is Avery quill and I need help.";
        let start = text.find("Avery").unwrap();
        for fuller_first in [false, true] {
            let combined = || {
                let mut detectors: Vec<Box<dyn NerDetector>> = vec![
                    Box::new(MockNerDetector {
                        spans: vec![fixture_span(text, start, start + 5, "PERSON", 0.95)],
                    }),
                    Box::new(heuristic::HeuristicNerDetector::new()),
                ];
                if fuller_first {
                    detectors.reverse();
                }
                CombinedNerDetector::new(detectors)
            };
            let detector = combined();
            for spans in std::iter::once(detector.detect_persons(text))
                .chain(detector.detect_persons_batch(&[text, text]))
            {
                assert_eq!(spans.len(), 2);
                assert!(
                    spans
                        .iter()
                        .any(|span| span.text == "Avery" && span.score == 0.95)
                );
                assert!(
                    spans
                        .iter()
                        .any(|span| span.text == "Avery quill" && span.score == 0.70)
                );
                for span in spans {
                    assert_eq!(&text[span.start..span.end], span.text);
                }
            }

            for (threshold, expected, score, suffix) in [
                (0.5, "Avery quill", 0.70, " and I need help."),
                (0.8, "Avery", 0.95, " quill and I need help."),
            ] {
                let mut anonymizer = crate::detection::Anonymizer::new(threshold);
                anonymizer.set_ner_detector(Box::new(combined()));
                let single = anonymizer.anonymize_text(text);
                let batch = anonymizer.anonymize_texts(&[text, text]);
                for (output, detections) in std::iter::once(single).chain(batch) {
                    assert_eq!(detections.len(), 1);
                    assert_eq!(detections[0].original, expected);
                    assert_eq!(detections[0].score, score);
                    assert_eq!(anonymizer.mapping.restore_bracketed(&output), text);
                    assert!(output.ends_with(suffix));
                }
            }
        }
    }

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
