use regex::Regex;
use serde_json::Value;

use crate::mapping::Mapping;
use crate::patterns::{
    CONTEXT_SCORE_BOOST, CONTEXT_WINDOW, CREW_CODE_BLOCKLIST, PATTERNS, luhn_check,
};

#[cfg(any(feature = "ner", feature = "ner-lite"))]
use crate::ner::NerDetector;

pub struct Anonymizer {
    pub patterns: Vec<CompiledPattern>,
    pub mapping: Mapping,
    pub threshold: f64,
    #[cfg(any(feature = "ner", feature = "ner-lite"))]
    ner_detector: Option<Box<dyn NerDetector>>,
}

pub struct CompiledPattern {
    pub entity_type: &'static str,
    #[allow(dead_code)]
    pub name: &'static str,
    pub regex: Regex,
    pub score: f64,
    pub context_keywords: &'static [&'static str],
    pub context_required: bool,
}

#[derive(Debug)]
pub struct Detection {
    pub entity_type: &'static str,
    pub original: String,
    pub start: usize,
    pub end: usize,
    pub score: f64,
}

impl Anonymizer {
    pub fn new(threshold: f64) -> Self {
        let patterns = PATTERNS
            .iter()
            .map(|p| CompiledPattern {
                entity_type: p.entity_type,
                name: p.name,
                regex: Regex::new(p.pattern)
                    .unwrap_or_else(|e| panic!("invalid regex for pattern '{}': {}", p.name, e)),
                score: p.score,
                context_keywords: p.context_keywords,
                context_required: p.context_required,
            })
            .collect();

        Self {
            patterns,
            mapping: Mapping::new(),
            threshold,
            #[cfg(any(feature = "ner", feature = "ner-lite"))]
            ner_detector: None,
        }
    }

    #[cfg(any(feature = "ner", feature = "ner-lite"))]
    pub fn set_ner_detector(&mut self, detector: Box<dyn NerDetector>) {
        self.ner_detector = Some(detector);
    }

    fn has_context(&self, text: &str, start: usize, end: usize, keywords: &[&str]) -> bool {
        if keywords.is_empty() {
            return false;
        }
        let mut window_start = start.saturating_sub(CONTEXT_WINDOW);
        let mut window_end = (end + CONTEXT_WINDOW).min(text.len());
        while !text.is_char_boundary(window_start) {
            window_start += 1;
        }
        while !text.is_char_boundary(window_end) {
            window_end -= 1;
        }
        let window = &text[window_start..window_end];
        let lower = window.to_lowercase();
        keywords.iter().any(|kw| lower.contains(*kw))
    }

    pub fn anonymize_text(&mut self, text: &str) -> (String, Vec<Detection>) {
        let mut detections: Vec<Detection> = Vec::new();

        for pat in &self.patterns {
            // Early threshold check: consider maximum possible score (with boost)
            let max_score = if !pat.context_keywords.is_empty() && !pat.context_required {
                (pat.score + CONTEXT_SCORE_BOOST).min(1.0)
            } else {
                pat.score
            };
            if max_score < self.threshold {
                continue;
            }

            for mat in pat.regex.find_iter(text) {
                // Check context presence
                let has_ctx = if !pat.context_keywords.is_empty() {
                    self.has_context(text, mat.start(), mat.end(), pat.context_keywords)
                } else {
                    false
                };

                // Context gating: required mode skips when no context found
                if pat.context_required && !pat.context_keywords.is_empty() && !has_ctx {
                    continue;
                }

                // Crew code blocklist
                if pat.entity_type == "CREW_CODE" {
                    let matched = mat.as_str();
                    if CREW_CODE_BLOCKLIST.contains(&matched) {
                        continue;
                    }
                }

                // Credit card Luhn validation
                if pat.entity_type == "CREDIT_CARD" && !luhn_check(mat.as_str()) {
                    continue;
                }

                // Compute detection score with optional context boost
                let detection_score = if !pat.context_required && !pat.context_keywords.is_empty() && has_ctx {
                    (pat.score + CONTEXT_SCORE_BOOST).min(1.0)
                } else {
                    pat.score
                };

                // Per-detection threshold check (for boost patterns without context)
                if detection_score < self.threshold {
                    continue;
                }

                detections.push(Detection {
                    entity_type: pat.entity_type,
                    original: mat.as_str().to_string(),
                    start: mat.start(),
                    end: mat.end(),
                    score: detection_score,
                });
            }
        }

        // Inject NER-based PERSON detections
        #[cfg(any(feature = "ner", feature = "ner-lite"))]
        if let Some(ref ner) = self.ner_detector {
            for span in ner.detect_persons(text) {
                if span.score >= self.threshold {
                    detections.push(Detection {
                        entity_type: "PERSON",
                        original: span.text,
                        start: span.start,
                        end: span.end,
                        score: span.score,
                    });
                }
            }
        }

        // Sort by position asc, then span length desc, then score desc
        // Matches Python/Presidio overlap resolution: position-first
        detections.sort_by(|a, b| {
            a.start.cmp(&b.start)
                .then_with(|| (b.end - b.start).cmp(&(a.end - a.start)))
                .then_with(|| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal))
        });

        // Remove overlapping detections (keep first = longest/highest score)
        let mut filtered: Vec<Detection> = Vec::new();
        for det in detections {
            let overlaps = filtered
                .iter()
                .any(|f| det.start < f.end && det.end > f.start);
            if !overlaps {
                filtered.push(det);
            }
        }

        // Sort by position for display
        filtered.sort_by(|a, b| a.start.cmp(&b.start));

        // Replace from end to start
        let mut result = text.to_string();
        for det in filtered.iter().rev() {
            let token = self.mapping.add(det.entity_type, &det.original);
            result = format!(
                "{}{}{}",
                &result[..det.start],
                token,
                &result[det.end..]
            );
        }

        (result, filtered)
    }

    pub fn anonymize_json_value(&mut self, value: &Value) -> (Value, Vec<Detection>) {
        let mut all_detections = Vec::new();
        let new_value = self.walk_json(value, &mut all_detections);
        (new_value, all_detections)
    }

    fn walk_json(&mut self, value: &Value, detections: &mut Vec<Detection>) -> Value {
        match value {
            Value::String(s) => {
                let (anonymized, dets) = self.anonymize_text(s);
                detections.extend(dets);
                Value::String(anonymized)
            }
            Value::Array(arr) => {
                let new_arr: Vec<Value> = arr.iter().map(|v| self.walk_json(v, detections)).collect();
                Value::Array(new_arr)
            }
            Value::Object(map) => {
                let new_map = map
                    .iter()
                    .map(|(k, v)| (k.clone(), self.walk_json(v, detections)))
                    .collect();
                Value::Object(new_map)
            }
            other => other.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("contact john@example.com now");
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].entity_type, "EMAIL_ADDRESS");
        assert!(result.contains("[EMAIL_ADDRESS_1]"));
    }

    #[test]
    fn test_url() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("visit https://example.com/path?q=1 now");
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].entity_type, "URL");
        assert!(result.contains("[URL_1]"));
    }

    #[test]
    fn test_fr_phone_intl() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("call +33 6 12 34 56 78");
        assert!(result.contains("[FR_PHONE_NUMBER_1]"));
    }

    #[test]
    fn test_fr_phone_national() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("call 06 12 34 56 78");
        assert!(result.contains("[FR_PHONE_NUMBER_1]"));
    }

    #[test]
    fn test_fr_phone_compact() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("appeler 0612345678 rapidement");
        assert!(result.contains("[FR_PHONE_NUMBER_"));
        assert!(!result.contains("0612345678"));
    }

    #[test]
    fn test_fr_iban() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("IBAN: FR76 1234 5678 9012 3456 7890 123");
        assert!(result.contains("[FR_IBAN_1]"));
    }

    #[test]
    fn test_fr_iban_compact() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("IBAN: FR7630006000011234567890189");
        assert!(result.contains("[FR_IBAN_"));
    }

    #[test]
    fn test_fr_ssn() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("NIR: 1 85 12 75 123 456 78");
        assert!(result.contains("[FR_SSN_1]"));
    }

    #[test]
    fn test_fr_ssn_compact() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("NIR: 185127512345678");
        assert!(result.contains("[FR_SSN_"));
    }

    #[test]
    fn test_fr_passport_with_context() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("passeport: 12AB34567");
        assert!(dets.iter().any(|d| d.entity_type == "FR_PASSPORT"));
        assert!(result.contains("[FR_PASSPORT_1]"));
    }

    #[test]
    fn test_fr_passport_without_context() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("code: 12AB34567");
        assert!(!dets.iter().any(|d| d.entity_type == "FR_PASSPORT"));
    }

    #[test]
    fn test_aircraft_fr() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("aircraft F-HOPA ready");
        assert!(result.contains("[AIRCRAFT_REGISTRATION_1]"));
    }

    #[test]
    fn test_aircraft_us_with_context() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("aircraft N12345 ready");
        assert!(dets.iter().any(|d| d.entity_type == "AIRCRAFT_REGISTRATION"));
        assert!(result.contains("[AIRCRAFT_REGISTRATION_1]"));
    }

    #[test]
    fn test_aircraft_us_two_letter_suffix() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("aircraft N12345AB ready");
        assert!(result.contains("[AIRCRAFT_REGISTRATION_"));
        assert!(!result.contains("N12345AB"));
    }

    #[test]
    fn test_crew_code_with_context() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("pilot: JDU is on duty");
        assert!(dets.iter().any(|d| d.entity_type == "CREW_CODE"));
        assert!(result.contains("[CREW_CODE_1]"));
    }

    #[test]
    fn test_crew_code_without_context() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("hello JDU world");
        assert!(!dets.iter().any(|d| d.entity_type == "CREW_CODE"));
    }

    #[test]
    fn test_crew_code_blocklist() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("crew member THE");
        assert!(!dets.iter().any(|d| d.entity_type == "CREW_CODE" && d.original == "THE"));
    }

    #[test]
    fn test_ip() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("server at 192.168.1.100");
        assert!(result.contains("[IP_ADDRESS_1]"));
    }

    #[test]
    fn test_uuid() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("id: 550e8400-e29b-41d4-a716-446655440000");
        assert!(result.contains("[UUID_1]"));
    }

    #[test]
    fn test_crypto_ethereum() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("wallet: 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18");
        assert!(dets.iter().any(|d| d.entity_type == "CRYPTO"));
        assert!(result.contains("[CRYPTO_1]"));
    }

    #[test]
    fn test_threshold() {
        let mut a = Anonymizer::new(0.8);
        let (_, dets) = a.anonymize_text("visit https://example.com call 06 12 34 56 78");
        // URL (0.9) should pass, fr_phone_national (0.7) should be filtered
        assert!(dets.iter().any(|d| d.entity_type == "URL"));
        assert!(!dets.iter().any(|d| d.entity_type == "FR_PHONE_NUMBER"));
    }

    #[test]
    fn test_consistency() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("john@example.com and john@example.com again");
        assert_eq!(result.matches("[EMAIL_ADDRESS_1]").count(), 2);
    }

    #[test]
    fn test_json_processing() {
        let mut a = Anonymizer::new(0.0);
        let json = serde_json::json!({
            "email": "john@example.com",
            "count": 42,
            "active": true,
            "nested": {
                "phone": "+33 6 12 34 56 78"
            }
        });
        let (result, dets) = a.anonymize_json_value(&json);
        assert_eq!(dets.len(), 2);
        assert_eq!(result["count"], 42);
        assert_eq!(result["active"], true);
        assert!(result["email"].as_str().unwrap().contains("[EMAIL_ADDRESS_1]"));
        assert!(result["nested"]["phone"].as_str().unwrap().contains("[FR_PHONE_NUMBER_1]"));
    }

    #[test]
    fn test_mapping_roundtrip() {
        let mut a = Anonymizer::new(0.0);
        let original = "contact john@example.com at 192.168.1.1";
        let (anonymized, _) = a.anonymize_text(original);
        let restored = a.mapping.restore(&anonymized);
        assert_eq!(restored, original);
    }

    #[test]
    fn test_context_score_boost() {
        // Without context keyword: base score
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("call 06 12 34 56 78");
        let phone_det = dets.iter().find(|d| d.entity_type == "FR_PHONE_NUMBER").unwrap();
        assert!((phone_det.score - 0.7).abs() < 0.01);

        // With context keyword "telephone": boosted score
        let mut a2 = Anonymizer::new(0.0);
        let (_, dets2) = a2.anonymize_text("telephone 06 12 34 56 78");
        let phone_det2 = dets2.iter().find(|d| d.entity_type == "FR_PHONE_NUMBER").unwrap();
        assert!((phone_det2.score - 0.85).abs() < 0.01); // 0.7 + 0.15 boost
    }

    #[test]
    fn test_utf8_context_window() {
        let mut a = Anonymizer::new(0.0);
        // French accented text with crew code context — should not panic
        let input = "L'équipage était composé du pilote JDU et du copilote André résumé";
        let (result, dets) = a.anonymize_text(input);
        assert!(dets.iter().any(|d| d.entity_type == "CREW_CODE"));
        assert!(result.contains("[CREW_CODE_1]"));
    }

    #[test]
    fn test_utf8_email_in_accented_text() {
        let mut a = Anonymizer::new(0.0);
        let input = "Héloïse a envoyé un mail à héloïse@example.com depuis Zürich";
        let (result, _) = a.anonymize_text(input);
        assert!(result.contains("[EMAIL_ADDRESS_1]"));
        // Verify the surrounding accented text is preserved
        assert!(result.contains("Héloïse"));
        assert!(result.contains("Zürich"));
    }
}
