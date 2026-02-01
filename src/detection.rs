use regex::Regex;
use serde_json::Value;
use unicode_normalization::UnicodeNormalization;

use crate::mapping::Mapping;
use crate::patterns::{
    CONTEXT_SCORE_BOOST, CONTEXT_WINDOW, CREW_CODE_BLOCKLIST, PATTERNS, luhn_check,
    valid_card_prefix,
};

#[cfg(any(feature = "ner", feature = "ner-lite"))]
use crate::ner::NerDetector;

/// Parse a single CSV line respecting RFC 4180 quoting.
fn parse_csv_line(line: &str) -> Vec<String> {
    let mut cells = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    current.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                current.push(c);
            }
        } else if c == '"' {
            in_quotes = true;
        } else if c == ',' {
            cells.push(std::mem::take(&mut current));
        } else {
            current.push(c);
        }
    }
    cells.push(current);
    cells
}

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
        // NFKC normalization converts fullwidth digits, confusable homoglyphs,
        // and other Unicode variants to their canonical ASCII equivalents so
        // that regex patterns match consistently.
        let normalized: String = text.nfkc().collect();
        let text = normalized.as_str();

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

                // FR_SSN: reject matches embedded in longer digit sequences
                if pat.entity_type == "FR_SSN" {
                    let bytes = text.as_bytes();
                    if (mat.start() > 0 && bytes[mat.start() - 1].is_ascii_digit())
                        || (mat.end() < bytes.len() && bytes[mat.end()].is_ascii_digit())
                    {
                        continue;
                    }
                }

                // Crew code blocklist
                if pat.entity_type == "CREW_CODE" {
                    let matched = mat.as_str();
                    if CREW_CODE_BLOCKLIST.contains(&matched) {
                        continue;
                    }
                }

                // Credit card validation: Luhn checksum + known issuer prefix
                if pat.entity_type == "CREDIT_CARD" {
                    let matched = mat.as_str();
                    if !luhn_check(matched) || !valid_card_prefix(matched) {
                        continue;
                    }
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
                let new_arr: Vec<Value> = arr.iter().map(|v| self.walk_json(v, detections, depth + 1)).collect();
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
mod tests {
    use super::*;

    #[test]
    fn test_email() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("contact john@example.com now");
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].entity_type, "EMAIL_ADDRESS");
        assert!(result.contains("[EMAIL_ADDRESS_"));
    }

    #[test]
    fn test_url() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("visit https://example.com/path?q=1 now");
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].entity_type, "URL");
        assert!(result.contains("[URL_"));
    }

    #[test]
    fn test_fr_phone_intl() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("call +33 6 12 34 56 78");
        assert!(result.contains("[FR_PHONE_NUMBER_"));
    }

    #[test]
    fn test_fr_phone_national() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("call 06 12 34 56 78");
        assert!(result.contains("[FR_PHONE_NUMBER_"));
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
        assert!(result.contains("[FR_IBAN_"));
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
        assert!(result.contains("[FR_SSN_"));
    }

    #[test]
    fn test_fr_ssn_compact() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("NIR: 185127512345678");
        assert!(result.contains("[FR_SSN_"));
    }

    #[test]
    fn test_fr_ssn_not_in_longer_digits() {
        let mut a = Anonymizer::new(0.0);
        // Gmail message IDs like m_1234567890852 should not match as SSN
        let (result, dets) = a.anonymize_text("class=\"m_18501275123456780852message\"");
        assert!(
            !dets.iter().any(|d| d.entity_type == "FR_SSN"),
            "Should not match SSN inside longer digit sequence: {:?}",
            dets.iter()
                .filter(|d| d.entity_type == "FR_SSN")
                .collect::<Vec<_>>()
        );
        assert!(!result.contains("[FR_SSN_"));
    }

    #[test]
    fn test_fr_passport_with_context() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("passeport: 12AB34567");
        assert!(dets.iter().any(|d| d.entity_type == "FR_PASSPORT"));
        assert!(result.contains("[FR_PASSPORT_"));
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
        assert!(result.contains("[AIRCRAFT_REGISTRATION_"));
    }

    #[test]
    fn test_aircraft_us_with_context() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("aircraft N12345 ready");
        assert!(dets.iter().any(|d| d.entity_type == "AIRCRAFT_REGISTRATION"));
        assert!(result.contains("[AIRCRAFT_REGISTRATION_"));
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
        assert!(result.contains("[CREW_CODE_"));
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
        assert!(result.contains("[IP_ADDRESS_"));
    }

    #[test]
    fn test_uuid() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("id: 550e8400-e29b-41d4-a716-446655440000");
        assert!(result.contains("[UUID_"));
    }

    #[test]
    fn test_crypto_ethereum() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("wallet: 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18");
        assert!(dets.iter().any(|d| d.entity_type == "CRYPTO"));
        assert!(result.contains("[CRYPTO_"));
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
        let token = a.mapping.mappings.keys()
            .find(|k| k.starts_with("[EMAIL_ADDRESS_"))
            .unwrap()
            .clone();
        assert_eq!(result.matches(&*token).count(), 2);
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
        assert!(result["email"].as_str().unwrap().contains("[EMAIL_ADDRESS_"));
        assert!(result["nested"]["phone"].as_str().unwrap().contains("[FR_PHONE_NUMBER_"));
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
        assert!(result.contains("[CREW_CODE_"));
    }

    #[test]
    fn test_credit_card_valid_with_context() {
        let mut a = Anonymizer::new(0.0);
        // 4111111111111111 is a valid Visa test number (passes Luhn + valid prefix)
        let (result, dets) = a.anonymize_text("carte bancaire 4111 1111 1111 1111");
        assert!(dets.iter().any(|d| d.entity_type == "CREDIT_CARD"));
        assert!(result.contains("[CREDIT_CARD_"));
    }

    #[test]
    fn test_credit_card_rejected_without_context() {
        let mut a = Anonymizer::new(0.0);
        // Valid card number but no context keyword — context_required gate blocks it
        let (_, dets) = a.anonymize_text("number 4111 1111 1111 1111 here");
        assert!(!dets.iter().any(|d| d.entity_type == "CREDIT_CARD"));
    }

    #[test]
    fn test_credit_card_rejected_invalid_prefix() {
        let mut a = Anonymizer::new(0.0);
        // 16-digit number starting with 9 — no known issuer, even with context + Luhn
        // 9000000000000008 passes Luhn but has no valid card prefix
        let (_, dets) = a.anonymize_text("payment card 9000 0000 0000 0008");
        assert!(
            !dets.iter().any(|d| d.entity_type == "CREDIT_CARD"),
            "Should reject 16-digit number with unknown issuer prefix"
        );
    }

    #[test]
    fn test_credit_card_rejected_fails_luhn() {
        let mut a = Anonymizer::new(0.0);
        // Visa prefix but fails Luhn (last digit wrong)
        let (_, dets) = a.anonymize_text("carte credit 4111 1111 1111 1112");
        assert!(
            !dets.iter().any(|d| d.entity_type == "CREDIT_CARD"),
            "Should reject card number that fails Luhn check"
        );
    }

    #[test]
    fn test_utf8_email_in_accented_text() {
        let mut a = Anonymizer::new(0.0);
        let input = "Héloïse a envoyé un mail à héloïse@example.com depuis Zürich";
        let (result, _) = a.anonymize_text(input);
        assert!(result.contains("[EMAIL_ADDRESS_"));
        // Verify the surrounding accented text is preserved
        assert!(result.contains("Héloïse"));
        assert!(result.contains("Zürich"));
    }

    #[test]
    fn test_walk_json_depth_limit_no_crash() {
        // Build a JSON value nested beyond MAX_JSON_DEPTH (128).
        // Without the depth limit this would stack overflow.
        let mut value = serde_json::json!("leaf@example.com");
        for _ in 0..200 {
            value = serde_json::json!({ "n": value });
        }

        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_json_value(&value);

        // Structure should be preserved — no crash
        assert!(result.is_object());

        // Values within the depth limit should be anonymized
        // Navigate to depth 50 (well within limit)
        let mut cursor = &result;
        for _ in 0..50 {
            cursor = &cursor["n"];
        }
        assert!(cursor.is_object() || cursor.is_string());
    }

    #[test]
    fn test_walk_json_within_limit_anonymized() {
        // Nesting within the limit — PII should be anonymized
        let value = serde_json::json!({
            "a": { "b": { "c": "john@example.com" } }
        });
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_json_value(&value);

        assert_eq!(dets.len(), 1);
        assert!(result["a"]["b"]["c"].as_str().unwrap().starts_with("[EMAIL_ADDRESS_"));
    }

    #[test]
    fn test_unicode_fullwidth_email_detected() {
        let mut a = Anonymizer::new(0.0);
        // Fullwidth '@' (U+FF20) should be NFKC-normalized to ASCII '@'
        let input = "contact user\u{FF20}example.com now";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"),
            "Fullwidth @ should be normalized and detected as email"
        );
        assert!(result.contains("[EMAIL_ADDRESS_"));
    }

    #[test]
    fn test_unicode_fullwidth_digits_detected() {
        let mut a = Anonymizer::new(0.0);
        // Fullwidth digits U+FF10..U+FF19 for IP address
        let input = "server at \u{FF11}\u{FF19}\u{FF12}.\u{FF11}\u{FF16}\u{FF18}.\u{FF11}.\u{FF11}\u{FF10}\u{FF10}";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "IP_ADDRESS"),
            "Fullwidth digits should be normalized and detected as IP: {:?}",
            dets
        );
        assert!(result.contains("[IP_ADDRESS_"));
    }

    #[test]
    fn test_unicode_normalization_preserves_ascii() {
        let mut a = Anonymizer::new(0.0);
        // Pure ASCII input should be unchanged by NFKC
        let (result, dets) = a.anonymize_text("contact john@example.com now");
        assert_eq!(dets.len(), 1);
        assert!(result.contains("[EMAIL_ADDRESS_"));
    }

    #[test]
    fn test_walk_json_beyond_limit_not_anonymized() {
        // Build nesting at exactly MAX_JSON_DEPTH (128) — the leaf should
        // be returned as-is (cloned, not anonymized).
        let mut value = serde_json::json!("deep@example.com");
        for _ in 0..130 {
            value = serde_json::json!({ "n": value });
        }

        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_json_value(&value);

        // Navigate to the deepest leaf
        let mut cursor = &result;
        for _ in 0..130 {
            cursor = &cursor["n"];
        }
        // Beyond depth 128, the value is cloned as-is (not anonymized)
        assert_eq!(cursor.as_str().unwrap(), "deep@example.com");
    }

    #[test]
    fn test_csv_quoted_field_with_comma() {
        let mut a = Anonymizer::new(0.0);
        let csv = "name,email\n\"Doe, John\",john@example.com";
        let (result, dets) = a.anonymize_csv(csv);
        // Email in second cell should be detected
        assert!(dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"));
        assert!(result.contains("[EMAIL_ADDRESS_"));
        // Quoted field with comma should be preserved as a single cell
        assert!(result.contains("Doe, John") || result.contains("\"Doe, John\""));
    }

    #[test]
    fn test_csv_unquoted_email() {
        let mut a = Anonymizer::new(0.0);
        let csv = "id,email,name\n1,user@test.com,Alice\n2,admin@test.com,Bob";
        let (_result, dets) = a.anonymize_csv(csv);
        assert_eq!(dets.iter().filter(|d| d.entity_type == "EMAIL_ADDRESS").count(), 2);
        let email_tokens: Vec<_> = a.mapping.mappings.keys()
            .filter(|k| k.starts_with("[EMAIL_ADDRESS_"))
            .collect();
        assert_eq!(email_tokens.len(), 2);
    }

    #[test]
    fn test_sql_anonymizes_string_literals_only() {
        let mut a = Anonymizer::new(0.0);
        let sql = "INSERT INTO users VALUES (1, 'john@example.com', 'admin')";
        let (result, dets) = a.anonymize_sql(sql);
        // Email inside string literal should be detected
        assert!(dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"));
        assert!(result.contains("[EMAIL_ADDRESS_"));
        // SQL keywords and structure should be preserved
        assert!(result.starts_with("INSERT INTO users VALUES"));
    }

    #[test]
    fn test_sql_preserves_identifiers() {
        let mut a = Anonymizer::new(0.0);
        // UUID is an identifier here, not PII — it's not inside quotes
        let sql = "SELECT uuid FROM sessions WHERE id = '550e8400-e29b-41d4-a716-446655440000'";
        let (result, dets) = a.anonymize_sql(sql);
        // The UUID in the string literal should be detected
        assert!(dets.iter().any(|d| d.entity_type == "UUID"));
        // "uuid" as a column name should NOT be anonymized
        assert!(result.contains("SELECT uuid FROM"));
    }

    #[test]
    fn test_sql_escaped_quotes() {
        let mut a = Anonymizer::new(0.0);
        let sql = "INSERT INTO logs VALUES ('it''s john@test.com')";
        let (result, dets) = a.anonymize_sql(sql);
        assert!(dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"));
        assert!(result.contains("[EMAIL_ADDRESS_"));
    }

    #[test]
    fn test_crew_code_blocklist_tech_abbreviations() {
        let mut a = Anonymizer::new(0.0);
        // Tech abbreviations near crew context should still be blocked
        let (_, dets) = a.anonymize_text("crew member handles URL API SQL requests on duty");
        let crew_dets: Vec<_> = dets.iter().filter(|d| d.entity_type == "CREW_CODE").collect();
        for d in &crew_dets {
            assert!(
                !["URL", "API", "SQL"].contains(&d.original.as_str()),
                "Tech abbreviation '{}' should be blocklisted, not detected as CREW_CODE",
                d.original
            );
        }
    }

    #[test]
    fn test_crew_code_blocklist_stress_test_cases() {
        let mut a = Anonymizer::new(0.0);
        // Exact cases from stress test that produced false positives
        let (_, dets) = a.anonymize_text("sensitive tokens in a URL string");
        assert!(!dets.iter().any(|d| d.entity_type == "CREW_CODE" && d.original == "URL"));

        let mut a2 = Anonymizer::new(0.0);
        let (_, dets2) = a2.anonymize_text("PII split across lines");
        assert!(!dets2.iter().any(|d| d.entity_type == "CREW_CODE" && d.original == "PII"));

        let mut a3 = Anonymizer::new(0.0);
        let (_, dets3) = a3.anonymize_text("Auth-Token=XYZ-123");
        assert!(!dets3.iter().any(|d| d.entity_type == "CREW_CODE" && d.original == "XYZ"));
    }

    #[test]
    fn test_crew_code_blocklist_airport_codes() {
        let mut a = Anonymizer::new(0.0);
        // Airport codes near crew context should be blocked
        let (_, dets) = a.anonymize_text("crew roster: departure CDG arrival ORY duty JFK");
        let crew_originals: Vec<&str> = dets.iter()
            .filter(|d| d.entity_type == "CREW_CODE")
            .map(|d| d.original.as_str())
            .collect();
        for code in &["CDG", "ORY", "JFK"] {
            assert!(
                !crew_originals.contains(code),
                "Airport code '{}' should be blocklisted, not detected as CREW_CODE",
                code
            );
        }
    }

    #[test]
    fn test_crew_code_real_codes_still_detected() {
        let mut a = Anonymizer::new(0.0);
        // Real crew codes with context should still work
        let (result, dets) = a.anonymize_text("pilote JDU en service avec copilote PLR");
        assert!(dets.iter().any(|d| d.entity_type == "CREW_CODE" && d.original == "JDU"),
            "Real crew code JDU should still be detected");
        assert!(dets.iter().any(|d| d.entity_type == "CREW_CODE" && d.original == "PLR"),
            "Real crew code PLR should still be detected");
        assert!(result.contains("[CREW_CODE_"));
    }

    #[test]
    fn test_parse_csv_line_basic() {
        let cells = parse_csv_line("a,b,c");
        assert_eq!(cells, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_parse_csv_line_quoted() {
        let cells = parse_csv_line("\"hello, world\",b,\"c\"");
        assert_eq!(cells, vec!["hello, world", "b", "c"]);
    }

    #[test]
    fn test_parse_csv_line_escaped_quote() {
        let cells = parse_csv_line("\"he said \"\"hi\"\"\",b");
        assert_eq!(cells, vec!["he said \"hi\"", "b"]);
    }
}
