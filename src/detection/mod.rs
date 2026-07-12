use std::borrow::Cow;
use std::collections::HashSet;

use regex::{Regex, RegexBuilder};
use serde_json::Value;

use crate::config::RecognizerConfigFile;
use crate::csv::{parse_csv_document, serialize_csv_field};
use crate::mapping::Mapping;
use crate::ner::{NerDetector, NerSpan};
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

    /// Add custom patterns from a YAML config file to the pattern list.
    ///
    /// Custom patterns are appended to the built-in patterns and participate
    /// in the same detection, context matching, and overlap resolution pipeline.
    pub fn add_custom_patterns(&mut self, config: &RecognizerConfigFile) {
        for recognizer in &config.recognizers {
            // Leak the strings to get 'static lifetime (safe because configs are loaded once)
            let entity_type: &'static str =
                Box::leak(recognizer.entity_type.clone().into_boxed_str());
            let name: &'static str = Box::leak(recognizer.name.clone().into_boxed_str());

            // Leak context keywords
            let keywords: Vec<&'static str> = recognizer
                .context_keywords
                .iter()
                .map(|s| -> &'static str { Box::leak(s.clone().into_boxed_str()) })
                .collect();
            let keywords_slice: &'static [&'static str] = Box::leak(keywords.into_boxed_slice());

            for pattern in &recognizer.patterns {
                // Build regex with the same size limit as config validation
                let regex = RegexBuilder::new(&pattern.regex)
                    .size_limit(1 << 20)
                    .build()
                    .expect("regex already validated in config loader");

                self.patterns.push(CompiledPattern {
                    entity_type: Cow::Borrowed(entity_type),
                    name: Cow::Borrowed(name),
                    regex,
                    score: pattern.score,
                    context_keywords: Cow::Borrowed(keywords_slice),
                    context_required: recognizer.context_required,
                });
            }
        }
    }

    /// Get all unique entity types from the pattern list.
    ///
    /// Includes both built-in and custom entity types.
    pub fn get_entity_types(&self) -> Vec<&str> {
        let mut seen = HashSet::new();
        self.patterns
            .iter()
            .filter_map(|p| {
                let entity_type = p.entity_type.as_ref();
                if seen.insert(entity_type) {
                    Some(entity_type)
                } else {
                    None
                }
            })
            .collect()
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

    /// Anonymize CSV content cell-by-cell while preserving its source structure.
    /// Unchanged fields, delimiters, and line endings are copied byte-for-byte.
    pub fn anonymize_csv(&mut self, text: &str) -> (String, Vec<Detection>) {
        let Some(document) = parse_csv_document(text) else {
            return (text.to_string(), Vec::new());
        };

        let mut all_detections = Vec::new();
        let mut output = String::with_capacity(text.len());
        let mut copied_until = 0;

        for record in document.records {
            for field in record.fields {
                output.push_str(&text[copied_until..field.start]);
                let value = field.value(text);
                let (anonymized, dets) = self.anonymize_text(&value);
                let changed = self.operator != Operator::Keep
                    && !dets.is_empty()
                    && anonymized != value.as_ref();
                all_detections.extend(dets);

                if changed {
                    output.push_str(&serialize_csv_field(&anonymized, field.quoted));
                } else {
                    output.push_str(&text[field.start..field.end]);
                }
                copied_until = field.end;
            }
        }
        output.push_str(&text[copied_until..]);

        (output, all_detections)
    }

    /// Anonymize SQL content by processing single-quoted and PostgreSQL
    /// dollar-quoted string literals. Identifiers, comments, keywords, and
    /// non-string content are preserved as-is.
    pub fn anonymize_sql(&mut self, text: &str) -> (String, Vec<Detection>) {
        let mut all_detections = Vec::new();
        let mut output = String::with_capacity(text.len());
        let bytes = text.as_bytes();
        let mut cursor = 0;
        let mut copied_until = 0;

        while cursor < bytes.len() {
            // Skip comments and quoted identifiers. Apostrophes inside these
            // regions are source text, not SQL string-literal delimiters.
            if bytes[cursor] == b'-' && bytes.get(cursor + 1) == Some(&b'-') {
                cursor += 2;
                while cursor < bytes.len() && bytes[cursor] != b'\n' {
                    cursor += 1;
                }
                continue;
            }
            if bytes[cursor] == b'/' && bytes.get(cursor + 1) == Some(&b'*') {
                cursor += 2;
                while cursor + 1 < bytes.len()
                    && !(bytes[cursor] == b'*' && bytes[cursor + 1] == b'/')
                {
                    cursor += 1;
                }
                cursor = (cursor + 2).min(bytes.len());
                continue;
            }
            if matches!(bytes[cursor], b'"' | b'`') {
                let delimiter = bytes[cursor];
                cursor += 1;
                while cursor < bytes.len() {
                    if bytes[cursor] == delimiter {
                        if bytes.get(cursor + 1) == Some(&delimiter) {
                            cursor += 2;
                        } else {
                            cursor += 1;
                            break;
                        }
                    } else {
                        cursor += 1;
                    }
                }
                continue;
            }
            if bytes[cursor] == b'$' {
                let delimiter_end = if bytes.get(cursor + 1) == Some(&b'$') {
                    Some(cursor + 2)
                } else {
                    let mut end = cursor + 1;
                    if bytes
                        .get(end)
                        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
                    {
                        end += 1;
                        while bytes
                            .get(end)
                            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                        {
                            end += 1;
                        }
                        (bytes.get(end) == Some(&b'$')).then_some(end + 1)
                    } else {
                        None
                    }
                };

                if let Some(delimiter_end) = delimiter_end {
                    let delimiter = &text[cursor..delimiter_end];
                    let content_start = delimiter_end;
                    let Some(relative_end) = text[content_start..].find(delimiter) else {
                        break;
                    };
                    let content_end = content_start + relative_end;
                    let literal_end = content_end + delimiter.len();
                    let literal = &text[content_start..content_end];
                    let (anonymized, dets) = self.anonymize_text(literal);
                    let changed = self.operator != Operator::Keep
                        && !dets.is_empty()
                        && anonymized != literal;
                    all_detections.extend(dets);

                    if changed {
                        output.push_str(&text[copied_until..cursor]);
                        if anonymized.contains(delimiter) {
                            output.push('\'');
                            output.push_str(&anonymized.replace('\'', "''"));
                            output.push('\'');
                        } else {
                            output.push_str(delimiter);
                            output.push_str(&anonymized);
                            output.push_str(delimiter);
                        }
                        copied_until = literal_end;
                    }
                    cursor = literal_end;
                    continue;
                }
            }
            if bytes[cursor] != b'\'' {
                cursor += 1;
                continue;
            }

            let literal_start = cursor;
            let backslash_escapes = sql_uses_backslash_escapes(text, literal_start);
            cursor += 1;
            let content_start = cursor;
            let mut closed_at = None;
            while cursor < bytes.len() {
                if backslash_escapes
                    && bytes[cursor] == b'\\'
                    && matches!(bytes.get(cursor + 1), Some(b'\\' | b'\''))
                {
                    cursor += 2;
                } else if bytes[cursor] == b'\'' {
                    if bytes.get(cursor + 1) == Some(&b'\'') {
                        cursor += 2;
                    } else {
                        closed_at = Some(cursor);
                        break;
                    }
                } else {
                    cursor += 1;
                }
            }

            // Invalid SQL is left byte-identical. In particular, never invent a
            // closing quote for an unterminated literal.
            let Some(content_end) = closed_at else {
                break;
            };

            let raw_literal = &text[content_start..content_end];
            // For PostgreSQL E-strings, keep the original escape spelling when
            // the selected operator cannot introduce quote/backslash syntax.
            // This makes the default token round trip byte-exact instead of
            // canonicalizing `\'` to `''` as a side effect.
            let preserve_e_string_spelling = backslash_escapes
                && match self.operator {
                    Operator::Token
                    | Operator::Redact
                    | Operator::Keep
                    | Operator::Hash
                    | Operator::Encrypt => true,
                    Operator::Mask => !matches!(self.mask_config.mask_char, '\'' | '\\'),
                    Operator::Custom => self.replace_with.as_deref().is_some_and(|replacement| {
                        !replacement.contains('\'') && !replacement.contains('\\')
                    }),
                };
            let literal = if preserve_e_string_spelling {
                Cow::Borrowed(raw_literal)
            } else {
                Cow::Owned(decode_sql_single_quoted(raw_literal, backslash_escapes))
            };
            let (anonymized, dets) = self.anonymize_text(&literal);
            let changed = self.operator != Operator::Keep
                && !dets.is_empty()
                && anonymized != literal.as_ref();
            all_detections.extend(dets);

            if changed {
                output.push_str(&text[copied_until..literal_start]);
                output.push('\'');
                if preserve_e_string_spelling {
                    output.push_str(&anonymized);
                } else {
                    output.push_str(&anonymized.replace('\'', "''"));
                }
                output.push('\'');
                copied_until = content_end + 1;
            }
            cursor = content_end + 1;
        }

        output.push_str(&text[copied_until..]);

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
                    .map(|(k, v)| (k.clone(), self.walk_json(v, detections, depth + 1)))
                    .collect();
                Value::Object(new_map)
            }
            other => other.clone(),
        }
    }

    /// Anonymize multiple texts in a batch, using batched NER inference for efficiency.
    ///
    /// This method produces identical results to calling `anonymize_text()` N times,
    /// but batches NER inference across all texts for better performance when NER is enabled.
    ///
    /// - Regex detection runs per-text (already fast)
    /// - NER detection uses `detect_persons_batch()` for efficient batched inference
    /// - Overlap resolution, name consistency, and replacement run per-text
    pub fn anonymize_texts(&mut self, texts: &[&str]) -> Vec<(String, Vec<Detection>)> {
        if texts.is_empty() {
            return Vec::new();
        }

        // Get batch NER results upfront if NER is enabled
        let batch_ner_results: Option<Vec<Vec<NerSpan>>> = self
            .ner_detector
            .as_ref()
            .map(|ner| ner.detect_persons_batch(texts));

        // Process each text
        let mut results = Vec::with_capacity(texts.len());
        for (i, text) in texts.iter().enumerate() {
            // Temporarily swap in a cached NER detector if we have batch results
            let cached_spans = batch_ner_results.as_ref().map(|r| r[i].clone());
            let original_detector = if cached_spans.is_some() {
                self.ner_detector.take()
            } else {
                None
            };

            if let Some(spans) = cached_spans {
                self.ner_detector = Some(Box::new(CachedNerDetector { spans }));
            }

            let result = self.anonymize_text(text);

            // Restore original detector
            if original_detector.is_some() {
                self.ner_detector = original_detector;
            }

            results.push(result);
        }

        results
    }
}

/// Internal NER detector that returns pre-computed cached spans.
/// Used by `anonymize_texts` to inject batch NER results into individual text processing.
struct CachedNerDetector {
    spans: Vec<NerSpan>,
}

impl NerDetector for CachedNerDetector {
    fn detect_persons(&self, _text: &str) -> Vec<NerSpan> {
        self.spans.clone()
    }
}

fn sql_uses_backslash_escapes(source: &str, quote_start: usize) -> bool {
    let prefix = &source.as_bytes()[..quote_start];
    let Some((&marker, before_marker)) = prefix.split_last() else {
        return false;
    };
    if !matches!(marker, b'E' | b'e') {
        return false;
    }
    before_marker
        .last()
        .is_none_or(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'_' | b'$'))
}

fn decode_sql_single_quoted(raw: &str, backslash_escapes: bool) -> String {
    let mut decoded = String::with_capacity(raw.len());
    let mut characters = raw.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\'' && characters.peek() == Some(&'\'') {
            characters.next();
            decoded.push('\'');
        } else if backslash_escapes
            && character == '\\'
            && matches!(characters.peek(), Some('\'' | '\\'))
        {
            decoded.push(characters.next().expect("peeked SQL escape"));
        } else {
            decoded.push(character);
        }
    }
    decoded
}

#[cfg(test)]
mod tests;
