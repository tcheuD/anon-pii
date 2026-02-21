use clap::ValueEnum;
use regex::Regex;
use serde_json::Value;
use unicode_normalization::UnicodeNormalization;

use crate::mapping::Mapping;
use crate::ner::{NerDetector, PERSON_BLOCKLIST};
use crate::patterns::{
    iban_mod97, luhn_check, valid_aba_routing, valid_au_abn, valid_au_acn, valid_au_medicare,
    valid_au_tfn, valid_card_prefix, valid_es_nie, valid_es_nif, valid_in_aadhaar, valid_in_gstin,
    valid_it_fiscal_code, valid_kr_brn, valid_kr_frn, valid_kr_rrn, valid_mac, valid_uk_nhs,
    valid_uk_nino, valid_us_itin, valid_us_ssn, CONTEXT_SCORE_BOOST, CONTEXT_WINDOW,
    CREW_CODE_BLOCKLIST, PATTERNS,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum Operator {
    /// Replace PII with tokens like [EMAIL_ADDRESS_a1b2c3d4] (default)
    #[default]
    Token,
    /// Remove PII entirely (empty string)
    Redact,
    /// Keep original PII unchanged (detection-only / dry-run)
    Keep,
    /// Replace PII with masking characters (e.g. *****)
    Mask,
}

#[derive(Clone, Copy, Debug)]
pub struct MaskConfig {
    pub mask_char: char,
    pub fixed_count: Option<usize>,
    pub from_end: bool,
}

impl Default for MaskConfig {
    fn default() -> Self {
        Self {
            mask_char: '*',
            fixed_count: None,
            from_end: false,
        }
    }
}

fn apply_mask(value: &str, config: &MaskConfig) -> String {
    let char_count = value.chars().count();
    let mask_len = config.fixed_count.unwrap_or(char_count);
    if config.from_end {
        let visible = char_count.saturating_sub(mask_len);
        let prefix: String = value.chars().take(visible).collect();
        format!(
            "{}{}",
            prefix,
            config.mask_char.to_string().repeat(char_count - visible)
        )
    } else {
        let visible = char_count.saturating_sub(mask_len);
        let suffix: String = value.chars().skip(char_count - visible).collect();
        format!(
            "{}{}",
            config.mask_char.to_string().repeat(char_count - visible),
            suffix
        )
    }
}

/// Strip Unicode diacritics: "Gaël" → "Gael", "René" → "Rene".
/// Uses NFD decomposition and removes combining marks.
fn strip_diacritics(s: &str) -> String {
    s.nfd()
        .filter(|c| !unicode_normalization::char::is_combining_mark(*c))
        .collect()
}

/// Patterns that may span across line breaks in wrapped log output.
const MULTILINE_ENTITY_TYPES: &[&str] = &["CREDIT_CARD", "FR_IBAN"];

/// Collapse `\s*\n\s*` sequences into a single space and build a mapping from
/// collapsed byte offsets back to original byte offsets. Returns `None` when the
/// input contains no newlines (no work to do).
fn collapse_newlines(text: &str) -> Option<(String, Vec<usize>)> {
    if !text.contains('\n') {
        return None;
    }
    let mut collapsed = String::with_capacity(text.len());
    // Maps each byte index in `collapsed` to the corresponding byte index in `text`.
    let mut pos_map: Vec<usize> = Vec::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Detect whitespace runs containing a newline and collapse to one space.
        if bytes[i].is_ascii_whitespace() {
            let run_start = i;
            let mut found_newline = bytes[i] == b'\n';
            let mut j = i + 1;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                if bytes[j] == b'\n' {
                    found_newline = true;
                }
                j += 1;
            }
            if found_newline {
                collapsed.push(' ');
                pos_map.push(run_start);
                i = j;
            } else {
                // Whitespace run without a newline — keep as-is.
                while i < j {
                    collapsed.push(bytes[i] as char);
                    pos_map.push(i);
                    i += 1;
                }
            }
        } else {
            collapsed.push(bytes[i] as char);
            pos_map.push(i);
            i += 1;
        }
    }
    Some((collapsed, pos_map))
}

/// Decode JSON-style `\uXXXX` escape sequences into their UTF-8 equivalents.
/// Only decodes BMP codepoints (U+0000..U+FFFF). Malformed sequences are left as-is.
fn decode_unicode_escapes(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' && chars.peek() == Some(&'u') {
            chars.next(); // consume 'u'
            let mut hex = String::with_capacity(4);
            for _ in 0..4 {
                match chars.peek() {
                    Some(&h) if h.is_ascii_hexdigit() => {
                        hex.push(h);
                        chars.next();
                    }
                    _ => break,
                }
            }
            if hex.len() == 4 {
                if let Ok(cp) = u32::from_str_radix(&hex, 16) {
                    if let Some(decoded) = char::from_u32(cp) {
                        result.push(decoded);
                        continue;
                    }
                }
            }
            // Malformed — emit the original characters
            result.push('\\');
            result.push('u');
            result.push_str(&hex);
        } else {
            result.push(c);
        }
    }
    result
}

/// Decode URL percent-encoded sequences (`%XX`) into their UTF-8 equivalents.
/// Only decodes valid two-hex-digit sequences for ASCII-range bytes (0x00-0x7F).
/// Malformed sequences and non-ASCII encodings are left as-is.
fn decode_percent_encoding(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let remaining: String = chars.as_str().chars().take(2).collect();
            if remaining.len() == 2 && remaining.chars().all(|h| h.is_ascii_hexdigit()) {
                let val =
                    (hex_val(remaining.as_bytes()[0]) << 4) | hex_val(remaining.as_bytes()[1]);
                if val < 0x80 {
                    result.push(val as char);
                    chars.nth(1); // skip the two hex chars
                    continue;
                }
            }
            result.push('%');
        } else {
            result.push(c);
        }
    }
    result
}

fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

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

/// Build a sorted mapping from stripped byte offset → original byte offset.
/// Each entry is (stripped_byte, orig_byte) at char boundaries.
fn build_byte_offset_map(original: &str) -> Vec<(usize, usize)> {
    let mut map = Vec::with_capacity(original.len());
    let mut stripped_offset = 0;
    for (orig_offset, ch) in original.char_indices() {
        map.push((stripped_offset, orig_offset));
        let mut ch_stripped_len = 0;
        unicode_normalization::char::decompose_canonical(ch, |nfd_ch| {
            if !unicode_normalization::char::is_combining_mark(nfd_ch) {
                ch_stripped_len += nfd_ch.len_utf8();
            }
        });
        stripped_offset += ch_stripped_len;
    }
    map.push((stripped_offset, original.len()));
    map
}

/// Map a stripped byte offset back to the original byte offset using binary search.
fn stripped_to_original_offset(map: &[(usize, usize)], stripped_offset: usize) -> Option<usize> {
    match map.binary_search_by_key(&stripped_offset, |&(s, _)| s) {
        Ok(i) => Some(map[i].1),
        Err(i) if i > 0 && i < map.len() => Some(map[i].1),
        _ => None,
    }
}

/// Check if a word looks like a name component: ALL-CAPS ("DUPONT") or Title-case ("Kowalski").
fn is_name_like_word(word: &str) -> bool {
    if word.len() < 2 {
        return false;
    }
    let mut chars = word.chars();
    let first = match chars.next() {
        Some(c) => c,
        None => return false,
    };
    if !first.is_uppercase() {
        return false;
    }
    // ALL-CAPS: every char is uppercase, hyphen, or apostrophe
    let all_upper = word
        .chars()
        .all(|c| c.is_uppercase() || c == '-' || c == '\'');
    if all_upper {
        return true;
    }
    // Title-case: first char uppercase, rest are lowercase/hyphen/apostrophe
    // (with uppercase allowed after hyphen for compound names like "Le-Goff")
    chars.all(|c| c.is_lowercase() || c == '-' || c == '\'')
}

/// Extend a PERSON span to include following name-like words (ALL-CAPS or Title-case).
/// e.g. if NER detected "Damien" at end=6, and text continues with " DUPONT" or " Kowalski",
/// extend to "Damien DUPONT" or "Damien Kowalski".
fn extend_person_span(text: &str, span_text: &str, span_end: usize) -> (String, usize) {
    let mut end = span_end;
    let mut result = span_text.to_string();
    // Only look at remaining text on the same line (don't cross newlines)
    let remaining = &text[end..];
    let same_line = remaining.split('\n').next().unwrap_or("");

    for word in same_line.split_whitespace().take(2) {
        let trimmed = word.trim_end_matches(|c: char| c.is_ascii_punctuation());
        if is_name_like_word(trimmed)
            && !PERSON_BLOCKLIST
                .iter()
                .any(|&b| b.eq_ignore_ascii_case(trimmed))
            && !CREW_CODE_BLOCKLIST.contains(&trimmed)
        {
            // Find the actual position of this word in the remaining text
            if let Some(word_offset) = text[end..].find(trimmed) {
                end = end + word_offset + trimmed.len();
                result = text[span_end - span_text.len()..end].to_string();
            } else {
                break;
            }
        } else {
            break;
        }
    }

    (result, end)
}

pub struct Anonymizer {
    pub patterns: Vec<CompiledPattern>,
    pub mapping: Mapping,
    pub threshold: f64,
    pub operator: Operator,
    pub mask_config: MaskConfig,
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
            operator: Operator::default(),
            mask_config: MaskConfig::default(),
            ner_detector: None,
        }
    }

    pub fn set_ner_detector(&mut self, detector: Box<dyn NerDetector>) {
        self.ner_detector = Some(detector);
    }

    fn has_context(&self, text: &str, start: usize, end: usize, keywords: &[&str]) -> bool {
        if keywords.is_empty() {
            return false;
        }
        // 1. Local window check (fast path)
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
        if keywords.iter().any(|kw| lower.contains(*kw)) {
            return true;
        }
        // 2. Column-header check: find the column offset of the match on its
        //    line, then scan upward for a header line that has a keyword at a
        //    similar column position.
        self.has_column_header_context(text, start, keywords)
    }

    /// Look above the match for a header line where a keyword sits at the same
    /// column position (±4 chars) as the match.
    fn has_column_header_context(&self, text: &str, start: usize, keywords: &[&str]) -> bool {
        // Find the line containing the match and its column offset.
        let line_start = text[..start].rfind('\n').map_or(0, |p| p + 1);
        let col = start - line_start;

        // Scan up to 20 lines above for a header line.
        let prefix = &text[..line_start];
        let lines_above: Vec<&str> = prefix.lines().rev().take(20).collect();

        for header_line in &lines_above {
            let header_lower = header_line.to_lowercase();
            for kw in keywords {
                if let Some(kw_pos) = header_lower.find(kw) {
                    // Check if the keyword column overlaps with the match column (±4 chars tolerance)
                    let kw_end = kw_pos + kw.len();
                    if col + 4 >= kw_pos && col <= kw_end + 4 {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Search for bare occurrences of a name part in text. Exact match first,
    /// then accent-insensitive via pre-computed stripped text + offset map.
    fn find_bare_name_occurrences(
        text: &str,
        name: &str,
        stripped_text: &str,
        offset_map: &[(usize, usize)],
        detections: &mut Vec<Detection>,
    ) {
        // Exact match pass
        Self::find_name_at_word_boundaries(text, name, detections);

        // Accent-insensitive pass (only if stripping changes the name)
        let stripped_name = strip_diacritics(name);
        if stripped_name != name {
            Self::find_name_in_stripped_text(
                text,
                stripped_text,
                &stripped_name,
                offset_map,
                detections,
            );
        }
    }

    fn find_name_at_word_boundaries(text: &str, search: &str, detections: &mut Vec<Detection>) {
        let mut search_from = 0;
        while let Some(pos) = text[search_from..].find(search) {
            let abs_pos = search_from + pos;
            let abs_end = abs_pos + search.len();

            let at_word_start =
                abs_pos == 0 || !text[..abs_pos].chars().last().unwrap().is_alphanumeric();
            let at_word_end =
                abs_end >= text.len() || !text[abs_end..].chars().next().unwrap().is_alphanumeric();

            if at_word_start && at_word_end {
                let already_covered = detections
                    .iter()
                    .any(|d| d.start <= abs_pos && d.end >= abs_end);
                if !already_covered {
                    detections.push(Detection {
                        entity_type: "PERSON",
                        original: search.to_string(),
                        start: abs_pos,
                        end: abs_end,
                        score: 0.50,
                    });
                }
            }

            search_from = abs_pos + search.len();
        }
    }

    /// Find accent-stripped name in text using pre-computed stripped text and offset map.
    fn find_name_in_stripped_text(
        original_text: &str,
        stripped_text: &str,
        stripped_name: &str,
        offset_map: &[(usize, usize)],
        detections: &mut Vec<Detection>,
    ) {
        let mut search_from = 0;
        while let Some(pos) = stripped_text[search_from..].find(stripped_name) {
            let stripped_start = search_from + pos;
            let stripped_end = stripped_start + stripped_name.len();

            let orig_start = stripped_to_original_offset(offset_map, stripped_start);
            let orig_end = stripped_to_original_offset(offset_map, stripped_end);

            if let (Some(abs_pos), Some(abs_end)) = (orig_start, orig_end) {
                let at_word_start = abs_pos == 0
                    || !original_text[..abs_pos]
                        .chars()
                        .last()
                        .unwrap()
                        .is_alphanumeric();
                let at_word_end = abs_end >= original_text.len()
                    || !original_text[abs_end..]
                        .chars()
                        .next()
                        .unwrap()
                        .is_alphanumeric();

                if at_word_start && at_word_end {
                    let already_covered = detections
                        .iter()
                        .any(|d| d.start <= abs_pos && d.end >= abs_end);
                    if !already_covered {
                        let matched_text = &original_text[abs_pos..abs_end];
                        detections.push(Detection {
                            entity_type: "PERSON",
                            original: matched_text.to_string(),
                            start: abs_pos,
                            end: abs_end,
                            score: 0.50,
                        });
                    }
                }
            }

            search_from = stripped_end;
        }
    }

    pub fn anonymize_text(&mut self, text: &str) -> (String, Vec<Detection>) {
        // NFKC normalization converts fullwidth digits, confusable homoglyphs,
        // and other Unicode variants to their canonical ASCII equivalents so
        // that regex patterns match consistently.
        let normalized: String = text.nfkc().collect();
        // Decode JSON-style \uXXXX escape sequences (e.g. \u0040 → @) so that
        // PII hidden behind unicode escapes in log lines is detected.
        let normalized = decode_unicode_escapes(&normalized);
        // Decode URL percent-encoding (e.g. %40 → @) so that PII in HTTP
        // access log query strings is detected.
        let normalized = decode_percent_encoding(&normalized);
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
                if pat.entity_type == "IBAN_CODE" && !iban_mod97(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "MAC_ADDRESS" && !valid_mac(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "US_SSN" && !valid_us_ssn(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "US_ITIN" && !valid_us_itin(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "ABA_ROUTING" && !valid_aba_routing(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "UK_NHS" && !valid_uk_nhs(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "UK_NINO" && !valid_uk_nino(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "ES_NIF" && !valid_es_nif(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "ES_NIE" && !valid_es_nie(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "IT_FISCAL_CODE" && !valid_it_fiscal_code(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "IN_AADHAAR" && !valid_in_aadhaar(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "IN_GSTIN" && !valid_in_gstin(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "AU_ABN" && !valid_au_abn(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "AU_ACN" && !valid_au_acn(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "AU_TFN" && !valid_au_tfn(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "AU_MEDICARE" && !valid_au_medicare(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "KR_RRN" && !valid_kr_rrn(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "KR_FRN" && !valid_kr_frn(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "KR_BRN" && !valid_kr_brn(mat.as_str()) {
                    continue;
                }

                // Compute detection score with optional context boost
                let detection_score =
                    if !pat.context_required && !pat.context_keywords.is_empty() && has_ctx {
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

        // Multiline second pass: collapse whitespace+newline runs into a single
        // space and re-run patterns that can span line breaks (credit cards, IBANs).
        // Detections are mapped back to original byte positions.
        if let Some((collapsed, pos_map)) = collapse_newlines(text) {
            for pat in &self.patterns {
                if !MULTILINE_ENTITY_TYPES.contains(&pat.entity_type) {
                    continue;
                }
                let max_score = if !pat.context_keywords.is_empty() && !pat.context_required {
                    (pat.score + CONTEXT_SCORE_BOOST).min(1.0)
                } else {
                    pat.score
                };
                if max_score < self.threshold {
                    continue;
                }
                for mat in pat.regex.find_iter(&collapsed) {
                    // Only consider matches that actually span a newline
                    let orig_start = pos_map[mat.start()];
                    let orig_end_idx = (mat.end() - 1).min(pos_map.len() - 1);
                    let orig_end_byte = pos_map[orig_end_idx];
                    let orig_span = &text[orig_start..=orig_end_byte];
                    if !orig_span.contains('\n') {
                        continue; // Already found by the single-line pass
                    }

                    // Compute original end as one past the last byte
                    let orig_end = if mat.end() < pos_map.len() {
                        pos_map[mat.end()]
                    } else {
                        text.len()
                    };

                    let matched = mat.as_str();

                    if pat.entity_type == "CREDIT_CARD"
                        && (!luhn_check(matched) || !valid_card_prefix(matched))
                    {
                        continue;
                    }
                    if pat.entity_type == "IBAN_CODE" && !iban_mod97(matched) {
                        continue;
                    }
                    if pat.entity_type == "MAC_ADDRESS" && !valid_mac(matched) {
                        continue;
                    }
                    if pat.entity_type == "US_SSN" && !valid_us_ssn(matched) {
                        continue;
                    }
                    if pat.entity_type == "US_ITIN" && !valid_us_itin(matched) {
                        continue;
                    }
                    if pat.entity_type == "ABA_ROUTING" && !valid_aba_routing(matched) {
                        continue;
                    }
                    if pat.entity_type == "UK_NHS" && !valid_uk_nhs(matched) {
                        continue;
                    }
                    if pat.entity_type == "UK_NINO" && !valid_uk_nino(matched) {
                        continue;
                    }
                    if pat.entity_type == "ES_NIF" && !valid_es_nif(matched) {
                        continue;
                    }
                    if pat.entity_type == "ES_NIE" && !valid_es_nie(matched) {
                        continue;
                    }
                    if pat.entity_type == "IT_FISCAL_CODE" && !valid_it_fiscal_code(matched) {
                        continue;
                    }
                    if pat.entity_type == "IN_AADHAAR" && !valid_in_aadhaar(matched) {
                        continue;
                    }
                    if pat.entity_type == "IN_GSTIN" && !valid_in_gstin(matched) {
                        continue;
                    }
                    if pat.entity_type == "AU_ABN" && !valid_au_abn(matched) {
                        continue;
                    }
                    if pat.entity_type == "AU_ACN" && !valid_au_acn(matched) {
                        continue;
                    }
                    if pat.entity_type == "AU_TFN" && !valid_au_tfn(matched) {
                        continue;
                    }
                    if pat.entity_type == "AU_MEDICARE" && !valid_au_medicare(matched) {
                        continue;
                    }
                    if pat.entity_type == "KR_RRN" && !valid_kr_rrn(matched) {
                        continue;
                    }
                    if pat.entity_type == "KR_FRN" && !valid_kr_frn(matched) {
                        continue;
                    }
                    if pat.entity_type == "KR_BRN" && !valid_kr_brn(matched) {
                        continue;
                    }

                    let has_ctx = if !pat.context_keywords.is_empty() {
                        self.has_context(text, orig_start, orig_end, pat.context_keywords)
                    } else {
                        false
                    };
                    if pat.context_required && !pat.context_keywords.is_empty() && !has_ctx {
                        continue;
                    }
                    let detection_score =
                        if !pat.context_required && !pat.context_keywords.is_empty() && has_ctx {
                            (pat.score + CONTEXT_SCORE_BOOST).min(1.0)
                        } else {
                            pat.score
                        };
                    if detection_score < self.threshold {
                        continue;
                    }

                    detections.push(Detection {
                        entity_type: pat.entity_type,
                        original: matched.to_string(),
                        start: orig_start,
                        end: orig_end,
                        score: detection_score,
                    });
                }
            }
        }

        // Inject NER-based PERSON and LOCATION detections
        if let Some(ref ner) = self.ner_detector {
            for span in ner.detect_persons(text) {
                if span.score >= self.threshold {
                    let trimmed = span.text.trim();
                    let is_person = span.label == "PERSON" || span.label == "PER";
                    let is_location = span.label == "LOCATION" || span.label == "LOC";

                    if is_person {
                        if PERSON_BLOCKLIST.contains(&trimmed) {
                            continue;
                        }
                        let (ext_text, ext_end) = extend_person_span(text, &span.text, span.end);
                        detections.push(Detection {
                            entity_type: "PERSON",
                            original: ext_text,
                            start: span.start,
                            end: ext_end,
                            score: span.score,
                        });
                    } else if is_location {
                        detections.push(Detection {
                            entity_type: "LOCATION",
                            original: span.text.clone(),
                            start: span.start,
                            end: span.end,
                            score: span.score,
                        });
                    }
                }
            }
        }

        // Sign-off name detection: find names after common closing salutations.
        // Catches nicknames and informal names like "Best regards,\nPrzemek".
        {
            static SIGNOFF_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
                Regex::new(
                    r"(?im)(?:best\s+regards|regards|brgds|brds|cordialement|cdlt|bien\s+[àa]\s+vous|sincerely|cheers|merci|thanks)[,.]?\s*\n?\s*([A-Z\p{Lu}][\p{L}'-]+)"
                ).unwrap()
            });
            for cap in SIGNOFF_RE.captures_iter(text) {
                if let Some(name_match) = cap.get(1) {
                    let name = name_match.as_str();
                    if name.len() >= 2
                        && is_name_like_word(name)
                        && !PERSON_BLOCKLIST
                            .iter()
                            .any(|&b| b.eq_ignore_ascii_case(name))
                    {
                        let already_covered = detections
                            .iter()
                            .any(|d| d.start <= name_match.start() && d.end >= name_match.end());
                        if !already_covered {
                            detections.push(Detection {
                                entity_type: "PERSON",
                                original: name.to_string(),
                                start: name_match.start(),
                                end: name_match.end(),
                                score: 0.60,
                            });
                        }
                    }
                }
            }
        }

        // Name consistency pass: if "Gaël FONTAINE" was detected as PERSON,
        // also detect bare "Gaël" and "FONTAINE" elsewhere in the text.
        // Uses accent-insensitive matching so "Gael" is caught when "Gaël" was detected.
        {
            let mut name_parts: Vec<String> = Vec::new();
            for d in detections
                .iter()
                .filter(|d| d.entity_type == "PERSON" && d.original.contains(' '))
            {
                let words: Vec<&str> = d.original.split_whitespace().collect();
                // First name
                if let Some(first) = words.first() {
                    if first.len() >= 2 {
                        name_parts.push(first.to_string());
                    }
                }
                // Last name(s) — at least 3 chars to avoid false positives
                for word in words.iter().skip(1) {
                    if word.len() >= 3 {
                        name_parts.push(word.to_string());
                    }
                }
            }
            name_parts.sort();
            name_parts.dedup();

            // Pre-compute stripped text and offset map once for accent-insensitive matching
            let stripped_text = strip_diacritics(text);
            let offset_map = build_byte_offset_map(text);

            for name_part in &name_parts {
                Self::find_bare_name_occurrences(
                    text,
                    name_part,
                    &stripped_text,
                    &offset_map,
                    &mut detections,
                );
            }
        }

        // Drop PASSWORD detections that fully contain a more specific detection
        // (e.g., PASSWORD wrapping a SECRET_KEY or AUTH_TOKEN value).
        if detections.iter().any(|d| d.entity_type == "PASSWORD") {
            let specific_spans: Vec<(usize, usize)> = detections
                .iter()
                .filter(|d| d.entity_type != "PASSWORD")
                .map(|d| (d.start, d.end))
                .collect();
            if !specific_spans.is_empty() {
                detections.retain(|det| {
                    if det.entity_type != "PASSWORD" {
                        return true;
                    }
                    !specific_spans
                        .iter()
                        .any(|&(s, e)| s >= det.start && e <= det.end)
                });
            }
        }

        // Sort by position asc, then span length desc, then score desc
        // Matches Python/Presidio overlap resolution: position-first
        detections.sort_by(|a, b| {
            a.start
                .cmp(&b.start)
                .then_with(|| (b.end - b.start).cmp(&(a.end - a.start)))
                .then_with(|| {
                    b.score
                        .partial_cmp(&a.score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
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

        // Extract inner PII from URL query parameters for audit visibility.
        // These are reported in the detection list but not used for replacement
        // (the entire URL is already masked as [URL_...]).
        let mut url_inner_detections: Vec<Detection> = Vec::new();
        for det in &filtered {
            if det.entity_type == "URL" {
                if let Some(qpos) = det.original.find('?') {
                    let query = &det.original[qpos + 1..];
                    for param in query.split('&') {
                        if let Some(eq) = param.find('=') {
                            let value = &param[eq + 1..];
                            if value.is_empty() {
                                continue;
                            }
                            let decoded = decode_percent_encoding(value);
                            for pat in &self.patterns {
                                if pat.entity_type == "URL" {
                                    continue;
                                }
                                for mat in pat.regex.find_iter(&decoded) {
                                    if pat.entity_type == "CREDIT_CARD"
                                        && (!luhn_check(mat.as_str())
                                            || !valid_card_prefix(mat.as_str()))
                                    {
                                        continue;
                                    }
                                    if pat.entity_type == "IBAN_CODE" && !iban_mod97(mat.as_str()) {
                                        continue;
                                    }
                                    if pat.entity_type == "CREW_CODE"
                                        && CREW_CODE_BLOCKLIST.contains(&mat.as_str())
                                    {
                                        continue;
                                    }
                                    if pat.entity_type == "US_ITIN" && !valid_us_itin(mat.as_str())
                                    {
                                        continue;
                                    }
                                    if pat.entity_type == "ABA_ROUTING"
                                        && !valid_aba_routing(mat.as_str())
                                    {
                                        continue;
                                    }
                                    if pat.entity_type == "UK_NHS" && !valid_uk_nhs(mat.as_str()) {
                                        continue;
                                    }
                                    if pat.entity_type == "UK_NINO" && !valid_uk_nino(mat.as_str())
                                    {
                                        continue;
                                    }
                                    if pat.entity_type == "ES_NIF" && !valid_es_nif(mat.as_str()) {
                                        continue;
                                    }
                                    if pat.entity_type == "ES_NIE" && !valid_es_nie(mat.as_str()) {
                                        continue;
                                    }
                                    if pat.entity_type == "IT_FISCAL_CODE"
                                        && !valid_it_fiscal_code(mat.as_str())
                                    {
                                        continue;
                                    }
                                    if pat.entity_type == "IN_AADHAAR"
                                        && !valid_in_aadhaar(mat.as_str())
                                    {
                                        continue;
                                    }
                                    if pat.entity_type == "IN_GSTIN"
                                        && !valid_in_gstin(mat.as_str())
                                    {
                                        continue;
                                    }
                                    if pat.entity_type == "AU_ABN" && !valid_au_abn(mat.as_str()) {
                                        continue;
                                    }
                                    if pat.entity_type == "AU_ACN" && !valid_au_acn(mat.as_str()) {
                                        continue;
                                    }
                                    if pat.entity_type == "AU_TFN" && !valid_au_tfn(mat.as_str()) {
                                        continue;
                                    }
                                    if pat.entity_type == "AU_MEDICARE"
                                        && !valid_au_medicare(mat.as_str())
                                    {
                                        continue;
                                    }
                                    if pat.entity_type == "KR_RRN" && !valid_kr_rrn(mat.as_str()) {
                                        continue;
                                    }
                                    if pat.entity_type == "KR_FRN" && !valid_kr_frn(mat.as_str()) {
                                        continue;
                                    }
                                    if pat.entity_type == "KR_BRN" && !valid_kr_brn(mat.as_str()) {
                                        continue;
                                    }
                                    let score = pat.score;
                                    if score < self.threshold {
                                        continue;
                                    }
                                    url_inner_detections.push(Detection {
                                        entity_type: pat.entity_type,
                                        original: mat.as_str().to_string(),
                                        start: det.start,
                                        end: det.start,
                                        score,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        // Replace from end to start
        let mut result = text.to_string();
        for det in filtered.iter().rev() {
            let replacement = match self.operator {
                Operator::Token => self.mapping.add(det.entity_type, &det.original),
                Operator::Redact => String::new(),
                Operator::Keep => continue,
                Operator::Mask => apply_mask(&det.original, &self.mask_config),
            };
            result = format!(
                "{}{}{}",
                &result[..det.start],
                replacement,
                &result[det.end..]
            );
        }

        filtered.extend(url_inner_detections);
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
                let new_arr: Vec<Value> = arr
                    .iter()
                    .map(|v| self.walk_json(v, detections, depth + 1))
                    .collect();
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

    // ── International phone number tests ──

    #[test]
    fn test_intl_phone_us_with_context() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("phone: +1 212 555 1234");
        assert!(
            dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
            "US phone not detected: {dets:?}"
        );
        assert!(result.contains("[PHONE_NUMBER_"));
    }

    #[test]
    fn test_intl_phone_uk_with_context() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("contact tel +44 20 7946 0958");
        assert!(
            dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
            "UK phone not detected: {dets:?}"
        );
        assert!(result.contains("[PHONE_NUMBER_"));
    }

    #[test]
    fn test_intl_phone_de_with_context() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("telephone +49 30 123456");
        assert!(
            dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
            "DE phone not detected: {dets:?}"
        );
        assert!(result.contains("[PHONE_NUMBER_"));
    }

    #[test]
    fn test_intl_phone_no_context_rejected() {
        let mut a = Anonymizer::new(0.0);
        // No context keyword — should NOT match (context_required)
        let (_, dets) = a.anonymize_text("value is +1 212 555 1234 here");
        assert!(
            !dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
            "intl phone without context should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_intl_phone_hyphenated() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("mobile: +44-20-7946-0958");
        assert!(
            dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
            "hyphenated phone not detected: {dets:?}"
        );
        assert!(result.contains("[PHONE_NUMBER_"));
    }

    #[test]
    fn test_intl_phone_parenthesized_area_code() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("call +1 (212) 555-1234");
        assert!(
            dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
            "parenthesized area code not detected: {dets:?}"
        );
        assert!(result.contains("[PHONE_NUMBER_"));
    }

    #[test]
    fn test_fr_phone_stays_fr_phone() {
        // French numbers should still match as FR_PHONE_NUMBER (higher confidence), not generic PHONE_NUMBER
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("call +33 6 12 34 56 78");
        assert!(
            dets.iter().any(|d| d.entity_type == "FR_PHONE_NUMBER"),
            "French phone should stay FR_PHONE_NUMBER: {dets:?}"
        );
        assert!(result.contains("[FR_PHONE_NUMBER_"));
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

    // ── Generic IBAN tests ──

    #[test]
    fn test_iban_german() {
        let mut a = Anonymizer::new(0.0);
        // DE89 3704 0044 0532 0130 00 — valid mod-97
        let (result, dets) = a.anonymize_text("iban DE89 3704 0044 0532 0130 00");
        assert!(
            dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
            "German IBAN not detected: {dets:?}"
        );
        assert!(result.contains("[IBAN_CODE_"));
    }

    #[test]
    fn test_iban_british() {
        let mut a = Anonymizer::new(0.0);
        // GB29 NWBK 6016 1331 9268 19 — valid mod-97
        let (result, dets) = a.anonymize_text("account GB29NWBK60161331926819");
        assert!(
            dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
            "British IBAN not detected: {dets:?}"
        );
        assert!(result.contains("[IBAN_CODE_"));
    }

    #[test]
    fn test_iban_spanish() {
        let mut a = Anonymizer::new(0.0);
        // ES91 2100 0418 4502 0005 1332 — valid mod-97
        let (result, dets) = a.anonymize_text("virement ES91 2100 0418 4502 0005 1332");
        assert!(
            dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
            "Spanish IBAN not detected: {dets:?}"
        );
        assert!(result.contains("[IBAN_CODE_"));
    }

    #[test]
    fn test_iban_invalid_checksum_rejected() {
        let mut a = Anonymizer::new(0.0);
        // DE00 3704 0044 0532 0130 00 — invalid check digits
        let (_, dets) = a.anonymize_text("iban DE00 3704 0044 0532 0130 00");
        assert!(
            !dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
            "IBAN with invalid checksum should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_iban_context_required() {
        let mut a = Anonymizer::new(0.0);
        // Valid IBAN but no context keyword — should be rejected
        let (_, dets) = a.anonymize_text("code DE89370400440532013000 here");
        assert!(
            !dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
            "IBAN without context should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_iban_fr_stays_fr_iban() {
        // French IBANs should still be detected as FR_IBAN (higher confidence)
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("IBAN: FR76 1234 5678 9012 3456 7890 123");
        assert!(
            dets.iter().any(|d| d.entity_type == "FR_IBAN"),
            "French IBAN should stay FR_IBAN: {dets:?}"
        );
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

    // ── MAC address tests ──

    #[test]
    fn test_mac_address_colon() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("device mac 00:1A:2B:3C:4D:5E");
        assert!(
            dets.iter().any(|d| d.entity_type == "MAC_ADDRESS"),
            "colon MAC not detected: {dets:?}"
        );
        assert!(result.contains("[MAC_ADDRESS_"));
    }

    #[test]
    fn test_mac_address_hyphen() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("mac address 00-1A-2B-3C-4D-5E");
        assert!(
            dets.iter().any(|d| d.entity_type == "MAC_ADDRESS"),
            "hyphen MAC not detected: {dets:?}"
        );
        assert!(result.contains("[MAC_ADDRESS_"));
    }

    #[test]
    fn test_mac_address_cisco_dot() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("interface mac 001a.2b3c.4d5e");
        assert!(
            dets.iter().any(|d| d.entity_type == "MAC_ADDRESS"),
            "Cisco dot MAC not detected: {dets:?}"
        );
        assert!(result.contains("[MAC_ADDRESS_"));
    }

    #[test]
    fn test_mac_address_broadcast_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("mac ff:ff:ff:ff:ff:ff");
        assert!(
            !dets.iter().any(|d| d.entity_type == "MAC_ADDRESS"),
            "broadcast MAC should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_mac_address_null_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("mac 00:00:00:00:00:00");
        assert!(
            !dets.iter().any(|d| d.entity_type == "MAC_ADDRESS"),
            "null MAC should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_mac_address_lowercase() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("device mac aa:bb:cc:dd:ee:11");
        assert!(
            dets.iter().any(|d| d.entity_type == "MAC_ADDRESS"),
            "lowercase MAC not detected: {dets:?}"
        );
        assert!(result.contains("[MAC_ADDRESS_"));
    }

    // ── DATE_TIME tests ──

    #[test]
    fn test_date_iso8601() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("created on 2024-01-15");
        assert!(
            dets.iter().any(|d| d.entity_type == "DATE_TIME"),
            "ISO date not detected: {dets:?}"
        );
        assert!(result.contains("[DATE_TIME_"));
    }

    #[test]
    fn test_date_iso8601_with_time() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("timestamp 2024-01-15T14:30:00Z");
        assert!(
            dets.iter().any(|d| d.entity_type == "DATE_TIME"),
            "ISO datetime not detected: {dets:?}"
        );
        assert!(result.contains("[DATE_TIME_"));
    }

    #[test]
    fn test_date_french_format() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("date de naissance 15/01/1990");
        assert!(
            dets.iter().any(|d| d.entity_type == "DATE_TIME"),
            "French date not detected: {dets:?}"
        );
        assert!(result.contains("[DATE_TIME_"));
    }

    #[test]
    fn test_date_french_format_no_context_rejected() {
        let mut a = Anonymizer::new(0.0);
        // dd/mm/yyyy without context — ambiguous, could be a path or version
        let (_, dets) = a.anonymize_text("value 15/01/1990 here");
        assert!(
            !dets.iter().any(|d| d.entity_type == "DATE_TIME"),
            "French date without context should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_date_written_french() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("le 15 janvier 2024");
        assert!(
            dets.iter().any(|d| d.entity_type == "DATE_TIME"),
            "written French date not detected: {dets:?}"
        );
        assert!(result.contains("[DATE_TIME_"));
    }

    #[test]
    fn test_date_written_english() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("born January 15, 2024");
        assert!(
            dets.iter().any(|d| d.entity_type == "DATE_TIME"),
            "written English date not detected: {dets:?}"
        );
        assert!(result.contains("[DATE_TIME_"));
    }

    #[test]
    fn test_date_does_not_match_version_numbers() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("version 3.14.159");
        assert!(
            !dets.iter().any(|d| d.entity_type == "DATE_TIME"),
            "version numbers should not be dates: {dets:?}"
        );
    }

    #[test]
    fn test_date_does_not_match_ip() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("server at 192.168.1.100");
        // IP should be detected as IP, not as a date
        assert!(
            !dets.iter().any(|d| d.entity_type == "DATE_TIME"),
            "IP addresses should not be dates: {dets:?}"
        );
    }

    // ── US_SSN tests ──

    #[test]
    fn test_us_ssn_with_context() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("SSN: 123-45-6789");
        assert!(
            dets.iter().any(|d| d.entity_type == "US_SSN"),
            "US SSN not detected: {dets:?}"
        );
        assert!(result.contains("[US_SSN_"));
    }

    #[test]
    fn test_us_ssn_spaced() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("social security 123 45 6789");
        assert!(
            dets.iter().any(|d| d.entity_type == "US_SSN"),
            "spaced US SSN not detected: {dets:?}"
        );
        assert!(result.contains("[US_SSN_"));
    }

    #[test]
    fn test_us_ssn_no_context_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("number 123-45-6789 value");
        assert!(
            !dets.iter().any(|d| d.entity_type == "US_SSN"),
            "US SSN without context should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_us_ssn_invalid_prefix_rejected() {
        let mut a = Anonymizer::new(0.0);
        // 000, 666, and 9xx prefixes are invalid
        let (_, dets) = a.anonymize_text("SSN: 000-45-6789");
        assert!(
            !dets.iter().any(|d| d.entity_type == "US_SSN"),
            "US SSN with 000 prefix should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_us_ssn_all_zeros_group_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("SSN: 123-00-6789");
        assert!(
            !dets.iter().any(|d| d.entity_type == "US_SSN"),
            "US SSN with 00 middle group should be rejected: {dets:?}"
        );
    }

    // ── MEDICAL_LICENSE tests ──

    #[test]
    fn test_medical_license_with_context() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("medical license ME12345678");
        assert!(
            dets.iter().any(|d| d.entity_type == "MEDICAL_LICENSE"),
            "medical license not detected: {dets:?}"
        );
        assert!(result.contains("[MEDICAL_LICENSE_"));
    }

    #[test]
    fn test_medical_license_no_context_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("code ME12345678 here");
        assert!(
            !dets.iter().any(|d| d.entity_type == "MEDICAL_LICENSE"),
            "medical license without context should be rejected: {dets:?}"
        );
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
        assert!(dets
            .iter()
            .any(|d| d.entity_type == "AIRCRAFT_REGISTRATION"));
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
        assert!(!dets
            .iter()
            .any(|d| d.entity_type == "CREW_CODE" && d.original == "THE"));
    }

    #[test]
    fn test_ip() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("server at 192.168.1.100");
        assert!(result.contains("[IP_ADDRESS_"));
    }

    // ── IPv6 tests ──

    #[test]
    fn test_ipv6_full() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("host 2001:0db8:85a3:0000:0000:8a2e:0370:7334 down");
        assert!(
            dets.iter().any(|d| d.entity_type == "IP_ADDRESS"),
            "full IPv6 not detected: {dets:?}"
        );
        assert!(result.contains("[IP_ADDRESS_"));
    }

    #[test]
    fn test_ipv6_collapsed() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("server at 2001:db8::1");
        assert!(
            dets.iter().any(|d| d.entity_type == "IP_ADDRESS"),
            "collapsed IPv6 not detected: {dets:?}"
        );
        assert!(result.contains("[IP_ADDRESS_"));
    }

    #[test]
    fn test_ipv6_loopback() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("localhost is ::1");
        assert!(
            dets.iter().any(|d| d.entity_type == "IP_ADDRESS"),
            "loopback ::1 not detected: {dets:?}"
        );
        assert!(result.contains("[IP_ADDRESS_"));
    }

    #[test]
    fn test_ipv6_link_local() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("interface fe80::1%eth0");
        assert!(
            dets.iter().any(|d| d.entity_type == "IP_ADDRESS"),
            "link-local IPv6 not detected: {dets:?}"
        );
        assert!(result.contains("[IP_ADDRESS_"));
    }

    #[test]
    fn test_ipv6_mapped_v4() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("mapped ::ffff:192.168.1.1");
        assert!(
            dets.iter().any(|d| d.entity_type == "IP_ADDRESS"),
            "IPv4-mapped IPv6 not detected: {dets:?}"
        );
        assert!(result.contains("[IP_ADDRESS_"));
    }

    #[test]
    fn test_ipv6_does_not_match_random_hex() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("token abcd:ef01:2345");
        assert!(
            !dets.iter().any(|d| d.entity_type == "IP_ADDRESS"),
            "short hex groups should not be IPv6: {dets:?}"
        );
    }

    #[test]
    fn test_ipv4_still_works() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("server at 10.0.0.1");
        assert!(
            dets.iter().any(|d| d.entity_type == "IP_ADDRESS"),
            "IPv4 should still work: {dets:?}"
        );
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
        let token = a
            .mapping
            .mappings
            .keys()
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
        assert!(result["email"]
            .as_str()
            .unwrap()
            .contains("[EMAIL_ADDRESS_"));
        assert!(result["nested"]["phone"]
            .as_str()
            .unwrap()
            .contains("[FR_PHONE_NUMBER_"));
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
        let phone_det = dets
            .iter()
            .find(|d| d.entity_type == "FR_PHONE_NUMBER")
            .unwrap();
        assert!((phone_det.score - 0.7).abs() < 0.01);

        // With context keyword "telephone": boosted score
        let mut a2 = Anonymizer::new(0.0);
        let (_, dets2) = a2.anonymize_text("telephone 06 12 34 56 78");
        let phone_det2 = dets2
            .iter()
            .find(|d| d.entity_type == "FR_PHONE_NUMBER")
            .unwrap();
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
        assert!(result["a"]["b"]["c"]
            .as_str()
            .unwrap()
            .starts_with("[EMAIL_ADDRESS_"));
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
        assert_eq!(
            dets.iter()
                .filter(|d| d.entity_type == "EMAIL_ADDRESS")
                .count(),
            2
        );
        let email_tokens: Vec<_> = a
            .mapping
            .mappings
            .keys()
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
        let crew_dets: Vec<_> = dets
            .iter()
            .filter(|d| d.entity_type == "CREW_CODE")
            .collect();
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
        assert!(!dets
            .iter()
            .any(|d| d.entity_type == "CREW_CODE" && d.original == "URL"));

        let mut a2 = Anonymizer::new(0.0);
        let (_, dets2) = a2.anonymize_text("PII split across lines");
        assert!(!dets2
            .iter()
            .any(|d| d.entity_type == "CREW_CODE" && d.original == "PII"));

        let mut a3 = Anonymizer::new(0.0);
        let (_, dets3) = a3.anonymize_text("Auth-Token=XYZ-123");
        assert!(!dets3
            .iter()
            .any(|d| d.entity_type == "CREW_CODE" && d.original == "XYZ"));
    }

    #[test]
    fn test_crew_code_blocklist_airport_codes() {
        let mut a = Anonymizer::new(0.0);
        // Airport codes near crew context should be blocked
        let (_, dets) = a.anonymize_text("crew roster: departure CDG arrival ORY duty JFK");
        let crew_originals: Vec<&str> = dets
            .iter()
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
        assert!(
            dets.iter()
                .any(|d| d.entity_type == "CREW_CODE" && d.original == "JDU"),
            "Real crew code JDU should still be detected"
        );
        assert!(
            dets.iter()
                .any(|d| d.entity_type == "CREW_CODE" && d.original == "PLR"),
            "Real crew code PLR should still be detected"
        );
        assert!(result.contains("[CREW_CODE_"));
    }

    #[test]
    fn test_unicode_escape_email_detected() {
        let mut a = Anonymizer::new(0.0);
        // \u0040 is @ — should be decoded and detected as email
        let (result, dets) = a.anonymize_text(r"client\u0040company.com requested refund");
        assert!(
            dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"),
            "Email with \\u0040 should be detected: {:?}",
            dets
        );
        assert!(result.contains("[EMAIL_ADDRESS_"));
    }

    #[test]
    fn test_unicode_escape_multiple_sequences() {
        let mut a = Anonymizer::new(0.0);
        // Multiple unicode escapes in one email
        let (result, dets) = a.anonymize_text(r"user\u0040domain\u002Ecom");
        assert!(
            dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"),
            "Email with multiple unicode escapes should be detected: {:?}",
            dets
        );
        assert!(result.contains("[EMAIL_ADDRESS_"));
    }

    #[test]
    fn test_unicode_escape_no_double_mask() {
        let mut a = Anonymizer::new(0.0);
        // Plain email (no escapes) should still work normally
        let (result, dets) = a.anonymize_text("contact jane@example.com here");
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].entity_type, "EMAIL_ADDRESS");
        assert!(result.contains("[EMAIL_ADDRESS_"));
    }

    #[test]
    fn test_unicode_escape_malformed_passthrough() {
        // Malformed \u sequences should pass through without panic
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text(r"bad escape \u00 and \u00GG here");
        assert!(result.contains(r"\u00"));
    }

    #[test]
    fn test_decode_unicode_escapes_basic() {
        assert_eq!(decode_unicode_escapes(r"hello\u0040world"), "hello@world");
        assert_eq!(decode_unicode_escapes(r"\u002B33 6 12"), "+33 6 12");
        assert_eq!(decode_unicode_escapes("no escapes"), "no escapes");
    }

    #[test]
    fn test_decode_unicode_escapes_malformed() {
        // Too short
        assert_eq!(decode_unicode_escapes(r"\u00"), r"\u00");
        // Non-hex
        assert_eq!(decode_unicode_escapes(r"\u00GG"), r"\u00GG");
        // Just backslash not followed by u
        assert_eq!(decode_unicode_escapes(r"\n"), r"\n");
    }

    #[test]
    fn test_percent_encoded_email_detected() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("email=j.smith%40provider.net&loyalty_id=9928374");
        assert!(
            dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"),
            "Email with %40 should be detected: {:?}",
            dets
        );
        assert!(result.contains("[EMAIL_ADDRESS_"));
    }

    #[test]
    fn test_percent_encoded_phone_detected() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("tel=%2B33612345678");
        assert!(
            dets.iter().any(|d| d.entity_type == "FR_PHONE_NUMBER"),
            "Phone with %2B should be detected: {:?}",
            dets
        );
        assert!(result.contains("[FR_PHONE_NUMBER_"));
    }

    #[test]
    fn test_percent_encoded_no_double_mask() {
        let mut a = Anonymizer::new(0.0);
        // Plain email (no encoding) should still work
        let (result, dets) = a.anonymize_text("email=j.smith@provider.net");
        assert_eq!(
            dets.iter()
                .filter(|d| d.entity_type == "EMAIL_ADDRESS")
                .count(),
            1
        );
        assert!(result.contains("[EMAIL_ADDRESS_"));
    }

    #[test]
    fn test_decode_percent_encoding_basic() {
        assert_eq!(
            decode_percent_encoding("j.smith%40provider.net"),
            "j.smith@provider.net"
        );
        assert_eq!(decode_percent_encoding("%2B33"), "+33");
        assert_eq!(decode_percent_encoding("hello%20world"), "hello world");
        assert_eq!(decode_percent_encoding("no encoding"), "no encoding");
    }

    #[test]
    fn test_decode_percent_encoding_malformed() {
        // Trailing %
        assert_eq!(decode_percent_encoding("end%"), "end%");
        // Only one hex digit
        assert_eq!(decode_percent_encoding("end%4"), "end%4");
        // Non-hex
        assert_eq!(decode_percent_encoding("%GG"), "%GG");
    }

    #[test]
    fn test_jwt_three_segments_detected() {
        let mut a = Anonymizer::new(0.0);
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let input = format!("Authorization: Bearer {jwt}");
        let (result, dets) = a.anonymize_text(&input);
        assert!(
            dets.iter().any(|d| d.entity_type == "AUTH_TOKEN"),
            "JWT with 3 segments should be detected: {:?}",
            dets
        );
        assert!(result.contains("[AUTH_TOKEN_"));
    }

    #[test]
    fn test_jwt_two_segments_detected() {
        let mut a = Anonymizer::new(0.0);
        // JWT without signature (2 segments) — common in URL params
        let input = "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0&cc_last4=4242";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "AUTH_TOKEN"),
            "JWT with 2 segments should be detected: {:?}",
            dets
        );
        assert!(result.contains("[AUTH_TOKEN_"));
    }

    #[test]
    fn test_jwt_not_detected_single_segment() {
        let mut a = Anonymizer::new(0.0);
        // Only 1 segment — not a JWT
        let (_, dets) = a.anonymize_text("version=eyJub3QiOiJhIHRva2VuIn0");
        assert!(
            !dets.iter().any(|d| d.entity_type == "AUTH_TOKEN"),
            "Single base64 segment should not be detected as JWT"
        );
    }

    #[test]
    fn test_jwt_not_detected_short_segments() {
        let mut a = Anonymizer::new(0.0);
        // Segments too short (< 10 chars each)
        let (_, dets) = a.anonymize_text("file.name.extension");
        assert!(
            !dets.iter().any(|d| d.entity_type == "AUTH_TOKEN"),
            "Short dot-separated words should not be detected as JWT"
        );
    }

    #[test]
    fn test_url_inner_pii_reported_in_detections() {
        let mut a = Anonymizer::new(0.0);
        let input = "Referer: https://site.com/search?email=user%40example.com&id=123";
        let (result, dets) = a.anonymize_text(input);
        // URL should be masked in output
        assert!(result.contains("[URL_"));
        assert!(!result.contains("example.com"));
        // Both URL and inner EMAIL_ADDRESS should be in detections
        assert!(
            dets.iter().any(|d| d.entity_type == "URL"),
            "URL detection missing"
        );
        assert!(
            dets.iter()
                .any(|d| d.entity_type == "EMAIL_ADDRESS" && d.original == "user@example.com"),
            "Inner email not reported in detections: {:?}",
            dets
        );
    }

    #[test]
    fn test_url_inner_pii_phone_reported() {
        let mut a = Anonymizer::new(0.0);
        let input = "visit https://example.com/contact?tel=%2B33612345678";
        let (result, dets) = a.anonymize_text(input);
        assert!(result.contains("[URL_"));
        assert!(
            dets.iter().any(|d| d.entity_type == "FR_PHONE_NUMBER"),
            "Inner phone not reported in detections: {:?}",
            dets
        );
    }

    #[test]
    fn test_url_without_query_no_inner_detections() {
        let mut a = Anonymizer::new(0.0);
        let input = "visit https://example.com/page";
        let (_, dets) = a.anonymize_text(input);
        // Only the URL detection, no extras
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].entity_type, "URL");
    }

    #[test]
    fn test_url_inner_pii_no_false_detections() {
        let mut a = Anonymizer::new(0.0);
        let input = "visit https://example.com/page?id=123&sort=asc";
        let (_, dets) = a.anonymize_text(input);
        // Only the URL detection — no PII in these params
        assert_eq!(
            dets.iter().filter(|d| d.entity_type != "URL").count(),
            0,
            "Should not detect PII in non-PII URL params: {:?}",
            dets
        );
    }

    #[test]
    fn test_multiline_credit_card_detected() {
        let mut a = Anonymizer::new(0.0);
        // 4111111111111111 is valid Visa (passes Luhn), split across newline
        let input =
            "Body: User: Alice | CC: 4111\n1111 1111 1111 (Credit card split across newline)";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "CREDIT_CARD"),
            "Credit card split across newline should be detected: {:?}",
            dets
        );
        assert!(result.contains("[CREDIT_CARD_"));
    }

    #[test]
    fn test_multiline_iban_detected() {
        let mut a = Anonymizer::new(0.0);
        let input = "IBAN: FR76 3000\n6000 0112 3456 7890 123";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "FR_IBAN"),
            "IBAN split across newline should be detected: {:?}",
            dets
        );
        assert!(result.contains("[FR_IBAN_"));
    }

    #[test]
    fn test_multiline_credit_card_trailing_space() {
        let mut a = Anonymizer::new(0.0);
        // Trailing space before newline — real-world log wrapping
        let input =
            "Body: User: Alice | CC: 4111 \n1111 1111 1111 (Valid Visa split across newline)";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "CREDIT_CARD"),
            "Credit card with trailing space before newline should be detected: {:?}",
            dets
        );
        assert!(result.contains("[CREDIT_CARD_"));
    }

    #[test]
    fn test_multiline_credit_card_indented_continuation() {
        let mut a = Anonymizer::new(0.0);
        // Indented continuation line — common in log dumps
        let input = "CC: 4111\n    1111 1111 1111";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "CREDIT_CARD"),
            "Credit card with indented continuation should be detected: {:?}",
            dets
        );
        assert!(result.contains("[CREDIT_CARD_"));
    }

    #[test]
    fn test_multiline_iban_trailing_space() {
        let mut a = Anonymizer::new(0.0);
        let input = "IBAN: FR76 3000 \n6000 0112 3456 7890 123";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "FR_IBAN"),
            "IBAN with trailing space before newline should be detected: {:?}",
            dets
        );
        assert!(result.contains("[FR_IBAN_"));
    }

    #[test]
    fn test_multiline_no_false_positive() {
        let mut a = Anonymizer::new(0.0);
        // Unrelated numbers on separate lines should NOT merge into a credit card
        let input = "count: 4111\ntotal: 1111";
        let (_, dets) = a.anonymize_text(input);
        assert!(
            !dets.iter().any(|d| d.entity_type == "CREDIT_CARD"),
            "Unrelated numbers on separate lines should not be a credit card: {:?}",
            dets
        );
    }

    #[test]
    fn test_multiline_full_stress_payload() {
        let mut a = Anonymizer::new(0.0);
        let input = "2024-03-15 10:20:01 [INFO]  Dumping raw socket content:\n\
                      Beginning of message...\n\
                      Body: User: Alice | CC: 4111 \n\
                      1111 1111 1111 (Valid Visa split across a newline)\n\
                      End of message.";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "CREDIT_CARD"),
            "Credit card in full log payload should be detected: {:?}",
            dets
        );
        assert!(result.contains("[CREDIT_CARD_"));
        assert!(!result.contains("4111"));
    }

    // ── NER pipeline tests (always compiled, use MockNerDetector) ──

    #[test]
    fn test_ner_pipeline_person_blocklist() {
        use crate::ner::{MockNerDetector, NerSpan};
        let mock = MockNerDetector {
            spans: vec![NerSpan {
                text: "Amelia".into(),
                start: 0,
                end: 6,
                score: 0.9,
                label: "PER".into(),
            }],
        };
        let mut a = Anonymizer::new(0.0);
        a.set_ner_detector(Box::new(mock));
        let (result, dets) = a.anonymize_text("Amelia said hello");
        assert!(
            !dets
                .iter()
                .any(|d| d.entity_type == "PERSON" && d.original == "Amelia"),
            "Blocklisted name 'Amelia' should not be detected as PERSON: {:?}",
            dets
        );
        assert!(result.contains("Amelia"));
    }

    #[test]
    fn test_ner_pipeline_person_detected() {
        use crate::ner::{MockNerDetector, NerSpan};
        let mock = MockNerDetector {
            spans: vec![NerSpan {
                text: "Dupont".into(),
                start: 12,
                end: 18,
                score: 0.9,
                label: "PER".into(),
            }],
        };
        let mut a = Anonymizer::new(0.0);
        a.set_ner_detector(Box::new(mock));
        let (result, dets) = a.anonymize_text("Le pilote M. Dupont a décollé.");
        assert!(
            dets.iter().any(|d| d.entity_type == "PERSON"),
            "Non-blocklisted name should be detected as PERSON: {:?}",
            dets
        );
        assert!(result.contains("[PERSON_"));
    }

    #[test]
    fn test_ner_pipeline_span_extension_allcaps() {
        use crate::ner::{MockNerDetector, NerSpan};
        let text = "Damien DUPONT a signé";
        let mock = MockNerDetector {
            spans: vec![NerSpan {
                text: "Damien".into(),
                start: 0,
                end: 6,
                score: 0.9,
                label: "PER".into(),
            }],
        };
        let mut a = Anonymizer::new(0.0);
        a.set_ner_detector(Box::new(mock));
        let (result, dets) = a.anonymize_text(text);
        assert!(
            dets.iter()
                .any(|d| d.entity_type == "PERSON" && d.original.contains("DUPONT")),
            "Span should extend to ALL-CAPS last name: {:?}",
            dets
        );
        assert!(!result.contains("DUPONT"));
        assert!(!result.contains("Damien"));
    }

    #[test]
    fn test_ner_pipeline_consistency_pass() {
        use crate::ner::{MockNerDetector, NerSpan};
        let text = "Pierre DUPONT a dit bonjour. Plus tard, Pierre a fait signe.";
        let mock = MockNerDetector {
            spans: vec![NerSpan {
                text: "Pierre".into(),
                start: 0,
                end: 6,
                score: 0.9,
                label: "PER".into(),
            }],
        };
        let mut a = Anonymizer::new(0.0);
        a.set_ner_detector(Box::new(mock));
        let (result, _dets) = a.anonymize_text(text);
        assert!(!result.contains("DUPONT"), "Full name should be anonymized");
        assert!(
            !result.contains("Pierre"),
            "Bare first name should be anonymized by consistency pass"
        );
    }

    #[test]
    fn test_ner_pipeline_no_detector_no_person() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("Le pilote M. Dupont a décollé.");
        assert!(
            !dets.iter().any(|d| d.entity_type == "PERSON"),
            "Without NER detector, PERSON should not be detected: {:?}",
            dets
        );
    }

    // ── LOCATION entity tests (via NER) ──

    #[test]
    fn test_ner_location_detected() {
        use crate::ner::{MockNerDetector, NerSpan};
        let mock = MockNerDetector {
            spans: vec![NerSpan {
                text: "Paris".into(),
                start: 12,
                end: 17,
                score: 0.9,
                label: "LOCATION".into(),
            }],
        };
        let mut a = Anonymizer::new(0.0);
        a.set_ner_detector(Box::new(mock));
        let (result, dets) = a.anonymize_text("Departure at Paris CDG terminal");
        assert!(
            dets.iter().any(|d| d.entity_type == "LOCATION"),
            "LOCATION not detected: {dets:?}"
        );
        assert!(result.contains("[LOCATION_"));
    }

    #[test]
    fn test_ner_location_and_person_together() {
        use crate::ner::{MockNerDetector, NerSpan};
        let mock = MockNerDetector {
            spans: vec![
                NerSpan {
                    text: "Dupont".into(),
                    start: 0,
                    end: 6,
                    score: 0.9,
                    label: "PERSON".into(),
                },
                NerSpan {
                    text: "Lyon".into(),
                    start: 18,
                    end: 22,
                    score: 0.85,
                    label: "LOCATION".into(),
                },
            ],
        };
        let mut a = Anonymizer::new(0.0);
        a.set_ner_detector(Box::new(mock));
        let (result, dets) = a.anonymize_text("Dupont arrived at Lyon airport");
        assert!(
            dets.iter().any(|d| d.entity_type == "PERSON"),
            "PERSON not detected: {dets:?}"
        );
        assert!(
            dets.iter().any(|d| d.entity_type == "LOCATION"),
            "LOCATION not detected: {dets:?}"
        );
        assert!(result.contains("[PERSON_"));
        assert!(result.contains("[LOCATION_"));
    }

    #[test]
    fn test_ner_location_no_span_extension() {
        // LOCATION should NOT get PERSON-style span extension to adjacent ALL-CAPS words
        use crate::ner::{MockNerDetector, NerSpan};
        let mock = MockNerDetector {
            spans: vec![NerSpan {
                text: "Paris".into(),
                start: 0,
                end: 5,
                score: 0.9,
                label: "LOCATION".into(),
            }],
        };
        let mut a = Anonymizer::new(0.0);
        a.set_ner_detector(Box::new(mock));
        let (result, _dets) = a.anonymize_text("Paris FRANCE is beautiful");
        // "FRANCE" should NOT be swallowed into the LOCATION span
        assert!(
            result.contains("FRANCE"),
            "LOCATION should not extend to adjacent words"
        );
    }

    // ── NER integration tests (feature-gated, use real detectors) ──

    #[cfg(feature = "ner-lite")]
    #[test]
    fn test_ner_lite_person_detected() {
        use crate::ner::heuristic::HeuristicNerDetector;
        let mut a = Anonymizer::new(0.0);
        a.set_ner_detector(Box::new(HeuristicNerDetector::new()));
        let (result, dets) = a.anonymize_text("Le pilote M. Dupont a décollé.");
        assert!(
            dets.iter().any(|d| d.entity_type == "PERSON"),
            "NER-lite should detect PERSON in 'M. Dupont': {:?}",
            dets
        );
        assert!(result.contains("[PERSON_"));
    }

    #[cfg(feature = "ner-lite")]
    #[test]
    fn test_ner_lite_no_person_without_detector() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("Le pilote M. Dupont a décollé.");
        assert!(
            !dets.iter().any(|d| d.entity_type == "PERSON"),
            "Without NER detector, PERSON should not be detected: {:?}",
            dets
        );
    }

    #[cfg(feature = "ner-lite")]
    #[test]
    fn test_ner_lite_person_in_complex_log() {
        use crate::ner::heuristic::HeuristicNerDetector;
        let mut a = Anonymizer::new(0.0);
        a.set_ner_detector(Box::new(HeuristicNerDetector::new()));
        let input =
            "2024-03-15 [INFO] Passager Philippe Martin a embarqué, email: phil@example.com";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "PERSON"),
            "PERSON should be detected alongside other PII: {:?}",
            dets
        );
        assert!(
            dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"),
            "EMAIL should still be detected with NER active: {:?}",
            dets
        );
        assert!(result.contains("[PERSON_"));
        assert!(result.contains("[EMAIL_ADDRESS_"));
    }

    #[cfg(feature = "ner-lite")]
    #[test]
    fn test_ner_lite_standalone_alice_with_user_context() {
        use crate::ner::heuristic::HeuristicNerDetector;
        let mut a = Anonymizer::new(0.0);
        a.set_ner_detector(Box::new(HeuristicNerDetector::new()));
        // This is the benchmark complex log line — "User: Alice" should trigger PERSON
        let input = r#"2024-03-15 10:20:01 [INFO] Dumping raw socket:
    Header: Auth-Token=XYZ-123
    Body: User: Alice | CC: 4111
    1111 1111 1111
    {"metadata": "{\"source\": \"partner_api\", \"raw\": \"client%40email.com\"}"}"#;
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "PERSON"),
            "Alice should be detected as PERSON with 'User:' context.\nDetections: {:?}\nResult: {}", dets, result
        );
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

    #[test]
    fn test_tabular_crew_codes_with_login_context() {
        let mut a = Anonymizer::new(0.0);
        let input = r#"Clean Orphaned Leave Records
     ===============================

      Found 3 orphaned leaves from 3 mappings.

      ------- ------------------------- ----------------- --------------- ------------- ------------ ------------
       Login   Email                     Leave ID          Duty IDs        Mapping IDs   Start        End
      ------- ------------------------- ----------------- --------------- ------------- ------------ ------------
       JDU     jdupont@example-air.com     26062001          65880001        90001         2026-03-01   2026-03-01
       MMA     mmartinez@example-air.com   26072001          65100001        90002         2026-03-02   2026-03-02
       BRN     bruneau@example-air.com     26055001          65090001        90003         2026-03-03   2026-03-03
      ------- ------------------------- ----------------- --------------- ------------- ------------ ------------"#;
        let (result, dets) = a.anonymize_text(input);

        // Crew codes should be anonymized (Login header provides context)
        assert!(
            dets.iter().any(|d| d.entity_type == "CREW_CODE"),
            "Crew codes (JDU, MMA, BRN) should be detected with 'Login' context.\nDetections: {:?}\nResult: {}",
            dets, result
        );
        assert!(!result.contains("JDU"), "JDU should be anonymized");
        assert!(!result.contains("MMA"), "MMA should be anonymized");
        assert!(!result.contains("BRN"), "BRN should be anonymized");

        // Emails should be anonymized
        assert!(
            !result.contains("jdupont@example-air.com"),
            "Email should be anonymized"
        );
        assert!(
            !result.contains("mmartinez@example-air.com"),
            "Email should be anonymized"
        );
        assert!(
            !result.contains("bruneau@example-air.com"),
            "Email should be anonymized"
        );
    }

    #[test]
    fn test_column_header_no_false_positive_wrong_column() {
        // Crew code at a column that does NOT align with "Login" header
        let mut a = Anonymizer::new(0.0);
        let input = "Login   Status\n------  ------\nOK      XYZ";
        let (_, dets) = a.anonymize_text(input);
        // XYZ is in the "Status" column, not "Login" — should NOT match CREW_CODE
        assert!(
            !dets
                .iter()
                .any(|d| d.entity_type == "CREW_CODE" && d.original == "XYZ"),
            "XYZ under 'Status' column should not be detected as CREW_CODE.\nDetections: {:?}",
            dets
        );
    }

    #[test]
    fn test_column_header_context_with_duty_keyword() {
        // "Duty" is also a CREW_CODE context keyword — test it as a column header
        let mut a = Anonymizer::new(0.0);
        let input = "Duty    Name\n------  ------\nJDU     Someone\nMMA     Another";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "CREW_CODE"),
            "Crew codes should be detected under 'Duty' header.\nDetections: {:?}\nResult: {}",
            dets,
            result
        );
        assert!(!result.contains("JDU"), "JDU should be anonymized");
        assert!(!result.contains("MMA"), "MMA should be anonymized");
    }

    #[test]
    fn test_column_header_no_header_above() {
        // No header line at all — crew code should NOT be detected
        let mut a = Anonymizer::new(0.0);
        let input = "JDU     some text here";
        let (_, dets) = a.anonymize_text(input);
        assert!(
            !dets.iter().any(|d| d.entity_type == "CREW_CODE"),
            "JDU without any context should not be detected.\nDetections: {:?}",
            dets
        );
    }

    #[test]
    fn test_column_header_many_rows_below_header() {
        // Header is 10+ rows above — should still work (within 20-line lookback)
        let mut a = Anonymizer::new(0.0);
        let mut lines = vec!["Crew  Info".to_string(), "----  ----".to_string()];
        for i in 0..15 {
            lines.push(format!("C{:02}   row {}", i, i));
        }
        lines.push("JDU   last row".to_string());
        let input = lines.join("\n");
        let (result, dets) = a.anonymize_text(&input);
        assert!(
            dets.iter().any(|d| d.entity_type == "CREW_CODE" && d.original == "JDU"),
            "JDU should be detected with 'Crew' header 17 lines above.\nDetections: {:?}\nResult: {}",
            dets, result
        );
    }

    #[test]
    fn test_off_not_detected_as_crew_code() {
        let mut a = Anonymizer::new(0.0);
        // "OFF" in duty schedule context — should NOT be a crew code
        let input = "les journées de OFF/Duty/X-D/... sont qualifiées comme absences";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            !dets
                .iter()
                .any(|d| d.entity_type == "CREW_CODE" && d.original == "OFF"),
            "OFF should be blocklisted as CREW_CODE.\nDetections: {:?}",
            dets
        );
        assert!(result.contains("OFF"), "OFF should remain in output");
    }

    #[cfg(feature = "ner-lite")]
    #[test]
    fn test_person_blocklist_amelia() {
        use crate::ner::heuristic::HeuristicNerDetector;
        let mut a = Anonymizer::new(0.0);
        a.set_ner_detector(Box::new(HeuristicNerDetector::new()));
        // "Amelia 1.0" is a product/company name, not a person
        let input = "Amelia 1.0\nDamien DUPONT\nFull-Stack Developer";
        let (result, dets) = a.anonymize_text(input);
        // Amelia should NOT be detected as PERSON
        assert!(
            !dets
                .iter()
                .any(|d| d.entity_type == "PERSON" && d.original.contains("Amelia")),
            "Amelia should be blocklisted as PERSON.\nDetections: {:?}",
            dets
        );
        assert!(result.contains("Amelia"), "Amelia should remain in output");
    }

    #[cfg(feature = "ner-lite")]
    #[test]
    fn test_person_allcaps_lastname_full_pipeline() {
        use crate::ner::heuristic::HeuristicNerDetector;
        let mut a = Anonymizer::new(0.0);
        a.set_ner_detector(Box::new(HeuristicNerDetector::new()));
        let input = "Created by Damien DUPONT 29 Jan 2026";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter()
                .any(|d| d.entity_type == "PERSON" && d.original.contains("DUPONT")),
            "Damien DUPONT should be detected as PERSON.\nDetections: {:?}\nResult: {}",
            dets,
            result
        );
        assert!(!result.contains("DUPONT"), "DUPONT should be anonymized");
        assert!(!result.contains("Damien"), "Damien should be anonymized");
    }

    #[cfg(feature = "ner-lite")]
    #[test]
    fn test_email_thread_anonymization() {
        use crate::ner::heuristic::HeuristicNerDetector;
        let mut a = Anonymizer::new(0.0);
        a.set_ner_detector(Box::new(HeuristicNerDetector::new()));
        let input = r#"--
Amelia 1.0
Sylvain Martin
Captain EMB145
Mobile : +33612345678
example-air.com"#;
        let (result, dets) = a.anonymize_text(input);
        // Sylvain Martin should be detected
        assert!(
            dets.iter()
                .any(|d| d.entity_type == "PERSON" && d.original.contains("Sylvain")),
            "Sylvain Martin should be detected.\nDetections: {:?}",
            dets
        );
        assert!(!result.contains("Sylvain"), "Sylvain should be anonymized");
        // Phone should be detected
        assert!(
            dets.iter().any(|d| d.entity_type == "FR_PHONE_NUMBER"),
            "Phone number should be detected.\nDetections: {:?}",
            dets
        );
        // Amelia should NOT be a person
        assert!(result.contains("Amelia"), "Amelia should remain in output");
    }

    #[cfg(feature = "ner-lite")]
    #[test]
    fn test_email_thread_realistic_format() {
        // Regression: real-world email threads have names repeated in headers,
        // signatures, forwarded blocks, and bare first names in greetings.
        use crate::ner::heuristic::HeuristicNerDetector;
        let mut a = Anonymizer::new(0.0);
        a.set_ner_detector(Box::new(HeuristicNerDetector::new()));
        let input = r#"Gaël FONTAINE
mar. 27 janv. 16:45
À Mathilde, moi

Hello @Damien DUPONT,

Pourrais-tu STP nous apporter tes lumières ?

--
Amelia 1.0
Gaël FONTAINE
DSI / CIO
example-air.com

Le mar. 27 janv. 2026 à 16:41, Camille BERNARD <cbernard@example-air.com> a écrit :
hello Gaël,

Merci d'avoir répondu à Mr DUPONT.

Amelia 1.0
Camille BERNARD
HR Director
Mobile : +33 7 00 00 00 01
example-air.com"#;
        let (result, dets) = a.anonymize_text(input);

        // Full names (first + last) should be anonymized
        assert!(
            !result.contains("FONTAINE"),
            "FONTAINE should be anonymized"
        );
        assert!(!result.contains("DUPONT"), "DUPONT should be anonymized");
        assert!(!result.contains("LEROY"), "LEROY should be anonymized");
        // Bare first names should also be caught by the name consistency pass
        // (they appear as part of full "Firstname LASTNAME" elsewhere in the text).
        assert!(
            !result.contains("Gaël"),
            "Bare 'Gaël' should be anonymized by consistency pass"
        );
        assert!(
            !result.contains("Mathilde"),
            "Bare 'Mathilde' should be anonymized by consistency pass"
        );

        // Email and phone should be caught
        assert!(
            !result.contains("cbernard@example-air.com"),
            "Email should be anonymized"
        );
        assert!(
            dets.iter().any(|d| d.entity_type == "FR_PHONE_NUMBER"),
            "Phone should be detected.\nDetections: {:?}",
            dets
        );

        // Amelia (company) should NOT be anonymized
        assert!(
            result.contains("Amelia"),
            "Amelia is a company name, not a person"
        );

        // Job titles in signature blocks should be anonymized
        assert!(
            !result.contains("HR Director"),
            "HR Director should be anonymized as JOB_TITLE"
        );
        assert!(
            !result.contains("DSI / CIO"),
            "DSI / CIO should be anonymized as JOB_TITLE"
        );

        assert!(
            !result.contains("FONTAINE"),
            "All FONTAINE instances should be anonymized"
        );
    }

    #[test]
    #[cfg(feature = "ner-lite")]
    fn test_name_consistency_pass_bare_first_names() {
        // When a full "Firstname LASTNAME" is detected, all bare occurrences
        // of that first name should also be anonymized.
        use crate::ner::heuristic::HeuristicNerDetector;
        let mut a = Anonymizer::new(0.0);
        a.set_ner_detector(Box::new(HeuristicNerDetector::new()));
        let input = "Pierre DUPONT a dit bonjour. Plus tard, Pierre a fait signe.";
        let (result, _dets) = a.anonymize_text(input);

        assert!(!result.contains("DUPONT"), "Full name should be anonymized");
        assert!(
            !result.contains("Pierre"),
            "Bare first name should be anonymized by consistency pass"
        );
    }

    // ── Ticket #35: extend person span to Title-case last names ──

    #[test]
    fn test_extend_person_span_titlecase_lastname() {
        // "Kowalski" is Title-case, not ALL-CAPS. The span extension should still
        // include it when it immediately follows a detected first name.
        use crate::ner::{MockNerDetector, NerSpan};
        let text = "Przemysław Kowalski\n13/Jan/26, 22:33\nDear Gaël,";
        let mock = MockNerDetector {
            spans: vec![NerSpan {
                text: "Przemysław".into(),
                start: 0,
                end: "Przemysław".len(),
                score: 0.9,
                label: "PER".into(),
            }],
        };
        let mut a = Anonymizer::new(0.0);
        a.set_ner_detector(Box::new(mock));
        let (result, dets) = a.anonymize_text(text);
        assert!(
            dets.iter()
                .any(|d| d.entity_type == "PERSON" && d.original.contains("Kowalski")),
            "Span should extend to Title-case last name 'Kowalski': {:?}",
            dets
        );
        assert!(
            !result.contains("Kowalski"),
            "Title-case last name should be anonymized"
        );
    }

    #[test]
    #[cfg(feature = "ner-lite")]
    fn test_extend_person_span_titlecase_full_pipeline() {
        // Full pipeline: heuristic NER detects a known first name followed by
        // a Title-case last name. Both should be anonymized together.
        use crate::ner::heuristic::HeuristicNerDetector;
        let mut a = Anonymizer::new(0.0);
        a.set_ner_detector(Box::new(HeuristicNerDetector::new()));
        let input = "Contact: Pierre Durand for details.";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter()
                .any(|d| d.entity_type == "PERSON" && d.original.contains("Durand")),
            "Pierre Durand should be detected as a full name.\nDetections: {:?}",
            dets
        );
        assert!(
            !result.contains("Durand"),
            "Title-case last name should be anonymized"
        );
        assert!(
            !result.contains("Pierre"),
            "First name should be anonymized"
        );
    }

    // ── Ticket #36: accent-insensitive name consistency ──

    #[test]
    fn test_name_consistency_accent_insensitive() {
        // When "Gaël" is detected, bare "Gael" (no accent) should also be caught.
        use crate::ner::{MockNerDetector, NerSpan};
        let text = "Gaël DUPONT a signé. Dear Gael, merci.";
        let gael_len = "Gaël".len(); // 5 bytes (ë = 2 bytes in UTF-8)
        let mock = MockNerDetector {
            spans: vec![NerSpan {
                text: "Gaël".into(),
                start: 0,
                end: gael_len,
                score: 0.9,
                label: "PER".into(),
            }],
        };
        let mut a = Anonymizer::new(0.0);
        a.set_ner_detector(Box::new(mock));
        let (result, _dets) = a.anonymize_text(text);
        assert!(
            !result.contains("Gael"),
            "Bare 'Gael' (no accent) should be anonymized when 'Gaël' was detected"
        );
    }

    #[test]
    #[cfg(feature = "ner-lite")]
    fn test_name_consistency_accent_insensitive_full_pipeline() {
        use crate::ner::heuristic::HeuristicNerDetector;
        let mut a = Anonymizer::new(0.0);
        a.set_ner_detector(Box::new(HeuristicNerDetector::new()));
        let input = "Gaël DUPONT a signé. Plus tard, Gael a confirmé.";
        let (result, _dets) = a.anonymize_text(input);
        assert!(
            !result.contains("Gael"),
            "Bare 'Gael' (no accent) should be caught by consistency pass"
        );
    }

    #[test]
    fn test_name_consistency_accent_insensitive_preserves_surrounding_text() {
        // Verify that replacing accent-stripped names doesn't corrupt adjacent multi-byte text.
        // "Héloïse" (7 bytes in UTF-8) and "café" surround the bare name to stress byte offsets.
        use crate::ner::{MockNerDetector, NerSpan};
        let text = "Héloïse saw Gaël DUPONT at the café. Later, Gael ordered thé.";
        let gael_start = text.find("Gaël").unwrap();
        let gael_len = "Gaël".len();
        let mock = MockNerDetector {
            spans: vec![NerSpan {
                text: "Gaël".into(),
                start: gael_start,
                end: gael_start + gael_len,
                score: 0.9,
                label: "PER".into(),
            }],
        };
        let mut a = Anonymizer::new(0.0);
        a.set_ner_detector(Box::new(mock));
        let (result, _dets) = a.anonymize_text(text);
        // Bare "Gael" should be caught
        assert!(!result.contains("Gael"), "Bare 'Gael' should be anonymized");
        // Surrounding multi-byte text must be intact
        assert!(
            result.contains("Héloïse"),
            "Multi-byte text before name should be preserved: {result}"
        );
        assert!(
            result.contains("café"),
            "Multi-byte text after name should be preserved: {result}"
        );
        assert!(
            result.contains("thé"),
            "Multi-byte text at end should be preserved: {result}"
        );
    }

    // ── Ticket #37: last-name consistency pass ──

    #[test]
    fn test_name_consistency_bare_last_name() {
        // When "Pierre DUPONT" is detected, bare "DUPONT" elsewhere should also be caught.
        use crate::ner::{MockNerDetector, NerSpan};
        let text = "Pierre DUPONT joined. Later, DUPONT confirmed the schedule.";
        let mock = MockNerDetector {
            spans: vec![NerSpan {
                text: "Pierre".into(),
                start: 0,
                end: 6,
                score: 0.9,
                label: "PER".into(),
            }],
        };
        let mut a = Anonymizer::new(0.0);
        a.set_ner_detector(Box::new(mock));
        let (result, _dets) = a.anonymize_text(text);
        assert!(
            !result.contains("DUPONT"),
            "Bare last name 'DUPONT' should be caught by consistency pass"
        );
    }

    #[test]
    fn test_name_consistency_bare_titlecase_last_name() {
        // Title-case last name appearing alone after the full name was detected.
        use crate::ner::{MockNerDetector, NerSpan};
        let text = "Przemysław Kowalski joined. Later, Kowalski confirmed.";
        let mock = MockNerDetector {
            spans: vec![NerSpan {
                text: "Przemysław".into(),
                start: 0,
                end: "Przemysław".len(),
                score: 0.9,
                label: "PER".into(),
            }],
        };
        let mut a = Anonymizer::new(0.0);
        a.set_ner_detector(Box::new(mock));
        let (result, _dets) = a.anonymize_text(text);
        assert!(
            !result.contains("Kowalski"),
            "Bare last name 'Kowalski' should be caught by consistency pass"
        );
    }

    #[test]
    fn test_name_consistency_short_last_name_skipped() {
        // Last names shorter than 3 chars should NOT be searched for bare occurrences
        // to avoid false positives (e.g., "Li", "Wu", "Ma" are too common).
        use crate::ner::{MockNerDetector, NerSpan};
        let text = "Wei Li joined the team. The Li River is beautiful.";
        let mock = MockNerDetector {
            spans: vec![NerSpan {
                text: "Wei".into(),
                start: 0,
                end: 3,
                score: 0.9,
                label: "PER".into(),
            }],
        };
        let mut a = Anonymizer::new(0.0);
        a.set_ner_detector(Box::new(mock));
        let (result, _dets) = a.anonymize_text(text);
        // "Li River" should NOT be anonymized — "Li" is too short for bare last name matching
        assert!(
            result.contains("Li River"),
            "Short last name 'Li' should not trigger bare last name consistency: result = {result}"
        );
    }

    // ── Ticket #38: sign-off name detection ──

    #[test]
    fn test_signoff_name_best_regards() {
        // "Przemek" after "Best regards," should be detected even without NER
        let mut a = Anonymizer::new(0.0);
        let input = "Our team has confirmed the change.\n\nBest regards,\nPrzemek";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter()
                .any(|d| d.entity_type == "PERSON" && d.original == "Przemek"),
            "Sign-off name 'Przemek' should be detected.\nDetections: {:?}",
            dets
        );
        assert!(
            !result.contains("Przemek"),
            "Sign-off name should be anonymized"
        );
    }

    #[test]
    fn test_signoff_name_brgds() {
        let mut a = Anonymizer::new(0.0);
        let input = "Please confirm.\n\nBrgds,\nJulia";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter()
                .any(|d| d.entity_type == "PERSON" && d.original == "Julia"),
            "Sign-off name 'Julia' should be detected.\nDetections: {:?}",
            dets
        );
        assert!(
            !result.contains("Julia"),
            "Sign-off name should be anonymized"
        );
    }

    #[test]
    fn test_signoff_name_cordialement() {
        let mut a = Anonymizer::new(0.0);
        let input = "Merci pour votre retour.\n\nCordialement,\nDamien";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter()
                .any(|d| d.entity_type == "PERSON" && d.original == "Damien"),
            "Sign-off name 'Damien' should be detected.\nDetections: {:?}",
            dets
        );
        assert!(
            !result.contains("Damien"),
            "Sign-off name should be anonymized"
        );
    }

    #[test]
    fn test_signoff_name_same_line() {
        // "Best regards, Przemek" on the same line
        let mut a = Anonymizer::new(0.0);
        let input = "I will revert once I receive details.\n\nBest regards, Przemek";
        let (result, _dets) = a.anonymize_text(input);
        assert!(
            !result.contains("Przemek"),
            "Sign-off name on same line should be anonymized"
        );
    }

    #[test]
    fn test_signoff_does_not_match_blocklist() {
        // Company names in PERSON_BLOCKLIST should not be detected
        let mut a = Anonymizer::new(0.0);
        let input = "Thank you.\n\nBest regards,\nAmelia";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            !dets
                .iter()
                .any(|d| d.entity_type == "PERSON" && d.original == "Amelia"),
            "Blocklisted word 'Amelia' should NOT be detected as PERSON.\nDetections: {:?}",
            dets
        );
        // Amelia is blocklisted so it should remain
        assert!(
            result.contains("Amelia"),
            "Blocklisted name should not be anonymized"
        );
    }

    #[test]
    fn test_phone_0033_format() {
        let mut a = Anonymizer::new(0.0);
        let input = "Mobile : 0033 7 00 00 00 01";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "FR_PHONE_NUMBER"),
            "0033 phone format should be detected.\nDetections: {:?}",
            dets
        );
        assert!(
            !result.contains("0033 7 00 00 00 01"),
            "Phone should be replaced"
        );
    }

    #[test]
    fn test_job_title_in_signature() {
        let mut a = Anonymizer::new(0.0);
        // Signature block with context keywords (example-air, linkedin)
        let input = "Jean DUPONT\nHR Director\nMobile : +33 6 12 34 56 78\nexample-air.com\nLinkedIn";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "JOB_TITLE"),
            "HR Director should be detected as JOB_TITLE.\nDetections: {:?}",
            dets
        );
        assert!(
            !result.contains("HR Director"),
            "Job title should be replaced"
        );
    }

    #[test]
    fn test_job_title_csuite_in_signature() {
        let mut a = Anonymizer::new(0.0);
        let input = "Jean DUPONT\nDSI / CIO\nexample-air.com\nLinkedIn";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "JOB_TITLE"),
            "DSI / CIO should be detected as JOB_TITLE.\nDetections: {:?}",
            dets
        );
        assert!(
            !result.contains("DSI / CIO"),
            "C-suite title should be replaced"
        );
    }

    #[test]
    fn test_job_title_not_in_prose() {
        let mut a = Anonymizer::new(0.0);
        // Without signature context keywords, titles should NOT match
        let input = "The HR Director asked about the report.";
        let (_result, dets) = a.anonymize_text(input);
        assert!(
            !dets.iter().any(|d| d.entity_type == "JOB_TITLE"),
            "JOB_TITLE should not match in regular prose without context.\nDetections: {:?}",
            dets
        );
    }

    #[test]
    fn test_employee_matricule_detected_with_context() {
        let mut a = Anonymizer::new(0.0);
        let input = "Le Capitaine (matricule AM-4872) a signalé un incident";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter()
                .any(|d| d.entity_type == "EMPLOYEE_ID" && d.original == "AM-4872"),
            "AM-4872 should be detected as EMPLOYEE_ID with 'matricule' context.\nDetections: {:?}",
            dets
        );
        assert!(
            !result.contains("AM-4872"),
            "Matricule should be anonymized"
        );
    }

    #[test]
    fn test_employee_matricule_not_detected_without_context() {
        let mut a = Anonymizer::new(0.0);
        let input = "reference AM-4872 in the system";
        let (_, dets) = a.anonymize_text(input);
        assert!(
            !dets.iter().any(|d| d.entity_type == "EMPLOYEE_ID"),
            "EMPLOYEE_ID should not match without context keywords.\nDetections: {:?}",
            dets
        );
    }

    #[test]
    fn test_flight_number_with_dash() {
        let mut a = Anonymizer::new(0.0);
        let input = "incident sur le vol AML-317 Paris-CDG";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter()
                .any(|d| d.entity_type == "FLIGHT_NUMBER" && d.original == "AML-317"),
            "AML-317 should be detected as FLIGHT_NUMBER.\nDetections: {:?}",
            dets
        );
        assert!(
            !result.contains("AML-317"),
            "Flight number should be anonymized"
        );
        // AML should NOT be detected separately as CREW_CODE
        assert!(
            !dets
                .iter()
                .any(|d| d.entity_type == "CREW_CODE" && d.original == "AML"),
            "AML should not be detected as CREW_CODE when part of flight number.\nDetections: {:?}",
            dets
        );
    }

    #[test]
    fn test_aviation_incident_report_regression() {
        // Regression test: realistic aviation incident report with mixed PII
        let mut a = Anonymizer::new(0.0);
        let input = "Le Capitaine Jean-Marc Dubois (matricule AM-4872) a signalé un incident \
            technique sur le vol AML-317 Paris-CDG → Beyrouth le 14/03/2025. Son copilote \
            Marie Lefèvre a confirmé. Contact RH : j.dupont@example-air.com, poste 2241. Le rapport \
            a été transmis à Dr. Philippe Nasser pour évaluation médicale.";
        let (result, dets) = a.anonymize_text(input);
        // Email must be detected
        assert!(
            dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"),
            "Email should be detected.\nDetections: {:?}",
            dets
        );
        // Matricule must be detected
        assert!(
            dets.iter()
                .any(|d| d.entity_type == "EMPLOYEE_ID" && d.original == "AM-4872"),
            "Matricule AM-4872 should be detected as EMPLOYEE_ID.\nDetections: {:?}",
            dets
        );
        assert!(
            !result.contains("AM-4872"),
            "Matricule should be anonymized in output"
        );
        // Flight number AML-317 must be detected as flight, not crew code
        assert!(
            dets.iter()
                .any(|d| d.entity_type == "FLIGHT_NUMBER" && d.original == "AML-317"),
            "AML-317 should be detected as FLIGHT_NUMBER.\nDetections: {:?}",
            dets
        );
        assert!(
            !dets
                .iter()
                .any(|d| d.entity_type == "CREW_CODE" && d.original == "AML"),
            "AML should not be a CREW_CODE.\nDetections: {:?}",
            dets
        );
    }

    #[test]
    fn test_phone_extension_poste() {
        let mut a = Anonymizer::new(0.0);
        let input = "Contact RH : j.dupont@example-air.com, poste 2241.";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter()
                .any(|d| d.entity_type == "PHONE_EXTENSION" && d.original.contains("2241")),
            "poste 2241 should be detected as PHONE_EXTENSION.\nDetections: {:?}",
            dets
        );
        assert!(
            !result.contains("2241"),
            "Phone extension should be anonymized"
        );
    }

    #[test]
    fn test_phone_extension_ext() {
        let mut a = Anonymizer::new(0.0);
        let input = "Call ext. 4510 for support";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter()
                .any(|d| d.entity_type == "PHONE_EXTENSION" && d.original.contains("4510")),
            "ext. 4510 should be detected as PHONE_EXTENSION.\nDetections: {:?}",
            dets
        );
        assert!(
            !result.contains("4510"),
            "Phone extension should be anonymized"
        );
    }

    #[test]
    fn test_bare_number_not_phone_extension() {
        let mut a = Anonymizer::new(0.0);
        let input = "There are 2241 items in the database";
        let (_, dets) = a.anonymize_text(input);
        assert!(
            !dets.iter().any(|d| d.entity_type == "PHONE_EXTENSION"),
            "Bare number should not be detected as PHONE_EXTENSION.\nDetections: {:?}",
            dets
        );
    }

    // ── Secret key tests ──

    #[test]
    fn test_secret_key_stripe_underscore() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) =
            a.anonymize_text("STRIPE_SECRET = \"sk_live_51N7xRgAv8bN2xT9mW5qJ7pL3kYz\"");
        assert!(
            dets.iter().any(|d| d.entity_type == "SECRET_KEY"),
            "Stripe key with underscores should be detected.\nDetections: {:?}",
            dets
        );
        assert!(result.contains("[SECRET_KEY_"));
    }

    #[test]
    fn test_secret_key_stripe_dash() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) =
            a.anonymize_text("key = sk-live-Rg4v8bN2xT9mW5qJ7pL3kYz6hD1fA0cE8iU2wX");
        assert!(
            dets.iter().any(|d| d.entity_type == "SECRET_KEY"),
            "Stripe key with dashes should be detected.\nDetections: {:?}",
            dets
        );
        assert!(result.contains("[SECRET_KEY_"));
    }

    #[test]
    fn test_secret_key_github_pat() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) =
            a.anonymize_text("export GH_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn");
        assert!(
            dets.iter().any(|d| d.entity_type == "SECRET_KEY"),
            "GitHub PAT should be detected.\nDetections: {:?}",
            dets
        );
        assert!(result.contains("[SECRET_KEY_"));
    }

    #[test]
    fn test_secret_key_aws() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("aws_access_key_id = AKIAIOSFODNN7EXAMPLE");
        assert!(
            dets.iter().any(|d| d.entity_type == "SECRET_KEY"),
            "AWS access key should be detected.\nDetections: {:?}",
            dets
        );
        assert!(result.contains("[SECRET_KEY_"));
    }

    #[test]
    fn test_secret_key_slack() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("SLACK_TOKEN=xoxb-1234567890-abcdefghij");
        assert!(
            dets.iter().any(|d| d.entity_type == "SECRET_KEY"),
            "Slack bot token should be detected.\nDetections: {:?}",
            dets
        );
        assert!(result.contains("[SECRET_KEY_"));
    }

    #[test]
    fn test_secret_key_openai() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a
            .anonymize_text("OPENAI_API_KEY=sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx");
        assert!(
            dets.iter().any(|d| d.entity_type == "SECRET_KEY"),
            "OpenAI key should be detected.\nDetections: {:?}",
            dets
        );
        assert!(result.contains("[SECRET_KEY_"));
    }

    #[test]
    fn test_secret_key_private_key_header() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("-----BEGIN RSA PRIVATE KEY-----");
        assert!(
            dets.iter().any(|d| d.entity_type == "SECRET_KEY"),
            "PEM private key header should be detected.\nDetections: {:?}",
            dets
        );
        assert!(result.contains("[SECRET_KEY_"));
    }

    #[test]
    fn test_secret_key_private_key_header_generic() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("-----BEGIN PRIVATE KEY-----");
        assert!(
            dets.iter().any(|d| d.entity_type == "SECRET_KEY"),
            "Generic PEM private key header should be detected.\nDetections: {:?}",
            dets
        );
        assert!(result.contains("[SECRET_KEY_"));
    }

    #[test]
    fn test_secret_key_short_not_detected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("prefix sk-live-abc");
        assert!(
            !dets
                .iter()
                .any(|d| d.entity_type == "SECRET_KEY" && d.original.contains("sk-live-abc")),
            "Short key-like strings should not be detected as SECRET_KEY.\nDetections: {:?}",
            dets
        );
    }

    // ── Connection string tests ──

    #[test]
    fn test_connection_string_postgresql() {
        let mut a = Anonymizer::new(0.0);
        let input =
            r#"DATABASE_URL = "postgresql://admin:F1eet$ecret2024@db.internal:5432/fleet_prod""#;
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "CONNECTION_STRING"),
            "PostgreSQL connection string should be detected.\nDetections: {:?}",
            dets
        );
        assert!(result.contains("[CONNECTION_STRING_"));
    }

    #[test]
    fn test_connection_string_redis() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("REDIS_URL=redis://:password@cache.internal:6379/0");
        assert!(
            dets.iter().any(|d| d.entity_type == "CONNECTION_STRING"),
            "Redis connection string should be detected.\nDetections: {:?}",
            dets
        );
        assert!(result.contains("[CONNECTION_STRING_"));
    }

    #[test]
    fn test_connection_string_mongodb_srv() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text(
            "MONGO_URI=mongodb+srv://user:pass@cluster.mongodb.net/mydb?retryWrites=true",
        );
        assert!(
            dets.iter().any(|d| d.entity_type == "CONNECTION_STRING"),
            "MongoDB+SRV connection string should be detected.\nDetections: {:?}",
            dets
        );
        assert!(result.contains("[CONNECTION_STRING_"));
    }

    #[test]
    fn test_connection_string_mysql() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("mysql://root:s3cret@localhost:3306/app_db");
        assert!(
            dets.iter().any(|d| d.entity_type == "CONNECTION_STRING"),
            "MySQL connection string should be detected.\nDetections: {:?}",
            dets
        );
        assert!(result.contains("[CONNECTION_STRING_"));
    }

    // ── Password assignment tests ──

    #[test]
    fn test_password_quoted() {
        let mut a = Anonymizer::new(0.0);
        let input = r#"SMTP_PASSWORD = "Sm7p!M4il2024""#;
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "PASSWORD"),
            "Quoted password assignment should be detected.\nDetections: {:?}",
            dets
        );
        assert!(result.contains("[PASSWORD_"));
    }

    #[test]
    fn test_password_single_quoted() {
        let mut a = Anonymizer::new(0.0);
        let input = "secret_key = 'MyS3cretV4lue!!'";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "PASSWORD"),
            "Single-quoted secret assignment should be detected.\nDetections: {:?}",
            dets
        );
        assert!(result.contains("[PASSWORD_"));
    }

    #[test]
    fn test_password_env_unquoted() {
        let mut a = Anonymizer::new(0.0);
        let input = "DB_PASSWORD=F1eet$ecret2024";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "PASSWORD"),
            "Unquoted env-file password should be detected.\nDetections: {:?}",
            dets
        );
        assert!(result.contains("[PASSWORD_"));
    }

    #[test]
    fn test_password_json_style() {
        let mut a = Anonymizer::new(0.0);
        let input = r#""password": "MyS3cretP4ssword!""#;
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "PASSWORD"),
            "JSON-style password should be detected.\nDetections: {:?}",
            dets
        );
        assert!(result.contains("[PASSWORD_"));
    }

    #[test]
    fn test_password_short_value_not_detected() {
        let mut a = Anonymizer::new(0.0);
        let input = r#"password = "short""#;
        let (_, dets) = a.anonymize_text(input);
        assert!(
            !dets.iter().any(|d| d.entity_type == "PASSWORD"),
            "Short password values (<8 chars) should not be detected.\nDetections: {:?}",
            dets
        );
    }

    #[test]
    fn test_password_no_keyword_not_detected() {
        let mut a = Anonymizer::new(0.0);
        let input = r#"username = "johndoe12345""#;
        let (_, dets) = a.anonymize_text(input);
        assert!(
            !dets.iter().any(|d| d.entity_type == "PASSWORD"),
            "Non-password keyword assignments should not be detected.\nDetections: {:?}",
            dets
        );
    }

    #[test]
    fn test_password_prefixed_keyword() {
        let mut a = Anonymizer::new(0.0);
        let input = r#"MY_APP_SECRET = "longEnoughSecretValue""#;
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "PASSWORD"),
            "Prefixed secret keyword should be detected.\nDetections: {:?}",
            dets
        );
        assert!(result.contains("[PASSWORD_"));
    }

    // ════════════════════════════════════════════════════════════════════
    // Battle tests for Phase 1 entities
    // ════════════════════════════════════════════════════════════════════

    // ── PHONE_NUMBER (international) battle tests ──

    #[test]
    fn test_intl_phone_japan() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("tel: +81 3 1234 5678");
        assert!(
            dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
            "Japan phone not detected: {dets:?}"
        );
        assert!(result.contains("[PHONE_NUMBER_"));
    }

    #[test]
    fn test_intl_phone_brazil() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("contact: +55 11 98765 4321");
        assert!(
            dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
            "Brazil phone not detected: {dets:?}"
        );
        assert!(result.contains("[PHONE_NUMBER_"));
    }

    #[test]
    fn test_intl_phone_australia() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("phone +61 2 9876 5432");
        assert!(
            dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
            "Australia phone not detected: {dets:?}"
        );
        assert!(result.contains("[PHONE_NUMBER_"));
    }

    #[test]
    fn test_intl_phone_india() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("mobile +91 98765 43210");
        assert!(
            dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
            "India phone not detected: {dets:?}"
        );
        assert!(result.contains("[PHONE_NUMBER_"));
    }

    #[test]
    fn test_intl_phone_e164_strict() {
        let mut a = Anonymizer::new(0.0);
        // E.164 format with no spaces
        let (result, dets) = a.anonymize_text("sms +447911123456");
        assert!(
            dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
            "E.164 phone not detected: {dets:?}"
        );
        assert!(result.contains("[PHONE_NUMBER_"));
    }

    #[test]
    fn test_intl_phone_dot_separated() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("fax: +49.30.123456");
        assert!(
            dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
            "dot-separated phone not detected: {dets:?}"
        );
        assert!(result.contains("[PHONE_NUMBER_"));
    }

    #[test]
    fn test_intl_phone_multiple_context_keywords() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("whatsapp +971 50 123 4567");
        assert!(
            dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
            "'whatsapp' should trigger phone detection: {dets:?}"
        );
        assert!(result.contains("[PHONE_NUMBER_"));
    }

    #[test]
    fn test_intl_phone_not_confused_with_math() {
        let mut a = Anonymizer::new(0.0);
        // "+1 212 555 1234" without any context should NOT match
        let (_, dets) = a.anonymize_text("result is +1 212 555 1234 end");
        assert!(
            !dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
            "phone without context in math-like text should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_intl_phone_short_number_rejected() {
        let mut a = Anonymizer::new(0.0);
        // Only 5 digits after country code — too short
        let (_, dets) = a.anonymize_text("tel +1 12345");
        assert!(
            !dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
            "too-short intl phone should not match: {dets:?}"
        );
    }

    #[test]
    fn test_intl_phone_consistency_same_number_same_token() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("call +44 20 7946 0958, again call +44 20 7946 0958");
        let tokens: Vec<_> = a
            .mapping
            .mappings
            .keys()
            .filter(|k| k.starts_with("[PHONE_NUMBER_"))
            .collect();
        assert_eq!(tokens.len(), 1, "same phone number should map to one token");
        let token = tokens[0].as_str();
        assert_eq!(
            result.matches(token).count(),
            2,
            "same token should appear twice"
        );
    }

    // ── PHONE_EXTENSION battle tests ──

    #[test]
    fn test_phone_extension_extension_keyword() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("reach us at extension 12345");
        assert!(
            dets.iter().any(|d| d.entity_type == "PHONE_EXTENSION"),
            "extension keyword not detected: {dets:?}"
        );
        assert!(result.contains("[PHONE_EXTENSION_"));
    }

    #[test]
    fn test_phone_extension_case_insensitive() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("call EXT 9876");
        assert!(
            dets.iter().any(|d| d.entity_type == "PHONE_EXTENSION"),
            "case-insensitive ext not detected: {dets:?}"
        );
        assert!(result.contains("[PHONE_EXTENSION_"));
    }

    #[test]
    fn test_phone_extension_two_digit_rejected() {
        let mut a = Anonymizer::new(0.0);
        // Only 2 digits — below min of 3
        let (_, dets) = a.anonymize_text("ext 42");
        assert!(
            !dets.iter().any(|d| d.entity_type == "PHONE_EXTENSION"),
            "2-digit extension should not match: {dets:?}"
        );
    }

    #[test]
    fn test_phone_extension_six_digit_rejected() {
        let mut a = Anonymizer::new(0.0);
        // 6 digits — above max of 5
        let (_, dets) = a.anonymize_text("poste 123456");
        assert!(
            !dets.iter().any(|d| d.entity_type == "PHONE_EXTENSION"),
            "6-digit extension should not match: {dets:?}"
        );
    }

    // ── IBAN_CODE (generic) battle tests ──

    #[test]
    fn test_iban_dutch() {
        let mut a = Anonymizer::new(0.0);
        // NL91 ABNA 0417 1643 00 — valid mod-97
        let (result, dets) = a.anonymize_text("bank account NL91ABNA0417164300");
        assert!(
            dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
            "Dutch IBAN not detected: {dets:?}"
        );
        assert!(result.contains("[IBAN_CODE_"));
    }

    #[test]
    fn test_iban_belgian() {
        let mut a = Anonymizer::new(0.0);
        // BE68 5390 0754 7034 — valid mod-97
        let (result, dets) = a.anonymize_text("iban: BE68539007547034");
        assert!(
            dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
            "Belgian IBAN not detected: {dets:?}"
        );
        assert!(result.contains("[IBAN_CODE_"));
    }

    #[test]
    fn test_iban_swiss() {
        let mut a = Anonymizer::new(0.0);
        // CH93 0076 2011 6238 5295 7 — valid mod-97
        let (result, dets) = a.anonymize_text("swift transfer CH9300762011623852957");
        assert!(
            dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
            "Swiss IBAN not detected: {dets:?}"
        );
        assert!(result.contains("[IBAN_CODE_"));
    }

    #[test]
    fn test_iban_with_spaces() {
        let mut a = Anonymizer::new(0.0);
        // Same German IBAN but with standard 4-char groups
        let (result, dets) = a.anonymize_text("payment DE89 3704 0044 0532 0130 00");
        assert!(
            dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
            "spaced IBAN not detected: {dets:?}"
        );
        assert!(result.contains("[IBAN_CODE_"));
    }

    #[test]
    fn test_iban_off_by_one_checksum_rejected() {
        let mut a = Anonymizer::new(0.0);
        // DE90 instead of DE89 — should fail mod-97
        let (_, dets) = a.anonymize_text("iban DE90370400440532013000");
        assert!(
            !dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
            "IBAN with wrong check digits should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_iban_lowercase_rejected() {
        let mut a = Anonymizer::new(0.0);
        // Country code must be uppercase per pattern
        let (_, dets) = a.anonymize_text("iban de89370400440532013000");
        assert!(
            !dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
            "lowercase IBAN should not match the regex: {dets:?}"
        );
    }

    #[test]
    fn test_iban_too_short_rejected() {
        let mut a = Anonymizer::new(0.0);
        // 4 check + only 6 BBAN chars = too short
        let (_, dets) = a.anonymize_text("iban XX12ABCDEF");
        assert!(
            !dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
            "too-short IBAN should not match: {dets:?}"
        );
    }

    #[test]
    fn test_iban_roundtrip() {
        let mut a = Anonymizer::new(0.0);
        let input = "virement sur le compte iban DE89370400440532013000";
        let (anon, _) = a.anonymize_text(input);
        let restored = a.mapping.restore(&anon);
        assert_eq!(restored, input, "IBAN roundtrip should restore original");
    }

    // ── MAC_ADDRESS battle tests ──

    #[test]
    fn test_mac_address_mixed_case() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("device 0A:1b:2C:3d:4E:5f online");
        assert!(
            dets.iter().any(|d| d.entity_type == "MAC_ADDRESS"),
            "mixed-case MAC not detected: {dets:?}"
        );
        assert!(result.contains("[MAC_ADDRESS_"));
    }

    #[test]
    fn test_mac_address_cisco_uppercase() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("interface AABB.CCDD.EEFF");
        assert!(
            dets.iter().any(|d| d.entity_type == "MAC_ADDRESS"),
            "uppercase Cisco MAC not detected: {dets:?}"
        );
        assert!(result.contains("[MAC_ADDRESS_"));
    }

    #[test]
    fn test_mac_address_near_broadcast_still_detected() {
        let mut a = Anonymizer::new(0.0);
        // ff:ff:ff:ff:ff:fe — one bit off from broadcast, should be valid
        let (result, dets) = a.anonymize_text("device ff:ff:ff:ff:ff:fe connected");
        assert!(
            dets.iter().any(|d| d.entity_type == "MAC_ADDRESS"),
            "near-broadcast MAC should be valid: {dets:?}"
        );
        assert!(result.contains("[MAC_ADDRESS_"));
    }

    #[test]
    fn test_mac_address_broadcast_cisco_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("broadcast ffff.ffff.ffff");
        assert!(
            !dets.iter().any(|d| d.entity_type == "MAC_ADDRESS"),
            "Cisco broadcast MAC should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_mac_address_null_hyphen_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("empty 00-00-00-00-00-00 address");
        assert!(
            !dets.iter().any(|d| d.entity_type == "MAC_ADDRESS"),
            "null hyphen MAC should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_mac_address_null_cisco_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("default 0000.0000.0000");
        assert!(
            !dets.iter().any(|d| d.entity_type == "MAC_ADDRESS"),
            "null Cisco MAC should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_mac_address_in_json_log() {
        let mut a = Anonymizer::new(0.0);
        let input = r#"{"device_mac": "AB:CD:EF:01:23:45", "status": "online"}"#;
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "MAC_ADDRESS"),
            "MAC in JSON should be detected: {dets:?}"
        );
        assert!(!result.contains("AB:CD:EF:01:23:45"));
    }

    #[test]
    fn test_mac_address_consistency() {
        let mut a = Anonymizer::new(0.0);
        let (_result, _) = a.anonymize_text("device 0A:1B:2C:3D:4E:5F and again 0A:1B:2C:3D:4E:5F");
        let tokens: Vec<_> = a
            .mapping
            .mappings
            .keys()
            .filter(|k| k.starts_with("[MAC_ADDRESS_"))
            .collect();
        assert_eq!(tokens.len(), 1, "same MAC should map to one token");
    }

    #[test]
    fn test_mac_address_not_confused_with_ipv6() {
        let mut a = Anonymizer::new(0.0);
        // Full IPv6 should be IP_ADDRESS, not MAC_ADDRESS
        let (_, dets) = a.anonymize_text("host 2001:0db8:85a3:0000:0000:8a2e:0370:7334");
        let mac_dets: Vec<_> = dets
            .iter()
            .filter(|d| d.entity_type == "MAC_ADDRESS")
            .collect();
        assert!(
            mac_dets.is_empty(),
            "IPv6 address should not be detected as MAC: {mac_dets:?}"
        );
    }

    // ── DATE_TIME battle tests ──

    #[test]
    fn test_date_iso8601_with_offset() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("sent at 2024-06-15T09:30:00+02:00");
        assert!(
            dets.iter().any(|d| d.entity_type == "DATE_TIME"),
            "ISO date with offset not detected: {dets:?}"
        );
        assert!(result.contains("[DATE_TIME_"));
    }

    #[test]
    fn test_date_iso8601_with_milliseconds() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("logged at 2024-01-15T14:30:00.123Z");
        assert!(
            dets.iter().any(|d| d.entity_type == "DATE_TIME"),
            "ISO date with ms not detected: {dets:?}"
        );
        assert!(result.contains("[DATE_TIME_"));
    }

    #[test]
    fn test_date_iso8601_date_only() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("born 1990-05-20");
        assert!(
            dets.iter().any(|d| d.entity_type == "DATE_TIME"),
            "ISO date-only not detected: {dets:?}"
        );
        assert!(result.contains("[DATE_TIME_"));
    }

    #[test]
    fn test_date_iso8601_space_separator() {
        let mut a = Anonymizer::new(0.0);
        // Space instead of T between date and time (common in logs)
        let (result, dets) = a.anonymize_text("created 2024-01-15 14:30:00Z");
        assert!(
            dets.iter().any(|d| d.entity_type == "DATE_TIME"),
            "ISO date with space separator not detected: {dets:?}"
        );
        assert!(result.contains("[DATE_TIME_"));
    }

    #[test]
    fn test_date_eu_dot_format_with_context() {
        let mut a = Anonymizer::new(0.0);
        // dd.mm.yyyy with context
        let (result, dets) = a.anonymize_text("date de naissance: 25.12.1990");
        assert!(
            dets.iter().any(|d| d.entity_type == "DATE_TIME"),
            "EU dot date not detected: {dets:?}"
        );
        assert!(result.contains("[DATE_TIME_"));
    }

    #[test]
    fn test_date_eu_various_contexts() {
        let contexts = [
            "departure 15/03/2024",
            "arrival date 15/03/2024",
            "dob: 15/03/1990",
            "né le 15/03/1990",
            "émis le 15/03/2024",
        ];
        for input in &contexts {
            let mut a = Anonymizer::new(0.0);
            let (_, dets) = a.anonymize_text(input);
            assert!(
                dets.iter().any(|d| d.entity_type == "DATE_TIME"),
                "EU date not detected in '{input}': {dets:?}"
            );
        }
    }

    #[test]
    fn test_date_written_french_premier() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("publié le 1er mars 2023");
        assert!(
            dets.iter().any(|d| d.entity_type == "DATE_TIME"),
            "'1er mars' not detected: {dets:?}"
        );
        assert!(result.contains("[DATE_TIME_"));
    }

    #[test]
    fn test_date_written_french_all_months() {
        let months = [
            "janvier",
            "février",
            "mars",
            "avril",
            "mai",
            "juin",
            "juillet",
            "août",
            "septembre",
            "octobre",
            "novembre",
            "décembre",
        ];
        for month in &months {
            let input = format!("le 15 {month} 2024");
            let mut a = Anonymizer::new(0.0);
            let (_, dets) = a.anonymize_text(&input);
            assert!(
                dets.iter().any(|d| d.entity_type == "DATE_TIME"),
                "French month '{month}' not detected: {dets:?}"
            );
        }
    }

    #[test]
    fn test_date_written_french_alt_spelling() {
        let mut a = Anonymizer::new(0.0);
        // "fevrier" without accent and "aout" without accent
        let (_, dets) = a.anonymize_text("le 15 fevrier 2024");
        assert!(
            dets.iter().any(|d| d.entity_type == "DATE_TIME"),
            "'fevrier' (no accent) not detected: {dets:?}"
        );
        let mut a2 = Anonymizer::new(0.0);
        let (_, dets2) = a2.anonymize_text("le 15 aout 2024");
        assert!(
            dets2.iter().any(|d| d.entity_type == "DATE_TIME"),
            "'aout' (no accent) not detected: {dets2:?}"
        );
    }

    #[test]
    fn test_date_written_english_all_months() {
        let months = [
            "January",
            "February",
            "March",
            "April",
            "May",
            "June",
            "July",
            "August",
            "September",
            "October",
            "November",
            "December",
        ];
        for month in &months {
            let input = format!("{month} 15, 2024");
            let mut a = Anonymizer::new(0.0);
            let (_, dets) = a.anonymize_text(&input);
            assert!(
                dets.iter().any(|d| d.entity_type == "DATE_TIME"),
                "English month '{month}' not detected: {dets:?}"
            );
        }
    }

    #[test]
    fn test_date_written_english_abbreviated() {
        let abbrevs = [
            "Jan", "Feb", "Mar", "Apr", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        for abbr in &abbrevs {
            let input = format!("{abbr} 15, 2024");
            let mut a = Anonymizer::new(0.0);
            let (_, dets) = a.anonymize_text(&input);
            assert!(
                dets.iter().any(|d| d.entity_type == "DATE_TIME"),
                "English abbreviated month '{abbr}' not detected: {dets:?}"
            );
        }
    }

    #[test]
    fn test_date_written_english_ordinal() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("born March 3rd, 2024");
        assert!(
            dets.iter().any(|d| d.entity_type == "DATE_TIME"),
            "ordinal date not detected: {dets:?}"
        );
        assert!(result.contains("[DATE_TIME_"));
    }

    #[test]
    fn test_date_invalid_month_rejected() {
        let mut a = Anonymizer::new(0.0);
        // Month 13 doesn't exist
        let (_, dets) = a.anonymize_text("2024-13-01");
        assert!(
            !dets.iter().any(|d| d.entity_type == "DATE_TIME"),
            "invalid month 13 should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_date_invalid_day_rejected() {
        let mut a = Anonymizer::new(0.0);
        // Day 32 doesn't exist
        let (_, dets) = a.anonymize_text("2024-01-32");
        assert!(
            !dets.iter().any(|d| d.entity_type == "DATE_TIME"),
            "invalid day 32 should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_date_year_boundary() {
        let mut a = Anonymizer::new(0.0);
        // Year 1899 — out of 19xx/20xx range for EU format
        let (_, dets) = a.anonymize_text("date 15/01/1899");
        assert!(
            !dets.iter().any(|d| d.entity_type == "DATE_TIME"),
            "year 1899 should not match dd/mm/yyyy pattern: {dets:?}"
        );
    }

    #[test]
    fn test_date_not_confused_with_semver() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("version 2.11.3");
        assert!(
            !dets.iter().any(|d| d.entity_type == "DATE_TIME"),
            "semver should not match as date: {dets:?}"
        );
    }

    #[test]
    fn test_date_not_confused_with_decimal() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("temperature 98.6.50 degrees");
        assert!(
            !dets.iter().any(|d| d.entity_type == "DATE_TIME"),
            "decimal-like number should not be a date: {dets:?}"
        );
    }

    #[test]
    fn test_date_iso_roundtrip() {
        let mut a = Anonymizer::new(0.0);
        let input = "created at 2024-06-15T09:30:00Z";
        let (anon, _) = a.anonymize_text(input);
        let restored = a.mapping.restore(&anon);
        assert_eq!(
            restored, input,
            "ISO date roundtrip should restore original"
        );
    }

    // ── IPv6 battle tests ──

    #[test]
    fn test_ipv6_real_world_dns() {
        let mut a = Anonymizer::new(0.0);
        // Google public DNS
        let (result, dets) = a.anonymize_text("dns server 2001:4860:4860::8888");
        assert!(
            dets.iter().any(|d| d.entity_type == "IP_ADDRESS"),
            "Google DNS IPv6 not detected: {dets:?}"
        );
        assert!(result.contains("[IP_ADDRESS_"));
    }

    #[test]
    fn test_ipv6_documentation_prefix() {
        let mut a = Anonymizer::new(0.0);
        // 2001:db8::/32 is documentation prefix
        let (result, dets) = a.anonymize_text("example 2001:db8:1::ab9:C0A8:102");
        assert!(
            dets.iter().any(|d| d.entity_type == "IP_ADDRESS"),
            "documentation IPv6 not detected: {dets:?}"
        );
        assert!(result.contains("[IP_ADDRESS_"));
    }

    #[test]
    fn test_ipv6_uppercase() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("host 2001:0DB8:85A3:0000:0000:8A2E:0370:7334");
        assert!(
            dets.iter().any(|d| d.entity_type == "IP_ADDRESS"),
            "uppercase IPv6 not detected: {dets:?}"
        );
        assert!(result.contains("[IP_ADDRESS_"));
    }

    #[test]
    fn test_ipv6_trailing_double_colon() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("prefix 2001:db8::");
        assert!(
            dets.iter().any(|d| d.entity_type == "IP_ADDRESS"),
            "trailing :: IPv6 not detected: {dets:?}"
        );
        assert!(result.contains("[IP_ADDRESS_"));
    }

    #[test]
    fn test_ipv6_mapped_v4_private() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("mapped ::ffff:10.0.0.1");
        assert!(
            dets.iter().any(|d| d.entity_type == "IP_ADDRESS"),
            "IPv4-mapped private not detected: {dets:?}"
        );
        assert!(result.contains("[IP_ADDRESS_"));
    }

    #[test]
    fn test_ipv6_in_url_bracket() {
        let mut a = Anonymizer::new(0.0);
        // IPv6 in URL brackets — URL should be detected
        let (result, dets) = a.anonymize_text("visit http://[2001:db8::1]:8080/path");
        assert!(
            dets.iter().any(|d| d.entity_type == "URL"),
            "URL with IPv6 not detected: {dets:?}"
        );
        assert!(result.contains("[URL_"));
    }

    #[test]
    fn test_ipv6_and_ipv4_together() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("primary 192.168.1.1 secondary 2001:db8::1");
        let ip_dets: Vec<_> = dets
            .iter()
            .filter(|d| d.entity_type == "IP_ADDRESS")
            .collect();
        assert_eq!(
            ip_dets.len(),
            2,
            "should detect both IPv4 and IPv6: {ip_dets:?}"
        );
        assert!(result.contains("[IP_ADDRESS_"));
    }

    #[test]
    fn test_ipv6_not_hex_string() {
        let mut a = Anonymizer::new(0.0);
        // Random hex without colons should not match
        let (_, dets) = a.anonymize_text("hash 0db885a30000000008a2e03707334");
        assert!(
            !dets.iter().any(|d| d.entity_type == "IP_ADDRESS"),
            "hex string without colons should not be IPv6: {dets:?}"
        );
    }

    #[test]
    fn test_ipv6_consistency() {
        let mut a = Anonymizer::new(0.0);
        let (_, _) = a.anonymize_text("host 2001:db8::1 and 2001:db8::1");
        let tokens: Vec<_> = a
            .mapping
            .mappings
            .keys()
            .filter(|k| k.starts_with("[IP_ADDRESS_"))
            .collect();
        assert_eq!(tokens.len(), 1, "same IPv6 should map to one token");
    }

    // ── US_SSN battle tests ──

    #[test]
    fn test_us_ssn_valid_range() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("SSN: 001-01-0001");
        assert!(
            dets.iter().any(|d| d.entity_type == "US_SSN"),
            "min valid SSN not detected: {dets:?}"
        );
        assert!(result.contains("[US_SSN_"));
    }

    #[test]
    fn test_us_ssn_area_666_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("SSN: 666-12-3456");
        assert!(
            !dets.iter().any(|d| d.entity_type == "US_SSN"),
            "SSN area 666 should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_us_ssn_area_900_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("social security 900-12-3456");
        assert!(
            !dets.iter().any(|d| d.entity_type == "US_SSN"),
            "SSN area 900+ should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_us_ssn_zero_serial_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("SSN: 123-45-0000");
        assert!(
            !dets.iter().any(|d| d.entity_type == "US_SSN"),
            "SSN with 0000 serial should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_us_ssn_various_contexts() {
        let inputs = [
            "social security number: 123-45-6789",
            "SSN 123-45-6789",
            "tax id 123-45-6789",
        ];
        for input in &inputs {
            let mut a = Anonymizer::new(0.0);
            let (_, dets) = a.anonymize_text(input);
            assert!(
                dets.iter().any(|d| d.entity_type == "US_SSN"),
                "US SSN not detected in '{input}': {dets:?}"
            );
        }
    }

    #[test]
    fn test_us_ssn_not_confused_with_date_dash() {
        let mut a = Anonymizer::new(0.0);
        // 2024-01-15 — looks like dashes but is a date
        let (_, dets) = a.anonymize_text("SSN: 2024-01-15");
        // This should be DATE_TIME, not US_SSN (date_iso8601 pattern)
        // 2024 as area is >=900 so SSN validator would reject anyway
        assert!(
            !dets.iter().any(|d| d.entity_type == "US_SSN"),
            "ISO date should not match as US_SSN: {dets:?}"
        );
    }

    #[test]
    fn test_us_ssn_roundtrip() {
        let mut a = Anonymizer::new(0.0);
        let input = "SSN: 123-45-6789";
        let (anon, _) = a.anonymize_text(input);
        let restored = a.mapping.restore(&anon);
        assert_eq!(restored, input, "US SSN roundtrip failed");
    }

    #[test]
    fn test_us_ssn_mixed_delimiters_rejected() {
        let mut a = Anonymizer::new(0.0);
        // dash + space mixed — should not match either pattern
        let (_, dets) = a.anonymize_text("SSN: 123-45 6789");
        assert!(
            !dets.iter().any(|d| d.entity_type == "US_SSN"),
            "mixed delimiters should be rejected: {dets:?}"
        );
        let (_, dets) = a.anonymize_text("SSN: 123 45-6789");
        assert!(
            !dets.iter().any(|d| d.entity_type == "US_SSN"),
            "mixed delimiters (space then dash) should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_us_ssn_max_valid_area() {
        let mut a = Anonymizer::new(0.0);
        // 899 is the highest valid area (900+ rejected)
        let (result, dets) = a.anonymize_text("SSN: 899-99-9999");
        assert!(
            dets.iter().any(|d| d.entity_type == "US_SSN"),
            "area 899 should be valid: {dets:?}"
        );
        assert!(result.contains("[US_SSN_"));
    }

    #[test]
    fn test_us_ssn_in_json() {
        // JSON walker anonymizes values independently — context keyword must be in the value itself
        let json = serde_json::json!({
            "note": "SSN: 123-45-6789"
        });
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_json_value(&json);
        assert!(
            dets.iter().any(|d| d.entity_type == "US_SSN"),
            "US SSN not detected in JSON: {dets:?}"
        );
        assert!(
            result["note"].as_str().unwrap().contains("[US_SSN_"),
            "JSON value not anonymized: {}",
            result["note"]
        );
    }

    #[test]
    fn test_us_ssn_in_json_bare_value_rejected() {
        // JSON key "ssn" is processed separately — it doesn't provide context to the value
        let json = serde_json::json!({
            "ssn": "123-45-6789"
        });
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_json_value(&json);
        assert!(
            !dets.iter().any(|d| d.entity_type == "US_SSN"),
            "bare SSN in JSON value without context should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_us_ssn_multiple_distinct_tokens() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("SSN: 123-45-6789, second SSN: 234-56-7890");
        let ssn_dets: Vec<_> = dets.iter().filter(|d| d.entity_type == "US_SSN").collect();
        assert_eq!(ssn_dets.len(), 2, "expected 2 SSN detections: {dets:?}");
        // Tokens use random hex, so just verify two distinct tokens exist
        let tokens: Vec<&str> = result
            .match_indices("[US_SSN_")
            .map(|(i, _)| {
                let end = result[i..].find(']').unwrap() + i + 1;
                &result[i..end]
            })
            .collect();
        assert_eq!(tokens.len(), 2, "expected 2 tokens in: {result}");
        assert_ne!(tokens[0], tokens[1], "tokens should be distinct: {result}");
    }

    #[test]
    fn test_us_ssn_duplicate_same_token() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("SSN: 123-45-6789, repeat SSN: 123-45-6789");
        let ssn_dets: Vec<_> = dets.iter().filter(|d| d.entity_type == "US_SSN").collect();
        assert_eq!(ssn_dets.len(), 2, "expected 2 SSN detections: {dets:?}");
        let tokens: Vec<&str> = result
            .match_indices("[US_SSN_")
            .map(|(i, _)| {
                let end = result[i..].find(']').unwrap() + i + 1;
                &result[i..end]
            })
            .collect();
        assert_eq!(tokens.len(), 2, "expected 2 tokens in: {result}");
        assert_eq!(
            tokens[0], tokens[1],
            "same SSN should get same token: {result}"
        );
    }

    #[test]
    fn test_us_ssn_at_string_start() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("SSN 123-45-6789 is on file");
        assert!(
            dets.iter().any(|d| d.entity_type == "US_SSN"),
            "SSN at start not detected: {dets:?}"
        );
        assert!(result.contains("[US_SSN_"));
    }

    #[test]
    fn test_us_ssn_at_string_end() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("tax 123-45-6789");
        assert!(
            dets.iter().any(|d| d.entity_type == "US_SSN"),
            "SSN at end not detected: {dets:?}"
        );
        assert!(result.contains("[US_SSN_"));
    }

    #[test]
    fn test_us_ssn_compact_no_delimiters_rejected() {
        let mut a = Anonymizer::new(0.0);
        // 9 digits without delimiters — no pattern matches this, too many false positives
        let (_, dets) = a.anonymize_text("SSN: 123456789");
        assert!(
            !dets.iter().any(|d| d.entity_type == "US_SSN"),
            "compact SSN without delimiters should not match: {dets:?}"
        );
    }

    #[test]
    fn test_us_ssn_context_beyond_window_rejected() {
        let mut a = Anonymizer::new(0.0);
        // CONTEXT_WINDOW is 80 chars — place keyword >80 chars before the SSN
        let padding = "x".repeat(81);
        let input = format!("SSN {padding} 123-45-6789");
        let (_, dets) = a.anonymize_text(&input);
        assert!(
            !dets.iter().any(|d| d.entity_type == "US_SSN"),
            "SSN with context beyond 80-char window should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_us_ssn_context_after() {
        let mut a = Anonymizer::new(0.0);
        // Context keyword AFTER the SSN — window looks both directions
        let (result, dets) = a.anonymize_text("number 123-45-6789 is the SSN");
        assert!(
            dets.iter().any(|d| d.entity_type == "US_SSN"),
            "SSN with context after should be detected: {dets:?}"
        );
        assert!(result.contains("[US_SSN_"));
    }

    #[test]
    fn test_us_ssn_context_case_insensitive() {
        let mut a = Anonymizer::new(0.0);
        let inputs = [
            "ssn: 123-45-6789",            // all lowercase
            "Ssn: 123-45-6789",            // title case
            "Social Security 123-45-6789", // mixed case
        ];
        for input in &inputs {
            let mut a2 = Anonymizer::new(0.0);
            let (_, dets) = a2.anonymize_text(input);
            assert!(
                dets.iter().any(|d| d.entity_type == "US_SSN"),
                "case-insensitive context failed for '{input}': {dets:?}"
            );
        }
        // Also verify uppercase-only (already tested elsewhere, but confirms parity)
        let (_, dets) = a.anonymize_text("SSN: 123-45-6789");
        assert!(
            dets.iter().any(|d| d.entity_type == "US_SSN"),
            "uppercase SSN context should work"
        );
    }

    #[test]
    fn test_us_ssn_context_across_newline() {
        let mut a = Anonymizer::new(0.0);
        // Context keyword on previous line, SSN on next — within 80-char window
        let (result, dets) = a.anonymize_text("SSN:\n123-45-6789");
        assert!(
            dets.iter().any(|d| d.entity_type == "US_SSN"),
            "SSN with context across newline should be detected: {dets:?}"
        );
        assert!(result.contains("[US_SSN_"));
    }

    // ── MEDICAL_LICENSE battle tests ──

    #[test]
    fn test_medical_license_dea_number() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("DEA number: AB1234567");
        assert!(
            dets.iter().any(|d| d.entity_type == "MEDICAL_LICENSE"),
            "DEA number not detected: {dets:?}"
        );
        assert!(result.contains("[MEDICAL_LICENSE_"));
    }

    #[test]
    fn test_medical_license_npi() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("NPI provider D1234567890");
        assert!(
            dets.iter().any(|d| d.entity_type == "MEDICAL_LICENSE"),
            "NPI number not detected: {dets:?}"
        );
        assert!(result.contains("[MEDICAL_LICENSE_"));
    }

    #[test]
    fn test_medical_license_not_random_alphanum() {
        let mut a = Anonymizer::new(0.0);
        // Without medical context, XX1234567 should not match
        let (_, dets) = a.anonymize_text("reference XX1234567");
        assert!(
            !dets.iter().any(|d| d.entity_type == "MEDICAL_LICENSE"),
            "random alphanumeric should not match without context: {dets:?}"
        );
    }

    // ── Cross-entity battle tests ──

    #[test]
    fn test_log_line_mixed_phase1_entities() {
        let mut a = Anonymizer::new(0.0);
        let input = "2024-06-15T10:30:00Z device mac 0A:1B:2C:3D:4E:5F connected from 2001:db8::1";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "DATE_TIME"),
            "ISO date not detected in mixed line: {dets:?}"
        );
        assert!(
            dets.iter().any(|d| d.entity_type == "MAC_ADDRESS"),
            "MAC not detected in mixed line: {dets:?}"
        );
        assert!(
            dets.iter().any(|d| d.entity_type == "IP_ADDRESS"),
            "IPv6 not detected in mixed line: {dets:?}"
        );
        assert!(!result.contains("0A:1B:2C:3D:4E:5F"));
        assert!(!result.contains("2001:db8::1"));
    }

    #[test]
    fn test_network_audit_log() {
        let mut a = Anonymizer::new(0.0);
        let input = "2024-03-15T08:45:00+01:00 DHCP lease: mac 00:1A:2B:3C:4D:5E \
            assigned 192.168.1.42, gateway 192.168.1.1";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "DATE_TIME"),
            "timestamp missing: {dets:?}"
        );
        assert!(
            dets.iter().any(|d| d.entity_type == "MAC_ADDRESS"),
            "MAC missing: {dets:?}"
        );
        let ip_count = dets
            .iter()
            .filter(|d| d.entity_type == "IP_ADDRESS")
            .count();
        assert!(ip_count >= 2, "should detect at least 2 IPs: {dets:?}");
        assert!(!result.contains("00:1A:2B:3C:4D:5E"));
        assert!(!result.contains("192.168.1.42"));
    }

    #[test]
    fn test_banking_log_iban_and_phone() {
        let mut a = Anonymizer::new(0.0);
        let input = "virement de 500EUR sur le compte iban DE89370400440532013000, \
            contact tel +49 30 12345678";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
            "IBAN not detected: {dets:?}"
        );
        assert!(
            dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
            "phone not detected: {dets:?}"
        );
        assert!(!result.contains("DE89370400440532013000"));
        assert!(!result.contains("+49"));
    }

    #[test]
    fn test_json_with_phase1_entities() {
        let mut a = Anonymizer::new(0.0);
        let json = serde_json::json!({
            "timestamp": "2024-01-15T14:30:00Z",
            "device_mac": "AB:CD:EF:01:23:45",
            "client_ip": "192.168.1.100",
            "iban": "iban DE89370400440532013000",
            "contact": "tel +44 20 7946 0958"
        });
        let (result, dets) = a.anonymize_json_value(&json);
        assert!(
            dets.iter().any(|d| d.entity_type == "DATE_TIME"),
            "JSON timestamp not detected: {dets:?}"
        );
        assert!(
            dets.iter().any(|d| d.entity_type == "MAC_ADDRESS"),
            "JSON MAC not detected: {dets:?}"
        );
        assert!(
            dets.iter().any(|d| d.entity_type == "IP_ADDRESS"),
            "JSON IP not detected: {dets:?}"
        );
        assert!(result["device_mac"]
            .as_str()
            .unwrap()
            .contains("[MAC_ADDRESS_"));
    }

    #[test]
    fn test_all_phase1_entities_coexist() {
        // Verify no entity type accidentally shadows another
        let mut a = Anonymizer::new(0.0);
        let input = "2024-01-15T10:00:00Z server 192.168.1.1 ipv6 2001:db8::1 \
            mac 0A:1B:2C:3D:4E:5F contact tel +44 20 7946 0958 \
            iban DE89370400440532013000 SSN: 123-45-6789 poste 4510 \
            medical license ME12345678";
        let (result, dets) = a.anonymize_text(input);
        let types: Vec<&str> = dets.iter().map(|d| &*d.entity_type).collect();
        assert!(types.contains(&"DATE_TIME"), "DATE_TIME missing: {types:?}");
        assert!(
            types.contains(&"IP_ADDRESS"),
            "IP_ADDRESS missing: {types:?}"
        );
        assert!(
            types.contains(&"MAC_ADDRESS"),
            "MAC_ADDRESS missing: {types:?}"
        );
        assert!(
            types.contains(&"PHONE_NUMBER"),
            "PHONE_NUMBER missing: {types:?}"
        );
        assert!(types.contains(&"IBAN_CODE"), "IBAN_CODE missing: {types:?}");
        assert!(types.contains(&"US_SSN"), "US_SSN missing: {types:?}");
        assert!(
            types.contains(&"PHONE_EXTENSION"),
            "PHONE_EXTENSION missing: {types:?}"
        );
        assert!(
            types.contains(&"MEDICAL_LICENSE"),
            "MEDICAL_LICENSE missing: {types:?}"
        );
        // Verify all PII is actually replaced in output
        assert!(!result.contains("192.168.1.1"));
        assert!(!result.contains("0A:1B:2C:3D:4E:5F"));
        assert!(!result.contains("123-45-6789"));
        assert!(!result.contains("ME12345678"));
    }

    // ── Operator tests ──

    #[test]
    fn test_operator_token_default() {
        let mut a = Anonymizer::new(0.0);
        assert_eq!(a.operator, Operator::Token);
        let (result, dets) = a.anonymize_text("contact john@example.com");
        assert!(!result.contains("john@example.com"));
        assert!(result.contains("[EMAIL_ADDRESS_"));
        assert_eq!(dets.len(), 1);
    }

    #[test]
    fn test_operator_redact_removes_pii() {
        let mut a = Anonymizer::new(0.0);
        a.operator = Operator::Redact;
        let (result, dets) = a.anonymize_text("contact john@example.com now");
        assert_eq!(result, "contact  now");
        assert!(!result.contains("john@example.com"));
        assert!(!result.contains("[EMAIL_ADDRESS"));
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].entity_type, "EMAIL_ADDRESS");
    }

    #[test]
    fn test_operator_keep_preserves_original() {
        let mut a = Anonymizer::new(0.0);
        a.operator = Operator::Keep;
        let input = "contact john@example.com now";
        let (result, dets) = a.anonymize_text(input);
        assert_eq!(result, input);
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].entity_type, "EMAIL_ADDRESS");
    }

    #[test]
    fn test_operator_redact_multiple_entities() {
        let mut a = Anonymizer::new(0.0);
        a.operator = Operator::Redact;
        let (result, dets) = a.anonymize_text("email: john@example.com, ip: 192.168.1.1");
        assert!(!result.contains("john@example.com"));
        assert!(!result.contains("192.168.1.1"));
        assert_eq!(result, "email: , ip: ");
        assert_eq!(dets.len(), 2);
    }

    #[test]
    fn test_operator_keep_still_detects() {
        let mut a = Anonymizer::new(0.0);
        a.operator = Operator::Keep;
        let (_, dets) = a.anonymize_text("email: john@example.com, ip: 192.168.1.1");
        assert_eq!(dets.len(), 2);
        let types: Vec<&str> = dets.iter().map(|d| d.entity_type).collect();
        assert!(types.contains(&"EMAIL_ADDRESS"));
        assert!(types.contains(&"IP_ADDRESS"));
    }

    #[test]
    fn test_operator_redact_no_mapping_entries() {
        let mut a = Anonymizer::new(0.0);
        a.operator = Operator::Redact;
        let _ = a.anonymize_text("john@example.com");
        assert!(a.mapping.mappings.is_empty());
    }

    #[test]
    fn test_operator_keep_no_mapping_entries() {
        let mut a = Anonymizer::new(0.0);
        a.operator = Operator::Keep;
        let _ = a.anonymize_text("john@example.com");
        assert!(a.mapping.mappings.is_empty());
    }

    #[test]
    fn test_operator_redact_json() {
        let mut a = Anonymizer::new(0.0);
        a.operator = Operator::Redact;
        let json: Value = serde_json::from_str(r#"{"email": "john@example.com"}"#).unwrap();
        let (result, dets) = a.anonymize_json_value(&json);
        assert_eq!(result["email"], "");
        assert_eq!(dets.len(), 1);
    }

    #[test]
    fn test_operator_keep_json() {
        let mut a = Anonymizer::new(0.0);
        a.operator = Operator::Keep;
        let json: Value = serde_json::from_str(r#"{"email": "john@example.com"}"#).unwrap();
        let (result, dets) = a.anonymize_json_value(&json);
        assert_eq!(result["email"], "john@example.com");
        assert_eq!(dets.len(), 1);
    }

    #[test]
    fn test_operator_mask_default() {
        let mut a = Anonymizer::new(0.0);
        a.operator = Operator::Mask;
        let (result, dets) = a.anonymize_text("contact john@example.com now");
        // "john@example.com" = 16 chars → 16 asterisks
        assert_eq!(result, "contact **************** now");
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].entity_type, "EMAIL_ADDRESS");
    }

    #[test]
    fn test_operator_mask_custom_char() {
        let mut a = Anonymizer::new(0.0);
        a.operator = Operator::Mask;
        a.mask_config.mask_char = '#';
        let (result, _) = a.anonymize_text("contact john@example.com now");
        assert_eq!(result, "contact ################ now");
    }

    #[test]
    fn test_operator_mask_fixed_count() {
        let mut a = Anonymizer::new(0.0);
        a.operator = Operator::Mask;
        a.mask_config.fixed_count = Some(5);
        // "john@example.com" is 16 chars, mask 5 from start → 11 visible at end
        let (result, _) = a.anonymize_text("contact john@example.com now");
        assert_eq!(result, "contact *****example.com now");
    }

    #[test]
    fn test_operator_mask_from_end() {
        let mut a = Anonymizer::new(0.0);
        a.operator = Operator::Mask;
        a.mask_config.fixed_count = Some(5);
        a.mask_config.from_end = true;
        // "john@example.com" is 16 chars, mask 5 from end → 11 visible at start
        let (result, _) = a.anonymize_text("contact john@example.com now");
        assert_eq!(result, "contact john@exampl***** now");
    }

    #[test]
    fn test_operator_mask_full_length_default() {
        let mut a = Anonymizer::new(0.0);
        a.operator = Operator::Mask;
        let (result, _) = a.anonymize_text("192.168.1.1");
        assert_eq!(result, "***********");
        assert_eq!(result.len(), "192.168.1.1".len());
    }

    #[test]
    fn test_operator_mask_no_mapping_entries() {
        let mut a = Anonymizer::new(0.0);
        a.operator = Operator::Mask;
        let _ = a.anonymize_text("john@example.com");
        assert!(a.mapping.mappings.is_empty());
    }

    #[test]
    fn test_operator_mask_json() {
        let mut a = Anonymizer::new(0.0);
        a.operator = Operator::Mask;
        let json: Value = serde_json::from_str(r#"{"ip": "192.168.1.1"}"#).unwrap();
        let (result, dets) = a.anonymize_json_value(&json);
        assert_eq!(result["ip"], "***********");
        assert_eq!(dets.len(), 1);
    }

    #[test]
    fn test_operator_mask_multiple_entities() {
        let mut a = Anonymizer::new(0.0);
        a.operator = Operator::Mask;
        let (result, dets) = a.anonymize_text("email: john@example.com, ip: 192.168.1.1");
        assert!(!result.contains("john@example.com"));
        assert!(!result.contains("192.168.1.1"));
        assert!(result.contains("****************")); // 16-char email mask
        assert!(result.contains("***********")); // 11-char IP mask
        assert_eq!(dets.len(), 2);
    }

    #[test]
    fn test_apply_mask_fixed_count_exceeds_length() {
        let masked = apply_mask(
            "abc",
            &MaskConfig {
                mask_char: '*',
                fixed_count: Some(10),
                from_end: false,
            },
        );
        assert_eq!(masked, "***");
    }

    #[test]
    fn test_apply_mask_zero_count() {
        let masked = apply_mask(
            "hello",
            &MaskConfig {
                mask_char: '*',
                fixed_count: Some(0),
                from_end: false,
            },
        );
        assert_eq!(masked, "hello");
    }

    // ── US_BANK_NUMBER tests ──

    #[test]
    fn test_us_bank_number_detected_with_context() {
        let mut anon = Anonymizer::new(0.0);
        let input = "Account number: 12345678901234";
        let (result, dets) = anon.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "US_BANK_NUMBER"),
            "US_BANK_NUMBER not detected in: {input}"
        );
        assert!(result.contains("[US_BANK_NUMBER_"));
    }

    #[test]
    fn test_us_bank_number_not_detected_without_context() {
        let mut anon = Anonymizer::new(0.0);
        let input = "Order ref 12345678901234 confirmed";
        let (_, dets) = anon.anonymize_text(input);
        assert!(
            !dets.iter().any(|d| d.entity_type == "US_BANK_NUMBER"),
            "US_BANK_NUMBER should not match without context"
        );
    }

    // ── US_DRIVER_LICENSE tests ──

    #[test]
    fn test_us_driver_license_alpha_short() {
        let mut anon = Anonymizer::new(0.0);
        // Use "DMV" context — specific to driver license, no overlap with MEDICAL_LICENSE
        let input = "DMV D1234567";
        let (result, dets) = anon.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "US_DRIVER_LICENSE"),
            "US_DRIVER_LICENSE not detected in: {input} — dets: {dets:?}"
        );
        assert!(result.contains("[US_DRIVER_LICENSE_"));
    }

    #[test]
    fn test_us_driver_license_alpha_long() {
        let mut anon = Anonymizer::new(0.0);
        // 1 letter + 12 digits (IL/FL/MD/MI/MN format)
        let input = "DMV D123456789012";
        let (result, dets) = anon.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "US_DRIVER_LICENSE"),
            "US_DRIVER_LICENSE (long) not detected in: {input} — dets: {dets:?}"
        );
        assert!(result.contains("[US_DRIVER_LICENSE_"));
    }

    #[test]
    fn test_us_driver_license_alpha_pair() {
        let mut anon = Anonymizer::new(0.0);
        let input = "DL: WA1234567";
        let (result, dets) = anon.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "US_DRIVER_LICENSE"),
            "US_DRIVER_LICENSE (pair) not detected in: {input} — dets: {dets:?}"
        );
        assert!(result.contains("[US_DRIVER_LICENSE_"));
    }

    #[test]
    fn test_us_driver_license_not_detected_without_context() {
        let mut anon = Anonymizer::new(0.0);
        let input = "Reference code: D1234567 in database";
        let (_, dets) = anon.anonymize_text(input);
        assert!(
            !dets.iter().any(|d| d.entity_type == "US_DRIVER_LICENSE"),
            "US_DRIVER_LICENSE should not match without context"
        );
    }

    // ── US_ITIN tests ──

    #[test]
    fn test_us_itin_detected_with_context() {
        let mut anon = Anonymizer::new(0.0);
        let input = "ITIN: 912-70-1234";
        let (result, dets) = anon.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "US_ITIN"),
            "US_ITIN not detected in: {input}"
        );
        assert!(result.contains("[US_ITIN_"));
    }

    #[test]
    fn test_us_itin_rejects_invalid_group() {
        let mut anon = Anonymizer::new(0.0);
        // Group 66 is invalid for ITIN
        let input = "ITIN: 912-66-1234";
        let (_, dets) = anon.anonymize_text(input);
        assert!(
            !dets.iter().any(|d| d.entity_type == "US_ITIN"),
            "US_ITIN should reject invalid group 66"
        );
    }

    #[test]
    fn test_us_itin_not_confused_with_ssn() {
        let mut anon = Anonymizer::new(0.0);
        // SSN context but 9xx area → SSN validator rejects, ITIN validator accepts
        let input = "Tax ITIN: 999-88-1234";
        let (_, dets) = anon.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "US_ITIN"),
            "US_ITIN should match 9xx numbers with ITIN context"
        );
        // SSN should not match 9xx area
        assert!(
            !dets.iter().any(|d| d.entity_type == "US_SSN"),
            "US_SSN should reject 9xx area"
        );
    }

    // ── US_PASSPORT tests ──

    #[test]
    fn test_us_passport_detected_with_context() {
        let mut anon = Anonymizer::new(0.0);
        let input = "Passport number: 123456789";
        let (result, dets) = anon.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "US_PASSPORT"),
            "US_PASSPORT not detected in: {input}"
        );
        assert!(result.contains("[US_PASSPORT_"));
    }

    #[test]
    fn test_us_passport_not_detected_without_context() {
        let mut anon = Anonymizer::new(0.0);
        let input = "Serial: 123456789 confirmed";
        let (_, dets) = anon.anonymize_text(input);
        assert!(
            !dets.iter().any(|d| d.entity_type == "US_PASSPORT"),
            "US_PASSPORT should not match without context"
        );
    }

    // ── US_MBI tests ──

    #[test]
    fn test_us_mbi_detected_with_context() {
        let mut anon = Anonymizer::new(0.0);
        // Valid MBI: 1EG4TE500K3
        let input = "Medicare MBI: 1EG4TE500K3";
        let (result, dets) = anon.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "US_MBI"),
            "US_MBI not detected in: {input}"
        );
        assert!(result.contains("[US_MBI_"));
    }

    #[test]
    fn test_us_mbi_rejects_excluded_letters() {
        let mut anon = Anonymizer::new(0.0);
        // 'S' in position 2 is excluded
        let input = "Medicare MBI: 1SG4TE500K3";
        let (_, dets) = anon.anonymize_text(input);
        assert!(
            !dets.iter().any(|d| d.entity_type == "US_MBI"),
            "US_MBI should reject excluded letter S in position 2"
        );
    }

    #[test]
    fn test_us_mbi_not_detected_without_context() {
        let mut anon = Anonymizer::new(0.0);
        let input = "Code: 1EG4TE500K3 reference";
        let (_, dets) = anon.anonymize_text(input);
        assert!(
            !dets.iter().any(|d| d.entity_type == "US_MBI"),
            "US_MBI should not match without context"
        );
    }

    // ── ABA_ROUTING tests ──

    #[test]
    fn test_aba_routing_detected_with_context() {
        let mut anon = Anonymizer::new(0.0);
        // Chase: 021000021 (valid checksum)
        let input = "Routing number: 021000021";
        let (result, dets) = anon.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "ABA_ROUTING"),
            "ABA_ROUTING not detected in: {input}"
        );
        assert!(result.contains("[ABA_ROUTING_"));
    }

    #[test]
    fn test_aba_routing_rejects_bad_checksum() {
        let mut anon = Anonymizer::new(0.0);
        let input = "Routing number: 021000022";
        let (_, dets) = anon.anonymize_text(input);
        assert!(
            !dets.iter().any(|d| d.entity_type == "ABA_ROUTING"),
            "ABA_ROUTING should reject bad checksum"
        );
    }

    #[test]
    fn test_aba_routing_not_detected_without_context() {
        let mut anon = Anonymizer::new(0.0);
        let input = "Reference: 021000021 noted";
        let (_, dets) = anon.anonymize_text(input);
        assert!(
            !dets.iter().any(|d| d.entity_type == "ABA_ROUTING"),
            "ABA_ROUTING should not match without context"
        );
    }

    // ── UK_NHS tests ──

    #[test]
    fn test_uk_nhs_with_context_spaced() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("NHS number: 943 476 5919");
        assert!(
            dets.iter().any(|d| d.entity_type == "UK_NHS"),
            "UK NHS not detected: {dets:?}"
        );
        assert!(result.contains("[UK_NHS_"));
    }

    #[test]
    fn test_uk_nhs_with_context_compact() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("Patient NHS: 9434765919");
        assert!(
            dets.iter().any(|d| d.entity_type == "UK_NHS"),
            "UK NHS compact not detected: {dets:?}"
        );
        assert!(result.contains("[UK_NHS_"));
    }

    #[test]
    fn test_uk_nhs_no_context_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("code 943 476 5919 end");
        assert!(
            !dets.iter().any(|d| d.entity_type == "UK_NHS"),
            "UK NHS without context should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_uk_nhs_bad_checksum_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("NHS number: 943 476 5910");
        assert!(
            !dets.iter().any(|d| d.entity_type == "UK_NHS"),
            "UK NHS with bad checksum should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_uk_nhs_remainder_10_rejected() {
        let mut a = Anonymizer::new(0.0);
        // 4300000000 has remainder 10 → invalid
        let (_, dets) = a.anonymize_text("NHS number: 430 000 0000");
        assert!(
            !dets.iter().any(|d| d.entity_type == "UK_NHS"),
            "UK NHS with remainder-10 should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_uk_nhs_check_digit_zero() {
        let mut a = Anonymizer::new(0.0);
        // 0000000000: sum=0, 0%11=0, 11-0=11 → check digit 0 ✓
        let (result, dets) = a.anonymize_text("NHS number: 0000000000");
        assert!(
            dets.iter().any(|d| d.entity_type == "UK_NHS"),
            "UK NHS with check digit 0 not detected: {dets:?}"
        );
        assert!(result.contains("[UK_NHS_"));
    }

    #[test]
    fn test_uk_nhs_roundtrip() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("NHS number: 943 476 5919");
        assert!(!result.contains("943 476 5919"));
        assert!(result.contains("[UK_NHS_"));
    }

    #[test]
    fn test_uk_nhs_various_contexts() {
        let mut a = Anonymizer::new(0.0);
        let contexts = [
            "patient ID 9434765919",
            "hospital record: 943 476 5919",
            "GP surgery ref 9434765919",
            "health service number: 943 476 5919",
        ];
        for ctx in &contexts {
            let (_, dets) = a.anonymize_text(ctx);
            assert!(
                dets.iter().any(|d| d.entity_type == "UK_NHS"),
                "UK NHS not detected in: {ctx}"
            );
        }
    }

    // ── UK_NINO tests ──

    #[test]
    fn test_uk_nino_with_context_spaced() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("National insurance: AB 12 34 56 C");
        assert!(
            dets.iter().any(|d| d.entity_type == "UK_NINO"),
            "UK NINO not detected: {dets:?}"
        );
        assert!(result.contains("[UK_NINO_"));
    }

    #[test]
    fn test_uk_nino_with_context_compact() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("NINO: AB123456C");
        assert!(
            dets.iter().any(|d| d.entity_type == "UK_NINO"),
            "UK NINO compact not detected: {dets:?}"
        );
        assert!(result.contains("[UK_NINO_"));
    }

    #[test]
    fn test_uk_nino_no_context_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("reference AB 12 34 56 C noted");
        assert!(
            !dets.iter().any(|d| d.entity_type == "UK_NINO"),
            "UK NINO without context should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_uk_nino_blocklisted_prefix_rejected() {
        let mut a = Anonymizer::new(0.0);
        let blocked = ["BG", "GB", "NK", "KN", "NT", "TN", "ZZ"];
        for prefix in &blocked {
            let input = format!("NINO: {prefix} 12 34 56 A");
            let (_, dets) = a.anonymize_text(&input);
            assert!(
                !dets.iter().any(|d| d.entity_type == "UK_NINO"),
                "UK NINO with blocked prefix {prefix} should be rejected: {dets:?}"
            );
        }
    }

    #[test]
    fn test_uk_nino_valid_suffix_letters() {
        let mut a = Anonymizer::new(0.0);
        for suffix in ['A', 'B', 'C', 'D'] {
            let input = format!("NI number: AB 12 34 56 {suffix}");
            let (_, dets) = a.anonymize_text(&input);
            assert!(
                dets.iter().any(|d| d.entity_type == "UK_NINO"),
                "UK NINO with suffix {suffix} not detected"
            );
        }
    }

    #[test]
    fn test_uk_nino_various_contexts() {
        let mut a = Anonymizer::new(0.0);
        let contexts = [
            "HMRC reference: CE123456A",
            "tax PAYE number CE123456A",
            "contributions: CE 12 34 56 A",
            "insurance number is CE123456A",
        ];
        for ctx in &contexts {
            let (_, dets) = a.anonymize_text(ctx);
            assert!(
                dets.iter().any(|d| d.entity_type == "UK_NINO"),
                "UK NINO not detected in: {ctx}"
            );
        }
    }

    #[test]
    fn test_uk_nino_roundtrip() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("NI number: AB 12 34 56 C");
        assert!(!result.contains("AB 12 34 56 C"));
        assert!(result.contains("[UK_NINO_"));
    }

    // ── ES NIF tests ──

    #[test]
    fn test_es_nif_with_context() {
        let mut a = Anonymizer::new(0.0);
        // 12345678Z: 12345678 % 23 = 14 → letter table[14] = 'Z' ✓
        let (result, dets) = a.anonymize_text("DNI: 12345678Z");
        assert!(
            dets.iter().any(|d| d.entity_type == "ES_NIF"),
            "ES NIF not detected: {dets:?}"
        );
        assert!(result.contains("[ES_NIF_"));
    }

    #[test]
    fn test_es_nif_with_separator() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("NIF: 12345678-Z");
        assert!(
            dets.iter().any(|d| d.entity_type == "ES_NIF"),
            "ES NIF with separator not detected: {dets:?}"
        );
        assert!(result.contains("[ES_NIF_"));
    }

    #[test]
    fn test_es_nif_no_context_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("code 12345678Z end");
        assert!(
            !dets.iter().any(|d| d.entity_type == "ES_NIF"),
            "ES NIF without context should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_es_nif_bad_checksum_rejected() {
        let mut a = Anonymizer::new(0.0);
        // 12345678Z is valid, 12345678A is invalid (expected Z)
        let (_, dets) = a.anonymize_text("DNI: 12345678A");
        assert!(
            !dets.iter().any(|d| d.entity_type == "ES_NIF"),
            "ES NIF with bad checksum should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_es_nif_various_context_keywords() {
        let mut a = Anonymizer::new(0.0);
        let contexts = [
            "documento nacional: 12345678Z",
            "identificación fiscal 12345678Z",
            "documento de identidad 12345678Z",
        ];
        for ctx in &contexts {
            let (_, dets) = a.anonymize_text(ctx);
            assert!(
                dets.iter().any(|d| d.entity_type == "ES_NIF"),
                "ES NIF not detected in: {ctx}"
            );
        }
    }

    #[test]
    fn test_es_nif_known_valid_numbers() {
        let mut a = Anonymizer::new(0.0);
        // 00000000T: 0 % 23 = 0 → 'T'
        let (result, dets) = a.anonymize_text("DNI: 00000000T");
        assert!(
            dets.iter().any(|d| d.entity_type == "ES_NIF"),
            "ES NIF 00000000T not detected: {dets:?}"
        );
        assert!(result.contains("[ES_NIF_"));
    }

    #[test]
    fn test_es_nif_roundtrip() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("NIF: 12345678Z");
        assert!(!result.contains("12345678Z"));
        assert!(result.contains("[ES_NIF_"));
    }

    // ── ES NIE tests ──

    #[test]
    fn test_es_nie_with_context() {
        let mut a = Anonymizer::new(0.0);
        // X→0, 01234567 % 23 = 19 → 'L'
        let (result, dets) = a.anonymize_text("NIE: X1234567L");
        assert!(
            dets.iter().any(|d| d.entity_type == "ES_NIE"),
            "ES NIE not detected: {dets:?}"
        );
        assert!(result.contains("[ES_NIE_"));
    }

    #[test]
    fn test_es_nie_y_prefix() {
        let mut a = Anonymizer::new(0.0);
        // Y→1, 11234567 % 23 = 10 → 'X'
        let (result, dets) = a.anonymize_text("NIE: Y1234567X");
        assert!(
            dets.iter().any(|d| d.entity_type == "ES_NIE"),
            "ES NIE Y-prefix not detected: {dets:?}"
        );
        assert!(result.contains("[ES_NIE_"));
    }

    #[test]
    fn test_es_nie_z_prefix() {
        let mut a = Anonymizer::new(0.0);
        // Z→2, 21234567 % 23 = 1 → 'R'
        let (result, dets) = a.anonymize_text("NIE extranjero: Z1234567R");
        assert!(
            dets.iter().any(|d| d.entity_type == "ES_NIE"),
            "ES NIE Z-prefix not detected: {dets:?}"
        );
        assert!(result.contains("[ES_NIE_"));
    }

    #[test]
    fn test_es_nie_with_separators() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("NIE: X-1234567-L");
        assert!(
            dets.iter().any(|d| d.entity_type == "ES_NIE"),
            "ES NIE with separators not detected: {dets:?}"
        );
        assert!(result.contains("[ES_NIE_"));
    }

    #[test]
    fn test_es_nie_no_context_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("ref X1234567L noted");
        assert!(
            !dets.iter().any(|d| d.entity_type == "ES_NIE"),
            "ES NIE without context should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_es_nie_bad_checksum_rejected() {
        let mut a = Anonymizer::new(0.0);
        // X1234567L is valid, X1234567A is not
        let (_, dets) = a.anonymize_text("NIE: X1234567A");
        assert!(
            !dets.iter().any(|d| d.entity_type == "ES_NIE"),
            "ES NIE with bad checksum should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_es_nie_various_context_keywords() {
        let mut a = Anonymizer::new(0.0);
        let contexts = [
            "extranjero: X1234567L",
            "residencia X1234567L",
            "foreigner ID X1234567L",
        ];
        for ctx in &contexts {
            let (_, dets) = a.anonymize_text(ctx);
            assert!(
                dets.iter().any(|d| d.entity_type == "ES_NIE"),
                "ES NIE not detected in: {ctx}"
            );
        }
    }

    #[test]
    fn test_es_nie_roundtrip() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("NIE: X1234567L");
        assert!(!result.contains("X1234567L"));
        assert!(result.contains("[ES_NIE_"));
    }

    // ── IT_FISCAL_CODE tests ──

    #[test]
    fn test_it_fiscal_code_with_context() {
        let mut a = Anonymizer::new(0.0);
        // AAABBB00A00A000J is a constructed valid code (checksum verified)
        let input = "codice fiscale: AAABBB00A00A000J";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "IT_FISCAL_CODE"),
            "Should detect IT_FISCAL_CODE: {dets:?}"
        );
        assert!(!result.contains("AAABBB00A00A000J"));
        assert!(result.contains("[IT_FISCAL_CODE_"));
    }

    #[test]
    fn test_it_fiscal_code_without_context() {
        let mut a = Anonymizer::new(0.0);
        // Fiscal code has context_required: false, so it should detect even without keywords
        let input = "The code is AAABBB00A00A000J";
        let (_, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "IT_FISCAL_CODE"),
            "IT_FISCAL_CODE should match without context (score=0.85): {dets:?}"
        );
    }

    #[test]
    fn test_it_fiscal_code_bad_checksum_rejected() {
        let mut a = Anonymizer::new(0.0);
        // AAABBB00A00A000K — wrong check letter (should be J)
        let input = "codice fiscale: AAABBB00A00A000K";
        let (_, dets) = a.anonymize_text(input);
        assert!(
            !dets.iter().any(|d| d.entity_type == "IT_FISCAL_CODE"),
            "Bad checksum should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_it_fiscal_code_invalid_month_not_matched() {
        let mut a = Anonymizer::new(0.0);
        // Invalid month letter 'F' — regex won't match [ABCDEHLMPRST]
        let input = "codice fiscale: AAABBB00F00A000X";
        let (_, dets) = a.anonymize_text(input);
        assert!(
            !dets.iter().any(|d| d.entity_type == "IT_FISCAL_CODE"),
            "Invalid month letter should not match: {dets:?}"
        );
    }

    #[test]
    fn test_it_fiscal_code_context_boost() {
        let mut a = Anonymizer::new(0.0);
        let input_ctx = "codice fiscale: AAABBB00A00A000J";
        let input_no_ctx = "data: AAABBB00A00A000J";
        let (_, dets_ctx) = a.anonymize_text(input_ctx);
        let (_, dets_no_ctx) = a.anonymize_text(input_no_ctx);
        let score_ctx = dets_ctx
            .iter()
            .find(|d| d.entity_type == "IT_FISCAL_CODE")
            .unwrap()
            .score;
        let score_no_ctx = dets_no_ctx
            .iter()
            .find(|d| d.entity_type == "IT_FISCAL_CODE")
            .unwrap()
            .score;
        assert!(
            score_ctx > score_no_ctx,
            "Context should boost score: {score_ctx} vs {score_no_ctx}"
        );
    }

    #[test]
    fn test_it_fiscal_code_roundtrip() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("CF: AAABBB00A00A000J");
        assert!(!result.contains("AAABBB00A00A000J"));
        assert!(result.contains("[IT_FISCAL_CODE_"));
    }

    // ── IT_DRIVER_LICENSE tests ──

    #[test]
    fn test_it_driver_license_with_context() {
        let mut a = Anonymizer::new(0.0);
        let input = "patente: AB1234567X";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "IT_DRIVER_LICENSE"),
            "Should detect IT_DRIVER_LICENSE: {dets:?}"
        );
        assert!(!result.contains("AB1234567X"));
        assert!(result.contains("[IT_DRIVER_LICENSE_"));
    }

    #[test]
    fn test_it_driver_license_no_context_rejected() {
        let mut a = Anonymizer::new(0.0);
        let input = "code: AB1234567X";
        let (_, dets) = a.anonymize_text(input);
        assert!(
            !dets.iter().any(|d| d.entity_type == "IT_DRIVER_LICENSE"),
            "IT_DRIVER_LICENSE without context should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_it_driver_license_various_contexts() {
        let mut a = Anonymizer::new(0.0);
        let contexts = [
            "patente di guida: AB1234567X",
            "driver license: AB1234567X",
            "driving licence: AB1234567X",
        ];
        for input in &contexts {
            let (_, dets) = a.anonymize_text(input);
            assert!(
                dets.iter().any(|d| d.entity_type == "IT_DRIVER_LICENSE"),
                "Should detect with context '{input}': {dets:?}"
            );
        }
    }

    // ── IT_VAT_CODE tests ──

    #[test]
    fn test_it_vat_code_with_context() {
        let mut a = Anonymizer::new(0.0);
        let input = "Partita IVA: 12345678901";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "IT_VAT_CODE"),
            "Should detect IT_VAT_CODE: {dets:?}"
        );
        assert!(!result.contains("12345678901"));
        assert!(result.contains("[IT_VAT_CODE_"));
    }

    #[test]
    fn test_it_vat_code_no_context_rejected() {
        let mut a = Anonymizer::new(0.0);
        let input = "number: 12345678901";
        let (_, dets) = a.anonymize_text(input);
        assert!(
            !dets.iter().any(|d| d.entity_type == "IT_VAT_CODE"),
            "IT_VAT_CODE without context should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_it_vat_code_piva_context() {
        let mut a = Anonymizer::new(0.0);
        let input = "P.IVA 12345678901";
        let (_, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "IT_VAT_CODE"),
            "Should detect with P.IVA context: {dets:?}"
        );
    }

    // ── IT_PASSPORT tests ──

    #[test]
    fn test_it_passport_with_context() {
        let mut a = Anonymizer::new(0.0);
        let input = "passaporto: AB1234567";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "IT_PASSPORT"),
            "Should detect IT_PASSPORT: {dets:?}"
        );
        assert!(!result.contains("AB1234567"));
        assert!(result.contains("[IT_PASSPORT_"));
    }

    #[test]
    fn test_it_passport_no_context_rejected() {
        let mut a = Anonymizer::new(0.0);
        let input = "ref: AB1234567";
        let (_, dets) = a.anonymize_text(input);
        assert!(
            !dets.iter().any(|d| d.entity_type == "IT_PASSPORT"),
            "IT_PASSPORT without context should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_it_passport_various_contexts() {
        let mut a = Anonymizer::new(0.0);
        let contexts = [
            "passport: AB1234567",
            "passaporto n. AB1234567",
            "travel document AB1234567",
        ];
        for input in &contexts {
            let (_, dets) = a.anonymize_text(input);
            assert!(
                dets.iter().any(|d| d.entity_type == "IT_PASSPORT"),
                "Should detect with context '{input}': {dets:?}"
            );
        }
    }

    // ── IT_IDENTITY_CARD tests ──

    #[test]
    fn test_it_identity_card_with_context() {
        let mut a = Anonymizer::new(0.0);
        let input = "carta d'identità: CA12345AB";
        let (result, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "IT_IDENTITY_CARD"),
            "Should detect IT_IDENTITY_CARD: {dets:?}"
        );
        assert!(!result.contains("CA12345AB"));
        assert!(result.contains("[IT_IDENTITY_CARD_"));
    }

    #[test]
    fn test_it_identity_card_no_context_rejected() {
        let mut a = Anonymizer::new(0.0);
        let input = "ref: CA12345AB";
        let (_, dets) = a.anonymize_text(input);
        assert!(
            !dets.iter().any(|d| d.entity_type == "IT_IDENTITY_CARD"),
            "IT_IDENTITY_CARD without context should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_it_identity_card_cie_context() {
        let mut a = Anonymizer::new(0.0);
        let input = "CIE: CA12345AB";
        let (_, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "IT_IDENTITY_CARD"),
            "Should detect with CIE context: {dets:?}"
        );
    }

    #[test]
    fn test_it_identity_card_various_contexts() {
        let mut a = Anonymizer::new(0.0);
        let contexts = [
            "carta identità: CA12345AB",
            "identity card: CA12345AB",
            "documento: CA12345AB",
        ];
        for input in &contexts {
            let (_, dets) = a.anonymize_text(input);
            assert!(
                dets.iter().any(|d| d.entity_type == "IT_IDENTITY_CARD"),
                "Should detect with context '{input}': {dets:?}"
            );
        }
    }

    #[test]
    fn test_it_identity_card_roundtrip() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("CIE: CA12345AB");
        assert!(!result.contains("CA12345AB"));
        assert!(result.contains("[IT_IDENTITY_CARD_"));
    }

    // ── IN_AADHAAR detection tests ──

    #[test]
    fn test_in_aadhaar_with_context_spaced() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("Aadhaar: 4991 1866 5246");
        assert!(
            dets.iter().any(|d| d.entity_type == "IN_AADHAAR"),
            "IN_AADHAAR not detected: {dets:?}"
        );
        assert!(result.contains("[IN_AADHAAR_"));
    }

    #[test]
    fn test_in_aadhaar_with_context_compact() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("UID number: 499118665246");
        assert!(
            dets.iter().any(|d| d.entity_type == "IN_AADHAAR"),
            "IN_AADHAAR compact not detected: {dets:?}"
        );
        assert!(result.contains("[IN_AADHAAR_"));
    }

    #[test]
    fn test_in_aadhaar_no_context_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("number 499118665246 end");
        assert!(
            !dets.iter().any(|d| d.entity_type == "IN_AADHAAR"),
            "IN_AADHAAR without context should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_in_aadhaar_bad_verhoeff_rejected() {
        let mut a = Anonymizer::new(0.0);
        // Flip last digit: 499118665246 is valid, 499118665247 should fail
        let (_, dets) = a.anonymize_text("Aadhaar: 4991 1866 5247");
        assert!(
            !dets.iter().any(|d| d.entity_type == "IN_AADHAAR"),
            "IN_AADHAAR with bad Verhoeff should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_in_aadhaar_repeated_digits_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("Aadhaar: 222222222222");
        assert!(
            !dets.iter().any(|d| d.entity_type == "IN_AADHAAR"),
            "IN_AADHAAR with repeated digits should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_in_aadhaar_roundtrip() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("Aadhaar: 4991 1866 5246");
        assert!(!result.contains("4991 1866 5246"));
        assert!(result.contains("[IN_AADHAAR_"));
    }

    // ── IN_PAN detection tests ──

    #[test]
    fn test_in_pan_with_context() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("PAN card: ABCPD1234E");
        assert!(
            dets.iter().any(|d| d.entity_type == "IN_PAN"),
            "IN_PAN not detected: {dets:?}"
        );
        assert!(result.contains("[IN_PAN_"));
    }

    #[test]
    fn test_in_pan_no_context_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("code ABCPD1234E end");
        assert!(
            !dets.iter().any(|d| d.entity_type == "IN_PAN"),
            "IN_PAN without context should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_in_pan_various_holder_types() {
        let mut a = Anonymizer::new(0.0);
        // P = Personal, C = Company, H = HUF, F = Firm
        for holder_type in ['P', 'C', 'H', 'F', 'A', 'T', 'B', 'L', 'J', 'G'] {
            let pan = format!("ABC{}D1234E", holder_type);
            let input = format!("PAN: {pan}");
            let (result, dets) = a.anonymize_text(&input);
            assert!(
                dets.iter().any(|d| d.entity_type == "IN_PAN"),
                "IN_PAN with holder type {holder_type} not detected: {dets:?}"
            );
            assert!(result.contains("[IN_PAN_"));
        }
    }

    #[test]
    fn test_in_pan_roundtrip() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("Income tax PAN: ABCPD1234E");
        assert!(!result.contains("ABCPD1234E"));
        assert!(result.contains("[IN_PAN_"));
    }

    // ── IN_VEHICLE_REGISTRATION detection tests ──

    #[test]
    fn test_in_vehicle_registration_with_context() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("Vehicle registration: MH-02-AB-1234");
        assert!(
            dets.iter()
                .any(|d| d.entity_type == "IN_VEHICLE_REGISTRATION"),
            "IN_VEHICLE_REGISTRATION not detected: {dets:?}"
        );
        assert!(result.contains("[IN_VEHICLE_REGISTRATION_"));
    }

    #[test]
    fn test_in_vehicle_registration_no_context_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("code MH02AB1234 end");
        assert!(
            !dets
                .iter()
                .any(|d| d.entity_type == "IN_VEHICLE_REGISTRATION"),
            "IN_VEHICLE_REGISTRATION without context should be rejected: {dets:?}"
        );
    }

    // ── IN_PASSPORT detection tests ──

    #[test]
    fn test_in_passport_with_context() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("Passport number: J1234567");
        assert!(
            dets.iter().any(|d| d.entity_type == "IN_PASSPORT"),
            "IN_PASSPORT not detected: {dets:?}"
        );
        assert!(result.contains("[IN_PASSPORT_"));
    }

    #[test]
    fn test_in_passport_no_context_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("code J1234567 end");
        assert!(
            !dets.iter().any(|d| d.entity_type == "IN_PASSPORT"),
            "IN_PASSPORT without context should be rejected: {dets:?}"
        );
    }

    // ── IN_VOTER detection tests ──

    #[test]
    fn test_in_voter_with_context() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("Voter ID: ABC1234567");
        assert!(
            dets.iter().any(|d| d.entity_type == "IN_VOTER"),
            "IN_VOTER not detected: {dets:?}"
        );
        assert!(result.contains("[IN_VOTER_"));
    }

    #[test]
    fn test_in_voter_no_context_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("code ABC1234567 end");
        assert!(
            !dets.iter().any(|d| d.entity_type == "IN_VOTER"),
            "IN_VOTER without context should be rejected: {dets:?}"
        );
    }

    // ── IN_GSTIN detection tests ──

    #[test]
    fn test_in_gstin_with_context() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("GST: 27AAPFU0939F1ZV");
        assert!(
            dets.iter().any(|d| d.entity_type == "IN_GSTIN"),
            "IN_GSTIN not detected: {dets:?}"
        );
        assert!(result.contains("[IN_GSTIN_"));
    }

    #[test]
    fn test_in_gstin_no_context_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("code 27AAPFU0939F1ZV end");
        assert!(
            !dets.iter().any(|d| d.entity_type == "IN_GSTIN"),
            "IN_GSTIN without context should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_in_gstin_bad_state_code_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("GST: 00AAPFU0939F1ZV");
        assert!(
            !dets.iter().any(|d| d.entity_type == "IN_GSTIN"),
            "IN_GSTIN with bad state code should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_in_gstin_roundtrip() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("GSTIN number: 27AAPFU0939F1ZV");
        assert!(!result.contains("27AAPFU0939F1ZV"));
        assert!(result.contains("[IN_GSTIN_"));
    }

    #[test]
    fn test_in_gstin_various_contexts() {
        let mut a = Anonymizer::new(0.0);
        let contexts = [
            "GST number: 27AAPFU0939F1ZV",
            "GSTIN: 27AAPFU0939F1ZV",
            "goods and services tax 27AAPFU0939F1ZV",
        ];
        for ctx in &contexts {
            let (_, dets) = a.anonymize_text(ctx);
            assert!(
                dets.iter().any(|d| d.entity_type == "IN_GSTIN"),
                "IN_GSTIN not detected in: {ctx}"
            );
        }
    }

    // ── AU_ABN tests ──

    #[test]
    fn test_au_abn_with_context_formatted() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("ABN: 51 824 753 556");
        assert!(
            dets.iter().any(|d| d.entity_type == "AU_ABN"),
            "AU ABN not detected: {dets:?}"
        );
        assert!(result.contains("[AU_ABN_"));
    }

    #[test]
    fn test_au_abn_with_context_compact() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("ABN: 51824753556");
        assert!(
            dets.iter().any(|d| d.entity_type == "AU_ABN"),
            "AU ABN compact not detected: {dets:?}"
        );
        assert!(result.contains("[AU_ABN_"));
    }

    #[test]
    fn test_au_abn_no_context_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("code 51824753556 end");
        assert!(
            !dets.iter().any(|d| d.entity_type == "AU_ABN"),
            "AU ABN without context should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_au_abn_bad_checksum_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("ABN: 51824753557");
        assert!(
            !dets.iter().any(|d| d.entity_type == "AU_ABN"),
            "AU ABN with bad checksum should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_au_abn_various_contexts() {
        let mut a = Anonymizer::new(0.0);
        let contexts = [
            "australian business number 51 824 753 556",
            "GST registered ABN: 51 824 753 556",
            "Tax invoice ABN 51 824 753 556",
        ];
        for ctx in &contexts {
            let (_, dets) = a.anonymize_text(ctx);
            assert!(
                dets.iter().any(|d| d.entity_type == "AU_ABN"),
                "AU ABN not detected in: {ctx}"
            );
        }
    }

    #[test]
    fn test_au_abn_roundtrip() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("ABN: 51 824 753 556");
        assert!(!result.contains("51 824 753 556"));
        assert!(result.contains("[AU_ABN_"));
    }

    // ── AU_ACN tests ──

    #[test]
    fn test_au_acn_with_context_formatted() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("ACN: 004 085 616");
        assert!(
            dets.iter().any(|d| d.entity_type == "AU_ACN"),
            "AU ACN not detected: {dets:?}"
        );
        assert!(result.contains("[AU_ACN_"));
    }

    #[test]
    fn test_au_acn_with_context_compact() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("ACN: 004085616");
        assert!(
            dets.iter().any(|d| d.entity_type == "AU_ACN"),
            "AU ACN compact not detected: {dets:?}"
        );
        assert!(result.contains("[AU_ACN_"));
    }

    #[test]
    fn test_au_acn_no_context_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("code 004085616 end");
        assert!(
            !dets.iter().any(|d| d.entity_type == "AU_ACN"),
            "AU ACN without context should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_au_acn_bad_checksum_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("ACN: 004085617");
        assert!(
            !dets.iter().any(|d| d.entity_type == "AU_ACN"),
            "AU ACN with bad checksum should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_au_acn_various_contexts() {
        let mut a = Anonymizer::new(0.0);
        let contexts = [
            "australian company number 004 085 616",
            "ASIC registered ACN: 004 085 616",
            "corporation ACN 004 085 616",
        ];
        for ctx in &contexts {
            let (_, dets) = a.anonymize_text(ctx);
            assert!(
                dets.iter().any(|d| d.entity_type == "AU_ACN"),
                "AU ACN not detected in: {ctx}"
            );
        }
    }

    #[test]
    fn test_au_acn_roundtrip() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("ACN: 004 085 616");
        assert!(!result.contains("004 085 616"));
        assert!(result.contains("[AU_ACN_"));
    }

    // ── AU_TFN tests ──

    #[test]
    fn test_au_tfn_with_context_formatted() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("TFN: 123 456 782");
        assert!(
            dets.iter().any(|d| d.entity_type == "AU_TFN"),
            "AU TFN not detected: {dets:?}"
        );
        assert!(result.contains("[AU_TFN_"));
    }

    #[test]
    fn test_au_tfn_with_context_compact() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("TFN: 123456782");
        assert!(
            dets.iter().any(|d| d.entity_type == "AU_TFN"),
            "AU TFN compact not detected: {dets:?}"
        );
        assert!(result.contains("[AU_TFN_"));
    }

    #[test]
    fn test_au_tfn_no_context_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("code 123456782 end");
        assert!(
            !dets.iter().any(|d| d.entity_type == "AU_TFN"),
            "AU TFN without context should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_au_tfn_bad_checksum_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("TFN: 123456789");
        assert!(
            !dets.iter().any(|d| d.entity_type == "AU_TFN"),
            "AU TFN with bad checksum should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_au_tfn_various_contexts() {
        let mut a = Anonymizer::new(0.0);
        let contexts = [
            "tax file number 123 456 782",
            "ATO tax file 123 456 782",
            "tax number: 123 456 782",
        ];
        for ctx in &contexts {
            let (_, dets) = a.anonymize_text(ctx);
            assert!(
                dets.iter().any(|d| d.entity_type == "AU_TFN"),
                "AU TFN not detected in: {ctx}"
            );
        }
    }

    #[test]
    fn test_au_tfn_roundtrip() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("TFN: 123 456 782");
        assert!(!result.contains("123 456 782"));
        assert!(result.contains("[AU_TFN_"));
    }

    // ── AU_MEDICARE tests ──

    #[test]
    fn test_au_medicare_with_context_formatted() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("Medicare: 2123 45670 1");
        assert!(
            dets.iter().any(|d| d.entity_type == "AU_MEDICARE"),
            "AU MEDICARE not detected: {dets:?}"
        );
        assert!(result.contains("[AU_MEDICARE_"));
    }

    #[test]
    fn test_au_medicare_with_context_compact() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("Medicare: 2123456701");
        assert!(
            dets.iter().any(|d| d.entity_type == "AU_MEDICARE"),
            "AU MEDICARE compact not detected: {dets:?}"
        );
        assert!(result.contains("[AU_MEDICARE_"));
    }

    #[test]
    fn test_au_medicare_no_context_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("code 2123456701 end");
        assert!(
            !dets.iter().any(|d| d.entity_type == "AU_MEDICARE"),
            "AU MEDICARE without context should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_au_medicare_bad_checksum_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("Medicare: 2123456711");
        assert!(
            !dets.iter().any(|d| d.entity_type == "AU_MEDICARE"),
            "AU MEDICARE with bad checksum should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_au_medicare_various_contexts() {
        let mut a = Anonymizer::new(0.0);
        let contexts = [
            "medicare number 2123 45670 1",
            "health card 2123 45670 1",
            "Medicare card: 2123 45670 1",
        ];
        for ctx in &contexts {
            let (_, dets) = a.anonymize_text(ctx);
            assert!(
                dets.iter().any(|d| d.entity_type == "AU_MEDICARE"),
                "AU MEDICARE not detected in: {ctx}"
            );
        }
    }

    #[test]
    fn test_au_medicare_roundtrip() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("Medicare: 2123 45670 1");
        assert!(!result.contains("2123 45670 1"));
        assert!(result.contains("[AU_MEDICARE_"));
    }

    #[test]
    fn test_au_medicare_first_digit_range() {
        let mut a = Anonymizer::new(0.0);
        // First digit must be 2-6 for Medicare; digit 1 should not match
        let (_, dets) = a.anonymize_text("Medicare: 1123456701");
        assert!(
            !dets.iter().any(|d| d.entity_type == "AU_MEDICARE"),
            "AU MEDICARE with first digit 1 should be rejected: {dets:?}"
        );
    }

    // ── KR_RRN tests ──

    #[test]
    fn test_kr_rrn_with_context() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("Resident registration: 850101-1234566");
        assert!(
            dets.iter().any(|d| d.entity_type == "KR_RRN"),
            "KR_RRN not detected with context: {dets:?}"
        );
        assert!(!result.contains("850101-1234566"));
        assert!(result.contains("[KR_RRN_"));
    }

    #[test]
    fn test_kr_rrn_no_context_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("850101-1234566");
        assert!(
            !dets.iter().any(|d| d.entity_type == "KR_RRN"),
            "KR_RRN should not match without context: {dets:?}"
        );
    }

    #[test]
    fn test_kr_rrn_bad_checksum_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("Resident registration: 850101-1234567");
        assert!(
            !dets.iter().any(|d| d.entity_type == "KR_RRN"),
            "KR_RRN with bad checksum should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_kr_rrn_roundtrip() {
        let mut a = Anonymizer::new(0.0);
        let (result, _) = a.anonymize_text("주민등록: 850101-1234566");
        assert!(!result.contains("850101-1234566"));
        assert!(result.contains("[KR_RRN_"));
    }

    #[test]
    fn test_kr_rrn_various_contexts() {
        let mut a = Anonymizer::new(0.0);
        let contexts = [
            "resident registration number: 850101-1234566",
            "주민등록번호: 850101-1234566",
            "주민번호 850101-1234566",
            "RRN: 850101-1234566",
        ];
        for ctx in &contexts {
            let (_, dets) = a.anonymize_text(ctx);
            assert!(
                dets.iter().any(|d| d.entity_type == "KR_RRN"),
                "KR_RRN not detected with context '{ctx}': {dets:?}"
            );
        }
    }

    // ── KR_FRN tests ──

    #[test]
    fn test_kr_frn_with_context() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("Foreign registration: 850101-5234567");
        assert!(
            dets.iter().any(|d| d.entity_type == "KR_FRN"),
            "KR_FRN not detected with context: {dets:?}"
        );
        assert!(!result.contains("850101-5234567"));
        assert!(result.contains("[KR_FRN_"));
    }

    #[test]
    fn test_kr_frn_no_context_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("850101-5234567");
        assert!(
            !dets.iter().any(|d| d.entity_type == "KR_FRN"),
            "KR_FRN should not match without context: {dets:?}"
        );
    }

    #[test]
    fn test_kr_frn_bad_checksum_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("Foreign registration: 850101-5234560");
        assert!(
            !dets.iter().any(|d| d.entity_type == "KR_FRN"),
            "KR_FRN with bad checksum should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_kr_frn_various_contexts() {
        let mut a = Anonymizer::new(0.0);
        let contexts = [
            "alien registration: 850101-5234567",
            "외국인등록: 850101-5234567",
            "FRN: 850101-5234567",
        ];
        for ctx in &contexts {
            let (_, dets) = a.anonymize_text(ctx);
            assert!(
                dets.iter().any(|d| d.entity_type == "KR_FRN"),
                "KR_FRN not detected with context '{ctx}': {dets:?}"
            );
        }
    }

    // ── KR_BRN tests ──

    #[test]
    fn test_kr_brn_with_context() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("Business registration: 123-45-67891");
        assert!(
            dets.iter().any(|d| d.entity_type == "KR_BRN"),
            "KR_BRN not detected with context: {dets:?}"
        );
        assert!(!result.contains("123-45-67891"));
        assert!(result.contains("[KR_BRN_"));
    }

    #[test]
    fn test_kr_brn_no_context_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("123-45-67891");
        assert!(
            !dets.iter().any(|d| d.entity_type == "KR_BRN"),
            "KR_BRN should not match without context: {dets:?}"
        );
    }

    #[test]
    fn test_kr_brn_bad_checksum_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("Business registration: 123-45-67890");
        assert!(
            !dets.iter().any(|d| d.entity_type == "KR_BRN"),
            "KR_BRN with bad checksum should be rejected: {dets:?}"
        );
    }

    #[test]
    fn test_kr_brn_various_contexts() {
        let mut a = Anonymizer::new(0.0);
        let contexts = [
            "사업자등록번호: 123-45-67891",
            "business number: 123-45-67891",
            "BRN: 123-45-67891",
            "tax id: 123-45-67891",
        ];
        for ctx in &contexts {
            let (_, dets) = a.anonymize_text(ctx);
            assert!(
                dets.iter().any(|d| d.entity_type == "KR_BRN"),
                "KR_BRN not detected with context '{ctx}': {dets:?}"
            );
        }
    }

    // ── KR_DRIVER_LICENSE tests ──

    #[test]
    fn test_kr_driver_license_with_context() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("Driver license: 11-22-123456-01");
        assert!(
            dets.iter().any(|d| d.entity_type == "KR_DRIVER_LICENSE"),
            "KR_DRIVER_LICENSE not detected with context: {dets:?}"
        );
        assert!(!result.contains("11-22-123456-01"));
        assert!(result.contains("[KR_DRIVER_LICENSE_"));
    }

    #[test]
    fn test_kr_driver_license_no_context_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("11-22-123456-01");
        assert!(
            !dets.iter().any(|d| d.entity_type == "KR_DRIVER_LICENSE"),
            "KR_DRIVER_LICENSE should not match without context: {dets:?}"
        );
    }

    #[test]
    fn test_kr_driver_license_various_regions() {
        let mut a = Anonymizer::new(0.0);
        // Test various valid regional codes (11=Seoul, 12=Busan, 28=Sejong)
        let regions = ["11", "12", "19", "20", "28"];
        for r in &regions {
            let input = format!("운전면허: {r}-03-456789-01");
            let (_, dets) = a.anonymize_text(&input);
            assert!(
                dets.iter().any(|d| d.entity_type == "KR_DRIVER_LICENSE"),
                "KR_DRIVER_LICENSE not detected for region {r}: {dets:?}"
            );
        }
    }

    #[test]
    fn test_kr_driver_license_invalid_region_rejected() {
        let mut a = Anonymizer::new(0.0);
        // Region 10 is below valid range (11-28)
        let (_, dets) = a.anonymize_text("Driver license: 10-22-123456-01");
        assert!(
            !dets.iter().any(|d| d.entity_type == "KR_DRIVER_LICENSE"),
            "KR_DRIVER_LICENSE with invalid region 10 should be rejected: {dets:?}"
        );
        // Region 29 is above valid range
        let (_, dets) = a.anonymize_text("Driver license: 29-22-123456-01");
        assert!(
            !dets.iter().any(|d| d.entity_type == "KR_DRIVER_LICENSE"),
            "KR_DRIVER_LICENSE with invalid region 29 should be rejected: {dets:?}"
        );
    }

    // ── KR_PASSPORT tests ──

    #[test]
    fn test_kr_passport_with_context() {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text("Passport: M12345678");
        assert!(
            dets.iter().any(|d| d.entity_type == "KR_PASSPORT"),
            "KR_PASSPORT not detected with context: {dets:?}"
        );
        assert!(!result.contains("M12345678"));
        assert!(result.contains("[KR_PASSPORT_"));
    }

    #[test]
    fn test_kr_passport_no_context_rejected() {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text("M12345678");
        assert!(
            !dets.iter().any(|d| d.entity_type == "KR_PASSPORT"),
            "KR_PASSPORT should not match without context: {dets:?}"
        );
    }

    #[test]
    fn test_kr_passport_various_type_letters() {
        let mut a = Anonymizer::new(0.0);
        for letter in ["M", "S", "R", "O", "D"] {
            let input = format!("여권번호: {letter}98765432");
            let (_, dets) = a.anonymize_text(&input);
            assert!(
                dets.iter().any(|d| d.entity_type == "KR_PASSPORT"),
                "KR_PASSPORT not detected for type letter {letter}: {dets:?}"
            );
        }
    }

    #[test]
    fn test_kr_passport_invalid_letter_rejected() {
        let mut a = Anonymizer::new(0.0);
        // 'A' is not a valid passport type letter
        let (_, dets) = a.anonymize_text("Passport: A12345678");
        assert!(
            !dets.iter().any(|d| d.entity_type == "KR_PASSPORT"),
            "KR_PASSPORT with invalid type letter should be rejected: {dets:?}"
        );
    }
}
