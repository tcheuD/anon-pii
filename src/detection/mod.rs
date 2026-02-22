use aes::Aes128;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use clap::ValueEnum;
use regex::Regex;
use serde_json::Value;
use unicode_normalization::UnicodeNormalization;

use crate::mapping::Mapping;
use crate::ner::{NerDetector, PERSON_BLOCKLIST};
use crate::patterns::{
    iban_mod97, luhn_check, valid_aba_routing, valid_au_abn, valid_au_acn, valid_au_medicare,
    valid_au_tfn, valid_card_prefix, valid_es_nie, valid_es_nif, valid_fi_identity_code,
    valid_in_aadhaar, valid_in_gstin, valid_it_fiscal_code, valid_kr_brn, valid_kr_frn,
    valid_kr_rrn, valid_mac, valid_pl_pesel, valid_sg_nric_fin, valid_si_emso, valid_si_tax_number,
    valid_th_tnin, valid_uk_nhs, valid_uk_nino, valid_us_itin, valid_us_ssn, CONTEXT_SCORE_BOOST,
    CONTEXT_WINDOW, CREW_CODE_BLOCKLIST, PATTERNS,
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
    /// Replace PII with a cryptographic hash
    Hash,
    /// AES-CBC encrypt PII (reversible without mapping file)
    Encrypt,
    /// Replace PII with a custom format string (e.g. '<{entity_type}>' or 'REDACTED')
    Custom,
}

type Aes128CbcEnc = cbc::Encryptor<Aes128>;
type Aes192CbcEnc = cbc::Encryptor<aes::Aes192>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum HashAlgo {
    #[default]
    Sha256,
    Sha512,
    Md5,
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

pub fn apply_mask(value: &str, config: &MaskConfig) -> String {
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

pub fn apply_hash(value: &str, algo: HashAlgo) -> String {
    use sha2::Digest;

    match algo {
        HashAlgo::Sha256 => {
            let hash = sha2::Sha256::digest(value.as_bytes());
            format!("{:x}", hash)
        }
        HashAlgo::Sha512 => {
            let hash = sha2::Sha512::digest(value.as_bytes());
            format!("{:x}", hash)
        }
        HashAlgo::Md5 => {
            let hash = md5::compute(value.as_bytes());
            format!("{:x}", hash)
        }
    }
}

pub fn apply_encrypt(value: &str, key: &[u8]) -> String {
    let mut iv_bytes = [0u8; 16];
    getrandom::fill(&mut iv_bytes).expect("getrandom failed");

    let ciphertext = match key.len() {
        16 => Aes128CbcEnc::new(key.into(), &iv_bytes.into())
            .encrypt_padded_vec_mut::<Pkcs7>(value.as_bytes()),
        24 => Aes192CbcEnc::new(key.into(), &iv_bytes.into())
            .encrypt_padded_vec_mut::<Pkcs7>(value.as_bytes()),
        32 => Aes256CbcEnc::new(key.into(), &iv_bytes.into())
            .encrypt_padded_vec_mut::<Pkcs7>(value.as_bytes()),
        _ => unreachable!("key length validated at CLI parse time"),
    };

    let mut hex = String::with_capacity((16 + ciphertext.len()) * 2);
    for b in &iv_bytes {
        hex.push_str(&format!("{:02x}", b));
    }
    for b in &ciphertext {
        hex.push_str(&format!("{:02x}", b));
    }
    format!("ENC[{hex}]")
}

pub fn apply_custom_replacement(entity_type: &str, format_str: &str) -> String {
    format_str.replace("{entity_type}", entity_type)
}

type Aes128CbcDec = cbc::Decryptor<Aes128>;
type Aes192CbcDec = cbc::Decryptor<aes::Aes192>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

fn decrypt_single(hex: &str, key: &[u8]) -> Option<String> {
    if hex.len() < 64 || !hex.len().is_multiple_of(2) {
        return None;
    }
    let raw: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .ok()?;
    if raw.len() < 32 {
        return None;
    }
    let (iv, ct) = raw.split_at(16);

    let plaintext = match key.len() {
        16 => Aes128CbcDec::new(key.into(), iv.into())
            .decrypt_padded_vec_mut::<Pkcs7>(ct)
            .ok()?,
        24 => Aes192CbcDec::new(key.into(), iv.into())
            .decrypt_padded_vec_mut::<Pkcs7>(ct)
            .ok()?,
        32 => Aes256CbcDec::new(key.into(), iv.into())
            .decrypt_padded_vec_mut::<Pkcs7>(ct)
            .ok()?,
        _ => return None,
    };
    String::from_utf8(plaintext).ok()
}

pub fn decrypt_encrypted(text: &str, key: &[u8]) -> String {
    let enc_re = Regex::new(r"ENC\[([0-9a-f]{64,})\]").unwrap();
    let mut result = String::with_capacity(text.len());
    let mut last = 0;
    for cap in enc_re.captures_iter(text) {
        let m = cap.get(0).unwrap();
        result.push_str(&text[last..m.start()]);
        if let Some(plaintext) = decrypt_single(&cap[1], key) {
            result.push_str(&plaintext);
        } else {
            result.push_str(m.as_str());
        }
        last = m.end();
    }
    result.push_str(&text[last..]);
    result
}

/// Parse a hex-encoded AES key, returning the raw bytes.
/// Accepts 32 (128-bit), 48 (192-bit), or 64 (256-bit) hex characters.
pub fn parse_encrypt_key(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() != 32 && hex.len() != 48 && hex.len() != 64 {
        return Err(format!(
            "encrypt key must be 32, 48, or 64 hex characters (128/192/256-bit), got {}",
            hex.len()
        ));
    }
    let bytes: Result<Vec<u8>, _> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect();
    bytes.map_err(|e| format!("invalid hex in encrypt key: {e}"))
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
    pub hash_algo: HashAlgo,
    pub encrypt_key: Option<Vec<u8>>,
    pub replace_with: Option<String>,
    pub context_boost: f64,
    pub min_score_with_context: f64,
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
                (pat.score + self.context_boost).min(1.0)
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
                if pat.entity_type == "SG_NRIC_FIN" && !valid_sg_nric_fin(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "PL_PESEL" && !valid_pl_pesel(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "SI_EMSO" && !valid_si_emso(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "SI_TAX_NUMBER" && !valid_si_tax_number(mat.as_str()) {
                    continue;
                }
                if pat.entity_type == "FI_PERSONAL_IDENTITY_CODE"
                    && !valid_fi_identity_code(mat.as_str())
                {
                    continue;
                }
                if pat.entity_type == "TH_TNIN" && !valid_th_tnin(mat.as_str()) {
                    continue;
                }

                // Compute detection score with optional context boost
                let boosted = !pat.context_required && !pat.context_keywords.is_empty() && has_ctx;
                let detection_score = if boosted {
                    (pat.score + self.context_boost).min(1.0)
                } else {
                    pat.score
                };

                // Per-detection threshold check (for boost patterns without context)
                if detection_score < self.threshold {
                    continue;
                }

                // Min-score-with-context filter: reject boosted matches below floor
                if boosted
                    && self.min_score_with_context > 0.0
                    && detection_score < self.min_score_with_context
                {
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
                    (pat.score + self.context_boost).min(1.0)
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
                    if pat.entity_type == "SG_NRIC_FIN" && !valid_sg_nric_fin(matched) {
                        continue;
                    }
                    if pat.entity_type == "PL_PESEL" && !valid_pl_pesel(matched) {
                        continue;
                    }
                    if pat.entity_type == "SI_EMSO" && !valid_si_emso(matched) {
                        continue;
                    }
                    if pat.entity_type == "SI_TAX_NUMBER" && !valid_si_tax_number(matched) {
                        continue;
                    }
                    if pat.entity_type == "FI_PERSONAL_IDENTITY_CODE"
                        && !valid_fi_identity_code(matched)
                    {
                        continue;
                    }
                    if pat.entity_type == "TH_TNIN" && !valid_th_tnin(matched) {
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
                    let boosted =
                        !pat.context_required && !pat.context_keywords.is_empty() && has_ctx;
                    let detection_score = if boosted {
                        (pat.score + self.context_boost).min(1.0)
                    } else {
                        pat.score
                    };
                    if detection_score < self.threshold {
                        continue;
                    }
                    if boosted
                        && self.min_score_with_context > 0.0
                        && detection_score < self.min_score_with_context
                    {
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
                                    if pat.entity_type == "SG_NRIC_FIN"
                                        && !valid_sg_nric_fin(mat.as_str())
                                    {
                                        continue;
                                    }
                                    if pat.entity_type == "PL_PESEL"
                                        && !valid_pl_pesel(mat.as_str())
                                    {
                                        continue;
                                    }
                                    if pat.entity_type == "SI_EMSO" && !valid_si_emso(mat.as_str())
                                    {
                                        continue;
                                    }
                                    if pat.entity_type == "SI_TAX_NUMBER"
                                        && !valid_si_tax_number(mat.as_str())
                                    {
                                        continue;
                                    }
                                    if pat.entity_type == "FI_PERSONAL_IDENTITY_CODE"
                                        && !valid_fi_identity_code(mat.as_str())
                                    {
                                        continue;
                                    }
                                    if pat.entity_type == "TH_TNIN" && !valid_th_tnin(mat.as_str())
                                    {
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
                Operator::Hash => apply_hash(&det.original, self.hash_algo),
                Operator::Encrypt => apply_encrypt(
                    &det.original,
                    self.encrypt_key.as_ref().expect("encrypt_key required"),
                ),
                Operator::Custom => apply_custom_replacement(
                    det.entity_type,
                    self.replace_with.as_deref().expect("replace_with required"),
                ),
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
mod tests;
