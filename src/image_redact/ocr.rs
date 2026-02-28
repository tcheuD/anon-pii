use std::fmt;
use std::path::Path;

use leptess::capi::TessPageIteratorLevel_RIL_WORD;
use leptess::LepTess;

use super::OcrWord;

/// Errors that can occur during OCR processing.
#[derive(Debug)]
pub enum OcrError {
    Init(String),
    ImageLoad(String),
    Extraction(String),
}

impl fmt::Display for OcrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OcrError::Init(msg) => write!(f, "OCR initialization failed: {msg}"),
            OcrError::ImageLoad(msg) => write!(f, "image load failed: {msg}"),
            OcrError::Extraction(msg) => write!(f, "OCR extraction failed: {msg}"),
        }
    }
}

impl std::error::Error for OcrError {}

/// Reconstructed text from OCR words, with byte-offset spans for each word.
///
/// `spans[i]` is the `(start, end)` byte range in `text` corresponding to `words[i]`
/// from the original input slice (not the sorted reading order).
///
/// When word count exceeds token count during `hybrid_reconstruct`, overflow words
/// receive a sentinel span `(0, 0)`. Use [`span_valid`](Self::span_valid) to check
/// for valid spans before slicing.
#[derive(Debug, Clone)]
pub struct ReconstructedText {
    pub text: String,
    pub spans: Vec<(usize, usize)>,
}

impl ReconstructedText {
    /// Returns `true` if the span at index `i` is valid (not a sentinel).
    ///
    /// Sentinel spans `(0, 0)` are assigned when `hybrid_reconstruct` has more
    /// word boxes than whitespace-delimited tokens in the full-page text.
    /// This method returns `false` for out-of-bounds indices as well.
    pub fn span_valid(&self, i: usize) -> bool {
        match self.spans.get(i) {
            Some(&(start, end)) => start != 0 || end != 0,
            None => false,
        }
    }
}

/// Extract words with bounding boxes from an image using Tesseract OCR.
pub fn extract_words(path: &Path, lang: &str) -> Result<Vec<OcrWord>, OcrError> {
    if lang.is_empty() || !lang.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return Err(OcrError::Init(format!("invalid language code: {lang}")));
    }
    if path.is_symlink() {
        return Err(OcrError::ImageLoad(
            "refusing to follow symlink".to_string(),
        ));
    }

    // Canonicalize the path so Leptonica can open it even when parent directories
    // are symlinks (e.g. macOS /tmp → /private/tmp).
    let canonical = path
        .canonicalize()
        .map_err(|e| OcrError::ImageLoad(format!("cannot resolve path {}: {e}", path.display())))?;

    let mut lt = LepTess::new(None, lang).map_err(|e| OcrError::Init(e.to_string()))?;
    lt.set_image(&canonical)
        .map_err(|e| OcrError::ImageLoad(e.to_string()))?;

    let boxes = match lt.get_component_boxes(TessPageIteratorLevel_RIL_WORD, true) {
        Some(boxes) => boxes,
        None => return Ok(Vec::new()),
    };

    let mut words = Vec::new();
    for b in &boxes {
        let geo = b.get_geometry();
        let x = geo.x.max(0);
        let y = geo.y.max(0);
        let w = geo.w.max(0);
        let h = geo.h.max(0);

        lt.set_rectangle(x, y, w, h);
        let text = lt
            .get_utf8_text()
            .map_err(|e| OcrError::Extraction(e.to_string()))?;
        let text = text.trim().to_string();
        if text.is_empty() {
            continue;
        }

        let conf = lt.mean_text_conf();
        words.push(OcrWord {
            text,
            x: x as u32,
            y: y as u32,
            width: w as u32,
            height: h as u32,
            confidence: (conf.clamp(0, 100) as f64) / 100.0,
        });
    }

    Ok(words)
}

/// Extract full-page text from an image using Tesseract OCR.
///
/// Unlike `extract_words`, this returns a single string without bounding boxes,
/// equivalent to running `tesseract <image> stdout`.
pub fn extract_text(path: &Path, lang: &str) -> Result<String, OcrError> {
    if lang.is_empty() || !lang.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return Err(OcrError::Init(format!("invalid language code: {lang}")));
    }
    if path.is_symlink() {
        return Err(OcrError::ImageLoad(
            "refusing to follow symlink".to_string(),
        ));
    }

    let canonical = path
        .canonicalize()
        .map_err(|e| OcrError::ImageLoad(format!("cannot resolve path {}: {e}", path.display())))?;

    let mut lt = LepTess::new(None, lang).map_err(|e| OcrError::Init(e.to_string()))?;
    lt.set_image(&canonical)
        .map_err(|e| OcrError::ImageLoad(e.to_string()))?;

    let text = lt
        .get_utf8_text()
        .map_err(|e| OcrError::Extraction(e.to_string()))?;

    Ok(text.trim_end().to_string())
}

/// Reconstruct reading-order text from OCR words, tracking byte offsets.
///
/// Groups words into lines by y-coordinate proximity, sorts each line by x,
/// and joins with spaces (within lines) and newlines (between lines).
/// Returns the full text and per-word byte spans in original input order.
pub fn reconstruct_text(words: &[OcrWord]) -> ReconstructedText {
    if words.is_empty() {
        return ReconstructedText {
            text: String::new(),
            spans: Vec::new(),
        };
    }

    // Pair each word with its original index
    let mut indexed: Vec<(usize, &OcrWord)> = words.iter().enumerate().collect();
    // Sort by (y, x) for reading order
    indexed.sort_by(|a, b| a.1.y.cmp(&b.1.y).then(a.1.x.cmp(&b.1.x)));

    // Group into lines using y-tolerance
    let mut lines: Vec<Vec<(usize, &OcrWord)>> = Vec::new();
    let mut current_line: Vec<(usize, &OcrWord)> = vec![indexed[0]];

    for &(idx, word) in &indexed[1..] {
        let last = current_line.last().unwrap().1;
        let tolerance = (last.height.min(word.height) / 2).max(1);
        let y_diff = (word.y as i64 - last.y as i64).unsigned_abs() as u32;
        if y_diff <= tolerance {
            current_line.push((idx, word));
        } else {
            lines.push(std::mem::take(&mut current_line));
            current_line.push((idx, word));
        }
    }
    lines.push(current_line);

    // Sort each line by x
    for line in &mut lines {
        line.sort_by_key(|(_, w)| w.x);
    }

    // Build text and track spans
    let mut text = String::new();
    // Will hold (original_index, start_byte, end_byte)
    let mut span_entries: Vec<(usize, usize, usize)> = Vec::with_capacity(words.len());

    for (line_idx, line) in lines.iter().enumerate() {
        if line_idx > 0 {
            text.push('\n');
        }
        for (word_idx, &(orig_idx, word)) in line.iter().enumerate() {
            if word_idx > 0 {
                text.push(' ');
            }
            let start = text.len();
            text.push_str(&word.text);
            let end = text.len();
            span_entries.push((orig_idx, start, end));
        }
    }

    // Sort spans back to original input order
    span_entries.sort_by_key(|(orig_idx, _, _)| *orig_idx);
    let spans = span_entries.into_iter().map(|(_, s, e)| (s, e)).collect();

    ReconstructedText { text, spans }
}

/// Align full-page OCR text with word-level bounding boxes.
///
/// Uses the clean full-page text (better quality) while mapping byte-offset
/// spans to the word boxes (for pixel-domain redaction). Words are sorted
/// into reading order, then greedily matched to whitespace-delimited tokens
/// in `full_text`.
pub fn hybrid_reconstruct(full_text: &str, words: &[OcrWord]) -> ReconstructedText {
    if words.is_empty() {
        return ReconstructedText {
            text: full_text.to_string(),
            spans: Vec::new(),
        };
    }

    // 1. Sort words into reading order (same y-grouping + x-sort as reconstruct_text)
    let mut indexed: Vec<(usize, &OcrWord)> = words.iter().enumerate().collect();
    indexed.sort_by(|a, b| a.1.y.cmp(&b.1.y).then(a.1.x.cmp(&b.1.x)));

    // Group into lines by y-tolerance
    let mut reading_order: Vec<(usize, &OcrWord)> = Vec::with_capacity(words.len());
    let mut lines: Vec<Vec<(usize, &OcrWord)>> = Vec::new();
    let mut current_line: Vec<(usize, &OcrWord)> = vec![indexed[0]];

    for &(idx, word) in &indexed[1..] {
        let last = current_line.last().unwrap().1;
        let tolerance = (last.height.min(word.height) / 2).max(1);
        let y_diff = (word.y as i64 - last.y as i64).unsigned_abs() as u32;
        if y_diff <= tolerance {
            current_line.push((idx, word));
        } else {
            lines.push(std::mem::take(&mut current_line));
            current_line.push((idx, word));
        }
    }
    lines.push(current_line);

    for line in &mut lines {
        line.sort_by_key(|(_, w)| w.x);
    }
    for line in &lines {
        reading_order.extend(line);
    }

    // 2. Collect whitespace-delimited tokens from full_text with byte positions
    let tokens: Vec<(usize, usize)> = TokenIter::new(full_text).collect();

    // 3. Greedy alignment: reading-order word N → token N
    // Stores (original_index, start_byte, end_byte)
    let mut span_entries: Vec<(usize, usize, usize)> = Vec::with_capacity(words.len());

    for (rank, &(orig_idx, _)) in reading_order.iter().enumerate() {
        if rank < tokens.len() {
            let (start, end) = tokens[rank];
            span_entries.push((orig_idx, start, end));
        } else {
            // More word boxes than tokens — fallback to (0, 0) sentinel
            span_entries.push((orig_idx, 0, 0));
        }
    }

    // 4. Sort back to original word order
    span_entries.sort_by_key(|(orig_idx, _, _)| *orig_idx);
    let spans = span_entries.into_iter().map(|(_, s, e)| (s, e)).collect();

    ReconstructedText {
        text: full_text.to_string(),
        spans,
    }
}

/// Try hybrid reconstruction using full-page text; fall back to word-only
/// reconstruction if `full_text` is an error.
pub fn try_hybrid_reconstruct(
    full_text: Result<String, OcrError>,
    words: &[OcrWord],
) -> ReconstructedText {
    match full_text {
        Ok(text) => hybrid_reconstruct(&text, words),
        Err(e) => {
            eprintln!(
                "Warning: full-page OCR failed ({e}), falling back to word-level reconstruction"
            );
            reconstruct_text(words)
        }
    }
}

/// Iterator over whitespace-delimited tokens, yielding `(start_byte, end_byte)`.
///
/// Uses `char::is_whitespace()` to handle Unicode whitespace characters such as
/// non-breaking space (`\u{00A0}`) and ideographic space (`\u{3000}`).
struct TokenIter<'a> {
    text: &'a str,
    pos: usize,
}

impl<'a> TokenIter<'a> {
    fn new(text: &'a str) -> Self {
        Self { text, pos: 0 }
    }
}

impl<'a> Iterator for TokenIter<'a> {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<Self::Item> {
        // Skip whitespace using char_indices for Unicode support
        for (byte_idx, ch) in self.text[self.pos..].char_indices() {
            if !ch.is_whitespace() {
                self.pos += byte_idx;
                break;
            }
            // If we're at the last character and it's whitespace, advance past it
            if self.pos + byte_idx + ch.len_utf8() >= self.text.len() {
                self.pos = self.text.len();
                return None;
            }
        }

        if self.pos >= self.text.len() {
            return None;
        }

        let start = self.pos;

        // Consume non-whitespace characters
        for (byte_idx, ch) in self.text[self.pos..].char_indices() {
            if ch.is_whitespace() {
                self.pos += byte_idx;
                return Some((start, self.pos));
            }
        }

        // Reached end of string
        self.pos = self.text.len();
        Some((start, self.pos))
    }
}
