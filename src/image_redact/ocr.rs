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
#[derive(Debug, Clone)]
pub struct ReconstructedText {
    pub text: String,
    pub spans: Vec<(usize, usize)>,
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

    let mut lt = LepTess::new(None, lang).map_err(|e| OcrError::Init(e.to_string()))?;
    lt.set_image(path)
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
