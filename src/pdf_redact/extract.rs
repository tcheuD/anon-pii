use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use lopdf::{Document, Encoding, Object};

use crate::patterns::MAX_INPUT_SIZE;

use super::{PdfError, PdfWord};

pub struct ReconstructedPdfText {
    pub text: String,
    pub spans: Vec<(usize, usize)>,
}

pub fn extract_words(path: &Path) -> Result<Vec<PdfWord>, PdfError> {
    let meta = fs::symlink_metadata(path).map_err(|e| PdfError::Io(e.to_string()))?;
    if meta.file_type().is_symlink() {
        return Err(PdfError::Io("refusing to follow symlink".to_string()));
    }
    if meta.len() > MAX_INPUT_SIZE {
        return Err(PdfError::Io(format!(
            "file too large: {} bytes (max {} bytes)",
            meta.len(),
            MAX_INPUT_SIZE
        )));
    }

    let bytes = fs::read(path).map_err(|e| PdfError::Io(e.to_string()))?;
    let doc = Document::load_mem(&bytes).map_err(|e| PdfError::Parse(e.to_string()))?;

    let pages: BTreeMap<u32, (u32, u16)> = doc.get_pages();
    let mut words = Vec::new();

    for (page_num, page_id) in &pages {
        let page_words = extract_words_from_page(&doc, *page_num, *page_id)?;
        words.extend(page_words);
    }

    Ok(words)
}

fn extract_words_from_page(
    doc: &Document,
    page_num: u32,
    page_id: (u32, u16),
) -> Result<Vec<PdfWord>, PdfError> {
    let content_data = doc
        .get_page_content_with_limit(page_id, MAX_INPUT_SIZE as usize)
        .map_err(|e| PdfError::Extraction(e.to_string()))?;

    let content = lopdf::content::Content::decode(&content_data)
        .map_err(|e| PdfError::Extraction(e.to_string()))?;

    let fonts = doc
        .get_page_fonts(page_id)
        .map_err(|e| PdfError::Extraction(e.to_string()))?;

    let encodings: BTreeMap<Vec<u8>, Encoding> = fonts
        .into_iter()
        .filter_map(|(name, font)| match font.get_font_encoding(doc) {
            Ok(enc) => Some((name, enc)),
            Err(_) => None,
        })
        .collect();

    let mut words = Vec::new();
    let mut text_matrix = TextMatrix::identity();
    let mut line_matrix = TextMatrix::identity();
    let mut current_encoding = None;
    let mut text_state = TextState::new();

    for op in &content.operations {
        match op.operator.as_str() {
            "BT" => {
                text_matrix = TextMatrix::identity();
                line_matrix = TextMatrix::identity();
            }
            "Tf" => {
                if let Some(Object::Name(font_name)) = op.operands.first() {
                    current_encoding = encodings.get(font_name);
                }
                if let Some(size) = op.operands.get(1) {
                    text_state.font_size = object_to_f64(size).unwrap_or(12.0).abs();
                }
            }
            "Tc" => {
                if let Some(value) = op.operands.first().and_then(object_to_f64) {
                    text_state.char_spacing = value;
                }
            }
            "Tw" => {
                if let Some(value) = op.operands.first().and_then(object_to_f64) {
                    text_state.word_spacing = value;
                }
            }
            "Tz" => {
                if let Some(value) = op.operands.first().and_then(object_to_f64) {
                    text_state.horizontal_scaling = value / 100.0;
                }
            }
            "TL" => {
                if let Some(value) = op.operands.first().and_then(object_to_f64) {
                    text_state.leading = value;
                }
            }
            "Tm" => {
                if op.operands.len() >= 6 {
                    let matrix = TextMatrix {
                        a: object_to_f64(&op.operands[0]).unwrap_or(1.0),
                        b: object_to_f64(&op.operands[1]).unwrap_or(0.0),
                        c: object_to_f64(&op.operands[2]).unwrap_or(0.0),
                        d: object_to_f64(&op.operands[3]).unwrap_or(1.0),
                        e: object_to_f64(&op.operands[4]).unwrap_or(0.0),
                        f: object_to_f64(&op.operands[5]).unwrap_or(0.0),
                    };
                    text_matrix = matrix;
                    line_matrix = matrix;
                }
            }
            "Td" | "TD" => {
                if op.operands.len() >= 2 {
                    let tx = object_to_f64(&op.operands[0]).unwrap_or(0.0);
                    let ty = object_to_f64(&op.operands[1]).unwrap_or(0.0);
                    if op.operator == "TD" {
                        text_state.leading = -ty;
                    }
                    line_matrix.translate(tx, ty);
                    text_matrix = line_matrix;
                }
            }
            "T*" => {
                line_matrix.translate(0.0, -text_state.leading);
                text_matrix = line_matrix;
            }
            "Tj" | "TJ" => {
                if let Some(encoding) = current_encoding {
                    let (x, y) = text_matrix.position();
                    let advance = push_words_from_operands(
                        &mut words,
                        encoding,
                        &op.operands,
                        page_num,
                        x,
                        y,
                        text_state,
                    );
                    text_matrix.translate(advance, 0.0);
                }
            }
            "'" | "\"" => {
                if op.operator == "\"" && op.operands.len() >= 3 {
                    if let Some(word_spacing) = op.operands.first().and_then(object_to_f64) {
                        text_state.word_spacing = word_spacing;
                    }
                    if let Some(char_spacing) = op.operands.get(1).and_then(object_to_f64) {
                        text_state.char_spacing = char_spacing;
                    }
                }
                line_matrix.translate(0.0, -text_state.leading);
                text_matrix = line_matrix;
                if let Some(encoding) = current_encoding {
                    let (x, y) = text_matrix.position();
                    let advance = push_words_from_operands(
                        &mut words,
                        encoding,
                        &op.operands,
                        page_num,
                        x,
                        y,
                        text_state,
                    );
                    text_matrix.translate(advance, 0.0);
                }
            }
            _ => {}
        }
    }

    Ok(words)
}

fn push_words_from_operands(
    words: &mut Vec<PdfWord>,
    encoding: &Encoding,
    operands: &[Object],
    page: u32,
    x: f64,
    y: f64,
    text_state: TextState,
) -> f64 {
    let mut text_run = ExtractedTextRun {
        words,
        page,
        x,
        y,
        text_state,
        current: String::new(),
        current_x: x,
        current_width: 0.0,
        advance: 0.0,
    };

    for operand in operands {
        push_words_from_operand(encoding, operand, &mut text_run);
    }

    text_run.finish_word();
    text_run.advance
}

struct ExtractedTextRun<'a> {
    words: &'a mut Vec<PdfWord>,
    page: u32,
    x: f64,
    y: f64,
    text_state: TextState,
    current: String,
    current_x: f64,
    current_width: f64,
    advance: f64,
}

impl ExtractedTextRun<'_> {
    fn push_text(&mut self, text: &str) {
        for ch in text.chars() {
            self.push_char(ch);
        }
    }

    fn push_char(&mut self, ch: char) {
        if ch.is_whitespace() {
            self.finish_word();
        } else {
            if self.current.is_empty() {
                self.current_x = self.x + self.advance;
            }
            self.current.push(ch);
            self.current_width += self.text_state.glyph_advance(ch);
        }
        self.advance += self.text_state.glyph_advance(ch);
    }

    fn apply_tj_adjustment(&mut self, value: f64) {
        if value < -100.0 {
            self.finish_word();
        }
        self.advance += self.text_state.tj_adjustment(value);
    }

    fn finish_word(&mut self) {
        if self.current.is_empty() {
            return;
        }

        self.words.push(PdfWord {
            text: std::mem::take(&mut self.current),
            page: self.page,
            x: self.current_x,
            y: self.y,
            width: self.current_width,
            height: self.text_state.font_size,
        });
        self.current_width = 0.0;
    }
}

fn push_words_from_operand(encoding: &Encoding, operand: &Object, text_run: &mut ExtractedTextRun) {
    match operand {
        Object::String(bytes, _) => {
            if let Ok(decoded) = Document::decode_text(encoding, bytes) {
                text_run.push_text(&decoded);
            }
        }
        Object::Array(items) => {
            for item in items {
                match item {
                    Object::Integer(i) => text_run.apply_tj_adjustment(*i as f64),
                    Object::Real(r) => text_run.apply_tj_adjustment(*r as f64),
                    _ => push_words_from_operand(encoding, item, text_run),
                }
            }
        }
        _ => {}
    }
}

#[derive(Clone, Copy)]
struct TextMatrix {
    a: f64,
    b: f64,
    c: f64,
    d: f64,
    e: f64,
    f: f64,
}

impl TextMatrix {
    fn identity() -> Self {
        Self {
            a: 1.0,
            b: 0.0,
            c: 0.0,
            d: 1.0,
            e: 0.0,
            f: 0.0,
        }
    }

    fn position(&self) -> (f64, f64) {
        (self.e, self.f)
    }

    fn translate(&mut self, tx: f64, ty: f64) {
        self.e += self.a * tx + self.c * ty;
        self.f += self.b * tx + self.d * ty;
    }
}

#[derive(Clone, Copy)]
struct TextState {
    font_size: f64,
    char_spacing: f64,
    word_spacing: f64,
    horizontal_scaling: f64,
    leading: f64,
}

impl TextState {
    fn new() -> Self {
        Self {
            font_size: 12.0,
            char_spacing: 0.0,
            word_spacing: 0.0,
            horizontal_scaling: 1.0,
            leading: 0.0,
        }
    }

    fn glyph_advance(&self, ch: char) -> f64 {
        let word_spacing = if ch == ' ' { self.word_spacing } else { 0.0 };
        (self.font_size * 0.6 + self.char_spacing + word_spacing) * self.horizontal_scaling
    }

    fn tj_adjustment(&self, value: f64) -> f64 {
        -(value / 1000.0) * self.font_size * self.horizontal_scaling
    }
}

fn object_to_f64(obj: &Object) -> Option<f64> {
    match obj {
        Object::Integer(i) => Some(*i as f64),
        Object::Real(r) => Some(*r as f64),
        _ => None,
    }
}

pub fn reconstruct_text(words: &[PdfWord]) -> ReconstructedPdfText {
    if words.is_empty() {
        return ReconstructedPdfText {
            text: String::new(),
            spans: Vec::new(),
        };
    }

    let mut indexed: Vec<(usize, &PdfWord)> = words.iter().enumerate().collect();

    indexed.sort_by(|a, b| {
        a.1.page
            .cmp(&b.1.page)
            .then_with(|| {
                b.1.y
                    .partial_cmp(&a.1.y)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| {
                a.1.x
                    .partial_cmp(&b.1.x)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    });

    let mut lines: Vec<Vec<(usize, &PdfWord)>> = Vec::new();
    let mut current_line: Vec<(usize, &PdfWord)> = vec![indexed[0]];
    let mut current_page = indexed[0].1.page;

    for &(idx, word) in &indexed[1..] {
        let last = current_line.last().unwrap().1;

        if word.page != current_page {
            lines.push(std::mem::take(&mut current_line));
            current_line.push((idx, word));
            current_page = word.page;
            continue;
        }

        let tolerance = (last.height.min(word.height) / 2.0).max(1.0);
        let y_diff = (word.y - last.y).abs();

        if y_diff <= tolerance {
            current_line.push((idx, word));
        } else {
            lines.push(std::mem::take(&mut current_line));
            current_line.push((idx, word));
        }
    }
    lines.push(current_line);

    for line in &mut lines {
        line.sort_by(|a, b| {
            a.1.x
                .partial_cmp(&b.1.x)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }

    let mut text = String::new();
    let mut span_entries: Vec<(usize, usize, usize)> = Vec::with_capacity(words.len());
    let mut prev_page: Option<u32> = None;

    for line in &lines {
        let line_page = line.first().map(|(_, w)| w.page);

        if let (Some(pp), Some(lp)) = (prev_page, line_page) {
            if lp != pp {
                text.push_str("\n\n");
            } else {
                text.push('\n');
            }
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

        prev_page = line_page;
    }

    span_entries.sort_by_key(|(orig_idx, _, _)| *orig_idx);
    let spans = span_entries.into_iter().map(|(_, s, e)| (s, e)).collect();

    ReconstructedPdfText { text, spans }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Security tests ──────────────────────────────────────────────────

    #[test]
    fn extract_words_rejects_symlink() {
        let dir = std::env::temp_dir().join("anon-test-pdf-symlink");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let target = dir.join("real.pdf");
        create_test_pdf(&target);

        let link = dir.join("link.pdf");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).unwrap();
        #[cfg(unix)]
        {
            let result = extract_words(&link);
            assert!(matches!(result, Err(PdfError::Io(_))));
            if let Err(PdfError::Io(msg)) = result {
                assert!(msg.contains("symlink"), "error should mention symlink");
            }
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn extract_words_rejects_too_large_file() {
        let dir = std::env::temp_dir().join("anon-test-pdf-large");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let large_file = dir.join("large.pdf");
        let content = vec![0u8; (MAX_INPUT_SIZE + 1) as usize];
        fs::write(&large_file, &content).unwrap();

        let result = extract_words(&large_file);
        assert!(matches!(result, Err(PdfError::Io(_))));
        if let Err(PdfError::Io(msg)) = result {
            assert!(
                msg.contains("too large") || msg.contains("size"),
                "error should mention file size"
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn extract_words_handles_missing_file() {
        let result = extract_words(Path::new("nonexistent.pdf"));
        assert!(matches!(result, Err(PdfError::Io(_))));
    }

    // ── Reconstruction unit tests ───────────────────────────────────────

    #[test]
    fn reconstruct_empty_words() {
        let result = reconstruct_text(&[]);
        assert!(result.text.is_empty());
        assert!(result.spans.is_empty());
    }

    #[test]
    fn reconstruct_single_word() {
        let words = vec![PdfWord {
            text: "hello".into(),
            page: 1,
            x: 72.0,
            y: 700.0,
            width: 30.0,
            height: 12.0,
        }];
        let result = reconstruct_text(&words);
        assert_eq!(result.text, "hello");
        assert_eq!(result.spans, vec![(0, 5)]);
    }

    #[test]
    fn reconstruct_same_line_sorted_by_x() {
        let words = vec![
            PdfWord {
                text: "world".into(),
                page: 1,
                x: 150.0,
                y: 700.0,
                width: 30.0,
                height: 12.0,
            },
            PdfWord {
                text: "hello".into(),
                page: 1,
                x: 72.0,
                y: 700.0,
                width: 30.0,
                height: 12.0,
            },
        ];
        let result = reconstruct_text(&words);
        assert_eq!(result.text, "hello world");
        assert_eq!(&result.text[result.spans[0].0..result.spans[0].1], "world");
        assert_eq!(&result.text[result.spans[1].0..result.spans[1].1], "hello");
    }

    #[test]
    fn reconstruct_different_lines() {
        let words = vec![
            PdfWord {
                text: "top".into(),
                page: 1,
                x: 72.0,
                y: 700.0,
                width: 20.0,
                height: 12.0,
            },
            PdfWord {
                text: "bottom".into(),
                page: 1,
                x: 72.0,
                y: 680.0,
                width: 40.0,
                height: 12.0,
            },
        ];
        let result = reconstruct_text(&words);
        assert_eq!(result.text, "top\nbottom");
        assert_eq!(&result.text[result.spans[0].0..result.spans[0].1], "top");
        assert_eq!(&result.text[result.spans[1].0..result.spans[1].1], "bottom");
    }

    #[test]
    fn reconstruct_multipage() {
        let words = vec![
            PdfWord {
                text: "page1".into(),
                page: 1,
                x: 72.0,
                y: 700.0,
                width: 35.0,
                height: 12.0,
            },
            PdfWord {
                text: "page2".into(),
                page: 2,
                x: 72.0,
                y: 700.0,
                width: 35.0,
                height: 12.0,
            },
        ];
        let result = reconstruct_text(&words);
        assert_eq!(result.text, "page1\n\npage2");
        assert_eq!(&result.text[result.spans[0].0..result.spans[0].1], "page1");
        assert_eq!(&result.text[result.spans[1].0..result.spans[1].1], "page2");
    }

    #[test]
    fn reconstruct_unicode_byte_offsets() {
        let words = vec![
            PdfWord {
                text: "cafe\u{0301}".into(),
                page: 1,
                x: 72.0,
                y: 700.0,
                width: 30.0,
                height: 12.0,
            },
            PdfWord {
                text: "resume\u{0301}".into(),
                page: 1,
                x: 150.0,
                y: 700.0,
                width: 40.0,
                height: 12.0,
            },
        ];
        let result = reconstruct_text(&words);
        assert_eq!(
            &result.text[result.spans[0].0..result.spans[0].1],
            "cafe\u{0301}"
        );
        assert_eq!(
            &result.text[result.spans[1].0..result.spans[1].1],
            "resume\u{0301}"
        );
    }

    // ── Integration tests (require test PDF) ────────────────────────────

    fn create_test_pdf(path: &Path) {
        use lopdf::content::{Content, Operation};
        use lopdf::{Document, Object, Stream, dictionary};

        let mut doc = Document::with_version("1.5");

        let pages_id = doc.new_object_id();
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font",
            "Subtype" => "Type1",
            "BaseFont" => "Courier",
        });
        let resources_id = doc.add_object(dictionary! {
            "Font" => dictionary! {
                "F1" => font_id,
            },
        });

        let page1_content = Content {
            operations: vec![
                Operation::new("BT", vec![]),
                Operation::new("Tf", vec!["F1".into(), 12.into()]),
                Operation::new("Td", vec![72.into(), 720.into()]),
                Operation::new("Tj", vec![Object::string_literal("Contact Information")]),
                Operation::new("Td", vec![0.into(), (-20).into()]),
                Operation::new(
                    "Tj",
                    vec![Object::string_literal("Email: john.smith@example.com")],
                ),
                Operation::new("Td", vec![0.into(), (-20).into()]),
                Operation::new("Tj", vec![Object::string_literal("Phone: +1-555-123-4567")]),
                Operation::new("ET", vec![]),
            ],
        };

        let page2_content = Content {
            operations: vec![
                Operation::new("BT", vec![]),
                Operation::new("Tf", vec!["F1".into(), 12.into()]),
                Operation::new("Td", vec![72.into(), 720.into()]),
                Operation::new("Tj", vec![Object::string_literal("Additional Information")]),
                Operation::new("Td", vec![0.into(), (-20).into()]),
                Operation::new("Tj", vec![Object::string_literal("IP: 192.168.1.100")]),
                Operation::new("ET", vec![]),
            ],
        };

        let content1_id =
            doc.add_object(Stream::new(dictionary! {}, page1_content.encode().unwrap()));
        let content2_id =
            doc.add_object(Stream::new(dictionary! {}, page2_content.encode().unwrap()));

        let page1_id = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "Contents" => content1_id,
        });

        let page2_id = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "Contents" => content2_id,
        });

        let pages = dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(page1_id), Object::Reference(page2_id)],
            "Count" => 2,
            "Resources" => resources_id,
            "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        };
        doc.objects.insert(pages_id, Object::Dictionary(pages));

        let catalog_id = doc.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
        });
        doc.trailer.set("Root", catalog_id);

        doc.save(path).expect("failed to save test PDF");
    }

    #[test]
    fn extract_words_from_generated_pdf() {
        let dir = std::env::temp_dir().join("anon-test-pdf-extract");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let pdf_path = dir.join("test.pdf");
        create_test_pdf(&pdf_path);

        let words = extract_words(&pdf_path).expect("should extract words from test PDF");
        assert!(!words.is_empty(), "test PDF should contain words");

        let text: String = words.iter().map(|w| format!("{} ", w.text)).collect();
        assert!(
            text.contains("john.smith@example.com"),
            "extracted text should contain email"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn extract_words_splits_text_showing_operations_into_words() {
        let dir = std::env::temp_dir().join("anon-test-pdf-word-split");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let pdf_path = dir.join("test.pdf");
        create_test_pdf(&pdf_path);

        let words = extract_words(&pdf_path).expect("should extract words from test PDF");
        let label = words
            .iter()
            .find(|word| word.text == "Email:")
            .expect("label should be its own extracted word");
        let email = words
            .iter()
            .find(|word| word.text == "john.smith@example.com")
            .expect("email should be its own extracted word");

        assert_eq!(label.page, email.page);
        assert!(
            email.x > label.x + label.width,
            "email should have a tighter box after the label: label={label:?} email={email:?}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn extract_words_uses_text_leading_for_next_line_operator() {
        use lopdf::content::{Content, Operation};
        use lopdf::{Document, Object, Stream, dictionary};

        let dir = std::env::temp_dir().join("anon-test-pdf-leading");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let pdf_path = dir.join("test.pdf");
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font",
            "Subtype" => "Type1",
            "BaseFont" => "Courier",
        });
        let resources_id = doc.add_object(dictionary! {
            "Font" => dictionary! {
                "F1" => font_id,
            },
        });
        let content = Content {
            operations: vec![
                Operation::new("BT", vec![]),
                Operation::new("Tf", vec!["F1".into(), 12.into()]),
                Operation::new("Td", vec![72.into(), 720.into()]),
                Operation::new("Tj", vec![Object::string_literal("Header")]),
                Operation::new("TD", vec![0.into(), (-36).into()]),
                Operation::new("Tj", vec![Object::string_literal("alice@example.com")]),
                Operation::new("T*", vec![]),
                Operation::new("Tj", vec![Object::string_literal("bob@example.com")]),
                Operation::new("ET", vec![]),
            ],
        };
        let content_id = doc.add_object(Stream::new(dictionary! {}, content.encode().unwrap()));
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "Contents" => content_id,
        });
        let pages = dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(page_id)],
            "Count" => 1,
            "Resources" => resources_id,
            "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        };
        doc.objects.insert(pages_id, Object::Dictionary(pages));
        let catalog_id = doc.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
        });
        doc.trailer.set("Root", catalog_id);
        doc.save(&pdf_path)
            .expect("failed to save leading test PDF");

        let words = extract_words(&pdf_path).expect("should extract words from test PDF");
        let bob = words
            .iter()
            .find(|word| word.text == "bob@example.com")
            .expect("second-line email should be extracted");

        assert!(
            (bob.y - 648.0).abs() < 0.01,
            "T* should move by TD-set leading, not font size: {bob:?}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn extract_words_multipage_generated_pdf() {
        let dir = std::env::temp_dir().join("anon-test-pdf-multipage");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let pdf_path = dir.join("test.pdf");
        create_test_pdf(&pdf_path);

        let words = extract_words(&pdf_path).expect("should extract words from test PDF");

        let pages: std::collections::HashSet<u32> = words.iter().map(|w| w.page).collect();
        assert!(
            pages.len() >= 2,
            "test PDF should have at least 2 pages, got {:?}",
            pages
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn extract_words_have_valid_positions() {
        let dir = std::env::temp_dir().join("anon-test-pdf-positions");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let pdf_path = dir.join("test.pdf");
        create_test_pdf(&pdf_path);

        let words = extract_words(&pdf_path).expect("should extract words from test PDF");

        for word in &words {
            assert!(word.page >= 1, "page should be >= 1");
            assert!(word.width > 0.0, "width should be positive");
            assert!(word.height > 0.0, "height should be positive");
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn extract_and_reconstruct_round_trip() {
        let dir = std::env::temp_dir().join("anon-test-pdf-roundtrip");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let pdf_path = dir.join("test.pdf");
        create_test_pdf(&pdf_path);

        let words = extract_words(&pdf_path).expect("should extract words from test PDF");
        let result = reconstruct_text(&words);

        assert_eq!(result.spans.len(), words.len());

        for (i, word) in words.iter().enumerate() {
            let (start, end) = result.spans[i];
            let extracted = &result.text[start..end];
            assert_eq!(extracted, word.text, "span {i} should match word text");
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    #[ignore]
    fn create_sample_pdf_in_testdata() {
        let path = Path::new("testdata/sample.pdf");
        create_test_pdf(path);
        assert!(path.exists());
    }

    #[test]
    fn extracted_text_contains_pii_for_detection() {
        let dir = std::env::temp_dir().join("anon-test-pdf-pii");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let pdf_path = dir.join("test.pdf");
        create_test_pdf(&pdf_path);

        let words = extract_words(&pdf_path).expect("should extract words from test PDF");
        let result = reconstruct_text(&words);

        let has_email = result.text.contains('@') && result.text.contains('.');
        let has_phone = result.text.contains('+') || result.text.contains('-');
        let has_ip = result.text.contains("192.168") || result.text.contains("10.");

        assert!(
            has_email || has_phone || has_ip,
            "reconstructed text should contain detectable PII patterns: {}",
            result.text
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
