use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use lopdf::content::{Content, Operation};
use lopdf::{Document, Encoding, Object, Stream, dictionary};

use super::{PdfError, RedactionRegion};
use crate::patterns::MAX_INPUT_SIZE;

/// Errors that can occur during PDF redaction.
#[derive(Debug)]
pub enum RedactError {
    InvalidColor(String),
    PdfLoad { path: PathBuf, source: String },
    PdfSave { path: PathBuf, source: String },
    UnmappedText { page: u32, entity_type: String },
}

impl fmt::Display for RedactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RedactError::InvalidColor(c) => write!(f, "invalid fill color: {c}"),
            RedactError::PdfLoad { path, source } => {
                write!(f, "failed to load PDF {}: {source}", path.display())
            }
            RedactError::PdfSave { path, source } => {
                write!(f, "failed to save PDF {}: {source}", path.display())
            }
            RedactError::UnmappedText { page, entity_type } => write!(
                f,
                "redaction region for {entity_type} on page {page} could not be mapped to removable PDF text"
            ),
        }
    }
}

impl std::error::Error for RedactError {}

impl From<PdfError> for RedactError {
    fn from(e: PdfError) -> Self {
        match e {
            PdfError::Io(msg) => RedactError::PdfLoad {
                path: PathBuf::new(),
                source: msg,
            },
            PdfError::Parse(msg) => RedactError::PdfLoad {
                path: PathBuf::new(),
                source: msg,
            },
            PdfError::Extraction(msg) => RedactError::PdfLoad {
                path: PathBuf::new(),
                source: msg,
            },
        }
    }
}

/// Parse a color string into RGB components (0.0 - 1.0 range for PDF).
///
/// Accepts named colors (black, white, red, green, blue, gray/grey) or hex
/// strings prefixed with `#` (3-digit or 6-digit).
pub fn parse_fill_color(color: &str) -> Result<(f64, f64, f64), RedactError> {
    let lower = color.to_lowercase();
    match lower.as_str() {
        "black" => return Ok((0.0, 0.0, 0.0)),
        "white" => return Ok((1.0, 1.0, 1.0)),
        "red" => return Ok((1.0, 0.0, 0.0)),
        "green" => return Ok((0.0, 0.5, 0.0)),
        "blue" => return Ok((0.0, 0.0, 1.0)),
        "gray" | "grey" => return Ok((0.5, 0.5, 0.5)),
        _ => {}
    }

    let hex = lower
        .strip_prefix('#')
        .ok_or_else(|| RedactError::InvalidColor(color.to_string()))?;

    let parse_hex_byte = |s: &str| -> Result<f64, RedactError> {
        u8::from_str_radix(s, 16)
            .map(|v| v as f64 / 255.0)
            .map_err(|_| RedactError::InvalidColor(color.to_string()))
    };

    match hex.len() {
        6 => {
            let r = parse_hex_byte(&hex[0..2])?;
            let g = parse_hex_byte(&hex[2..4])?;
            let b = parse_hex_byte(&hex[4..6])?;
            Ok((r, g, b))
        }
        3 => {
            let r = parse_hex_byte(&hex[0..1].repeat(2))?;
            let g = parse_hex_byte(&hex[1..2].repeat(2))?;
            let b = parse_hex_byte(&hex[2..3].repeat(2))?;
            Ok((r, g, b))
        }
        _ => Err(RedactError::InvalidColor(color.to_string())),
    }
}

/// Check if two rectangles overlap.
/// PDF annotation Rect is [llx, lly, urx, ury] (lower-left x/y, upper-right x/y).
/// RedactionRegion uses x, y, width, height where (x, y) is lower-left corner.
fn rects_overlap(
    annot_rect: &[Object],
    region_x: f64,
    region_y: f64,
    region_width: f64,
    region_height: f64,
) -> bool {
    if annot_rect.len() < 4 {
        return false;
    }

    let extract_f64 = |obj: &Object| -> Option<f64> {
        match obj {
            Object::Integer(i) => Some(*i as f64),
            Object::Real(r) => Some(*r as f64),
            _ => None,
        }
    };

    let Some(llx) = extract_f64(&annot_rect[0]) else {
        return false;
    };
    let Some(lly) = extract_f64(&annot_rect[1]) else {
        return false;
    };
    let Some(urx) = extract_f64(&annot_rect[2]) else {
        return false;
    };
    let Some(ury) = extract_f64(&annot_rect[3]) else {
        return false;
    };

    // Redaction region bounds
    let r_llx = region_x;
    let r_lly = region_y;
    let r_urx = region_x + region_width;
    let r_ury = region_y + region_height;

    // Two rectangles overlap if they intersect in both dimensions
    let x_overlap = llx < r_urx && urx > r_llx;
    let y_overlap = lly < r_ury && ury > r_lly;

    x_overlap && y_overlap
}

/// Remove annotations from a page that overlap with any of the given redaction regions.
fn remove_overlapping_annotations(
    doc: &mut Document,
    page_id: (u32, u16),
    regions: &[&RedactionRegion],
) {
    // Get the page dictionary
    let Ok(Object::Dictionary(page_dict)) = doc.get_object(page_id) else {
        return;
    };

    // Get the Annots array (can be direct or a reference)
    let Ok(annots_obj) = page_dict.get(b"Annots") else {
        return; // No annotations on this page
    };

    // Get the actual array of annotation references
    let annot_refs: Vec<Object> = match annots_obj {
        Object::Array(arr) => arr.clone(),
        Object::Reference(r) => {
            let Ok(Object::Array(arr)) = doc.get_object((r.0, r.1)) else {
                return;
            };
            arr.clone()
        }
        _ => return,
    };

    // Filter out annotations that overlap with any redaction region
    let mut kept_annots: Vec<Object> = Vec::new();

    for annot_ref in &annot_refs {
        let Object::Reference(ref_id) = annot_ref else {
            // Keep non-reference items as-is (unusual but possible)
            kept_annots.push(annot_ref.clone());
            continue;
        };

        // Get the annotation dictionary
        let Ok(Object::Dictionary(annot_dict)) = doc.get_object((ref_id.0, ref_id.1)) else {
            kept_annots.push(annot_ref.clone());
            continue;
        };

        // Get the annotation's Rect
        let Ok(rect_obj) = annot_dict.get(b"Rect") else {
            kept_annots.push(annot_ref.clone());
            continue;
        };

        let rect: &[Object] = match rect_obj {
            Object::Array(arr) => arr,
            Object::Reference(r) => {
                let Ok(Object::Array(arr)) = doc.get_object((r.0, r.1)) else {
                    kept_annots.push(annot_ref.clone());
                    continue;
                };
                arr
            }
            _ => {
                kept_annots.push(annot_ref.clone());
                continue;
            }
        };

        // Check if this annotation overlaps with any redaction region
        let overlaps = regions
            .iter()
            .any(|region| rects_overlap(rect, region.x, region.y, region.width, region.height));

        if !overlaps {
            kept_annots.push(annot_ref.clone());
        }
        // If overlaps, we drop the annotation by not adding it to kept_annots
    }

    // Update the page's Annots array
    if let Ok(Object::Dictionary(page_dict_mut)) = doc.get_object_mut(page_id) {
        if kept_annots.is_empty() {
            // Remove the Annots key entirely if no annotations remain
            page_dict_mut.remove(b"Annots");
        } else {
            page_dict_mut.set("Annots", Object::Array(kept_annots));
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PdfRedactionMode {
    Destructive,
    VisualOnly,
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

    fn glyph_width(&self) -> f64 {
        self.font_size * 0.6 * self.horizontal_scaling
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

fn region_overlaps_box(region: &RedactionRegion, x: f64, y: f64, width: f64, height: f64) -> bool {
    let region_right = region.x + region.width;
    let region_top = region.y + region.height;
    let box_right = x + width;
    let box_top = y + height;

    region.x < box_right && region_right > x && region.y < box_top && region_top > y
}

fn redact_text_showing_operation(
    op: &mut Operation,
    encoding: &Encoding,
    text_matrix: &TextMatrix,
    text_state: TextState,
    page_regions: &[(usize, &RedactionRegion)],
) -> TextRewriteResult {
    let (x, y) = text_matrix.position();

    let mut text_run = TextRunState {
        x,
        y,
        text_state,
        advance: 0.0,
        current_word_has_chars: false,
        current_word_regions: Vec::new(),
        completed_regions: Vec::new(),
        incomplete_regions: Vec::new(),
    };
    for operand in &mut op.operands {
        redact_operand_text_by_region(encoding, operand, &mut text_run, page_regions);
    }
    text_run.finish_word();

    TextRewriteResult {
        advance: text_run.advance,
        completed_regions: text_run.completed_regions,
        incomplete_regions: text_run.incomplete_regions,
    }
}

struct TextRewriteResult {
    advance: f64,
    completed_regions: Vec<usize>,
    incomplete_regions: Vec<usize>,
}

struct TextRunState {
    x: f64,
    y: f64,
    text_state: TextState,
    advance: f64,
    current_word_has_chars: bool,
    current_word_regions: Vec<(usize, bool)>,
    completed_regions: Vec<usize>,
    incomplete_regions: Vec<usize>,
}

impl TextRunState {
    fn record_word_char(&mut self, char_matches: &[usize]) {
        for (idx, fully_matched) in &mut self.current_word_regions {
            if !char_matches.contains(idx) {
                *fully_matched = false;
            }
        }

        for idx in char_matches {
            if !self
                .current_word_regions
                .iter()
                .any(|(existing, _)| existing == idx)
            {
                self.current_word_regions
                    .push((*idx, !self.current_word_has_chars));
            }
        }

        self.current_word_has_chars = true;
    }

    fn finish_word(&mut self) {
        if !self.current_word_has_chars {
            return;
        }

        for (idx, fully_matched) in self.current_word_regions.drain(..) {
            if fully_matched {
                self.completed_regions.push(idx);
            } else {
                self.incomplete_regions.push(idx);
            }
        }
        self.current_word_has_chars = false;
    }
}

fn redact_operand_text_by_region(
    encoding: &Encoding,
    object: &mut Object,
    text_run: &mut TextRunState,
    page_regions: &[(usize, &RedactionRegion)],
) {
    match object {
        Object::String(bytes, _) => {
            let Ok(decoded) = Document::decode_text(encoding, bytes) else {
                return;
            };
            let char_width = text_run.text_state.glyph_width();
            let mut replacement = String::with_capacity(decoded.len());
            let mut changed = false;

            for ch in decoded.chars() {
                let char_x = text_run.x + text_run.advance;
                if ch.is_whitespace() {
                    text_run.finish_word();
                    replacement.push(ch);
                } else {
                    let char_matches: Vec<usize> = page_regions
                        .iter()
                        .filter_map(|(idx, region)| {
                            region_overlaps_box(
                                region,
                                char_x,
                                text_run.y,
                                char_width,
                                text_run.text_state.font_size,
                            )
                            .then_some(*idx)
                        })
                        .collect();

                    if !char_matches.is_empty() {
                        replacement.push('X');
                        changed = true;
                    } else {
                        replacement.push(ch);
                    }
                    text_run.record_word_char(&char_matches);
                }
                text_run.advance += text_run.text_state.glyph_advance(ch);
            }

            if changed {
                *bytes = Document::encode_text(encoding, &replacement);
            }
        }
        Object::Array(items) => {
            for item in items {
                match item {
                    Object::Integer(i) => {
                        if *i < -100 {
                            text_run.finish_word();
                        }
                        text_run.advance += text_run.text_state.tj_adjustment(*i as f64);
                    }
                    Object::Real(r) => {
                        if *r < -100.0 {
                            text_run.finish_word();
                        }
                        text_run.advance += text_run.text_state.tj_adjustment(*r as f64);
                    }
                    _ => redact_operand_text_by_region(encoding, item, text_run, page_regions),
                }
            }
        }
        _ => {}
    }
}

fn rewrite_page_text_operands(
    doc: &Document,
    input: &Path,
    page_id: (u32, u16),
    content: &mut Content,
    page_regions: &[(usize, &RedactionRegion)],
) -> Result<Vec<usize>, RedactError> {
    let fonts = doc
        .get_page_fonts(page_id)
        .map_err(|e| RedactError::PdfLoad {
            path: input.to_path_buf(),
            source: format!("failed to read page fonts: {e}"),
        })?;
    let encodings: BTreeMap<Vec<u8>, Encoding> = fonts
        .into_iter()
        .filter_map(|(name, font)| match font.get_font_encoding(doc) {
            Ok(enc) => Some((name, enc)),
            Err(_) => None,
        })
        .collect();

    let mut completed_regions = Vec::new();
    let mut incomplete_regions = Vec::new();
    let mut text_matrix = TextMatrix::identity();
    let mut line_matrix = TextMatrix::identity();
    let mut current_encoding = None;
    let mut text_state = TextState::new();

    for op in &mut content.operations {
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
                    let result = redact_text_showing_operation(
                        op,
                        encoding,
                        &text_matrix,
                        text_state,
                        page_regions,
                    );
                    completed_regions.extend(result.completed_regions);
                    incomplete_regions.extend(result.incomplete_regions);
                    text_matrix.translate(result.advance, 0.0);
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
                    let result = redact_text_showing_operation(
                        op,
                        encoding,
                        &text_matrix,
                        text_state,
                        page_regions,
                    );
                    completed_regions.extend(result.completed_regions);
                    incomplete_regions.extend(result.incomplete_regions);
                    text_matrix.translate(result.advance, 0.0);
                }
            }
            _ => {}
        }
    }

    completed_regions.retain(|idx| !incomplete_regions.contains(idx));
    Ok(completed_regions)
}

fn append_visual_mask_operations(
    content: &mut Content,
    page_regions: &[&RedactionRegion],
    r: f64,
    g: f64,
    b: f64,
) {
    content.operations.push(Operation::new("q", vec![]));
    content.operations.push(Operation::new(
        "rg",
        vec![
            Object::Real(r as f32),
            Object::Real(g as f32),
            Object::Real(b as f32),
        ],
    ));

    for region in page_regions {
        content.operations.push(Operation::new(
            "re",
            vec![
                Object::Real(region.x as f32),
                Object::Real(region.y as f32),
                Object::Real(region.width as f32),
                Object::Real(region.height as f32),
            ],
        ));
        content.operations.push(Operation::new("f", vec![]));
    }

    content.operations.push(Operation::new("Q", vec![]));
}

/// Destructively redact supported text regions of a PDF and draw opaque rectangles over them.
///
/// Opens the input PDF, draws filled rectangles over each region on the
/// appropriate page, removes overlapping annotations, and saves to the output
/// path. Preserves the original layout, page count, and non-PII content.
pub fn redact_pdf(
    input: &Path,
    output: &Path,
    regions: &[RedactionRegion],
    fill_color: &str,
) -> Result<(), RedactError> {
    redact_pdf_with_mode(
        input,
        output,
        regions,
        fill_color,
        PdfRedactionMode::Destructive,
    )
}

/// Visually mask regions of a PDF by drawing opaque rectangles without rewriting text streams.
pub fn visual_mask_pdf(
    input: &Path,
    output: &Path,
    regions: &[RedactionRegion],
    fill_color: &str,
) -> Result<(), RedactError> {
    redact_pdf_with_mode(
        input,
        output,
        regions,
        fill_color,
        PdfRedactionMode::VisualOnly,
    )
}

fn redact_pdf_with_mode(
    input: &Path,
    output: &Path,
    regions: &[RedactionRegion],
    fill_color: &str,
    mode: PdfRedactionMode,
) -> Result<(), RedactError> {
    let (r, g, b) = parse_fill_color(fill_color)?;

    // Security: check for symlinks and file size before loading
    let meta = fs::symlink_metadata(input).map_err(|e| RedactError::PdfLoad {
        path: input.to_path_buf(),
        source: e.to_string(),
    })?;
    if meta.file_type().is_symlink() {
        return Err(RedactError::PdfLoad {
            path: input.to_path_buf(),
            source: "refusing to follow symlink".to_string(),
        });
    }
    if meta.len() > MAX_INPUT_SIZE {
        return Err(RedactError::PdfLoad {
            path: input.to_path_buf(),
            source: format!(
                "file too large: {} bytes (max {} bytes)",
                meta.len(),
                MAX_INPUT_SIZE
            ),
        });
    }

    let bytes = fs::read(input).map_err(|e| RedactError::PdfLoad {
        path: input.to_path_buf(),
        source: e.to_string(),
    })?;
    let mut doc = Document::load_mem(&bytes).map_err(|e| RedactError::PdfLoad {
        path: input.to_path_buf(),
        source: e.to_string(),
    })?;

    // Group regions by page number
    let mut regions_by_page: BTreeMap<u32, Vec<(usize, &RedactionRegion)>> = BTreeMap::new();
    for (idx, region) in regions.iter().enumerate() {
        regions_by_page
            .entry(region.page)
            .or_default()
            .push((idx, region));
    }

    let pages = doc.get_pages();
    let mut mapped_regions = vec![mode == PdfRedactionMode::VisualOnly; regions.len()];

    // For each page with regions, rewrite supported text then append visual masking rectangles.
    for (page_num, page_regions) in &regions_by_page {
        let Some(&page_id) = pages.get(page_num) else {
            continue;
        };

        // Get existing content
        let existing_content = doc.get_page_content(page_id).unwrap_or_default();
        let mut content = if existing_content.is_empty() {
            Content { operations: vec![] }
        } else {
            Content::decode(&existing_content).map_err(|e| RedactError::PdfLoad {
                path: input.to_path_buf(),
                source: format!("failed to decode page content: {e}"),
            })?
        };

        if mode == PdfRedactionMode::Destructive {
            for idx in rewrite_page_text_operands(&doc, input, page_id, &mut content, page_regions)?
            {
                if let Some(mapped) = mapped_regions.get_mut(idx) {
                    *mapped = true;
                }
            }
        }

        let page_region_refs: Vec<&RedactionRegion> =
            page_regions.iter().map(|(_, region)| *region).collect();
        append_visual_mask_operations(&mut content, &page_region_refs, r, g, b);

        // Encode and update the page content
        let encoded = content.encode().map_err(|e| RedactError::PdfSave {
            path: output.to_path_buf(),
            source: format!("failed to encode page content: {e}"),
        })?;

        // Create new content stream object
        let new_content_id = doc.add_object(Stream::new(dictionary! {}, encoded));

        // Update page to point to new content
        if let Ok(Object::Dictionary(page_dict)) = doc.get_object_mut(page_id) {
            page_dict.set("Contents", Object::Reference(new_content_id));
        }

        // Remove annotations that overlap with masked regions
        remove_overlapping_annotations(&mut doc, page_id, &page_region_refs);
    }

    if mode == PdfRedactionMode::Destructive {
        if let Some((idx, _)) = mapped_regions
            .iter()
            .enumerate()
            .find(|(_, mapped)| !**mapped)
        {
            let region = &regions[idx];
            return Err(RedactError::UnmappedText {
                page: region.page,
                entity_type: region.entity_type.clone(),
            });
        }
    }

    // Save the modified PDF
    doc.save(output).map_err(|e| RedactError::PdfSave {
        path: output.to_path_buf(),
        source: e.to_string(),
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lopdf::content::{Content, Operation};
    use lopdf::{Object, Stream, dictionary};
    use std::fs;

    // ---------------------------------------------------------------------------
    // Color parsing tests
    // ---------------------------------------------------------------------------

    #[test]
    fn parse_named_colors() {
        let cases = [
            ("black", (0.0, 0.0, 0.0)),
            ("white", (1.0, 1.0, 1.0)),
            ("red", (1.0, 0.0, 0.0)),
            ("green", (0.0, 0.5, 0.0)),
            ("blue", (0.0, 0.0, 1.0)),
            ("gray", (0.5, 0.5, 0.5)),
            ("grey", (0.5, 0.5, 0.5)),
        ];
        for (name, expected) in &cases {
            let result = parse_fill_color(name).unwrap();
            assert!(
                (result.0 - expected.0).abs() < 0.01
                    && (result.1 - expected.1).abs() < 0.01
                    && (result.2 - expected.2).abs() < 0.01,
                "failed for color name: {name}"
            );
        }
    }

    #[test]
    fn parse_case_insensitive() {
        let black = parse_fill_color("BLACK").unwrap();
        assert!((black.0 - 0.0).abs() < 0.01);
        let mixed = parse_fill_color("Black").unwrap();
        assert!((mixed.0 - 0.0).abs() < 0.01);
    }

    #[test]
    fn parse_hex_6_digit() {
        let result = parse_fill_color("#FF0000").unwrap();
        assert!((result.0 - 1.0).abs() < 0.01);
        assert!((result.1 - 0.0).abs() < 0.01);
        assert!((result.2 - 0.0).abs() < 0.01);
    }

    #[test]
    fn parse_hex_6_lowercase() {
        let result = parse_fill_color("#ff0000").unwrap();
        assert!((result.0 - 1.0).abs() < 0.01);
    }

    #[test]
    fn parse_hex_3_digit() {
        let result = parse_fill_color("#F00").unwrap();
        assert!((result.0 - 1.0).abs() < 0.01);
        assert!((result.1 - 0.0).abs() < 0.01);
    }

    #[test]
    fn parse_hex_black() {
        let result = parse_fill_color("#000000").unwrap();
        assert!((result.0 - 0.0).abs() < 0.01);
        let short = parse_fill_color("#000").unwrap();
        assert!((short.0 - 0.0).abs() < 0.01);
    }

    #[test]
    fn parse_invalid_name() {
        let result = parse_fill_color("purple");
        assert!(matches!(result, Err(RedactError::InvalidColor(_))));
    }

    #[test]
    fn parse_invalid_hex_length() {
        let result = parse_fill_color("#FFFF");
        assert!(matches!(result, Err(RedactError::InvalidColor(_))));
    }

    #[test]
    fn parse_invalid_hex_chars() {
        let result = parse_fill_color("#GGGGGG");
        assert!(matches!(result, Err(RedactError::InvalidColor(_))));
    }

    #[test]
    fn parse_empty() {
        let result = parse_fill_color("");
        assert!(matches!(result, Err(RedactError::InvalidColor(_))));
    }

    #[test]
    fn parse_no_hash() {
        let result = parse_fill_color("FF0000");
        assert!(matches!(result, Err(RedactError::InvalidColor(_))));
    }

    // ---------------------------------------------------------------------------
    // Test helper to create a test PDF
    // ---------------------------------------------------------------------------

    fn create_test_pdf(path: &Path) {
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

        let page3_content = Content {
            operations: vec![
                Operation::new("BT", vec![]),
                Operation::new("Tf", vec!["F1".into(), 12.into()]),
                Operation::new("Td", vec![72.into(), 720.into()]),
                Operation::new("Tj", vec![Object::string_literal("Page 3 Data")]),
                Operation::new("Td", vec![0.into(), (-20).into()]),
                Operation::new("Tj", vec![Object::string_literal("SSN: 123-45-6789")]),
                Operation::new("ET", vec![]),
            ],
        };

        let content1_id =
            doc.add_object(Stream::new(dictionary! {}, page1_content.encode().unwrap()));
        let content2_id =
            doc.add_object(Stream::new(dictionary! {}, page2_content.encode().unwrap()));
        let content3_id =
            doc.add_object(Stream::new(dictionary! {}, page3_content.encode().unwrap()));

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

        let page3_id = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "Contents" => content3_id,
        });

        let pages = dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(page1_id), Object::Reference(page2_id), Object::Reference(page3_id)],
            "Count" => 3,
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

    fn test_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("anon_pdf_test_{}_{name}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn content_text_operands(content: &Content) -> String {
        let mut text = String::new();
        for op in &content.operations {
            for operand in &op.operands {
                append_operand_text(operand, &mut text);
            }
        }
        text
    }

    fn append_operand_text(object: &Object, output: &mut String) {
        match object {
            Object::String(bytes, _) => output.push_str(&String::from_utf8_lossy(bytes)),
            Object::Array(items) => {
                for item in items {
                    append_operand_text(item, output);
                }
            }
            _ => {}
        }
    }

    // ---------------------------------------------------------------------------
    // PDF redaction tests
    // ---------------------------------------------------------------------------

    #[test]
    fn redact_single_region_on_page1() {
        let dir = test_dir("single_region_p1");
        let input = dir.join("input.pdf");
        let output = dir.join("output.pdf");
        create_test_pdf(&input);

        let regions = vec![RedactionRegion {
            page: 1,
            x: 122.0,
            y: 696.0,
            width: 160.0,
            height: 20.0,
            entity_type: "EMAIL_ADDRESS".to_string(),
        }];

        redact_pdf(&input, &output, &regions, "black").unwrap();

        assert!(output.exists(), "output PDF should be created");

        // Verify the PDF is valid and has the same page count
        let doc = Document::load(&output).expect("output should be valid PDF");
        assert_eq!(doc.get_pages().len(), 3, "should preserve page count");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn redact_multiple_regions_same_page() {
        let dir = test_dir("multi_region_same_page");
        let input = dir.join("input.pdf");
        let output = dir.join("output.pdf");
        create_test_pdf(&input);

        let regions = vec![
            RedactionRegion {
                page: 1,
                x: 122.0,
                y: 696.0,
                width: 160.0,
                height: 20.0,
                entity_type: "EMAIL_ADDRESS".to_string(),
            },
            RedactionRegion {
                page: 1,
                x: 122.0,
                y: 676.0,
                width: 120.0,
                height: 20.0,
                entity_type: "PHONE_NUMBER".to_string(),
            },
        ];

        redact_pdf(&input, &output, &regions, "black").unwrap();

        assert!(output.exists());
        let doc = Document::load(&output).expect("output should be valid PDF");
        assert_eq!(doc.get_pages().len(), 3);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn redact_multipage_regions() {
        let dir = test_dir("multipage");
        let input = dir.join("input.pdf");
        let output = dir.join("output.pdf");
        create_test_pdf(&input);

        // Redact on page 1 and page 3
        let regions = vec![
            RedactionRegion {
                page: 1,
                x: 122.0,
                y: 696.0,
                width: 160.0,
                height: 20.0,
                entity_type: "EMAIL_ADDRESS".to_string(),
            },
            RedactionRegion {
                page: 3,
                x: 108.0,
                y: 696.0,
                width: 85.0,
                height: 20.0,
                entity_type: "US_SSN".to_string(),
            },
        ];

        redact_pdf(&input, &output, &regions, "black").unwrap();

        assert!(output.exists());
        let doc = Document::load(&output).expect("output should be valid PDF");
        assert_eq!(doc.get_pages().len(), 3, "should preserve all 3 pages");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn redact_page3_only() {
        let dir = test_dir("page3_only");
        let input = dir.join("input.pdf");
        let output = dir.join("output.pdf");
        create_test_pdf(&input);

        // Redact only on page 3 to verify multi-page targeting works
        let regions = vec![RedactionRegion {
            page: 3,
            x: 108.0,
            y: 696.0,
            width: 85.0,
            height: 20.0,
            entity_type: "US_SSN".to_string(),
        }];

        redact_pdf(&input, &output, &regions, "black").unwrap();

        assert!(output.exists());
        let doc = Document::load(&output).expect("output should be valid PDF");
        assert_eq!(doc.get_pages().len(), 3);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn redact_with_white_fill() {
        let dir = test_dir("white_fill");
        let input = dir.join("input.pdf");
        let output = dir.join("output.pdf");
        create_test_pdf(&input);

        let regions = vec![RedactionRegion {
            page: 1,
            x: 122.0,
            y: 696.0,
            width: 160.0,
            height: 20.0,
            entity_type: "EMAIL_ADDRESS".to_string(),
        }];

        redact_pdf(&input, &output, &regions, "white").unwrap();

        assert!(output.exists());
        let doc = Document::load(&output).expect("output should be valid PDF");
        assert_eq!(doc.get_pages().len(), 3);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn redact_with_hex_color() {
        let dir = test_dir("hex_color");
        let input = dir.join("input.pdf");
        let output = dir.join("output.pdf");
        create_test_pdf(&input);

        let regions = vec![RedactionRegion {
            page: 1,
            x: 122.0,
            y: 696.0,
            width: 160.0,
            height: 20.0,
            entity_type: "EMAIL_ADDRESS".to_string(),
        }];

        redact_pdf(&input, &output, &regions, "#FF0000").unwrap();

        assert!(output.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn redact_empty_regions() {
        let dir = test_dir("empty_regions");
        let input = dir.join("input.pdf");
        let output = dir.join("output.pdf");
        create_test_pdf(&input);

        redact_pdf(&input, &output, &[], "black").unwrap();

        assert!(output.exists());
        let doc = Document::load(&output).expect("output should be valid PDF");
        assert_eq!(doc.get_pages().len(), 3);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn redact_invalid_color() {
        let dir = test_dir("invalid_color");
        let input = dir.join("input.pdf");
        let output = dir.join("output.pdf");
        create_test_pdf(&input);

        let regions = vec![RedactionRegion {
            page: 1,
            x: 72.0,
            y: 700.0,
            width: 100.0,
            height: 20.0,
            entity_type: "EMAIL_ADDRESS".to_string(),
        }];

        let result = redact_pdf(&input, &output, &regions, "invalidcolor");
        assert!(matches!(result, Err(RedactError::InvalidColor(_))));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn redact_input_not_found() {
        let dir = test_dir("not_found");
        let input = dir.join("nonexistent.pdf");
        let output = dir.join("output.pdf");

        let regions = vec![RedactionRegion {
            page: 1,
            x: 72.0,
            y: 700.0,
            width: 100.0,
            height: 20.0,
            entity_type: "EMAIL_ADDRESS".to_string(),
        }];

        let result = redact_pdf(&input, &output, &regions, "black");
        assert!(matches!(result, Err(RedactError::PdfLoad { .. })));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn redact_preserves_original_content() {
        let dir = test_dir("preserves_content");
        let input = dir.join("input.pdf");
        let output = dir.join("output.pdf");
        create_test_pdf(&input);

        // Get original page count
        let original = Document::load(&input).unwrap();
        let original_page_count = original.get_pages().len();

        let regions = vec![RedactionRegion {
            page: 1,
            x: 122.0,
            y: 696.0,
            width: 160.0,
            height: 20.0,
            entity_type: "EMAIL_ADDRESS".to_string(),
        }];

        redact_pdf(&input, &output, &regions, "black").unwrap();

        let redacted = Document::load(&output).unwrap();
        assert_eq!(
            redacted.get_pages().len(),
            original_page_count,
            "page count should be preserved"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // ---------------------------------------------------------------------------
    // Redaction region content verification
    // ---------------------------------------------------------------------------

    #[test]
    fn redact_adds_drawing_operations() {
        let dir = test_dir("drawing_ops");
        let input = dir.join("input.pdf");
        let output = dir.join("output.pdf");
        create_test_pdf(&input);

        let regions = vec![RedactionRegion {
            page: 1,
            x: 122.0,
            y: 696.0,
            width: 160.0,
            height: 20.0,
            entity_type: "EMAIL_ADDRESS".to_string(),
        }];

        redact_pdf(&input, &output, &regions, "black").unwrap();

        // Load output and check that page 1 has rectangle drawing operations
        let doc = Document::load(&output).unwrap();
        let pages = doc.get_pages();
        let page1_id = pages.get(&1).unwrap();

        let content_data = doc.get_page_content(*page1_id).unwrap();
        let content = Content::decode(&content_data).unwrap();

        // Look for rectangle and fill operations (re, f)
        let has_rect = content.operations.iter().any(|op| op.operator == "re");
        let has_fill = content.operations.iter().any(|op| op.operator == "f");

        assert!(has_rect, "output should contain rectangle operation (re)");
        assert!(has_fill, "output should contain fill operation (f)");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn redact_removes_extractable_pii_from_pdf_text_streams() {
        let dir = test_dir("destructive_text_removal");
        let input = dir.join("input.pdf");
        let output = dir.join("output.pdf");
        create_test_pdf(&input);

        let original_text = crate::pdf_redact::extract::reconstruct_text(
            &crate::pdf_redact::extract::extract_words(&input).unwrap(),
        )
        .text;
        assert!(original_text.contains("john.smith@example.com"));

        let regions = vec![RedactionRegion {
            page: 1,
            x: 70.0,
            y: 696.0,
            width: 230.0,
            height: 20.0,
            entity_type: "EMAIL_ADDRESS".to_string(),
        }];

        redact_pdf(&input, &output, &regions, "black").unwrap();

        let redacted_text = crate::pdf_redact::extract::reconstruct_text(
            &crate::pdf_redact::extract::extract_words(&output).unwrap(),
        )
        .text;
        assert!(
            !redacted_text.contains("john.smith@example.com"),
            "PII should not be recoverable through project PDF extraction: {redacted_text}"
        );

        let doc = Document::load(&output).unwrap();
        let pages = doc.get_pages();
        let page1_id = pages.get(&1).unwrap();
        let content_data = doc.get_page_content(*page1_id).unwrap();
        let content = Content::decode(&content_data).unwrap();
        let text_operands = content_text_operands(&content);

        assert!(
            !text_operands.contains("john.smith@example.com"),
            "PII should not remain in decoded PDF text operands: {text_operands}"
        );
        assert!(
            content.operations.iter().any(|op| op.operator == "re"),
            "visual masking rectangles should still be drawn"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn redact_preserves_unmatched_text_in_same_pdf_text_operation() {
        let dir = test_dir("preserve_unmatched_text");
        let input = dir.join("input.pdf");
        let output = dir.join("output.pdf");
        create_test_pdf(&input);

        let regions = vec![RedactionRegion {
            page: 1,
            x: 122.0,
            y: 696.0,
            width: 160.0,
            height: 20.0,
            entity_type: "EMAIL_ADDRESS".to_string(),
        }];

        redact_pdf(&input, &output, &regions, "black").unwrap();

        let doc = Document::load(&output).unwrap();
        let pages = doc.get_pages();
        let page1_id = pages.get(&1).unwrap();
        let content_data = doc.get_page_content(*page1_id).unwrap();
        let content = Content::decode(&content_data).unwrap();
        let text_operands = content_text_operands(&content);

        assert!(
            text_operands.contains("Email:"),
            "redaction should preserve text outside the selected region: {text_operands}"
        );
        assert!(
            !text_operands.contains("john.smith@example.com"),
            "redaction should remove the selected PII text: {text_operands}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn redact_fails_closed_when_region_only_partially_rewrites_text_token() {
        let dir = test_dir("partial_token_overlap");
        let input = dir.join("input.pdf");
        let output = dir.join("output.pdf");
        create_test_pdf(&input);

        let regions = vec![RedactionRegion {
            page: 1,
            x: 72.0,
            y: 696.0,
            width: 60.0,
            height: 20.0,
            entity_type: "EMAIL_ADDRESS".to_string(),
        }];

        let err = redact_pdf(&input, &output, &regions, "black")
            .expect_err("partial token rewrite should fail closed");
        assert!(
            err.to_string().contains("could not be mapped"),
            "error should explain the fail-closed mapping problem: {err}"
        );
        assert!(
            !output.exists(),
            "partial token rewrite should not produce a redacted output"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn redact_advances_text_matrix_with_pdf_text_state_spacing() {
        let dir = test_dir("text_state_spacing");
        let input = dir.join("input.pdf");
        let output = dir.join("output.pdf");

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
                Operation::new("Tc", vec![5.into()]),
                Operation::new("Tw", vec![20.into()]),
                Operation::new("Tz", vec![150.into()]),
                Operation::new("Td", vec![72.into(), 720.into()]),
                Operation::new(
                    "TJ",
                    vec![Object::Array(vec![
                        Object::string_literal("Reference"),
                        Object::Integer(-3000),
                        Object::string_literal(" code "),
                    ])],
                ),
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
        doc.save(&input).expect("failed to save spacing test PDF");

        let regions = vec![RedactionRegion {
            page: 1,
            x: 450.0,
            y: 716.0,
            width: 280.0,
            height: 20.0,
            entity_type: "EMAIL_ADDRESS".to_string(),
        }];

        redact_pdf(&input, &output, &regions, "black").unwrap();

        let redacted_doc = Document::load(&output).unwrap();
        let pages = redacted_doc.get_pages();
        let page1_id = pages.get(&1).unwrap();
        let content_data = redacted_doc.get_page_content(*page1_id).unwrap();
        let content = Content::decode(&content_data).unwrap();
        let text_operands = content_text_operands(&content);

        assert!(
            !text_operands.contains("bob@example.com"),
            "later text runs should be matched after applying Tc/Tw/Tz/TJ displacement: {text_operands}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn redact_uses_text_leading_for_next_line_operator() {
        let dir = test_dir("text_leading");
        let input = dir.join("input.pdf");
        let output = dir.join("output.pdf");

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
        doc.save(&input).expect("failed to save leading test PDF");

        let regions = vec![RedactionRegion {
            page: 1,
            x: 70.0,
            y: 644.0,
            width: 125.0,
            height: 20.0,
            entity_type: "EMAIL_ADDRESS".to_string(),
        }];

        redact_pdf(&input, &output, &regions, "black").unwrap();

        let redacted_doc = Document::load(&output).unwrap();
        let pages = redacted_doc.get_pages();
        let page1_id = pages.get(&1).unwrap();
        let content_data = redacted_doc.get_page_content(*page1_id).unwrap();
        let content = Content::decode(&content_data).unwrap();
        let text_operands = content_text_operands(&content);

        assert!(
            !text_operands.contains("bob@example.com"),
            "T* should redact using TD-set leading, not font size: {text_operands}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn redact_fails_closed_when_region_cannot_be_mapped_to_text() {
        let dir = test_dir("unmapped_text_region");
        let input = dir.join("input.pdf");
        let output = dir.join("output.pdf");
        create_test_pdf(&input);

        let regions = vec![RedactionRegion {
            page: 1,
            x: 500.0,
            y: 500.0,
            width: 20.0,
            height: 20.0,
            entity_type: "EMAIL_ADDRESS".to_string(),
        }];

        let err = redact_pdf(&input, &output, &regions, "black")
            .expect_err("unmapped text redaction should fail closed");
        assert!(
            err.to_string().contains("could not be mapped"),
            "error should explain the fail-closed mapping problem: {err}"
        );
        assert!(
            !output.exists(),
            "fail-closed redaction should not write an overlay-only PDF"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // ---------------------------------------------------------------------------
    // Security tests
    // ---------------------------------------------------------------------------

    #[test]
    fn redact_rejects_symlink() {
        let dir = test_dir("symlink_reject");
        let target = dir.join("real.pdf");
        create_test_pdf(&target);

        let link = dir.join("link.pdf");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).unwrap();

        #[cfg(unix)]
        {
            let output = dir.join("output.pdf");
            let regions = vec![RedactionRegion {
                page: 1,
                x: 72.0,
                y: 700.0,
                width: 100.0,
                height: 20.0,
                entity_type: "EMAIL_ADDRESS".to_string(),
            }];

            let result = redact_pdf(&link, &output, &regions, "black");
            assert!(
                matches!(result, Err(RedactError::PdfLoad { .. })),
                "should reject symlink input"
            );
            if let Err(RedactError::PdfLoad { source, .. }) = result {
                assert!(source.contains("symlink"), "error should mention symlink");
            }
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn redact_rejects_too_large_file() {
        use crate::patterns::MAX_INPUT_SIZE;

        let dir = test_dir("large_file_reject");
        let large_file = dir.join("large.pdf");

        // Create a file that exceeds MAX_INPUT_SIZE
        let content = vec![0u8; (MAX_INPUT_SIZE + 1) as usize];
        fs::write(&large_file, &content).unwrap();

        let output = dir.join("output.pdf");
        let regions = vec![RedactionRegion {
            page: 1,
            x: 72.0,
            y: 700.0,
            width: 100.0,
            height: 20.0,
            entity_type: "EMAIL_ADDRESS".to_string(),
        }];

        let result = redact_pdf(&large_file, &output, &regions, "black");
        assert!(
            matches!(result, Err(RedactError::PdfLoad { .. })),
            "should reject file exceeding MAX_INPUT_SIZE"
        );
        if let Err(RedactError::PdfLoad { source, .. }) = result {
            assert!(
                source.contains("too large") || source.contains("size"),
                "error should mention file size"
            );
        }

        let _ = fs::remove_dir_all(&dir);
    }

    // ---------------------------------------------------------------------------
    // Annotation removal tests
    // ---------------------------------------------------------------------------

    /// Create a test PDF with a mailto: link annotation on page 1
    fn create_test_pdf_with_mailto_link(path: &Path) {
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
                Operation::new("Td", vec![72.into(), 700.into()]),
                Operation::new("Tj", vec![Object::string_literal("john.smith@example.com")]),
                Operation::new("ET", vec![]),
            ],
        };

        let content1_id =
            doc.add_object(Stream::new(dictionary! {}, page1_content.encode().unwrap()));

        // Create a mailto: link annotation overlapping the email text region
        // Rect is [llx, lly, urx, ury] in PDF coordinate space
        let annot_id = doc.add_object(dictionary! {
            "Type" => "Annot",
            "Subtype" => "Link",
            "Rect" => vec![72.into(), 690.into(), 200.into(), 715.into()],
            "A" => dictionary! {
                "Type" => "Action",
                "S" => "URI",
                "URI" => Object::string_literal("mailto:john.smith@example.com"),
            },
        });

        let page1_id = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "Contents" => content1_id,
            "Annots" => vec![Object::Reference(annot_id)],
        });

        let pages = dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(page1_id)],
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

        doc.save(path).expect("failed to save test PDF");
    }

    /// Create a test PDF with an https: link annotation on page 1
    fn create_test_pdf_with_https_link(path: &Path) {
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
                Operation::new("Td", vec![72.into(), 700.into()]),
                Operation::new("Tj", vec![Object::string_literal("https://example.com")]),
                Operation::new("ET", vec![]),
            ],
        };

        let content1_id =
            doc.add_object(Stream::new(dictionary! {}, page1_content.encode().unwrap()));

        // Create an https: link annotation overlapping the URL text region
        let annot_id = doc.add_object(dictionary! {
            "Type" => "Annot",
            "Subtype" => "Link",
            "Rect" => vec![72.into(), 690.into(), 200.into(), 715.into()],
            "A" => dictionary! {
                "Type" => "Action",
                "S" => "URI",
                "URI" => Object::string_literal("https://example.com"),
            },
        });

        let page1_id = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "Contents" => content1_id,
            "Annots" => vec![Object::Reference(annot_id)],
        });

        let pages = dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(page1_id)],
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

        doc.save(path).expect("failed to save test PDF");
    }

    /// Create a test PDF with multiple annotations: one inside redaction region, one outside
    fn create_test_pdf_with_multiple_annotations(path: &Path) {
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
                Operation::new("Td", vec![72.into(), 700.into()]),
                Operation::new(
                    "Tj",
                    vec![Object::string_literal("Email: john@example.com")],
                ),
                Operation::new("Td", vec![0.into(), (-100).into()]),
                Operation::new("Tj", vec![Object::string_literal("Safe link to docs")]),
                Operation::new("ET", vec![]),
            ],
        };

        let content1_id =
            doc.add_object(Stream::new(dictionary! {}, page1_content.encode().unwrap()));

        // Annotation 1: overlaps redaction region (should be removed)
        let annot1_id = doc.add_object(dictionary! {
            "Type" => "Annot",
            "Subtype" => "Link",
            "Rect" => vec![100.into(), 690.into(), 220.into(), 715.into()],
            "A" => dictionary! {
                "S" => "URI",
                "URI" => Object::string_literal("mailto:john@example.com"),
            },
        });

        // Annotation 2: outside redaction region (should be preserved)
        let annot2_id = doc.add_object(dictionary! {
            "Type" => "Annot",
            "Subtype" => "Link",
            "Rect" => vec![72.into(), 580.into(), 200.into(), 610.into()],
            "A" => dictionary! {
                "S" => "URI",
                "URI" => Object::string_literal("https://docs.example.com"),
            },
        });

        let page1_id = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "Contents" => content1_id,
            "Annots" => vec![Object::Reference(annot1_id), Object::Reference(annot2_id)],
        });

        let pages = dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(page1_id)],
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

        doc.save(path).expect("failed to save test PDF");
    }

    /// Helper to count annotations on a specific page
    fn count_page_annotations(doc: &Document, page_num: u32) -> usize {
        let pages = doc.get_pages();
        let Some(&page_id) = pages.get(&page_num) else {
            return 0;
        };
        let Ok(Object::Dictionary(page_dict)) = doc.get_object(page_id) else {
            return 0;
        };
        let Ok(annots) = page_dict.get(b"Annots") else {
            return 0;
        };
        match annots {
            Object::Array(arr) => arr.len(),
            Object::Reference(r) => {
                if let Ok(Object::Array(arr)) = doc.get_object((r.0, r.1)) {
                    arr.len()
                } else {
                    0
                }
            }
            _ => 0,
        }
    }

    #[test]
    fn redact_removes_overlapping_mailto_link_annotation() {
        let dir = test_dir("mailto_link_removal");
        let input = dir.join("input.pdf");
        let output = dir.join("output.pdf");
        create_test_pdf_with_mailto_link(&input);

        // Verify input has the annotation
        let input_doc = Document::load(&input).unwrap();
        assert_eq!(
            count_page_annotations(&input_doc, 1),
            1,
            "input should have 1 annotation"
        );

        // Redact the email region (overlaps with the link annotation rect)
        let regions = vec![RedactionRegion {
            page: 1,
            x: 70.0,
            y: 688.0,
            width: 170.0,
            height: 30.0,
            entity_type: "EMAIL_ADDRESS".to_string(),
        }];

        redact_pdf(&input, &output, &regions, "black").unwrap();

        // Verify output has no annotations on page 1
        let output_doc = Document::load(&output).unwrap();
        assert_eq!(
            count_page_annotations(&output_doc, 1),
            0,
            "output should have 0 annotations after redaction"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn redact_removes_overlapping_https_link_annotation() {
        let dir = test_dir("https_link_removal");
        let input = dir.join("input.pdf");
        let output = dir.join("output.pdf");
        create_test_pdf_with_https_link(&input);

        // Verify input has the annotation
        let input_doc = Document::load(&input).unwrap();
        assert_eq!(
            count_page_annotations(&input_doc, 1),
            1,
            "input should have 1 annotation"
        );

        // Redact the URL region
        let regions = vec![RedactionRegion {
            page: 1,
            x: 70.0,
            y: 688.0,
            width: 135.0,
            height: 30.0,
            entity_type: "URL".to_string(),
        }];

        redact_pdf(&input, &output, &regions, "black").unwrap();

        // Verify output has no annotations on page 1
        let output_doc = Document::load(&output).unwrap();
        assert_eq!(
            count_page_annotations(&output_doc, 1),
            0,
            "output should have 0 annotations after redaction"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn redact_preserves_non_overlapping_annotations() {
        let dir = test_dir("preserve_non_overlapping");
        let input = dir.join("input.pdf");
        let output = dir.join("output.pdf");
        create_test_pdf_with_multiple_annotations(&input);

        // Verify input has 2 annotations
        let input_doc = Document::load(&input).unwrap();
        assert_eq!(
            count_page_annotations(&input_doc, 1),
            2,
            "input should have 2 annotations"
        );

        // Redact only the email region (overlaps annot1, not annot2)
        let regions = vec![RedactionRegion {
            page: 1,
            x: 122.0,
            y: 696.0,
            width: 120.0,
            height: 20.0,
            entity_type: "EMAIL_ADDRESS".to_string(),
        }];

        redact_pdf(&input, &output, &regions, "black").unwrap();

        // Verify output has exactly 1 annotation (annot2 preserved)
        let output_doc = Document::load(&output).unwrap();
        assert_eq!(
            count_page_annotations(&output_doc, 1),
            1,
            "output should preserve the non-overlapping annotation"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn redact_partial_overlap_removes_annotation() {
        let dir = test_dir("partial_overlap_removal");
        let input = dir.join("input.pdf");
        let output = dir.join("output.pdf");
        create_test_pdf_with_mailto_link(&input);

        // Redact a region that only partially overlaps the annotation rect
        // Annotation rect is [72, 690, 200, 715]
        // Redaction region is [150, 700, 100, 20] -> overlaps in [150, 200] x [700, 715]
        let regions = vec![RedactionRegion {
            page: 1,
            x: 150.0,
            y: 700.0,
            width: 100.0,
            height: 20.0,
            entity_type: "EMAIL_ADDRESS".to_string(),
        }];

        visual_mask_pdf(&input, &output, &regions, "black").unwrap();

        // Any overlap should remove the annotation
        let output_doc = Document::load(&output).unwrap();
        assert_eq!(
            count_page_annotations(&output_doc, 1),
            0,
            "partial overlap should still remove annotation"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn redact_no_overlap_preserves_annotation() {
        let dir = test_dir("no_overlap_preserve");
        let input = dir.join("input.pdf");
        let output = dir.join("output.pdf");
        create_test_pdf_with_mailto_link(&input);

        // Redact a region that does NOT overlap the annotation rect
        // Annotation rect is [72, 690, 200, 715]
        // Redaction region is [300, 500, 50, 20] -> no overlap
        let regions = vec![RedactionRegion {
            page: 1,
            x: 300.0,
            y: 500.0,
            width: 50.0,
            height: 20.0,
            entity_type: "OTHER".to_string(),
        }];

        visual_mask_pdf(&input, &output, &regions, "black").unwrap();

        // Annotation should be preserved
        let output_doc = Document::load(&output).unwrap();
        assert_eq!(
            count_page_annotations(&output_doc, 1),
            1,
            "non-overlapping redaction should preserve annotation"
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
