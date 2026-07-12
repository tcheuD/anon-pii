use std::borrow::Cow;
use std::ops::Range;

use unicode_normalization::{UnicodeNormalization, is_nfkc};
use unicode_segmentation::UnicodeSegmentation;

/// A compact mapping from a derived text range back to its source range.
///
/// Unchanged runs are represented by one linear segment. A transformed unit
/// (an NFKC grapheme, escape, or collapsed whitespace run) is represented by
/// its source/output stride, so adjacent equal-sized units form one RLE-style
/// segment. A match touching part of a transformed unit projects to that whole
/// source unit. This keeps ranges on UTF-8 boundaries without allocating one
/// offset per byte or per repeated transformed character.
#[derive(Clone, Debug)]
struct OffsetSegment {
    output: Range<usize>,
    source: Range<usize>,
    mapping: OffsetMapping,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OffsetMapping {
    Linear,
    Strided {
        output_unit: usize,
        source_unit: usize,
    },
}

type EscapeMatch = (Range<usize>, char);
type EscapeFinder = fn(&str, usize) -> Option<EscapeMatch>;

#[derive(Debug)]
struct MappedText<'a> {
    text: Cow<'a, str>,
    segments: Vec<OffsetSegment>,
    source_len: usize,
}

impl<'a> MappedText<'a> {
    fn identity(text: &'a str) -> Self {
        Self {
            text: Cow::Borrowed(text),
            segments: Vec::new(),
            source_len: text.len(),
        }
    }

    fn as_str(&self) -> &str {
        self.text.as_ref()
    }

    fn project_range(&self, range: Range<usize>) -> Option<Range<usize>> {
        if range.start > range.end
            || range.end > self.text.len()
            || !self.text.is_char_boundary(range.start)
            || !self.text.is_char_boundary(range.end)
        {
            return None;
        }
        if self.segments.is_empty() {
            return Some(range);
        }
        if range.is_empty() {
            return self.project_boundary(range.start).map(|pos| pos..pos);
        }

        let first_index = self
            .segments
            .partition_point(|segment| segment.output.end <= range.start);
        let last_exclusive = self
            .segments
            .partition_point(|segment| segment.output.start < range.end);
        let first = self.segments.get(first_index)?;
        let last = self.segments.get(last_exclusive.checked_sub(1)?)?;

        let start = first.project_start(range.start);
        let end = last.project_end(range.end);
        (start <= end && end <= self.source_len).then_some(start..end)
    }

    fn project_boundary(&self, position: usize) -> Option<usize> {
        if position > self.text.len() {
            return None;
        }
        if position == self.text.len() {
            return Some(self.source_len);
        }
        let index = self
            .segments
            .partition_point(|segment| segment.output.end <= position);
        let segment = self.segments.get(index)?;
        Some(segment.project_start(position))
    }

    fn decode_unicode_escapes(self) -> Self {
        self.decode_with(find_unicode_escape)
    }

    fn decode_percent_encoding(self) -> Self {
        self.decode_with(find_percent_escape)
    }

    fn decode_with(self, find_next: EscapeFinder) -> Self {
        let Some((first_range, first_char)) = find_next(self.as_str(), 0) else {
            return self;
        };

        let mut builder = MappedTextBuilder::with_capacity(self.text.len(), self.source_len);
        let mut copied_until = 0;
        let mut next = Some((first_range, first_char));
        while let Some((range, decoded)) = next {
            builder.push_copy(&self, copied_until..range.start);
            let source = self
                .project_range(range.clone())
                .expect("decoded escape range must project to its source");
            builder.push_atomic(source, decoded.encode_utf8(&mut [0; 4]));
            copied_until = range.end;
            next = find_next(self.as_str(), copied_until);
        }
        builder.push_copy(&self, copied_until..self.text.len());
        builder.finish()
    }
}

struct MappedTextBuilder {
    text: String,
    segments: Vec<OffsetSegment>,
    source_len: usize,
}

impl MappedTextBuilder {
    fn with_capacity(capacity: usize, source_len: usize) -> Self {
        Self {
            text: String::with_capacity(capacity),
            segments: Vec::new(),
            source_len,
        }
    }

    fn push_linear(&mut self, source: Range<usize>, value: &str) {
        debug_assert_eq!(source.len(), value.len());
        self.push_segment(source, value, OffsetMapping::Linear);
    }

    fn push_atomic(&mut self, source: Range<usize>, value: &str) {
        self.push_strided(source.clone(), value, value.len(), source.len());
    }

    fn push_strided(
        &mut self,
        source: Range<usize>,
        value: &str,
        output_unit: usize,
        source_unit: usize,
    ) {
        debug_assert!(output_unit > 0 && source_unit > 0);
        debug_assert_eq!(value.len() % output_unit, 0);
        debug_assert_eq!(source.len() % source_unit, 0);
        debug_assert_eq!(source.len() / source_unit, value.len() / output_unit);
        self.push_segment(
            source,
            value,
            OffsetMapping::Strided {
                output_unit,
                source_unit,
            },
        );
    }

    fn push_segment(&mut self, source: Range<usize>, value: &str, mapping: OffsetMapping) {
        if value.is_empty() {
            return;
        }
        let output_start = self.text.len();
        self.text.push_str(value);
        let output = output_start..self.text.len();

        if let Some(previous) = self.segments.last_mut() {
            let can_merge = match (&previous.mapping, &mapping) {
                (OffsetMapping::Linear, OffsetMapping::Linear) => {
                    let previous_delta =
                        previous.source.start as isize - previous.output.start as isize;
                    let delta = source.start as isize - output.start as isize;
                    previous_delta == delta
                }
                (OffsetMapping::Strided { .. }, OffsetMapping::Strided { .. }) => {
                    previous.mapping == mapping
                }
                _ => false,
            };
            if can_merge
                && previous.output.end == output.start
                && previous.source.end == source.start
            {
                previous.output.end = output.end;
                previous.source.end = source.end;
                return;
            }
        }

        self.segments.push(OffsetSegment {
            output,
            source,
            mapping,
        });
    }

    fn push_copy(&mut self, source_text: &MappedText<'_>, range: Range<usize>) {
        if range.is_empty() {
            return;
        }
        if source_text.segments.is_empty() {
            self.push_linear(range.clone(), &source_text.as_str()[range]);
            return;
        }

        let first = source_text
            .segments
            .partition_point(|segment| segment.output.end <= range.start);
        for segment in source_text.segments[first..]
            .iter()
            .take_while(|segment| segment.output.start < range.end)
        {
            let start = range.start.max(segment.output.start);
            let end = range.end.min(segment.output.end);
            let value = &source_text.as_str()[start..end];
            match segment.mapping {
                OffsetMapping::Linear => {
                    let source_start = segment.source.start + (start - segment.output.start);
                    self.push_linear(source_start..source_start + value.len(), value);
                }
                OffsetMapping::Strided {
                    output_unit,
                    source_unit,
                } => {
                    let source = segment.project_start(start)..segment.project_end(end);
                    let starts_on_unit = (start - segment.output.start) % output_unit == 0;
                    let ends_on_unit = (end - segment.output.start) % output_unit == 0;
                    if starts_on_unit && ends_on_unit {
                        self.push_strided(source, value, output_unit, source_unit);
                    } else {
                        self.push_atomic(source, value);
                    }
                }
            }
        }
    }

    fn finish<'a>(self) -> MappedText<'a> {
        MappedText {
            text: Cow::Owned(self.text),
            segments: self.segments,
            source_len: self.source_len,
        }
    }
}

impl OffsetSegment {
    fn project_start(&self, position: usize) -> usize {
        match self.mapping {
            OffsetMapping::Linear => self.source.start + (position - self.output.start),
            OffsetMapping::Strided {
                output_unit,
                source_unit,
            } => {
                let unit = (position - self.output.start) / output_unit;
                self.source.start + unit * source_unit
            }
        }
    }

    fn project_end(&self, position: usize) -> usize {
        match self.mapping {
            OffsetMapping::Linear => self.source.start + (position - self.output.start),
            OffsetMapping::Strided {
                output_unit,
                source_unit,
            } => {
                let offset = position - self.output.start;
                let units = offset.div_ceil(output_unit);
                self.source.start + units * source_unit
            }
        }
    }
}

/// Detection text normalized for matching, with compact provenance back to the
/// caller's exact input.
pub(super) struct NormalizedText<'a>(MappedText<'a>);

impl<'a> NormalizedText<'a> {
    pub(super) fn new(raw: &'a str) -> Self {
        let mapped = if is_nfkc(raw) {
            MappedText::identity(raw)
        } else {
            let mut builder = MappedTextBuilder::with_capacity(raw.len(), raw.len());
            for (start, grapheme) in raw.grapheme_indices(true) {
                let source = start..start + grapheme.len();
                if is_nfkc(grapheme) {
                    builder.push_linear(source, grapheme);
                } else {
                    let normalized: String = grapheme.nfkc().collect();
                    builder.push_atomic(source, &normalized);
                }
            }
            builder.finish()
        };

        Self(mapped.decode_unicode_escapes().decode_percent_encoding())
    }

    pub(super) fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub(super) fn project_range(&self, range: Range<usize>) -> Option<Range<usize>> {
        self.0.project_range(range)
    }
}

/// Newline-collapsed matching text with compact offsets back to the normalized
/// detection view.
pub(super) struct CollapsedText(MappedText<'static>);

impl CollapsedText {
    pub(super) fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub(super) fn project_range(&self, range: Range<usize>) -> Option<Range<usize>> {
        self.0.project_range(range)
    }
}

fn find_unicode_escape(input: &str, from: usize) -> Option<(Range<usize>, char)> {
    let bytes = input.as_bytes();
    let mut index = from;
    while index + 6 <= bytes.len() {
        if bytes[index] == b'\\'
            && bytes[index + 1] == b'u'
            && bytes[index + 2..index + 6]
                .iter()
                .all(u8::is_ascii_hexdigit)
        {
            let codepoint = bytes[index + 2..index + 6]
                .iter()
                .fold(0_u32, |value, byte| {
                    (value << 4) | u32::from(hex_val(*byte))
                });
            if let Some(decoded) = char::from_u32(codepoint) {
                return Some((index..index + 6, decoded));
            }
        }
        index += 1;
    }
    None
}

fn find_percent_escape(input: &str, from: usize) -> Option<(Range<usize>, char)> {
    let bytes = input.as_bytes();
    let mut index = from;
    while index + 3 <= bytes.len() {
        if bytes[index] == b'%'
            && bytes[index + 1].is_ascii_hexdigit()
            && bytes[index + 2].is_ascii_hexdigit()
        {
            let value = (hex_val(bytes[index + 1]) << 4) | hex_val(bytes[index + 2]);
            if value < 0x80 {
                return Some((index..index + 3, char::from(value)));
            }
        }
        index += 1;
    }
    None
}

/// Strip Unicode diacritics: "Gael" -> "Gael", "Rene" -> "Rene".
/// Uses NFD decomposition and removes combining marks.
pub(super) fn strip_diacritics(s: &str) -> String {
    s.nfd()
        .filter(|c| !unicode_normalization::char::is_combining_mark(*c))
        .collect()
}

/// Patterns that may span across line breaks in wrapped log output.
pub(super) const MULTILINE_ENTITY_TYPES: &[&str] = &["CREDIT_CARD", "FR_IBAN"];

/// Collapse ASCII-whitespace runs containing a newline into a single space.
/// Returns `None` when the input contains no newlines (no work to do).
pub(super) fn collapse_newlines(text: &str) -> Option<CollapsedText> {
    if !text.contains('\n') {
        return None;
    }
    let mut builder = MappedTextBuilder::with_capacity(text.len(), text.len());
    let mut chars = text.char_indices().peekable();
    let mut copied_until = 0;
    while let Some((i, c)) = chars.next() {
        if c.is_ascii_whitespace() {
            let run_start = i;
            let mut found_newline = c == '\n';
            let mut run_end = i + c.len_utf8();
            while let Some(&(j, cj)) = chars.peek() {
                if !cj.is_ascii_whitespace() {
                    break;
                }
                if cj == '\n' {
                    found_newline = true;
                }
                run_end = j + cj.len_utf8();
                chars.next();
            }
            if found_newline {
                builder.push_linear(copied_until..run_start, &text[copied_until..run_start]);
                builder.push_atomic(run_start..run_end, " ");
                copied_until = run_end;
            }
        }
    }
    builder.push_linear(copied_until..text.len(), &text[copied_until..]);
    Some(CollapsedText(builder.finish()))
}

/// Decode JSON-style `\uXXXX` escape sequences into their UTF-8 equivalents.
/// Only decodes BMP codepoints (U+0000..U+FFFF). Malformed sequences are left as-is.
#[cfg(test)]
pub(super) fn decode_unicode_escapes(input: &str) -> String {
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
pub(super) fn decode_percent_encoding(input: &str) -> String {
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

pub(super) fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

/// Parse a single CSV line respecting RFC 4180 quoting.
pub(super) fn parse_csv_line(line: &str) -> Vec<String> {
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

#[cfg(test)]
mod provenance_tests {
    use super::*;

    #[test]
    fn normalized_identity_view_borrows_input_without_segments() {
        let input = "plain text without encoded data";
        let normalized = NormalizedText::new(input);

        assert!(matches!(normalized.0.text, Cow::Borrowed(_)));
        assert!(normalized.0.segments.is_empty());
    }

    #[test]
    fn long_unchanged_runs_are_compacted_around_transformations() {
        let input = format!("{}%40{}", "a".repeat(10_000), "b".repeat(10_000));
        let normalized = NormalizedText::new(&input);

        assert_eq!(normalized.0.segments.len(), 3);
        assert_eq!(normalized.as_str().len(), input.len() - 2);
    }

    #[test]
    fn repeated_nfkc_transformations_are_run_length_encoded() {
        let input = "＠".repeat(10_000);
        let normalized = NormalizedText::new(&input);

        assert_eq!(normalized.0.segments.len(), 1);
        assert_eq!(normalized.as_str(), "@".repeat(10_000));
        assert_eq!(normalized.project_range(5..7), Some(15..21));
    }

    #[test]
    fn grapheme_normalization_matches_whole_string_nfkc() {
        let input = "x\u{1100}\u{1161}\u{11a8}e\u{301}\u{fb00}y";
        let expected: String = input.nfkc().collect();
        let normalized = NormalizedText::new(input);

        assert_eq!(normalized.as_str(), expected);
    }
}
