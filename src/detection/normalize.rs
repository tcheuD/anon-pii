use unicode_normalization::UnicodeNormalization;

/// Strip Unicode diacritics: "Gael" -> "Gael", "Rene" -> "Rene".
/// Uses NFD decomposition and removes combining marks.
pub(super) fn strip_diacritics(s: &str) -> String {
    s.nfd()
        .filter(|c| !unicode_normalization::char::is_combining_mark(*c))
        .collect()
}

/// Patterns that may span across line breaks in wrapped log output.
pub(super) const MULTILINE_ENTITY_TYPES: &[&str] = &["CREDIT_CARD", "FR_IBAN"];

/// Collapse `\s*\n\s*` sequences into a single space and build a mapping from
/// collapsed byte offsets back to original byte offsets. Returns `None` when the
/// input contains no newlines (no work to do).
pub(super) fn collapse_newlines(text: &str) -> Option<(String, Vec<usize>)> {
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
