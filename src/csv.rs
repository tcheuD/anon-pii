use std::borrow::Cow;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CsvField {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) quoted: bool,
}

impl CsvField {
    pub(crate) fn value<'a>(&self, source: &'a str) -> Cow<'a, str> {
        let raw = &source[self.start..self.end];
        if self.quoted {
            Cow::Owned(raw[1..raw.len() - 1].replace("\"\"", "\""))
        } else {
            Cow::Borrowed(raw)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CsvRecord {
    pub(crate) fields: Vec<CsvField>,
    blank: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CsvDocument {
    pub(crate) records: Vec<CsvRecord>,
}

impl CsvDocument {
    pub(crate) fn has_consistent_table_shape(&self) -> bool {
        let mut records = self.records.iter().filter(|record| !record.blank);
        let Some(first) = records.next() else {
            return false;
        };
        let width = first.fields.len();
        width >= 2
            && records.clone().count() >= 1
            && records.all(|record| record.fields.len() == width)
    }
}

fn csv_record(fields: Vec<CsvField>) -> CsvRecord {
    let blank = fields.len() == 1 && !fields[0].quoted && fields[0].start == fields[0].end;
    CsvRecord { fields, blank }
}

/// Parse a comma-delimited RFC 4180-style document while retaining byte spans
/// for every field. Newlines inside quoted fields are data; CRLF and LF record
/// separators are both accepted. Malformed quoting is rejected rather than
/// guessed at, so callers can leave unsupported input untouched.
pub(crate) fn parse_csv_document(source: &str) -> Option<CsvDocument> {
    let bytes = source.as_bytes();
    let mut records = Vec::new();
    let mut cursor = 0;

    while cursor < bytes.len() {
        let mut fields = Vec::new();

        loop {
            let start = cursor;
            let quoted = bytes.get(cursor) == Some(&b'"');

            if quoted {
                cursor += 1;
                let mut closed = false;
                while cursor < bytes.len() {
                    if bytes[cursor] == b'"' {
                        if bytes.get(cursor + 1) == Some(&b'"') {
                            cursor += 2;
                        } else {
                            cursor += 1;
                            closed = true;
                            break;
                        }
                    } else {
                        cursor += 1;
                    }
                }
                if !closed {
                    return None;
                }
            } else {
                while cursor < bytes.len()
                    && bytes[cursor] != b','
                    && bytes[cursor] != b'\n'
                    && bytes[cursor] != b'\r'
                {
                    // A quote in an unquoted field is not valid RFC 4180.
                    if bytes[cursor] == b'"' {
                        return None;
                    }
                    cursor += 1;
                }
            }

            let end = cursor;
            fields.push(CsvField { start, end, quoted });

            match bytes.get(cursor) {
                Some(b',') => {
                    cursor += 1;
                }
                Some(b'\n') => {
                    cursor += 1;
                    records.push(csv_record(fields));
                    break;
                }
                Some(b'\r') if bytes.get(cursor + 1) == Some(&b'\n') => {
                    cursor += 2;
                    records.push(csv_record(fields));
                    break;
                }
                Some(_) => return None,
                None => {
                    records.push(csv_record(fields));
                    break;
                }
            }
        }
    }

    Some(CsvDocument { records })
}

pub(crate) fn serialize_csv_field(value: &str, preserve_quotes: bool) -> String {
    let needs_quotes = preserve_quotes
        || value
            .as_bytes()
            .iter()
            .any(|byte| matches!(byte, b',' | b'"' | b'\r' | b'\n'));

    if !needs_quotes {
        return value.to_string();
    }

    let mut serialized = String::with_capacity(value.len() + 2);
    serialized.push('"');
    for character in value.chars() {
        if character == '"' {
            serialized.push('"');
        }
        serialized.push(character);
    }
    serialized.push('"');
    serialized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quoted_multiline_fields_and_crlf() {
        let source = "name,notes\r\nAlice,\"first line\r\nsecond, line\"\r\n";
        let document = parse_csv_document(source).unwrap();

        assert!(document.has_consistent_table_shape());
        assert_eq!(document.records.len(), 2);
        assert_eq!(document.records[1].fields.len(), 2);
        assert_eq!(
            document.records[1].fields[1].value(source),
            "first line\r\nsecond, line"
        );
    }

    #[test]
    fn parses_doubled_quotes() {
        let source = "note,value\n\"said \"\"hello\"\"\",ok";
        let document = parse_csv_document(source).unwrap();
        assert_eq!(
            document.records[1].fields[0].value(source),
            "said \"hello\""
        );
    }

    #[test]
    fn rejects_malformed_quoting() {
        assert!(parse_csv_document("a,b\n1,\"unterminated").is_none());
        assert!(parse_csv_document("a,b\n1,un\"quoted").is_none());
        assert!(parse_csv_document("a,b\n1,\"closed\"junk").is_none());
    }

    #[test]
    fn table_shape_ignores_blank_records() {
        let document = parse_csv_document("name,email\nAlice,a@example.com\n\n").unwrap();
        assert!(document.has_consistent_table_shape());
    }
}
