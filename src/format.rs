use serde_json::Value;

use crate::csv::parse_csv_document;

pub enum DetectedFormat {
    Json(Value),
    Sql,
    Csv,
    Text,
}

pub fn detect_format(content: &str) -> DetectedFormat {
    let trimmed = content.trim_start();

    // JSON
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
            return DetectedFormat::Json(value);
        }
    }

    // SQL — require a leading keyword AND a confirming SQL keyword
    if let Some(first_word) = trimmed.split_whitespace().next() {
        let upper_first = first_word.to_uppercase();
        let is_sql_lead = matches!(
            upper_first.as_str(),
            "SELECT" | "INSERT" | "UPDATE" | "DELETE" | "CREATE" | "ALTER" | "DROP"
        );
        if is_sql_lead {
            let upper = trimmed.to_uppercase();
            let has_confirming = upper.contains(" FROM ")
                || upper.contains(" INTO ")
                || upper.contains(" SET ")
                || upper.contains(" TABLE ")
                || upper.contains(" WHERE ")
                || upper.contains(" VALUES ")
                || upper.contains(" JOIN ")
                || upper.contains(" INDEX ");
            if has_confirming {
                return DetectedFormat::Sql;
            }
        }
    }

    // CSV: parse complete records so quoted commas and newlines are data, then
    // require a consistent table shape rather than tolerating ragged prose.
    if parse_csv_document(content).is_some_and(|csv| csv.has_consistent_table_shape()) {
        return DetectedFormat::Csv;
    }

    DetectedFormat::Text
}

pub fn detect_json_indent(content: &str) -> usize {
    for line in content.lines().skip(1) {
        let stripped = line.trim_start();
        if !stripped.is_empty() && line.len() > stripped.len() {
            // Use byte length difference — JSON indent is always ASCII spaces/tabs
            let indent = line.len() - stripped.len();
            if indent <= 8 {
                return indent;
            }
        }
    }
    2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_detection_json() {
        assert!(matches!(
            detect_format(r#"{"key": "value"}"#),
            DetectedFormat::Json(_)
        ));
        assert!(matches!(
            detect_format(r#"[1, 2, 3]"#),
            DetectedFormat::Json(_)
        ));
    }

    #[test]
    fn test_format_detection_text() {
        assert!(matches!(detect_format("hello world"), DetectedFormat::Text));
        assert!(matches!(
            detect_format("{invalid json"),
            DetectedFormat::Text
        ));
    }

    #[test]
    fn test_format_detection_sql() {
        assert!(matches!(
            detect_format("SELECT * FROM users WHERE id = 1"),
            DetectedFormat::Sql
        ));
        assert!(matches!(
            detect_format("INSERT INTO logs VALUES (1, 'test')"),
            DetectedFormat::Sql
        ));
        assert!(matches!(
            detect_format("  DELETE FROM sessions"),
            DetectedFormat::Sql
        ));
        assert!(matches!(
            detect_format("UPDATE users SET name = 'x'"),
            DetectedFormat::Sql
        ));
        assert!(matches!(
            detect_format("CREATE TABLE foo (id INT)"),
            DetectedFormat::Sql
        ));
    }

    #[test]
    fn test_format_detection_sql_not_plain_text() {
        // These start with SQL keywords but aren't SQL — should be Text
        assert!(matches!(
            detect_format("Select the best option"),
            DetectedFormat::Text
        ));
        assert!(matches!(
            detect_format("Delete this paragraph please"),
            DetectedFormat::Text
        ));
        assert!(matches!(
            detect_format("Update your profile"),
            DetectedFormat::Text
        ));
        assert!(matches!(
            detect_format("Create a new document"),
            DetectedFormat::Text
        ));
        assert!(matches!(
            detect_format("Drop me a message"),
            DetectedFormat::Text
        ));
    }

    #[test]
    fn test_format_detection_csv() {
        let csv = "name,email,phone\nJohn,john@test.com,0612345678\nJane,jane@test.com,0698765432";
        assert!(matches!(detect_format(csv), DetectedFormat::Csv));
        // Single line with commas is not CSV
        assert!(!matches!(
            detect_format("hello, world, foo"),
            DetectedFormat::Csv
        ));
    }

    #[test]
    fn test_format_detection_csv_understands_quotes_and_crlf() {
        let csv = "name,notes,email\r\nAlice,\"line one\r\nline two, still one field\",alice@example.com\r\n";
        assert!(matches!(detect_format(csv), DetectedFormat::Csv));
        assert!(matches!(
            detect_format("name,email\nAlice,alice@example.com\n\n"),
            DetectedFormat::Csv
        ));
    }

    #[test]
    fn test_format_detection_rejects_ragged_or_prose_input() {
        assert!(matches!(
            detect_format("name,email\nAlice,alice@example.com,extra"),
            DetectedFormat::Text
        ));
        assert!(matches!(
            detect_format("Hello, world.\nThis is ordinary prose."),
            DetectedFormat::Text
        ));
        assert!(matches!(
            detect_format("name,email\nAlice,\"unterminated"),
            DetectedFormat::Text
        ));
    }
}
