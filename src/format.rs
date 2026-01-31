use serde_json::Value;

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

    // CSV: multiple lines with consistent comma counts
    let lines: Vec<&str> = trimmed.lines().collect();
    if lines.len() > 1 && lines[0].contains(',') {
        let counts: Vec<usize> = lines
            .iter()
            .take(5)
            .filter(|l| !l.trim().is_empty())
            .map(|l| l.matches(',').count())
            .collect();
        if !counts.is_empty() {
            let first = counts[0] as isize;
            if counts.iter().all(|&c| (c as isize - first).abs() <= 1) {
                return DetectedFormat::Csv;
            }
        }
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
        assert!(matches!(detect_format(r#"{"key": "value"}"#), DetectedFormat::Json(_)));
        assert!(matches!(detect_format(r#"[1, 2, 3]"#), DetectedFormat::Json(_)));
    }

    #[test]
    fn test_format_detection_text() {
        assert!(matches!(detect_format("hello world"), DetectedFormat::Text));
        assert!(matches!(detect_format("{invalid json"), DetectedFormat::Text));
    }

    #[test]
    fn test_format_detection_sql() {
        assert!(matches!(detect_format("SELECT * FROM users WHERE id = 1"), DetectedFormat::Sql));
        assert!(matches!(detect_format("INSERT INTO logs VALUES (1, 'test')"), DetectedFormat::Sql));
        assert!(matches!(detect_format("  DELETE FROM sessions"), DetectedFormat::Sql));
    }

    #[test]
    fn test_format_detection_csv() {
        let csv = "name,email,phone\nJohn,john@test.com,0612345678\nJane,jane@test.com,0698765432";
        assert!(matches!(detect_format(csv), DetectedFormat::Csv));
        // Single line with commas is not CSV
        assert!(!matches!(detect_format("hello, world, foo"), DetectedFormat::Csv));
    }
}
