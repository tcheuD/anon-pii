use super::super::*;

// -- SQL tests --

#[test]
fn test_sql_anonymizes_string_literals_only() {
    let mut a = Anonymizer::new(0.0);
    let sql = "INSERT INTO users VALUES (1, 'john@example.com', 'admin')";
    let (result, dets) = a.anonymize_sql(sql);
    // Email inside string literal should be detected
    assert!(dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"));
    assert!(result.contains("[EMAIL_ADDRESS_"));
    // SQL keywords and structure should be preserved
    assert!(result.starts_with("INSERT INTO users VALUES"));
}

#[test]
fn test_sql_preserves_identifiers() {
    let mut a = Anonymizer::new(0.0);
    // UUID is an identifier here, not PII — it's not inside quotes
    let sql = "SELECT uuid FROM sessions WHERE id = '550e8400-e29b-41d4-a716-446655440000'";
    let (result, dets) = a.anonymize_sql(sql);
    // The UUID in the string literal should be detected
    assert!(dets.iter().any(|d| d.entity_type == "UUID"));
    // "uuid" as a column name should NOT be anonymized
    assert!(result.contains("SELECT uuid FROM"));
}

#[test]
fn test_sql_escaped_quotes() {
    let mut a = Anonymizer::new(0.0);
    let sql = "INSERT INTO logs VALUES ('it''s john@test.com')";
    let (result, dets) = a.anonymize_sql(sql);
    assert!(dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"));
    assert!(result.contains("[EMAIL_ADDRESS_"));
    assert!(result.contains("'it''s [EMAIL_ADDRESS_"));
    assert_eq!(a.mapping.restore_bracketed(&result), sql);
}

#[test]
fn test_sql_multibyte_utf8_literal_not_corrupted() {
    let mut a = Anonymizer::new(0.0);
    // Accented characters inside and outside literals must not be corrupted
    // by byte-wise scanning.
    let sql =
        "INSERT INTO clients VALUES ('Gaël Müller, réf café', 'mail: john@test.com') -- N° dossier";
    let (result, dets) = a.anonymize_sql(sql);
    assert!(dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"));
    assert!(result.contains("[EMAIL_ADDRESS_"));
    assert!(
        result.contains("-- N° dossier"),
        "Non-literal SQL must pass through byte-identical: {result}"
    );
    assert!(
        !result.contains('\u{FFFD}') && !result.contains("GaÃ«l"),
        "Multibyte characters must not be corrupted: {result}"
    );
}

#[test]
fn test_sql_unterminated_literal_is_left_byte_identical() {
    let mut a = Anonymizer::new(0.0);
    let sql = "INSERT INTO logs VALUES ('john@example.com";
    let (result, dets) = a.anonymize_sql(sql);

    assert!(dets.is_empty());
    assert_eq!(result, sql);
}

#[test]
fn test_sql_without_changes_is_byte_identical() {
    let mut a = Anonymizer::new(0.0);
    let sql = "SELECT 'it''s ordinary' AS note;\r\nSELECT 42;\r\n";
    let (result, dets) = a.anonymize_sql(sql);

    assert!(dets.is_empty());
    assert_eq!(result, sql);
}

#[test]
fn test_sql_changed_literal_preserves_crlf_and_surrounding_source() {
    let mut a = Anonymizer::new(0.0);
    let sql = "INSERT INTO logs(value)\r\nVALUES ('email john@example.com');\r\n";
    let (result, dets) = a.anonymize_sql(sql);

    assert!(dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"));
    assert!(result.starts_with("INSERT INTO logs(value)\r\nVALUES ('email "));
    assert!(result.ends_with("');\r\n"));
    assert_eq!(result.matches("\r\n").count(), 2);
    assert_eq!(a.mapping.restore_bracketed(&result), sql);
}

#[test]
fn test_sql_does_not_anonymize_quotes_inside_comments_or_identifiers() {
    let mut a = Anonymizer::new(0.0);
    let sql = "-- 'john@example.com'\r\nSELECT \"'jane@example.com'\" FROM users /* 'x@y.test' */;";
    let (result, dets) = a.anonymize_sql(sql);

    assert!(dets.is_empty());
    assert_eq!(result, sql);
}

#[test]
fn test_sql_backslash_escaped_quote_does_not_hide_later_pii() {
    let mut a = Anonymizer::new(0.0);
    let sql = r"SELECT E'it\'s john@example.com' AS note;";
    let (result, dets) = a.anonymize_sql(sql);

    assert!(dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"));
    assert!(result.contains(r"E'it\'s [EMAIL_ADDRESS_"));
    assert!(result.ends_with("' AS note;"));
    assert_eq!(a.mapping.restore_bracketed(&result), sql);
}

#[test]
fn test_sql_standard_backslash_does_not_consume_the_next_literal() {
    let mut a = Anonymizer::new(0.0);
    let sql = r"SELECT 'john@example.com\', 'jane@example.com';";
    let (result, dets) = a.anonymize_sql(sql);

    assert_eq!(
        dets.iter()
            .filter(|d| d.entity_type == "EMAIL_ADDRESS")
            .count(),
        2
    );
    assert_eq!(result.matches("[EMAIL_ADDRESS_").count(), 2);
    assert_eq!(a.mapping.restore_bracketed(&result), sql);
}

#[test]
fn test_sql_dollar_quoted_literal_is_anonymized_and_roundtrips() {
    let mut a = Anonymizer::new(0.0);
    let sql = "SELECT $body$owner john@example.com's address$body$ AS note;";
    let (result, dets) = a.anonymize_sql(sql);

    assert_eq!(
        dets.iter()
            .filter(|d| d.entity_type == "EMAIL_ADDRESS")
            .count(),
        1,
        "a dollar-quoted literal must report each detection exactly once"
    );
    assert!(result.contains("$body$owner [EMAIL_ADDRESS_"));
    assert_eq!(a.mapping.restore_bracketed(&result), sql);
}
