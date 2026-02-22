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
}
