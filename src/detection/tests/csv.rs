use super::super::*;
use crate::csv::parse_csv_document;

// -- CSV tests --

#[test]
fn test_csv_quoted_field_with_comma() {
    let mut a = Anonymizer::new(0.0);
    let csv = "name,email\n\"Doe, John\",john@example.com";
    let (result, dets) = a.anonymize_csv(csv);
    // Email in second cell should be detected
    assert!(dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"));
    assert!(result.contains("[EMAIL_ADDRESS_"));
    // Quoted field with comma should be preserved as a single cell
    assert!(result.contains("Doe, John") || result.contains("\"Doe, John\""));
}

#[test]
fn test_csv_unquoted_email() {
    let mut a = Anonymizer::new(0.0);
    let csv = "id,email,name\n1,user@test.com,Alice\n2,admin@test.com,Bob";
    let (_result, dets) = a.anonymize_csv(csv);
    assert_eq!(
        dets.iter()
            .filter(|d| d.entity_type == "EMAIL_ADDRESS")
            .count(),
        2
    );
    let email_tokens: Vec<_> = a
        .mapping
        .mappings
        .keys()
        .filter(|k| k.starts_with("[EMAIL_ADDRESS_"))
        .collect();
    assert_eq!(email_tokens.len(), 2);
}

#[test]
fn test_csv_multiline_field_and_crlf_are_preserved() {
    let mut a = Anonymizer::new(0.0);
    let csv = "id,notes,email\r\n1,\"called yesterday\r\nfollow up, please\",john@example.com\r\n";
    let (result, dets) = a.anonymize_csv(csv);

    assert!(dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"));
    assert!(result.contains("\"called yesterday\r\nfollow up, please\""));
    assert_eq!(result.matches("\r\n").count(), 3);

    let parsed = parse_csv_document(&result).unwrap();
    assert_eq!(parsed.records.len(), 2);
    assert!(parsed.records.iter().all(|record| record.fields.len() == 3));
}

#[test]
fn test_csv_escaped_quotes_roundtrip() {
    let mut a = Anonymizer::new(0.0);
    let csv = "name,note\nAlice,\"said \"\"contact john@example.com\"\" today\"\n";
    let (result, dets) = a.anonymize_csv(csv);

    assert!(dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"));
    assert!(result.contains("said \"\"contact [EMAIL_ADDRESS_"));
    assert_eq!(a.mapping.restore_bracketed(&result), csv);
}

#[test]
fn test_csv_encoded_comma_remains_inside_one_field() {
    let mut a = Anonymizer::new(0.0);
    let csv = "id,note\n1,alpha%2Cjohn@example.com\n";
    let (result, dets) = a.anonymize_csv(csv);

    assert!(dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"));
    let parsed = parse_csv_document(&result).unwrap();
    assert!(parsed.records.iter().all(|record| record.fields.len() == 2));
    assert!(
        parsed.records[1].fields[1]
            .value(&result)
            .starts_with("alpha%2C[EMAIL_ADDRESS_")
    );
}

#[test]
fn test_csv_without_detections_is_byte_identical() {
    let mut a = Anonymizer::new(0.0);
    let csv = "id,note\r\n1,\"plain, text\"\r\n";
    let (result, dets) = a.anonymize_csv(csv);

    assert!(dets.is_empty());
    assert_eq!(result, csv);
}

#[test]
fn test_malformed_csv_is_not_reconstructed() {
    let mut a = Anonymizer::new(0.0);
    let csv = "id,email\n1,\"john@example.com";
    let (result, dets) = a.anonymize_csv(csv);

    assert!(dets.is_empty());
    assert_eq!(result, csv);
}
