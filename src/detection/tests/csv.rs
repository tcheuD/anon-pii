use super::super::*;

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
fn test_parse_csv_line_basic() {
    let cells = parse_csv_line("a,b,c");
    assert_eq!(cells, vec!["a", "b", "c"]);
}

#[test]
fn test_parse_csv_line_quoted() {
    let cells = parse_csv_line("\"hello, world\",b,\"c\"");
    assert_eq!(cells, vec!["hello, world", "b", "c"]);
}

#[test]
fn test_parse_csv_line_escaped_quote() {
    let cells = parse_csv_line("\"he said \"\"hi\"\"\",b");
    assert_eq!(cells, vec!["he said \"hi\"", "b"]);
}
