use super::super::*;
use crate::csv::parse_csv_document;

// -- CSV tests --

#[test]
fn csv_encoded_url_masks_complete_field_span_and_restores_source() {
    let url = "ｈttps://example.invalid/?account=gb82%20west%201234%205698%207654%2032";
    let field = format!("Échec 🧪 \"\"quoted\"\" {url} ; fin");
    let csv = format!("id,note\r\n1,\"{field}\"\r\n");
    let mut anonymizer = Anonymizer::new(0.5);
    let (output, detections) = anonymizer.anonymize_csv(&csv);
    let urls: Vec<_> = detections
        .iter()
        .filter(|d| d.entity_type == "URL")
        .collect();
    assert_eq!(urls.len(), 1, "{detections:?}");
    assert_eq!(urls[0].original, url);
    assert_eq!(&field[urls[0].start..urls[0].end], url);
    assert!(
        output.starts_with("id,note\r\n1,\"Échec 🧪 \"\"quoted\"\" [URL_"),
        "{output}"
    );
    assert!(output.ends_with("] ; fin\"\r\n"), "{output}");
    assert!(!output.contains("%20"), "{output}");
    assert_eq!(anonymizer.mapping.mappings.len(), 1);
    assert_eq!(anonymizer.mapping.restore_bracketed(&output), csv);
    let parsed = parse_csv_document(&output).unwrap();
    assert_eq!(parsed.records.len(), 2);
    assert!(parsed.records.iter().all(|record| record.fields.len() == 2));
}

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

fn csv_quote_spanning_anonymizer() -> Anonymizer {
    let mut anonymizer = Anonymizer::new(0.5);
    anonymizer.patterns = vec![CompiledPattern {
        name: Cow::Borrowed("csv_quote_fixture"),
        entity_type: Cow::Borrowed("CSV_FIXTURE"),
        regex: Regex::new(r#"debug"owner"#).unwrap(),
        score: 1.0,
        context_keywords: Cow::Borrowed(&[]),
        context_required: false,
    }];
    anonymizer
}

#[test]
fn csv_quote_spanning_tokens_preserve_structure_and_distinct_raw_mapping() {
    for csv in [
        "id,note\r\n1,\"prefix debug\"\"owner, ok\r\nnext line\"\r\n",
        "id,note\n1,\"debug\"\"owner\"\n2,\"debug\"\"owner\"\n",
        "id,note\n1,\"said \"\"debug\"\"owner\"\" today\"\n",
    ] {
        let mut anonymizer = csv_quote_spanning_anonymizer();
        let plain = "debug\"owner";
        let (plain_output, _) = anonymizer.anonymize_text(plain);
        let (output, detections) = anonymizer.anonymize_csv(csv);
        assert!(!detections.is_empty());
        assert!(detections.iter().all(|d| d.original == "debug\"\"owner"));
        let parsed = parse_csv_document(&output).expect("anonymized CSV must remain valid");
        assert_eq!(
            parsed.records.len(),
            parse_csv_document(csv).unwrap().records.len()
        );
        assert!(parsed.records.iter().all(|record| record.fields.len() == 2));
        assert_eq!(anonymizer.mapping.mappings.len(), 2);
        assert_eq!(anonymizer.mapping.restore_bracketed(&output), csv);
        assert_eq!(anonymizer.mapping.restore_bracketed(&plain_output), plain);
    }
}

#[test]
fn csv_quote_provenance_composes_with_normalized_detection() {
    for raw_field in [
        r#"Préfixe 🏡 ｄebug""owner suffixe"#,
        r"debug%22owner",
        r"debug\u0022owner",
    ] {
        let csv = format!("id,note\n1,\"{raw_field}\"\n");
        let mut anonymizer = csv_quote_spanning_anonymizer();
        let (output, detections) = anonymizer.anonymize_csv(&csv);
        assert_eq!(detections.len(), 1, "input: {csv}");
        let detection = &detections[0];
        assert_eq!(
            &raw_field[detection.start..detection.end],
            detection.original
        );
        assert!(parse_csv_document(&output).is_some());
        assert_eq!(anonymizer.mapping.restore_bracketed(&output), csv);
    }
}

#[test]
fn csv_ner_sees_decoded_quotes_and_restores_their_source_spelling() {
    struct QuotedNameDetector;
    impl NerDetector for QuotedNameDetector {
        fn detect_persons(&self, text: &str) -> Vec<NerSpan> {
            let name = "Avery \"Orbit\" Vale";
            let Some(start) = text.find(name) else {
                return Vec::new();
            };
            vec![NerSpan {
                text: name.to_string(),
                start,
                end: start + name.len(),
                score: 0.9,
                label: "PERSON".to_string(),
            }]
        }
    }

    let csv = "id,note\r\n1,\"Met Avery \"\"Orbit\"\" Vale yesterday\"\r\n";
    let mut anonymizer = Anonymizer::new(0.5);
    anonymizer.set_ner_detector(Box::new(QuotedNameDetector));
    let (output, detections) = anonymizer.anonymize_csv(csv);
    assert!(detections.iter().any(|detection| {
        detection.entity_type == "PERSON" && detection.original == "Avery \"\"Orbit\"\" Vale"
    }));
    assert!(!output.contains("Orbit"));
    assert!(parse_csv_document(&output).is_some());
    assert_eq!(anonymizer.mapping.restore_bracketed(&output), csv);
}

#[test]
fn csv_non_token_operators_keep_decoded_value_semantics() {
    let csv = "id,note\n1,\"debug\"\"owner\"\n";
    let mut keep = csv_quote_spanning_anonymizer();
    keep.operator = Operator::Keep;
    let (output, detections) = keep.anonymize_csv(csv);
    assert_eq!(output, csv);
    assert_eq!(detections[0].original, "debug\"owner");
    assert!(keep.mapping.mappings.is_empty());

    let mut custom = csv_quote_spanning_anonymizer();
    custom.operator = Operator::Custom;
    custom.replace_with = Some("redacted \"value\"".to_string());
    let (output, _) = custom.anonymize_csv(csv);
    let parsed = parse_csv_document(&output).expect("custom quote replacement must be escaped");
    assert_eq!(
        parsed.records[1].fields[1].value(&output),
        "redacted \"value\""
    );
    assert!(custom.mapping.mappings.is_empty());
}
