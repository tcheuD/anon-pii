//! Tests for `Anonymizer::anonymize_texts` batch API.

use super::super::*;
use crate::ner::{MockNerDetector, NerSpan};

// -- Basic functionality --

#[test]
fn test_anonymize_texts_empty_input() {
    let mut a = Anonymizer::new(0.0);
    let texts: Vec<&str> = vec![];
    let results = a.anonymize_texts(&texts);
    assert!(results.is_empty());
}

#[test]
fn test_anonymize_texts_single_text() {
    let mut a = Anonymizer::new(0.0);
    let texts = vec!["Contact john@example.com please."];
    let results = a.anonymize_texts(&texts);
    assert_eq!(results.len(), 1);
    let (anonymized, detections) = &results[0];
    assert!(anonymized.contains("[EMAIL_ADDRESS_"));
    assert!(detections.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"));
}

#[test]
fn test_anonymize_texts_multiple_texts() {
    let mut a = Anonymizer::new(0.0);
    let texts = vec![
        "Email: alice@example.com",
        "IP: 192.168.1.1",
        "Phone: +33 6 12 34 56 78",
    ];
    let results = a.anonymize_texts(&texts);
    assert_eq!(results.len(), 3);

    let (anon0, dets0) = &results[0];
    assert!(anon0.contains("[EMAIL_ADDRESS_"));
    assert!(dets0.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"));

    let (anon1, dets1) = &results[1];
    assert!(anon1.contains("[IP_ADDRESS_"));
    assert!(dets1.iter().any(|d| d.entity_type == "IP_ADDRESS"));

    let (anon2, dets2) = &results[2];
    assert!(anon2.contains("[FR_PHONE_NUMBER_") || anon2.contains("[PHONE_NUMBER_"));
    assert!(
        dets2
            .iter()
            .any(|d| d.entity_type == "FR_PHONE_NUMBER" || d.entity_type == "PHONE_NUMBER")
    );
}

// -- Consistency with sequential anonymize_text --

#[test]
fn test_anonymize_texts_identical_to_sequential() {
    // Results from batch should match sequential calls exactly
    let texts = vec![
        "Email: test@example.org",
        "IBAN: iban DE89370400440532013000",
        "SSN: 123-45-6789",
    ];

    // Sequential
    let mut a_seq = Anonymizer::new(0.0);
    let seq_results: Vec<(String, Vec<Detection>)> =
        texts.iter().map(|t| a_seq.anonymize_text(t)).collect();

    // Batch
    let mut a_batch = Anonymizer::new(0.0);
    let batch_results = a_batch.anonymize_texts(&texts);

    assert_eq!(seq_results.len(), batch_results.len());
    for i in 0..texts.len() {
        // Detection counts should match
        assert_eq!(
            seq_results[i].1.len(),
            batch_results[i].1.len(),
            "Text {}: detection count mismatch. Sequential: {:?}, Batch: {:?}",
            i,
            seq_results[i].1,
            batch_results[i].1
        );

        // Entity types should match (in order)
        let seq_types: Vec<&str> = seq_results[i]
            .1
            .iter()
            .map(|d| d.entity_type.as_ref())
            .collect();
        let batch_types: Vec<&str> = batch_results[i]
            .1
            .iter()
            .map(|d| d.entity_type.as_ref())
            .collect();
        assert_eq!(seq_types, batch_types, "Text {}: entity types mismatch", i);

        // Original values should match
        let seq_originals: Vec<&str> = seq_results[i]
            .1
            .iter()
            .map(|d| d.original.as_str())
            .collect();
        let batch_originals: Vec<&str> = batch_results[i]
            .1
            .iter()
            .map(|d| d.original.as_str())
            .collect();
        assert_eq!(
            seq_originals, batch_originals,
            "Text {}: original values mismatch",
            i
        );
    }
}

// -- Mapping consistency --

#[test]
fn test_anonymize_texts_mapping_consistency() {
    // Same email appearing in different texts should get the same token
    let texts = vec!["First: test@example.com", "Second: test@example.com again"];

    let mut a = Anonymizer::new(0.0);
    let results = a.anonymize_texts(&texts);

    // Extract the email token from first result
    let (anon0, _) = &results[0];
    let token = anon0
        .split_whitespace()
        .find(|s| s.starts_with("[EMAIL_ADDRESS_"))
        .expect("Should find email token in first text");

    // Same token should appear in second result
    let (anon1, _) = &results[1];
    assert!(
        anon1.contains(token),
        "Same email should get same token across texts. Token: {}, Second: {}",
        token,
        anon1
    );
}

#[test]
fn test_anonymize_texts_mapping_same_as_sequential() {
    // Mapping should produce equivalent results whether batch or sequential
    let texts = vec!["user@company.com contacted support"];

    let mut a_seq = Anonymizer::new(0.0);
    let (seq_result, _) = a_seq.anonymize_text(texts[0]);

    let mut a_batch = Anonymizer::new(0.0);
    let batch_results = a_batch.anonymize_texts(&texts);
    let (batch_result, _) = &batch_results[0];

    // Both should contain an EMAIL_ADDRESS token (not necessarily the same suffix)
    assert!(seq_result.contains("[EMAIL_ADDRESS_"));
    assert!(batch_result.contains("[EMAIL_ADDRESS_"));
}

// -- NER integration --

#[test]
fn test_anonymize_texts_with_ner_detector() {
    let mock = MockNerDetector {
        spans: vec![NerSpan {
            text: "Dupont".to_string(),
            start: 8,
            end: 14,
            score: 0.9,
            label: "PERSON".to_string(),
        }],
    };

    let mut a = Anonymizer::new(0.0);
    a.set_ner_detector(Box::new(mock));

    let texts = vec!["Contact Dupont at jean@example.com"];
    let results = a.anonymize_texts(&texts);

    let (anonymized, detections) = &results[0];
    assert!(
        detections.iter().any(|d| d.entity_type == "PERSON"),
        "PERSON should be detected via NER. Detections: {:?}",
        detections
    );
    assert!(
        detections.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"),
        "EMAIL should still be detected. Detections: {:?}",
        detections
    );
    assert!(anonymized.contains("[PERSON_"));
    assert!(anonymized.contains("[EMAIL_ADDRESS_"));
}

#[test]
fn test_anonymize_texts_without_ner_no_person() {
    // Without NER detector, PERSON entities should not be detected
    let mut a = Anonymizer::new(0.0);
    let texts = vec!["Contact M. Dupont at the office"];
    let results = a.anonymize_texts(&texts);

    let (_, detections) = &results[0];
    assert!(
        !detections.iter().any(|d| d.entity_type == "PERSON"),
        "Without NER, PERSON should not be detected. Detections: {:?}",
        detections
    );
}

#[test]
fn test_anonymize_texts_ner_batch_used() {
    // Verify that NER batch API is called (by checking results are correct)
    // The MockNerDetector returns the same spans for all texts via the default
    // batch implementation, which we can verify works correctly.
    let mock = MockNerDetector {
        spans: vec![NerSpan {
            text: "Alice".to_string(),
            start: 0,
            end: 5,
            score: 0.9,
            label: "PERSON".to_string(),
        }],
    };

    let mut a = Anonymizer::new(0.0);
    a.set_ner_detector(Box::new(mock));

    let texts = vec!["Alice sent an email", "Bob replied to Alice"];
    let results = a.anonymize_texts(&texts);

    // Both texts should have PERSON detections from the mock
    for (i, (_, dets)) in results.iter().enumerate() {
        assert!(
            dets.iter().any(|d| d.entity_type == "PERSON"),
            "Text {}: PERSON should be detected via batch NER. Detections: {:?}",
            i,
            dets
        );
    }
}

// -- Operator modes --

#[test]
fn test_anonymize_texts_with_redact_operator() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Redact;

    let texts = vec!["Delete email: hidden@example.com"];
    let results = a.anonymize_texts(&texts);

    let (anonymized, _) = &results[0];
    assert_eq!(anonymized, "Delete email: ");
    assert!(!anonymized.contains("hidden@example.com"));
}

#[test]
fn test_anonymize_texts_with_keep_operator() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Keep;

    let texts = vec!["Keep email: visible@example.com"];
    let results = a.anonymize_texts(&texts);

    let (anonymized, detections) = &results[0];
    // Original text unchanged
    assert_eq!(anonymized, "Keep email: visible@example.com");
    // But detections still reported
    assert!(detections.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"));
}

// -- Test data file integration --

#[test]
fn test_anonymize_texts_debug_log_lines() {
    // Process multiple lines from debug-log.txt format
    let lines = vec![
        "2024-03-15 08:42:01 [INFO]  Contact: jean.dupont@example-air.com / +33 6 12 34 56 78",
        "2024-03-15 08:43:22 [ERROR] Passenger data sync failed from 10.42.8.201 to 192.168.1.50",
        "2024-03-15 08:45:12 [INFO]  Replacement crew member PBR assigned, passport: 12AB34567",
    ];

    // Sequential
    let mut a_seq = Anonymizer::new(0.0);
    let seq_results: Vec<(String, Vec<Detection>)> =
        lines.iter().map(|l| a_seq.anonymize_text(l)).collect();

    // Batch
    let mut a_batch = Anonymizer::new(0.0);
    let batch_results = a_batch.anonymize_texts(&lines);

    // Detection counts should match for each line
    for i in 0..lines.len() {
        assert_eq!(
            seq_results[i].1.len(),
            batch_results[i].1.len(),
            "Line {}: detection count should match. Seq: {:?}, Batch: {:?}",
            i,
            seq_results[i].1,
            batch_results[i].1
        );
    }

    // Line 0: email + phone
    assert!(
        batch_results[0]
            .1
            .iter()
            .any(|d| d.entity_type == "EMAIL_ADDRESS")
    );
    assert!(
        batch_results[0]
            .1
            .iter()
            .any(|d| d.entity_type == "FR_PHONE_NUMBER")
    );

    // Line 1: IPs
    let ip_count = batch_results[1]
        .1
        .iter()
        .filter(|d| d.entity_type == "IP_ADDRESS")
        .count();
    assert!(ip_count >= 2, "Should detect at least 2 IPs in line 1");
}

#[test]
fn test_anonymize_texts_csv_cells() {
    // CSV-like data (individual cells, not full CSV parsing)
    let cells = vec![
        "jean.dupont@example-air.com",
        "+33 6 12 34 56 78",
        "FR7630006000011234567890189",
    ];

    let mut a = Anonymizer::new(0.0);
    let results = a.anonymize_texts(&cells);

    assert!(
        results[0]
            .1
            .iter()
            .any(|d| d.entity_type == "EMAIL_ADDRESS")
    );
    assert!(
        results[1]
            .1
            .iter()
            .any(|d| d.entity_type == "FR_PHONE_NUMBER")
    );
    assert!(results[2].1.iter().any(|d| d.entity_type == "FR_IBAN"));
}
