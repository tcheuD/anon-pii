use super::super::*;

// -- Multiline detection tests --

#[test]
fn test_multiline_credit_card_detected() {
    let mut a = Anonymizer::new(0.0);
    // 4111111111111111 is valid Visa (passes Luhn), split across newline
    let input = "Body: User: Alice | CC: 4111\n1111 1111 1111 (Credit card split across newline)";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "CREDIT_CARD"),
        "Credit card split across newline should be detected: {:?}",
        dets
    );
    assert!(result.contains("[CREDIT_CARD_"));
}

#[test]
fn test_multiline_iban_detected() {
    let mut a = Anonymizer::new(0.0);
    let input = "IBAN: FR76 3000\n6000 0112 3456 7890 123";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "FR_IBAN"),
        "IBAN split across newline should be detected: {:?}",
        dets
    );
    assert!(result.contains("[FR_IBAN_"));
}

#[test]
fn test_multiline_credit_card_trailing_space() {
    let mut a = Anonymizer::new(0.0);
    // Trailing space before newline — real-world log wrapping
    let input = "Body: User: Alice | CC: 4111 \n1111 1111 1111 (Valid Visa split across newline)";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "CREDIT_CARD"),
        "Credit card with trailing space before newline should be detected: {:?}",
        dets
    );
    assert!(result.contains("[CREDIT_CARD_"));
}

#[test]
fn test_multiline_credit_card_indented_continuation() {
    let mut a = Anonymizer::new(0.0);
    // Indented continuation line — common in log dumps
    let input = "CC: 4111\n    1111 1111 1111";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "CREDIT_CARD"),
        "Credit card with indented continuation should be detected: {:?}",
        dets
    );
    assert!(result.contains("[CREDIT_CARD_"));
}

#[test]
fn test_multiline_iban_trailing_space() {
    let mut a = Anonymizer::new(0.0);
    let input = "IBAN: FR76 3000 \n6000 0112 3456 7890 123";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "FR_IBAN"),
        "IBAN with trailing space before newline should be detected: {:?}",
        dets
    );
    assert!(result.contains("[FR_IBAN_"));
}

#[test]
fn test_multiline_no_false_positive() {
    let mut a = Anonymizer::new(0.0);
    // Unrelated numbers on separate lines should NOT merge into a credit card
    let input = "count: 4111\ntotal: 1111";
    let (_, dets) = a.anonymize_text(input);
    assert!(
        !dets.iter().any(|d| d.entity_type == "CREDIT_CARD"),
        "Unrelated numbers on separate lines should not be a credit card: {:?}",
        dets
    );
}

#[test]
fn test_multiline_full_stress_payload() {
    let mut a = Anonymizer::new(0.0);
    let input = "2024-03-15 10:20:01 [INFO]  Dumping raw socket content:\n\
                  Beginning of message...\n\
                  Body: User: Alice | CC: 4111 \n\
                  1111 1111 1111 (Valid Visa split across a newline)\n\
                  End of message.";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "CREDIT_CARD"),
        "Credit card in full log payload should be detected: {:?}",
        dets
    );
    assert!(result.contains("[CREDIT_CARD_"));
    assert!(!result.contains("4111"));
}
