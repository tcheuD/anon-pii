use super::super::*;

#[test]
fn test_email() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("contact john@example.com now");
    assert_eq!(dets.len(), 1);
    assert_eq!(dets[0].entity_type, "EMAIL_ADDRESS");
    assert!(result.contains("[EMAIL_ADDRESS_"));
}

#[test]
fn test_unicode_local_part_is_detected_as_one_complete_email() {
    let mut a = Anonymizer::new(0.0);
    let input = "Email iñes@example.com";
    let (result, dets) = a.anonymize_text(input);

    assert_eq!(dets.len(), 1);
    assert_eq!(dets[0].entity_type, "EMAIL_ADDRESS");
    assert_eq!(dets[0].original, "iñes@example.com");
    assert_eq!((dets[0].start, dets[0].end), (6, input.len()));
    assert_eq!(a.mapping.restore_bracketed(&result), input);
}

#[test]
fn test_utf8_email_in_accented_text() {
    let mut a = Anonymizer::new(0.0);
    let input = "Heloise a envoye un mail a heloise@example.com depuis Zurich";
    let (result, _) = a.anonymize_text(input);
    assert!(result.contains("[EMAIL_ADDRESS_"));
    // Verify the surrounding accented text is preserved
    assert!(result.contains("Heloise"));
    assert!(result.contains("Zurich"));
}

#[test]
fn test_unicode_fullwidth_email_detected() {
    let mut a = Anonymizer::new(0.0);
    // Fullwidth '@' (U+FF20) should be NFKC-normalized to ASCII '@'
    let input = "contact user\u{FF20}example.com now";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"),
        "Fullwidth @ should be normalized and detected as email"
    );
    assert!(result.contains("[EMAIL_ADDRESS_"));
}

#[test]
fn test_unicode_normalization_preserves_ascii() {
    let mut a = Anonymizer::new(0.0);
    // Pure ASCII input should be unchanged by NFKC
    let (result, dets) = a.anonymize_text("contact john@example.com now");
    assert_eq!(dets.len(), 1);
    assert!(result.contains("[EMAIL_ADDRESS_"));
}

#[test]
fn test_unicode_escape_email_detected() {
    let mut a = Anonymizer::new(0.0);
    // \u0040 is @ - should be decoded and detected as email
    let (result, dets) = a.anonymize_text(r"client\u0040company.com requested refund");
    assert!(
        dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"),
        "Email with \\u0040 should be detected: {:?}",
        dets
    );
    assert!(result.contains("[EMAIL_ADDRESS_"));
}

#[test]
fn test_unicode_escape_multiple_sequences() {
    let mut a = Anonymizer::new(0.0);
    // Multiple unicode escapes in one email
    let (result, dets) = a.anonymize_text(r"user\u0040domain\u002Ecom");
    assert!(
        dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"),
        "Email with multiple unicode escapes should be detected: {:?}",
        dets
    );
    assert!(result.contains("[EMAIL_ADDRESS_"));
}

#[test]
fn test_unicode_escape_no_double_mask() {
    let mut a = Anonymizer::new(0.0);
    // Plain email (no escapes) should still work normally
    let (result, dets) = a.anonymize_text("contact jane@example.com here");
    assert_eq!(dets.len(), 1);
    assert_eq!(dets[0].entity_type, "EMAIL_ADDRESS");
    assert!(result.contains("[EMAIL_ADDRESS_"));
}

#[test]
fn test_unicode_escape_malformed_passthrough() {
    // Malformed \u sequences should pass through without panic
    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_text(r"bad escape \u00 and \u00GG here");
    assert!(result.contains(r"\u00"));
}

#[test]
fn test_percent_encoded_email_detected() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("email=j.smith%40provider.net&loyalty_id=9928374");
    assert!(
        dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS"),
        "Email with %40 should be detected: {:?}",
        dets
    );
    assert!(result.contains("[EMAIL_ADDRESS_"));
}

#[test]
fn test_percent_encoded_no_double_mask() {
    let mut a = Anonymizer::new(0.0);
    // Plain email (no encoding) should still work
    let (result, dets) = a.anonymize_text("email=j.smith@provider.net");
    assert_eq!(
        dets.iter()
            .filter(|d| d.entity_type == "EMAIL_ADDRESS")
            .count(),
        1
    );
    assert!(result.contains("[EMAIL_ADDRESS_"));
}
