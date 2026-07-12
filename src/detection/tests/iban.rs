use super::super::*;

#[test]
fn test_fr_iban() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("IBAN: FR14 2004 1010 0505 0001 3M02 606");
    assert!(
        dets.iter().any(|d| d.entity_type == "FR_IBAN"),
        "canonical French IBAN not detected: {dets:?}"
    );
    assert!(result.contains("[FR_IBAN_"));
}

#[test]
fn test_fr_iban_compact() {
    for iban in ["FR1420041010050500013M02606", "FR7630006000011234567890189"] {
        let mut a = Anonymizer::new(0.0);
        let (result, dets) = a.anonymize_text(&format!("IBAN: {iban}"));
        assert!(
            dets.iter().any(|d| d.entity_type == "FR_IBAN"),
            "valid French IBAN rejected: {iban}; detections: {dets:?}"
        );
        assert!(result.contains("[FR_IBAN_"));
    }
}

#[test]
fn test_fr_iban_invalid_checksums_rejected() {
    for iban in [
        "FR7612345678901234567890123",
        "FR1520041010050500013M02606",
        "FR1420041010050500013M02607",
        "FR1420041010050500013N02606",
    ] {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text(&format!("IBAN: {iban}"));
        assert!(
            !dets
                .iter()
                .any(|d| matches!(d.entity_type.as_ref(), "FR_IBAN" | "IBAN_CODE")),
            "invalid French IBAN accepted: {iban}; detections: {dets:?}"
        );
    }
}

#[test]
fn test_fr_iban_url_inner_checksum_validation() {
    let mut valid = Anonymizer::new(0.0);
    let (_, valid_dets) =
        valid.anonymize_text("visit https://example.com/pay?iban=FR1420041010050500013%4D02606");
    assert!(
        valid_dets.iter().any(|d| d.entity_type == "FR_IBAN"),
        "valid URL-encoded French IBAN not reported: {valid_dets:?}"
    );

    let mut invalid = Anonymizer::new(0.0);
    let (_, invalid_dets) =
        invalid.anonymize_text("visit https://example.com/pay?iban=FR1520041010050500013%4D02606");
    assert!(
        !invalid_dets
            .iter()
            .any(|d| matches!(d.entity_type.as_ref(), "FR_IBAN" | "IBAN_CODE")),
        "invalid URL-encoded French IBAN reported: {invalid_dets:?}"
    );
}

#[test]
fn test_fr_iban_roundtrip_preserves_alphanumeric_account() {
    let mut a = Anonymizer::new(0.0);
    let input = "virement sur IBAN FR14 2004 1010 0505 0001 3M02 606";
    let (anon, dets) = a.anonymize_text(input);
    assert!(dets.iter().any(|d| {
        d.entity_type == "FR_IBAN" && d.original == "FR14 2004 1010 0505 0001 3M02 606"
    }));
    assert_eq!(a.mapping.restore(&anon), input);
}

// -- Generic IBAN tests --

#[test]
fn test_iban_german() {
    let mut a = Anonymizer::new(0.0);
    // DE89 3704 0044 0532 0130 00 - valid mod-97
    let (result, dets) = a.anonymize_text("iban DE89 3704 0044 0532 0130 00");
    assert!(
        dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
        "German IBAN not detected: {dets:?}"
    );
    assert!(result.contains("[IBAN_CODE_"));
}

#[test]
fn test_iban_british() {
    let mut a = Anonymizer::new(0.0);
    // GB29 NWBK 6016 1331 9268 19 - valid mod-97
    let (result, dets) = a.anonymize_text("account GB29NWBK60161331926819");
    assert!(
        dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
        "British IBAN not detected: {dets:?}"
    );
    assert!(result.contains("[IBAN_CODE_"));
}

#[test]
fn test_iban_spanish() {
    let mut a = Anonymizer::new(0.0);
    // ES91 2100 0418 4502 0005 1332 - valid mod-97
    let (result, dets) = a.anonymize_text("virement ES91 2100 0418 4502 0005 1332");
    assert!(
        dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
        "Spanish IBAN not detected: {dets:?}"
    );
    assert!(result.contains("[IBAN_CODE_"));
}

#[test]
fn test_iban_invalid_checksum_rejected() {
    let mut a = Anonymizer::new(0.0);
    // DE00 3704 0044 0532 0130 00 - invalid check digits
    let (_, dets) = a.anonymize_text("iban DE00 3704 0044 0532 0130 00");
    assert!(
        !dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
        "IBAN with invalid checksum should be rejected: {dets:?}"
    );
}

#[test]
fn test_iban_context_required() {
    let mut a = Anonymizer::new(0.0);
    // Valid IBAN but no context keyword - should be rejected
    let (_, dets) = a.anonymize_text("code DE89370400440532013000 here");
    assert!(
        !dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
        "IBAN without context should be rejected: {dets:?}"
    );
}

#[test]
fn test_iban_fr_stays_fr_iban() {
    // French IBANs should still be detected as FR_IBAN (higher confidence)
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("IBAN: FR14 2004 1010 0505 0001 3M02 606");
    assert!(
        dets.iter().any(|d| d.entity_type == "FR_IBAN"),
        "French IBAN should stay FR_IBAN: {dets:?}"
    );
    assert!(result.contains("[FR_IBAN_"));
}

// -- IBAN_CODE (generic) battle tests --

#[test]
fn test_iban_dutch() {
    let mut a = Anonymizer::new(0.0);
    // NL91 ABNA 0417 1643 00 - valid mod-97
    let (result, dets) = a.anonymize_text("bank account NL91ABNA0417164300");
    assert!(
        dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
        "Dutch IBAN not detected: {dets:?}"
    );
    assert!(result.contains("[IBAN_CODE_"));
}

#[test]
fn test_iban_belgian() {
    let mut a = Anonymizer::new(0.0);
    // BE68 5390 0754 7034 - valid mod-97
    let (result, dets) = a.anonymize_text("iban: BE68539007547034");
    assert!(
        dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
        "Belgian IBAN not detected: {dets:?}"
    );
    assert!(result.contains("[IBAN_CODE_"));
}

#[test]
fn test_iban_swiss() {
    let mut a = Anonymizer::new(0.0);
    // CH93 0076 2011 6238 5295 7 - valid mod-97
    let (result, dets) = a.anonymize_text("swift transfer CH9300762011623852957");
    assert!(
        dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
        "Swiss IBAN not detected: {dets:?}"
    );
    assert!(result.contains("[IBAN_CODE_"));
}

#[test]
fn test_iban_with_spaces() {
    let mut a = Anonymizer::new(0.0);
    // Same German IBAN but with standard 4-char groups
    let (result, dets) = a.anonymize_text("payment DE89 3704 0044 0532 0130 00");
    assert!(
        dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
        "spaced IBAN not detected: {dets:?}"
    );
    assert!(result.contains("[IBAN_CODE_"));
}

#[test]
fn test_iban_off_by_one_checksum_rejected() {
    let mut a = Anonymizer::new(0.0);
    // DE90 instead of DE89 - should fail mod-97
    let (_, dets) = a.anonymize_text("iban DE90370400440532013000");
    assert!(
        !dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
        "IBAN with wrong check digits should be rejected: {dets:?}"
    );
}

#[test]
fn test_iban_lowercase_rejected() {
    let mut a = Anonymizer::new(0.0);
    // Country code must be uppercase per pattern
    let (_, dets) = a.anonymize_text("iban de89370400440532013000");
    assert!(
        !dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
        "lowercase IBAN should not match the regex: {dets:?}"
    );
}

#[test]
fn test_iban_too_short_rejected() {
    let mut a = Anonymizer::new(0.0);
    // 4 check + only 6 BBAN chars = too short
    let (_, dets) = a.anonymize_text("iban XX12ABCDEF");
    assert!(
        !dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
        "too-short IBAN should not match: {dets:?}"
    );
}

#[test]
fn test_iban_roundtrip() {
    let mut a = Anonymizer::new(0.0);
    let input = "virement sur le compte iban DE89370400440532013000";
    let (anon, _) = a.anonymize_text(input);
    let restored = a.mapping.restore(&anon);
    assert_eq!(restored, input, "IBAN roundtrip should restore original");
}
