use super::super::*;

#[test]
fn test_fr_phone_intl() {
    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_text("call +33 6 12 34 56 78");
    assert!(result.contains("[FR_PHONE_NUMBER_"));
}

#[test]
fn test_fr_phone_national() {
    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_text("call 06 12 34 56 78");
    assert!(result.contains("[FR_PHONE_NUMBER_"));
}

#[test]
fn test_fr_phone_compact() {
    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_text("appeler 0612345678 rapidement");
    assert!(result.contains("[FR_PHONE_NUMBER_"));
    assert!(!result.contains("0612345678"));
}

// -- International phone number tests --

#[test]
fn test_intl_phone_us_with_context() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("phone: +1 212 555 1234");
    assert!(
        dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
        "US phone not detected: {dets:?}"
    );
    assert!(result.contains("[PHONE_NUMBER_"));
}

#[test]
fn test_intl_phone_uk_with_context() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("contact tel +44 20 7946 0958");
    assert!(
        dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
        "UK phone not detected: {dets:?}"
    );
    assert!(result.contains("[PHONE_NUMBER_"));
}

#[test]
fn test_intl_phone_de_with_context() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("telephone +49 30 123456");
    assert!(
        dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
        "DE phone not detected: {dets:?}"
    );
    assert!(result.contains("[PHONE_NUMBER_"));
}

#[test]
fn test_intl_phone_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    // No context keyword - should NOT match (context_required)
    let (_, dets) = a.anonymize_text("value is +1 212 555 1234 here");
    assert!(
        !dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
        "intl phone without context should be rejected: {dets:?}"
    );
}

#[test]
fn test_intl_phone_hyphenated() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("mobile: +44-20-7946-0958");
    assert!(
        dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
        "hyphenated phone not detected: {dets:?}"
    );
    assert!(result.contains("[PHONE_NUMBER_"));
}

#[test]
fn test_intl_phone_parenthesized_area_code() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("call +1 (212) 555-1234");
    assert!(
        dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
        "parenthesized area code not detected: {dets:?}"
    );
    assert!(result.contains("[PHONE_NUMBER_"));
}

#[test]
fn test_fr_phone_stays_fr_phone() {
    // French numbers should still match as FR_PHONE_NUMBER (higher confidence), not generic PHONE_NUMBER
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("call +33 6 12 34 56 78");
    assert!(
        dets.iter().any(|d| d.entity_type == "FR_PHONE_NUMBER"),
        "French phone should stay FR_PHONE_NUMBER: {dets:?}"
    );
    assert!(result.contains("[FR_PHONE_NUMBER_"));
}

#[test]
fn test_percent_encoded_phone_detected() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("tel=%2B33612345678");
    assert!(
        dets.iter().any(|d| d.entity_type == "FR_PHONE_NUMBER"),
        "Phone with %2B should be detected: {:?}",
        dets
    );
    assert!(result.contains("[FR_PHONE_NUMBER_"));
}

#[test]
fn test_phone_0033_format() {
    let mut a = Anonymizer::new(0.0);
    let input = "Mobile : 0033 7 00 00 00 01";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "FR_PHONE_NUMBER"),
        "0033 phone format should be detected.\nDetections: {:?}",
        dets
    );
    assert!(
        !result.contains("0033 7 00 00 00 01"),
        "Phone should be replaced"
    );
}

// -- PHONE_NUMBER (international) battle tests --

#[test]
fn test_intl_phone_japan() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("tel: +81 3 1234 5678");
    assert!(
        dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
        "Japan phone not detected: {dets:?}"
    );
    assert!(result.contains("[PHONE_NUMBER_"));
}

#[test]
fn test_intl_phone_brazil() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("contact: +55 11 98765 4321");
    assert!(
        dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
        "Brazil phone not detected: {dets:?}"
    );
    assert!(result.contains("[PHONE_NUMBER_"));
}

#[test]
fn test_intl_phone_australia() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("phone +61 2 9876 5432");
    assert!(
        dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
        "Australia phone not detected: {dets:?}"
    );
    assert!(result.contains("[PHONE_NUMBER_"));
}

#[test]
fn test_intl_phone_india() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("mobile +91 98765 43210");
    assert!(
        dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
        "India phone not detected: {dets:?}"
    );
    assert!(result.contains("[PHONE_NUMBER_"));
}

#[test]
fn test_intl_phone_e164_strict() {
    let mut a = Anonymizer::new(0.0);
    // E.164 format with no spaces
    let (result, dets) = a.anonymize_text("sms +447911123456");
    assert!(
        dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
        "E.164 phone not detected: {dets:?}"
    );
    assert!(result.contains("[PHONE_NUMBER_"));
}

#[test]
fn test_intl_phone_dot_separated() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("fax: +49.30.123456");
    assert!(
        dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
        "dot-separated phone not detected: {dets:?}"
    );
    assert!(result.contains("[PHONE_NUMBER_"));
}

#[test]
fn test_intl_phone_multiple_context_keywords() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("whatsapp +971 50 123 4567");
    assert!(
        dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
        "'whatsapp' should trigger phone detection: {dets:?}"
    );
    assert!(result.contains("[PHONE_NUMBER_"));
}

#[test]
fn test_intl_phone_not_confused_with_math() {
    let mut a = Anonymizer::new(0.0);
    // "+1 212 555 1234" without any context should NOT match
    let (_, dets) = a.anonymize_text("result is +1 212 555 1234 end");
    assert!(
        !dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
        "phone without context in math-like text should be rejected: {dets:?}"
    );
}

#[test]
fn test_intl_phone_short_number_rejected() {
    let mut a = Anonymizer::new(0.0);
    // Only 5 digits after country code - too short
    let (_, dets) = a.anonymize_text("tel +1 12345");
    assert!(
        !dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
        "too-short intl phone should not match: {dets:?}"
    );
}

#[test]
fn test_intl_phone_consistency_same_number_same_token() {
    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_text("call +44 20 7946 0958, again call +44 20 7946 0958");
    let tokens: Vec<_> = a
        .mapping
        .mappings
        .keys()
        .filter(|k| k.starts_with("[PHONE_NUMBER_"))
        .collect();
    assert_eq!(tokens.len(), 1, "same phone number should map to one token");
    let token = tokens[0].as_str();
    assert_eq!(
        result.matches(token).count(),
        2,
        "same token should appear twice"
    );
}

// -- PHONE_EXTENSION battle tests --

#[test]
fn test_phone_extension_poste() {
    let mut a = Anonymizer::new(0.0);
    let input = "Contact RH : j.dupont@example-air.com, poste 2241.";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter()
            .any(|d| d.entity_type == "PHONE_EXTENSION" && d.original.contains("2241")),
        "poste 2241 should be detected as PHONE_EXTENSION.\nDetections: {:?}",
        dets
    );
    assert!(
        !result.contains("2241"),
        "Phone extension should be anonymized"
    );
}

#[test]
fn test_phone_extension_ext() {
    let mut a = Anonymizer::new(0.0);
    let input = "Call ext. 4510 for support";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter()
            .any(|d| d.entity_type == "PHONE_EXTENSION" && d.original.contains("4510")),
        "ext. 4510 should be detected as PHONE_EXTENSION.\nDetections: {:?}",
        dets
    );
    assert!(
        !result.contains("4510"),
        "Phone extension should be anonymized"
    );
}

#[test]
fn test_bare_number_not_phone_extension() {
    let mut a = Anonymizer::new(0.0);
    let input = "There are 2241 items in the database";
    let (_, dets) = a.anonymize_text(input);
    assert!(
        !dets.iter().any(|d| d.entity_type == "PHONE_EXTENSION"),
        "Bare number should not be detected as PHONE_EXTENSION.\nDetections: {:?}",
        dets
    );
}

#[test]
fn test_phone_extension_extension_keyword() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("reach us at extension 12345");
    assert!(
        dets.iter().any(|d| d.entity_type == "PHONE_EXTENSION"),
        "extension keyword not detected: {dets:?}"
    );
    assert!(result.contains("[PHONE_EXTENSION_"));
}

#[test]
fn test_phone_extension_case_insensitive() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("call EXT 9876");
    assert!(
        dets.iter().any(|d| d.entity_type == "PHONE_EXTENSION"),
        "case-insensitive ext not detected: {dets:?}"
    );
    assert!(result.contains("[PHONE_EXTENSION_"));
}

#[test]
fn test_phone_extension_two_digit_rejected() {
    let mut a = Anonymizer::new(0.0);
    // Only 2 digits - below min of 3
    let (_, dets) = a.anonymize_text("ext 42");
    assert!(
        !dets.iter().any(|d| d.entity_type == "PHONE_EXTENSION"),
        "2-digit extension should not match: {dets:?}"
    );
}

#[test]
fn test_phone_extension_six_digit_rejected() {
    let mut a = Anonymizer::new(0.0);
    // 6 digits - above max of 5
    let (_, dets) = a.anonymize_text("poste 123456");
    assert!(
        !dets.iter().any(|d| d.entity_type == "PHONE_EXTENSION"),
        "6-digit extension should not match: {dets:?}"
    );
}

// ── Ticket #40: phone coverage gaps ──

#[test]
fn test_intl_phone_plus1_hyphenated() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("phone: +1-202-555-0173");
    assert!(
        dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
        "+1-xxx-xxx-xxxx should be detected as PHONE_NUMBER: {dets:?}"
    );
    assert!(result.contains("[PHONE_NUMBER_"));
}

#[test]
fn test_intl_phone_plus1_hyphenated_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("code +1-202-555-0173 end");
    assert!(
        !dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
        "+1 hyphenated without context should be rejected: {dets:?}"
    );
}

#[test]
fn test_us_phone_parenthesized() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("phone: (202) 555-0173");
    assert!(
        dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
        "(xxx) xxx-xxxx should be detected as PHONE_NUMBER: {dets:?}"
    );
    assert!(result.contains("[PHONE_NUMBER_"));
}

#[test]
fn test_us_phone_parenthesized_dot_separated() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("call (415) 555.1234");
    assert!(
        dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
        "(xxx) xxx.xxxx should be detected as PHONE_NUMBER: {dets:?}"
    );
    assert!(result.contains("[PHONE_NUMBER_"));
}

#[test]
fn test_us_phone_parenthesized_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("value (202) 555-0173 here");
    assert!(
        !dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
        "parenthesized phone without context should be rejected: {dets:?}"
    );
}

#[test]
fn test_uk_local_phone() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("call 020 7946 0958");
    assert!(
        dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
        "UK local 0xx xxxx xxxx should be detected as PHONE_NUMBER: {dets:?}"
    );
    assert!(result.contains("[PHONE_NUMBER_"));
}

#[test]
fn test_uk_local_phone_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("ref 020 7946 0958 end");
    assert!(
        !dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
        "UK local phone without context should be rejected: {dets:?}"
    );
}

#[test]
fn test_uk_phone_not_confused_with_fr_phone() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("call 020 7946 0958");
    assert!(
        !dets.iter().any(|d| d.entity_type == "FR_PHONE_NUMBER"),
        "UK local phone should not match FR_PHONE_NUMBER: {dets:?}"
    );
}
