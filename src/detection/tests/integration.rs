use super::super::*;
use serde_json::Value;

// -- Consistency & mapping tests --

#[test]
fn test_consistency() {
    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_text("john@example.com and john@example.com again");
    let token = a
        .mapping
        .mappings
        .keys()
        .find(|k| k.starts_with("[EMAIL_ADDRESS_"))
        .unwrap()
        .clone();
    assert_eq!(result.matches(&*token).count(), 2);
}

#[test]
fn test_mapping_roundtrip() {
    let mut a = Anonymizer::new(0.0);
    let original = "contact john@example.com at 192.168.1.1";
    let (anonymized, _) = a.anonymize_text(original);
    let restored = a.mapping.restore(&anonymized);
    assert_eq!(restored, original);
}

// -- Credit card tests --

#[test]
fn test_credit_card_valid_with_context() {
    let mut a = Anonymizer::new(0.0);
    // 4111111111111111 is a valid Visa test number (passes Luhn + valid prefix)
    let (result, dets) = a.anonymize_text("carte bancaire 4111 1111 1111 1111");
    assert!(dets.iter().any(|d| d.entity_type == "CREDIT_CARD"));
    assert!(result.contains("[CREDIT_CARD_"));
}

#[test]
fn test_credit_card_rejected_without_context() {
    let mut a = Anonymizer::new(0.0);
    // Valid card number but no context keyword — context_required gate blocks it
    let (_, dets) = a.anonymize_text("number 4111 1111 1111 1111 here");
    assert!(!dets.iter().any(|d| d.entity_type == "CREDIT_CARD"));
}

#[test]
fn test_credit_card_rejected_invalid_prefix() {
    let mut a = Anonymizer::new(0.0);
    // 16-digit number starting with 9 — no known issuer, even with context + Luhn
    // 9000000000000008 passes Luhn but has no valid card prefix
    let (_, dets) = a.anonymize_text("payment card 9000 0000 0000 0008");
    assert!(
        !dets.iter().any(|d| d.entity_type == "CREDIT_CARD"),
        "Should reject 16-digit number with unknown issuer prefix"
    );
}

#[test]
fn test_credit_card_rejected_fails_luhn() {
    let mut a = Anonymizer::new(0.0);
    // Visa prefix but fails Luhn (last digit wrong)
    let (_, dets) = a.anonymize_text("carte credit 4111 1111 1111 1112");
    assert!(
        !dets.iter().any(|d| d.entity_type == "CREDIT_CARD"),
        "Should reject card number that fails Luhn check"
    );
}

// -- Unicode fullwidth digit test (IP) --

#[test]
fn test_unicode_fullwidth_digits_detected() {
    let mut a = Anonymizer::new(0.0);
    // Fullwidth digits U+FF10..U+FF19 for IP address
    let input = "server at \u{FF11}\u{FF19}\u{FF12}.\u{FF11}\u{FF16}\u{FF18}.\u{FF11}.\u{FF11}\u{FF10}\u{FF10}";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "IP_ADDRESS"),
        "Fullwidth digits should be normalized and detected as IP: {:?}",
        dets
    );
    assert!(result.contains("[IP_ADDRESS_"));
}

// -- Unicode/percent decode unit tests --

#[test]
fn test_decode_unicode_escapes_basic() {
    assert_eq!(decode_unicode_escapes(r"hello\u0040world"), "hello@world");
    assert_eq!(decode_unicode_escapes(r"\u002B33 6 12"), "+33 6 12");
    assert_eq!(decode_unicode_escapes("no escapes"), "no escapes");
}

#[test]
fn test_decode_unicode_escapes_malformed() {
    // Too short
    assert_eq!(decode_unicode_escapes(r"\u00"), r"\u00");
    // Non-hex
    assert_eq!(decode_unicode_escapes(r"\u00GG"), r"\u00GG");
    // Just backslash not followed by u
    assert_eq!(decode_unicode_escapes(r"\n"), r"\n");
}

#[test]
fn test_decode_percent_encoding_basic() {
    assert_eq!(
        decode_percent_encoding("j.smith%40provider.net"),
        "j.smith@provider.net"
    );
    assert_eq!(decode_percent_encoding("%2B33"), "+33");
    assert_eq!(decode_percent_encoding("hello%20world"), "hello world");
    assert_eq!(decode_percent_encoding("no encoding"), "no encoding");
}

#[test]
fn test_decode_percent_encoding_malformed() {
    // Trailing %
    assert_eq!(decode_percent_encoding("end%"), "end%");
    // Only one hex digit
    assert_eq!(decode_percent_encoding("end%4"), "end%4");
    // Non-hex
    assert_eq!(decode_percent_encoding("%GG"), "%GG");
}

// -- Cross-entity battle tests --

#[test]
fn test_log_line_mixed_phase1_entities() {
    let mut a = Anonymizer::new(0.0);
    let input = "2024-06-15T10:30:00Z device mac 0A:1B:2C:3D:4E:5F connected from 2001:db8::1";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "DATE_TIME"),
        "ISO date not detected in mixed line: {dets:?}"
    );
    assert!(
        dets.iter().any(|d| d.entity_type == "MAC_ADDRESS"),
        "MAC not detected in mixed line: {dets:?}"
    );
    assert!(
        dets.iter().any(|d| d.entity_type == "IP_ADDRESS"),
        "IPv6 not detected in mixed line: {dets:?}"
    );
    assert!(!result.contains("0A:1B:2C:3D:4E:5F"));
    assert!(!result.contains("2001:db8::1"));
}

#[test]
fn test_network_audit_log() {
    let mut a = Anonymizer::new(0.0);
    let input = "2024-03-15T08:45:00+01:00 DHCP lease: mac 00:1A:2B:3C:4D:5E \
        assigned 192.168.1.42, gateway 192.168.1.1";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "DATE_TIME"),
        "timestamp missing: {dets:?}"
    );
    assert!(
        dets.iter().any(|d| d.entity_type == "MAC_ADDRESS"),
        "MAC missing: {dets:?}"
    );
    let ip_count = dets
        .iter()
        .filter(|d| d.entity_type == "IP_ADDRESS")
        .count();
    assert!(ip_count >= 2, "should detect at least 2 IPs: {dets:?}");
    assert!(!result.contains("00:1A:2B:3C:4D:5E"));
    assert!(!result.contains("192.168.1.42"));
}

#[test]
fn test_banking_log_iban_and_phone() {
    let mut a = Anonymizer::new(0.0);
    let input = "virement de 500EUR sur le compte iban DE89370400440532013000, \
        contact tel +49 30 12345678";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "IBAN_CODE"),
        "IBAN not detected: {dets:?}"
    );
    assert!(
        dets.iter().any(|d| d.entity_type == "PHONE_NUMBER"),
        "phone not detected: {dets:?}"
    );
    assert!(!result.contains("DE89370400440532013000"));
    assert!(!result.contains("+49"));
}

#[test]
fn test_all_phase1_entities_coexist() {
    // Verify no entity type accidentally shadows another
    let mut a = Anonymizer::new(0.0);
    let input = "2024-01-15T10:00:00Z server 192.168.1.1 ipv6 2001:db8::1 \
        mac 0A:1B:2C:3D:4E:5F contact tel +44 20 7946 0958 \
        iban DE89370400440532013000 SSN: 123-45-6789 poste 4510 \
        medical license ME12345678";
    let (result, dets) = a.anonymize_text(input);
    let types: Vec<&str> = dets.iter().map(|d| &*d.entity_type).collect();
    assert!(types.contains(&"DATE_TIME"), "DATE_TIME missing: {types:?}");
    assert!(
        types.contains(&"IP_ADDRESS"),
        "IP_ADDRESS missing: {types:?}"
    );
    assert!(
        types.contains(&"MAC_ADDRESS"),
        "MAC_ADDRESS missing: {types:?}"
    );
    assert!(
        types.contains(&"PHONE_NUMBER"),
        "PHONE_NUMBER missing: {types:?}"
    );
    assert!(types.contains(&"IBAN_CODE"), "IBAN_CODE missing: {types:?}");
    assert!(types.contains(&"US_SSN"), "US_SSN missing: {types:?}");
    assert!(
        types.contains(&"PHONE_EXTENSION"),
        "PHONE_EXTENSION missing: {types:?}"
    );
    assert!(
        types.contains(&"MEDICAL_LICENSE"),
        "MEDICAL_LICENSE missing: {types:?}"
    );
    // Verify all PII is actually replaced in output
    assert!(!result.contains("192.168.1.1"));
    assert!(!result.contains("0A:1B:2C:3D:4E:5F"));
    assert!(!result.contains("123-45-6789"));
    assert!(!result.contains("ME12345678"));
}

// -- Custom operator (--replace-with) tests --

#[test]
fn test_operator_custom_entity_type_placeholder() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Custom;
    a.replace_with = Some("<{entity_type}>".to_string());
    let (result, dets) = a.anonymize_text("contact john@example.com now");
    assert_eq!(result, "contact <EMAIL_ADDRESS> now");
    assert!(!result.contains("john@example.com"));
    assert_eq!(dets.len(), 1);
}

#[test]
fn test_operator_custom_static_string() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Custom;
    a.replace_with = Some("REDACTED".to_string());
    let (result, _) = a.anonymize_text("contact john@example.com now");
    assert_eq!(result, "contact REDACTED now");
}

#[test]
fn test_operator_custom_multiple_entities() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Custom;
    a.replace_with = Some("<{entity_type}>".to_string());
    let (result, dets) = a.anonymize_text("email: john@example.com, ip: 192.168.1.1");
    assert!(!result.contains("john@example.com"));
    assert!(!result.contains("192.168.1.1"));
    assert!(result.contains("<EMAIL_ADDRESS>"));
    assert!(result.contains("<IP_ADDRESS>"));
    assert_eq!(dets.len(), 2);
}

#[test]
fn test_operator_custom_no_mapping_entries() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Custom;
    a.replace_with = Some("XXX".to_string());
    let _ = a.anonymize_text("john@example.com");
    assert!(a.mapping.mappings.is_empty());
}

#[test]
fn test_operator_custom_json() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Custom;
    a.replace_with = Some("<{entity_type}>".to_string());
    let json: Value = serde_json::from_str(r#"{"email": "john@example.com"}"#).unwrap();
    let (result, dets) = a.anonymize_json_value(&json);
    assert_eq!(result["email"], "<EMAIL_ADDRESS>");
    assert_eq!(dets.len(), 1);
}

#[test]
fn test_operator_custom_empty_string() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Custom;
    a.replace_with = Some(String::new());
    let (result, _) = a.anonymize_text("contact john@example.com now");
    assert_eq!(result, "contact  now");
}

#[test]
fn test_operator_custom_literal_braces() {
    let mut a = Anonymizer::new(0.0);
    a.operator = Operator::Custom;
    a.replace_with = Some("[{entity_type}]".to_string());
    let (result, _) = a.anonymize_text("contact john@example.com now");
    assert_eq!(result, "contact [EMAIL_ADDRESS] now");
}

// -- context_boost + min_score_with_context tests --

#[test]
fn test_custom_context_boost_changes_score() {
    // IT_FISCAL_CODE: base score 0.85, context_required: false
    // With boost 0.05 -> min(0.85 + 0.05, 1.0) = 0.90
    // With boost 0.10 -> min(0.85 + 0.10, 1.0) = 0.95
    let mut a_small = Anonymizer::new(0.0);
    a_small.context_boost = 0.05;
    let mut a_larger = Anonymizer::new(0.0);
    a_larger.context_boost = 0.10;

    let input = "codice fiscale: AAABBB00A00A000J";
    let (_, dets_small) = a_small.anonymize_text(input);
    let (_, dets_larger) = a_larger.anonymize_text(input);

    let score_small = dets_small
        .iter()
        .find(|d| d.entity_type == "IT_FISCAL_CODE")
        .unwrap()
        .score;
    let score_larger = dets_larger
        .iter()
        .find(|d| d.entity_type == "IT_FISCAL_CODE")
        .unwrap()
        .score;

    assert!(
        (score_small - 0.90).abs() < f64::EPSILON,
        "Boost 0.05 on base 0.85 should yield 0.90, got {score_small}"
    );
    assert!(
        (score_larger - 0.95).abs() < f64::EPSILON,
        "Boost 0.10 on base 0.85 should yield 0.95, got {score_larger}"
    );
}

#[test]
fn test_context_boost_zero_disables_boost() {
    let mut a = Anonymizer::new(0.0);
    a.context_boost = 0.0;

    let input_ctx = "codice fiscale: AAABBB00A00A000J";
    let input_no_ctx = "data: AAABBB00A00A000J";
    let (_, dets_ctx) = a.anonymize_text(input_ctx);
    let (_, dets_no_ctx) = a.anonymize_text(input_no_ctx);

    let score_ctx = dets_ctx
        .iter()
        .find(|d| d.entity_type == "IT_FISCAL_CODE")
        .unwrap()
        .score;
    let score_no_ctx = dets_no_ctx
        .iter()
        .find(|d| d.entity_type == "IT_FISCAL_CODE")
        .unwrap()
        .score;

    assert!(
        (score_ctx - score_no_ctx).abs() < f64::EPSILON,
        "With context_boost=0.0, scores should be equal: {score_ctx} vs {score_no_ctx}"
    );
}

#[test]
fn test_min_score_with_context_filters_low_matches() {
    // IT_FISCAL_CODE: base score 0.85, with boost 0.05 -> 0.90
    // Set min_score_with_context = 0.95 -> should be filtered out
    let mut a = Anonymizer::new(0.0);
    a.context_boost = 0.05;
    a.min_score_with_context = 0.95;

    let input = "codice fiscale: AAABBB00A00A000J";
    let (_, dets) = a.anonymize_text(input);

    let found = dets.iter().any(|d| d.entity_type == "IT_FISCAL_CODE");
    assert!(
        !found,
        "IT_FISCAL_CODE with boosted score 0.90 should be filtered by min_score_with_context=0.95"
    );
}

#[test]
fn test_min_score_with_context_allows_high_matches() {
    // IT_FISCAL_CODE: base score 0.85, with boost 0.10 -> 0.95
    // Set min_score_with_context = 0.95 -> should pass (equal)
    let mut a = Anonymizer::new(0.0);
    a.context_boost = 0.10;
    a.min_score_with_context = 0.95;

    let input = "codice fiscale: AAABBB00A00A000J";
    let (_, dets) = a.anonymize_text(input);

    let found = dets.iter().any(|d| d.entity_type == "IT_FISCAL_CODE");
    assert!(
        found,
        "IT_FISCAL_CODE with boosted score 0.95 should pass min_score_with_context=0.95"
    );
}

#[test]
fn test_min_score_with_context_does_not_affect_non_boosted() {
    // EMAIL_ADDRESS has no context keywords (score = 1.0, no boost involved)
    // min_score_with_context should not affect it
    let mut a = Anonymizer::new(0.0);
    a.min_score_with_context = 0.99;

    let input = "contact john@example.com please";
    let (_, dets) = a.anonymize_text(input);

    let found = dets.iter().any(|d| d.entity_type == "EMAIL_ADDRESS");
    assert!(
        found,
        "EMAIL_ADDRESS should not be affected by min_score_with_context"
    );
}

#[test]
fn test_default_context_boost_unchanged() {
    // Verify default Anonymizer produces the same behavior as before
    let a = Anonymizer::new(0.5);
    assert!(
        (a.context_boost - 0.15).abs() < f64::EPSILON,
        "Default context_boost should be 0.15"
    );
    assert!(
        a.min_score_with_context.abs() < f64::EPSILON,
        "Default min_score_with_context should be 0.0 (disabled)"
    );
}

#[test]
fn test_context_boost_json_path() {
    // Verify context_boost works through anonymize_json_value (delegates to anonymize_text)
    let mut a = Anonymizer::new(0.0);
    a.context_boost = 0.05;

    let json: serde_json::Value =
        serde_json::from_str(r#"{"cf": "codice fiscale: AAABBB00A00A000J"}"#).unwrap();
    let (_, dets) = a.anonymize_json_value(&json);

    let score = dets
        .iter()
        .find(|d| d.entity_type == "IT_FISCAL_CODE")
        .unwrap()
        .score;
    assert!(
        (score - 0.90).abs() < f64::EPSILON,
        "JSON path should use custom context_boost: expected 0.90, got {score}"
    );
}

#[test]
fn test_context_boost_does_not_affect_gated_patterns() {
    // context_required: true patterns use gating, not boosting.
    // Changing context_boost should not affect their scores.
    let mut a_default = Anonymizer::new(0.0);
    let mut a_custom = Anonymizer::new(0.0);
    a_custom.context_boost = 0.50;

    // CREDIT_CARD is context_required: true — score is fixed at base, not boosted
    let input = "credit card: 4532015112830366";
    let (_, dets_default) = a_default.anonymize_text(input);
    let (_, dets_custom) = a_custom.anonymize_text(input);

    let score_default = dets_default
        .iter()
        .find(|d| d.entity_type == "CREDIT_CARD")
        .unwrap()
        .score;
    let score_custom = dets_custom
        .iter()
        .find(|d| d.entity_type == "CREDIT_CARD")
        .unwrap()
        .score;

    assert!(
        (score_default - score_custom).abs() < f64::EPSILON,
        "Gated patterns should not be affected by context_boost: {score_default} vs {score_custom}"
    );
}

#[test]
fn test_context_boost_capped_at_one() {
    // Even with a large boost, score should never exceed 1.0
    let mut a = Anonymizer::new(0.0);
    a.context_boost = 0.99;

    let input = "codice fiscale: AAABBB00A00A000J";
    let (_, dets) = a.anonymize_text(input);

    let score = dets
        .iter()
        .find(|d| d.entity_type == "IT_FISCAL_CODE")
        .unwrap()
        .score;
    assert!(
        (score - 1.0).abs() < f64::EPSILON,
        "Score should be capped at 1.0, got {score}"
    );
}
