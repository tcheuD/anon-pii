use super::super::*;
use serde_json::Value;

// -- US_SSN tests --

#[test]
fn test_us_ssn_with_context() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("SSN: 123-45-6789");
    assert!(
        dets.iter().any(|d| d.entity_type == "US_SSN"),
        "US SSN not detected: {dets:?}"
    );
    assert!(result.contains("[US_SSN_"));
}

#[test]
fn test_us_ssn_spaced() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("social security 123 45 6789");
    assert!(
        dets.iter().any(|d| d.entity_type == "US_SSN"),
        "spaced US SSN not detected: {dets:?}"
    );
    assert!(result.contains("[US_SSN_"));
}

#[test]
fn test_us_ssn_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("number 123-45-6789 value");
    assert!(
        !dets.iter().any(|d| d.entity_type == "US_SSN"),
        "US SSN without context should be rejected: {dets:?}"
    );
}

#[test]
fn test_us_ssn_invalid_prefix_rejected() {
    let mut a = Anonymizer::new(0.0);
    // 000, 666, and 9xx prefixes are invalid
    let (_, dets) = a.anonymize_text("SSN: 000-45-6789");
    assert!(
        !dets.iter().any(|d| d.entity_type == "US_SSN"),
        "US SSN with 000 prefix should be rejected: {dets:?}"
    );
}

#[test]
fn test_us_ssn_all_zeros_group_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("SSN: 123-00-6789");
    assert!(
        !dets.iter().any(|d| d.entity_type == "US_SSN"),
        "US SSN with 00 middle group should be rejected: {dets:?}"
    );
}

// -- US_SSN battle tests --

#[test]
fn test_us_ssn_valid_range() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("SSN: 001-01-0001");
    assert!(
        dets.iter().any(|d| d.entity_type == "US_SSN"),
        "min valid SSN not detected: {dets:?}"
    );
    assert!(result.contains("[US_SSN_"));
}

#[test]
fn test_us_ssn_area_666_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("SSN: 666-12-3456");
    assert!(
        !dets.iter().any(|d| d.entity_type == "US_SSN"),
        "SSN area 666 should be rejected: {dets:?}"
    );
}

#[test]
fn test_us_ssn_area_900_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("social security 900-12-3456");
    assert!(
        !dets.iter().any(|d| d.entity_type == "US_SSN"),
        "SSN area 900+ should be rejected: {dets:?}"
    );
}

#[test]
fn test_us_ssn_zero_serial_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("SSN: 123-45-0000");
    assert!(
        !dets.iter().any(|d| d.entity_type == "US_SSN"),
        "SSN with 0000 serial should be rejected: {dets:?}"
    );
}

#[test]
fn test_us_ssn_various_contexts() {
    let inputs = [
        "social security number: 123-45-6789",
        "SSN 123-45-6789",
        "tax id 123-45-6789",
    ];
    for input in &inputs {
        let mut a = Anonymizer::new(0.0);
        let (_, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "US_SSN"),
            "US SSN not detected in '{input}': {dets:?}"
        );
    }
}

#[test]
fn test_us_ssn_not_confused_with_date_dash() {
    let mut a = Anonymizer::new(0.0);
    // 2024-01-15 - looks like dashes but is a date
    let (_, dets) = a.anonymize_text("SSN: 2024-01-15");
    // This should be DATE_TIME, not US_SSN (date_iso8601 pattern)
    // 2024 as area is >=900 so SSN validator would reject anyway
    assert!(
        !dets.iter().any(|d| d.entity_type == "US_SSN"),
        "ISO date should not match as US_SSN: {dets:?}"
    );
}

#[test]
fn test_us_ssn_roundtrip() {
    let mut a = Anonymizer::new(0.0);
    let input = "SSN: 123-45-6789";
    let (anon, _) = a.anonymize_text(input);
    let restored = a.mapping.restore(&anon);
    assert_eq!(restored, input, "US SSN roundtrip failed");
}

#[test]
fn test_us_ssn_mixed_delimiters_rejected() {
    let mut a = Anonymizer::new(0.0);
    // dash + space mixed - should not match either pattern
    let (_, dets) = a.anonymize_text("SSN: 123-45 6789");
    assert!(
        !dets.iter().any(|d| d.entity_type == "US_SSN"),
        "mixed delimiters should be rejected: {dets:?}"
    );
    let (_, dets) = a.anonymize_text("SSN: 123 45-6789");
    assert!(
        !dets.iter().any(|d| d.entity_type == "US_SSN"),
        "mixed delimiters (space then dash) should be rejected: {dets:?}"
    );
}

#[test]
fn test_us_ssn_max_valid_area() {
    let mut a = Anonymizer::new(0.0);
    // 899 is the highest valid area (900+ rejected)
    let (result, dets) = a.anonymize_text("SSN: 899-99-9999");
    assert!(
        dets.iter().any(|d| d.entity_type == "US_SSN"),
        "area 899 should be valid: {dets:?}"
    );
    assert!(result.contains("[US_SSN_"));
}

#[test]
fn test_us_ssn_in_json() {
    // JSON walker anonymizes values independently - context keyword must be in the value itself
    let json = serde_json::json!({
        "note": "SSN: 123-45-6789"
    });
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_json_value(&json);
    assert!(
        dets.iter().any(|d| d.entity_type == "US_SSN"),
        "US SSN not detected in JSON: {dets:?}"
    );
    assert!(
        result["note"].as_str().unwrap().contains("[US_SSN_"),
        "JSON value not anonymized: {}",
        result["note"]
    );
}

#[test]
fn test_us_ssn_in_json_bare_value_rejected() {
    // JSON key "ssn" is processed separately - it doesn't provide context to the value
    let json = serde_json::json!({
        "ssn": "123-45-6789"
    });
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_json_value(&json);
    assert!(
        !dets.iter().any(|d| d.entity_type == "US_SSN"),
        "bare SSN in JSON value without context should be rejected: {dets:?}"
    );
}

#[test]
fn test_us_ssn_multiple_distinct_tokens() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("SSN: 123-45-6789, second SSN: 234-56-7890");
    let ssn_dets: Vec<_> = dets.iter().filter(|d| d.entity_type == "US_SSN").collect();
    assert_eq!(ssn_dets.len(), 2, "expected 2 SSN detections: {dets:?}");
    // Tokens use random hex, so just verify two distinct tokens exist
    let tokens: Vec<&str> = result
        .match_indices("[US_SSN_")
        .map(|(i, _)| {
            let end = result[i..].find(']').unwrap() + i + 1;
            &result[i..end]
        })
        .collect();
    assert_eq!(tokens.len(), 2, "expected 2 tokens in: {result}");
    assert_ne!(tokens[0], tokens[1], "tokens should be distinct: {result}");
}

#[test]
fn test_us_ssn_duplicate_same_token() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("SSN: 123-45-6789, repeat SSN: 123-45-6789");
    let ssn_dets: Vec<_> = dets.iter().filter(|d| d.entity_type == "US_SSN").collect();
    assert_eq!(ssn_dets.len(), 2, "expected 2 SSN detections: {dets:?}");
    let tokens: Vec<&str> = result
        .match_indices("[US_SSN_")
        .map(|(i, _)| {
            let end = result[i..].find(']').unwrap() + i + 1;
            &result[i..end]
        })
        .collect();
    assert_eq!(tokens.len(), 2, "expected 2 tokens in: {result}");
    assert_eq!(
        tokens[0], tokens[1],
        "same SSN should get same token: {result}"
    );
}

#[test]
fn test_us_ssn_at_string_start() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("SSN 123-45-6789 is on file");
    assert!(
        dets.iter().any(|d| d.entity_type == "US_SSN"),
        "SSN at start not detected: {dets:?}"
    );
    assert!(result.contains("[US_SSN_"));
}

#[test]
fn test_us_ssn_at_string_end() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("tax 123-45-6789");
    assert!(
        dets.iter().any(|d| d.entity_type == "US_SSN"),
        "SSN at end not detected: {dets:?}"
    );
    assert!(result.contains("[US_SSN_"));
}

#[test]
fn test_us_ssn_compact_no_delimiters_rejected() {
    let mut a = Anonymizer::new(0.0);
    // 9 digits without delimiters - no pattern matches this, too many false positives
    let (_, dets) = a.anonymize_text("SSN: 123456789");
    assert!(
        !dets.iter().any(|d| d.entity_type == "US_SSN"),
        "compact SSN without delimiters should not match: {dets:?}"
    );
}

#[test]
fn test_us_ssn_context_beyond_window_rejected() {
    let mut a = Anonymizer::new(0.0);
    // CONTEXT_WINDOW is 80 chars - place keyword >80 chars before the SSN
    let padding = "x".repeat(81);
    let input = format!("SSN {padding} 123-45-6789");
    let (_, dets) = a.anonymize_text(&input);
    assert!(
        !dets.iter().any(|d| d.entity_type == "US_SSN"),
        "SSN with context beyond 80-char window should be rejected: {dets:?}"
    );
}

#[test]
fn test_us_ssn_context_after() {
    let mut a = Anonymizer::new(0.0);
    // Context keyword AFTER the SSN - window looks both directions
    let (result, dets) = a.anonymize_text("number 123-45-6789 is the SSN");
    assert!(
        dets.iter().any(|d| d.entity_type == "US_SSN"),
        "SSN with context after should be detected: {dets:?}"
    );
    assert!(result.contains("[US_SSN_"));
}

#[test]
fn test_us_ssn_context_case_insensitive() {
    let mut a = Anonymizer::new(0.0);
    let inputs = [
        "ssn: 123-45-6789",            // all lowercase
        "Ssn: 123-45-6789",            // title case
        "Social Security 123-45-6789", // mixed case
    ];
    for input in &inputs {
        let mut a2 = Anonymizer::new(0.0);
        let (_, dets) = a2.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "US_SSN"),
            "case-insensitive context failed for '{input}': {dets:?}"
        );
    }
    // Also verify uppercase-only (already tested elsewhere, but confirms parity)
    let (_, dets) = a.anonymize_text("SSN: 123-45-6789");
    assert!(
        dets.iter().any(|d| d.entity_type == "US_SSN"),
        "uppercase SSN context should work"
    );
}

#[test]
fn test_us_ssn_context_across_newline() {
    let mut a = Anonymizer::new(0.0);
    // Context keyword on previous line, SSN on next - within 80-char window
    let (result, dets) = a.anonymize_text("SSN:\n123-45-6789");
    assert!(
        dets.iter().any(|d| d.entity_type == "US_SSN"),
        "SSN with context across newline should be detected: {dets:?}"
    );
    assert!(result.contains("[US_SSN_"));
}

// -- MEDICAL_LICENSE tests --

#[test]
fn test_medical_license_with_context() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("medical license ME12345678");
    assert!(
        dets.iter().any(|d| d.entity_type == "MEDICAL_LICENSE"),
        "medical license not detected: {dets:?}"
    );
    assert!(result.contains("[MEDICAL_LICENSE_"));
}

#[test]
fn test_medical_license_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("code ME12345678 here");
    assert!(
        !dets.iter().any(|d| d.entity_type == "MEDICAL_LICENSE"),
        "medical license without context should be rejected: {dets:?}"
    );
}

// -- MEDICAL_LICENSE battle tests --

#[test]
fn test_medical_license_dea_number() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("DEA number: AB1234567");
    assert!(
        dets.iter().any(|d| d.entity_type == "MEDICAL_LICENSE"),
        "DEA number not detected: {dets:?}"
    );
    assert!(result.contains("[MEDICAL_LICENSE_"));
}

#[test]
fn test_medical_license_npi() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("NPI provider D1234567890");
    assert!(
        dets.iter().any(|d| d.entity_type == "MEDICAL_LICENSE"),
        "NPI number not detected: {dets:?}"
    );
    assert!(result.contains("[MEDICAL_LICENSE_"));
}

#[test]
fn test_medical_license_not_random_alphanum() {
    let mut a = Anonymizer::new(0.0);
    // Without medical context, XX1234567 should not match
    let (_, dets) = a.anonymize_text("reference XX1234567");
    assert!(
        !dets.iter().any(|d| d.entity_type == "MEDICAL_LICENSE"),
        "random alphanumeric should not match without context: {dets:?}"
    );
}

// -- US_BANK_NUMBER tests --

#[test]
fn test_us_bank_number_detected_with_context() {
    let mut anon = Anonymizer::new(0.0);
    let input = "Account number: 12345678901234";
    let (result, dets) = anon.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "US_BANK_NUMBER"),
        "US_BANK_NUMBER not detected in: {input}"
    );
    assert!(result.contains("[US_BANK_NUMBER_"));
}

#[test]
fn test_us_bank_number_not_detected_without_context() {
    let mut anon = Anonymizer::new(0.0);
    let input = "Order ref 12345678901234 confirmed";
    let (_, dets) = anon.anonymize_text(input);
    assert!(
        !dets.iter().any(|d| d.entity_type == "US_BANK_NUMBER"),
        "US_BANK_NUMBER should not match without context"
    );
}

// -- US_DRIVER_LICENSE tests --

#[test]
fn test_us_driver_license_alpha_short() {
    let mut anon = Anonymizer::new(0.0);
    // Use "DMV" context - specific to driver license, no overlap with MEDICAL_LICENSE
    let input = "DMV D1234567";
    let (result, dets) = anon.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "US_DRIVER_LICENSE"),
        "US_DRIVER_LICENSE not detected in: {input} - dets: {dets:?}"
    );
    assert!(result.contains("[US_DRIVER_LICENSE_"));
}

#[test]
fn test_us_driver_license_alpha_long() {
    let mut anon = Anonymizer::new(0.0);
    // 1 letter + 12 digits (IL/FL/MD/MI/MN format)
    let input = "DMV D123456789012";
    let (result, dets) = anon.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "US_DRIVER_LICENSE"),
        "US_DRIVER_LICENSE (long) not detected in: {input} - dets: {dets:?}"
    );
    assert!(result.contains("[US_DRIVER_LICENSE_"));
}

#[test]
fn test_us_driver_license_alpha_pair() {
    let mut anon = Anonymizer::new(0.0);
    let input = "DL: WA1234567";
    let (result, dets) = anon.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "US_DRIVER_LICENSE"),
        "US_DRIVER_LICENSE (pair) not detected in: {input} - dets: {dets:?}"
    );
    assert!(result.contains("[US_DRIVER_LICENSE_"));
}

#[test]
fn test_us_driver_license_not_detected_without_context() {
    let mut anon = Anonymizer::new(0.0);
    let input = "Reference code: D1234567 in database";
    let (_, dets) = anon.anonymize_text(input);
    assert!(
        !dets.iter().any(|d| d.entity_type == "US_DRIVER_LICENSE"),
        "US_DRIVER_LICENSE should not match without context"
    );
}

// -- US_ITIN tests --

#[test]
fn test_us_itin_detected_with_context() {
    let mut anon = Anonymizer::new(0.0);
    let input = "ITIN: 912-70-1234";
    let (result, dets) = anon.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "US_ITIN"),
        "US_ITIN not detected in: {input}"
    );
    assert!(result.contains("[US_ITIN_"));
}

#[test]
fn test_us_itin_rejects_invalid_group() {
    let mut anon = Anonymizer::new(0.0);
    // Group 66 is invalid for ITIN
    let input = "ITIN: 912-66-1234";
    let (_, dets) = anon.anonymize_text(input);
    assert!(
        !dets.iter().any(|d| d.entity_type == "US_ITIN"),
        "US_ITIN should reject invalid group 66"
    );
}

#[test]
fn test_us_itin_not_confused_with_ssn() {
    let mut anon = Anonymizer::new(0.0);
    // SSN context but 9xx area - SSN validator rejects, ITIN validator accepts
    let input = "Tax ITIN: 999-88-1234";
    let (_, dets) = anon.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "US_ITIN"),
        "US_ITIN should match 9xx numbers with ITIN context"
    );
    // SSN should not match 9xx area
    assert!(
        !dets.iter().any(|d| d.entity_type == "US_SSN"),
        "US_SSN should reject 9xx area"
    );
}

// -- US_PASSPORT tests --

#[test]
fn test_us_passport_detected_with_context() {
    let mut anon = Anonymizer::new(0.0);
    let input = "Passport number: 123456789";
    let (result, dets) = anon.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "US_PASSPORT"),
        "US_PASSPORT not detected in: {input}"
    );
    assert!(result.contains("[US_PASSPORT_"));
}

#[test]
fn test_us_passport_not_detected_without_context() {
    let mut anon = Anonymizer::new(0.0);
    let input = "Serial: 123456789 confirmed";
    let (_, dets) = anon.anonymize_text(input);
    assert!(
        !dets.iter().any(|d| d.entity_type == "US_PASSPORT"),
        "US_PASSPORT should not match without context"
    );
}

// -- US_MBI tests --

#[test]
fn test_us_mbi_detected_with_context() {
    let mut anon = Anonymizer::new(0.0);
    // Valid MBI: 1EG4TE500K3
    let input = "Medicare MBI: 1EG4TE500K3";
    let (result, dets) = anon.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "US_MBI"),
        "US_MBI not detected in: {input}"
    );
    assert!(result.contains("[US_MBI_"));
}

#[test]
fn test_us_mbi_rejects_excluded_letters() {
    let mut anon = Anonymizer::new(0.0);
    // 'S' in position 2 is excluded
    let input = "Medicare MBI: 1SG4TE500K3";
    let (_, dets) = anon.anonymize_text(input);
    assert!(
        !dets.iter().any(|d| d.entity_type == "US_MBI"),
        "US_MBI should reject excluded letter S in position 2"
    );
}

#[test]
fn test_us_mbi_not_detected_without_context() {
    let mut anon = Anonymizer::new(0.0);
    let input = "Code: 1EG4TE500K3 reference";
    let (_, dets) = anon.anonymize_text(input);
    assert!(
        !dets.iter().any(|d| d.entity_type == "US_MBI"),
        "US_MBI should not match without context"
    );
}

// -- ABA_ROUTING tests --

#[test]
fn test_aba_routing_detected_with_context() {
    let mut anon = Anonymizer::new(0.0);
    // Chase: 021000021 (valid checksum)
    let input = "Routing number: 021000021";
    let (result, dets) = anon.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "ABA_ROUTING"),
        "ABA_ROUTING not detected in: {input}"
    );
    assert!(result.contains("[ABA_ROUTING_"));
}

#[test]
fn test_aba_routing_rejects_bad_checksum() {
    let mut anon = Anonymizer::new(0.0);
    let input = "Routing number: 021000022";
    let (_, dets) = anon.anonymize_text(input);
    assert!(
        !dets.iter().any(|d| d.entity_type == "ABA_ROUTING"),
        "ABA_ROUTING should reject bad checksum"
    );
}

#[test]
fn test_aba_routing_not_detected_without_context() {
    let mut anon = Anonymizer::new(0.0);
    let input = "Reference: 021000021 noted";
    let (_, dets) = anon.anonymize_text(input);
    assert!(
        !dets.iter().any(|d| d.entity_type == "ABA_ROUTING"),
        "ABA_ROUTING should not match without context"
    );
}
