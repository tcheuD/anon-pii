use super::super::*;

// -- IN_AADHAAR detection tests --

#[test]
fn test_in_aadhaar_with_context_spaced() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("Aadhaar: 4991 1866 5246");
    assert!(
        dets.iter().any(|d| d.entity_type == "IN_AADHAAR"),
        "IN_AADHAAR not detected: {dets:?}"
    );
    assert!(result.contains("[IN_AADHAAR_"));
}

#[test]
fn test_in_aadhaar_with_context_compact() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("UID number: 499118665246");
    assert!(
        dets.iter().any(|d| d.entity_type == "IN_AADHAAR"),
        "IN_AADHAAR compact not detected: {dets:?}"
    );
    assert!(result.contains("[IN_AADHAAR_"));
}

#[test]
fn test_in_aadhaar_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("number 499118665246 end");
    assert!(
        !dets.iter().any(|d| d.entity_type == "IN_AADHAAR"),
        "IN_AADHAAR without context should be rejected: {dets:?}"
    );
}

#[test]
fn test_in_aadhaar_bad_verhoeff_rejected() {
    let mut a = Anonymizer::new(0.0);
    // Flip last digit: 499118665246 is valid, 499118665247 should fail
    let (_, dets) = a.anonymize_text("Aadhaar: 4991 1866 5247");
    assert!(
        !dets.iter().any(|d| d.entity_type == "IN_AADHAAR"),
        "IN_AADHAAR with bad Verhoeff should be rejected: {dets:?}"
    );
}

#[test]
fn test_in_aadhaar_repeated_digits_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("Aadhaar: 222222222222");
    assert!(
        !dets.iter().any(|d| d.entity_type == "IN_AADHAAR"),
        "IN_AADHAAR with repeated digits should be rejected: {dets:?}"
    );
}

#[test]
fn test_in_aadhaar_roundtrip() {
    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_text("Aadhaar: 4991 1866 5246");
    assert!(!result.contains("4991 1866 5246"));
    assert!(result.contains("[IN_AADHAAR_"));
}

// -- IN_PAN detection tests --

#[test]
fn test_in_pan_with_context() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("PAN card: ABCPD1234E");
    assert!(
        dets.iter().any(|d| d.entity_type == "IN_PAN"),
        "IN_PAN not detected: {dets:?}"
    );
    assert!(result.contains("[IN_PAN_"));
}

#[test]
fn test_in_pan_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("code ABCPD1234E end");
    assert!(
        !dets.iter().any(|d| d.entity_type == "IN_PAN"),
        "IN_PAN without context should be rejected: {dets:?}"
    );
}

#[test]
fn test_in_pan_various_holder_types() {
    let mut a = Anonymizer::new(0.0);
    // P = Personal, C = Company, H = HUF, F = Firm
    for holder_type in ['P', 'C', 'H', 'F', 'A', 'T', 'B', 'L', 'J', 'G'] {
        let pan = format!("ABC{}D1234E", holder_type);
        let input = format!("PAN: {pan}");
        let (result, dets) = a.anonymize_text(&input);
        assert!(
            dets.iter().any(|d| d.entity_type == "IN_PAN"),
            "IN_PAN with holder type {holder_type} not detected: {dets:?}"
        );
        assert!(result.contains("[IN_PAN_"));
    }
}

#[test]
fn test_in_pan_roundtrip() {
    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_text("Income tax PAN: ABCPD1234E");
    assert!(!result.contains("ABCPD1234E"));
    assert!(result.contains("[IN_PAN_"));
}

// -- IN_VEHICLE_REGISTRATION detection tests --

#[test]
fn test_in_vehicle_registration_with_context() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("Vehicle registration: MH-02-AB-1234");
    assert!(
        dets.iter()
            .any(|d| d.entity_type == "IN_VEHICLE_REGISTRATION"),
        "IN_VEHICLE_REGISTRATION not detected: {dets:?}"
    );
    assert!(result.contains("[IN_VEHICLE_REGISTRATION_"));
}

#[test]
fn test_in_vehicle_registration_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("code MH02AB1234 end");
    assert!(
        !dets
            .iter()
            .any(|d| d.entity_type == "IN_VEHICLE_REGISTRATION"),
        "IN_VEHICLE_REGISTRATION without context should be rejected: {dets:?}"
    );
}

// -- IN_PASSPORT detection tests --

#[test]
fn test_in_passport_with_context() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("Passport number: J1234567");
    assert!(
        dets.iter().any(|d| d.entity_type == "IN_PASSPORT"),
        "IN_PASSPORT not detected: {dets:?}"
    );
    assert!(result.contains("[IN_PASSPORT_"));
}

#[test]
fn test_in_passport_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("code J1234567 end");
    assert!(
        !dets.iter().any(|d| d.entity_type == "IN_PASSPORT"),
        "IN_PASSPORT without context should be rejected: {dets:?}"
    );
}

// -- IN_VOTER detection tests --

#[test]
fn test_in_voter_with_context() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("Voter ID: ABC1234567");
    assert!(
        dets.iter().any(|d| d.entity_type == "IN_VOTER"),
        "IN_VOTER not detected: {dets:?}"
    );
    assert!(result.contains("[IN_VOTER_"));
}

#[test]
fn test_in_voter_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("code ABC1234567 end");
    assert!(
        !dets.iter().any(|d| d.entity_type == "IN_VOTER"),
        "IN_VOTER without context should be rejected: {dets:?}"
    );
}

// -- IN_GSTIN detection tests --

#[test]
fn test_in_gstin_with_context() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("GST: 27AAPFU0939F1ZV");
    assert!(
        dets.iter().any(|d| d.entity_type == "IN_GSTIN"),
        "IN_GSTIN not detected: {dets:?}"
    );
    assert!(result.contains("[IN_GSTIN_"));
}

#[test]
fn test_in_gstin_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("code 27AAPFU0939F1ZV end");
    assert!(
        !dets.iter().any(|d| d.entity_type == "IN_GSTIN"),
        "IN_GSTIN without context should be rejected: {dets:?}"
    );
}

#[test]
fn test_in_gstin_bad_state_code_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("GST: 00AAPFU0939F1ZV");
    assert!(
        !dets.iter().any(|d| d.entity_type == "IN_GSTIN"),
        "IN_GSTIN with bad state code should be rejected: {dets:?}"
    );
}

#[test]
fn test_in_gstin_roundtrip() {
    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_text("GSTIN number: 27AAPFU0939F1ZV");
    assert!(!result.contains("27AAPFU0939F1ZV"));
    assert!(result.contains("[IN_GSTIN_"));
}

#[test]
fn test_in_gstin_various_contexts() {
    let mut a = Anonymizer::new(0.0);
    let contexts = [
        "GST number: 27AAPFU0939F1ZV",
        "GSTIN: 27AAPFU0939F1ZV",
        "goods and services tax 27AAPFU0939F1ZV",
    ];
    for ctx in &contexts {
        let (_, dets) = a.anonymize_text(ctx);
        assert!(
            dets.iter().any(|d| d.entity_type == "IN_GSTIN"),
            "IN_GSTIN not detected in: {ctx}"
        );
    }
}
