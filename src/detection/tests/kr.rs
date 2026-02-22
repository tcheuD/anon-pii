use super::super::*;

// -- KR_RRN tests --

#[test]
fn test_kr_rrn_with_context() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("Resident registration: 850101-1234566");
    assert!(
        dets.iter().any(|d| d.entity_type == "KR_RRN"),
        "KR_RRN not detected with context: {dets:?}"
    );
    assert!(!result.contains("850101-1234566"));
    assert!(result.contains("[KR_RRN_"));
}

#[test]
fn test_kr_rrn_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("850101-1234566");
    assert!(
        !dets.iter().any(|d| d.entity_type == "KR_RRN"),
        "KR_RRN should not match without context: {dets:?}"
    );
}

#[test]
fn test_kr_rrn_bad_checksum_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("Resident registration: 850101-1234567");
    assert!(
        !dets.iter().any(|d| d.entity_type == "KR_RRN"),
        "KR_RRN with bad checksum should be rejected: {dets:?}"
    );
}

#[test]
fn test_kr_rrn_roundtrip() {
    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_text("주민등록: 850101-1234566");
    assert!(!result.contains("850101-1234566"));
    assert!(result.contains("[KR_RRN_"));
}

#[test]
fn test_kr_rrn_various_contexts() {
    let mut a = Anonymizer::new(0.0);
    let contexts = [
        "resident registration number: 850101-1234566",
        "주민등록번호: 850101-1234566",
        "주민번호 850101-1234566",
        "RRN: 850101-1234566",
    ];
    for ctx in &contexts {
        let (_, dets) = a.anonymize_text(ctx);
        assert!(
            dets.iter().any(|d| d.entity_type == "KR_RRN"),
            "KR_RRN not detected with context '{ctx}': {dets:?}"
        );
    }
}

// -- KR_FRN tests --

#[test]
fn test_kr_frn_with_context() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("Foreign registration: 850101-5234567");
    assert!(
        dets.iter().any(|d| d.entity_type == "KR_FRN"),
        "KR_FRN not detected with context: {dets:?}"
    );
    assert!(!result.contains("850101-5234567"));
    assert!(result.contains("[KR_FRN_"));
}

#[test]
fn test_kr_frn_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("850101-5234567");
    assert!(
        !dets.iter().any(|d| d.entity_type == "KR_FRN"),
        "KR_FRN should not match without context: {dets:?}"
    );
}

#[test]
fn test_kr_frn_bad_checksum_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("Foreign registration: 850101-5234560");
    assert!(
        !dets.iter().any(|d| d.entity_type == "KR_FRN"),
        "KR_FRN with bad checksum should be rejected: {dets:?}"
    );
}

#[test]
fn test_kr_frn_various_contexts() {
    let mut a = Anonymizer::new(0.0);
    let contexts = [
        "alien registration: 850101-5234567",
        "외국인등록: 850101-5234567",
        "FRN: 850101-5234567",
    ];
    for ctx in &contexts {
        let (_, dets) = a.anonymize_text(ctx);
        assert!(
            dets.iter().any(|d| d.entity_type == "KR_FRN"),
            "KR_FRN not detected with context '{ctx}': {dets:?}"
        );
    }
}

// -- KR_BRN tests --

#[test]
fn test_kr_brn_with_context() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("Business registration: 123-45-67891");
    assert!(
        dets.iter().any(|d| d.entity_type == "KR_BRN"),
        "KR_BRN not detected with context: {dets:?}"
    );
    assert!(!result.contains("123-45-67891"));
    assert!(result.contains("[KR_BRN_"));
}

#[test]
fn test_kr_brn_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("123-45-67891");
    assert!(
        !dets.iter().any(|d| d.entity_type == "KR_BRN"),
        "KR_BRN should not match without context: {dets:?}"
    );
}

#[test]
fn test_kr_brn_bad_checksum_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("Business registration: 123-45-67890");
    assert!(
        !dets.iter().any(|d| d.entity_type == "KR_BRN"),
        "KR_BRN with bad checksum should be rejected: {dets:?}"
    );
}

#[test]
fn test_kr_brn_various_contexts() {
    let mut a = Anonymizer::new(0.0);
    let contexts = [
        "사업자등록번호: 123-45-67891",
        "business number: 123-45-67891",
        "BRN: 123-45-67891",
        "tax id: 123-45-67891",
    ];
    for ctx in &contexts {
        let (_, dets) = a.anonymize_text(ctx);
        assert!(
            dets.iter().any(|d| d.entity_type == "KR_BRN"),
            "KR_BRN not detected with context '{ctx}': {dets:?}"
        );
    }
}

// -- KR_DRIVER_LICENSE tests --

#[test]
fn test_kr_driver_license_with_context() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("Driver license: 11-22-123456-01");
    assert!(
        dets.iter().any(|d| d.entity_type == "KR_DRIVER_LICENSE"),
        "KR_DRIVER_LICENSE not detected with context: {dets:?}"
    );
    assert!(!result.contains("11-22-123456-01"));
    assert!(result.contains("[KR_DRIVER_LICENSE_"));
}

#[test]
fn test_kr_driver_license_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("11-22-123456-01");
    assert!(
        !dets.iter().any(|d| d.entity_type == "KR_DRIVER_LICENSE"),
        "KR_DRIVER_LICENSE should not match without context: {dets:?}"
    );
}

#[test]
fn test_kr_driver_license_various_regions() {
    let mut a = Anonymizer::new(0.0);
    // Test various valid regional codes (11=Seoul, 12=Busan, 28=Sejong)
    let regions = ["11", "12", "19", "20", "28"];
    for r in &regions {
        let input = format!("운전면허: {r}-03-456789-01");
        let (_, dets) = a.anonymize_text(&input);
        assert!(
            dets.iter().any(|d| d.entity_type == "KR_DRIVER_LICENSE"),
            "KR_DRIVER_LICENSE not detected for region {r}: {dets:?}"
        );
    }
}

#[test]
fn test_kr_driver_license_invalid_region_rejected() {
    let mut a = Anonymizer::new(0.0);
    // Region 10 is below valid range (11-28)
    let (_, dets) = a.anonymize_text("Driver license: 10-22-123456-01");
    assert!(
        !dets.iter().any(|d| d.entity_type == "KR_DRIVER_LICENSE"),
        "KR_DRIVER_LICENSE with invalid region 10 should be rejected: {dets:?}"
    );
    // Region 29 is above valid range
    let (_, dets) = a.anonymize_text("Driver license: 29-22-123456-01");
    assert!(
        !dets.iter().any(|d| d.entity_type == "KR_DRIVER_LICENSE"),
        "KR_DRIVER_LICENSE with invalid region 29 should be rejected: {dets:?}"
    );
}

// -- KR_PASSPORT tests --

#[test]
fn test_kr_passport_with_context() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("Passport: M12345678");
    assert!(
        dets.iter().any(|d| d.entity_type == "KR_PASSPORT"),
        "KR_PASSPORT not detected with context: {dets:?}"
    );
    assert!(!result.contains("M12345678"));
    assert!(result.contains("[KR_PASSPORT_"));
}

#[test]
fn test_kr_passport_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("M12345678");
    assert!(
        !dets.iter().any(|d| d.entity_type == "KR_PASSPORT"),
        "KR_PASSPORT should not match without context: {dets:?}"
    );
}

#[test]
fn test_kr_passport_various_type_letters() {
    let mut a = Anonymizer::new(0.0);
    for letter in ["M", "S", "R", "O", "D"] {
        let input = format!("여권번호: {letter}98765432");
        let (_, dets) = a.anonymize_text(&input);
        assert!(
            dets.iter().any(|d| d.entity_type == "KR_PASSPORT"),
            "KR_PASSPORT not detected for type letter {letter}: {dets:?}"
        );
    }
}

#[test]
fn test_kr_passport_invalid_letter_rejected() {
    let mut a = Anonymizer::new(0.0);
    // 'A' is not a valid passport type letter
    let (_, dets) = a.anonymize_text("Passport: A12345678");
    assert!(
        !dets.iter().any(|d| d.entity_type == "KR_PASSPORT"),
        "KR_PASSPORT with invalid type letter should be rejected: {dets:?}"
    );
}
