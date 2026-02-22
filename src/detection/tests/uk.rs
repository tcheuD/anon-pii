use super::super::*;

// -- UK_NHS tests --

#[test]
fn test_uk_nhs_with_context_spaced() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("NHS number: 943 476 5919");
    assert!(
        dets.iter().any(|d| d.entity_type == "UK_NHS"),
        "UK NHS not detected: {dets:?}"
    );
    assert!(result.contains("[UK_NHS_"));
}

#[test]
fn test_uk_nhs_with_context_compact() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("Patient NHS: 9434765919");
    assert!(
        dets.iter().any(|d| d.entity_type == "UK_NHS"),
        "UK NHS compact not detected: {dets:?}"
    );
    assert!(result.contains("[UK_NHS_"));
}

#[test]
fn test_uk_nhs_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("code 943 476 5919 end");
    assert!(
        !dets.iter().any(|d| d.entity_type == "UK_NHS"),
        "UK NHS without context should be rejected: {dets:?}"
    );
}

#[test]
fn test_uk_nhs_bad_checksum_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("NHS number: 943 476 5910");
    assert!(
        !dets.iter().any(|d| d.entity_type == "UK_NHS"),
        "UK NHS with bad checksum should be rejected: {dets:?}"
    );
}

#[test]
fn test_uk_nhs_remainder_10_rejected() {
    let mut a = Anonymizer::new(0.0);
    // 4300000000 has remainder 10 -> invalid
    let (_, dets) = a.anonymize_text("NHS number: 430 000 0000");
    assert!(
        !dets.iter().any(|d| d.entity_type == "UK_NHS"),
        "UK NHS with remainder-10 should be rejected: {dets:?}"
    );
}

#[test]
fn test_uk_nhs_check_digit_zero() {
    let mut a = Anonymizer::new(0.0);
    // 0000000000: sum=0, 0%11=0, 11-0=11 -> check digit 0
    let (result, dets) = a.anonymize_text("NHS number: 0000000000");
    assert!(
        dets.iter().any(|d| d.entity_type == "UK_NHS"),
        "UK NHS with check digit 0 not detected: {dets:?}"
    );
    assert!(result.contains("[UK_NHS_"));
}

#[test]
fn test_uk_nhs_roundtrip() {
    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_text("NHS number: 943 476 5919");
    assert!(!result.contains("943 476 5919"));
    assert!(result.contains("[UK_NHS_"));
}

#[test]
fn test_uk_nhs_various_contexts() {
    let mut a = Anonymizer::new(0.0);
    let contexts = [
        "patient ID 9434765919",
        "hospital record: 943 476 5919",
        "GP surgery ref 9434765919",
        "health service number: 943 476 5919",
    ];
    for ctx in &contexts {
        let (_, dets) = a.anonymize_text(ctx);
        assert!(
            dets.iter().any(|d| d.entity_type == "UK_NHS"),
            "UK NHS not detected in: {ctx}"
        );
    }
}

// -- UK_NINO tests --

#[test]
fn test_uk_nino_with_context_spaced() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("National insurance: AB 12 34 56 C");
    assert!(
        dets.iter().any(|d| d.entity_type == "UK_NINO"),
        "UK NINO not detected: {dets:?}"
    );
    assert!(result.contains("[UK_NINO_"));
}

#[test]
fn test_uk_nino_with_context_compact() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("NINO: AB123456C");
    assert!(
        dets.iter().any(|d| d.entity_type == "UK_NINO"),
        "UK NINO compact not detected: {dets:?}"
    );
    assert!(result.contains("[UK_NINO_"));
}

#[test]
fn test_uk_nino_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("reference AB 12 34 56 C noted");
    assert!(
        !dets.iter().any(|d| d.entity_type == "UK_NINO"),
        "UK NINO without context should be rejected: {dets:?}"
    );
}

#[test]
fn test_uk_nino_blocklisted_prefix_rejected() {
    let mut a = Anonymizer::new(0.0);
    let blocked = ["BG", "GB", "NK", "KN", "NT", "TN", "ZZ"];
    for prefix in &blocked {
        let input = format!("NINO: {prefix} 12 34 56 A");
        let (_, dets) = a.anonymize_text(&input);
        assert!(
            !dets.iter().any(|d| d.entity_type == "UK_NINO"),
            "UK NINO with blocked prefix {prefix} should be rejected: {dets:?}"
        );
    }
}

#[test]
fn test_uk_nino_valid_suffix_letters() {
    let mut a = Anonymizer::new(0.0);
    for suffix in ['A', 'B', 'C', 'D'] {
        let input = format!("NI number: AB 12 34 56 {suffix}");
        let (_, dets) = a.anonymize_text(&input);
        assert!(
            dets.iter().any(|d| d.entity_type == "UK_NINO"),
            "UK NINO with suffix {suffix} not detected"
        );
    }
}

#[test]
fn test_uk_nino_various_contexts() {
    let mut a = Anonymizer::new(0.0);
    let contexts = [
        "HMRC reference: CE123456A",
        "tax PAYE number CE123456A",
        "contributions: CE 12 34 56 A",
        "insurance number is CE123456A",
    ];
    for ctx in &contexts {
        let (_, dets) = a.anonymize_text(ctx);
        assert!(
            dets.iter().any(|d| d.entity_type == "UK_NINO"),
            "UK NINO not detected in: {ctx}"
        );
    }
}

#[test]
fn test_uk_nino_roundtrip() {
    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_text("NI number: AB 12 34 56 C");
    assert!(!result.contains("AB 12 34 56 C"));
    assert!(result.contains("[UK_NINO_"));
}
