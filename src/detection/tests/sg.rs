use super::super::*;

// -- SG_NRIC_FIN tests --

#[test]
fn test_sg_nric_fin_with_context() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("NRIC: S1234567D");
    assert!(
        dets.iter().any(|d| d.entity_type == "SG_NRIC_FIN"),
        "SG_NRIC_FIN not detected with context: {dets:?}"
    );
    assert!(!result.contains("S1234567D"));
    assert!(result.contains("[SG_NRIC_FIN_"));
}

#[test]
fn test_sg_nric_fin_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("S1234567D");
    assert!(
        !dets.iter().any(|d| d.entity_type == "SG_NRIC_FIN"),
        "SG_NRIC_FIN should not match without context: {dets:?}"
    );
}

#[test]
fn test_sg_nric_fin_bad_checksum_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("NRIC: S1234567A");
    assert!(
        !dets.iter().any(|d| d.entity_type == "SG_NRIC_FIN"),
        "SG_NRIC_FIN with bad checksum should be rejected: {dets:?}"
    );
}

#[test]
fn test_sg_nric_fin_all_prefixes() {
    let mut a = Anonymizer::new(0.0);
    let cases = [
        ("NRIC: S1234567D", "S"),
        ("NRIC: T1234567J", "T"),
        ("FIN: F1234567N", "F"),
        ("FIN: G1234567X", "G"),
        ("FIN: M1234567K", "M"),
    ];
    for (input, prefix) in &cases {
        let (_, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "SG_NRIC_FIN"),
            "SG_NRIC_FIN not detected for {prefix} prefix: {dets:?}"
        );
    }
}

#[test]
fn test_sg_nric_fin_various_contexts() {
    let mut a = Anonymizer::new(0.0);
    let contexts = [
        "Singapore ID: S1234567D",
        "IC number: S1234567D",
        "identification: S1234567D",
        "NRIC: S1234567D",
    ];
    for ctx in &contexts {
        let (_, dets) = a.anonymize_text(ctx);
        assert!(
            dets.iter().any(|d| d.entity_type == "SG_NRIC_FIN"),
            "SG_NRIC_FIN not detected with context '{ctx}': {dets:?}"
        );
    }
}

#[test]
fn test_sg_nric_fin_roundtrip() {
    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_text("Singapore ID: S1234567D");
    assert!(!result.contains("S1234567D"));
    assert!(result.contains("[SG_NRIC_FIN_"));
}

// -- SG_UEN tests --

#[test]
fn test_sg_uen_entity_format_with_context() {
    let mut a = Anonymizer::new(0.0);
    // Format C: T08GA0001L
    let (result, dets) = a.anonymize_text("UEN: T08GA0001L");
    assert!(
        dets.iter().any(|d| d.entity_type == "SG_UEN"),
        "SG_UEN entity format not detected with context: {dets:?}"
    );
    assert!(!result.contains("T08GA0001L"));
    assert!(result.contains("[SG_UEN_"));
}

#[test]
fn test_sg_uen_company_format_with_context() {
    let mut a = Anonymizer::new(0.0);
    // Format B: 201912345W
    let (result, dets) = a.anonymize_text("Company UEN: 201912345W");
    assert!(
        dets.iter().any(|d| d.entity_type == "SG_UEN"),
        "SG_UEN company format not detected with context: {dets:?}"
    );
    assert!(!result.contains("201912345W"));
    assert!(result.contains("[SG_UEN_"));
}

#[test]
fn test_sg_uen_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("T08GA0001L");
    assert!(
        !dets.iter().any(|d| d.entity_type == "SG_UEN"),
        "SG_UEN should not match without context: {dets:?}"
    );
}

#[test]
fn test_sg_uen_various_contexts() {
    let mut a = Anonymizer::new(0.0);
    let contexts = [
        "Unique entity number: T08GA0001L",
        "ACRA entity: T08GA0001L",
        "Business: T08GA0001L",
        "Singapore company: T08GA0001L",
    ];
    for ctx in &contexts {
        let (_, dets) = a.anonymize_text(ctx);
        assert!(
            dets.iter().any(|d| d.entity_type == "SG_UEN"),
            "SG_UEN not detected with context '{ctx}': {dets:?}"
        );
    }
}
