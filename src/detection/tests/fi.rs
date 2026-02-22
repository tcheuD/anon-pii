use super::super::*;

// -- FI_PERSONAL_IDENTITY_CODE tests --

#[test]
fn test_fi_identity_code_with_context() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("Henkilötunnus: 131052-308T");
    assert!(
        dets.iter()
            .any(|d| d.entity_type == "FI_PERSONAL_IDENTITY_CODE"),
        "FI_PERSONAL_IDENTITY_CODE not detected with context: {dets:?}"
    );
    assert!(!result.contains("131052-308T"));
    assert!(result.contains("[FI_PERSONAL_IDENTITY_CODE_"));
}

#[test]
fn test_fi_identity_code_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("131052-308T");
    assert!(
        !dets
            .iter()
            .any(|d| d.entity_type == "FI_PERSONAL_IDENTITY_CODE"),
        "FI_PERSONAL_IDENTITY_CODE should not match without context: {dets:?}"
    );
}

#[test]
fn test_fi_identity_code_bad_checksum_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("HETU: 131052-308A");
    assert!(
        !dets
            .iter()
            .any(|d| d.entity_type == "FI_PERSONAL_IDENTITY_CODE"),
        "FI_PERSONAL_IDENTITY_CODE with bad checksum should be rejected: {dets:?}"
    );
}

#[test]
fn test_fi_identity_code_century_plus() {
    let mut a = Anonymizer::new(0.0);
    // 010199002 % 31 = 2 -> CONTROL_CHARS[2] = '2'
    let (result, dets) = a.anonymize_text("HETU: 010199+0022");
    assert!(
        dets.iter()
            .any(|d| d.entity_type == "FI_PERSONAL_IDENTITY_CODE"),
        "FI_PERSONAL_IDENTITY_CODE with + separator not detected: {dets:?}"
    );
    assert!(result.contains("[FI_PERSONAL_IDENTITY_CODE_"));
}

#[test]
fn test_fi_identity_code_century_a() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("HETU: 010100A002H");
    assert!(
        dets.iter()
            .any(|d| d.entity_type == "FI_PERSONAL_IDENTITY_CODE"),
        "FI_PERSONAL_IDENTITY_CODE with A separator not detected: {dets:?}"
    );
    assert!(result.contains("[FI_PERSONAL_IDENTITY_CODE_"));
}

#[test]
fn test_fi_identity_code_various_contexts() {
    let mut a = Anonymizer::new(0.0);
    let contexts = [
        "Henkilötunnus: 131052-308T",
        "HETU: 131052-308T",
        "personal identity code 131052-308T",
        "Finland identification number: 131052-308T",
        "Finnish ID: 131052-308T",
    ];
    for ctx in &contexts {
        let (_, dets) = a.anonymize_text(ctx);
        assert!(
            dets.iter()
                .any(|d| d.entity_type == "FI_PERSONAL_IDENTITY_CODE"),
            "FI_PERSONAL_IDENTITY_CODE not detected with context '{ctx}': {dets:?}"
        );
    }
}

#[test]
fn test_fi_identity_code_roundtrip() {
    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_text("HETU: 131052-308T");
    assert!(!result.contains("131052-308T"));
    assert!(result.contains("[FI_PERSONAL_IDENTITY_CODE_"));
}

#[test]
fn test_fi_identity_code_bad_individual_number_rejected() {
    let mut a = Anonymizer::new(0.0);
    // Individual number 000 is invalid (< 002)
    let (_, dets) = a.anonymize_text("HETU: 131052-000T");
    assert!(
        !dets
            .iter()
            .any(|d| d.entity_type == "FI_PERSONAL_IDENTITY_CODE"),
        "FI_PERSONAL_IDENTITY_CODE with individual 000 should be rejected: {dets:?}"
    );
}
