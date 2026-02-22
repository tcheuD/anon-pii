use super::super::*;

#[test]
fn test_fr_ssn() {
    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_text("NIR: 1 85 12 75 123 456 78");
    assert!(result.contains("[FR_SSN_"));
}

#[test]
fn test_fr_ssn_compact() {
    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_text("NIR: 185127512345678");
    assert!(result.contains("[FR_SSN_"));
}

#[test]
fn test_fr_ssn_not_in_longer_digits() {
    let mut a = Anonymizer::new(0.0);
    // Gmail message IDs like m_1234567890852 should not match as SSN
    let (result, dets) = a.anonymize_text("class=\"m_18501275123456780852message\"");
    assert!(
        !dets.iter().any(|d| d.entity_type == "FR_SSN"),
        "Should not match SSN inside longer digit sequence: {:?}",
        dets.iter()
            .filter(|d| d.entity_type == "FR_SSN")
            .collect::<Vec<_>>()
    );
    assert!(!result.contains("[FR_SSN_"));
}

#[test]
fn test_fr_passport_with_context() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("passeport: 12AB34567");
    assert!(dets.iter().any(|d| d.entity_type == "FR_PASSPORT"));
    assert!(result.contains("[FR_PASSPORT_"));
}

#[test]
fn test_fr_passport_without_context() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("code: 12AB34567");
    assert!(!dets.iter().any(|d| d.entity_type == "FR_PASSPORT"));
}
