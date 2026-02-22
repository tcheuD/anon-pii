use super::super::*;

// -- SI_EMSO tests --

#[test]
fn test_si_emso_with_context() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("EMSO: 0101006500006");
    assert!(
        dets.iter().any(|d| d.entity_type == "SI_EMSO"),
        "SI_EMSO not detected with context: {dets:?}"
    );
    assert!(!result.contains("0101006500006"));
    assert!(result.contains("[SI_EMSO_"));
}

#[test]
fn test_si_emso_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("0101006500006");
    assert!(
        !dets.iter().any(|d| d.entity_type == "SI_EMSO"),
        "SI_EMSO should not match without context: {dets:?}"
    );
}

#[test]
fn test_si_emso_bad_checksum_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("EMSO: 0101006500007");
    assert!(
        !dets.iter().any(|d| d.entity_type == "SI_EMSO"),
        "SI_EMSO with bad checksum should be rejected: {dets:?}"
    );
}

#[test]
fn test_si_emso_bad_region_rejected() {
    let mut a = Anonymizer::new(0.0);
    // Region 49 (not Slovenia) - even if checksum were valid, region check fails
    let (_, dets) = a.anonymize_text("EMSO: 0101006490006");
    assert!(
        !dets.iter().any(|d| d.entity_type == "SI_EMSO"),
        "SI_EMSO with non-Slovenian region should be rejected: {dets:?}"
    );
}

#[test]
fn test_si_emso_various_contexts() {
    let mut a = Anonymizer::new(0.0);
    let contexts = [
        "matična številka: 0101006500006",
        "JMBG: 0101006500006",
        "Slovenia personal id: 0101006500006",
    ];
    for ctx in &contexts {
        let (_, dets) = a.anonymize_text(ctx);
        assert!(
            dets.iter().any(|d| d.entity_type == "SI_EMSO"),
            "SI_EMSO not detected with context '{ctx}': {dets:?}"
        );
    }
}

#[test]
fn test_si_emso_roundtrip() {
    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_text("EMSO: 0101006500006");
    assert!(!result.contains("0101006500006"));
    assert!(result.contains("[SI_EMSO_"));
}

// -- SI_TAX_NUMBER tests --

#[test]
fn test_si_tax_number_with_context() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("Davčna številka: 15012557");
    assert!(
        dets.iter().any(|d| d.entity_type == "SI_TAX_NUMBER"),
        "SI_TAX_NUMBER not detected with context: {dets:?}"
    );
    assert!(!result.contains("15012557"));
    assert!(result.contains("[SI_TAX_NUMBER_"));
}

#[test]
fn test_si_tax_number_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("15012557");
    assert!(
        !dets.iter().any(|d| d.entity_type == "SI_TAX_NUMBER"),
        "SI_TAX_NUMBER should not match without context: {dets:?}"
    );
}

#[test]
fn test_si_tax_number_bad_checksum_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("tax number: 15012558");
    assert!(
        !dets.iter().any(|d| d.entity_type == "SI_TAX_NUMBER"),
        "SI_TAX_NUMBER with bad checksum should be rejected: {dets:?}"
    );
}

#[test]
fn test_si_tax_number_various_contexts() {
    let mut a = Anonymizer::new(0.0);
    let contexts = [
        "DDV: 15012557",
        "tax id: 15012557",
        "Slovenia tax number: 15012557",
    ];
    for ctx in &contexts {
        let (_, dets) = a.anonymize_text(ctx);
        assert!(
            dets.iter().any(|d| d.entity_type == "SI_TAX_NUMBER"),
            "SI_TAX_NUMBER not detected with context '{ctx}': {dets:?}"
        );
    }
}

#[test]
fn test_si_tax_number_roundtrip() {
    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_text("tax number: 15012557");
    assert!(!result.contains("15012557"));
    assert!(result.contains("[SI_TAX_NUMBER_"));
}
