use super::super::*;

// -- ES NIF tests --

#[test]
fn test_es_nif_with_context() {
    let mut a = Anonymizer::new(0.0);
    // 12345678Z: 12345678 % 23 = 14 -> letter table[14] = 'Z'
    let (result, dets) = a.anonymize_text("DNI: 12345678Z");
    assert!(
        dets.iter().any(|d| d.entity_type == "ES_NIF"),
        "ES NIF not detected: {dets:?}"
    );
    assert!(result.contains("[ES_NIF_"));
}

#[test]
fn test_es_nif_with_separator() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("NIF: 12345678-Z");
    assert!(
        dets.iter().any(|d| d.entity_type == "ES_NIF"),
        "ES NIF with separator not detected: {dets:?}"
    );
    assert!(result.contains("[ES_NIF_"));
}

#[test]
fn test_es_nif_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("code 12345678Z end");
    assert!(
        !dets.iter().any(|d| d.entity_type == "ES_NIF"),
        "ES NIF without context should be rejected: {dets:?}"
    );
}

#[test]
fn test_es_nif_bad_checksum_rejected() {
    let mut a = Anonymizer::new(0.0);
    // 12345678Z is valid, 12345678A is invalid (expected Z)
    let (_, dets) = a.anonymize_text("DNI: 12345678A");
    assert!(
        !dets.iter().any(|d| d.entity_type == "ES_NIF"),
        "ES NIF with bad checksum should be rejected: {dets:?}"
    );
}

#[test]
fn test_es_nif_various_context_keywords() {
    let mut a = Anonymizer::new(0.0);
    let contexts = [
        "documento nacional: 12345678Z",
        "identificacion fiscal 12345678Z",
        "documento de identidad 12345678Z",
    ];
    for ctx in &contexts {
        let (_, dets) = a.anonymize_text(ctx);
        assert!(
            dets.iter().any(|d| d.entity_type == "ES_NIF"),
            "ES NIF not detected in: {ctx}"
        );
    }
}

#[test]
fn test_es_nif_known_valid_numbers() {
    let mut a = Anonymizer::new(0.0);
    // 00000000T: 0 % 23 = 0 -> 'T'
    let (result, dets) = a.anonymize_text("DNI: 00000000T");
    assert!(
        dets.iter().any(|d| d.entity_type == "ES_NIF"),
        "ES NIF 00000000T not detected: {dets:?}"
    );
    assert!(result.contains("[ES_NIF_"));
}

#[test]
fn test_es_nif_roundtrip() {
    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_text("NIF: 12345678Z");
    assert!(!result.contains("12345678Z"));
    assert!(result.contains("[ES_NIF_"));
}

// -- ES NIE tests --

#[test]
fn test_es_nie_with_context() {
    let mut a = Anonymizer::new(0.0);
    // X->0, 01234567 % 23 = 19 -> 'L'
    let (result, dets) = a.anonymize_text("NIE: X1234567L");
    assert!(
        dets.iter().any(|d| d.entity_type == "ES_NIE"),
        "ES NIE not detected: {dets:?}"
    );
    assert!(result.contains("[ES_NIE_"));
}

#[test]
fn test_es_nie_y_prefix() {
    let mut a = Anonymizer::new(0.0);
    // Y->1, 11234567 % 23 = 10 -> 'X'
    let (result, dets) = a.anonymize_text("NIE: Y1234567X");
    assert!(
        dets.iter().any(|d| d.entity_type == "ES_NIE"),
        "ES NIE Y-prefix not detected: {dets:?}"
    );
    assert!(result.contains("[ES_NIE_"));
}

#[test]
fn test_es_nie_z_prefix() {
    let mut a = Anonymizer::new(0.0);
    // Z->2, 21234567 % 23 = 1 -> 'R'
    let (result, dets) = a.anonymize_text("NIE extranjero: Z1234567R");
    assert!(
        dets.iter().any(|d| d.entity_type == "ES_NIE"),
        "ES NIE Z-prefix not detected: {dets:?}"
    );
    assert!(result.contains("[ES_NIE_"));
}

#[test]
fn test_es_nie_with_separators() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("NIE: X-1234567-L");
    assert!(
        dets.iter().any(|d| d.entity_type == "ES_NIE"),
        "ES NIE with separators not detected: {dets:?}"
    );
    assert!(result.contains("[ES_NIE_"));
}

#[test]
fn test_es_nie_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("ref X1234567L noted");
    assert!(
        !dets.iter().any(|d| d.entity_type == "ES_NIE"),
        "ES NIE without context should be rejected: {dets:?}"
    );
}

#[test]
fn test_es_nie_bad_checksum_rejected() {
    let mut a = Anonymizer::new(0.0);
    // X1234567L is valid, X1234567A is not
    let (_, dets) = a.anonymize_text("NIE: X1234567A");
    assert!(
        !dets.iter().any(|d| d.entity_type == "ES_NIE"),
        "ES NIE with bad checksum should be rejected: {dets:?}"
    );
}

#[test]
fn test_es_nie_various_context_keywords() {
    let mut a = Anonymizer::new(0.0);
    let contexts = [
        "extranjero: X1234567L",
        "residencia X1234567L",
        "foreigner ID X1234567L",
    ];
    for ctx in &contexts {
        let (_, dets) = a.anonymize_text(ctx);
        assert!(
            dets.iter().any(|d| d.entity_type == "ES_NIE"),
            "ES NIE not detected in: {ctx}"
        );
    }
}

#[test]
fn test_es_nie_roundtrip() {
    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_text("NIE: X1234567L");
    assert!(!result.contains("X1234567L"));
    assert!(result.contains("[ES_NIE_"));
}
