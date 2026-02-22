use super::super::*;

// -- IT_FISCAL_CODE tests --

#[test]
fn test_it_fiscal_code_with_context() {
    let mut a = Anonymizer::new(0.0);
    // AAABBB00A00A000J is a constructed valid code (checksum verified)
    let input = "codice fiscale: AAABBB00A00A000J";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "IT_FISCAL_CODE"),
        "Should detect IT_FISCAL_CODE: {dets:?}"
    );
    assert!(!result.contains("AAABBB00A00A000J"));
    assert!(result.contains("[IT_FISCAL_CODE_"));
}

#[test]
fn test_it_fiscal_code_without_context() {
    let mut a = Anonymizer::new(0.0);
    // Fiscal code has context_required: false, so it should detect even without keywords
    let input = "The code is AAABBB00A00A000J";
    let (_, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "IT_FISCAL_CODE"),
        "IT_FISCAL_CODE should match without context (score=0.85): {dets:?}"
    );
}

#[test]
fn test_it_fiscal_code_bad_checksum_rejected() {
    let mut a = Anonymizer::new(0.0);
    // AAABBB00A00A000K - wrong check letter (should be J)
    let input = "codice fiscale: AAABBB00A00A000K";
    let (_, dets) = a.anonymize_text(input);
    assert!(
        !dets.iter().any(|d| d.entity_type == "IT_FISCAL_CODE"),
        "Bad checksum should be rejected: {dets:?}"
    );
}

#[test]
fn test_it_fiscal_code_invalid_month_not_matched() {
    let mut a = Anonymizer::new(0.0);
    // Invalid month letter 'F' - regex won't match [ABCDEHLMPRST]
    let input = "codice fiscale: AAABBB00F00A000X";
    let (_, dets) = a.anonymize_text(input);
    assert!(
        !dets.iter().any(|d| d.entity_type == "IT_FISCAL_CODE"),
        "Invalid month letter should not match: {dets:?}"
    );
}

#[test]
fn test_it_fiscal_code_context_boost() {
    let mut a = Anonymizer::new(0.0);
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
        score_ctx > score_no_ctx,
        "Context should boost score: {score_ctx} vs {score_no_ctx}"
    );
}

#[test]
fn test_it_fiscal_code_roundtrip() {
    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_text("CF: AAABBB00A00A000J");
    assert!(!result.contains("AAABBB00A00A000J"));
    assert!(result.contains("[IT_FISCAL_CODE_"));
}

// -- IT_DRIVER_LICENSE tests --

#[test]
fn test_it_driver_license_with_context() {
    let mut a = Anonymizer::new(0.0);
    let input = "patente: AB1234567X";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "IT_DRIVER_LICENSE"),
        "Should detect IT_DRIVER_LICENSE: {dets:?}"
    );
    assert!(!result.contains("AB1234567X"));
    assert!(result.contains("[IT_DRIVER_LICENSE_"));
}

#[test]
fn test_it_driver_license_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let input = "code: AB1234567X";
    let (_, dets) = a.anonymize_text(input);
    assert!(
        !dets.iter().any(|d| d.entity_type == "IT_DRIVER_LICENSE"),
        "IT_DRIVER_LICENSE without context should be rejected: {dets:?}"
    );
}

#[test]
fn test_it_driver_license_various_contexts() {
    let mut a = Anonymizer::new(0.0);
    let contexts = [
        "patente di guida: AB1234567X",
        "driver license: AB1234567X",
        "driving licence: AB1234567X",
    ];
    for input in &contexts {
        let (_, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "IT_DRIVER_LICENSE"),
            "Should detect with context '{input}': {dets:?}"
        );
    }
}

// -- IT_VAT_CODE tests --

#[test]
fn test_it_vat_code_with_context() {
    let mut a = Anonymizer::new(0.0);
    let input = "Partita IVA: 12345678901";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "IT_VAT_CODE"),
        "Should detect IT_VAT_CODE: {dets:?}"
    );
    assert!(!result.contains("12345678901"));
    assert!(result.contains("[IT_VAT_CODE_"));
}

#[test]
fn test_it_vat_code_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let input = "number: 12345678901";
    let (_, dets) = a.anonymize_text(input);
    assert!(
        !dets.iter().any(|d| d.entity_type == "IT_VAT_CODE"),
        "IT_VAT_CODE without context should be rejected: {dets:?}"
    );
}

#[test]
fn test_it_vat_code_piva_context() {
    let mut a = Anonymizer::new(0.0);
    let input = "P.IVA 12345678901";
    let (_, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "IT_VAT_CODE"),
        "Should detect with P.IVA context: {dets:?}"
    );
}

// -- IT_PASSPORT tests --

#[test]
fn test_it_passport_with_context() {
    let mut a = Anonymizer::new(0.0);
    let input = "passaporto: AB1234567";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "IT_PASSPORT"),
        "Should detect IT_PASSPORT: {dets:?}"
    );
    assert!(!result.contains("AB1234567"));
    assert!(result.contains("[IT_PASSPORT_"));
}

#[test]
fn test_it_passport_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let input = "ref: AB1234567";
    let (_, dets) = a.anonymize_text(input);
    assert!(
        !dets.iter().any(|d| d.entity_type == "IT_PASSPORT"),
        "IT_PASSPORT without context should be rejected: {dets:?}"
    );
}

#[test]
fn test_it_passport_various_contexts() {
    let mut a = Anonymizer::new(0.0);
    let contexts = [
        "passport: AB1234567",
        "passaporto n. AB1234567",
        "travel document AB1234567",
    ];
    for input in &contexts {
        let (_, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "IT_PASSPORT"),
            "Should detect with context '{input}': {dets:?}"
        );
    }
}

// -- IT_IDENTITY_CARD tests --

#[test]
fn test_it_identity_card_with_context() {
    let mut a = Anonymizer::new(0.0);
    let input = "carta d'identita: CA12345AB";
    let (result, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "IT_IDENTITY_CARD"),
        "Should detect IT_IDENTITY_CARD: {dets:?}"
    );
    assert!(!result.contains("CA12345AB"));
    assert!(result.contains("[IT_IDENTITY_CARD_"));
}

#[test]
fn test_it_identity_card_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let input = "ref: CA12345AB";
    let (_, dets) = a.anonymize_text(input);
    assert!(
        !dets.iter().any(|d| d.entity_type == "IT_IDENTITY_CARD"),
        "IT_IDENTITY_CARD without context should be rejected: {dets:?}"
    );
}

#[test]
fn test_it_identity_card_cie_context() {
    let mut a = Anonymizer::new(0.0);
    let input = "CIE: CA12345AB";
    let (_, dets) = a.anonymize_text(input);
    assert!(
        dets.iter().any(|d| d.entity_type == "IT_IDENTITY_CARD"),
        "Should detect with CIE context: {dets:?}"
    );
}

#[test]
fn test_it_identity_card_various_contexts() {
    let mut a = Anonymizer::new(0.0);
    let contexts = [
        "carta identita: CA12345AB",
        "identity card: CA12345AB",
        "documento: CA12345AB",
    ];
    for input in &contexts {
        let (_, dets) = a.anonymize_text(input);
        assert!(
            dets.iter().any(|d| d.entity_type == "IT_IDENTITY_CARD"),
            "Should detect with context '{input}': {dets:?}"
        );
    }
}

#[test]
fn test_it_identity_card_roundtrip() {
    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_text("CIE: CA12345AB");
    assert!(!result.contains("CA12345AB"));
    assert!(result.contains("[IT_IDENTITY_CARD_"));
}
