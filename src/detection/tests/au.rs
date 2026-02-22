use super::super::*;

// -- AU_ABN tests --

#[test]
fn test_au_abn_with_context_formatted() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("ABN: 51 824 753 556");
    assert!(
        dets.iter().any(|d| d.entity_type == "AU_ABN"),
        "AU ABN not detected: {dets:?}"
    );
    assert!(result.contains("[AU_ABN_"));
}

#[test]
fn test_au_abn_with_context_compact() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("ABN: 51824753556");
    assert!(
        dets.iter().any(|d| d.entity_type == "AU_ABN"),
        "AU ABN compact not detected: {dets:?}"
    );
    assert!(result.contains("[AU_ABN_"));
}

#[test]
fn test_au_abn_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("code 51824753556 end");
    assert!(
        !dets.iter().any(|d| d.entity_type == "AU_ABN"),
        "AU ABN without context should be rejected: {dets:?}"
    );
}

#[test]
fn test_au_abn_bad_checksum_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("ABN: 51824753557");
    assert!(
        !dets.iter().any(|d| d.entity_type == "AU_ABN"),
        "AU ABN with bad checksum should be rejected: {dets:?}"
    );
}

#[test]
fn test_au_abn_various_contexts() {
    let mut a = Anonymizer::new(0.0);
    let contexts = [
        "australian business number 51 824 753 556",
        "GST registered ABN: 51 824 753 556",
        "Tax invoice ABN 51 824 753 556",
    ];
    for ctx in &contexts {
        let (_, dets) = a.anonymize_text(ctx);
        assert!(
            dets.iter().any(|d| d.entity_type == "AU_ABN"),
            "AU ABN not detected in: {ctx}"
        );
    }
}

#[test]
fn test_au_abn_roundtrip() {
    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_text("ABN: 51 824 753 556");
    assert!(!result.contains("51 824 753 556"));
    assert!(result.contains("[AU_ABN_"));
}

// -- AU_ACN tests --

#[test]
fn test_au_acn_with_context_formatted() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("ACN: 004 085 616");
    assert!(
        dets.iter().any(|d| d.entity_type == "AU_ACN"),
        "AU ACN not detected: {dets:?}"
    );
    assert!(result.contains("[AU_ACN_"));
}

#[test]
fn test_au_acn_with_context_compact() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("ACN: 004085616");
    assert!(
        dets.iter().any(|d| d.entity_type == "AU_ACN"),
        "AU ACN compact not detected: {dets:?}"
    );
    assert!(result.contains("[AU_ACN_"));
}

#[test]
fn test_au_acn_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("code 004085616 end");
    assert!(
        !dets.iter().any(|d| d.entity_type == "AU_ACN"),
        "AU ACN without context should be rejected: {dets:?}"
    );
}

#[test]
fn test_au_acn_bad_checksum_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("ACN: 004085617");
    assert!(
        !dets.iter().any(|d| d.entity_type == "AU_ACN"),
        "AU ACN with bad checksum should be rejected: {dets:?}"
    );
}

#[test]
fn test_au_acn_various_contexts() {
    let mut a = Anonymizer::new(0.0);
    let contexts = [
        "australian company number 004 085 616",
        "ASIC registered ACN: 004 085 616",
        "corporation ACN 004 085 616",
    ];
    for ctx in &contexts {
        let (_, dets) = a.anonymize_text(ctx);
        assert!(
            dets.iter().any(|d| d.entity_type == "AU_ACN"),
            "AU ACN not detected in: {ctx}"
        );
    }
}

#[test]
fn test_au_acn_roundtrip() {
    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_text("ACN: 004 085 616");
    assert!(!result.contains("004 085 616"));
    assert!(result.contains("[AU_ACN_"));
}

// -- AU_TFN tests --

#[test]
fn test_au_tfn_with_context_formatted() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("TFN: 123 456 782");
    assert!(
        dets.iter().any(|d| d.entity_type == "AU_TFN"),
        "AU TFN not detected: {dets:?}"
    );
    assert!(result.contains("[AU_TFN_"));
}

#[test]
fn test_au_tfn_with_context_compact() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("TFN: 123456782");
    assert!(
        dets.iter().any(|d| d.entity_type == "AU_TFN"),
        "AU TFN compact not detected: {dets:?}"
    );
    assert!(result.contains("[AU_TFN_"));
}

#[test]
fn test_au_tfn_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("code 123456782 end");
    assert!(
        !dets.iter().any(|d| d.entity_type == "AU_TFN"),
        "AU TFN without context should be rejected: {dets:?}"
    );
}

#[test]
fn test_au_tfn_bad_checksum_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("TFN: 123456789");
    assert!(
        !dets.iter().any(|d| d.entity_type == "AU_TFN"),
        "AU TFN with bad checksum should be rejected: {dets:?}"
    );
}

#[test]
fn test_au_tfn_various_contexts() {
    let mut a = Anonymizer::new(0.0);
    let contexts = [
        "tax file number 123 456 782",
        "ATO tax file 123 456 782",
        "tax number: 123 456 782",
    ];
    for ctx in &contexts {
        let (_, dets) = a.anonymize_text(ctx);
        assert!(
            dets.iter().any(|d| d.entity_type == "AU_TFN"),
            "AU TFN not detected in: {ctx}"
        );
    }
}

#[test]
fn test_au_tfn_roundtrip() {
    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_text("TFN: 123 456 782");
    assert!(!result.contains("123 456 782"));
    assert!(result.contains("[AU_TFN_"));
}

// -- AU_MEDICARE tests --

#[test]
fn test_au_medicare_with_context_formatted() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("Medicare: 2123 45670 1");
    assert!(
        dets.iter().any(|d| d.entity_type == "AU_MEDICARE"),
        "AU MEDICARE not detected: {dets:?}"
    );
    assert!(result.contains("[AU_MEDICARE_"));
}

#[test]
fn test_au_medicare_with_context_compact() {
    let mut a = Anonymizer::new(0.0);
    let (result, dets) = a.anonymize_text("Medicare: 2123456701");
    assert!(
        dets.iter().any(|d| d.entity_type == "AU_MEDICARE"),
        "AU MEDICARE compact not detected: {dets:?}"
    );
    assert!(result.contains("[AU_MEDICARE_"));
}

#[test]
fn test_au_medicare_no_context_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("code 2123456701 end");
    assert!(
        !dets.iter().any(|d| d.entity_type == "AU_MEDICARE"),
        "AU MEDICARE without context should be rejected: {dets:?}"
    );
}

#[test]
fn test_au_medicare_bad_checksum_rejected() {
    let mut a = Anonymizer::new(0.0);
    let (_, dets) = a.anonymize_text("Medicare: 2123456711");
    assert!(
        !dets.iter().any(|d| d.entity_type == "AU_MEDICARE"),
        "AU MEDICARE with bad checksum should be rejected: {dets:?}"
    );
}

#[test]
fn test_au_medicare_various_contexts() {
    let mut a = Anonymizer::new(0.0);
    let contexts = [
        "medicare number 2123 45670 1",
        "health card 2123 45670 1",
        "Medicare card: 2123 45670 1",
    ];
    for ctx in &contexts {
        let (_, dets) = a.anonymize_text(ctx);
        assert!(
            dets.iter().any(|d| d.entity_type == "AU_MEDICARE"),
            "AU MEDICARE not detected in: {ctx}"
        );
    }
}

#[test]
fn test_au_medicare_roundtrip() {
    let mut a = Anonymizer::new(0.0);
    let (result, _) = a.anonymize_text("Medicare: 2123 45670 1");
    assert!(!result.contains("2123 45670 1"));
    assert!(result.contains("[AU_MEDICARE_"));
}

#[test]
fn test_au_medicare_first_digit_range() {
    let mut a = Anonymizer::new(0.0);
    // First digit must be 2-6 for Medicare; digit 1 should not match
    let (_, dets) = a.anonymize_text("Medicare: 1123456701");
    assert!(
        !dets.iter().any(|d| d.entity_type == "AU_MEDICARE"),
        "AU MEDICARE with first digit 1 should be rejected: {dets:?}"
    );
}
